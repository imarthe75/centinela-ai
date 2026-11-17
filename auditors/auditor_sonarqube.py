"""
Centinela SonarQube Integration — Real Code Quality & Security Analysis
Runs sonar-scanner against cloned GitLab repositories via an ephemeral sibling
container (same docker-outside-of-docker pattern as auditor_zap.py), polls the
real SonarQube Compute Engine task, and ingests real issues/measures/quality
gate results into vulnerability_log via the shared dedup engine.
"""
import os
import re
import shutil
import subprocess
import time
import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

import requests

from core import db_manager, deduplication_engine

logger = logging.getLogger(__name__)

SONAR_HOST_URL = os.getenv("SONAR_HOST_URL", "http://centinela-sonarqube:9000")
SONAR_TOKEN = os.getenv("SONAR_TOKEN", "")
SONAR_DOCKER_NETWORK = "aura-network"
# sonarsource/sonar-scanner-cli is JVM-based and not baked into centinela-ai's own image
# (see Dockerfile — only Python-native SAST tools live there); invoked as a sibling
# container instead, same reasoning as ZAP.
SONAR_SCANNER_IMAGE = os.getenv("SONAR_SCANNER_IMAGE", "sonarsource/sonar-scanner-cli:latest")

# GitLabIntegrator.scan_workspace ("/tmp/centinela_gitlab_scans") lives only inside
# centinela-ai's own container filesystem -- invisible to a sibling container spawned via
# docker.sock, which resolves `-v` bind-mount sources against the REAL HOST filesystem
# (same class of bug already documented for ZAP's original cache path). This workspace
# instead lives under the `.:/app` bind mount, so `/app/data/sonar_scans/<key>` inside
# centinela-ai corresponds to a real, host-visible path.
SONARQUBE_WORKSPACE = "/app/data/sonar_scans"
HOST_PROJECT_ROOT = os.getenv("HOST_PROJECT_ROOT", "/opt/centinela-ai")

SCANNER_TIMEOUT = int(os.getenv("SONAR_SCANNER_TIMEOUT", "600"))       # 10 min
CE_TASK_TIMEOUT = int(os.getenv("SONAR_CE_TASK_TIMEOUT", "600"))       # 10 min
CE_TASK_POLL_INTERVAL = 4
MIN_RESCAN_INTERVAL_HOURS = 24

MARKER_CVE_ID = "SONARQUBE-QUALITY-GATE"

# Legacy issue["severity"]: BLOCKER > CRITICAL > MAJOR > MINOR > INFO.
_LEGACY_SEVERITY_MAP = {
    "BLOCKER": "CRITICAL",
    "CRITICAL": "CRITICAL",
    "MAJOR": "HIGH",
    "MINOR": "MEDIUM",
    "INFO": "LOW",
}
# Newer issue["impacts"][*]["severity"] (Clean Code taxonomy, SonarQube 10.x+):
# BLOCKER/HIGH/MEDIUM/LOW/INFO. Which shape a given server actually returns must be
# confirmed live against the real pinned version -- this maps both rather than guessing.
_IMPACT_SEVERITY_MAP = {
    "BLOCKER": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
    "INFO": "LOW",
}


SECRET_REDACTION_KEY = "sonar.security.secretSourceRedaction.enabled"
# Changing a global setting needs the "Administer System" permission; the scan token
# (centinela-scanner: provisioning + scan) cannot. Optional, set only by the owner.
SONAR_ADMIN_TOKEN = os.getenv("SONAR_ADMIN_TOKEN", "")
_redaction_state: Dict[str, Any] = {"checked": False, "status": None}


def secret_redaction_status(force: bool = False) -> Dict[str, Any]:
    """
    Reports (and, when SONAR_ADMIN_TOKEN is set, enforces) SonarQube's "mask detected secret
    values in source code" setting (SonarQube 26.10+). With it off, SonarQube's own source
    view and source-returning Web API show every detected secret in clear text.

    Returns {"enabled": bool|None, "changed": bool, "detail": str}. `enabled` is None when
    the server could not be asked -- never reported as on without the server saying so.
    Checked once per process unless `force`.
    """
    if _redaction_state["checked"] and not force:
        return _redaction_state["status"]
    status: Dict[str, Any] = {"enabled": None, "changed": False, "detail": ""}
    try:
        resp = requests.get(f"{SONAR_HOST_URL}/api/settings/values",
                            params={"keys": SECRET_REDACTION_KEY},
                            headers={"Authorization": f"Bearer {SONAR_TOKEN}"}, timeout=10)
        resp.raise_for_status()
        values = resp.json().get("settings", [])
        current = values[0].get("value") if values else None
        if current is None:
            status["detail"] = "SonarQube no expone el ajuste (versión anterior a 26.10)."
        else:
            status["enabled"] = str(current).lower() == "true"
        if status["enabled"] is False:
            if SONAR_ADMIN_TOKEN:
                set_resp = requests.post(f"{SONAR_HOST_URL}/api/settings/set",
                                         data={"key": SECRET_REDACTION_KEY, "value": "true"},
                                         headers={"Authorization": f"Bearer {SONAR_ADMIN_TOKEN}"}, timeout=10)
                if set_resp.status_code in (200, 204):
                    status.update(enabled=True, changed=True, detail="Activado con SONAR_ADMIN_TOKEN.")
                else:
                    status["detail"] = (f"SONAR_ADMIN_TOKEN no pudo activarlo (HTTP {set_resp.status_code}); "
                                        "actívelo en Administración > Configuración > Seguridad.")
            else:
                status["detail"] = ("Desactivado: SonarQube muestra los secretos detectados en claro. Requiere un "
                                    "administrador (Administración > Configuración > Seguridad) o SONAR_ADMIN_TOKEN.")
    except Exception as e:
        logger.error("SonarQube secret-redaction check failed", exc_info=True)
        status["detail"] = f"No se pudo consultar SonarQube: {e}"
    if status["enabled"] is False:
        logger.warning("⚠️ [SonarQube-Auditor] %s", status["detail"])
    _redaction_state.update(checked=True, status=status)
    return status


class SonarQubeScanError(Exception):
    """Raised when a scan could not be completed (scanner failure, CE task failure/timeout)."""
    pass


# ---------------------------------------------------------------------------
# Pure functions (no DB, no network, no docker) -- unit-testable in isolation.
# ---------------------------------------------------------------------------

def _sanitize_project_key(name: str) -> str:
    """Builds a SonarQube-safe project key from a GitLab path_with_namespace or repo name."""
    key = re.sub(r"[^a-zA-Z0-9._-]+", "-", str(name or "").strip()).strip("-").lower()
    return key or "centinela-unknown-project"


def _map_sonar_severity(issue: Dict[str, Any]) -> str:
    """Maps a SonarQube issue to Centinela's CRITICAL/HIGH/MEDIUM/LOW scale."""
    legacy = str(issue.get("severity") or "").upper()
    if legacy in _LEGACY_SEVERITY_MAP:
        return _LEGACY_SEVERITY_MAP[legacy]

    impacts = issue.get("impacts") or []
    if impacts:
        impact_severity = str(impacts[0].get("severity") or "").upper()
        if impact_severity in _IMPACT_SEVERITY_MAP:
            return _IMPACT_SEVERITY_MAP[impact_severity]

    return "MEDIUM"


def _build_cve_id(rule_key: str) -> str:
    return "SONAR-" + str(rule_key or "unknown-rule").replace(":", "-")


def _build_url_path(issue: Dict[str, Any], project_key: str) -> str:
    component = str(issue.get("component") or "")
    prefix = f"{project_key}:"
    component_path = component[len(prefix):] if component.startswith(prefix) else component
    line = issue.get("line")
    if not line:
        text_range = issue.get("textRange") or {}
        line = text_range.get("startLine")
    return f"{component_path}:{line}" if line else component_path


def _extract_ce_task_id_from_output(stdout: str) -> Optional[str]:
    """
    Extracts the real Compute Engine task id from sonar-scanner's own stdout, e.g.:
    "More about the report processing at http://.../api/ce/task?id=<uuid>". Deliberately NOT
    read from `.scannerwork/report-task.txt` on disk -- confirmed live (via `docker diff` on a
    non---rm run) that sonarsource/sonar-scanner-cli:12.1.0.3233_8.0.1 (SonarScanner CLI
    8.0.1, the current unified engine) writes that file under /tmp inside its own ephemeral
    container, NOT under the mounted project directory (`-w /usr/src`) as the classic
    sonar-scanner shell script used to -- so it was never visible on the host side at all.
    Parsing stdout instead is also more robust across scanner engine versions in general.
    """
    # Must anchor on "ce/task?id=" specifically, not a bare "?id=" -- sonar-scanner's own
    # stdout prints an earlier "...dashboard?id=<projectKey>" line first (confirmed live),
    # which a generic "id=" match would grab instead of the real Compute Engine task id.
    match = re.search(r"ce/task\?id=([\w-]+)", stdout or "")
    return match.group(1) if match else None


def _build_marker_description(outcome: str, detail: Dict[str, Any]) -> str:
    """
    Builds the honest completion-marker description for the 3 real outcomes, mirroring
    auditor_cis_benchmarks.py's log_cis_findings() SIN_CONEXION/partial/complete pattern:
    always describe what actually happened, never a fabricated success.
    """
    if outcome == "success":
        gate_status = detail.get("gate_status", "UNKNOWN")
        issue_count = detail.get("issue_count", 0)
        measures = detail.get("measures", {})
        return (
            f"Auditoría SonarQube completada. Quality Gate: {gate_status} "
            f"({issue_count} issues abiertos). "
            f"ncloc={measures.get('ncloc', 'N/D')}, "
            f"complexity={measures.get('complexity', 'N/D')}, "
            f"cognitive_complexity={measures.get('cognitive_complexity', 'N/D')}, "
            f"duplicated_lines_density={measures.get('duplicated_lines_density', 'N/D')}%, "
            f"coverage={measures.get('coverage', 'N/D')}%."
        )
    if outcome == "scan_failed":
        return (
            f"Auditoría SonarQube: el escaneo no pudo completarse "
            f"({detail.get('reason', 'error desconocido')}). No se generó Quality Gate."
        )
    return f"Auditoría SonarQube: resultado no reconocido ({outcome})."


# ---------------------------------------------------------------------------
# Docker-outside-of-docker + SonarQube Web API calls.
# ---------------------------------------------------------------------------

def _materialize_host_visible_copy(target_dir: str, safe_key: str) -> str:
    """
    Copies the already-cloned repo (wherever GitLabIntegrator put it) into a location
    under the `.:/app` bind mount, so its REAL HOST path can be bind-mounted into the
    sibling sonar-scanner container. Returns the container-local path (/app/data/...);
    the caller derives the host-side path via HOST_PROJECT_ROOT for the actual `docker run -v`.

    symlinks=True: confirmed live and deterministic (not the transient race below) against two
    real GitLab projects (arquitectura/proyecto-n, arquitectura/proyecto-o),
    both containing a broken symlink named "backups". shutil.copytree()'s default
    (symlinks=False) dereferences symlinks and tries to copy the FILE CONTENT their target
    points to -- for a broken symlink that target doesn't exist, so every single attempt to
    scan either repo failed identically with "[Errno 2] No such file or directory", not just
    once. Confirmed the same underlying broken symlink independently trips up
    auditor_master_vulnerabilities.py/auditor_sca_dependencies.py too (their own os.walk-based
    logging shows the identical path), so this isn't specific to this auditor's copy step.
    symlinks=True preserves the symlink itself (as git and every other real auditor here
    already effectively does), matching real repo content instead of trying to resolve it.

    One further bounded retry on shutil.Error/FileNotFoundError, for a genuinely different,
    transient cause: confirmed live against a real GitLab project (arquitectura/proyecto-m)
    that GitLabIntegrator's own clone_or_pull() can still be mutating `target_dir` (git pull)
    while this copy runs, so an unrelated file can vanish mid-copytree (TOCTOU race between
    shutil's listdir and copy passes). A second attempt against the (by then quiescent) source
    directory is sufficient; this one isn't a persistent condition the way the symlink case was.
    """
    dest = os.path.join(SONARQUBE_WORKSPACE, safe_key)
    os.makedirs(SONARQUBE_WORKSPACE, exist_ok=True)

    for attempt in range(2):
        if os.path.exists(dest):
            shutil.rmtree(dest, ignore_errors=True)
        try:
            shutil.copytree(target_dir, dest, symlinks=True, ignore=shutil.ignore_patterns(".git"))
            return dest
        except (shutil.Error, FileNotFoundError):
            if attempt == 1:
                raise
            print(f"⚠️ [SonarQube-Auditor] Transient copy error for {safe_key}, retrying once...")


SONAR_EXCLUSIONS = os.getenv(
    "SONAR_EXCLUSIONS",
    "**/node_modules/**,**/vendor/**,**/dist/**,**/build/**,**/target/**,**/*.min.js,**/*.min.css,"
    "**/assets/layout/**,**/assets/demo/**,**/assets/themes/**,**/*.bundle.js,**/*.map",
)


def _run_sonar_scanner(container_local_path: str, safe_key: str, project_name: str) -> str:
    """Runs sonar-scanner as a sibling container. Returns its stdout. Raises SonarQubeScanError on any failure."""
    host_path = f"{HOST_PROJECT_ROOT}/data/sonar_scans/{safe_key}"

    # Same permissions lesson as ZAP's launch_zap_container(): the scanner image's uid may
    # not be able to write into a directory created host-side under a different uid --
    # cheap insurance, matches the proven ZAP fix.
    subprocess.run(
        ["docker", "run", "--rm", "-v", f"{host_path}:/target", "busybox",
         "chmod", "-R", "0777", "/target"],
        capture_output=True, timeout=30
    )

    cmd = [
        "docker", "run", "--rm",
        "--network", SONAR_DOCKER_NETWORK,
        "-v", f"{host_path}:/usr/src",
        "-w", "/usr/src",
        "-e", f"SONAR_HOST_URL={SONAR_HOST_URL}",
        "-e", f"SONAR_TOKEN={SONAR_TOKEN}",
        SONAR_SCANNER_IMAGE,
        f"-Dsonar.projectKey={safe_key}",
        f"-Dsonar.projectName={project_name}",
        "-Dsonar.sources=.",
        # Third-party / generated code is not the team's code: 43% of all SonarQube rows (2026-09-23)
        # were CSS smells inside a vendored PrimeNG theme (src/assets/layout/styles/theme/*).
        f"-Dsonar.exclusions={SONAR_EXCLUSIONS}",
    ]
    print(f"🔍 [SonarQube-Auditor] Running sonar-scanner for {safe_key}...")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=SCANNER_TIMEOUT)
    except subprocess.TimeoutExpired as e:
        raise SonarQubeScanError(f"sonar-scanner timed out after {SCANNER_TIMEOUT}s") from e

    if result.returncode != 0:
        raise SonarQubeScanError(f"sonar-scanner exited {result.returncode}: {result.stderr[-2000:]}")

    return result.stdout


def _poll_ce_task(ce_task_id: str) -> Dict[str, Any]:
    """Polls the real Compute Engine task until SUCCESS/FAILED/CANCELED. Never assumes instant completion."""
    headers = {"Authorization": f"Bearer {SONAR_TOKEN}"}
    deadline = time.time() + CE_TASK_TIMEOUT
    while time.time() < deadline:
        resp = requests.get(f"{SONAR_HOST_URL}/api/ce/task", params={"id": ce_task_id},
                             headers=headers, timeout=10)
        resp.raise_for_status()
        task = resp.json().get("task", {})
        status = task.get("status")
        if status == "SUCCESS":
            return task
        if status in ("FAILED", "CANCELED"):
            raise SonarQubeScanError(f"Compute Engine task {status}: {task.get('errorMessage', 'no detail')}")
        time.sleep(CE_TASK_POLL_INTERVAL)
    raise SonarQubeScanError(f"Compute Engine task {ce_task_id} did not finish within {CE_TASK_TIMEOUT}s")


SONAR_MAX_RESULTS_WINDOW = 10000   # SonarQube's api/issues/search refuses p*ps beyond this
_SONAR_TYPES = ("VULNERABILITY", "SECURITY_HOTSPOT", "BUG", "CODE_SMELL")
_SONAR_SEVERITIES = ("BLOCKER", "CRITICAL", "MAJOR", "MINOR", "INFO")


def _fetch_issues_slice(project_key: str, extra: Dict[str, str]) -> "tuple[List[Dict[str, Any]], int]":
    headers = {"Authorization": f"Bearer {SONAR_TOKEN}"}
    issues: List[Dict[str, Any]] = []
    page, page_size, total = 1, 500, 0
    while True:
        resp = requests.get(
            f"{SONAR_HOST_URL}/api/issues/search",
            params={"componentKeys": project_key, "statuses": "OPEN,CONFIRMED,REOPENED",
                    "p": page, "ps": page_size, **extra},
            headers=headers, timeout=30
        )
        resp.raise_for_status()
        data = resp.json()
        issues.extend(data.get("issues", []))
        total = data.get("paging", {}).get("total", len(issues))
        if len(issues) >= total or not data.get("issues") or page * page_size >= SONAR_MAX_RESULTS_WINDOW:
            break
        page += 1
    return issues, total


def _fetch_issues(project_key: str) -> List[Dict[str, Any]]:
    """All open issues. SonarQube caps a single query at 10,000 results, so a big project is
    fetched per (type, severity) slice. If any slice still exceeds the window the result would be
    PARTIAL -- that must never be treated as complete (it drives reconcile-as-resolved), so it raises."""
    issues, total = _fetch_issues_slice(project_key, {})
    if total <= SONAR_MAX_RESULTS_WINDOW:
        return issues
    seen: Dict[str, Dict[str, Any]] = {}
    for t in _SONAR_TYPES:
        for sev in _SONAR_SEVERITIES:
            part, part_total = _fetch_issues_slice(project_key, {"types": t, "severities": sev})
            if part_total > SONAR_MAX_RESULTS_WINDOW:
                raise SonarQubeScanError(
                    f"{project_key}: slice {t}/{sev} has {part_total} issues (> {SONAR_MAX_RESULTS_WINDOW}); "
                    "refusing to treat a truncated result as complete")
            for it in part:
                seen[it["key"]] = it
    return list(seen.values())


def _fetch_measures(project_key: str) -> Dict[str, str]:
    headers = {"Authorization": f"Bearer {SONAR_TOKEN}"}
    metric_keys = "ncloc,complexity,cognitive_complexity,duplicated_lines_density,coverage,sqale_index"
    resp = requests.get(
        f"{SONAR_HOST_URL}/api/measures/component",
        params={"component": project_key, "metricKeys": metric_keys},
        headers=headers, timeout=15
    )
    resp.raise_for_status()
    measures = resp.json().get("component", {}).get("measures", [])
    return {m["metric"]: m.get("value") for m in measures}


def _fetch_quality_gate(project_key: str) -> str:
    headers = {"Authorization": f"Bearer {SONAR_TOKEN}"}
    resp = requests.get(
        f"{SONAR_HOST_URL}/api/qualitygates/project_status",
        params={"projectKey": project_key},
        headers=headers, timeout=15
    )
    resp.raise_for_status()
    return resp.json().get("projectStatus", {}).get("status", "UNKNOWN")


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

def _recently_scanned(asset_id: Optional[str], min_interval_hours: int = MIN_RESCAN_INTERVAL_HOURS) -> bool:
    """Self-throttle: sonar-scanner takes minutes per repo, not seconds -- without this,
    scanning 59+ real GitLab projects on every ~30s idle-loop cycle would make one full
    cycle take hours. Mirrors CIS-BENCHMARK-AUDIT's own detected_at-based pattern."""
    if asset_id is None:
        return False
    with db_manager.get_db_cursor() as cur:
        cur.execute(
            "SELECT detected_at FROM public.vulnerability_log "
            "WHERE asset_id = %s AND cve_id = %s",
            (asset_id, MARKER_CVE_ID)
        )
        row = cur.fetchone()
    return bool(row) and row[0] > datetime.utcnow() - timedelta(hours=min_interval_hours)


# Informational issues (code smells and reliability bugs) are stored ONE ROW PER RULE AND FILE, with every line listed, instead of one row
# per occurrence (ADR-0019 phase 2): 178k occurrence rows were 66k rule/file groups and drowned every list and report. Security issues
# (VULNERABILITY, SECURITY_HOTSPOT) keep one row per occurrence: each one is a separate thing to fix and to triage.
SECURITY_TYPES = ("VULNERABILITY", "SECURITY_HOTSPOT")
_SEV_ORDER = tuple(sorted(deduplication_engine._SEV_RANK, key=deduplication_engine._SEV_RANK.get))   # CRITICAL first, INFO last
MAX_LINES_LISTED = 200


def is_informational(issue: Dict[str, Any]) -> bool:
    return issue.get("type") not in SECURITY_TYPES


def file_of(url_path: str) -> str:
    """'src/a.ts:12' -> 'src/a.ts' (a trailing number after the last colon is the line)."""
    head, sep, tail = str(url_path or "").rpartition(":")
    return head if sep and tail.isdigit() else str(url_path or "")


def line_of(url_path: str) -> Optional[int]:
    head, sep, tail = str(url_path or "").rpartition(":")
    return int(tail) if sep and tail.isdigit() else None


def aggregate_description(sonar_type: str, rule: str, messages: List[str], lines: List[int], efforts: List[str]) -> str:
    lines = sorted(set(lines))
    shown = ", ".join(str(n) for n in lines[:MAX_LINES_LISTED]) + (f" (+{len(lines) - MAX_LINES_LISTED} más)" if len(lines) > MAX_LINES_LISTED else "")
    distinct = list(dict.fromkeys(m for m in messages if m))[:3]
    n = max(len(messages), len(lines), 1)
    return (f"**SonarQube {sonar_type}** ({rule}) — {n} ocurrencia(s) en este archivo\n"
            + "\n".join(distinct or ["Sin descripción"])
            + (f"\n**Líneas:** {shown}" if lines else "")
            + f"\n**Esfuerzo estimado (por ocurrencia):** {efforts[0] if efforts else 'N/D'}")


def finding_rows(issues: List[Dict[str, Any]], project_key: str) -> List[Dict[str, Any]]:
    """What a scan stores: one row per security occurrence, one per (rule, file) for informational issues."""
    rows: List[Dict[str, Any]] = []
    groups: Dict[tuple, Dict[str, Any]] = {}
    for issue in issues:
        cve_id = _build_cve_id(issue.get("rule"))
        url_path = _build_url_path(issue, project_key)
        severity = _map_sonar_severity(issue)
        if not is_informational(issue):
            rows.append({"cve_id": cve_id, "url_path": url_path, "severity": severity, "finding_category": "VULNERABILITY",
                         "description": (f"**SonarQube {issue.get('type', 'ISSUE')}** ({issue.get('rule')})\n"
                                         f"{issue.get('message', 'Sin descripción')}\n**Esfuerzo estimado:** {issue.get('effort', 'N/D')}")})
            continue
        key = (cve_id, file_of(url_path))
        g = groups.setdefault(key, {"type": issue.get("type", "ISSUE"), "rule": issue.get("rule"), "messages": [], "lines": [],
                                    "efforts": [], "severity": severity})
        g["messages"].append(issue.get("message") or "")
        if line_of(url_path) is not None:
            g["lines"].append(line_of(url_path))
        if issue.get("effort"):
            g["efforts"].append(issue["effort"])
        if _SEV_ORDER.index(severity) < _SEV_ORDER.index(g["severity"]):
            g["severity"] = severity
    for (cve_id, path), g in groups.items():
        rows.append({"cve_id": cve_id, "url_path": path, "severity": g["severity"], "finding_category": "INFORMATIONAL",
                     "description": aggregate_description(g["type"], g["rule"], g["messages"], g["lines"], g["efforts"])})
    return rows


def _persist_issues(cur, asset_id: Optional[str], project_key: str, issues: List[Dict[str, Any]]) -> int:
    count = 0
    for row in finding_rows(issues, project_key):
        deduplication_engine.log_finding_deduplicated(
            cur, asset_id, row["cve_id"], row["severity"], row["description"], "sonarqube",
            url_path=row["url_path"], open_status="OPEN", preserve_status=True,
            finding_category=row["finding_category"]
        )
        count += 1
    return count


def _persist_marker(cur, asset_id: Optional[str], outcome: str, detail: Dict[str, Any]) -> None:
    marker_desc = _build_marker_description(outcome, detail)
    deduplication_engine.log_finding_deduplicated(
        cur, asset_id, MARKER_CVE_ID, "Info", marker_desc, "sonarqube",
        url_path=MARKER_CVE_ID, open_status="NEW", preserve_status=True
    )


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def run_sonarqube_audit(target_dir: str, asset_id: str = None,
                         project_key: str = None, repo_display_name: str = None) -> List[Dict[str, Any]]:
    """
    Runs a real SonarQube analysis against `target_dir` (an already-cloned repo) and
    ingests real issues + a completion marker into vulnerability_log.

    Mirrors run_iac_scan(target_dir, asset_id=None)/run_sca_audit(target_dir, asset_id=None)'s
    calling convention for drop-in use from GitLabIntegrator.scan_all_projects().

    On genuine scan failure (scanner error, CE task FAILED/timeout), still writes an honest
    failure marker (same philosophy as CIS-BENCHMARK-AUDIT's SIN_CONEXION -- never fabricate
    success) and then re-raises, so the caller's own exception handling logs the full
    traceback (Rule #6: no silent swallowing).
    """
    safe_key = _sanitize_project_key(project_key or repo_display_name or os.path.basename(target_dir.rstrip("/")))
    project_name = repo_display_name or safe_key

    # Never scan/persist without a real asset: a SONARQUBE-QUALITY-GATE marker (or issues) with
    # asset_id NULL is invisible in every asset-scoped view and just accumulates as noise. Every
    # legitimate caller (GitLabIntegrator, the self-audit endpoints, the local re-scan script)
    # resolves and passes one -- if it's missing or points at a deleted asset, that's a bug in
    # the caller, not something to paper over with an orphan row. (2026-08-27)
    if asset_id is None:
        print(f"⏭️  [SonarQube-Auditor] {safe_key}: no asset_id -- skipping (would create an orphan marker).")
        return []
    try:
        with db_manager.get_db_cursor() as _chk:
            _chk.execute("SELECT 1 FROM public.infra_inventory WHERE id = %s", (asset_id,))
            if _chk.fetchone() is None:
                print(f"⏭️  [SonarQube-Auditor] {safe_key}: asset_id {asset_id} not in infra_inventory -- skipping.")
                return []
    except Exception as _e:
        print(f"⚠️  [SonarQube-Auditor] {safe_key}: could not verify asset_id {asset_id} ({_e}) -- skipping this cycle.")
        return []

    if _recently_scanned(asset_id):
        print(f"⏭️  [SonarQube-Auditor] {safe_key} scanned within the last {MIN_RESCAN_INTERVAL_HOURS}h -- skipping")
        return []

    secret_redaction_status()
    container_local_path = _materialize_host_visible_copy(target_dir, safe_key)

    try:
        scanner_stdout = _run_sonar_scanner(container_local_path, safe_key, project_name)
        ce_task_id = _extract_ce_task_id_from_output(scanner_stdout)
        if not ce_task_id:
            raise SonarQubeScanError(f"Could not find a Compute Engine task id in scanner output: {scanner_stdout[-1000:]}")

        _poll_ce_task(ce_task_id)

        issues = _fetch_issues(safe_key)
        measures = _fetch_measures(safe_key)
        gate_status = _fetch_quality_gate(safe_key)

        with db_manager.get_db_cursor() as cur:
            persisted = _persist_issues(cur, asset_id, safe_key, issues)
            # Close findings this complete scan no longer reproduces (fixed code, or newly excluded
            # vendored paths) instead of leaving them open forever.
            active_fps = {
                deduplication_engine.calculate_fingerprint(asset_id, r["cve_id"], r["url_path"])
                for r in finding_rows(issues, safe_key)
            }
            resolved = deduplication_engine.reconcile_resolved_findings(cur, asset_id, "sonarqube", active_fps)
            if resolved:
                print(f"🧹 [SonarQube-Auditor] {safe_key}: {resolved} stale issue(s) reconciled as RESOLVED.")
            _persist_marker(cur, asset_id, "success", {
                "gate_status": gate_status, "issue_count": len(issues), "measures": measures,
            })

        print(f"✅ [SonarQube-Auditor] {safe_key}: {persisted} issues, Quality Gate {gate_status}")
        return issues

    except SonarQubeScanError as e:
        import traceback
        traceback.print_exc()
        print(f"⚠️ [SonarQube-Auditor] Scan failed for {safe_key}: {e}")
        with db_manager.get_db_cursor() as cur:
            _persist_marker(cur, asset_id, "scan_failed", {"reason": str(e)})
        raise
    finally:
        shutil.rmtree(container_local_path, ignore_errors=True)


# ---------------------------------------------------------------------------
# One-time consolidation of rows stored per occurrence (before ADR-0019 phase 2)
# ---------------------------------------------------------------------------
_DESC_RE = re.compile(r"^\*\*SonarQube (?P<type>[A-Z_]+)\*\* \((?P<rule>[^)]*)\)(?: —[^\n]*)?\n(?P<msg>[^\n]*)(?:[\s\S]*?\*\*Esfuerzo estimado[^:]*:\*\* (?P<effort>[^\n]*))?")
_LINES_RE = re.compile(r"\*\*Líneas:\*\* ([0-9, ]+)")


def consolidate_informational_rows(cur, asset_id: str) -> Dict[str, int]:
    """Turns the open informational SonarQube rows of one asset into one row per (rule, file), exactly what a fresh scan now writes, so
    the next scan updates them in place instead of 'resolving' thousands of per-line rows. The survivor of each group keeps its id and
    analysis; the rest are deleted with their remediation_history and comparison-baseline rows. Rows with a human decision are never
    touched. Returns counts; the caller owns the transaction."""
    cur.execute("""
        SELECT v.id::text, v.cve_id, v.url_path, UPPER(v.severity), v.description, v.status, v.detected_at, v.fingerprint_hash
          FROM public.vulnerability_log v
         WHERE v.asset_id = %s AND v.scan_engine = 'sonarqube' AND v.finding_category = 'INFORMATIONAL'
           AND v.status NOT IN ('RESOLVED', 'SUPPRESSED')
           AND NOT EXISTS (SELECT 1 FROM public.remediation_history r WHERE r.vuln_id = v.id AND r.approval_token <> 'PENDING_APPROVAL')
    """, (asset_id,))
    groups: Dict[tuple, List[tuple]] = {}
    for row in cur.fetchall():
        groups.setdefault((row[1], file_of(row[2])), []).append(row)
    stats = {"groups": 0, "rows_before": sum(len(g) for g in groups.values()), "deleted": 0, "updated": 0}
    doomed: List[str] = []
    for (cve_id, path), rows in groups.items():
        target_fp = deduplication_engine.calculate_fingerprint(asset_id, cve_id, path)
        cur.execute("SELECT id::text, status FROM public.vulnerability_log WHERE fingerprint_hash = %s", (target_fp,))
        holder = cur.fetchone()
        ids = [r[0] for r in rows]
        if holder and holder[0] in ids:
            survivor_id = holder[0]
        elif holder:                                  # an existing (e.g. resolved) row already has the aggregated identity: reuse it
            survivor_id = holder[0]
        else:
            survivor_id = max(rows, key=lambda r: (r[6] is not None, r[6]))[0]
        messages, lines, efforts, sev, stype, rule = [], [], [], "INFO", "CODE_SMELL", cve_id
        for r in rows:
            m = _DESC_RE.match(r[4] or "")
            if m:
                stype, rule = m.group("type"), m.group("rule")
                messages.append(m.group("msg"))
                if m.group("effort"):
                    efforts.append(m.group("effort"))
            listed = _LINES_RE.search(r[4] or "")
            if listed:
                lines += [int(x) for x in listed.group(1).replace(" ", "").split(",") if x.isdigit()]
            if line_of(r[2]) is not None:
                lines.append(line_of(r[2]))
            s = r[3] if r[3] in _SEV_ORDER else "MEDIUM"
            if _SEV_ORDER.index(s) < _SEV_ORDER.index(sev):
                sev = s
        others = [i for i in ids if i != survivor_id]
        doomed += others
        if others:
            cur.execute("DELETE FROM public.remediation_history WHERE vuln_id = ANY(%s::uuid[])", (others,))
            cur.execute("DELETE FROM public.scan_run_baseline WHERE finding_id = ANY(%s::uuid[])", (others,))
            cur.execute("DELETE FROM public.vulnerability_log WHERE id = ANY(%s::uuid[])", (others,))
        cur.execute("""UPDATE public.vulnerability_log
                          SET url_path = %s, description = %s, severity = %s, fingerprint_hash = %s,
                              status = CASE WHEN status = 'RESOLVED' THEN 'OPEN' ELSE status END
                        WHERE id = %s::uuid""",
                    (path, aggregate_description(stype, rule, messages, lines, efforts), sev, target_fp, survivor_id))
        stats["groups"] += 1
        stats["updated"] += 1
    stats["deleted"] = len(doomed)
    return stats
