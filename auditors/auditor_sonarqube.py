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
    real GitLab projects (arquitectura/consulta-smart, arquitectura/consulta-rag-universal),
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
    transient cause: confirmed live against a real GitLab project (arquitectura/geo-ircep-smart)
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


def _fetch_issues(project_key: str) -> List[Dict[str, Any]]:
    headers = {"Authorization": f"Bearer {SONAR_TOKEN}"}
    issues: List[Dict[str, Any]] = []
    page = 1
    page_size = 500
    while True:
        resp = requests.get(
            f"{SONAR_HOST_URL}/api/issues/search",
            params={"componentKeys": project_key, "statuses": "OPEN,CONFIRMED,REOPENED",
                    "p": page, "ps": page_size},
            headers=headers, timeout=30
        )
        resp.raise_for_status()
        data = resp.json()
        issues.extend(data.get("issues", []))
        total = data.get("paging", {}).get("total", len(issues))
        if len(issues) >= total or not data.get("issues"):
            break
        page += 1
    return issues


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

def _recently_scanned(asset_id: Optional[int], min_interval_hours: int = MIN_RESCAN_INTERVAL_HOURS) -> bool:
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


def _persist_issues(cur, asset_id: Optional[int], project_key: str, issues: List[Dict[str, Any]]) -> int:
    count = 0
    for issue in issues:
        # Only real VULNERABILITY-type issues are meaningfully "attacker technique"-shaped;
        # CODE_SMELL is code-quality, not a MITRE ATT&CK-mappable finding -- same exclusion
        # precedent already used for STD-ISO25010-LONG-METHOD/HEURISTIC-SECURITY-DEBT in
        # core/mitre_attack.py's own _RULES table (no SONAR- entries added there for v1).
        cve_id = _build_cve_id(issue.get("rule"))
        severity = _map_sonar_severity(issue)
        url_path = _build_url_path(issue, project_key)
        description = (
            f"**SonarQube {issue.get('type', 'ISSUE')}** ({issue.get('rule')})\n"
            f"{issue.get('message', 'Sin descripción')}\n"
            f"**Esfuerzo estimado:** {issue.get('effort', 'N/D')}"
        )
        # Real per-issue category from SonarQube's own API "type" field. Only VULNERABILITY and
        # SECURITY_HOTSPOT are genuinely security-relevant; CODE_SMELL is maintainability, and
        # -- real bug fixed 2026-08-21, found live while building a report on 3 new projects --
        # BUG is a functional-reliability defect (code that will misbehave at runtime), a
        # different axis of SonarQube's taxonomy entirely, not a security vulnerability either.
        # The original reasoning here ("VULNERABILITY/BUG/SECURITY_HOTSPOT are real security-
        # relevant") was wrong -- confirmed live against a real project: 469 of 487 "vulnerabilities"
        # reported for one Angular frontend were actually type BUG (mostly HTML/accessibility
        # defects like InputWithoutLabelCheck), not security issues at all; the real count was 18.
        finding_category = "VULNERABILITY" if issue.get("type") in ("VULNERABILITY", "SECURITY_HOTSPOT") else "INFORMATIONAL"
        deduplication_engine.log_finding_deduplicated(
            cur, asset_id, cve_id, severity, description, "sonarqube",
            url_path=url_path, open_status="OPEN", preserve_status=True,
            finding_category=finding_category
        )
        count += 1
    return count


def _persist_marker(cur, asset_id: Optional[int], outcome: str, detail: Dict[str, Any]) -> None:
    marker_desc = _build_marker_description(outcome, detail)
    deduplication_engine.log_finding_deduplicated(
        cur, asset_id, MARKER_CVE_ID, "Info", marker_desc, "sonarqube",
        url_path=MARKER_CVE_ID, open_status="NEW", preserve_status=True
    )


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def run_sonarqube_audit(target_dir: str, asset_id: int = None,
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
