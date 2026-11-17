"""
Secrets in GIT HISTORY for the GitLab fleet (queue kind 'secrets_history').

Why a separate job: the regular fleet scan clones with --depth 1, so it can only ever see the current tree. A credential committed last year and "deleted"
afterwards is still readable by anyone with clone access, and until 2026-10-12 NOTHING in the fleet pipeline looked for it (the `secrets` engine had 0 rows
in production; its code only ran for the old local-"Repository" path). This job makes ONE full clone per project, runs TruffleHog over the whole history,
deletes the clone, and repeats weekly.

Honesty rules:
  * a TruffleHog failure or timeout RAISES (the queue records it and retries) -- it never turns into a "0 findings" success;
  * a repo above SECRETS_HISTORY_MAX_MB is skipped and the skip is reported, never counted as clean;
  * live verification (sending a candidate credential to its issuer) stays OFF unless SECRETS_VERIFY_LIVE=1, as in auditor_secrets;
  * the raw secret is never stored (parse_trufflehog_output keeps only the detector's redacted preview).
Findings attach to the project's primary asset ("<path>@<branch the fleet scan audits>"). History findings are NOT auto-resolved: a leaked secret stays
a finding until it is rotated, even if a later commit removed it from the tree.
"""
import os
import shutil
import subprocess
import tempfile
from typing import Any, Dict, Optional
from urllib.parse import urlparse

SECRETS_JOB_KIND = "secrets_history"
MAX_MB = int(os.getenv("SECRETS_HISTORY_MAX_MB", "800"))
CLONE_TIMEOUT = int(os.getenv("SECRETS_HISTORY_CLONE_TIMEOUT", "900"))
SCAN_TIMEOUT = int(os.getenv("SECRETS_HISTORY_SCAN_TIMEOUT", "1500"))
RESCAN_HOURS = float(os.getenv("SECRETS_HISTORY_RESCAN_HOURS", "168"))     # weekly


def enqueue_secrets_history_scans(min_interval_hours: Optional[float] = None) -> Dict[str, Any]:
    """Queue one history scan per project of every configured instance (idempotent; a project scanned in the last RESCAN_HOURS is skipped)."""
    from auditors.gitlab_integration import GitLabIntegrator
    from core import gitlab_instances, job_queue
    import traceback
    hours = RESCAN_HOURS if min_interval_hours is None else min_interval_hours
    summary: Dict[str, Any] = {"projects_seen": 0, "enqueued": 0, "skipped": 0, "instances_failed": []}
    for inst in gitlab_instances.configured_instances():
        try:
            projects = GitLabIntegrator(instance=inst.key).fetch_projects()
        except Exception:
            traceback.print_exc()
            summary["instances_failed"].append(inst.key)
            continue
        exclusions = gitlab_instances.scan_exclusions()
        for proj in projects:
            summary["projects_seen"] += 1
            if gitlab_instances.is_scan_excluded(inst, proj.get("path_with_namespace") or "", exclusions):
                summary["excluded"] = summary.get("excluded", 0) + 1
                continue
            target = f"{inst.key}:{proj.get('path_with_namespace') or proj.get('id')}"
            job_id = job_queue.enqueue(SECRETS_JOB_KIND, target, {"instance": inst.key, "project": {"id": proj.get("id"), "path_with_namespace": proj.get("path_with_namespace"),
                                                                                                    "http_url_to_repo": proj.get("http_url_to_repo")}},
                                       min_interval_hours=hours)
            summary["enqueued" if job_id else "skipped"] += 1
    return summary


def _clone_full(repo_url: str, instance, dest: str) -> None:
    """Full clone (history included). The token goes ONLY into a URL of this instance's own host (same guard as GitLabIntegrator.clone_or_pull)."""
    if urlparse(repo_url).netloc.split("@")[-1].lower() != urlparse(instance.url).netloc.lower():
        raise RuntimeError(f"refusing to clone from '{urlparse(repo_url).netloc}': not the configured GitLab host '{urlparse(instance.url).netloc}'")
    url = repo_url
    if instance.token and "@" not in url:
        url = url.replace("http://", f"http://oauth2:{instance.token}@").replace("https://", f"https://oauth2:{instance.token}@")
    r = subprocess.run(["git", "clone", "--quiet", "--no-checkout", url, dest], capture_output=True, text=True, timeout=CLONE_TIMEOUT)
    if r.returncode != 0:
        raise RuntimeError(f"git clone failed: {r.stderr.replace(instance.token or '<none>', '***')[-300:]}")
    # --no-checkout leaves no .git/index and TruffleHog's git source needs one to open the repository (seen live on the first run). read-tree builds the
    # index from HEAD without writing the working tree, so no source files are materialised on disk.
    rt = subprocess.run(["git", "-C", dest, "read-tree", "HEAD"], capture_output=True, text=True, timeout=120)
    if rt.returncode != 0:
        raise RuntimeError(f"git read-tree failed: {rt.stderr[-300:]}")


_SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


def aggregate_detections(findings):
    """ONE finding per (detector, file), not one per detection.

    Measured on the first full run (2026-10-12): 11,270 findings, of which 10,056 came from two SQL dumps committed to git (9,108 'JWT' detections in one file). A dump full
    of tokens is a single decision for the owner -- remove it from the history and rotate what it contained -- not 9,108 tickets, and thousands of NEW rows would have flooded
    the AI queue. The representative keeps the first line/commit; the description states how many detections and in how many commits, so nothing is hidden."""
    groups = {}
    for f in findings:
        groups.setdefault((f["type"], f["file"]), []).append(f)
    out = []
    for (typ, file_), items in groups.items():
        rep = dict(items[0])
        rep["severity"] = max((i["severity"] for i in items), key=lambda x: _SEV_RANK.get(x, 0))
        n, commits = len(items), len({i.get("commit") for i in items if i.get("commit")})
        if n > 1:
            extra = f" ({n} detecciones en {commits} commit(s) distintos de este archivo; se muestra la primera)"
            rep["description"] = f"{rep['description']}{extra}"
            if file_.lower().endswith((".sql", ".dump", ".bak", ".csv")) and n >= 20:
                rep["description"] += (" -- parece un VOLCADO de base de datos versionado: el volcado completo en el repositorio es en sí un riesgo de exposición de datos "
                                       "(quitarlo del historial y rotar las credenciales y tokens que contenía)")
        out.append(rep)
    return out


def run_secrets_history_job(job: Dict[str, Any]) -> Dict[str, Any]:
    from auditors import auditor_secrets
    from auditors.gitlab_integration import GitLabIntegrator
    from core import db_manager
    payload = job["payload"]
    integ = GitLabIntegrator(instance=payload["instance"])
    proj = integ.get_project_details(payload["project"].get("id") or payload["project"]["path_with_namespace"])
    if not proj:
        raise RuntimeError(f"project {payload['project']} not found in GitLab")
    path_ns = proj["path_with_namespace"]

    # size guard (statistics need their own query flag)
    import requests
    stats = requests.get(f"{integ.gitlab_url}/api/v4/projects/{proj['id']}", params={"statistics": "true"},
                         headers={"PRIVATE-TOKEN": integ.token} if integ.token else {}, timeout=20)
    size_mb = ((stats.json().get("statistics") or {}).get("repository_size", 0) or 0) / 1_048_576 if stats.status_code == 200 else 0
    if size_mb > MAX_MB:
        print(f"⏭️ [Secrets-History] {path_ns}: repository is {size_mb:.0f} MB (> {MAX_MB} MB) -- NOT scanned (reported as skipped, not as clean)")
        return {"status": "skipped", "reason": f"repo_too_large_{size_mb:.0f}MB", "project": path_ns}
    if proj.get("empty_repo"):
        return {"status": "skipped", "reason": "empty_repo", "project": path_ns}

    branch = integ.pick_branch(proj["id"]) or proj.get("default_branch") or ""
    asset_name = integ.instance.asset_name(path_ns, branch)
    with db_manager.get_db_cursor() as cur:
        cur.execute("SELECT id FROM public.infra_inventory WHERE asset_name = %s", (asset_name,))
        row = cur.fetchone()
    if not row:
        raise RuntimeError(f"asset '{asset_name}' is not registered yet (the regular scan creates it); retried later")
    asset_id = str(row[0])

    tmp = tempfile.mkdtemp(prefix="secrets_hist_")
    try:
        dest = os.path.join(tmp, "repo")
        _clone_full(proj.get("http_url_to_repo") or payload["project"].get("http_url_to_repo"), integ.instance, dest)
        verify_live = os.getenv("SECRETS_VERIFY_LIVE", "0") == "1"
        cmd = ["trufflehog", "git", f"file://{dest}", "--json", "--no-update", "--concurrency=2", auditor_secrets.TRUFFLEHOG_RESULTS_VERIFY if verify_live else "--no-verification"]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=SCAN_TIMEOUT)
        if r.returncode not in (0, 183):     # 183 = findings present when --fail is used; plain runs exit 0
            raise RuntimeError(f"trufflehog exited {r.returncode}: {(r.stderr or '')[-300:]}")
        findings = auditor_secrets.parse_trufflehog_output(r.stdout, verify_live)
        whitelist = auditor_secrets.SecretsScanner.load_whitelist(dest)
        findings = [f for f in findings if not auditor_secrets.SecretsScanner.is_whitelisted(f["type"], f.get("masked_context"), whitelist)]
        raw_detections = len(findings)
        findings = aggregate_detections(findings)
        if findings:
            auditor_secrets.log_secrets(asset_id, dest, findings, "3")
        print(f"🔐 [Secrets-History] {path_ns}: {raw_detections} detection(s) in the full history -> {len(findings)} finding(s) (grouped by detector and file)")
        return {"status": "success", "project": path_ns, "asset": asset_name, "secrets": len(findings), "detections": raw_detections, "repo_mb": round(size_mb)}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
