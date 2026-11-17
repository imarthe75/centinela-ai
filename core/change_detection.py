"""Change detection for GitLab assets: re-analyze only what changed since the last analysis.

"What was analyzed" = (commit, engine_version) of the asset's last finished GitLab scan (scan_runs). "What is available" = the latest
commit of the asset's branch in GitLab (gitlab_branch_heads, refreshed in the background and on demand: one GitLab call per project
returns the head of every branch). States of an asset:

  CAMBIOS         the branch has a commit newer than the analyzed one        -> a person may re-analyze it
  SIN_ANALISIS    the asset exists but no finished scan recorded a commit     -> a person may analyze it
  REGLAS_NUEVAS   same commit, but the detectors changed since                -> the fleet branch is picked up by the nightly run;
                                                                                 a branch chosen by hand waits for its next commit (no manual button)
  AL_DIA          same commit and same detectors                              -> nothing to do
  RAMA_ELIMINADA  the branch no longer exists in GitLab                       -> nothing to scan
  SIN_VERIFICAR   GitLab has not been asked yet for this branch               -> refresh first
  EN_COLA         a scan of this asset is already queued or running

The point is not to spend scanner time and AI tokens on code that did not change: a manual re-analysis is only allowed for CAMBIOS and
SIN_ANALISIS, and the daily fleet run skips a project whose fleet branch is AL_DIA.
"""
import concurrent.futures
import hashlib
import logging
import os
import uuid
from typing import Any, Dict, Iterable, List, Optional, Tuple

from core import db_manager

logger = logging.getLogger("centinela")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# Code whose change can change the findings of an unchanged repository: the auditors and the shared classifier/fingerprint logic.
ENGINE_PATHS = ("auditors", os.path.join("core", "deduplication_engine.py"))

CAMBIOS, SIN_ANALISIS, REGLAS_NUEVAS, AL_DIA = "CAMBIOS", "SIN_ANALISIS", "REGLAS_NUEVAS", "AL_DIA"
RAMA_ELIMINADA, SIN_VERIFICAR, EN_COLA = "RAMA_ELIMINADA", "SIN_VERIFICAR", "EN_COLA"
MANUAL_RESCAN_STATES = (CAMBIOS, SIN_ANALISIS)

PREFERRED_FLEET_BRANCHES = ("develop", "development", "desarrollo", "dev")   # same order as GitLabIntegrator._PREFERRED_BRANCHES
GITLAB_JOB_KIND = "gitlab_project"
RESCAN_PRIORITY = 20          # above the periodic fleet backlog (0) and a single branch asked for by a person (10)
MAX_ASSETS_PER_REQUEST = 400
REFRESH_WORKERS = int(os.getenv("GITLAB_HEADS_REFRESH_WORKERS", "6"))   # parallel GitLab calls when refreshing many projects

_engine_cache: Dict[str, Any] = {"key": None, "version": None}


def _engine_files(root: str = REPO_ROOT) -> List[str]:
    files = []
    for rel in ENGINE_PATHS:
        p = os.path.join(root, rel)
        if os.path.isfile(p):
            files.append(p)
        elif os.path.isdir(p):
            for dp, dn, fn in os.walk(p):
                dn[:] = [d for d in dn if d != "__pycache__"]
                files += [os.path.join(dp, f) for f in fn if f.endswith(".py")]
    return sorted(files)


def engine_version(root: str = REPO_ROOT) -> str:
    """Short fingerprint of the detector code (path + content of every file in ENGINE_PATHS). Re-hashed only when a file's mtime or the
    file set changes, so it is cheap to call per scan; the code is a live bind mount, so a long-running process sees edits."""
    files = _engine_files(root)
    key = tuple((f, os.path.getmtime(f)) for f in files)
    if _engine_cache["key"] == key:
        return _engine_cache["version"]
    h = hashlib.sha256()
    for f in files:
        h.update(os.path.relpath(f, root).encode())
        with open(f, "rb") as fh:
            h.update(fh.read())
    version = h.hexdigest()[:16]
    _engine_cache.update(key=key, version=version)
    return version


def pick_fleet_branch(branches: Iterable[Dict[str, Any]]) -> Optional[str]:
    """The branch the daily fleet scan audits: the first preferred name present (case-insensitive), else the default branch.
    Mirrors GitLabIntegrator.pick_branch but from an already-fetched branch list (no extra API call)."""
    branches = list(branches)
    lower = {str(b.get("name", "")).lower(): b.get("name") for b in branches}
    for pref in PREFERRED_FLEET_BRANCHES:
        if pref in lower:
            return lower[pref]
    for b in branches:
        if b.get("default"):
            return b.get("name")
    return None


def classify(analyzed_commit: Optional[str], analyzed_engine: Optional[str], remote_commit: Optional[str], missing: bool,
             checked: bool, queued: bool, current_engine: str) -> str:
    """State of one asset from its facts (pure; see the module docstring)."""
    if queued:
        return EN_COLA
    if not checked:
        return SIN_VERIFICAR
    if missing or not remote_commit:
        return RAMA_ELIMINADA
    if not analyzed_commit:
        return SIN_ANALISIS
    if analyzed_commit != remote_commit:
        return CAMBIOS
    if analyzed_engine != current_engine:
        return REGLAS_NUEVAS
    return AL_DIA


# --- GitLab heads ------------------------------------------------------------------------------------------------------------------

def _project_assets(inst, path: str) -> Dict[str, str]:
    """{branch: asset_name} of the GitLab assets this project has in the inventory."""
    with db_manager.get_db_cursor() as cur:
        cur.execute("SELECT asset_name FROM public.infra_inventory WHERE asset_name LIKE %s",
                    (inst.asset_name(path).replace("%", r"\%").replace("_", r"\_") + "@%",))
        out = {}
        for (name,) in cur.fetchall():
            out[name.split("@", 1)[1]] = name
        return out


def refresh_project(inst, path: str) -> Dict[str, Any]:
    """Ask GitLab for every branch head of one project and store the ones that matter: branches with an asset, plus the fleet branch.
    Branch assets whose branch disappeared are marked missing. Raises when GitLab cannot be asked (callers decide how to report it)."""
    from auditors.gitlab_integration import GitLabIntegrator
    branches = GitLabIntegrator(instance=inst.key).list_branches(path)
    fleet = pick_fleet_branch(branches)
    remote = {b["name"]: b for b in branches}
    assets = _project_assets(inst, path)
    wanted = set(assets) | ({fleet} if fleet else set())
    with db_manager.get_db_cursor() as cur:
        for br in wanted:
            b = remote.get(br)
            cur.execute("""
                INSERT INTO public.gitlab_branch_heads (instance, project_path, branch, asset_name, commit_sha, committed_at, is_fleet_branch, missing, checked_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, now())
                ON CONFLICT (instance, project_path, branch) DO UPDATE SET asset_name = EXCLUDED.asset_name, commit_sha = EXCLUDED.commit_sha,
                    committed_at = EXCLUDED.committed_at, is_fleet_branch = EXCLUDED.is_fleet_branch, missing = EXCLUDED.missing, checked_at = now()
            """, (inst.key, path, br, inst.asset_name(path, br), (b or {}).get("commit_sha"), (b or {}).get("last_commit_at"),
                  br == fleet, b is None))
        cur.execute("DELETE FROM public.gitlab_branch_heads WHERE instance = %s AND project_path = %s AND NOT (branch = ANY(%s))",
                    (inst.key, path, list(wanted) or [""]))
    return {"fleet_branch": fleet, "branches": len(branches)}


def refresh_projects(projects: Iterable[Tuple[Any, str]], max_workers: Optional[int] = None) -> Dict[str, Any]:
    """Refresh many (instance, path) pairs in parallel. One failing project never stops the others; failures are returned."""
    projects = list({(i.key, p): (i, p) for i, p in projects}.values())
    failed: List[Dict[str, str]] = []

    def _one(ip):
        try:
            refresh_project(*ip)
            return None
        except Exception as e:
            logger.error("[change-detection] cannot read branches of %s:%s", ip[0].key, ip[1], exc_info=True)
            return {"project": f"{ip[0].asset_prefix}{ip[1]}", "error": f"{type(e).__name__}: {e}"[:300]}

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers or REFRESH_WORKERS) as ex:
        for r in ex.map(_one, projects):
            if r:
                failed.append(r)
    return {"projects": len(projects), "failed": failed}


def refresh_assets(asset_names: Iterable[str]) -> Dict[str, Any]:
    from core.gitlab_instances import parse_asset_name
    pairs = []
    for n in asset_names:
        inst, path, _ = parse_asset_name(n)
        if inst and path:
            pairs.append((inst, path))
    return refresh_projects(pairs)


def refresh_all_inventory() -> Dict[str, Any]:
    """Background refresh: every project that has GitLab assets (excluded projects skipped)."""
    from core import gitlab_instances
    exclusions = gitlab_instances.scan_exclusions()
    names = select_asset_names()
    pairs = []
    for n in names:
        inst, path, _ = gitlab_instances.parse_asset_name(n)
        if inst and path and not gitlab_instances.is_scan_excluded(inst, path, exclusions):
            pairs.append((inst, path))
    return refresh_projects(pairs)


# --- states ------------------------------------------------------------------------------------------------------------------------

def select_asset_names(prefix: Optional[str] = None, assets: Optional[List[str]] = None) -> List[str]:
    """GitLab asset names under a prefix ("GitLab/grupo/") or from an explicit list."""
    with db_manager.get_db_cursor() as cur:
        if assets:
            cur.execute(r"SELECT asset_name FROM public.infra_inventory WHERE asset_name = ANY(%s) AND asset_name ~ '^GitLab[0-9]*/'", (list(assets),))
        elif prefix:
            cur.execute(r"SELECT asset_name FROM public.infra_inventory WHERE asset_name LIKE %s AND asset_name ~ '^GitLab[0-9]*/'",
                        (prefix.replace("%", r"\%").replace("_", r"\_") + "%",))
        else:
            cur.execute(r"SELECT asset_name FROM public.infra_inventory WHERE asset_name ~ '^GitLab[0-9]*/'")
        return sorted(r[0] for r in cur.fetchall())


def _active_jobs() -> Dict[str, str]:
    """{asset_name: status} for GitLab scans queued or running. A fleet job (target 'inst:path') audits the project's fleet branch."""
    from core.gitlab_instances import get_instance
    out: Dict[str, str] = {}
    with db_manager.get_db_cursor() as cur:
        cur.execute("""SELECT j.target, j.status, j.payload->>'branch', h.branch
                       FROM public.scan_jobs j
                       LEFT JOIN public.gitlab_branch_heads h ON h.instance = split_part(j.target, ':', 1)
                            AND h.project_path = substring(j.target from position(':' in j.target) + 1) AND h.is_fleet_branch
                       WHERE j.kind = %s AND j.status IN ('QUEUED', 'RUNNING')""", (GITLAB_JOB_KIND,))
        for target, status, payload_branch, fleet_branch in cur.fetchall():
            key, _, rest = target.partition(":")
            path, at, branch = rest.partition("@")
            branch = branch if at else (payload_branch or fleet_branch)
            if not branch:
                continue
            try:
                out[get_instance(key).asset_name(path, branch)] = status
            except KeyError:
                continue
    return out


def asset_states(prefix: Optional[str] = None, assets: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    """Change state of every GitLab asset selected (database only, no GitLab call)."""
    current = engine_version()
    names = select_asset_names(prefix, assets)
    if not names:
        return []
    active = _active_jobs()
    with db_manager.get_db_cursor() as cur:
        cur.execute("""
            SELECT i.asset_name, r.commit_sha, r.engine_version, r.finished_at, h.commit_sha, h.committed_at, h.checked_at, h.missing, h.is_fleet_branch
            FROM public.infra_inventory i
            LEFT JOIN LATERAL (SELECT s.commit_sha, s.engine_version, s.finished_at FROM public.scan_runs s
                               WHERE s.asset_id = i.id AND s.status = 'DONE' AND s.source LIKE 'gitlab:%%' AND s.commit_sha IS NOT NULL
                               ORDER BY s.finished_at DESC LIMIT 1) r ON true
            LEFT JOIN public.gitlab_branch_heads h ON h.asset_name = i.asset_name
            WHERE i.asset_name = ANY(%s)
        """, (names,))
        rows = cur.fetchall()
    out = []
    for name, a_sha, a_eng, a_at, r_sha, r_at, checked_at, missing, is_fleet in rows:
        state = classify(a_sha, a_eng, r_sha, bool(missing), checked_at is not None, name in active, current)
        out.append({"asset_name": name, "state": state, "rescan_allowed": state in MANUAL_RESCAN_STATES,
                    "analyzed_commit": a_sha, "analyzed_engine": a_eng, "analyzed_at": a_at.isoformat() if a_at else None,
                    "remote_commit": r_sha, "remote_committed_at": r_at.isoformat() if r_at else None,
                    "checked_at": checked_at.isoformat() if checked_at else None, "is_fleet_branch": bool(is_fleet),
                    "job_status": active.get(name)})
    return sorted(out, key=lambda x: x["asset_name"])


def summarize(states: List[Dict[str, Any]]) -> Dict[str, int]:
    s: Dict[str, int] = {}
    for x in states:
        s[x["state"]] = s.get(x["state"], 0) + 1
    s["rescan_allowed"] = sum(1 for x in states if x["rescan_allowed"])
    return s


# --- daily fleet run -----------------------------------------------------------------------------------------------------------

def fleet_branch_unchanged(inst, path: str, fresh_after) -> Tuple[bool, Optional[str]]:
    """(True, reason) when the project's fleet branch was already analyzed at its current commit with the current detectors, so the
    daily run can skip it. Uses the stored head when it was checked after `fresh_after`; otherwise asks GitLab once. Any doubt (no head,
    no analysis, GitLab error) returns False: when in doubt, scan."""
    def _load():
        with db_manager.get_db_cursor() as cur:
            cur.execute("""SELECT h.branch, h.commit_sha, h.checked_at FROM public.gitlab_branch_heads h
                           WHERE h.instance = %s AND h.project_path = %s AND h.is_fleet_branch""", (inst.key, path))
            return cur.fetchone()
    head = _load()
    if not head or head[2] is None or (fresh_after is not None and head[2] < fresh_after):
        try:
            refresh_project(inst, path)
        except Exception:
            logger.error("[change-detection] fleet check of %s:%s failed; scanning it anyway", inst.key, path, exc_info=True)
            return False, None
        head = _load()
    if not head or not head[1]:
        return False, None
    with db_manager.get_db_cursor() as cur:
        cur.execute("""SELECT s.commit_sha, s.engine_version FROM public.scan_runs s JOIN public.infra_inventory i ON i.id = s.asset_id
                       WHERE i.asset_name = %s AND s.status = 'DONE' AND s.source LIKE 'gitlab:%%' AND s.commit_sha IS NOT NULL
                       ORDER BY s.finished_at DESC LIMIT 1""", (inst.asset_name(path, head[0]),))
        run = cur.fetchone()
    if run and run[0] == head[1] and run[1] == engine_version():
        return True, f"{head[0]}@{head[1][:8]} ya analizado con los detectores actuales"
    return False, None


# --- manual re-analysis of what changed ---------------------------------------------------------------------------------------

def enqueue_changed(prefix: Optional[str] = None, assets: Optional[List[str]] = None) -> Dict[str, Any]:
    """Re-analyze, as one batch, the selected assets whose code changed (CAMBIOS) or that were never analyzed (SIN_ANALISIS). Asks GitLab
    first so the decision is made on the current heads, never on a stale cache. Returns the batch id and what was (not) queued."""
    from auditors.gitlab_integration import GitLabIntegrator
    from core import gitlab_instances, job_queue
    names = select_asset_names(prefix, assets)
    if not names:
        raise LookupError("No hay activos de GitLab en la selección")
    if len(names) > MAX_ASSETS_PER_REQUEST:
        raise ValueError(f"La selección tiene {len(names)} activos; el máximo por solicitud es {MAX_ASSETS_PER_REQUEST}. Elija un subgrupo.")
    refresh = refresh_assets(names)
    states = asset_states(assets=names)
    batch_id = str(uuid.uuid4())
    queued, joined, skipped = [], [], []
    projects: Dict[Tuple[str, str], Any] = {}
    for st in states:
        if st["state"] == EN_COLA:
            inst, path, branch = gitlab_instances.parse_asset_name(st["asset_name"])
            _join_active(inst, path, branch, st["is_fleet_branch"], batch_id)
            joined.append(st["asset_name"])
            continue
        if not st["rescan_allowed"]:
            skipped.append({"asset_name": st["asset_name"], "state": st["state"]})
            continue
        inst, path, branch = gitlab_instances.parse_asset_name(st["asset_name"])
        key = (inst.key, path)
        if key not in projects:
            projects[key] = GitLabIntegrator(instance=inst.key).get_project_details(path)
        proj = projects[key]
        if not proj:
            skipped.append({"asset_name": st["asset_name"], "state": "PROYECTO_NO_ENCONTRADO"})
            continue
        payload = {"instance": inst.key, "project": proj, "branch": branch, "priority": RESCAN_PRIORITY, "batch_id": batch_id}
        if st["is_fleet_branch"]:
            target = f"{inst.key}:{path}"                      # same target as the daily run: never two scans of the same asset
        else:
            target = f"{inst.key}:{path}@{branch}"
            payload["separate_asset"] = True
        if job_queue.enqueue(GITLAB_JOB_KIND, target, payload):
            queued.append(st["asset_name"])
        else:                                                   # became active between the state read and now
            _join_active(inst, path, branch, st["is_fleet_branch"], batch_id)
            joined.append(st["asset_name"])
    return {"batch_id": batch_id if (queued or joined) else None, "queued": queued, "already_queued": joined,
            "skipped": skipped, "refresh_failed": refresh["failed"], "selected": len(names)}


def _join_active(inst, path: str, branch: Optional[str], is_fleet: bool, batch_id: str) -> None:
    """Attach an already queued/running scan to the batch (so the progress counts it) and move a queued one up to the batch priority."""
    targets = [f"{inst.key}:{path}@{branch}"] + ([f"{inst.key}:{path}"] if is_fleet else [])
    with db_manager.get_db_cursor() as cur:
        cur.execute("""UPDATE public.scan_jobs SET payload = payload || jsonb_build_object('batch_id', %s::text,
                           'priority', GREATEST(COALESCE((payload->>'priority')::int, 0), %s))
                       WHERE kind = %s AND target = ANY(%s) AND status IN ('QUEUED', 'RUNNING')""",
                    (batch_id, RESCAN_PRIORITY, GITLAB_JOB_KIND, targets))


def batch_progress(batch_id: str) -> Dict[str, Any]:
    with db_manager.get_db_cursor() as cur:
        cur.execute("""SELECT status, count(*) FROM public.scan_jobs WHERE kind = %s AND payload->>'batch_id' = %s GROUP BY status""",
                    (GITLAB_JOB_KIND, batch_id))
        counts = {s: n for s, n in cur.fetchall()}
        cur.execute("""SELECT target FROM public.scan_jobs WHERE kind = %s AND payload->>'batch_id' = %s AND status = 'RUNNING' LIMIT 1""",
                    (GITLAB_JOB_KIND, batch_id))
        running = cur.fetchone()
    total = sum(counts.values())
    finished = counts.get("DONE", 0) + counts.get("FAILED", 0)
    return {"batch_id": batch_id, "total": total, "done": counts.get("DONE", 0), "failed": counts.get("FAILED", 0),
            "running": counts.get("RUNNING", 0), "queued": counts.get("QUEUED", 0), "current": running[0] if running else None,
            "percent": round(100 * finished / total) if total else 0, "finished": total > 0 and finished == total}
