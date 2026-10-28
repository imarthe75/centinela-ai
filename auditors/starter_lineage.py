"""
Starter lineage (ADR-0012 D5): which of a project's files come UNCHANGED from the organisation's Starter Core, which were modified, and which
are the project's own -- so a finding in an inherited file is reported as "fix once in the Starter" instead of N separate defects.

The Starter Core is the WHOLE GitLab group `starters/` (owner's definition, 2026-10-14): every project in it is part of the reusable base.
    STARTER_CORE_GROUPS="starters"          (default; comma-separated GitLab groups)
    STARTER_CORE_PROJECTS=""                (optional extra single projects outside those groups)
The comparison uses the clones the fleet scanner already keeps. With no clone it answers "no evaluable"; it never invents a lineage. Pure functions take plain paths so they are testable with real temp directories.

States per project file (compared with the Starter's file at the SAME relative path, content normalised: BOM, CRLF, trailing blanks):
  inherited  identical to the Starter file
  diverged   same path, different content (the project customised it)
  moved      identical content to a Starter file at a DIFFERENT path
  own        no counterpart in the Starter
Limits: whole-file comparison (a one-line change makes the file `diverged` even if the flagged line is the inherited part); generated and
vendored paths are ignored; files > 1 MB are ignored; a project that copied the Starter once and drifted from an OLDER version shows as diverged.
"""
import hashlib
import os
from collections import defaultdict
from typing import Dict, Iterable, List, Optional

IGNORE_DIRS = {".git", "node_modules", "target", "build", "dist", ".gradle", ".idea", ".vscode", "__pycache__", "venv", ".venv", "coverage",
               ".angular", ".next", "out", "bin", "obj"}
IGNORE_FILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "gradle.lockfile"}
MAX_BYTES = 1_000_000
MAX_FILES = 40_000   # a tree with more comparable files than this is truncated (and says so) instead of reading forever
DEFAULT_STARTER_GROUPS = "starters"

INHERITED, DIVERGED, MOVED, OWN = "inherited", "diverged", "moved", "own"


def normalize_hash(data: bytes) -> str:
    """sha256 of the content after BOM / line-ending / trailing-whitespace normalisation (so a CRLF checkout does not look 'modified')."""
    if data.startswith(b"\xef\xbb\xbf"):
        data = data[3:]
    text = data.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    text = b"\n".join(line.rstrip() for line in text.split(b"\n")).rstrip(b"\n") + b"\n"
    return hashlib.sha256(text).hexdigest()


class TreeTooLarge(Exception):
    """The tree has more than MAX_FILES comparable files: refuse a partial index that would read as a full one."""


def index_tree(root: str) -> Dict[str, str]:
    """{relative/posix/path: content hash} for every comparable file under root. Raises TreeTooLarge past MAX_FILES (never a silent partial index)."""
    out: Dict[str, str] = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS]
        for fn in filenames:
            if fn in IGNORE_FILES:
                continue
            full = os.path.join(dirpath, fn)
            try:
                if os.path.islink(full) or os.path.getsize(full) > MAX_BYTES:
                    continue
                with open(full, "rb") as f:
                    out[os.path.relpath(full, root).replace(os.sep, "/")] = normalize_hash(f.read())
                if len(out) > MAX_FILES:
                    raise TreeTooLarge(f"{root}: más de {MAX_FILES} archivos comparables")
            except OSError:
                continue
    return out


def classify_files(project_index: Dict[str, str], starter_indexes: Dict[str, Dict[str, str]]) -> Dict[str, dict]:
    """{project path: {"state": ..., "starter": <starter name>, "starter_path": <path in the starter>}}"""
    by_hash: Dict[str, List[tuple]] = defaultdict(list)
    for name, idx in starter_indexes.items():
        for p, h in idx.items():
            by_hash[h].append((name, p))
    out: Dict[str, dict] = {}
    for path, h in project_index.items():
        same_path = [(n, idx[path]) for n, idx in starter_indexes.items() if path in idx]
        exact = next(((n, path) for n, ph in same_path if ph == h), None)
        if exact:
            out[path] = {"state": INHERITED, "starter": exact[0], "starter_path": exact[1]}
        elif same_path:
            out[path] = {"state": DIVERGED, "starter": same_path[0][0], "starter_path": path}
        elif h in by_hash:
            n, p = by_hash[h][0]
            out[path] = {"state": MOVED, "starter": n, "starter_path": p}
        else:
            out[path] = {"state": OWN, "starter": None, "starter_path": None}
    return out


def split_location(url_path: Optional[str]) -> Optional[str]:
    """'a/b/File.java:12' -> 'a/b/File.java' (None for anything that is not a repo-relative path)."""
    if not url_path:
        return None
    rel = url_path.rpartition(":")[0] if url_path.rpartition(":")[2].isdigit() else url_path
    rel = rel.strip().replace("\\", "/")
    if not rel or rel.startswith("/") or ".." in rel.split("/"):
        return None
    return rel


def annotate_findings(findings: Iterable[dict], lineage: Dict[str, dict]) -> List[dict]:
    """Adds `lineage` (state dict, or {"state": 'unknown'} when the finding has no file or the file is not in the clone) to each finding."""
    out = []
    for f in findings:
        rel = split_location(f.get("url_path"))
        info = lineage.get(rel) if rel else None
        g = dict(f)
        g["lineage"] = info or {"state": "unknown", "starter": None, "starter_path": None}
        out.append(g)
    return out


def starter_groups() -> List[str]:
    return [g.strip().strip("/") for g in os.getenv("STARTER_CORE_GROUPS", DEFAULT_STARTER_GROUPS).split(",") if g.strip()]


def starter_projects() -> List[str]:
    """Extra single projects (outside the configured groups) that also belong to the Starter Core."""
    return [p.strip().strip("/") for p in os.getenv("STARTER_CORE_PROJECTS", "").split(",") if p.strip()]


def is_starter_path(project_path: str) -> bool:
    """True if a GitLab project path (no instance prefix, no @branch) belongs to the Starter Core: used to keep the Starter out of its own comparison."""
    p = (project_path or "").strip("/")
    return any(p == g or p.startswith(g + "/") for g in starter_groups()) or p in starter_projects()


def starter_dirs(workspace: str = "/tmp/centinela_gitlab_scans", instance_key: str = "primary") -> Dict[str, str]:
    """{label: clone dir} for every project of the Starter Core that has a clone on disk. Group members are found by the clone folder prefix
    (`<group>_...`); a project cloned both as `<name>` (legacy) and `<name>@<branch>-<hash>` counts once, preferring the branch clone."""
    from core import gitlab_instances as gi
    inst = gi.get_instance(instance_key)
    entries = sorted(os.listdir(workspace)) if os.path.isdir(workspace) else []
    best: Dict[str, str] = {}
    for g in starter_groups():
        prefix = inst.folder_prefix + g + "_"
        for d in entries:
            if not d.startswith(prefix) or not os.path.isdir(os.path.join(workspace, d)):
                continue
            key = d.split("@", 1)[0]
            if key not in best or ("@" in d and "@" not in best[key]):
                best[key] = d
    found = {f"{g}/{k[len(inst.folder_prefix + g) + 1:]}" if k.startswith(inst.folder_prefix + g + "_") else k: os.path.join(workspace, d)
             for k, d in best.items() for g in starter_groups() if k.startswith(inst.folder_prefix + g + "_")}
    for proj in starter_projects():
        base = os.path.join(workspace, inst.clone_folder(proj))
        if os.path.isdir(base):
            found[proj] = base
            continue
        cands = sorted(d for d in entries if d.startswith(os.path.basename(base) + "@"))
        if cands:
            found[proj] = os.path.join(workspace, cands[0])
    return found
