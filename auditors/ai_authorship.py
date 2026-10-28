"""
Defect density of code with an AI-assistant trace vs the rest (ADR-0012 D6). READ-ONLY on the repository.

The internal methodology says CMMI asks to MEASURE, not declare, that AI reduces errors. This is the measurement Centinela can make from
facts it already has: `git blame` tells which commit wrote each surviving line, and a commit whose message carries a `Co-Authored-By:` trailer of
an AI assistant is "AI-assisted". Findings anchored to `file:line` are attributed the same way.

What this does NOT show, and every report must say: (1) only commits that carry the trailer are counted -- a team that does not use trailers
looks 100% human; (2) a shallow clone has no history, its lines blame to the clone's boundary commit and are reported as NOT EVALUABLE, never as
human; (3) density per 1,000 surviving lines compares populations that differ in age, size and file type: it is a correlation, not a causal claim;
(4) lines inside lockfiles/vendored/generated paths are excluded.
"""
import os
import re
import subprocess
from collections import defaultdict
from typing import Dict, Iterable, List, Optional, Tuple

_DEFAULT_AI_PATTERNS = r"claude|anthropic|copilot|gemini|chatgpt|openai|codex|cursor|devin|aider|codeium"
CODE_EXT = {".java", ".py", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".html", ".scss", ".css", ".xml", ".yml", ".yaml", ".properties", ".sql", ".go",
            ".cs", ".php", ".rb", ".kt", ".scala", ".rs", ".tf", ".sh", ".gradle", ".json"}
SKIP_DIRS = {".git", "node_modules", "target", "build", "dist", ".gradle", "vendor", "__pycache__", ".angular", "coverage"}
SKIP_FILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock"}
MAX_FILES = 3000


def ai_trailer_regex() -> "re.Pattern":
    pats = os.getenv("AI_AUTHOR_PATTERNS", _DEFAULT_AI_PATTERNS)
    return re.compile(r"^\s*co-authored-by:\s*[^\n]*(?:" + pats + r")", re.IGNORECASE | re.MULTILINE)


def _git(repo: str, *args: str, timeout: int = 120) -> str:
    r = subprocess.run(["git", "-C", repo, *args], capture_output=True, text=True, timeout=timeout)
    if r.returncode != 0:
        raise RuntimeError(f"git {' '.join(args[:2])} failed: {r.stderr.strip()[:200]}")
    return r.stdout


def is_shallow(repo: str) -> bool:
    try:
        return _git(repo, "rev-parse", "--is-shallow-repository").strip() == "true"
    except RuntimeError:
        return True        # cannot tell -> treat as not evaluable


UNCOMMITTED = "0" * 40


def commit_is_ai(repo: str, sha: str, cache: Dict[str, bool]) -> bool:
    if sha not in cache:
        msg = _git(repo, "show", "-s", "--format=%B", sha)
        cache[sha] = bool(ai_trailer_regex().search(msg))
    return cache[sha]


_BLAME_HDR = re.compile(r"^([0-9a-f]{40}) (\d+) (\d+)(?: (\d+))?$")


def blame_file(repo: str, rel: str) -> List[Tuple[int, int, str, bool]]:
    """[(start_line, n_lines, sha, boundary)] for the file as it is checked out."""
    out = _git(repo, "blame", "--porcelain", "--", rel, timeout=180)
    groups, boundary = [], set()
    cur = None
    for line in out.split("\n"):
        m = _BLAME_HDR.match(line)
        if m and m.group(4):                       # a header that opens a group carries the group size
            cur = [int(m.group(3)), int(m.group(4)), m.group(1)]
            groups.append(cur)
        elif line.startswith("boundary") and cur:
            boundary.add(cur[2])
    return [(s, n, sha, sha in boundary) for s, n, sha in groups]


def _source_files(repo: str) -> List[str]:
    files = _git(repo, "ls-files").split("\n")
    out = []
    for f in files:
        if not f or os.path.basename(f) in SKIP_FILES or set(f.split("/")[:-1]) & SKIP_DIRS:
            continue
        if os.path.splitext(f)[1].lower() in CODE_EXT:
            out.append(f)
    return out[:MAX_FILES]


def measure(repo: str, findings: Iterable[dict]) -> dict:
    """findings: dicts with `url_path` ('rel/file:line'). Returns the density report (see module docstring for its limits)."""
    caveats = ["Solo cuentan los commits con trailer Co-Authored-By de un asistente de IA; un equipo que no los usa aparece como 100 % humano.",
               "Correlación, no causalidad: las poblaciones difieren en antigüedad, tamaño y tipo de archivo."]
    if is_shallow(repo):
        return {"evaluable": False, "reason": "clon superficial (sin historial): las líneas se atribuyen al commit de corte; no se cuentan como humanas",
                "caveats": caveats}
    cache: Dict[str, bool] = {}
    from auditors.starter_lineage import split_location
    blames: Dict[str, List[Tuple[int, int, str, bool]]] = {}
    ai_lines = other_lines = 0
    for rel in _source_files(repo):
        try:
            g = blame_file(repo, rel)
        except (RuntimeError, subprocess.TimeoutExpired):
            continue
        blames[rel] = g
        for _, n, sha, _b in g:
            if sha == UNCOMMITTED:                      # lines not committed yet have no author to attribute
                continue
            if commit_is_ai(repo, sha, cache):
                ai_lines += n
            else:
                other_lines += n
    f_ai = f_other = f_unattr = f_noloc = 0
    for f in findings:
        loc = (f.get("url_path") or "")
        rel = split_location(loc)
        line = int(loc.rpartition(":")[2]) if loc.rpartition(":")[2].isdigit() else None
        sha = None
        if rel is None or line is None:
            f_noloc += 1                                 # e.g. container-image / dependency findings: no file:line to blame
            continue
        if rel in blames and line:
            for s, n, h, _b in blames[rel]:
                if s <= line < s + n:
                    sha = h
                    break
        if sha is None or sha == UNCOMMITTED:
            f_unattr += 1
        elif commit_is_ai(repo, sha, cache):
            f_ai += 1
        else:
            f_other += 1
    total = ai_lines + other_lines

    def dens(n, lines):
        return round(1000.0 * n / lines, 2) if lines else None
    return {
        "evaluable": True, "surviving_lines": total, "ai_lines": ai_lines, "other_lines": other_lines,
        "ai_commits": sum(1 for v in cache.values() if v), "commits_seen": len(cache),
        "findings_ai": f_ai, "findings_other": f_other, "findings_unattributed": f_unattr, "findings_without_file_line": f_noloc,
        "density_per_kloc_ai": dens(f_ai, ai_lines), "density_per_kloc_other": dens(f_other, other_lines),
        "small_sample": (f_ai + f_other) < 30 or ai_lines < 1000,
        "caveats": caveats,
    }
