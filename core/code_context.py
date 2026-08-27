"""
Item 5 (2026-08-27): blast-radius / enclosing-scope context for GitLab-Repo remediation prompts.

correlate_vulnerability() used to hand the LLM only the single flagged line plus the scanner's
short description, then ask for a `git apply`-ready unified diff. CodeRabbit's headline
advantage over that is context -- the enclosing function, and the call sites a change would
ripple to. gather_repo_context() reproduces the cheap ~80% of that with no new dependency:
it reads the enclosing block straight from the clone the fleet scanner already left on disk
(/tmp/centinela_gitlab_scans/<namespace>) and runs `git grep` for the flagged symbol to list
other references.

Strictly best-effort and read-only. Any failure (repo not on disk, unparseable url_path, git
missing) returns an empty-but-well-formed dict -- it never raises, so correlate_vulnerability()
can call it unconditionally and just check whether `enclosing_snippet` came back non-empty.
"""
import os
import re
import subprocess
from typing import Any, Dict, List, Optional

DEFAULT_SCAN_WORKSPACE = "/tmp/centinela_gitlab_scans"

_MAX_SNIPPET_LINES = 60
_MAX_CALLERS = 15
# Too many `git grep -w` hits => the symbol isn't distinctive enough for a caller list to mean
# anything (e.g. a common method name). Above this we still show the enclosing snippet but omit
# the BLAST RADIUS list rather than print misleading noise.
_MAX_GREP_HITS_FOR_BLAST = 40

# A line that opens a callable/scope: Python def/class, JS function/arrow/const, or a C-family
# (Java/C#/TS/Go/...) method header `[modifiers] [type] NAME(`. `name` is best-effort; the
# authoritative symbol is re-derived in _symbol_from_scope_line() as "identifier just before (".
_SCOPE_START_RE = re.compile(
    r'^(?P<indent>[ \t]*)'
    r'(?:@|\s)*'
    r'(?:async\s+)?(?:def|class|function|func|fn|sub)\b'
    r'|^(?P<indent2>[ \t]*)(?:export\s+|default\s+)*(?:public|private|protected|internal|'
    r'static|final|abstract|override|async|const|let|var)\s+.*'
)
_CALL_HEADER_RE = re.compile(r'([A-Za-z_$][\w$]*)\s*\(')
_DEF_NAME_RE = re.compile(
    r'\b(?:def|class|function|func|fn|sub)\s+([A-Za-z_$][\w$]*)'
)
_CONST_ARROW_RE = re.compile(
    r'\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\(?[^)]*\)?\s*=>'
)
_IDENT_RE = re.compile(r'[A-Za-z_$][\w$]*')

# Identifiers too generic for `git grep` to say anything useful about: control-flow keywords,
# access modifiers, and -- importantly for Java/C#/TS -- primitive type names and universal
# method names that would otherwise be mistaken for the enclosing symbol.
_STOPWORDS = {
    "if", "for", "while", "return", "self", "this", "def", "class", "function", "func",
    "const", "let", "var", "true", "false", "null", "none", "import", "from", "new",
    "await", "async", "public", "private", "protected", "static", "final", "abstract",
    "export", "default", "value", "data", "result", "err", "error", "req", "res", "ctx",
    "i", "j", "k", "x", "y", "e", "o",
    # primitive / built-in type names
    "boolean", "bool", "void", "int", "integer", "long", "short", "byte", "char",
    "float", "double", "string", "str", "object", "list", "dict", "map", "set", "array",
    "number", "any", "unknown", "var", "val",
    # universal method names
    "equals", "hashcode", "tostring", "get", "set", "post", "put", "delete", "patch",
    "main", "run", "init", "constructor", "value_of", "valueof", "clone", "compareto",
}


def _resolve_repo_dir(asset_name: str, repo_root: Optional[str], workspace: str) -> Optional[str]:
    if repo_root:
        return repo_root if os.path.isdir(repo_root) else None
    if not asset_name:
        return None
    # The self-audit asset's "repo" is Centinela's own live source tree, bind-mounted at /app
    # inside every Python service and a real git work tree there -- not a clone under `workspace`.
    if asset_name.startswith("Centinela-AI (Self-Audit)"):
        return "/app" if os.path.isdir("/app/.git") else None
    if asset_name.startswith("Self-Audit: "):
        d = asset_name[len("Self-Audit: "):].strip()
        return d if os.path.isdir(d) else None
    path_ns = asset_name.split("GitLab/", 1)[-1] if asset_name.startswith("GitLab/") else asset_name
    safe_folder = path_ns.replace("/", "_")
    candidate = os.path.join(workspace, safe_folder)
    return candidate if os.path.isdir(candidate) else None


def _parse_url_path(url_path: str) -> Optional[tuple]:
    """'relative/path/to/file.py:123' -> ('relative/path/to/file.py', 123). None if not that shape.
    Rejects absolute paths and `..` traversal -- a SAST finding's location is always
    repo-relative, and os.path.join() silently discards the repo root when handed an absolute
    second arg, which would let it read a file from anywhere on disk."""
    if not url_path or ":" not in url_path:
        return None
    rel, _, line_str = url_path.rpartition(":")
    rel = rel.strip()
    if not rel or not line_str.isdigit():
        return None
    if os.path.isabs(rel) or ".." in rel.split("/"):
        return None
    return rel, int(line_str)


def _indent_width(line: str) -> int:
    return len(line) - len(line.lstrip(" \t"))


def _symbol_from_scope_line(raw: str) -> Optional[str]:
    """Best-effort callable name from a scope-opening line, across languages.
    Priority: `def/class/function NAME`  >  `const NAME = () =>`  >  identifier right before `(`.
    """
    m = _DEF_NAME_RE.search(raw)
    if m and m.group(1).lower() not in _STOPWORDS:
        return m.group(1)
    m = _CONST_ARROW_RE.search(raw)
    if m and m.group(1).lower() not in _STOPWORDS:
        return m.group(1)
    # C-family method header: last `identifier(` on the line whose identifier isn't a keyword.
    best = None
    for m in _CALL_HEADER_RE.finditer(raw):
        cand = m.group(1)
        if cand.lower() not in _STOPWORDS:
            best = cand
    return best


def _extract_enclosing(lines: List[str], line_no: int) -> "tuple[str, Optional[str]]":
    """Return (snippet_with_line_numbers, enclosing_symbol_name_or_None) around 1-indexed line_no."""
    idx = line_no - 1
    if idx < 0 or idx >= len(lines):
        return "", None

    flagged_indent = _indent_width(lines[idx]) if lines[idx].strip() else 999
    start = idx
    symbol = None
    for i in range(idx, -1, -1):
        raw = lines[i]
        if not raw.strip():
            continue
        if _SCOPE_START_RE.match(raw) and _indent_width(raw) < flagged_indent:
            start = i
            symbol = _symbol_from_scope_line(raw)
            break
        if i == 0:
            start = 0

    start_indent = _indent_width(lines[start])
    end = idx
    for i in range(idx + 1, min(len(lines), start + _MAX_SNIPPET_LINES)):
        raw = lines[i]
        # Standard "dedent ends the block": stop at the first non-blank line indented at or
        # left of the enclosing scope's own header (a sibling def/class, or code after the
        # function). Blank lines and more-indented body lines stay in the snippet.
        if raw.strip() and _indent_width(raw) <= start_indent:
            break
        end = i
    end = min(end, start + _MAX_SNIPPET_LINES - 1)

    out = []
    for i in range(start, end + 1):
        marker = ">>" if i == idx else "  "
        out.append(f"{marker} {i + 1:>5} | {lines[i].rstrip()}")
    return "\n".join(out), symbol


def _pick_symbol(flagged_line: str, enclosing_symbol: Optional[str]) -> Optional[str]:
    if enclosing_symbol and enclosing_symbol.lower() not in _STOPWORDS:
        return enclosing_symbol
    # Fall back to the most distinctive identifier on the flagged line itself: prefer one that
    # is immediately followed by `(` (a call), else the longest non-keyword token.
    calls = [m.group(1) for m in _CALL_HEADER_RE.finditer(flagged_line or "")
             if m.group(1).lower() not in _STOPWORDS and len(m.group(1)) >= 4]
    if calls:
        return max(calls, key=len)
    cands = [t for t in _IDENT_RE.findall(flagged_line or "")
             if t.lower() not in _STOPWORDS and len(t) >= 4]
    return max(cands, key=len) if cands else None


def _git_grep_callers(repo_dir: str, symbol: str, skip_rel: str, skip_line: int) -> "tuple[List[str], int]":
    """Returns (caller_lines, total_hit_count). total_hit_count is the raw number of
    `git grep -w` matches (minus the definition line) BEFORE the _MAX_CALLERS cap -- the caller
    uses it to decide whether the symbol is distinctive enough to be worth showing at all."""
    try:
        proc = subprocess.run(
            ["git", "-C", repo_dir, "grep", "-n", "-w", "--", symbol],
            capture_output=True, text=True, timeout=20,
        )
    except Exception:
        return [], 0
    if proc.returncode not in (0, 1):  # 1 == no matches, still fine
        return [], 0

    callers: List[str] = []
    total = 0
    for raw in proc.stdout.splitlines():
        parts = raw.split(":", 2)
        if len(parts) < 3:
            continue
        f_path, l_str, code = parts[0], parts[1], parts[2]
        if not l_str.isdigit():
            continue
        if f_path == skip_rel and int(l_str) == skip_line:
            continue
        total += 1
        if len(callers) < _MAX_CALLERS:
            callers.append(f"{f_path}:{l_str}  {code.strip()[:160]}")
    return callers, total


def gather_repo_context(asset_name: str, url_path: str,
                        repo_root: Optional[str] = None,
                        workspace: str = DEFAULT_SCAN_WORKSPACE) -> Dict[str, Any]:
    """
    Best-effort code context for a GitLab-Repo SAST/SCA finding.

    Returns a dict with keys: repo_dir, rel_path, line, symbol, enclosing_snippet,
    callers (list[str]), caller_count, prompt_block (ready-to-embed text or '').
    On any failure every field is empty/zero and prompt_block == ''.
    """
    empty = {
        "repo_dir": None, "rel_path": None, "line": None, "symbol": None,
        "enclosing_snippet": "", "callers": [], "caller_count": 0, "prompt_block": "",
    }

    repo_dir = _resolve_repo_dir(asset_name, repo_root, workspace)
    if not repo_dir:
        return empty

    parsed = _parse_url_path(url_path or "")
    if not parsed:
        return empty
    rel_path, line_no = parsed

    file_path = os.path.join(repo_dir, rel_path)
    if not os.path.isfile(file_path):
        return empty

    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.read().splitlines()
    except Exception:
        return empty
    if not lines or line_no > len(lines):
        return empty

    snippet, enclosing_symbol = _extract_enclosing(lines, line_no)
    symbol = _pick_symbol(lines[line_no - 1] if line_no - 1 < len(lines) else "", enclosing_symbol)

    callers: List[str] = []
    total_hits = 0
    symbol_is_distinctive = False
    if symbol:
        callers, total_hits = _git_grep_callers(repo_dir, symbol, rel_path, line_no)
        # Only surface a BLAST RADIUS list when the symbol is distinctive enough for it to
        # actually mean something. A common name (`equals`, a primitive type slipping past the
        # stopword list) grepping to hundreds of lines would be misleading noise, not context.
        symbol_is_distinctive = 1 <= total_hits <= _MAX_GREP_HITS_FOR_BLAST

    result = {
        "repo_dir": repo_dir,
        "rel_path": rel_path,
        "line": line_no,
        "symbol": symbol,
        "enclosing_snippet": snippet,
        "callers": callers if symbol_is_distinctive else [],
        "caller_count": total_hits if symbol_is_distinctive else 0,
        "prompt_block": "",
    }

    if snippet:
        block = [
            f"CONTEXTO DE CÓDIGO (bloque que contiene la línea {line_no} de {rel_path}; "
            f"`>>` marca la línea señalada):",
            "```",
            snippet,
            "```",
        ]
        if symbol_is_distinctive and callers:
            block.append("")
            shown = min(len(callers), _MAX_CALLERS)
            more = f" (mostrando {shown} de {total_hits})" if total_hits > shown else ""
            block.append(
                f"BLAST RADIUS -- {total_hits} referencia(s) a `{symbol}` en el repositorio"
                f"{more}; verifica si el parche las afecta:"
            )
            block.extend(f"  - {c}" for c in callers[:_MAX_CALLERS])
        elif symbol and total_hits == 0:
            block.append("")
            block.append(f"BLAST RADIUS -- sin otras referencias a `{symbol}` en el repositorio "
                         f"(cambio localizado).")
        result["prompt_block"] = "\n".join(block)

    return result
