"""
Centinela-AI — discovery of the application profiles (roles) from a repository clone, for the "credenciales de prueba" dropdown.

Read-only static discovery; it never connects to the application's database. Sources, from most to least reliable:
  sql       `INSERT INTO <...rol|perfil...> (cols) VALUES (...)`: the role-name column of every tuple (migration seeds = what the database holds)
  java-auth Spring Security: hasRole / hasAuthority / hasAnyRole / hasAnyAuthority / @Secured / @RolesAllowed / @PreAuthorize arguments
  constant  Java/TS constants such as `ID_ROL_OFICIAL_DE_PARTES = 5` (name taken from the constant)
  frontend  Angular/TS route data `roles: ['A', 'B']` and hasRole('X') calls
Names are returned as found; nothing is invented. A repository with none of these returns an empty list (the user can still type a profile).
"""
import os
import re
from typing import Dict, List, Tuple

SKIP_DIRS = {".git", "node_modules", "target", "build", "dist", "__pycache__", ".gradle", ".idea", "venv", ".venv"}
MAX_FILES = 20000
MAX_BYTES = 2_000_000
_NAME_COLS = ("dsrol", "dsperfil", "nombre", "name", "rol", "perfil", "descripcion", "description", "role", "authority")
_TABLE_RE = re.compile(r"INSERT\s+INTO\s+(?:\"?\w+\"?\.)?\"?(\w*(?:rol|perfil|role)\w*)\"?\s*(?:\(([^)]*)\))?\s*VALUES", re.IGNORECASE)
_JAVA_CALL_RE = re.compile(r"\b(hasRole|hasAnyRole|hasAuthority|hasAnyAuthority)\s*\(([^)]*)\)|@(Secured|RolesAllowed)\s*\(([^)]*)\)")
_CONST_RE = re.compile(r"\bID_ROL_([A-Z0-9_]{3,})\s*=")
_TS_ROLES_RE = re.compile(r"\broles?\s*:\s*\[([^\]]*)\]")
_TS_HASROLE_RE = re.compile(r"\bhas(?:Any)?Role\s*\(([^)]*)\)")
_QUOTED = re.compile(r"""['"]([^'"\n]{2,60})['"]""")


def _quoted(text: str) -> List[str]:
    return [m.group(1).strip() for m in _QUOTED.finditer(text or "")]


def _split_tuples(values_text: str) -> List[List[str]]:
    """Top-level (...) tuples of a VALUES list, each split on top-level commas (quote-aware)."""
    tuples, depth, cur, in_q, i = [], 0, [], False, 0
    fields: List[str] = []
    buf: List[str] = []
    while i < len(values_text):
        ch = values_text[i]
        if in_q:
            buf.append(ch)
            if ch == "'":
                if i + 1 < len(values_text) and values_text[i + 1] == "'":
                    buf.append("'"); i += 1
                else:
                    in_q = False
        elif ch == "'":
            in_q = True; buf.append(ch)
        elif ch == "(":
            depth += 1
            if depth == 1:
                fields, buf = [], []
            else:
                buf.append(ch)
        elif ch == ")":
            depth -= 1
            if depth == 0:
                fields.append("".join(buf).strip()); tuples.append(fields); fields, buf = [], []
            else:
                buf.append(ch)
        elif ch == "," and depth == 1:
            fields.append("".join(buf).strip()); buf = []
        elif ch == ";" and depth == 0:
            break
        elif depth >= 1:
            buf.append(ch)
        i += 1
    return tuples


def _sql_roles(text: str, rel: str) -> List[Dict[str, str]]:
    out = []
    for m in _TABLE_RE.finditer(text):
        cols = [c.strip().strip('"').lower() for c in (m.group(2) or "").split(",")] if m.group(2) else []
        idx = next((cols.index(c) for c in _NAME_COLS if c in cols), None)
        tuples = _split_tuples(text[m.end():m.end() + 20000])
        for t in tuples:
            if idx is not None and idx < len(t):
                cand = t[idx]
            else:   # no column list: first quoted string of the tuple
                cand = next((f for f in t if f.startswith("'")), "")
            if cand.startswith("'") and cand.endswith("'") and len(cand) > 2:
                out.append({"role": cand[1:-1].replace("''", "'").strip(), "source": "sql", "file": rel})
    return out


def discover_roles(root: str) -> List[Dict[str, str]]:
    """[{role, source, file}] found under `root`, de-duplicated by (role, source)."""
    found: Dict[Tuple[str, str], Dict[str, str]] = {}
    seen_files = 0

    def add(role: str, source: str, rel: str):
        role = (role or "").strip()
        if 2 <= len(role) <= 60 and re.search(r"[A-Za-zÁÉÍÓÚáéíóúÑñ]", role):
            found.setdefault((role.lower(), source), {"role": role, "source": source, "file": rel})

    for dirpath, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in files:
            ext = os.path.splitext(name)[1].lower()
            if ext not in (".sql", ".java", ".ts", ".tsx", ".js", ".kt"):
                continue
            seen_files += 1
            if seen_files > MAX_FILES:
                return sorted(found.values(), key=lambda r: (r["source"], r["role"].lower()))
            path = os.path.join(dirpath, name)
            try:
                if os.path.getsize(path) > MAX_BYTES:
                    continue
                text = open(path, encoding="utf-8", errors="replace").read()
            except OSError:
                continue
            rel = os.path.relpath(path, root)
            if ext == ".sql":
                for r in _sql_roles(text, rel):
                    add(r["role"], "sql", rel)
            if ext in (".java", ".kt"):
                for m in _JAVA_CALL_RE.finditer(text):
                    for q in _quoted(m.group(2) or m.group(4)):
                        add(q, "java-auth", rel)
            if ext in (".java", ".kt", ".ts"):
                for m in _CONST_RE.finditer(text):
                    add(m.group(1).replace("_", " ").title(), "constant", rel)
            if ext in (".ts", ".tsx", ".js"):
                for m in _TS_ROLES_RE.finditer(text):
                    for q in _quoted(m.group(1)):
                        add(q, "frontend", rel)
                for m in _TS_HASROLE_RE.finditer(text):
                    for q in _quoted(m.group(1)):
                        add(q, "frontend", rel)
    return sorted(found.values(), key=lambda r: (r["source"], r["role"].lower()))


def persist_roles(cur, asset_id: str, roles: List[Dict[str, str]]) -> int:
    """Replace the discovered roles of one asset (names only). Returns how many were stored."""
    cur.execute("DELETE FROM public.asset_auth_roles WHERE asset_id = %s", (asset_id,))
    for r in roles:
        cur.execute("""INSERT INTO public.asset_auth_roles (asset_id, role_name, source, source_file) VALUES (%s, %s, %s, %s)
                       ON CONFLICT (asset_id, role_name, source) DO NOTHING""", (asset_id, r["role"], r["source"], r.get("file")))
    return len(roles)
