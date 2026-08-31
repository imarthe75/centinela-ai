"""
Centinela-AI — Static Authorization / Broken Access Control Auditor  (scan_engine: authz-static)

Detects the code-level root causes of OWASP A01:2021 (Broken Access Control) and
API1/API5:2023 (BOLA / Broken Function Level Authorization) — the class of bug where a
low-privilege user reaches an admin-only function because authorization is either missing,
inconsistent, or enforced only in the browser.

Motivated by a real retest finding on SIDECO (Aug 2026): the account TcsCSA2 (non-admin)
received HTTP 200 on `GET /v1/usr/getUsuarios/{id}` and could edit users / assign elevated
roles. Root causes, all visible in the source:
  A. ResourceServerConfig hardens `/v1/catalogos/roles*` with `@roleSecurity.isAdmin` but has
     NO rule for the sibling `/v1/usr/**` — it falls through to `.antMatchers("/v1/**").authenticated()`.
  B. The Angular admin module is gated only by a `canActivate:[AutorizacionGuard]` route guard;
     the backend it calls never checks a role -> rewriting a 403->200 in a proxy defeats it.
  C. 0 of 36 controllers carry any method-level `@PreAuthorize`/`@Secured`.

This module is pure static analysis (no network). The runtime confirmation lives in
auditor_authz_dast.py (multi-role replay + IDOR probe), which needs credentials.

Checks emitted:
  AUTHZ-NO-RULE                 HIGH   endpoint has no matching security rule AND no method annotation
  AUTHZ-ONLY-AUTHENTICATED-WRITE MEDIUM state-changing endpoint gated only by `.authenticated()` (no role)
  AUTHZ-PERMITALL-WRITE         HIGH   POST/PUT/DELETE/PATCH endpoint matched by a `permitAll()` rule
  AUTHZ-INCONSISTENT-FAMILY     HIGH   a sensitive endpoint (user/role/permiso/admin) is weaker than a
                                       hardened sibling in the same resource family  <-- the SIDECO case
  AUTHZ-NAMESPACE-GAP           MEDIUM controllers/clients use a path prefix (e.g. /api/) that no
                                       security rule covers, while another prefix (/v1/) is matched
  AUTHZ-CSRF-DISABLED           MEDIUM `.csrf().disable()` with cookie/session auth in play
  AUTHZ-NO-METHOD-ANNOTATIONS   LOW    a controller package relies 100% on URL matchers, 0 @PreAuthorize
  AUTHZ-CLIENT-SIDE-ONLY        HIGH   an admin route is protected only by a front-end guard and the
                                       backend has no role enforcement for that resource
  AUTHZ-CLIENT-SIDE-UI-GATE     MEDIUM admin UI shown/hidden by a client-side role check (*ngIf isAdmin)
  AUTHZ-ADMIN-BUNDLE-EXPOSED    LOW    admin components compiled into the SPA bundle, hidden only client-side
"""
from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Optional, Tuple

try:
    from core import db_manager, deduplication_engine
except Exception:  # pragma: no cover
    db_manager = None
    deduplication_engine = None

_SCAN_ENGINE = "authz-static"

_EXCLUDE = (".git", "node_modules", "__pycache__", ".venv", "/test/", "\\test\\", "/tests",
            "\\tests", "data/remediation", "data/sonar_scans", "everything-claude-code",
            ".mvn", "/target/", "\\target\\", "/dist/", "\\dist\\")

# words that mark an endpoint / route / component as security-sensitive (admin surface).
# Kept deliberately narrow to the identity/authorization surface -- generic words like "menu"
# or "config" alone caused false positives on citizen-facing screens.
_SENSITIVE = re.compile(
    r"(usuario|usuarios|/usr/|\busr\b|guardarusuario|\buser\b|\brol\b|\broles\b|catrol|"
    r"asignarrol|cambiarrol|rolmenu|rolruta|permiso|permisos|\bperm\b|privileg|grant|"
    r"administrac|resetpassword|reset-password|accesosistema)",
    re.IGNORECASE,
)
# IDENTITY ADMINISTRATION surface: an endpoint that *manages* users / roles / permissions
# (not one that merely takes a {usuario} id to serve that user's own calendar/appointments).
# An endpoint here without an admin gate, in an app that HAS an admin concept, is a
# privilege-escalation risk. Two shapes:
#   1. a mutation verb on identity:      guardar/save/crear/upd/update/edit/delete/asignar/cambiar/reset + usuario/rol/permiso/menu/acceso
#   2. a catalog getter over the whole set: getUsuarios / obtenerAllRoles / catRoles / rolesWithMenus / obtenerPermisos*  (no per-subject param)
_IDENTITY_MUTATION = re.compile(
    r"(guardar|save|crear|create|nuevo|registrar|upd(?:ate)?|edit|modific|delete|del[A-Z]|elimina|"
    r"asignar|cambiar|revocar|reset|blindaje|grant|accesosistema)"
    r"[A-Za-z]*"
    r"(usuario|user|\brol|permiso|menu|acceso|password|pass\b)",
    re.IGNORECASE,
)
_IDENTITY_CATALOG_GET = re.compile(
    r"(getusuarios|listusuarios|obtenerusuarios|allusuarios|"
    r"getroles|obtenerallroles|catroles|roleswith(out)?menus|obtenerrolesperm|obtenerallroles|"
    r"obtenerpermisos|getpermisos|catmenu|obtenermenu)"
    r"($|/|\b)",
    re.IGNORECASE,
)
# a path param that names a *subject* whose own data is being served (IDOR surface, not priv-esc)
_SUBJECT_PARAM = re.compile(r"\{(id)?usuario\}|\{iduser\}|\{idusuario\}", re.IGNORECASE)
# loose identity word, used only for the "state-change + no subject param" fallback
_IDENTITY_ADMIN_LOOSE = re.compile(r"(usuario|/usr/|\brol|permiso|\bmenu\b|acceso)", re.IGNORECASE)
_STATE_CHANGE = {"POST", "PUT", "DELETE", "PATCH"}

_MAPPING_VERB = {
    "GetMapping": "GET", "PostMapping": "POST", "PutMapping": "PUT",
    "DeleteMapping": "DELETE", "PatchMapping": "PATCH",
}
_ANNOTATION_AUTHZ = re.compile(r"@(PreAuthorize|PostAuthorize|Secured|RolesAllowed)\b")


# --------------------------------------------------------------------------- helpers
def _walk(target_dir: str):
    for root, _, files in os.walk(target_dir):
        if any(x in root for x in _EXCLUDE):
            continue
        for f in files:
            yield os.path.join(root, f)


def _read(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            return fh.read()
    except Exception:
        return ""


def _ant_to_regex(pattern: str) -> re.Pattern:
    """Spring AntPathMatcher -> regex. `**` = any incl. `/`, `*` = one segment, `{x}` = one segment."""
    p = re.escape(pattern)
    p = p.replace(r"\*\*", "§DS§").replace(r"\*", "§S§").replace(r"\{", "§L§").replace(r"\}", "§R§")
    p = p.replace("§DS§", ".*").replace("§S§", "[^/]*")
    p = re.sub(r"§L§[^§]*§R§", "[^/]+", p)
    return re.compile("^" + p + "$")


# --------------------------------------------------------------------------- Spring security config
def _strip_comments(src: str) -> str:
    """Remove // line and /* */ block comments without touching string literals."""
    out = []
    i, n = 0, len(src)
    while i < n:
        ch = src[i]
        if ch in ('"', "'"):
            q = ch
            out.append(ch)
            i += 1
            while i < n:
                out.append(src[i])
                if src[i] == "\\" and i + 1 < n:
                    out.append(src[i + 1])
                    i += 2
                    continue
                if src[i] == q:
                    i += 1
                    break
                i += 1
            continue
        if ch == "/" and i + 1 < n and src[i + 1] == "/":
            while i < n and src[i] != "\n":
                i += 1
            continue
        if ch == "/" and i + 1 < n and src[i + 1] == "*":
            i += 2
            while i + 1 < n and not (src[i] == "*" and src[i + 1] == "/"):
                i += 1
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _balanced(src: str, open_idx: int) -> "tuple[str, int]":
    """src[open_idx] must be '('. Return (inner_text, index_after_matching_close)."""
    depth = 0
    i = open_idx
    n = len(src)
    while i < n:
        c = src[i]
        if c in ('"', "'"):
            q = c
            i += 1
            while i < n:
                if src[i] == "\\":
                    i += 2
                    continue
                if src[i] == q:
                    break
                i += 1
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return src[open_idx + 1:i], i + 1
        i += 1
    return src[open_idx + 1:], n


def _decision_from_tail(tail: str) -> str:
    low = tail.lower().replace(" ", "")
    if "@rolesecurity.isadmin" in low or "isadmin(" in low or 'hasrole("admin' in low or "hasrole('admin" in low \
            or 'hasauthority("admin' in low or "hasauthority('admin" in low or 'hasrole("role_admin' in low:
        return "admin"
    if "hasrole" in low or "hasauthority" in low or "hasanyrole" in low or "hasanyauthority" in low:
        return "role"
    if "permitall" in low:
        return "permitAll"
    if "denyall" in low:
        return "denyAll"
    if "anonymous" in low:
        return "anonymous"
    if "authenticated" in low:            # covers authenticated()/isAuthenticated()/fullyAuthenticated()
        return "authenticated"
    if "access(" in low or "hasipaddress" in low:
        return "custom"
    return "authenticated"


_MATCHER_CALL = re.compile(r"\.(antMatchers|requestMatchers|mvcMatchers|securityMatcher|regexMatchers)\s*\(")


def _parse_security_configs(files_java: List[Tuple[str, str]]) -> Tuple[List[dict], List[str], List[str]]:
    """
    Returns (rules, config_files, csrf_disabled_files).
    Each rule: {"file","methods":set|None,"pattern":str,"regex":Pattern,"decision":str,"raw":str}
      decision in {"admin","role","authenticated","permitAll","denyAll","custom","anonymous"}

    Char-scanned (not one big regex): for each `.antMatchers(...)` we take the balanced-paren
    argument list, then walk forward over whitespace/comments collecting the chained
    `.foo(...).bar(...)` terminal calls until the next matcher / `.and(` / `;` -- so a
    `.access("@x.isAdmin(auth)")` with its own nested parens, or a blank line + `//` comment
    between two `.antMatchers`, no longer truncates the rule list. (A real bug: SIDECO's
    develop ResourceServerConfig has 8 rules; the old regex parsed only 1, so 53 genuinely
    `.authenticated()` endpoints were mis-reported as AUTHZ-NO-RULE.)
    """
    rules: List[dict] = []
    config_files: List[str] = []
    csrf_off: List[str] = []

    for path, raw_content in files_java:
        if not re.search(r"(HttpSecurity|authorizeRequests|authorizeHttpRequests|antMatchers|requestMatchers|securityMatcher)", raw_content):
            continue
        config_files.append(path)
        content = _strip_comments(raw_content)
        if re.search(r"\.csrf\s*\(\s*\)\s*\.disable\s*\(\s*\)|csrf\s*\(\s*\w*\s*->\s*\w*\.disable\s*\(\s*\)\s*\)|csrf\s*\(\s*AbstractHttpConfigurer::disable\s*\)",
                     content):
            csrf_off.append(path)

        for mc in _MATCHER_CALL.finditer(content):
            kind = mc.group(1)
            args, after = _balanced(content, mc.end() - 1)
            if kind in ("securityMatcher", "requestMatchers") and args.strip() == "":
                continue  # OAuth2 filter-chain selector, not an authorization rule

            methods = None
            hm = re.match(r"\s*HttpMethod\.([A-Z]+)\s*,", args)
            if hm:
                methods = {hm.group(1)}
                args = args[hm.end():]
            patterns = re.findall(r'"([^"]+)"', args)
            if not patterns:
                continue

            # collect the chained terminal calls: .a(...).b(...) ... until next matcher/.and(/;
            j = after
            n = len(content)
            tail_parts = []
            while j < n:
                while j < n and content[j] in " \t\r\n":
                    j += 1
                if j >= n or content[j] != ".":
                    break
                nm = re.match(r"\.([A-Za-z0-9_]+)\s*\(", content[j:])
                if not nm:
                    break
                name = nm.group(1)
                if name in ("antMatchers", "requestMatchers", "mvcMatchers", "regexMatchers", "and", "securityMatcher"):
                    break
                inner, j2 = _balanced(content, j + nm.end() - 1)
                tail_parts.append(f".{name}({inner})")
                j = j2
            tail = "".join(tail_parts)
            decision = _decision_from_tail(tail)

            for pat in patterns:
                rules.append({
                    "file": path, "methods": methods, "pattern": pat,
                    "regex": _ant_to_regex(pat), "decision": decision, "raw": tail.strip()[:120],
                })

        # `anyRequest().authenticated()` / `.denyAll()` / `.permitAll()` -> a catch-all
        am = re.search(r"\.anyRequest\s*\(\s*\)\s*\.([A-Za-z]+)\s*\(", content)
        if am:
            d = am.group(1).lower()
            dec = {"authenticated": "authenticated", "denyall": "denyAll",
                   "permitall": "permitAll"}.get(d, "authenticated")
            rules.append({"file": path, "methods": None, "pattern": "/**",
                          "regex": _ant_to_regex("/**"), "decision": dec, "raw": "anyRequest()." + d})

    return rules, config_files, csrf_off


# --------------------------------------------------------------------------- Spring controllers
_CLASS_RM = re.compile(r'@RequestMapping\s*\(\s*(?:value\s*=\s*)?(?:\{\s*)?"([^"]*)"')
_METHOD_MAP = re.compile(
    r'@(GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping|RequestMapping)\s*\(\s*'
    r'(?:value\s*=\s*|path\s*=\s*)?(?:\{\s*)?(?:"([^"]*)")?'
)


def _extract_endpoints(files_java: List[Tuple[str, str]]) -> List[dict]:
    """Returns endpoint dicts: {file, line, cls, path, method, annotated(bool), pkg}"""
    out: List[dict] = []
    for path, content in files_java:
        if not re.search(r"@(RestController|Controller)\b", content):
            continue
        base = ""
        cm = _CLASS_RM.search(content)
        if cm:
            base = cm.group(1)
        class_annotated = bool(_ANNOTATION_AUTHZ.search(content.split("class ", 1)[0])) if "class " in content else False
        cls_name = ""
        cnm = re.search(r"\b(?:public\s+)?class\s+([A-Za-z0-9_]+)", content)
        if cnm:
            cls_name = cnm.group(1)
        pkg = os.path.dirname(path)

        lines = content.splitlines()
        for i, ln in enumerate(lines):
            mm = _METHOD_MAP.search(ln)
            if not mm:
                continue
            kind, sub = mm.group(1), (mm.group(2) or "")
            if kind == "RequestMapping":
                vm = re.search(r"method\s*=\s*RequestMethod\.([A-Z]+)", ln) or \
                     re.search(r"method\s*=\s*\{?\s*RequestMethod\.([A-Z]+)", ln)
                verb = vm.group(1) if vm else "ANY"
            else:
                verb = _MAPPING_VERB[kind]
            # method-level annotation: look at the ~4 lines just above/at the mapping
            window = "\n".join(lines[max(0, i - 4):i + 2])
            annotated = class_annotated or bool(_ANNOTATION_AUTHZ.search(window))
            full = "/" + "/".join(p for p in (base.strip("/"), sub.strip("/")) if p)
            full = re.sub(r"/+", "/", full)
            out.append({"file": path, "line": i + 1, "cls": cls_name, "path": full,
                        "method": verb, "annotated": annotated, "pkg": pkg})
    return out


def _match_rule(ep: dict, rules: List[dict]) -> Optional[dict]:
    """First matching rule (Spring evaluates in order; first match wins)."""
    for r in rules:
        if r["methods"] and ep["method"] != "ANY" and ep["method"] not in r["methods"]:
            continue
        if r["regex"].match(ep["path"]) or r["regex"].match(ep["path"] + "/"):
            return r
    return None


# --------------------------------------------------------------------------- front-end (Angular / React)
_GUARD_ROUTE = re.compile(
    r"path\s*:\s*['\"]([^'\"]*)['\"][^}]*?canActivate\s*:\s*\[([^\]]+)\]"
    r"|canActivate\s*:\s*\[([^\]]+)\][^}]*?path\s*:\s*['\"]([^'\"]*)['\"]",
    re.S,
)
_NGIF_ROLE = re.compile(
    r"\*ngIf\s*=\s*[\"'][^\"']*(isAdmin|esAdmin|hasRole|tienePermiso|tieneRol|roles?\.(includes|indexOf)|"
    r"perfil\s*==|rol\s*==)[^\"']*[\"']",
    re.IGNORECASE,
)
_REACT_GUARD = re.compile(r"<(PrivateRoute|ProtectedRoute|AdminRoute|RequireRole|RequireAuth)\b|"
                          r"\brole\s*===\s*['\"]admin|\bisAdmin\b|\bhasР|hasPermission\(")


# STRICT: only route/component/file names that clearly denote an ADMINISTRATION surface
# (not citizen self-service screens like `perfilUsuario` / `usuarioInactivo`).
_FE_ADMIN_CTX = re.compile(
    r"((^|[/_-])admin([/_-]|istrac|$)|catusuariosadmin|catrolesadmin|catsalasadmin|"
    r"gestion[a-z]*(usuario|rol)|administrac[a-z]*(usuario|rol)|catalogos-admin|"
    r"cat(usuarios|roles|menu|menus)\b|asignarrol|blindaje|manageusers|usermanagement)",
    re.IGNORECASE,
)


def _scan_frontend(files_ts_html: List[Tuple[str, str]], backend_has_role_enforcement: bool) -> List[dict]:
    findings: List[dict] = []
    admin_guarded_routes: List[Tuple[str, str, str, int]] = []  # (route, guard, file, line)
    lazy_admin_modules: List[Tuple[str, str, int]] = []
    guard_files = 0

    for path, content in files_ts_html:
        low = os.path.basename(path).lower()
        lines = content.splitlines()
        is_route_file = low.endswith("routing.module.ts") or low.endswith(".routes.ts") or \
            ("Routes" in content and "canActivate" in content)

        if is_route_file and "canActivate" in content:
            guard_files += 1
            file_is_admin = bool(_FE_ADMIN_CTX.search(os.path.dirname(path)))
            for gm in re.finditer(r"canActivate\s*:\s*\[([^\]]+)\]", content):
                guard = gm.group(1).strip()
                seg = content[max(0, gm.start() - 500):gm.end() + 500]
                pm = re.search(r"path\s*:\s*['\"]([^'\"]*)['\"]", seg)
                route = pm.group(1) if pm else ""
                comps = re.findall(r"component\s*:\s*([A-Za-z0-9_]+)", seg)
                # flag only when an ADMIN surface is clearly in scope: route name, a nearby
                # component name, or the module directory itself.
                if _FE_ADMIN_CTX.search(route) or any(_FE_ADMIN_CTX.search(c) for c in comps) or \
                        (file_is_admin and route in ("", "(módulo)")):
                    ln = content[:gm.start()].count("\n") + 1
                    admin_guarded_routes.append((route or "(módulo admin)", guard, path, ln))
            for lm in re.finditer(r"path\s*:\s*['\"]([^'\"]*)['\"][^}]*?loadChildren\s*:\s*[^,}]*?['\"]([^'\"]+)['\"]", content):
                route, chunk = lm.group(1), lm.group(2)
                if _FE_ADMIN_CTX.search(route) or _FE_ADMIN_CTX.search(chunk):
                    ln = content[:lm.start()].count("\n") + 1
                    lazy_admin_modules.append((route or chunk, path, ln))

        for i, ln in enumerate(lines, 1):
            if _NGIF_ROLE.search(ln) and (_SENSITIVE.search(ln) or _SENSITIVE.search(path)):
                findings.append({
                    "cve_id": "AUTHZ-CLIENT-SIDE-UI-GATE", "severity": "MEDIUM",
                    "file": path, "line": i,
                    "description": ("La visibilidad de una función sensible se decide en el navegador con "
                                    f"`*ngIf` sobre un chequeo de rol. Un atacante que manipule la respuesta "
                                    f"o edite el DOM la ve igual.\nLínea {i}: {ln.strip()[:160]}"),
                })
            if _REACT_GUARD.search(ln) and _SENSITIVE.search(ln):
                findings.append({
                    "cve_id": "AUTHZ-CLIENT-SIDE-UI-GATE", "severity": "MEDIUM",
                    "file": path, "line": i,
                    "description": (f"Chequeo de rol/permiso del lado del cliente para una función sensible.\n"
                                    f"Línea {i}: {ln.strip()[:160]}"),
                })

    for route, guard, path, ln in admin_guarded_routes:
        sev = "HIGH" if not backend_has_role_enforcement else "MEDIUM"
        extra = ("  El backend NO tiene ninguna regla de rol (`@PreAuthorize` / `hasRole` / `isAdmin`) "
                 "para estos recursos, por lo que reescribir la respuesta del guard (403→200) da acceso real."
                 if not backend_has_role_enforcement else
                 "  El backend sí tiene reglas de rol; verificar que cubren TODOS los endpoints que consume "
                 "este módulo, no solo algunos.")
        findings.append({
            "cve_id": "AUTHZ-CLIENT-SIDE-ONLY", "severity": sev,
            "file": path, "line": ln,
            "description": (f"El módulo administrativo `{route or '(ruta admin)'}` se protege únicamente con "
                            f"un guard de front-end (`canActivate: [{guard}]`).{extra}\n"
                            "CWE-602 (Client-Side Enforcement of Server-Side Security)."),
        })
    for route, path, ln in lazy_admin_modules:
        findings.append({
            "cve_id": "AUTHZ-ADMIN-BUNDLE-EXPOSED", "severity": "LOW",
            "file": path, "line": ln,
            "description": (f"Los componentes del módulo `{route}` se compilan y entregan a todos los clientes; "
                            "si su única protección es un guard, se pueden renderizar manipulando la respuesta. "
                            "El control de acceso debe estar en el servidor."),
        })
    return findings


# --------------------------------------------------------------------------- main
def run_authz_audit(target_dir: str = "/app", asset_id: int = None) -> List[Dict[str, Any]]:
    """Static Broken-Access-Control audit over target_dir. Persists + reconciles when asset_id given."""
    files_java: List[Tuple[str, str]] = []
    files_fe: List[Tuple[str, str]] = []
    for path in _walk(target_dir):
        ext = os.path.splitext(path)[1].lower()
        if ext == ".java":
            files_java.append((path, _read(path)))
        elif ext in (".ts", ".js", ".html"):
            c = _read(path)
            if c:
                files_fe.append((path, c))

    findings: List[dict] = []

    rules, config_files, csrf_off = _parse_security_configs(files_java)
    endpoints = _extract_endpoints(files_java)

    backend_role_enforcement = any(r["decision"] in ("admin", "role") for r in rules) or \
        any(e["annotated"] for e in endpoints)

    # ---- CSRF disabled
    for f in csrf_off:
        findings.append({
            "cve_id": "AUTHZ-CSRF-DISABLED", "severity": "MEDIUM", "file": f, "line": 1,
            "description": ("`.csrf().disable()` en la configuración de seguridad. Si la app usa cookies/sesión "
                            "para autenticar (se detectó `httpBasic()`/form login o cookie de sesión), queda "
                            "expuesta a CSRF. Aceptable solo si TODO el acceso es por Bearer token en header."),
        })

    # ---- per-endpoint checks
    n_controllers = len({e["file"] for e in endpoints})
    n_annotated = sum(1 for e in endpoints if e["annotated"])
    families: Dict[str, List[Tuple[dict, Optional[dict]]]] = {}

    for ep in endpoints:
        rule = _match_rule(ep, rules)
        seg = [s for s in ep["path"].split("/") if s and not s.startswith("{")]
        fam = "/".join(seg[:2]) if seg else "/"
        families.setdefault(fam, []).append((ep, rule))

        if rule is None and not ep["annotated"]:
            findings.append({
                "cve_id": "AUTHZ-NO-RULE", "severity": "HIGH", "file": ep["file"], "line": ep["line"],
                "description": (f"`{ep['method']} {ep['path']}` ({ep['cls']}) no coincide con ninguna regla de "
                               f"`antMatchers`/`requestMatchers` ni tiene `@PreAuthorize`/`@Secured`. Su "
                               f"autorización es indefinida — puede quedar totalmente abierto o depender del "
                               f"orden de filtros. {len(config_files)} archivo(s) de config revisados."),
            })
        elif rule and rule["decision"] == "permitAll" and ep["method"] in _STATE_CHANGE:
            findings.append({
                "cve_id": "AUTHZ-PERMITALL-WRITE", "severity": "HIGH", "file": ep["file"], "line": ep["line"],
                "description": (f"`{ep['method']} {ep['path']}` está cubierto por una regla `permitAll()` "
                               f"(`{rule['pattern']}` en {os.path.basename(rule['file'])}). Un verbo que muta "
                               f"estado no debe ser público."),
            })
        elif rule and rule["decision"] == "authenticated" and ep["method"] in _STATE_CHANGE and _SENSITIVE.search(ep["path"]) \
                and not _IDENTITY_ADMIN_LOOSE.search(ep["path"]):
            findings.append({
                "cve_id": "AUTHZ-ONLY-AUTHENTICATED-WRITE", "severity": "MEDIUM", "file": ep["file"], "line": ep["line"],
                "description": (f"`{ep['method']} {ep['path']}` (recurso sensible) solo exige `.authenticated()` "
                               f"(regla `{rule['pattern']}`). Cualquier usuario con sesión puede invocarlo; "
                               f"falta un chequeo de rol (`hasRole`/`@PreAuthorize`/`isAdmin`)."),
            })

    # ---- inconsistent authorization: identity-admin endpoint left weak while siblings are hardened
    #      (THE SIDECO CASE: /v1/catalogos/roles hardened, /v1/usr/** forgotten)
    codebase_has_admin_rule = any(r["decision"] == "admin" for r in rules)
    codebase_has_role_rule = any(r["decision"] in ("admin", "role") for r in rules)
    _idor_seen: set = set()
    for fam, eps in families.items():
        fam_has_admin = any(r and r["decision"] == "admin" for _, r in eps)
        for ep, rule in eps:
            weak = (rule is None) or (rule and rule["decision"] in ("authenticated", "permitAll", "custom", "anonymous"))
            if not weak or ep["annotated"]:
                continue
            last_seg = ep["path"].rstrip("/").split("/")[-1]
            is_identity_admin = (
                _IDENTITY_MUTATION.search(ep["path"])
                or _IDENTITY_CATALOG_GET.search(ep["path"])
                or (ep["method"] in _STATE_CHANGE and _IDENTITY_ADMIN_LOOSE.search(ep["path"]) and not _SUBJECT_PARAM.search(ep["path"]))
            )
            if is_identity_admin and (codebase_has_admin_rule or codebase_has_role_rule):
                findings.append({
                    "cve_id": "AUTHZ-INCONSISTENT-FAMILY", "severity": "HIGH", "file": ep["file"], "line": ep["line"],
                    "description": (f"`{ep['method']} {ep['path']}` ({ep['cls']}) administra identidad "
                                   f"(usuarios / roles / permisos / acceso al sistema) y solo tiene "
                                   f"`{(rule['decision'] if rule else 'ninguna regla de seguridad')}`, "
                                   f"mientras que en la misma app hay endpoints hermanos blindados con rol de "
                                   f"administrador (`@roleSecurity.isAdmin` / `hasRole`). Patrón "
                                   f"'blindaron `/catalogos/roles` y olvidaron `/usr/**`': un usuario "
                                   f"autenticado sin rol admin llega a una función administrativa — escalación "
                                   f"de privilegios (retest SIDECO, cuenta TcsCSA2)."),
                })
            elif fam_has_admin and _SENSITIVE.search(ep["path"]) and not _SUBJECT_PARAM.search(ep["path"]):
                findings.append({
                    "cve_id": "AUTHZ-INCONSISTENT-FAMILY", "severity": "HIGH", "file": ep["file"], "line": ep["line"],
                    "description": (f"En la familia `/{fam}/…` hay endpoints con rol de administrador, pero "
                                   f"`{ep['method']} {ep['path']}` ({ep['cls']}) solo tiene "
                                   f"`{(rule['decision'] if rule else 'ninguna regla')}` y toca datos sensibles. "
                                   f"Escalación de privilegios por inconsistencia."),
                })
            # object-level (IDOR) surface: a {usuario}/{id...} param on a non-identity-admin
            # endpoint -> flag ONCE per controller for manual review (the real check is the DAST
            # IDOR probe in auditor_authz_dast.py).
            elif _SUBJECT_PARAM.search(ep["path"]) and ep["cls"] not in _idor_seen:
                _idor_seen.add(ep["cls"])
                findings.append({
                    "cve_id": "AUTHZ-IDOR-PARAM-REVIEW", "severity": "MEDIUM", "file": ep["file"], "line": ep["line"],
                    "description": (f"`{ep['cls']}` expone endpoints que reciben el identificador del usuario "
                                   f"como parámetro de ruta (p. ej. `{ep['method']} {ep['path']}`) y solo exigen "
                                   f"`.authenticated()`. Verificar que cada uno comprueba que el recurso "
                                   f"pertenece a quien lo pide (IDOR / BOLA). La confirmación automática la hace "
                                   f"la sonda IDOR autenticada (auditor_authz_dast)."),
                })

    # ---- namespace gap: controllers under a prefix no rule covers, while another prefix is matched
    ep_prefixes = {("/" + p["path"].strip("/").split("/", 1)[0]) for p in endpoints if p["path"].strip("/")}
    rule_prefixes = {("/" + r["pattern"].strip("/").split("/", 1)[0]) for r in rules if r["pattern"].strip("/").split("/", 1)[0] not in ("**", "*")}
    fe_api_prefixes = set()
    for _p, c in files_fe:
        for am in re.finditer(r"apiUrl\s*[:=]\s*['\"]([^'\"]+)['\"]", c):
            v = am.group(1).strip("/")
            if v:
                fe_api_prefixes.add("/" + v.split("/")[-1] if "/" in v else "/" + v)
        for am in re.finditer(r"['\"](/api|/rest|/svc|/ws\w*)/", c):
            fe_api_prefixes.add(am.group(1))
    uncovered = {pfx for pfx in (ep_prefixes | fe_api_prefixes)
                 if pfx not in rule_prefixes and pfx not in ("/", "/**") and not any(rp in ("/**", "/") for rp in rule_prefixes)}
    if uncovered and rule_prefixes:
        example = ", ".join(sorted(uncovered)[:5])
        findings.append({
            "cve_id": "AUTHZ-NAMESPACE-GAP", "severity": "MEDIUM",
            "file": (config_files[0] if config_files else target_dir), "line": 1,
            "description": (f"Los `antMatchers` cubren prefijos como {sorted(rule_prefixes)[:4]} pero hay "
                           f"controladores y/o llamadas del front-end bajo {example}, que ninguna regla "
                           f"contempla. Un rewrite de proxy (`/api/**` → `/v1/**`) o una ruta directa por ese "
                           f"prefijo evita por completo el control de acceso."),
        })

    # ---- 100% URL-matcher authz, zero method annotations
    if n_controllers >= 5 and n_annotated == 0 and rules:
        findings.append({
            "cve_id": "AUTHZ-NO-METHOD-ANNOTATIONS", "severity": "LOW",
            "file": (config_files[0] if config_files else target_dir), "line": 1,
            "description": (f"{n_controllers} controladores y 0 anotaciones `@PreAuthorize`/`@Secured`. Toda la "
                           f"autorización depende de una lista de URLs mantenida a mano en "
                           f"{len(config_files)} `SecurityConfig`. Es frágil: cualquier endpoint nuevo o "
                           f"renombrado queda sin protección hasta que alguien recuerde añadir la regla. "
                           f"Recomendación: defensa en profundidad con `@PreAuthorize` a nivel de método."),
        })

    # ---- front-end
    findings.extend(_scan_frontend(files_fe, backend_role_enforcement))

    _persist(findings, target_dir, asset_id)
    return findings


def _persist(findings: List[dict], target_dir: str, asset_id: Optional[int]) -> None:
    if asset_id is None or db_manager is None or deduplication_engine is None:
        return
    _SEV_TXT = {
        "AUTHZ-NO-RULE": "Endpoint sin autorización definida",
        "AUTHZ-PERMITALL-WRITE": "Escritura pública (permitAll)",
        "AUTHZ-ONLY-AUTHENTICATED-WRITE": "Escritura sensible solo autenticada, sin rol",
        "AUTHZ-INCONSISTENT-FAMILY": "Autorización inconsistente — escalación de privilegios",
        "AUTHZ-NAMESPACE-GAP": "Prefijo de rutas sin cobertura de seguridad",
        "AUTHZ-CSRF-DISABLED": "Protección CSRF deshabilitada",
        "AUTHZ-NO-METHOD-ANNOTATIONS": "Autorización solo por lista de URLs (frágil)",
        "AUTHZ-CLIENT-SIDE-ONLY": "Autorización del módulo admin solo en el cliente",
        "AUTHZ-CLIENT-SIDE-UI-GATE": "Función sensible ocultada solo del lado del cliente",
        "AUTHZ-ADMIN-BUNDLE-EXPOSED": "Componentes admin entregados a todos los clientes",
    }
    try:
        active = set()
        with db_manager.get_db_cursor() as cur:
            for it in findings:
                rel = os.path.relpath(it["file"], target_dir) if os.path.isabs(it["file"]) else it["file"]
                loc = f"{rel}:{it.get('line', 0)}"
                title = _SEV_TXT.get(it["cve_id"], it["cve_id"])
                desc = f"**{title}**\n**Archivo:** `{rel}` (Línea {it.get('line', 0)})\n\n{it['description']}"
                active.add(deduplication_engine.calculate_fingerprint(asset_id, it["cve_id"], loc))
                deduplication_engine.log_finding_deduplicated(
                    cur, asset_id, it["cve_id"], it["severity"], desc, _SCAN_ENGINE,
                    url_path=loc, open_status="OPEN", preserve_status=True,
                )
            n = deduplication_engine.reconcile_resolved_findings(cur, asset_id, _SCAN_ENGINE, active)
            if n:
                print(f"✅ [Authz-Auditor] Reconciled {n} stale authz-static finding(s) as RESOLVED for asset {asset_id}.")
        print(f"🔐 [Authz-Auditor] {len(findings)} broken-access-control finding(s) for asset {asset_id}.")
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"⚠️ [Authz-Auditor] Could not persist findings: {e}")


def run(asset_id: int, endpoint: str = None, target_dir: str = "/app"):
    """auditor_ext-style entrypoint (kept for symmetry; the fleet loop calls run_authz_audit directly)."""
    return run_authz_audit(target_dir, asset_id)


if __name__ == "__main__":
    import sys, json
    d = sys.argv[1] if len(sys.argv) > 1 else "/app"
    res = run_authz_audit(d, asset_id=None)
    print(json.dumps([{k: v for k, v in f.items() if k != "description"} for f in res], indent=1, ensure_ascii=False))
    print(f"\n{len(res)} findings")
