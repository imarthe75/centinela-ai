"""
API contract drift for repositories (engine 'api-contract', OWASP API9 "Improper Inventory Management").

Compares the HTTP routes the SOURCE declares with the OpenAPI/Swagger document the repository versions:
  Spring (@RestController + @Get/Post/...Mapping, class-level @RequestMapping), NestJS (@Controller + @Get...), Express (app/router.get...),
  FastAPI / Flask (@app/@router/@bp .get / .route).

Rules (path-level comparison; the method is shown but not compared -- too many frameworks differ on it):
  API-ROUTE-NOT-IN-CONTRACT        MEDIUM  routes the code serves that the versioned contract does not list ("shadow" endpoints). One finding per source file.
  API-CONTRACT-ROUTE-NOT-IMPLEMENTED LOW   contract paths no route in the code serves (documentation promising something that is gone). One per repository.
  API-CONTRACT-MISMATCH            LOW     the versioned contract shares NO path with the code: it is stale or belongs to something else; no per-route findings are made.
  API-NO-CONTRACT                  LOW     >=3 routes, no contract file and no library that publishes one at runtime (springdoc, springfox, @nestjs/swagger, FastAPI...).

Limits stated in every description: gateway / context-path prefixes are matched by suffix, contracts generated only at runtime cannot be compared statically (those
repos get NO finding at all, not an "ok"), and a path-level match does not prove the schemas agree.
"""
import json
import os
import re
from typing import Any, Dict, List, Optional, Set, Tuple

ENGINE = "api-contract"
URL_PATH = "api-contract"
_SKIP_DIRS = ("node_modules", "/target/", "/build/", "/dist/", "/.git/", "/test/", "/tests/", "__tests__", "/vendor/", "/venv/", "/.venv/", "/e2e/")
_SPEC_NAME = re.compile(r"^(openapi|swagger|api-docs)[\w.\-]*\.(json|ya?ml)$", re.IGNORECASE)
_RUNTIME_DOC_LIBS = re.compile(r"springdoc|springfox|swagger-ui|swagger-jsdoc|@nestjs/swagger|swagger-ui-express|fastapi|drf-spectacular|flasgger|connexion|tsoa|nswag", re.IGNORECASE)


def normalize_path(p: str) -> str:
    p = (p or "").split("?")[0].strip()
    p = re.sub(r"\{[^}/]*\}", "{}", p)                 # {id} / {id:regex}
    p = re.sub(r"<[^>/]*>", "{}", p)                    # flask <int:id>
    p = re.sub(r"(?<=/):[A-Za-z_]\w*", "{}", p)        # express :id
    p = re.sub(r"/+", "/", "/" + p.strip("/"))
    return p.lower().rstrip("/") or "/"


def _join(base: str, sub: str) -> str:
    return normalize_path((base or "") + "/" + (sub or ""))


def _strings(args: str) -> List[str]:
    return re.findall(r'"([^"]*)"', args)


# ---------------------------------------------------------------------------------------------------------------- route extraction
def routes_spring(content: str) -> List[Tuple[str, str]]:
    if not re.search(r"@(Rest)?Controller\b", content):
        return []
    cls = re.search(r"@(?:Rest)?Controller\b.*?\bclass\s+\w+", content, re.DOTALL)
    head = content[: cls.end()] if cls else ""
    base_m = re.findall(r"@RequestMapping\s*\(([^)]*)\)", head)
    bases = _strings(base_m[-1]) if base_m else [""]
    bases = bases or [""]
    out: List[Tuple[str, str]] = []
    for m in re.finditer(r"@(Get|Post|Put|Delete|Patch|Request)Mapping\b(\s*\(([^)]*)\))?", content[len(head):] if cls else content):
        kind, args = m.group(1), (m.group(3) or "")
        if kind == "Request" and not re.search(r"method\s*=", args):
            continue                                                        # a bare @RequestMapping on a method without verb: skip (ambiguous)
        verb = kind.upper() if kind != "Request" else (re.search(r"RequestMethod\.(\w+)", args) or [None, "ANY"])[1]
        subs = _strings(args) or [""]
        for b in bases:
            for s_ in subs:
                out.append((verb, _join(b, s_)))
    return out


def routes_nest(content: str) -> List[Tuple[str, str]]:
    cm = re.search(r"@Controller\s*\(\s*(?:['\"]([^'\"]*)['\"])?", content)
    if not cm:
        return []
    base = cm.group(1) or ""
    return [(m.group(1).upper(), _join(base, m.group(2) or "")) for m in re.finditer(r"@(Get|Post|Put|Delete|Patch)\s*\(\s*(?:['\"]([^'\"]*)['\"])?", content)]


def routes_express(content: str) -> List[Tuple[str, str]]:
    return [(m.group(2).upper(), normalize_path(m.group(3)))
            for m in re.finditer(r"\b(app|router|\w*[Rr]outer|api|server)\.(get|post|put|delete|patch)\s*\(\s*['\"`](/[^'\"`]*)['\"`]", content)]


def routes_python(content: str) -> List[Tuple[str, str]]:
    out = [(m.group(2).upper(), normalize_path(m.group(3)))
           for m in re.finditer(r"@(app|router|bp|blueprint|api)\.(get|post|put|delete|patch)\s*\(\s*['\"]([^'\"]+)['\"]", content)]
    for m in re.finditer(r"@(?:app|bp|blueprint)\.route\s*\(\s*['\"]([^'\"]+)['\"]([^)]*)\)", content):
        meth = re.search(r"methods\s*=\s*\[([^\]]*)\]", m.group(2))
        out.append(((meth.group(1).replace("'", "").replace('"', "").split(",")[0].strip().upper() if meth else "GET"), normalize_path(m.group(1))))
    return out


def extract_routes(file_path: str, content: str) -> List[Tuple[str, str]]:
    if file_path.endswith(".java"):
        return routes_spring(content)
    if file_path.endswith(".ts"):
        return routes_nest(content) or (routes_express(content) if not file_path.endswith(".component.ts") else [])
    if file_path.endswith(".js"):
        return routes_express(content)
    if file_path.endswith(".py"):
        return routes_python(content)
    return []


# ---------------------------------------------------------------------------------------------------------------- contract
def load_spec_paths(spec_text: str, name: str) -> Optional[Set[str]]:
    """Normalized paths of an OpenAPI 3 / Swagger 2 document, with its server/basePath prefix applied as an ALTERNATIVE (both forms match)."""
    try:
        if name.lower().endswith(".json"):
            doc = json.loads(spec_text)
        else:
            import yaml
            doc = yaml.safe_load(spec_text)
    except Exception:
        return None
    if not isinstance(doc, dict) or not isinstance(doc.get("paths"), dict):
        return None
    prefixes = {""}
    if isinstance(doc.get("basePath"), str):
        prefixes.add(doc["basePath"])
    for srv in doc.get("servers") or []:
        if isinstance(srv, dict) and isinstance(srv.get("url"), str):
            m = re.match(r"^(?:https?://[^/]+)?(/.*)?$", srv["url"])
            if m and m.group(1):
                prefixes.add(m.group(1))
    return {_join(pre, p) for p in doc["paths"] for pre in prefixes}


def covered(route: str, spec_paths: Set[str]) -> bool:
    """Suffix tolerance: a gateway/context-path prefix on either side must not create a false 'shadow' route."""
    return any(route == s or route.endswith(s) or s.endswith(route) for s in spec_paths if s != "/" and route != "/") or route in spec_paths


def compare(code_routes: Dict[str, List[Tuple[str, str]]], spec_paths: Set[str]) -> Dict[str, Any]:
    """code_routes: {file: [(verb, path)]}. Returns undocumented per file, unimplemented spec paths, and the overlap."""
    all_code = {p for rs in code_routes.values() for _, p in rs}
    overlap = {p for p in all_code if covered(p, spec_paths)}
    undocumented = {f: [(v, p) for v, p in rs if not covered(p, spec_paths)] for f, rs in code_routes.items()}
    undocumented = {f: rs for f, rs in undocumented.items() if rs}
    unimplemented = sorted(s for s in spec_paths if not any(covered(p, {s}) for p in all_code))
    # a spec path with a servers/basePath prefix is the same operation as the bare one: report each operation once
    unimplemented = [s for s in unimplemented if not any(s != o and s.endswith(o) for o in unimplemented)]
    return {"overlap": len(overlap), "total_routes": len(all_code), "undocumented": undocumented, "unimplemented": unimplemented}


# ---------------------------------------------------------------------------------------------------------------- repository scan
def scan_repo(target_dir: str) -> Dict[str, Any]:
    code_routes: Dict[str, List[Tuple[str, str]]] = {}
    spec_files: List[str] = []
    runtime_doc = False
    for root, _, files in os.walk(target_dir):
        norm = "/" + root.replace("\\", "/") + "/"
        if any(s in norm for s in _SKIP_DIRS):
            continue
        for fn in files:
            full = os.path.join(root, fn)
            rel = os.path.relpath(full, target_dir)
            if _SPEC_NAME.match(fn):
                spec_files.append(rel)
                continue
            if fn in ("pom.xml", "build.gradle", "build.gradle.kts", "package.json", "requirements.txt", "pyproject.toml"):
                try:
                    if _RUNTIME_DOC_LIBS.search(open(full, encoding="utf-8", errors="ignore").read()):
                        runtime_doc = True
                except OSError:
                    pass
            if fn.endswith((".java", ".ts", ".js", ".py")) and not fn.endswith((".spec.ts", ".test.ts", ".min.js", ".d.ts")):
                try:
                    content = open(full, encoding="utf-8", errors="ignore").read()
                except OSError:
                    continue
                rs = extract_routes(full, content)
                if rs:
                    code_routes[rel] = rs
    return {"routes": code_routes, "spec_files": spec_files, "runtime_doc": runtime_doc}


def audit_repo(target_dir: str) -> List[Dict[str, Any]]:
    info = scan_repo(target_dir)
    routes, specs = info["routes"], info["spec_files"]
    total = len({p for rs in routes.values() for _, p in rs})
    out: List[Dict[str, Any]] = []
    if total == 0:
        return out
    if not specs:
        if total >= 3 and not info["runtime_doc"]:
            out.append({"cve_id": "API-NO-CONTRACT", "severity": "LOW", "url_path": URL_PATH,
                        "description": (f"El repositorio expone {total} rutas HTTP pero no versiona ningún contrato OpenAPI/Swagger ni incluye una librería que lo publique (springdoc, "
                                        f"springfox, @nestjs/swagger, FastAPI...). Sin contrato no hay inventario de la API ni base para pruebas de contrato o de fuzzing (OWASP API9). "
                                        f"Publicar un contrato y versionarlo con el código.")})
        return out
    spec_paths: Set[str] = set()
    parsed = []
    for rel in specs:
        try:
            ps = load_spec_paths(open(os.path.join(target_dir, rel), encoding="utf-8", errors="ignore").read(), rel)
        except OSError:
            ps = None
        if ps:
            spec_paths |= ps
            parsed.append(rel)
    if not parsed:
        return out                                          # spec files exist but none parses: say nothing rather than guess
    cmp_ = compare(routes, spec_paths)
    if cmp_["overlap"] == 0:
        out.append({"cve_id": "API-CONTRACT-MISMATCH", "severity": "LOW", "url_path": parsed[0],
                    "description": (f"El contrato versionado ({', '.join(parsed)}) no comparte ninguna ruta con las {total} que sirve el código: está desactualizado o pertenece a otro servicio. "
                                    f"Requiere validación: no se comparó ruta por ruta para no inventar diferencias.")})
        return out
    for rel, rs in sorted(cmp_["undocumented"].items()):
        listing = "; ".join(f"{v} {p}" for v, p in rs[:15]) + (f"; y {len(rs) - 15} más" if len(rs) > 15 else "")
        out.append({"cve_id": "API-ROUTE-NOT-IN-CONTRACT", "severity": "MEDIUM", "url_path": rel,
                    "description": (f"{len(rs)} ruta(s) de este controlador no aparecen en el contrato versionado ({', '.join(parsed)}): {listing}. Endpoints fuera del inventario escapan de las "
                                    f"revisiones de seguridad basadas en el contrato (OWASP API9). Requiere validación: los prefijos de gateway/context-path se comparan por sufijo y un "
                                    f"contrato parcial puede ser intencional. Documentarlas o retirarlas.")})
    if cmp_["unimplemented"]:
        lst = cmp_["unimplemented"]
        out.append({"cve_id": "API-CONTRACT-ROUTE-NOT-IMPLEMENTED", "severity": "LOW", "url_path": parsed[0],
                    "description": (f"{len(lst)} ruta(s) del contrato no tienen ningún controlador en el código: {'; '.join(lst[:15])}{'; y %d más' % (len(lst) - 15) if len(lst) > 15 else ''}. "
                                    f"Documentación desactualizada que promete endpoints inexistentes (o que viven en otro servicio). Requiere validación.")})
    return out


def run_api_contract_audit(target_dir: str, asset_id: Optional[str] = None, display_name: str = "") -> List[Dict[str, Any]]:
    findings = audit_repo(target_dir)
    if asset_id is None:
        return findings
    from core import db_manager, deduplication_engine
    try:
        active = set()
        with db_manager.get_db_cursor() as cur:
            for f in findings:
                active.add(deduplication_engine.calculate_fingerprint(asset_id, f["cve_id"], f["url_path"]))
                deduplication_engine.log_finding_deduplicated(cur, asset_id, f["cve_id"], f["severity"], f["description"], ENGINE,
                                                              url_path=f["url_path"], preserve_status=True)
            deduplication_engine.reconcile_resolved_findings(cur, asset_id, ENGINE, active)
    except Exception:
        import traceback
        traceback.print_exc()
        print(f"⚠️ [API-Contract] could not persist findings for {display_name or asset_id}")
    return findings
