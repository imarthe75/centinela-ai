"""
GitLab project configuration + CI/CD pipeline auditor.

Closes a coverage gap found 2026-09-23: Centinela scanned the *code* of ~95 repos but never the
platform that governs it -- unprotected default branches, projects visible beyond their team,
secrets in CI variables that are not masked, and `.gitlab-ci.yml` patterns such as `curl | sh`
or unpinned `:latest` images. This is the CMMI CM / the internal methodology "control de cambios" evidence
that a source scanner cannot see.

* `evaluate_project_settings()` and `evaluate_ci_file()` are PURE (unit-tested, no network).
* `audit_project()` reads GitLab's REST API with the service token, read-only. Any endpoint the
  token cannot read is skipped and reported as not-evaluated -- never guessed, and never used to
  reconcile (close) previously open findings.
* Secret VALUES returned by the variables API are never stored or logged -- only key names.
* GitLab CE has no merge-request approval rules (API 404); that control is documented as not
  auditable here rather than reported as missing.
"""
import os
import re
import traceback
from typing import Any, Dict, List, Optional

import requests

SCAN_ENGINE = "gitlab-config"
MARKER_CVE = "GITLAB-CONFIG-AUDIT"
_SECRET_KEY_RE = re.compile(r"(PASS(WORD)?|SECRET|TOKEN|API[_-]?KEY|PRIVATE[_-]?KEY|PWD|CREDENTIAL)", re.I)
_DEV_PUSH = 30  # GitLab access level: Developer


# --------------------------------------------------------------------------- project settings (pure)
def evaluate_project_settings(project: Dict[str, Any], protected_branches: Optional[List[Dict[str, Any]]],
                              hooks: Optional[List[Dict[str, Any]]], variables: Optional[List[Dict[str, Any]]],
                              has_ci_file: Optional[bool], branch_names: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    """None for an input means 'could not be read' -> that check is skipped, never a finding."""
    out: List[Dict[str, Any]] = []
    path = project.get("path_with_namespace", "?")
    loc = f"gitlab:{path}"
    default_branch = project.get("default_branch")

    vis = project.get("visibility")
    if vis == "public":
        out.append({"cve_id": "GITLAB-PROJECT-PUBLIC-VISIBILITY", "severity": "CRITICAL", "url_path": f"{loc}#visibility",
                    "description": f"**Repositorio público:** `{path}` es visible para cualquiera sin autenticación, incluido su código fuente e historial."})
    elif vis == "internal":
        out.append({"cve_id": "GITLAB-PROJECT-PUBLIC-VISIBILITY", "severity": "MEDIUM", "url_path": f"{loc}#visibility",
                    "description": f"**Repositorio con visibilidad 'internal':** `{path}` es legible por cualquier usuario autenticado de la instancia, no solo por su equipo."})

    if protected_branches is not None and default_branch:
        by_name = {b.get("name"): b for b in protected_branches}
        wildcard = [b for n, b in by_name.items() if n and "*" in n]
        prot = by_name.get(default_branch)
        if prot is None and not any(re.fullmatch(re.escape(n).replace(r"\*", ".*"), default_branch) for n in by_name if "*" in n):
            out.append({"cve_id": "GITLAB-PROJECT-DEFAULT-BRANCH-UNPROTECTED", "severity": "HIGH",
                        "url_path": f"{loc}#branch={default_branch}",
                        "description": (f"**La rama por defecto `{default_branch}` de `{path}` no está protegida.** Cualquier miembro con rol "
                                        f"Developer puede empujar directo o reescribir su historial sin Merge Request ni revisión. "
                                        f"Ramas protegidas actuales: {sorted(n for n in by_name) or 'ninguna'}.")})
        else:
            b = prot or wildcard[0]
            if b.get("allow_force_push"):
                out.append({"cve_id": "GITLAB-PROJECT-BRANCH-FORCE-PUSH", "severity": "HIGH",
                            "url_path": f"{loc}#branch={default_branch}",
                            "description": f"**Force-push permitido** en la rama protegida `{default_branch}` de `{path}`: el historial auditado puede reescribirse."})
            if any(l.get("access_level", 0) == _DEV_PUSH for l in b.get("push_access_levels", [])):
                out.append({"cve_id": "GITLAB-PROJECT-BRANCH-DEVELOPER-PUSH", "severity": "MEDIUM",
                            "url_path": f"{loc}#branch={default_branch}",
                            "description": f"**Push directo permitido a Developers** en `{default_branch}` de `{path}`: se omite la revisión por Merge Request."})

    if has_ci_file is False:
        out.append({"cve_id": "CICD-NO-PIPELINE", "severity": "LOW", "url_path": f"{loc}#ci",
                    "description": f"**Sin pipeline de CI/CD:** `{path}` no tiene `.gitlab-ci.yml`; ningún control automático (pruebas, escaneo) corre antes de integrar cambios."})
    elif has_ci_file and not project.get("only_allow_merge_if_pipeline_succeeds"):
        out.append({"cve_id": "GITLAB-PROJECT-MR-NO-PIPELINE-GATE", "severity": "LOW", "url_path": f"{loc}#merge-gate",
                    "description": f"**Los Merge Requests de `{path}` pueden integrarse con el pipeline fallido:** 'Pipelines must succeed' está desactivado aunque el proyecto tiene CI."})

    for h in hooks or []:
        url = h.get("url", "")
        if url.startswith("http://") or h.get("enable_ssl_verification") is False:
            why = "usa HTTP sin cifrar" if url.startswith("http://") else "desactiva la verificación del certificado TLS"
            out.append({"cve_id": "GITLAB-PROJECT-WEBHOOK-INSECURE", "severity": "MEDIUM", "url_path": f"{loc}#hook={h.get('id')}",
                        "description": f"**Webhook inseguro** en `{path}` ({url}): {why}; el payload del repositorio viaja expuesto o es suplantable."})

    for v in variables or []:
        key = v.get("key", "")
        if _SECRET_KEY_RE.search(key):
            if not v.get("masked"):
                out.append({"cve_id": "GITLAB-PROJECT-CI-VARIABLE-UNMASKED", "severity": "HIGH", "url_path": f"{loc}#var={key}",
                            "description": f"**Variable de CI con aspecto de secreto sin enmascarar:** `{key}` en `{path}`; su valor puede aparecer en claro en los logs de los jobs."})
            elif not v.get("protected"):
                out.append({"cve_id": "GITLAB-PROJECT-CI-VARIABLE-UNPROTECTED", "severity": "LOW", "url_path": f"{loc}#var={key}",
                            "description": f"**Variable secreta `{key}` disponible en ramas no protegidas** de `{path}`: cualquier rama (o un MR de un colaborador) puede leerla desde un job."})
    return out


# --------------------------------------------------------------------------- CI file (pure)
_CI_RULES = [
    ("CICD-CURL-PIPE-SHELL", "HIGH", re.compile(r"(curl|wget)\b[^\n|;]*\|\s*(sudo\s+)?(ba)?sh\b"),
     "descarga y ejecuta código remoto (`curl | sh`) sin verificar integridad"),
    ("CICD-TLS-VERIFICATION-DISABLED", "MEDIUM",
     re.compile(r"(GIT_SSL_NO_VERIFY|NODE_TLS_REJECT_UNAUTHORIZED\s*[:=]\s*['\"]?0|strict-ssl\s+false|curl\b[^\n]*\s(-k|--insecure)\b|\bverify=False)"),
     "desactiva la verificación de certificados TLS"),
    ("CICD-DOCKER-PRIVILEGED", "MEDIUM", re.compile(r"^\s*(privileged\s*:\s*true|--privileged\b)|\bdocker run\b[^\n]*--privileged"),
     "ejecuta contenedores privilegiados en el runner (equivale a root en el host)"),
]
_INLINE_IMAGE_RE = re.compile(r"^\s*image\s*:\s*['\"]?([^\s'\"#]+)['\"]?\s*(?:#.*)?$")
_LITERAL_SECRET_RE = re.compile(r"^\s*([A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|PRIVATE_KEY)[A-Z0-9_]*)\s*:\s*['\"]?([^\s'\"$#][^\s'\"#]*)['\"]?\s*$", re.I)
_REMOTE_INCLUDE_RE = re.compile(r"^\s*-?\s*remote\s*:\s*['\"]?(http://[^\s'\"]+)")


def _looks_like_secret_value(v: str) -> bool:
    """A literal that could plausibly be a credential (not a number/boolean/short flag)."""
    return len(v) >= 6 and not v.isdigit() and v.lower() not in ("true", "false", "none", "null", "enabled", "disabled")


def evaluate_ci_file(text: str, path: str = ".gitlab-ci.yml") -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for lineno, line in enumerate((text or "").splitlines(), 1):
        code = line.split(" #", 1)[0] if not line.lstrip().startswith("#") else ""
        if not code.strip():
            continue
        loc = f"{path}:{lineno}"
        for cve, sev, rx, why in _CI_RULES:
            if rx.search(code):
                out.append({"cve_id": cve, "severity": sev, "url_path": loc,
                            "description": f"**Pipeline CI:** la línea `{code.strip()[:140]}` {why}."})
        m = _INLINE_IMAGE_RE.match(code)
        if m:
            img = m.group(1)
            if "$" not in img and ("@sha256:" not in img) and (img.endswith(":latest") or ":" not in img.rsplit("/", 1)[-1]):
                out.append({"cve_id": "CICD-UNPINNED-IMAGE", "severity": "MEDIUM", "url_path": loc,
                            "description": f"**Imagen de CI sin versión fija:** `{img}` (tag `latest` o ausente); el build deja de ser reproducible y puede ejecutar una imagen alterada."})
        m = _LITERAL_SECRET_RE.match(code)
        if m and not code.lstrip().startswith(("-", "script")) and _looks_like_secret_value(m.group(2)):
            out.append({"cve_id": "CICD-HARDCODED-SECRET", "severity": "HIGH", "url_path": loc,
                        "description": f"**Secreto literal en el pipeline:** la variable `{m.group(1)}` tiene un valor escrito en `.gitlab-ci.yml` (visible en el repositorio y su historial); use variables de CI enmascaradas."})
        m = _REMOTE_INCLUDE_RE.match(code)
        if m:
            out.append({"cve_id": "CICD-REMOTE-INCLUDE-INSECURE", "severity": "MEDIUM", "url_path": loc,
                        "description": f"**`include: remote` por HTTP sin cifrar:** `{m.group(1)}`; la definición del pipeline puede ser alterada en tránsito."})
    return out


# --------------------------------------------------------------------------- API orchestration
class _Api:
    def __init__(self, base: str, token: str):
        self.base, self.h = base.rstrip("/"), {"PRIVATE-TOKEN": token}

    def get(self, path: str, params: Optional[dict] = None):
        """JSON on 200, None on any failure (404/403/network) -- caller treats None as not-evaluable."""
        try:
            r = requests.get(f"{self.base}/api/v4{path}", headers=self.h, params=params or {}, timeout=20)
        except requests.RequestException:
            print(f"❌ [GitLab-Config] request failed: {path}")
            traceback.print_exc()
            return None
        if r.status_code == 200:
            return r.json()
        if r.status_code not in (403, 404):
            print(f"⚠️ [GitLab-Config] {path} -> HTTP {r.status_code}")
        return None


def audit_project(project: Dict[str, Any], repo_dir: Optional[str], gitlab_url: Optional[str] = None,
                  token: Optional[str] = None) -> Dict[str, Any]:
    """Returns {"findings": [...], "complete": bool, "not_evaluated": [...]}."""
    api = _Api(gitlab_url or os.getenv("GITLAB_URL", "http://192.0.2.12"), token or os.getenv("GITLAB_TOKEN", ""))
    pid = project["id"]
    not_eval: List[str] = []
    prot = api.get(f"/projects/{pid}/protected_branches")
    hooks = api.get(f"/projects/{pid}/hooks")
    variables = api.get(f"/projects/{pid}/variables")
    for name, val in (("protected_branches", prot), ("hooks", hooks), ("variables", variables)):
        if val is None:
            not_eval.append(name)

    has_ci: Optional[bool] = None
    ci_text = ""
    if repo_dir and os.path.isdir(repo_dir):
        ci_path = os.path.join(repo_dir, ".gitlab-ci.yml")
        has_ci = os.path.isfile(ci_path)
        if has_ci:
            with open(ci_path, "r", encoding="utf-8", errors="replace") as fh:
                ci_text = fh.read()
    else:
        not_eval.append("ci_file")

    findings = evaluate_project_settings(project, prot, hooks, variables, has_ci)
    if ci_text:
        findings.extend(evaluate_ci_file(ci_text))
    return {"findings": findings, "complete": not not_eval, "not_evaluated": not_eval}


def log_gitlab_config_findings(asset_id: str, project_path: str, result: Dict[str, Any]) -> int:
    from core import db_manager, deduplication_engine
    with db_manager.get_db_cursor() as cur:
        marker = (f"Auditoría de configuración GitLab de {project_path}: {len(result['findings'])} hallazgo(s)"
                  + ("" if result["complete"] else f"; NO evaluado: {', '.join(result['not_evaluated'])}") + ".")
        deduplication_engine.log_finding_deduplicated(
            cur, asset_id, MARKER_CVE, "Info", marker, SCAN_ENGINE, url_path=MARKER_CVE,
            open_status="NEW", preserve_status=True)
        active = {deduplication_engine.calculate_fingerprint(asset_id, MARKER_CVE, MARKER_CVE)}
        for f in result["findings"]:
            active.add(deduplication_engine.calculate_fingerprint(asset_id, f["cve_id"], f["url_path"]))
            deduplication_engine.log_finding_deduplicated(
                cur, asset_id, f["cve_id"], f["severity"], f["description"], SCAN_ENGINE,
                url_path=f["url_path"], open_status="OPEN", preserve_status=True)
        if result["complete"]:   # a partial view must never close findings it simply couldn't see
            deduplication_engine.reconcile_resolved_findings(cur, asset_id, SCAN_ENGINE, active)
    return len(result["findings"])
