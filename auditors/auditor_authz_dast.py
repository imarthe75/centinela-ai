"""
Centinela-AI — Authenticated Multi-Role Authorization DAST  (scan_engine: authz-dast)

The runtime confirmation for OWASP A01 / API1+API5 (Broken Access Control / BOLA /
Broken Function Level Authorization). This is what actually reproduces what a pentester
does by hand: log in as several accounts of different privilege, replay the same requests
with each, and flag any endpoint a low-privilege account reaches that it shouldn't.

Needs credentials. It reads a per-asset config; if none exists it logs an honest "skipped —
no multi-role credentials configured" and does nothing (same pattern as CIS Benchmarks when
no SSH credentials are in Vault). See DECISIONS/0005 for the config contract and the
provisioning decision.

Config (Vault `secret/casmarts/authz/{asset_name}`, KV v2 with v1 fallback; or a JSON file at
$CENTINELA_AUTHZ_CONFIG_DIR/{asset_name}.json):

  {
    "base_url": "https://sideco.edomex.gob.mx/wsbev1",
    "roles": [
      {"name": "admin",      "kind": "admin", "token": "eyJ..."},
      {"name": "conciliador","kind": "user",  "login": {
          "url": "https://.../oauth/token",
          "method": "POST",
          "form": {"grant_type":"password","username":"TcsCSA2","password":"...","client_id":"..."},
          "token_json_path": "access_token"
      }}
    ],
    "endpoints": ["/api/usr/getUsuarios/1", "/api/catalogos/roles", ...],   // optional
    "openapi_url": "https://.../v2/api-docs",                               // optional
    "access_model": {                                                      // optional
        "admin_only":     ["*/usr/*", "*/catalogos/roles*", "*/permisos*", "*/catMenu*"],
        "authenticated":  ["*/**"],
        "public":         ["*/mail/*", "*/comunicados/*"]
    },
    "allow_mutating_probes": false,     // default false -> only GET is replayed
    "idor_probe": true                  // default true  -> vary {id} path params, GET only
  }

Findings:
  AUTHZ-DAST-BROKEN-FUNCTION-LEVEL   CRITICAL  a non-admin role got 2xx on an admin-only endpoint
  AUTHZ-DAST-IDOR                    HIGH      as role A, changing an id path param returned 2xx + different body
  AUTHZ-DAST-DENY-LEAKS-BODY        MEDIUM    a 401/403 response still returned a substantial JSON payload
  AUTHZ-DAST-INCONSISTENT-STATUS    MEDIUM    same endpoint: some sensitive sibling 403s for role A while this one 200s
  AUTHZ-DAST-NO-CREDS               INFO      (marker) auditor ran but no multi-role config -> not exercised
"""
from __future__ import annotations

import fnmatch
import json
import os
import re
import time
from typing import Any, Dict, List, Optional

import requests

try:
    from core import db_manager, deduplication_engine
except Exception:  # pragma: no cover
    db_manager = None
    deduplication_engine = None

_SCAN_ENGINE = "authz-dast"
_TIMEOUT = 12
_MAX_ENDPOINTS = 400
_DENY = {401, 403}
_OK = range(200, 300)

_DEFAULT_ADMIN_ONLY = [
    "*/usr/*", "*/usuarios*", "*/getUsuarios*", "*/guardarUsuarios*",
    "*/catalogos/roles*", "*/catRoles*", "*/rolesWith*", "*/saveRolMenu*",
    "*/permisos*", "*/obtenerPermisos*", "*/catMenu*", "*/admin/*", "*/administracion/*",
    "*/asignarRol*", "*/accesoSistema*", "*/resetPassword*",
]
_ID_PARAM_RE = re.compile(r"/(\d{1,10})(?=/|$)")


# --------------------------------------------------------------------------- config
def _load_config(asset_name: str) -> Optional[dict]:
    # 1. local JSON (dev / air-gapped)
    cfg_dir = os.getenv("CENTINELA_AUTHZ_CONFIG_DIR", "/app/data/authz")
    p = os.path.join(cfg_dir, f"{re.sub(r'[^A-Za-z0-9._-]', '_', asset_name)}.json")
    if os.path.isfile(p):
        try:
            return json.load(open(p, encoding="utf-8"))
        except Exception as e:
            print(f"⚠️ [Authz-DAST] Bad config file {p}: {e}")
    # 2. Vault
    try:
        import main as _m
        client = _m.get_vault_client()
        if client:
            for reader in (
                lambda: client.secrets.kv.v2.read_secret_version(path=f"casmarts/authz/{asset_name}", mount_point="secret")["data"]["data"],
                lambda: client.secrets.kv.v1.read_secret(path=f"casmarts/authz/{asset_name}", mount_point="secret")["data"],
            ):
                try:
                    data = reader()
                    if isinstance(data.get("config"), str):
                        return json.loads(data["config"])
                    return data
                except Exception:
                    continue
    except Exception:
        pass

    # 3. PostgreSQL cat_asset_credentials table (fallback)
    if db_manager:
        try:
            with db_manager.get_db_cursor() as cur:
                cur.execute("""
                    SELECT config_json FROM public.cat_asset_credentials
                    WHERE asset_name = %s
                    LIMIT 1;
                """, (asset_name,))
                row = cur.fetchone()
                if row:
                    return row[0] if isinstance(row[0], dict) else json.loads(row[0])
        except Exception as db_err:
            print(f"⚠️ [Authz-DAST] Could not load config from cat_asset_credentials: {db_err}")

    return None


def _resolve_token(role: dict) -> Optional[str]:
    if role.get("token"):
        return role["token"].strip()
    login = role.get("login")
    if not login:
        return None
    try:
        method = (login.get("method") or "POST").upper()
        kw = {"timeout": _TIMEOUT, "verify": login.get("verify", False)}
        if login.get("form"):
            kw["data"] = login["form"]
        elif login.get("json"):
            kw["json"] = login["json"]
        if login.get("headers"):
            kw["headers"] = login["headers"]
        if login.get("basic"):
            kw["auth"] = tuple(login["basic"])
        r = requests.request(method, login["url"], **kw)
        if r.status_code not in _OK:
            print(f"⚠️ [Authz-DAST] login for role '{role.get('name')}' -> HTTP {r.status_code}")
            return None
        body = r.json()
        path = (login.get("token_json_path") or "access_token").split(".")
        for k in path:
            body = body[k]
        return str(body)
    except Exception as e:
        print(f"⚠️ [Authz-DAST] login failed for role '{role.get('name')}': {e}")
        return None


# --------------------------------------------------------------------------- endpoints
def _endpoints_from_openapi(spec_url: str) -> List[dict]:
    try:
        r = requests.get(spec_url, timeout=_TIMEOUT, verify=False)
        if r.status_code not in _OK:
            return []
        spec = r.json()
        base = ""
        if spec.get("basePath"):
            base = spec["basePath"].rstrip("/")
        elif spec.get("servers"):
            base = (spec["servers"][0].get("url") or "").rstrip("/")
        out = []
        for path, ops in (spec.get("paths") or {}).items():
            for method, op in ops.items():
                if method.lower() not in ("get", "post", "put", "delete", "patch"):
                    continue
                # required role from OpenAPI security / x-required-role, if present
                req_role = op.get("x-required-role")
                out.append({"path": base + path, "method": method.upper(),
                            "required_role": req_role})
        return out
    except Exception as e:
        print(f"⚠️ [Authz-DAST] OpenAPI fetch failed ({spec_url}): {e}")
        return []


def _endpoints_from_static(asset_id: Optional[int]) -> List[dict]:
    """Reuse the routes the static authz auditor already discovered for this asset."""
    if asset_id is None or db_manager is None:
        return []
    try:
        with db_manager.get_db_cursor() as cur:
            cur.execute(
                "SELECT description, url_path FROM vulnerability_log "
                "WHERE asset_id=%s AND scan_engine='authz-static' AND status NOT IN ('RESOLVED','SUPPRESSED')",
                (asset_id,))
            eps = []
            for desc, _ in cur.fetchall():
                m = re.search(r"`([A-Z]+) (/[^`]+)`", desc or "")
                if m:
                    eps.append({"path": m.group(2), "method": m.group(1), "required_role": None})
            return eps
    except Exception:
        return []


# --------------------------------------------------------------------------- probing
def _classify(path: str, model: Optional[dict], static_flagged: set) -> str:
    """Return 'admin_only' | 'authenticated' | 'public' | 'unknown'."""
    if any(fnmatch.fnmatch(path, g) for g in (model or {}).get("public", [])):
        return "public"
    if any(fnmatch.fnmatch(path, g) for g in (model or {}).get("admin_only", _DEFAULT_ADMIN_ONLY)):
        return "admin_only"
    if path in static_flagged:
        return "admin_only"
    if any(fnmatch.fnmatch(path, g) for g in (model or {}).get("authenticated", [])):
        return "authenticated"
    return "unknown"


def _req(session_token: str, base: str, ep: dict, allow_mut: bool):
    url = base.rstrip("/") + "/" + ep["path"].lstrip("/")
    method = ep["method"]
    if method != "GET" and not allow_mut:
        return None
    try:
        r = requests.request(method, url, headers={"Authorization": f"Bearer {session_token}",
                                                   "Accept": "application/json"},
                             timeout=_TIMEOUT, verify=False, allow_redirects=False)
        return r
    except Exception:
        return None


def _looks_like_data(text: str) -> bool:
    t = (text or "").strip()
    if len(t) < 40:
        return False
    if not (t.startswith("{") or t.startswith("[")):
        return False
    return bool(re.search(r'"(id|nombre|correo|email|rol|role|usuario|password|curp|domicilio)"', t, re.I))


def run_authz_dast(asset_id: int, asset_name: str, base_url: str = None) -> List[Dict[str, Any]]:
    cfg = _load_config(asset_name)
    findings: List[dict] = []

    if not cfg or not cfg.get("roles"):
        _persist([{
            "cve_id": "AUTHZ-DAST-NO-CREDS", "severity": "INFO", "url_path": "authz-dast:config",
            "description": ("Prueba de autorización autenticada multi-rol NO ejecutada: no hay "
                            f"credenciales configuradas para `{asset_name}` (Vault "
                            f"`secret/casmarts/authz/{asset_name}` o "
                            f"`$CENTINELA_AUTHZ_CONFIG_DIR/{asset_name}.json`). Este es el único control "
                            "que confirma en vivo una escalación de privilegios como la del retest de "
                            "SIDECO. Ver DECISIONS/0005 para el contrato de configuración."),
        }], asset_id)
        print(f"ℹ️ [Authz-DAST] {asset_name}: no multi-role config — skipped (marker written).")
        return findings

    base = (cfg.get("base_url") or base_url or "").rstrip("/")
    if not base:
        print(f"⚠️ [Authz-DAST] {asset_name}: no base_url — skipped.")
        return findings

    model = cfg.get("access_model")
    allow_mut = bool(cfg.get("allow_mutating_probes", False))
    do_idor = bool(cfg.get("idor_probe", True))

    # resolve sessions
    roles = []
    for r in cfg["roles"]:
        tok = _resolve_token(r)
        if tok:
            roles.append({"name": r.get("name", "role"), "kind": (r.get("kind") or "user").lower(), "token": tok})
    if len({rl["kind"] for rl in roles}) < 2 and not any(rl["kind"] == "admin" for rl in roles):
        print(f"⚠️ [Authz-DAST] {asset_name}: need at least one admin and one non-admin session; got {[r['kind'] for r in roles]}.")
        return findings
    non_admin = [r for r in roles if r["kind"] != "admin"]
    admins = [r for r in roles if r["kind"] == "admin"]

    # endpoints
    eps: List[dict] = []
    for e in (cfg.get("endpoints") or []):
        eps.append({"path": e if isinstance(e, str) else e.get("path"),
                    "method": (e.get("method") if isinstance(e, dict) else "GET") or "GET",
                    "required_role": (e.get("required_role") if isinstance(e, dict) else None)})
    if cfg.get("openapi_url"):
        eps += _endpoints_from_openapi(cfg["openapi_url"])
    if not eps:
        eps = _endpoints_from_static(asset_id)
    # de-dup
    seen = set(); uniq = []
    for e in eps:
        k = (e["method"], e["path"])
        if e["path"] and k not in seen:
            seen.add(k); uniq.append(e)
    eps = uniq[:_MAX_ENDPOINTS]
    if not eps:
        print(f"⚠️ [Authz-DAST] {asset_name}: no endpoints (config/openapi/static all empty) — skipped.")
        return findings

    static_flagged = {e["path"] for e in _endpoints_from_static(asset_id)}
    print(f"🔐 [Authz-DAST] {asset_name}: {len(eps)} endpoints × {len(roles)} roles "
          f"({[r['name'] for r in roles]}), base={base}")

    for ep in eps:
        cls = _classify(ep["path"], model, static_flagged)
        if ep.get("required_role") == "admin":
            cls = "admin_only"
        if cls == "public":
            continue

        # baseline: does an admin actually get in? (skip if the endpoint is just broken)
        adm_ok = None
        if admins:
            ra = _req(admins[0]["token"], base, ep, allow_mut)
            adm_ok = ra is not None and ra.status_code in _OK

        for role in non_admin:
            rr = _req(role["token"], base, ep, allow_mut)
            if rr is None:
                continue
            body = rr.text[:4000]

            if cls == "admin_only" and rr.status_code in _OK and (adm_ok is None or adm_ok):
                findings.append({
                    "cve_id": "AUTHZ-DAST-BROKEN-FUNCTION-LEVEL", "severity": "CRITICAL",
                    "url_path": f"{ep['method']} {ep['path']}",
                    "description": (f"El rol **{role['name']}** (no administrador) recibió **HTTP "
                                    f"{rr.status_code}** en `{ep['method']} {ep['path']}`, un endpoint "
                                    f"que debe ser solo de administrador"
                                    + (" (marcado por el análisis estático como inconsistente)"
                                       if ep['path'] in static_flagged else "")
                                    + f". Escalación de privilegios confirmada en vivo. "
                                    + (f"Respuesta con datos: {body[:200]}…" if _looks_like_data(body) else "")),
                })
            elif cls == "unknown" and rr.status_code in _OK and _looks_like_data(body) and adm_ok:
                findings.append({
                    "cve_id": "AUTHZ-DAST-INCONSISTENT-STATUS", "severity": "MEDIUM",
                    "url_path": f"{ep['method']} {ep['path']}",
                    "description": (f"El rol **{role['name']}** recibió HTTP {rr.status_code} con un cuerpo "
                                    f"que parece contener datos en `{ep['method']} {ep['path']}` y no hay un "
                                    f"modelo de acceso que lo autorice explícitamente. Verificar si debería "
                                    f"requerir rol."),
                })

            if rr.status_code in _DENY and _looks_like_data(body):
                findings.append({
                    "cve_id": "AUTHZ-DAST-DENY-LEAKS-BODY", "severity": "MEDIUM",
                    "url_path": f"{ep['method']} {ep['path']}",
                    "description": (f"`{ep['method']} {ep['path']}` devolvió **{rr.status_code}** al rol "
                                    f"{role['name']}, pero el cuerpo de la respuesta aún trae datos "
                                    f"(≈{len(body)} bytes JSON). Un 401/403 no debe filtrar el payload — "
                                    f"habilita el bypass reescribiendo solo la línea de estado."),
                })

            # IDOR: vary a numeric id in the path, GET only
            if do_idor and ep["method"] == "GET" and rr.status_code in _OK and _ID_PARAM_RE.search(ep["path"]):
                m = _ID_PARAM_RE.search(ep["path"])
                orig = int(m.group(1))
                base_body = body
                for cand in {orig + 1, orig + 2, max(1, orig - 1), 1, 2}:
                    if cand == orig:
                        continue
                    alt_path = ep["path"][:m.start(1)] + str(cand) + ep["path"][m.end(1):]
                    ar = _req(role["token"], base, {"path": alt_path, "method": "GET"}, allow_mut)
                    if ar is not None and ar.status_code in _OK and _looks_like_data(ar.text) \
                            and ar.text[:500] != base_body[:500]:
                        findings.append({
                            "cve_id": "AUTHZ-DAST-IDOR", "severity": "HIGH",
                            "url_path": f"GET {alt_path}",
                            "description": (f"Como rol **{role['name']}**, cambiar el identificador en la ruta "
                                            f"`{ep['path']}` → `{alt_path}` devolvió HTTP {ar.status_code} con "
                                            f"datos distintos. El endpoint no valida que el recurso pertenezca "
                                            f"a quien lo pide (IDOR / BOLA — OWASP API1:2023)."),
                        })
                        break
            time.sleep(0.05)

    _persist(findings, asset_id)
    print(f"🔐 [Authz-DAST] {asset_name}: {len(findings)} authorization finding(s).")
    return findings


def _persist(findings: List[dict], asset_id: Optional[int]) -> None:
    if asset_id is None or db_manager is None or deduplication_engine is None:
        return
    try:
        active = set()
        with db_manager.get_db_cursor() as cur:
            for it in findings:
                loc = it["url_path"]
                active.add(deduplication_engine.calculate_fingerprint(asset_id, it["cve_id"], loc))
                deduplication_engine.log_finding_deduplicated(
                    cur, asset_id, it["cve_id"], it["severity"], it["description"],
                    _SCAN_ENGINE, url_path=loc, open_status="OPEN", preserve_status=True,
                )
            n = deduplication_engine.reconcile_resolved_findings(cur, asset_id, _SCAN_ENGINE, active)
            if n:
                print(f"✅ [Authz-DAST] Reconciled {n} stale authz-dast finding(s) for asset {asset_id}.")
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"⚠️ [Authz-DAST] persist failed: {e}")


def run(asset_id: int, endpoint: str = None):
    """auditor_ext-style entrypoint."""
    name = None
    if db_manager is not None:
        try:
            with db_manager.get_db_cursor() as cur:
                cur.execute("SELECT asset_name FROM infra_inventory WHERE id=%s", (asset_id,))
                row = cur.fetchone()
                name = row[0] if row else None
        except Exception:
            pass
    return run_authz_dast(asset_id, name or f"asset-{asset_id}", base_url=endpoint)


if __name__ == "__main__":
    import sys
    aid = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    nm = sys.argv[2] if len(sys.argv) > 2 else "manual-test"
    for f in run_authz_dast(aid or None, nm):
        print(f"[{f['severity']}] {f['cve_id']}  {f['url_path']}")
