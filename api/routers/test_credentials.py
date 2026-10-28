"""Test credentials per application profile (role). Secrets go to Vault only and are never returned.

  GET    /api/test-credentials?asset_name=            profiles discovered in the code/seeds + what is configured (usernames, has_password)
  GET    /api/test-credentials/candidates?q=          repositories that can be used as a source of profiles
  PUT    /api/test-credentials/config                 base URL + shared login of the application + source repositories
  PUT    /api/test-credentials/role                   username / password of one profile
  DELETE /api/test-credentials/role?asset_name=&role= remove one profile
  GET    /api/test-credentials/openapi-profiles?asset_name=&url=  profiles named by the app's OpenAPI document (apps with no code in the inventory)
  POST   /api/test-credentials/test-login?asset_name=&role=  try the API login of one profile (answers ok/not ok, never the token)
Writes need an Admin in `enforce` mode (core/auth.py); in `log`/`off` mode they are allowed and the access is only recorded.
"""
import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from core import agent_ledger, auth, db_manager, openapi_profiles, test_credentials as tc

router = APIRouter()
logger = logging.getLogger(__name__)


def _guard(request: Request) -> str:
    claims = getattr(request.state, "user", None)
    if auth.mode() == "enforce" and not auth.is_admin(claims):
        raise HTTPException(status_code=403, detail="Solo un administrador puede gestionar credenciales de prueba")
    return (claims or {}).get("preferred_username") or (claims or {}).get("email") or (claims or {}).get("sub") or "anonymous"


def _asset(cur, name: str) -> Dict[str, Any]:
    cur.execute("SELECT id, asset_name, asset_type FROM public.infra_inventory WHERE asset_name = %s", (name,))
    row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Activo no encontrado")
    return {"id": str(row[0]), "asset_name": row[1], "asset_type": row[2]}


def _profiles(cur, asset_id: str, source_names: List[str]) -> List[Dict[str, Any]]:
    cur.execute("""SELECT r.role_name, r.source, r.source_file, i.asset_name FROM public.asset_auth_roles r JOIN public.infra_inventory i ON i.id = r.asset_id
                   WHERE r.asset_id = %s OR i.asset_name = ANY(%s) ORDER BY r.source, lower(r.role_name)""", (asset_id, source_names or [""]))
    seen, out = set(), []
    for name, source, file, origin in cur.fetchall():
        if name.lower() in seen:
            continue
        seen.add(name.lower())
        out.append({"role": name, "source": source, "file": file, "from_asset": origin})
    return out


def _vault_error(e: Exception) -> HTTPException:
    if isinstance(e, tc.CredentialsError):
        return HTTPException(status_code=400, detail=str(e))
    logger.error("test credentials: Vault operation failed", exc_info=True)
    return HTTPException(status_code=502, detail="No se pudo completar la operación en Vault")


@router.get("/api/test-credentials")
def get_test_credentials(asset_name: str):
    with db_manager.get_db_cursor() as cur:
        asset = _asset(cur, asset_name)
        try:
            cfg = tc.describe(asset_name)
        except Exception as e:
            raise _vault_error(e)
        profiles = _profiles(cur, asset["id"], cfg.get("source_assets", []))
    return {"asset_name": asset_name, "asset_type": asset["asset_type"], "config": cfg, "profiles": profiles}


@router.get("/api/test-credentials/candidates")
def credential_source_candidates(q: str = "", limit: int = 30):
    with db_manager.get_db_cursor() as cur:
        cur.execute("""SELECT i.asset_name, (SELECT count(*) FROM public.asset_auth_roles r WHERE r.asset_id = i.id) AS roles
                       FROM public.infra_inventory i WHERE i.asset_type = 'GitLab-Repo' AND i.asset_name ILIKE %s ORDER BY roles DESC, i.asset_name LIMIT %s""",
                    (f"%{q}%", max(1, min(limit, 100))))
        return [{"asset_name": r[0], "profiles": r[1]} for r in cur.fetchall()]


class AppLogin(BaseModel):
    url: str = ""
    method: str = "POST"
    body: str = "json"
    username_field: str = "username"
    password_field: str = "password"
    token_json_path: str = "access_token"
    token_header: str = ""
    extra_fields: Dict[str, str] = {}


class LoginUi(BaseModel):
    url: str = ""
    routes: List[str] = []
    user_selector: str = ""
    pass_selector: str = ""
    submit_selector: str = ""


class AuthzScope(BaseModel):
    endpoints: List[str] = []
    openapi_url: str = ""
    admin_only: List[str] = []


class ConfigBody(BaseModel):
    asset_name: str
    base_url: str = ""
    app_login: Optional[AppLogin] = None
    login_ui: Optional[LoginUi] = None
    authz: Optional[AuthzScope] = None
    source_assets: List[str] = []


class RoleBody(BaseModel):
    asset_name: str
    role: str
    username: str
    password: str = ""
    kind: str = "user"


@router.put("/api/test-credentials/config")
def put_config(body: ConfigBody, request: Request):
    actor = _guard(request)
    with db_manager.get_db_cursor() as cur:
        _asset(cur, body.asset_name)
    try:
        tc.set_app_config(body.asset_name, body.base_url, body.app_login.dict() if body.app_login else None,
                          login_ui=body.login_ui.dict() if body.login_ui else None,
                          authz=body.authz.dict() if body.authz else None)
        tc.set_source_assets(body.asset_name, body.source_assets)
    except Exception as e:
        raise _vault_error(e)
    agent_ledger.record_action(agent_ledger.ACTION_TEST_CREDENTIALS, f"Configuración de acceso de pruebas actualizada para {body.asset_name}", actor=actor,
                               entity_type="asset", detail={"what": "config"})
    return {"status": "ok"}


@router.put("/api/test-credentials/role")
def put_role(body: RoleBody, request: Request):
    actor = _guard(request)
    with db_manager.get_db_cursor() as cur:
        _asset(cur, body.asset_name)
    try:
        tc.upsert_role(body.asset_name, body.role, body.username, body.password, body.kind)
    except Exception as e:
        raise _vault_error(e)
    agent_ledger.record_action(agent_ledger.ACTION_TEST_CREDENTIALS, f"Credencial de prueba guardada para el perfil '{body.role}' de {body.asset_name}", actor=actor,
                               entity_type="asset", detail={"what": "role", "role": body.role})   # never the username's password
    return {"status": "ok"}


@router.delete("/api/test-credentials/role")
def delete_role(asset_name: str, role: str, request: Request):
    actor = _guard(request)
    with db_manager.get_db_cursor() as cur:
        _asset(cur, asset_name)
    try:
        removed = tc.delete_role(asset_name, role)
    except Exception as e:
        raise _vault_error(e)
    if not removed:
        raise HTTPException(status_code=404, detail="Ese perfil no tiene credenciales guardadas")
    agent_ledger.record_action(agent_ledger.ACTION_TEST_CREDENTIALS, f"Credencial de prueba eliminada del perfil '{role}' de {asset_name}", actor=actor,
                               entity_type="asset", detail={"what": "role_deleted", "role": role})
    return {"status": "ok"}


@router.post("/api/test-credentials/test-login")
def test_login(asset_name: str, role: str, request: Request):
    _guard(request)
    with db_manager.get_db_cursor() as cur:
        _asset(cur, asset_name)
    try:
        return tc.test_login(asset_name, role)
    except Exception as e:
        raise _vault_error(e)


@router.get("/api/test-credentials/openapi-profiles")
def profiles_from_openapi(asset_name: str, url: Optional[str] = None):
    """Profiles named by the OpenAPI document (configured one, or `url`): for applications with no code in the inventory."""
    with db_manager.get_db_cursor() as cur:
        _asset(cur, asset_name)
    try:
        target = url or tc.describe(asset_name).get("authz", {}).get("openapi_url") or ""
        if not target:
            raise HTTPException(status_code=400, detail="Indica la URL de OpenAPI/Swagger del aplicativo")
        return {"url": target, "profiles": openapi_profiles.fetch_profiles(target)}
    except HTTPException:
        raise
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception:
        logger.error("openapi profile discovery failed for %s", asset_name, exc_info=True)
        raise HTTPException(status_code=502, detail="No se pudo leer el documento OpenAPI")
