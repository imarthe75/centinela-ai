"""Per-project / per-group data access administration (ADR-0019, phase 1).

Grants live in public.access_scopes: a user (preferred_username or e-mail) or an Authentik group may see the assets equal to or below
an asset prefix. Only Admins (group "Centinela Admin") and the service token manage grants; anyone can read their own scope.
"""
import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from core import access_scope, agent_ledger, auth, db_manager

logger = logging.getLogger(__name__)
router = APIRouter()


class AccessScopeIn(BaseModel):
    """A grant: `subject_type` user|group, `subject` (username/e-mail or group name) and the asset prefix it may see."""
    subject_type: str = Field(..., pattern="^(user|group)$")
    subject: str = Field(..., min_length=1, max_length=200)
    asset_prefix: str = Field(..., min_length=1, max_length=500)
    note: Optional[str] = Field(None, max_length=500)


def _caller(request: Request) -> Optional[dict]:
    return getattr(request.state, "user", None)


def _require_admin(request: Request) -> str:
    """Name of the admin caller, or 403. With API auth off (tests, local) there is no caller to check."""
    if auth.mode() == "off":
        return "auth-off"
    claims = _caller(request)
    if claims and (claims.get("sub") == "service-token" or auth.is_admin(claims)):
        return str(claims.get("preferred_username") or claims.get("email") or claims.get("sub"))
    raise HTTPException(status_code=403, detail="Solo un administrador gestiona los alcances de datos.")


@router.get("/api/access-scopes/me", summary="Alcance de datos del usuario actual")
def my_access_scope(request: Request):
    """`unrestricted` true for Admins, the service token and users with no grant while ACCESS_SCOPE_DEFAULT=all; else the prefixes."""
    scope = access_scope.resolve(_caller(request))
    return {"unrestricted": scope is access_scope.UNRESTRICTED, "prefixes": [] if scope is None else scope,
            "default_policy": access_scope.default_policy()}


@router.get("/api/access-scopes", summary="Listar alcances de datos (Admin)")
def list_access_scopes(request: Request):
    """Every grant, newest first."""
    _require_admin(request)
    with db_manager.get_db_cursor() as cur:
        cur.execute("""SELECT id::text, subject_type, subject, asset_prefix, note, created_by, created_at
                         FROM public.access_scopes ORDER BY created_at DESC""")
        cols = [d[0] for d in cur.description]
        rows = [dict(zip(cols, r)) for r in cur.fetchall()]
    for r in rows:
        r["created_at"] = r["created_at"].isoformat() if r.get("created_at") else None
    return {"default_policy": access_scope.default_policy(), "scopes": rows}


@router.post("/api/access-scopes", summary="Otorgar alcance de datos (Admin)")
def create_access_scope(body: AccessScopeIn, request: Request):
    """Grants `subject` the assets equal to or below `asset_prefix`. 409 when the same grant already exists."""
    who = _require_admin(request)
    prefix = body.asset_prefix.strip().rstrip("/")
    with db_manager.get_db_cursor() as cur:
        cur.execute("""INSERT INTO public.access_scopes (subject_type, subject, asset_prefix, note, created_by)
                       VALUES (%s, %s, %s, %s, %s) ON CONFLICT (subject_type, subject, asset_prefix) DO NOTHING RETURNING id::text""",
                    (body.subject_type, body.subject.strip(), prefix, body.note, who))
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=409, detail="Ese alcance ya existe.")
        cur.execute("SELECT count(*) FROM public.infra_inventory WHERE asset_name = %s OR asset_name LIKE %s OR asset_name LIKE %s",
                    (prefix, prefix + "/%", prefix + "@%"))
        matched = cur.fetchone()[0]
    access_scope.invalidate()
    agent_ledger.record_action("access_scope_granted", f"Alcance {prefix} para {body.subject_type} {body.subject}",
                               entity_type="access_scope", entity_id=row[0], actor=who)
    return {"id": row[0], "asset_prefix": prefix, "matching_assets": matched}


@router.delete("/api/access-scopes/{scope_id}", summary="Retirar alcance de datos (Admin)")
def delete_access_scope(scope_id: str, request: Request):
    """Removes one grant. 404 when it does not exist."""
    who = _require_admin(request)
    with db_manager.get_db_cursor() as cur:
        cur.execute("DELETE FROM public.access_scopes WHERE id::text = %s RETURNING subject_type, subject, asset_prefix", (scope_id,))
        row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Alcance no encontrado.")
    access_scope.invalidate()
    agent_ledger.record_action("access_scope_revoked", f"Retirado {row[2]} de {row[0]} {row[1]}", entity_type="access_scope",
                               entity_id=scope_id, actor=who)
    return {"deleted": scope_id}
