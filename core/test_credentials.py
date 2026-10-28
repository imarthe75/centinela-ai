"""
Per-application test credentials, one set per profile (role), stored ONLY in Vault: `<namespace>/authz/<asset>`.

The implementation lives in `centinela_core.test_credentials` (shared library, submodule `libs/centinela-core`, see
DECISIONS/0015). This module keeps Centinela's import path and two Centinela-specific pieces:
  * `vault_client()` stays here so callers and tests can patch `core.test_credentials.vault_client`;
  * `test_login()` uses this platform's authorization auditor.
Use `update_authz()` (partial) from scripts; `set_app_config()` is a FULL replace and removes app_login/login_ui passed as None.
"""
import sys
from typing import Any, Dict

from centinela_core import test_credentials as _core
from centinela_core.test_credentials import (  # noqa: F401  (re-exported API)
    CredentialsError, _clean_login_ui, _derive_login, _write, delete_role, describe, get_profile, read_raw, set_app_config,
    set_source_assets, update_authz, upsert_role, vault_key,
)

from core import org_config


def vault_client():
    return _core.default_vault_client()


def _path(asset_name: str) -> str:
    return _core.vault_path(asset_name)


# The library resolves the client through this module at call time, so patching `vault_client` here still works.
_core.configure(namespace=org_config.VAULT_NAMESPACE, client_factory=lambda: sys.modules[__name__].vault_client())


def test_login(asset_name: str, role: str, client=None) -> Dict[str, Any]:
    """Try the API login of one profile and report whether a token came back. Never returns the token or the password."""
    from auditors import auditor_authz_dast as dast
    data = read_raw(asset_name, client)
    entry = next((r for r in data.get("roles", []) if (r.get("name") or "").lower() == (role or "").lower()), None)
    if not entry:
        raise CredentialsError("Ese perfil no tiene credenciales guardadas")
    if not entry.get("login"):
        raise CredentialsError("Falta la configuración del inicio de sesión del aplicativo (URL, campos): guárdala primero")
    token = dast._resolve_token(entry)
    return {"ok": bool(token), "detail": "Se obtuvo un token de sesión" if token else "El inicio de sesión no devolvió un token (revisa usuario, contraseña, campos y la ruta del token)"}
