"""Test credentials per application profile + role discovery.
The Vault here is an in-memory fake (VALIDATED WITH A FAKE VAULT ONLY: the real Vault write path is exercised separately by hand);
the database is the disposable test database and every row is rolled back."""
import os
import tempfile
import unittest
import uuid
from unittest import mock

from fastapi.testclient import TestClient

from auditors import role_discovery as rd
from core import db_manager, test_credentials as tc


class FakeVault:
    class _V2:
        def __init__(self):
            self.store = {}

        def read_secret_version(self, path, mount_point="secret", raise_on_deleted_version=True):
            if path not in self.store:
                class InvalidPath(Exception):
                    pass
                raise InvalidPath()
            return {"data": {"data": dict(self.store[path])}}

        def create_or_update_secret(self, path, secret, mount_point="secret"):
            self.store[path] = dict(secret)

    def __init__(self):
        v2 = self._V2()
        self.secrets = type("S", (), {"kv": type("K", (), {"v2": v2})()})()
        self.store = v2.store


def _tree(files):
    d = tempfile.mkdtemp()
    for name, text in files.items():
        p = os.path.join(d, name)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        open(p, "w", encoding="utf-8").write(text)
    return d


class TestRoleDiscovery(unittest.TestCase):
    def roles(self, files):
        return {(r["source"], r["role"]) for r in rd.discover_roles(_tree(files))}

    def test_sql_seed_with_column_list(self):
        r = self.roles({"db/1.sql": "INSERT INTO public.ct_roles (id, dsrol) VALUES (1, 'Super Administrador'), (2, 'O''Brien Revisor');\n"})
        self.assertIn(("sql", "Super Administrador"), r)
        self.assertIn(("sql", "O'Brien Revisor"), r)

    def test_sql_without_column_list_uses_first_string(self):
        self.assertIn(("sql", "Capturista"), self.roles({"a.sql": "INSERT INTO ct_perfiles VALUES (4, 'Capturista');\n"}))

    def test_unrelated_tables_are_ignored(self):
        self.assertEqual(self.roles({"a.sql": "INSERT INTO ct_clientes (id, nombre) VALUES (1, 'Acme');\n"}), set())

    def test_spring_security_calls(self):
        r = self.roles({"A.java": '@PreAuthorize("hasAnyAuthority(\'ADMIN\', \'AUDITOR\')")\n@Secured("ROLE_OPERADOR")\nx.hasRole("SUPERVISOR");\n'})
        self.assertTrue({("java-auth", "ADMIN"), ("java-auth", "AUDITOR"), ("java-auth", "ROLE_OPERADOR"), ("java-auth", "SUPERVISOR")} <= r)

    def test_constants_and_frontend_roles(self):
        r = self.roles({"C.java": "public static final Long ID_ROL_OFICIAL_DE_PARTES = 5L;\n", "app.routes.ts": "data: { roles: ['Analista', \"Gestor\"] }\n"})
        self.assertIn(("constant", "Oficial De Partes"), r)
        self.assertTrue({("frontend", "Analista"), ("frontend", "Gestor")} <= r)

    def test_node_modules_and_nothing_found(self):
        self.assertEqual(self.roles({"node_modules/x/a.ts": "roles: ['Hidden']", "README.md": "hasRole('X')"}), set())


class TestCredentialStore(unittest.TestCase):
    def setUp(self):
        self.v = FakeVault()
        self.asset = "http://app.example.test/login"

    def test_role_roundtrip_hides_password_and_derives_login(self):
        tc.set_app_config(self.asset, "http://app.example.test/api", {"url": "http://app.example.test/api/auth/login", "username_field": "correo",
                                                                      "password_field": "contrasena", "token_json_path": "data.token"}, client=self.v)
        tc.upsert_role(self.asset, "Oficial de Partes", "oficialia@example.test", "s3cret-pass", client=self.v)
        shown = tc.describe(self.asset, client=self.v)
        self.assertNotIn("s3cret-pass", repr(shown))
        self.assertEqual(shown["roles"], [{"name": "Oficial de Partes", "kind": "user", "username": "oficialia@example.test", "has_password": True, "has_token": False}])
        raw = tc.read_raw(self.asset, client=self.v)
        login = raw["roles"][0]["login"]
        self.assertEqual(login["json"], {"correo": "oficialia@example.test", "contrasena": "s3cret-pass"})
        self.assertEqual(login["token_json_path"], "data.token")

    def test_editing_username_keeps_password_and_login_change_rederives(self):
        tc.upsert_role(self.asset, "Admin", "a@example.test", "pw-1", kind="admin", client=self.v)
        tc.upsert_role(self.asset, "admin", "b@example.test", "", kind="admin", client=self.v)
        raw = tc.read_raw(self.asset, client=self.v)
        self.assertEqual((len(raw["roles"]), raw["roles"][0]["username"], raw["roles"][0]["password"]), (1, "b@example.test", "pw-1"))
        tc.set_app_config(self.asset, "", {"url": "http://x.test/login", "body": "form"}, client=self.v)
        self.assertIn("form", tc.read_raw(self.asset, client=self.v)["roles"][0]["login"])

    def test_validation_and_delete(self):
        with self.assertRaises(tc.CredentialsError):
            tc.upsert_role(self.asset, "A", "u", "p", client=self.v)           # name too short
        with self.assertRaises(tc.CredentialsError):
            tc.upsert_role(self.asset, "Perfil", "u", "", client=self.v)       # new role without password
        with self.assertRaises(tc.CredentialsError):
            tc.set_app_config(self.asset, "ftp://x", None, client=self.v)
        tc.upsert_role(self.asset, "Perfil", "u", "p", client=self.v)
        self.assertTrue(tc.delete_role(self.asset, "perfil", client=self.v))
        self.assertFalse(tc.delete_role(self.asset, "perfil", client=self.v))

    def test_other_vault_keys_are_preserved(self):
        self.v.store[tc._path(self.asset)] = {"openapi_url": "http://x/api-docs", "allow_mutating_probes": False}
        tc.upsert_role(self.asset, "Perfil", "u", "p", client=self.v)
        raw = tc.read_raw(self.asset, client=self.v)
        self.assertEqual(raw["openapi_url"], "http://x/api-docs")


class TestEndpoints(unittest.TestCase):
    def setUp(self):
        from main import app
        self.client = TestClient(app)
        self.v = FakeVault()
        self.name = f"http://test-cred-{uuid.uuid4().hex[:8]}.example.test/"
        with db_manager.get_db_cursor() as cur:
            cur.execute("INSERT INTO public.infra_inventory (asset_name, asset_type, endpoint) VALUES (%s, 'URL', %s) RETURNING id", (self.name, self.name))
            self.asset_id = str(cur.fetchone()[0])
            cur.execute("INSERT INTO public.asset_auth_roles (asset_id, role_name, source, source_file) VALUES (%s, 'Revisor', 'sql', 'x.sql')", (self.asset_id,))
        self.patch = mock.patch.object(tc, "vault_client", return_value=self.v)
        self.patch.start()

    def tearDown(self):
        self.patch.stop()
        with db_manager.get_db_cursor() as cur:
            cur.execute("DELETE FROM public.infra_inventory WHERE id = %s", (self.asset_id,))   # cascades to asset_auth_roles

    def test_full_flow_never_returns_the_password(self):
        r = self.client.put("/api/test-credentials/config", json={"asset_name": self.name, "base_url": "http://app.example.test/api",
                                                                  "app_login": {"url": "http://app.example.test/login"}})
        self.assertEqual(r.status_code, 200, r.text)
        r = self.client.put("/api/test-credentials/role", json={"asset_name": self.name, "role": "Revisor", "username": "rev@example.test", "password": "never-show-me"})
        self.assertEqual(r.status_code, 200, r.text)
        g = self.client.get("/api/test-credentials", params={"asset_name": self.name})
        self.assertEqual(g.status_code, 200)
        self.assertNotIn("never-show-me", g.text)
        self.assertEqual([p["role"] for p in g.json()["profiles"]], ["Revisor"])
        self.assertTrue(g.json()["config"]["roles"][0]["has_password"])
        d = self.client.delete("/api/test-credentials/role", params={"asset_name": self.name, "role": "Revisor"})
        self.assertEqual(d.status_code, 200)
        self.assertEqual(self.client.delete("/api/test-credentials/role", params={"asset_name": self.name, "role": "Revisor"}).status_code, 404)

    def test_unknown_asset_and_bad_input(self):
        self.assertEqual(self.client.get("/api/test-credentials", params={"asset_name": "nope"}).status_code, 404)
        r = self.client.put("/api/test-credentials/role", json={"asset_name": self.name, "role": "X", "username": "u", "password": "p"})
        self.assertEqual(r.status_code, 400)

    def test_enforce_mode_requires_an_admin_group(self):
        from fastapi import HTTPException
        from api.routers.test_credentials import _guard

        def req(user):
            return type("R", (), {"state": type("S", (), {"user": user})()})()
        with mock.patch("core.auth.mode", return_value="enforce"):
            with self.assertRaises(HTTPException) as cm:
                _guard(req({"sub": "x", "groups": ["Centinela Viewer"]}))
            self.assertEqual(cm.exception.status_code, 403)
            self.assertEqual(_guard(req({"preferred_username": "ana", "groups": ["Centinela Admin"]})), "ana")
        with mock.patch("core.auth.mode", return_value="log"):
            self.assertEqual(_guard(req(None)), "anonymous")      # log mode: allowed, only recorded


if __name__ == "__main__":
    unittest.main()


class TestAuthzScopeAndLoginUi(unittest.TestCase):
    def test_scope_and_browser_login_are_stored_and_listed_without_secrets(self):
        v, a = FakeVault(), "http://app.example.test/"
        tc.set_app_config(a, "http://app.example.test/api", None, client=v,
                          login_ui={"url": "http://app.example.test/login", "routes": ["http://app.example.test/home", " "], "submit_selector": "#go"},
                          authz={"endpoints": ["/usuario/all", "/admin/config"], "openapi_url": "http://app.example.test/v3/api-docs", "admin_only": ["*/admin/*"]})
        d = tc.describe(a, client=v)
        self.assertEqual(d["authz"], {"endpoints": ["/usuario/all", "/admin/config"], "openapi_url": "http://app.example.test/v3/api-docs", "admin_only": ["*/admin/*"]})
        self.assertEqual(d["login_ui"]["routes"], ["http://app.example.test/home"])
        raw = tc.read_raw(a, client=v)
        self.assertEqual(raw["access_model"]["admin_only"], ["*/admin/*"])          # the exact shape auditor_authz_dast reads

    def test_bad_scope_input_is_rejected(self):
        v, a = FakeVault(), "http://app.example.test/"
        with self.assertRaises(tc.CredentialsError):
            tc.set_app_config(a, "", None, client=v, authz={"endpoints": ["no-slash"]})
        with self.assertRaises(tc.CredentialsError):
            tc.set_app_config(a, "", None, client=v, login_ui={"url": "http://x.test/l", "routes": ["/relative"]})


class TestUrlOnlyApplications(unittest.TestCase):
    """Applications registered only as a URL/endpoint (no repository)."""
    def test_vault_key_is_url_safe_and_stable(self):
        for name in ("http://192.0.2.10/fe-app-qa/auth/login", "GitLab2/grupo-a/x/y@develop", "https://api.example.test:8443/v1/"):
            k = tc.vault_key(name)
            self.assertRegex(k, r"^[A-Za-z0-9._@-]+$")
            self.assertEqual(k, tc.vault_key(name))
        self.assertNotEqual(tc.vault_key("http://a.test/x"), tc.vault_key("http://a.test/y"))

    def test_credentials_of_a_url_asset_roundtrip_under_the_slug_path(self):
        v, a = FakeVault(), "http://192.0.2.10/fe-app-qa/auth/login"
        tc.upsert_role(a, "Oficial de Partes", "o@example.test", "pw", client=v)
        self.assertTrue(all("//" not in p and ":" not in p for p in v.store))
        self.assertEqual(tc.describe(a, client=v)["roles"][0]["name"], "Oficial de Partes")

    def test_openapi_spec_profiles(self):
        from core import openapi_profiles as op
        spec = {"components": {"securitySchemes": {"oauth": {"type": "oauth2", "flows": {"password": {"scopes": {"admin": "x", "lectura": "y"}}}}}},
                "paths": {"/u": {"get": {"x-roles": ["Auditor"], "parameters": [{"name": "rol", "in": "query", "schema": {"enum": ["Capturista"]}, "enum": ["Capturista"]}]}}}}
        names = {p["role"] for p in op.parse_profiles(spec)}
        self.assertEqual(names, {"admin", "lectura", "Auditor", "Capturista"})
        self.assertEqual(op.parse_profiles({"openapi": "3.0.0", "paths": {}}), [])

    def test_openapi_fetch_rejects_bad_urls_and_reads_a_real_document(self):
        import json
        import threading
        from http.server import BaseHTTPRequestHandler, HTTPServer
        from core import openapi_profiles as op

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                b = json.dumps({"securityDefinitions": {"k": {"type": "oauth2", "scopes": {"supervisor": "s"}}}}).encode()
                self.send_response(200); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
        srv = HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            self.assertEqual([p["role"] for p in op.fetch_profiles(f"http://127.0.0.1:{srv.server_port}/v2/api-docs")], ["supervisor"])
        finally:
            srv.shutdown()
        for bad in ("ftp://x.test/a", "http://169.254.169.254/latest/meta-data"):
            with self.assertRaises(ValueError):
                op.fetch_profiles(bad)
