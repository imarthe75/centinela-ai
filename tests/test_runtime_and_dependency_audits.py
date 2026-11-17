"""Runtime-session findings (pure transformation of the worker's JSON), dependency probe, and the PII-aware authorization severity.
The browser worker itself was verified by hand against a toy application in the Dockerfile.a11y image (see DECISIONS/0014); no browser runs here."""
import os
import socket
import tempfile
import threading
import unittest

from auditors import auditor_authz as az
from auditors import auditor_dependency_probe as dp
from auditors import auditor_runtime_session as rs


def _tree(files):
    d = tempfile.mkdtemp()
    for name, text in files.items():
        p = os.path.join(d, name)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        open(p, "w", encoding="utf-8").write(text)
    return d


RES = {"login_ok": True, "console": [{"type": "log", "text": "STOMP Debug: Authorization:Bearer ***", "url": "http://app/home", "secret": "eyJhbG***"}],
       "pii": [{"url": "http://app/api/usuario/servidor-publico/77", "kind": "CURP", "count": 1, "sample": "ABCD12***"},
               {"url": "http://app/api/usuario/servidor-publico/77", "kind": "EMAIL", "count": 2, "sample": "ana@ex***"}],
       "responses": [{"url": "http://app/api/refresh-token?i=%d" % i, "status": 403, "method": "GET"} for i in range(4)] + [{"url": "http://app/api/x", "status": 502, "method": "GET"}],
       "storage": [{"area": "localStorage", "key": "access"}], "errors": []}


class TestRuntimeSessionFindings(unittest.TestCase):
    def ids(self, res, kind="user"):
        return [f["cve_id"] for f in rs.findings_from_result(res, "Oficial de Partes", kind, "http://app/login")]

    def test_all_runtime_findings_for_a_regular_profile(self):
        found = rs.findings_from_result(RES, "Oficial de Partes", "user", "http://app/login")
        ids = [f["cve_id"] for f in found]
        for rid in ("RUNTIME-TOKEN-IN-CONSOLE", "RUNTIME-PII-IN-RESPONSE", "RUNTIME-AUTH-ERRORS", "RUNTIME-SERVER-ERRORS", "RUNTIME-TOKEN-IN-STORAGE"):
            self.assertIn(rid, ids)
        pii = [f for f in found if f["cve_id"] == "RUNTIME-PII-IN-RESPONSE"]
        self.assertEqual(len(pii), 1)                                     # one finding per endpoint, kinds merged (the fingerprint is per endpoint)
        self.assertEqual(pii[0]["url_path"], "/api/usuario/servidor-publico/{id}")
        self.assertNotIn("ABCD123456", " ".join(f["description"] for f in found))      # never a real value

    def test_admin_profile_does_not_get_pii_finding(self):
        self.assertNotIn("RUNTIME-PII-IN-RESPONSE", self.ids(RES, kind="admin"))

    def test_few_403s_are_not_reported_and_clean_session_is_empty(self):
        clean = {"login_ok": True, "console": [], "pii": [], "responses": [{"url": "http://app/a", "status": 403, "method": "GET"}], "storage": [], "errors": []}
        self.assertEqual(self.ids(clean), [])

    def test_failed_login_is_an_honest_marker_not_a_clean_result(self):
        out = rs.findings_from_result({"login_ok": False, "errors": ["login: TimeoutError"]}, "Admin", "admin", "http://app/login")
        self.assertEqual([f["cve_id"] for f in out], ["RUNTIME-SESSION-NOT-EXERCISED"])
        self.assertEqual(out[0]["severity"], "INFO")

    def test_without_credentials_nothing_is_invented(self):
        class V:
            class V2:
                def read_secret_version(self, **kw):
                    class InvalidPath(Exception):
                        pass
                    raise InvalidPath()
            secrets = type("S", (), {"kv": type("K", (), {"v2": V2()})()})()
        self.assertEqual(rs.run_runtime_session_audit("http://nothing.example.test/", None, client=V()), [])


class TestDependencyProbe(unittest.TestCase):
    def test_parse_endpoint_skips_what_cannot_be_probed(self):
        self.assertEqual(dp.parse_endpoint("jdbc:postgresql://user:pw@192.0.2.8:5432/db"), ("192.0.2.8", 5432, "postgresql"))
        self.assertEqual(dp.parse_endpoint("https://docs.internal-corp.net/path"), ("docs.internal-corp.net", 443, "https"))
        for bad in ("http://localhost:8080", "http://${HOST}:80", "http://redis:6379", "https://api.example.com", "http://127.0.0.1:9"):
            self.assertIsNone(dp.parse_endpoint(bad), bad)

    def test_extract_reads_configuration_files_only_and_drops_credentials(self):
        d = _tree({"src/main/resources/application-qa.properties": "spring.datasource.url=jdbc:postgresql://admin:secret@192.0.2.25:5432/app\n# url=http://192.0.2.23:80\n",
                   "src/environments/environment.dev.ts": "export const environment = { onlyoffice: 'http://192.0.2.22:8099' }\n",
                   "src/main/java/A.java": 'String u = "http://192.0.2.21:80";\n'})
        deps = dp.extract_dependencies(d)
        self.assertEqual({(x["host"], x["port"], x["profile"]) for x in deps}, {("192.0.2.25", 5432, "qa"), ("192.0.2.22", 8099, "dev")})
        self.assertNotIn("secret", repr(deps))

    def test_real_tcp_probe_reachable_and_refused(self):
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        t = threading.Thread(target=lambda: srv.accept()[0].close(), daemon=True)
        t.start()
        self.assertEqual(dp.probe("127.0.0.1", port), "ok")
        t.join(5)          # a still-blocked accept() keeps the socket listening after close(): the next probe would be "ok"
        srv.close()
        dp._cache.clear()
        self.assertIn(dp.probe("127.0.0.1", port), ("refused", "timeout"))

    def test_findings_severity_by_profile_and_secret_free(self):
        deps = [{"host": "192.0.2.5", "port": 8099, "scheme": "http", "file": "src/main/resources/application-qa.properties", "line": 7, "profile": "qa"},
                {"host": "192.0.2.6", "port": 80, "scheme": "http", "file": "src/main/resources/application-dev.properties", "line": 3, "profile": "dev"},
                {"host": "192.0.2.7", "port": 80, "scheme": "http", "file": "x/application.yml", "line": 1, "profile": "base"}]
        out = dp.check_dependencies(deps, prober=lambda h, p: "ok" if h.endswith("3") else "timeout")
        self.assertEqual([(f["severity"], f["url_path"]) for f in out], [("MEDIUM", "src/main/resources/application-qa.properties:7"), ("LOW", "src/main/resources/application-dev.properties:3")])


class TestPiiAwareAuthzSeverity(unittest.TestCase):
    def sev(self, controller):
        d = _tree({"src/main/java/a/Cfg.java": "package a;\n@EnableMethodSecurity\n@Configuration\npublic class Cfg {}\n",
                   "src/main/java/a/PersonaDto.java": "package a;\npublic class PersonaDto { String curp; String rfc; String correo; }\n",
                   "src/main/java/a/Ok.java": 'package a;\n@RestController\n@RequestMapping("/ok")\npublic class Ok {\n  @PreAuthorize("hasAuthority(\'X\')")\n  @GetMapping("/a")\n  public String a() { return ""; }\n}\n',
                   "src/main/java/a/C.java": controller})
        return {f["severity"] for f in az.run_authz_audit(d, None) if f["cve_id"] == "AUTHZ-NO-METHOD-AUTHZ" and f["file"].endswith("C.java")}

    def test_read_of_people_data_without_authorization_is_critical(self):
        self.assertEqual(self.sev('package a;\n@RestController\n@RequestMapping("/usuario")\npublic class C {\n  @GetMapping("/servidor-publico/{id}")\n  public PersonaDto get(@PathVariable Long id) { return null; }\n}\n'), {"CRITICAL"})

    def test_catalogue_read_stays_medium(self):
        self.assertEqual(self.sev('package a;\n@RestController\n@RequestMapping("/catalogo")\npublic class C {\n  @GetMapping("/all")\n  public String all() { return ""; }\n}\n'), {"MEDIUM"})


if __name__ == "__main__":
    unittest.main()
