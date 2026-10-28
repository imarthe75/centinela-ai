"""Rules added 2026-10-01 to close statically-detectable OWASP/WSTG gaps (see core/coverage_matrix.py)."""
import os
import tempfile
import unittest

from auditors.auditor_master_vulnerabilities import scan_sast_code, scan_iac_dockerfile


def ids(path, content):
    return [f["cve_id"] for f in scan_sast_code(path, content)]


class TestOwaspCoverageRules(unittest.TestCase):
    def test_mass_assignment_entity_binding(self):
        ctrl = '@RestController\nclass C {\n  @PostMapping\n  public X crear(@RequestBody @Valid UsuarioEntity u) { return null; }\n}\n'
        self.assertIn("MASS-ASSIGNMENT-ENTITY-BINDING", ids("/r/C.java", ctrl))
        dto = '@RestController\nclass C {\n  @PostMapping\n  public X crear(@RequestBody @Valid UsuarioRequest u) { return null; }\n}\n'
        self.assertNotIn("MASS-ASSIGNMENT-ENTITY-BINDING", ids("/r/C.java", dto))
        service = 'class S {\n  void guardar(@RequestBody UsuarioEntity u) {}\n}\n'   # not a controller
        self.assertNotIn("MASS-ASSIGNMENT-ENTITY-BINDING", ids("/r/S.java", service))

    def test_insecure_random_for_secret(self):
        self.assertIn("INSECURE-RANDOM-FOR-SECRET", ids("/r/A.java", 'String token = String.valueOf(new Random().nextLong());\n'))
        self.assertIn("INSECURE-RANDOM-FOR-SECRET", ids("/r/a.py", 'password = "".join(random.choice(chars) for _ in range(8))\n'))
        self.assertNotIn("INSECURE-RANDOM-FOR-SECRET", ids("/r/A.java", 'String token = new SecureRandom().toString();\n'))
        self.assertNotIn("INSECURE-RANDOM-FOR-SECRET", ids("/r/A.java", 'int dado = new Random().nextInt(6);\n'))
        self.assertNotIn("INSECURE-RANDOM-FOR-SECRET", ids("/r/a.py", 'token = secrets.token_hex(16)\n'))

    def test_crypto_modes_and_legacy_primitives(self):
        self.assertIn("CRYPTO-CBC-NO-AUTHENTICATION", ids("/r/A.java", 'Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");\n'))
        self.assertNotIn("CRYPTO-CBC-NO-AUTHENTICATION", ids("/r/A.java", 'Cipher c = Cipher.getInstance("AES/GCM/NoPadding");\n'))
        self.assertIn("WEAK-CRYPTOGRAPHY", ids("/r/A.java", 'Cipher c = Cipher.getInstance("AES");\n'))
        self.assertIn("WEAK-CRYPTOGRAPHY", ids("/r/A.java", 'Cipher c = Cipher.getInstance("DES/CBC/PKCS5Padding");\n'.replace("DES/CBC/PKCS5Padding", "DES")))
        self.assertIn("WEAK-CRYPTOGRAPHY", ids("/r/A.java", 'MessageDigest md = MessageDigest.getInstance("MD5");\n'))
        self.assertNotIn("WEAK-CRYPTOGRAPHY", ids("/r/A.java", 'MessageDigest md = MessageDigest.getInstance("SHA-256");\n'))
        self.assertNotIn("WEAK-CRYPTOGRAPHY", ids("/r/A.java", '// Cipher.getInstance("AES") era el codigo viejo\n'))

    def test_websocket_postmessage_redirect_storage(self):
        self.assertIn("INSECURE-WEBSOCKET", ids("/r/a.ts", 'const ws = new WebSocket("ws://api.example.internal/stream");\n'))
        self.assertNotIn("INSECURE-WEBSOCKET", ids("/r/a.ts", 'const ws = new WebSocket("wss://api.example.internal/stream");\n'))
        self.assertNotIn("INSECURE-WEBSOCKET", ids("/r/a.ts", 'const ws = new WebSocket("ws://localhost:4200/sockjs");\n'))
        self.assertIn("POSTMESSAGE-WILDCARD-ORIGIN", ids("/r/a.ts", 'parent.postMessage({ok: 1}, "*");\n'))
        self.assertNotIn("POSTMESSAGE-WILDCARD-ORIGIN", ids("/r/a.ts", 'parent.postMessage({ok: 1}, "https://app.example.internal");\n'))
        self.assertIn("POSTMESSAGE-NO-ORIGIN-CHECK", ids("/r/a.ts", 'window.addEventListener("message", (e) => {\n  this.data = e.data;\n});\n'))
        self.assertNotIn("POSTMESSAGE-NO-ORIGIN-CHECK", ids("/r/a.ts", 'window.addEventListener("message", (e) => {\n  if (e.origin !== X) return;\n  this.data = e.data;\n});\n'))
        self.assertIn("CLIENT-SIDE-REDIRECT", ids("/r/a.ts", 'window.location.href = this.route.snapshot.queryParams["next"];\n'))
        self.assertNotIn("CLIENT-SIDE-REDIRECT", ids("/r/a.ts", 'window.location.href = "/inicio";\n'))
        self.assertIn("FRONTEND-SENSITIVE-STORAGE", ids("/r/a.ts", 'localStorage.setItem("password", pwd);\n'))
        self.assertNotIn("FRONTEND-SENSITIVE-STORAGE", ids("/r/a.ts", 'localStorage.setItem("tema", "oscuro");\n'))

    def test_session_fixation_graphql_ssti_xpath_ldap(self):
        self.assertIn("SESSION-FIXATION-DISABLED", ids("/r/S.java", "http.sessionManagement().sessionFixation().none();\n"))
        self.assertNotIn("SESSION-FIXATION-DISABLED", ids("/r/S.java", "http.sessionManagement().sessionFixation().migrateSession();\n"))
        self.assertIn("GRAPHQL-INTROSPECTION-ENABLED", ids("/r/application.properties", "spring.graphql.graphiql.enabled=true\n"))
        self.assertNotIn("GRAPHQL-INTROSPECTION-ENABLED", ids("/r/application.properties", "spring.graphql.graphiql.enabled=false\n"))
        self.assertIn("SSTI-TEMPLATE-FROM-INPUT", ids("/r/a.py", "return render_template_string(page)\n"))
        self.assertIn("SSTI-TEMPLATE-FROM-INPUT", ids("/r/a.py", 'return render_template_string(f"<h1>{name}</h1>")\n'))
        self.assertNotIn("SSTI-TEMPLATE-FROM-INPUT", ids("/r/a.py", 'return render_template_string("<h1>fijo</h1>")\n'))
        self.assertIn("XPATH-INJECTION-CONCAT", ids("/r/A.java", 'xpath.evaluate("//user[name=\'" + n + "\']", doc);\n'))
        self.assertNotIn("XPATH-INJECTION-CONCAT", ids("/r/A.java", 'xpath.evaluate("//user", doc);\n'))
        self.assertIn("LDAP-INJECTION-CONCAT", ids("/r/A.java", 'String f = "(uid=" + user + ")";\n'))
        self.assertNotIn("LDAP-INJECTION-CONCAT", ids("/r/A.java", 'String f = "(uid={0})";\n'))

    def test_supply_chain_pinning(self):
        with tempfile.TemporaryDirectory() as d:
            pj = os.path.join(d, "package.json")
            body = '{\n "dependencies": {\n  "axios": "^1.6.0"\n }\n}\n'
            open(pj, "w").write(body)
            self.assertIn("SUPPLY-CHAIN-NO-LOCKFILE", ids(pj, body))
            open(os.path.join(d, "package-lock.json"), "w").write("{}")
            self.assertNotIn("SUPPLY-CHAIN-NO-LOCKFILE", ids(pj, body))
        self.assertIn("SUPPLY-CHAIN-UNPINNED-DEPENDENCY", ids("/r/package.json", '{\n "dependencies": {\n  "lodash": "latest"\n }\n}\n'))
        self.assertIn("SUPPLY-CHAIN-UNPINNED-DEPENDENCY", ids("/r/pom.xml", "<dependency><artifactId>x</artifactId>\n<version>[1.0,2.0)</version></dependency>\n"))
        self.assertNotIn("SUPPLY-CHAIN-UNPINNED-DEPENDENCY", ids("/r/pom.xml", "<dependency><artifactId>x</artifactId>\n<version>1.2.3</version></dependency>\n"))
        self.assertIn("SUPPLY-CHAIN-UNPINNED-DEPENDENCY", ids("/r/requirements.txt", "flask>=2.0\nrequests\n"))
        self.assertNotIn("SUPPLY-CHAIN-UNPINNED-DEPENDENCY", ids("/r/requirements.txt", "flask==2.3.2\n# comentario\n-r otro.txt\n"))

    def test_dockerfile_curl_pipe_shell(self):
        df = "FROM debian:12\nRUN curl -fsSL https://x.sh | sh\nUSER app\n"
        self.assertIn("DOCKER-CURL-PIPE-SHELL", [f["cve_id"] for f in scan_iac_dockerfile("/r/Dockerfile", df)])
        ok = "FROM debian:12\nRUN curl -fsSLo /tmp/x.sh https://x.sh && sha256sum -c x.sha && sh /tmp/x.sh\nUSER app\n"
        self.assertNotIn("DOCKER-CURL-PIPE-SHELL", [f["cve_id"] for f in scan_iac_dockerfile("/r/Dockerfile", ok)])


if __name__ == "__main__":
    unittest.main()


class TestVendoredFrontendFilesAreSkipped(unittest.TestCase):
    def test_bundles_and_third_party_plugins_do_not_trigger_browser_rules(self):
        js = 'window.addEventListener("message", function(e){ run(e.data); });\n'
        self.assertIn("POSTMESSAGE-NO-ORIGIN-CHECK", ids("/r/src/app/chat.service.ts", js))
        self.assertNotIn("POSTMESSAGE-NO-ORIGIN-CHECK", ids("/r/assets/plugins/custom/prismjs/prismjs.bundle.js", js))
        self.assertNotIn("POSTMESSAGE-NO-ORIGIN-CHECK", ids("/r/webapp/resources/js/qz-tray/qz-tray.js", js))
        self.assertNotIn("POSTMESSAGE-NO-ORIGIN-CHECK", ids("/r/dist/app.min.js", js))
