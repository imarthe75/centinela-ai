"""
Regression tests for the gaps found by comparing un colaborador's pentest / un colaborador's analyses with
Centinela's scan of proyecto-g (un colaborador's PDF, 2026-10-01): method-level authorization
(@PreAuthorize) coverage, commented-out @PreAuthorize, test controllers in src/main, secrets in
application*.properties|yml, timing-unsafe comparisons, password-policy DTOs, tokens in URLs and
test routes in the Angular router. Pure static analysis on tmp dirs -- no DB writes.
"""
import os
import tempfile
import unittest

from auditors import auditor_authz
from auditors.auditor_master_vulnerabilities import scan_sast_code

SEC = """
package x;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
@EnableMethodSecurity
public class SecurityConfig {
  void c(HttpSecurity http) throws Exception {
    http.authorizeHttpRequests(a -> a.requestMatchers("/public/**").permitAll().anyRequest().authenticated());
  }
}
"""

CTRL = """
package x;
import org.springframework.security.access.prepost.PreAuthorize;
@RestController
@RequestMapping("/api/cosas")
public class CosaController {
    @PreAuthorize("hasAuthority('COSAS_CREAR')")
    @PostMapping
    @Operation(summary = "crear",
        security = @SecurityRequirement(name = "bearerAuth"))
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200"),
        @ApiResponse(responseCode = "400"),
        @ApiResponse(responseCode = "401"),
        @ApiResponse(responseCode = "403"),
        @ApiResponse(responseCode = "404")
    })
    public Object crear() { return null; }

    @GetMapping("/{id}")
    @Operation(summary = "leer")
    @PreAuthorize("hasAuthority('COSAS_CONSULTAR')")
    public Object leer() { return null; }

    @DeleteMapping("/{id}")
    @Operation(summary = "borrar")
    public Object borrar() { return null; }

    @PutMapping("/{id}")
//    @PreAuthorize("hasAuthority('COSAS_EDITAR')")
    @Operation(summary = "editar")
    public Object editar() { return null; }
}
"""

CLASS_LEVEL = """
package x;
@RestController
@PreAuthorize("hasRole('ADMIN')")
@RequestMapping("/api/admin")
public class AdminController {
    @GetMapping("/a") public Object a() { return null; }
}
"""

TESTCTRL = """
package x;
@RestController
@RequestMapping("/test")
public class AuthorizationTestController {
    @GetMapping("/ping") public Object p() { return null; }
}
"""

PROFILE_TESTCTRL = """
package x;
@Profile("dev")
@RestController
public class EjemploController {
    @GetMapping("/ping") public Object p() { return null; }
}
"""


def _write(d, rel, content):
    path = os.path.join(d, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        fh.write(content)


class TestMethodLevelAuthz(unittest.TestCase):
    def _run(self, files):
        with tempfile.TemporaryDirectory() as d:
            for rel, c in files.items():
                _write(d, rel, c)
            return auditor_authz.run_authz_audit(d, None)

    def test_flags_only_unannotated_endpoints_even_with_long_annotation_blocks(self):
        f = self._run({"src/main/java/x/SecurityConfig.java": SEC, "src/main/java/x/CosaController.java": CTRL})
        no_authz = [x for x in f if x["cve_id"] == "AUTHZ-NO-METHOD-AUTHZ"]
        lines = sorted(x["line"] for x in no_authz)
        # crear (annotation BEFORE 20-line @Operation/@ApiResponses block) and leer (annotation AFTER
        # @Operation) are covered; only DELETE (borrar) lacks any annotation. PUT's is commented out.
        self.assertEqual(len(no_authz), 1, no_authz)
        self.assertIn("DELETE", no_authz[0]["description"])
        self.assertEqual(no_authz[0]["severity"], "HIGH")
        self.assertEqual(lines[0], next(i for i, l in enumerate(CTRL.splitlines(), 1) if "@DeleteMapping" in l))

    def test_commented_out_preauthorize_is_its_own_finding(self):
        f = self._run({"src/main/java/x/SecurityConfig.java": SEC, "src/main/java/x/CosaController.java": CTRL})
        c = [x for x in f if x["cve_id"] == "AUTHZ-PREAUTHORIZE-COMMENTED-OUT"]
        self.assertEqual(len(c), 1)
        self.assertIn("PUT", c[0]["description"])
        # not double-reported as a plain "missing" finding
        self.assertFalse(any(x["cve_id"] == "AUTHZ-NO-METHOD-AUTHZ" and "PUT" in x["description"] for x in f))

    def test_class_level_annotation_covers_every_method(self):
        f = self._run({"src/main/java/x/SecurityConfig.java": SEC, "src/main/java/x/AdminController.java": CLASS_LEVEL})
        self.assertEqual([x for x in f if x["cve_id"] == "AUTHZ-NO-METHOD-AUTHZ"], [])

    def test_project_without_any_method_security_is_not_flagged(self):
        # no @EnableMethodSecurity and no annotated endpoint: authz is URL-based by design here ->
        # the existing AUTHZ-NO-METHOD-ANNOTATIONS (LOW) logic owns that case, not this rule.
        bare = CLASS_LEVEL.replace('@PreAuthorize("hasRole(\'ADMIN\')")', "")
        sec = SEC.replace("@EnableMethodSecurity", "")
        f = self._run({"src/main/java/x/SecurityConfig.java": sec, "src/main/java/x/AdminController.java": bare})
        self.assertEqual([x for x in f if x["cve_id"] == "AUTHZ-NO-METHOD-AUTHZ"], [])

    def test_test_controller_flagged_unless_profile_gated(self):
        f = self._run({"src/main/java/x/SecurityConfig.java": SEC, "src/main/java/x/AuthorizationTestController.java": TESTCTRL})
        self.assertEqual(len([x for x in f if x["cve_id"] == "AUTHZ-TEST-ENDPOINT-EXPOSED"]), 1)
        f = self._run({"src/main/java/x/SecurityConfig.java": SEC, "src/main/java/x/EjemploController.java": PROFILE_TESTCTRL})
        self.assertEqual([x for x in f if x["cve_id"] == "AUTHZ-TEST-ENDPOINT-EXPOSED"], [])

    def test_public_sensitive_read(self):
        sec = SEC.replace('"/public/**"', '"/api/usuarios/**"')
        ctrl = CTRL.replace("/api/cosas", "/api/usuarios").replace(
            "    @DeleteMapping", "    @GetMapping(\"/lista\")\n    public Object lista() { return null; }\n\n    @DeleteMapping", 1)
        f = self._run({"src/main/java/x/SecurityConfig.java": sec, "src/main/java/x/UsuarioController.java": ctrl})
        self.assertTrue(any(x["cve_id"] == "AUTHZ-PUBLIC-SENSITIVE-READ" for x in f))


def ids(path, content):
    return [f["cve_id"] for f in scan_sast_code(path, content)]


class TestConfigAndCodeRules(unittest.TestCase):
    def test_literal_secret_in_properties_flagged_without_leaking_value(self):
        content = "jwt.secret=SuperSecretValue1234567890abcdef\nspring.datasource.password=Hunter2Hunter2\n"
        res = scan_sast_code("/r/src/main/resources/application.properties", content)
        got = {f["cve_id"] for f in res}
        self.assertEqual(got, {"CONFIG-JWT-SECRET-LITERAL", "CONFIG-SECRET-LITERAL"})
        self.assertNotIn("SuperSecretValue", " ".join(f["description"] for f in res))
        self.assertNotIn("Hunter2", " ".join(f["description"] for f in res))

    def test_placeholders_env_refs_and_benign_keys_are_clean(self):
        content = ("jwt.secret=${JWT_SECRET}\nspring.datasource.password=${DB_PASSWORD:}\n"
                   "jwt.token.expiration=3600\nsecurity.password-file=/run/secrets/x\n"
                   "keycloak.token-url=https://idp/token\nauthentik.api.recovery-token-duration=minutes=30\n# api.key=abcdefghijklmnop\n")
        self.assertEqual(ids("/r/application.properties", content), [])

    def test_yaml_secret(self):
        self.assertIn("CONFIG-SECRET-LITERAL", ids("/r/application.yml", "spring:\n  datasource:\n    password: Pr0dPassw0rd!\n"))

    def test_spanish_credential_keys_are_detected_but_references_are_not(self):
        """Real gap (12-oct-2026): `firmauni.conexion.contrasena=<literal>` in proyecto-a's application-*.properties was invisible because the keyword list was English-only."""
        self.assertIn("CONFIG-SECRET-LITERAL", ids("/r/application-qa.properties", "firmauni.conexion.contrasena=Abc123xyz\n"))
        self.assertIn("CONFIG-SECRET-LITERAL", ids("/r/application-prod.properties", "api.clave=Zz9988776655\n"))
        self.assertIn("CONFIG-SECRET-LITERAL", ids("/r/application-prod.properties", "app.contraseña = Zz9988776655\n"))
        self.assertNotIn("CONFIG-SECRET-LITERAL", ids("/r/application-prod.properties", "firmauni.conexion.contrasena=${FIRMAUNI_CONTRASENA}\n"))
        self.assertNotIn("CONFIG-SECRET-LITERAL", ids("/r/application-prod.properties", "mail.clave.expiracion=30\n"))        # benign tail (a duration)

    def test_dev_profile_downgraded(self):
        res = scan_sast_code("/r/application-local.properties", "db.password=localpass123\n")
        self.assertEqual(res[0]["severity"], "MEDIUM")

    def test_timing_unsafe_comparison(self):
        self.assertIn("TIMING-UNSAFE-SECRET-COMPARISON", ids("/r/A.java", "if (apiKey.equals(header)) { }\n"))
        self.assertIn("TIMING-UNSAFE-SECRET-COMPARISON", ids("/r/A.java", "if (header.equals(expectedToken)) { }\n"))
        self.assertNotIn("TIMING-UNSAFE-SECRET-COMPARISON", ids("/r/A.java", "if (tokenType.equals(\"Bearer\")) { }\n"))
        self.assertNotIn("TIMING-UNSAFE-SECRET-COMPARISON", ids("/r/A.java", "if (MessageDigest.isEqual(a, b)) { } // token.equals(x)\n"))

    def test_password_policy_dto(self):
        bad = "public class CrearUsuarioRequest {\n    private String password;\n}\n"
        good = "public class CrearUsuarioRequest {\n    @Size(min = 12)\n    @Pattern(regexp = \".*\")\n    private String password;\n}\n"
        login = "public class LoginRequest {\n    private String password;\n}\n"
        self.assertIn("PASSWORD-POLICY-NOT-ENFORCED", ids("/r/CrearUsuarioRequest.java", bad))
        self.assertNotIn("PASSWORD-POLICY-NOT-ENFORCED", ids("/r/CrearUsuarioRequest.java", good))
        self.assertNotIn("PASSWORD-POLICY-NOT-ENFORCED", ids("/r/LoginRequest.java", login))

    def test_token_in_url_and_test_route(self):
        self.assertIn("FRONTEND-TOKEN-IN-URL", ids("/r/a.service.ts", "new EventSource(`${api}/stream?token=${jwt}`);\n"))
        self.assertNotIn("FRONTEND-TOKEN-IN-URL", ids("/r/a.service.ts", "const q = 'tokenType=bearer';\n"))
        self.assertIn("FRONTEND-TEST-ROUTE-EXPOSED", ids("/r/app.routes.ts", "  { path: 'authorization-test', component: X },\n"))
        self.assertNotIn("FRONTEND-TEST-ROUTE-EXPOSED", ids("/r/app.routes.ts", "  { path: 'contestacion', component: X },\n"))
        self.assertNotIn("FRONTEND-TEST-ROUTE-EXPOSED", ids("/r/other.ts", "  { path: 'test', component: X },\n"))


if __name__ == "__main__":
    unittest.main()


class _FakeCur:
    def __init__(self, row):
        self.row, self.sql = row, []

    def execute(self, sql, params=None):
        self.sql.append((sql, params))

    def fetchone(self):
        return self.row


class TestUnreachableDowngrade(unittest.TestCase):
    def test_one_level_down_and_sla_recomputed(self):
        from datetime import datetime
        from auditors.auditor_sca_dependencies import _apply_unreachable_downgrade
        from core import deduplication_engine as de
        t0 = datetime(2026, 1, 1)
        cur = _FakeCur({"risk_verdict": None, "real_severity": None, "detected_at": t0})
        _apply_unreachable_downgrade(cur, de, "vid", "HIGH")
        upd = [x for x in cur.sql if x[0].startswith("UPDATE")]
        self.assertEqual(len(upd), 1)
        self.assertEqual(upd[0][1], ("MEDIUM", t0 + de.get_sla_delta("MEDIUM"), "vid"))

    def test_never_overrides_human_or_existing_verdict_and_ignores_low(self):
        from datetime import datetime
        from auditors.auditor_sca_dependencies import _apply_unreachable_downgrade
        from core import deduplication_engine as de
        t0 = datetime(2026, 1, 1)
        for row, sev in (({"risk_verdict": "ANALYST_OVERRIDDEN", "real_severity": None, "detected_at": t0}, "HIGH"),
                         ({"risk_verdict": "DOWNGRADED", "real_severity": "LOW", "detected_at": t0}, "HIGH"),
                         ({"risk_verdict": None, "real_severity": None, "detected_at": t0}, "LOW")):
            cur = _FakeCur(row)
            _apply_unreachable_downgrade(cur, de, "vid", sev)
            self.assertFalse([x for x in cur.sql if x[0].startswith("UPDATE")], (row, sev))


class TestAngularBypassBlobGuard(unittest.TestCase):
    def test_blob_url_lowered_but_arbitrary_input_stays_high(self):
        blob = ("const url = URL.createObjectURL(new Blob([data]));\n"
                "this.safe = this.sanitizer.bypassSecurityTrustResourceUrl(url);\n")
        raw = "this.safe = this.sanitizer.bypassSecurityTrustHtml(userInput);\n"
        b = [f for f in scan_sast_code("/r/v.component.ts", blob) if f["cve_id"] == "ANGULAR-BYPASS-SECURITY-TRUST"]
        r = [f for f in scan_sast_code("/r/v.component.ts", raw) if f["cve_id"] == "ANGULAR-BYPASS-SECURITY-TRUST"]
        self.assertEqual([f["severity"] for f in b], ["LOW"])
        self.assertEqual([f["severity"] for f in r], ["HIGH"])


class TestWcagMissingLabelFalsePositive(unittest.TestCase):
    def _hits(self, html):
        return [f for f in scan_sast_code("/r/x.component.html", html) if f["cve_id"] == "ACCESSIBILITY-WCAG-MISSING-LABEL"]

    def test_buttons_with_an_accessible_name_attribute_are_not_flagged(self):
        for line in ('<button type="submit" pButton pRipple label="Aceptar" class="w-full"></button>\n',
                     '<button pButton [label]="texto"></button>\n',
                     '<button aria-label="Cerrar" (click)="x()"></button>\n',
                     '<button title="Guardar" (click)="x()"></button>\n'):
            self.assertEqual(self._hits(line), [], line)

    def test_button_without_any_name_is_still_flagged(self):
        self.assertTrue(self._hits('<button type="button" (click)="x()"></button>\n'))


class TestFileUploadRuleAccuracy(unittest.TestCase):
    """12-oct-2026, found remediating proyecto-a: the rule counted commented-out code and did not recognise a dedicated validator component."""
    CTRL = "@RestController class C {\n  @PostMapping(\"/up\") public void up(@RequestPart MultipartFile archivo) {\n%s\n  }\n}\n"

    def test_unvalidated_upload_is_flagged(self):
        self.assertIn("FILE-UPLOAD-NO-VALIDATION", ids("/r/C.java", self.CTRL % "    service.save(archivo);"))

    def test_a_dedicated_validator_component_counts_as_validation(self):
        self.assertNotIn("FILE-UPLOAD-NO-VALIDATION", ids("/r/C.java", self.CTRL % "    uploadValidator.validarDocumento(archivo);\n    service.save(archivo);"))
        self.assertNotIn("FILE-UPLOAD-NO-VALIDATION", ids("/r/C.java", self.CTRL % "    archivoValidator.validar(archivo);"))

    def test_commented_out_endpoint_is_not_reported(self):
        code = "@RestController class C {\n/*@PostMapping(\"/up\")\npublic void up(@RequestPart MultipartFile archivo) { service.save(archivo); }*/\n}\n"
        self.assertNotIn("FILE-UPLOAD-NO-VALIDATION", ids("/r/C.java", code))
        self.assertNotIn("FILE-UPLOAD-NO-VALIDATION", ids("/r/C.java", "class C {\n // public void up(MultipartFile archivo) {}\n}\n"))

    def test_a_validation_that_only_exists_in_a_comment_does_not_count(self):
        self.assertIn("FILE-UPLOAD-NO-VALIDATION", ids("/r/C.java", self.CTRL % "    // uploadValidator.validarDocumento(archivo)\n    service.save(archivo);"))

    def test_line_numbers_survive_comment_blanking(self):
        res = scan_sast_code("/r/C.java", "/* una\n  linea\n  larga */\nclass C { void up(MultipartFile f) { save(f); } }\n")
        self.assertEqual([f["line"] for f in res if f["cve_id"] == "FILE-UPLOAD-NO-VALIDATION"], [4])


class TestTlsBypassRuleAccuracy(unittest.TestCase):
    """12-oct-2026 (proyecto-a): the rule fired on any mention of X509TrustManager, including the correct `(X509TrustManager) trustManagers[0]`."""
    TRUST_ALL = ("class A { void f() { TrustManager[] t = new TrustManager[]{ new X509TrustManager() {\n"
                 "  public void checkClientTrusted(X509Certificate[] c, String a) throws CertificateException {\n  }\n"
                 "  public void checkServerTrusted(X509Certificate[] c, String a) throws CertificateException {\n  }\n"
                 "  public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[]{}; } } }; } }\n")

    def test_trust_everything_implementation_is_flagged_at_its_line(self):
        res = [f for f in scan_sast_code("/r/ApiClient.java", self.TRUST_ALL) if f["cve_id"] == "JVM-GLOBAL-SSL-BYPASS"]
        self.assertEqual(len(res), 2)                                   # checkClientTrusted and checkServerTrusted, both empty
        self.assertEqual(sorted(f["line"] for f in res), [2, 4])

    def test_always_true_hostname_verifier_is_flagged(self):
        code = "class A { HostnameVerifier v = new HostnameVerifier() {\n public boolean verify(String hostname, SSLSession session) { return true; }\n}; }\n"
        self.assertIn("JVM-GLOBAL-SSL-BYPASS", ids("/r/A.java", code))

    def test_correct_use_of_the_real_trust_manager_is_not_flagged(self):
        code = ("class A { void f() { SSLContext c = SSLContext.getInstance(\"TLS\"); c.init(k, trustManagers, new SecureRandom());\n"
                " b.sslSocketFactory(c.getSocketFactory(), (X509TrustManager) trustManagers[0]).hostnameVerifier(OkHostnameVerifier.INSTANCE); } }\n")
        self.assertNotIn("JVM-GLOBAL-SSL-BYPASS", ids("/r/A.java", code))

    def test_a_verifier_that_really_checks_is_not_flagged(self):
        code = "class A { boolean verify(String h, SSLSession s) { return HttpsURLConnection.getDefaultHostnameVerifier().verify(h, s); } }\n"
        self.assertNotIn("JVM-GLOBAL-SSL-BYPASS", ids("/r/A.java", code))

    def test_commented_out_trust_all_is_not_flagged(self):
        self.assertNotIn("JVM-GLOBAL-SSL-BYPASS", ids("/r/A.java", "class A {\n/* public void checkServerTrusted(X509Certificate[] c, String a) { } */\n}\n"))

    def test_the_upload_validator_component_is_not_flagged_for_validating(self):
        self.assertNotIn("FILE-UPLOAD-NO-VALIDATION", ids("/r/UploadValidator.java", "class UploadValidator { private boolean contenidoCoincide(MultipartFile archivo, String ext) { return true; } }\n"))


class TestHtmlCommentsAndButtonNames(unittest.TestCase):
    """13-oct-2026 (proyecto-a): markup inside <!-- --> was reported, and a button whose only content is an <img alt="..."> was reported as unnamed."""

    def _rules(self, html, name="x.component.html"):
        from auditors.auditor_accessibility_wcag import audit_wcag_accessibility
        return [f["cve_id"] for f in scan_sast_code("/r/" + name, html)] + [f["cve_id"] for f in audit_wcag_accessibility("/r/" + name, html)]

    def test_commented_out_input_is_not_reported(self):
        self.assertNotIn("WCAG-1.3.1-FORM-CONTROL-NO-LABEL", self._rules("<div><!-- <input type=\"text\" pInputText placeholder=\"Search\" /> --></div>\n"))

    def test_the_same_input_outside_a_comment_is_reported(self):
        self.assertIn("WCAG-1.3.1-FORM-CONTROL-NO-LABEL", self._rules("<div><input type=\"text\" pInputText /></div>\n"))

    def test_line_numbers_do_not_move_after_a_multiline_comment(self):
        from auditors.auditor_accessibility_wcag import audit_wcag_accessibility
        res = [f for f in audit_wcag_accessibility("/r/a.html", "<!--\nx\ny\n-->\n<input type=\"text\" />\n") if f["cve_id"] == "WCAG-1.3.1-FORM-CONTROL-NO-LABEL"]
        self.assertEqual([f["line"] for f in res], [5])

    def test_button_with_image_alt_has_an_accessible_name(self):
        html = "<button class=\"p-link\" (click)=\"x()\">\n  <img src=\"a.svg\" alt=\"Tema azul\">\n</button>\n"
        self.assertNotIn("ACCESSIBILITY-WCAG-MISSING-LABEL", self._rules(html))

    def test_icon_only_button_is_still_reported(self):
        html = "<button class=\"p-link\" (click)=\"x()\">\n  <i class=\"pi pi-cog\"></i>\n</button>\n"
        self.assertIn("ACCESSIBILITY-WCAG-MISSING-LABEL", self._rules(html))


class TestGlobalAuditFilterRecognition(unittest.TestCase):
    FILTER = ("package x;\nimport org.springframework.web.filter.OncePerRequestFilter;\npublic class AuditoriaFilter extends OncePerRequestFilter {\n"
              "  private static final Set<String> M = Set.of(\"POST\", \"PUT\", \"DELETE\");\n  protected void doFilterInternal(HttpServletRequest r, HttpServletResponse s, FilterChain c) {\n"
              "    c.doFilter(r, s); AUDITORIA.info(\"usuario={} metodo={}\", u, r.getMethod()); } }\n")

    def _dir(self, files):
        import tempfile
        d = tempfile.mkdtemp()
        for name, src in files.items():
            with open(os.path.join(d, name), "w") as fh:
                fh.write(src)
        return d

    def test_a_logging_filter_for_state_changing_methods_is_recognised(self):
        from auditors.auditor_compliance_standards import project_has_global_audit_filter
        self.assertTrue(project_has_global_audit_filter(self._dir({"AuditoriaFilter.java": self.FILTER})))

    def test_a_filter_that_does_not_log_or_audit_is_not_recognised(self):
        from auditors.auditor_compliance_standards import project_has_global_audit_filter
        other = "class JwtFilter extends OncePerRequestFilter { void f(HttpServletRequest r) { r.getMethod(); } }\n"
        self.assertFalse(project_has_global_audit_filter(self._dir({"JwtFilter.java": other})))

    def test_no_filter_at_all_is_not_recognised(self):
        from auditors.auditor_compliance_standards import project_has_global_audit_filter
        self.assertFalse(project_has_global_audit_filter(self._dir({"A.java": "class A {}\n"})))


class TestSanitizationBypassAccuracy(unittest.TestCase):
    """13-oct-2026 (proyecto-a): [innerHTML] was reported as a bypass (Angular sanitizes it) and commented-out bypassSecurityTrust* calls were reported as code."""

    def _ids(self, name, src):
        return [f["cve_id"] for f in scan_sast_code("/r/" + name, src)]

    def test_innerhtml_binding_is_not_a_sanitization_bypass(self):
        self.assertNotIn("ANGULAR-BYPASS-SECURITY-TRUST", self._ids("a.component.html", '<div [innerHTML]="mensaje"></div>\n'))

    def test_bypass_call_is_still_reported(self):
        self.assertIn("ANGULAR-BYPASS-SECURITY-TRUST", self._ids("a.component.ts", "this.url = this.s.bypassSecurityTrustResourceUrl(x);\n"))

    def test_commented_out_bypass_call_is_not_reported(self):
        src = "// this.url = this.s.bypassSecurityTrustResourceUrl(x);\n/*\nthis.h = this.s.bypassSecurityTrustHtml(y);\n*/\n"
        self.assertNotIn("ANGULAR-BYPASS-SECURITY-TRUST", self._ids("a.component.ts", src))


class TestWriteAndOwnershipDetectionAccuracy(unittest.TestCase):
    def _ids(self, src, name="S.java"):
        return [f["cve_id"] for f in scan_sast_code("/r/" + name, src)]

    def test_crypto_update_calls_are_not_database_writes(self):
        src = "class U { public static byte[] f(byte[] a) { Signature s = Signature.getInstance(\"SHA256withRSA\"); s.update(a); digest.update(a); return s.sign(); } }\n"
        self.assertNotIn("JPA-MULTI-WRITE-NO-TRANSACTIONAL", self._ids(src))

    def test_two_repository_writes_without_transaction_are_still_reported(self):
        src = "class S { public void f(A a) { aRepository.save(a); bRepository.delete(a); } }\n"
        self.assertIn("JPA-MULTI-WRITE-NO-TRANSACTIONAL", self._ids(src))

    def test_an_access_policy_call_counts_as_an_ownership_check(self):
        src = ("class C {\n  @GetMapping(\"/{id}\")\n  public R get(@PathVariable Long id) {\n    var a = service.findById(id);\n    solicitudAccessPolicy.exigirAcceso(a.getIdSolicitud());\n    return ok(a);\n  }\n}\n")
        self.assertNotIn("POTENTIAL-IDOR-NO-OWNERSHIP-CHECK", self._ids(src, "C.java"))


class TestSpringDangerousConfigRules(unittest.TestCase):
    """Familia «configuración peligrosa de Spring» (2026-10-19), a raíz de CVE-2026-40972 (DevTools remoto)."""

    def test_devtools_remote_secret_flagged_without_leaking_value(self):
        res = scan_sast_code("/r/application.properties", "spring.devtools.remote.secret=MiSecretoRemoto123\n")
        got = {f["cve_id"] for f in res}
        self.assertIn("SPRING-DEVTOOLS-REMOTE-ENABLED", got)
        self.assertNotIn("CONFIG-SECRET-LITERAL", got)                       # la regla específica es la dueña de esa línea
        self.assertNotIn("MiSecretoRemoto123", " ".join(f["description"] for f in res))
        self.assertEqual(next(f["severity"] for f in res if f["cve_id"] == "SPRING-DEVTOOLS-REMOTE-ENABLED"), "HIGH")

    def test_devtools_remote_enabled_true_flagged(self):
        self.assertIn("SPRING-DEVTOOLS-REMOTE-ENABLED",
                      ids("/r/application.properties", "spring.devtools.remote.enabled=true\n"))

    def test_h2_console_enabled_flagged_and_downgraded_in_dev(self):
        self.assertIn("SPRING-H2-CONSOLE-ENABLED", ids("/r/application.properties", "spring.h2.console.enabled=true\n"))
        self.assertNotIn("SPRING-H2-CONSOLE-ENABLED", ids("/r/application.properties", "spring.h2.console.enabled=false\n"))
        dev = scan_sast_code("/r/application-dev.properties", "spring.h2.console.enabled=true\n")
        self.assertEqual(next(f["severity"] for f in dev if f["cve_id"] == "SPRING-H2-CONSOLE-ENABLED"), "MEDIUM")

    def test_actuator_wildcard_and_sensitive_exposure(self):
        self.assertIn("SPRING-ACTUATOR-SENSITIVE-EXPOSED",
                      ids("/r/application.properties", "management.endpoints.web.exposure.include=*\n"))
        self.assertIn("SPRING-ACTUATOR-SENSITIVE-EXPOSED",
                      ids("/r/application.properties", "management.endpoints.web.exposure.include=health,env,info\n"))

    def test_actuator_health_only_is_clean(self):
        self.assertNotIn("SPRING-ACTUATOR-SENSITIVE-EXPOSED",
                         ids("/r/application.properties", "management.endpoints.web.exposure.include=health,info\n"))
