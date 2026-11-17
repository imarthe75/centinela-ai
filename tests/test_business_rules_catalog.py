"""Detectors derived from the CORE/Starter business-rule catalogue (auditors/auditor_business_rules.py).
Positive cases are shaped after real code found in the fleet on 2026-10-28; negatives are the false positives seen there."""
import unittest

from auditors.auditor_business_rules import scan_business_rules
from core.coverage_matrix import classify_rule
from core.deduplication_engine import classify_finding_category


def ids(path, content):
    return sorted({f["cve_id"] for f in scan_business_rules(path, content)})


class TestPasswordMin(unittest.TestCase):
    def test_java_record_size_under_10(self):
        src = 'public record CrearUsuarioRequest(\n  @NotBlank @Size(min = 8, message = "x") String contraseniaInicial) {}'
        self.assertEqual(ids("/r/src/main/java/a/CrearUsuarioRequest.java", src), ["PASSWORD-MIN-LENGTH-BELOW-STANDARD"])

    def test_java_size_10_is_fine(self):
        src = 'public record R(@Size(min = 10) String password) {}'
        self.assertEqual(ids("/r/src/main/java/a/R.java", src), [])

    def test_angular_validator(self):
        self.assertEqual(ids("/r/src/app/u.component.ts", "password: ['', [Validators.minLength(6)]],"), ["PASSWORD-MIN-LENGTH-BELOW-STANDARD"])
        self.assertEqual(ids("/r/src/app/u.component.ts", "this.f.get('newPassword')?.setValidators([Validators.minLength(8)]);"),
                         ["PASSWORD-MIN-LENGTH-BELOW-STANDARD"])
        self.assertEqual(ids("/r/src/app/u.component.ts", "password: ['', [Validators.minLength(12)]],"), [])

    def test_catalogue_key_named_clave_is_not_a_password(self):
        self.assertEqual(ids("/r/src/main/java/a/CrearPuestoRequest.java", '@Size(min = 2, max = 20) String clave,'), [])


class TestNumericCodes(unittest.TestCase):
    def test_sql_numeric_postal_code(self):
        self.assertEqual(ids("/r/db/changelog/x.sql", "ALTER TABLE t\n    ADD COLUMN IF NOT EXISTS c_cp numeric(5,0),"), ["NUMERIC-CODE-STORED-AS-NUMBER"])

    def test_plpgsql_variable_is_not_a_column(self):
        self.assertEqual(ids("/r/db/changelog/x.sql", "DECLARE\n    v_count_cp integer;"), [])

    def test_ts_and_java(self):
        self.assertEqual(ids("/r/src/app/m/datos.ts", "  codigoPostal: number;"), ["NUMERIC-CODE-STORED-AS-NUMBER"])
        self.assertEqual(ids("/r/src/main/java/a/Usuario.java", "    private int codigoPostal;"), ["NUMERIC-CODE-STORED-AS-NUMBER"])
        self.assertEqual(ids("/r/src/app/m/datos.ts", "  codigoPostal: string;"), [])

    def test_generic_key_is_not_geographic(self):
        self.assertEqual(ids("/r/src/main/java/a/Color.java", "    private Integer cveColor;"), [])


class TestAuditLogMutation(unittest.TestCase):
    def test_delete_on_bitacora_controller(self):
        src = '@RestController\n@RequestMapping("/api/bitacora")\npublic class BitacoraController {\n  @DeleteMapping("/{id}")\n  void borrar() {}\n}'
        self.assertEqual(ids("/r/src/main/java/a/BitacoraController.java", src), ["AUDIT-LOG-MUTATION-ENDPOINT"])

    def test_read_only_audit_controller_with_post_search(self):
        src = '@RequestMapping("/admin/auditoria")\npublic class AuditAdminController {\n  @PostMapping("/search") X s() {}\n  @GetMapping("/modulos") Y m() {}\n}'
        self.assertEqual(ids("/r/src/main/java/a/AuditAdminController.java", src), [])

    def test_repository_delete_of_audit_rows(self):
        self.assertEqual(ids("/r/src/main/java/a/Svc.java", "bitacoraRepository.deleteById(id);"), ["AUDIT-LOG-MUTATION-ENDPOINT"])


class TestSvgUpload(unittest.TestCase):
    def test_svg_in_upload_allowlist_without_sanitizer(self):
        src = ('class ImagenService {\n  static final Set<String> ALLOWED_TYPES = Set.of("image/png", "image/jpeg", "image/svg+xml");\n'
               '  void subir(MultipartFile f) { if (!ALLOWED_TYPES.contains(f.getContentType())) throw new X(); }\n}')
        self.assertEqual(ids("/r/src/main/java/a/ImagenService.java", src), ["SVG-UPLOAD-WITHOUT-SANITIZATION"])

    def test_with_sanitizer(self):
        src = ('static final Set<String> ALLOWED_TYPES = Set.of("image/png", "image/svg+xml");\n void subir(MultipartFile f) {}\n'
               'String limpio = svgSanitizer.sanitize(contenido);')
        self.assertEqual(ids("/r/src/main/java/a/ImagenService.java", src), [])

    def test_svg_output_content_type_is_not_an_upload(self):
        src = 'String t = esPng ? "image/png"\n    : "image/svg+xml";\nString ct = resp.getContentType();'
        self.assertEqual(ids("/r/src/main/java/a/QrClient.java", src), [])


class TestTemplateEscape(unittest.TestCase):
    def test_raw_value_into_email_template(self):
        src = 'class EmailServiceImpl {\n void f(String template) {\n  template = template.replace("{{" + keyStr + "}}", valStr);\n }\n}'
        self.assertEqual(ids("/r/src/main/java/a/EmailServiceImpl.java", src), ["HTML-TEMPLATE-UNESCAPED-SUBSTITUTION"])

    def test_escaped_value(self):
        src = 'class EmailServiceImpl {\n void f(String template) {\n  template = template.replace("{{" + k + "}}", HtmlUtils.htmlEscape(v));\n }\n}'
        self.assertEqual(ids("/r/src/main/java/a/EmailServiceImpl.java", src), [])

    def test_character_class_replace_is_not_a_template(self):
        src = 'class PlantillaController {\n String f(String s) { return s.replaceAll("[áàâãä]", "A"); }\n}'
        self.assertEqual(ids("/r/src/main/java/a/PlantillaController.java", src), [])


class TestFolio(unittest.TestCase):
    def test_last_plus_one_without_lock(self):
        src = 'class FolioService {\n void emitir() {\n  cfg.setConsecutivo(cfg.getConsecutivo() + 1);\n  repo.save(cfg);\n }\n}'
        self.assertEqual(ids("/r/src/main/java/a/FolioService.java", src), ["SEQUENTIAL-FOLIO-FROM-MAX"])

    def test_with_select_for_update(self):
        src = ('class EmisionFolioServiceImpl {\n void e() {\n  var c = folioConsecutivoRepository.findForUpdate(a, b, y).orElseThrow();\n'
               '  long nuevoConsecutivo = c.getUltimoConsecutivo() + 1;\n }\n}')
        self.assertEqual(ids("/r/src/main/java/a/EmisionFolioServiceImpl.java", src), [])

    def test_sequence_reset_and_seed_insert(self):
        self.assertEqual(ids("/r/db/changelog/73.sql",
                             "-- consecutivo\nSELECT setval(pg_get_serial_sequence('t','id'), (SELECT MAX(id) + 1 FROM t));"), [])
        self.assertEqual(ids("/r/db/changelog/74.sql", "-- consecutivo\nINSERT INTO t SELECT max(id) + 1, 'x' FROM t;"), [])

    def test_comparison_is_not_emission(self):
        src = 'class Navega { boolean f() { return o.getConsecutivo() == (t.getConsecutivo() + 1); } } // consecutivo'
        self.assertEqual(ids("/r/src/main/java/a/Navega.java", src), [])


class TestEnumeration(unittest.TestCase):
    def test_recovery_reveals_unknown_email(self):
        src = 'class ResetPasswordService {\n void r() { dto.setMessage("No se encontro el usuario con el correo:" + e); }\n}'
        self.assertEqual(ids("/r/src/main/java/a/ResetPasswordService.java", src), ["ACCOUNT-ENUMERATION-RESPONSE"])

    def test_unrelated_message_and_server_log(self):
        src = ('class ResetPasswordService {\n void r() {\n  throw new X("No existe el rol seleccionado para el usuario");\n'
               '  log.warn("usuario no encontrado {}", e);\n }\n}')
        self.assertEqual(ids("/r/src/main/java/a/ResetPasswordService.java", src), [])

    def test_only_recovery_files(self):
        self.assertEqual(ids("/r/src/main/java/a/UsuarioService.java", 'throw new X("Usuario no encontrado");'), [])


class TestRegistration(unittest.TestCase):
    RULES = ["PASSWORD-MIN-LENGTH-BELOW-STANDARD", "NUMERIC-CODE-STORED-AS-NUMBER", "AUDIT-LOG-MUTATION-ENDPOINT",
             "SVG-UPLOAD-WITHOUT-SANITIZATION", "HTML-TEMPLATE-UNESCAPED-SUBSTITUTION", "SEQUENTIAL-FOLIO-FROM-MAX",
             "ACCOUNT-ENUMERATION-RESPONSE"]

    def test_classified_in_coverage_matrix(self):
        self.assertEqual([r for r in self.RULES if classify_rule(r) is None], [])

    def test_categories(self):
        self.assertEqual(classify_finding_category("NUMERIC-CODE-STORED-AS-NUMBER", "sast-native"), "INFORMATIONAL")
        for r in self.RULES:
            if r != "NUMERIC-CODE-STORED-AS-NUMBER":
                self.assertEqual(classify_finding_category(r, "sast-native"), "VULNERABILITY", r)

    def test_heuristic_routing_substrings_avoided(self):
        for r in self.RULES:
            for bad in ("PORT", "OPEN", "EXPOSED", "NET", "SSH", "CIS", "DOCKER", "CONTAINER", "AUTH"):
                self.assertNotIn(bad, r, (r, bad))

    def test_reached_through_the_standards_dispatcher(self):
        from auditors.auditor_standards_rules import scan_standards_rules
        found = {f["cve_id"] for f in scan_standards_rules("/r/src/app/u.component.ts", "password: ['', [Validators.minLength(6)]],")}
        self.assertIn("PASSWORD-MIN-LENGTH-BELOW-STANDARD", found)


if __name__ == "__main__":
    unittest.main()
