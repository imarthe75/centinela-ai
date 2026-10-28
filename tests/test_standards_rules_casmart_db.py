"""Rules added 2026-10-27 from the shared org skills: org database/audit standard in .sql migrations, dangerous ddl-auto,
insecure OIDC client config and Starter code conventions. Each rule has a case that must fire and one that must not."""
import unittest

from auditors.auditor_standards_rules import scan_standards_rules
from core.coverage_matrix import classify_rule
from core.deduplication_engine import classify_finding_category


def ids(path, content):
    return sorted({f["cve_id"] for f in scan_standards_rules(path, content)})


STANDARD_TABLE = """CREATE TABLE IF NOT EXISTS public.ct_sedes ();
ALTER TABLE public.ct_sedes ADD COLUMN IF NOT EXISTS id uuid NOT NULL DEFAULT uuidv7(), ADD COLUMN IF NOT EXISTS ref uuid,
 ADD COLUMN IF NOT EXISTS row_version integer, ADD COLUMN IF NOT EXISTS fecha_creacion timestamptz, ADD COLUMN IF NOT EXISTS datos jsonb,
 ADD COLUMN IF NOT EXISTS monto numeric(12,2), ADD COLUMN IF NOT EXISTS creado timestamp with time zone DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE public.ct_sedes ADD CONSTRAINT pk_ct_sedes PRIMARY KEY (id);
"""


class TestSqlStandard(unittest.TestCase):
    def test_table_following_the_standard_is_clean(self):
        # also the regression of SQL-TABLE-WITHOUT-PRIMARY-KEY: the key added later with ALTER TABLE counts
        self.assertEqual(ids("/r/db/V1.sql", STANDARD_TABLE), [])

    def test_non_conforming_table_fires_each_rule(self):
        sql = "CREATE TABLE ventas (id bigserial PRIMARY KEY, fecha timestamp, extra json, monto double precision);"
        self.assertEqual(ids("/r/db/V2.sql", sql), ["SQL-FLOAT-FOR-MONEY", "SQL-JSON-NOT-JSONB", "SQL-PK-NOT-UUID",
                                                    "SQL-TABLE-WITHOUT-AUDIT-COLUMNS", "SQL-TIMESTAMP-WITHOUT-TIMEZONE"])

    def test_legacy_audit_convention_is_left_alone(self):
        sql = "CREATE TABLE app.personas (id uuid PRIMARY KEY, fccreacion timestamp DEFAULT localtimestamp, boborrado boolean);"
        self.assertEqual(ids("/r/db/V3.sql", sql), [])

    def test_audit_schema_objects_are_not_asked_for_uuid(self):
        sql = ("CREATE TABLE auditoria.log_auditoria (id bigint NOT NULL, recorddatetime timestamp with time zone);\n"
               "ALTER TABLE ONLY auditoria.log_auditoria ADD CONSTRAINT log_auditoria_pk PRIMARY KEY (id, recorddatetime);")
        self.assertEqual(ids("/r/db/auditoria.sql", sql), [])

    def test_other_engine_tables_are_skipped(self):
        sql = "CREATE TABLE analytics.eventos (id UInt64, ts DateTime) ENGINE = MergeTree ORDER BY id;"
        self.assertEqual(ids("/r/sql/clickhouse.sql", sql), [])

    def test_aggregated_per_file(self):
        sql = "\n".join(f"CREATE TABLE t{i} (id serial PRIMARY KEY, row_version int);" for i in range(15))
        found = [f for f in scan_standards_rules("/r/db/V4.sql", sql) if f["cve_id"] == "SQL-PK-NOT-UUID"]
        self.assertEqual(len(found), 1)
        self.assertIn("15 tabla(s)", found[0]["description"])


class TestSpringConfig(unittest.TestCase):
    def test_ddl_auto_update_in_base_profile(self):
        f = scan_standards_rules("/r/src/main/resources/application.properties", "spring.jpa.hibernate.ddl-auto=update\n")
        self.assertEqual([(x["cve_id"], x["severity"]) for x in f], [("SPRING-JPA-DDL-AUTO-SCHEMA-CHANGE", "MEDIUM")])

    def test_create_drop_is_high_and_dev_profile_low(self):
        hi = scan_standards_rules("/r/application-qa.yml", "spring:\n  jpa:\n    hibernate:\n      ddl-auto: create-drop\n")
        lo = scan_standards_rules("/r/application-dev.yml", "    ddl-auto: create-drop\n")
        self.assertEqual(hi[0]["severity"], "HIGH")
        self.assertEqual(lo[0]["severity"], "LOW")

    def test_none_and_validate_are_fine(self):
        self.assertEqual(ids("/r/application.properties", "spring.jpa.hibernate.ddl-auto=none\n"), [])
        self.assertEqual(ids("/r/application.yml", "ddl-auto: validate\n"), [])


class TestJavaConventions(unittest.TestCase):
    def test_controller_conventions_fire(self):
        java = ("@RestController\npublic class A { @Autowired\n  private FooService foo;\n  @Autowired private BarRepository bar;\n"
                "  @Transactional\n  @PostMapping public void x(){}\n  List<Object[]> q();\n}")
        self.assertEqual(ids("/r/src/main/java/A.java", java),
                         ["API-ENDPOINT-UNDOCUMENTED", "FIELD-INJECTION-AUTOWIRED", "JPA-OBJECT-ARRAY-RESULT", "TRANSACTIONAL-ON-CONTROLLER"])

    def test_constructor_injection_is_fine(self):
        java = ("@RestController @RequiredArgsConstructor\npublic class B { private final FooService foo;\n"
                "  @Autowired\n  public B(FooService f){ this.foo=f; } }")
        self.assertEqual(ids("/r/src/main/java/B.java", java), [])

    def test_tests_are_skipped(self):
        self.assertEqual(ids("/r/src/test/java/ATest.java", "@Autowired\nprivate Foo foo;\n"), [])


class TestApiDocumentation(unittest.TestCase):
    def test_undocumented_endpoint_fires_with_count(self):
        java = ('@RestController\n@RequestMapping("/sedes")\npublic class SedeController {\n'
                '  @Operation(summary = "Listar")\n  @GetMapping\n  public List<X> listar(){return null;}\n'
                '  @PostMapping\n  public X crear(@Valid @RequestBody X x){return null;}\n}')
        f = [x for x in scan_standards_rules("/r/src/main/java/SedeController.java", java) if x["cve_id"] == "API-ENDPOINT-UNDOCUMENTED"]
        self.assertEqual(len(f), 1)
        self.assertIn("1 de 2", f[0]["description"])

    def test_fully_documented_controller_is_fine(self):
        java = ('@RestController\n@RequestMapping("/sedes")\npublic class SedeController {\n'
                '  @Operation(summary = "Listar")\n  @ApiResponses({@ApiResponse(responseCode = "200")})\n  @GetMapping\n  public List<X> listar(){return null;}\n}')
        self.assertNotIn("API-ENDPOINT-UNDOCUMENTED", ids("/r/src/main/java/SedeController.java", java))


class TestFrontendRules(unittest.TestCase):
    def test_insecure_oidc_in_production_environment(self):
        self.assertEqual(ids("/r/src/environments/environment.prod.ts",
                             "export const environment={production:true, oidc:{requireHttps: false}};"), ["FRONTEND-OIDC-INSECURE-CONFIG"])

    def test_local_dev_environment_and_guarded_code_are_fine(self):
        self.assertEqual(ids("/r/src/environments/environment.local.ts", "export const e={oidc:{requireHttps: false}};"), [])
        self.assertEqual(ids("/r/src/environments/environment.ts", "export const e={production: false, oidc:{requireHttps: false}};"), [])
        guarded = "if (environment.useLocalMockAuth) {\n  oauthService.configure({ requireHttps: false });\n  return; }"
        self.assertEqual(ids("/r/src/app/core/auth/oidc.initializer.ts", guarded), [])

    def test_hardcoded_url_in_service(self):
        self.assertEqual(ids("/r/src/app/x/tramite.service.ts", "return this.http.get('https://api.ejemplo.gob.mx/v1/t');"),
                         ["FRONTEND-HARDCODED-API-URL"])
        self.assertEqual(ids("/r/src/app/x/tramite.service.ts", "return this.api.get(API_ENDPOINTS.TRAMITES.BASE);"), [])


class TestRegistration(unittest.TestCase):
    NEW = ["SQL-PK-NOT-UUID", "SQL-TIMESTAMP-WITHOUT-TIMEZONE", "SQL-JSON-NOT-JSONB", "SQL-FLOAT-FOR-MONEY", "SQL-TABLE-WITHOUT-AUDIT-COLUMNS",
           "TRANSACTIONAL-ON-CONTROLLER", "FIELD-INJECTION-AUTOWIRED", "JPA-OBJECT-ARRAY-RESULT", "FRONTEND-HARDCODED-API-URL",
           "SPRING-JPA-DDL-AUTO-SCHEMA-CHANGE", "FRONTEND-OIDC-INSECURE-CONFIG"]
    INFO_EXTRA = ["API-ENDPOINT-UNDOCUMENTED"]

    def test_every_new_rule_is_classified_in_the_coverage_matrix(self):
        self.assertEqual([r for r in self.NEW + self.INFO_EXTRA if classify_rule(r) is None], [])

    def test_categories(self):
        for r in self.NEW[:9] + self.INFO_EXTRA:
            self.assertEqual(classify_finding_category(r, "sast-native"), "INFORMATIONAL", r)
        for r in self.NEW[9:]:
            self.assertEqual(classify_finding_category(r, "sast-native"), "VULNERABILITY", r)


if __name__ == "__main__":
    unittest.main()
