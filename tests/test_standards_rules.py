"""ADR-0012: rules taken from the Estándar Maestro (5.4 silent failures, 5.10 destructive confirmation, 5.11 DDL, 6 CI/test gates).
Every rule has positive AND negative cases; they run on real text, not mocks."""
import unittest

from auditors.auditor_master_vulnerabilities import run_master_vulnerability_scan, scan_sast_code
from auditors.auditor_standards_rules import scan_standards_rules
from core import coverage_matrix as cm
from core import deduplication_engine as de


def rules(path, content, rule=None):
    return [f for f in scan_standards_rules(path, content) if rule is None or f["cve_id"] == rule]


class TestSwallowed(unittest.TestCase):
    def test_empty_catch_js_ts_java(self):
        self.assertEqual(len(rules("a.ts", "try { f(); } catch (e) {}\n", "SWALLOWED-ERROR")), 1)
        self.assertEqual(len(rules("A.java", "try { f(); } catch (IOException e) {\n}\n", "SWALLOWED-ERROR")), 1)
        self.assertEqual(rules("a.ts", "try { f(); } catch (e) { console.error(e); }\n"), [])
        self.assertEqual(rules("a.ts", "try { f(); } catch (ignored) {}\n"), [])                       # intent is stated
        self.assertEqual(rules("A.java", "try { t.join(); } catch (InterruptedException e) {}\n"), [])

    def test_catch_returning_default(self):
        for code in ("this.http.get(u).pipe(catchError(...)).toPromise().catch(() => []);", "p.catch(e => null)", "p.catch(() => of([]))"):
            self.assertEqual(len(rules("s.ts", code + "\n", "SWALLOWED-ERROR")), 1, code)
        self.assertEqual(rules("s.ts", "p.catch(e => this.log(e));\n"), [])

    def test_python_broad_except_pass_only(self):
        self.assertEqual(len(rules("a.py", "try:\n    f()\nexcept Exception:\n    pass\n", "SWALLOWED-ERROR")), 1)
        self.assertEqual(len(rules("a.py", "try:\n    f()\nexcept:\n    pass\n", "SWALLOWED-ERROR")), 1)
        self.assertEqual(rules("a.py", "try:\n    import x\nexcept ImportError:\n    pass\n"), [])         # deliberate optional import
        self.assertEqual(rules("a.py", "try:\n    f()\nexcept Exception as e:\n    logger.error(e)\n"), [])


class TestConfirm(unittest.TestCase):
    NO = "@Component({ selector: 'a', template: '' })\nexport class C {\n  eliminar(id: number) {\n    this.service.delete(id).subscribe();\n  }\n}\n"
    YES_BODY = ("@Component({ selector: 'a', template: '' })\nexport class C {\n  eliminar(id: number) {\n    this.confirmationService.confirm({ accept: () => {\n"
                "      this.service.delete(id).subscribe();\n    }});\n  }\n}\n")
    YES_CALLER = ("@Component({ selector: 'a', template: '' })\nexport class C {\n  askDelete(id: number) {\n    this.confirmationService.confirm({ accept: () => this.eliminar(id) });\n  }\n"
                  "  eliminar(id: number) {\n    this.service.delete(id).subscribe();\n  }\n}\n")

    def test_flags_only_unconfirmed(self):
        self.assertEqual(len(rules("c.ts", self.NO, "DESTRUCTIVE-ACTION-NO-CONFIRM")), 1)
        self.assertEqual(rules("c.ts", self.YES_BODY, "DESTRUCTIVE-ACTION-NO-CONFIRM"), [])
        self.assertEqual(rules("c.ts", self.YES_CALLER, "DESTRUCTIVE-ACTION-NO-CONFIRM"), [])      # confirmed by the method that invokes it

    def test_unrelated_confirm_far_away_does_not_excuse_it(self):
        far = "@Component({ selector: 'a', template: '' })\nexport class C {\n  a() { this.confirmationService.confirm({}); }\n" + "  x() {}\n" * 60 + self.NO.split("{\n", 1)[1]
        self.assertEqual(len(rules("c.ts", far, "DESTRUCTIVE-ACTION-NO-CONFIRM")), 1)

    def test_native_dialog_but_not_library_calls_or_method_definitions(self):
        self.assertEqual(len(rules("c.ts", "if (confirm('¿Seguro?')) { go(); }\n", "NATIVE-BROWSER-DIALOG")), 1)
        self.assertEqual(len(rules("c.ts", "window.alert('listo');\n", "NATIVE-BROWSER-DIALOG")), 1)
        self.assertEqual(rules("c.ts", "this.confirmationService.confirm({});\n", "NATIVE-BROWSER-DIALOG"), [])
        self.assertEqual(rules("c.ts", "  confirm() {\n    this.done.emit();\n  }\n", "NATIVE-BROWSER-DIALOG"), [])

    def test_tests_are_skipped(self):
        self.assertEqual(rules("c.spec.ts", self.NO), [])

    def test_a_data_service_wrapping_http_delete_is_not_flagged_but_a_component_is(self):
        svc = "@Injectable({ providedIn: 'root' })\nexport class S {\n  delete(id: number) {\n    return this.http.delete(`/x/${id}`);\n  }\n}\n"
        self.assertEqual(rules("s.service.ts", svc, "DESTRUCTIVE-ACTION-NO-CONFIRM"), [])
        comp = "@Component({ selector: 'a', template: '' })\n" + self.NO
        self.assertEqual(len(rules("c.component.ts", comp, "DESTRUCTIVE-ACTION-NO-CONFIRM")), 1)

    def test_template_event_handlers_named_confirm_are_not_native_dialogs(self):
        self.assertEqual(rules("c.ts", "template: `<p-button (click)=\"confirm($event)\" label=\"x\"></p-button>`\n", "NATIVE-BROWSER-DIALOG"), [])
        self.assertEqual(rules("c.ts", "template: `<button onclick=\"confirm('x')\">`\n", "NATIVE-BROWSER-DIALOG"), [])


class TestSql(unittest.TestCase):
    def test_table_without_primary_key(self):
        sql = "CREATE TABLE a (x int);\nCREATE TABLE b (id uuid PRIMARY KEY);\nCREATE TABLE c (x int, y int, PRIMARY KEY (x,y));\n"
        got = rules("db/V1.sql", sql, "SQL-TABLE-WITHOUT-PRIMARY-KEY")
        self.assertEqual([(f["line"]) for f in got], [1])
        self.assertIn("`a`", got[0]["description"])

    def test_exceptions(self):
        sql = ("CREATE TEMP TABLE t (x int);\nCREATE TABLE d AS SELECT 1;\nCREATE TABLE e (LIKE b INCLUDING ALL);\n"
               "CREATE TABLE f PARTITION OF g FOR VALUES IN (1);\n-- CREATE TABLE commented (x int);\n/* CREATE TABLE blockc (x int); */\n")
        self.assertEqual(rules("m.sql", sql), [])

    def test_constraint_with_nested_parens_and_if_not_exists(self):
        sql = 'CREATE TABLE IF NOT EXISTS "s"."t" (\n  id numeric(10,2) NOT NULL,\n  CONSTRAINT pk PRIMARY KEY (id)\n);\n'
        self.assertEqual(rules("m.sql", sql, "SQL-TABLE-WITHOUT-PRIMARY-KEY"), [])
        self.assertEqual(len(rules("m.sql", 'CREATE TABLE IF NOT EXISTS "s"."t" (\n  id numeric(10,2) NOT NULL\n);\n', "SQL-TABLE-WITHOUT-PRIMARY-KEY")), 1)

    def test_only_sql_files(self):
        self.assertEqual(rules("notes.md", "CREATE TABLE a (x int);"), [])


class TestCI(unittest.TestCase):
    def test_gitlab_allow_failure_on_test_jobs_only(self):
        ci = "unit-tests:\n  stage: test\n  script: [pytest]\n  allow_failure: true\n\nbuild:\n  stage: build\n  script: [make]\n  allow_failure: true\n\nlint:\n  script: [x]\n  allow_failure: false\n"
        got = rules(".gitlab-ci.yml", ci, "CICD-GATE-ALLOW-FAILURE")
        self.assertEqual(len(got), 1)
        self.assertIn("unit-tests", got[0]["description"])
        self.assertEqual(got[0]["line"], 4)

    def test_github_continue_on_error(self):
        wf = ("jobs:\n  tests:\n    runs-on: ubuntu-latest\n    continue-on-error: true\n    steps:\n      - run: pytest\n"
              "  deploy:\n    runs-on: ubuntu-latest\n    steps:\n      - name: Run unit tests\n        run: pytest\n        continue-on-error: true\n"
              "      - name: notify\n        run: curl x\n        continue-on-error: true\n")
        got = rules(".github/workflows/ci.yml", wf, "CICD-GATE-ALLOW-FAILURE")
        self.assertEqual(len(got), 2)                                  # the tests job and the test step; `notify` is not a gate

    def test_other_yaml_and_broken_yaml_are_ignored(self):
        self.assertEqual(rules("config/app.yml", "tests:\n  allow_failure: true\n"), [])
        self.assertEqual(rules(".gitlab-ci.yml", "a: [unclosed\n"), [])


class TestSkipped(unittest.TestCase):
    def test_js(self):
        self.assertEqual(len(rules("a.spec.ts", "it.skip('x', () => {});\nxdescribe('y', () => {});\n", "TEST-SKIPPED-WITHOUT-REASON")), 2)
        self.assertEqual(len(rules("a.spec.ts", "fit('x', () => {});\ndescribe.only('y', () => {});\n", "TEST-SKIPPED-WITHOUT-REASON")), 2)
        self.assertEqual(rules("a.spec.ts", "it.skip('x', () => {}); // flaky on CI, see TICKET-12\n"), [])
        self.assertEqual(rules("a.ts", "it.skip('x', () => {});\n"), [])                      # not a test file

    def test_java_and_python(self):
        self.assertEqual(len(rules("src/test/java/ATest.java", "  @Disabled\n  void a() {}\n", "TEST-SKIPPED-WITHOUT-REASON")), 1)
        self.assertEqual(rules("src/test/java/ATest.java", '  @Disabled("flaky, issue 4")\n  void a() {}\n'), [])
        self.assertEqual(len(rules("tests/test_a.py", "@pytest.mark.skip\ndef test_a():\n    pass\n", "TEST-SKIPPED-WITHOUT-REASON")), 1)
        self.assertEqual(rules("tests/test_a.py", '@pytest.mark.skip(reason="needs db")\ndef test_a():\n    pass\n'), [])


class TestIntegration(unittest.TestCase):
    def test_wired_into_the_sast_scan_and_classified(self):
        f = [x for x in scan_sast_code("web/src/app/a.ts", "try { f(); } catch (e) {}\n") if x["cve_id"] == "SWALLOWED-ERROR"]
        self.assertEqual(len(f), 1)
        for rid in ("SWALLOWED-ERROR", "DESTRUCTIVE-ACTION-NO-CONFIRM", "NATIVE-BROWSER-DIALOG", "SQL-TABLE-WITHOUT-PRIMARY-KEY",
                    "CICD-GATE-ALLOW-FAILURE", "TEST-SKIPPED-WITHOUT-REASON"):
            self.assertEqual(de.classify_finding_category(rid, "sast-native", ""), "INFORMATIONAL", rid)
            self.assertEqual(cm.unclassified([rid]), [], rid)

    def test_sql_files_reach_the_scanner(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "db").mkdir()
            (Path(d) / "db" / "V1.sql").write_text("CREATE TABLE t (x int);\n")
            got = run_master_vulnerability_scan(d, asset_id=None)
        self.assertIn("SQL-TABLE-WITHOUT-PRIMARY-KEY", [x["cve_id"] for x in got])


if __name__ == "__main__":
    unittest.main()
