"""Group triage report: classification by the analyst's rules, dedup, plan arithmetic, workbook, and the API against a real schema.

DB-backed tests run inside ONE transaction that is rolled back (project rule #8) with db_manager.get_db_cursor patched to share it.
"""
import contextlib
import importlib.util
import io
import unittest
import zipfile
from datetime import datetime
from unittest import mock

from fastapi.testclient import TestClient

from core import db_manager, triage
from core.gitlab_instances import GitLabInstance
from core.triage_workbook import build_workbook

INST = GitLabInstance("gitlab2", "http://gitlab.example", "", "GitLab2/", "gitlab2__")


def F(repo="repo1", engine="sonarqube", rule="SONAR-x", url_path="src/A.java:10", sev="HIGH", effort=None, desc="d", db_id="1"):
    file_, line = triage.parse_location(url_path)
    return dict(db_id=db_id, asset_name=f"GitLab2/grp/sub/{repo}", repo=repo, rule=rule, engine=engine, url_path=url_path, file=file_, line=line,
                severity_raw=sev, severity_eff=sev, no_risk=False, reach="", description=desc, title=desc, effort_min=effort, outdated=False, dep={})


CAUSES = {
    "V-01": dict(code="V-01", classification="Vulnerabilidad", title="Secretos", kind="Seguridad", severity="Crítico", dedup_scope="line",
                 plan=dict(order=1, phase="1 · Inmediato", activity="Rotar", unit="por secreto", minutes=60, extra_hours=9, confirm_hours=0,
                           area_pct=[0.4, 0.4, 0.2, 0], minutes_source="Análisis")),
    "FP-01": dict(code="FP-01", classification="Falso positivo", title="Dev", kind="Artefacto de desarrollo", dedup_scope="line"),
    "C-01": dict(code="C-01", classification="Calidad", title="Docker root", kind="Endurecimiento", dedup_scope="file",
                 plan=dict(order=2, phase="3 · Mediano plazo", activity="USER", unit="por imagen", minutes=15, extra_hours=0, confirm_hours=1,
                           area_pct=[1, 0, 0, 0], default_criticality="Medio")),
}


class TestParsing(unittest.TestCase):
    def test_location(self):
        self.assertEqual(triage.parse_location("src/Foo.java:57"), ("src/Foo.java", 57))
        self.assertEqual(triage.parse_location("Dockerfile"), ("Dockerfile", None))
        self.assertEqual(triage.parse_location("gitlab:grp/r#merge-gate"), ("gitlab:grp/r#merge-gate", None))
        self.assertEqual(triage.parse_location(None), ("", None))

    def test_effort(self):
        self.assertEqual(triage.parse_effort_minutes("x\n**Esfuerzo estimado:** 5min"), 5)
        self.assertEqual(triage.parse_effort_minutes("**Esfuerzo estimado:** 1h30min"), 90)
        self.assertEqual(triage.parse_effort_minutes("**Esfuerzo estimado:** 1d"), 480)
        self.assertIsNone(triage.parse_effort_minutes("**Esfuerzo estimado:** N/D"))
        self.assertIsNone(triage.parse_effort_minutes("sin estimado"))

    def test_dependency(self):
        d = triage.parse_dependency("**Paquete:** ckeditor5\n**Versión instalada:** 45.0.0\n**Versión segura:** 45.2.2\n")
        self.assertEqual(d, {"package": "ckeditor5", "installed": "45.0.0", "fixed": "45.2.2"})


class TestClassification(unittest.TestCase):
    def rules(self):
        return [dict(id="g", rule_regex="^SONAR-x$", engine=None, asset_regex=None, path_regex=None, line=None, root_cause_code="V-01", priority=0, note=None),
                dict(id="f", rule_regex="^SONAR-x$", engine=None, asset_regex="/repo2$", path_regex=r"^src/Dev\.java(:\d+)?$", line=None,
                     root_cause_code="FP-01", priority=10, note="perfil dev"),
                dict(id="l", rule_regex="^SONAR-x$", engine=None, asset_regex="/repo2$", path_regex=r"^src/Dev\.java(:\d+)?$", line=7,
                     root_cause_code="C-01", priority=20, note=None)]

    def test_most_specific_rule_wins_and_unknown_stays_unclassified(self):
        fs = [F("repo1"), F("repo2", url_path="src/Dev.java:3"), F("repo2", url_path="src/Dev.java:7"), F("repo1", rule="OTHER")]
        triage.classify(fs, self.rules(), CAUSES)
        self.assertEqual([f["cause"] for f in fs], ["V-01", "FP-01", "C-01", triage.UNCLASSIFIED])
        self.assertEqual(fs[1]["note"], "perfil dev")
        self.assertEqual(fs[3]["classification"], "Sin clasificar")

    def test_rule_pointing_at_a_missing_cause_does_not_classify(self):
        fs = [F()]
        triage.classify(fs, [dict(id="x", rule_regex=".", root_cause_code="V-99", priority=0)], CAUSES)
        self.assertEqual(fs[0]["cause"], triage.UNCLASSIFIED)

    def test_engine_filter(self):
        fs = [F(engine="semgrep", rule="java.x.spring-actuator-abc")]
        triage.classify(fs, [dict(id="e", rule_regex="spring\\-actuator", engine="sonarqube", root_cause_code="V-01", priority=0)], CAUSES)
        self.assertEqual(fs[0]["cause"], triage.UNCLASSIFIED)


class TestDuplicates(unittest.TestCase):
    def prep(self, fs, causes=CAUSES):
        for f in fs:
            f["cause"] = f.pop("_c", "V-01")
        triage.number_occurrences(fs)
        triage.mark_duplicates(fs, causes)
        return fs

    def test_same_line_two_engines_keeps_best_ranked(self):
        a, b = F(engine="sonarqube", db_id="1"), F(engine="sast-native", rule="CFG", db_id="2")
        self.prep([a, b])
        self.assertEqual(a["duplicate_of"], "")
        self.assertEqual(b["duplicate_of"], a["occ_id"])

    def test_same_engine_same_line_is_not_a_duplicate(self):
        a, b = F(rule="R1", db_id="1"), F(rule="R2", db_id="2")
        self.prep([a, b])
        self.assertEqual((a["duplicate_of"], b["duplicate_of"]), ("", ""))

    def test_different_cause_same_line_is_not_a_duplicate(self):
        a, b = F(engine="sonarqube", db_id="1"), F(engine="semgrep", db_id="2")
        b["_c"] = "FP-01"
        self.prep([a, b])
        self.assertEqual(b["duplicate_of"], "")

    def test_file_scope_collapses_different_lines(self):
        a = F(engine="sonarqube", url_path="Dockerfile:1", db_id="1"); a["_c"] = "C-01"
        b = F(engine="semgrep", url_path="Dockerfile:29", db_id="2"); b["_c"] = "C-01"
        self.prep([a, b])
        self.assertEqual(b["duplicate_of"], a["occ_id"])

    def test_repo_level_check_without_line_is_never_merged(self):
        a, b = F(url_path="gitlab:grp/r#merge-gate", db_id="1"), F(url_path="gitlab:grp/r#merge-gate", engine="semgrep", db_id="2")
        self.prep([a, b])
        self.assertEqual((a["duplicate_of"], b["duplicate_of"]), ("", ""))


class TestPlan(unittest.TestCase):
    GROUP = dict(hours_per_day=8, test_pct=0.3, fp_check_hours=0.5, areas=[])

    def make(self):
        fs = [F(db_id="1", effort=60), F(db_id="2", url_path="src/B.java:2", effort=60), F(db_id="3", url_path="src/C.java:3"),
              F(db_id="4", url_path="src/D.java:4")]
        for f, c in zip(fs, ["V-01", "V-01", "FP-01", "C-01"]):
            f["cause"] = c
        fs[0]["classification"] = "Vulnerabilidad"
        triage.number_occurrences(fs)
        triage.mark_duplicates(fs, CAUSES)
        return fs

    def test_arithmetic(self):
        rows = triage.compute_plan(self.GROUP, CAUSES, self.make())
        by = {r["code"]: r for r in rows}
        self.assertNotIn("FP-01", by)                       # false positives are outside the plan
        v = by["V-01"]
        self.assertEqual(v["qty"], 2)
        self.assertAlmostEqual(v["correction"], 2.0)        # 2 x 60 min
        self.assertAlmostEqual(v["tests"], (2.0 + 9) * 0.3)
        self.assertAlmostEqual(v["total"], 2.0 + 9 + 3.3)
        self.assertAlmostEqual(v["centinela_h"], 2.0)       # only what the tool estimated
        self.assertAlmostEqual(v["days"], v["total"] / 8)
        self.assertEqual(v["criticality"], "Crítico")
        self.assertEqual(by["C-01"]["criticality"], "Medio")
        self.assertEqual([r["code"] for r in rows], ["V-01", "C-01"])  # criticality order

    def test_fixed_quantity_overrides_occurrence_count_but_only_while_findings_remain(self):
        causes = {**CAUSES, "V-01": {**CAUSES["V-01"], "plan": {**CAUSES["V-01"]["plan"], "fixed_qty": 5}}}
        fs = self.make()
        rows = {r["code"]: r for r in triage.compute_plan(self.GROUP, causes, fs)}
        self.assertEqual(rows["V-01"]["qty"], 5)                       # 2 occurrences, but the analyst planned 5 units of work
        self.assertAlmostEqual(rows["V-01"]["correction"], 5.0)
        self.assertNotIn("V-01", [r["code"] for r in triage.compute_plan(self.GROUP, causes, [f for f in fs if f["cause"] != "V-01"])])

    def test_cause_without_findings_is_not_planned(self):
        fs = [f for f in self.make() if f["cause"] != "C-01"]
        self.assertNotIn("C-01", [r["code"] for r in triage.compute_plan(self.GROUP, CAUSES, fs)])


def _data(findings, coverage=None):
    triage.number_occurrences(findings)
    triage.classify(findings, [dict(id="g", rule_regex="^SONAR-x$", root_cause_code="V-01", priority=0)], CAUSES)
    triage.mark_duplicates(findings, CAUSES)
    group = dict(group_path="grp/sub", title="TEST", instance="gitlab2", hours_per_day=8, test_pct=0.3, fp_check_hours=0.5,
                 areas=[dict(name="Prog", people=1, dedication=1)])
    return dict(group=group, instance=INST, causes=CAUSES, rules=[], findings=findings, informational=5, coverage_error=None,
                coverage=coverage or [dict(repo="repo1", path="grp/sub/repo1", status="Escaneado", last_audit="2026-10-09", findings=len(findings), note="")],
                plan=triage.compute_plan(group, CAUSES, findings), generated_at=datetime(2026, 10, 9, 12, 0))


def _cached(xlsx_bytes, sheet, cell):
    spec = importlib.util.spec_from_file_location("bts", "/app/scripts/build_triage_seed.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".xlsx") as tf:
        tf.write(xlsx_bytes); tf.flush()
        rows = mod.Book(tf.name).sheet(sheet)
    import re
    col, row = re.match(r"([A-Z]+)(\d+)", cell).groups()
    return rows.get(int(row), {}).get(col)


class TestWorkbook(unittest.TestCase):
    def test_workbook_sheets_and_cached_values_match_the_data(self):
        fs = [F(db_id="1", effort=60), F(db_id="2", url_path="src/B.java:2"), F(db_id="3", rule="UNKNOWN", url_path="src/C.java:3")]
        blob = build_workbook(_data(fs))
        z = zipfile.ZipFile(io.BytesIO(blob))
        wbx = z.read("xl/workbook.xml").decode()
        for name in ("Resumen", "Cobertura", "Plan de trabajo", "Vulnerabilidades", "Falsos positivos", "Calidad", "Versiones desactualizadas", "Detalle", "Criterios"):
            self.assertIn(f'name="{name}"', wbx)
        self.assertEqual(_cached(blob, "Resumen", "B6"), "2")      # Vulnerabilidad
        self.assertEqual(_cached(blob, "Resumen", "B9"), "1")      # Sin clasificar: nothing is guessed
        self.assertEqual(_cached(blob, "Resumen", "B10"), "3")
        self.assertEqual(_cached(blob, "Resumen", "C11"), "Cuadra con Centinela")
        self.assertEqual(_cached(blob, "Detalle", "M4"), triage.UNCLASSIFIED)
        sheet_xml = "".join(z.read(n).decode() for n in z.namelist() if n.startswith("xl/worksheets/sheet"))
        self.assertIn("<f>COUNTIF(Detalle!$K$2:$K$4,A6)</f>", sheet_xml)   # counts are live formulas over Detalle

    def test_empty_group_builds(self):
        blob = build_workbook(_data([], coverage=[]))
        self.assertTrue(blob.startswith(b"PK"))


class TestGroupCoverage(unittest.TestCase):
    def test_not_scanned_is_not_reported_as_clean(self):
        assets = {"GitLab2/grp/sub/a": {"asset_name": "GitLab2/grp/sub/a", "last_audit": "2026-10-09T00:00:00"},
                  "GitLab2/grp/sub/old": {"asset_name": "GitLab2/grp/sub/old", "last_audit": "2026-10-01T00:00:00"}}
        gl = [dict(path="grp/sub/a", archived=False), dict(path="grp/sub/b", archived=False), dict(path="grp/other/z", archived=True)]
        cov = triage.build_coverage(INST, "grp/sub", assets, [F("a")], gl, None)
        by = {c["path"]: c for c in cov}
        self.assertEqual(by["grp/sub/a"]["status"], "Escaneado")
        self.assertTrue(by["grp/sub/b"]["status"].startswith("Sin escanear"))
        self.assertIn("ya no lo lista", by["grp/sub/old"]["note"])
        self.assertEqual(by["grp/other/z"]["note"], "Archivado en GitLab")

    def test_gitlab_error_is_surfaced_not_hidden(self):
        with mock.patch("requests.get", side_effect=ConnectionError("boom")):
            projects, err = triage.list_group_projects(INST, "grp/sub")
        self.assertEqual(projects, [])
        self.assertIn("No se pudo consultar GitLab", err)

    def test_group_listing_paginates_and_includes_subgroups(self):
        def page(n):
            return mock.Mock(status_code=200, json=lambda: [{"path_with_namespace": f"grp/sub/p{n}-{i}", "archived": False} for i in range(100 if n == 1 else 3)])
        with mock.patch("requests.get", side_effect=[page(1), page(2)]) as g:
            projects, err = triage.list_group_projects(INST, "grp/sub")
        self.assertIsNone(err)
        self.assertEqual(len(projects), 103)
        self.assertEqual(g.call_args_list[0].kwargs["params"]["include_subgroups"], "true")


class TestTriageApi(unittest.TestCase):
    """Real schema, one rolled-back transaction."""

    def setUp(self):
        self._stack = contextlib.ExitStack()
        self.addCleanup(self._cleanup)
        self.conn = self._stack.enter_context(db_manager.get_db_connection())

        @contextlib.contextmanager
        def shared_cursor(cursor_factory=None):
            cur = self.conn.cursor(cursor_factory=cursor_factory)
            try:
                yield cur
            finally:
                cur.close()

        self._stack.enter_context(mock.patch.object(db_manager, "get_db_cursor", shared_cursor))
        self._stack.enter_context(mock.patch("api.routers.triage.get_instance", return_value=INST))
        self._stack.enter_context(mock.patch("core.triage.list_group_projects", return_value=(
            [dict(path="tgrp/sub/a", archived=False), dict(path="tgrp/sub/never", archived=False)], None)))
        from main import app
        self.client = TestClient(app)
        cur = self.conn.cursor()
        cur.execute("""INSERT INTO infra_inventory (asset_name, asset_type, endpoint, criticality, status, last_audit)
                       VALUES ('GitLab2/tgrp/sub/a','GitLab-Repo','x','LOW','ACTIVE','2026-10-09T00:00:00') RETURNING id""")
        aid = cur.fetchone()[0]
        for i, (rule, up, cat) in enumerate([("SONAR-x", "src/A.java:1", "VULNERABILITY"), ("SONAR-x", "src/B.java:2", "VULNERABILITY"),
                                             ("NO-RULE-COVERS-THIS", "src/C.java:3", "VULNERABILITY"), ("SMELL", "src/D.java:4", "INFORMATIONAL")]):
            cur.execute("""INSERT INTO vulnerability_log (asset_id, cve_id, severity, status, scan_engine, url_path, description, finding_category,
                               fingerprint_hash) VALUES (%s,%s,'HIGH','CORRELATED','sonarqube',%s,%s,%s,%s)""",
                        (aid, rule, up, "**SonarQube VULNERABILITY** (x)\ntexto\n**Esfuerzo estimado:** 5min", cat, f"tfp-triage-{i}"))
        triage.load_seed(cur, dict(
            group=dict(instance="gitlab2", group_path="tgrp/sub", title="T", hours_per_day=8, test_pct=0.3, fp_check_hours=0.5, areas=[]),
            root_causes=[dict(code="V-01", classification="Vulnerabilidad", title="Causa", severity="Alto", plan=dict(order=1, minutes=10, phase="1 · Inmediato"))],
            rules=[dict(rule_regex="^SONAR-x$", root_cause_code="V-01", priority=0)]), "pytest")

    def _cleanup(self):
        try:
            self.conn.rollback()
        finally:
            self._stack.close()

    def test_summary_takes_the_whole_group_and_flags_what_is_unclassified_or_unscanned(self):
        r = self.client.get("/api/triage/summary", params={"group": "tgrp/sub", "instance": "gitlab2"})
        self.assertEqual(r.status_code, 200, r.text)
        j = r.json()
        self.assertEqual(j["total"], 3)                                   # informational is not part of the report
        self.assertEqual(j["by_classification"]["Vulnerabilidad"]["reported"], 2)
        self.assertEqual(j["unclassified"], 1)
        self.assertEqual(j["informational_not_in_report"], 1)
        self.assertEqual(j["not_scanned"], ["tgrp/sub/never"])

    def test_unclassified_listing_and_workbook(self):
        r = self.client.get("/api/triage/unclassified", params={"group": "tgrp/sub", "instance": "gitlab2"})
        self.assertEqual([f["rule"] for f in r.json()["findings"]], ["NO-RULE-COVERS-THIS"])
        x = self.client.get("/api/triage/report.xlsx", params={"group": "tgrp/sub", "instance": "gitlab2"})
        self.assertEqual(x.status_code, 200)
        self.assertTrue(x.content.startswith(b"PK"))
        self.assertIn("tgrp_sub_hallazgos_clasificados.xlsx", x.headers["content-disposition"])

    def test_unknown_group_is_404_and_bad_regex_is_400(self):
        self.assertEqual(self.client.get("/api/triage/summary", params={"group": "no/such", "instance": "gitlab2"}).status_code, 404)
        r = self.client.post("/api/triage/rules", json={"instance": "gitlab2", "group": "tgrp/sub", "rule_regex": "([", "root_cause_code": "V-01"})
        self.assertEqual(r.status_code, 400)

    def test_new_rule_classifies_the_leftover_and_a_wrong_code_prefix_is_rejected(self):
        r = self.client.post("/api/triage/root-causes", json={"instance": "gitlab2", "group": "tgrp/sub", "code": "X-01", "classification": "Calidad", "title": "t"})
        self.assertEqual(r.status_code, 400)
        r = self.client.post("/api/triage/root-causes", json={"instance": "gitlab2", "group": "tgrp/sub", "code": "C-01", "classification": "Calidad", "title": "Mejora"})
        self.assertEqual(r.status_code, 200, r.text)
        r = self.client.post("/api/triage/rules", json={"instance": "gitlab2", "group": "tgrp/sub", "rule_regex": "^NO-RULE", "root_cause_code": "C-01",
                                                         "path_regex": "C\\.java"})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["priority"], 10)
        j = self.client.get("/api/triage/summary", params={"group": "tgrp/sub", "instance": "gitlab2"}).json()
        self.assertEqual(j["unclassified"], 0)
        self.assertEqual(j["by_classification"]["Calidad"]["reported"], 1)
        d = self.client.delete(f"/api/triage/rules/{r.json()['id']}")
        self.assertEqual(d.status_code, 200)


if __name__ == "__main__":
    unittest.main()


def test_rules_anchored_on_the_project_name_still_match_branch_assets():
    """Regression 2026-10-12: renaming assets to '<project>@<branch>' made every analyst rule ending in '$' stop matching."""
    from core.triage import match_rule
    rule = dict(rule_regex=r"^ANGULAR\-BYPASS\-SECURITY\-TRUST$", asset_regex=r"/fe\-app$", path_regex=None, line=None,
                engine=None, priority=10, root_cause_code="FP-07")
    base = dict(engine="sast-native", rule="ANGULAR-BYPASS-SECURITY-TRUST", url_path="src/a.ts:3", line=3)
    assert match_rule({**base, "asset_name": "GitLab2/grupo-a/proyecto-a/frontend/fe-app@develop"}, [rule]) is rule
    assert match_rule({**base, "asset_name": "GitLab2/grupo-a/proyecto-a/frontend/fe-app"}, [rule]) is rule
    assert match_rule({**base, "asset_name": "GitLab2/grupo-a/proyecto-a/frontend/otro-repo@develop"}, [rule]) is None


class TestSingleProjectScope(TestTriageApi):
    """A triage 'group' may be ONE project ('grupo-b/proyecto-c'): its '<name>@branch' assets belong to it, a look-alike ('proyecto-cv2') does not."""

    def test_project_path_matches_its_branch_assets_but_not_lookalikes(self):
        cur = self.conn.cursor()
        for name in ("GitLab2/tgrp/proyecto-c@develop", "GitLab2/tgrp/proyecto-cv2/dominio@develop", "GitLab2/tgrp/proyecto-c/sub@main"):
            cur.execute("""INSERT INTO infra_inventory (asset_name, asset_type, endpoint, criticality, status) VALUES (%s,'GitLab-Repo','x','LOW','ACTIVE')""", (name,))
        got = set(triage.fetch_group_assets(cur, "GitLab2/tgrp/proyecto-c/"))
        self.assertEqual(got, {"GitLab2/tgrp/proyecto-c@develop", "GitLab2/tgrp/proyecto-c/sub@main"})


class TestProjectListing(unittest.TestCase):
    def test_a_project_that_gitlab_does_not_know_as_group_is_listed_as_project(self):
        calls = [mock.Mock(status_code=404), mock.Mock(status_code=200, json=lambda: {"path_with_namespace": "grupo-b/proyecto-c", "archived": False})]
        with mock.patch("requests.get", side_effect=calls):
            projects, err = triage.list_group_projects(INST, "grupo-b/proyecto-c")
        self.assertIsNone(err)
        self.assertEqual(projects, [{"path": "grupo-b/proyecto-c", "archived": False}])
