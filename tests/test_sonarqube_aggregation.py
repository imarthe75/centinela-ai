"""SonarQube informational issues are stored one row per (rule, file) (ADR-0019 phase 2); security issues stay per occurrence.
The consolidation of old per-line rows runs inside a transaction that is rolled back (rule 8)."""
import contextlib
import unittest

from auditors import auditor_sonarqube as sq
from core import db_manager, deduplication_engine


def _issue(rule, typ, comp, line, sev="MAJOR", msg="m"):
    return {"rule": rule, "type": typ, "component": f"pk:{comp}", "line": line, "severity": sev, "message": msg, "effort": "5min"}


class TestFindingRows(unittest.TestCase):
    def test_smells_grouped_by_rule_and_file_security_kept_per_line(self):
        issues = [_issue("ts:S1", "CODE_SMELL", "src/a.ts", 3), _issue("ts:S1", "CODE_SMELL", "src/a.ts", 9, sev="CRITICAL"),
                  _issue("ts:S1", "CODE_SMELL", "src/b.ts", 1), _issue("ts:S2", "VULNERABILITY", "src/a.ts", 3),
                  _issue("ts:S2", "VULNERABILITY", "src/a.ts", 4)]
        rows = sq.finding_rows(issues, "pk")
        info = [r for r in rows if r["finding_category"] == "INFORMATIONAL"]
        vuln = [r for r in rows if r["finding_category"] == "VULNERABILITY"]
        self.assertEqual(sorted(r["url_path"] for r in info), ["src/a.ts", "src/b.ts"])
        a = next(r for r in info if r["url_path"] == "src/a.ts")
        self.assertIn("2 ocurrencia(s)", a["description"])
        self.assertIn("**Líneas:** 3, 9", a["description"])
        self.assertEqual(a["severity"], sq._map_sonar_severity(_issue("x", "CODE_SMELL", "f", 1, sev="CRITICAL")))
        self.assertEqual(sorted(r["url_path"] for r in vuln), ["src/a.ts:3", "src/a.ts:4"])
        self.assertTrue(a["description"].startswith("**SonarQube CODE_SMELL**"))      # classifier fallback still recognises it

    def test_file_and_line_parsing(self):
        self.assertEqual((sq.file_of("a/b.ts:12"), sq.line_of("a/b.ts:12")), ("a/b.ts", 12))
        self.assertEqual((sq.file_of("a/b.ts"), sq.line_of("a/b.ts")), ("a/b.ts", None))
        self.assertEqual(sq.file_of("c:\\x"), "c:\\x")


class TestConsolidation(unittest.TestCase):
    def setUp(self):
        self._stack = contextlib.ExitStack()
        self.conn = self._stack.enter_context(db_manager.get_db_connection())
        self.cur = self.conn.cursor()
        self.cur.execute("INSERT INTO infra_inventory (asset_name, asset_type, endpoint) VALUES ('test-sonar/x@d', 'GitLab-Repo', 't') RETURNING id")
        self.aid = str(self.cur.fetchone()[0])

    def tearDown(self):
        self.conn.rollback()
        self._stack.close()

    def _row(self, line, status="OPEN", category="INFORMATIONAL", decided=False):
        up = f"src/a.ts:{line}"
        self.cur.execute("""INSERT INTO vulnerability_log (asset_id, cve_id, severity, description, status, scan_engine, url_path,
                                                          finding_category, fingerprint_hash)
                            VALUES (%s, 'SONAR-ts-S1', 'MEDIUM', %s, %s, 'sonarqube', %s, %s, %s) RETURNING id""",
                         (self.aid, f"**SonarQube CODE_SMELL** (ts:S1)\nmsg {line}\n**Esfuerzo estimado:** 5min", status, up, category,
                          deduplication_engine.calculate_fingerprint(self.aid, "SONAR-ts-S1", up)))
        vid = self.cur.fetchone()[0]
        self.cur.execute("INSERT INTO remediation_history (vuln_id, approval_token) VALUES (%s, %s)", (vid, "APPROVED" if decided else "PENDING_APPROVAL"))
        return str(vid)

    def test_rows_merge_into_one_and_a_rescan_updates_it_in_place(self):
        ids = [self._row(n) for n in (3, 9, 20)]
        kept = self._row(30, decided=True)                         # a human decision is never merged away
        st = sq.consolidate_informational_rows(self.cur, self.aid)
        self.assertEqual((st["groups"], st["deleted"]), (1, 2))
        self.cur.execute("""SELECT id::text, url_path, description FROM vulnerability_log
                            WHERE asset_id = %s AND scan_engine = 'sonarqube' ORDER BY url_path""", (self.aid,))
        rows = self.cur.fetchall()
        self.assertEqual([r[1] for r in rows], ["src/a.ts", "src/a.ts:30"])
        self.assertIn(rows[0][0], ids)
        self.assertIn("**Líneas:** 3, 9, 20", rows[0][2])
        self.assertEqual(rows[1][0], kept)
        self.cur.execute("SELECT count(*) FROM remediation_history r WHERE r.vuln_id = ANY(%s::uuid[])", ([i for i in ids if i != rows[0][0]],))
        self.assertEqual(self.cur.fetchone()[0], 0)
        # A fresh scan computes the same identity: it updates the survivor instead of opening a new row.
        new_rows = sq.finding_rows([_issue("ts:S1", "CODE_SMELL", "src/a.ts", 3)], "pk")
        fp = deduplication_engine.calculate_fingerprint(self.aid, new_rows[0]["cve_id"], new_rows[0]["url_path"])
        self.cur.execute("SELECT id::text FROM vulnerability_log WHERE fingerprint_hash = %s", (fp,))
        self.assertEqual(self.cur.fetchone()[0], rows[0][0])


if __name__ == "__main__":
    unittest.main()
