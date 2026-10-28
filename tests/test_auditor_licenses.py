"""License classification (pure) + the SBOM -> findings step, and the persisted INFORMATIONAL / reconcile behaviour on the real schema."""
import contextlib
import unittest
from unittest import mock

from auditors import auditor_licenses as L
from core import db_manager


class TestClassification(unittest.TestCase):
    def test_common_licenses(self):
        c = L.classify_license
        for ok in ["MIT", "Apache-2.0", "BSD-3-Clause", "ISC", "0BSD", "CC0-1.0", "Unlicense", "BlueOak-1.0.0", "Python-2.0"]:
            self.assertEqual(c(ok), L.PERMISSIVE, ok)
        for weak in ["MPL-2.0", "LGPL-3.0-or-later", "EPL-2.0", "CDDL-1.1"]:
            self.assertEqual(c(weak), L.WEAK_COPYLEFT, weak)
        self.assertEqual(c("GPL-3.0-only"), L.STRONG_COPYLEFT)
        self.assertEqual(c("GPL-2.0-or-later"), L.STRONG_COPYLEFT)
        self.assertEqual(c("AGPL-3.0-only"), L.NETWORK_COPYLEFT)
        for bad in ["SSPL-1.0", "BUSL-1.1", "CC-BY-NC-4.0", "Elastic-2.0"]:
            self.assertEqual(c(bad), L.RESTRICTED, bad)

    def test_unknown_and_empty_are_unknown_not_permissive(self):
        for u in ["", None, "NOASSERTION", "SEE LICENSE IN LICENSE.md", "LicenseRef-custom", "Totally-Made-Up-1.0"]:
            self.assertEqual(L.classify_license(u), L.UNKNOWN, u)

    def test_or_picks_the_least_restrictive_and_picks_the_most(self):
        self.assertEqual(L.classify_license("(MIT OR GPL-3.0-only)"), L.PERMISSIVE)         # licensee chooses MIT
        self.assertEqual(L.classify_license("(MIT AND GPL-3.0-only)"), L.STRONG_COPYLEFT)   # both apply
        self.assertEqual(L.classify_license("GPL-2.0-only OR AGPL-3.0-only"), L.STRONG_COPYLEFT)
        self.assertEqual(L.classify_license("(MIT OR CC0-1.0)"), L.PERMISSIVE)

    def test_classpath_exception_makes_gpl_weak(self):
        self.assertEqual(L.classify_license("GPL-2.0-only WITH Classpath-exception-2.0"), L.WEAK_COPYLEFT)

    def test_lgpl_is_not_mistaken_for_gpl(self):
        self.assertEqual(L.classify_license("LGPL-2.1-only"), L.WEAK_COPYLEFT)


def art(name, lic, typ="npm", ver="1.0.0"):
    return {"name": name, "version": ver, "type": typ, "licenses": ([{"value": lic, "spdxExpression": lic}] if lic else [])}


class TestSbomToFindings(unittest.TestCase):
    def test_one_finding_per_category_listing_packages(self):
        sbom = {"artifacts": [art("a", "MIT"), art("b", "GPL-3.0-only"), art("c", "GPL-2.0-only"), art("d", "AGPL-3.0-only"), art("e", None), art("f", "MPL-2.0")]}
        out = {f["cve_id"]: f for f in L.audit_sbom_licenses(sbom)}
        self.assertEqual(set(out), {"SCA-LICENSE-STRONG-COPYLEFT", "SCA-LICENSE-NETWORK-COPYLEFT", "SCA-LICENSE-UNKNOWN"})   # MIT and MPL: no finding
        self.assertEqual(out["SCA-LICENSE-STRONG-COPYLEFT"]["count"], 2)
        self.assertEqual(out["SCA-LICENSE-NETWORK-COPYLEFT"]["severity"], "HIGH")
        self.assertIn("b@1.0.0", out["SCA-LICENSE-STRONG-COPYLEFT"]["description"])
        self.assertIn("Requiere validación", out["SCA-LICENSE-STRONG-COPYLEFT"]["description"])

    def test_clean_sbom_produces_nothing_and_binaries_are_ignored(self):
        self.assertEqual(L.audit_sbom_licenses({"artifacts": [art("a", "MIT"), art("b", "Apache-2.0")]}), [])
        self.assertEqual(L.audit_sbom_licenses({"artifacts": [art("bin", None, typ="binary")]}), [])
        self.assertEqual(L.audit_sbom_licenses({}), [])

    def test_long_lists_are_capped_but_counted(self):
        out = L.audit_sbom_licenses({"artifacts": [art(f"p{i}", "GPL-3.0-only") for i in range(40)]})[0]
        self.assertEqual(out["count"], 40)
        self.assertIn("y 15 más", out["description"])

    def test_syft_failure_never_becomes_a_clean_result(self):
        with mock.patch("subprocess.run", return_value=mock.Mock(returncode=1, stderr="boom", stdout="")):
            self.assertIsNone(L.generate_sbom("/nonexistent"))
        self.assertEqual(L.run_license_audit("/nonexistent"), [])


class TestPersistence(unittest.TestCase):
    """Real schema, one rolled-back transaction (project rule #8)."""

    def setUp(self):
        self._stack = contextlib.ExitStack()
        self.addCleanup(self._cleanup)
        self.conn = self._stack.enter_context(db_manager.get_db_connection())

        @contextlib.contextmanager
        def shared(cursor_factory=None):
            cur = self.conn.cursor(cursor_factory=cursor_factory)
            try:
                yield cur
            finally:
                cur.close()
        self._stack.enter_context(mock.patch.object(db_manager, "get_db_cursor", shared))
        cur = self.conn.cursor()
        cur.execute("""INSERT INTO infra_inventory (asset_name, asset_type, endpoint, criticality, status) VALUES ('GitLab/tlic/repo@main','GitLab-Repo','x','LOW','ACTIVE') RETURNING id""")
        self.asset = cur.fetchone()[0]

    def _cleanup(self):
        try:
            self.conn.rollback()
        finally:
            self._stack.close()

    def _rows(self):
        cur = self.conn.cursor()
        cur.execute("SELECT cve_id, status, finding_category, scan_engine FROM vulnerability_log WHERE asset_id=%s ORDER BY cve_id", (self.asset,))
        return cur.fetchall()

    def test_persisted_as_informational_and_resolved_when_the_dependency_goes_away(self):
        gpl = {"artifacts": [art("lib", "GPL-3.0-only")]}
        with mock.patch.object(L, "generate_sbom", return_value=gpl):
            L.run_license_audit("/x", asset_id=self.asset, display_name="repo")
        rows = self._rows()
        self.assertEqual([(r[0], r[2], r[3]) for r in rows], [("SCA-LICENSE-STRONG-COPYLEFT", "INFORMATIONAL", "sca-license")])
        self.assertNotEqual(rows[0][1], "RESOLVED")
        with mock.patch.object(L, "generate_sbom", return_value={"artifacts": [art("lib", "MIT")]}):
            L.run_license_audit("/x", asset_id=self.asset, display_name="repo")      # dependency replaced by a permissive one
        self.assertEqual(self._rows()[0][1], "RESOLVED")

    def test_rescan_does_not_duplicate(self):
        gpl = {"artifacts": [art("lib", "GPL-3.0-only")]}
        for _ in range(3):
            with mock.patch.object(L, "generate_sbom", return_value=gpl):
                L.run_license_audit("/x", asset_id=self.asset, display_name="repo")
        self.assertEqual(len(self._rows()), 1)
