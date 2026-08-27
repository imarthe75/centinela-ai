"""
Unit test for the CMMI v3.0 practice-area realignment (2026-08-25).

Regression coverage for the real fix: the auditor used to score against fabricated codes ("SAM",
"MSR") that don't exist in C&A's own ISACA-verified 19-area tailored CMMI V3.0 model (see
Manual_Metodologia_CA_v2_COMPLETO.docx, Parte II cap. 10). Fixed by dropping those two, adding a
real CM (Configuration Management) area with genuine Git-history evidence, and merging the old
connectivity/last-audit checks into a correctly-named MC (Monitor and Control) area instead of
mislabeling them as the real (and semantically different) EST/PLAN codes.
"""
import unittest
from unittest.mock import MagicMock
from auditors.compliance_mapper import evaluate_cmmi_v3_for_asset, CMMI_V3_PRACTICE_AREAS


def _row(cve_id, severity="MEDIUM", description="", status="OPEN", scan_engine="sast-native", url_path=None):
    return {
        "cve_id": cve_id, "severity": severity, "description": description,
        "status": status, "scan_engine": scan_engine, "url_path": url_path,
    }


class TestCMMIRealignment(unittest.TestCase):
    def test_no_fabricated_area_codes(self):
        codes = {a["code"] for a in CMMI_V3_PRACTICE_AREAS}
        self.assertNotIn("SAM", codes, "SAM is not a real area in C&A's own tailored 19-area model")
        self.assertNotIn("MSR", codes, "MSR is not a real CMMI V3.0 code under any taxonomy")
        self.assertEqual(codes, {"CAR", "PQA", "CM", "MC", "VV"})

    def test_cm_is_na_for_non_repo_asset(self):
        asset = {
            "id": 1, "asset_name": "test-server", "asset_type": "SERVER",
            "endpoint": "10.0.0.1", "status": "ACTIVE", "agent_id": "abc",
            "last_audit": "2026-08-25", "cis_grade": "A",
        }
        cur = MagicMock()
        result = evaluate_cmmi_v3_for_asset(cur, asset, vulns=[])
        cm = next(pa for pa in result["practice_areas_breakdown"] if pa["area"].startswith("CM "))
        self.assertIsNone(cm["passed"], "CM must be N/A (not forced pass/fail) for a non-repository asset")
        self.assertIn("N/A", cm["status"])

    def test_cm_na_does_not_deflate_score(self):
        # A SERVER asset with everything else genuinely passing must score 100%, not 80% --
        # dividing by a fixed area count would fabricate a ceiling for an area that doesn't apply.
        asset = {
            "id": 1, "asset_name": "test-server", "asset_type": "SERVER",
            "endpoint": "10.0.0.1", "status": "ACTIVE", "agent_id": "abc",
            "last_audit": "2026-08-25", "cis_grade": "A",
        }
        cur = MagicMock()
        result = evaluate_cmmi_v3_for_asset(cur, asset, vulns=[])
        self.assertEqual(result["cmmi_compliance_percentage"], 100.0)

    def test_cm_evaluated_for_repo_with_no_git_marker(self):
        asset = {
            "id": 2, "asset_name": "test-repo", "asset_type": "GitLab-Repo",
            "endpoint": "https://gitlab.example/test-repo", "status": "monitored",
            "agent_id": None, "last_audit": "2026-08-25", "cis_grade": None,
        }
        cur = MagicMock()
        # No CMMI-GIT-HISTORY-CHECK marker in vulns -- must fail honestly, not silently pass.
        result = evaluate_cmmi_v3_for_asset(cur, asset, vulns=[])
        cm = next(pa for pa in result["practice_areas_breakdown"] if pa["area"].startswith("CM "))
        self.assertFalse(cm["passed"])

    def test_cm_passes_with_real_git_history_marker(self):
        asset = {
            "id": 2, "asset_name": "test-repo", "asset_type": "GitLab-Repo",
            "endpoint": "https://gitlab.example/test-repo", "status": "monitored",
            "agent_id": None, "last_audit": "2026-08-25", "cis_grade": None,
        }
        cur = MagicMock()
        marker = _row("CMMI-GIT-HISTORY-CHECK", severity="INFO",
                       description="Verificación de control de versiones (CM): 42 commits reales detectados en /repo.",
                       scan_engine="cmmi-audit")
        result = evaluate_cmmi_v3_for_asset(cur, asset, vulns=[marker])
        cm = next(pa for pa in result["practice_areas_breakdown"] if pa["area"].startswith("CM "))
        self.assertTrue(cm["passed"])

    def test_pqa_absorbs_former_msr_evidence(self):
        # A hardcoded-sleep finding (formerly scored under the fabricated "MSR" area) must now
        # fail PQA -- there is no honest CMMI area for it under C&A's real 19-area model, so it's
        # folded into code-hygiene (PQA) rather than dropped or kept under a fake label.
        asset = {
            "id": 3, "asset_name": "test-repo2", "asset_type": "GitLab-Repo",
            "endpoint": "x", "status": "monitored", "agent_id": None,
            "last_audit": "2026-08-25", "cis_grade": None,
        }
        cur = MagicMock()
        vulns = [_row("CMMI-MSR-HARDCODED-SLEEP", scan_engine="cmmi-audit")]
        result = evaluate_cmmi_v3_for_asset(cur, asset, vulns=vulns)
        pqa = next(pa for pa in result["practice_areas_breakdown"] if pa["area"].startswith("PQA "))
        self.assertFalse(pqa["passed"])

    def test_areas_not_evaluated_disclosed(self):
        asset = {
            "id": 1, "asset_name": "x", "asset_type": "SERVER", "endpoint": "x",
            "status": "ACTIVE", "agent_id": "a", "last_audit": "2026-08-25", "cis_grade": "A",
        }
        cur = MagicMock()
        result = evaluate_cmmi_v3_for_asset(cur, asset, vulns=[])
        not_evaluated_codes = {a["code"] for a in result["areas_not_evaluated"]}
        # Real areas from C&A's own 19-area model that this scanner honestly cannot see.
        for code in ("RDM", "EST", "PLAN", "RSK", "OT", "DAR", "GOV", "II", "MPM", "PAD", "PCM", "PR", "TS", "PI"):
            self.assertIn(code, not_evaluated_codes)


if __name__ == "__main__":
    unittest.main()
