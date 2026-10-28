"""Guards for core/coverage_matrix.py: official universe sizes, no typo'd mapping targets, and -- the one that stops
coverage numbers from drifting -- every rule id the code can emit is classified (mapped or an explicit non-finding)."""
import glob
import re
import unittest
from pathlib import Path

from core import coverage_matrix as cm

ROOT = Path(__file__).resolve().parents[1]

EMIT_PATTERNS = [
    re.compile(r'["\']cve_id["\']\s*:\s*["\']([A-Z][A-Z0-9.-]{4,})["\']'),
    re.compile(r'\(\s*r?["\'].*?["\']\s*,\s*["\']([A-Z][A-Z0-9-]{5,})["\']\s*,\s*["\'](?:CRITICAL|HIGH|MEDIUM|LOW|INFO)["\']'),
    re.compile(r'rule_id\s*=\s*["\']([A-Z][A-Z0-9.-]{4,})["\']'),
    re.compile(r'cve_id\s*=\s*["\']([A-Z][A-Z0-9.-]{4,})["\']'),
    re.compile(r'log_finding_deduplicated\(\s*cur,\s*[\w.]+,\s*["\']([A-Z][A-Z0-9-]{4,})["\']'),
]
# not rule ids: placeholders/defaults that happen to match the patterns above
IGNORE = {"UNKNOWN-FINDING", "SECURITY-FINDING"}


def emitted_rule_ids():
    ids = set()
    for f in sorted(glob.glob(str(ROOT / "auditors" / "*.py")) + glob.glob(str(ROOT / "core" / "*.py"))):
        if f.endswith("coverage_matrix.py"):
            continue
        txt = Path(f).read_text(errors="ignore")
        for p in EMIT_PATTERNS:
            ids.update(m.group(1) for m in p.finditer(txt))
    return ids - IGNORE


class TestUniverses(unittest.TestCase):
    def test_official_sizes(self):
        self.assertEqual(len(cm.WSTG_42), 97)
        self.assertEqual(len(cm.WCAG_21_AA), 50)
        self.assertEqual(sum(1 for v in cm.WCAG_21_AA.values() if v[1] == "A"), 30)
        self.assertEqual(sum(1 for v in cm.WCAG_21_AA.values() if v[1] == "AA"), 20)
        self.assertEqual(len(cm.ISO_27001_2022), 93)
        self.assertEqual({s: sum(1 for v in cm.ISO_27001_2022.values() if v["scope"] == s) for s in ("org", "personas", "fisico", "tecnologico")},
                         {"org": 37, "personas": 8, "fisico": 14, "tecnologico": 34})
        self.assertEqual((len(cm.OWASP_TOP10_2021), len(cm.OWASP_API_TOP10_2023), len(cm.OWASP_LLM_TOP10_2025),
                          len(cm.OWASP_ASVS_4_CHAPTERS), len(cm.CMMI_CA_19)), (10, 10, 10, 14, 19))

    def test_wstg_per_category_counts_match_the_official_checklist(self):
        counts = {}
        for k in cm.WSTG_42:
            counts[k.split("-")[0]] = counts.get(k.split("-")[0], 0) + 1
        self.assertEqual(counts, {"INFO": 10, "CONF": 11, "IDNT": 5, "ATHN": 10, "AUTHZ": 4, "SESS": 9, "INPV": 19,
                                  "ERRH": 2, "CRYP": 4, "BUSL": 9, "CLNT": 13, "APIT": 1})

    def test_every_mapping_target_exists_in_its_universe(self):
        for rx, mapping in cm.RULE_MAP:
            for fw, items in mapping.items():
                self.assertIn(fw, cm.FRAMEWORKS, rx.pattern)
                for it in items:
                    self.assertIn(it, cm.FRAMEWORKS[fw][1], f"{rx.pattern} -> {fw}:{it}")
        for engine, mapping in cm.EXTERNAL_ENGINES.items():
            for fw, items in mapping.items():
                for it in items:
                    self.assertIn(it, cm.FRAMEWORKS[fw][1], f"{engine} -> {fw}:{it}")


class TestClassification(unittest.TestCase):
    def test_every_emitted_rule_id_is_classified(self):
        missing = cm.unclassified(emitted_rule_ids())
        self.assertEqual(missing, [], "rule ids emitted by the code but absent from core/coverage_matrix.py RULE_MAP: " + ", ".join(missing))

    def test_markers_are_not_findings_and_unknown_is_none(self):
        self.assertEqual(cm.classify_rule("SCAN-AUDIT"), {})
        self.assertEqual(cm.classify_rule("CIS-BENCHMARK-AUDIT"), {})
        self.assertIsNone(cm.classify_rule("TOTALLY-NEW-RULE"))

    def test_wstg_legacy_misnumbered_ids_map_to_the_official_test(self):
        self.assertEqual(cm.classify_rule("WSTG-ATHN-02-CLEARTEXT-LOGIN")["wstg"], ["ATHN-01"])
        self.assertEqual(cm.classify_rule("WSTG-AUTH-02-DEFAULT-CREDENTIALS")["wstg"], ["ATHN-02"])


class TestCoverageNumbers(unittest.TestCase):
    def test_counts_add_up_and_nothing_is_counted_without_a_detector(self):
        cov = cm.compute_coverage()
        for fw, r in cov.items():
            self.assertEqual(r["native"] + r["external_only"] + r["none"], r["total"], fw)
        # physical / people controls have no scanner domain, so they must never show native coverage
        for cid, meta in cm.ISO_27001_2022.items():
            if meta["scope"] in ("fisico", "personas"):
                self.assertNotIn(cid, cm.native_coverage()["iso"], cid)

    def test_markdown_renders(self):
        md = cm.to_markdown()
        self.assertIn("OWASP WSTG v4.2", md)
        self.assertIn("| 97 |", md)


if __name__ == "__main__":
    unittest.main()


class TestCmmiCoverageIsEvidenceBased(unittest.TestCase):
    def test_cmmi_native_coverage_comes_only_from_real_collectors(self):
        cov = cm.native_coverage()["cmmi"]
        collectors = cm.cmmi_collectors()
        self.assertEqual(set(cov), {a for a, i in collectors.items() if i["with_collector"]})
        # the weak code-hygiene proxy must NOT make CAR look covered; the organization's manual asks for causal analysis on real defects
        self.assertNotIn("CAR", cov)
        for area in ("RDM", "EST", "PLAN", "MC", "RSK", "OT", "MPM", "CAR"):
            self.assertNotIn(area, cov, f"{area} has no real collector today")
