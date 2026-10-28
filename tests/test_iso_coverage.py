import re

from auditors import compliance_mapper as cm
from core import coverage_matrix as cov


def test_score_is_bounded_even_when_every_mapped_control_is_violated():
    vulns = [{"cve_id": k} for k in cm.COMPLIANCE_MAPPING_MATRIX]
    r = cm.compute_iso_control_coverage(vulns)
    assert 0 <= r["score"] <= 100
    assert r["violated_count"] <= r["control_universe_size"]


def test_universe_is_derived_from_the_detector_matrix():
    """Every distinct control some detector can violate is in the denominator (legacy matrix AND coverage registry),
    and composite labels like 'A.8.20 ... / A.8.24 ...' no longer count as extra, separate controls."""
    universe_labels = {b["area"] for b in cm.compute_iso_control_coverage([])["breakdown"]}
    universe_ids = {m.group(1) for lab in universe_labels for m in re.finditer(r"^A\.(\d+\.\d+)", lab)}
    for label in (v["ISO_27001"] for v in cm.COMPLIANCE_MAPPING_MATRIX.values()):
        for cid in re.findall(r"A\.(\d+\.\d+)", label):
            assert cid in universe_ids, f"{label} -> {cid} missing from the ISO universe"
        if label.startswith("ISO 25010"):
            assert label in universe_labels
    for cid in cov.native_coverage()["iso"]:
        assert cid in universe_ids, f"registry control {cid} has a detector but is not in the denominator"
    assert not any("/" in lab for lab in universe_labels), "composite labels must not be separate universe entries"


def test_universe_never_contains_controls_no_scanner_can_measure():
    """Physical and people controls have no detector: they must not pad the denominator (2026-09-17 incident)."""
    for lab in (b["area"] for b in cm.compute_iso_control_coverage([])["breakdown"]):
        m = re.match(r"^A\.(\d+\.\d+)", lab)
        if m:
            assert cov.ISO_27001_2022[m.group(1)]["scope"] not in ("fisico", "personas"), lab


def test_no_findings_is_100_and_states_its_scope():
    r = cm.compute_iso_control_coverage([])
    assert r["score"] == 100.0 and "no es una certificación" in r["scope_note"].lower()
    assert r["annex_a_total"] == 93 and 0 < r["annex_a_with_detector"] < 93


def test_a_rule_the_legacy_matrix_ignored_now_counts_against_its_control():
    """AUTHZ-INCONSISTENT-FAMILY was in no ISO mapping before, so privilege-escalation findings cost an asset nothing."""
    clean = cm.compute_iso_control_coverage([])["score"]
    hit = cm.compute_iso_control_coverage([{"cve_id": "AUTHZ-INCONSISTENT-FAMILY", "description": "x"}])
    assert hit["score"] < clean
    assert any(b["area"].startswith("A.5.15") and not b["passed"] for b in hit["breakdown"])
