from auditors import auditor_a11y_render as a
from core import coverage_matrix as cm


def _page(**kw):
    base = {"url": "http://x/", "ok": True, "elements": 300, "text_len": 100, "violations": []}
    base.update(kw)
    return base


def test_axe_tags_to_criteria():
    assert a.criteria_from_tags(["cat.color", "wcag2aa", "wcag143"]) == ["1.4.3"]
    assert a.criteria_from_tags(["wcag1412", "wcag21aa"]) == ["1.4.12"]
    assert a.criteria_from_tags(["best-practice"]) == []


def test_findings_use_axe_wcag_tag_and_drop_best_practice():
    page = _page(violations=[
        {"rule": "color-contrast", "impact": "serious", "help": "contrast", "helpUrl": "u", "tags": ["wcag2aa", "wcag143"], "node_count": 1, "nodes": [{"target": ["p"]}]},
        {"rule": "region", "impact": "moderate", "help": "landmarks", "helpUrl": "u", "tags": ["best-practice"], "node_count": 2, "nodes": []},
    ])
    f = a.violations_to_findings(page)
    assert [x["cve_id"] for x in f] == ["WCAG-1.4.3-AXE-COLOR-CONTRAST"] and f[0]["severity"] == "MEDIUM"


def test_every_emitted_id_is_classified_and_manual_criteria_are_not_claimed():
    for crit, (_n, _l, how) in cm.WCAG_21_AA.items():
        got = cm.classify_rule(f"WCAG-{crit}-AXE-SOMETHING")
        if crit in cm.AXE_DECIDABLE:
            assert crit in got["wcag"]
        elif how == "manual" or crit in ("1.4.10", "1.4.11", "4.1.3"):      # no axe rule / human judgement: must not be claimed by AXE ids
            assert got is None or crit not in got.get("wcag", [])


def test_empty_shell_is_not_a_valid_render():
    assert not a.rendered_meaningfully(_page(text_len=0, elements=34))
    assert a.rendered_meaningfully(_page())


def test_empty_render_persists_nothing(monkeypatch):
    monkeypatch.setattr(a, "run_browser_audit", lambda urls: {"results": [_page(text_len=0, elements=34)]})
    monkeypatch.setattr(a, "persist", lambda *x: (_ for _ in ()).throw(AssertionError("must not persist")))
    assert a.scan_url_assets("00000000-0000-0000-0000-000000000000", "http://x/") is None
