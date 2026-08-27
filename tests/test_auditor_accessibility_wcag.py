"""
Unit test for the WCAG 2.1 accessibility auditor (added 2026-08-25).
"""
import os
import tempfile
import unittest
from auditors.auditor_accessibility_wcag import audit_wcag_accessibility, run_wcag_accessibility_audit
from core.db_manager import get_db_cursor


class TestWCAGAccessibilityAudit(unittest.TestCase):
    def test_img_missing_alt(self):
        findings = audit_wcag_accessibility("page.html", '<img src="logo.png">')
        self.assertTrue(any(f["cve_id"] == "WCAG-1.1.1-IMG-MISSING-ALT" for f in findings))

    def test_img_with_empty_alt_not_flagged(self):
        # alt="" is a legitimate way to mark a decorative image -- must not be flagged.
        findings = audit_wcag_accessibility("page.html", '<img src="deco.png" alt="">')
        self.assertFalse(any(f["cve_id"] == "WCAG-1.1.1-IMG-MISSING-ALT" for f in findings))

    def test_input_without_label(self):
        findings = audit_wcag_accessibility("page.html", '<input type="text" id="nombre">')
        self.assertTrue(any(f["cve_id"] == "WCAG-1.3.1-FORM-CONTROL-NO-LABEL" for f in findings))

    def test_input_with_matching_label_not_flagged(self):
        content = '<label for="nombre">Nombre</label>\n<input type="text" id="nombre">'
        findings = audit_wcag_accessibility("page.html", content)
        self.assertFalse(any(f["cve_id"] == "WCAG-1.3.1-FORM-CONTROL-NO-LABEL" for f in findings))

    def test_input_with_broken_label_association_is_flagged(self):
        # Real false-negative check: <label for="X"> where the input never got id="X" (uses
        # formControlName instead, a real bug pattern confirmed live against SIDECO's frontend)
        # leaves the association broken in the real DOM -- must still be flagged.
        content = '<label for="nombre">Nombre</label>\n<input type="text" formControlName="nombre">'
        findings = audit_wcag_accessibility("page.html", content)
        self.assertTrue(any(f["cve_id"] == "WCAG-1.3.1-FORM-CONTROL-NO-LABEL" for f in findings))

    def test_hidden_input_not_flagged(self):
        findings = audit_wcag_accessibility("page.html", '<input type="hidden" name="csrf">')
        self.assertFalse(any(f["cve_id"] == "WCAG-1.3.1-FORM-CONTROL-NO-LABEL" for f in findings))

    def test_empty_button_flagged(self):
        findings = audit_wcag_accessibility("page.html", '<button (click)="save()"></button>')
        self.assertTrue(any(f["cve_id"] == "WCAG-2.4.4-EMPTY-INTERACTIVE-ELEMENT" for f in findings))

    def test_primeng_label_attribute_not_flagged(self):
        # Real false positive found and fixed live against SIDECO's frontend (301 real pButton
        # occurrences in that one repo): PrimeNG's `label=` attribute renders as the button's
        # visible/accessible text -- must not be flagged as empty.
        findings = audit_wcag_accessibility("page.html", '<button pButton label="Guardar" (click)="save()"></button>')
        self.assertFalse(any(f["cve_id"] == "WCAG-2.4.4-EMPTY-INTERACTIVE-ELEMENT" for f in findings))

    def test_thymeleaf_th_text_not_flagged(self):
        # Real false positive found and fixed live against the SIDECO backend's email templates:
        # th:text/th:utext replaces the tag's body with server-rendered text at render time, so
        # the tag is only empty in the static source, not in the real output.
        findings = audit_wcag_accessibility("page.html", '<a th:text="${llsolicitud}"></a>')
        self.assertFalse(any(f["cve_id"] == "WCAG-2.4.4-EMPTY-INTERACTIVE-ELEMENT" for f in findings))

    def test_icon_only_button_still_flagged(self):
        # Real, confirmed-live finding: an icon-only PrimeNG button with no label/aria-label/title
        # is a genuine WCAG violation, not framework noise.
        findings = audit_wcag_accessibility("page.html", '<button pButton icon="pi pi-trash" (click)="del()"></button>')
        self.assertTrue(any(f["cve_id"] == "WCAG-2.4.4-EMPTY-INTERACTIVE-ELEMENT" for f in findings))

    def test_html_missing_lang(self):
        findings = audit_wcag_accessibility("index.html", '<html><head></head></html>')
        self.assertTrue(any(f["cve_id"] == "WCAG-3.1.1-HTML-MISSING-LANG" for f in findings))

    def test_positive_tabindex_flagged(self):
        findings = audit_wcag_accessibility("page.html", '<input tabindex="3">')
        self.assertTrue(any(f["cve_id"] == "WCAG-2.4.3-POSITIVE-TABINDEX" for f in findings))

    def test_zero_tabindex_not_flagged(self):
        findings = audit_wcag_accessibility("page.html", '<div tabindex="0" role="button"></div>')
        self.assertFalse(any(f["cve_id"] == "WCAG-2.4.3-POSITIVE-TABINDEX" for f in findings))

    def test_clickable_div_without_role_flagged(self):
        findings = audit_wcag_accessibility("page.html", '<div onclick="doThing()">Click me</div>')
        self.assertTrue(any(f["cve_id"] == "WCAG-4.1.2-CLICKABLE-DIV-NO-ROLE" for f in findings))

    def test_clickable_div_with_role_not_flagged(self):
        content = '<div role="button" tabindex="0" onclick="doThing()">Click me</div>'
        findings = audit_wcag_accessibility("page.html", content)
        self.assertFalse(any(f["cve_id"] == "WCAG-4.1.2-CLICKABLE-DIV-NO-ROLE" for f in findings))

    def test_run_wcag_audit_persists_with_asset_id_and_url_path(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "page.html"), "w") as f:
                f.write('<img src="logo.png">')
            try:
                findings = run_wcag_accessibility_audit(tmpdir, asset_id=None)
                self.assertTrue(len(findings) >= 1)
                with get_db_cursor() as cur:
                    cur.execute(
                        "SELECT asset_id, url_path, fingerprint_hash, finding_category FROM vulnerability_log "
                        "WHERE scan_engine='accessibility-wcag' AND cve_id='WCAG-1.1.1-IMG-MISSING-ALT' "
                        "AND url_path = 'page.html:1'"
                    )
                    row = cur.fetchone()
                self.assertIsNotNone(row, "finding was not persisted with the expected url_path")
                self.assertIsNotNone(row[2], "fingerprint_hash must be populated for real dedup")
                self.assertEqual(row[3], "VULNERABILITY", "a real accessibility finding must not be classified INFORMATIONAL")
            finally:
                with get_db_cursor() as cur:
                    cur.execute(
                        "DELETE FROM vulnerability_log WHERE scan_engine='accessibility-wcag' AND url_path='page.html:1'"
                    )


if __name__ == "__main__":
    unittest.main()
