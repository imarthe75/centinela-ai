"""WCAG 2.1 expansion (2026-10-01): one positive and one negative case per new static rule, including the
false-positive guards (muted autoplay video, fragments without <html>, vendored CSS, focus alternatives)."""
import unittest

from auditors.auditor_accessibility_wcag import audit_wcag_accessibility, audit_wcag_css


def ids(html, path="/r/x.component.html"):
    return [f["cve_id"] for f in audit_wcag_accessibility(path, html)]


def css_ids(css, path="/r/src/styles.scss"):
    return [f["cve_id"] for f in audit_wcag_css(path, css)]


class TestWcagExpansion(unittest.TestCase):
    def test_1_4_4_viewport(self):
        self.assertIn("WCAG-1.4.4-VIEWPORT-ZOOM-DISABLED", ids('<meta name="viewport" content="width=device-width, user-scalable=no">'))
        self.assertIn("WCAG-1.4.4-VIEWPORT-ZOOM-DISABLED", ids('<meta name="viewport" content="width=device-width, maximum-scale=1">'))
        self.assertNotIn("WCAG-1.4.4-VIEWPORT-ZOOM-DISABLED", ids('<meta name="viewport" content="width=device-width, initial-scale=1">'))
        self.assertNotIn("WCAG-1.4.4-VIEWPORT-ZOOM-DISABLED", ids('<meta name="viewport" content="width=device-width, maximum-scale=5">'))

    def test_2_4_2_title_only_for_full_documents(self):
        self.assertIn("WCAG-2.4.2-MISSING-TITLE", ids("<html lang='es'><head></head><body></body></html>"))
        self.assertIn("WCAG-2.4.2-MISSING-TITLE", ids("<html lang='es'><head><title> </title></head></html>"))
        self.assertNotIn("WCAG-2.4.2-MISSING-TITLE", ids("<html lang='es'><head><title>Inicio</title></head></html>"))
        self.assertNotIn("WCAG-2.4.2-MISSING-TITLE", ids("<div class='card'>fragmento de componente</div>"))

    def test_4_1_2_iframe(self):
        self.assertIn("WCAG-4.1.2-IFRAME-NO-TITLE", ids('<iframe src="/x"></iframe>'))
        self.assertNotIn("WCAG-4.1.2-IFRAME-NO-TITLE", ids('<iframe src="/x" title="Mapa"></iframe>'))
        self.assertNotIn("WCAG-4.1.2-IFRAME-NO-TITLE", ids('<iframe [title]="t" src="/x"></iframe>'))

    def test_1_3_5_autocomplete(self):
        self.assertIn("WCAG-1.3.5-INPUT-NO-AUTOCOMPLETE", ids('<label for="e">Correo</label><input id="e" type="email">'))
        self.assertIn("WCAG-1.3.5-INPUT-NO-AUTOCOMPLETE", ids('<label for="p">Clave</label><input id="p" type="password">'))
        self.assertNotIn("WCAG-1.3.5-INPUT-NO-AUTOCOMPLETE", ids('<label for="e">Correo</label><input id="e" type="email" autocomplete="email">'))
        self.assertNotIn("WCAG-1.3.5-INPUT-NO-AUTOCOMPLETE", ids('<label for="q">Buscar</label><input id="q" type="search">'))
        self.assertNotIn("WCAG-1.3.5-INPUT-NO-AUTOCOMPLETE", ids('<label for="f">Folio</label><input id="f" type="text">'))

    def test_2_2_2_marquee(self):
        self.assertIn("WCAG-2.2.2-MARQUEE-BLINK", ids("<marquee>Aviso</marquee>"))
        self.assertNotIn("WCAG-2.2.2-MARQUEE-BLINK", ids("<p>Aviso</p>"))

    def test_1_4_2_autoplay(self):
        self.assertIn("WCAG-1.4.2-AUTOPLAY-MEDIA", ids('<audio src="a.mp3" autoplay></audio>'))
        self.assertIn("WCAG-1.4.2-AUTOPLAY-MEDIA", ids('<video src="v.mp4" autoplay></video>'))
        self.assertNotIn("WCAG-1.4.2-AUTOPLAY-MEDIA", ids('<video src="v.mp4" autoplay muted loop></video>'))
        self.assertNotIn("WCAG-1.4.2-AUTOPLAY-MEDIA", ids('<video src="v.mp4" controls></video>'))

    def test_1_2_2_video_captions(self):
        self.assertIn("WCAG-1.2.2-VIDEO-NO-CAPTIONS", ids('<video src="v.mp4" controls>\n</video>'))
        self.assertNotIn("WCAG-1.2.2-VIDEO-NO-CAPTIONS", ids('<video controls><source src="v.mp4"><track kind="captions" src="v.vtt"></video>'))
        self.assertNotIn("WCAG-1.2.2-VIDEO-NO-CAPTIONS", ids('<video src="v.mp4" autoplay muted loop></video>'))

    def test_4_1_1_duplicate_id_literal_only(self):
        self.assertIn("WCAG-4.1.1-DUPLICATE-ID", ids('<div id="a"></div>\n<span id="a"></span>'))
        self.assertNotIn("WCAG-4.1.1-DUPLICATE-ID", ids('<div id="a"></div>\n<span id="b"></span>'))
        self.assertNotIn("WCAG-4.1.1-DUPLICATE-ID", ids('<div [id]="x"></div>\n<span [id]="x"></span>'))
        self.assertNotIn("WCAG-4.1.1-DUPLICATE-ID", ids('<div data-id="a"></div>\n<span data-id="a"></span>'))

    def test_2_4_6_empty_heading(self):
        self.assertIn("WCAG-2.4.6-EMPTY-HEADING", ids("<h2></h2>"))
        self.assertNotIn("WCAG-2.4.6-EMPTY-HEADING", ids("<h2>Título</h2>"))
        self.assertNotIn("WCAG-2.4.6-EMPTY-HEADING", ids("<h2>{{ titulo }}</h2>"))
        self.assertNotIn("WCAG-2.4.6-EMPTY-HEADING", ids('<h2 aria-label="Resumen"></h2>'))

    def test_2_5_3_label_in_name(self):
        self.assertIn("WCAG-2.5.3-LABEL-IN-NAME", ids('<button aria-label="Cerrar sesión">Salir</button>'))
        self.assertNotIn("WCAG-2.5.3-LABEL-IN-NAME", ids('<button aria-label="Guardar cambios">Guardar</button>'))
        self.assertNotIn("WCAG-2.5.3-LABEL-IN-NAME", ids('<button aria-label="Cerrar">{{ texto }}</button>'))

    def test_2_4_7_focus_outline(self):
        self.assertIn("WCAG-2.4.7-FOCUS-OUTLINE-REMOVED", css_ids("a:focus { outline: none; }"))
        self.assertIn("WCAG-2.4.7-FOCUS-OUTLINE-REMOVED", css_ids(".btn:focus-visible { outline: 0; color: red; }"))
        self.assertNotIn("WCAG-2.4.7-FOCUS-OUTLINE-REMOVED", css_ids("a:focus { outline: none; box-shadow: 0 0 0 3px #36c; }"))
        self.assertNotIn("WCAG-2.4.7-FOCUS-OUTLINE-REMOVED", css_ids("a:focus { outline: 2px solid #36c; }"))
        self.assertNotIn("WCAG-2.4.7-FOCUS-OUTLINE-REMOVED", css_ids("a:hover { outline: none; }"))
        self.assertNotIn("WCAG-2.4.7-FOCUS-OUTLINE-REMOVED", css_ids("a:focus { outline: none; }", path="/r/src/assets/layout/styles/theme.css"))
        self.assertNotIn("WCAG-2.4.7-FOCUS-OUTLINE-REMOVED", css_ids("a:focus { outline: none; }", path="/r/dist/app.min.css"))


if __name__ == "__main__":
    unittest.main()


class TestDuplicateIdConditionalGuard(unittest.TestCase):
    def test_ids_behind_structural_conditions_are_not_reported(self):
        two_ngif = '<small *ngIf="a" id="help"></small>\n<small *ngIf="b" id="help"></small>'
        self.assertNotIn("WCAG-4.1.1-DUPLICATE-ID", ids(two_ngif))
        one_ngif = '<small *ngIf="a" id="help"></small>\n<small id="help"></small>'
        self.assertNotIn("WCAG-4.1.1-DUPLICATE-ID", ids(one_ngif))
        plain = '<input id="curp">\n<input id="curp">'
        self.assertIn("WCAG-4.1.1-DUPLICATE-ID", ids(plain))


class TestSkipLink(unittest.TestCase):
    def test_app_shell_without_skip_link_is_flagged_but_routed_pages_are_not(self):
        shell = '<app-header></app-header>\n<router-outlet></router-outlet>'
        self.assertIn("WCAG-2.4.1-NO-SKIP-LINK", ids(shell, path="/r/src/app/app.component.html"))
        self.assertNotIn("WCAG-2.4.1-NO-SKIP-LINK", ids(shell, path="/r/src/app/pages/home/home.component.html"))
        ok = '<a class="skip-link" href="#main">Saltar al contenido</a>\n<router-outlet></router-outlet>'
        self.assertNotIn("WCAG-2.4.1-NO-SKIP-LINK", ids(ok, path="/r/src/app/app.component.html"))
        ok2 = '<a href="#contenido">Ir al contenido principal</a><router-outlet></router-outlet>'
        self.assertNotIn("WCAG-2.4.1-NO-SKIP-LINK", ids(ok2, path="/r/src/app/app.component.html"))
