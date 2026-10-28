"""WSTG additions of 2026-10-01 (INFO-03, CONF-08, INFO-05, ATHN-06), exercised against REAL local HTTP servers
(no mocks): one that leaks everything and one that is clean."""
import http.server
import threading
import unittest

from auditors.auditor_wstg import audit_url_wstg

LEAKY_PAGE = b"""<html><head><title>x</title></head><body>
<!-- TODO: quitar usuario: admin password: Sup3r -->
<p>servidor interno 192.0.2.13</p>
<form><input type="password" name="p"></form></body></html>"""
CLEAN_PAGE = b"<html><head><title>ok</title></head><body><p>Hola</p></body></html>"


def _serve(routes):
    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):  # silence
            pass

        def do_GET(self):
            status, ctype, body, headers = routes.get(self.path, (404, "text/plain", b"not found", {}))
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            for k, v in headers.items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


class TestWstgDynamicAdditions(unittest.TestCase):
    def _ids(self, routes):
        srv = _serve(routes)
        self.addCleanup(srv.shutdown)
        findings = audit_url_wstg(f"http://127.0.0.1:{srv.server_address[1]}", asset_id=None, timeout=3)
        return {f["cve_id"] for f in findings}

    def test_leaky_server_triggers_all_four(self):
        got = self._ids({
            "/": (200, "text/html", LEAKY_PAGE, {}),
            "/robots.txt": (200, "text/plain", b"User-agent: *\nDisallow: /admin/\nDisallow: /backup/db.sql\nDisallow: /css/\n", {}),
            "/crossdomain.xml": (200, "text/xml", b'<cross-domain-policy><allow-access-from domain="*"/></cross-domain-policy>', {}),
        })
        for rid in ("WSTG-INFO-03-METAFILE-LEAK", "WSTG-CONF-08-CROSSDOMAIN-WILDCARD", "WSTG-INFO-05-CONTENT-LEAK", "WSTG-ATHN-06-LOGIN-CACHEABLE"):
            self.assertIn(rid, got)

    def test_clean_server_triggers_none_of_them(self):
        got = self._ids({
            "/": (200, "text/html", CLEAN_PAGE, {}),
            "/robots.txt": (200, "text/plain", b"User-agent: *\nDisallow: /css/\nDisallow: /img/\n", {}),
            "/crossdomain.xml": (200, "text/xml", b'<cross-domain-policy><allow-access-from domain="app.example.internal"/></cross-domain-policy>', {}),
        })
        for rid in ("WSTG-INFO-03-METAFILE-LEAK", "WSTG-CONF-08-CROSSDOMAIN-WILDCARD", "WSTG-INFO-05-CONTENT-LEAK", "WSTG-ATHN-06-LOGIN-CACHEABLE"):
            self.assertNotIn(rid, got)

    def test_login_page_with_no_store_is_not_flagged(self):
        got = self._ids({"/": (200, "text/html", b'<html><body><input type="password"></body></html>', {"Cache-Control": "no-store"})})
        self.assertNotIn("WSTG-ATHN-06-LOGIN-CACHEABLE", got)

    def test_html_error_page_as_robots_is_not_a_leak(self):
        # SPA fallback: every path returns the app shell as 200 text/html; that must not look like a robots.txt
        got = self._ids({"/": (200, "text/html", CLEAN_PAGE, {}),
                         "/robots.txt": (200, "text/html", b"<html><body>Disallow: /admin</body></html>", {})})
        self.assertNotIn("WSTG-INFO-03-METAFILE-LEAK", got)


if __name__ == "__main__":
    unittest.main()
