"""ZIP upload hardening, AI error classification / prompt caps and the AI-status read model."""
import os
import stat
import tempfile
import unittest
import zipfile

import centinela
from auditors import zip_source_scan
from core import ai_status, code_context


def _zip(entries, symlink=None):
    f = tempfile.NamedTemporaryFile(suffix=".zip", delete=False)
    f.close()
    with zipfile.ZipFile(f.name, "w") as z:
        for name, data in entries.items():
            z.writestr(name, data)
        if symlink:
            info = zipfile.ZipInfo(symlink)
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            z.writestr(info, "/etc/passwd")
    return f.name


class TestSafeExtract(unittest.TestCase):
    def test_extracts_normal_zip(self):
        zp = _zip({"proj/a.py": "x=1\n", "proj/sub/b.txt": "y"})
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(zip_source_scan.safe_extract(zp, d), 2)
            self.assertTrue(os.path.isfile(os.path.join(d, "proj/sub/b.txt")))

    def test_rejects_zip_slip(self):
        zp = _zip({"../../evil.txt": "x"})
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(zip_source_scan.ZipRejected):
                zip_source_scan.safe_extract(zp, d)
            self.assertFalse(os.path.exists(os.path.join(d, "..", "..", "evil.txt")))

    def test_rejects_symlink(self):
        zp = _zip({"a.txt": "x"}, symlink="link")
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(zip_source_scan.ZipRejected):
                zip_source_scan.safe_extract(zp, d)

    def test_rejects_non_zip(self):
        f = tempfile.NamedTemporaryFile(suffix=".zip", delete=False)
        f.write(b"not a zip")
        f.close()
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(zip_source_scan.ZipRejected):
                zip_source_scan.safe_extract(f.name, d)

    def test_asset_name_is_namespaced_and_sanitised(self):
        self.assertEqual(zip_source_scan.asset_name_for("mi app/../x"), "Local/mi-app-..-x")
        self.assertTrue(zip_source_scan.asset_name_for("demo").startswith("Local/"))
        with self.assertRaises(zip_source_scan.ZipRejected):
            zip_source_scan.asset_name_for("   ")


class TestAiErrorClassification(unittest.TestCase):
    def test_oversized_prompt_does_not_pause_the_tier(self):
        msg = "Error code: 400 - {'error': {'message': 'Please reduce the length of the messages or completion.', 'type': 'invalid_request_error'}}"
        self.assertEqual(centinela._cooldown_seconds(msg), 0)
        self.assertEqual(centinela._cooldown_seconds("This endpoint's maximum context length is 262144 tokens"), 0)

    def test_real_auth_failures_still_pause_long(self):
        self.assertEqual(centinela._cooldown_seconds("Error code: 401 - Incorrect API key provided"), 1800)
        self.assertEqual(centinela._cooldown_seconds("400 API_KEY_INVALID"), 1800)


class TestPromptAndSnippetCaps(unittest.TestCase):
    def test_minified_line_is_truncated_in_code_context(self):
        lines = ["function f() {", "  var x = '" + "a" * 3_000_000 + "';", "}"]
        snippet, _ = code_context._extract_enclosing(lines, 2)
        self.assertLess(len(snippet), 2000)
        self.assertIn("línea truncada", snippet)


class TestAiStatus(unittest.TestCase):
    def test_status_lists_every_tier_without_network(self):
        st = ai_status.get_status()
        labels = [t["label"] for t in st["tiers"]]
        self.assertIn("openrouter", labels)
        for t in st["tiers"]:
            self.assertIn(t["state"], {"disponible", "agotado", "en_pausa", "revisar", "sin_llave", "sin_uso"})
            self.assertGreaterEqual(t["ok_today"], 0)


if __name__ == "__main__":
    unittest.main()
