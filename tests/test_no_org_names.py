"""The shipped source and README must not name the company that runs the private deployment: those names live in `.env`
(see core/org_config.py). A mention is a leak into the public snapshot and ties the project to one organisation."""
import os
import re
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCAN = ["api", "auditors", "core", "workers", "remediation", "discovery", "frontend/src", "frontend/public", "config",
        "centinela.py", "sentinel.py", "main.py", "docker-compose.yml", ".env.example", "README.md"]
# `core/triage_seeds` and the triage-catalog scripts hold per-customer decisions and are excluded from the public release by the builder.
SKIP_PARTS = ("frontend/public/descargas", "core/triage_seeds", "__pycache__", "node_modules")
FORBIDDEN = re.compile(r"(?i:org)|the organization\b")
EXT = {".py", ".js", ".jsx", ".css", ".html", ".yml", ".yaml", ".md", ".sh", ".json", ".example", ""}


def _files():
    for entry in SCAN:
        path = os.path.join(ROOT, entry)
        if os.path.isfile(path):
            yield path
            continue
        for base, dirs, names in os.walk(path):
            dirs[:] = [d for d in dirs if d not in ("node_modules", "__pycache__", "dist")]
            for n in names:
                p = os.path.join(base, n)
                if any(part in p.replace("\\", "/") for part in SKIP_PARTS):
                    continue
                if os.path.splitext(n)[1].lower() in EXT:
                    yield p


class TestNoOrganisationNames(unittest.TestCase):
    def test_source_and_readme_do_not_name_the_organisation(self):
        hits = []
        for p in _files():
            try:
                txt = open(p, encoding="utf-8").read()
            except (UnicodeDecodeError, OSError):
                continue
            for i, line in enumerate(txt.splitlines(), 1):
                if FORBIDDEN.search(line):
                    hits.append(f"{os.path.relpath(p, ROOT)}:{i}: {line.strip()[:90]}")
        self.assertEqual(hits, [], "organisation names found:\n" + "\n".join(hits[:30]))

    def test_org_config_is_environment_driven(self):
        from core import org_config
        self.assertEqual(org_config.vault_path("ansible", "x"), f"{org_config.VAULT_NAMESPACE}/ansible/x")


if __name__ == "__main__":
    unittest.main()
