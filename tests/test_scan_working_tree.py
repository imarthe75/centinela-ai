import os
import subprocess
import tempfile
import unittest

from scripts import scan_working_tree as swt


def _repo(files):
    d = tempfile.mkdtemp()
    subprocess.run(["git", "-C", d, "init", "-q"], check=True)
    for name, body in files.items():
        os.makedirs(os.path.dirname(os.path.join(d, name)), exist_ok=True)
        with open(os.path.join(d, name), "w", encoding="utf-8") as fh:
            fh.write(body)
    subprocess.run(["git", "-C", d, "add", "."], check=True)
    return d


class TestScanWorkingTree(unittest.TestCase):
    def test_flags_dangerous_code_and_exits_1(self):
        d = _repo({"a.py": 'import os\ndef f(x):\n    os.system("ls " + x)\n    return eval(x)\n'})
        self.assertEqual(swt.main(["--repo", d]), 1)

    def test_clean_code_exits_0(self):
        d = _repo({"a.py": "def add(a, b):\n    return a + b\n"})
        self.assertEqual(swt.main(["--repo", d]), 0)

    def test_unreadable_repo_exits_2(self):
        self.assertEqual(swt.main(["--repo", "/nonexistent-dir-xyz"]), 2)


if __name__ == "__main__":
    unittest.main()


class TestExtraDetectors(unittest.TestCase):
    def _ids(self, files):
        d = _repo(files)
        paths = swt.changed_files(d)
        return {f.get("cve_id") for f in swt.extra_findings(d, paths)}

    def test_wcag_image_without_alt(self):
        ids = self._ids({"a.html": '<html lang="es"><body><img src="x.png"></body></html>\n'})
        self.assertTrue(any("WCAG" in (i or "") for i in ids), ids)

    def test_privileged_kubernetes_container(self):
        ids = self._ids({"d.yaml": "apiVersion: v1\nkind: Pod\nspec:\n  containers:\n  - name: a\n    image: x:1\n    securityContext:\n      privileged: true\n"})
        self.assertIn("K8S-PRIVILEGED-CONTAINER", ids)

    def test_open_security_group(self):
        ids = self._ids({"m.tf": 'resource "aws_security_group" "s" {\n  ingress {\n    from_port = 22\n    to_port = 22\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\n'})
        self.assertTrue(ids & {"TF-OPEN-SECURITY-GROUP", "TF-ADMIN-PORT-WORLD-OPEN"}, ids)

    def test_ci_curl_pipe_shell(self):
        ids = self._ids({".gitlab-ci.yml": "build:\n  script:\n    - curl -sSL https://x.example/i.sh | sh\n"})
        self.assertIn("CICD-CURL-PIPE-SHELL", ids)

    def test_clean_html_and_yaml_produce_nothing(self):
        ids = self._ids({"a.html": '<html lang="es"><head><title>t</title></head><body><img src="x.png" alt="logo"></body></html>\n', "c.yaml": "a: 1\n"})
        self.assertFalse({i for i in ids if i and i.startswith(("K8S", "TF-", "CICD"))}, ids)


class TestAuthzOnWorkingTree(unittest.TestCase):
    def test_endpoint_without_method_authorization_is_flagged_and_annotated_one_is_not(self):
        d = _repo({
            "src/main/java/a/Cfg.java": "package a;\n@EnableMethodSecurity\n@Configuration\npublic class Cfg {}\n",
            "src/main/java/a/Ok.java": 'package a;\n@RestController\n@RequestMapping("/ok")\npublic class Ok {\n  @PreAuthorize("hasAuthority(\'X\')")\n  @GetMapping("/a")\n  public String a() { return ""; }\n}\n',
            "src/main/java/a/Bad.java": 'package a;\n@RestController\n@RequestMapping("/bad")\npublic class Bad {\n  @DeleteMapping("/{id}")\n  public void del(@PathVariable Long id) { }\n}\n',
        })
        found = swt.extra_findings(d, swt.changed_files(d))
        files = {f["rel_path"] for f in found if str(f.get("cve_id", "")).startswith("AUTHZ-")}
        self.assertIn("src/main/java/a/Bad.java", files)
        self.assertNotIn("src/main/java/a/Ok.java", files)
