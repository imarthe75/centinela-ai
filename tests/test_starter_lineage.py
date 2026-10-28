"""ADR-0012 D5: starter lineage on REAL temporary directory trees (no mocks)."""
import os
import tempfile
import unittest

from auditors import starter_lineage as sl


def write(root, rel, content, mode="w"):
    p = os.path.join(root, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, mode if mode == "wb" else "w", **({} if mode == "wb" else {"encoding": "utf-8", "newline": ""})) as f:
        f.write(content)


class TestLineage(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.TemporaryDirectory()
        self.addCleanup(self.t.cleanup)
        self.starter = os.path.join(self.t.name, "starter")
        self.proj = os.path.join(self.t.name, "proj")
        write(self.starter, "src/Auth.java", "class Auth {\n  void login() {}\n}\n")
        write(self.starter, "src/Util.java", "class Util {}\n")
        write(self.starter, "config/app.yml", "port: 8080\n")
        write(self.starter, "node_modules/x/index.js", "ignored\n")
        write(self.proj, "src/Auth.java", "class Auth {\r\n  void login() {}   \r\n}\r\n")          # same, CRLF + trailing blanks
        write(self.proj, "src/Util.java", "class Util { int x; }\n")                                # modified
        write(self.proj, "lib/Moved.yml", "port: 8080\n")                                           # same content as config/app.yml, other path
        write(self.proj, "src/Own.java", "class Own {}\n")                                          # only in the project

    def test_states(self):
        s_idx = {"starter": sl.index_tree(self.starter)}
        self.assertNotIn("node_modules/x/index.js", s_idx["starter"])
        lin = sl.classify_files(sl.index_tree(self.proj), s_idx)
        self.assertEqual(lin["src/Auth.java"]["state"], sl.INHERITED)       # line endings / trailing spaces do not count as a change
        self.assertEqual(lin["src/Util.java"]["state"], sl.DIVERGED)
        self.assertEqual(lin["lib/Moved.yml"]["state"], sl.MOVED)
        self.assertEqual(lin["lib/Moved.yml"]["starter_path"], "config/app.yml")
        self.assertEqual(lin["src/Own.java"]["state"], sl.OWN)

    def test_findings_are_annotated_by_file(self):
        lin = sl.classify_files(sl.index_tree(self.proj), {"starter": sl.index_tree(self.starter)})
        fs = sl.annotate_findings([{"url_path": "src/Auth.java:2"}, {"url_path": "src/Util.java:1"}, {"url_path": "src/Own.java:1"},
                                   {"url_path": "src/Missing.java:3"}, {"url_path": None}, {"url_path": "../etc/passwd:1"}], lin)
        self.assertEqual([f["lineage"]["state"] for f in fs], [sl.INHERITED, sl.DIVERGED, sl.OWN, "unknown", "unknown", "unknown"])

    def test_split_location(self):
        self.assertEqual(sl.split_location("a/b.java:12"), "a/b.java")
        self.assertEqual(sl.split_location("a/b.java"), "a/b.java")
        self.assertIsNone(sl.split_location("/abs/x.java:1"))
        self.assertIsNone(sl.split_location(""))

    def test_empty_starter_never_claims_lineage(self):
        lin = sl.classify_files(sl.index_tree(self.proj), {})
        self.assertTrue(all(v["state"] == sl.OWN for v in lin.values()))

    def test_a_huge_tree_is_refused_not_partially_indexed(self):
        old = sl.MAX_FILES
        sl.MAX_FILES = 2
        try:
            with self.assertRaises(sl.TreeTooLarge):
                sl.index_tree(self.proj)                    # 3 comparable files > 2
        finally:
            sl.MAX_FILES = old

    def _env(self, **kw):
        old = {k: os.environ.get(k) for k in ("STARTER_CORE_GROUPS", "STARTER_CORE_PROJECTS")}
        for k in old:
            os.environ.pop(k, None)
        os.environ.update({k: v for k, v in kw.items() if v is not None})

        def restore():
            for k, v in old.items():
                os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)
        self.addCleanup(restore)

    def test_the_whole_group_is_the_starter_core(self):
        self._env()
        ws = os.path.join(self.t.name, "ws")
        for d in ("starters_starter-backend@desarrollo-c745a3", "starters_plantillas_backend-modulo-a",
                  "starters_plantillas_backend-modulo-a@desarrollo-c745a3", "starters_app-ui@main-b28b7a",
                  "starters_wiki-repo", "otros_proyecto@main-111111", "gitlab2__starters_x@main-222222"):
            os.makedirs(os.path.join(ws, d))
        found = sl.starter_dirs(ws, "primary")
        self.assertEqual(sorted(found), ["starters/app-ui", "starters/plantillas_backend-modulo-a",
                                         "starters/starter-backend", "starters/wiki-repo"])
        # a project cloned twice (legacy + branch) counts once, and the branch clone wins
        self.assertTrue(found["starters/plantillas_backend-modulo-a"].endswith("@desarrollo-c745a3"))
        # another instance's group and unrelated projects are not the Starter
        self.assertFalse(any("otros" in v or "gitlab2__" in v for v in found.values()))

    def test_groups_and_extra_projects_are_configurable_and_the_starter_excludes_itself(self):
        self._env(STARTER_CORE_GROUPS="starters, plantillas", STARTER_CORE_PROJECTS="arquitectura/core-app")
        self.assertEqual(sl.starter_groups(), ["starters", "plantillas"])
        for path, expect in (("starters/app-ui", True), ("plantillas/x/y", True), ("arquitectura/core-app", True),
                             ("startersX/otro", False), ("grupo-b/starters/app", False), ("proyecto-g/backend", False), ("", False)):
            self.assertEqual(sl.is_starter_path(path), expect, path)

    def test_no_clones_means_no_starter_not_an_invented_one(self):
        self._env()
        self.assertEqual(sl.starter_dirs(os.path.join(self.t.name, "nowhere"), "primary"), {})

if __name__ == "__main__":
    unittest.main()
