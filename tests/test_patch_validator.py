"""Patch validation must be decided by `git apply --check` against real file contents."""
import os
import subprocess

import pytest

from core import patch_validator as pv


@pytest.fixture()
def repo(tmp_path):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "App.java").write_text(
        "class App {\n    String name = \"admin\";\n    int x = 1;\n}\n")
    return str(tmp_path)


REAL = ("--- a/src/App.java\n+++ b/src/App.java\n@@ -1,4 +1,4 @@\n class App {\n"
        "-    String name = \"admin\";\n+    String name = \"root\";\n     int x = 1;\n }\n")

FABRICATED = ("--- a/src/App.java\n+++ b/src/App.java\n@@ -18,2 +18,2 @@\n"
              "-    String Nombre_Usuario = \"admin\";\n+    String nombreUsuario = \"admin\";\n")


def test_real_patch_validates_and_applies(repo):
    ok, why = pv.validate_patch(repo, REAL)
    assert ok, why
    ok, why = pv.apply_patch(repo, REAL)
    assert ok, why
    assert "root" in open(os.path.join(repo, "src/App.java")).read()


def test_fenced_patch_is_accepted(repo):
    ok, why = pv.validate_patch(repo, "```diff\n" + REAL + "```")
    assert ok, why


def test_templated_patch_with_invented_lines_is_rejected(repo):
    ok, why = pv.validate_patch(repo, FABRICATED)
    assert not ok and why.startswith("does_not_apply")


def test_missing_file_and_wrong_format_and_empty_are_rejected(repo):
    assert pv.validate_patch(repo, REAL.replace("src/App.java", "src/Nope.java"))[1].startswith("target_file_missing")
    assert pv.validate_patch(repo, "*** Begin Patch\n*** Update File: x\n@@\n-a\n+b\n")[1] == "not_git_unified_diff"
    assert pv.validate_patch(repo, "") == (False, "empty")
    assert pv.validate_patch(None, REAL) == (False, "repo_unavailable")


def test_path_traversal_rejected(repo):
    evil = REAL.replace("src/App.java", "../../etc/passwd")
    ok, why = pv.validate_patch(repo, evil)
    assert not ok and why.startswith("unsafe_path")
