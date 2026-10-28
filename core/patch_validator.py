"""
Real verification of unified-diff patches against the actual repository they claim to fix.

Why this exists (2026-09-23): a backfill wrote templated diffs (invented hunk headers and invented
"before" lines) into `vulnerability_log.fix_patch` for ~115k findings and they were shipped in PDF
reports as if real. A patch is only "real" if `git apply --check` succeeds against the real file
contents, so that is the single acceptance criterion used everywhere (AI correlation, purge tool,
GitLab autofix).
"""
import os
import re
import subprocess
from typing import List, Optional, Tuple

_FENCE_RE = re.compile(r"^\s*```[a-zA-Z]*\s*\n|\n\s*```\s*$")
_TARGET_RE = re.compile(r"^\+\+\+ b/(.+?)\s*$", re.MULTILINE)
_SOURCE_RE = re.compile(r"^--- a/(.+?)\s*$", re.MULTILINE)

# Flags shared by check and apply so "validated" always means "will apply".
_APPLY_FLAGS = ["--recount", "--whitespace=nowarn"]


def clean_patch(patch: str) -> str:
    """Strip markdown code fences an LLM may wrap around a diff; normalise the trailing newline."""
    if not patch:
        return ""
    text = patch.replace("\r\n", "\n")
    text = _FENCE_RE.sub("", text.strip("\n"))
    text = text.strip("\n")
    return (text + "\n").replace("\r\n", "\n") if text.strip() else ""      # whitespace-only (e.g. a lone "\r") is empty, not a patch; keeps clean_patch idempotent


def patch_target_files(patch: str) -> List[str]:
    return sorted(set(_SOURCE_RE.findall(patch)) | set(_TARGET_RE.findall(patch)))


def _safe_relative(path: str) -> bool:
    return bool(path) and not os.path.isabs(path) and ".." not in path.split("/")


def validate_patch(repo_dir: Optional[str], patch: str, timeout: int = 20) -> Tuple[bool, str]:
    """Return (ok, reason). ok is True only if the patch is a real git-format diff whose target
    files exist under repo_dir and whose context/removed lines match the real file contents."""
    if not repo_dir or not os.path.isdir(repo_dir):
        return False, "repo_unavailable"
    cleaned = clean_patch(patch)
    if not cleaned.strip():
        return False, "empty"
    if not (_SOURCE_RE.search(cleaned) and _TARGET_RE.search(cleaned) and "\n@@" in "\n" + cleaned):
        return False, "not_git_unified_diff"
    for rel in patch_target_files(cleaned):
        if not _safe_relative(rel):
            return False, f"unsafe_path:{rel}"
        if not os.path.isfile(os.path.join(repo_dir, rel)):
            return False, f"target_file_missing:{rel}"
    try:
        res = subprocess.run(
            ["git", "-C", repo_dir, "apply", "--check", *_APPLY_FLAGS, "-"],
            input=cleaned, capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return False, "git_apply_timeout"
    if res.returncode != 0:
        return False, "does_not_apply:" + (res.stderr.strip().splitlines() or ["?"])[0][:160]
    return True, "ok"


def apply_patch(repo_dir: str, patch: str, timeout: int = 30) -> Tuple[bool, str]:
    """Apply a previously validated patch to the working tree (same flags as validate_patch)."""
    ok, reason = validate_patch(repo_dir, patch, timeout=timeout)
    if not ok:
        return False, reason
    res = subprocess.run(
        ["git", "-C", repo_dir, "apply", *_APPLY_FLAGS, "-"],
        input=clean_patch(patch), capture_output=True, text=True, timeout=timeout,
    )
    if res.returncode != 0:
        return False, "apply_failed:" + res.stderr.strip()[:300]
    return True, "ok"
