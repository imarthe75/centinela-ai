#!/usr/bin/env python3
"""PostToolUse hook for development sessions on this repository: shrink very long Bash output before it enters the agent's context.

Everything that enters the context is billed again on every later turn; a long test or build log costs far more than the reply that
follows it. This hook gives the agent a shorter version and keeps the complete original in a private file named in the shortened text.

Guarantees (tests: tests/test_compress_output_hook.py):
- Only the Bash tool. Claude Code accepts a replacement only in the tool's own output shape, documented for Bash
  (stdout, stderr, interrupted, isImage); Read/Edit/Write are never touched because their exact text feeds later edits.
- Nothing is lost: before the middle of an output is cut, the full original is written to a file (0600 in a 0700 directory owned
  by this user). If that fails, only the lossless cleanup runs. The test evidence that CLAUDE.md rule 2 requires stays complete there.
- Errors and test/build summaries survive the cut (up to a cap); first and last lines are always kept.
- Short outputs pass through; a replacement is emitted only when it saves a meaningful amount; any internal error = no replacement.

Environment: CENTINELA_COMPRESS_OUTPUT=0 disables; CENTINELA_COMPRESS_MAX_CHARS (8000), _HEAD_LINES (60), _TAIL_LINES (40),
_KEEP_LINES (80), _SPILL_DIR (default <tmp>/centinela-tool-output-<uid>; the newest 40 originals are kept).

Idea from the Chisle project (JayPokale, MIT); our own implementation (same design as resident-agent-os scripts/hooks/compress-output.js).
"""
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
import time
import traceback

ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")
IMPORTANT = re.compile(
    r"error|fail|exception|traceback|panic|fatal|denied|refused|warn|assert|cannot|can't|not found|no such|timed? ?out|"
    r"segmentation|killed|abort|^\s+at\s|^\s*file \"|^\s*caused by|"
    r"\b\d+\s+(passed|failed|errors?|skipped|tests?)\b|tests? run:|build (success|failure)|^=+ .* =+$|^-+ .* -+$|exit (code|status)",
    re.IGNORECASE,
)
KEEP_FILES = 40
MIN_SAVING = 200


def _env_int(name, default):
    try:
        v = int(os.environ.get(name, ""))
        return v if v >= 0 else default
    except ValueError:
        return default


def limits():
    return {k: _env_int(f"CENTINELA_COMPRESS_{k.upper()}", d)
            for k, d in (("max_chars", 8000), ("head_lines", 60), ("tail_lines", 40), ("keep_lines", 80))}


def clean(text):
    """Lossless: drop terminal color codes, squeeze blank runs, fold >=4 identical consecutive lines into one plus a count."""
    lines = ANSI.sub("", text).replace("\r\n", "\n").split("\n")
    out, i = [], 0
    while i < len(lines):
        j = i + 1
        while j < len(lines) and lines[j] == lines[i]:
            j += 1
        run = j - i
        if not lines[i].strip():
            out.append("")
        elif run >= 4:
            out += [lines[i], f"[línea anterior repetida {run - 1} veces más]"]
        else:
            out += lines[i:j]
        i = j
    return "\n".join(out)


def cut(text, lim, spill_path):
    lines = text.split("\n")
    head, tail = lim["head_lines"], lim["tail_lines"]
    if len(text) <= lim["max_chars"] or len(lines) <= head + tail + 1:
        return text
    kept, gap, salvaged = [], 0, 0
    for line in lines[head:len(lines) - tail]:
        if salvaged < lim["keep_lines"] and IMPORTANT.search(line):
            if gap:
                kept.append(f"[… {gap} líneas omitidas; salida completa en {spill_path}]")
                gap = 0
            kept.append(line)
            salvaged += 1
        else:
            gap += 1
    if gap:
        kept.append(f"[… {gap} líneas omitidas; salida completa en {spill_path}]")
    return "\n".join(lines[:head] + kept + lines[len(lines) - tail:])


def spill_dir():
    return os.environ.get("CENTINELA_COMPRESS_SPILL_DIR") or os.path.join(
        tempfile.gettempdir(), f"centinela-tool-output-{os.getuid()}")


def spill(original):
    """Write the full original privately; return its path or None (then nothing may be cut)."""
    try:
        d = spill_dir()
        os.makedirs(d, mode=0o700, exist_ok=True)
        st = os.lstat(d)
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid():
            return None
        os.chmod(d, 0o700)
        name = f"{time.time_ns()}-{hashlib.sha256(original.encode('utf-8', 'replace')).hexdigest()[:12]}.txt"
        path = os.path.join(d, name)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8", errors="replace") as f:
            f.write(original)
        old = sorted(f for f in os.listdir(d) if f.endswith(".txt"))
        for f in old[:max(0, len(old) - KEEP_FILES)]:
            os.remove(os.path.join(d, f))
        return path
    except OSError:
        return None


def shrink(text, lim=None):
    if not isinstance(text, str) or not text:
        return text
    lim = lim or limits()
    tidy = clean(text)
    if len(tidy) <= lim["max_chars"]:
        return tidy
    path = spill(text)
    return cut(tidy, lim, path) if path else tidy


def process_payload(payload):
    """Hook payload -> replacement tool output (same shape), or None to keep the original."""
    if os.environ.get("CENTINELA_COMPRESS_OUTPUT") == "0" or not isinstance(payload, dict):
        return None
    if payload.get("tool_name") != "Bash":
        return None
    resp = payload.get("tool_response")
    if not isinstance(resp, dict) or resp.get("isImage"):
        return None
    if not isinstance(resp.get("stdout"), str) and not isinstance(resp.get("stderr"), str):
        return None
    updated, saved = dict(resp), 0
    for key in ("stdout", "stderr"):
        if isinstance(resp.get(key), str):
            updated[key] = shrink(resp[key])
            saved += len(resp[key]) - len(updated[key])
    return updated if saved >= MIN_SAVING else None


def main():
    try:
        updated = process_payload(json.load(sys.stdin))
        if updated is not None:
            json.dump({"hookSpecificOutput": {"hookEventName": "PostToolUse", "updatedToolOutput": updated}}, sys.stdout)
    except Exception:  # noqa: BLE001 -- a hook must never break the tool pipeline; no replacement means the original reaches the agent
        traceback.print_exc(file=sys.stderr)  # rule 6: never silent; exit 0 keeps the original output in place
    return 0


if __name__ == "__main__":
    sys.exit(main())
