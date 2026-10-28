#!/usr/bin/env python3
"""Claude Code PostToolUse hook: reject an edit that leaves a file syntactically broken (idea taken from resident-agent-os, ADR-0012).

Reads the hook JSON from stdin (tool_input.file_path). Checks only what can be decided without running the project:
  .py -> parses   .json -> parses   .yml/.yaml -> parses
Exit 0 = fine or not applicable; exit 2 = broken (Claude Code treats 2 as blocking and shows stderr to the model; exit 1 would only warn).
It never modifies anything and never runs project code (compile() only parses the source).
"""
import json
import sys
from pathlib import Path


def check(path: Path):
    """Returns an error string, or None when the file is fine / not checked."""
    ext = path.suffix.lower()
    try:
        if ext == ".py":
            compile(path.read_text(encoding="utf-8"), str(path), "exec")      # parses only; nothing is executed or written
        elif ext == ".json":
            json.loads(path.read_text(encoding="utf-8"))
        elif ext in (".yml", ".yaml"):
            import yaml
            list(yaml.safe_load_all(path.read_text(encoding="utf-8")))
    except SyntaxError as e:
        return f"SyntaxError in {path}:{e.lineno}: {e.msg}"
    except json.JSONDecodeError as e:
        return f"Invalid JSON in {path}: {e}"
    except Exception as e:                      # yaml.YAMLError, UnicodeDecodeError...
        if ext in (".yml", ".yaml") or isinstance(e, UnicodeDecodeError):
            return f"Cannot parse {path}: {e}"
        raise
    return None


def main() -> int:
    try:
        data = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        return 0                                # not invoked by Claude Code: nothing to check
    fp = (data.get("tool_input") or {}).get("file_path")
    if not fp or not Path(fp).is_file():
        return 0
    err = check(Path(fp))
    if err:
        print(err, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
