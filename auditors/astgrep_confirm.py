"""
Structural confirmation of line-regex findings with ast-grep (ADR-0022 §8; ast-grep is MIT, https://ast-grep.github.io).

The native SAST engine finds risky calls with single-line regular expressions. A regex cannot tell a real call from the
same characters inside a string or comment, `window.open(url + x)` from a file `open(path + x)`, or `eval(variable)` from
`eval("2+2")`. Measured in production 2026-11-12: of the open findings of these four families, the AI had marked
"no real risk" 88/148 PATH-TRAVERSAL-RISK in .js (mostly minified jQuery and vendored plugins), 37/139 + 44/84
CODE-INJECTION-EVAL in .js/.java and 14/23 SQL-INJECTION-CONCAT.

How it works: after the regex pass of a file, if (and only if) the file has a finding of one of these families, ast-grep
parses that file once and looks for the dangerous SHAPE -- a call whose argument is NOT a constant literal:

  CODE-INJECTION-EVAL       eval(<no literal>) [Python/JS/TS]; <receiver>.eval(<no literal>) [Java ScriptEngine & co.]
  CMD-INJECTION-SHELL-TRUE  subprocess.<f>(<no literal>, ..., shell=True) [Python]
  PATH-TRAVERSAL-RISK       open(<concatenation or f-string>) [Python]; fs.<read/write/open/stream>(<no literal>) [JS/TS]
  SQL-INJECTION-CONCAT      <x>.execute/query/executeQuery/createQuery/...(<concatenation>) [Python/JS/TS/Java]

A regex finding whose line holds no such shape is dropped; one that does is kept and says it was structurally confirmed.
Fail-closed: no ast-grep binary, an unsupported language, a parse error or a timeout keeps every finding untouched.
"""
import json
import os
import shutil
import subprocess
import traceback
from typing import Any, Dict, List, Tuple

FAMILIES = ("CODE-INJECTION-EVAL", "CMD-INJECTION-SHELL-TRUE", "PATH-TRAVERSAL-RISK", "SQL-INJECTION-CONCAT")
LANG_BY_EXT = {".py": "python", ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".jsx": "javascript",
               ".ts": "typescript", ".tsx": "tsx", ".java": "java"}
TIMEOUT_S = int(os.getenv("ASTGREP_TIMEOUT_S", "60"))
# Java has no global eval: `x.eval(...)` is only code execution when x is a script/expression engine. The receiver's type is
# not visible to a syntax tree, so the file must also import one (measured 2026-11-12: OFBiz's own `condition.eval(context)`
# methods were the bulk of the Java CODE-INJECTION-EVAL findings).
JAVA_SCRIPT_ENGINE_IMPORT = __import__("re").compile(
    r"^\s*import\s+(static\s+)?(javax\.script|groovy\.(lang|util)|org\.codehaus\.groovy|org\.apache\.commons\.jexl\d?|org\.mvel2|"
    r"ognl|org\.mozilla\.javascript|jdk\.nashorn|org\.openjdk\.nashorn|org\.graalvm\.polyglot|bsh)\b", __import__("re").M)
CONFIRMED_NOTE = " [Confirmado por análisis estructural (ast-grep): la llamada recibe un valor no constante.]"

# A literal that cannot carry outside input: a plain string (no interpolation) / a template without substitutions.
_PY_LITERAL = "all: [{kind: string}, {not: {has: {kind: interpolation, stopBy: end}}}]"
_JS_LITERAL = "any: [{kind: string}, {all: [{kind: template_string}, {not: {has: {kind: template_substitution, stopBy: end}}}]}]"
_JAVA_LITERAL = "kind: string_literal"


def _call_any(callee: str, var: str) -> str:
    """`callee(VAR)` or `callee(VAR, ...)` (ast-grep's `$$$` after a comma needs at least one more argument)."""
    return f"any: [{{pattern: '{callee}(${var})'}}, {{pattern: '{callee}(${var}, $$$REST)'}}]"


def _rules() -> Dict[str, str]:
    """Rule YAML per ast-grep language. Rule ids are `<FAMILY>::<n>`."""
    js_like = lambda lang: f"""
id: CODE-INJECTION-EVAL::js
language: {lang}
rule: {{{_call_any('eval', 'X')}}}
constraints: {{X: {{not: {{{_JS_LITERAL}}}}}}}
---
id: PATH-TRAVERSAL-RISK::js
language: {lang}
rule: {{{_call_any('$FS.$M', 'P')}}}
constraints:
  FS: {{regex: '^(fs|fsp|fsPromises|fse)$'}}
  M: {{regex: '^(open|openSync|readFile|readFileSync|writeFile|writeFileSync|createReadStream|createWriteStream|unlink|unlinkSync|appendFile|appendFileSync)$'}}
  P: {{not: {{{_JS_LITERAL}}}}}
---
id: SQL-INJECTION-CONCAT::js
language: {lang}
rule: {{{_call_any('$C.$M', 'Q')}}}
constraints:
  M: {{regex: '^(execute|query|raw|exec)$'}}
  Q: {{any: [{{kind: binary_expression}}, {{all: [{{kind: template_string}}, {{has: {{kind: template_substitution, stopBy: end}}}}]}}]}}
"""
    return {
        "python": f"""
id: CODE-INJECTION-EVAL::py
language: python
rule: {{{_call_any('eval', 'X')}}}
constraints: {{X: {{not: {{{_PY_LITERAL}}}}}}}
---
id: CMD-INJECTION-SHELL-TRUE::py
language: python
rule:
  all:
    - {{pattern: 'subprocess.$F($CMD, $$$REST)'}}
    - {{has: {{kind: argument_list, has: {{kind: keyword_argument, regex: '^shell\\s*=\\s*True$'}}}}}}
constraints: {{CMD: {{not: {{{_PY_LITERAL}}}}}}}
---
id: PATH-TRAVERSAL-RISK::py
language: python
rule: {{{_call_any('open', 'P')}}}
constraints:
  P: {{any: [{{kind: binary_operator}}, {{all: [{{kind: string}}, {{has: {{kind: interpolation, stopBy: end}}}}]}}]}}
---
id: SQL-INJECTION-CONCAT::py
language: python
rule: {{{_call_any('$C.execute', 'Q')}}}
constraints: {{Q: {{kind: binary_operator}}}}
""",
        "javascript": js_like("javascript"),
        "typescript": js_like("typescript"),
        "tsx": js_like("tsx"),
        "java": f"""
id: CODE-INJECTION-EVAL::java
language: java
rule: {{{_call_any('$R.eval', 'X')}}}
constraints: {{X: {{not: {{{_JAVA_LITERAL}}}}}}}
---
id: SQL-INJECTION-CONCAT::java
language: java
rule: {{{_call_any('$C.$M', 'Q')}}}
constraints:
  M: {{regex: '^(execute|executeQuery|executeUpdate|prepareStatement|prepareCall|createQuery|createNativeQuery|addBatch)$'}}
  Q: {{kind: binary_expression}}
""",
    }


def available() -> bool:
    return shutil.which("ast-grep") is not None


def structural_matches(file_path: str, language: str) -> List[Tuple[str, int, int]]:
    """[(family, first_line, last_line)] (1-based). Raises on any ast-grep failure: the caller fails closed."""
    res = subprocess.run(["ast-grep", "scan", "--inline-rules", _rules()[language], "--json=compact", file_path],
                         capture_output=True, text=True, timeout=TIMEOUT_S)
    if res.returncode not in (0, 1):
        raise RuntimeError(f"ast-grep rc={res.returncode}: {res.stderr[-300:]}")
    out = []
    for m in json.loads(res.stdout or "[]"):
        rng = m.get("range") or {}
        out.append((str(m.get("ruleId", "")).split("::", 1)[0],
                    int(rng["start"]["line"]) + 1, int(rng["end"]["line"]) + 1))
    return out


def confirm(file_path: str, findings: List[Dict[str, Any]], content: str = None) -> Tuple[List[Dict[str, Any]], int]:
    """(findings kept, how many regex findings were dropped). Only the four families are touched.
    `content` is the exact text the regex pass saw; ast-grep analyses THAT text (written to a temporary file with the same
    extension), so a relative or stale `file_path` can never make a real finding disappear. Without content the file on
    disk is used, and if it does not exist everything is kept."""
    candidates = [f for f in findings if f.get("cve_id") in FAMILIES]
    lang = LANG_BY_EXT.get(os.path.splitext(file_path)[1].lower())
    if not candidates or not lang or not available():
        return findings, 0
    tmp = None
    try:
        if content is not None:
            import tempfile
            fd, tmp = tempfile.mkstemp(suffix=os.path.splitext(file_path)[1].lower())
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(content)
            target = tmp
        elif os.path.isfile(file_path):
            target = file_path
        else:
            return findings, 0
        matches = structural_matches(target, lang)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
        print(f"⚠️ [ast-grep] could not confirm {file_path}; keeping the regex findings:")
        traceback.print_exc()
        return findings, 0
    finally:
        if tmp:
            try:
                os.remove(tmp)
            except OSError as exc:
                print(f"⚠️ [ast-grep] could not remove temporary file {tmp}: {exc}")
    if lang == "java":
        try:
            if content is None:
                with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
                    content = fh.read()
            has_engine = bool(JAVA_SCRIPT_ENGINE_IMPORT.search(content))
        except OSError:
            traceback.print_exc()
            has_engine = True   # fail closed
        if not has_engine:
            matches = [m for m in matches if m[0] != "CODE-INJECTION-EVAL"]
    kept, dropped = [], 0
    for f in findings:
        if f.get("cve_id") not in FAMILIES:
            kept.append(f)
            continue
        line = int(f.get("line") or 0)
        if any(fam == f["cve_id"] and first <= line <= last for fam, first, last in matches):
            kept.append({**f, "description": str(f.get("description", "")) + CONFIRMED_NOTE})
        else:
            dropped += 1
    return kept, dropped
