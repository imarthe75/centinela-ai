"""
Centinela Native Compliance & Master Standards Auditor
Audits codebase against Master Audit Standards (ISO 25010, STRIDE Threat Model, OWASP API, CIS Benchmarks).
"""
import os
import re
from typing import List, Dict, Any
from core import db_manager


# Real bug fixed 2026-08-13, same self-referential class already fixed in
# auditor_master_vulnerabilities.py's CODE-INJECTION-EVAL check: naive substring matching on
# "jwt.decode"/"password"/etc. flags this scanner's OWN detector logic (which necessarily
# contains those words to define what it looks for) and any log message merely *mentioning* a
# word like "password" as descriptive English text (e.g. "Attempting Password authentication...")
# without ever interpolating a real secret value. Confirmed live: 100% of this codebase's own
# STD-STRIDE-JWT-INSECURE-ALG (1/1) and STD-STRIDE-LOG-SENSITIVE-DATA (8/8) findings were exactly
# this, not real issues.
_JWT_WEAK_ALG_RE = re.compile(r'jwt\.decode\s*\([^)]*algorithms\s*=\s*\[[^\]]*(HS256|none)', re.IGNORECASE)
# Only flags a log statement that actually *interpolates* a sensitive-looking variable
# ({password}, {token}, f"{obj.secret_key}", %s formatting of one, etc.) -- not the word
# appearing anywhere in the message text. Extended 2026-08-22 (see the module docstring's
# multi-language note) to also catch SLF4J's own "{}" placeholder style used the same way by
# Java's log.info/debug/warn/error(...), and JS/TS's console.* -- kept as ONE combined pattern
# since the "call name, then a sensitive var inside {}/%s" shape is identical across all three;
# only the call-name alternation differs per language.
_SENSITIVE_INTERPOLATION_RE = re.compile(
    r'(print|logger\.\w+|log\.\w+|console\.\w+)\s*\(.*[{%](\s*\w*\.)?(password|jwt|secret_key|auth_token|token|secret)\w*[}%s]', re.IGNORECASE
)
# Java string-concatenation form of the same risk (SLF4J/System.out don't require {}/%s --
# "contraseña: " + password is just as real a disclosure). Deliberately separate from the
# interpolation regex above rather than one combined pattern: concatenation has no natural analog
# in the Python f-string-first codebase this was originally built for, so keeping it as its own
# rule makes it easy to see (and remove) if it turns out too noisy on real Java code, without
# touching the already-verified interpolation pattern.
_SENSITIVE_CONCAT_RE = re.compile(
    r'(log\.\w+|System\.out\.print\w*|logger\.\w+|console\.\w+)\s*\(.*["\']\s*\+\s*\w*(password|contraseña|secret|token|jwt)\w*\b', re.IGNORECASE
)

# Real Java/Spring equivalent of the FastAPI @app.post(...) route decorator this codebase was
# originally written against -- @PostMapping/@PutMapping/@DeleteMapping/@PatchMapping are the
# real, modern (Spring 4.3+) dedicated annotations for exactly the same "this method changes
# server state" question. The one part that does NOT generalize is the original Python
# audit-evidence check ("remediation_history"/"vulnerability_log" not in content) -- those are
# Centinela's OWN schema table names, meaningless against an unrelated Java government system.
# Replaced with a language-agnostic set of real audit-trail vocabulary (English AND Spanish,
# since SIDECO/SIAT's own code and DB tables are Spanish-language -- confirmed live, e.g.
# ct_conciliaciones) that a genuine audit-logging call site would plausibly contain.
# Real false positive caught live 2026-08-22 verifying against SIDECO's own code:
# ProcesoConciliacionController.java has a bare class-level @RequestMapping("/v1/...") (just a
# base URL path, no HTTP method implied) and only a @GetMapping method inside -- no state-changing
# endpoint at all -- but the first version of this pattern included bare "@RequestMapping" and
# flagged it as one anyway. Spring's @RequestMapping defaults to matching ALL methods (including
# read-only GET) when no method= is given, so it is NOT a reliable state-change signal on its own.
# Restricted to the unambiguous, modern (Spring 4.3+) dedicated annotations, which are already the
# dominant style in this exact codebase (confirmed live: @GetMapping used right next to the
# false-positive @RequestMapping above) -- old-style "@RequestMapping(method = RequestMethod.POST)"
# is a real, disclosed coverage gap rather than risk another false positive parsing that variant.
_JAVA_STATE_CHANGE_RE = re.compile(r'@(PostMapping|PutMapping|DeleteMapping|PatchMapping)\b')
_AUDIT_EVIDENCE_KEYWORDS = ("audit", "auditoria", "auditoría", "bitacora", "bitácora", "historial", "logaction", "trazabilidad")


def audit_stride_threat_matrix(file_path: str, content: str) -> List[Dict[str, Any]]:
    """Audits code against STRIDE threat model standards."""
    findings = []
    lines = content.splitlines()

    # 1. Spoofing: Unsigned or HS256 JWT algorithm check -- requires an actual jwt.decode(...)
    # call with an algorithms=[...] argument naming a weak algorithm, not just those words
    # appearing anywhere on the line (which self-matched this very detector's own source).
    for idx, line in enumerate(lines, 1):
        if _JWT_WEAK_ALG_RE.search(line) and not line.lstrip().startswith("#"):
            findings.append({
                "standard": "STRIDE-SPOOFING",
                "cve_id": "STD-STRIDE-JWT-INSECURE-ALG",
                "severity": "HIGH",
                "file": file_path,
                "line": idx,
                "description": f"STRIDE Spoofing Violation: JWT configured with weak algorithm (HS256/none). Standard requires RS256/Ed25519 asymmetric signatures. Line {idx}: {line.strip()}"
            })

    # 2. Repudiation: Missing audit logging in state-changing endpoints (POST/PUT/DELETE).
    # Real FastAPI route decorators (Python) OR real Spring MVC mapping annotations (Java) --
    # not any file that merely mentions the word "FastAPI" or contains the substring "@app.post"
    # inside an unrelated regex/string (e.g. a route-discovery detector's own pattern definition).
    # Extended 2026-08-22 for Java: the original "audit evidence" signal (absence of the literal
    # strings "remediation_history"/"vulnerability_log") was Centinela's OWN schema table names --
    # meaningless against an unrelated Java codebase, so it's replaced here with a language-
    # agnostic set of real audit-trail vocabulary (English + Spanish, since SIDECO/SIAT's own
    # code and DB tables are Spanish-language).
    is_python_route = bool(re.search(r'@app\.(post|put|delete|patch)\s*\(', content))
    is_java_route = bool(_JAVA_STATE_CHANGE_RE.search(content))
    has_audit_evidence = any(kw in content.lower() for kw in _AUDIT_EVIDENCE_KEYWORDS)
    if is_python_route and "db_manager" in content and not has_audit_evidence:
        findings.append({
            "standard": "STRIDE-REPUDIATION",
            "cve_id": "STD-STRIDE-MISSING-AUDIT-LOG",
            "severity": "MEDIUM",
            "file": file_path,
            "line": 1,
            "description": "STRIDE Repudiation Violation: Endpoint modifies state without writing an immutable audit log entry (who, what, when)."
        })
    elif is_java_route and not has_audit_evidence:
        findings.append({
            "standard": "STRIDE-REPUDIATION",
            "cve_id": "STD-STRIDE-MISSING-AUDIT-LOG",
            "severity": "MEDIUM",
            "file": file_path,
            "line": 1,
            "description": "STRIDE Repudiation Violation: Spring endpoint (@PostMapping/@PutMapping/@DeleteMapping/@PatchMapping) modifies state with no audit-trail vocabulary (audit/bitácora/historial/trazabilidad) found anywhere in this file."
        })

    # 3. Information Disclosure: only flags when a sensitive-looking VARIABLE is actually
    # interpolated into the log call -- not when the word merely appears as descriptive text
    # (e.g. "Attempting Password authentication..." logs no real secret value at all). Extended
    # 2026-08-22 to also catch the Java string-concatenation form (see _SENSITIVE_CONCAT_RE).
    for idx, line in enumerate(lines, 1):
        if _SENSITIVE_INTERPOLATION_RE.search(line) or _SENSITIVE_CONCAT_RE.search(line):
            findings.append({
                "standard": "STRIDE-INFO-DISCLOSURE",
                "cve_id": "STD-STRIDE-LOG-SENSITIVE-DATA",
                "severity": "HIGH",
                "file": file_path,
                "line": idx,
                "description": f"STRIDE Information Disclosure: Sensitive credential or token logged directly. Line {idx}: {line.strip()}"
            })

    return findings


_PY_FN_RE = re.compile(r'^\s*(async\s+)?def\s+(\w+)\s*\(')
# Java: requires a real access/visibility modifier before the method name -- distinguishes a
# method signature from control-flow keywords (if/for/while/switch/catch) which share the same
# "keyword (...) {" shape but never carry public/private/protected. Misses package-private
# methods (no modifier at all, legal but uncommon in real Spring code, which is annotation- and
# modifier-heavy) -- a known, disclosed gap rather than widening the pattern and risking
# false-positive matches on control-flow blocks instead.
_JAVA_FN_RE = re.compile(r'^\s*(public|private|protected)\s+(static\s+)?(final\s+)?(synchronized\s+)?[\w<>\[\],.\s]+?\s+(\w+)\s*\([^)]*\)\s*(throws\s+[\w,.\s]+)?\s*\{?\s*$')
# TypeScript/JavaScript: three real method-defining shapes -- a `function` declaration, a class
# method with a TS return-type annotation (the ":" is what excludes if/for/while, which never
# have one), and an arrow function assigned to a name.
_TS_FN_RE = re.compile(
    r'^\s*(export\s+)?(default\s+)?(async\s+)?function\s+(\w+)\s*\('
    r'|^\s*(public|private|protected)?\s*(static\s+)?(async\s+)?(\w+)\s*\([^)]*\)\s*:\s*[\w<>\[\]|,.\s]+\s*\{'
    r'|^\s*(export\s+)?(const|let)\s+(\w+)\s*=\s*(async\s+)?\([^)]*\)\s*(:\s*[\w<>\[\]|,.\s]+)?\s*=>\s*\{'
)


def _extract_fn_name(line: str, lang: str) -> str:
    """Best-effort function/method name extraction for the finding description -- cosmetic only,
    never used for matching, so a slightly imprecise name on an unusual signature is harmless."""
    stripped = line.strip()
    if lang == "python":
        return stripped.split("(")[0].replace("async def ", "").replace("def ", "").strip()
    # Java/TS: the name is whatever word immediately precedes the first "(".
    before_paren = stripped.split("(")[0]
    tokens = before_paren.replace("=", " ").split()
    return tokens[-1] if tokens else "?"


def audit_iso_25010_quality(file_path: str, content: str) -> List[Dict[str, Any]]:
    """
    Audits code against ISO/IEC 25010 Quality Model (Maintainability & Clean Code).

    Extended 2026-08-22 for Java/TypeScript/JavaScript. Python's own boundary detection (function
    ends at the next "def"/"async def", since Python's indentation makes that reliable) doesn't
    generalize to brace languages, where nested functions/lambdas inside a method are routine --
    "until the next function signature" would silently merge a method with everything nested
    inside it. Java/TS instead track real brace depth: a method's body starts at its own opening
    "{" and ends when the depth returns to that same level, which is the actual, correct
    definition of "how long is this method" for these languages. This is still line-based (not a
    real parser) and can be thrown off by a brace inside a string/comment on the same line as a
    real code brace -- the same class of simplification every other regex-based rule in this file
    already accepts, not a new risk introduced here.
    """
    findings = []
    lines = content.splitlines()
    ext = os.path.splitext(file_path)[1]

    if ext == ".py":
        current_fn = None
        fn_start = 0
        fn_len = 0
        for idx, line in enumerate(lines, 1):
            if _PY_FN_RE.match(line):
                if current_fn and fn_len > 60:
                    findings.append({
                        "standard": "ISO25010-MAINTAINABILITY", "cve_id": "STD-ISO25010-LONG-METHOD",
                        "severity": "LOW", "file": file_path, "line": fn_start,
                        "description": f"ISO 25010 Maintainability Violation: Function '{current_fn}' exceeds 60 lines limit ({fn_len} lines). Extract methods to reduce cognitive complexity."
                    })
                current_fn = _extract_fn_name(line, "python")
                fn_start = idx
                fn_len = 0
            elif current_fn:
                fn_len += 1
        return findings

    # Java/TS/JS: brace-depth-based boundary.
    fn_re = _JAVA_FN_RE if ext == ".java" else (_TS_FN_RE if ext in (".ts", ".tsx", ".js", ".jsx") else None)
    if fn_re is None:
        return findings

    idx = 0
    n = len(lines)
    while idx < n:
        line = lines[idx]
        m = fn_re.match(line)
        if not m:
            idx += 1
            continue
        fn_name = _extract_fn_name(line, "java" if ext == ".java" else "ts")
        fn_start = idx + 1  # 1-indexed for the finding
        # Find the opening brace (same line, or scan forward a few lines for a signature that
        # wraps onto its own "{" line -- common with long parameter lists/throws clauses).
        scan = idx
        depth = 0
        opened = False
        while scan < n and scan < idx + 5:
            depth += lines[scan].count("{") - lines[scan].count("}")
            if depth > 0:
                opened = True
                break
            scan += 1
        if not opened:
            idx += 1
            continue
        body_start = scan
        body_lines = 0
        while scan < n:
            depth += lines[scan].count("{") - lines[scan].count("}") if scan != body_start else 0
            if scan != body_start:
                body_lines += 1
            if depth <= 0 and scan != body_start:
                break
            scan += 1
        if body_lines > 60:
            findings.append({
                "standard": "ISO25010-MAINTAINABILITY", "cve_id": "STD-ISO25010-LONG-METHOD",
                "severity": "LOW", "file": file_path, "line": fn_start,
                "description": f"ISO 25010 Maintainability Violation: Function '{fn_name}' exceeds 60 lines limit ({body_lines} lines). Extract methods to reduce cognitive complexity."
            })
        idx = scan + 1

    return findings


def run_compliance_standards_audit(target_dir: str = "/app", asset_id: int = None) -> List[Dict[str, Any]]:
    """Runs full Master Audit Standards compliance check across target codebase."""
    all_findings = []

    for root, _, files in os.walk(target_dir):
        # "tests" excluded too -- see the identical exclusion (and its reasoning) in
        # auditor_master_vulnerabilities.py's run_master_vulnerability_scan().
        if any(ignored in root for ignored in [".git", "node_modules", "__pycache__", ".venv", "/tests", "\\tests", "data/remediation", "data/sonar_scans", ".mvn"]):
            continue
        for file in files:
            full_path = os.path.join(root, file)
            if file.endswith((".py", ".js", ".jsx", ".ts", ".tsx", ".java")):
                try:
                    with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()

                    all_findings.extend(audit_stride_threat_matrix(full_path, content))
                    all_findings.extend(audit_iso_25010_quality(full_path, content))
                except Exception as e:
                    print(f"⚠️ [Standards-Auditor] Error reading {full_path}: {e}")

    # Persist findings to database. Same fixes as the other two native engines: file location
    # stored in url_path, and deduplication_engine.log_finding_deduplicated() replaces the old
    # no-op "ON CONFLICT DO NOTHING" -- also merges cross-tool duplicates instead of creating a
    # second ticket for the same real finding reported by a different engine.
    try:
        from core import deduplication_engine
        active_fingerprints = set()
        with db_manager.get_db_cursor() as cur:
            for item in all_findings:
                rel_path = os.path.relpath(item["file"], target_dir) if item.get("file") else "unknown"
                location = f"{rel_path}:{item.get('line', 0)}"
                description = f"**Archivo:** `{rel_path}` (Línea {item.get('line', 0)})\n{item['description']}"

                active_fingerprints.add(deduplication_engine.calculate_fingerprint(asset_id, item["cve_id"], location))
                deduplication_engine.log_finding_deduplicated(
                    cur, asset_id, item["cve_id"], item["severity"], description,
                    "standards-audit", url_path=location, open_status="OPEN", preserve_status=True
                )

            if asset_id is not None:
                resolved_count = deduplication_engine.reconcile_resolved_findings(cur, asset_id, "standards-audit", active_fingerprints)
                if resolved_count:
                    print(f"✅ [Standards-Auditor] Reconciled {resolved_count} stale standards-audit finding(s) as RESOLVED for asset {asset_id}.")
    except Exception as db_err:
        print(f"⚠️ [Standards-Auditor] Could not log findings to DB: {db_err}")

    return all_findings
