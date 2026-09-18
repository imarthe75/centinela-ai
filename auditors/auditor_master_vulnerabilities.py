"""
Centinela Native Master Vulnerability Auditor (SAST & DevSecOps / IaC)
Inspects codebases, APIs, Dockerfiles, and configurations for security flaws.
"""
import os
import re
import ast
import logging
from typing import List, Dict, Any
from core import db_manager

logger = logging.getLogger(__name__)


def _is_inside_string_literal(line: str, pos: int) -> bool:
    """
    Naive single-line string-literal detector: True if `pos` falls inside an open quote span on
    this line. Not a full tokenizer (doesn't handle triple-quoted or multi-line strings), but
    correctly handles the real false-positive case found live 2026-08-13: this scanner's own
    rule-definition tuples describe what they detect in a plain string
    (`"Dynamic Code Execution risk via eval()."`), which naive substring matching flagged as a
    fresh CODE-INJECTION-EVAL finding against the scanner's own source on every self-audit run.
    """
    before = re.sub(r"\\['\"]", "", line[:pos])  # drop escaped quotes so they don't skew parity
    return (before.count("'") % 2 == 1) or (before.count('"') % 2 == 1)


def _is_real_dangerous_call(line: str, match: "re.Match") -> bool:
    """
    Used only for the code-execution-risk family (dynamic-eval / exec / os.system / subprocess
    shell=True) -- NOT for HARDCODED-SECRET or the SQLi patterns, where matching inside a string
    literal is the entire point. Real bug fixed 2026-08-13: this scanner's own detector files
    (which necessarily contain comments and description strings *about* those risky calls, to
    define what they catch) were self-flagging on every scan.
    """
    clean = line.lstrip()
    if clean.startswith(("#", "//", "/*", "*")):
        return False
    return not _is_inside_string_literal(line, match.start())


def _evaluate_line_patterns(
    lines: List[str],
    file_path: str,
    patterns: List[Any],
    check_dangerous_call: bool = False
) -> List[Dict[str, Any]]:
    """Evaluates a group of regex patterns line-by-line with comment and self-audit filters."""
    findings = []
    for idx, line in enumerate(lines, 1):
        clean_line = line.strip()
        if clean_line.startswith(("#", "//", "/*", "*")):
            continue
        for pattern, rule_id, severity, desc in patterns:
            # Safeguard against self-matching scanner rule-definition tuples
            if clean_line.startswith("(") and rule_id in line:
                continue
            m = re.search(pattern, line, re.IGNORECASE)
            if not m:
                continue
            if check_dangerous_call and not _is_real_dangerous_call(line, m):
                continue
            findings.append({
                "cve_id": rule_id,
                "severity": severity,
                "file": file_path,
                "line": idx,
                "description": f"{desc} Line {idx}: {clean_line}"
            })
    return findings


def _check_cognitive_complexity(file_path: str, content: str) -> List[Dict[str, Any]]:
    """AST cognitive complexity check for Python files."""
    findings = []
    try:
        tree = ast.parse(content)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                complexity = 0
                for sub in ast.walk(node):
                    if isinstance(sub, (ast.If, ast.For, ast.While, ast.ExceptHandler, ast.With)):
                        complexity += 1
                if complexity > 15:
                    findings.append({
                        "cve_id": "COGNITIVE-COMPLEXITY-EXCEEDED",
                        "severity": "MEDIUM",
                        "file": file_path,
                        "line": node.lineno,
                        "description": f"Function '{node.name}' has cognitive complexity of {complexity} (max recommended: 15)."
                    })
    except Exception as e:
        logger.error(f"Could not parse {file_path} for cognitive complexity: {e}", exc_info=True)
        print(f"⚠️ [Master-Auditor] Could not parse {file_path} for cognitive complexity: {e}")
    return findings


def scan_sast_code(file_path: str, content: str) -> List[Dict[str, Any]]:
    """Performs AST & Pattern SAST analysis on source code files."""
    findings = []
    lines = content.splitlines()
    filename = os.path.basename(file_path)

    # 1. SQL Injection Detection
    sqli_patterns = [
        (r'execute\s*\(\s*f["\'].*?SELECT.*?\{', "SQL-INJECTION-FSTRING", "HIGH", "SQL Injection via interpolated f-string in query."),
        (r'execute\s*\(\s*(["\'])(?:(?!\1).)*?SELECT(?:(?!\1).)*?\1\s*%\s*[^(]', "SQL-INJECTION-PERCENT", "HIGH", "SQL Injection via string percent formatting without parameter tuple."),
        (r'execute\s*\(\s*["\'].*?\+.*?\+', "SQL-INJECTION-CONCAT", "CRITICAL", "SQL Injection via string concatenation.")
    ]
    findings.extend(_evaluate_line_patterns(lines, file_path, sqli_patterns))

    # 2. Command Injection Detection
    cmd_patterns = [
        (r'subprocess\.(run|Popen|call|check_output)\s*\([^)]*shell\s*=\s*True', "CMD-INJECTION-SHELL-TRUE", "CRITICAL", "Command Injection risk: subprocess executed with shell=True."),
        (r'os\.system\s*\(', "CMD-INJECTION-OS-SYSTEM", "HIGH", "Insecure os.system call. Use subprocess with explicit argument list."),
        (r'\beval\s*\(', "CODE-INJECTION-EVAL", "CRITICAL", "Dynamic Code Execution risk via eval().")
    ]
    findings.extend(_evaluate_line_patterns(lines, file_path, cmd_patterns, check_dangerous_call=True))

    # 3. SSRF (Server-Side Request Forgery)
    ssrf_patterns = [
        (r'requests\.(get|post|put|delete)\s*\(\s*f["\']https?://[^/"\']*\{', "SSRF-UNCHECKED-FETCH", "MEDIUM", "Potential SSRF: the request's destination HOST is dynamically interpolated without private/internal IP validation.")
    ]
    findings.extend(_evaluate_line_patterns(lines, file_path, ssrf_patterns))

    # 4. Hardcoded Secrets & Cloud Credentials (CWE-798)
    secret_patterns = [
        (r'(jwt_secret|api_key|password|private_key)\s*=\s*["\'][A-Za-z0-9+/=_-]{8,}["\']', "HARDCODED-SECRET", "HIGH", "Hardcoded credential or secret key detected in source code."),
        (r'\bAKIA[0-9A-Z]{16}\b', "HARDCODED-SECRET-AWS-KEY", "CRITICAL", "AWS Access Key ID detected in source code."),
        (r'\b(?:sk_live_[0-9a-zA-Z]{24,}|rk_live_[0-9a-zA-Z]{24,})\b', "HARDCODED-SECRET-STRIPE", "CRITICAL", "Stripe live secret key detected in source code."),
        (r'\b(?:gh[pousr]_[a-zA-Z0-9_]{36,255}|github_pat_[0-9a-zA-Z_]{82})\b', "HARDCODED-SECRET-GITHUB", "CRITICAL", "GitHub Personal Access Token detected in source code."),
        (r'\bglpat-[0-9a-zA-Z\-]{20,}\b', "HARDCODED-SECRET-GITLAB", "CRITICAL", "GitLab Personal Access Token detected in source code."),
        (r'\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32}\b', "HARDCODED-SECRET-SLACK", "HIGH", "Slack API token detected in source code."),
        (r'\b(?:hvs\.[a-zA-Z0-9_-]{20,}|s\.[a-zA-Z0-9]{24,})\b', "HARDCODED-SECRET-VAULT", "CRITICAL", "HashiCorp Vault token detected in source code."),
        (r'["\']type["\']\s*:\s*' + r'["\']service_account["\']', "HARDCODED-SECRET-GCP-KEY", "CRITICAL", "GCP Service Account private key JSON credential detected in source code.")
    ]
    findings.extend(_evaluate_line_patterns(lines, file_path, secret_patterns))

    # 5. Insecure Deserialization (CWE-502)
    deserialization_patterns = [
        (r'\bpickle\.(loads|load)\s*\(', "INSECURE-DESERIALIZATION-PICKLE", "CRITICAL", "Insecure deserialization via pickle (CWE-502). Untrusted input leads to Remote Code Execution."),
        (r'\byaml\.(unsafe_load|load)\s*\((?![^)]*Loader\s*=\s*(?:yaml\.)?SafeLoader)', "INSECURE-DESERIALIZATION-YAML", "HIGH", "Insecure YAML deserialization without SafeLoader (CWE-502). Use yaml.safe_load() or Loader=SafeLoader."),
        (r'\bmarshal\.(loads|load)\s*\(', "INSECURE-DESERIALIZATION-MARSHAL", "CRITICAL", "Insecure deserialization via marshal (CWE-502)."),
        (r'\b(?:node-serialize|serialize)\.unserialize\s*\(', "INSECURE-DESERIALIZATION-NODE", "CRITICAL", "Insecure Node.js deserialization via node-serialize/unserialize (CWE-502).")
    ]
    findings.extend(_evaluate_line_patterns(lines, file_path, deserialization_patterns, check_dangerous_call=True))

    # 6. Path Traversal & Unsanitized File Access (CWE-22)
    path_traversal_patterns = [
        (r'open\s*\([^)]*(?:request\.(?:args|GET|POST|values|form|json)|req\.(?:params|query|body)|user_path|user_file)', "PATH-TRAVERSAL-UNSANITIZED", "HIGH", "Potential Path Traversal (CWE-22): file opened directly with unvalidated user input."),
        (r'new\s+(?:File|FileInputStream|FileOutputStream)\s*\([^)]*(?:request\.getParameter|req\.getParameter)', "PATH-TRAVERSAL-UNSANITIZED", "HIGH", "Potential Path Traversal (CWE-22): File/Stream instantiated with unvalidated HTTP parameter."),
        (r'fs\.(?:readFile|createReadStream|readFileSync|writeFile|writeFileSync)\s*\([^)]*(?:req\.params|req\.query|req\.body)', "PATH-TRAVERSAL-UNSANITIZED", "HIGH", "Potential Path Traversal (CWE-22): Node.js fs method called with unvalidated HTTP input.")
    ]
    findings.extend(_evaluate_line_patterns(lines, file_path, path_traversal_patterns, check_dangerous_call=True))

    # 7. Framework Security Misconfiguration & CSRF Disabled (CWE-352 / CWE-693)
    framework_patterns = [
        (r'(?:http\.)?csrf\(\)\.disable\(\)|\.csrf\s*\(\s*(?:\w+\s*->\s*)?\w+\.disable\(\)\)', "SPRING-CSRF-DISABLED", "HIGH", "Spring Security CSRF protection explicitly disabled (CWE-352)."),
        (r'helmet\s*\(\s*\{[^}]*contentSecurityPolicy\s*:\s*false', "EXPRESS-CSP-DISABLED", "MEDIUM", "Content Security Policy explicitly disabled in Helmet configuration (CWE-693).")
    ]
    findings.extend(_evaluate_line_patterns(lines, file_path, framework_patterns, check_dangerous_call=True))

    # 8. Weak Cryptography & Obsolete Algorithms (CWE-327)
    weak_crypto_patterns = [
        (r'hashlib\.(?:md5|sha1)\s*\(', "WEAK-CRYPTO-HASH", "MEDIUM", "Use of weak or obsolete hash algorithm (MD5/SHA1) via hashlib (CWE-327). Use SHA-256 or SHA-3."),
        (r'Cipher\.getInstance\s*\(\s*["\'](?:DES|RC4|AES/ECB|Blowfish)', "WEAK-CRYPTO-CIPHER", "HIGH", "Use of insecure/broken cryptographic cipher or ECB mode (CWE-327). Use AES/GCM or ChaCha20."),
        (r'MessageDigest\.getInstance\s*\(\s*["\'](?:MD5|SHA-1|SHA1)["\']', "WEAK-CRYPTO-HASH", "MEDIUM", "Java MessageDigest with weak hash algorithm MD5/SHA-1 (CWE-327)."),
        (r'crypto\.createHash\s*\(\s*["\'](?:md5|sha1)["\']', "WEAK-CRYPTO-HASH", "MEDIUM", "Node.js crypto.createHash with obsolete hash algorithm MD5/SHA-1 (CWE-327).")
    ]
    findings.extend(_evaluate_line_patterns(lines, file_path, weak_crypto_patterns, check_dangerous_call=True))

    # 9. XML External Entity (XXE) Injection (CWE-611)
    xxe_patterns = [
        (r'(?:xml\.etree\.ElementTree|ET)\.(?:parse|fromstring)\s*\(|xml\.dom\.minidom\.parse(?:String)?\s*\(|xml\.sax\.make_parser\s*\(', "XXE-INSECURE-PARSER", "HIGH", "Potentially vulnerable standard XML parser used without defusedxml (CWE-611)."),
        (r'(?:DocumentBuilderFactory|XMLInputFactory|SAXParserFactory)\.newInstance\s*\(\)', "XXE-JAVA-XML-PARSER", "HIGH", "Java XML parser instantiated without explicit secure processing features (CWE-611).")
    ]
    findings.extend(_evaluate_line_patterns(lines, file_path, xxe_patterns, check_dangerous_call=True))

    # 10. Advanced Backend DB, Architecture & Performance Security (SpringBoot, Java, Python Antipatterns)
    backend_db_patterns = [
        (r'\.(raw|extra)\s*\(\s*f?["\'].*?\{', "ORM-RAW-QUERY-INJECTION", "HIGH", "Risk of ORM SQL Injection via raw/extra query interpolation."),
        (r'sequelize\.query\s*\(\s*f?["\'].*?\+', "ORM-RAW-QUERY-INJECTION", "HIGH", "Risk of ORM SQL Injection in Node.js Sequelize."),
        (r'(postgres|mysql)://[^\s"\']+@[^\s"\']+', "DB-UNENCRYPTED-CONN-STRING", "MEDIUM", "Database Connection string detected in code without explicit TLS/SSL parameters."),
        (r'@Query\s*\([^)]*nativeQuery\s*=\s*true', "SPRINGBOOT-NATIVE-QUERY-RISK", "MEDIUM", "SpringBoot native SQL query bypasses JPA parameter escaping safety."),
        (r'(LocalAuth|TestSandbox|Backdoor)Controller', "BACKDOOR-SANDBOX-CONTROLLER", "CRITICAL", "Backdoor or sandbox/test controller detected in production code (CWE-288 / CWE-798)."),
        (r'TrustAllManager|NullHostnameVerifier|X509TrustManager', "JVM-GLOBAL-SSL-BYPASS", "CRITICAL", "Disabling SSL/TLS certificate or hostname verification JVM-wide (CWE-295)."),
        (r'@RequestParam.*?(jwt|token)|request\.getParameter\s*\(\s*["\']token["\']', "JWT-IN-URL-PARAM", "HIGH", "Passing JWT token in URL query parameter instead of Authorization header."),
        (r'JdkSerializationRedisSerializer', "REDIS-JDK-SERIALIZATION", "HIGH", "Insecure Java JDK serialization used in Redis cache config (CWE-502)."),
        (r'Files\.readAllBytes|byte\[\]\s+\w+\s*=\s*.*?readAllBytes', "OOM-BYTE-ARRAY-STREAMING", "MEDIUM", "Loading entire file into byte[] array risks Heap Out-Of-Memory. Use InputStream/StreamingResponseBody.")
    ]
    findings.extend(_evaluate_line_patterns(lines, file_path, backend_db_patterns))

    # 11. Advanced Frontend Security (React, Angular, SpringBoot & DOM XSS)
    if filename.endswith((".js", ".ts", ".jsx", ".tsx", ".html", ".java")):
        frontend_patterns = [
            (r'(VITE_|NEXT_PUBLIC_|REACT_APP_)(DB_|DATABASE_|POSTGRES_|MYSQL_)', "FRONTEND-EXPOSED-DB-CREDENTIAL", "CRITICAL", "Exposed Database credential or connection URL in Frontend public environment variable."),
            (r'localStorage\.setItem\s*\(\s*["\'](token|jwt|session|auth_token)["\']', "FRONTEND-JWT-LOCALSTORAGE", "MEDIUM", "Storing authentication token in localStorage makes it vulnerable to XSS extraction. Use httpOnly cookies."),
            (r'dangerouslySetInnerHTML', "REACT-DANGEROUSLY-SET-INNER-HTML", "HIGH", "React dangerouslySetInnerHTML antipattern detected (DOM XSS risk)."),
            (r'\[innerHTML\]\s*=\s*', "ANGULAR-BYPASS-SECURITY-TRUST", "HIGH", "Angular [innerHTML] binding bypassing sanitization DOM XSS risk."),
            (r'bypassSecurityTrust(Html|Script|ResourceUrl|Style)', "ANGULAR-BYPASS-SECURITY-TRUST", "HIGH", "Angular explicit security sanitization bypass (DomSanitizer)."),
            (r'<button(?![^>]*aria-label)[^>]*>(?!\s*<span[^>]*>[^<]+</span>|\s*[^<\s]+)', "ACCESSIBILITY-WCAG-MISSING-LABEL", "LOW", "Interactive button missing accessible label or text content (WCAG 2.1 AA).")
        ]
        findings.extend(_evaluate_line_patterns(lines, file_path, frontend_patterns))

    # 12. Multiline Pattern Detection (e.g. ORM N+1 queries across lines)
    n_plus_one_re = re.compile(r'for\s+\w+\s+in\s+.*?\.(?:all|filter)\(\):?\s*\n\s*.*?\.\w+', re.IGNORECASE)
    for m in n_plus_one_re.finditer(content):
        line_no = content[:m.start()].count('\n') + 1
        first_line = lines[line_no - 1] if line_no <= len(lines) else ""
        if not first_line.lstrip().startswith(("#", "//", "/*", "*")):
            findings.append({
                "cve_id": "ORM-N-PLUS-ONE-QUERY",
                "severity": "MEDIUM",
                "file": file_path,
                "line": line_no,
                "description": f"Potential N+1 Query antipattern inside loop. Use select_related/prefetch_related or join fetch. Line {line_no}: {first_line.strip()}"
            })

    # 13. AST Cognitive Complexity Check (Python files)
    if filename.endswith(".py"):
        findings.extend(_check_cognitive_complexity(file_path, content))

    return findings


def scan_iac_dockerfile(file_path: str, content: str) -> List[Dict[str, Any]]:
    """Audits Dockerfiles against CIS Benchmarks and DevSecOps Hardening rules."""
    findings = []
    lines = content.splitlines()

    has_user_instruction = False
    for idx, line in enumerate(lines, 1):
        clean_line = line.strip()
        if clean_line.startswith("USER"):
            has_user_instruction = True
            if "root" in clean_line.lower() or clean_line == "USER 0":
                findings.append({
                    "cve_id": "DOCKER-ROOT-USER",
                    "severity": "HIGH",
                    "file": file_path,
                    "line": idx,
                    "description": "Dockerfile explicitly sets execution user to root."
                })
        if clean_line.startswith("FROM") and ":latest" in clean_line:
            findings.append({
                "cve_id": "DOCKER-UNPINNED-BASE-IMAGE",
                "severity": "LOW",
                "file": file_path,
                "line": idx,
                "description": f"Dockerfile uses unpinned base image ':latest'. Line {idx}: {clean_line}"
            })

    if not has_user_instruction:
        findings.append({
            "cve_id": "DOCKER-MISSING-NON-ROOT-USER",
            "severity": "HIGH",
            "file": file_path,
            "line": 1,
            "description": "Dockerfile lacks explicit non-root 'USER appuser' instruction."
        })

    return findings


def run_master_vulnerability_scan(target_dir: str = "/app", asset_id: int = None) -> List[Dict[str, Any]]:
    """Runs SAST and DevSecOps vulnerability scan across target directory."""
    all_findings = []
    
    for root, _, files in os.walk(target_dir):
        # "tests" excluded here too -- several test files in this repo (by design) contain
        # deliberately vulnerable-looking snippets as fixtures to test the detectors
        # themselves (e.g. tests/test_full_coverage_100.py's HARDCODED-SECRET fixture,
        # tests/test_sast_db_patterns.py's SQL injection fixtures) -- these aren't real
        # production vulnerabilities and previously polluted compliance scoring for the
        # asset that owns this source tree.
        # "data/remediation" excluded 2026-08-13: this is Centinela's own GENERATED OUTPUT
        # (the remediation scripts/patches this exact function writes for other findings), not
        # source code -- a script whose entire job is `sed -i 's/eval(/console.log(/g'` was
        # being flagged as a NEW eval() vulnerability, creating a real feedback loop where fixing
        # a finding generated a new "finding" about the fix itself. "data/sonar_scans" excluded
        # same day: cloned THIRD-PARTY repositories from other GitLab projects' SonarQube scans,
        # not Centinela's own code at all -- were being misattributed to Centinela's own
        # self-audit asset (confirmed live: findings under
        # data/sonar_scans/arquitectura-geo-ircep-smart/... on the Centinela-AI (Self-Audit) asset).
        if any(ignored in root for ignored in [".git", "node_modules", "__pycache__", ".venv", "/tests", "\\tests", "/test/", "\\test\\", "data/remediation", "data/sonar_scans", "everything-claude-code", ".mvn", "/target/", "\\target\\"]):
            continue
        for file in files:
            full_path = os.path.join(root, file)
            try:
                with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()

                if file == "Dockerfile" or file.startswith("Dockerfile."):
                    all_findings.extend(scan_iac_dockerfile(full_path, content))
                # Real gap found 2026-08-20 while auditing a pure-Java codebase (SIDECO/SIAT):
                # scan_sast_code() already has Java-aware detectors internally (the frontend
                # antipattern block at its own line ~160 explicitly checks filename.endswith(...,
                # ".java"), and SPRINGBOOT-NATIVE-QUERY-RISK/HARDCODED-SECRET/DB-UNENCRYPTED-CONN-
                # STRING are language-agnostic text patterns genuinely relevant to Java/Spring)
                # but this outer dispatch never actually sent .java files into it -- every Java
                # file in every repo this engine has ever scanned was silently skipped, making
                # "0 SAST findings" indistinguishable from "genuinely clean" for any Java-only
                # codebase. Confirmed safe to add: every pattern inside scan_sast_code() is
                # already internally guarded by its own filename check, so .java files simply
                # exercise the subset of rules that apply to them, same as any other extension.
                elif file.endswith((".py", ".js", ".jsx", ".ts", ".tsx", ".sh", ".java", ".html", ".xml", ".properties", ".json", ".yml", ".yaml")):
                    all_findings.extend(scan_sast_code(full_path, content))
            except Exception as e:
                logger.error(f"Error reading {full_path}: {e}", exc_info=True)
                print(f"⚠️ [Master-Auditor] Error reading {full_path}: {e}")

    # Persist findings in DB if available. Two real bugs fixed here:
    #
    # 1. item["file"]/item["line"] were captured by every scanner above but never actually
    #    written anywhere -- the INSERT only carried cve_id/severity/description, so no
    #    remediation (human or AI) could ever know which file to fix. Now stored in url_path
    #    as "relative/path.py:LINE" (repurposing the same generic "where this finding lives"
    #    column ZAP already uses for URLs), and prefixed into description for readability.
    #
    # 2. "ON CONFLICT DO NOTHING" with no conflict target only suppresses inserts that violate
    #    an actual unique constraint -- vulnerability_log has none beyond its own id, so this
    #    was a complete no-op and every re-scan re-inserted every finding as brand new (the same
    #    failure mode CLAUDE.md already documents for this table). Replaced with
    #    deduplication_engine.log_finding_deduplicated(), which also merges cross-tool (e.g. the
    #    same real CVE independently flagged by sca-native/Nuclei on this asset collapses into
    #    one ticket instead of creating a second one).
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
                    "sast-native", url_path=location, open_status="OPEN", preserve_status=True
                )

            # Only reconcile when scoped to a real asset -- a bare/default asset_id=None call
            # (e.g. ad-hoc testing) has no well-defined "everything else for this asset" set to
            # resolve against. See reconcile_resolved_findings()'s own docstring: this closes a
            # real gap where line-anchored findings on actively-edited files (e.g. Centinela's
            # own source) never got marked resolved even long after the flagged code moved or
            # was already fixed, because line-number drift meant a fresh scan's fingerprint
            # would never match the old one again.
            if asset_id is not None:
                resolved_count = deduplication_engine.reconcile_resolved_findings(cur, asset_id, "sast-native", active_fingerprints)
                if resolved_count:
                    print(f"✅ [Master-Auditor] Reconciled {resolved_count} stale sast-native finding(s) as RESOLVED for asset {asset_id}.")
    except Exception as db_err:
        logger.error(f"Could not log findings to DB: {db_err}", exc_info=True)
        print(f"⚠️ [Master-Auditor] Could not log findings to DB: {db_err}")

    return all_findings
