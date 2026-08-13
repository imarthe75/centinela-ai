"""
Centinela Native Master Vulnerability Auditor (SAST & DevSecOps / IaC)
Inspects codebases, APIs, Dockerfiles, and configurations for security flaws.
"""
import os
import re
import ast
from typing import List, Dict, Any
from core import db_manager


def scan_sast_code(file_path: str, content: str) -> List[Dict[str, Any]]:
    """Performs AST & Pattern SAST analysis on source code files."""
    findings = []
    lines = content.splitlines()
    filename = os.path.basename(file_path)

    # 1. SQL Injection Detection
    sqli_patterns = [
        (r'execute\s*\(\s*f["\'].*?SELECT.*?\{', "SQL-INJECTION-FSTRING", "HIGH", "SQL Injection via interpolated f-string in query."),
        (r'execute\s*\(\s*["\'].*?SELECT.*?["\']\s*%\s*[^(]', "SQL-INJECTION-PERCENT", "HIGH", "SQL Injection via string percent formatting without parameter tuple."),
        (r'execute\s*\(\s*["\'].*?\+.*?\+', "SQL-INJECTION-CONCAT", "CRITICAL", "SQL Injection via string concatenation.")
    ]
    for idx, line in enumerate(lines, 1):
        for pattern, rule_id, severity, desc in sqli_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                findings.append({
                    "cve_id": rule_id,
                    "severity": severity,
                    "file": file_path,
                    "line": idx,
                    "description": f"{desc} Line {idx}: {line.strip()}"
                })

    # 2. Command Injection Detection
    cmd_patterns = [
        (r'subprocess\.(run|Popen|call|check_output)\s*\([^)]*shell\s*=\s*True', "CMD-INJECTION-SHELL-TRUE", "CRITICAL", "Command Injection risk: subprocess executed with shell=True."),
        (r'os\.system\s*\(', "CMD-INJECTION-OS-SYSTEM", "HIGH", "Insecure os.system call. Use subprocess with explicit argument list."),
        # \b is required: without it this matched "eval(" as a substring inside any longer
        # identifier ending in those letters (e.g. onErrorEval(err), retrieval(x)) -- confirmed
        # against real production data where 136 of 140 logged CODE-INJECTION-EVAL findings were
        # exactly this false positive, not an actual eval() call.
        (r'\beval\s*\(', "CODE-INJECTION-EVAL", "CRITICAL", "Dynamic Code Execution risk via eval().")
    ]
    for idx, line in enumerate(lines, 1):
        for pattern, rule_id, severity, desc in cmd_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                findings.append({
                    "cve_id": rule_id,
                    "severity": severity,
                    "file": file_path,
                    "line": idx,
                    "description": f"{desc} Line {idx}: {line.strip()}"
                })

    # 3. SSRF (Server-Side Request Forgery)
    ssrf_patterns = [
        (r'requests\.(get|post|put|delete)\s*\(\s*f["\']https?://', "SSRF-UNCHECKED-FETCH", "MEDIUM", "Potential SSRF via dynamic URL fetch without private IP validation.")
    ]
    for idx, line in enumerate(lines, 1):
        for pattern, rule_id, severity, desc in ssrf_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                findings.append({
                    "cve_id": rule_id,
                    "severity": severity,
                    "file": file_path,
                    "line": idx,
                    "description": f"{desc} Line {idx}: {line.strip()}"
                })

    # 4. Hardcoded Secrets & JWT Tokens
    secret_patterns = [
        (r'(jwt_secret|api_key|password|private_key)\s*=\s*["\'][A-Za-z0-9+/=_-]{8,}["\']', "HARDCODED-SECRET", "HIGH", "Hardcoded credential or secret key detected in source code.")
    ]
    for idx, line in enumerate(lines, 1):
        for pattern, rule_id, severity, desc in secret_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                findings.append({
                    "cve_id": rule_id,
                    "severity": severity,
                    "file": file_path,
                    "line": idx,
                    "description": f"{desc} Line {idx}: {line.strip()}"
                })

    # 5. Advanced Backend DB & Performance Security (SpringBoot, Python, ORM N+1 & Antipatterns)
    backend_db_patterns = [
        (r'\.(raw|extra)\s*\(\s*f?["\'].*?\{', "ORM-RAW-QUERY-INJECTION", "HIGH", "Risk of ORM SQL Injection via raw/extra query interpolation."),
        (r'sequelize\.query\s*\(\s*f?["\'].*?\+', "ORM-RAW-QUERY-INJECTION", "HIGH", "Risk of ORM SQL Injection in Node.js Sequelize."),
        (r'(postgres|mysql)://[^\s"\']+@[^\s"\']+', "DB-UNENCRYPTED-CONN-STRING", "MEDIUM", "Database Connection string detected in code without explicit TLS/SSL parameters."),
        # N+1 Query Antipatterns (Python Django/SQLAlchemy/SpringBoot)
        (r'for\s+\w+\s+in\s+.*?\.(all|filter)\(\):?\s*\n\s*.*?\.\w+', "ORM-N-PLUS-ONE-QUERY", "MEDIUM", "Potential N+1 Query antipattern inside loop. Use select_related/prefetch_related or join fetch."),
        (r'@Query\s*\([^)]*nativeQuery\s*=\s*true', "SPRINGBOOT-NATIVE-QUERY-RISK", "MEDIUM", "SpringBoot native SQL query bypasses JPA parameter escaping safety.")
    ]
    for idx, line in enumerate(lines, 1):
        for pattern, rule_id, severity, desc in backend_db_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                findings.append({
                    "cve_id": rule_id,
                    "severity": severity,
                    "file": file_path,
                    "line": idx,
                    "description": f"{desc} Line {idx}: {line.strip()}"
                })

    # 6. Advanced Frontend Security (React, Angular, SpringBoot & DOM XSS)
    if filename.endswith((".js", ".ts", ".jsx", ".tsx", ".html", ".java")):
        frontend_patterns = [
            (r'(VITE_|NEXT_PUBLIC_|REACT_APP_)(DB_|DATABASE_|POSTGRES_|MYSQL_)', "FRONTEND-EXPOSED-DB-CREDENTIAL", "CRITICAL", "Exposed Database credential or connection URL in Frontend public environment variable."),
            (r'localStorage\.setItem\s*\(\s*["\'](token|jwt|session|auth_token)["\']', "FRONTEND-JWT-LOCALSTORAGE", "MEDIUM", "Storing authentication token in localStorage makes it vulnerable to XSS extraction. Use httpOnly cookies."),
            # React & Angular Specific Security Antipatterns
            (r'dangerouslySetInnerHTML', "REACT-DANGEROUSLY-SET-INNER-HTML", "HIGH", "React dangerouslySetInnerHTML antipattern detected (DOM XSS risk)."),
            (r'\[innerHTML\]\s*=\s*', "ANGULAR-BYPASS-SECURITY-TRUST", "HIGH", "Angular [innerHTML] binding bypassing sanitization DOM XSS risk."),
            (r'bypassSecurityTrust(Html|Script|ResourceUrl)', "ANGULAR-BYPASS-SECURITY-TRUST", "HIGH", "Angular explicit security sanitization bypass (DomSanitizer).")
        ]
        for idx, line in enumerate(lines, 1):
            for pattern, rule_id, severity, desc in frontend_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append({
                        "cve_id": rule_id,
                        "severity": severity,
                        "file": file_path,
                        "line": idx,
                        "description": f"{desc} Line {idx}: {line.strip()}"
                    })

    # 5. AST Cognitive Complexity Check (Python files)
    if filename.endswith(".py"):
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
            print(f"⚠️ [Master-Auditor] Could not parse {file_path} for cognitive complexity: {e}")

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


def run_master_vulnerability_scan(target_dir: str = "/opt/centinela-ai", asset_id: int = None) -> List[Dict[str, Any]]:
    """Runs SAST and DevSecOps vulnerability scan across target directory."""
    all_findings = []
    
    for root, _, files in os.walk(target_dir):
        if any(ignored in root for ignored in [".git", "node_modules", "__pycache__", ".venv"]):
            continue
        for file in files:
            full_path = os.path.join(root, file)
            try:
                with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()

                if file == "Dockerfile" or file.startswith("Dockerfile."):
                    all_findings.extend(scan_iac_dockerfile(full_path, content))
                elif file.endswith((".py", ".js", ".jsx", ".ts", ".tsx", ".sh")):
                    all_findings.extend(scan_sast_code(full_path, content))
            except Exception as e:
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
        with db_manager.get_db_cursor() as cur:
            for item in all_findings:
                rel_path = os.path.relpath(item["file"], target_dir) if item.get("file") else "unknown"
                location = f"{rel_path}:{item.get('line', 0)}"
                description = f"**Archivo:** `{rel_path}` (Línea {item.get('line', 0)})\n{item['description']}"

                deduplication_engine.log_finding_deduplicated(
                    cur, asset_id, item["cve_id"], item["severity"], description,
                    "sast-native", url_path=location, open_status="OPEN", preserve_status=True
                )
    except Exception as db_err:
        print(f"⚠️ [Master-Auditor] Could not log findings to DB: {db_err}")

    return all_findings
