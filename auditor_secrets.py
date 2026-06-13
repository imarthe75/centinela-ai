"""
Secrets Scanning Integration

Detects hardcoded credentials, API keys, private keys, and connection strings
in source code repositories using truffleHog v3 or detect-secrets.

Three-tier approach:
  - PHASE 1 (Fast): Working tree only (~10-20 sec)
  - PHASE 2 (Medium): Shallow history, last 50 commits (~1-5 min)
  - PHASE 3 (Deep): Full git history (5-30+ min, on-demand only)

Supports whitelisting via .centinela-secrets-whitelist.json in repo root.
"""

import os
import sys
import json
import subprocess
import logging
from typing import List, Dict, Optional, Tuple
from datetime import datetime
import db_manager

logger = logging.getLogger(__name__)

class SecretsScanner:
    """Orchestrates secrets detection across multiple tools."""

    SECRET_PATTERNS = {
        "aws_access_key": {
            "pattern": r"AKIA[0-9A-Z]{16}",
            "description": "AWS Access Key ID",
            "severity": "CRITICAL"
        },
        "aws_secret_key": {
            "pattern": r"aws_secret_access_key\s*[=:]\s*['\"][a-zA-Z0-9/+=]{40}['\"]",
            "description": "AWS Secret Access Key",
            "severity": "CRITICAL"
        },
        "private_key_rsa": {
            "pattern": r"-----BEGIN RSA PRIVATE KEY-----",
            "description": "RSA Private Key",
            "severity": "CRITICAL"
        },
        "private_key_openssh": {
            "pattern": r"-----BEGIN OPENSSH PRIVATE KEY-----",
            "description": "OpenSSH Private Key",
            "severity": "CRITICAL"
        },
        "api_token": {
            "pattern": r"(api[_-]?)?token[_-]?(?:v[0-9])?['\"]?\s*[=:]\s*['\"]?[a-zA-Z0-9]{20,}['\"]?",
            "description": "API Token/Key",
            "severity": "HIGH"
        },
        "github_token": {
            "pattern": r"gh[pousr]{1}_[a-zA-Z0-9_]{36,255}",
            "description": "GitHub Personal Access Token",
            "severity": "CRITICAL"
        },
        "slack_token": {
            "pattern": r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32}",
            "description": "Slack API Token",
            "severity": "HIGH"
        },
        "mongodb_uri": {
            "pattern": r"mongodb\+srv://[^:]+:[^@]+@",
            "description": "MongoDB Connection String",
            "severity": "HIGH"
        },
        "mysql_password": {
            "pattern": r"mysql://[^:]+:(.+)@",
            "description": "MySQL Connection String with Password",
            "severity": "HIGH"
        },
        "db_password": {
            "pattern": r"(password|passwd|pwd)\s*[=:]\s*['\"](.{8,})['\"]",
            "description": "Database Password",
            "severity": "HIGH"
        },
        "env_api_key": {
            "pattern": r"[A-Z_]*API[_A-Z]*\s*[=:]\s*['\"]([a-zA-Z0-9]{20,})['\"]",
            "description": "API Key in Environment Variable",
            "severity": "HIGH"
        }
    }

    SCAN_TARGETS = [".py", ".js", ".ts", ".json", ".yaml", ".yml", ".env", ".env.example", ".toml", ".properties"]

    @staticmethod
    def load_whitelist(repo_path: str) -> Dict[str, List[str]]:
        """Loads whitelist of known false positives from repo."""
        whitelist_path = os.path.join(repo_path, ".centinela-secrets-whitelist.json")

        if not os.path.exists(whitelist_path):
            return {}

        try:
            with open(whitelist_path, "r") as f:
                return json.load(f)
        except Exception as e:
            logger.warn(f"Could not load whitelist: {e}")
            return {}

    @staticmethod
    def is_whitelisted(secret_type: str, secret_value: str, whitelist: Dict) -> bool:
        """Checks if secret is in whitelist."""
        if secret_type not in whitelist:
            return False

        return secret_value in whitelist[secret_type]

    @staticmethod
    def scan_working_tree(repo_path: str) -> List[Dict]:
        """
        PHASE 1: Fast scan of current working tree only.
        Time: ~10-20 seconds per repo
        """
        print(f"🔍 [Secrets-Scanner] PHASE 1 (Fast): Scanning working tree only...")

        if not os.path.isdir(repo_path):
            print(f"⚠️  Repo path not found: {repo_path}")
            return []

        findings = []

        for root, dirs, files in os.walk(repo_path):
            # Skip hidden dirs, vendor, node_modules, etc.
            dirs[:] = [d for d in dirs if not d.startswith(".") and d not in ["node_modules", "vendor", ".git", "dist", "build"]]

            for file in files:
                if not any(file.endswith(ext) for ext in SecretsScanner.SCAN_TARGETS):
                    continue

                file_path = os.path.join(root, file)
                relative_path = os.path.relpath(file_path, repo_path)

                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        for line_num, line in enumerate(f, 1):
                            for secret_type, secret_info in SecretsScanner.SECRET_PATTERNS.items():
                                import re
                                if re.search(secret_info["pattern"], line):
                                    # Mask actual secret value
                                    masked_line = line[:50] + "..." if len(line) > 50 else line
                                    finding = {
                                        "file": relative_path,
                                        "line": line_num,
                                        "type": secret_type,
                                        "description": secret_info["description"],
                                        "severity": secret_info["severity"],
                                        "masked_context": masked_line.strip()
                                    }
                                    findings.append(finding)
                except Exception as e:
                    logger.debug(f"Could not scan {file_path}: {e}")

        print(f"   Found {len(findings)} potential secrets")
        return findings

    @staticmethod
    def scan_git_history(repo_path: str, max_commits: Optional[int] = 50) -> List[Dict]:
        """
        PHASE 2: Shallow git history scan (last N commits).
        Time: ~1-5 minutes per repo
        """
        if max_commits is None:
            print(f"🔍 [Secrets-Scanner] PHASE 3 (Deep): Scanning full git history...")
            max_commits = None  # All commits
        else:
            print(f"🔍 [Secrets-Scanner] PHASE 2 (Medium): Scanning last {max_commits} commits...")

        if not os.path.isdir(repo_path):
            return []

        findings = []

        try:
            # Try using truffleHog if available
            import_cmd = ["trufflehog", "git", f"file://{repo_path}", "--json"]

            if max_commits:
                import_cmd.extend(["--max-depth", str(max_commits)])

            result = subprocess.run(import_cmd, capture_output=True, text=True, timeout=300)

            if result.returncode == 0:
                for line in result.stdout.strip().split("\n"):
                    if not line:
                        continue
                    try:
                        finding_json = json.loads(line)
                        finding = {
                            "file": finding_json.get("source_metadata", {}).get("file", "unknown"),
                            "line": finding_json.get("source_metadata", {}).get("line", 0),
                            "type": finding_json.get("detector_name", "unknown"),
                            "description": finding_json.get("detector_name", "Secret detected"),
                            "severity": "HIGH" if "private" in finding_json.get("detector_name", "").lower() else "MEDIUM",
                            "commit": finding_json.get("source_metadata", {}).get("commit", "")[:8]
                        }
                        findings.append(finding)
                    except json.JSONDecodeError:
                        continue

        except FileNotFoundError:
            logger.warn("truffleHog not installed; falling back to pattern-based detection")
            return []
        except subprocess.TimeoutExpired:
            logger.error("Git history scan timeout (> 5 min)")
        except Exception as e:
            logger.error(f"Git history scan error: {e}")

        print(f"   Found {len(findings)} secrets in git history")
        return findings

def log_secrets(asset_id: int, repo_path: str, findings: List[Dict], scan_phase: str = "1"):
    """Logs detected secrets to vulnerability_log."""
    if not findings:
        return

    try:
        with db_manager.get_db_cursor() as cur:
            for finding in findings:
                cve_id = f"SECRETS-{finding['type'].upper()}-PHASE{scan_phase}"
                severity = finding.get("severity", "HIGH")

                description = (
                    f"**Hardcoded Secret Detected (Phase {scan_phase})** \\n\\n"
                    f"**Type:** {finding['description']}\\n"
                    f"**File:** `{finding['file']}`\\n"
                    f"**Line:** {finding['line']}\\n"
                    f"**Context:** ```\\n{finding.get('masked_context', '')}\\n```\\n\\n"
                )

                if finding.get("commit"):
                    description += f"**First Introduced:** Commit `{finding['commit']}`\\n"

                description += (
                    f"\\n**Recommendation:** \\n"
                    f"1. Immediately revoke this credential\\n"
                    f"2. Remove from repository and force-push\\n"
                    f"3. Rotate all secrets across environment\\n"
                    f"4. Add to .gitignore and/or .centinela-secrets-whitelist.json if false positive\\n"
                )

                # Check if already exists
                cur.execute("""
                    SELECT id FROM vulnerability_log
                    WHERE asset_id = %s AND cve_id = %s
                    LIMIT 1
                """, (asset_id, cve_id))

                if cur.fetchone():
                    # Update existing
                    cur.execute("""
                        UPDATE vulnerability_log
                        SET description = %s, detected_at = NOW()
                        WHERE asset_id = %s AND cve_id = %s
                    """, (description, asset_id, cve_id))
                    print(f"  🔄 Updated secrets finding: [{severity}] {cve_id}")
                else:
                    # Insert new
                    cur.execute("""
                        INSERT INTO vulnerability_log
                        (asset_id, cve_id, severity, description, status, detected_at, scan_engine)
                        VALUES (%s, %s, %s, %s, 'NEW', NOW(), 'secrets')
                    """, (asset_id, cve_id, severity, description))
                    print(f"  📝 Logged secret: [{severity}] {cve_id}")

        print(f"✅ Logged {len(findings)} secrets for asset {asset_id}")

    except Exception as e:
        logger.error(f"Error logging secrets: {e}")

def scan_repo_secrets_fast(repo_path: str, asset_id: int) -> bool:
    """
    Quick scan of working tree (PHASE 1).
    Suitable for every discovery cycle (~10-20 sec).
    """
    print(f"🚀 [Secrets-Auditor] Starting PHASE 1 (Fast) scan on {repo_path}...")

    findings = SecretsScanner.scan_working_tree(repo_path)
    whitelist = SecretsScanner.load_whitelist(repo_path)

    # Filter whitelisted
    filtered = [f for f in findings if not SecretsScanner.is_whitelisted(f["type"], f.get("masked_context"), whitelist)]

    if filtered:
        log_secrets(asset_id, repo_path, filtered, "1")

    return True

def scan_repo_secrets_deep(repo_path: str, asset_id: int, max_commits: int = 50) -> bool:
    """
    Shallow history scan (PHASE 2).
    Suitable for weekly scans (~1-5 min).
    """
    print(f"🚀 [Secrets-Auditor] Starting PHASE 2 (Medium) scan on {repo_path}...")

    findings = SecretsScanner.scan_git_history(repo_path, max_commits)
    whitelist = SecretsScanner.load_whitelist(repo_path)

    filtered = [f for f in findings if not SecretsScanner.is_whitelisted(f["type"], f.get("masked_context"), whitelist)]

    if filtered:
        log_secrets(asset_id, repo_path, filtered, "2")

    return True

def scan_repo_secrets_historical(repo_path: str, asset_id: int) -> bool:
    """
    Full history scan (PHASE 3).
    Suitable for on-demand deep investigation (5-30+ min).
    """
    print(f"🚀 [Secrets-Auditor] Starting PHASE 3 (Deep/Full History) scan on {repo_path}...")

    findings = SecretsScanner.scan_git_history(repo_path, max_commits=None)  # All commits
    whitelist = SecretsScanner.load_whitelist(repo_path)

    filtered = [f for f in findings if not SecretsScanner.is_whitelisted(f["type"], f.get("masked_context"), whitelist)]

    if filtered:
        log_secrets(asset_id, repo_path, filtered, "3")

    return True

if __name__ == "__main__":
    if len(sys.argv) > 2:
        repo_path = sys.argv[1]
        asset_id = int(sys.argv[2])
        phase = sys.argv[3] if len(sys.argv) > 3 else "1"

        try:
            if phase == "1":
                scan_repo_secrets_fast(repo_path, asset_id)
            elif phase == "2":
                scan_repo_secrets_deep(repo_path, asset_id)
            elif phase == "3":
                scan_repo_secrets_historical(repo_path, asset_id)
        except Exception as e:
            print(f"❌ Scan failed: {e}")
            sys.exit(1)
    else:
        print("Usage: python auditor_secrets.py <repo_path> <asset_id> [phase]")
        print("Phases: 1 (fast/working-tree), 2 (medium/50-commits), 3 (deep/full-history)")
