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
from core import db_manager

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

        # Live verification sends the candidate credential to its issuer (AWS, GitHub...) to learn whether it still works. That is an
        # outward-facing action on customer secrets, so it is opt-in: SECRETS_VERIFY_LIVE=1. Off -> --no-verification (nothing leaves the host).
        verify_live = os.getenv("SECRETS_VERIFY_LIVE", "0") == "1"
        cmd = ["trufflehog", "git", f"file://{repo_path}", "--json", "--no-update"]
        cmd.append(TRUFFLEHOG_RESULTS_VERIFY if verify_live else "--no-verification")
        if max_commits:
            cmd.extend(["--max-depth", str(max_commits)])

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            if result.returncode != 0:
                logger.error("trufflehog exited %s: %s", result.returncode, (result.stderr or "")[-500:])
            findings = parse_trufflehog_output(result.stdout, verify_live)
        except FileNotFoundError:
            logger.error("trufflehog not installed; git-history secret scan skipped", exc_info=True)
            return []
        except subprocess.TimeoutExpired:
            logger.error("Git history scan timeout (> 5 min)", exc_info=True)
        except Exception:
            logger.error("Git history scan error", exc_info=True)

        print(f"   Found {len(findings)} secrets in git history")
        return findings


# With live verification on, "unknown" (the issuer could not be asked: network error, rate limit) must be requested explicitly
# alongside verified/unverified. It was missing until 2026-11-06, so a possibly-live credential whose check errored was dropped.
TRUFFLEHOG_RESULTS_VERIFY = "--results=verified,unverified,unknown"

VERIFICATION_LABELS = {
    "verified": " (VERIFIED LIVE: credential still active)",
    "error": " (verificación en vivo fallida por error: podría seguir activa)",
    "unconfirmed": " (no confirmada en vivo: inválida o sin verificador para este tipo)",
    "not_run": "",
}


def verification_status(rec: Dict, verify_live: bool) -> str:
    """verified | error | unconfirmed (checked, not valid -- or no verifier exists) | not_run (live verification off)."""
    if not verify_live:
        return "not_run"
    if rec.get("Verified"):
        return "verified"
    if rec.get("VerificationError"):
        return "error"
    return "unconfirmed"


def parse_trufflehog_output(stdout: str, verify_live: bool = False) -> List[Dict]:
    """Parse `trufflehog --json` (v3.x) lines. The raw secret (`Raw`/`RawV2`/`SecretParts`) is NEVER copied into a finding: only the
    detector's own redacted preview is kept. `verified` is True/False when live verification ran, None when it did not (unknown, not "dead")."""
    findings: List[Dict] = []
    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if "DetectorName" not in rec:           # a log line, not a finding
            continue
        git = ((rec.get("SourceMetadata") or {}).get("Data") or {}).get("Git") or {}
        name = rec.get("DetectorName") or "unknown"
        status = verification_status(rec, verify_live)
        is_verified = status == "verified"
        base = "HIGH" if "private" in name.lower() else "MEDIUM"
        severity = "CRITICAL" if is_verified else ("HIGH" if status == "error" else base)
        findings.append({
            "file": git.get("file") or "unknown",
            "line": git.get("line") or 0,
            "type": name,
            "description": name + VERIFICATION_LABELS[status],
            "severity": severity,
            "commit": (git.get("commit") or "")[:8],
            "verified": is_verified if verify_live else None,
            "verification": status,
            "masked_context": (rec.get("Redacted") or "")[:40],
        })
    return findings

def log_secrets(asset_id: str, repo_path: str, findings: List[Dict], scan_phase: str = "1"):
    """Logs detected secrets to vulnerability_log."""
    if not findings:
        return

    try:
        from core import deduplication_engine
        with db_manager.get_db_cursor() as cur:
            for finding in findings:
                # cve_id was previously built ONLY from the secret type ("SECRETS-API_KEY-
                # PHASE1"), with no file/line -- a real bug, not just duplicate spam: two
                # distinct hardcoded secrets of the same type in two different files shared the
                # same dedup key and silently overwrote each other on every scan, meaning only
                # the last one scanned was ever visible. location now disambiguates by file+line.
                cve_id = f"SECRETS-{finding['type'].upper()}-PHASE{scan_phase}"
                location = f"{finding.get('file', 'unknown')}:{finding.get('line', 0)}"
                severity = finding.get("severity", "HIGH")

                description = (
                    f"**Hardcoded Secret Detected (Phase {scan_phase})** \\n\\n"
                    f"**Type:** {finding['description']}\\n"
                    f"**File:** `{finding['file']}`\\n"
                    f"**Line:** {finding['line']}\\n"
                    f"**Context:** ```\\n{finding.get('masked_context', '')}\\n```\\n\\n"
                )

                if finding.get("verified") is True:
                    description += "**Verification:** the issuer confirmed this credential is STILL ACTIVE. Rotate it now.\\n"
                elif finding.get("verified") is False:
                    description += "**Verification:** the issuer did not confirm it as active (revoked, expired or a false positive).\\n"
                if finding.get("commit"):
                    description += f"**First Introduced:** Commit `{finding['commit']}`\\n"

                description += (
                    f"\\n**Recommendation:** \\n"
                    f"1. Immediately revoke this credential\\n"
                    f"2. Remove from repository and force-push\\n"
                    f"3. Rotate all secrets across environment\\n"
                    f"4. Add to .gitignore and/or .centinela-secrets-whitelist.json if false positive\\n"
                )

                action, _ = deduplication_engine.log_finding_deduplicated(
                    cur, asset_id, cve_id, severity, description, "secrets",
                    url_path=location, open_status="NEW", preserve_status=True
                )
                if action == "updated":
                    print(f"  🔄 Updated secrets finding: [{severity}] {cve_id} @ {location}")
                elif action == "merged":
                    print(f"  🔗 Merged secrets finding into existing cross-tool ticket: [{severity}] {cve_id}")
                elif action == "suppressed":
                    print(f"  🔇 Suppressed secrets finding (analyst-recorded): [{severity}] {cve_id} @ {location}")
                else:
                    print(f"  📝 Logged secret: [{severity}] {cve_id} @ {location}")

        print(f"✅ Logged {len(findings)} secrets for asset {asset_id}")

    except Exception:
        logger.error("Error logging secrets", exc_info=True)

def scan_repo_secrets_fast(repo_path: str, asset_id: str) -> bool:
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

def scan_repo_secrets_deep(repo_path: str, asset_id: str, max_commits: int = 50) -> bool:
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

def scan_repo_secrets_historical(repo_path: str, asset_id: str) -> bool:
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
