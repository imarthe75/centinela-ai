"""
auditor_semgrep.py — Centinela-AI v3
Motor de análisis estático de código fuente (SAST) usando Semgrep.
Escanea repositorios Git montados o rutas locales y reporta hallazgos
en vulnerability_log con scan_engine='semgrep'.
"""

import subprocess
import json
import os
import traceback
from core import db_manager, deduplication_engine

SEMGREP_BIN = os.getenv("SEMGREP_BIN", "semgrep")
REPOS_BASE  = os.getenv("REPOS_BASE", "/app/repos")   # directorio donde se montan repos
# Real gap found 2026-08-22 auditing 3 Java/TypeScript projects: this was ONE fixed ruleset list
# (defaulting to p/python + p/javascript only) applied to every single repo Centinela ever scans
# with semgrep, including the periodic automatic GitLab loop -- a Java-only repo would silently
# never get p/java rules unless someone manually overrode SEMGREP_RULESETS globally, which would
# then apply that same override to every OTHER repo too (Python ones wasting scan time running
# irrelevant Java rules). SEMGREP_RULESETS is kept as a full override escape hatch (set it and it
# wins outright, matching the exact behavior every caller already relies on), but when unset the
# ruleset is now chosen per-scan from the real languages actually present in `path`.
RULESETS    = os.getenv("SEMGREP_RULESETS", "")
_LANG_RULESETS = {
    ".py": "p/python",
    ".js": "p/javascript", ".jsx": "p/javascript",
    ".ts": "p/typescript", ".tsx": "p/typescript",
    ".java": "p/java",
    ".go": "p/golang",
    ".php": "p/php",
    # Extended 2026-08-25 after a real, live discovery: querying the fleet's own vulnerability_log
    # url_path extensions found genuine Rust (.rs, 39 findings via SonarQube, geo-ircep-smart's
    # vendored `everything-claude-code` Rust codebase) and Terraform (.tf, 2 findings) already
    # present in the GitLab fleet, neither ever getting a language-specific Semgrep ruleset before
    # this. Every ruleset name below was verified live against semgrep's real registry API
    # (https://semgrep.dev/api/registry/rulesets) before being added -- NOT guessed: a bad
    # ruleset name fails with a real, loud "HTTP 404 configuration not found" error from semgrep
    # itself (confirmed live with a deliberately-invalid name), so a wrong entry here would be a
    # visible, self-disclosing failure, not a silent 0-findings gap -- but verifying first avoids
    # ever hitting that failure in production. Deliberately NOT added: C++, HTML, Bash, Dart --
    # confirmed live via the same registry query that semgrep has no official `p/` ruleset for
    # any of these (each returns a real HTTP 404), so adding them would silently produce 0
    # findings forever, indistinguishable from "clean code" -- exactly the kind of fake coverage
    # this project's own rules prohibit. If one of these languages becomes a real audit target,
    # the honest fix is a project-specific custom Semgrep rule pack, not a guessed registry name.
    ".rs": "p/rust",
    ".tf": "p/terraform",
    ".rb": "p/ruby",
    ".cs": "p/csharp",
    ".c": "p/c", ".h": "p/c",
    ".kt": "p/kotlin", ".kts": "p/kotlin",
    ".swift": "p/swift",
    ".scala": "p/scala",
    ".ex": "p/elixir", ".exs": "p/elixir",
}


def _severity_from_semgrep(impact: str) -> str:
    mapping = {
        "ERROR":   "HIGH",
        "WARNING": "MEDIUM",
        "INFO":    "LOW",
    }
    return mapping.get((impact or "").upper(), "LOW")


def detect_language_rulesets(path: str) -> list[str]:
    """
    Real, language-agnostic rulesets (owasp-top-ten, secrets) always run; language-specific ones
    are added only for extensions genuinely found under `path` -- confirmed live against SIDECO
    (Java) and its Angular frontend (TypeScript), each correctly picks up only its own real
    language instead of the old Python/JS-only default silently missing both.
    """
    found_exts = set()
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in (".git", "node_modules", "__pycache__", ".venv", ".mvn")]
        for f in files:
            ext = os.path.splitext(f)[1].lower()
            if ext in _LANG_RULESETS:
                found_exts.add(ext)
        if len(found_exts) == len(set(_LANG_RULESETS.values())):
            break  # every known language already found, no need to keep walking
    lang_rulesets = sorted({_LANG_RULESETS[e] for e in found_exts})
    return ["p/owasp-top-ten", "p/secrets"] + lang_rulesets


def scan_path(path: str, asset_id: int, asset_name: str) -> list[dict]:
    """Run semgrep on `path` and return list of normalized findings."""
    rulesets = RULESETS.split() if RULESETS else detect_language_rulesets(path)
    cmd = [SEMGREP_BIN, "--json", "--quiet"] + [f"--config={r}" for r in rulesets] + [path]
    print(f"🔍 [Semgrep] Scanning {path} with rulesets: {rulesets}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if result.returncode not in (0, 1):
            print(f"⚠️ [Semgrep] Non-zero exit {result.returncode}: {result.stderr[:200]}")
            return []
        data = json.loads(result.stdout or "{}")
    except subprocess.TimeoutExpired:
        print(f"⏰ [Semgrep] Timeout scanning {path}")
        return []
    except json.JSONDecodeError as e:
        print(f"⚠️ [Semgrep] JSON parse error: {e}")
        return []

    findings = []
    for r in data.get("results", []):
        check_id  = r.get("check_id", "semgrep-finding")
        severity  = _severity_from_semgrep(r.get("extra", {}).get("severity"))
        file_path = r.get("path", "unknown")
        start_line = r.get("start", {}).get("line", 0)
        message   = r.get("extra", {}).get("message", "Sin descripción")
        findings.append({
            "asset_id":    asset_id,
            "asset_name":  asset_name,
            "cve_id":      check_id,
            "severity":    severity,
            "description": f"[{file_path}:{start_line}] {message}",
            "url_path":    f"{file_path}:{start_line}",
            "scan_engine": "semgrep",
        })
    print(f"✅ [Semgrep] {len(findings)} findings for {asset_name} at {path}")
    return findings


def persist_findings(findings: list[dict]):
    """
    Persists semgrep findings via the shared cross-tool dedup engine. Previously this ran its
    own ad-hoc `SELECT ... WHERE asset_id=%s AND cve_id=%s AND scan_engine='semgrep'` check and,
    on a match, did nothing at all -- not even refreshing detected_at/severity -- meaning
    re-detected findings never got their SLA due date, fingerprint_hash, or MITRE ATT&CK
    mapping computed, because none of that lives in this ad-hoc INSERT; every other auditor in
    this codebase already funnels through log_finding_deduplicated() for exactly that reason.
    preserve_status=True: semgrep re-scans the same GitLab repos repeatedly via the idle loop,
    same reasoning as ZAP's documented preserve_status bug -- without it, every re-detection
    would reset an already-triaged finding back to OPEN.
    """
    if not findings:
        return
    persisted = 0
    with db_manager.get_db_cursor() as cur:
        for f in findings:
            deduplication_engine.log_finding_deduplicated(
                cur, f["asset_id"], f["cve_id"], f["severity"], f["description"],
                "semgrep", url_path=f["url_path"], open_status="OPEN", preserve_status=True
            )
            persisted += 1
    print(f"💾 [Semgrep] Persisted {persisted} findings to vulnerability_log")


def run(asset_id: int, asset_name: str, repo_path: str = None):
    """Entry point called by auditor_ext."""
    path = repo_path or os.path.join(REPOS_BASE, asset_name.replace(" ", "_"))
    if not os.path.isdir(path):
        print(f"⚠️ [Semgrep] Path not found: {path} — skipping {asset_name}")
        return
    findings = scan_path(path, asset_id, asset_name)
    persist_findings(findings)
