"""
auditor_api.py — Centinela-AI v3
Motor de descubrimiento y auditoría de APIs usando ffuf y Kiterunner.
Fuzzea y escanea endpoints para descubrir rutas ocultas, fugas de info,
y endpoints no autorizados en activos de tipo URL/AppServer.
"""

import subprocess
import json
import os
import tempfile
import time
import logging
from core import db_manager
from datetime import datetime
from psycopg2.extras import RealDictCursor

logger = logging.getLogger(__name__)

FFUF_BIN = os.getenv("FFUF_BIN", "ffuf")
KR_BIN   = os.getenv("KR_BIN", "kr")
WORDLISTS_DIR = "/app/data/wordlists"
DEFAULT_WORDLIST = os.path.join(WORDLISTS_DIR, "common_api.txt")

def ensure_wordlists():
    """Ensure a basic wordlist exists for fuzzing."""
    os.makedirs(WORDLISTS_DIR, exist_ok=True)
    if not os.path.exists(DEFAULT_WORDLIST):
        words = [
            "api", "api/v1", "api/v2", "admin", "admin/login", "administrator",
            "swagger", "swagger-ui.html", "swagger/index.html", "v2/api-docs",
            "actuator", "actuator/health", "actuator/env", "config", "env",
            ".git", ".env", "backup", "db", "database", "login", "register",
            "metrics", "health", "info", "wp-admin", "xmlrpc.php", "console",
            "api/users", "api/auth", "api/settings", "status", "debug", "test"
        ]
        with open(DEFAULT_WORDLIST, "w") as f:
            f.write("\n".join(words) + "\n")
        print(f"📝 Created default API wordlist with {len(words)} entries.")

AUDIT_LOG_DIR = os.getenv("FFUF_AUDIT_LOG_DIR", "/app/data/audit_logs/ffuf")   # internal (data/ is never served)
AUDIT_LOG_RETENTION_DAYS = int(os.getenv("FFUF_AUDIT_LOG_RETENTION_DAYS", "30"))


def ffuf_location(word: str) -> str:
    return "/" + (word or "").lstrip("/")


def prune_audit_logs(directory: str = None, days: int = None) -> int:
    directory = directory or AUDIT_LOG_DIR
    days = AUDIT_LOG_RETENTION_DAYS if days is None else days
    if not os.path.isdir(directory):
        return 0
    cutoff = time.time() - days * 86400
    removed = 0
    for name in os.listdir(directory):
        path = os.path.join(directory, name)
        if os.path.isfile(path) and os.path.getmtime(path) < cutoff:
            os.unlink(path)
            removed += 1
    return removed


def parse_ffuf_results(data: dict, asset_id: str) -> list[dict]:
    findings = []
    for res in data.get("results", []):
        input_word = res.get("input", {}).get("FUZZ", "")
        status = res.get("status", 0)
        redirect = res.get("redirectlocation", "")
        length = res.get("length", 0)
        desc = f"Discovered endpoint: /{input_word} (Status: {status}, Length: {length} bytes)"
        if redirect:
            desc += f" -> Redirects to {redirect}"
        severity = "INFO"
        if status == 200:
            if any(x in input_word.lower() for x in [".env", ".git", "actuator", "config"]):
                severity = "HIGH"
            elif any(x in input_word.lower() for x in ["admin", "debug", "backup", "db"]):
                severity = "MEDIUM"
            else:
                severity = "LOW"
        elif status in [401, 403]:
            severity = "LOW"
        findings.append({
            "asset_id": asset_id,
            "cve_id": f"FFUF-DISCOVER-{input_word.replace('/', '-').upper()}",
            "severity": severity,
            "description": desc,
            "url_path": ffuf_location(input_word),
            "scan_engine": "ffuf",
        })
    return findings


class FfufFindings(list):
    """Findings plus whether ffuf finished the whole (fixed) wordlist -- only then may it close findings."""
    def __init__(self, items=(), complete: bool = False, audit_log: str = ""):
        super().__init__(items)
        self.complete = complete
        self.audit_log = audit_log


def run_ffuf(url: str, asset_id: str) -> "FfufFindings":
    """Run ffuf against the URL. Every request/response is kept in an audit log (ffuf -audit-log) as evidence of what was sent."""
    ensure_wordlists()
    base_url = url.rstrip('/')
    target = f"{base_url}/FUZZ"
    print(f"🔍 [ffuf] Scanning {target}...")

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        out_path = tmp.name
    os.makedirs(AUDIT_LOG_DIR, exist_ok=True)
    prune_audit_logs()
    audit_path = os.path.join(AUDIT_LOG_DIR, f"{asset_id}_{time.strftime('%Y%m%dT%H%M%S')}.jsonl")

    # -mc: match status codes. -ac: auto-calibration -- ffuf first requests random paths and filters every response that
    # looks like them. Without it an SPA, which answers 200 with its index.html for ANY path, produced one finding per word
    # of the list (".env", ".git/HEAD" and "actuator/env" reported HIGH on a frontend that only served its index page).
    cmd = [
        FFUF_BIN,
        "-u", target,
        "-w", DEFAULT_WORDLIST,
        "-mc", "200,204,301,302,307,401,403",
        "-ac",
        "-of", "json",
        "-o", out_path,
        "-audit-log", audit_path,
        "-s",
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=200)
        if result.returncode != 0 or not os.path.exists(out_path) or os.path.getsize(out_path) == 0:
            logger.error("ffuf failed on %s (exit %s): %s", url, result.returncode, (result.stderr or "")[-500:])
            return FfufFindings(audit_log=audit_path)
        with open(out_path, "r") as f:
            data = json.load(f)
        return FfufFindings(parse_ffuf_results(data, asset_id), complete=True, audit_log=audit_path)
    except subprocess.TimeoutExpired:
        logger.error("ffuf timed out on %s", url, exc_info=True)
    except Exception:
        logger.error("ffuf error scanning %s", url, exc_info=True)
    finally:
        if os.path.exists(out_path):
            os.unlink(out_path)
    return FfufFindings(audit_log=audit_path)


def persist_ffuf(asset_id: str, findings: "FfufFindings") -> dict:
    """Shared dedup engine; a complete run closes the paths it no longer finds (the wordlist is fixed and run in full)."""
    from core import deduplication_engine as de
    seen = set()
    with db_manager.get_db_cursor() as cur:
        for f in findings:
            de.log_finding_deduplicated(cur, asset_id, f["cve_id"], f["severity"], f["description"], "ffuf",
                                        url_path=f["url_path"], open_status="NEW", preserve_status=True)
            seen.add(de.calculate_fingerprint(asset_id, f["cve_id"], f["url_path"]))
        resolved = de.reconcile_resolved_findings(cur, asset_id, "ffuf", seen) if getattr(findings, "complete", False) else 0
    print(f"💾 [ffuf] {len(findings)} findings, {resolved} no longer found -> RESOLVED"
          + (f"; audit log {findings.audit_log}" if getattr(findings, "audit_log", "") else ""))
    return {"persisted": len(findings), "resolved": resolved}

def run_kiterunner(url: str, asset_id: str) -> list[dict]:
    """Run kiterunner scan against target URL."""
    ensure_wordlists()
    print(f"🔍 [Kiterunner] Scanning {url}...")
    findings = []

    # kr scan <url> -w <wordlist>
    # Note: Kiterunner can output JSON using -o json
    # However, kr by default can run text scan. Let's run text scan and parse lines.
    # kr scan <url> -w <wordlist> --fail-status-codes 400,404,500,502,503,504
    cmd = [
        KR_BIN, "scan", url,
        "-w", DEFAULT_WORDLIST,
        "--fail-status-codes", "400,404,500,501,502,503,504"
    ]

    try:
        # kr might log to stderr or stdout. We capture everything.
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=200)
        # Parse lines: typically output contains something like "GET [200, 1024, 0.05s] http://target/api"
        for line in result.stdout.splitlines():
            if not line.strip() or "ERR" in line:
                continue
            if "[" in line and "]" in line:
                # E.g. "GET  200 [    124,   0.05s] http://target/api"
                # Let's extract the endpoint/path, status code
                parts = line.split()
                if len(parts) >= 4:
                    method = parts[0]
                    try:
                        status = int(parts[1])
                    except ValueError:
                        continue
                    
                    found_url = parts[-1]
                    path_discovered = found_url.replace(url, "")
                    
                    severity = "INFO"
                    if status == 200:
                        if any(x in path_discovered.lower() for x in [".env", ".git", "actuator", "config"]):
                            severity = "HIGH"
                        elif any(x in path_discovered.lower() for x in ["admin", "debug", "backup", "db"]):
                            severity = "MEDIUM"
                        else:
                            severity = "LOW"
                    
                    findings.append({
                        "asset_id": asset_id,
                        "cve_id": f"KR-DISCOVER-{path_discovered.strip('/').replace('/', '-').upper()}",
                        "severity": severity,
                        "description": f"Kiterunner discovered endpoint: {method} {path_discovered} (Status: {status})",
                        "scan_engine": "kiterunner"
                    })
    except subprocess.TimeoutExpired:
        print(f"⏰ [Kiterunner] Timeout for {url}")
    except Exception as e:
        print(f"⚠️ [Kiterunner] Error scanning {url}: {e}")

    return findings

def persist_findings(findings: list[dict], engine: str):
    if not findings:
        return
    inserted = 0
    with db_manager.get_db_cursor(cursor_factory=RealDictCursor) as cur:
        for f in findings:
            cur.execute("""
                SELECT id FROM public.vulnerability_log
                WHERE asset_id = %s AND cve_id = %s AND scan_engine = %s
                LIMIT 1
            """, (f["asset_id"], f["cve_id"], engine))
            if cur.fetchone():
                continue
            cur.execute("""
                INSERT INTO public.vulnerability_log
                    (asset_id, cve_id, severity, description, status, scan_engine, detected_at)
                VALUES (%s, %s, %s, %s, 'PENDING', %s, %s)
            """, (
                f["asset_id"], f["cve_id"], f["severity"],
                f["description"], engine, datetime.utcnow()
            ))
            inserted += 1
    print(f"💾 [{engine}] Persisted {inserted} new findings to vulnerability_log")

def run(asset_id: str, asset_name: str, endpoint: str):
    """Entry point called by auditor_ext."""
    # Ensure endpoint is a valid URL
    if not (endpoint.startswith("http://") or endpoint.startswith("https://")):
        # If it's just host/IP, build HTTP URL
        url = f"http://{endpoint}"
    else:
        url = endpoint

    # 1. Run ffuf
    ffuf_findings = run_ffuf(url, asset_id)
    persist_ffuf(asset_id, ffuf_findings)

    # 2. Run kiterunner
    kr_findings = run_kiterunner(url, asset_id)
    persist_findings(kr_findings, "kiterunner")
