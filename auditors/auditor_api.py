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
from core import db_manager
from datetime import datetime
from psycopg2.extras import RealDictCursor

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

def run_ffuf(url: str, asset_id: int) -> list[dict]:
    """Run ffuf against the URL and return findings."""
    ensure_wordlists()
    # Strip trailing slash if present
    base_url = url.rstrip('/')
    target = f"{base_url}/FUZZ"
    print(f"🔍 [ffuf] Scanning {target}...")

    findings = []
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        out_path = tmp.name

    # -mc: match status codes, -sf: stop on spam/errors
    cmd = [
        FFUF_BIN,
        "-u", target,
        "-w", DEFAULT_WORDLIST,
        "-mc", "200,204,301,302,307,401,403",
        "-of", "json",
        "-o", out_path,
        "-s" # silent/quiet
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=200)
        if not os.path.exists(out_path) or os.path.getsize(out_path) == 0:
            print(f"ℹ️ [ffuf] No results or empty output for {url}")
            return []

        with open(out_path, "r") as f:
            data = json.load(f)

        for res in data.get("results", []):
            input_word = res.get("input", {}).get("FUZZ", "")
            status = res.get("status", 0)
            redirect = res.get("redirectlocation", "")
            length = res.get("length", 0)
            
            # Formulate description
            desc = f"Discovered endpoint: /{input_word} (Status: {status}, Length: {length} bytes)"
            if redirect:
                desc += f" -> Redirects to {redirect}"
            
            # Severity mapping based on status / known paths
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
                "scan_engine": "ffuf"
            })
    except subprocess.TimeoutExpired:
        print(f"⏰ [ffuf] Timeout for {url}")
    except Exception as e:
        print(f"⚠️ [ffuf] Error scanning {url}: {e}")
    finally:
        if os.path.exists(out_path):
            os.unlink(out_path)

    return findings

def run_kiterunner(url: str, asset_id: int) -> list[dict]:
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

def run(asset_id: int, asset_name: str, endpoint: str):
    """Entry point called by auditor_ext."""
    # Ensure endpoint is a valid URL
    if not (endpoint.startswith("http://") or endpoint.startswith("https://")):
        # If it's just host/IP, build HTTP URL
        url = f"http://{endpoint}"
    else:
        url = endpoint

    # 1. Run ffuf
    ffuf_findings = run_ffuf(url, asset_id)
    persist_findings(ffuf_findings, "ffuf")

    # 2. Run kiterunner
    kr_findings = run_kiterunner(url, asset_id)
    persist_findings(kr_findings, "kiterunner")
