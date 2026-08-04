"""
auditor_cloud.py — Centinela-AI v3
Orquestador de Prowler para evaluar la postura de seguridad en la nube (CSPM).
Utiliza credenciales de GCP/AWS/Azure si están disponibles para buscar fallos de configuración.
"""

import subprocess
import json
import os
import glob
from core import db_manager
from datetime import datetime
from psycopg2.extras import RealDictCursor

PROWLER_BIN = os.getenv("PROWLER_BIN", "prowler")
CREDENTIALS_PATH = "/app/credentials.json"

def _map_severity(prowler_sev: str) -> str:
    mapping = {
        "CRITICAL": "CRITICAL",
        "HIGH":     "HIGH",
        "MEDIUM":   "MEDIUM",
        "LOW":      "LOW",
        "INFO":     "INFO",
    }
    return mapping.get((prowler_sev or "").upper(), "INFO")

def run_prowler(asset_id: int, provider: str = "gcp") -> list[dict]:
    """Run prowler and return findings."""
    print(f"☁️ [Prowler] Starting cloud compliance scan for provider: {provider}...")
    
    findings = []
    output_dir = "/tmp/prowler"
    os.makedirs(output_dir, exist_ok=True)

    # Base command: prowler gcp --credentials-file /app/credentials.json
    cmd = [PROWLER_BIN, provider]
    
    if provider == "gcp":
        if os.path.exists(CREDENTIALS_PATH):
            cmd += ["--credentials-file", CREDENTIALS_PATH]
        else:
            # Try to run with default credentials if active in environment
            print("ℹ️ [Prowler] /app/credentials.json not found, using default env/metadata credentials")
    
    cmd += ["-o", output_dir, "-M", "json"]

    try:
        # Run prowler. Prowler scans might take a while, we set a 300s timeout.
        print(f"🚀 [Prowler] Running command: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        # Prowler outputs json files inside output_dir, name format: prowler-output-*-*.json
        json_pattern = os.path.join(output_dir, "*.json")
        json_files = glob.glob(json_pattern)
        
        if not json_files:
            print("⚠️ [Prowler] No JSON output files found")
            return []
            
        # Parse the latest json file
        latest_file = max(json_files, key=os.path.getmtime)
        print(f"📖 [Prowler] Parsing results from {latest_file}")
        
        with open(latest_file, "r") as f:
            # Prowler JSON might be line-delimited JSON or a standard JSON array depending on version
            content = f.read().strip()
            if content.startswith("["):
                records = json.loads(content)
            else:
                records = []
                for line in content.splitlines():
                    if line.strip():
                        try:
                            records.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue

        for r in records:
            # We filter for FAIL status checks
            status = r.get("Status") or r.get("status", "")
            if status != "FAIL":
                continue
                
            check_id = r.get("CheckID") or r.get("check_id", "PROWLER-CHECK")
            severity = _map_severity(r.get("Severity") or r.get("severity", "INFO"))
            desc = r.get("Description") or r.get("description") or "Cloud misconfiguration detected"
            resource = r.get("ResourceID") or r.get("resource_id") or "N/A"
            remediation = r.get("Remediation", {}).get("Recommendation", {}).get("Text", "")
            
            full_description = f"Resource: {resource}. {desc}. Recommendation: {remediation}"
            
            findings.append({
                "asset_id": asset_id,
                "cve_id": check_id,
                "severity": severity,
                "description": full_description[:1000],
                "scan_engine": "prowler"
            })
            
    except subprocess.TimeoutExpired:
        print("⏰ [Prowler] Scan timeout reached")
    except Exception as e:
        print(f"❌ [Prowler] Error executing scan: {e}")
        
    return findings

def persist_findings(findings: list[dict]):
    if not findings:
        return
    inserted = 0
    with db_manager.get_db_cursor(cursor_factory=RealDictCursor) as cur:
        for f in findings:
            cur.execute("""
                SELECT id FROM public.vulnerability_log
                WHERE asset_id = %s AND cve_id = %s AND scan_engine = 'prowler'
                LIMIT 1
            """, (f["asset_id"], f["cve_id"]))
            if cur.fetchone():
                continue
            cur.execute("""
                INSERT INTO public.vulnerability_log
                    (asset_id, cve_id, severity, description, status, scan_engine, detected_at)
                VALUES (%s, %s, %s, %s, 'PENDING', 'prowler', %s)
            """, (
                f["asset_id"], f["cve_id"], f["severity"],
                f["description"], datetime.utcnow()
            ))
            inserted += 1
    print(f"💾 [Prowler] Persisted {inserted} new findings to vulnerability_log")

def run(asset_id: int, asset_name: str, provider: str = "gcp"):
    """Entry point called by auditor_ext."""
    findings = run_prowler(asset_id, provider)
    if findings:
        persist_findings(findings)
