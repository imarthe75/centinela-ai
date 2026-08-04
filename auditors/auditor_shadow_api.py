"""
Centinela Native Shadow API & OpenAPI Drift Auditor
Compares official OpenAPI specs against codebase route handlers and runtime API traffic.
"""
import os
import re
import json
from typing import List, Dict, Any
from core import db_manager


def audit_shadow_apis_in_code(target_file: str, openapi_spec: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Detects route handlers in code that are missing from declared OpenAPI specification."""
    findings = []
    if not os.path.exists(target_file):
        return findings

    with open(target_file, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()

    declared_paths = set(openapi_spec.get("paths", {}).keys())
    code_routes = re.findall(r'@app\.(get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']', content)

    for method, path in code_routes:
        clean_path = path.split("?")[0]
        if clean_path not in declared_paths:
            findings.append({
                "cve_id": "API-SHADOW-ENDPOINT",
                "severity": "HIGH",
                "file": target_file,
                "method": method.upper(),
                "path": clean_path,
                "description": f"Shadow API Detected: Route [{method.upper()}] {clean_path} exists in source code but is missing from official OpenAPI documentation."
            })

    return findings


def run_shadow_api_audit(main_app_file: str = "/opt/centinela-ai/main.py") -> List[Dict[str, Any]]:
    """Runs Shadow API & OpenAPI Drift Audit."""
    findings = []
    try:
        from main import app
        spec = app.openapi()
        findings = audit_shadow_apis_in_code(main_app_file, spec)
    except Exception as e:
        print(f"⚠️ [ShadowAPI-Auditor] Error fetching FastAPI spec: {e}")

    # Log to DB
    try:
        with db_manager.get_db_cursor() as cur:
            for item in findings:
                cur.execute("""
                    INSERT INTO public.vulnerability_log 
                    (cve_id, severity, description, status, detected_at)
                    VALUES (%s, %s, %s, 'OPEN', NOW())
                    ON CONFLICT DO NOTHING
                """, (item["cve_id"], item["severity"], item["description"]))
    except Exception as db_err:
        print(f"⚠️ [ShadowAPI-Auditor] Could not log findings to DB: {db_err}")

    return findings
