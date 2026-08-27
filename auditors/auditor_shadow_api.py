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


def run_shadow_api_audit(main_app_file: str = "/app/main.py", asset_id: int = None) -> List[Dict[str, Any]]:
    """Runs Shadow API & OpenAPI Drift Audit."""
    findings = []
    try:
        from main import app
        spec = app.openapi()
        findings = audit_shadow_apis_in_code(main_app_file, spec)
    except Exception as e:
        print(f"⚠️ [ShadowAPI-Auditor] Error fetching FastAPI spec: {e}")

    # Log to DB. Two real bugs fixed here:
    # 1. main_app_file defaulted to "/opt/centinela-ai/main.py" -- a host-side path that doesn't
    #    exist inside any container (the real bind mount is /app), so this silently found zero
    #    findings on every call with the default (confirmed live: same failure mode as the
    #    /api/audit/full-spectrum bug documented elsewhere in this codebase).
    # 2. The INSERT had no asset_id column at all and used a target-less "ON CONFLICT DO
    #    NOTHING" -- with no asset_id, findings could never JOIN to infra_inventory to be
    #    AI-correlated, and repeat scans would re-insert duplicates since no real unique
    #    constraint backs a targetless ON CONFLICT. Replaced with the shared dedup logger
    #    every other auditor already uses.
    try:
        from core import deduplication_engine
        with db_manager.get_db_cursor() as cur:
            # Don't create dangling rows: auditor_ext.py dispatches API-Gateway assets here with
            # ids from a Valkey discovery message (observed as synthetic 99xxx with no
            # infra_inventory row), and this auditor only ever inspects local /app/main.py, not
            # the remote endpoint -- nothing to attribute to such an asset. (2026-08-27)
            if asset_id is not None:
                cur.execute("SELECT 1 FROM public.infra_inventory WHERE id = %s", (asset_id,))
                if cur.fetchone() is None:
                    print(f"⚠️ [ShadowAPI-Auditor] asset_id {asset_id} not in infra_inventory -- "
                          f"returning {len(findings)} finding(s) without persisting.")
                    return findings
            for item in findings:
                deduplication_engine.log_finding_deduplicated(
                    cur, asset_id, item["cve_id"], item["severity"], item["description"],
                    "shadow-api-native", url_path=item.get("file", ""), open_status="OPEN", preserve_status=True
                )
    except Exception as db_err:
        print(f"⚠️ [ShadowAPI-Auditor] Could not log findings to DB: {db_err}")

    return findings


def run(asset_id: int = None, endpoint: str = "") -> List[Dict[str, Any]]:
    """Wrapper function for auditor_ext compatibility."""
    print(f"🌐 [Auditor-ShadowAPI] Auditing API Gateway or Shadow API routes: {endpoint}")
    return run_shadow_api_audit(asset_id=asset_id)
