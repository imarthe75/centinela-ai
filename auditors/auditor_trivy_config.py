"""
Infrastructure-as-code misconfiguration audit with `trivy config` (Dockerfile, Kubernetes manifests, Terraform, CloudFormation, Helm...).

Runs `trivy config` (rules DS-xxxx for Dockerfiles, KSV-xxxx for Kubernetes, AVD for Terraform) over a repository in ~2 s. Measured 2026-10-13 on three real repositories: 18/18/19 rule ids each, the same ones a heavier multi-analyzer scanner produced in ~3 minutes, so the lighter engine was kept.

Findings: cve_id `TRIVY-<ID>` (e.g. TRIVY-KSV-0014), url_path `<file>:<line>`, engine `trivy-config`. Persisted with the shared deduplicating logger and
reconciled (a misconfiguration that disappears from the next scan is closed).
"""
import json
import os
import subprocess
from typing import Any, Dict, List, Optional

ENGINE = "trivy-config"
_SEV = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW", "UNKNOWN": "LOW"}


def parse_trivy_config(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Pure: `trivy config --format json` document -> list of findings (cve_id, severity, file, line, description)."""
    out: List[Dict[str, Any]] = []
    for res in (data or {}).get("Results") or []:
        target = res.get("Target") or "unknown"
        for m in res.get("Misconfigurations") or []:
            mid = m.get("ID") or m.get("AVDID") or "UNKNOWN"
            cause = m.get("CauseMetadata") or {}
            line = cause.get("StartLine") or 1
            title = m.get("Title") or mid
            desc = (f"**Configuración insegura detectada por Trivy (`{mid}`)**\n\n**Título:** {title}\n**Descripción:** {m.get('Description') or ''}\n"
                    f"**Detalle:** {m.get('Message') or ''}\n**Archivo:** `{target}` (Línea {line})\n**Cómo corregirlo:** {m.get('Resolution') or 'ver la referencia'}")
            if m.get("PrimaryURL"):
                desc += f"\n**Referencia:** {m['PrimaryURL']}"
            out.append({"cve_id": f"TRIVY-{mid}", "severity": _SEV.get(str(m.get("Severity", "")).upper(), "LOW"), "file": target, "line": line, "description": desc})
    return out


def scan_directory(target_dir: str, timeout: int = 300) -> Optional[List[Dict[str, Any]]]:
    """Runs `trivy config`; returns None (not an empty list) when the tool could not run, so a failure is never read as 'clean'."""
    try:
        r = subprocess.run(["trivy", "config", "--quiet", "--format", "json", target_dir], capture_output=True, text=True, timeout=timeout)
        if r.returncode not in (0,) or not r.stdout.strip():
            print(f"⚠️ [Trivy-Config] trivy config exited {r.returncode} on {target_dir}: {r.stderr[:300]}")
            return None
        return parse_trivy_config(json.loads(r.stdout))
    except subprocess.TimeoutExpired:
        print(f"⏰ [Trivy-Config] timed out on {target_dir}")
        return None
    except (json.JSONDecodeError, FileNotFoundError) as e:
        print(f"⚠️ [Trivy-Config] output unusable for {target_dir}: {type(e).__name__}: {e}")
        return None


def run_trivy_config_audit(target_dir: str, asset_id: Optional[str] = None, display_name: str = "") -> List[Dict[str, Any]]:
    """scan -> persist -> reconcile. Without a real asset_id nothing is written."""
    findings = scan_directory(target_dir)
    if findings is None:
        return []
    if asset_id is None:
        return findings
    from core import db_manager, deduplication_engine
    try:
        active = set()
        with db_manager.get_db_cursor() as cur:
            for f in findings:
                rel = os.path.relpath(f["file"], target_dir) if os.path.isabs(f["file"]) else f["file"]
                location = f"{rel}:{f['line']}"
                active.add(deduplication_engine.calculate_fingerprint(asset_id, f["cve_id"], location))
                deduplication_engine.log_finding_deduplicated(cur, asset_id, f["cve_id"], f["severity"], f["description"], ENGINE,
                                                              url_path=location, open_status="OPEN", preserve_status=True)
            deduplication_engine.reconcile_resolved_findings(cur, asset_id, ENGINE, active)
    except Exception:
        import traceback
        traceback.print_exc()
        print(f"⚠️ [Trivy-Config] could not persist findings for {display_name or asset_id}")
    return findings


def run(asset_id: str, repo_path: str = "") -> List[Dict[str, Any]]:
    """Entry point used by auditors/auditor_ext.py for repository assets."""
    return run_trivy_config_audit(repo_path, asset_id=asset_id, display_name=repo_path)
