"""
Centinela Native IaC & Kubernetes Security Auditor
Inspects Terraform files, Kubernetes manifests, and Helm Charts for cloud security misconfigurations.
"""
import os
import re
import yaml
from typing import List, Dict, Any
from core import db_manager


def audit_kubernetes_manifest(file_path: str, content: str) -> List[Dict[str, Any]]:
    """Audits Kubernetes YAML manifests for container security risks."""
    findings = []
    lines = content.splitlines()

    # 1. Privileged Container Check
    for idx, line in enumerate(lines, 1):
        if "privileged: true" in line:
            findings.append({
                "cve_id": "K8S-PRIVILEGED-CONTAINER",
                "severity": "CRITICAL",
                "file": file_path,
                "line": idx,
                "description": f"Kubernetes Security Violation: Pod container configured with 'privileged: true'. Line {idx}: {line.strip()}"
            })
        if "allowPrivilegeEscalation: true" in line:
            findings.append({
                "cve_id": "K8S-PRIVILEGE-ESCALATION",
                "severity": "HIGH",
                "file": file_path,
                "line": idx,
                "description": f"Kubernetes Security Violation: Pod allows privilege escalation. Line {idx}: {line.strip()}"
            })

    # 2. Missing Resource Limits Check
    if "resources:" not in content or "limits:" not in content:
        findings.append({
            "cve_id": "K8S-MISSING-RESOURCE-LIMITS",
            "severity": "MEDIUM",
            "file": file_path,
            "line": 1,
            "description": "Kubernetes Resilience Violation: Pod manifest lacks explicit CPU and Memory resource limits (DoS risk)."
        })

    return findings


def audit_terraform_file(file_path: str, content: str) -> List[Dict[str, Any]]:
    """Audits Terraform HCL files for cloud infrastructure misconfigurations."""
    findings = []
    lines = content.splitlines()

    for idx, line in enumerate(lines, 1):
        # 1. Public S3 Bucket Check
        if 'acl' in line and ('public-read' in line or 'public-read-write' in line):
            findings.append({
                "cve_id": "TF-PUBLIC-STORAGE-BUCKET",
                "severity": "CRITICAL",
                "file": file_path,
                "line": idx,
                "description": f"Terraform Misconfiguration: Cloud Storage Bucket configured with public ACL. Line {idx}: {line.strip()}"
            })
        # 2. Open Security Group Check
        if 'cidr_blocks' in line and '"0.0.0.0/0"' in line:
            findings.append({
                "cve_id": "TF-OPEN-SECURITY-GROUP",
                "severity": "HIGH",
                "file": file_path,
                "line": idx,
                "description": f"Terraform Misconfiguration: Security group ingress open to entire internet (0.0.0.0/0). Line {idx}: {line.strip()}"
            })

    return findings


def run_iac_k8s_audit(target_dir: str = "/opt/centinela-ai") -> List[Dict[str, Any]]:
    """Scans target directory for Terraform and Kubernetes manifests."""
    all_findings = []

    for root, _, files in os.walk(target_dir):
        if any(ignored in root for ignored in [".git", "node_modules", "__pycache__", ".venv"]):
            continue
        for file in files:
            full_path = os.path.join(root, file)
            try:
                with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()

                if file.endswith((".yaml", ".yml")) and ("apiVersion:" in content or "kind:" in content):
                    all_findings.extend(audit_kubernetes_manifest(full_path, content))
                elif file.endswith(".tf"):
                    all_findings.extend(audit_terraform_file(full_path, content))
            except Exception as e:
                print(f"⚠️ [IaC-Auditor] Error reading {full_path}: {e}")

    # Persist findings to DB
    try:
        with db_manager.get_db_cursor() as cur:
            for item in all_findings:
                cur.execute("""
                    INSERT INTO public.vulnerability_log 
                    (cve_id, severity, description, status, detected_at)
                    VALUES (%s, %s, %s, 'OPEN', NOW())
                    ON CONFLICT DO NOTHING
                """, (item["cve_id"], item["severity"], item["description"]))
    except Exception as db_err:
        print(f"⚠️ [IaC-Auditor] Could not log findings to DB: {db_err}")

    return all_findings
