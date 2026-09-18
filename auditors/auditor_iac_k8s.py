"""
Centinela Native IaC Auditor for Kubernetes (.yaml) & Terraform (.tf)
Evaluates infrastructure manifests against security hardening standards.
"""
import os
import re
from typing import List, Dict, Any
from core import db_manager
from core.deduplication_engine import log_finding_deduplicated

def audit_kubernetes_yaml(file_path: str, content: str) -> List[Dict[str, Any]]:
    """Audits Kubernetes deployment/pod YAML files for security misconfigurations."""
    findings = []
    lines = content.splitlines()

    rules = [
        (r'privileged:\s*true', "K8S-PRIVILEGED-CONTAINER", "CRITICAL", "Kubernetes container is configured with privileged: true (root host access)."),
        (r'hostPath:', "K8S-HOSTPATH-MOUNT", "HIGH", "Kubernetes pod uses insecure hostPath volume mount."),
        (r'readOnlyRootFilesystem:\s*false', "K8S-WRITABLE-ROOT-FS", "MEDIUM", "Container root filesystem is writable. Should be readOnlyRootFilesystem: true."),
        (r'automountServiceAccountToken:\s*true', "K8S-AUTOMOUNT-TOKEN", "MEDIUM", "Pod automatically mounts ServiceAccount token (credential exposure risk)."),
        (r'allowPrivilegeEscalation:\s*true', "K8S-PRIVILEGE-ESCALATION", "HIGH", "Container allows privilege escalation (allowPrivilegeEscalation: true)."),
        (r'runAsNonRoot:\s*false|runAsUser:\s*0', "K8S-RUN-AS-ROOT", "HIGH", "Container explicitly allowed to run as root user.")
    ]

    for idx, line in enumerate(lines, 1):
        for pattern, rule_id, severity, desc in rules:
            if re.search(pattern, line, re.IGNORECASE):
                findings.append({
                    "cve_id": rule_id,
                    "severity": severity,
                    "file": file_path,
                    "line": idx,
                    "description": f"{desc} Line {idx}: {line.strip()}"
                })

    return findings

def audit_terraform_tf(file_path: str, content: str) -> List[Dict[str, Any]]:
    """Audits Terraform .tf files for cloud security risks."""
    findings = []
    lines = content.splitlines()

    rules = [
        (r'cidr_blocks\s*=\s*\[\s*["\']0\.0\.0\.0/0["\']\s*\]', "TF-OPEN-SECURITY-GROUP", "HIGH", "Terraform Security Group opens port access to 0.0.0.0/0 (world accessible)."),
        (r'acl\s*=\s*["\']public-read["\']|acl\s*=\s*["\']public-read-write["\']', "TF-PUBLIC-S3-BUCKET", "CRITICAL", "Terraform S3 bucket is configured with public-read/write ACL."),
        (r'ingress\s*\{[^}]*port\s*=\s*(22|3389|5432|3306)[^}]*0\.0\.0\.0/0', "TF-ADMIN-PORT-WORLD-OPEN", "CRITICAL", "Terraform opens administrative port (22/3389/5432/3306) to 0.0.0.0/0.")
    ]

    for idx, line in enumerate(lines, 1):
        for pattern, rule_id, severity, desc in rules:
            if re.search(pattern, line, re.IGNORECASE):
                findings.append({
                    "cve_id": rule_id,
                    "severity": severity,
                    "file": file_path,
                    "line": idx,
                    "description": f"{desc} Line {idx}: {line.strip()}"
                })

    return findings

def run_iac_scan(target_dir: str = "/app", asset_id: int = None) -> List[Dict[str, Any]]:
    """Scans target directory for Kubernetes YAML and Terraform files, persisting findings to the DB."""
    findings = []
    for root, _, files in os.walk(target_dir):
        if any(ignored in root for ignored in [".git", "node_modules", "__pycache__", ".venv", "data/remediation", "data/sonar_scans", "everything-claude-code", ".mvn", "/target/", "\\target\\"]):
            continue
        for file in files:
            full_path = os.path.join(root, file)
            try:
                with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()

                if file.endswith((".yaml", ".yml")) and ("apiVersion:" in content or "kind:" in content):
                    findings.extend(audit_kubernetes_yaml(full_path, content))
                elif file.endswith(".tf"):
                    findings.extend(audit_terraform_tf(full_path, content))
            except Exception:
                continue

    try:
        with db_manager.get_db_cursor() as cur:
            for item in findings:
                rel_path = os.path.relpath(item["file"], target_dir)
                log_finding_deduplicated(
                    cur, asset_id, item["cve_id"], item["severity"],
                    f"{rel_path}:{item['line']} - {item['description']}",
                    "iac-native", url_path=f"{rel_path}:{item['line']}", preserve_status=True
                )
    except Exception as e:
        print(f"⚠️ [IaC-Auditor] Error logging to DB: {e}")

    return findings
