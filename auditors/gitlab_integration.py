"""
Centinela GitLab Integration & Automated Repository Auditor
Discovers, clones, and audits all projects from a GitLab instance (SAST, SCA, IaC, Standards).
"""
import os
import shutil
import subprocess
import requests
from typing import List, Dict, Any
from auditors import auditor_master_vulnerabilities, auditor_sca_dependencies, auditor_compliance_standards, auditor_semgrep
from core import db_manager


class GitLabIntegrator:
    def __init__(self, gitlab_url: str = None, token: str = None):
        self.gitlab_url = (gitlab_url or os.getenv("GITLAB_URL") or "http://10.4.3.10").rstrip("/")
        self.token = token or os.getenv("GITLAB_TOKEN") or ""
        self.scan_workspace = "/tmp/centinela_gitlab_scans"

    def fetch_projects(self) -> List[Dict[str, Any]]:
        """Queries GitLab REST API v4 to fetch all accessible projects."""
        url = f"{self.gitlab_url}/api/v4/projects"
        headers = {}
        if self.token:
            headers["PRIVATE-TOKEN"] = self.token
            
        params = {"per_page": 100, "simple": True, "archived": False}
        try:
            res = requests.get(url, headers=headers, params=params, timeout=10)
            if res.status_code == 200:
                projects = res.json()
                print(f"🦊 [GitLab-Integrator] Discovered {len(projects)} projects on {self.gitlab_url}.")
                return projects
            else:
                print(f"⚠️ [GitLab-Integrator] API return status {res.status_code}: {res.text}")
                return []
        except Exception as e:
            print(f"❌ [GitLab-Integrator] Failed to query GitLab API at {self.gitlab_url}: {e}")
            return []

    def clone_or_pull(self, http_url_to_repo: str, path_with_namespace: str) -> str:
        """Clones or pulls the GitLab repository into the scan workspace."""
        safe_folder = path_with_namespace.replace("/", "_")
        target_dir = os.path.join(self.scan_workspace, safe_folder)
        os.makedirs(self.scan_workspace, exist_ok=True)

        # Inject auth token into clone URL if provided
        clone_url = http_url_to_repo
        if self.token and "@" not in clone_url:
            clone_url = clone_url.replace("http://", f"http://oauth2:{self.token}@").replace("https://", f"https://oauth2:{self.token}@")

        if os.path.exists(target_dir):
            try:
                subprocess.run(["git", "-C", target_dir, "pull"], capture_output=True, timeout=60)
                print(f"🔄 [GitLab-Integrator] Pulled latest changes for {path_with_namespace}")
            except Exception as e:
                print(f"⚠️ [GitLab-Integrator] Pull failed for {path_with_namespace}, re-cloning: {e}")
                shutil.rmtree(target_dir, ignore_errors=True)
                subprocess.run(["git", "clone", "--depth", "1", clone_url, target_dir], capture_output=True, timeout=120)
        else:
            try:
                subprocess.run(["git", "clone", "--depth", "1", clone_url, target_dir], capture_output=True, timeout=120)
                print(f"📥 [GitLab-Integrator] Cloned repository {path_with_namespace}")
            except Exception as e:
                print(f"❌ [GitLab-Integrator] Failed to clone {path_with_namespace}: {e}")
                return ""

        return target_dir

    def scan_all_projects(self) -> Dict[str, Any]:
        """Fetches all GitLab projects, clones/pulls each, and executes full Omni-Audit."""
        projects = self.fetch_projects()
        summary = {
            "total_projects": len(projects),
            "scanned_projects": 0,
            "total_vulnerabilities": 0,
            "projects_breakdown": []
        }

        for proj in projects:
            path_ns = proj.get("path_with_namespace", proj.get("name", "unknown"))
            repo_url = proj.get("http_url_to_repo", "")
            if not repo_url:
                continue

            target_dir = self.clone_or_pull(repo_url, path_ns)
            if not target_dir or not os.path.exists(target_dir):
                continue

            # Register (or refresh) the asset for this project first, so every finding
            # below can be attributed to its own asset_id instead of landing unassigned.
            asset_id = None
            try:
                with db_manager.get_db_cursor() as cur:
                    cur.execute("""
                        INSERT INTO public.infra_inventory (asset_name, asset_type, endpoint, criticality, last_audit, status)
                        VALUES (%s, 'GitLab-Repo', %s, 'MEDIUM', NOW(), 'monitored')
                        ON CONFLICT (asset_name) DO UPDATE SET last_audit = NOW(), status = 'monitored'
                        RETURNING id
                    """, (f"GitLab/{path_ns}", proj.get("web_url", repo_url)))
                    row = cur.fetchone()
                    asset_id = row[0] if row else None
            except Exception as db_err:
                print(f"⚠️ [GitLab-Integrator] Error registering asset in DB: {db_err}")

            print(f"🔍 [GitLab-Integrator] Auditing GitLab Project: {path_ns} (asset_id={asset_id})...")
            sast_findings = auditor_master_vulnerabilities.run_master_vulnerability_scan(target_dir, asset_id=asset_id)
            sca_findings = auditor_sca_dependencies.run_sca_audit(target_dir, asset_id=asset_id)
            std_findings = auditor_compliance_standards.run_compliance_standards_audit(target_dir, asset_id=asset_id)
            
            try:
                from auditors import auditor_iac_k8s, auditor_cmmi_v3
                iac_findings = auditor_iac_k8s.run_iac_scan(target_dir, asset_id=asset_id)
                cmmi_findings = auditor_cmmi_v3.run_cmmi_audit(target_dir, asset_id=asset_id)
            except Exception as e:
                import traceback
                traceback.print_exc()
                print(f"⚠️ [GitLab-Integrator] IaC/CMMI audit error for {path_ns}: {e}")
                iac_findings = []
                cmmi_findings = []

            try:
                from auditors import auditor_accessibility_wcag
                wcag_findings = auditor_accessibility_wcag.run_wcag_accessibility_audit(target_dir, asset_id=asset_id)
            except Exception as e:
                import traceback
                traceback.print_exc()
                print(f"⚠️ [GitLab-Integrator] WCAG accessibility audit error for {path_ns}: {e}")
                wcag_findings = []

            try:
                from auditors import auditor_sonarqube
                sonar_findings = auditor_sonarqube.run_sonarqube_audit(
                    target_dir, asset_id=asset_id, repo_display_name=path_ns
                )
            except Exception as sonar_err:
                import traceback
                traceback.print_exc()
                print(f"⚠️ [GitLab-Integrator] SonarQube audit error for {path_ns}: {sonar_err}")
                sonar_findings = []

            # Real gap found and fixed 2026-08-25: Semgrep was never actually wired into this
            # periodic fleet-wide loop -- it was only ever invoked from auditor_ext.py's separate
            # dispatch path and by manual one-off calls. Every GitLab-Repo asset this loop covers
            # (71 at last count) had been missing Semgrep's multi-language coverage on every
            # automatic re-scan since this integration was written; expanding _LANG_RULESETS'
            # language coverage (same commit) would have been dead weight without this fix, since
            # nothing periodic would ever call it for these assets.
            try:
                semgrep_findings = auditor_semgrep.scan_path(target_dir, asset_id, path_ns)
                auditor_semgrep.persist_findings(semgrep_findings)
            except Exception as e:
                import traceback
                traceback.print_exc()
                print(f"⚠️ [GitLab-Integrator] Semgrep audit error for {path_ns}: {e}")
                semgrep_findings = []

            total_findings = len(sast_findings) + len(sca_findings) + len(std_findings) + len(iac_findings) + len(cmmi_findings) + len(sonar_findings) + len(wcag_findings) + len(semgrep_findings)
            summary["scanned_projects"] += 1
            summary["total_vulnerabilities"] += total_findings
            summary["projects_breakdown"].append({
                "id": proj.get("id"),
                "asset_id": asset_id,
                "name": path_ns,
                "web_url": proj.get("web_url"),
                "sast_count": len(sast_findings),
                "sca_count": len(sca_findings),
                "standards_count": len(std_findings),
                "sonarqube_count": len(sonar_findings),
                "total_vulnerabilities": total_findings
            })

        return summary
