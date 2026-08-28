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
        """
        Queries GitLab REST API v4 for every accessible project, following pagination.

        The previous version issued a single `per_page=100` request with no page loop -- so on
        an instance with more than 100 visible projects, every project past the first page was
        silently never scanned (no error, just missing coverage). Now walks `X-Next-Page` until
        exhausted.
        """
        url = f"{self.gitlab_url}/api/v4/projects"
        headers = {}
        if self.token:
            headers["PRIVATE-TOKEN"] = self.token

        projects: List[Dict[str, Any]] = []
        page = 1
        try:
            while True:
                params = {"per_page": 100, "page": page, "simple": True, "archived": False}
                res = requests.get(url, headers=headers, params=params, timeout=15)
                if res.status_code != 200:
                    print(f"⚠️ [GitLab-Integrator] API return status {res.status_code} on page {page}: {res.text[:200]}")
                    break
                batch = res.json()
                if not batch:
                    break
                projects.extend(batch)
                next_page = res.headers.get("X-Next-Page")
                if not next_page:
                    break
                page = int(next_page)
            print(f"🦊 [GitLab-Integrator] Discovered {len(projects)} projects on {self.gitlab_url} (across {page} page(s)).")
            return projects
        except Exception as e:
            print(f"❌ [GitLab-Integrator] Failed to query GitLab API at {self.gitlab_url}: {e}")
            return projects

    # Branch names (case-insensitive, exact match) that hold the real integration code when a
    # project keeps its default branch as a near-empty release/stub branch. Real case, this
    # instance's `edomex-casmart` group: every project's `main` is just a README (or a lone
    # .gitlab-ci.yml) while all the actual source lives on `develop` -- a `--depth 1` clone of
    # the default branch was scanning empty repos and reporting "audited, ~0 findings".
    _PREFERRED_BRANCHES = ("develop", "development", "desarrollo", "dev")

    def pick_branch(self, project_id) -> str:
        """
        Returns the branch most likely to contain the real code: a develop-style branch if the
        project has one, otherwise the project's own default branch. Best-effort -- any API
        failure returns "" and the caller falls back to a plain default-branch clone.
        """
        if not project_id:
            return ""
        headers = {"PRIVATE-TOKEN": self.token} if self.token else {}
        # Retry a couple of times -- a transient API hiccup here used to return "", which made
        # clone_or_pull fall back to the default branch and (via its pull-fails-> re-clone path)
        # destroy a good develop-branch clone from a prior run.
        for attempt in range(3):
            try:
                br = requests.get(f"{self.gitlab_url}/api/v4/projects/{project_id}/repository/branches",
                                  headers=headers, params={"per_page": 100}, timeout=15)
                if br.status_code != 200:
                    continue
                names = [b["name"] for b in br.json()]
                lower = {n.lower(): n for n in names}
                for pref in self._PREFERRED_BRANCHES:
                    if pref in lower:
                        return lower[pref]
                proj = requests.get(f"{self.gitlab_url}/api/v4/projects/{project_id}",
                                    headers=headers, timeout=15)
                if proj.status_code == 200:
                    return proj.json().get("default_branch", "") or ""
                return ""
            except Exception as e:
                print(f"⚠️ [GitLab-Integrator] Branch resolve attempt {attempt + 1}/3 failed for project {project_id}: {e}")
        return ""

    def clone_or_pull(self, http_url_to_repo: str, path_with_namespace: str, branch: str = "") -> str:
        """Clones or pulls the GitLab repository (a specific branch if given) into the scan workspace."""
        safe_folder = path_with_namespace.replace("/", "_")
        target_dir = os.path.join(self.scan_workspace, safe_folder)
        os.makedirs(self.scan_workspace, exist_ok=True)

        # Inject auth token into clone URL if provided
        clone_url = http_url_to_repo
        if self.token and "@" not in clone_url:
            clone_url = clone_url.replace("http://", f"http://oauth2:{self.token}@").replace("https://", f"https://oauth2:{self.token}@")

        clone_cmd = ["git", "clone", "--depth", "1"]
        if branch:
            clone_cmd += ["--branch", branch]
        clone_cmd += [clone_url, target_dir]

        def _current_branch():
            r = subprocess.run(["git", "-C", target_dir, "rev-parse", "--abbrev-ref", "HEAD"],
                               capture_output=True, text=True, timeout=30)
            return r.stdout.strip()

        if os.path.exists(target_dir):
            cur = _current_branch()
            # If a previous run cloned a different branch (e.g. the old code always took the
            # default branch), the checked-out tree is stale/wrong -- re-clone rather than try
            # to switch a shallow clone in place.
            if branch and cur and cur != branch:
                print(f"🔀 [GitLab-Integrator] {path_with_namespace}: switching branch "
                      f"{cur!r} -> {branch!r}, re-cloning.")
                shutil.rmtree(target_dir, ignore_errors=True)
                subprocess.run(clone_cmd, capture_output=True, timeout=120)
            else:
                # When branch couldn't be resolved (transient API failure -> branch=""), keep
                # whatever branch this clone is already on -- pulling it, and re-cloning that
                # SAME branch on failure -- instead of silently falling back to the default
                # branch and destroying a good non-default clone.
                effective_branch = branch or cur
                recl = ["git", "clone", "--depth", "1"]
                if effective_branch:
                    recl += ["--branch", effective_branch]
                recl += [clone_url, target_dir]
                try:
                    subprocess.run(["git", "-C", target_dir, "pull"], capture_output=True, timeout=60)
                    print(f"🔄 [GitLab-Integrator] Pulled latest changes for {path_with_namespace} ({effective_branch or 'default'})")
                except Exception as e:
                    print(f"⚠️ [GitLab-Integrator] Pull failed for {path_with_namespace}, re-cloning ({effective_branch or 'default'}): {e}")
                    shutil.rmtree(target_dir, ignore_errors=True)
                    subprocess.run(recl, capture_output=True, timeout=120)
        else:
            try:
                subprocess.run(clone_cmd, capture_output=True, timeout=120)
                print(f"📥 [GitLab-Integrator] Cloned repository {path_with_namespace} ({branch or 'default'})")
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

            branch = self.pick_branch(proj.get("id"))
            target_dir = self.clone_or_pull(repo_url, path_ns, branch=branch)
            if not target_dir or not os.path.exists(target_dir):
                continue

            # Register (or refresh) the asset for this project first, so every finding
            # below can be attributed to its own asset_id instead of landing unassigned.
            #
            # Real incident 2026-08-27: a transient "server closed the connection unexpectedly"
            # from the pool during this registration was caught here, `asset_id` stayed None,
            # and the ENTIRE repo scan below then ran unattributed -- ~2,560 orphan findings
            # (2,239 SonarQube alone) piled up over ~13h, invisible to every asset-scoped view
            # and never AI-correlated (the correlation query JOINs infra_inventory). Retry the
            # registration a couple of times (a dead pooled connection is discarded on the next
            # getconn), and if it still fails, SKIP this repo for this cycle rather than scan it
            # with asset_id=None -- it will be picked up cleanly on the next pass. Rule #6: never
            # proceed on a swallowed error with a false "success" state.
            asset_id = None
            last_err = None
            for attempt in range(3):
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
                    if asset_id is not None:
                        break
                except Exception as db_err:
                    last_err = db_err
                    print(f"⚠️ [GitLab-Integrator] Asset registration attempt {attempt + 1}/3 failed for {path_ns}: {db_err}")

            if asset_id is None:
                print(f"⏭️ [GitLab-Integrator] SKIPPING {path_ns} this cycle -- could not register "
                      f"its asset ({last_err}); will retry next pass. NOT scanning unattributed.")
                continue

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
