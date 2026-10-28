import logging
"""
Centinela GitLab Integration & Automated Repository Auditor
Discovers, clones, and audits all projects from a GitLab instance (SAST, SCA, IaC, Standards).
"""
import os
import shutil
import subprocess
import requests
from typing import List, Dict, Any, Union, Optional
from auditors import auditor_master_vulnerabilities, auditor_sca_dependencies, auditor_compliance_standards, auditor_semgrep
from core import db_manager, gitlab_instances

DEFAULT_MONITORED_BRANCHES = ("develop", "desarrollo", "main", "master", "dev", "development")

def is_monitored_branch(branch_name: str) -> bool:
    """
    Checks if a given branch name matches the monitored branches list (develop, desarrollo, main, master, etc.).
    Supports customization via GITLAB_MONITORED_BRANCHES env var (comma-separated).
    """
    if not branch_name:
        return False
    custom = os.getenv("GITLAB_MONITORED_BRANCHES", "")
    if custom:
        monitored = {b.strip().lower() for b in custom.split(",") if b.strip()}
    else:
        monitored = {b.lower() for b in DEFAULT_MONITORED_BRANCHES}
    return branch_name.lower().strip() in monitored



class GitLabIntegrator:
    def __init__(self, gitlab_url: str = None, token: str = None, instance: str = None):
        """`instance` selects a configured GitLab (core.gitlab_instances: "primary", "gitlab2", ...).
        An explicit gitlab_url/token override (the manual /api/gitlab/scan body) wins and is attributed
        to whichever configured instance owns that host, or to "primary" naming if none does."""
        from core import gitlab_instances
        if gitlab_url:
            inst = gitlab_instances.instance_for_host(gitlab_url) or gitlab_instances.get_instance(None)
            self.instance = inst._replace(url=gitlab_url.rstrip("/"), token=token or inst.token)
        else:
            inst = gitlab_instances.get_instance(instance)
            self.instance = inst._replace(token=token or inst.token)
        self.gitlab_url = self.instance.url
        self.token = self.instance.token
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
    # instance's a customer group: every project's `main` is just a README (or a lone
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

    def clone_or_pull(self, http_url_to_repo: str, path_with_namespace: str, branch: str = "", separate_folder: bool = False) -> str:
        """Clones or pulls the GitLab repository (a specific branch if given) into the scan workspace.
        separate_folder=True keeps this branch in its own clone folder, so auditing a branch on its own never
        disturbs (or re-clones over) the project's regular clone."""
        safe_folder = self.instance.clone_folder(path_with_namespace, branch if separate_folder and branch else None)
        target_dir = os.path.join(self.scan_workspace, safe_folder)
        os.makedirs(self.scan_workspace, exist_ok=True)

        # Inject auth token into clone URL if provided -- but ONLY for our own GitLab host.
        # A repo URL can originate from an untrusted payload; embedding the token into an
        # arbitrary host's URL would hand that host our credential.
        from urllib.parse import urlparse
        clone_url = http_url_to_repo
        if urlparse(clone_url).netloc.split("@")[-1].lower() != urlparse(self.gitlab_url).netloc.lower():
            print(f"🚫 [GitLab-Integrator] Refusing to clone {path_with_namespace}: repo host "
                  f"'{urlparse(clone_url).netloc}' is not the configured GitLab host '{urlparse(self.gitlab_url).netloc}'.")
            return ""
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

    def get_project_details(self, project_id_or_path: Union[int, str]) -> Optional[Dict[str, Any]]:
        """Queries GitLab REST API v4 for project metadata by ID or URL-encoded path."""
        headers = {}
        if self.token:
            headers["PRIVATE-TOKEN"] = self.token
        try:
            pid = requests.utils.quote(str(project_id_or_path), safe='') if isinstance(project_id_or_path, str) else project_id_or_path
            url = f"{self.gitlab_url}/api/v4/projects/{pid}"
            res = requests.get(url, headers=headers, timeout=15)
            if res.status_code == 200:
                return res.json()
            print(f"⚠️ [GitLab-Integrator] get_project_details status {res.status_code} for {project_id_or_path}: {res.text[:200]}")
            return None
        except Exception as e:
            import traceback
            traceback.print_exc()
            print(f"❌ [GitLab-Integrator] Failed to get project details for {project_id_or_path}: {e}")
            return None

    def list_branches(self, project_id) -> List[Dict[str, Any]]:
        """Branches of a project straight from GitLab (name, default flag, protected flag, last commit date). Raises on API
        failure so callers never mistake 'could not ask' for 'has no branches'."""
        headers = {"PRIVATE-TOKEN": self.token} if self.token else {}
        pid = requests.utils.quote(str(project_id), safe='')
        out: List[Dict[str, Any]] = []
        page = 1
        while True:
            res = requests.get(f"{self.gitlab_url}/api/v4/projects/{pid}/repository/branches",
                               headers=headers, params={"per_page": 100, "page": page}, timeout=20)
            if res.status_code != 200:
                raise RuntimeError(f"GitLab devolvió {res.status_code} al listar ramas de {project_id}: {res.text[:200]}")
            for b in res.json():
                out.append({"name": b.get("name"), "default": bool(b.get("default")), "protected": bool(b.get("protected")),
                            "last_commit_at": (b.get("commit") or {}).get("committed_date")})
            nxt = res.headers.get("X-Next-Page")
            if not nxt:
                break
            page = int(nxt)
        return out

    def scan_single_project(self, project: Union[Dict[str, Any], int, str], branch: str = "", separate_asset: bool = False) -> Dict[str, Any]:
        """
        Clones/pulls and audits a single GitLab project on a specific branch (or best-effort resolved branch).
        Accepts a project metadata dict or a project ID / path.

        Every scan registers its asset WITH the branch it audited: "GitLab/<path>@<branch>", in a clone folder of its own, so the findings
        of different branches never overwrite or reconcile away each other.
        separate_asset=True (requires `branch`): a branch picked on purpose (not the one the fleet scan resolves on its own). Project-level
        checks that do not depend on the branch (GitLab settings/CI audit, CMMI process evidence) are not repeated for it.
        """
        proj = project if isinstance(project, dict) else self.get_project_details(project)
        if not proj:
            print(f"❌ [GitLab-Integrator] Cannot scan project: project details not found for {project}")
            return {"status": "error", "reason": "project_not_found", "project": project}

        path_ns = proj.get("path_with_namespace", proj.get("name", "unknown"))
        repo_url = proj.get("http_url_to_repo") or proj.get("git_http_url") or proj.get("http_url", "")
        if not repo_url:
            print(f"⚠️ [GitLab-Integrator] Missing repository URL for project {path_ns}")
            return {"status": "error", "reason": "missing_repo_url", "name": path_ns}

        if separate_asset and not branch:
            return {"status": "error", "reason": "separate_asset requires an explicit branch", "name": path_ns}
        effective_branch = branch or self.pick_branch(proj.get("id"))
        if not effective_branch:
            # pick_branch is best-effort ("" on an API failure); fall back to the project's own default branch. Never register a branchless
            # asset: it would be a duplicate of the "@branch" one the next time the branch resolves.
            effective_branch = proj.get("default_branch") or (self.get_project_details(proj.get("id")) or {}).get("default_branch") or ""
        if not effective_branch:
            print(f"⚠️ [GitLab-Integrator] {path_ns}: could not resolve which branch to audit; skipped this cycle (retried on the next one).")
            return {"status": "error", "reason": "branch_unresolved", "name": path_ns}
        target_dir = self.clone_or_pull(repo_url, path_ns, branch=effective_branch, separate_folder=True)
        if not target_dir or not os.path.exists(target_dir):
            # A repository with no commits cannot be cloned and has nothing to audit: that is not an error (seen live: 3 empty projects
            # failed 130 times each). Ask GitLab before reporting a failure.
            details = self.get_project_details(proj.get("id")) if proj.get("id") else None
            if details and details.get("empty_repo"):
                print(f"ℹ️ [GitLab-Integrator] {path_ns} is an empty repository (no commits); nothing to audit")
                return {"status": "skipped", "reason": "empty_repo", "name": path_ns}
            print(f"❌ [GitLab-Integrator] Clone/pull failed for {path_ns} ({effective_branch})")
            return {"status": "error", "reason": "clone_or_pull_failed", "name": path_ns, "branch": effective_branch}

        # Register (or refresh) the asset for this project first, so every finding
        # below can be attributed to its own asset_id instead of landing unassigned.
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
                    """, (self.instance.asset_name(path_ns, effective_branch), proj.get("web_url", repo_url)))
                    row = cur.fetchone()
                    asset_id = row[0] if row else None
                if asset_id is not None:
                    break
            except Exception as db_err:
                last_err = db_err
                print(f"⚠️ [GitLab-Integrator] Asset registration attempt {attempt + 1}/3 failed for {path_ns}: {db_err}")

        if asset_id is None:
            print(f"⏭️ [GitLab-Integrator] SKIPPING {path_ns} -- could not register its asset ({last_err}); NOT scanning unattributed.")
            return {"status": "error", "reason": f"asset registration failed: {last_err}", "name": path_ns, "project_id": proj.get("id")}

        print(f"🔍 [GitLab-Integrator] Auditing GitLab Project: {path_ns} ({effective_branch or 'default'}) [asset_id={asset_id}]...")
        # Baseline of what was open before this scan: feeds the "última versión vs anterior" comparison (core/scan_comparison.py).
        from core import scan_comparison
        scan_run_id = scan_comparison.open_run(asset_id, f"gitlab:{self.instance.key}", scan_comparison.git_head(target_dir))
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

        # Dependency licenses (syft inventory -> copyleft / restricted / unknown). Legal risk, stored INFORMATIONAL. Added 2026-10-12: nothing in the
        # fleet pipeline looked at licenses before.
        try:
            from auditors import auditor_licenses
            license_findings = auditor_licenses.run_license_audit(target_dir, asset_id=asset_id, display_name=path_ns)
        except Exception as e:
            import traceback
            traceback.print_exc()
            print(f"⚠️ [GitLab-Integrator] License audit error for {path_ns}: {e}")
            license_findings = []

        try:
            from auditors import auditor_sonarqube
            sonar_findings = auditor_sonarqube.run_sonarqube_audit(
                target_dir, asset_id=asset_id,
                repo_display_name=f"{path_ns}@{gitlab_instances.branch_slug(branch)}" if separate_asset else path_ns
            )
        except Exception as sonar_err:
            import traceback
            traceback.print_exc()
            print(f"⚠️ [GitLab-Integrator] SonarQube audit error for {path_ns}: {sonar_err}")
            sonar_findings = []

        try:
            semgrep_findings = auditor_semgrep.scan_path(target_dir, asset_id, path_ns)
            auditor_semgrep.persist_findings(semgrep_findings)
        except Exception as e:
            import traceback
            traceback.print_exc()
            print(f"⚠️ [GitLab-Integrator] Semgrep audit error for {path_ns}: {e}")
            semgrep_findings = []

        try:
            from auditors import auditor_authz
            authz_findings = auditor_authz.run_authz_audit(target_dir, asset_id=asset_id)
        except Exception as e:
            import traceback
            traceback.print_exc()
            print(f"⚠️ [GitLab-Integrator] Authz audit error for {path_ns}: {e}")
            authz_findings = []

        # Application profiles (roles) found in the code and in the migration seeds: names only, they feed the "credenciales de prueba" dropdown.
        try:
            from auditors import role_discovery
            roles = role_discovery.discover_roles(target_dir)
            with db_manager.get_db_cursor() as cur:
                role_discovery.persist_roles(cur, asset_id, roles)
            print(f"👤 [GitLab-Integrator] {len(roles)} application profile(s) discovered for {path_ns}")
        except Exception:
            logging.getLogger(__name__).error("role discovery failed for %s", path_ns, exc_info=True)

        # External dependencies declared in the configuration (host:port) that do not answer from Centinela's network.
        try:
            from auditors import auditor_dependency_probe
            dep_findings = auditor_dependency_probe.run_dependency_probe(target_dir, asset_id=asset_id)
        except Exception:
            logging.getLogger(__name__).error("dependency probe failed for %s", path_ns, exc_info=True)
            dep_findings = []

        # API contract drift (routes in the code vs the versioned OpenAPI/Swagger). Added 2026-10-12.
        try:
            from auditors import auditor_api_contract
            api_contract_findings = auditor_api_contract.run_api_contract_audit(target_dir, asset_id=asset_id, display_name=path_ns)
        except Exception as e:
            import traceback
            traceback.print_exc()
            print(f"⚠️ [GitLab-Integrator] API contract audit error for {path_ns}: {e}")
            api_contract_findings = []

        # Dockerfile / Kubernetes / Terraform misconfigurations (`trivy config`).
        try:
            from auditors import auditor_trivy_config
            trivy_cfg_findings = auditor_trivy_config.run_trivy_config_audit(target_dir, asset_id=asset_id, display_name=path_ns)
        except Exception as e:
            import traceback
            traceback.print_exc()
            print(f"⚠️ [GitLab-Integrator] trivy config audit error for {path_ns}: {e}")
            trivy_cfg_findings = []

        # Project-level checks (GitLab settings / CI file, CMMI process evidence) describe the project, not a branch: a branch asset skips them.
        gitlab_cfg_findings = []
        if not separate_asset:
            try:
                from auditors import auditor_gitlab_config
                cfg_res = auditor_gitlab_config.audit_project(proj, target_dir, gitlab_url=self.gitlab_url, token=self.token)
                gitlab_cfg_findings = cfg_res["findings"]
                auditor_gitlab_config.log_gitlab_config_findings(asset_id, path_ns, cfg_res)
            except Exception as e:
                import traceback
                traceback.print_exc()
                print(f"⚠️ [GitLab-Integrator] GitLab config/CI audit error for {path_ns}: {e}")
                gitlab_cfg_findings = []

            # CMMI evidence (DECISIONS/0007 phase A): PR / VV / CM / TS / PI / DAR items measured from this project's GitLab data and
            # clone. Separate from the findings above; a failure here never blocks the scan, but it is logged with its traceback.
            try:
                from auditors import auditor_cmmi_evidence
                auditor_cmmi_evidence.collect_asset_evidence(asset_id, self.instance.asset_name(path_ns, effective_branch), self.instance, proj, branch=effective_branch)
            except Exception as e:
                import traceback
                traceback.print_exc()
                print(f"⚠️ [GitLab-Integrator] CMMI evidence collection error for {path_ns}: {e}")

        total_findings = (
            len(sast_findings) + len(sca_findings) + len(std_findings) +
            len(iac_findings) + len(cmmi_findings) + len(sonar_findings) +
            len(wcag_findings) + len(semgrep_findings) + len(authz_findings) + len(gitlab_cfg_findings) + len(license_findings) + len(api_contract_findings) + len(trivy_cfg_findings)
        )

        scan_comparison.close_run(scan_run_id, True)
        return {
            "status": "success",
            "id": proj.get("id"),
            "project_id": proj.get("id"),
            "asset_id": asset_id,
            "name": path_ns,
            "path_with_namespace": path_ns,
            "branch": effective_branch,
            "asset_name": self.instance.asset_name(path_ns, effective_branch),
            "web_url": proj.get("web_url"),
            "sast_count": len(sast_findings),
            "sca_count": len(sca_findings),
            "standards_count": len(std_findings),
            "iac_count": len(iac_findings),
            "cmmi_count": len(cmmi_findings),
            "wcag_count": len(wcag_findings),
            "sonarqube_count": len(sonar_findings),
            "semgrep_count": len(semgrep_findings),
            "authz_count": len(authz_findings),
            "gitlab_config_count": len(gitlab_cfg_findings),
            "total_vulnerabilities": total_findings
        }

    def scan_all_projects(self) -> Dict[str, Any]:
        """Fetches all GitLab projects, clones/pulls each, and executes full Omni-Audit."""
        projects = self.fetch_projects()
        summary = {
            "total_projects": len(projects),
            "scanned_projects": 0,
            "total_vulnerabilities": 0,
            "projects_breakdown": []
        }

        from core import gitlab_instances
        exclusions = gitlab_instances.scan_exclusions()
        for proj in projects:
            if gitlab_instances.is_scan_excluded(self.instance, proj.get("path_with_namespace") or "", exclusions):
                continue
            res = self.scan_single_project(proj)
            if res.get("status") == "success":
                summary["scanned_projects"] += 1
                summary["total_vulnerabilities"] += res.get("total_vulnerabilities", 0)
                summary["projects_breakdown"].append({
                    "id": res.get("project_id"),
                    "asset_id": res.get("asset_id"),
                    "name": res.get("path_with_namespace"),
                    "web_url": proj.get("web_url"),
                    "branch": res.get("branch"),
                    "sast_count": res.get("sast_count", 0),
                    "sca_count": res.get("sca_count", 0),
                    "standards_count": res.get("standards_count", 0),
                    "sonarqube_count": res.get("sonarqube_count", 0),
                    "total_vulnerabilities": res.get("total_vulnerabilities", 0)
                })

        return summary



def scan_all_instances() -> Dict[str, Any]:
    """Full scan of every configured GitLab instance. A failure on one instance (unreachable, bad
    token) is logged with its traceback and never prevents the others from being scanned."""
    from core import gitlab_instances
    import traceback
    combined: Dict[str, Any] = {"instances": {}, "total_projects": 0, "scanned_projects": 0, "total_vulnerabilities": 0}
    for inst in gitlab_instances.configured_instances():
        try:
            res = GitLabIntegrator(instance=inst.key).scan_all_projects()
        except Exception as e:
            traceback.print_exc()
            print(f"❌ [GitLab-Integrator] Instance '{inst.key}' ({inst.url}) scan failed: {e}")
            combined["instances"][inst.key] = {"error": str(e)}
            continue
        combined["instances"][inst.key] = {k: res.get(k) for k in ("total_projects", "scanned_projects", "total_vulnerabilities")}
        for k in ("total_projects", "scanned_projects", "total_vulnerabilities"):
            combined[k] += res.get(k, 0) or 0
    return combined


# --- persistent job queue integration (ADR-0008 #4) -------------------------------------------------------------------------
GITLAB_JOB_KIND = "gitlab_project"


def enqueue_fleet_scan(min_interval_hours: float = None) -> Dict[str, Any]:
    """Queue one scan job per project of every configured GitLab instance. Idempotent: a project already queued/running is skipped, and so
    is one already scanned in the current daily window (since the last GITLAB_SCAN_DAILY_AT, default 03:00 SCAN_TIMEZONE, see
    core.scan_schedule). With GITLAB_SCAN_DAILY_AT empty, or an explicit min_interval_hours, the rolling interval applies instead
    (GITLAB_RESCAN_HOURS, default 24). A failure on one instance never blocks the others."""
    from core import gitlab_instances, job_queue, scan_schedule
    import traceback
    cutoff = scan_schedule.configured_fleet_cutoff() if min_interval_hours is None else None
    hours = 0 if cutoff else (float(os.getenv("GITLAB_RESCAN_HOURS", "24")) if min_interval_hours is None else min_interval_hours)
    summary: Dict[str, Any] = {"projects_seen": 0, "enqueued": 0, "skipped": 0, "instances_failed": []}
    for inst in gitlab_instances.configured_instances():
        try:
            projects = GitLabIntegrator(instance=inst.key).fetch_projects()
        except Exception as e:
            traceback.print_exc()
            summary["instances_failed"].append(inst.key)
            print(f"❌ [GitLab-Integrator] Cannot list projects of instance '{inst.key}': {e}")
            continue
        exclusions = gitlab_instances.scan_exclusions()
        for proj in projects:
            summary["projects_seen"] += 1
            if gitlab_instances.is_scan_excluded(inst, proj.get("path_with_namespace") or "", exclusions):
                summary["excluded"] = summary.get("excluded", 0) + 1
                continue
            target = f"{inst.key}:{proj.get('path_with_namespace') or proj.get('id')}"
            job_id = job_queue.enqueue(GITLAB_JOB_KIND, target, {"instance": inst.key, "project": proj},
                                       min_interval_hours=hours, not_finished_since=cutoff)
            summary["enqueued" if job_id else "skipped"] += 1
    return summary


def run_scan_job(job: Dict[str, Any]) -> Dict[str, Any]:
    """Execute one queued project scan. Raises when the scan did not succeed, so the queue records the failure and retries."""
    payload = job["payload"]
    from core import gitlab_instances
    integ = GitLabIntegrator(instance=payload["instance"])
    path_ns = (payload.get("project") or {}).get("path_with_namespace") or ""
    # A periodic job queued before the project was excluded is dropped here; a branch scan a person asked for (separate_asset) still runs.
    if not payload.get("separate_asset") and gitlab_instances.is_scan_excluded(integ.instance, path_ns):
        print(f"⏭️ [GitLab-Integrator] {path_ns}: excluded from periodic scanning (config/gitlab_scan_exclude.txt); job dropped")
        return {"status": "skipped", "reason": "excluded", "name": path_ns}
    res = integ.scan_single_project(
        payload["project"], branch=payload.get("branch") or "", separate_asset=bool(payload.get("separate_asset")))
    if res.get("status") == "skipped":      # e.g. empty repository: a legitimate, final outcome -> the job is DONE, not a failure
        return res
    if res.get("status") != "success":
        raise RuntimeError(f"scan of {job['target']} did not succeed: {res.get('reason') or res}")
    return res


def enqueue_branch_scan(project_id, branch: str, instance: Optional[str] = None) -> Dict[str, Any]:
    """Queue an audit of ONE branch as its own asset ("GitLab/<path>@<branch>"). Validates the branch against GitLab first, so a typo
    is rejected here instead of failing later in the worker. Returns the asset name the findings will appear under."""
    from core import job_queue
    integ = GitLabIntegrator(instance=instance)
    proj = integ.get_project_details(project_id)
    if not proj:
        raise LookupError(f"Proyecto {project_id} no encontrado en la instancia '{integ.instance.key}'")
    names = {b["name"] for b in integ.list_branches(proj["id"])}
    if branch not in names:
        raise ValueError(f"La rama '{branch}' no existe en {proj.get('path_with_namespace')}")
    path_ns = proj["path_with_namespace"]
    job_id = job_queue.enqueue(GITLAB_JOB_KIND, f"{integ.instance.key}:{path_ns}@{branch}",
                               {"instance": integ.instance.key, "project": proj, "branch": branch, "separate_asset": True,
                                "priority": 10})  # asked for by a person: ahead of the periodic fleet backlog
    return {"job_id": job_id, "already_queued": job_id is None, "asset_name": integ.instance.asset_name(path_ns, branch),
            "project": path_ns, "branch": branch}
