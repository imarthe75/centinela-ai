"""
Centinela GitLab Auto-Fixer / Merge Request Generator

Clones the affected repo, applies a real fix (deterministic patch for well-defined mechanical
cases, or an AI-generated unified diff for anything requiring code understanding), pushes it to
a new branch, and opens a Merge Request for human review. Never commits directly to the
default branch.

Rewritten because the previous version was non-functional end-to-end: it referenced `re`
without importing it, never cloned/edited/committed/pushed anything, and called the GitLab MR
API with a `source_branch` that was never actually created (which GitLab has always rejected) --
opening a Merge Request without first pushing that branch does not, and cannot, work.
"""
import os
import re
import shutil
import subprocess
import tempfile
from typing import Dict, Any, Optional
from psycopg2.extras import RealDictCursor
from core import db_manager

# Deterministic patchers: safe, mechanical fixes that don't require an LLM. Each takes the
# cloned repo dir + the vulnerability row and returns (changed: bool, summary: str).


def _find_dockerfiles(repo_dir: str, hint_path: str = None):
    if hint_path:
        candidate = os.path.join(repo_dir, hint_path)
        if os.path.exists(candidate):
            return [candidate]
    found = []
    for root, dirs, files in os.walk(repo_dir):
        if ".git" in root:
            continue
        for f in files:
            if f == "Dockerfile" or f.startswith("Dockerfile."):
                found.append(os.path.join(root, f))
    return found


def patch_dockerfile_non_root_user(repo_dir: str, vuln: Dict[str, Any]):
    """Adds (or fixes) a non-root USER directive in the Dockerfile(s)."""
    hint = (vuln.get("url_path") or "").split(":")[0]
    dockerfiles = _find_dockerfiles(repo_dir, hint)
    if not dockerfiles:
        return False, "No se encontró ningún Dockerfile en el repositorio."

    changed_any = False
    for path in dockerfiles:
        with open(path, "r") as f:
            lines = f.read().splitlines()

        has_user = any(l.strip().startswith("USER") for l in lines)
        is_root_user = any(l.strip() in ("USER root", "USER 0") for l in lines)

        if has_user and not is_root_user:
            continue  # already has a real non-root USER, nothing to do for this file

        new_lines = []
        if is_root_user:
            for l in lines:
                if l.strip() in ("USER root", "USER 0"):
                    new_lines.append("USER appuser")
                else:
                    new_lines.append(l)
        else:
            # No USER instruction at all: insert user creation + USER right before the first
            # CMD/ENTRYPOINT (the conventional place), or at the end if neither exists.
            insert_idx = len(lines)
            for i, l in enumerate(lines):
                if l.strip().startswith("CMD") or l.strip().startswith("ENTRYPOINT"):
                    insert_idx = i
                    break
            new_lines = (
                lines[:insert_idx]
                + ["", "RUN useradd -m -u 10001 appuser", "USER appuser", ""]
                + lines[insert_idx:]
            )

        with open(path, "w") as f:
            f.write("\n".join(new_lines) + "\n")
        changed_any = True

    if not changed_any:
        return False, "El/los Dockerfile(s) ya tenían un USER no-root válido."
    return True, f"Se agregó/corrigió la directiva USER no-root en {len(dockerfiles)} Dockerfile(s)."


def patch_dependency_bump(repo_dir: str, vuln: Dict[str, Any]):
    """
    Bumps a vulnerable dependency to the known-fixed version. Parses the package/
    installed_version/fixed_version/manifest fields auditor_sca_dependencies.py embeds into the
    description (see its Fix Set 1 update) rather than re-deriving them.
    """
    desc = vuln.get("description", "") or ""

    def extract(label):
        m = re.search(rf"\*\*{label}:\*\*\s*(.+)", desc)
        return m.group(1).strip() if m else None

    package = extract("Paquete")
    fixed_version = extract("Versión segura")
    manifest = extract("Manifiesto")
    file_hint = (vuln.get("url_path") or "").split(":")[0]

    if not (package and fixed_version and manifest):
        return False, "No se pudo determinar paquete/versión segura/manifiesto desde el hallazgo."

    manifest_path = os.path.join(repo_dir, file_hint) if file_hint else None
    if not manifest_path or not os.path.exists(manifest_path):
        # Fall back to searching for the manifest by name.
        for root, _, files in os.walk(repo_dir):
            if ".git" in root:
                continue
            if manifest in files:
                manifest_path = os.path.join(root, manifest)
                break
    if not manifest_path or not os.path.exists(manifest_path):
        return False, f"No se encontró {manifest} en el repositorio."

    with open(manifest_path, "r") as f:
        content = f.read()

    if manifest == "requirements.txt":
        new_content, n = re.subn(
            rf"^{re.escape(package)}\s*(==|<=|>=|<|>)?\s*[0-9a-zA-Z.]*",
            f"{package}=={fixed_version}",
            content,
            flags=re.IGNORECASE | re.MULTILINE,
        )
    elif manifest == "package.json":
        new_content, n = re.subn(
            rf'("{re.escape(package)}"\s*:\s*")[^"]*(")',
            rf"\g<1>^{fixed_version}\g<2>",
            content,
            flags=re.IGNORECASE,
        )
    else:
        return False, f"Tipo de manifiesto no soportado para bump automático: {manifest}"

    if n == 0:
        return False, f"No se encontró '{package}' en {manifest} para actualizar."

    with open(manifest_path, "w") as f:
        f.write(new_content)
    return True, f"{package} actualizado a {fixed_version} en {manifest}."


DETERMINISTIC_PATCHERS = {
    "DOCKER-MISSING-NON-ROOT-USER": patch_dockerfile_non_root_user,
    "DOCKER-ROOT-USER": patch_dockerfile_non_root_user,
}


class GitLabAutoFixer:
    def __init__(self, gitlab_url: str = None, token: str = None):
        self.gitlab_url = (gitlab_url or os.getenv("GITLAB_URL") or "http://10.4.3.10").rstrip("/")
        self.token = token or os.getenv("GITLAB_TOKEN") or ""
        self.workspace = "/tmp/centinela_gitlab_autofix"

    def _clone(self, http_url_to_repo: str, path_with_namespace: str) -> Optional[str]:
        safe_folder = path_with_namespace.replace("/", "_")
        target_dir = os.path.join(self.workspace, safe_folder)
        os.makedirs(self.workspace, exist_ok=True)
        shutil.rmtree(target_dir, ignore_errors=True)  # always start from a clean clone

        clone_url = http_url_to_repo
        if self.token and "@" not in clone_url:
            clone_url = clone_url.replace("http://", f"http://oauth2:{self.token}@").replace(
                "https://", f"https://oauth2:{self.token}@"
            )

        # Full (non-shallow) clone: a shallow --depth 1 clone has no branch history to push a
        # new branch from cleanly in every GitLab setup, and this repo is only used transiently.
        result = subprocess.run(["git", "clone", clone_url, target_dir], capture_output=True, text=True, timeout=180)
        if result.returncode != 0:
            print(f"❌ [GitLab-AutoFix] Clone failed for {path_with_namespace}: {result.stderr}")
            return None
        return target_dir

    def _push_branch(self, repo_dir: str, branch_name: str, commit_msg: str) -> bool:
        def run(*args):
            return subprocess.run(["git", "-C", repo_dir] + list(args), capture_output=True, text=True, timeout=60)

        run("checkout", "-b", branch_name)
        run("add", "-A")
        commit = run("-c", "user.email=centinela-ai@casmart.internal", "-c", "user.name=Centinela AI",
                      "commit", "-m", commit_msg)
        if commit.returncode != 0:
            print(f"⚠️ [GitLab-AutoFix] Nothing to commit or commit failed: {commit.stderr}")
            return False
        push = run("push", "-u", "origin", branch_name)
        if push.returncode != 0:
            print(f"❌ [GitLab-AutoFix] Push failed: {push.stderr}")
            return False
        return True

    def _resolve_project_id(self, path_with_namespace: str) -> Optional[int]:
        import requests
        from urllib.parse import quote

        url = f"{self.gitlab_url}/api/v4/projects/{quote(path_with_namespace, safe='')}"
        headers = {"PRIVATE-TOKEN": self.token} if self.token else {}
        try:
            res = requests.get(url, headers=headers, timeout=10)
            if res.status_code == 200:
                return res.json().get("id")
        except Exception as e:
            print(f"⚠️ [GitLab-AutoFix] Could not resolve project id for {path_with_namespace}: {e}")
        return None

    def create_merge_request(self, project_id: int, source_branch: str, target_branch: str, title: str, description: str) -> Dict[str, Any]:
        import requests

        url = f"{self.gitlab_url}/api/v4/projects/{project_id}/merge_requests"
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["PRIVATE-TOKEN"] = self.token
        payload = {
            "source_branch": source_branch,
            "target_branch": target_branch,
            "title": title,
            "description": description,
            "remove_source_branch": True,
        }
        try:
            res = requests.post(url, json=payload, headers=headers, timeout=10)
            if res.status_code in (200, 201):
                mr_data = res.json()
                print(f"✅ [GitLab-AutoFix] Opened Merge Request !{mr_data.get('iid')}: {mr_data.get('web_url')}")
                return {"status": "created", "url": mr_data.get("web_url"), "iid": mr_data.get("iid")}
            print(f"⚠️ [GitLab-AutoFix] GitLab MR creation failed ({res.status_code}): {res.text}")
            return {"status": "failed", "detail": res.text}
        except Exception as e:
            print(f"❌ [GitLab-AutoFix] Error creating MR on GitLab: {e}")
            return {"status": "error", "detail": str(e)}

    def auto_fix_vuln(self, vuln_id: int, project_id: Optional[int] = None) -> Dict[str, Any]:
        """
        Full pipeline: resolve the vuln's real repo (never a hardcoded/default project),
        clone it, apply a real fix, push a branch, open an MR. Returns a dict describing what
        actually happened -- callers must not assume success just because no exception was
        raised.
        """
        with db_manager.get_db_cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT v.*, a.asset_name, a.asset_type, a.endpoint
                FROM public.vulnerability_log v
                JOIN public.infra_inventory a ON v.asset_id = a.id
                WHERE v.id = %s
            """, (vuln_id,))
            vuln = cur.fetchone()

        if not vuln:
            return {"status": "failed", "message": "Vulnerability not found"}
        if vuln["asset_type"] != "GitLab-Repo":
            return {"status": "failed", "message": f"Asset type '{vuln['asset_type']}' is not a GitLab repo -- nothing to clone/patch."}

        # asset_name is "GitLab/<path_with_namespace>" (see gitlab_integration.py), endpoint is
        # the project's web_url.
        path_with_namespace = vuln["asset_name"].split("GitLab/", 1)[-1]
        http_url_to_repo = vuln["endpoint"]
        if not http_url_to_repo.endswith(".git"):
            http_url_to_repo = http_url_to_repo.rstrip("/") + ".git"

        repo_dir = self._clone(http_url_to_repo, path_with_namespace)
        if not repo_dir:
            return {"status": "failed", "message": f"No se pudo clonar {path_with_namespace}."}

        cve_id = vuln["cve_id"]
        changed, summary = False, "Sin acción automática disponible para este tipo de hallazgo."

        patcher = DETERMINISTIC_PATCHERS.get(cve_id)
        if patcher:
            changed, summary = patcher(repo_dir, vuln)
        elif cve_id.startswith("SCA-CVE-"):
            changed, summary = patch_dependency_bump(repo_dir, vuln)
        elif vuln.get("fix_patch"):
            # AI-generated unified diff, produced ahead of time by correlate_vulnerability()
            # and stored in vulnerability_log.fix_patch -- apply it here instead of asking an
            # LLM again at execution time.
            patch_file = os.path.join(repo_dir, ".centinela.patch")
            with open(patch_file, "w") as f:
                f.write(vuln["fix_patch"])
            result = subprocess.run(["git", "-C", repo_dir, "apply", "--whitespace=fix", patch_file],
                                     capture_output=True, text=True, timeout=30)
            os.remove(patch_file)
            if result.returncode == 0:
                changed, summary = True, "Parche generado por IA aplicado correctamente."
            else:
                changed, summary = False, f"El parche generado por IA no aplicó limpiamente: {result.stderr[:500]}"

        if not changed:
            shutil.rmtree(repo_dir, ignore_errors=True)
            return {"status": "skipped", "message": summary}

        branch_name = f"centinela-fix/{cve_id.lower()}-{vuln_id}"
        commit_msg = f"fix: {cve_id} (Centinela AI SOAR)\n\n{summary}"
        pushed = self._push_branch(repo_dir, branch_name, commit_msg)
        shutil.rmtree(repo_dir, ignore_errors=True)

        if not pushed:
            return {"status": "failed", "message": "El parche se generó pero no se pudo hacer commit/push (¿sin cambios reales, o sin permisos de push?)."}

        resolved_project_id = project_id or self._resolve_project_id(path_with_namespace)
        if not resolved_project_id:
            return {"status": "failed", "message": f"Cambios subidos a la rama {branch_name}, pero no se pudo resolver el project_id de GitLab para abrir el MR automáticamente."}

        mr_res = self.create_merge_request(
            project_id=resolved_project_id,
            source_branch=branch_name,
            target_branch="main",
            title=f"🛡️ [Centinela SOAR] Fix {cve_id} ({vuln['severity']})",
            description=f"""## 🛡️ Centinela Automated Security Patch

**CVE / Rule:** `{cve_id}`
**Severity:** `{vuln['severity']}`
**Change:** {summary}

**Original finding:**
{vuln['description']}

---
*Generated automatically by Centinela-AI SOAR Engine. Review before merging.*
""",
        )
        return mr_res
