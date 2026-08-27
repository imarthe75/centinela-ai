"""
Item 1 (2026-08-27): shift-left Merge Request review + merge-blocking commit status.

Centinela's GitLab integration scans whole repos on a periodic loop and opens fix MRs *after*
a vulnerability has already landed on the default branch. CodeRabbit's core value is reviewing
the change *before* it merges. This module does exactly that:

  1. Pull the MR's changed files + unified diff from the GitLab API.
  2. Check out the MR head commit into a scratch clone.
  3. Run the existing native detectors (SAST regex, Dockerfile, secrets) on ONLY the changed
     files, and keep ONLY the findings that land on a line the MR actually added/changed.
  4. Post one inline discussion per finding on the MR (idempotent -- re-running updates nothing
     it already said), plus a single summary note.
  5. Set an external commit status `centinela/security` on the MR head SHA -- `failed` if any
     finding is at or above the blocking severity, else `success`. A project that requires this
     status (Settings -> Merge requests -> "Pipelines must succeed" / status checks) will then
     block the merge until it's resolved.

The GitLab I/O and the pure diff/scan logic are deliberately separated so the logic
(parse_added_lines, findings_on_changed_lines, decide_state) is unit-testable with no network.
"""
import os
import re
import shutil
import subprocess
import tempfile
from typing import Any, Dict, List, Optional, Set, Tuple

import requests

from auditors import auditor_master_vulnerabilities as _sast
from auditors import auditor_sca_dependencies as _sca
from auditors import auditor_semgrep as _semgrep
from auditors.auditor_secrets import SecretsScanner
from core import agent_ledger

MARKER = "<!-- centinela-mr-review -->"
STATUS_CONTEXT = "centinela/security"

_SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
_SOURCE_EXT = (
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rb", ".php", ".cs",
    ".c", ".cpp", ".sh", ".sql", ".kt", ".scala", ".rs",
)
_SECRET_SCAN_EXT = _SOURCE_EXT + (
    ".env", ".yml", ".yaml", ".json", ".xml", ".properties", ".txt", ".cfg", ".ini", ".conf",
)
_SCA_MANIFESTS = {
    "requirements.txt": "audit_requirements_txt",
    "package.json": "audit_package_json",
    "pom.xml": "audit_pom_xml",
    "go.mod": "audit_go_mod",
    "composer.json": "audit_composer_json",
}
_SEMGREP_TIMEOUT_S = 120

# ----------------------------------------------------------------------------- pure logic

_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def parse_added_lines(diff_text: str) -> Set[int]:
    """
    Given one file's unified diff, return the set of NEW-file line numbers that this diff
    adds or modifies (i.e. lines starting with '+', excluding the '+++' header). Context and
    removed lines are ignored -- a finding on an unchanged line is not this MR's problem.
    """
    added: Set[int] = set()
    new_ln = 0
    in_hunk = False
    for raw in (diff_text or "").splitlines():
        m = _HUNK_RE.match(raw)
        if m:
            new_ln = int(m.group(1))
            in_hunk = True
            continue
        if not in_hunk:
            continue
        if raw.startswith("+++") or raw.startswith("---"):
            continue
        if raw.startswith("+"):
            added.add(new_ln)
            new_ln += 1
        elif raw.startswith("-"):
            # removed line -- does not advance the new-file counter
            continue
        else:
            # context line (leading space) or "\ No newline at end of file"
            if raw.startswith("\\"):
                continue
            new_ln += 1
    return added


def findings_on_changed_lines(findings: List[Dict[str, Any]],
                              added_by_file: Dict[str, Set[int]],
                              fuzz: int = 2) -> List[Dict[str, Any]]:
    """
    Keep only findings whose (rel_path, line) falls on -- or within `fuzz` lines of -- a line
    this MR added. The small fuzz absorbs the off-by-a-line differences between a detector's
    reported line and the exact '+' line (e.g. a multi-line construct flagged at its opening).
    """
    kept = []
    for f in findings:
        rel = f.get("rel_path") or f.get("file") or ""
        added = added_by_file.get(rel)
        if not added:
            continue
        ln = int(f.get("line") or 0)
        if any((ln - d) in added for d in range(-fuzz, fuzz + 1)):
            kept.append(f)
    return kept


def decide_state(findings: List[Dict[str, Any]], blocking_severity: str = "HIGH") -> str:
    """'failed' if any finding is at/above blocking_severity, else 'success'."""
    threshold = _SEVERITY_RANK.get(blocking_severity.upper(), 3)
    for f in findings:
        if _SEVERITY_RANK.get(str(f.get("severity", "")).upper(), 0) >= threshold:
            return "failed"
    return "success"


def _semgrep_changed(repo_dir: str, source_rels: List[str]) -> List[Dict[str, Any]]:
    """Run one scoped semgrep invocation over just the changed source files (no DB write)."""
    if not source_rels:
        return []
    abs_files = [os.path.join(repo_dir, r) for r in source_rels
                 if os.path.isfile(os.path.join(repo_dir, r))]
    if not abs_files:
        return []
    try:
        rulesets = _semgrep.RULESETS.split() if getattr(_semgrep, "RULESETS", "") \
            else _semgrep.detect_language_rulesets(repo_dir)
    except Exception:
        rulesets = ["p/owasp-top-ten", "p/secrets"]
    cmd = [_semgrep.SEMGREP_BIN, "--json", "--quiet"] + \
          [f"--config={r}" for r in rulesets] + abs_files
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=_SEMGREP_TIMEOUT_S)
        if res.returncode not in (0, 1):
            return []
        import json as _json
        data = _json.loads(res.stdout or "{}")
    except Exception:
        return []
    out = []
    for r in data.get("results", []):
        abs_p = r.get("path", "")
        try:
            rel_p = os.path.relpath(abs_p, repo_dir)
        except ValueError:
            rel_p = abs_p
        out.append({
            "rel_path": rel_p, "file": rel_p,
            "line": r.get("start", {}).get("line", 0),
            "cve_id": r.get("check_id", "semgrep-finding"),
            "severity": _semgrep._severity_from_semgrep(r.get("extra", {}).get("severity")),
            "description": r.get("extra", {}).get("message", "Hallazgo Semgrep."),
        })
    return out


def scan_changed_files(repo_dir: str, changed_paths: List[str]) -> List[Dict[str, Any]]:
    """Run the native no-DB detectors (SAST regex, Dockerfile, secrets, SCA manifests, Semgrep)
    over just the given repo-relative paths."""
    out: List[Dict[str, Any]] = []
    secret_patterns = SecretsScanner.SECRET_PATTERNS
    source_rels: List[str] = []

    for rel in changed_paths:
        abs_path = os.path.join(repo_dir, rel)
        if not os.path.isfile(abs_path):
            continue
        try:
            with open(abs_path, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
        except Exception:
            continue

        base = os.path.basename(rel)
        if rel.endswith(_SOURCE_EXT):
            source_rels.append(rel)
            for f in _sast.scan_sast_code(rel, content):
                f["rel_path"] = rel
                out.append(f)
        if base == "Dockerfile" or base.startswith("Dockerfile."):
            for f in _sast.scan_iac_dockerfile(rel, content):
                f["rel_path"] = rel
                out.append(f)
        if base in _SCA_MANIFESTS:
            try:
                fn = getattr(_sca, _SCA_MANIFESTS[base])
                for f in fn(rel, content):
                    f["rel_path"] = f.get("file") or rel
                    out.append(f)
            except Exception as e:
                print(f"⚠️ [MR-Review] SCA scan of {rel} failed: {e}")
        if rel.endswith(_SECRET_SCAN_EXT):
            for ln_no, line in enumerate(content.splitlines(), 1):
                for stype, sinfo in secret_patterns.items():
                    try:
                        if re.search(sinfo["pattern"], line):
                            out.append({
                                "rel_path": rel, "file": rel, "line": ln_no,
                                "cve_id": f"SECRETS-{stype}",
                                "severity": sinfo.get("severity", "HIGH"),
                                "description": f"{sinfo.get('description', 'Possible hardcoded secret')} "
                                               f"(línea {ln_no}).",
                            })
                    except re.error:
                        continue

    out.extend(_semgrep_changed(repo_dir, source_rels))
    return out


# ----------------------------------------------------------------------------- GitLab I/O

class MRReviewer:
    def __init__(self, gitlab_url: Optional[str] = None, token: Optional[str] = None):
        self.gitlab_url = (gitlab_url or os.getenv("GITLAB_URL") or "http://10.4.3.10").rstrip("/")
        self.token = token or os.getenv("GITLAB_TOKEN") or ""
        self.s = requests.Session()
        if self.token:
            self.s.headers["PRIVATE-TOKEN"] = self.token

    # -- low level ---------------------------------------------------------------
    def _api(self, method: str, path: str, **kw) -> requests.Response:
        return self.s.request(method, f"{self.gitlab_url}/api/v4{path}", timeout=30, **kw)

    def get_mr(self, project_id: Any, mr_iid: int) -> Dict[str, Any]:
        r = self._api("GET", f"/projects/{_pid(project_id)}/merge_requests/{mr_iid}")
        r.raise_for_status()
        return r.json()

    def get_mr_changes(self, project_id: Any, mr_iid: int) -> Dict[str, Any]:
        r = self._api("GET", f"/projects/{_pid(project_id)}/merge_requests/{mr_iid}/changes")
        r.raise_for_status()
        return r.json()

    def existing_discussion_keys(self, project_id: Any, mr_iid: int) -> Set[str]:
        """Set of '<path>:<line>:<cve>' keys Centinela has already commented on this MR."""
        keys: Set[str] = set()
        page = 1
        while True:
            r = self._api("GET", f"/projects/{_pid(project_id)}/merge_requests/{mr_iid}/discussions",
                          params={"per_page": 100, "page": page})
            if r.status_code != 200:
                break
            batch = r.json()
            for disc in batch:
                for note in disc.get("notes", []):
                    body = note.get("body", "")
                    if MARKER in body:
                        m = re.search(r"<!-- key:(.*?) -->", body)
                        if m:
                            keys.add(m.group(1))
            if len(batch) < 100:
                break
            page += 1
        return keys

    def post_inline(self, project_id: Any, mr_iid: int, diff_refs: Dict[str, str],
                    rel_path: str, line: int, body: str) -> bool:
        payload = {
            "body": body,
            "position[position_type]": "text",
            "position[base_sha]": diff_refs.get("base_sha"),
            "position[start_sha]": diff_refs.get("start_sha"),
            "position[head_sha]": diff_refs.get("head_sha"),
            "position[new_path]": rel_path,
            "position[old_path]": rel_path,
            "position[new_line]": line,
        }
        r = self._api("POST", f"/projects/{_pid(project_id)}/merge_requests/{mr_iid}/discussions",
                      data=payload)
        if r.status_code in (200, 201):
            return True
        # A position GitLab can't anchor (line not in its own diff view) -> fall back to a plain
        # MR note so the finding is still visible rather than silently dropped.
        self._api("POST", f"/projects/{_pid(project_id)}/merge_requests/{mr_iid}/notes",
                  data={"body": f"{body}\n\n_(no se pudo anclar a `{rel_path}:{line}` en el diff)_"})
        return False

    def upsert_summary_note(self, project_id: Any, mr_iid: int, body: str) -> None:
        r = self._api("GET", f"/projects/{_pid(project_id)}/merge_requests/{mr_iid}/notes",
                      params={"per_page": 100})
        note_id = None
        if r.status_code == 200:
            for n in r.json():
                if MARKER in n.get("body", "") and "resumen" in n.get("body", "").lower():
                    note_id = n["id"]
                    break
        if note_id:
            self._api("PUT", f"/projects/{_pid(project_id)}/merge_requests/{mr_iid}/notes/{note_id}",
                      data={"body": body})
        else:
            self._api("POST", f"/projects/{_pid(project_id)}/merge_requests/{mr_iid}/notes",
                      data={"body": body})

    def set_status(self, project_id: Any, sha: str, state: str, description: str,
                   target_url: Optional[str] = None) -> bool:
        data = {"state": state, "context": STATUS_CONTEXT, "description": description[:140]}
        if target_url:
            data["target_url"] = target_url
        r = self._api("POST", f"/projects/{_pid(project_id)}/statuses/{sha}", data=data)
        return r.status_code in (200, 201)

    def _checkout_mr_head(self, repo_http_url: str, path_ns: str, mr_iid: int, head_sha: str) -> Optional[str]:
        workdir = tempfile.mkdtemp(prefix="centinela-mr-")
        clone_url = repo_http_url
        if self.token and "@" not in clone_url:
            clone_url = clone_url.replace("http://", f"http://oauth2:{self.token}@") \
                                 .replace("https://", f"https://oauth2:{self.token}@")
        try:
            subprocess.run(["git", "clone", "--filter=blob:none", "--no-checkout", clone_url, workdir],
                           capture_output=True, timeout=180, check=True)
            # GitLab publishes every MR head at this ref -- reliable even for shallow/partial clones.
            fetched = subprocess.run(
                ["git", "-C", workdir, "fetch", "origin", f"refs/merge-requests/{mr_iid}/head"],
                capture_output=True, timeout=120)
            target = "FETCH_HEAD" if fetched.returncode == 0 else head_sha
            co = subprocess.run(["git", "-C", workdir, "checkout", target],
                                capture_output=True, timeout=60)
            if co.returncode != 0:
                shutil.rmtree(workdir, ignore_errors=True)
                return None
            return workdir
        except Exception:
            shutil.rmtree(workdir, ignore_errors=True)
            return None

    # -- orchestration --------------------------------------------------------------
    def review(self, project_id: Any, mr_iid: int, blocking_severity: str = "HIGH") -> Dict[str, Any]:
        mr = self.get_mr(project_id, mr_iid)
        if mr.get("state") not in ("opened", "reopened", "locked"):
            return {"status": "skipped", "reason": f"MR state is {mr.get('state')}"}

        changes = self.get_mr_changes(project_id, mr_iid)
        diff_refs = changes.get("diff_refs") or {}
        head_sha = diff_refs.get("head_sha") or mr.get("sha")
        raw_changes = changes.get("changes", [])

        added_by_file: Dict[str, Set[int]] = {}
        changed_paths: List[str] = []
        for ch in raw_changes:
            if ch.get("deleted_file"):
                continue
            new_path = ch.get("new_path")
            if not new_path:
                continue
            changed_paths.append(new_path)
            added_by_file[new_path] = parse_added_lines(ch.get("diff", ""))

        repo_http_url = mr.get("web_url", "").rsplit("/-/merge_requests/", 1)[0] + ".git"
        path_ns = mr.get("references", {}).get("full", "").split("!")[0] or f"project-{project_id}"

        repo_dir = self._checkout_mr_head(repo_http_url, path_ns, mr_iid, head_sha)
        if not repo_dir:
            self.set_status(project_id, head_sha, "failed",
                            "Centinela no pudo clonar/checkout la rama del MR para revisarla")
            return {"status": "error", "reason": "checkout failed", "head_sha": head_sha}

        try:
            all_findings = scan_changed_files(repo_dir, changed_paths)
        finally:
            shutil.rmtree(repo_dir, ignore_errors=True)

        findings = findings_on_changed_lines(all_findings, added_by_file)
        findings.sort(key=lambda f: (-_SEVERITY_RANK.get(str(f.get("severity", "")).upper(), 0),
                                     f.get("rel_path", ""), f.get("line", 0)))

        already = self.existing_discussion_keys(project_id, mr_iid)
        posted = 0
        for f in findings:
            key = f"{f['rel_path']}:{f['line']}:{f['cve_id']}"
            if key in already:
                continue
            body = (
                f"{MARKER}\n<!-- key:{key} -->\n"
                f"### 🛡️ Centinela — `{f['cve_id']}` ({str(f.get('severity','')).upper()})\n\n"
                f"{f.get('description', '').strip()}\n\n"
                f"_Detectado en una línea introducida por este MR (`{f['rel_path']}:{f['line']}`). "
                f"Corrige antes de fusionar, o marca como falso positivo en Centinela "
                f"(`POST /api/suppressions`)._"
            )
            if self.post_inline(project_id, mr_iid, diff_refs, f["rel_path"], f["line"], body):
                posted += 1

        state = decide_state(findings, blocking_severity)
        by_sev: Dict[str, int] = {}
        for f in findings:
            by_sev[str(f.get("severity", "")).upper()] = by_sev.get(str(f.get("severity", "")).upper(), 0) + 1
        sev_line = ", ".join(f"{k}: {v}" for k, v in sorted(
            by_sev.items(), key=lambda kv: -_SEVERITY_RANK.get(kv[0], 0))) or "0"

        summary = (
            f"{MARKER}\n## 🛡️ Centinela — resumen de revisión de seguridad\n\n"
            f"- Archivos cambiados analizados: **{len(changed_paths)}**\n"
            f"- Hallazgos en líneas nuevas de este MR: **{len(findings)}** ({sev_line})\n"
            f"- Estado del check `{STATUS_CONTEXT}`: **{state.upper()}** "
            f"(bloquea a partir de severidad `{blocking_severity.upper()}`)\n\n"
            + ("✅ Sin hallazgos de seguridad en el código introducido por este MR.\n"
               if not findings else
               "❌ Revisa los comentarios en línea. Cada hallazgo está sobre una línea que "
               "este MR añade o modifica.\n")
        )
        self.upsert_summary_note(project_id, mr_iid, summary)

        desc = (f"{len(findings)} hallazgo(s) en líneas nuevas ({sev_line})"
                if findings else "sin hallazgos en el código introducido")
        self.set_status(project_id, head_sha, state, desc, target_url=mr.get("web_url"))

        agent_ledger.record_action(
            agent_ledger.ACTION_MR_REVIEW,
            f"Revisión MR !{mr_iid} en {path_ns}: {len(findings)} hallazgo(s) en líneas nuevas -> check {state}",
            entity_type="merge_request", entity_id=mr_iid,
            detail={"project_id": project_id, "head_sha": head_sha, "state": state,
                    "findings": len(findings), "by_severity": by_sev, "comments_posted": posted,
                    "changed_files": len(changed_paths)},
            evidence=mr.get("web_url"),
            outcome="success",
        )
        return {"status": "reviewed", "mr_iid": mr_iid, "head_sha": head_sha,
                "check_state": state, "findings": len(findings), "comments_posted": posted,
                "by_severity": by_sev}


def _pid(project_id: Any) -> str:
    """GitLab accepts a numeric id or a URL-encoded 'group/subgroup/project' path."""
    s = str(project_id)
    return s if s.isdigit() else requests.utils.quote(s, safe="")


def _sev_rank(sev: str) -> int:
    return _SEVERITY_RANK.get(str(sev).upper(), 0)
