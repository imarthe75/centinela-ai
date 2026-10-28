#!/usr/bin/env python3
"""
Scan the changes of a working tree with Centinela's own offline detectors BEFORE declaring work done.

Used by developers and by AI coding agents (skills/centinela-developer-standards §12.1): the goal is zero findings of Centinela's
own rules in new code. Read-only: it writes nothing to the database and to the repository.

  python3 scripts/scan_working_tree.py --repo /path/to/project            # modified + untracked files (git)
  python3 scripts/scan_working_tree.py --repo /path --base origin/master  # files changed against a base
  python3 scripts/scan_working_tree.py --repo /path --all                 # every tracked file
  python3 scripts/scan_working_tree.py --repo /path --paths a.java b.ts   # explicit files

Exit code: 0 = no finding at or above --fail-on (default HIGH); 1 = findings; 2 = could not run.
Covers the offline detectors: SAST/architecture/standards rules, Dockerfile, secrets, dependency manifests (OSV, needs network),
Semgrep when installed, static WCAG, Kubernetes/Terraform, .gitlab-ci.yml and method-level authorization.
It does NOT run the engines that need a deployed target (ZAP, WSTG, TLS, CIS, OS patches, authenticated DAST): say so in the delivery.
"""
import argparse
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def changed_files(repo: str, base: str = None, everything: bool = False):
    def git(*args):
        return subprocess.run(["git", "-c", "safe.directory=*", "-C", repo, *args], capture_output=True, text=True, check=True).stdout.splitlines()
    if subprocess.run(["git", "-c", "safe.directory=*", "-C", repo, "rev-parse", "--verify", "-q", "HEAD"], capture_output=True).returncode != 0:
        return sorted(set(git("ls-files")) | set(git("ls-files", "--others", "--exclude-standard")))   # no commit yet: everything
    if everything:
        return git("ls-files")
    if base:
        return sorted(set(git("diff", "--name-only", f"{base}...HEAD")) | set(git("diff", "--name-only")) | set(git("ls-files", "--others", "--exclude-standard")))
    return sorted(set(git("diff", "--name-only", "HEAD")) | set(git("ls-files", "--others", "--exclude-standard")))


_WCAG_EXT = (".html", ".htm", ".jsx", ".tsx", ".vue")
_CSS_EXT = (".css", ".scss")


def extra_findings(repo: str, paths, everything: bool = False):
    """Detectors that are not part of the merge-request scan: WCAG (static), IaC, CI file and method-level authorization."""
    from auditors import auditor_accessibility_wcag as wcag, auditor_iac_k8s as iac, auditor_gitlab_config as gl, auditor_authz as authz
    out = []

    def add(items, rel):
        for f in items or []:
            f.setdefault("rel_path", f.get("file") or rel)
            out.append(f)

    for rel in paths:
        path = os.path.join(repo, rel)
        if not os.path.isfile(path):
            continue
        try:
            content = open(path, encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        low = rel.lower()
        if low.endswith(_WCAG_EXT):
            add(wcag.audit_wcag_accessibility(rel, content), rel)
            add(wcag.audit_wcag_extended(rel, content), rel)
        elif low.endswith(_CSS_EXT):
            add(wcag.audit_wcag_css(rel, content), rel)
        elif low.endswith((".yaml", ".yml")) and os.path.basename(low) != ".gitlab-ci.yml":
            add(iac.audit_kubernetes_yaml(rel, content), rel)
        if low.endswith(".tf"):
            add(iac.audit_terraform_tf(rel, content), rel)
        if os.path.basename(low) == ".gitlab-ci.yml":
            add(gl.evaluate_ci_file(content, rel), rel)
    # Authorization depends on the whole project (security config + controllers): run it on the tree and keep the changed files.
    if any(p.endswith((".java", ".ts", ".html")) for p in paths):
        keep = {os.path.normpath(p) for p in paths}
        for f in authz.run_authz_audit(repo, None) or []:
            rel = os.path.relpath(f.get("file", ""), repo) if os.path.isabs(str(f.get("file", ""))) else str(f.get("file", ""))
            if everything or os.path.normpath(rel) in keep:
                f["rel_path"] = rel
                out.append(f)
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--repo", default=".")
    ap.add_argument("--base")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--paths", nargs="*")
    ap.add_argument("--fail-on", default="HIGH", choices=list(_RANK))
    args = ap.parse_args(argv)
    repo = os.path.abspath(args.repo)
    try:
        paths = args.paths if args.paths else changed_files(repo, args.base, args.all)
        from auditors.mr_review import scan_changed_files
        findings = scan_changed_files(repo, paths) + extra_findings(repo, paths, args.all)
    except Exception as e:
        print(f"❌ no se pudo ejecutar el escaneo: {e}", file=sys.stderr)
        return 2
    findings.sort(key=lambda f: (-_RANK.get(str(f.get("severity", "")).upper(), 0), f.get("rel_path", ""), f.get("line", 0)))
    print(f"Archivos revisados: {len(paths)} | hallazgos: {len(findings)}")
    for f in findings:
        print(f"[{str(f.get('severity', '?')).upper():8}] {f.get('rel_path', f.get('file', '?'))}:{f.get('line', '?')}  {f.get('cve_id', '?')}")
    blocking = [f for f in findings if _RANK.get(str(f.get("severity", "")).upper(), 0) >= _RANK[args.fail_on]]
    print(f"Bloqueantes (>= {args.fail_on}): {len(blocking)}")
    print("No ejecutado aquí (requiere un despliegue): ZAP, WSTG, TLS, CIS, parches de SO, DAST autenticado.")
    return 1 if blocking else 0


if __name__ == "__main__":
    sys.exit(main())
