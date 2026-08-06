"""
Centinela Native Software Composition Analysis (SCA) & Dependency Auditor
Parses package manifests (requirements.txt, package.json) to detect vulnerable dependencies and security risks.
"""
import os
import json
import re
import requests
from typing import List, Dict, Any, Tuple
from core import db_manager

OSV_API_BASE = "https://api.osv.dev/v1"
OSV_TIMEOUT = 15

# Fallback only: used when OSV.dev is unreachable (offline environment, outage). OSV is the
# primary, live-updated source (queried per real installed version) -- this tiny static table
# existed before that integration and is kept only so a network outage doesn't mean zero SCA
# coverage, not as the main source of truth.
KNOWN_VULNERABLE_PACKAGES = {
    "requests": [("<2.31.0", "CVE-2023-32681", "HIGH", "Unintended leak of Proxy-Authorization header")],
    "urllib3": [("<1.26.17", "CVE-2023-45803", "MEDIUM", "Request body not stripped on HTTP redirect")],
    "jinja2": [("<3.1.3", "CVE-2024-22195", "MEDIUM", "Cross-site scripting (XSS) vulnerability in xmlattr filter")],
    "pyyaml": [("<5.4", "CVE-2020-14343", "CRITICAL", "Arbitrary Code Execution via FullLoader")],
    "cryptography": [("<41.0.6", "CVE-2023-49083", "HIGH", "NULL pointer dereference in PKCS12 parsing")],
    "express": [("<4.19.2", "CVE-2024-29041", "HIGH", "Open redirect vulnerability in express.static")],
    "axios": [("<1.7.4", "CVE-2024-39338", "HIGH", "Server-Side Request Forgery via relative URL manipulation")]
}

_OSV_SEVERITY_MAP = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MODERATE": "MEDIUM", "MEDIUM": "MEDIUM", "LOW": "LOW"}


def _osv_cvss_to_severity(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def _osv_severity(vuln: Dict[str, Any]) -> str:
    for sev in vuln.get("severity", []) or []:
        try:
            # CVSS vector strings end in "/S:.../.../AV:N/AC:L/.../C:H/..." -- OSV also exposes
            # a numeric "score" on some entries; fall back to parsing the vector's base score
            # isn't reliable without a CVSS library, so prefer database_specific first and only
            # use this as a last resort when nothing else is present.
            if "score" in sev:
                return _osv_cvss_to_severity(float(sev["score"]))
        except (ValueError, TypeError):
            pass
    db_sev = str(vuln.get("database_specific", {}).get("severity", "")).upper()
    if db_sev in _OSV_SEVERITY_MAP:
        return _OSV_SEVERITY_MAP[db_sev]
    return "MEDIUM"


def _osv_fixed_version(vuln: Dict[str, Any], ecosystem: str) -> str:
    for affected in vuln.get("affected", []) or []:
        if affected.get("package", {}).get("ecosystem") != ecosystem:
            continue
        for rng in affected.get("ranges", []) or []:
            # ECOSYSTEM/SEMVER ranges carry a real published version number (OSV uses ECOSYSTEM
            # for some registries, e.g. PyPI, and SEMVER for others, e.g. npm -- confirmed both
            # live). GIT-type ranges (same affected entry, different range) use commit hashes
            # for "fixed", which is meaningless as a "safe version to upgrade to" -- skip those.
            if rng.get("type") not in ("ECOSYSTEM", "SEMVER"):
                continue
            for event in rng.get("events", []) or []:
                if "fixed" in event:
                    return event["fixed"]
    return ""


def _osv_cve_id(vuln: Dict[str, Any]) -> str:
    for alias in vuln.get("aliases", []) or []:
        if alias.startswith("CVE-"):
            return alias
    return vuln.get("id", "UNKNOWN")


def query_osv_batch(deps: List[Tuple[str, str]], ecosystem: str):
    """
    Queries OSV.dev (osv.dev — the Open Source Vulnerability database backing GitHub's own
    dependency alerts, aggregating NVD/GHSA/PyPA/npm advisories) for every (package, version)
    pair, live. Two-phase: a batch query for matching vuln IDs (cheap, one request for the
    whole manifest), then one detail fetch per distinct ID actually found (typically far fewer
    than the number of dependencies).

    Returns a dict (possibly empty -- that legitimately means "no vulnerabilities found") on
    success, or None specifically on network/API failure, so callers can tell "OSV says this is
    clean" apart from "couldn't reach OSV" and only fall back to the static table in the latter
    case.
    """
    if not deps:
        return {}
    try:
        queries = [{"version": v, "package": {"name": n, "ecosystem": ecosystem}} for n, v in deps]
        res = requests.post(f"{OSV_API_BASE}/querybatch", json={"queries": queries}, timeout=OSV_TIMEOUT)
        res.raise_for_status()
        results = res.json().get("results", [])
    except Exception as e:
        print(f"⚠️ [SCA-Auditor] OSV.dev batch query failed, falling back to static table: {e}")
        return None

    # Collect every distinct vuln id across the whole manifest, fetch full details once each.
    id_to_dep = {}
    for (name, version), result in zip(deps, results):
        for v in result.get("vulns", []) or []:
            id_to_dep.setdefault(v["id"], []).append((name, version))

    details_by_id = {}
    for vuln_id in id_to_dep:
        try:
            r = requests.get(f"{OSV_API_BASE}/vulns/{vuln_id}", timeout=OSV_TIMEOUT)
            r.raise_for_status()
            details_by_id[vuln_id] = r.json()
        except Exception as e:
            print(f"⚠️ [SCA-Auditor] Could not fetch OSV detail for {vuln_id}: {e}")

    out: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
    seen_cve_per_dep: Dict[Tuple[str, str], set] = {}
    for vuln_id, dep_list in id_to_dep.items():
        detail = details_by_id.get(vuln_id)
        if not detail:
            continue
        cve = _osv_cve_id(detail)
        for dep in dep_list:
            # The same CVE is often aliased by multiple independent OSV entries (e.g. a GHSA
            # advisory and a PYSEC entry both pointing at the same CVE) -- without this, each
            # alias produced its own duplicate finding for the same real vulnerability.
            seen = seen_cve_per_dep.setdefault(dep, set())
            if cve in seen:
                continue
            seen.add(cve)
            out.setdefault(dep, []).append({
                "cve": cve,
                "severity": _osv_severity(detail),
                "fixed_version": _osv_fixed_version(detail, ecosystem) or "ver aviso original",
                "desc": (detail.get("summary") or detail.get("details") or "Sin resumen disponible.")[:300],
            })
    return out


def _static_fallback_findings(pkg_name: str, version: str, idx: int, file_path: str, manifest: str) -> List[Dict[str, Any]]:
    findings = []
    if pkg_name in KNOWN_VULNERABLE_PACKAGES:
        for target_ver, cve, severity, desc in KNOWN_VULNERABLE_PACKAGES[pkg_name]:
            fixed_version = target_ver.lstrip("<>=")
            findings.append({
                "cve_id": f"SCA-{cve}", "severity": severity, "file": file_path, "line": idx,
                "package": pkg_name, "installed_version": version, "fixed_version": fixed_version,
                "manifest": manifest,
                "description": f"Vulnerable dependency '{pkg_name}' ({version}). {desc} ({cve}). Fixed in {fixed_version}.",
            })
    return findings


def _findings_from_osv(deps_with_lines: Dict[str, Tuple[str, int]], ecosystem: str, manifest: str, file_path: str) -> List[Dict[str, Any]]:
    """deps_with_lines: {package_name: (version, line_number)}"""
    findings = []
    queryable = {name: (version, line) for name, (version, line) in deps_with_lines.items() if version}
    osv_results = query_osv_batch([(n, v) for n, (v, _l) in queryable.items()], ecosystem)

    if osv_results is None:
        # OSV unreachable -- fall back to the static table for every dependency so a network
        # outage degrades coverage instead of eliminating it.
        for name, (version, idx) in deps_with_lines.items():
            findings.extend(_static_fallback_findings(name, version, idx, file_path, manifest))
        return findings

    for name, (version, idx) in queryable.items():
        for vuln in osv_results.get((name, version), []):
            findings.append({
                "cve_id": f"SCA-{vuln['cve']}", "severity": vuln["severity"], "file": file_path, "line": idx,
                "package": name, "installed_version": version, "fixed_version": vuln["fixed_version"],
                "manifest": manifest,
                "description": f"Vulnerable dependency '{name}' ({version}). {vuln['desc']} ({vuln['cve']}). Fixed in {vuln['fixed_version']}. Fuente: OSV.dev.",
            })
    return findings


def audit_requirements_txt(file_path: str, content: str) -> List[Dict[str, Any]]:
    """Audits Python requirements.txt file against OSV.dev (live), falling back to the static table if unreachable."""
    deps_with_lines: Dict[str, Tuple[str, int]] = {}
    for idx, line in enumerate(content.splitlines(), 1):
        clean_line = line.strip()
        if not clean_line or clean_line.startswith("#"):
            continue
        match = re.match(r'^([a-zA-Z0-9_-]+)\s*(==)?\s*([0-9][0-9a-zA-Z.]*)?', clean_line)
        if match and match.group(1):
            deps_with_lines[match.group(1).lower()] = (match.group(3) or "", idx)

    return _findings_from_osv(deps_with_lines, "PyPI", "requirements.txt", file_path)


def audit_package_json(file_path: str, content: str) -> List[Dict[str, Any]]:
    """Audits Node.js package.json file against OSV.dev (live), falling back to the static table if unreachable."""
    try:
        data = json.loads(content)
        raw_deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
    except Exception as e:
        print(f"⚠️ [SCA-Auditor] Error parsing {file_path}: {e}")
        return []

    # package.json pins ranges (^5.1.0, ~1.2.3, >=2.0.0), not exact installed versions --
    # without a lockfile, strip the range operator and treat the numeric floor as the version
    # to check (the same approximation the previous static-only version used).
    deps_with_lines: Dict[str, Tuple[str, int]] = {}
    for pkg_name, version in raw_deps.items():
        clean_version = re.sub(r'^[\^~>=<\s]+', '', str(version))
        deps_with_lines[pkg_name.lower()] = (clean_version, 1)

    return _findings_from_osv(deps_with_lines, "npm", "package.json", file_path)


def check_reachability(target_dir: str, package: str, manifest: str) -> str:
    """
    Real (if simplified) reachability check: is this dependency actually imported anywhere in
    the source tree, or only declared in the manifest? A package can be listed in
    requirements.txt/package.json but never actually imported (leftover from a refactor,
    installed for a script that was since removed, a transitive dependency someone pinned
    directly) -- in that case, the vulnerable code path can never execute here regardless of
    the CVE's severity.

    This is import-statement matching, not true call-graph/taint analysis into the specific
    vulnerable function (which would need per-CVE "this exact symbol is unsafe" metadata that
    isn't reliably available across ecosystems) -- a real, honest, coarser signal: "is this
    package's code reachable at all" rather than "is the specific vulnerable line reachable".
    Returns 'REACHABLE' or 'UNREACHABLE'.
    """
    if manifest == "requirements.txt":
        # Python import names sometimes differ from the PyPI package name (e.g. package
        # "pyyaml" imports as "yaml") -- match on the package name itself, which covers the
        # common case where they're identical or the import uses a prefix of the package name.
        patterns = [
            re.compile(rf'^\s*import\s+{re.escape(package)}\b', re.MULTILINE),
            re.compile(rf'^\s*from\s+{re.escape(package)}\b', re.MULTILINE),
        ]
        extensions = (".py",)
    elif manifest == "package.json":
        patterns = [
            re.compile(rf'require\(["\']({re.escape(package)})(/[^"\']*)?["\']\)'),
            re.compile(rf'from\s+["\']({re.escape(package)})(/[^"\']*)?["\']'),
            re.compile(rf'import\s+["\']({re.escape(package)})(/[^"\']*)?["\']'),
        ]
        extensions = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")
    else:
        return "REACHABLE"  # unknown manifest type -- don't claim unreachable without real evidence

    for root, _, files in os.walk(target_dir):
        if any(ignored in root for ignored in [".git", "node_modules", "__pycache__", ".venv"]):
            continue
        for file in files:
            if not file.endswith(extensions):
                continue
            try:
                with open(os.path.join(root, file), "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                if any(p.search(content) for p in patterns):
                    return "REACHABLE"
            except Exception:
                continue
    return "UNREACHABLE"


def run_sca_audit(target_dir: str = "/opt/centinela-ai", asset_id: int = None) -> List[Dict[str, Any]]:
    """Scans target directory for package manifests and audits open-source dependencies."""
    all_findings = []

    for root, _, files in os.walk(target_dir):
        if any(ignored in root for ignored in [".git", "node_modules", "__pycache__", ".venv"]):
            continue
        for file in files:
            full_path = os.path.join(root, file)
            try:
                with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()

                if file == "requirements.txt":
                    all_findings.extend(audit_requirements_txt(full_path, content))
                elif file == "package.json":
                    all_findings.extend(audit_package_json(full_path, content))
            except Exception as e:
                print(f"⚠️ [SCA-Auditor] Could not read {full_path}: {e}")

    # Persist findings to database. Same fixes as auditor_master_vulnerabilities.py: file
    # location stored in url_path, and deduplication_engine.log_finding_deduplicated() replaces
    # the old no-op "ON CONFLICT DO NOTHING" -- also merges cross-tool (e.g. the same real CVE
    # independently flagged by Nuclei/sast-native on this asset collapses into one ticket).
    # Description embeds package/installed/fixed_version/manifest in a parseable form so a real
    # "bump to fixed_version in manifest" patch can be generated later without re-deriving this
    # from KNOWN_VULNERABLE_PACKAGES/OSV again.
    try:
        from core import deduplication_engine
        with db_manager.get_db_cursor() as cur:
            for item in all_findings:
                rel_path = os.path.relpath(item["file"], target_dir) if item.get("file") else "unknown"
                location = f"{rel_path}:{item.get('line', 0)}"

                # Reachability: is the package actually imported anywhere, or only declared in
                # the manifest? See check_reachability()'s own docstring for exactly what this
                # does and doesn't prove -- import-based, not per-CVE call-graph analysis.
                reachability = check_reachability(target_dir, item["package"], item["manifest"])
                reachability_note = (
                    "⚠️ **No se encontró ningún `import`/`require` de este paquete en el código -- "
                    "puede ser una dependencia sin uso real.**\n\n"
                    if reachability == "UNREACHABLE" else ""
                )
                description = (
                    f"{reachability_note}"
                    f"**Archivo:** `{rel_path}`\n"
                    f"**Paquete:** {item['package']}\n"
                    f"**Versión instalada:** {item['installed_version']}\n"
                    f"**Versión segura:** {item['fixed_version']}\n"
                    f"**Manifiesto:** {item['manifest']}\n"
                    f"**Alcanzabilidad:** {reachability}\n"
                    f"{item['description']}"
                )

                deduplication_engine.log_finding_deduplicated(
                    cur, asset_id, item["cve_id"], item["severity"], description,
                    "sca-native", url_path=location, open_status="OPEN",
                    reachability_status=reachability
                )
    except Exception as db_err:
        print(f"⚠️ [SCA-Auditor] Could not log findings to DB: {db_err}")

    return all_findings
