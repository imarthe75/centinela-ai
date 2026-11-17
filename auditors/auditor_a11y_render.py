"""WCAG 2.1 A/AA on the RENDERED page (headless Chromium + axe-core) -- closes what the static auditor cannot see: real colour
contrast (1.4.3), the computed accessibility tree/ARIA of SPAs, language parts, text-spacing overrides.

The browser runs in a sibling container built from Dockerfile.a11y (docker.sock, same pattern as ZAP), so Chromium never enters the
main images. Read-only: loads the page, inspects the DOM; no clicks, no form submission. Only the landing page of each registered URL
asset is audited -- screens behind a login are NOT covered (they need credentials; see ADR-0005) and this is stated in every finding."""
import json
import logging
import re
import subprocess
import time
from typing import Dict, List, Optional
from urllib.parse import urlparse

from core import db_manager, deduplication_engine as de

logger = logging.getLogger(__name__)
IMAGE = "centinela-a11y:latest"
ENGINE = "wcag-render"
NETWORK = "aura-network"
_IMPACT_SEVERITY = {"critical": "HIGH", "serious": "MEDIUM", "moderate": "LOW", "minor": "LOW"}


def criteria_from_tags(tags: List[str]) -> List[str]:
    """axe tags 'wcag143' / 'wcag1412' -> '1.4.3' / '1.4.12' (criterion = first digit, second digit, rest)."""
    out = []
    for t in tags or []:
        m = re.fullmatch(r"wcag(\d)(\d)(\d+)", t)
        if m:
            out.append(f"{m.group(1)}.{m.group(2)}.{m.group(3)}")
    return out


def violations_to_findings(page: Dict) -> List[Dict]:
    """One finding per (axe rule, page). The criterion comes from axe's own WCAG tag; a rule with no 2.1 A/AA criterion is dropped
    (best-practice rules are not WCAG conformance failures and must not be reported as such)."""
    from core.coverage_matrix import WCAG_21_AA
    findings = []
    for v in page.get("violations", []):
        crits = [c for c in criteria_from_tags(v.get("tags")) if c in WCAG_21_AA]
        if not crits:
            continue
        crit = crits[0]
        nodes = v.get("nodes", [])
        sample = "; ".join(f"`{(n.get('target') or ['?'])[-1]}`" for n in nodes[:5])
        findings.append({
            "cve_id": f"WCAG-{crit}-AXE-{v['rule'].upper()}",
            "severity": _IMPACT_SEVERITY.get((v.get("impact") or "").lower(), "LOW"),
            "url_path": page["url"],
            "description": (f"**WCAG {crit} ({WCAG_21_AA[crit][0]}), nivel {WCAG_21_AA[crit][1]}** - {v.get('help')}.\\n\\n"
                            f"Detectado al renderizar la página con Chromium + axe-core: {v.get('node_count', len(nodes))} elemento(s), p. ej. {sample}.\\n"
                            f"Referencia: {v.get('helpUrl')}\\n\\n"
                            f"_Alcance: solo la página de entrada; las pantallas tras el login no se auditaron._"),
        })
    return findings


def rendered_meaningfully(page: Dict) -> bool:
    return (page.get("text_len") or 0) > 0 and (page.get("elements") or 0) >= 50


def run_browser_audit(urls: List[str], timeout: int = 240) -> Dict:
    """Run the worker container; returns its parsed JSON. Raises when the image is missing, docker fails or the output is not JSON."""
    name = f"a11y-render-{int(time.time())}"
    cmd = ["docker", "run", "--rm", "--name", name, "--network", NETWORK, "--memory", "1g", "--cpus", "1", IMAGE, *urls]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, errors="replace")
    except subprocess.TimeoutExpired:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)       # --rm does not fire when the client is killed
        raise
    if proc.returncode != 0:
        raise RuntimeError(f"a11y worker exited {proc.returncode}: {(proc.stderr or '')[-400:]}")
    return json.loads(proc.stdout)


def persist(asset_id, page: Dict) -> int:
    findings = violations_to_findings(page)
    origin = urlparse(page["url"])
    scope = f"{origin.scheme}://{origin.netloc}"
    seen = set()
    with db_manager.get_db_cursor() as cur:
        for f in findings:
            de.log_finding_deduplicated(cur, asset_id, f["cve_id"], f["severity"], f["description"], ENGINE,
                                        url_path=f["url_path"], open_status="NEW", preserve_status=True)
            seen.add(de.calculate_fingerprint(asset_id, f["cve_id"], f["url_path"]))
        # Only a page that rendered OK reaches this point, so "not reproduced" really means fixed.
        de.reconcile_resolved_findings(cur, asset_id, ENGINE, seen, url_origin=scope)
    return len(findings)


def describe_js_errors(page: Dict) -> str:
    errs = (page.get("page_errors") or []) + (page.get("console_errors") or [])
    if not errs:
        return "sin errores de JavaScript registrados"
    return f"{len(errs)} error(es) de JavaScript, p. ej. «{errs[0]}»"


def scan_url_assets(asset_id, url: str) -> Optional[int]:
    """Audit one URL and persist. Returns the finding count, or None when the audit could not run (logged with traceback)."""
    try:
        res = run_browser_audit([url])
    except Exception:
        logger.error("a11y render audit failed for %s", url, exc_info=True)
        return None
    page = (res.get("results") or [{}])[0]
    if not page.get("ok"):
        logger.error("a11y render could not load %s: %s (%s)", url, page.get("error"), describe_js_errors(page))
        return None
    if not rendered_meaningfully(page):
        # Zero visible text means the SPA never hydrated (blocked external script, JS error...). "0 violations" on an empty shell is not
        # evidence of accessibility, so nothing is persisted or reconciled.
        logger.error("a11y render of %s produced an empty page (elements=%s, text=%s chars; %s); audit not valid",
                     url, page.get("elements"), page.get("text_len"), describe_js_errors(page))
        return None
    n = persist(asset_id, page)
    print(f"♿ [A11y-Render] {url}: {n} WCAG violations ({page.get('passes')} rules passed, {page.get('incomplete')} need manual review; "
          f"{describe_js_errors(page)})")
    return n
