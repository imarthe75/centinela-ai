"""
Dependency-license audit (syft inventory -> license risk), engine id 'sca-license'.

Source of truth is the SBOM `syft` builds from the repository's manifests/lockfiles (it reads the license each package declares). Findings are legal /
compliance risks, NOT security vulnerabilities, so they are stored as INFORMATIONAL (they never inflate the "real vulnerabilities" headline) but still
carry a severity and an SLA, and they are mapped to ISO 27001:2022 A.5.32 (intellectual property rights).

One finding per (repository, risk category), listing the packages: a repo with 40 GPL transitive packages is ONE decision for the owner, not 40 tickets.
What it cannot know, and says so: whether a package is only a build/dev tool (never distributed -> copyleft does not apply) and the project's own
license / how the product is delivered. Hence "requiere validación" in every description. Pure functions first; the syft run + DB write are at the bottom.
"""
import json
import os
import re
import subprocess
from typing import Any, Dict, List, Optional

PERMISSIVE, WEAK_COPYLEFT, UNKNOWN, STRONG_COPYLEFT, NETWORK_COPYLEFT, RESTRICTED = (
    "PERMISSIVE", "WEAK_COPYLEFT", "UNKNOWN", "STRONG_COPYLEFT", "NETWORK_COPYLEFT", "RESTRICTED")
_RANK = {PERMISSIVE: 0, WEAK_COPYLEFT: 1, UNKNOWN: 2, STRONG_COPYLEFT: 3, NETWORK_COPYLEFT: 4, RESTRICTED: 5}

# (rule id, severity, human description) by category; PERMISSIVE and WEAK_COPYLEFT are deliberately not findings (MIT/Apache/MPL are normal and a finding per
# MPL-2.0 package would be noise).
RULES = {
    NETWORK_COPYLEFT: ("SCA-LICENSE-NETWORK-COPYLEFT", "HIGH", "licencia de copyleft de red (AGPL): obliga a publicar el código fuente de todo el servicio que la use, aunque solo se acceda por red"),
    RESTRICTED: ("SCA-LICENSE-RESTRICTED", "HIGH", "licencia restringida o no libre (SSPL, BUSL, uso no comercial, Elastic...): limita su uso comercial o su despliegue como servicio"),
    STRONG_COPYLEFT: ("SCA-LICENSE-STRONG-COPYLEFT", "MEDIUM", "licencia de copyleft fuerte (GPL): si el componente se distribuye junto con el producto, obliga a licenciar el producto igual"),
    UNKNOWN: ("SCA-LICENSE-UNKNOWN", "LOW", "sin licencia declarada o no reconocida: no hay derecho explícito de uso; se debe confirmar con el autor o sustituir"),
}
ENGINE = "sca-license"
URL_PATH = "sbom-licencias"

_PERMISSIVE_RE = re.compile(r"^(MIT(-0)?|X11|NCSA|ISC|0BSD|BSD(-\d-CLAUSE.*)?|BSD-.*|APACHE.*|ZLIB|UNLICENSE|CC0-1\.0|WTFPL|PYTHON.*|PSF.*|BLUEOAK.*|BSL-1\.0|UPL-1\.0|"
                            r"CC-BY-(3|4)\.0|OFL.*|ARTISTIC.*|PUBLIC DOMAIN|JSON|HPND.*|LIBPNG.*|FTL|CC-BY.*|AFL-.*|POSTGRESQL|OPENSSL.*|IMAGEMAGICK|MS-PL)$")
_WEAK_RE = re.compile(r"^(LGPL.*|MPL.*|EPL.*|CDDL.*|CPL.*|EUPL.*|OSL.*|CC-BY-SA.*|APSL.*|CECILL-C|MS-RL)$")
_RESTRICTED_RE = re.compile(r"^(SSPL.*|BUSL.*|ELASTIC.*|COMMONS-CLAUSE|CC-BY-NC.*|POLYFORM-(NONCOMMERCIAL|SHIELD|PERIMETER).*|PROPRIETARY.*|COMMERCIAL.*|"
                            r"CONFLUENT.*|REDIS.*|RSAL.*|FSL-.*)$")


def _single(token: str) -> str:
    t = token.strip().strip("()").strip().upper()
    if not t or t in ("NOASSERTION", "NONE", "UNKNOWN") or t.startswith("SEE LICENSE") or t.startswith("LICENSEREF"):
        return UNKNOWN
    if t.startswith("AGPL"):
        return NETWORK_COPYLEFT
    if _RESTRICTED_RE.match(t):
        return RESTRICTED
    if t.startswith("GPL") or t.startswith("GNU GPL"):
        return STRONG_COPYLEFT
    if _WEAK_RE.match(t):
        return WEAK_COPYLEFT
    if _PERMISSIVE_RE.match(t):
        return PERMISSIVE
    return UNKNOWN


def classify_license(expr: Optional[str]) -> str:
    """Risk category of an SPDX expression. `A OR B` -> the licensee may pick, so the LEAST restrictive alternative; `A AND B` -> all apply, the MOST
    restrictive; `X WITH exception` -> a linking exception exists, so a GPL with it is weak copyleft."""
    if not expr or not str(expr).strip():
        return UNKNOWN
    text = str(expr).strip()
    alternatives = re.split(r"\s+OR\s+", text, flags=re.IGNORECASE)
    best = None
    for alt in alternatives:
        parts = re.split(r"\s+AND\s+", alt.strip().strip("()"), flags=re.IGNORECASE)
        worst = PERMISSIVE
        for part in parts:
            if re.search(r"\s+WITH\s+", part, flags=re.IGNORECASE):
                cat = WEAK_COPYLEFT if _single(re.split(r"\s+WITH\s+", part, flags=re.IGNORECASE)[0]) in (STRONG_COPYLEFT, WEAK_COPYLEFT) else _single(part.split()[0])
            else:
                cat = _single(part)
            if _RANK[cat] > _RANK[worst]:
                worst = cat
        if best is None or _RANK[worst] < _RANK[best]:
            best = worst
    return best or UNKNOWN


def _package_license(artifact: Dict[str, Any]) -> str:
    vals = []
    for l in artifact.get("licenses") or []:
        v = l.get("spdxExpression") or l.get("value")
        if v:
            vals.append(str(v))
    return " AND ".join(vals) if len(vals) > 1 else (vals[0] if vals else "")


def audit_sbom_licenses(sbom: Dict[str, Any], display_name: str = "") -> List[Dict[str, Any]]:
    """One finding per risk category present in the SBOM (pure function)."""
    buckets: Dict[str, List[str]] = {}
    for a in sbom.get("artifacts") or []:
        if a.get("type") in ("binary", "file", "unknown-type"):   # not a dependency the project chose
            continue
        lic = _package_license(a)
        cat = classify_license(lic)
        if cat in RULES:
            buckets.setdefault(cat, []).append(f"{a.get('name', '?')}@{a.get('version', '?')} ({lic or 'sin licencia'})")
    findings = []
    for cat, pkgs in buckets.items():
        rule, sev, meaning = RULES[cat]
        pkgs = sorted(set(pkgs))
        listing = "; ".join(pkgs[:25]) + (f"; y {len(pkgs) - 25} más" if len(pkgs) > 25 else "")
        findings.append({
            "cve_id": rule, "severity": sev, "file": URL_PATH, "line": 0, "count": len(pkgs),
            "description": (f"{len(pkgs)} dependencia(s) con {meaning}. Paquetes: {listing}. Requiere validación: si el paquete es solo una herramienta de "
                            f"desarrollo/compilación (no se distribuye) el riesgo no aplica; depende además de la licencia propia del proyecto y de cómo se entrega. "
                            f"Decisión del responsable legal/de arquitectura: sustituir, obtener licencia comercial o documentar la excepción (ruta 0B-3)."),
        })
    return findings


def generate_sbom(target_dir: str, timeout: int = 300) -> Optional[Dict[str, Any]]:
    """syft over a directory. Returns None (with the reason printed) when it fails -- never a fake empty SBOM."""
    try:
        r = subprocess.run([os.getenv("SYFT_BIN", "syft"), f"dir:{target_dir}", "-o", "json", "--quiet"], capture_output=True, text=True, timeout=timeout)
        if r.returncode != 0:
            print(f"⚠️ [License-Auditor] syft failed on {target_dir}: {r.stderr[:300]}")
            return None
        return json.loads(r.stdout)
    except subprocess.TimeoutExpired:
        print(f"⏰ [License-Auditor] syft timed out on {target_dir}")
        return None
    except (json.JSONDecodeError, FileNotFoundError) as e:
        print(f"⚠️ [License-Auditor] syft output unusable for {target_dir}: {type(e).__name__}: {e}")
        return None


def run_license_audit(target_dir: str, asset_id: Optional[str] = None, display_name: str = "") -> List[Dict[str, Any]]:
    """syft -> classify -> persist (INFORMATIONAL) -> reconcile. Without a real asset_id nothing is written (nothing to attribute to)."""
    sbom = generate_sbom(target_dir)
    if sbom is None:
        return []
    findings = audit_sbom_licenses(sbom, display_name)
    if asset_id is None:
        return findings
    from core import db_manager, deduplication_engine
    try:
        active = set()
        with db_manager.get_db_cursor() as cur:
            for f in findings:
                active.add(deduplication_engine.calculate_fingerprint(asset_id, f["cve_id"], URL_PATH))
                deduplication_engine.log_finding_deduplicated(cur, asset_id, f["cve_id"], f["severity"], f["description"], ENGINE,
                                                              url_path=URL_PATH, preserve_status=True, finding_category="INFORMATIONAL")
            deduplication_engine.reconcile_resolved_findings(cur, asset_id, ENGINE, active)
    except Exception:
        import traceback
        traceback.print_exc()
        print(f"⚠️ [License-Auditor] could not persist license findings for {display_name or asset_id}")
    return findings
