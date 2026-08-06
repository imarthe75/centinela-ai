"""
Real-time threat intelligence: EPSS exploitation probability (FIRST.org) and CISA KEV
(confirmed actively-exploited-in-the-wild) status.

Both are free, public, no-auth-required feeds. Neither existed anywhere in the codebase before
this -- vulnerability_log.epss_score/is_cisa_kev were schema columns nothing ever wrote to, so
every risk-score computation silently used a fixed 0.15 EPSS default and is_cisa_kev=False for
every single finding, regardless of real-world exploitation status.
"""
import re
import time
import requests
from typing import Dict, List, Optional, Set

EPSS_API = "https://api.first.org/data/v1/epss"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
REQUEST_TIMEOUT = 20

_kev_cache: Optional[Set[str]] = None
_kev_cache_time: float = 0.0
_KEV_CACHE_TTL = 6 * 3600  # CISA updates this catalog occasionally, not continuously -- no need to refetch on every use

CVE_PATTERN = re.compile(r'CVE-\d{4}-\d{4,}')


def extract_cve(cve_id: str) -> Optional[str]:
    """
    Extracts a real CVE identifier from one of Centinela's own cve_id values (e.g.
    'SCA-CVE-2024-29041' -> 'CVE-2024-29041'). Returns None for findings that aren't CVE-based
    at all (ZAP-10021, DOCKER-MISSING-NON-ROOT-USER, STD-STRIDE-*, etc.) -- EPSS/KEV only exist
    for real CVEs, there's nothing to look up for Centinela's own rule IDs.
    """
    m = CVE_PATTERN.search(str(cve_id or '').upper())
    return m.group(0) if m else None


def get_cisa_kev_set() -> Set[str]:
    """Returns the cached set of CVE IDs CISA has confirmed are being actively exploited."""
    global _kev_cache, _kev_cache_time
    if _kev_cache is not None and (time.time() - _kev_cache_time) < _KEV_CACHE_TTL:
        return _kev_cache
    try:
        res = requests.get(CISA_KEV_URL, timeout=REQUEST_TIMEOUT)
        res.raise_for_status()
        data = res.json()
        _kev_cache = {v["cveID"] for v in data.get("vulnerabilities", [])}
        _kev_cache_time = time.time()
        print(f"🛰️ [Threat-Intel] CISA KEV catalog refreshed: {len(_kev_cache)} actively-exploited CVEs known.")
    except Exception as e:
        print(f"⚠️ [Threat-Intel] Could not refresh CISA KEV catalog: {e}")
        if _kev_cache is None:
            _kev_cache = set()
    return _kev_cache


def get_epss_scores(cve_ids: List[str]) -> Dict[str, float]:
    """
    Batched EPSS (Exploit Prediction Scoring System) lookup -- the real probability (0.0-1.0)
    that each CVE will be exploited in the wild in the next 30 days, per FIRST.org. Missing
    entries in the response (CVE not in EPSS's dataset, typically too new or too obscure) are
    simply absent from the returned dict; callers should fall back to a conservative default.
    """
    unique = sorted(set(c for c in cve_ids if c))
    if not unique:
        return {}
    out: Dict[str, float] = {}
    # FIRST.org's API defaults to 100 results per request -- chunk manifests/repos with many CVEs.
    for i in range(0, len(unique), 100):
        chunk = unique[i:i + 100]
        try:
            res = requests.get(EPSS_API, params={"cve": ",".join(chunk)}, timeout=REQUEST_TIMEOUT)
            res.raise_for_status()
            for row in res.json().get("data", []):
                out[row["cve"]] = float(row["epss"])
        except Exception as e:
            print(f"⚠️ [Threat-Intel] EPSS batch query failed for a chunk of {len(chunk)} CVEs: {e}")
    return out
