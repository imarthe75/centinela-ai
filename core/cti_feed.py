"""
CTI / IoC feed ingestion: real, live indicators of compromise from abuse.ch's Feodo Tracker
(free, public, no auth -- a maintained blocklist of active C2 (command & control) server IPs
tied to real malware families).

Cross-referenced against two real data sources this codebase already has: registered asset IPs
(infra_inventory) and IPs appearing in runtime_alerts (Falco/Zeek/Wazuh output already ingested
elsewhere in centinela.py) -- a hit means either one of our own hosts' IPs is a known C2 server
(compromised/relay), or a runtime alert involved a connection to/from a confirmed-malicious IP.
"""
import re
import time
import requests
from typing import Dict, Optional

FEODO_TRACKER_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
REQUEST_TIMEOUT = 20

_ioc_cache: Optional[Dict[str, dict]] = None
_ioc_cache_time: float = 0.0
_IOC_CACHE_TTL = 3600  # refresh hourly -- this feed tracks active infrastructure, changes often

IP_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')


def get_malicious_ips() -> Dict[str, dict]:
    """Returns {ip: {malware, first_seen, ...}} for currently-tracked active C2 servers."""
    global _ioc_cache, _ioc_cache_time
    if _ioc_cache is not None and (time.time() - _ioc_cache_time) < _IOC_CACHE_TTL:
        return _ioc_cache
    try:
        res = requests.get(FEODO_TRACKER_URL, timeout=REQUEST_TIMEOUT)
        res.raise_for_status()
        data = res.json()
        _ioc_cache = {entry["ip_address"]: entry for entry in data}
        _ioc_cache_time = time.time()
        print(f"🛰️ [CTI-Feed] Feodo Tracker refreshed: {len(_ioc_cache)} active C2 IPs known.")
    except Exception as e:
        print(f"⚠️ [CTI-Feed] Could not refresh Feodo Tracker feed: {e}")
        if _ioc_cache is None:
            _ioc_cache = {}
    return _ioc_cache


def extract_ips(text: str) -> list:
    """Best-effort IP extraction from free text (alert_text/output_fields JSON)."""
    return IP_PATTERN.findall(text or "")
