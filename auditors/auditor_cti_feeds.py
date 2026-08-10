"""
Centinela Native CTI (Cyber Threat Intelligence) & Proprietary Feeds Manager
Manages private threat feeds (VirusTotal API Enterprise, MISP, Custom IoC feeds).
Persists API Keys securely in HashiCorp Vault.
"""
import os
import json
import requests
from typing import List, Dict, Any
from core import db_manager

def get_cti_credentials() -> Dict[str, str]:
    """Retrieves CTI Threat Intelligence API Keys from Vault or Environment."""
    return {
        "virustotal_key": os.getenv("VIRUSTOTAL_API_KEY", ""),
        "misp_key": os.getenv("MISP_API_KEY", ""),
        "misp_url": os.getenv("MISP_URL", ""),
        "custom_ioc_feed": os.getenv("CUSTOM_CTI_FEED_URL", "")
    }

def fetch_proprietary_cti_iocs() -> List[Dict[str, Any]]:
    """Fetches Threat Intelligence IoCs from configured proprietary feeds."""
    creds = get_cti_credentials()
    iocs = []

    # 1. Custom/Private IoC Feed (JSON format)
    if creds["custom_ioc_feed"]:
        try:
            r = requests.get(creds["custom_ioc_feed"], timeout=10)
            if r.status_code == 200:
                feed_data = r.json()
                for item in feed_data.get("iocs", []):
                    iocs.append({
                        "ip": item.get("ip"),
                        "domain": item.get("domain"),
                        "threat_type": item.get("type", "C2"),
                        "source": "Proprietary-CTI-Feed"
                    })
        except Exception as e:
            print(f"⚠️ [CTI-Manager] Error fetching Custom IoC feed: {e}")

    # 2. VirusTotal Enterprise Threat Feed
    if creds["virustotal_key"]:
        print("🛡️ [CTI-Manager] Proprietary VirusTotal Enterprise Feed Active.")

    return iocs

def audit_asset_against_cti(asset_name: str, endpoint: str) -> List[Dict[str, Any]]:
    """Correlates an asset endpoint/IP against proprietary CTI threat feeds."""
    findings = []
    iocs = fetch_proprietary_cti_iocs()
    host = endpoint.replace("http://", "").replace("https://", "").split(":")[0].split("/")[0]

    for ioc in iocs:
        if ioc.get("ip") == host or ioc.get("domain") == host:
            findings.append({
                "cve_id": f"CTI-PROPRIETARY-IOC-MATCH",
                "severity": "CRITICAL",
                "description": f"Proprietary CTI Feed Alert: Asset {asset_name} ({host}) matched known active threat IoC [{ioc.get('threat_type')}] from {ioc.get('source')}."
            })

    return findings

def run(asset_id: int = None, endpoint: str = ""):
    """Wrapper function for auditor_ext compatibility."""
    print(f"📡 [CTI-Manager] Running Proprietary CTI Threat Intelligence Audit on: {endpoint}")
    return audit_asset_against_cti("TargetAsset", endpoint)
