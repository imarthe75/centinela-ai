import os
import sys
import json
import socket
import urllib.request
from urllib.error import URLError
from core import db_manager

SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")

def passive_dns_resolve(domain):
    """Performs passive DNS resolution using standard socket library."""
    print(f"🌐 [OSINT-Discovery] Resolving domain: {domain}")
    try:
        # Strip scheme if present
        host = domain
        if "://" in host:
            host = host.split("://")[1]
        if ":" in host:
            host = host.split(":")[0]
        if "/" in host:
            host = host.split("/")[0]
            
        ip = socket.gethostbyname(host)
        print(f"✅ [OSINT-Discovery] Resolved {domain} to {ip}")
        return ip
    except Exception as e:
        print(f"⚠️ [OSINT-Discovery] DNS resolution failed for {domain}: {e}")
        return None

def geolocate_ip_passive(ip):
    """
    Geolocates IP passively using ip-api.com; RFC1918/loopback ranges are correctly reported
    as internal without a network call (that's real, known-true information, not a guess).
    Returns {"real": bool, ...} -- "real": False previously didn't exist at all: on any failure
    of the public geolocation call (timeout, non-200, rate limit) this silently returned a fixed
    hardcoded {"Mexico", "Querétaro", "CASMARTS Headquarters"} for every single IP regardless of
    where it actually is, presented downstream as if it were a genuine lookup result -- a real
    violation of this project's own zero-fabrication rule, caught during a live gap-sweep
    (2026-08-13). Now returns an honest "unavailable" result instead of a fabricated guess.
    """
    parts = ip.split('.')
    if len(parts) == 4:
        if (parts[0] == '10' or
            (parts[0] == '172' and 16 <= int(parts[1]) <= 31) or
            (parts[0] == '192' and parts[1] == '168') or
            parts[0] == '127'):
            return {
                "real": True,
                "country": "Local Network",
                "city": "Internal LAN",
                "org": "CASMARTS Internal Spoke"
            }

    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,message,country,city,org"
        with urllib.request.urlopen(url, timeout=5) as response:
            data = json.loads(response.read().decode())
            if data.get("status") == "success":
                return {
                    "real": True,
                    "country": data.get("country", "Unknown"),
                    "city": data.get("city", "Unknown"),
                    "org": data.get("org", "Unknown")
                }
    except Exception as e:
        print(f"⚠️ [OSINT-Discovery] Geolocation service failed: {e}")

    return {"real": False, "country": "Unknown", "city": "Unknown", "org": "Unknown"}

def shodan_query_passive(ip):
    """
    Queries the real Shodan API when SHODAN_API_KEY is configured. Returns {"real": bool, ...}.
    Previously, with no key configured (the only configuration this deployment has ever had --
    confirmed live 2026-08-13: SHODAN_API_KEY is unset), this silently returned a fixed,
    entirely fabricated port/service list (e.g. claiming Nginx/PostgreSQL/Valkey/Vault were
    "detected passively" on every single internal IP) with no real scan behind it at all -- a
    real violation of this project's zero-fabrication rule, not just a cosmetic placeholder.
    Now honestly reports no real data instead of guessing.
    """
    print(f"🔍 [OSINT-Discovery] Querying Shodan passively for: {ip}")
    if SHODAN_API_KEY:
        try:
            url = f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}"
            with urllib.request.urlopen(url, timeout=5) as response:
                data = json.loads(response.read().decode())
                ports = data.get("ports", [])
                services = [item.get("product", "") for item in data.get("data", []) if item.get("product")]
                return {
                    "real": True,
                    "ports": ports,
                    "services": list(set(services)),
                    "vulns": data.get("vulns", [])
                }
        except Exception as e:
            print(f"⚠️ [OSINT-Discovery] Shodan API request failed: {e}")
    else:
        print("⏭️ [OSINT-Discovery] SHODAN_API_KEY not configured -- skipping passive port/service enrichment (no fabricated fallback).")

    return {"real": False, "ports": [], "services": [], "vulns": []}

def run_osint_discovery():
    """Main routine to discover surface details of assets registered in infra_inventory."""
    print("🚀 [OSINT-Discovery] Starting Passive OSINT Gathering Cycle...")
    
    try:
        with db_manager.get_db_cursor() as cur:
            # Query domains, URLs, and IPs to enrich
            cur.execute("""
                SELECT id, asset_name, asset_type, endpoint, criticality 
                FROM infra_inventory 
                WHERE asset_type IN ('IP', 'URL', 'AppServer')
            """)
            assets = cur.fetchall()
    except Exception as e:
        print(f"❌ [OSINT-Discovery] Failed to query database: {e}")
        return
        
    for asset_id, name, asset_type, endpoint, criticality in assets:
        try:
            print(f"\n🔎 Processing Asset: {name} ({asset_type})")
            
            # 1. Resolve host IP if domain/URL
            resolved_ip = None
            if asset_type == 'URL':
                resolved_ip = passive_dns_resolve(endpoint)
            elif asset_type == 'IP':
                resolved_ip = endpoint
            elif asset_type == 'AppServer':
                # AppServer might have IP address in endpoint
                if endpoint != 'remote-agent':
                    resolved_ip = endpoint
                    
            if not resolved_ip:
                print(f"⏭️ Could not resolve IP for asset: {name}. Skipping enrich.")
                continue
                
            # 2. Geolocate IP
            geo = geolocate_ip_passive(resolved_ip)
            print(f"📍 Geolocation: {geo['city']}, {geo['country']} ({geo['org']})")

            # 3. Shodan passive profile
            shodan_info = shodan_query_passive(resolved_ip)
            print(f"📡 Passive Ports: {shodan_info['ports']}")
            print(f"🛠️ Services: {shodan_info['services']}")

            # If neither source produced real data, there's nothing genuine to report --
            # skip rather than log an enrichment entry with no real content behind it (see
            # geolocate_ip_passive/shodan_query_passive: both used to silently fabricate
            # plausible-looking data for exactly this case).
            if not geo["real"] and not shodan_info["real"]:
                print(f"⏭️ No real passive OSINT data available for {name} ({resolved_ip}) -- skipping enrichment entry.")
                continue

            # 4. Save metadata back to DB as an audit log/enrichment
            geo_line = (f"**Geolocalización:** {geo['city']}, {geo['country']} - {geo['org']}\n"
                        if geo["real"] else "**Geolocalización:** No disponible (servicio de geolocalización no respondió).\n")
            if shodan_info["real"]:
                ports_line = f"**Puertos Detectados Pasivamente (Shodan):** {', '.join(map(str, shodan_info['ports']))}\n"
                services_line = f"**Tecnologías/Servicios (Shodan):** {', '.join(shodan_info['services'])}\n"
            else:
                ports_line = "**Puertos/Servicios:** No disponible (SHODAN_API_KEY no configurada).\n"
                services_line = ""

            enrich_summary = (
                f"ℹ️ **ENRIQUECIMIENTO OSINT PASIVO** ℹ️\n\n"
                f"**IP Resuelta:** `{resolved_ip}`\n"
                f"{geo_line}"
                f"{ports_line}"
                f"{services_line}"
            )
            if shodan_info.get('vulns'):
                enrich_summary += f"\n**Vulnerabilidades Shodan:** {', '.join(shodan_info['vulns'])}"

            # Log via the shared dedup logger -- the raw "ON CONFLICT (asset_id, cve_id)" this
            # used before targets a unique constraint that has never existed on vulnerability_log
            # (only its id primary key and a partial fingerprint_hash index do), so every single
            # insert here silently threw a real DB error, caught by this function's own broad
            # except and logged as a false "✅ Enriched" -- confirmed live: 0 real OSINT-ENRICH
            # rows exist in the DB despite this running every scan cycle. Same failure signature
            # already fixed once for auditor_spiderfoot.py; this file was missed at the time.
            from core import deduplication_engine
            with db_manager.get_db_cursor() as cur:
                deduplication_engine.log_finding_deduplicated(
                    cur, asset_id, "OSINT-ENRICH", "Info", enrich_summary,
                    "osint-passive", open_status="NEW", preserve_status=True
                )
                print(f"✅ Enriched asset {name} inside vulnerability_log")

        except Exception as e:
            print(f"❌ [OSINT-Discovery] Error enriching asset {name}: {e}")

if __name__ == "__main__":
    run_osint_discovery()
