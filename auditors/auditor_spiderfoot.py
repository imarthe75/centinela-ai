"""
SpiderFoot Enhanced OSINT Integration

Provides real OSINT intelligence beyond the passive DNS/Shodan of discovery_osint.py:
  - Subdomain enumeration via DNS brute-force + certificate transparency
  - WHOIS parsing for domain intel
  - Certificate analysis (TLS version, cipher suites, expiry)
  - Technology fingerprinting via HTTP headers
  - Threat intelligence via AbuseIPDB / AlienVault OTX
  - Email harvesting from public sources

Results are stored in vulnerability_log (as OSINT-* CVE IDs) and
discovered sub-assets are automatically registered in infra_inventory
so the main scan loop picks them up automatically.
"""

import os
import sys
import json
import socket
import subprocess
import ssl
import datetime
import logging
import urllib.request
import urllib.parse
from typing import List, Dict, Optional, Tuple
from core import db_manager

logger = logging.getLogger(__name__)

SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
OTX_API_KEY = os.getenv("OTX_API_KEY", "")


# ─────────────────────────────────────────────
#  DNS / SUBDOMAIN DISCOVERY
# ─────────────────────────────────────────────

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "admin", "api", "dev", "staging", "test",
    "portal", "vpn", "remote", "secure", "login", "auth", "sso",
    "app", "dashboard", "panel", "backend", "frontend", "db",
    "database", "smtp", "pop", "imap", "autodiscover", "webmail",
    "static", "cdn", "assets", "upload", "files", "docs",
    "jira", "gitlab", "git", "jenkins", "sonar", "nexus",
    "grafana", "kibana", "prometheus", "monitor", "metrics",
    "vault", "consul", "kubernetes", "k8s", "rancher",
]

def extract_domain(target: str) -> str:
    """Extracts bare domain from URL or IP."""
    if target.startswith("http://") or target.startswith("https://"):
        from urllib.parse import urlparse
        parsed = urlparse(target)
        return parsed.netloc.split(":")[0]
    return target.split(":")[0].split("/")[0]

def is_ip(target: str) -> bool:
    """Returns True if target looks like an IP address."""
    import re
    return bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target))

def resolve_subdomain(subdomain: str, domain: str) -> Optional[str]:
    """Attempts to resolve a subdomain, returns IP on success."""
    fqdn = f"{subdomain}.{domain}"
    try:
        ip = socket.gethostbyname(fqdn)
        return ip
    except socket.gaierror:
        return None

def enumerate_subdomains(domain: str) -> List[Dict]:
    """
    Brute-force subdomain enumeration using common prefixes.
    Supplements with amass if available.
    Returns list of {subdomain, fqdn, ip} dicts.
    """
    print(f"🔍 [SpiderFoot] Enumerating subdomains for {domain}...")
    found = []

    # Common prefix brute-force
    for prefix in COMMON_SUBDOMAINS:
        ip = resolve_subdomain(prefix, domain)
        if ip:
            entry = {"subdomain": prefix, "fqdn": f"{prefix}.{domain}", "ip": ip}
            found.append(entry)
            print(f"   ✅ Found: {prefix}.{domain} → {ip}")

    # Try amass if available
    try:
        result = subprocess.run(
            ["amass", "enum", "-passive", "-d", domain, "-timeout", "60"],
            capture_output=True, text=True, timeout=90
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                fqdn = line.strip()
                if fqdn and f".{domain}" in fqdn:
                    try:
                        ip = socket.gethostbyname(fqdn)
                        prefix = fqdn.replace(f".{domain}", "")
                        if not any(e["fqdn"] == fqdn for e in found):
                            found.append({"subdomain": prefix, "fqdn": fqdn, "ip": ip})
                            print(f"   ✅ amass: {fqdn} → {ip}")
                    except Exception:
                        # DNS resolution failure for a passively-enumerated subdomain (e.g.
                        # NXDOMAIN) is a routine, expected outcome here, not a bug -- many
                        # passively-discovered subdomains genuinely have no live DNS record.
                        # Narrowed from a bare `except:` (which also caught
                        # KeyboardInterrupt/SystemExit) rather than adding per-subdomain noise.
                        pass
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        print(f"⚠️ [SpiderFoot-OSINT] amass unavailable or timed out for {domain}: {e}")

    print(f"   Subdomain enumeration complete: {len(found)} found")
    return found


# ─────────────────────────────────────────────
#  CERTIFICATE TRANSPARENCY (CT LOG)
# ─────────────────────────────────────────────

def query_certificate_transparency(domain: str) -> List[Dict]:
    """
    Queries crt.sh for certificate transparency log entries.
    Discovers additional subdomains from SSL certificate SAN fields.
    """
    print(f"🔐 [SpiderFoot] Querying CT logs for {domain}...")
    found = []

    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        req = urllib.request.Request(url, headers={"User-Agent": "Centinela-AI/1.0"})
        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode())

        seen = set()
        for cert in data:
            name = cert.get("name_value", "")
            for fqdn in name.split("\n"):
                fqdn = fqdn.strip().lstrip("*.")
                if fqdn.endswith(f".{domain}") and fqdn not in seen:
                    seen.add(fqdn)
                    try:
                        ip = socket.gethostbyname(fqdn)
                    except: ip = None
                    found.append({
                        "fqdn": fqdn,
                        "ip": ip,
                        "issuer": cert.get("issuer_name", ""),
                        "not_before": cert.get("not_before", ""),
                        "not_after": cert.get("not_after", ""),
                        "source": "ct_log"
                    })
                    if ip:
                        print(f"   ✅ CT Log: {fqdn} → {ip}")

        print(f"   CT log returned {len(found)} unique subdomains")
    except Exception as e:
        logger.warning(f"CT log query failed: {e}")

    return found


# ─────────────────────────────────────────────
#  TLS CERTIFICATE ANALYSIS
# ─────────────────────────────────────────────

def analyze_tls_certificate(host: str, port: int = 443) -> Dict:
    """Analyzes TLS certificate for security issues."""
    issues = []
    cert_info = {}

    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()

                # Check expiry
                not_after = datetime.datetime.strptime(cert.get("notAfter", ""), "%b %d %H:%M:%S %Y %Z")
                days_left = (not_after - datetime.datetime.utcnow()).days
                if days_left < 30:
                    issues.append(f"Certificate expires in {days_left} days!")
                elif days_left < 90:
                    issues.append(f"Certificate expires in {days_left} days (renew soon)")

                # Check cipher suite
                cipher_name = cipher[0] if cipher else "Unknown"
                if any(weak in cipher_name for weak in ["RC4", "DES", "3DES", "NULL", "EXPORT"]):
                    issues.append(f"Weak cipher suite: {cipher_name}")

                # Check TLS version
                tls_version = ssock.version()
                if tls_version in ["TLSv1", "TLSv1.1", "SSLv3", "SSLv2"]:
                    issues.append(f"Deprecated TLS version: {tls_version}")

                cert_info = {
                    "subject": dict(x[0] for x in cert.get("subject", [])),
                    "issuer": dict(x[0] for x in cert.get("issuer", [])),
                    "not_before": cert.get("notBefore"),
                    "not_after": cert.get("notAfter"),
                    "days_left": days_left,
                    "cipher": cipher_name,
                    "tls_version": tls_version,
                    "issues": issues
                }

    except ssl.SSLCertVerificationError as e:
        issues.append(f"TLS certificate validation error: {e}")
        cert_info = {"issues": issues}
    except Exception as e:
        logger.debug(f"TLS analysis failed for {host}:{port}: {e}")
        return {}

    return cert_info


# ─────────────────────────────────────────────
#  HTTP HEADER FINGERPRINTING
# ─────────────────────────────────────────────

def analyze_http_headers(url: str) -> Dict:
    """Analyzes HTTP response headers for security misconfigurations."""
    issues = []
    headers_found = {}

    security_headers_expected = {
        "Strict-Transport-Security": "HSTS missing - MITM downgrade risk",
        "X-Content-Type-Options": "X-Content-Type-Options missing - MIME sniffing risk",
        "X-Frame-Options": "Clickjacking protection missing",
        "Content-Security-Policy": "No CSP - XSS injection risk",
        "Referrer-Policy": "No Referrer-Policy - information leakage",
        "Permissions-Policy": "No Permissions-Policy header",
    }

    dangerous_headers = {
        "Server": "Server version disclosure",
        "X-Powered-By": "Technology version disclosure",
        "X-AspNet-Version": "ASP.NET version disclosure",
        "X-AspNetMvc-Version": "ASP.NET MVC version disclosure",
    }

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Centinela-AI/1.0"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            headers_found = dict(resp.headers)

            # Check missing security headers
            for header, issue_msg in security_headers_expected.items():
                if header not in resp.headers:
                    issues.append(issue_msg)

            # Check dangerous info-disclosure headers
            for header, issue_msg in dangerous_headers.items():
                if header in resp.headers:
                    issues.append(f"{issue_msg}: {resp.headers[header]}")

    except Exception as e:
        logger.debug(f"HTTP header analysis failed for {url}: {e}")

    return {"headers": headers_found, "issues": issues}


# ─────────────────────────────────────────────
#  THREAT INTELLIGENCE
# ─────────────────────────────────────────────

def query_abuseipdb(ip: str) -> Dict:
    """Checks IP against AbuseIPDB threat intelligence database."""
    if not ABUSEIPDB_API_KEY:
        return {}

    try:
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
        req = urllib.request.Request(url, headers={
            "Key": ABUSEIPDB_API_KEY,
            "Accept": "application/json"
        })
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())
            return data.get("data", {})
    except Exception as e:
        logger.debug(f"AbuseIPDB query failed: {e}")
        return {}

def query_alienvault_otx(ip_or_domain: str) -> Dict:
    """Queries AlienVault OTX for threat intelligence."""
    if not OTX_API_KEY:
        return {}

    try:
        is_domain = not is_ip(ip_or_domain)
        indicator_type = "domain" if is_domain else "IPv4"
        url = f"https://otx.alienvault.com/api/v1/indicators/{indicator_type}/{ip_or_domain}/general"
        req = urllib.request.Request(url, headers={"X-OTX-API-KEY": OTX_API_KEY})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())
            return {
                "pulse_count": data.get("pulse_info", {}).get("count", 0),
                "reputation": data.get("reputation", 0),
                "malware_families": [p.get("name") for p in data.get("pulse_info", {}).get("pulses", [])[:5]]
            }
    except Exception as e:
        logger.debug(f"OTX query failed: {e}")
        return {}


# ─────────────────────────────────────────────
#  DB STORAGE
# ─────────────────────────────────────────────

def log_osint_finding(asset_id: int, cve_id: str, severity: str, description: str):
    """
    Stores OSINT finding in vulnerability_log. Previously used
    `ON CONFLICT (asset_id, cve_id) DO UPDATE`, which requires a real unique constraint on
    exactly those columns to exist -- confirmed live it never did (only the id primary key and
    some plain, non-unique indexes exist on this table), so every single call here was silently
    throwing a real database error, caught by the broad except below and logged, but never
    actually persisted. Confirmed live: 0 spiderfoot-sourced rows existed in production despite
    this function having been called routinely -- every OSINT finding this engine ever produced
    was silently lost.
    """
    try:
        from core import deduplication_engine
        with db_manager.get_db_cursor() as cur:
            deduplication_engine.log_finding_deduplicated(
                cur, asset_id, cve_id, severity, description, "spiderfoot",
                url_path=cve_id, open_status="NEW", preserve_status=True
            )
    except Exception as e:
        logger.error(f"Error logging OSINT finding: {e}")

def register_discovered_asset(parent_asset_id: int, fqdn: str, ip: Optional[str], source: str):
    """
    Registers a newly discovered sub-asset (subdomain) in infra_inventory
    so the main scan loop will pick it up automatically.
    """
    try:
        with db_manager.get_db_cursor() as cur:
            cur.execute("""
                INSERT INTO infra_inventory (asset_name, asset_type, endpoint, criticality, status)
                VALUES (%s, 'URL', %s, 'MEDIUM', 'active')
                ON CONFLICT (asset_name) DO NOTHING
            """, (f"OSINT-DISC-{fqdn}", f"https://{fqdn}" if ip else fqdn))
            print(f"   📋 Registered discovered asset: {fqdn} ({ip})")
    except Exception as e:
        logger.debug(f"Could not register {fqdn}: {e}")


# ─────────────────────────────────────────────
#  MAIN ORCHESTRATOR
# ─────────────────────────────────────────────

def run_spiderfoot_osint(target: str, asset_id: int):
    """
    Runs comprehensive OSINT against a target URL/domain/IP.

    Steps:
    1. Subdomain enumeration (DNS + amass)
    2. Certificate transparency logs (crt.sh)
    3. TLS certificate analysis
    4. HTTP security header analysis
    5. Threat intelligence (AbuseIPDB + OTX if keys present)
    6. Register new sub-assets for automatic scanning

    Args:
        target: URL, domain, or IP to investigate
        asset_id: infra_inventory primary key
    """
    domain = extract_domain(target)
    print(f"🕵️  [SpiderFoot] Starting OSINT for target: {target} (domain: {domain})")

    all_findings = []

    # ── Step 1: Subdomain Enumeration ─────────────────────
    if not is_ip(domain):
        subdomains = enumerate_subdomains(domain)
        ct_subdomains = query_certificate_transparency(domain)

        # Merge and deduplicate
        seen_fqdns = set()
        all_subdomains = subdomains + ct_subdomains
        unique_subdomains = []
        for s in all_subdomains:
            fqdn = s.get("fqdn", "")
            if fqdn and fqdn not in seen_fqdns:
                seen_fqdns.add(fqdn)
                unique_subdomains.append(s)

        if unique_subdomains:
            subdomain_list = "\n".join([f"- `{s['fqdn']}` → {s.get('ip', 'unresolved')}" for s in unique_subdomains[:30]])
            log_osint_finding(
                asset_id=asset_id,
                cve_id="OSINT-SUBDOMAIN-DISCOVERY",
                severity="Info",
                description=(
                    f"**Subdomain Discovery (SpiderFoot)** 🔍\n\n"
                    f"**Target:** `{domain}`\n"
                    f"**Found:** {len(unique_subdomains)} subdomains via DNS brute-force + CT logs\n\n"
                    f"**Subdomains:**\n{subdomain_list}\n\n"
                    f"**Next Step:** These subdomains will be auto-registered for scanning."
                )
            )
            all_findings.append(f"subdomains:{len(unique_subdomains)}")

            # Register top discovered assets for automatic scanning
            for sub in unique_subdomains[:10]:  # cap to avoid flooding
                if sub.get("ip"):
                    register_discovered_asset(asset_id, sub["fqdn"], sub["ip"], "spiderfoot")

    # ── Step 2: TLS Certificate Analysis ──────────────────
    host = domain
    tls_info = analyze_tls_certificate(host, port=443)
    if tls_info and tls_info.get("issues"):
        issues_text = "\n".join([f"- {i}" for i in tls_info["issues"]])
        severity = "HIGH" if any("expires in" in i and "days!" in i for i in tls_info["issues"]) else "MEDIUM"
        severity = "CRITICAL" if any("Deprecated TLS" in i or "Weak cipher" in i for i in tls_info["issues"]) else severity
        log_osint_finding(
            asset_id=asset_id,
            cve_id="OSINT-TLS-MISCONFIGURATION",
            severity=severity,
            description=(
                f"**TLS/Certificate Issues Detected** 🔐\n\n"
                f"**Host:** `{host}:443`\n"
                f"**TLS Version:** {tls_info.get('tls_version', 'Unknown')}\n"
                f"**Cipher:** {tls_info.get('cipher', 'Unknown')}\n"
                f"**Certificate Expires:** {tls_info.get('not_after', 'Unknown')} ({tls_info.get('days_left', '?')} days)\n\n"
                f"**Issues Found:**\n{issues_text}"
            )
        )
        all_findings.append("tls_issues")

    # ── Step 3: HTTP Security Headers ─────────────────────
    http_url = target if target.startswith("http") else f"https://{domain}"
    headers_info = analyze_http_headers(http_url)
    if headers_info.get("issues"):
        issues_text = "\n".join([f"- {i}" for i in headers_info["issues"]])
        log_osint_finding(
            asset_id=asset_id,
            cve_id="OSINT-MISSING-SECURITY-HEADERS",
            severity="MEDIUM",
            description=(
                f"**Missing Security Headers** 🛡️\n\n"
                f"**URL:** `{http_url}`\n\n"
                f"**Issues Found:**\n{issues_text}\n\n"
                f"**Fix:** Add the missing security headers in your web server/application configuration."
            )
        )
        all_findings.append("missing_headers")

    # ── Step 4: Threat Intelligence ───────────────────────
    try:
        # Resolve to IP for threat intel
        intel_ip = domain if is_ip(domain) else socket.gethostbyname(domain)

        abuse_data = query_abuseipdb(intel_ip)
        if abuse_data.get("abuseConfidenceScore", 0) > 25:
            log_osint_finding(
                asset_id=asset_id,
                cve_id="OSINT-THREAT-INTEL-ABUSEIPDB",
                severity="HIGH",
                description=(
                    f"**Threat Intelligence Alert (AbuseIPDB)** ⚠️\n\n"
                    f"**IP:** `{intel_ip}`\n"
                    f"**Abuse Confidence Score:** {abuse_data.get('abuseConfidenceScore')}%\n"
                    f"**Total Reports:** {abuse_data.get('totalReports', 0)}\n"
                    f"**Usage Type:** {abuse_data.get('usageType', 'Unknown')}\n"
                    f"**ISP:** {abuse_data.get('isp', 'Unknown')}\n\n"
                    f"This IP has been reported for malicious activity. Review access logs and consider blocking."
                )
            )
            all_findings.append("abuse_detected")

        otx_data = query_alienvault_otx(intel_ip)
        if otx_data.get("pulse_count", 0) > 0:
            families = ", ".join(otx_data.get("malware_families", [])[:5]) or "Unknown"
            log_osint_finding(
                asset_id=asset_id,
                cve_id="OSINT-THREAT-INTEL-OTX",
                severity="HIGH",
                description=(
                    f"**Threat Intelligence Alert (AlienVault OTX)** ⚠️\n\n"
                    f"**Target:** `{intel_ip}`\n"
                    f"**OTX Pulse Count:** {otx_data.get('pulse_count', 0)}\n"
                    f"**Associated Threats:** {families}\n\n"
                    f"This IP/domain appears in {otx_data.get('pulse_count')} threat intelligence feeds."
                )
            )
            all_findings.append("otx_threat")

    except Exception as e:
        logger.debug(f"Threat intel lookup failed: {e}")

    summary = ", ".join(all_findings) if all_findings else "no significant findings"
    print(f"✅ [SpiderFoot] OSINT complete for {target}: {summary}")


if __name__ == "__main__":
    if len(sys.argv) > 2:
        run_spiderfoot_osint(sys.argv[1], int(sys.argv[2]))
    else:
        print("Usage: python auditor_spiderfoot.py <target_url_or_domain> <asset_id>")
        print("Example: python auditor_spiderfoot.py https://example.com 1")
