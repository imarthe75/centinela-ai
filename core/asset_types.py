"""Asset-type groups and the public-target guard shared by every active scanner (2026-11-13).

Why this exists: the registration form offers "Servidor Linux" (SERVER_LINUX) and SERVER_WINDOWS, but each scanner kept its own
literal list of host types and none of them included those two, so a server registered from the form was never port-scanned,
never got nuclei/WSTG, CIS, OS-patch or TLS checks. One list here, used everywhere.

Opening those types up also exposed a second gap: nothing stopped an active scan against an address outside the organization
(an asset with a public IP was registered as SERVER_LINUX). Active scanning is only allowed against private/internal addresses
unless the target is listed in SCAN_ALLOWED_PUBLIC_TARGETS (comma-separated host names or IPs) -- fail-closed.
"""
import ipaddress
import logging
import os
import socket
from typing import Optional, Tuple
from urllib.parse import urlparse

logger = logging.getLogger("centinela.asset_types")

# Hosts reached over SSH with Linux checks (CIS Level 1, pending OS patches).
LINUX_HOST_TYPES = ("SERVER", "SERVER_LINUX", "AppServer", "Database (SQL)", "GITLAB")
# Hosts that get the network-level scan (ports, nuclei, WSTG on web ports): any OS.
NETWORK_HOST_TYPES = ("AppServer", "SERVER", "SERVER_LINUX", "SERVER_WINDOWS", "KUBERNETES", "Datacenter")
# Endpoints whose TLS posture is checked.
TLS_TYPES = ("SERVER", "SERVER_LINUX", "SERVER_WINDOWS", "AppServer", "GITLAB", "URL", "API-Gateway", "Identity-IdP")


def endpoint_host(endpoint: str) -> Optional[str]:
    """Host part of an endpoint that may be a bare IP/host, host:port, or a URL."""
    e = (endpoint or "").strip()
    if not e or e == "remote-agent":
        return None
    try:
        return urlparse(e if "://" in e else f"//{e}").hostname
    except ValueError:
        return None


def _allowed_public() -> set:
    return {h.strip().lower() for h in os.getenv("SCAN_ALLOWED_PUBLIC_TARGETS", "").split(",") if h.strip()}


def scan_target_allowed(endpoint: str) -> Tuple[bool, str]:
    """(allowed, reason). Private, loopback-free internal addresses pass; public ones only when explicitly allowlisted;
    an endpoint whose host does not resolve passes (the scanner itself will just fail to connect -- nothing leaves the network)."""
    host = endpoint_host(endpoint)
    if not host:
        return True, "sin host de red"
    if host.lower() in _allowed_public():
        return True, "destino público autorizado en SCAN_ALLOWED_PUBLIC_TARGETS"
    try:
        addrs = {ai[4][0] for ai in socket.getaddrinfo(host, None)}
    except socket.gaierror:
        return True, "el nombre no resuelve"
    for a in addrs:
        ip = ipaddress.ip_address(a.split("%")[0])
        if not ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast:
            return False, (f"{host} resuelve a {ip}, fuera de la red interna; no se escanea sin autorización "
                           f"(añádalo a SCAN_ALLOWED_PUBLIC_TARGETS si la organización es dueña de ese destino)")
    return True, "red interna"


def url_scan_target(asset_name: str, endpoint: str) -> str:
    """The URL to scan for a URL-type asset. The form can store the full URL as the name and only the host as the endpoint
    (seen 2026-11-13: name 'http://192.0.2.12/fe-.../auth/login', endpoint '192.0.2.12'), which made every web scanner receive a
    scheme-less address. Prefer the endpoint when it is a URL; otherwise the name when it is a URL on that same host;
    otherwise http://<endpoint>."""
    e = (endpoint or "").strip()
    if "://" in e:
        return e
    n = (asset_name or "").strip()
    if "://" in n and endpoint_host(n) and endpoint_host(n) == endpoint_host(e):
        return n
    return f"http://{e}" if e else n
