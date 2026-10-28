"""
TLS posture auditor: certificate lifecycle/strength + protocol & cipher hygiene.

Closes a coverage gap found 2026-09-23 (nothing in Centinela looked at certificate expiry, key
strength, legacy TLS versions or weak/static-RSA cipher suites -- PCI DSS 4.1 / NIST SP 800-52r2 /
ISO A.8.24 topics). Read-only and non-intrusive: one `nmap ssl-enum-ciphers` connect scan of a
short list of well-known TLS ports per host (no port sweeps, no fuzzing) plus a normal TLS
handshake to read the certificate.

Decision logic (`evaluate_tls`) is a PURE function over parsed nmap output + parsed certificate
facts so it is unit-tested without touching the network. Anything that cannot be observed (port
closed, nmap failure, no cert) produces no finding -- never a guess.
"""
import re
import socket
import ssl
import subprocess
import traceback
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

SCAN_ENGINE = "tls-audit"
MARKER_CVE = "TLS-AUDIT"
TLS_PORTS = (443, 8443, 9443, 4443, 636, 993, 995, 465, 5986)
LEGACY_PROTOCOLS = ("SSLv3", "TLSv1.0", "TLSv1.1")
_WEAK_STRENGTH = {"D": "MEDIUM", "E": "HIGH", "F": "HIGH"}


# --------------------------------------------------------------------------- nmap
def parse_nmap_ssl_xml(xml_text: str) -> Dict[int, Dict[str, Any]]:
    """{port: {"protocols": {"TLSv1.2": [{"name":..., "strength": "A"}]}, "least_strength": "A"}}"""
    result: Dict[int, Dict[str, Any]] = {}
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return result
    for port_el in root.iter("port"):
        script = next((s for s in port_el.findall("script") if s.get("id") == "ssl-enum-ciphers"), None)
        if script is None:
            continue
        info: Dict[str, Any] = {"protocols": {}, "least_strength": None}
        for tbl in script.findall("table"):
            proto = tbl.get("key")
            ciphers = []
            for ctbl in tbl.findall("table"):
                if ctbl.get("key") != "ciphers":
                    continue
                for c in ctbl.findall("table"):
                    name = next((e.text for e in c.findall("elem") if e.get("key") == "name"), None)
                    strength = next((e.text for e in c.findall("elem") if e.get("key") == "strength"), None)
                    if name:
                        ciphers.append({"name": name, "strength": strength})
            if proto:
                info["protocols"][proto] = ciphers
        for e in script.findall("elem"):
            if e.get("key") == "least strength":
                info["least_strength"] = e.text
        result[int(port_el.get("portid"))] = info
    return result


def run_nmap_ssl_enum(host: str, ports=TLS_PORTS, timeout: int = 180) -> Optional[Dict[int, Dict[str, Any]]]:
    """None = nmap could not run at all (distinct from 'ran, found no TLS')."""
    cmd = ["nmap", "-Pn", "--script", "ssl-enum-ciphers", "-p", ",".join(str(p) for p in ports), host, "-oX", "-"]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        print(f"❌ [TLS-Audit] nmap failed for {host}:")
        traceback.print_exc()
        return None
    if res.returncode != 0:
        print(f"❌ [TLS-Audit] nmap exit {res.returncode} for {host}: {res.stderr[-300:]}")
        return None
    return parse_nmap_ssl_xml(res.stdout)


# --------------------------------------------------------------------------- certificate
def fetch_certificate_facts(host: str, port: int, timeout: float = 8.0) -> Optional[Dict[str, Any]]:
    """Normal TLS handshake (verification off: we WANT to inspect bad certs) -> parsed cert facts."""
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                der = tls.getpeercert(binary_form=True)
    except (OSError, ssl.SSLError):
        return None
    if not der:
        return None
    cert = x509.load_der_x509_certificate(der)
    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        key_type, key_bits = "RSA", pub.key_size
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        key_type, key_bits = "EC", pub.curve.key_size
    else:
        key_type, key_bits = type(pub).__name__, None
    from cryptography.exceptions import UnsupportedAlgorithm
    try:
        sig_hash = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else None
    except (UnsupportedAlgorithm, ValueError):
        sig_hash = None   # e.g. Ed25519/PSS certs have no separate hash: nothing to judge
    not_after = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after.replace(tzinfo=timezone.utc)
    return {"subject": cert.subject.rfc4514_string(), "issuer": cert.issuer.rfc4514_string(),
            "not_after": not_after, "key_type": key_type, "key_bits": key_bits, "sig_hash": sig_hash}


# --------------------------------------------------------------------------- decision (pure)
def evaluate_tls(host: str, port: int, nmap_info: Optional[Dict[str, Any]], cert: Optional[Dict[str, Any]],
                 now: Optional[datetime] = None) -> List[Dict[str, Any]]:
    now = now or datetime.now(timezone.utc)
    loc = f"{host}:{port}"
    out: List[Dict[str, Any]] = []

    if cert:
        days = (cert["not_after"] - now).days
        if cert["not_after"] < now:
            out.append({"cve_id": "TLS-CERT-EXPIRED", "severity": "CRITICAL", "url_path": loc,
                        "description": f"**Certificado TLS vencido** en {loc} (venció {cert['not_after'].date()}). "
                                       f"Los clientes lo rechazan o el usuario aprende a ignorar la advertencia (MITM trivial)."})
        elif days <= 30:
            out.append({"cve_id": "TLS-CERT-EXPIRING-SOON", "severity": "HIGH" if days <= 14 else "MEDIUM", "url_path": loc,
                        "description": f"**El certificado TLS de {loc} vence en {days} día(s)** ({cert['not_after'].date()})."})
        if cert.get("key_bits") and ((cert["key_type"] == "RSA" and cert["key_bits"] < 2048)
                                     or (cert["key_type"] == "EC" and cert["key_bits"] < 224)):
            out.append({"cve_id": "TLS-CERT-WEAK-KEY", "severity": "HIGH", "url_path": loc,
                        "description": f"**Llave del certificado débil** en {loc}: {cert['key_type']} de {cert['key_bits']} bits "
                                       f"(mínimo aceptado: RSA 2048 / EC 224)."})
        if cert.get("sig_hash") in ("sha1", "md5"):
            out.append({"cve_id": "TLS-CERT-WEAK-SIGNATURE", "severity": "HIGH", "url_path": loc,
                        "description": f"**Certificado firmado con {cert['sig_hash'].upper()}** en {loc}: algoritmo de firma roto/obsoleto."})
        if cert.get("subject") and cert["subject"] == cert.get("issuer"):
            out.append({"cve_id": "TLS-CERT-SELF-SIGNED", "severity": "LOW", "url_path": loc,
                        "description": f"**Certificado autofirmado** en {loc} ({cert['subject']}): ningún cliente puede validar su "
                                       f"identidad sin instalar manualmente ese certificado."})

    if nmap_info:
        protos = nmap_info.get("protocols", {})
        legacy = [p for p in LEGACY_PROTOCOLS if protos.get(p)]
        if legacy:
            out.append({"cve_id": "TLS-LEGACY-PROTOCOL-ENABLED", "severity": "HIGH", "url_path": loc,
                        "description": f"**Protocolo(s) TLS obsoleto(s) habilitado(s)** en {loc}: {', '.join(legacy)}. "
                                       f"PCI DSS y NIST SP 800-52r2 exigen TLS 1.2 como mínimo."})
        weak = sorted({c["name"] for ciphers in protos.values() for c in ciphers if c.get("strength") in _WEAK_STRENGTH})
        if weak:
            worst = "HIGH" if any(c.get("strength") in ("E", "F") for ciphers in protos.values() for c in ciphers) else "MEDIUM"
            out.append({"cve_id": "TLS-WEAK-CIPHER-ENABLED", "severity": worst, "url_path": loc,
                        "description": f"**Suites de cifrado débiles habilitadas** en {loc}: {', '.join(weak[:6])}"
                                       f"{'…' if len(weak) > 6 else ''}."})
        static_rsa = sorted({c["name"] for p in ("TLSv1.2",) for c in protos.get(p, []) if c["name"].startswith("TLS_RSA_WITH_")})
        if static_rsa:
            out.append({"cve_id": "TLS-STATIC-RSA-KEX-ENABLED", "severity": "LOW", "url_path": loc,
                        "description": f"**Intercambio de llaves RSA estático (sin forward secrecy)** aceptado en {loc} "
                                       f"({len(static_rsa)} suites `TLS_RSA_WITH_*`): si la llave privada se compromete, "
                                       f"todo el tráfico pasado grabado queda descifrable. Restringir a suites ECDHE."})
    return out


def evaluate_no_tls(host: str, port: int) -> Dict[str, Any]:
    return {"cve_id": "TLS-NOT-ENABLED", "severity": "HIGH", "url_path": f"{host}:{port}",
            "description": (f"**Servicio expuesto solo por HTTP sin cifrar** en {host}:{port}: el host no ofrece ningún servicio TLS "
                            f"en los puertos habituales. Credenciales y tokens de sesión viajan en texto claro (PCI DSS 4.2.1, NIST SC-8).")}


# --------------------------------------------------------------------------- orchestration
def host_from_endpoint(endpoint: str) -> Optional[str]:
    ep = str(endpoint or "").strip()
    if not ep or ep == "remote-agent":
        return None
    if "://" not in ep:
        ep = "//" + ep
    host = urlparse(ep).hostname
    return host if host and re.match(r"^[A-Za-z0-9.-]+$", host) else None


def run_tls_audit(asset_name: str, endpoint: str) -> Dict[str, Any]:
    host = host_from_endpoint(endpoint)
    if not host:
        return {"asset_name": asset_name, "evaluated_ports": [], "findings": [], "status": "no_host"}
    nmap_result = run_nmap_ssl_enum(host)
    if nmap_result is None:
        return {"asset_name": asset_name, "host": host, "evaluated_ports": [], "findings": [], "status": "scan_failed"}
    findings: List[Dict[str, Any]] = []
    for port, info in sorted(nmap_result.items()):
        cert = fetch_certificate_facts(host, port)
        findings.extend(evaluate_tls(host, port, info, cert))
    # An endpoint declared as plain http:// that answers on its port while the host offers NO TLS
    # service at all: credentials/session tokens travel in clear text.
    parsed = urlparse(str(endpoint))
    if parsed.scheme == "http" and not nmap_result:
        port = parsed.port or 80
        try:
            with socket.create_connection((host, port), timeout=5):
                findings.append(evaluate_no_tls(host, port))
        except OSError:
            pass  # not listening: nothing to report
    return {"asset_name": asset_name, "host": host, "evaluated_ports": sorted(nmap_result), "findings": findings,
            "status": "ok"}


def log_tls_findings(asset_id: str, result: Dict[str, Any]) -> int:
    from core import db_manager, deduplication_engine
    status = result["status"]
    with db_manager.get_db_cursor() as cur:
        if status == "ok":
            ports = result["evaluated_ports"]
            marker = (f"Auditoría TLS completada en {result['host']}: puertos TLS evaluados: {ports or 'ninguno'}; "
                      f"{len(result['findings'])} hallazgo(s).")
        else:
            marker = f"Auditoría TLS no ejecutada ({status}); ningún control fue evaluado."
        deduplication_engine.log_finding_deduplicated(
            cur, asset_id, MARKER_CVE, "Info", marker, SCAN_ENGINE, url_path=MARKER_CVE,
            open_status="NEW", preserve_status=True)
        if status != "ok":
            return 0
        active = {deduplication_engine.calculate_fingerprint(asset_id, MARKER_CVE, MARKER_CVE)}
        for f in result["findings"]:
            active.add(deduplication_engine.calculate_fingerprint(asset_id, f["cve_id"], f["url_path"]))
            deduplication_engine.log_finding_deduplicated(
                cur, asset_id, f["cve_id"], f["severity"], f["description"], SCAN_ENGINE,
                url_path=f["url_path"], open_status="OPEN", preserve_status=True)
        deduplication_engine.reconcile_resolved_findings(cur, asset_id, SCAN_ENGINE, active)
    return len(result["findings"])
