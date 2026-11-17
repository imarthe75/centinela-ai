"""
Certificates baked into a container image -- from Trivy's crypto inventory (CBOM).

`trivy image --scanners crypto --format cyclonedx` (Trivy 0.75+) lists every X.509 certificate it finds in the image's files,
with its validity, signature algorithm and public key. On a normal image almost all of them are public trust stores (the OS
CA bundle, certifi, botocore, grpc roots): those are skipped, an expired or SHA-1 root inside a trust store is not something
the image owner can fix and does not mean the image uses it.

What is left are certificates someone added to the image on purpose (a client certificate, an internal CA, a test cert copied
in by mistake). Those produce a finding when they are expired, carry a weak key (security level < 112 bits, i.e. RSA < 2048)
or are signed with SHA-1/MD5. Measured on Centinela's own images (2026-11-06): 432 crypto assets, all inside trust stores,
0 findings. Private keys are not in this inventory (Trivy's secret scanner covers them).
"""
import json
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

RULE_EXPIRED = "IMAGE-CERT-EXPIRED"
RULE_WEAK_KEY = "IMAGE-CERT-WEAK-KEY"
RULE_WEAK_SIGNATURE = "IMAGE-CERT-WEAK-SIGNATURE"

# Path fragments of public trust stores shipped by the OS, language runtimes and libraries.
TRUST_STORE_MARKERS = (
    "etc/ssl/certs/", "etc/pki/", "usr/share/ca-certificates/", "ca-certificates.crt", "ca-bundle",
    "cacert.pem", "certifi/", "/cacerts", "roots.pem", "trusted.pem", "tls-ca-bundle",
)
WEAK_SIGNATURE_MARKERS = ("SHA-1", "SHA1", "MD5", "MD2")
MIN_SECURITY_BITS = 112   # NIST SP 800-57: RSA-2048 / P-224 and up


def is_trust_store(location: str) -> bool:
    loc = (location or "").lower()
    return any(m in loc for m in TRUST_STORE_MARKERS)


def _parse_time(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def own_certificates(cbom: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Certificates found outside public trust stores, with their key and signature algorithm resolved."""
    comps = {c.get("bom-ref"): c for c in cbom.get("components", []) if c.get("type") == "cryptographic-asset"}
    out = []
    for c in comps.values():
        props = c.get("cryptoProperties", {})
        if props.get("assetType") != "certificate":
            continue
        locations = [o.get("location", "") for o in c.get("evidence", {}).get("occurrences", [])]
        own = [loc for loc in locations if not is_trust_store(loc)]
        if not own:
            continue
        cert = props.get("certificateProperties", {})
        signature = key = None
        for rel in cert.get("relatedCryptographicAssets", []):
            target = comps.get(rel.get("ref"))
            if not target:
                continue
            if rel.get("type") == "algorithm":
                signature = target
            elif rel.get("type") == "publicKey":
                key = target
        key_bits = None
        if key is not None:
            material = key.get("cryptoProperties", {}).get("relatedCryptoMaterialProperties", {})
            for rel in material.get("relatedCryptographicAssets", []):
                alg = comps.get(rel.get("ref"))
                if rel.get("type") == "algorithm" and alg:
                    key_bits = alg.get("cryptoProperties", {}).get("algorithmProperties", {}).get("classicalSecurityLevel")
            if key_bits is None and key.get("name", "").upper().startswith("RSA") and isinstance(material.get("size"), int):
                # RSA size -> classical security level (NIST SP 800-57 table 2)
                size = material["size"]
                key_bits = 80 if size < 2048 else 112 if size < 3072 else 128
        out.append({
            "subject": cert.get("subjectName", ""),
            "issuer": cert.get("issuerName", ""),
            "not_after": cert.get("notValidAfter"),
            "fingerprint": (cert.get("fingerprint") or {}).get("content", ""),
            "locations": own,
            "signature": (signature or {}).get("name", ""),
            "key": (key or {}).get("name", ""),
            "key_security_bits": key_bits,
        })
    return out


def findings_from_cbom(cbom: Dict[str, Any], image: str, now: Optional[datetime] = None) -> List[Dict[str, Any]]:
    """[{cve_id, severity, url_path, description}] for the image's own certificates that are expired, weak-keyed or SHA-1/MD5-signed."""
    now = now or datetime.now(timezone.utc)
    results = []
    for cert in own_certificates(cbom):
        where = f"{image}/{cert['locations'][0]}"
        label = f"[{image}] {cert['locations'][0]}: certificado «{cert['subject']}»"
        if len(cert["locations"]) > 1:
            label += f" (y {len(cert['locations']) - 1} ubicación(es) más)"
        not_after = _parse_time(cert["not_after"])
        if not_after and not_after < now:
            results.append({"cve_id": RULE_EXPIRED, "severity": "MEDIUM", "url_path": where,
                            "description": f"{label} venció el {not_after.date().isoformat()}. Un certificado vencido dentro de la "
                                           "imagen falla al usarse o invita a desactivar la validación. Renovarlo o quitarlo de la imagen."})
        bits = cert["key_security_bits"]
        if isinstance(bits, (int, float)) and bits < MIN_SECURITY_BITS:
            results.append({"cve_id": RULE_WEAK_KEY, "severity": "HIGH", "url_path": where,
                            "description": f"{label} usa una llave débil ({cert['key'] or 'desconocida'}, {int(bits)} bits de seguridad; "
                                           f"el mínimo es {MIN_SECURITY_BITS}, RSA-2048). Reemitirlo con RSA ≥ 2048 o ECDSA P-256+."})
        sig = cert["signature"].upper()
        self_signed = cert["subject"] and cert["subject"] == cert["issuer"]
        if any(m in sig for m in WEAK_SIGNATURE_MARKERS) and not self_signed:
            results.append({"cve_id": RULE_WEAK_SIGNATURE, "severity": "MEDIUM", "url_path": where,
                            "description": f"{label} está firmado con {cert['signature']}, un algoritmo de firma roto. Reemitirlo con SHA-256 o superior."})
    return results


def parse(stdout: str) -> Dict[str, Any]:
    """CycloneDX JSON from trivy. Raises ValueError when trivy did not produce a document (never read as 'no certificates')."""
    data = json.loads(stdout)
    if not isinstance(data, dict) or data.get("bomFormat") != "CycloneDX":
        raise ValueError("trivy did not return a CycloneDX document")
    return data


def summarize(cbom: Dict[str, Any]) -> Dict[str, int]:
    comps: Iterable[Dict[str, Any]] = (c for c in cbom.get("components", []) if c.get("type") == "cryptographic-asset")
    total = own = 0
    for c in comps:
        total += 1
        if c.get("cryptoProperties", {}).get("assetType") == "certificate" and any(
                not is_trust_store(o.get("location", "")) for o in c.get("evidence", {}).get("occurrences", [])):
            own += 1
    return {"crypto_assets": total, "own_certificates": own}
