"""Trivy CBOM -> findings for certificates baked into an image (auditors/trivy_crypto.py)."""
from datetime import datetime, timezone

import pytest

from auditors import trivy_crypto as t

NOW = datetime(2026, 11, 6, tzinfo=timezone.utc)


def _cbom(location, subject="CN=app.internal", issuer="CN=Internal CA", not_after="2030-01-01T00:00:00+00:00",
          sig="RSA-PKCS1-1.5-SHA-256", key_size=2048, key_level=112):
    alg_ref = f"crypto:algorithm:rsa:{key_size}"
    return {"bomFormat": "CycloneDX", "components": [
        {"bom-ref": "cert1", "type": "cryptographic-asset", "name": subject,
         "evidence": {"occurrences": [{"location": location}]},
         "cryptoProperties": {"assetType": "certificate", "certificateProperties": {
             "subjectName": subject, "issuerName": issuer, "notValidAfter": not_after,
             "relatedCryptographicAssets": [{"type": "algorithm", "ref": "sig1"}, {"type": "publicKey", "ref": "key1"}]}}},
        {"bom-ref": "sig1", "type": "cryptographic-asset", "name": sig,
         "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": {"primitive": "signature"}}},
        {"bom-ref": "key1", "type": "cryptographic-asset", "name": f"RSA-{key_size} public key",
         "cryptoProperties": {"assetType": "related-crypto-material", "relatedCryptoMaterialProperties": {
             "type": "public-key", "size": key_size, "relatedCryptographicAssets": [{"type": "algorithm", "ref": alg_ref}]}}},
        {"bom-ref": alg_ref, "type": "cryptographic-asset", "name": f"RSA-{key_size}",
         "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": {"classicalSecurityLevel": key_level}}},
    ]}


def ids(found):
    return sorted(f["cve_id"] for f in found)


def test_trust_store_certificates_are_ignored_even_if_weak_or_expired():
    for loc in ("etc/ssl/certs/ca-certificates.crt", "usr/lib/python3/site-packages/certifi/cacert.pem",
                "usr/local/lib/python3.11/site-packages/grpc/_cython/_credentials/roots.pem"):
        cb = _cbom(loc, not_after="2010-01-01T00:00:00+00:00", sig="RSA-PKCS1-1.5-SHA-1", key_size=1024, key_level=80)
        assert t.findings_from_cbom(cb, "img", NOW) == []


def test_healthy_own_certificate_has_no_findings():
    assert t.findings_from_cbom(_cbom("app/certs/client.pem"), "img", NOW) == []


def test_expired_weak_and_sha1_own_certificate():
    cb = _cbom("app/certs/client.pem", not_after="2024-05-01T00:00:00+00:00", sig="RSA-PKCS1-1.5-SHA-1", key_size=1024, key_level=80)
    found = t.findings_from_cbom(cb, "img", NOW)
    assert ids(found) == [t.RULE_EXPIRED, t.RULE_WEAK_KEY, t.RULE_WEAK_SIGNATURE]
    assert all(f["url_path"] == "img/app/certs/client.pem" for f in found)
    assert {f["severity"] for f in found if f["cve_id"] == t.RULE_WEAK_KEY} == {"HIGH"}


def test_rsa_size_fallback_when_level_missing():
    cb = _cbom("app/c.pem", key_size=1024, key_level=None)
    assert ids(t.findings_from_cbom(cb, "img", NOW)) == [t.RULE_WEAK_KEY]


def test_self_signed_sha1_is_not_a_signature_finding():
    cb = _cbom("app/c.pem", subject="CN=x", issuer="CN=x", sig="RSA-PKCS1-1.5-SHA-1")
    assert t.findings_from_cbom(cb, "img", NOW) == []


def test_parse_rejects_non_cyclonedx():
    with pytest.raises(ValueError):
        t.parse('{"Results": []}')
    with pytest.raises(ValueError):
        t.parse("not json")


def test_summarize_counts_only_own_certificates():
    cb = _cbom("app/c.pem")
    assert t.summarize(cb) == {"crypto_assets": 4, "own_certificates": 1}
