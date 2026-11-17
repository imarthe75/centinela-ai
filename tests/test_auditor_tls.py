from datetime import datetime, timedelta, timezone

from auditors import auditor_tls as t

NOW = datetime(2026, 9, 23, tzinfo=timezone.utc)
XML = """<nmaprun><host><ports><port protocol="tcp" portid="443"><script id="ssl-enum-ciphers" output="">
<table key="TLSv1.0"><table key="ciphers"><table><elem key="name">TLS_RSA_WITH_3DES_EDE_CBC_SHA</elem><elem key="strength">D</elem></table></table></table>
<table key="TLSv1.2"><table key="ciphers"><table><elem key="name">TLS_RSA_WITH_AES_128_GCM_SHA256</elem><elem key="strength">A</elem></table>
<table><elem key="name">TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384</elem><elem key="strength">A</elem></table></table></table>
<elem key="least strength">D</elem></script></port></ports></host></nmaprun>"""


def cert(**kw):
    base = {"subject": "CN=a", "issuer": "CN=ca", "not_after": NOW + timedelta(days=200),
            "key_type": "RSA", "key_bits": 2048, "sig_hash": "sha256"}
    base.update(kw)
    return base


def ids(c=None, n=None):
    return {f["cve_id"] for f in t.evaluate_tls("h", 443, n, c, NOW)}


def test_healthy_cert_no_findings():
    assert ids(cert()) == set()


def test_expired_expiring_weak_selfsigned():
    assert ids(cert(not_after=NOW - timedelta(days=1))) == {"TLS-CERT-EXPIRED"}
    f = t.evaluate_tls("h", 443, None, cert(not_after=NOW + timedelta(days=10)), NOW)
    assert f[0]["cve_id"] == "TLS-CERT-EXPIRING-SOON" and f[0]["severity"] == "HIGH"
    assert ids(cert(key_bits=1024)) == {"TLS-CERT-WEAK-KEY"}
    assert ids(cert(sig_hash="sha1")) == {"TLS-CERT-WEAK-SIGNATURE"}
    assert ids(cert(issuer="CN=a")) == {"TLS-CERT-SELF-SIGNED"}


def test_nmap_xml_parsing_and_protocol_cipher_findings():
    info = t.parse_nmap_ssl_xml(XML)[443]
    assert info["least_strength"] == "D" and "TLSv1.0" in info["protocols"]
    got = ids(None, info)
    assert got == {"TLS-LEGACY-PROTOCOL-ENABLED", "TLS-WEAK-CIPHER-ENABLED", "TLS-STATIC-RSA-KEX-ENABLED"}


def test_modern_only_server_is_clean_apart_from_static_rsa():
    xml = XML.replace("TLSv1.0", "TLSv1.3").replace("TLS_RSA_WITH_3DES_EDE_CBC_SHA", "TLS_AKE_WITH_AES_256_GCM_SHA384").replace('"D"', '"A"').replace(">D<", ">A<")
    assert ids(None, t.parse_nmap_ssl_xml(xml)[443]) == {"TLS-STATIC-RSA-KEX-ENABLED"}


def test_garbage_xml_and_missing_inputs_yield_nothing():
    assert t.parse_nmap_ssl_xml("not xml") == {}
    assert ids(None, None) == set()


def test_host_extraction():
    assert t.host_from_endpoint("http://192.0.2.11:8092/citaOnline/") == "192.0.2.11"
    assert t.host_from_endpoint("postgresql://192.0.2.15:5432") == "192.0.2.15"
    assert t.host_from_endpoint("192.0.2.16") == "192.0.2.16"
    assert t.host_from_endpoint("remote-agent") is None


def test_no_tls_finding_shape_and_guidance():
    f = t.evaluate_no_tls("192.0.2.14", 80)
    assert f["cve_id"] == "TLS-NOT-ENABLED" and f["severity"] == "HIGH" and f["url_path"] == "192.0.2.14:80"
    import centinela
    g = centinela._infra_hygiene_guidance({"cve_id": "TLS-NOT-ENABLED", "url_path": "192.0.2.14:80", "asset_name": "gl", "endpoint": "http://192.0.2.14"})
    assert g and g[4] is False and "HTTPS" in g[2]
