"""DNS/e-mail audit: every rule has a positive and a negative case, driven by a fake resolver (no network)."""
import unittest

from auditors import auditor_dns_security as D


def zone(**records):
    """query(name, rdtype) over a dict {'name|TYPE': [texts]}; a missing key is 'name exists, no such record' ([]) unless the name is marked absent."""
    def q(name, rdtype):
        key = f"{name}|{rdtype}"
        if f"{name}|ABSENT" in records:
            return None
        return records.get(key, [])
    return q


def rules(res):
    return {f["cve_id"]: f["severity"] for f in res["findings"]}


GOOD = {"example.gob.mx|NS": ["ns1."], "example.gob.mx|SOA": ["x"], "example.gob.mx|MX": ["10 mx.example.gob.mx."],
        "example.gob.mx|TXT": ["v=spf1 include:_spf.google.com -all"], "_dmarc.example.gob.mx|TXT": ["v=DMARC1; p=reject; rua=mailto:a@example.gob.mx"],
        "_mta-sts.example.gob.mx|TXT": ["v=STSv1; id=1"], "example.gob.mx|CAA": ['0 issue "letsencrypt.org"'], "example.gob.mx|DS": ["12345 13 2 abc"],
        "_spf.google.com|TXT": ["v=spf1 ip4:1.2.3.4 -all"]}


class TestDomainHandling(unittest.TestCase):
    def test_registrable_domain(self):
        r = D.registrable_domain
        self.assertEqual(r("https://portal.proyecto-j.example.gob.mx/app"), "example.gob.mx")
        self.assertEqual(r("www.ejemplo.com"), "ejemplo.com")
        self.assertEqual(r("tienda.empresa.com.mx:8443"), "empresa.com.mx")

    def test_ips_internal_names_and_garbage_are_not_domains(self):
        for v in ["http://192.0.2.9:8092/x", "192.0.2.15", "centinela.example.internal", "host.local", "localhost", "", None, "http://[::1]/"]:
            self.assertIsNone(D.registrable_domain(v), v)


class TestEvaluation(unittest.TestCase):
    def test_a_well_configured_domain_has_no_findings(self):
        res = D.evaluate_domain("example.gob.mx", zone(**GOOD))
        self.assertEqual(res["status"], "ok")
        self.assertEqual(res["findings"], [])
        self.assertTrue(any("DKIM" in n for n in res["not_evaluated"]))          # said, not hidden

    def test_internal_and_unresolvable_are_not_evaluated_not_clean(self):
        self.assertEqual(D.evaluate_domain("sistema.example.internal", zone())["status"], "internal")
        z = zone(**{"nada.com|ABSENT": 1})
        self.assertEqual(D.evaluate_domain("nada.com", lambda n, t: None)["status"], "unresolvable")
        self.assertEqual(D.evaluate_domain("nada.com", z)["findings"], [])

    def test_spf_missing_is_medium_with_mail_and_low_without(self):
        z = dict(GOOD); z["example.gob.mx|TXT"] = []
        self.assertEqual(rules(D.evaluate_domain("example.gob.mx", zone(**z)))["DNS-SPF-MISSING"], "MEDIUM")
        z["example.gob.mx|MX"] = []
        self.assertEqual(rules(D.evaluate_domain("example.gob.mx", zone(**z)))["DNS-SPF-MISSING"], "LOW")

    def test_null_mx_means_no_mail(self):
        z = dict(GOOD); z["example.gob.mx|MX"] = ["0 ."]; z["example.gob.mx|TXT"] = []
        res = D.evaluate_domain("example.gob.mx", zone(**z))
        self.assertFalse(res["has_mx"])
        self.assertEqual(rules(res)["DNS-SPF-MISSING"], "LOW")
        self.assertNotIn("DNS-MTASTS-MISSING", rules(res))

    def test_spf_qualifiers(self):
        for spf, expected in [("v=spf1 +all", ("DNS-SPF-PERMISSIVE", "HIGH")), ("v=spf1 all", ("DNS-SPF-PERMISSIVE", "HIGH")), ("v=spf1 ip4:1.1.1.1 ?all", ("DNS-SPF-PERMISSIVE", "MEDIUM")),
                              ("v=spf1 ip4:1.1.1.1", ("DNS-SPF-PERMISSIVE", "MEDIUM"))]:
            z = dict(GOOD); z["example.gob.mx|TXT"] = [spf]
            self.assertEqual(rules(D.evaluate_domain("example.gob.mx", zone(**z))).get(expected[0]), expected[1], spf)
        z = dict(GOOD); z["example.gob.mx|TXT"] = ["v=spf1 ip4:1.1.1.1 -all"]
        self.assertNotIn("DNS-SPF-PERMISSIVE", rules(D.evaluate_domain("example.gob.mx", zone(**z))))
        z["example.gob.mx|TXT"] = ["v=spf1 redirect=_spf.google.com"]
        self.assertNotIn("DNS-SPF-PERMISSIVE", rules(D.evaluate_domain("example.gob.mx", zone(**z))))      # redirect= is a valid final policy

    def test_softfail_only_matters_without_enforcing_dmarc(self):
        z = dict(GOOD); z["example.gob.mx|TXT"] = ["v=spf1 ip4:1.1.1.1 ~all"]
        self.assertNotIn("DNS-SPF-SOFTFAIL", rules(D.evaluate_domain("example.gob.mx", zone(**z))))        # DMARC reject backs it up
        z["_dmarc.example.gob.mx|TXT"] = ["v=DMARC1; p=none"]
        self.assertIn("DNS-SPF-SOFTFAIL", rules(D.evaluate_domain("example.gob.mx", zone(**z))))

    def test_multiple_spf_records(self):
        z = dict(GOOD); z["example.gob.mx|TXT"] = ["v=spf1 -all", "v=spf1 ip4:1.1.1.1 -all"]
        self.assertIn("DNS-SPF-MULTIPLE", rules(D.evaluate_domain("example.gob.mx", zone(**z))))

    def test_spf_lookup_limit_follows_includes(self):
        z = dict(GOOD)
        z["example.gob.mx|TXT"] = ["v=spf1 " + " ".join(f"include:s{i}.example.net" for i in range(6)) + " -all"]
        for i in range(6):
            z[f"s{i}.example.net|TXT"] = ["v=spf1 a mx -all"]            # 6 includes + 6*2 = 18 lookups
        self.assertIn("DNS-SPF-TOO-MANY-LOOKUPS", rules(D.evaluate_domain("example.gob.mx", zone(**z))))
        self.assertNotIn("DNS-SPF-TOO-MANY-LOOKUPS", rules(D.evaluate_domain("example.gob.mx", zone(**GOOD))))

    def test_dmarc_missing_monitor_only_partial(self):
        z = dict(GOOD); del z["_dmarc.example.gob.mx|TXT"]
        self.assertEqual(rules(D.evaluate_domain("example.gob.mx", zone(**z)))["DNS-DMARC-MISSING"], "MEDIUM")
        z["_dmarc.example.gob.mx|TXT"] = ["v=DMARC1; p=none; rua=mailto:a@b.c"]
        self.assertEqual(rules(D.evaluate_domain("example.gob.mx", zone(**z)))["DNS-DMARC-MONITOR-ONLY"], "MEDIUM")
        z["_dmarc.example.gob.mx|TXT"] = ["v=DMARC1; p=quarantine; pct=25"]
        self.assertIn("DNS-DMARC-PARTIAL", rules(D.evaluate_domain("example.gob.mx", zone(**z))))
        z["_dmarc.example.gob.mx|TXT"] = ["v=DMARC1; p=quarantine"]
        self.assertEqual([r for r in rules(D.evaluate_domain("example.gob.mx", zone(**z))) if r.startswith("DNS-DMARC")], [])

    def test_mtasts_caa_dnssec(self):
        z = dict(GOOD); del z["_mta-sts.example.gob.mx|TXT"]; del z["example.gob.mx|CAA"]; del z["example.gob.mx|DS"]
        r = rules(D.evaluate_domain("example.gob.mx", zone(**z)))
        self.assertEqual({k: v for k, v in r.items()}, {"DNS-MTASTS-MISSING": "LOW", "DNS-CAA-MISSING": "LOW", "DNS-DNSSEC-NOT-ENABLED": "LOW"})


class TestPersistence(unittest.TestCase):
    def test_unresolvable_writes_only_a_marker_and_returns_zero(self):
        import contextlib
        from unittest import mock
        from core import db_manager
        with contextlib.ExitStack() as st:
            conn = st.enter_context(db_manager.get_db_connection())

            @contextlib.contextmanager
            def shared(cursor_factory=None):
                c = conn.cursor(cursor_factory=cursor_factory)
                try:
                    yield c
                finally:
                    c.close()
            st.enter_context(mock.patch.object(db_manager, "get_db_cursor", shared))
            cur = conn.cursor()
            cur.execute("INSERT INTO infra_inventory (asset_name, asset_type, endpoint, criticality, status) VALUES ('zz-test.example','Domain','zz-test.example','LOW','ACTIVE') RETURNING id")
            aid = cur.fetchone()[0]
            res = {"status": "unresolvable", "domain": "zz-test.example", "findings": [], "not_evaluated": [], "has_mx": False}
            self.assertEqual(D.log_dns_findings(aid, res), 0)
            cur.execute("SELECT cve_id, finding_category FROM vulnerability_log WHERE asset_id=%s", (aid,))
            self.assertEqual(cur.fetchall(), [("DNS-SECURITY-AUDIT", "INFORMATIONAL")])
            conn.rollback()
