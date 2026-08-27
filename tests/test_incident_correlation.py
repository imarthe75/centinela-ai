"""
Item 2 (2026-08-27): incident correlation engine.

Pure-logic unit tests (indicators, tactic, union-find grouping, fingerprint stability,
narrative) + integration tests against the real centinela_db for attach_or_create_incidents /
reconcile_closed_incidents, including the "no signals -> nothing created" contract.
"""
import unittest
from datetime import datetime, timedelta

from core import incident_engine as ie
from core.db_manager import get_db_cursor


def _sig(key, asset_id, minutes, sev="CRITICAL", rule="ITDR-AUTHENTIK-BRUTE-FORCE",
         ips=None, users=None, standalone=False, source="runtime_alert", sid=None):
    base = datetime(2026, 8, 27, 12, 0, 0)
    return ie.Signal(
        key=key, source=source, source_id=sid if sid is not None else int(key.split(":")[-1]),
        asset_id=asset_id, occurred_at=base + timedelta(minutes=minutes),
        severity=sev, rule_name=rule, summary=f"{rule} evento {key}",
        tactic=ie.classify_tactic(rule, ""), ips=set(ips or []), users=set(users or []),
        standalone_worthy=standalone,
    )


class TestPureLogic(unittest.TestCase):
    def test_extract_indicators(self):
        got = ie.extract_indicators(
            "ITDR-AUTHENTIK-BRUTE-FORCE",
            "Ataque de Fuerza Bruta desde IP 192.168.1.100 contra el usuario 'admin_test'",
            {"user.name": "svc_bot", "src_ip": "10.4.3.9"},
        )
        self.assertIn("192.168.1.100", got["ips"])
        self.assertIn("10.4.3.9", got["ips"])
        self.assertIn("admin_test", got["users"])
        self.assertIn("svc_bot", got["users"])

    def test_classify_tactic(self):
        self.assertEqual(ie.classify_tactic("ITDR-AUTHENTIK-BRUTE-FORCE", ""), "Credential Access")
        self.assertEqual(ie.classify_tactic("CTI-IOC-MATCH-1", ""), "Command and Control")
        self.assertEqual(ie.classify_tactic("BLOODHOUND-PATH-3", ""), "Privilege Escalation")
        self.assertEqual(ie.classify_tactic("Clear Log Activities", ""), "Defense Evasion")

    def test_noise_and_standalone(self):
        self.assertTrue(ie.is_noise("ZEEK-CONN-HEARTBEAT"))
        self.assertFalse(ie.is_noise("ITDR-AUTHENTIK-BRUTE-FORCE"))
        self.assertTrue(ie.is_standalone_worthy("ITDR-AUTHENTIK-BRUTE-FORCE", ""))
        self.assertTrue(ie.is_standalone_worthy("Falco X", "Reverse shell detected"))
        self.assertFalse(ie.is_standalone_worthy("Some rule", "nothing special"))

    def test_group_by_asset_and_indicator(self):
        sigs = [
            _sig("runtime_alert:1", 5, 0, ips=["1.2.3.4"]),
            _sig("runtime_alert:2", 5, 3),                      # same asset, 3 min later
            _sig("runtime_alert:3", None, 5, ips=["1.2.3.4"]),  # no asset, shared IP
            _sig("runtime_alert:4", 9, 200),                    # different asset, far in time
        ]
        groups = ie.group_signals(sigs, window_minutes=60)
        sizes = sorted(len(g) for g in groups)
        self.assertEqual(sizes, [1, 3])

    def test_time_window_splits_groups(self):
        sigs = [_sig("runtime_alert:1", 5, 0), _sig("runtime_alert:2", 5, 120)]
        groups = ie.group_signals(sigs, window_minutes=60)
        self.assertEqual(sorted(len(g) for g in groups), [1, 1])

    def test_fingerprint_stable_and_discriminating(self):
        t = datetime(2026, 8, 27, 12, 0, 0)
        a = ie.incident_fingerprint(5, t, {"1.2.3.4"})
        b = ie.incident_fingerprint(5, t + timedelta(minutes=30), {"1.2.3.4"})  # same 6h bucket
        c = ie.incident_fingerprint(5, t, {"9.9.9.9"})
        self.assertEqual(a, b)
        self.assertNotEqual(a, c)

    def test_summarize_group_kill_chain_escalates_severity(self):
        sigs = [
            _sig("runtime_alert:1", 5, 0, sev="HIGH", rule="ITDR-AUTHENTIK-BRUTE-FORCE"),
            _sig("runtime_alert:2", 5, 1, sev="HIGH", rule="Clear Log Activities"),
            _sig("runtime_alert:3", 5, 2, sev="HIGH", rule="Reverse shell in container"),
        ]
        summ = ie.summarize_group(sigs)
        self.assertGreaterEqual(len(summ["kill_chain"]), 3)
        self.assertEqual(summ["severity"], "CRITICAL")  # >=3 tactics bumps HIGH -> CRITICAL
        self.assertIn("- 2026-08-27", summ["narrative"])

    def test_materializable_rules(self):
        one_worthy = [_sig("runtime_alert:1", 5, 0, standalone=True)]
        one_plain = [_sig("runtime_alert:1", 5, 0, rule="x", standalone=False)]
        one_plain[0].standalone_worthy = False
        one_plain[0].tactic = None
        self.assertTrue(ie.group_is_materializable(one_worthy, min_events=2))
        self.assertFalse(ie.group_is_materializable(one_plain, min_events=2))


class TestIncidentPersistence(unittest.TestCase):
    TAG = "pytest-incident-corr"

    def setUp(self):
        with get_db_cursor() as cur:
            cur.execute("""
                INSERT INTO infra_inventory (asset_name, asset_type, endpoint, criticality, status)
                VALUES (%s, 'SERVER', '10.255.255.254', 'LOW', 'monitored')
                ON CONFLICT (asset_name) DO UPDATE SET status = 'monitored'
                RETURNING id
            """, (f"{self.TAG}-asset",))
            self.asset_id = cur.fetchone()[0]

    def tearDown(self):
        with get_db_cursor() as cur:
            cur.execute("""DELETE FROM incident_events WHERE incident_id IN
                           (SELECT id FROM incidents WHERE title LIKE %s)""", (f"%{self.TAG}%",))
            cur.execute("DELETE FROM incidents WHERE title LIKE %s", (f"%{self.TAG}%",))
            cur.execute("DELETE FROM infra_inventory WHERE asset_name = %s", (f"{self.TAG}-asset",))

    def _mk(self, n, asset_id, minutes, **kw):
        aid = self.asset_id if asset_id is not None else None
        s = _sig(f"runtime_alert:{900000 + n}", aid, minutes,
                 rule=f"{kw.get('rule', 'RULE')} {self.TAG}", sid=900000 + n,
                 **{k: v for k, v in kw.items() if k != 'rule'})
        return s

    def test_no_signals_creates_nothing(self):
        with get_db_cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM incidents")
            before = cur.fetchone()[0]
            stats = ie.attach_or_create_incidents(cur, [], window_minutes=60)
        self.assertEqual(stats, {"created": 0, "attached": 0, "events_linked": 0})
        with get_db_cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM incidents")
            self.assertEqual(cur.fetchone()[0], before)

    def test_burst_becomes_one_incident_idempotently(self):
        group = [self._mk(i, 4242, i, ips=["203.0.113.7"], users=["admin_test"]) for i in range(4)]
        with get_db_cursor() as cur:
            s1 = ie.attach_or_create_incidents(cur, [group], window_minutes=60, min_events=2)
        self.assertEqual(s1["created"], 1)
        self.assertEqual(s1["events_linked"], 4)

        # re-run with the SAME signals -> no new incident, no new events
        with get_db_cursor() as cur:
            s2 = ie.attach_or_create_incidents(cur, [group], window_minutes=60, min_events=2)
        self.assertEqual(s2["created"], 0)
        self.assertEqual(s2["events_linked"], 0)

        with get_db_cursor() as cur:
            cur.execute("SELECT id, event_count, kill_chain, severity FROM incidents WHERE title LIKE %s",
                        (f"%{self.TAG}%",))
            rows = cur.fetchall()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][1], 4)

    def test_later_related_signals_attach_not_duplicate(self):
        g1 = [self._mk(i, 4243, i, ips=["203.0.113.8"]) for i in range(2)]
        with get_db_cursor() as cur:
            ie.attach_or_create_incidents(cur, [g1], window_minutes=60, min_events=2)
        g2 = [self._mk(i + 10, 4243, 20 + i, ips=["203.0.113.8"]) for i in range(2)]
        with get_db_cursor() as cur:
            s2 = ie.attach_or_create_incidents(cur, [g2], window_minutes=60, min_events=2)
        self.assertEqual(s2["created"], 0)
        self.assertEqual(s2["attached"], 1)
        with get_db_cursor() as cur:
            cur.execute("SELECT COUNT(*), MAX(event_count) FROM incidents WHERE title LIKE %s",
                        (f"%{self.TAG}%",))
            cnt, ec = cur.fetchone()
        self.assertEqual(cnt, 1)
        self.assertEqual(ec, 4)

    def test_reconcile_closes_idle_incident(self):
        group = [self._mk(i, 4244, i) for i in range(3)]
        with get_db_cursor() as cur:
            ie.attach_or_create_incidents(cur, [group], window_minutes=60, min_events=2)
            cur.execute("""UPDATE incidents SET last_event_at = NOW() - INTERVAL '100 hours',
                           detected_at = NOW() - INTERVAL '100 hours' WHERE title LIKE %s""",
                        (f"%{self.TAG}%",))
            closed = ie.reconcile_closed_incidents(cur, idle_hours=72)
        self.assertGreaterEqual(closed, 1)
        with get_db_cursor() as cur:
            cur.execute("SELECT status FROM incidents WHERE title LIKE %s", (f"%{self.TAG}%",))
            self.assertEqual(cur.fetchone()[0], "CLOSED")


if __name__ == "__main__":
    unittest.main()
