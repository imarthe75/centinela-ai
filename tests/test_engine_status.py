import unittest

from core import engine_status as E


class TestEngineStatus(unittest.TestCase):
    def test_classification(self):
        c = E.classify
        self.assertEqual(c("scheduled", 3, 100, 1.0), "ACTIVO")
        self.assertEqual(c("scheduled", 3, 100, 9.0), "OBSOLETO")
        self.assertEqual(c("scheduled", 3, 0, None), "SIN_DATOS")
        self.assertEqual(c("on_demand", None, 0, None), "BAJO_DEMANDA")      # opt-in engines are not judged
        self.assertEqual(c("disabled", None, 0, None), "DESACTIVADO")

    def test_an_installed_but_silent_engine_is_never_active(self):
        entries = {e["engine"]: e for e in E.compute({})}
        self.assertEqual(entries["secrets"]["state"], "SIN_DATOS")
        self.assertNotIn("grype", entries)                                  # removed for good (2026-10-12)
        self.assertEqual(entries["trivy-config"]["state"], "SIN_DATOS")
        self.assertEqual(entries["api-fuzz"]["state"], "BAJO_DEMANDA")
        self.assertEqual(entries["dns-security"]["state"], "BAJO_DEMANDA")     # no public domains to audit: not a failure

    def test_unregistered_engines_in_the_db_are_surfaced(self):
        out = E.compute({"mystery-scanner": {"open": 3, "total": 3, "days_since": 0.1}})
        self.assertIn(("mystery-scanner", "NO_REGISTRADO"), [(e["engine"], e["state"]) for e in out])

    def test_summary_is_online_only_when_every_scheduled_engine_has_recent_data(self):
        fresh = {e: {"open": 1, "total": 1, "days_since": 0.1} for e, v in E.REGISTRY.items() if v[1] == "scheduled"}
        self.assertEqual(E.health_summary(E.compute(fresh)), "Online")
        del fresh["secrets"]
        s = E.health_summary(E.compute(fresh))
        self.assertTrue(s.startswith("Stale (") and "secrets" in s)

    def test_every_registered_engine_has_a_mode_the_summary_understands(self):
        self.assertTrue(all(v[1] in ("scheduled", "on_demand", "disabled") for v in E.REGISTRY.values()))
