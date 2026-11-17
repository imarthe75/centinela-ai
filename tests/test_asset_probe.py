"""Pre-registration connection probe: root is refused, bad addresses are explained, nothing needs real credentials."""
import unittest

from core import asset_probe


class TestRootPolicy(unittest.TestCase):
    def test_root_is_rejected_in_any_case(self):
        for u in ("root", "ROOT", " Root "):
            with self.assertRaises(asset_probe.ProbeInputError):
                asset_probe.reject_root_user(u)

    def test_normal_and_empty_users_are_allowed(self):
        asset_probe.reject_root_user("ubuntu")
        asset_probe.reject_root_user("")
        asset_probe.reject_root_user(None)


class TestParseHost(unittest.TestCase):
    def test_extracts_host_from_common_forms(self):
        self.assertEqual(asset_probe.parse_host("192.0.2.16"), "192.0.2.16")
        self.assertEqual(asset_probe.parse_host("http://192.0.2.16:8080/x"), "192.0.2.16")
        self.assertEqual(asset_probe.parse_host("[2001:db8::1]:22"), "2001:db8::1")

    def test_rejects_loopback_linklocal_and_garbage(self):
        for bad in ("127.0.0.1", "169.254.169.254", "::1", "0.0.0.0", "not a host!", ""):
            with self.assertRaises(asset_probe.ProbeInputError, msg=bad):
                asset_probe.parse_host(bad)


class TestProbeShortCircuits(unittest.TestCase):
    def test_root_user_fails_before_any_network_use(self):
        r = asset_probe.probe("192.0.2.16", "SERVER_LINUX", user="root", password="x")
        self.assertFalse(r["ok"])
        self.assertEqual([s["id"] for s in r["steps"]], ["format", "user"])

    def test_loopback_fails_at_format_step(self):
        r = asset_probe.probe("127.0.0.1", "SERVER_LINUX")
        self.assertFalse(r["ok"])
        self.assertEqual(r["steps"][0]["status"], "fail")


if __name__ == "__main__":
    unittest.main()
