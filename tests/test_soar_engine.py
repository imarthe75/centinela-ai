"""SOAR autoresponse: policy gates, real queueing through the Sentinel channel, TTL expiry.

Uses a disposable GitLab-Repo asset so Sentinel (which polls every 10s) can never run a network
script for it, and monkeypatches the policy / ledger so the live policy table and production
ledger are never touched.
"""
import os
import uuid

import pytest

from core import db_manager, soar_engine

PUBLIC_IP = "45.33.32.156"   # global address (not RFC1918 / reserved)


def _policy(**over):
    base = {"action_kind": "proxy_ip_block", "max_severity_auto": "CRITICAL", "asset_scope": "NON_CRITICAL",
            "require_cti_confirmed": True, "daily_cap": 3, "dry_run": True, "active": True}
    base.update(over)
    return lambda kind: {**base, "action_kind": kind}


@pytest.fixture()
def asset():
    name = f"soar-test-{uuid.uuid4().hex[:8]}"
    with db_manager.get_db_cursor() as cur:
        cur.execute("INSERT INTO public.infra_inventory (asset_name, asset_type, endpoint, criticality, status) "
                    "VALUES (%s, 'GitLab-Repo', 'http://soar.test.invalid', 'LOW', 'monitored') RETURNING id", (name,))
        aid = cur.fetchone()[0]
    yield {"id": aid, "name": name}
    with db_manager.get_db_cursor() as cur:
        cur.execute("DELETE FROM public.soar_ip_blocks WHERE asset_id = %s", (aid,))
        cur.execute("DELETE FROM public.remediation_history WHERE vuln_id IN (SELECT id FROM public.vulnerability_log WHERE asset_id = %s)", (aid,))
        cur.execute("DELETE FROM public.vulnerability_log WHERE asset_id = %s", (aid,))
        cur.execute("DELETE FROM public.infra_inventory WHERE id = %s", (aid,))


def test_policy_tables_exist_and_seed_is_observation_only():
    p = soar_engine.get_autoresponse_policy("proxy_ip_block")
    assert p["dry_run"] is True                    # seed must never ship autonomous
    assert soar_engine.get_autoresponse_policy("host_isolate")["active"] is False


def test_host_isolate_is_always_manual(capture_ledger):
    res = soar_engine.evaluate_and_execute_response("host_isolate", "srv", "8.8.8.8", "u", 0.99, cti_hit=True)
    assert res["mode"] == "MANUAL_APPROVAL_REQUIRED" and res["executed"] is False


@pytest.mark.parametrize("ip,why", [("192.0.2.17", "not_a_public_ip"), ("127.0.0.1", "not_a_public_ip"),
                                    ("203.0.113.5", "not_a_public_ip"), ("garbage", "invalid_ip")])
def test_non_public_ips_are_never_blockable(ip, why):
    assert soar_engine.is_blockable_ip(ip) == (False, why)


def test_own_asset_ip_is_never_blockable(asset):
    with db_manager.get_db_cursor() as cur:
        cur.execute("UPDATE public.infra_inventory SET endpoint = %s WHERE id = %s", (f"http://{PUBLIC_IP}:8080", asset["id"]))
    assert soar_engine.is_blockable_ip(PUBLIC_IP) == (False, "is_own_asset")


def test_low_confidence_and_missing_cti_go_manual(monkeypatch, capture_ledger):
    monkeypatch.setattr(soar_engine, "get_autoresponse_policy", _policy(dry_run=False))
    r1 = soar_engine.evaluate_and_execute_response("ITDR-X-BRUTE", "a", PUBLIC_IP, "u", 0.80, cti_hit=True)
    r2 = soar_engine.evaluate_and_execute_response("ITDR-X-BRUTE", "a", PUBLIC_IP, "u", 0.99, cti_hit=False)
    assert r1["mode"] == r2["mode"] == "MANUAL_APPROVAL_REQUIRED"
    assert not r1["executed"] and not r2["executed"]


def test_inactive_policy_goes_manual(monkeypatch, capture_ledger):
    monkeypatch.setattr(soar_engine, "get_autoresponse_policy", _policy(active=False, dry_run=False))
    assert soar_engine.evaluate_and_execute_response("proxy_ip_block", "a", PUBLIC_IP, "u", 0.99, True)["mode"] == "MANUAL_APPROVAL_REQUIRED"


def test_dry_run_records_would_have_and_changes_nothing(monkeypatch, capture_ledger, asset):
    monkeypatch.setattr(soar_engine, "get_autoresponse_policy", _policy(dry_run=True))
    monkeypatch.setenv("SOAR_PROXY_ASSET", asset["name"])
    res = soar_engine.evaluate_and_execute_response("proxy_ip_block", asset["name"], PUBLIC_IP, "u", 0.99, True)
    assert res["mode"] == "DRY_RUN" and res["executed"] is False
    assert capture_ledger[-1]["detail"]["phase"] == "dry_run"
    with db_manager.get_db_cursor() as cur:
        cur.execute("SELECT count(*) FROM public.soar_ip_blocks WHERE asset_id = %s", (asset["id"],))
        assert cur.fetchone()[0] == 0


def test_protected_user_session_revoke_is_manual(monkeypatch, capture_ledger):
    monkeypatch.setattr(soar_engine, "get_autoresponse_policy", _policy(dry_run=False, require_cti_confirmed=False))
    res = soar_engine.evaluate_and_execute_response("ITDR-AUTHENTIK-PRIVILEGE-ESCALATION", "a", PUBLIC_IP, "akadmin", 0.99)
    assert res["mode"] == "MANUAL_APPROVAL_REQUIRED" and "protegida" in res["message"]


def test_daily_cap_stops_execution(monkeypatch, capture_ledger, asset):
    monkeypatch.setattr(soar_engine, "get_autoresponse_policy", _policy(dry_run=False, daily_cap=1))
    monkeypatch.setattr(soar_engine, "_executed_today", lambda kind: 1)
    monkeypatch.setenv("SOAR_PROXY_ASSET", asset["name"])
    res = soar_engine.evaluate_and_execute_response("proxy_ip_block", asset["name"], PUBLIC_IP, "u", 0.99, True)
    assert res["mode"] == "MANUAL_APPROVAL_REQUIRED" and "tope diario" in res["message"]


def test_autonomous_block_is_really_queued_then_expired_and_lifted(monkeypatch, capture_ledger, asset):
    monkeypatch.setattr(soar_engine, "get_autoresponse_policy", _policy(dry_run=False))
    monkeypatch.setattr(soar_engine, "_executed_today", lambda kind: 0)
    monkeypatch.setenv("SOAR_PROXY_ASSET", asset["name"])

    res = soar_engine.evaluate_and_execute_response("proxy_ip_block", asset["name"], PUBLIC_IP, "u", 0.99, True)
    assert res["mode"] == "AUTONOMOUS" and res["executed"] is True, res

    with db_manager.get_db_cursor() as cur:
        cur.execute("""SELECT rh.approval_token, rh.script_path, b.id, b.expires_at
                       FROM public.soar_ip_blocks b JOIN public.remediation_history rh ON rh.id = b.remediation_id
                       WHERE b.asset_id = %s AND b.ip = %s""", (asset["id"], PUBLIC_IP))
        token, script_path, block_id, expires_at = cur.fetchone()
    assert token in ("APPROVED", "EXECUTING", "COMPLETED", "FAILED")
    script = open(script_path).read()
    assert f"deny {PUBLIC_IP};" in script and "# centinela-auto expires=" in script

    # Not yet expired -> nothing to lift.
    assert soar_engine.reap_expired_ip_blocks()["unblock_queued"] == 0

    # Force the TTL to pass and mark the block as really applied by Sentinel.
    with db_manager.get_db_cursor() as cur:
        cur.execute("UPDATE public.soar_ip_blocks SET expires_at = NOW() - interval '1 minute' WHERE id = %s", (block_id,))
        cur.execute("UPDATE public.remediation_history SET approval_token = 'COMPLETED' WHERE id = "
                    "(SELECT remediation_id FROM public.soar_ip_blocks WHERE id = %s)", (block_id,))
    soar_engine.reap_expired_ip_blocks()
    with db_manager.get_db_cursor() as cur:
        cur.execute("SELECT unblock_remediation_id FROM public.soar_ip_blocks WHERE id = %s", (block_id,))
        unblock_rem = cur.fetchone()[0]
        assert unblock_rem is not None
        cur.execute("SELECT script_path FROM public.remediation_history WHERE id = %s", (unblock_rem,))
        unblock_script = open(cur.fetchone()[0]).read()
        cur.execute("UPDATE public.remediation_history SET approval_token = 'COMPLETED' WHERE id = %s", (unblock_rem,))
    assert "centinela-auto" in unblock_script and "sed -i" in unblock_script

    assert soar_engine.reap_expired_ip_blocks()["unblocked"] >= 1
    with db_manager.get_db_cursor() as cur:
        cur.execute("SELECT unblocked_at FROM public.soar_ip_blocks WHERE id = %s", (block_id,))
        assert cur.fetchone()[0] is not None
