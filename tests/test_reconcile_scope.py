"""Per-port scans of one asset must not resolve each other's findings (WSTG flapping bug)."""
import uuid

import pytest

from core import db_manager, deduplication_engine as de


@pytest.fixture()
def asset_id():
    with db_manager.get_db_cursor() as cur:
        cur.execute("INSERT INTO public.infra_inventory (asset_name, asset_type, endpoint, criticality, status) "
                    "VALUES (%s, 'GitLab-Repo', 'http://reconcile.test.invalid', 'LOW', 'monitored') RETURNING id",
                    (f"reconcile-test-{uuid.uuid4().hex[:8]}",))
        aid = cur.fetchone()[0]
    yield aid
    with db_manager.get_db_cursor() as cur:
        cur.execute("DELETE FROM public.vulnerability_log WHERE asset_id = %s", (aid,))
        cur.execute("DELETE FROM public.infra_inventory WHERE id = %s", (aid,))


def _log(cur, aid, url):
    de.log_finding_deduplicated(cur, aid, "WSTG-TEST", "LOW", "d", "wstg-perimeter", url_path=url, open_status="OPEN", preserve_status=True)
    return de.calculate_fingerprint(aid, "WSTG-TEST", url)


def _status(cur, aid, url):
    cur.execute("SELECT status FROM public.vulnerability_log WHERE asset_id = %s AND url_path = %s", (aid, url))
    return cur.fetchone()[0]


def test_origin_scoped_reconcile_leaves_other_ports_alone(asset_id):
    with db_manager.get_db_cursor() as cur:
        _log(cur, asset_id, "http://h:80")
        _log(cur, asset_id, "http://h:80/login/?x=1")
        fp8080 = _log(cur, asset_id, "http://h:8080")
        # scan of port 8080 reproduces only its own finding
        n = de.reconcile_resolved_findings(cur, asset_id, "wstg-perimeter", {fp8080}, url_origin="http://h:8080")
        assert n == 0
        assert _status(cur, asset_id, "http://h:80") == "OPEN"
        assert _status(cur, asset_id, "http://h:80/login/?x=1") == "OPEN"


def test_origin_scoped_reconcile_still_resolves_its_own_stale_findings(asset_id):
    with db_manager.get_db_cursor() as cur:
        _log(cur, asset_id, "http://h:80")
        stale = _log(cur, asset_id, "http://h:80/login/?x=1")
        keep = de.calculate_fingerprint(asset_id, "WSTG-TEST", "http://h:80")
        n = de.reconcile_resolved_findings(cur, asset_id, "wstg-perimeter", {keep}, url_origin="http://h:80")
        assert n == 1
        assert _status(cur, asset_id, "http://h:80/login/?x=1") == "RESOLVED"
        assert _status(cur, asset_id, "http://h:80") == "OPEN"


def test_port_80_scope_does_not_match_port_8080(asset_id):
    with db_manager.get_db_cursor() as cur:
        _log(cur, asset_id, "http://h:8080")
        n = de.reconcile_resolved_findings(cur, asset_id, "wstg-perimeter", set(), url_origin="http://h:80")
        assert n == 0 and _status(cur, asset_id, "http://h:8080") == "OPEN"
