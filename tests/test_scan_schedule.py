"""Daily scan schedule (core/scan_schedule.py) and the queue's not_finished_since rule. Queue tests run on the disposable test DB."""
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from core import db_manager, job_queue, scan_schedule

UTC = timezone.utc


def test_cutoff_is_today_after_the_daily_time():
    # 08:00 Mexico City (UTC-6) = 14:00 UTC -> cutoff 03:00 local today = 09:00 UTC
    now = datetime(2026, 10, 28, 14, 0, tzinfo=UTC)
    assert scan_schedule.daily_cutoff(now, "03:00", "America/Mexico_City") == datetime(2026, 10, 28, 9, 0, tzinfo=UTC)


def test_cutoff_is_yesterday_before_the_daily_time():
    # 02:00 local = 08:00 UTC -> cutoff is 03:00 local of the previous day
    now = datetime(2026, 10, 28, 8, 0, tzinfo=UTC)
    assert scan_schedule.daily_cutoff(now, "03:00", "America/Mexico_City") == datetime(2026, 10, 27, 9, 0, tzinfo=UTC)


def test_cutoff_at_exactly_the_daily_time_is_now():
    now = datetime(2026, 10, 28, 9, 0, tzinfo=UTC)
    assert scan_schedule.daily_cutoff(now, "03:00", "America/Mexico_City") == now


@pytest.mark.parametrize("bad", ["3", "24:00", "03:60", "tres", "03-00"])
def test_invalid_time_is_rejected(bad):
    with pytest.raises(ValueError):
        scan_schedule.parse_daily_at(bad)


def test_empty_env_falls_back_to_rolling_interval(monkeypatch):
    monkeypatch.setenv("GITLAB_SCAN_DAILY_AT", "")
    assert scan_schedule.configured_fleet_cutoff() is None
    monkeypatch.setenv("GITLAB_SCAN_DAILY_AT", "03:00")
    assert scan_schedule.configured_fleet_cutoff() is not None


@pytest.fixture()
def kind():
    k = f"test-{uuid.uuid4().hex[:8]}"
    yield k
    with db_manager.get_db_cursor() as cur:
        cur.execute("DELETE FROM scan_jobs WHERE kind = %s", (k,))


def _finish(kind, target, finished_at):
    job_queue.enqueue(kind, target)
    job = job_queue.claim(kind)
    job_queue.complete(job["id"])
    with db_manager.get_db_cursor() as cur:
        cur.execute("UPDATE scan_jobs SET finished_at = %s WHERE id = %s", (finished_at, job["id"]))


def test_scanned_before_cutoff_is_due_again(kind):
    cutoff = datetime.now(UTC) - timedelta(hours=1)
    _finish(kind, "proj-old", cutoff - timedelta(minutes=5))
    assert job_queue.enqueue(kind, "proj-old", not_finished_since=cutoff)


def test_scanned_after_cutoff_waits_for_next_day(kind):
    cutoff = datetime.now(UTC) - timedelta(hours=1)
    _finish(kind, "proj-new", cutoff + timedelta(minutes=5))
    assert job_queue.enqueue(kind, "proj-new", not_finished_since=cutoff) is None


def test_naive_cutoff_is_rejected(kind):
    with pytest.raises(ValueError):
        job_queue.enqueue(kind, "proj-x", not_finished_since=datetime.now())
