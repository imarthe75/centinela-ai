"""ADR-0008 #4: persistent job queue. Runs against the disposable test DB (see tests/conftest.py guard)."""
import time
import uuid

import pytest

from core import db_manager, job_queue


@pytest.fixture()
def kind():
    k = f"test-{uuid.uuid4().hex[:8]}"
    yield k
    with db_manager.get_db_cursor() as cur:
        cur.execute("DELETE FROM scan_jobs WHERE kind = %s", (k,))


def _row(job_id):
    with db_manager.get_db_cursor() as cur:
        cur.execute("SELECT status, attempts, worker, last_error FROM scan_jobs WHERE id = %s", (job_id,))
        return cur.fetchone()


def test_enqueue_is_idempotent_while_active(kind):
    first = job_queue.enqueue(kind, "proj-a", {"x": 1})
    assert first
    assert job_queue.enqueue(kind, "proj-a") is None          # already QUEUED
    job = job_queue.claim(kind)
    assert job["id"] == first and job["payload"] == {"x": 1}
    assert job_queue.enqueue(kind, "proj-a") is None          # already RUNNING
    job_queue.complete(job["id"])
    assert job_queue.enqueue(kind, "proj-a")                   # finished -> may be queued again


def test_min_interval_skips_recently_finished(kind):
    job_queue.enqueue(kind, "proj-b")
    job = job_queue.claim(kind)
    job_queue.complete(job["id"])
    assert job_queue.enqueue(kind, "proj-b", min_interval_hours=24) is None
    assert job_queue.enqueue(kind, "proj-b", min_interval_hours=0)


def test_two_workers_never_get_the_same_job(kind):
    ids = {job_queue.enqueue(kind, f"p{i}") for i in range(3)}
    got = [job_queue.claim(kind, worker=f"w{i}") for i in range(3)]
    assert {j["id"] for j in got} == ids
    assert job_queue.claim(kind, worker="w9") is None


def test_dead_worker_job_is_requeued_and_finished_by_another(kind):
    """The point of the whole thing: a worker that dies mid-job (no heartbeat) must not lose the job."""
    job_queue.enqueue(kind, "proj-c")
    job = job_queue.claim(kind, worker="worker-that-will-die", lease_seconds=1)
    assert job_queue.claim(kind, worker="other") is None       # still leased
    time.sleep(1.5)                                             # lease expires, nobody renewed it
    assert job_queue.requeue_expired() >= 1
    again = job_queue.claim(kind, worker="survivor")
    assert again["id"] == job["id"] and again["attempts"] == 2
    assert job_queue.heartbeat(job["id"], worker="worker-that-will-die") is False   # the dead worker no longer owns it
    job_queue.complete(job["id"], worker="survivor")
    assert _row(job["id"])[0] == "DONE"


def test_attempts_are_bounded(kind):
    job_queue.enqueue(kind, "proj-d", max_attempts=2)
    for n in (1, 2):
        job = job_queue.claim(kind, worker="w")
        assert job["attempts"] == n
        job_queue.fail(job["id"], "boom", worker="w")
    assert job_queue.claim(kind) is None
    status, attempts, _, err = _row(job["id"])
    assert (status, attempts, err) == ("FAILED", 2, "boom")


def test_heartbeat_extends_the_lease(kind):
    job_queue.enqueue(kind, "proj-e")
    job = job_queue.claim(kind, worker="w", lease_seconds=1)
    for _ in range(3):
        time.sleep(0.6)
        assert job_queue.heartbeat(job["id"], worker="w", lease_seconds=1)
    assert job_queue.requeue_expired() == 0
    job_queue.complete(job["id"], worker="w")


def test_asset_scans_are_queued_once_and_respect_the_rescan_interval():
    """auditors.auditor_ext: durable queue instead of the old in-memory dispatcher."""
    from auditors import auditor_ext
    aid = str(uuid.uuid4())
    assets = [(aid, "URL", "http://asset.test")]
    try:
        assert auditor_ext.enqueue_asset_scans(assets, 6) == 1
        assert auditor_ext.enqueue_asset_scans(assets, 6) == 0         # already queued
        job = job_queue.claim(auditor_ext.ASSET_SCAN_JOB_KIND)
        assert job["target"] == aid and job["payload"] == {"id": aid, "type": "URL", "endpoint": "http://asset.test"}
        job_queue.complete(job["id"])
        assert auditor_ext.enqueue_asset_scans(assets, 6) == 0         # scanned recently
        assert auditor_ext.enqueue_asset_scans(assets, 0) == 1         # a NEW asset path (interval 0) is always queued
    finally:
        with db_manager.get_db_cursor() as cur:
            cur.execute("DELETE FROM scan_jobs WHERE kind = %s AND target = %s", (auditor_ext.ASSET_SCAN_JOB_KIND, aid))


def test_a_target_that_failed_for_good_is_not_requeued_until_the_interval_passes(kind):
    """Regression: failed jobs used to be re-queued by the producer on every pass (retry storm of 395 failures from 3 unclonable repos)."""
    job_queue.enqueue(kind, "proj-f", max_attempts=1)
    job = job_queue.claim(kind, worker="w")
    job_queue.fail(job["id"], "clone_or_pull_failed", worker="w")
    assert _row(job["id"])[0] == "FAILED"
    assert job_queue.enqueue(kind, "proj-f", min_interval_hours=24) is None      # must wait
    assert job_queue.enqueue(kind, "proj-f", min_interval_hours=0)               # explicit immediate retry still possible


def test_empty_repository_is_skipped_not_failed(monkeypatch):
    """Regression: 3 empty GitLab projects were retried ~130 times each as 'clone_or_pull_failed'."""
    from auditors import gitlab_integration as gi

    from core import gitlab_instances

    class FakeIntegrator:
        def __init__(self, instance="primary"):
            self.instance = gitlab_instances.GitLabInstance(key="primary", url="http://gitlab.test", token="t", asset_prefix="GitLab/", folder_prefix="")
        def scan_single_project(self, proj, branch="", separate_asset=False): return {"status": "skipped", "reason": "empty_repo", "name": "x/y"}

    monkeypatch.setattr(gi, "GitLabIntegrator", FakeIntegrator)
    res = gi.run_scan_job({"target": "primary:x/y", "payload": {"instance": "primary", "project": {"id": 1}}})
    assert res["status"] == "skipped"          # returned (job completes) instead of raising


def test_scan_single_project_reports_empty_repo_when_the_clone_fails(monkeypatch):
    from auditors import gitlab_integration as gi
    inst = gi.GitLabIntegrator.__new__(gi.GitLabIntegrator)
    monkeypatch.setattr(inst, "pick_branch", lambda pid: "main", raising=False)
    monkeypatch.setattr(inst, "clone_or_pull", lambda *a, **k: None, raising=False)
    monkeypatch.setattr(inst, "get_project_details", lambda pid: {"empty_repo": True}, raising=False)
    res = inst.scan_single_project({"id": 7, "path_with_namespace": "g/empty", "http_url_to_repo": "http://gitlab.test/g/empty.git"})
    assert res["status"] == "skipped" and res["reason"] == "empty_repo"
    monkeypatch.setattr(inst, "get_project_details", lambda pid: {"empty_repo": False}, raising=False)
    assert inst.scan_single_project({"id": 7, "path_with_namespace": "g/x", "http_url_to_repo": "http://gitlab.test/g/x.git"})["reason"] == "clone_or_pull_failed"


def test_a_prioritized_job_is_claimed_before_an_older_unprioritized_one(kind):
    older = job_queue.enqueue(kind, "periodic-fleet-scan", {})
    asked_by_a_person = job_queue.enqueue(kind, "branch-scan", {"priority": 10})
    assert job_queue.claim(kind)["id"] == asked_by_a_person
    assert job_queue.claim(kind)["id"] == older
