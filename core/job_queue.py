"""Persistent job queue backed by Postgres (table scan_jobs, migration 0002) -- ADR-0008 #4.

Guarantees:
  * enqueue is idempotent: one active (QUEUED/RUNNING) job per (kind, target), enforced by a partial unique index;
  * a job is handed to exactly one worker (FOR UPDATE SKIP LOCKED);
  * a RUNNING job holds a lease the worker must keep renewing; if the worker dies the lease expires and the job is re-queued
    (up to max_attempts), so a service restart no longer loses the work in flight;
  * `min_interval_hours` stops a project from being re-queued right after it finished OR failed for good.
Every function raises on database errors (callers log with traceback); nothing here swallows exceptions.
"""
import json
import socket
from datetime import datetime
from typing import Any, Dict, Optional

from psycopg2.extras import RealDictCursor

from core import db_manager

DEFAULT_LEASE_SECONDS = 300
WORKER_ID = f"{socket.gethostname()}"


def enqueue(kind: str, target: str, payload: Optional[Dict[str, Any]] = None, *, max_attempts: int = 3,
            min_interval_hours: float = 0, not_finished_since: Optional[datetime] = None) -> Optional[str]:
    """Queue a job. Returns its id, or None when it was skipped: already active, finished less than min_interval_hours ago, or
    finished at/after `not_finished_since` (an aware datetime -- the daily cutoff of core.scan_schedule). DONE and FAILED both count."""
    with db_manager.get_db_cursor() as cur:
        if not_finished_since is not None:
            if not_finished_since.tzinfo is None:
                raise ValueError("not_finished_since must be timezone-aware")
            cur.execute("""SELECT 1 FROM scan_jobs WHERE kind = %s AND target = %s AND status IN ('DONE', 'FAILED')
                           AND finished_at >= %s LIMIT 1""", (kind, target, not_finished_since))
            if cur.fetchone():
                return None
        if min_interval_hours:
            # DONE *and* FAILED count: a target that exhausted its attempts must wait the interval too, otherwise the producer re-queues it
            # on its next pass and an unfixable job (e.g. a repo that cannot be cloned) is retried forever (seen live: 395 failures from 3 projects).
            cur.execute("""SELECT 1 FROM scan_jobs WHERE kind = %s AND target = %s AND status IN ('DONE', 'FAILED')
                           AND finished_at > now() - make_interval(secs => %s) LIMIT 1""", (kind, target, min_interval_hours * 3600))
            if cur.fetchone():
                return None
        cur.execute("""INSERT INTO scan_jobs (kind, target, payload, max_attempts) VALUES (%s, %s, %s::jsonb, %s)
                       ON CONFLICT (kind, target) WHERE status IN ('QUEUED', 'RUNNING') DO NOTHING RETURNING id""",
                    (kind, target, json.dumps(payload or {}), max_attempts))
        row = cur.fetchone()
        return str(row[0]) if row else None


def requeue_expired() -> int:
    """Jobs whose worker stopped renewing the lease go back to QUEUED, or FAILED once attempts are exhausted. Returns how many were touched."""
    with db_manager.get_db_cursor() as cur:
        cur.execute("""UPDATE scan_jobs SET
                          status = CASE WHEN attempts >= max_attempts THEN 'FAILED' ELSE 'QUEUED' END,
                          finished_at = CASE WHEN attempts >= max_attempts THEN now() ELSE NULL END,
                          last_error = COALESCE(last_error, '') || 'lease expired (worker died or hung); ',
                          worker = NULL, lease_until = NULL
                       WHERE status = 'RUNNING' AND lease_until < now()""")
        return cur.rowcount


def claim(kind: Optional[str] = None, worker: str = WORKER_ID, lease_seconds: int = DEFAULT_LEASE_SECONDS) -> Optional[Dict[str, Any]]:
    """Take the highest-priority (payload.priority, default 0), then oldest, QUEUED job (optionally of one kind) for this worker. Returns the job row as a dict, or None when the queue is empty."""
    with db_manager.get_db_cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("""UPDATE scan_jobs SET status = 'RUNNING', worker = %s, attempts = attempts + 1,
                              started_at = now(), lease_until = now() + make_interval(secs => %s)
                       WHERE id = (SELECT id FROM scan_jobs WHERE status = 'QUEUED' AND (%s::text IS NULL OR kind = %s)
                                   ORDER BY COALESCE((payload->>'priority')::int, 0) DESC, created_at FOR UPDATE SKIP LOCKED LIMIT 1)
                       RETURNING id, kind, target, payload, attempts, max_attempts""", (worker, lease_seconds, kind, kind))
        row = cur.fetchone()
        if row:
            row["id"] = str(row["id"])
        return row


def heartbeat(job_id: str, worker: str = WORKER_ID, lease_seconds: int = DEFAULT_LEASE_SECONDS) -> bool:
    """Renew the lease. False when the job is no longer ours (it expired and was re-queued) -- the worker should stop."""
    with db_manager.get_db_cursor() as cur:
        cur.execute("""UPDATE scan_jobs SET lease_until = now() + make_interval(secs => %s)
                       WHERE id = %s AND worker = %s AND status = 'RUNNING'""", (lease_seconds, job_id, worker))
        return cur.rowcount == 1


def complete(job_id: str, worker: str = WORKER_ID) -> None:
    with db_manager.get_db_cursor() as cur:
        cur.execute("""UPDATE scan_jobs SET status = 'DONE', finished_at = now(), lease_until = NULL
                       WHERE id = %s AND worker = %s AND status = 'RUNNING'""", (job_id, worker))


def fail(job_id: str, error: str, worker: str = WORKER_ID) -> None:
    """Record a failure: back to QUEUED while attempts remain, FAILED afterwards."""
    with db_manager.get_db_cursor() as cur:
        cur.execute("""UPDATE scan_jobs SET
                          status = CASE WHEN attempts >= max_attempts THEN 'FAILED' ELSE 'QUEUED' END,
                          finished_at = CASE WHEN attempts >= max_attempts THEN now() ELSE NULL END,
                          last_error = %s, worker = NULL, lease_until = NULL
                       WHERE id = %s AND worker = %s AND status = 'RUNNING'""", (error[:2000], job_id, worker))


def stats() -> Dict[str, int]:
    with db_manager.get_db_cursor() as cur:
        cur.execute("SELECT status, count(*) FROM scan_jobs GROUP BY status")
        return {s: n for s, n in cur.fetchall()}
