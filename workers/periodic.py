"""Moved verbatim from centinela.py (ADR-0008 #3)."""
import os
import re
import logging
import threading
import time
import json
import redis
import psycopg2
import concurrent.futures
from psycopg2.extras import RealDictCursor
from core import db_manager, asset_types
from core import agent_ledger
from core import deduplication_engine

import hvac
import urllib.request
import urllib.error
import ssl


from core.ip_block_script import generate_ip_block_virtual_patch, generate_ip_unblock_script  # noqa: E402  (shared with core/soar_engine.py)
import logging
logger = logging.getLogger("centinela")




def run_secrets_history_worker_loop():
    """Consumer of the git-history secrets queue (one job at a time, own lease/heartbeat, independent of the per-project scan worker)."""
    from auditors.secrets_history_job import SECRETS_JOB_KIND, run_secrets_history_job
    run_scan_worker_loop(poll_seconds=60, heartbeat_seconds=60, kind=SECRETS_JOB_KIND, runner=run_secrets_history_job)


def run_fleet_enqueue_loop(interval_seconds: int = 600):
    """Producer: every 10 minutes queue the GitLab projects that are due for a scan (idempotent, see enqueue_fleet_scan)."""
    from auditors.gitlab_integration import enqueue_fleet_scan
    while True:
        try:
            s = enqueue_fleet_scan()
            if s["enqueued"] or s["instances_failed"] or s.get("unchanged"):
                print(f"📥 [Fleet-Queue] {s['enqueued']} projects queued, {s.get('unchanged', 0)} unchanged since last analysis (not scanned), "
                      f"{s['skipped']} skipped (active/recent), {s['projects_seen']} seen"
                      + (f", instances failed: {s['instances_failed']}" if s["instances_failed"] else ""))
        except Exception:
            logger.error("[Fleet-Queue] enqueue failed", exc_info=True)
        try:
            from auditors.secrets_history_job import enqueue_secrets_history_scans
            h = enqueue_secrets_history_scans()
            if h["enqueued"]:
                print(f"🔐 [Fleet-Queue] {h['enqueued']} git-history secret scans queued ({h['skipped']} recent/active)")
        except Exception:
            logger.error("[Fleet-Queue] secrets-history enqueue failed", exc_info=True)
        time.sleep(interval_seconds)



def run_gitlab_heads_refresh_loop(interval_minutes: float = None):
    """Keep gitlab_branch_heads current (latest commit of every branch with a GitLab asset), so the UI can tell which assets changed since
    their last analysis without asking GitLab on every page view. One GitLab call per project per pass (GITLAB_HEADS_REFRESH_MINUTES, 15)."""
    from core import change_detection
    minutes = interval_minutes or float(os.getenv("GITLAB_HEADS_REFRESH_MINUTES", "15"))
    while True:
        try:
            r = change_detection.refresh_all_inventory()
            if r["failed"]:
                print(f"⚠️ [Heads-Refresh] {r['projects']} projects checked, {len(r['failed'])} could not be read")
        except Exception:
            logger.error("[Heads-Refresh] refresh failed", exc_info=True)
        time.sleep(minutes * 60)


def run_scan_worker_loop(poll_seconds: int = 30, heartbeat_seconds: int = 60, kind: str = None, runner=None):
    """Consumer: takes one queued scan job at a time and keeps its lease alive while it runs. If this process dies, the lease expires and
    the job is re-queued (core/job_queue.py), so a restart no longer loses the scan in flight.
    Default kind is the per-project GitLab scan; the git-history secrets job reuses the same loop with its own kind/runner."""
    from core import job_queue
    from auditors.gitlab_integration import GITLAB_JOB_KIND, run_scan_job
    kind = kind or GITLAB_JOB_KIND
    runner = runner or run_scan_job
    while True:
        try:
            requeued = job_queue.requeue_expired()
            if requeued:
                print(f"♻️ [Scan-Worker] {requeued} job(s) with an expired lease returned to the queue")
            job = job_queue.claim(kind=kind)
            if not job:
                time.sleep(poll_seconds)
                continue
            print(f"🔍 [Scan-Worker] {job['target']} (attempt {job['attempts']}/{job['max_attempts']})")
            stop = threading.Event()

            def _beat(job_id=job["id"]):
                while not stop.wait(heartbeat_seconds):
                    try:
                        if not job_queue.heartbeat(job_id):
                            logger.error("[Scan-Worker] lost the lease of job %s", job_id)
                            return
                    except Exception:
                        logger.error("[Scan-Worker] heartbeat failed", exc_info=True)
            threading.Thread(target=_beat, daemon=True).start()
            try:
                res = runner(job)
                job_queue.complete(job["id"])
                print(f"✅ [Scan-Worker:{kind}] {job['target']}: " + (f"{res.get('total_vulnerabilities', 0)} findings" if kind == GITLAB_JOB_KIND else str(res)))
            except Exception as e:
                logger.error("[Scan-Worker] job %s failed", job["target"], exc_info=True)
                job_queue.fail(job["id"], f"{type(e).__name__}: {e}")
            finally:
                stop.set()
        except Exception:
            logger.error("[Scan-Worker] loop error", exc_info=True)
            time.sleep(poll_seconds)


def run_heuristics_loop():
    """Runs the temporal correlation engine every 60 seconds."""
    from core import heuristics_engine
    while True:
        try:
            heuristics_engine.run_heuristics_correlation()
        except Exception as e:
            print(f"❌ [Centinela-AI] Error running heuristics correlation: {e}")
        time.sleep(60)



def _criticality_weight(criticality: str) -> float:
    """Maps infra_inventory.criticality (real text field, values seen: CRITICAL/HIGH/MEDIUM/LOW,
    mixed case) to the 0.5-2.0 range calculate_centinela_risk_score expects."""
    c = str(criticality or '').upper()
    return {"CRITICAL": 2.0, "HIGH": 1.5, "MEDIUM": 1.0, "LOW": 0.5}.get(c, 1.0)



def run_threat_intel_enrichment_loop():
    """
    Backfills real EPSS exploitation-probability scores and real CISA KEV (confirmed
    actively-exploited) status onto vulnerability_log rows, and (re)computes a real Centinela
    Risk Score from them plus the asset's real criticality.

    Previously nothing ever wrote epss_score/is_cisa_kev, so every risk score used a fixed 0.15
    EPSS default and is_cisa_kev=False for every finding regardless of real-world exploitation
    status -- e.g. a finding for Log4Shell (CVE-2021-44228, confirmed CISA KEV, EPSS ~1.0) and
    an obscure CVE with near-zero real exploitation likelihood got an identical score. Runs as
    a background pass (not per-request) since EPSS/KEV are external API calls -- both endpoints
    are batched, but recomputing on every dashboard page load would be slow and wasteful. This
    also backfills the large volume of pre-existing rows from before this fix existed.
    """
    from core import threat_intel, deduplication_engine
    # During a backlog catch-up this loop iterates every ~5s; a ledger row per iteration would
    # be pure noise (~17k rows/day). Accumulate instead and record ONE summary row when the
    # backlog drains (the `if not rows` branch), plus an immediate row for any pass that finds
    # a CISA-KEV hit (that signal shouldn't wait for the backlog to clear).
    _enriched_since_idle = 0
    _kev_since_idle = 0
    while True:
        try:
            with db_manager.get_db_cursor(cursor_factory=RealDictCursor) as cur:
                # epss_score/is_cisa_kev default to 0.0/FALSE at the column level (never NULL),
                # so "never enriched" can't be told apart from "genuinely zero" by NULL-ness --
                # and most findings aren't CVE-based at all (ZAP-*/DOCKER-*/STD-* rule IDs), so
                # they'd always legitimately get real epss=0.0/kev=false written back, which
                # would re-match a filter based on those values on every single pass forever.
                # threat_intel_checked_at is a real completion marker instead: set once per row
                # below, and re-checked after 24h since EPSS scores do genuinely change over time
                # as real-world exploitation data comes in.
                cur.execute("""
                    SELECT v.id, v.cve_id, COALESCE(v.real_severity, v.severity) AS severity, i.criticality
                    FROM vulnerability_log v
                    JOIN infra_inventory i ON v.asset_id = i.id
                    WHERE (v.threat_intel_checked_at IS NULL OR v.threat_intel_checked_at < NOW() - INTERVAL '24 hours')
                    AND v.status != 'RESOLVED'
                    ORDER BY v.id DESC
                    LIMIT 200
                """)
                rows = cur.fetchall()

            if not rows:
                if _enriched_since_idle:
                    agent_ledger.record_action(
                        agent_ledger.ACTION_THREAT_INTEL_ENRICH,
                        f"Backlog EPSS/CISA KEV al día: {_enriched_since_idle} hallazgo(s) enriquecidos "
                        f"en esta ronda; {_kev_since_idle} en KEV (explotación activa confirmada)",
                        detail={"enriched": _enriched_since_idle, "kev_hits": _kev_since_idle},
                        outcome="success",
                    )
                    _enriched_since_idle = 0
                    _kev_since_idle = 0
                time.sleep(300)
                continue

            print(f"🛰️ [Centinela-AI] Enriching {len(rows)} finding(s) with real EPSS/CISA KEV threat intel...")

            cve_by_row = {r["id"]: threat_intel.extract_cve(r["cve_id"]) for r in rows}
            real_cves = [c for c in cve_by_row.values() if c]
            epss_scores = threat_intel.get_epss_scores(real_cves) if real_cves else {}
            kev_set = threat_intel.get_cisa_kev_set()

            with db_manager.get_db_cursor() as write_cur:
                for r in rows:
                    cve = cve_by_row[r["id"]]
                    # No real CVE (ZAP/DOCKER/STD/etc. -- Centinela's own rule IDs, not CVEs):
                    # 0.0/False is the honest value (no EPSS/KEV data exists for a non-CVE), not
                    # a copy of the old fake "unknown so assume 0.15" placeholder.
                    epss = epss_scores.get(cve, 0.0) if cve else 0.0
                    is_kev = (cve in kev_set) if cve else False

                    sev = str(r.get("severity") or "MEDIUM").upper()
                    # No numeric CVSS is stored anywhere in this schema; approximating from the
                    # severity bucket a real scanner (OSV/ZAP/etc.) already assigned is the best
                    # available signal without adding a slow, heavily rate-limited per-CVE NVD
                    # lookup to a bulk backfill pass.
                    cvss_approx = {"CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 2.5}.get(sev, 5.0)
                    risk_score = deduplication_engine.calculate_centinela_risk_score(
                        cvss_approx, epss, is_kev, _criticality_weight(r.get("criticality"))
                    )

                    write_cur.execute("""
                        UPDATE vulnerability_log
                        SET epss_score = %s, is_cisa_kev = %s, risk_score = %s, threat_intel_checked_at = NOW()
                        WHERE id = %s
                    """, (epss, is_kev, risk_score, r["id"]))

            kev_hits = sum(1 for r in rows if (cve_by_row[r["id"]] in kev_set if cve_by_row[r["id"]] else False))
            if kev_hits:
                print(f"🚨 [Centinela-AI] {kev_hits} finding(s) in this batch are CISA-confirmed actively exploited (KEV).")

            _enriched_since_idle += len(rows)
            _kev_since_idle += kev_hits
            if kev_hits:
                agent_ledger.record_action(
                    agent_ledger.ACTION_THREAT_INTEL_ENRICH,
                    f"{kev_hits} hallazgo(s) marcados CISA-KEV (explotación activa confirmada) en esta tanda de {len(rows)}",
                    detail={"enriched_batch": len(rows), "kev_hits": kev_hits}, outcome="success",
                )

            # Brief pacing between batches during backlog catch-up so this doesn't hammer
            # FIRST.org/CISA back-to-back with no gap; harmless once the backlog is drained and
            # each pass finds nothing (that case sleeps 300s via the `if not rows` branch above).
            time.sleep(5)

        except Exception as e:
            print(f"❌ [Centinela-AI] Error in threat intel enrichment loop: {e}")
            time.sleep(60)



def run_cis_benchmark_loop():
    """
    Periodically runs the real CIS Level 1 hardening check subset (auditors/auditor_cis_benchmarks.py)
    over SSH against every SERVER/AppServer asset. Previously this only ever ran when a human hit
    POST /api/cis-benchmark/check/{asset_name} by hand -- the health check honestly reported
    "Available (On-Demand, Not Yet Run)" because nothing ever actually triggered it. All checks
    are read-only (file permissions, sshd_config, systemctl is-active, etc); nothing is modified
    on the target host. log_cis_findings() always writes a CIS-BENCHMARK-AUDIT completion marker
    (pass or fail) so "never checked" can be told apart from "checked N days ago, all green" via
    its own detected_at, the same pattern threat_intel_checked_at uses above.
    """
    from auditors.auditor_cis_benchmarks import run_cis_audit, log_cis_findings
    RECHECK_INTERVAL_DAYS = 7
    while True:
        try:
            with db_manager.get_db_cursor(cursor_factory=RealDictCursor) as cur:
                # Real bug fixed here 2026-08-12: 'Database (SQL)' and 'GITLAB' asset types were
                # never in scope, even though CIS Level 1 checks are pure Linux OS hardening (SSH
                # config, /etc/shadow perms, firewall, etc) -- they evaluate the underlying host,
                # not "is this asset type a generic app server". Confirmed live: 74/83 assets
                # showed as permanently "never evaluated" on the dashboard; of those, 67 are
                # GitLab-Repo (correctly out of scope -- a code repository has no OS to harden)
                # but 4 Database (SQL) assets and 1 GITLAB asset were real, potentially reachable
                # Linux hosts silently excluded by this filter alone, not by any real
                # unreachability. GitLab-Repo/GITLAB-org-level and other non-host types are still
                # deliberately excluded -- CIS Level 1 genuinely does not apply to them.
                cur.execute("""
                    SELECT i.id, i.asset_name, i.endpoint
                    FROM infra_inventory i
                    LEFT JOIN vulnerability_log v
                        ON v.asset_id = i.id AND v.cve_id = 'CIS-BENCHMARK-AUDIT'
                    WHERE i.asset_type IN %s
                        AND i.endpoint != 'remote-agent'
                    GROUP BY i.id, i.asset_name, i.endpoint
                    HAVING MAX(v.detected_at) IS NULL
                        OR MAX(v.detected_at) < NOW() - (%s || ' days')::interval
                    ORDER BY MAX(v.detected_at) ASC NULLS FIRST
                    LIMIT 20
                """, (asset_types.LINUX_HOST_TYPES, RECHECK_INTERVAL_DAYS))
                due_assets = [a for a in cur.fetchall() if _scan_allowed(a)][:5]

            if not due_assets:
                time.sleep(3600)
                continue

            for asset in due_assets:
                try:
                    print(f"🛡️ [Centinela-AI] Running CIS Benchmark audit on {asset['asset_name']}...")
                    result = run_cis_audit(asset["asset_name"], asset["endpoint"])
                    log_cis_findings(asset["id"], result)
                    print(f"✅ [Centinela-AI] CIS Benchmark on {asset['asset_name']}: grade {result['grade']} ({result['percentage']}%)")
                except Exception as asset_err:
                    # Most commonly: no SSH credentials stored in Vault for this asset yet --
                    # skip it and let the next asset in the batch proceed rather than stalling
                    # the whole loop on one host.
                    print(f"⚠️ [Centinela-AI] CIS Benchmark on {asset['asset_name']} failed (likely missing SSH credentials): {asset_err}")
                time.sleep(10)

        except Exception as e:
            print(f"❌ [Centinela-AI] Error in CIS Benchmark loop: {e}")
            time.sleep(60)



def _scan_allowed(asset) -> bool:
    """Active checks (SSH, nmap) only against internal addresses unless allowlisted (core.asset_types.scan_target_allowed)."""
    ok, reason = asset_types.scan_target_allowed(asset["endpoint"])
    if not ok:
        print(f"⛔ [Centinela-AI] {asset['asset_name']}: {reason}")
    return ok


def _due_assets_for_marker(marker_cve: str, types, interval_days: int, limit: int = 5, guard: bool = True):
    """Assets whose last completion marker for this audit is missing or older than interval_days. With guard, assets whose
    endpoint is outside the internal network (and not allowlisted) are dropped; more rows are read so they can't starve the rest."""
    with db_manager.get_db_cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("""
            SELECT i.id, i.asset_name, i.endpoint
            FROM infra_inventory i
            LEFT JOIN vulnerability_log v ON v.asset_id = i.id AND v.cve_id = %s
            WHERE i.asset_type = ANY(%s) AND i.endpoint IS NOT NULL AND i.endpoint != 'remote-agent'
            GROUP BY i.id, i.asset_name, i.endpoint
            HAVING MAX(v.detected_at) IS NULL OR MAX(v.detected_at) < NOW() - (%s || ' days')::interval
            ORDER BY MAX(v.detected_at) ASC NULLS FIRST
            LIMIT %s
        """, (marker_cve, list(types), interval_days, limit * 4 if guard else limit))
        rows = cur.fetchall()
    return [a for a in rows if _scan_allowed(a)][:limit] if guard else rows



def run_os_patch_and_tls_audit_loop():
    """
    Weekly, read-only infrastructure hygiene audits added 2026-09-23 to close two coverage gaps:
    OS patch level / EOL (auditors/auditor_os_patches.py, SSH) and TLS posture
    (auditors/auditor_tls.py, nmap + handshake). Same scheduling contract as the CIS loop: the
    completion marker's own detected_at tells "never checked" from "checked recently".
    """
    from auditors import auditor_os_patches, auditor_tls, auditor_dns_security
    host_types = asset_types.LINUX_HOST_TYPES
    tls_types = asset_types.TLS_TYPES
    while True:
        did_work = False
        try:
            for a in _due_assets_for_marker(auditor_os_patches.MARKER_CVE, host_types, 7):
                did_work = True
                try:
                    res = auditor_os_patches.run_os_patch_audit(a['asset_name'], a['endpoint'])
                    n = auditor_os_patches.log_os_patch_findings(a['id'], res)
                    print(f"🩹 [OS-Patch] {a['asset_name']}: reachable={res['reachable']} findings={n}")
                except Exception:
                    import traceback
                    print(f"❌ [OS-Patch] audit failed for {a['asset_name']}:")
                    traceback.print_exc()
                time.sleep(5)
            for a in _due_assets_for_marker(auditor_tls.MARKER_CVE, tls_types, 7):
                did_work = True
                try:
                    res = auditor_tls.run_tls_audit(a['asset_name'], a['endpoint'])
                    n = auditor_tls.log_tls_findings(a['id'], res)
                    print(f"🔐 [TLS-Audit] {a['asset_name']}: status={res['status']} ports={res.get('evaluated_ports')} findings={n}")
                except Exception:
                    import traceback
                    print(f"❌ [TLS-Audit] audit failed for {a['asset_name']}:")
                    traceback.print_exc()
                time.sleep(5)
            for a in _due_assets_for_marker(auditor_dns_security.MARKER_CVE, ('Domain',), 7, guard=False):
                did_work = True
                try:
                    res = auditor_dns_security.run_dns_audit(a['asset_name'], a['endpoint'])
                    n = auditor_dns_security.log_dns_findings(a['id'], res)
                    print(f"🌐 [DNS-Audit] {a['asset_name']}: status={res['status']} findings={n}")
                except Exception:
                    import traceback
                    print(f"❌ [DNS-Audit] audit failed for {a['asset_name']}:")
                    traceback.print_exc()
                time.sleep(2)
        except Exception:
            import traceback
            print("❌ [Centinela-AI] Error in OS-patch/TLS audit loop:")
            traceback.print_exc()
            time.sleep(60)
            continue
        time.sleep(30 if did_work else 3600)



def run_wazuh_discovery_loop():
    """
    Periodically runs discovery.discover_wazuh_agents() -- confirmed live (2026-08-13) that this
    function, despite being real and working correctly, was never actually called anywhere in the
    running system; it only ever ran when a human manually exec'd it in a container. That means
    any agent enrolled via the zero-trust curl-one-liner install path (main.py's
    /api/inventory response includes a one-liner that self-enrolls with Wazuh directly, with no
    Python-side asset_id link at install time -- see hostname column notes in discovery.py) would
    sit enrolled in Wazuh but never actually get linked to (or created in) infra_inventory until
    someone remembered to run discovery by hand. All of this function's DB writes are simple
    upserts keyed by real IP/hostname/asset_name matches (see discovery.py) -- safe to run
    unattended on a schedule, same risk profile as the other periodic loops here.
    """
    from discovery import discovery
    while True:
        try:
            discovery.discover_wazuh_agents()
        except Exception as e:
            print(f"❌ [Centinela-AI] Error in Wazuh discovery loop: {e}")
        time.sleep(600)



def run_soar_expiry_loop():
    """Everything with a TTL: temporary SOAR IP blocks (lifted through Sentinel, same channel that added them) and finding
    suppressions / accepted risks (their findings reopen when they expire, ADR-0022 §1)."""
    from core import agent_ledger, soar_engine, suppression_lifecycle
    while True:
        try:
            stats = soar_engine.reap_expired_ip_blocks()
            if any(stats.values()):
                print(f"🔓 [SOAR-Expiry] {stats}")
        except Exception:
            import traceback
            print("❌ [Centinela-AI] Error in SOAR expiry loop:")
            traceback.print_exc()
        try:
            with db_manager.get_db_cursor() as cur:
                sstats = suppression_lifecycle.expire_due(cur)
            if sstats["expired"]:
                print(f"⏰ [Suppression-Expiry] {sstats}")
                agent_ledger.record_action(agent_ledger.ACTION_SUPPRESSION_EXPIRED,
                                           f"{sstats['expired']} supresiones vencidas; {sstats['reopened']} hallazgos reabiertos",
                                           entity_type="batch", detail=sstats, actor="centinela-ai", outcome="success")
        except Exception:
            import traceback
            print("❌ [Centinela-AI] Error expiring finding suppressions:")
            traceback.print_exc()
        time.sleep(300)



def renew_secrets_token() -> str:
    """Renews this service's own OpenBao/Vault token (`auth/token/renew-self`). Centinela's token is periodic
    (scripts/openbao_provision_centinela.sh): it lives as long as it is renewed within its period. Returns
    "renewed", "not_renewable" (e.g. a root or non-periodic token: nothing to do) or "failed" (logged with traceback)."""
    import hvac
    addr, token = os.getenv("VAULT_ADDR"), os.getenv("VAULT_TOKEN")
    if not addr or not token:
        return "not_renewable"
    try:
        client = hvac.Client(url=addr, token=token, timeout=15)
        info = client.auth.token.lookup_self()["data"]
        if not info.get("renewable"):
            return "not_renewable"
        client.auth.token.renew_self()
        return "renewed"
    except hvac.exceptions.Forbidden:
        print("❌ [Secrets] OpenBao rechaza el token de .env (permiso denegado): es un token de otro clúster o revocado. "
              "Ejecute scripts/openbao_provision_centinela.sh y recree los servicios.")
        return "failed"
    except Exception:
        import traceback
        print("❌ [Secrets] could not renew the OpenBao/Vault token:")
        traceback.print_exc()
        return "failed"


def run_secrets_token_renew_loop(interval_hours: float = 24):
    """Daily renewal, far inside the 768h period: a missed day or a restart never lets the token lapse."""
    while True:
        result = renew_secrets_token()
        if result != "not_renewable":
            print(f"🔑 [Secrets] token renewal: {result}")
        time.sleep(interval_hours * 3600)


def seconds_until_next(daily_at: str, tz: str, now=None) -> float:
    """Seconds from `now` to the next occurrence of `daily_at` (HH:MM) in zone `tz` (always > 0)."""
    from datetime import datetime, timedelta, timezone
    from core import scan_schedule
    now = now or datetime.now(timezone.utc)
    nxt = scan_schedule.daily_cutoff(now, daily_at, tz) + timedelta(days=1)
    return max(1.0, (nxt - now).total_seconds())


def run_reverify_loop():
    """ADR-0021 backfill, nightly: severity reductions still without a second opinion get one, up to REVERIFY_DAILY_LIMIT per night
    (default 1000) at REVERIFY_DAILY_AT (default 06:00, SCAN_TIMEZONE), i.e. after the 03:00 fleet pass has re-cloned the repositories the
    verifier reads; a repository finding without its clone stays pending. Stops by itself when every free provider is out of quota.
    REVERIFY_DAILY_AT empty -> disabled."""
    import importlib.util
    import sys
    daily_at = os.getenv("REVERIFY_DAILY_AT", "06:00").strip()
    if not daily_at:
        print("ℹ️ [Reverify] nightly re-verification disabled (REVERIFY_DAILY_AT empty)")
        return
    tz = os.getenv("SCAN_TIMEZONE", "America/Mexico_City").strip() or "America/Mexico_City"
    limit = int(os.getenv("REVERIFY_DAILY_LIMIT", "1000"))
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts", "reverify_ai_downgrades.py")
    while True:
        time.sleep(seconds_until_next(daily_at, tz))
        try:
            spec = importlib.util.spec_from_file_location("reverify_ai_downgrades", path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            engine = sys.modules.get("__main__")
            if not hasattr(engine, "call_ai_cascade"):
                engine = None   # not running inside centinela.py: the script imports it itself
            outcomes = mod.reverify_step(limit, "%", engine=engine)
            agent_ledger.record_action("ai_reverify_nightly", f"Re-verificación nocturna: {dict(outcomes)}",
                                       detail={"outcomes": dict(outcomes), "limit": limit}, actor="centinela",
                                       outcome="success")
        except Exception as e:
            import traceback
            traceback.print_exc()
            print(f"⚠️ [Reverify] nightly run failed: {e}")


def run_zap_reaper_loop(interval_minutes: float = 15):
    """Orphaned zap-scan-* containers (parent restarted mid-scan) are reaped every 15 min, not only at startup: the
    40-min age gate in reap_orphaned_zap_containers() keeps scans in flight in either service safe."""
    from auditors.auditor_zap import reap_orphaned_zap_containers
    while True:
        time.sleep(interval_minutes * 60)
        reap_orphaned_zap_containers(quiet=True)


def run_cmmi_org_evidence_loop():
    """Organizational CMMI evidence (GOV, II, PAD, PCM, PQA of Centinela's own AI): collected once at start and then daily.
    Evidence rows expire after 30 days, so a dead loop makes the evidence stop counting instead of going stale silently."""
    from auditors import auditor_cmmi_evidence
    while True:
        try:
            res = auditor_cmmi_evidence.collect_org_evidence()
            print(f"📐 [CMMI-Evidence] Organizational evidence refreshed: {res}")
        except Exception as e:
            import traceback
            traceback.print_exc()
            print(f"⚠️ [CMMI-Evidence] Organizational evidence collection failed: {e}")
        time.sleep(24 * 3600)



def run_incident_correlation_loop():
    """
    Item 2 (2026-08-27): incident correlation. Groups related runtime/CTI/BloodHound/KEV
    signals that already exist in runtime_alerts / vulnerability_log into one incident with a
    timeline, an ATT&CK kill chain, and an MTTD/MTTC clock. Deterministic (union-find, no LLM);
    an optional AI executive summary is layered on the deterministic narrative and never
    invents events. Fail-safe: with nothing worth grouping it creates nothing. Full design in
    DECISIONS/0003; noise handling (this deployment's runtime_alerts is ~93% Falco self-noise)
    lives in core/incident_engine.NOISE_RULES.
    """
    from core import incident_engine as ie

    interval = int(os.getenv("INCIDENT_CORRELATION_INTERVAL_S", "120"))
    window = int(os.getenv("INCIDENT_CORRELATION_WINDOW_MIN", "60"))
    lookback = int(os.getenv("INCIDENT_LOOKBACK_HOURS", "6"))
    idle_close = int(os.getenv("INCIDENT_AUTO_CLOSE_IDLE_HOURS", "72"))
    min_events = int(os.getenv("INCIDENT_MIN_EVENTS", "2"))
    ai_summary_enabled = os.getenv("INCIDENT_AI_SUMMARY", "1") not in ("0", "false", "False")

    while True:
        try:
            signals = []
            with db_manager.get_db_cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT r.id, r.asset_id, r.priority, r.rule_name, r.alert_text,
                           r.output_fields, r.detected_at
                    FROM runtime_alerts r
                    WHERE r.detected_at > NOW() - make_interval(hours => %s)
                      AND NOT EXISTS (
                          SELECT 1 FROM incident_events ie
                          WHERE ie.source = 'runtime_alert' AND ie.source_id = r.id)
                    ORDER BY r.detected_at
                    LIMIT 3000
                """, (lookback,))
                rt_rows = cur.fetchall()

            fresh_assets = set()
            for r in rt_rows:
                if ie.is_noise(r["rule_name"]):
                    continue
                inds = ie.extract_indicators(r["rule_name"], r["alert_text"], r["output_fields"])
                sev = ie.normalize_severity(r["priority"])
                # plain INFO/LOW runtime noise with no indicators is not incident material
                if sev in ("INFO", "LOW") and not inds["ips"] and not inds["users"] \
                   and not ie.is_standalone_worthy(r["rule_name"], r["alert_text"]):
                    continue
                if r["asset_id"] is not None:
                    fresh_assets.add(r["asset_id"])
                signals.append(ie.Signal(
                    key=f"runtime_alert:{r['id']}", source="runtime_alert", source_id=r["id"],
                    asset_id=r["asset_id"], occurred_at=r["detected_at"], severity=sev,
                    rule_name=r["rule_name"] or "runtime alert",
                    summary=(r["alert_text"] or r["rule_name"] or "")[:400],
                    tactic=ie.classify_tactic(r["rule_name"], r["alert_text"]),
                    ips=inds["ips"], users=inds["users"],
                    standalone_worthy=ie.is_standalone_worthy(r["rule_name"], r["alert_text"]),
                ))

            with db_manager.get_db_cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT v.id, v.asset_id, v.severity, v.cve_id, v.description, v.detected_at,
                           v.is_cisa_kev
                    FROM vulnerability_log v
                    WHERE v.detected_at > NOW() - make_interval(hours => %s)
                      AND v.status NOT IN ('RESOLVED', 'SUPPRESSED')
                      AND (v.cve_id LIKE 'CTI-IOC-MATCH%%' OR v.cve_id LIKE 'BLOODHOUND-PATH%%'
                           OR v.is_cisa_kev = TRUE)
                      AND NOT EXISTS (
                          SELECT 1 FROM incident_events ie
                          WHERE ie.source = 'vulnerability' AND ie.source_id = v.id)
                    ORDER BY v.detected_at
                    LIMIT 500
                """, (lookback,))
                vuln_rows = cur.fetchall()

            for v in vuln_rows:
                cve_u = str(v["cve_id"] or "").upper()
                is_cti_or_bh = cve_u.startswith("CTI-IOC-MATCH") or cve_u.startswith("BLOODHOUND-PATH")
                # A KEV finding alone is not an incident -- only if the SAME asset also has a
                # fresh non-noise runtime signal this pass. CTI/BloodHound rows are worthy alone.
                if not is_cti_or_bh and v["asset_id"] not in fresh_assets:
                    continue
                inds = ie.extract_indicators(v["cve_id"], v["description"], None)
                signals.append(ie.Signal(
                    key=f"vulnerability:{v['id']}", source="vulnerability", source_id=v["id"],
                    asset_id=v["asset_id"], occurred_at=v["detected_at"],
                    severity=ie.normalize_severity(v["severity"]),
                    rule_name=v["cve_id"] or "vulnerability",
                    summary=(v["description"] or v["cve_id"] or "")[:400],
                    tactic=ie.classify_tactic(v["cve_id"], v["description"]),
                    ips=inds["ips"], users=inds["users"],
                    standalone_worthy=is_cti_or_bh,
                ))

            if not signals:
                time.sleep(interval)
                continue

            groups = ie.group_signals(signals, window_minutes=window)
            with db_manager.get_db_cursor() as cur:
                stats = ie.attach_or_create_incidents(cur, groups, window_minutes=window,
                                                      min_events=min_events)
                closed = ie.reconcile_closed_incidents(cur, idle_hours=idle_close)

            if stats["created"] or stats["attached"] or closed:
                print(f"🧩 [Centinela-AI] Incident correlation: +{stats['created']} nuevos, "
                      f"{stats['attached']} ampliados, {stats['events_linked']} eventos, "
                      f"{closed} cerrados por inactividad.")
                agent_ledger.record_action(
                    agent_ledger.ACTION_INCIDENT_CORRELATION,
                    f"{stats['created']} incidente(s) nuevos, {stats['attached']} ampliados, "
                    f"{stats['events_linked']} evento(s) vinculados, {closed} cerrados",
                    detail=stats | {"closed": closed, "signals": len(signals)},
                    outcome="success",
                )

            # Optional AI executive summary for HIGH/CRITICAL incidents that don't have one yet.
            if ai_summary_enabled:
                _fill_incident_ai_summaries()

            time.sleep(interval)
        except Exception as e:
            print(f"❌ [Centinela-AI] Error in incident correlation loop: {e}")
            import traceback
            traceback.print_exc()
            time.sleep(60)



def _fill_incident_ai_summaries(limit: int = 3):
    """Adds a short executive summary (via call_ai_cascade) to HIGH/CRITICAL incidents that
    don't have one. Built from the already-complete deterministic narrative -- if the cascade
    doesn't answer, ai_summary stays NULL and the narrative remains the source of truth."""
    try:
        with db_manager.get_db_cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT id, title, severity, kill_chain, narrative
                FROM public.incidents
                WHERE status IN ('OPEN', 'INVESTIGATING')
                  AND ai_summary IS NULL
                  AND UPPER(severity) IN ('HIGH', 'CRITICAL')
                ORDER BY detected_at DESC
                LIMIT %s
            """, (limit,))
            rows = cur.fetchall()
        for r in rows:
            prompt = f"""Actúa como analista SOC. Resume este incidente en 3-4 frases
para un reporte ejecutivo: qué está ocurriendo, por qué importa, y el siguiente paso de
investigación. NO inventes datos que no estén abajo.

Título: {r['title']}
Severidad: {r['severity']}
Cadena ATT&CK observada: {', '.join(r['kill_chain'] or []) or 'n/d'}
Línea de tiempo:
{r['narrative']}
"""
            summary = __import__('centinela').call_ai_cascade(prompt, want_json=False)
            if summary and summary.strip():
                with db_manager.get_db_cursor() as wcur:
                    wcur.execute("UPDATE public.incidents SET ai_summary = %s WHERE id = %s",
                                 (summary.strip()[:4000], r["id"]))
    except Exception as e:
        print(f"⚠️ [Centinela-AI] _fill_incident_ai_summaries failed (non-fatal): {e}")



def run_cti_correlation_loop():
    """
    Real CTI/IoC correlation against abuse.ch's Feodo Tracker (live, active C2 server IPs).
    Checks two real data sources this codebase already has: registered asset IPs
    (infra_inventory), and IPs mentioned in runtime_alerts (Falco/Zeek output already ingested
    by process_falco_alerts()/process_zeek_alerts()). A hit on the first means one of our own
    hosts' IPs is a known-malicious C2 server; a hit on the second means a runtime alert
    involved a connection to/from one.
    """
    from core import cti_feed, deduplication_engine

    while True:
        try:
            malicious_ips = cti_feed.get_malicious_ips()
            if not malicious_ips:
                time.sleep(3600)
                continue

            hits = 0
            with db_manager.get_db_cursor(cursor_factory=RealDictCursor) as cur:
                # Source 1: our own registered asset IPs.
                cur.execute("SELECT id, asset_name, endpoint FROM infra_inventory")
                for asset in cur.fetchall():
                    for ip in cti_feed.extract_ips(asset.get("endpoint") or ""):
                        if ip in malicious_ips:
                            ioc = malicious_ips[ip]
                            desc = (
                                f"**IP del activo `{asset['asset_name']}` ({ip}) aparece en Feodo Tracker "
                                f"(abuse.ch) como servidor C2 activo.**\n\n"
                                f"**Malware asociado:** {ioc.get('malware', 'desconocido')}\n"
                                f"**Primera vez visto:** {ioc.get('first_seen', 'desconocido')}\n"
                                f"**Estado:** {ioc.get('status', 'desconocido')}"
                            )
                            deduplication_engine.log_finding_deduplicated(
                                cur, asset["id"], "CTI-IOC-MATCH-ASSET", "CRITICAL", desc,
                                "cti-feed", url_path=ip, open_status="PENDING", preserve_status=True
                            )
                            hits += 1

                # Source 2: IPs seen in real runtime alerts (Falco/Zeek), checked against the
                # same live feed -- empty today (no runtime_alerts have fired yet in this
                # deployment), but the mechanism is real and starts working the moment they do.
                cur.execute("""
                    SELECT id, asset_id, alert_text, output_fields, rule_name
                    FROM runtime_alerts
                    WHERE detected_at > NOW() - INTERVAL '1 hour'
                """)
                for alert in cur.fetchall():
                    text = f"{alert.get('alert_text') or ''} {alert.get('output_fields') or ''}"
                    for ip in cti_feed.extract_ips(text):
                        if ip in malicious_ips and alert.get("asset_id"):
                            ioc = malicious_ips[ip]
                            desc = (
                                f"**Alerta runtime `{alert['rule_name']}` involucra la IP {ip}, "
                                f"presente en Feodo Tracker (abuse.ch) como servidor C2 activo.**\n\n"
                                f"**Malware asociado:** {ioc.get('malware', 'desconocido')}"
                            )
                            deduplication_engine.log_finding_deduplicated(
                                cur, alert["asset_id"], "CTI-IOC-MATCH-RUNTIME", "CRITICAL", desc,
                                "cti-feed", url_path=f"alert-{alert['id']}-{ip}", open_status="PENDING",
                                preserve_status=True
                            )
                            hits += 1

            if hits:
                print(f"🚨 [Centinela-AI] CTI correlation found {hits} real IoC match(es) against Feodo Tracker.")

        except Exception as e:
            print(f"❌ [Centinela-AI] Error in CTI correlation loop: {e}")

        time.sleep(1800)  # 30 min -- feed itself only refreshes hourly
