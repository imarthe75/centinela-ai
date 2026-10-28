#!/usr/bin/env python3
"""
Purge every `vulnerability_log.fix_patch` that does not apply to the real repository.

Context (2026-09-23 audit): backfill_fleet_ai.py / rebuild_precise_patches.py / remediate_all_*.py
wrote templated diffs with invented hunk headers and invented "before" lines into ~115k rows.
A stored patch is only kept if `git apply --check` succeeds against the actual clone/source tree
of the asset it belongs to (core.patch_validator). Everything else is set to NULL.

Safety: the affected columns are first copied to a backup table (created once, never overwritten),
nothing but `fix_patch` (and `remediation_history.can_automate`) is modified, and rows that carry a
real human decision in `remediation_history.approval_token` are reported, never silently changed.

Run inside `centinela-ai` (it owns the clones under /tmp/centinela_gitlab_scans):
    docker exec -w /app -e PYTHONPATH=/app centinela-ai python3 scripts/purge_unverified_fix_patches.py [--apply]
Without --apply it is a dry run (validation only, no writes, no backup).
"""
import argparse
import glob
import os
import sys
from collections import Counter

sys.path.insert(0, os.environ.get("APP_ROOT", "/app"))
from core import code_context, db_manager, patch_validator  # noqa: E402

WORKSPACE = "/tmp/centinela_gitlab_scans"
BACKUP_TABLE = "vulnerability_log_fixpatch_backup_20260923"
# CVE ids whose fix is produced by a deterministic patcher at MR time (no stored diff needed).
DETERMINISTIC_PREFIXES = ("SCA-CVE-", "DOCKER-MISSING-NON-ROOT-USER", "DOCKER-ROOT-USER", "CMD-INJECTION-SHELL-TRUE")


def candidate_dirs(asset_name: str):
    """All real source trees this asset's patch could legitimately apply to."""
    dirs = []
    d = code_context._resolve_repo_dir(asset_name, None, WORKSPACE)
    if d:
        dirs.append(d)
    if asset_name.startswith("Local/proyecto-j/"):
        p = os.path.join("/app/proyecto-j", asset_name.split("/", 2)[2])
        if os.path.isdir(p):
            dirs.append(p)
    if asset_name.startswith("Local/proyecto-j-qa/"):
        dirs.extend(sorted(glob.glob("/app/proyecto-j_qa/*/")))
        dirs.extend(sorted(glob.glob("/app/proyecto-j_qa/*/*/")))
    return dirs


def validates_anywhere(asset_name: str, patch: str):
    reasons = []
    for d in candidate_dirs(asset_name):
        ok, why = patch_validator.validate_patch(d, patch)
        if ok:
            return True, "ok"
        reasons.append(why)
    return False, (reasons[0] if reasons else "repo_unavailable")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true")
    args = ap.parse_args()

    with db_manager.get_db_cursor() as cur:
        cur.execute("""
            SELECT v.asset_id, COALESCE(i.asset_name, ''), v.fix_patch, array_agg(v.id)
            FROM public.vulnerability_log v LEFT JOIN public.infra_inventory i ON i.id = v.asset_id
            WHERE v.fix_patch IS NOT NULL AND v.fix_patch <> ''
            GROUP BY v.asset_id, i.asset_name, v.fix_patch
        """)
        groups = cur.fetchall()
    print(f"distinct (asset, patch) groups to verify: {len(groups)}")

    keep_ids, drop_ids, reasons = [], [], Counter()
    for n, (asset_id, asset_name, patch, ids) in enumerate(groups, 1):
        ok, why = validates_anywhere(asset_name, patch)
        if ok:
            keep_ids.extend(ids)
        else:
            drop_ids.extend(ids)
            reasons[why.split(":")[0]] += len(ids)
        if n % 5000 == 0:
            print(f"  ...{n}/{len(groups)} groups checked (keep={len(keep_ids)} drop={len(drop_ids)})")

    print(f"VERIFIED-REAL patches kept : {len(keep_ids)}")
    print(f"UNVERIFIED patches to purge: {len(drop_ids)}")
    for why, c in reasons.most_common():
        print(f"    {why:28s} {c}")

    if not args.apply:
        print("dry run: nothing written (use --apply)")
        return 0

    with db_manager.get_db_cursor() as cur:
        cur.execute(f"""
            CREATE TABLE IF NOT EXISTS public.{BACKUP_TABLE} AS
            SELECT id, asset_id, cve_id, description, fix_patch, executive_summary, business_impact, developer_steps
            FROM public.vulnerability_log WHERE fix_patch IS NOT NULL AND fix_patch <> ''
        """)
        cur.execute(f"SELECT count(*) FROM public.{BACKUP_TABLE}")
        print(f"backup table {BACKUP_TABLE}: {cur.fetchone()[0]} rows")

        # A human decision must never be silently changed.
        cur.execute("""
            SELECT count(*) FROM public.remediation_history
            WHERE vuln_id = ANY(%s::uuid[]) AND approval_token NOT IN ('PENDING_APPROVAL')
        """, (drop_ids,))
        decided = cur.fetchone()[0]
        print(f"rows to purge that already carry a human decision (will keep can_automate untouched): {decided}")

        for i in range(0, len(drop_ids), 5000):
            chunk = drop_ids[i:i + 5000]
            cur.execute("UPDATE public.vulnerability_log SET fix_patch = NULL WHERE id = ANY(%s::uuid[])", (chunk,))
            # No stored diff -> the finding is no longer auto-fixable unless a deterministic patcher exists.
            cur.execute("""
                UPDATE public.remediation_history rh SET can_automate = 'false'
                FROM public.vulnerability_log v
                WHERE rh.vuln_id = v.id AND v.id = ANY(%s::uuid[])
                  AND rh.approval_token = 'PENDING_APPROVAL'
                  AND NOT (v.cve_id LIKE ANY(%s))
            """, (chunk, [p + "%" for p in DETERMINISTIC_PREFIXES]))
        print("purge committed")
    return 0


if __name__ == "__main__":
    rc = main()
    sys.stdout.flush()
    os._exit(rc)
