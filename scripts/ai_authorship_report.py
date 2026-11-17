#!/usr/bin/env python3
"""
Defect density: AI-assisted code vs the rest, for ONE asset (ADR-0012 D6). READ-ONLY.
    docker exec -w /app centinela-backend python scripts/ai_authorship_report.py "Centinela-AI (Self-Audit)"
The repository comes from the clone the fleet scanner keeps (or /app for the self-audit asset). See auditors/ai_authorship.py for the limits.
"""
import json
import sys

sys.path.insert(0, ".")
from auditors import ai_authorship  # noqa: E402
from core import code_context, db_manager  # noqa: E402


def main(asset):
    repo = code_context._resolve_repo_dir(asset, None, "/tmp/centinela_gitlab_scans")
    if not repo:
        print(json.dumps({"evaluable": False, "reason": f"sin clon local para {asset!r}"}, ensure_ascii=False, indent=2))
        return 1
    with db_manager.get_db_cursor() as cur:
        cur.execute("""SELECT v.url_path FROM vulnerability_log v JOIN infra_inventory i ON i.id=v.asset_id
                       WHERE i.asset_name=%s AND v.finding_category IN ('VULNERABILITY','COMPLIANCE') AND v.status NOT IN ('RESOLVED','SUPPRESSED')
                         AND v.url_path IS NOT NULL""", (asset,))
        findings = [{"url_path": r[0]} for r in cur.fetchall()]
    res = ai_authorship.measure(repo, findings)
    res.update(asset=asset, repo=repo, findings_considered=len(findings))
    print(json.dumps(res, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "Centinela-AI (Self-Audit)"))
