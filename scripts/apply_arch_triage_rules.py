#!/usr/bin/env python3
"""Adds the architecture causes (C-13..C-15) and their generic rules (core/triage_seeds/arquitectura.json) to EVERY existing triage group.
Idempotent (causes are upserted, this script's own rules are replaced). Approved by the project owner on 2026-10-12: classified as Calidad.
The causes carry NO work-plan hours on purpose: hours are the analyst's assumption and none was given.
usage (inside centinela-backend):  python scripts/apply_arch_triage_rules.py
"""
import json
import os
import sys

sys.path.insert(0, "/app")
from psycopg2.extras import Json  # noqa: E402
from core import db_manager  # noqa: E402

ACTOR = "seed:arquitectura-2026-10-12"
SEED = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "core", "triage_seeds", "arquitectura.json")

if __name__ == "__main__":
    seed = json.load(open(SEED, encoding="utf-8"))
    with db_manager.get_db_cursor() as cur:
        cur.execute("SELECT group_key FROM triage_groups ORDER BY group_key")
        groups = [r[0] for r in cur.fetchall()]
        for key in groups:
            for c in seed["root_causes"]:
                cur.execute("""INSERT INTO triage_root_causes (group_key, code, classification, kind, title, severity, certainty, rationale, how_to_confirm,
                                   strategy, owner, outdated, dedup_scope, plan, classified_by) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,false,'line',%s,%s)
                               ON CONFLICT (group_key, code) DO UPDATE SET classification=EXCLUDED.classification, kind=EXCLUDED.kind, title=EXCLUDED.title,
                                   certainty=EXCLUDED.certainty, rationale=EXCLUDED.rationale, how_to_confirm=EXCLUDED.how_to_confirm, strategy=EXCLUDED.strategy,
                                   owner=EXCLUDED.owner, plan=EXCLUDED.plan, classified_by=EXCLUDED.classified_by, classified_at=now()""",
                            (key, c["code"], c["classification"], c.get("kind"), c["title"], None, c.get("certainty"), c.get("rationale"), c.get("how_to_confirm"),
                             c.get("strategy"), c.get("owner"), Json(c["plan"]) if c.get("plan") else None, ACTOR))
            cur.execute("DELETE FROM triage_rules WHERE group_key=%s AND created_by=%s", (key, ACTOR))
            for r in seed["rules"]:
                cur.execute("""INSERT INTO triage_rules (group_key, rule_regex, engine, asset_regex, path_regex, line, root_cause_code, priority, note, created_by)
                               VALUES (%s,%s,NULL,NULL,NULL,NULL,%s,%s,%s,%s)""", (key, r["rule_regex"], r["root_cause_code"], r.get("priority", 0), seed["note"], ACTOR))
            print(f"{key}: {len(seed['root_causes'])} causas, {len(seed['rules'])} reglas")
