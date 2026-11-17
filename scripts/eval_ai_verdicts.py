#!/usr/bin/env python3
"""
Compares the AI's risk verdicts with HUMAN decisions (ADR-0012 D3). READ-ONLY (SELECT only).

Gold set, and why it is the only one that exists today (measured 2026-10-13):
  * finding_suppressions reviewed by a person: 0 (374 AI proposals are all PENDING)  -> nothing to compare yet
  * vulnerability_log.risk_verdict = 'ANALYST_OVERRIDDEN': 0
  * triage_rules written by the analyst from the proyecto-a workbook (created_by 'seed:proyecto-a_Hallazgos...'): 118 rules -> each open finding of that
    group that a rule classifies (Vulnerabilidad / Falso positivo / Calidad) is a human-labelled example.
Caveat that every report prints: the analyst's label is RULE-level (a root cause), not a per-occurrence judgement, and the AI verdict is
per-occurrence, so a disagreement is a lead to inspect, not proof the AI is wrong.

Usage (inside a Python container):  python scripts/eval_ai_verdicts.py [--rules-created-by-prefix seed:proyecto-a_Hallazgos] [--json]
"""
import argparse
import json
import sys
from collections import Counter, defaultdict

sys.path.insert(0, ".")
from core import db_manager  # noqa: E402
from core import triage  # noqa: E402

VERDICT_COLS = ["(sin veredicto)", "CONDITIONAL", "DOWNGRADED", "CONFIRMED_NO_RISK", "NO_RISK_PENDING_REVIEW", "AI_DOWNGRADE_REJECTED"]
SMALL_SAMPLE = 30


def labelled_findings(cur, prefix_filter):
    cur.execute("SELECT DISTINCT group_key FROM triage_rules WHERE created_by LIKE %s", (prefix_filter + "%",))
    out = []
    for (gk,) in cur.fetchall():
        group, causes, rules = triage.load_group_catalog(cur, gk)
        cur.execute("SELECT id::text FROM triage_rules WHERE group_key=%s AND created_by LIKE %s", (gk, prefix_filter + "%"))
        gold_ids = {r[0] for r in cur.fetchall()}
        from core import gitlab_instances as gi
        inst = gi.get_instance(group["instance"])
        pre = f"{inst.asset_prefix}{group['group_path'].strip('/')}"
        sql, params = triage._match("i.asset_name", pre)
        cur.execute("""SELECT i.asset_name, v.id::text, v.cve_id, v.scan_engine, v.url_path, v.severity, COALESCE(v.real_severity, v.severity),
                              v.risk_verdict
                       FROM vulnerability_log v JOIN infra_inventory i ON i.id=v.asset_id
                       WHERE """ + sql + """ AND v.finding_category IN ('VULNERABILITY','COMPLIANCE') AND v.status NOT IN %s""",
                    (*params, triage.CLOSED_STATUSES))
        for name, vid, rule, engine, up, sev_raw, sev_eff, verdict in cur.fetchall():
            file_, line = triage.parse_location(up)
            f = dict(asset_name=name, rule=rule or "", engine=engine or "", url_path=up or "", file=file_, line=line)
            r = triage.match_rule(f, rules)
            if not r or r["id"] not in gold_ids or r["root_cause_code"] not in causes:
                continue
            out.append(dict(group=gk, id=vid, rule=rule, cause=r["root_cause_code"], analyst=causes[r["root_cause_code"]]["classification"],
                            ai=verdict or "(sin veredicto)", sev_raw=sev_raw, sev_eff=sev_eff))
    return out


def summarize(rows):
    matrix = defaultdict(Counter)
    for r in rows:
        matrix[r["analyst"]][r["ai"]] += 1
    total = len(rows)
    vuln = matrix["Vulnerabilidad"]
    fp = matrix["Falso positivo"]
    n_vuln, n_fp = sum(vuln.values()), sum(fp.values())
    # "falsos descartes": analyst says it IS a vulnerability but the AI declared no real risk (the costly error)
    # "FP detectados": analyst says false positive and the AI also lowered/dismissed it
    return {
        "labelled_findings": total,
        "matrix": {a: dict(c) for a, c in matrix.items()},
        "false_dismissals": vuln["CONFIRMED_NO_RISK"],
        "false_dismissals_pct_of_vulnerabilities": round(100 * vuln["CONFIRMED_NO_RISK"] / n_vuln, 1) if n_vuln else None,
        "false_positives_recognised": fp["CONFIRMED_NO_RISK"] + fp["DOWNGRADED"],
        "false_positives_recognised_pct_of_fp": round(100 * (fp["CONFIRMED_NO_RISK"] + fp["DOWNGRADED"]) / n_fp, 1) if n_fp else None,
        "n_vulnerability": n_vuln, "n_false_positive": n_fp,
        "small_sample": total < SMALL_SAMPLE,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rules-created-by-prefix", default="seed:proyecto-a_Hallazgos")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    with db_manager.get_db_cursor() as cur:
        rows = labelled_findings(cur, a.rules_created_by_prefix)
        cur.execute("SELECT count(*) FILTER (WHERE review_status IN ('APPROVED','REJECTED')), count(*) FILTER (WHERE review_status='PENDING') "
                    "FROM finding_suppressions WHERE created_by='centinela-ai'")
        reviewed, pending = cur.fetchone()
        cur.execute("SELECT count(*) FROM vulnerability_log WHERE risk_verdict='ANALYST_OVERRIDDEN'")
        overridden = cur.fetchone()[0]
    res = summarize(rows)
    res.update(suppressions_reviewed_by_a_person=reviewed, suppressions_pending=pending, analyst_overridden=overridden)
    if a.json:
        print(json.dumps(res, indent=2, ensure_ascii=False))
        return
    print("Evaluación de veredictos de IA contra decisiones humanas (solo lectura)\n")
    print(f"Supresiones de IA revisadas por una persona: {reviewed}  (pendientes: {pending});  veredictos rechazados por el analista: {overridden}")
    print(f"Hallazgos etiquetados por el analista (reglas del Excel) con veredicto de IA comparable: {res['labelled_findings']}\n")
    print("Analista / IA".ljust(18) + "".join(f"{c:>20}" for c in VERDICT_COLS))
    for cls in ("Vulnerabilidad", "Falso positivo", "Calidad"):
        c = res["matrix"].get(cls, {})
        print(f"{cls:<18}" + "".join(f"{c.get(col, 0):>20}" for col in VERDICT_COLS))
    print(f"\nFalsos descartes (analista: vulnerabilidad / IA: sin riesgo): {res['false_dismissals']}"
          f"  ({res['false_dismissals_pct_of_vulnerabilities']}% de {res['n_vulnerability']})")
    print(f"Falsos positivos que la IA también bajó o descartó: {res['false_positives_recognised']}"
          f"  ({res['false_positives_recognised_pct_of_fp']}% de {res['n_false_positive']})")
    if res["small_sample"]:
        print(f"\n⚠ Muestra pequeña (<{SMALL_SAMPLE}): no se saca ninguna conclusión.")
    print("\nLímite: la etiqueta del analista es de CAUSA RAÍZ (regla), la de la IA es por ocurrencia; un desacuerdo es una pista, no una prueba.")


if __name__ == "__main__":
    main()
