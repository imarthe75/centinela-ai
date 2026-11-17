"""
Applies ADR-0021 to severity reductions the AI made BEFORE verification existed (one model's word, no second opinion).

Two independent steps; nothing is written without the flag that names it:

  --apply-guard     Deterministic, no AI call. Open findings with risk_verdict=CONFIRMED_NO_RISK whose subject is
                    security-sensitive (core.ai_verification.is_safety_protected) go back to the scanner's severity
                    and become NO_RISK_PENDING_REVIEW: the existing suppression proposal stays, and a human approves or
                    rejects it in "Supresiones IA". SLA recomputed from the raw severity.
  --reverify N      Up to N remaining DOWNGRADED / CONFIRMED_NO_RISK findings get the adversarial second opinion
                    (core.ai_verification.verify_downgrade) through the provider cascade; the result is stored exactly
                    as the correlation loop now stores it. Costs one provider call per finding (free-tier quota).
                    Run inside centinela-ai (the GitLab clones the verifier reads live there).

Without flags: dry run, prints what each step would touch.

    docker exec -i centinela-ai python3 scripts/reverify_ai_downgrades.py
    docker exec -i centinela-ai python3 scripts/reverify_ai_downgrades.py --apply-guard
    docker exec -i centinela-ai python3 scripts/reverify_ai_downgrades.py --reverify 50 [--asset-like 'GitLab/proyecto-g/%']
"""
import argparse
import os
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import agent_ledger, ai_verification, db_manager, deduplication_engine  # noqa: E402

OPEN = ("RESOLVED", "SUPPRESSED")


def _rows(cur, verdicts, asset_like, limit=None, exclude_verified=False):
    cur.execute(f"""
        SELECT v.id, v.cve_id, v.severity, v.description, v.scan_engine, v.url_path, v.detected_at, v.business_impact,
               v.developer_steps, v.real_severity, v.risk_verdict, v.asset_id, i.asset_name, i.asset_type, i.endpoint,
               i.criticality, i.agent_id
        FROM vulnerability_log v JOIN infra_inventory i ON i.id = v.asset_id
        WHERE v.risk_verdict = ANY(%s) AND v.status NOT IN %s AND i.asset_name LIKE %s
          {'''AND NOT EXISTS (SELECT 1 FROM agent_actions a           -- verified once = done: an upheld downgrade keeps its
                          WHERE a.action_type = 'ai_downgrade_verification'   -- DOWNGRADED verdict and must not come back every run
                            AND a.entity_id = v.id::text)''' if exclude_verified else ''}
        ORDER BY v.detected_at DESC {'LIMIT %s' if limit else ''}
    """, (list(verdicts), OPEN, asset_like) + ((limit,) if limit else ()))
    cols = [d[0] for d in cur.description]
    return [dict(zip(cols, r)) for r in cur.fetchall()]


def guard_step(apply: bool, asset_like: str) -> int:
    with db_manager.get_db_cursor() as cur:
        rows = [r for r in _rows(cur, ["CONFIRMED_NO_RISK"], asset_like)
                if ai_verification.is_safety_protected(r["cve_id"], r["description"], r["scan_engine"])]
        print(f"[guard] {len(rows)} hallazgos de seguridad marcados 'sin riesgo' por una sola IA -> NO_RISK_PENDING_REVIEW")
        for rule, n in Counter(r["cve_id"] for r in rows).most_common(12):
            print(f"         {n:5d}  {rule}")
        if not apply or not rows:
            return len(rows)
        note = ("[Verificación IA: hallazgo de categoría de seguridad que una sola IA marcó sin riesgo; vuelve a la severidad de la "
                "herramienta hasta que un analista apruebe o rechace la propuesta en «Supresiones IA».]\n")
        for r in rows:
            due = r["detected_at"] + deduplication_engine.get_sla_delta(r["severity"]) if r["detected_at"] else None
            cur.execute("""UPDATE vulnerability_log SET real_severity = NULL, risk_verdict = %s, business_impact = %s,
                                  sla_due_date = COALESCE(%s, sla_due_date) WHERE id = %s""",
                        (ai_verification.NO_RISK_PENDING_REVIEW, note + str(r["business_impact"] or ""), due, r["id"]))
    agent_ledger.record_action(agent_ledger.ACTION_AI_VERIFICATION,
                               f"Guarda de seguridad aplicada a {len(rows)} veredictos 'sin riesgo' previos a la verificación",
                               entity_type="batch", detail={"step": "guard", "rows": len(rows), "asset_like": asset_like},
                               actor="script:reverify_ai_downgrades", outcome="success")
    print(f"[guard] aplicado a {len(rows)} filas")
    return len(rows)


def reverify_step(limit: int, asset_like: str, engine=None) -> Counter:
    """`engine` = the module that provides call_ai_cascade / cascade_all_unavailable / _infra_exposure_context. Inside the running
    centinela-ai service it is that process's own module (importing `centinela` again there would start a second copy of it)."""
    if engine is None:
        import centinela as engine
    from core import code_context, repo_facts
    with db_manager.get_db_cursor() as cur:
        rows = _rows(cur, ai_verification.REDUCING_VERDICTS, asset_like, limit, exclude_verified=True)
    print(f"[reverify] {len(rows)} hallazgos a verificar")
    outcomes = Counter()
    for r in rows:
        is_repo = str(r["asset_type"]).upper() == "GITLAB-REPO"
        ctx = code_context.gather_repo_context(r["asset_name"], r["url_path"] or "") if is_repo else {}
        if is_repo and not ctx.get("repo_dir"):
            # No clone on disk (e.g. right after the container was recreated): a verdict here would be reasoned from the description
            # alone. Measured 2026-11-12: 91 such blind runs overturned 52 code-backed decisions. Leave it pending for a run with code.
            outcomes["sin_codigo"] += 1
            continue
        facts = repo_facts.load_repo_facts(r["asset_name"], ctx.get("repo_dir"))["text"] if is_repo else ""
        result = ai_verification.verify_downgrade(
            vuln=r, proposed={"real_severity": r["real_severity"], "risk_verdict": r["risk_verdict"]},
            analysis={"evidence_refs": [], "business_impact": r["business_impact"], "developer_steps": r["developer_steps"]},
            ask=lambda p: engine.call_ai_cascade(p, want_json=True), repo_dir=ctx.get("repo_dir"),
            code_block=ctx.get("enclosing_snippet", ""), callers=ctx.get("callers", []),
            exposure_block="" if is_repo else engine._infra_exposure_context(r), repo_facts=facts)
        outcomes[result["outcome"]] += 1
        if result["outcome"] == "sin_verificador" and engine.cascade_all_unavailable():
            print("[reverify] sin proveedores disponibles: se detiene (lo pendiente se reintenta en otra corrida)")
            break
        final = result["risk_verdict"]
        level = result["real_severity"]
        sev_for_sla = level or r["severity"]
        due = r["detected_at"] + deduplication_engine.get_sla_delta(sev_for_sla) if r["detected_at"] else None
        with db_manager.get_db_cursor() as cur:
            cur.execute("""UPDATE vulnerability_log SET real_severity = %s, risk_verdict = %s, business_impact = %s,
                                  sla_due_date = COALESCE(%s, sla_due_date) WHERE id = %s""",
                        (level, final, f"[Verificación IA: {result['note']}]\n{r['business_impact'] or ''}", due, r["id"]))
        agent_ledger.record_action(agent_ledger.ACTION_AI_VERIFICATION,
                                   f"Re-verificación de {r['cve_id']} en {r['asset_name']}: {result['outcome']}",
                                   entity_type="vulnerability", entity_id=r["id"], asset_id=r["asset_id"],
                                   detail={**result.get("detail", {}), "final_verdict": final, "backfill": True},
                                   actor="script:reverify_ai_downgrades",
                                   outcome="success" if result["outcome"] == "sostiene_baja" else "skipped")
        print(f"   {r['cve_id']:40s} {r['asset_name'][:50]:50s} {r['risk_verdict']:18s} -> {result['outcome']} ({final})")
    print(f"[reverify] resultados: {dict(outcomes)}")
    return outcomes


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--apply-guard", action="store_true")
    ap.add_argument("--reverify", type=int, default=0)
    ap.add_argument("--asset-like", default="%")
    a = ap.parse_args()
    guard_step(a.apply_guard, a.asset_like)
    with db_manager.get_db_cursor() as cur:
        pending = _rows(cur, ai_verification.REDUCING_VERDICTS, a.asset_like, exclude_verified=True)
    print(f"[reverify] pendientes de segunda opinión: {len(pending)} "
          f"({dict(Counter(r['risk_verdict'] for r in pending))})")
    if a.reverify:
        reverify_step(a.reverify, a.asset_like)


if __name__ == "__main__":
    main()
    sys.stdout.flush()
    os._exit(0)   # importing centinela starts provider clients; a hard-deadline thread must not hold the exit (see CLAUDE.md)
