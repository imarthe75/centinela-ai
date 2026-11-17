#!/usr/bin/env python3
"""
Human check of the adversarial AI verification (ADR-0021): is the second opinion right?

The verifier decides whether a severity reduction proposed by the first model stands. Nobody has yet compared those
decisions with a person's judgement, so its rejection rate (73 % on 2026-11-12) is a number without a reference. This
script closes that gap without any new screen:

  sample   picks N verifications (stratified by the verifier's decision, only ones where the verifier had the code in
           front of it) and writes an Excel workbook: what the scanner found, what the first model proposed and why, what
           the verifier decided and why, a link to the exact file and line in GitLab, and three columns for the reviewer.
  score    reads the workbook back (standard library only: an .xlsx is a zip of XML) and reports how often the person
           agrees with the verifier, per decision type. Read-only on findings: it records the labels in agent_actions
           (action_type 'ai_verification_human_review') so scripts/eval_ai_verdicts.py-style reports can reuse them.

    docker exec -i centinela-backend python3 scripts/ai_verification_review_sample.py sample --n 30 --out data/reports/validacion_ia/muestra.xlsx
    docker exec -i centinela-backend python3 scripts/ai_verification_review_sample.py score --in data/reports/validacion_ia/muestra.xlsx

30 cases give a rough reading (each case moves the agreement rate by ~3 points); the report says so.
"""
import argparse
import os
import random
import re
import sys
import zipfile
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from datetime import date

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import agent_ledger, db_manager, gitlab_instances  # noqa: E402

STRATA = (("rechaza_baja", 0.4), ("sostiene_baja", 0.4), ("inconcluso", 0.2))
OUTCOME_LABEL = {"rechaza_baja": "Rechaza la baja (el riesgo es real)",
                 "sostiene_baja": "Sostiene la baja (el riesgo es menor)",
                 "inconcluso": "No pudo decidir"}
HUMAN_CHOICES = ["La baja es correcta (riesgo menor)", "La baja es incorrecta (el riesgo es real)", "No se puede saber"]
SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
ACTION = "ai_verification_human_review"


def _first_ai_text(business_impact: str) -> str:
    """The first model's explanation: business_impact minus the '[Verificación IA: ...]' lines the verifier prepended."""
    lines = (business_impact or "").split("\n")
    while lines and lines[0].startswith("[Verificación IA:"):
        lines.pop(0)
    return "\n".join(lines).strip()[:1800]


def gitlab_link(asset_name: str, url_path: str) -> str:
    inst, path, branch = gitlab_instances.parse_asset_name(asset_name or "")
    m = re.match(r"^(.+?):(\d+)", url_path or "")
    if not inst or not path or not m:
        return ""
    return f"{inst.url}/{path}/-/blob/{branch or 'HEAD'}/{m.group(1)}#L{m.group(2)}"


def candidates(cur):
    """Latest verification per finding, only those decided WITH evidence available (repo: verifier cited lines that exist)."""
    cur.execute("""
        SELECT a.entity_id, a.detail, v.cve_id, v.severity, v.description, v.url_path,
               v.business_impact, v.status, i.asset_name, i.asset_type
        FROM agent_actions a
        JOIN vulnerability_log v ON v.id::text = a.entity_id
        JOIN infra_inventory i ON i.id = v.asset_id
        WHERE a.action_type = 'ai_downgrade_verification'
        ORDER BY a.created_at DESC""")
    out, seen = [], set()
    for eid, d, cve, sev, desc, url_path, bi, status, asset, atype in cur.fetchall():   # newest first: keep the newest WITH evidence
        if eid in seen:
            continue
        d = d or {}
        is_repo = str(atype).upper() == "GITLAB-REPO"
        valid = (d.get("refuter_refs") or {}).get("valid") or []
        if is_repo and not valid:
            continue                       # decided without the code: not a fair test of the verifier
        if d.get("refuter_outcome") not in dict(STRATA):
            continue
        seen.add(eid)
        out.append({"id": eid, "outcome": d["refuter_outcome"], "proposed_level": d.get("proposed_level") or "",
                    "proposed_verdict": d.get("proposed_verdict") or "", "reason": d.get("refuter_reason") or "",
                    "refs": ", ".join(valid[:6]), "cve_id": cve, "severity": sev, "description": (desc or "")[:900],
                    "url_path": url_path or "", "first_ai": _first_ai_text(bi), "asset": asset, "status": status,
                    "link": gitlab_link(asset, url_path) if is_repo else ""})
    return out


def pick(rows, n, seed):
    rng = random.Random(seed)
    by = defaultdict(list)
    for r in rows:
        by[r["outcome"]].append(r)
    chosen = []
    for outcome, share in STRATA:
        pool = by[outcome]
        rng.shuffle(pool)
        # at most 2 per rule so one noisy rule cannot dominate the sample
        per_rule = Counter()
        for r in pool:
            if len([c for c in chosen if c["outcome"] == outcome]) >= round(n * share):
                break
            if per_rule[r["cve_id"]] < 2:
                per_rule[r["cve_id"]] += 1
                chosen.append(r)
    # a decision type with too few cases leaves room: fill it from the rest, same 2-per-rule cap
    rest = [r for r in rows if r not in chosen]
    rng.shuffle(rest)
    per_rule = Counter(c["cve_id"] for c in chosen)
    for r in rest:
        if len(chosen) >= n:
            break
        if per_rule[r["cve_id"]] < 2:
            per_rule[r["cve_id"]] += 1
            chosen.append(r)
    rng.shuffle(chosen)
    return chosen


def write_workbook(rows, out_path):
    import xlsxwriter
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    wb = xlsxwriter.Workbook(out_path)
    wrap = wb.add_format({"text_wrap": True, "valign": "top"})
    head = wb.add_format({"bold": True, "bg_color": "#1F3A5F", "font_color": "#FFFFFF", "text_wrap": True, "valign": "top"})
    human = wb.add_format({"bg_color": "#FFF7D6", "text_wrap": True, "valign": "top", "border": 1})
    link = wb.add_format({"font_color": "#1155CC", "underline": 1, "valign": "top"})

    info = wb.add_worksheet("Instrucciones")
    info.set_column(0, 0, 110, wrap)
    for i, line in enumerate([
        "Validación de la segunda opinión de IA (ADR-0021)",
        "",
        "Cada fila es un hallazgo al que una IA le propuso BAJAR la severidad, y una segunda IA (el verificador) decidió si esa baja procede.",
        "Su tarea: con el código a la vista (columna «Ver en GitLab»), decidir usted si la baja es correcta. No necesita ver lo que decidió el",
        "verificador para opinar; si prefiere juzgar a ciegas, oculte las columnas «Decisión del verificador» y «Razón del verificador».",
        "",
        "Llene solo las tres columnas amarillas: su veredicto, la severidad que usted pondría y un comentario opcional.",
        "No cambie la columna «id» ni el orden de las columnas. Al terminar, guarde el archivo y entréguelo para el cálculo",
        "(scripts/ai_verification_review_sample.py score).",
        "",
        f"Muestra de {len(rows)} casos, generada el {date.today().isoformat()}, estratificada por la decisión del verificador",
        "(40 % rechaza, 40 % sostiene, 20 % no pudo decidir) y solo con casos donde el verificador tuvo el código disponible.",
        "Con 30 casos el resultado es orientativo: cada caso mueve el porcentaje de acuerdo unos 3 puntos.",
    ]):
        info.write(i, 0, line)

    ws = wb.add_worksheet("Revisión")
    cols = [("id", 10), ("Activo", 30), ("Regla", 28), ("Archivo:línea", 28), ("Ver en GitLab", 14),
            ("Severidad de la herramienta", 12), ("Qué detectó la herramienta", 45), ("Severidad propuesta por la 1.ª IA", 12),
            ("Por qué la 1.ª IA propone bajarla", 60), ("Decisión del verificador", 22), ("Razón del verificador", 60),
            ("Líneas que citó el verificador", 26), ("SU VEREDICTO", 26), ("Severidad que usted pondría", 14), ("Comentario", 40)]
    for c, (name, width) in enumerate(cols):
        ws.write(0, c, name, head)
        ws.set_column(c, c, width, wrap)
    ws.set_column(0, 0, 10, wrap, {"hidden": False})
    for r, row in enumerate(rows, start=1):
        vals = [row["id"], row["asset"], row["cve_id"], row["url_path"], None, row["severity"], row["description"],
                row["proposed_level"] or row["proposed_verdict"], row["first_ai"], OUTCOME_LABEL[row["outcome"]],
                row["reason"], row["refs"]]
        for c, v in enumerate(vals):
            if c == 4:
                if row["link"]:
                    ws.write_url(r, c, row["link"], link, "abrir")
                else:
                    ws.write(r, c, "(activo de infraestructura)", wrap)
            else:
                ws.write(r, c, v, wrap)
        ws.write_blank(r, 12, None, human)
        ws.write_blank(r, 13, None, human)
        ws.write_blank(r, 14, None, human)
        ws.set_row(r, 150)
    n = len(rows)
    ws.data_validation(1, 12, n, 12, {"validate": "list", "source": HUMAN_CHOICES})
    ws.data_validation(1, 13, n, 13, {"validate": "list", "source": SEVERITIES})
    ws.freeze_panes(1, 3)
    ws.autofilter(0, 0, n, len(cols) - 1)
    wb.close()


# ------------------------------------------------------------------------------------------------ reading .xlsx (stdlib)

_NS = {"m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}


def _col_index(ref: str) -> int:
    letters = re.match(r"[A-Z]+", ref).group(0)
    n = 0
    for ch in letters:
        n = n * 26 + (ord(ch) - 64)
    return n - 1


def read_review_sheet(path):
    """Rows of the 'Revisión' sheet as lists of strings (shared and inline strings resolved)."""
    with zipfile.ZipFile(path) as z:
        shared = []
        if "xl/sharedStrings.xml" in z.namelist():
            for si in ET.fromstring(z.read("xl/sharedStrings.xml")).findall("m:si", _NS):
                shared.append("".join(t.text or "" for t in si.iter(f"{{{_NS['m']}}}t")))
        wbx = ET.fromstring(z.read("xl/workbook.xml"))
        rels = ET.fromstring(z.read("xl/_rels/workbook.xml.rels"))
        rid = next(s.get("{http://schemas.openxmlformats.org/officeDocument/2006/relationships}id")
                   for s in wbx.find("m:sheets", _NS) if s.get("name") == "Revisión")
        target = next(r.get("Target") for r in rels if r.get("Id") == rid)
        sheet = ET.fromstring(z.read("xl/" + target.lstrip("/").replace("xl/", "", 1)))
    rows = []
    for row in sheet.find("m:sheetData", _NS):
        vals = {}
        for c in row:
            v = c.find("m:v", _NS)
            t = c.get("t")
            if t == "s" and v is not None:
                text = shared[int(v.text)]
            elif t == "inlineStr":
                text = "".join(x.text or "" for x in c.iter(f"{{{_NS['m']}}}t"))
            else:
                text = v.text if v is not None else ""
            vals[_col_index(c.get("r"))] = (text or "").strip()
        rows.append([vals.get(i, "") for i in range(max(vals) + 1 if vals else 0)])
    return rows


def score(path, reviewer):
    rows = read_review_sheet(path)
    header, data = rows[0], rows[1:]
    i_id, i_dec, i_human, i_sev, i_note = (header.index("id"), header.index("Decisión del verificador"),
                                           header.index("SU VEREDICTO"), header.index("Severidad que usted pondría"),
                                           header.index("Comentario"))
    label_to_outcome = {v: k for k, v in OUTCOME_LABEL.items()}
    per = defaultdict(Counter)
    labels = []
    for r in data:
        r = r + [""] * (len(header) - len(r))
        human = r[i_human]
        if not human:
            continue
        outcome = label_to_outcome.get(r[i_dec], r[i_dec])
        agrees = ((outcome == "sostiene_baja" and human == HUMAN_CHOICES[0]) or
                  (outcome == "rechaza_baja" and human == HUMAN_CHOICES[1]))
        bucket = "no_se_puede_saber" if human == HUMAN_CHOICES[2] else ("de_acuerdo" if agrees else "en_desacuerdo")
        if outcome == "inconcluso" and human != HUMAN_CHOICES[2]:
            bucket = "humano_si_pudo_decidir"
        per[outcome][bucket] += 1
        labels.append({"id": r[i_id], "verifier": outcome, "human": human, "human_severity": r[i_sev], "note": r[i_note][:300]})
    total_dec = sum(per[o]["de_acuerdo"] + per[o]["en_desacuerdo"] for o in ("rechaza_baja", "sostiene_baja"))
    agree = sum(per[o]["de_acuerdo"] for o in ("rechaza_baja", "sostiene_baja"))
    print(f"Casos con veredicto humano: {len(labels)} de {len(data)}")
    for o in ("rechaza_baja", "sostiene_baja", "inconcluso"):
        print(f"  {OUTCOME_LABEL[o]:42s} {dict(per[o])}")
    if total_dec:
        print(f"Acuerdo humano-verificador (casos donde ambos decidieron): {agree}/{total_dec} = {100 * agree / total_dec:.0f} %")
    if len(labels) < 30:
        print("Aviso: menos de 30 casos; el porcentaje es solo orientativo.")
    agent_ledger.record_action(ACTION, f"Revisión humana de la verificación IA: {agree}/{total_dec} de acuerdo",
                               actor=reviewer or "human", detail={"file": os.path.basename(path), "per_outcome":
                                                                    {k: dict(v) for k, v in per.items()}, "labels": labels},
                               outcome="success")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("sample")
    s.add_argument("--n", type=int, default=30)
    s.add_argument("--seed", type=int, default=20261113)
    s.add_argument("--out", required=True)
    sc = sub.add_parser("score")
    sc.add_argument("--in", dest="inp", required=True)
    sc.add_argument("--reviewer", default="")
    a = ap.parse_args()
    if a.cmd == "sample":
        with db_manager.get_db_cursor() as cur:
            rows = candidates(cur)
        print(f"Verificaciones con evidencia disponibles: {len(rows)} ({dict(Counter(r['outcome'] for r in rows))})")
        chosen = pick(rows, a.n, a.seed)
        write_workbook(chosen, a.out)
        print(f"Muestra de {len(chosen)} casos escrita en {a.out} ({dict(Counter(r['outcome'] for r in chosen))})")
    else:
        score(a.inp, a.reviewer)


if __name__ == "__main__":
    main()
