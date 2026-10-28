"""Builds the group triage workbook (.xlsx) from core.triage.build_report_data().

Same shape as the analyst's hand-made workbook (Resumen / Plan de trabajo / Vulnerabilidades / Falsos positivos / Calidad / Versiones desactualizadas
/ Detalle / Criterios) plus a Cobertura sheet. Every count is an Excel FORMULA over Detalle, so reclassifying a row (Detalle column M, a dropdown)
updates the whole book; the cached value of each formula is also written so previewers that do not recalculate show the right numbers.
"""
import io
import re
from collections import Counter, defaultdict
from typing import Any, Dict, List

import xlsxwriter
from xlsxwriter.utility import xl_rowcol_to_cell

from core.triage import CLASSES, CRIT_ORDER, SEV_TO_CRIT, UNCLASSIFIED, class_of_code

SLACK = 30  # blank catalog rows included in lookup ranges so the analyst can append a root cause
SEVS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]  # INFO = Centinela concluded there is no real risk (see "sin riesgo real")
CRITS = ["Crítico", "Alto", "Medio", "Bajo"]
PHASES = ["1 · Inmediato", "2 · Corto plazo", "3 · Mediano plazo", "4 · Mejora continua"]


class _W:
    """Tiny helper: formulas always carry their computed value."""

    def __init__(self, ws):
        self.ws = ws

    def f(self, cell, formula, fmt, value):
        self.ws.write_formula(cell, "=" + formula.lstrip("="), fmt, value)


def build_workbook(data: Dict[str, Any]) -> bytes:
    group, causes, findings = data["group"], data["causes"], data["findings"]
    plan, coverage, inst = data["plan"], data["coverage"], data["instance"]
    title = group["title"]
    n = len(findings)
    last = n + 1  # last Detalle row (1-based)

    buf = io.BytesIO()
    wb = xlsxwriter.Workbook(buf, {"in_memory": True})
    wb.set_calc_mode("auto")
    fm = dict(
        title=wb.add_format({"bold": True, "font_size": 15, "font_color": "#1F3A5F"}),
        h2=wb.add_format({"bold": True, "font_size": 12, "font_color": "#1F3A5F"}),
        note=wb.add_format({"italic": True, "font_color": "#555555", "text_wrap": True, "valign": "top"}),
        head=wb.add_format({"bold": True, "font_color": "#FFFFFF", "bg_color": "#1F3A5F", "text_wrap": True, "valign": "vcenter", "border": 1,
                            "border_color": "#C9D2DD"}),
        cell=wb.add_format({"text_wrap": True, "valign": "top", "border": 1, "border_color": "#C9D2DD"}),
        int=wb.add_format({"valign": "top", "border": 1, "border_color": "#C9D2DD", "num_format": "#,##0"}),
        num=wb.add_format({"valign": "top", "border": 1, "border_color": "#C9D2DD", "num_format": "#,##0.0"}),
        pct=wb.add_format({"valign": "top", "border": 1, "border_color": "#C9D2DD", "num_format": "0.0%"}),
        pct0=wb.add_format({"valign": "top", "border": 1, "border_color": "#C9D2DD", "num_format": "0%"}),
        edit=wb.add_format({"text_wrap": True, "valign": "top", "border": 1, "border_color": "#C9D2DD", "bg_color": "#FFF2CC"}),
        editnum=wb.add_format({"valign": "top", "border": 1, "border_color": "#C9D2DD", "bg_color": "#FFF2CC", "num_format": "#,##0.0"}),
        editpct=wb.add_format({"valign": "top", "border": 1, "border_color": "#C9D2DD", "bg_color": "#FFF2CC", "num_format": "0%"}),
        tot=wb.add_format({"bold": True, "top": 2, "valign": "top", "num_format": "#,##0.0"}),
        totl=wb.add_format({"bold": True, "top": 2}),
        warn=wb.add_format({"text_wrap": True, "valign": "top", "border": 1, "border_color": "#C9D2DD", "bg_color": "#FCE4D6"}),
    )

    by_class: Dict[str, List[str]] = {c: [] for c in CLASSES}
    for code, c in sorted(causes.items()):
        by_class[class_of_code(code) if class_of_code(code) in by_class else c["classification"]].append(code)
    cnt_all = Counter(f["cause"] for f in findings)
    cnt_uniq = Counter(f["cause"] for f in findings if not f["duplicate_of"])

    def rng(col):  # Detalle column range
        return f"Detalle!${col}$2:${col}${last}"

    def cat_rng(sheet, col, count):
        return f"{sheet}!${col}$5:${col}${5 + count + SLACK}"

    q = {"Vulnerabilidades": ("Vulnerabilidades", len(by_class["Vulnerabilidad"])),
         "Falsos positivos": ("'Falsos positivos'", len(by_class["Falso positivo"])),
         "Calidad": ("Calidad", len(by_class["Calidad"]))}

    # sheet creation order = tab order
    ws_res = wb.add_worksheet("Resumen")
    ws_cov = wb.add_worksheet("Cobertura")
    ws_plan = wb.add_worksheet("Plan de trabajo")
    ws_v = wb.add_worksheet("Vulnerabilidades")
    ws_fp = wb.add_worksheet("Falsos positivos")
    ws_c = wb.add_worksheet("Calidad")
    ws_old = wb.add_worksheet("Versiones desactualizadas")
    ws_det = wb.add_worksheet("Detalle")
    ws_lists = wb.add_worksheet("Listas")
    ws_crit = wb.add_worksheet("Criterios")
    ws_lists.hide()

    # ------------------------------------------------------------------ Listas (dropdown source)
    all_codes = by_class["Vulnerabilidad"] + by_class["Falso positivo"] + by_class["Calidad"]
    for i, code in enumerate(all_codes):
        ws_lists.write(i, 0, code)
    ws_lists.write(len(all_codes), 0, UNCLASSIFIED)

    # ------------------------------------------------------------------ Detalle
    heads = ["ID ocurrencia", "Repositorio", "Motor", "Regla", "Severidad Centinela", "Severidad de la herramienta",
             'Centinela: "sin riesgo real"', "Archivo", "Línea", "Descripción (Centinela)", "Clasificación", "Tipo / familia", "Causa raíz",
             "Nota del análisis", "Duplicado de", "Versión desactualizada", "Esfuerzo Centinela (min, sin duplicar)"]
    for c, h in enumerate(heads):
        ws_det.write(0, c, h, fm["head"])
    cause_type = {code: (c.get("kind") or "") for code, c in causes.items()}
    wd = _W(ws_det)
    for i, f in enumerate(findings):
        r = i + 2
        ws_det.write(f"A{r}", f["occ_id"], fm["cell"])
        ws_det.write(f"B{r}", f["repo"], fm["cell"])
        ws_det.write(f"C{r}", f["engine"], fm["cell"])
        ws_det.write(f"D{r}", f["rule"][:120], fm["cell"])
        ws_det.write(f"E{r}", f["severity_eff"], fm["cell"])
        ws_det.write(f"F{r}", f["severity_raw"], fm["cell"])
        ws_det.write(f"G{r}", "Sí" if f["no_risk"] else "No", fm["cell"])
        ws_det.write(f"H{r}", f["file"], fm["cell"])
        if f["line"] is not None:
            ws_det.write_number(f"I{r}", f["line"], fm["cell"])
        else:
            ws_det.write(f"I{r}", "", fm["cell"])
        ws_det.write(f"J{r}", f["title"], fm["cell"])
        wd.f(f"K{r}", f'IF(LEFT(M{r},2)="V-","Vulnerabilidad",IF(LEFT(M{r},3)="FP-","Falso positivo",IF(LEFT(M{r},2)="C-","Calidad","Sin clasificar")))',
             fm["cell"], f["classification"])
        look = "IFERROR(INDEX({v}!$C$5:$C${ve},MATCH(M{r},{v}!$A$5:$A${ve},0)),IFERROR(INDEX({p}!$C$5:$C${pe},MATCH(M{r},{p}!$A$5:$A${pe},0)),IFERROR(INDEX({c}!$C$5:$C${ce},MATCH(M{r},{c}!$A$5:$A${ce},0)),\"\")))".format(
            v="Vulnerabilidades", ve=5 + q["Vulnerabilidades"][1] + SLACK, p="'Falsos positivos'", pe=5 + q["Falsos positivos"][1] + SLACK,
            c="Calidad", ce=5 + q["Calidad"][1] + SLACK, r=r)
        wd.f(f"L{r}", look, fm["cell"], cause_type.get(f["cause"], ""))
        ws_det.write(f"M{r}", f["cause"], fm["edit"])
        ws_det.write(f"N{r}", f.get("note") or "", fm["cell"])
        ws_det.write(f"O{r}", f["duplicate_of"], fm["cell"])
        ws_det.write(f"P{r}", "Sí" if f["outdated"] else "No", fm["cell"])
        eff = 0 if f["duplicate_of"] else (f["effort_min"] or 0)
        ws_det.write_number(f"Q{r}", eff, fm["cell"])
    ws_det.data_validation(1, 12, max(last - 1, 1), 12, {"validate": "list", "source": f"=Listas!$A$1:$A${len(all_codes) + 1}"})
    ws_det.freeze_panes(1, 2)
    ws_det.autofilter(0, 0, max(last - 1, 0), len(heads) - 1)
    for col, w in zip("ABCDEFGHIJKLMNOPQ", [11, 26, 16, 34, 12, 12, 12, 44, 7, 60, 15, 28, 11, 40, 12, 12, 14]):
        ws_det.set_column(f"{col}:{col}", w)

    # ------------------------------------------------------------------ catalogs
    def repos_of(code):
        return ", ".join(sorted({f["repo"] for f in findings if f["cause"] == code}))

    def rules_of(code):
        rs = []
        for f in findings:
            if f["cause"] == code:
                name = f["rule"] if not f["engine"] == "semgrep" else "semgrep " + f["rule"].split(".")[-1][:40]
                if name not in rs:
                    rs.append(name)
        return ", ".join(rs[:6]) + (" …" if len(rs) > 6 else "")

    plan_rows_n = len(plan)
    plan_end = 6 + plan_rows_n + 19

    def cnt_formulas(w, rowcell_col_all, rowcell_col_uniq, r, code):
        w.f(f"{rowcell_col_all}{r}", f"COUNTIF({rng('M')},A{r})", fm["int"], cnt_all[code])
        w.f(f"{rowcell_col_uniq}{r}", f'COUNTIFS({rng("M")},A{r},{rng("O")},"")', fm["int"], cnt_uniq[code])

    # Vulnerabilidades
    ws_v.write("A1", "Vulnerabilidades que sí aplican: base de la estrategia de corrección", fm["title"])
    ws_v.write("A2", 'Severidad con la matriz estándar ART-SOP-02 (crítico · alto · medio · bajo), leída como "si llegara a producción tal como está". '
                     "Columnas amarillas: las llena el responsable.", fm["note"])
    vh = ["ID", "Causa raíz", "Familia 0B-2", "Severidad propuesta (ART-SOP-02)", "Certeza", "Ocurrencias reportadas", "Ocurrencias únicas", "Repositorios",
          "Reglas de Centinela", "Prueba que la confirma", "Estrategia de corrección", "Responsable propuesto", "Versión desactualizada",
          "Decisión (Dirección de Tecnología)", "Fecha compromiso (del plan)", "Estado (del plan)", "Evidencia de cierre"]
    for c, h in enumerate(vh):
        ws_v.write(3, c, h, fm["head"])
    wv = _W(ws_v)
    plan_by_code = {p["code"]: p for p in plan}
    for i, code in enumerate(by_class["Vulnerabilidad"]):
        r, c = 5 + i, causes[code]
        ws_v.write(f"A{r}", code, fm["cell"]); ws_v.write(f"B{r}", c["title"], fm["cell"]); ws_v.write(f"C{r}", c.get("kind") or "", fm["cell"])
        ws_v.write(f"D{r}", c.get("severity") or "", fm["cell"]); ws_v.write(f"E{r}", c.get("certainty") or "", fm["cell"])
        cnt_formulas(wv, "F", "G", r, code)
        ws_v.write(f"H{r}", repos_of(code), fm["cell"]); ws_v.write(f"I{r}", rules_of(code), fm["cell"])
        ws_v.write(f"J{r}", c.get("how_to_confirm") or "", fm["cell"]); ws_v.write(f"K{r}", c.get("strategy") or "", fm["cell"])
        ws_v.write(f"L{r}", c.get("owner") or "", fm["cell"]); ws_v.write(f"M{r}", "Sí" if c.get("outdated") else "No", fm["cell"])
        ws_v.write(f"N{r}", "", fm["edit"])
        wv.f(f"O{r}", f"IFERROR(IF(INDEX('Plan de trabajo'!$Y$6:$Y${plan_end},MATCH(A{r},'Plan de trabajo'!$B$6:$B${plan_end},0))=\"\",\"\",INDEX('Plan de trabajo'!$Y$6:$Y${plan_end},MATCH(A{r},'Plan de trabajo'!$B$6:$B${plan_end},0))),\"\")", fm["cell"], "")
        wv.f(f"P{r}", f"IFERROR(IF(INDEX('Plan de trabajo'!$Z$6:$Z${plan_end},MATCH(A{r},'Plan de trabajo'!$B$6:$B${plan_end},0))=\"\",\"Pendiente\",INDEX('Plan de trabajo'!$Z$6:$Z${plan_end},MATCH(A{r},'Plan de trabajo'!$B$6:$B${plan_end},0))),\"\")", fm["cell"], "Pendiente" if code in plan_by_code else "")
        ws_v.write(f"Q{r}", "", fm["edit"])
    for col, w in zip("ABCDEFGHIJKLMNOPQ", [8, 44, 22, 14, 22, 11, 11, 28, 30, 44, 56, 34, 12, 22, 14, 12, 28]):
        ws_v.set_column(f"{col}:{col}", w)
    ws_v.freeze_panes(4, 2)

    # Falsos positivos
    ws_fp.write("A1", "Falsos positivos y hallazgos que no aplican", fm["title"])
    ws_fp.write("A2", 'Cada renglón dice por qué no es vulnerabilidad y qué tendría que pasar para reclasificarlo. "Requiere prueba" = el fundamento es '
                      "sólido, pero hay que confirmarlo antes de cerrarlo.", fm["note"])
    fh = ["ID", "Motivo", "Tipo", "Certeza", "Ocurrencias reportadas", "Ocurrencias únicas", "Repositorios", "Reglas de Centinela", "Fundamento",
          "Cómo confirmarlo o cuándo reclasificar", "Versión desactualizada", "Validó (nombre y fecha)"]
    for c, h in enumerate(fh):
        ws_fp.write(3, c, h, fm["head"])
    wf = _W(ws_fp)
    for i, code in enumerate(by_class["Falso positivo"]):
        r, c = 5 + i, causes[code]
        ws_fp.write(f"A{r}", code, fm["cell"]); ws_fp.write(f"B{r}", c["title"], fm["cell"]); ws_fp.write(f"C{r}", c.get("kind") or "", fm["cell"])
        ws_fp.write(f"D{r}", c.get("certainty") or "", fm["cell"])
        cnt_formulas(wf, "E", "F", r, code)
        ws_fp.write(f"G{r}", repos_of(code), fm["cell"]); ws_fp.write(f"H{r}", rules_of(code), fm["cell"])
        ws_fp.write(f"I{r}", c.get("rationale") or "", fm["cell"]); ws_fp.write(f"J{r}", c.get("how_to_confirm") or "", fm["cell"])
        ws_fp.write(f"K{r}", "Sí" if c.get("outdated") else "No", fm["cell"]); ws_fp.write(f"L{r}", "", fm["edit"])
    for col, w in zip("ABCDEFGHIJKL", [8, 44, 22, 22, 11, 11, 28, 30, 56, 48, 12, 24]):
        ws_fp.set_column(f"{col}:{col}", w)
    ws_fp.freeze_panes(4, 2)

    # Calidad
    ws_c.write("A1", "Calidad y mejora: endurecimiento, accesibilidad, calidad de código y cumplimiento", fm["title"])
    ws_c.write("A2", "No abren por sí solos una vía de ataque. Van al backlog de mejora; la accesibilidad es requisito legal para el sector público "
                     "(0B-2), así que no es opcional aunque no sea seguridad.", fm["note"])
    ch = ["ID", "Tema", "Tipo", "Ocurrencias reportadas", "Ocurrencias únicas", "Repositorios", "Reglas de Centinela", "Por qué no es vulnerabilidad",
          "Recomendación", "Responsable propuesto", "Prioridad (decisión)", "Estado (del plan)"]
    for c, h in enumerate(ch):
        ws_c.write(3, c, h, fm["head"])
    wc = _W(ws_c)
    for i, code in enumerate(by_class["Calidad"]):
        r, c = 5 + i, causes[code]
        ws_c.write(f"A{r}", code, fm["cell"]); ws_c.write(f"B{r}", c["title"], fm["cell"]); ws_c.write(f"C{r}", c.get("kind") or "", fm["cell"])
        cnt_formulas(wc, "D", "E", r, code)
        ws_c.write(f"F{r}", repos_of(code), fm["cell"]); ws_c.write(f"G{r}", rules_of(code), fm["cell"])
        ws_c.write(f"H{r}", c.get("rationale") or "", fm["cell"]); ws_c.write(f"I{r}", c.get("strategy") or "", fm["cell"])
        ws_c.write(f"J{r}", c.get("owner") or "", fm["cell"]); ws_c.write(f"K{r}", "", fm["edit"])
        wc.f(f"L{r}", f"IFERROR(IF(INDEX('Plan de trabajo'!$Z$6:$Z${plan_end},MATCH(A{r},'Plan de trabajo'!$B$6:$B${plan_end},0))=\"\",\"Pendiente\",INDEX('Plan de trabajo'!$Z$6:$Z${plan_end},MATCH(A{r},'Plan de trabajo'!$B$6:$B${plan_end},0))),\"\")", fm["cell"], "Pendiente" if code in plan_by_code else "")
    for col, w in zip("ABCDEFGHIJKL", [8, 44, 18, 11, 11, 28, 30, 48, 56, 34, 14, 12]):
        ws_c.set_column(f"{col}:{col}", w)
    ws_c.freeze_panes(4, 2)

    # ------------------------------------------------------------------ Versiones desactualizadas
    olds = [f for f in findings if f["outdated"]]
    ws_old.write("A1", "Hallazgos derivados de versiones desactualizadas (dependencias con CVE publicado)", fm["title"])
    ws_old.write("A2", "La columna Clasificación sale de la causa raíz de cada ocurrencia (hoja Detalle).", fm["note"])
    oh = ["Paquete", "Versión instalada", "CVE", "Descripción (Centinela)", "Severidad Centinela", "Severidad de la herramienta",
          "Versión con corrección (según Centinela)", "Alcanzabilidad (Centinela)", "Causa raíz", "Clasificación", "Por qué", "ID de ocurrencia"]
    for c, h in enumerate(oh):
        ws_old.write(3, c, h, fm["head"])
    wo = _W(ws_old)
    olds.sort(key=lambda f: (f["dep"].get("package", ""), f["rule"]))
    for i, f in enumerate(olds):
        r = 5 + i
        ws_old.write(f"A{r}", f["dep"].get("package", ""), fm["cell"]); ws_old.write(f"B{r}", f["dep"].get("installed", ""), fm["cell"])
        ws_old.write(f"C{r}", f["rule"].replace("SCA-", ""), fm["cell"]); ws_old.write(f"D{r}", _cve_text(f), fm["cell"])
        ws_old.write(f"E{r}", f["severity_eff"], fm["cell"]); ws_old.write(f"F{r}", f["severity_raw"], fm["cell"])
        ws_old.write(f"G{r}", f["dep"].get("fixed", ""), fm["cell"]); ws_old.write(f"H{r}", f["reach"], fm["cell"])
        ws_old.write(f"I{r}", f["cause"], fm["cell"])
        wo.f(f"J{r}", f'IF(LEFT(I{r},2)="V-","Vulnerabilidad",IF(LEFT(I{r},3)="FP-","Falso positivo",IF(LEFT(I{r},2)="C-","Calidad","Sin clasificar")))',
             fm["cell"], f["classification"])
        cz = causes.get(f["cause"]) or {}
        ws_old.write(f"K{r}", (cz.get("rationale") or cz.get("strategy") or cz.get("title") or "")[:300], fm["cell"])
        ws_old.write(f"L{r}", f["occ_id"], fm["cell"])
    # one package usually closes several CVEs with a single bump: group by package and name the version that closes all of them
    def vkey(v):
        return tuple(int(x) for x in re.findall(r"\d+", v or "")[:4]) or (0,)
    pkgs = defaultdict(list)
    for f in olds:
        pkgs[(f["dep"].get("package", ""), f["dep"].get("installed", ""))].append(f)
    r0p = 5 + len(olds) + 2
    ws_old.write(f"A{r0p}", "Por paquete: una sola actualización puede cerrar varias CVE", fm["h2"])
    for c, h in enumerate(["Paquete", "Versión instalada", "CVE", "Versión mínima que las cierra todas", "Severidad máxima", "Alcanzabilidad", "Causas raíz",
                           "Clasificación"]):
        ws_old.write(r0p, c, h, fm["head"])
    for i, ((pkg, inst_v), fs) in enumerate(sorted(pkgs.items())):
        r = r0p + 2 + i
        fixed = max((f["dep"].get("fixed", "") for f in fs), key=vkey)
        sev = min((f["severity_eff"] for f in fs), key=lambda x: SEVS.index(x) if x in SEVS else 9)
        causes_ = sorted({f["cause"] for f in fs})
        ws_old.write(f"A{r}", pkg, fm["cell"]); ws_old.write(f"B{r}", inst_v, fm["cell"]); ws_old.write_number(f"C{r}", len(fs), fm["int"])
        ws_old.write(f"D{r}", fixed, fm["cell"]); ws_old.write(f"E{r}", sev, fm["cell"])
        ws_old.write(f"F{r}", ", ".join(sorted({f["reach"] for f in fs if f["reach"]})), fm["cell"])
        ws_old.write(f"G{r}", ", ".join(causes_), fm["cell"]); ws_old.write(f"H{r}", ", ".join(sorted({class_of_code(c) for c in causes_})), fm["cell"])
    for col, w in zip("ABCDEFGHIJKL", [20, 14, 18, 60, 12, 12, 16, 14, 10, 15, 60, 12]):
        ws_old.set_column(f"{col}:{col}", w)
    ws_old.freeze_panes(4, 1)

    # ------------------------------------------------------------------ Plan de trabajo
    areas = group.get("areas") or []
    area_names = [a["name"] for a in areas] + [""] * (4 - len(areas))
    ws_plan.write("A1", f"Plan de trabajo · corrección de vulnerabilidades y mejoras de calidad de {title} (sin falsos positivos)", fm["title"])
    ws_plan.write("A2", "Ordenado por criticidad (crítico → bajo; en cada nivel, vulnerabilidades antes que calidad). Celdas amarillas: supuestos del "
                        "analista, editables. SOLO la columna «Según Centinela» es una estimación de la herramienta (SonarQube); el resto son supuestos.",
                  fm["note"])
    ws_plan.write("A3", "Horas por jornada", fm["totl"]); ws_plan.write_number("D3", group["hours_per_day"], fm["editnum"])
    ws_plan.write("E3", "Pruebas, revisión y despliegue (% sobre corrección + adicional)", fm["totl"]); ws_plan.write_number("G3", group["test_pct"], fm["editpct"])
    ws_plan.write("A4", "Las pruebas de confirmación van primero: si una descarta la vulnerabilidad, cambia su causa raíz en Detalle y la cantidad baja "
                        "a cero (solo queda el tiempo de la prueba).", fm["note"])
    ph = ["Orden", "ID", "Clasificación", "Criticidad", "Fase sugerida", "Actividad", "Repositorios", "Unidad de trabajo", "Cantidad", "Minutos por unidad",
          "Fuente del estimado", "Según Centinela (h)", "Corrección (h)", "Trabajo adicional (h)", "Qué incluye el trabajo adicional",
          "Prueba de confirmación (h)", "Pruebas, revisión y despliegue (h)", "Total (h)", "Jornadas"] + [f"% {a}" if a else "% (área)" for a in area_names] + \
         ["Inicio", "Fin", "Estado"]
    for c, h in enumerate(ph):
        ws_plan.write(4, c, h, fm["head"])
    wp = _W(ws_plan)
    hpd, tp = group["hours_per_day"], group["test_pct"]
    for i, p in enumerate(plan):
        r = 6 + i
        ws_plan.write_number(f"A{r}", i + 1, fm["int"]); ws_plan.write(f"B{r}", p["code"], fm["cell"])
        wp.f(f"C{r}", f'IF(LEFT(B{r},2)="V-","Vulnerabilidad","Calidad")', fm["cell"], p["classification"])
        if p["classification"] == "Vulnerabilidad":
            ve = 5 + q["Vulnerabilidades"][1] + SLACK
            wp.f(f"D{r}", f"INDEX(Vulnerabilidades!$D$5:$D${ve},MATCH(B{r},Vulnerabilidades!$A$5:$A${ve},0))", fm["cell"], p["criticality"])
        else:
            ce = 5 + q["Calidad"][1] + SLACK
            sel = f"INDEX(Calidad!$K$5:$K${ce},MATCH(B{r},Calidad!$A$5:$A${ce},0))"
            wp.f(f"D{r}", f'IF({sel}="","{p["criticality"]}",{sel})', fm["cell"], p["criticality"])
        ws_plan.write(f"E{r}", p["phase"] or "", fm["edit"]); ws_plan.write(f"F{r}", p["activity"] or "", fm["cell"])
        ws_plan.write(f"G{r}", ", ".join(p["repos"]), fm["cell"]); ws_plan.write(f"H{r}", p["unit"] or "", fm["cell"])
        count_expr = f'COUNTIFS({rng("M")},B{r},{rng("O")},"")'
        if p.get("fixed_qty") is not None:
            wp.f(f"I{r}", f"IF({count_expr}>0,{p['fixed_qty']:g},0)", fm["int"], p["qty"])
        else:
            wp.f(f"I{r}", count_expr, fm["int"], p["qty"])
        ws_plan.write_number(f"J{r}", p["minutes"], fm["editnum"]); ws_plan.write(f"K{r}", p["minutes_source"] or "", fm["cell"])
        wp.f(f"L{r}", f'SUMIFS({rng("Q")},{rng("M")},B{r})/60', fm["num"], p["centinela_h"])
        wp.f(f"M{r}", f"I{r}*J{r}/60", fm["num"], p["correction"])
        ws_plan.write_number(f"N{r}", p["extra"], fm["editnum"]); ws_plan.write(f"O{r}", p["extra_text"] or "", fm["cell"])
        ws_plan.write_number(f"P{r}", p["confirm"], fm["editnum"])
        wp.f(f"Q{r}", f"IF(I{r}>0,(M{r}+N{r})*$G$3,0)", fm["num"], p["tests"])
        wp.f(f"R{r}", f"P{r}+IF(I{r}>0,M{r}+N{r}+Q{r},0)", fm["num"], p["total"])
        wp.f(f"S{r}", f"IF($D$3=0,0,R{r}/$D$3)", fm["num"], p["days"])
        for k, col in enumerate("TUVW"):
            ws_plan.write_number(f"{col}{r}", p["area_pct"][k] if k < len(p["area_pct"]) else 0, fm["editpct"])
        ws_plan.write(f"X{r}", "", fm["edit"]); ws_plan.write(f"Y{r}", "", fm["edit"]); ws_plan.write(f"Z{r}", "", fm["edit"])
    first, lastp = 6, 5 + plan_rows_n
    tr = lastp + 1
    ws_plan.write(f"F{tr}", "Total del plan", fm["totl"])
    tot = lambda key: sum(p[key] for p in plan)
    for col, key in (("L", "centinela_h"), ("M", "correction"), ("N", "extra"), ("P", "confirm"), ("Q", "tests"), ("R", "total"), ("S", "days")):
        wp.f(f"{col}{tr}", f"SUM({col}{first}:{col}{lastp})" if plan_rows_n else "0", fm["tot"], tot(key))
    rr = tr + 3
    ws_plan.write(f"A{rr}", "Impacto en el equipo", fm["h2"])
    for c, h in (("A", "Concepto"), ("F", "Horas"), ("G", "Jornadas")):
        ws_plan.write(f"{c}{rr + 1}", h, fm["head"])
    cr = lambda col: f"${col}${first}:${col}${max(lastp, first)}"
    v_h = sum(p["total"] for p in plan if p["classification"] == "Vulnerabilidad")
    c_h = sum(p["total"] for p in plan if p["classification"] == "Calidad")
    tests_h = tot("confirm")
    qty_with_est = sum(1 for f in findings if f["classification"] != "Falso positivo" and not f["duplicate_of"] and f["effort_min"])
    qty_nonfp = sum(1 for f in findings if f["classification"] != "Falso positivo" and not f["duplicate_of"])
    imp = [("Total del plan (vulnerabilidades + calidad)", f"R{tr}", tot("total")),
           ("Vulnerabilidades", f'SUMIF({cr("C")},"Vulnerabilidad",{cr("R")})', v_h),
           ("Calidad y mejora", f'SUMIF({cr("C")},"Calidad",{cr("R")})', c_h),
           ("…de las cuales, pruebas de confirmación (van primero)", f"P{tr}", tests_h),
           ("Lo que estima Centinela (solo hallazgos de SonarQube, sin pruebas ni despliegue)", f"L{tr}", tot("centinela_h"))]
    for k, (label, formula, val) in enumerate(imp):
        r = rr + 2 + k
        ws_plan.write(f"A{r}", label, fm["cell"])
        wp.f(f"F{r}", formula, fm["num"], val)
        wp.f(f"G{r}", f"IF($D$3=0,0,F{r}/$D$3)", fm["num"], val / hpd if hpd else 0)
    r = rr + 2 + len(imp)
    ws_plan.write(f"A{r}", "Ocurrencias del plan que traen estimado de Centinela", fm["cell"])
    wp.f(f"F{r}", f'IFERROR(COUNTIFS({rng("Q")},">0",{rng("K")},"<>Falso positivo")/COUNTIFS({rng("K")},"<>Falso positivo",{rng("O")},""),0)',
         fm["pct"], (qty_with_est / qty_nonfp) if qty_nonfp else 0)
    r += 2
    ws_plan.write(f"A{r}", "Criticidad", fm["h2"])
    for c, h in (("A", "Criticidad"), ("F", "Horas"), ("G", "Jornadas"), ("H", "Actividades")):
        ws_plan.write(f"{c}{r + 1}", h, fm["head"])
    for k, crit in enumerate(CRITS):
        rw = r + 2 + k
        hrs = sum(p["total"] for p in plan if p["criticality"] == crit)
        ws_plan.write(f"A{rw}", crit, fm["cell"])
        wp.f(f"F{rw}", f'SUMIF({cr("D")},A{rw},{cr("R")})', fm["num"], hrs)
        wp.f(f"G{rw}", f"IF($D$3=0,0,F{rw}/$D$3)", fm["num"], hrs / hpd if hpd else 0)
        wp.f(f"H{rw}", f'COUNTIF({cr("D")},A{rw})', fm["int"], sum(1 for p in plan if p["criticality"] == crit))
    r = r + 2 + len(CRITS) + 1
    ws_plan.write(f"A{r}", "Fase sugerida", fm["h2"])
    for c, h in (("A", "Fase"), ("F", "Horas"), ("G", "Jornadas"), ("H", "Actividades")):
        ws_plan.write(f"{c}{r + 1}", h, fm["head"])
    for k, ph_ in enumerate(PHASES):
        rw = r + 2 + k
        hrs = sum(p["total"] for p in plan if p["phase"] == ph_)
        ws_plan.write(f"A{rw}", ph_, fm["cell"])
        wp.f(f"F{rw}", f'SUMIF({cr("E")},A{rw},{cr("R")})', fm["num"], hrs)
        wp.f(f"G{rw}", f"IF($D$3=0,0,F{rw}/$D$3)", fm["num"], hrs / hpd if hpd else 0)
        wp.f(f"H{rw}", f'COUNTIF({cr("E")},A{rw})', fm["int"], sum(1 for p in plan if p["phase"] == ph_))
    r = r + 2 + len(PHASES) + 1
    ws_plan.write(f"A{r}", "Duración por área", fm["h2"])
    for c, h in (("A", "Área"), ("F", "Horas"), ("G", "Jornadas"), ("H", "Personas asignadas"), ("I", "Dedicación al plan"), ("J", "Semanas estimadas")):
        ws_plan.write(f"{c}{r + 1}", h, fm["head"])
    area_rows = []
    weeks_vals = []
    for k in range(4):
        a = areas[k] if k < len(areas) else {"name": "", "people": 1, "dedication": 1}
        rw = r + 2 + k
        col = "TUVW"[k]
        hrs = sum(p["total"] * (p["area_pct"][k] if k < len(p["area_pct"]) else 0) for p in plan)
        days = hrs / hpd if hpd else 0
        weeks = (days / (a["people"] * a["dedication"]) / 5) if a["people"] * a["dedication"] else ""
        weeks_vals.append(weeks if weeks != "" else 0)
        ws_plan.write(f"A{rw}", a["name"], fm["cell"])
        wp.f(f"F{rw}", f'SUMPRODUCT({cr("R")},{col}${first}:{col}${max(lastp, first)})', fm["num"], hrs)
        wp.f(f"G{rw}", f"IF($D$3=0,0,F{rw}/$D$3)", fm["num"], days)
        ws_plan.write_number(f"H{rw}", a["people"], fm["editnum"]); ws_plan.write_number(f"I{rw}", a["dedication"], fm["editpct"])
        wp.f(f"J{rw}", f'IF(H{rw}*I{rw}=0,"",G{rw}/(H{rw}*I{rw})/5)', fm["num"], weeks)
        area_rows.append(rw)
    rw = r + 6
    ws_plan.write(f"A{rw}", "Duración del plan si las áreas avanzan en paralelo (semanas, sin modelar dependencias: mínimo optimista)", fm["cell"])
    wp.f(f"F{rw}", f"MAX(J{area_rows[0]}:J{area_rows[-1]})", fm["num"], max(weeks_vals) if weeks_vals else 0)
    ws_plan.write(f"A{rw + 1}", "Personas y dedicación son supuestos editables: ajústalos a quienes estén asignados al proyecto.", fm["note"])
    plan_dur_cell, plan_total_cell = f"F{rw}", f"R{tr}"
    fp_n = sum(1 for f in findings if f["classification"] == "Falso positivo")
    ws_plan.write(f"A{rw + 3}", "Fuera del plan: falsos positivos", fm["h2"])
    ws_plan.write(f"A{rw + 4}", "Motivos de falso positivo", fm["cell"])
    wp.f(f"F{rw + 4}", f"COUNTA('Falsos positivos'!$A$5:$A${5 + q['Falsos positivos'][1] + SLACK})", fm["int"], len(by_class["Falso positivo"]))
    ws_plan.write(f"A{rw + 5}", "Ocurrencias", fm["cell"])
    wp.f(f"F{rw + 5}", f'COUNTIF({rng("K")},"Falso positivo")', fm["int"], fp_n)
    req = sum(1 for code in by_class["Falso positivo"] if (causes[code].get("certainty") or "").startswith("Requiere prueba"))
    ws_plan.write(f"A{rw + 6}", "Motivos que requieren una verificación antes de cerrarse", fm["cell"])
    wp.f(f"F{rw + 6}", f"COUNTIF('Falsos positivos'!$D$5:$D${5 + q['Falsos positivos'][1] + SLACK},\"Requiere prueba*\")", fm["int"], req)
    ws_plan.write(f"A{rw + 7}", "Horas por verificación (supuesto editable)", fm["cell"]); ws_plan.write_number(f"F{rw + 7}", group["fp_check_hours"], fm["editnum"])
    ws_plan.write(f"A{rw + 8}", "Horas de verificación (no suman al total del plan)", fm["cell"])
    wp.f(f"F{rw + 8}", f"F{rw + 6}*F{rw + 7}", fm["num"], req * group["fp_check_hours"])
    for col, w in zip(["A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z"],
                      [7, 7, 14, 11, 18, 54, 28, 18, 9, 10, 40, 11, 11, 11, 44, 11, 13, 10, 9, 11, 11, 11, 11, 11, 11, 12]):
        ws_plan.set_column(f"{col}:{col}", w)
    ws_plan.freeze_panes(5, 2)

    # ------------------------------------------------------------------ Resumen
    repos = sorted({c["repo"] for c in coverage} | {f["repo"] for f in findings})
    wr = _W(ws_res)
    ws_res.write("A1", f"{title} · Hallazgos de Centinela clasificados", fm["title"])
    ws_res.write("A2", data.get("source_text") or (
        f"Fuente: Centinela-AI, consulta del {data['generated_at']:%d/%m/%Y %H:%M} sobre el grupo «{group['group_path']}» de GitLab "
        f"({inst.url}) y sus {len(coverage)} subproyectos. Clasificación: criterio del analista guardado en Centinela "
        "(causas raíz y reglas), aplicado a los hallazgos abiertos de seguridad."), fm["note"])
    ws_res.write("A3", f"Cómo leer: cada una de las {n:,} ocurrencias tiene una causa raíz en la hoja Detalle (columna M, lista desplegable); la "
                       "clasificación y todos los conteos salen de ahí con fórmulas. Una ocurrencia que ningún criterio cubre aparece como "
                       f"«{UNCLASSIFIED}»: no se adivina. Celdas amarillas: las llena el responsable.", fm["note"])
    for c, h in enumerate(["Clasificación", "Ocurrencias reportadas", "Ocurrencias únicas (sin duplicados)", "Causas raíz", "% de lo reportado", "Qué sigue"]):
        ws_res.write(4, c, h, fm["head"])
    nxt = {"Vulnerabilidad": "Entra a la estrategia de corrección (hoja Vulnerabilidades).",
           "Falso positivo": "Se documenta su fundamento y se cierra (hoja Falsos positivos).",
           "Calidad": "Backlog de mejora: endurecimiento, accesibilidad, calidad de código y cumplimiento (hoja Calidad).",
           "Sin clasificar": "Pendiente de criterio del analista: asigna su causa raíz en Detalle (o agrega una regla en Centinela)."}
    cls_rows = ["Vulnerabilidad", "Falso positivo", "Calidad", "Sin clasificar"]
    cat_sheet = {"Vulnerabilidad": "Vulnerabilidades", "Falso positivo": "'Falsos positivos'", "Calidad": "Calidad"}
    tot_all = n
    for k, cl in enumerate(cls_rows):
        r = 6 + k
        a_ = sum(1 for f in findings if f["classification"] == cl)
        u_ = sum(1 for f in findings if f["classification"] == cl and not f["duplicate_of"])
        ws_res.write(f"A{r}", cl, fm["cell"])
        wr.f(f"B{r}", f"COUNTIF({rng('K')},A{r})", fm["int"], a_)
        wr.f(f"C{r}", f'COUNTIFS({rng("K")},A{r},{rng("O")},"")', fm["int"], u_)
        if cl in cat_sheet:
            nc = len(by_class[cl])
            wr.f(f"D{r}", f"COUNTA({cat_sheet[cl]}!$A$5:$A${5 + nc + SLACK})", fm["int"], nc)
        else:
            ws_res.write(f"D{r}", "—", fm["cell"])
        wr.f(f"E{r}", f"IF($B$10=0,0,B{r}/$B$10)", fm["pct"], (a_ / tot_all) if tot_all else 0)
        ws_res.write(f"F{r}", nxt[cl], fm["cell"])
    ws_res.write("A10", "Total", fm["totl"])
    for col in "BCD":
        wr.f(f"{col}10", f"SUM({col}6:{col}9)", fm["tot"], {"B": n, "C": sum(1 for f in findings if not f["duplicate_of"]), "D": sum(len(v) for v in by_class.values())}[col])
    wr.f("E10", "SUM(E6:E9)", fm["tot"], 1 if n else 0)
    ws_res.write("A11", "Total que reporta Centinela (hallazgos abiertos de seguridad del grupo)", fm["cell"])
    ws_res.write_number("B11", n, fm["int"])
    wr.f("C11", 'IF(B10=B11,"Cuadra con Centinela","Revisar")', fm["cell"], "Cuadra con Centinela")
    if data.get("informational") is None:
        ws_res.write("A12", "Los hallazgos informativos (code smells, deuda de proceso) no vienen en los PDF por repositorio; este libro no los cuenta.", fm["note"])
    else:
        ws_res.write("A12", f"Fuera de este libro: {data['informational']:,} hallazgos informativos (calidad de código y deuda de proceso, p. ej. code smells de "
                            "SonarQube), que Centinela cuenta aparte de las vulnerabilidades.", fm["note"])

    ws_res.write("A14", "Derivadas de versiones desactualizadas (dependencias con CVE publicado)", fm["h2"])
    ws_res.write("A15", "Concepto", fm["head"]); ws_res.write("B15", "Ocurrencias", fm["head"])
    o_all = sum(1 for f in findings if f["outdated"])
    o_v = sum(1 for f in findings if f["outdated"] and f["classification"] == "Vulnerabilidad")
    o_fp = sum(1 for f in findings if f["outdated"] and f["classification"] == "Falso positivo")
    ws_res.write("A16", "Total con versión desactualizada", fm["cell"]); wr.f("B16", f'COUNTIF({rng("P")},"Sí")', fm["int"], o_all)
    ws_res.write("A17", "…que sí aplican (vulnerabilidad)", fm["cell"]); wr.f("B17", f'COUNTIFS({rng("P")},"Sí",{rng("K")},"Vulnerabilidad")', fm["int"], o_v)
    ws_res.write("A18", "…que son falso positivo (p. ej. código no alcanzable)", fm["cell"]); wr.f("B18", f'COUNTIFS({rng("P")},"Sí",{rng("K")},"Falso positivo")', fm["int"], o_fp)
    ws_res.write("A19", "Detalle por paquete y CVE en la hoja Versiones desactualizadas.", fm["note"])

    ws_res.write("A21", "Causas raíz de vulnerabilidad por severidad propuesta (escala ART-SOP-02)", fm["h2"])
    for c, h in enumerate(["Severidad", "Causas raíz", "Ocurrencias"]):
        ws_res.write(21, c, h, fm["head"])
    nv = len(by_class["Vulnerabilidad"])
    ve = 5 + nv + SLACK
    for k, crit in enumerate(CRITS):
        r = 23 + k
        codes = [c for c in by_class["Vulnerabilidad"] if (causes[c].get("severity") or "") == crit]
        ws_res.write(f"A{r}", crit, fm["cell"])
        wr.f(f"B{r}", f"COUNTIF(Vulnerabilidades!$D$5:$D${ve},A{r})", fm["int"], len(codes))
        wr.f(f"C{r}", f"SUMIF(Vulnerabilidades!$D$5:$D${ve},A{r},Vulnerabilidades!$F$5:$F${ve})", fm["int"], sum(cnt_all[c] for c in codes))

    r0 = 28
    ws_res.write(f"A{r0}", "Por repositorio (ocurrencias reportadas)", fm["h2"])
    for c, h in enumerate(["Repositorio", "Vulnerabilidad", "Falso positivo", "Calidad", "Sin clasificar", "Total"]):
        ws_res.write(r0, c, h, fm["head"])
    hdr_row = r0 + 1
    for k, repo in enumerate(repos):
        r = hdr_row + 1 + k
        ws_res.write(f"A{r}", repo, fm["cell"])
        tot_r = 0
        for col, cl in zip("BCDE", ["Vulnerabilidad", "Falso positivo", "Calidad", "Sin clasificar"]):
            v = sum(1 for f in findings if f["repo"] == repo and f["classification"] == cl)
            tot_r += v
            wr.f(f"{col}{r}", f"COUNTIFS({rng('B')},$A{r},{rng('K')},{col}${hdr_row})", fm["int"], v)
        wr.f(f"F{r}", f"SUM(B{r}:E{r})", fm["int"], tot_r)
    r_end = hdr_row + len(repos)
    rt = r_end + 1
    ws_res.write(f"A{rt}", "Total", fm["totl"])
    for col in "BCDEF":
        v = n if col == "F" else sum(1 for f in findings if f["classification"] == {"B": "Vulnerabilidad", "C": "Falso positivo", "D": "Calidad", "E": "Sin clasificar"}[col])
        wr.f(f"{col}{rt}", f"SUM({col}{hdr_row + 1}:{col}{r_end})" if repos else "0", fm["tot"], v)

    rs = rt + 2
    ws_res.write(f"A{rs}", "Severidad que asignó Centinela frente a la clasificación", fm["h2"])
    for c, h in enumerate(["Severidad Centinela", "Vulnerabilidad", "Falso positivo", "Calidad", "Sin clasificar", "Total"]):
        ws_res.write(rs, c, h, fm["head"])
    sh = rs + 1
    for k, sev in enumerate(SEVS):
        r = sh + 1 + k
        ws_res.write(f"A{r}", sev, fm["cell"])
        tot_r = 0
        for col, cl in zip("BCDE", ["Vulnerabilidad", "Falso positivo", "Calidad", "Sin clasificar"]):
            v = sum(1 for f in findings if f["severity_eff"] == sev and f["classification"] == cl)
            tot_r += v
            wr.f(f"{col}{r}", f"COUNTIFS({rng('E')},$A{r},{rng('K')},{col}${sh})", fm["int"], v)
        wr.f(f"F{r}", f"SUM(B{r}:E{r})", fm["int"], tot_r)
    rst = sh + 1 + len(SEVS)
    ws_res.write(f"A{rst}", "Total", fm["totl"])
    for col in "BCDEF":
        v = sum(1 for f in findings if f["severity_eff"] in SEVS and (col == "F" or f["classification"] == {"B": "Vulnerabilidad", "C": "Falso positivo", "D": "Calidad", "E": "Sin clasificar"}[col]))
        wr.f(f"{col}{rst}", f"SUM({col}{sh + 1}:{col}{rst - 1})", fm["tot"], v)
    nr = sum(1 for f in findings if f["no_risk"])
    ws_res.write(f"A{rst + 1}", 'Hallazgos que Centinela etiquetó como "sin riesgo real" (aparecen como INFO en la tabla de arriba; la severidad de la herramienta sigue en Detalle):', fm["cell"])
    wr.f(f"B{rst + 1}", f'COUNTIF({rng("G")},"Sí")', fm["int"], nr)

    rp = rst + 3
    ws_res.write(f"A{rp}", "Plan de trabajo (sin falsos positivos)", fm["h2"])
    for c, h in enumerate(["Concepto", "Horas", "Jornadas"]):
        ws_res.write(rp, c, h, fm["head"])
    rr_ = rr + 2  # first row of the impact block in the plan sheet
    items = [("Total del plan", rr_, tot("total")), ("Vulnerabilidades", rr_ + 1, v_h), ("Calidad y mejora", rr_ + 2, c_h),
             ("Lo que estima Centinela (solo SonarQube)", rr_ + 4, tot("centinela_h"))]
    for k, (lab, prow, val) in enumerate(items):
        r = rp + 2 + k
        ws_res.write(f"A{r}", lab, fm["cell"])
        wr.f(f"B{r}", f"'Plan de trabajo'!F{prow}", fm["num"], val)
        wr.f(f"C{r}", f"'Plan de trabajo'!G{prow}", fm["num"], val / hpd if hpd else 0)
    r = rp + 2 + len(items)
    ws_res.write(f"A{r}", "Duración con las áreas en paralelo (semanas)", fm["cell"])
    wr.f(f"B{r}", f"'Plan de trabajo'!{plan_dur_cell}", fm["num"], max(weeks_vals) if weeks_vals else 0)
    no_est = [c for c in all_codes if class_of_code(c) != "Falso positivo" and cnt_all[c] and not (causes[c].get("plan"))]
    if no_est:
        ws_res.write(f"A{r + 1}", f"Causas con ocurrencias pero SIN estimación en el plan (no suman horas): {', '.join(no_est)}.", fm["warn"])
    for col, w in zip("ABCDEF", [58, 16, 18, 14, 14, 70]):
        ws_res.set_column(f"{col}:{col}", w)

    # ------------------------------------------------------------------ Cobertura
    ws_cov.write("A1", "Cobertura: subproyectos del grupo en GitLab frente a lo que Centinela escaneó", fm["title"])
    cov_note = ("Lista tomada de GitLab (grupo y subgrupos). 'Sin escanear' NO significa limpio: significa que Centinela no tiene resultados de ese repositorio."
                if not data["coverage_error"] else
                f"No se pudo verificar contra GitLab: {data['coverage_error']}. Se muestran solo los activos que Centinela ya tiene registrados.")
    ws_cov.write("A2", cov_note, fm["warn"] if data["coverage_error"] else fm["note"])
    for c, h in enumerate(["Subproyecto", "Ruta en GitLab", "Estado", "Última auditoría", "Hallazgos de seguridad abiertos", "Nota"]):
        ws_cov.write(3, c, h, fm["head"])
    for i, cv in enumerate(coverage):
        r = 5 + i
        bad = not cv["status"].startswith("Escaneado")
        ws_cov.write(f"A{r}", cv["repo"], fm["warn"] if bad else fm["cell"]); ws_cov.write(f"B{r}", cv["path"], fm["cell"])
        ws_cov.write(f"C{r}", cv["status"], fm["warn"] if bad else fm["cell"]); ws_cov.write(f"D{r}", str(cv["last_audit"])[:19], fm["cell"])
        ws_cov.write_number(f"E{r}", cv["findings"], fm["int"]); ws_cov.write(f"F{r}", cv["note"], fm["cell"])
    for col, w in zip("ABCDEF", [32, 52, 44, 20, 16, 50]):
        ws_cov.set_column(f"{col}:{col}", w)
    ws_cov.freeze_panes(4, 1)

    # ------------------------------------------------------------------ Criterios
    ws_crit.write("A1", "Criterios de clasificación", fm["title"])
    ws_crit.write("A2", "Cómo se decidió cada renglón, qué significa cada columna y de dónde salen los datos.", fm["note"])
    crit_rows = [
        ("h", "Las cuatro preguntas"),
        ("1. ¿Existe en código que se ejecuta?", "Si el patrón está comentado, en un archivo copia, en datos dummy, en una dependencia que no se empaqueta o en un perfil que no llega a producción, no es vulnerabilidad: es falso positivo o «no aplica»."),
        ("2. ¿Un atacante lo alcanza en producción?", "Atacante = alguien de fuera, un usuario autenticado o alguien con acceso al repositorio. Si solo importa cuando otra cosa ya falló, es endurecimiento (hoja Calidad). Si la premisa de la herramienta no se cumple (SSR, cookies, Java 8), es falso positivo."),
        ("3. ¿Qué se pierde si se explota?", "Confidencialidad, integridad o disponibilidad de datos, identidad o firmas. Si no hay pérdida de seguridad, es calidad o cumplimiento."),
        ("4. ¿Se puede demostrar?", "Con una prueba mínima en QA. Donde la prueba no se ha hecho, la certeza dice «Requiere prueba»."),
        ("h", "Clasificaciones"),
        ("Vulnerabilidad", "Pasa las preguntas 1 a 3. Entra a la estrategia de corrección. Corresponde a la familia de seguridad de 0B-2."),
        ("Falso positivo", "Tipos: artefacto de desarrollo, código que no se ejecuta, por diseño, premisa técnica falsa, no alcanzable. Se documenta su fundamento y se cierra; incluye la condición que lo haría reabrirse."),
        ("Calidad", "Tipos: endurecimiento (defensa en profundidad), accesibilidad (0B-2, requisito legal), calidad de código (0B-2) y cumplimiento. Va al backlog de mejora."),
        ("Sin clasificar", "Hallazgo real de Centinela que ningún criterio del analista cubre todavía. No se asume nada: queda a la vista hasta que se le asigne una causa raíz."),
        ("Versión desactualizada", "«Sí» cuando el hallazgo es un CVE de una dependencia por su versión instalada (0B-1, catálogo tecnológico). Se marca en cualquiera de las clasificaciones."),
        ("h", "Columnas"),
        ("Duplicado de", "Mismo hallazgo reportado por más de un motor en la misma línea (o, en las causas que así lo declaran, en el mismo archivo: un Dockerfile, un par de propiedades contiguas). Se conserva para trazabilidad y no cuenta en «Ocurrencias únicas»."),
        ("Severidad Centinela", "Severidad efectiva de Centinela (ya degradada cuando su análisis concluyó que el riesgo real es menor). «Severidad de la herramienta» es la cruda del motor."),
        ("Severidad propuesta", "Matriz estándar ART-SOP-02 (crítico, alto, medio, bajo), leída como «si llegara a producción tal como está». Es una propuesta; el orden de corrección lo decide la Dirección de Tecnología con desarrollo."),
        ("Causa raíz (Detalle, columna M)", "Es la única columna que se edita para reclasificar. Clasificación, Tipo y todos los conteos salen de ella con fórmulas. Si cambias algo aquí, para que Centinela lo recuerde en el próximo reporte, pide al analista que lo registre como regla en Centinela."),
        ("h", "De dónde sale cada dato"),
        ("Medido por Centinela", "Hallazgos abiertos, severidades, motor, regla, archivo y línea, duplicados entre motores, versiones desactualizadas y alcanzabilidad, estimación de esfuerzo de SonarQube y cobertura de subproyectos (contra GitLab)."),
        ("Criterio del analista", "Causa raíz de cada hallazgo, fundamento de los falsos positivos, estrategia, responsable, certeza y los supuestos del plan de trabajo (minutos por unidad, trabajo adicional, reparto entre áreas, personas y dedicación). Centinela los guarda con autor y fecha; no los calcula ni los inventa."),
        ("Límites", "La clasificación se hizo sobre la evidencia de los reportes, sin ejecutar pruebas contra el sistema. Donde la certeza dice «Requiere prueba», el cierre exige esa prueba. Solo SonarQube trae tiempo estimado; para los demás motores los minutos del plan son supuestos del analista (celdas amarillas)."),
        ("h", "Relación con la metodología interna"),
        ("0B-2", "Estándares de seguridad, accesibilidad y calidad de código: sus tres familias corresponden a Vulnerabilidad (seguridad) y Calidad (accesibilidad y calidad de código)."),
        ("0B-1", "Catálogo tecnológico versionado: las versiones desactualizadas se contrastan aquí (estado de ciclo de vida)."),
        ("0B-3 / ART-F2-04", "Si se decide no corregir una vulnerabilidad, se tramita como excepción; las desviaciones de seguridad son irreversibles por defecto y las resuelve el comité."),
        ("ART-F2-03", "Registro de validación contra 0B-1 y 0B-2: este libro es su anexo de detalle."),
    ]
    r = 4
    for label, text in crit_rows:
        if label == "h":
            r += 1
            ws_crit.write(f"A{r}", text, fm["h2"])
        else:
            ws_crit.write(f"A{r}", label, fm["cell"]); ws_crit.write(f"B{r}", text, fm["cell"])
        r += 1
    ws_crit.set_column("A:A", 36); ws_crit.set_column("B:B", 120)

    wb.close()
    return buf.getvalue()


def _cve_text(f: Dict[str, Any]) -> str:
    d = f.get("description") or ""
    i = d.find("Vulnerable dependency")
    if i >= 0:
        txt = d[i:].split("\n")[0]
        return txt[:260]
    return f.get("title", "")
