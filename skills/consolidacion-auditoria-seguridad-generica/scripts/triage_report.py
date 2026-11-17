#!/usr/bin/env python3
"""Clasifica los hallazgos de Centinela (leídos de los PDF) con el catálogo de causas raíz del analista y genera el libro de triage + la matriz.

Uso:
  python triage_report.py <centinela.json> <catalogo.json> <salida.xlsx> [--matriz matriz_centinela.json] [--titulo SISTEMA] [--grupo grupo/sistema]

  centinela.json : salida de parse_centinela.py
  catalogo.json  : catálogo del analista (causas raíz + reglas); ver references/triage_catalogo.md y assets/catalogo_ejemplo.json
  salida.xlsx    : libro con Resumen, Cobertura, Plan de trabajo, Vulnerabilidades, Falsos positivos, Calidad, Versiones desactualizadas, Detalle, Criterios
  --matriz       : registros para build_matrix_xlsx.py (esquema de references/matriz_schema.md)
  --pendientes   : JSON con los grupos SIN CLASIFICAR (repositorio x regla): evidencia, ubicaciones de muestra y los precedentes del catálogo para esa regla

Lo medido sale de los PDF; la clasificación sale SOLO del catálogo. Un hallazgo que ninguna regla cubre queda como SIN CLASIFICAR (no se adivina) y se
lista al final para que el analista decida su causa raíz. Requiere `pip install xlsxwriter`.
"""
import collections
import json
import os
import sys
from datetime import datetime
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    import xlsxwriter  # noqa: F401
except ImportError:
    sys.exit("Falta xlsxwriter: pip install xlsxwriter")

from core import triage, triage_matrix, triage_pdf  # noqa: E402
from core.triage_workbook import build_workbook  # noqa: E402


def load_catalog(path):
    cat = json.load(open(path, encoding='utf-8'))
    causes = {}
    for c in cat['root_causes']:
        c = dict(c)
        c.setdefault('dedup_scope', 'line')
        causes[c['code']] = c
    rules = sorted(cat['rules'], key=lambda r: r.get('priority', 0))
    return cat['group'], causes, rules


def pendientes(data, parsed):
    """SIN CLASIFICAR grouped by repository x rule, with the evidence the analyst needs. `precedentes` lists how the SAME rule was classified elsewhere in this
    run: a pointer for the analyst, never an applied decision (a rule can be a vulnerability in one file and a false positive in another)."""
    que = {(repo, it['rule']): it for repo, items in parsed.items() for it in items}
    prec = collections.defaultdict(collections.Counter)
    for f in data['findings']:
        if f['cause'] != triage.UNCLASSIFIED:
            prec[f['rule']][f['cause']] += 1
    groups = collections.defaultdict(list)
    for f in data['findings']:
        if f['cause'] == triage.UNCLASSIFIED:
            groups[(f['repo'], f['rule'])].append(f)
    out = []
    for (repo, rule), fs in sorted(groups.items(), key=lambda kv: (-len(kv[1]), kv[0])):
        it = que.get((repo, rule), {})
        out.append(dict(repositorio=repo, regla=rule, motor=fs[0]['engine'], severidad=fs[0]['severity_eff'], ocurrencias=len(fs),
                        muestra=[f['url_path'] for f in fs if not f.get('unlisted')][:5], que_encontro=(it.get('que') or '')[:400],
                        riesgo=(it.get('riesgo') or '')[:300], sin_riesgo_real=bool(it.get('norisk')),
                        precedentes_misma_regla={c: n for c, n in prec.get(rule, {}).items()}))
    return out


def main(parsed_path, catalog_path, out, matriz=None, titulo=None, grupo=None, pendientes_out=None):
    parsed = json.load(open(parsed_path, encoding='utf-8'))
    group, causes, rules = load_catalog(catalog_path)
    if titulo:
        group['title'] = titulo
    if grupo:
        group['group_path'] = grupo
    findings = triage_pdf.findings_from_parsed_pdf(parsed)
    coverage = triage_pdf.coverage_from_pdf(parsed, findings)
    inst = SimpleNamespace(url='(PDF de Centinela)', key=group.get('instance', 'pdf'))
    declared = sum(it['n'] for items in parsed.values() for it in items)
    data = triage.assemble_report_data(
        group, causes, rules, findings, coverage, inst, informational=None,
        coverage_error='Sin acceso a GitLab: la lista de subproyectos es la de los PDF recibidos. Un repositorio que Centinela no escaneó NO aparece aquí.',
        now=datetime.now(),
        source_text=(f"Fuente: {len(parsed)} reportes PDF de Centinela-AI del grupo «{group['group_path']}» "
                     f"(generados el {datetime.now():%d/%m/%Y}). Clasificación: criterio del analista (catálogo de causas raíz y reglas), "
                     "aplicado a lo que los PDF listan; las ocurrencias que el PDF no lista aparecen como «No listado en el PDF»."))
    data['source_label'] = 'Centinela (PDF)'
    open(out, 'wb').write(build_workbook(data))
    cls = collections.Counter(f['classification'] for f in data['findings'])
    uniq = collections.Counter(f['classification'] for f in data['findings'] if not f['duplicate_of'])
    print(f"Ocurrencias: {len(data['findings'])} (los PDF declaran {declared}) -> "
          + ', '.join(f"{k}: {cls.get(k, 0)} (únicas {uniq.get(k, 0)})" for k in ('Vulnerabilidad', 'Falso positivo', 'Calidad', 'Sin clasificar')))
    unl = sum(1 for f in data['findings'] if f.get('unlisted'))
    if unl:
        print(f"  {unl} ocurrencias no aparecen listadas en los PDF (se clasifican solo por regla genérica).")
    sin = [f for f in data['findings'] if f['cause'] == triage.UNCLASSIFIED]
    if sin:
        print(f"\nSIN CLASIFICAR: {len(sin)} ocurrencias. Hay que decidir su causa raíz y agregarla al catálogo:")
        for (repo, rule), n in collections.Counter((f['repo'], f['rule']) for f in sin).most_common(25):
            print(f"  {repo:34} {rule}  x{n}")
    if pendientes_out:
        pend = pendientes(data, parsed)
        json.dump(pend, open(pendientes_out, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
        print(f"\nPendientes de clasificar: {len(pend)} grupos -> {pendientes_out}")
    if matriz:
        recs = triage_matrix.matrix_records(data)
        json.dump(recs, open(matriz, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
        print(f"\nMatriz: {len(recs)} registros -> {matriz}")
    print(f"Libro: {out}")


if __name__ == '__main__':
    argv = sys.argv[1:]
    opts = {}
    for flag, key in (('--matriz', 'matriz'), ('--titulo', 'titulo'), ('--grupo', 'grupo'), ('--pendientes', 'pendientes_out')):
        if flag in argv:
            i = argv.index(flag)
            opts[key] = argv[i + 1]
            del argv[i:i + 2]
    if len(argv) < 3:
        sys.exit(__doc__)
    main(argv[0], argv[1], argv[2], **opts)
