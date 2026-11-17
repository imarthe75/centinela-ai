#!/usr/bin/env python3
"""Parsea los PDF de Centinela (ya convertidos a texto) a una fila por regla x repositorio, CON todas las ubicaciones (archivo + líneas).

Uso: python parse_centinela.py <dir_txt> <salida.json> [prefijo=] [--grupo GitLab/grupo/sistema]

Lee <prefijo><repo>.txt (omite los GENERAL). Funciona con el texto de `pdftotext -layout` y con el de extract_inputs.py (un .txt por página).
v2 respecto a la versión anterior:
  * el formato nuevo del PDF lista TODAS las ubicaciones como «📁 ruta   líneas 4, 36» (la ruta se parte en varias líneas al imprimir; aquí se
    reconstruye) y no solo las primeras 10; el encabezado «UBICACIÓN EN CÓDIGO (N ubicaciones en M archivo(s))» declara cuántas hay,
    así que `n_ubic_declaradas` (pares archivo:línea) vs lo parseado delata cualquier truncamiento; cuando el PDF recorta («Se muestran 60 de 81 archivos
    afectados») queda en `truncado`;
  * el nombre completo del activo (GitLab/grupo/sistema/backend/servicio-a) sale del encabezado de cada PDF: sirve para saber a qué grupo pertenece;
  * esfuerzo estimado de SonarQube, paquete/versiones/alcanzabilidad de SCA, CWE, marca «SIN RIESGO REAL» y si trae parche.

Campos por fila: asset, repo, rule, sev, norisk, n, motor, ubicaciones [{file, lines[]}], n_ubic_declaradas, n_archivos_declarados, cwe, que, riesgo,
esfuerzo_min, noact, patch, sca [paquete, instalada, segura, alcanzabilidad].
"""
import glob
import json
import os
import re
import sys

SEV = r'(CRITICAL|HIGH|MEDIUM|LOW|INFO)'
# A heading is «BADGE  rule  (N Ocurrencias)  Motor: x». The PDF wraps it unpredictably (the rule id, «Motor: sast-/native», or «(1 / Motor: x / Ocurrencias)»),
# so it is matched on whitespace-collapsed text with the rule and motor pulled out of whatever lies between the badge and «Ocurrencias)».
HEAD = re.compile(SEV + r'(?: \(HERRAMIENTA: ' + SEV + r'\))?( · SIN RIESGO REAL)? (?P<mid>[^()]{3,220}?) ?\((?P<n>\d+)(?P<mid2> Motor: [a-z0-9]+(?:-(?: [a-z0-9]+)?)?)? Ocurrencias?\)(?P<after> Motor: [a-z0-9]+(?:-[a-z0-9]+)*(?:-(?: [a-z0-9]+)?)?)?')
END_LOC = re.compile(r'💡|SOLUCI[ÓO]N RECOMENDADA|✅|Se muestran \d+ de \d+|SIN PARCHE AUTOM|PARCHE AUTOM|SIN ACCI[ÓO]N REQUERIDA|Pasos de Remediaci|🛠')
ASSET = re.compile(r'((?:GitLab\d*|SERVER|URL|Local)/[A-Za-z0-9_.\-/]+)')
FOOTER = re.compile(r'\b\d+ / \d+\b')
LOC = re.compile(r'📁\s*(?P<p>.+?)(?:\s+l[íi]neas?\s+(?P<l>\d+(?:\s*,\s*\d+)*))?(?=\s*📁|\s*$)')


def _heading_fields(m, flat):
    """(rule, motor) from a heading whose pieces the PDF scattered. Engine names with a hyphen wrap («sast-» / «native», or «accessibility-» ... «wcag»
    printed AFTER «(79 Ocurrencias)»); rule ids contain no spaces, so once the «Motor: x» fragment is cut out the wrap points of the id just disappear."""
    mid = m.group('mid')
    motor, rule_text = '', mid
    mt = re.search(r'Motor:\s*(\S+)', mid)
    if mt:
        t1 = mt.group(1)
        rest = mid[mt.end():].split()
        if t1.endswith('-') and rest and re.fullmatch(r'[a-z0-9]+', rest[0]):
            motor = t1 + rest[0]
            rule_text = mid[:mt.start()] + ' ' + ' '.join(rest[1:])
        else:
            rule_text = mid[:mt.start()] + ' ' + mid[mt.end():]
            motor = t1
            if t1.endswith('-'):
                cont = re.match(r'\s*([a-z0-9]+)(?=\s|$)', flat[m.end():])
                if cont:
                    motor = t1 + cont.group(1)
    else:
        extra = (m.group('mid2') or '') + ' ' + (m.group('after') or '')
        mm = re.search(r'Motor:\s*(\S+)(?:\s+([a-z0-9]+))?', extra)
        if mm:
            motor = mm.group(1) + (mm.group(2) or '') if mm.group(1).endswith('-') else mm.group(1)
    return re.sub(r'\s+', '', rule_text), motor


def parse_locations(sec):
    m = re.search(r'UBICACI[ÓO]N EN C[ÓO]DIGO\s*\((\d+)\s+ubicaci\w+\s+en\s+(\d+)\s+archivo', sec)
    declared = (int(m.group(1)), int(m.group(2))) if m else (None, None)
    if not m:
        return [], declared, None
    tail = sec[m.end():]
    cut = re.search(r'Se muestran (\d+) de (\d+) archivos', tail)
    shown = {'archivos_mostrados': int(cut.group(1)), 'archivos_totales': int(cut.group(2))} if cut else None
    e = END_LOC.search(tail)
    if e:
        tail = tail[:e.start()]
    result = []
    for lm in LOC.finditer(tail):
        # a wrapped path keeps its break as one space: drop it after '/' or '-', keep it otherwise (real names such as 'a.component copy.html')
        path = re.sub(r'(?<=[/\-])\s+', '', lm.group('p').strip())
        nums = [int(x) for x in re.findall(r'\d+', lm.group('l') or '')]
        result.append({'file': path, 'lines': nums})
    return result, declared, shown


def parse_text(txt):
    txt = re.sub(r'=== PAG \d+ ===', ' ', txt)
    flat = re.sub(r'\s+', ' ', FOOTER.sub(' ', txt))
    am = ASSET.search(flat)
    asset = am.group(1) if am else ''
    heads = list(HEAD.finditer(flat))
    items = []
    for i, m in enumerate(heads):
        block = flat[m.end(): heads[i + 1].start() if i + 1 < len(heads) else len(flat)]
        rule, motor = _heading_fields(m, flat)
        locs, declared, shown = parse_locations(block)
        q = re.search(r'Qué encontramos:\s*(.{0,500}?)(?:\s*⚠|\s*Qué significa)', block)
        r = re.search(r'Riesgo al Negocio:\s*(.{0,300})', block)
        sca = re.search(r'Paquete:\s*(\S+)\s+Versión instalada:\s*(\S+)\s+Versión segura:\s*(\S+)', block)
        alc = re.search(r'Alcanzabilidad:\s*(\S+)', block)
        eff = re.search(r'Esfuerzo estimado:\s*((?:\d+d)?\s*(?:\d+h)?\s*(?:\d+min)?)', block)
        minutes = None
        if eff and eff.group(1).strip():
            minutes = sum(int(v) * {'d': 480, 'h': 60, 'min': 1}[u] for v, u in re.findall(r'(\d+)\s*(d|h|min)', eff.group(1))) or None
        norisk = bool(m.group(3))
        items.append(dict(
            asset=asset, sev=m.group(1), sev_herramienta=m.group(2) or m.group(1), norisk=norisk, rule=rule, n=int(m.group('n')), motor=motor,
            ubicaciones=locs, n_ubic_declaradas=declared[0], n_archivos_declarados=declared[1], truncado=shown,
            cwe=sorted(set(re.findall(r'CWE-\d+', block))), que=(q.group(1).strip() if q else ''), riesgo=(r.group(1).strip() if r else ''),
            esfuerzo_min=minutes,
            noact=('SIN ACCIÓN REQUERIDA' in block) or norisk or 'Riesgo real NULO' in block,
            patch=('SIN PARCHE AUTOMÁTICO' not in block) and ('SIN ACCIÓN REQUERIDA' not in block),
            sca=(list(sca.groups()) + [alc.group(1) if alc else None]) if sca else None))
    return items


def header_total(txt):
    """Total de hallazgos que declara el propio PDF («Se encontraron N hallazgos en total»): sirve para cuadrar lo parseado."""
    m = re.search(r'Se encontraron (\d+) hallazgos', re.sub(r'\s+', ' ', txt))
    return int(m.group(1)) if m else None


HEADER = {}


def main(d, out, prefix='', grupo=None):
    res = {}
    for f in sorted(glob.glob(os.path.join(d, prefix + '*.txt'))):
        name = os.path.basename(f)[len(prefix):-4]
        if name.upper().startswith('GENERAL') or 'GENERAL' in name.upper():
            continue
        raw = open(f, encoding='utf-8', errors='ignore').read()
        items = parse_text(raw)
        HEADER[name] = header_total(raw)
        if grupo and items and not (items[0]['asset'] or '').startswith(grupo):
            continue
        res[name] = items
    json.dump(res, open(out, 'w'), ensure_ascii=False, indent=1)
    for repo, items in res.items():
        s = {}
        for it in items:
            s[it['sev']] = s.get(it['sev'], 0) + it['n']
        trunc = sum(1 for it in items if it['n_ubic_declaradas'] and sum(max(1, len(u['lines'])) for u in it['ubicaciones']) < it['n_ubic_declaradas'])
        total, decl = sum(it['n'] for it in items), HEADER.get(repo)
        cuadre = 'sin dato' if decl is None else ('OK' if decl == total else f'ALERTA: el PDF declara {decl}')
        print(f"{repo:36} reglas={len(items):3} ocurrencias={total:4} cuadre_con_encabezado={cuadre}  {s}  reglas_con_ubicaciones_incompletas={trunc} (truncadas por el PDF: {sum(1 for it in items if it['truncado'])})")


if __name__ == '__main__':
    args = [a for a in sys.argv[1:] if not a.startswith('--')]
    grupo = sys.argv[sys.argv.index('--grupo') + 1] if '--grupo' in sys.argv else None
    if grupo:
        args = [a for a in args if a != grupo]
    if len(args) < 2:
        sys.exit(__doc__)
    main(args[0], args[1], args[2] if len(args) > 2 else '', grupo)
