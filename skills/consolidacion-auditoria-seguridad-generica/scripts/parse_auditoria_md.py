#!/usr/bin/env python3
"""Extrae hallazgos de reportes de auditoría de código en Markdown.

Uso: python parse_auditoria_md.py <archivo.md> [<archivo.md> ...] > auditoria.json

Formatos reconocidos (los de los reportes de auditoría habituales):
  Backend : secciones "## 2." a "## 4." con encabezados "### CRIT-01: ..." / MED- / MEN- / MIN-
            CRIT=Crítica, MED=Media, MEN/MIN=Baja. Toma ubicaciones de los enlaces [Archivo.java](...#L10).
  Frontend: sección "## 1x. Clasificación de hallazgos" con subtítulos de severidad
            (CRÍTICO/ALTO/MEDIO/BAJO, en lista o en ###) y viñetas; o bien "### Hallazgo N:"
            con línea "Severidad:".
Si un reporte tiene otro formato, el script lo reporta en stderr: extráelo a mano.
Recuerda registrar aparte los riesgos de las secciones "Riesgos de seguridad" que no
tengan número propio.
"""
import re, sys, json
SEVMAP = {'CRIT': 'Crítica', 'MED': 'Media', 'MEN': 'Baja', 'MIN': 'Baja'}
SV = {'CRÍTICO': 'Crítica', 'CRITICO': 'Crítica', 'CRÍTICOS': 'Crítica', 'ALTO': 'Alta', 'ALTOS': 'Alta',
      'MEDIO': 'Media', 'MEDIOS': 'Media', 'BAJO': 'Baja', 'BAJOS': 'Baja'}

def fecha(t):
    m = re.search(r'Fecha[^:\n]*:\**\s*([^\n|]+)', t)
    return m.group(1).strip(' *') if m else 's/f'

def backend(t, f):
    m = re.search(r'\n## 2\..*?(?=\n## 5\.)', t, re.S)
    if not m: return []
    rows = []
    for p in re.split(r'\n(?=### )', m.group(0)):
        h = re.match(r'### \[?((CRIT|MED|MEN|MIN)-\d+)\]?:?\s*(.*)', p.split('\n')[0])
        if not h: continue
        locs = []
        for a, b, c in re.findall(r'\[`?([A-Za-z0-9_.\-]+\.(?:java|ts|properties|yml|yaml|sql|html))(?::([\d\-]+))?`?\]\([^)]*?(?:#L(\d+(?:-L?\d+)?))?\)', p):
            s = a + (':' + (b or c).replace('L', '') if (b or c) else '')
            if s not in locs: locs.append(s)
        rows.append(dict(doc=f, capa='Backend', oid=h.group(1), tit=h.group(3).replace('`', '').strip(),
                         sev=SEVMAP[h.group(2)], loc='; '.join(locs), cwe=sorted(set(re.findall(r'CWE-\d+', p)))))
    return rows

def frontend(t, f):
    rows = []
    hs = re.findall(r'\n### Hallazgo (\d+): (.*?)\n(.*?)(?=\n### |\n## |$)', t, re.S)
    if hs:
        for n, tit, body in hs:
            sv = re.search(r'Severidad:\*\*\s*\S*\s*(\w+)', body)
            fl = re.search(r'Archivos? afectados?:\*\*\s*(.*)', body)
            if sv and sv.group(1).upper() in SV:
                rows.append(dict(doc=f, capa='Frontend', oid=f'Hallazgo {n}', tit=tit.replace('`', ''),
                                 sev=SV[sv.group(1).upper()], loc=(fl.group(1) if fl else '').replace('`', ''), cwe=sorted(set(re.findall(r'CWE-\d+', tit)))))
        if rows: return rows
    m = re.search(r'\n## \d+\. Clasificaci.*?(?=\n## )', t, re.S)
    if not m: return []
    cur = None; i = 0
    for line in m.group(0).split('\n'):
        l = line.strip()
        s = re.match(r'^(?:###\s*|\*+\s*\*\*)([A-Za-zÁÉÍÓÚáéíóú]+)(?:\s*\((\d+)\))?:?\*?\*?:?\s*(.*)$', l)
        if s and s.group(1).upper() in SV:
            cur = SV[s.group(1).upper()]; rest = s.group(3).strip()
            if s.group(2) == '0': rest = ''
            if rest:
                i += 1; rows.append(dict(doc=f, capa='Frontend', oid=f'F-{i:02d}', tit=rest, sev=cur, loc='', cwe=[]))
            continue
        b = re.match(r'^(?:\d+\.|\*)\s+(.*)$', l)
        if b and cur:
            i += 1; txt = b.group(1)
            mid = re.match(r'\*\*([A-Z\-]+-\d+):\*\*\s*(.*)', txt)
            oid, tit = (mid.group(1), mid.group(2)) if mid else (f'F-{i:02d}', txt)
            rows.append(dict(doc=f, capa='Frontend', oid=oid, tit=re.sub(r'\*\*|`', '', tit).strip(), sev=cur, loc='',
                             cwe=sorted(set(re.findall(r'CWE-\d+', tit)))))
    return rows

def main(files):
    out = []
    for f in files:
        t = open(f, encoding='utf-8', errors='ignore').read().replace('\r', '')
        rows = backend(t, f) or frontend(t, f)
        for r in rows: r['fecha'] = fecha(t)
        if not rows: print(f'AVISO: formato no reconocido en {f}; extraer a mano', file=sys.stderr)
        else: print(f'{f}: {len(rows)} hallazgos', file=sys.stderr)
        out += rows
    json.dump(out, sys.stdout, ensure_ascii=False, indent=1)

if __name__ == '__main__':
    if len(sys.argv) < 2: sys.exit(__doc__)
    main(sys.argv[1:])
