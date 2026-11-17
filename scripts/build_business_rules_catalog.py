"""Convert data/Catalogo_reglas_negocio_CORE_STARTER.xlsx into the skill references (JSON + Markdown). Stdlib only.
Usage: python3 scripts/build_business_rules_catalog.py <xlsx> <out.json> <out.md>"""
import zipfile, sys, json, xml.etree.ElementTree as ET
NS = {'m': 'http://schemas.openxmlformats.org/spreadsheetml/2006/main'}
R = '{http://schemas.openxmlformats.org/officeDocument/2006/relationships}id'
z = zipfile.ZipFile(sys.argv[1]); out_json, out_md = sys.argv[2], sys.argv[3]
ss = [''.join(t.text or '' for t in si.iter('{%s}t' % NS['m'])) for si in ET.fromstring(z.read('xl/sharedStrings.xml')).findall('m:si', NS)]
rels = {r.get('Id'): r.get('Target') for r in ET.fromstring(z.read('xl/_rels/workbook.xml.rels'))}
def rows(name):
    for s in ET.fromstring(z.read('xl/workbook.xml')).find('m:sheets', NS):
        if s.get('name') == name:
            t = rels[s.get(R)].lstrip('/'); t = t if t.startswith('xl/') else 'xl/' + t
            for row in ET.fromstring(z.read(t)).iter('{%s}row' % NS['m']):
                vals = []
                for c in row.findall('m:c', NS):
                    v = c.find('m:v', NS)
                    vals.append(ss[int(v.text)] if c.get('t') == 's' and v is not None else (v.text if v is not None else ''))
                if any(vals): yield vals
cat = list(rows('Catálogo general')); hdr = cat[0]
keys = ['id', 'modulo', 'entidad', 'regla', 'origen', 'tipo_dato', 'mascara', 'por_confirmar', 'manual', 'paginas', 'estado']
assert len(hdr) == len(keys), hdr
reglas = [dict(zip(keys, (r + [''] * 11)[:11])) for r in cat[1:]]
criterios = [r[0] for r in rows('Criterios y alcance')]
json.dump({'fuente': 'Catalogo_reglas_negocio_CORE_STARTER.xlsx', 'recibido': '2026-10-28', 'criterios': criterios, 'reglas': reglas},
          open(out_json, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
esc = lambda x: str(x).replace('|', '\\|').replace('\n', ' ')
with open(out_md, 'w', encoding='utf-8') as f:
    f.write('# Catálogo de reglas de negocio — CORE / Starter\n\nGenerado desde `Catalogo_reglas_negocio_CORE_STARTER.xlsx` (recibido 2026-10-28) con '
            '`scripts/build_business_rules_catalog.py`. No editar a mano: la hoja de cálculo es la fuente.\n\n## Criterios del catálogo\n\n')
    for c in criterios[1:]: f.write(f'- {c}\n')
    mod = None
    for r in reglas:
        if r['modulo'] != mod:
            mod = r['modulo']; f.write(f'\n## {mod}\n\n| ID | Entidad / campo | Regla | Origen | Máscara / patrón | Por confirmar | Estado |\n|---|---|---|---|---|---|---|\n')
        f.write('| ' + ' | '.join(esc(r[k]) for k in ['id', 'entidad', 'regla', 'origen', 'mascara', 'por_confirmar', 'estado']) + ' |\n')
print(len(reglas), {o: sum(1 for r in reglas if r['origen'] == o) for o in {r['origen'] for r in reglas}})
