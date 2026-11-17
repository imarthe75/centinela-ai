#!/usr/bin/env python3
"""Genera la matriz de seguimiento en Excel (con fórmulas) a partir de JSON.

Uso: python build_matrix_xlsx.py matriz.json params.json salida.xlsx [hojas_extra.json]

- matriz.json : lista de registros con el esquema de references/matriz_schema.md
- params.json : fecha base, SLAs, gerencias/escalamiento, firmas (plantilla en el mismo archivo)
- hojas_extra : opcional; lista de {"nombre","titulo","subtitulo","columnas":[...],"filas":[[...]],"anchos":[...]}
                para Cruce, Cuadre, Evaluación de analistas, Infraestructura, etc. Las celdas que
                empiecen con "=" se escriben como fórmula.
Después ejecutar el recalc.py del skill xlsx y verificar cero errores.
"""
import json, sys, datetime
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter as L
from openpyxl.worksheet.datavalidation import DataValidation
from openpyxl.formatting.rule import CellIsRule, FormulaRule

FN = 'Arial'
H = Font(name=FN, bold=True, color='FFFFFF', size=10); HF = PatternFill('solid', fgColor='1F3864')
N = Font(name=FN, size=10); B = Font(name=FN, size=10, bold=True); T = Font(name=FN, size=14, bold=True, color='1F3864')
INP = PatternFill('solid', fgColor='FFF2CC'); BLUE = Font(name=FN, size=10, color='0000FF')
thin = Side(style='thin', color='BFBFBF'); BOR = Border(left=thin, right=thin, top=thin, bottom=thin)
WR = Alignment(wrap_text=True, vertical='top')
SEG = {'Seguridad', 'Dependencias (SCA)', 'CI/CD', 'Infraestructura (IaC)'}
EST = ['Abierto', 'En corrección', 'Corregido – por validar', 'Cerrado (validado)', 'Validar falso positivo',
       'Falso positivo aceptado', 'Riesgo aceptado', 'Duplicado (ver principal)']
SEVS = ['Crítica', 'Alta', 'Media', 'Baja', 'Informativa']

def hdr(ws, row, cols, widths=None):
    for i, c in enumerate(cols, 1):
        x = ws.cell(row=row, column=i, value=c); x.font = H; x.fill = HF; x.border = BOR
        x.alignment = Alignment(wrap_text=True, vertical='center')
    for i, w in enumerate(widths or [], 1): ws.column_dimensions[L(i)].width = w

def put(ws, row, vals, font=N):
    for i, v in enumerate(vals, 1):
        x = ws.cell(row=row, column=i, value=v); x.font = font; x.alignment = WR; x.border = BOR

def evid(r, firma_seg):
    t = r['Tipo']
    if r['Sev'] == 'Informativa': return ('Justificación técnica del falso positivo, con fecha de revisión', 'Aprobación del Director de Tecnología')
    if r.get('Secreto') == 'Sí': return ('Ticket de rotación + valor retirado del repositorio + purga del historial git', 'Escaneo de secretos del historial + prueba de que la credencial anterior ya no autentica')
    if t == 'Seguridad': return ('Merge Request: commit, revisor distinto del autor, centinela/security en verde', 'Re-escaneo de Centinela (huella RESOLVED) + prueba autenticada multirol cuando aplique')
    if t == 'Dependencias (SCA)': return ('package-lock/pom actualizado a versión segura', 'Re-escaneo SCA sin la CVE')
    if t == 'CI/CD': return ('Exportación de la configuración del proyecto por API de GitLab', 'Re-escaneo gitlab-config')
    if t == 'Infraestructura (IaC)': return ('Manifiesto corregido vía MR', 'Re-escaneo + verificación en el entorno por Infraestructura')
    return ('Merge Request con pruebas unitarias o de integración', 'Prueba funcional o de carga por QA + re-escaneo cuando aplique')

def main(mpath, ppath, out, xpath=None):
    M = json.load(open(mpath)); P = json.load(open(ppath))
    X_extra = json.load(open(xpath)) if xpath else []
    wb = Workbook()
    # Léeme
    ws = wb.active; ws.title = 'Léeme'
    ws['A1'] = P.get('titulo', 'Matriz de seguimiento de hallazgos de seguridad'); ws['A1'].font = T
    dup = sum(1 for r in M if r.get('Principal', 'Sí') == 'No')
    lee = P.get('leeme', []) + [
        ['Registros', f'{len(M)} en la hoja Matriz; {dup} duplicados (Registro principal = No) no cuentan en el Resumen.'],
        ['Celdas editables', 'Fondo amarillo: Parámetros (fecha base, SLAs, gerencias) y en Matriz: Gerencia responsable, Apoyo, Estatus, Fecha de cierre real, Notas.'],
        ['Fórmulas', 'Titular, escalamiento, días y fechas de contención/compromiso y días para vencer se calculan solos.'],
        ['Ejemplo', 'Al corregirse un hallazgo: Estatus = "Corregido – por validar", Notas = "MR !123". Tras re-escaneo y prueba: "Cerrado (validado)" y la fecha de firma.'],
        ['Advertencia', 'Esta matriz no reproduce secretos. Si los documentos fuente los traen, distribúyelos con restricción y rota las credenciales.']]
    for i, (a, b) in enumerate(lee, 3):
        ws.cell(row=i, column=1, value=a).font = B; c = ws.cell(row=i, column=2, value=b); c.font = N; c.alignment = WR
    ws.column_dimensions['A'].width = 22; ws.column_dimensions['B'].width = 130
    # Parámetros
    Pm = wb.create_sheet('Parámetros'); Pm['A1'] = 'Parámetros del modelo de seguimiento'; Pm['A1'].font = T
    Pm['A3'] = 'Fecha base de seguimiento'; Pm['A3'].font = B
    Pm['B3'] = datetime.date.fromisoformat(P['fecha_base']); Pm['B3'].number_format = 'dd/mm/yyyy'; Pm['B3'].fill = INP; Pm['B3'].font = BLUE
    Pm['A4'] = 'Días de contención para secreto expuesto'; Pm['A4'].font = B; Pm['B4'] = P.get('dias_secreto', 1); Pm['B4'].fill = INP; Pm['B4'].font = BLUE
    Pm['A6'] = 'Tabla de SLAs (días naturales)'; Pm['A6'].font = B
    hdr(Pm, 7, ['Clave', 'Clase SLA', 'Severidad', 'Días contención', 'Días corrección', 'Fundamento'])
    for i, s in enumerate(P['slas'], 8):
        put(Pm, i, [f'=B{i}&"|"&C{i}', s['clase'], s['severidad'], s.get('contencion', ''), s['correccion'], s.get('fundamento', '')])
        for col in (4, 5): Pm.cell(row=i, column=col).fill = INP; Pm.cell(row=i, column=col).font = BLUE
    S1, S2 = 8, 7 + len(P['slas'])
    g0 = S2 + 3; Pm.cell(row=g0 - 1, column=1, value='Gerencias, titulares y escalamiento').font = B
    hdr(Pm, g0, ['Gerencia', 'Titular', 'Escalamiento N3', 'Escalamiento N4', 'Dirección', 'Nota'])
    for i, g in enumerate(P['gerencias'], g0 + 1):
        put(Pm, i, [g['gerencia'], g['titular'], g['n3'], g.get('n4', 'Dirección General'), g.get('direccion', ''), g.get('nota', '')])
        for col in (1, 2, 3, 4): Pm.cell(row=i, column=col).fill = INP
    G1, G2 = g0 + 1, g0 + len(P['gerencias'])
    e0 = G2 + 3; Pm.cell(row=e0 - 1, column=1, value='Valores de Estatus').font = B
    for i, e in enumerate(EST, e0): Pm.cell(row=i, column=1, value=e).font = N
    E1, E2 = e0, e0 + len(EST) - 1
    for col, w in zip('ABCDEF', [44, 22, 44, 22, 26, 70]): Pm.column_dimensions[col].width = w
    # Matriz
    X = wb.create_sheet('Matriz')
    cols = ['ID', 'Origen', 'Fuente (archivo y sección)', 'Fecha de la fuente', 'Repositorio', 'Módulo', 'Capa', 'Tipo', 'Clase SLA', 'ID original', 'Hallazgo', 'Ubicación', 'Ocurrencias', 'Sev. auditoría', 'Sev. Centinela', 'Sev. consolidada', 'CWE', 'Regla Centinela', 'Regla en catálogo', 'Cobertura (a/b/c/d)', 'Relación / evidencia cruzada', 'Secreto expuesto', 'Registro principal', 'Gerencia responsable', 'Titular', 'Apoyo', 'Escalamiento N3', 'Días contención', 'Fecha límite contención', 'Días corrección', 'Fecha compromiso', 'Evidencia de cierre requerida', 'Método de validación', 'Valida / firma', 'Estatus', 'Fecha de cierre real', 'Días para vencer', 'Notas']
    hdr(X, 1, cols, [16, 10, 34, 11, 16, 22, 13, 15, 11, 16, 50, 40, 9, 10, 10, 11, 14, 26, 14, 10, 45, 9, 9, 26, 18, 26, 30, 9, 12, 9, 12, 40, 40, 30, 20, 12, 10, 45])
    gA = f'Parámetros!$A${G1}:$A${G2}'; key = f'Parámetros!$A${S1}:$A${S2}'
    for i, r in enumerate(M, 2):
        clase = 'Seguridad' if r['Tipo'] in SEG else 'No seguridad'
        ev, va = evid(r, P['firma_seguridad'])
        princ = r.get('Principal', 'Sí')
        est = r.get('Estatus') or ('Duplicado (ver principal)' if princ == 'No' else ('Validar falso positivo' if r['Sev'] == 'Informativa' else 'Abierto'))
        vals = [r['ID'], r['Origen'], r.get('Fuente', ''), r.get('FechaFuente', ''), r.get('Repositorio', ''), r.get('Modulo', ''), r.get('Capa', ''), r['Tipo'], clase, r.get('IDorig', ''), r['Titulo'], r.get('Ubicacion', ''), r.get('Ocurr', 1), r.get('SevAuditoria', ''), r.get('SevCent', ''), r['Sev'], r.get('CWE', ''), r.get('Regla', ''), r.get('EnCatalogo', ''), r.get('Cobertura', ''), r.get('Relacion', ''), r.get('Secreto', 'No'), princ, r['Gerencia'],
                f'=IFERROR(INDEX(Parámetros!$B${G1}:$B${G2},MATCH(X{i},{gA},0)),"")', r.get('Apoyo', ''),
                f'=IFERROR(INDEX(Parámetros!$C${G1}:$C${G2},MATCH(X{i},{gA},0)),"")',
                f'=IF(W{i}<>"Sí","",IF(V{i}="Sí",Parámetros!$B$4,IFERROR(INDEX(Parámetros!$D${S1}:$D${S2},MATCH(I{i}&"|"&P{i},{key},0)),"")))',
                f'=IF(OR(AB{i}="",AB{i}=0),"",Parámetros!$B$3+AB{i})',
                f'=IF(W{i}<>"Sí","",IFERROR(INDEX(Parámetros!$E${S1}:$E${S2},MATCH(I{i}&"|"&P{i},{key},0)),""))',
                f'=IF(AD{i}="","",Parámetros!$B$3+AD{i})',
                ev, va, P['firma_seguridad'] if clase == 'Seguridad' else P['firma_no_seguridad'], est, None,
                f'=IF(OR(AE{i}="",AI{i}="Cerrado (validado)",AI{i}="Falso positivo aceptado",AI{i}="Riesgo aceptado",AI{i}="Duplicado (ver principal)"),"",AE{i}-TODAY())',
                r.get('Nota', '')]
        put(X, i, vals)
        for c in (29, 31, 36): X.cell(row=i, column=c).number_format = 'dd/mm/yyyy'
        for c in (24, 26, 35, 36, 38): X.cell(row=i, column=c).fill = INP
    last = len(M) + 1
    dv = DataValidation(type='list', formula1=f'=Parámetros!$A${E1}:$A${E2}'); X.add_data_validation(dv); dv.add(f'AI2:AI{last}')
    dv2 = DataValidation(type='list', formula1=f'=Parámetros!$A${G1}:$A${G2}'); X.add_data_validation(dv2); dv2.add(f'X2:X{last}')
    X.freeze_panes = 'C2'; X.auto_filter.ref = f'A1:{L(len(cols))}{last}'; X.row_dimensions[1].height = 42
    red = PatternFill('solid', fgColor='F8CBAD'); org = PatternFill('solid', fgColor='FCE4D6'); yel = PatternFill('solid', fgColor='FFF2CC'); grn = PatternFill('solid', fgColor='E2EFDA')
    X.conditional_formatting.add(f'P2:P{last}', CellIsRule(operator='equal', formula=['"Crítica"'], fill=red))
    X.conditional_formatting.add(f'P2:P{last}', CellIsRule(operator='equal', formula=['"Alta"'], fill=org))
    X.conditional_formatting.add(f'AK2:AK{last}', FormulaRule(formula=['AND(ISNUMBER(AK2),AK2<0)'], fill=red))
    X.conditional_formatting.add(f'AK2:AK{last}', FormulaRule(formula=['AND(ISNUMBER(AK2),AK2>=0,AK2<=7)'], fill=yel))
    X.conditional_formatting.add(f'AI2:AI{last}', CellIsRule(operator='equal', formula=['"Cerrado (validado)"'], fill=grn))
    MR = f'Matriz!$W$2:$W${last}'; rng = lambda c: f'Matriz!${c}$2:${c}${last}'
    # Resumen
    R = wb.create_sheet('Resumen', 1); R['A1'] = 'Resumen (solo registros principales)'; R['A1'].font = T
    row = 4; R.cell(row=3, column=1, value='Abiertos por gerencia y severidad').font = B
    hdr(R, row, ['Gerencia'] + SEVS + ['Total'])
    closed = ['Cerrado (validado)', 'Falso positivo aceptado', 'Riesgo aceptado']
    for j, g in enumerate([g['gerencia'] for g in P['gerencias']], row + 1):
        R.cell(row=j, column=1, value=g).font = N
        for k, s in enumerate(SEVS, 2):
            base = f'{MR},"Sí",{rng("X")},$A{j},{rng("P")},"{s}"'
            f = f'=COUNTIFS({base})' + ''.join(f'-COUNTIFS({base},{rng("AI")},"{c}")' for c in closed)
            R.cell(row=j, column=k, value=f).font = N
        R.cell(row=j, column=7, value=f'=SUM(B{j}:F{j})').font = B
    tj = row + 1 + len(P['gerencias']); R.cell(row=tj, column=1, value='Total').font = B
    for k in range(2, 8): R.cell(row=tj, column=k, value=f'=SUM({L(k)}{row+1}:{L(k)}{tj-1})').font = B
    row = tj + 3; R.cell(row=row - 1, column=1, value='Por tipo').font = B
    hdr(R, row, ['Tipo', 'Total', 'Crítica', 'Alta'])
    tipos = sorted({r['Tipo'] for r in M})
    for j, t in enumerate(tipos, row + 1):
        R.cell(row=j, column=1, value=t).font = N
        R.cell(row=j, column=2, value=f'=COUNTIFS({MR},"Sí",{rng("H")},$A{j})').font = N
        for k, s in ((3, 'Crítica'), (4, 'Alta')):
            R.cell(row=j, column=k, value=f'=COUNTIFS({MR},"Sí",{rng("H")},$A{j},{rng("P")},"{s}")').font = N
    row = row + len(tipos) + 3; R.cell(row=row - 1, column=1, value='Cobertura de Centinela sobre seguridad de la auditoría').font = B
    hdr(R, row, ['Clase', 'Hallazgos'])
    for j, c in enumerate('abcd', row + 1):
        R.cell(row=j, column=1, value=c).font = N
        R.cell(row=j, column=2, value=f'=COUNTIFS({MR},"Sí",{rng("T")},$A{j},{rng("H")},"Seguridad")').font = N
    row = row + 7; R.cell(row=row - 1, column=1, value='Indicadores').font = B
    hdr(R, row, ['Indicador', 'Valor'])
    ind = [('Registros principales', f'=COUNTIFS({MR},"Sí")'),
           ('Cerrados y validados', f'=COUNTIFS({MR},"Sí",{rng("AI")},"Cerrado (validado)")'),
           ('% cerrados y validados', f'=IFERROR(B{row+2}/B{row+1},0)'),
           ('Corregidos por validar', f'=COUNTIFS({MR},"Sí",{rng("AI")},"Corregido – por validar")'),
           ('Vencidos', f'=COUNTIFS({MR},"Sí",{rng("AK")},"<0")'),
           ('Vencen en 7 días o menos', f'=COUNTIFS({MR},"Sí",{rng("AK")},">=0",{rng("AK")},"<=7")'),
           ('Secretos expuestos sin cerrar', f'=COUNTIFS({MR},"Sí",{rng("V")},"Sí")-COUNTIFS({MR},"Sí",{rng("V")},"Sí",{rng("AI")},"Cerrado (validado)")')]
    for j, (a, f) in enumerate(ind, row + 1):
        R.cell(row=j, column=1, value=a).font = N; R.cell(row=j, column=2, value=f).font = B
    R.cell(row=row + 3, column=2).number_format = '0.0%'
    for col, w in zip('ABCDEFG', [48, 14, 12, 12, 12, 12, 10]): R.column_dimensions[col].width = w
    # Hojas extra
    for sh in X_extra:
        S = wb.create_sheet(sh['nombre'][:31]); S['A1'] = sh.get('titulo', sh['nombre']); S['A1'].font = T
        if sh.get('subtitulo'): S['A2'] = sh['subtitulo']; S['A2'].font = N
        hdr(S, 4, sh['columnas'], sh.get('anchos'))
        for i, f in enumerate(sh['filas'], 5): put(S, i, f)
        S.freeze_panes = 'A5'
    wb.move_sheet('Parámetros', offset=len(wb.sheetnames))
    wb.save(out); print(f'Guardado {out}: {len(M)} registros, {len(X_extra)} hojas extra')

if __name__ == '__main__':
    if len(sys.argv) < 4: sys.exit(__doc__)
    main(*sys.argv[1:])
