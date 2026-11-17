#!/usr/bin/env python3
"""Extrae texto de los insumos del proyecto detectando su tipo REAL (no la extensión).

Uso: python extract_inputs.py <dir_origen> <dir_destino>

Casos cubiertos (observados en proyectos reales):
  - .pdf que en realidad es un ZIP con <n>.jpeg + <n>.txt por página -> concatena páginas.
  - .pdf real -> pdftotext -layout.
  - .docx que en realidad es texto/Markdown -> copia limpiando UTF-8 inválido.
  - .docx real (ZIP OOXML) -> pandoc a texto plano.
  - .md/.txt/.html -> copia (HTML sin etiquetas).
Imprime un inventario con tipo real, páginas y tamaño.
"""
import os, re, sys, zipfile, subprocess

def real_type(path):
    with open(path, 'rb') as f:
        head = f.read(8)
    if head.startswith(b'%PDF'): return 'pdf'
    if head.startswith(b'PK'):
        try:
            names = zipfile.ZipFile(path).namelist()
        except zipfile.BadZipFile:
            return 'zip?'
        if any(n.startswith('word/') for n in names): return 'docx'
        if any(re.fullmatch(r'\d+\.txt', n) for n in names): return 'zip-paginas'
        return 'zip'
    return 'texto'

def clean(b):
    return b.decode('utf-8', 'ignore').replace('\r', '')

def main(src, dst):
    os.makedirs(dst, exist_ok=True)
    print(f"{'archivo':70} {'tipo real':12} {'páginas':>7} {'chars':>9}")
    for name in sorted(os.listdir(src)):
        p = os.path.join(src, name)
        if not os.path.isfile(p): continue
        t = real_type(p); pages = ''
        out = os.path.join(dst, os.path.splitext(name)[0] + '.txt')
        if t == 'zip-paginas':
            z = zipfile.ZipFile(p)
            nums = sorted(int(n[:-4]) for n in z.namelist() if re.fullmatch(r'\d+\.txt', n))
            txt = ''.join(f'=== PAG {i} ===\n' + clean(z.read(f'{i}.txt')) + '\n' for i in nums)
            pages = len(nums)
        elif t == 'pdf':
            txt = subprocess.run(['pdftotext', '-layout', p, '-'], capture_output=True).stdout.decode('utf-8', 'ignore')
        elif t == 'docx':
            txt = subprocess.run(['pandoc', p, '-t', 'plain', '--wrap=none'], capture_output=True).stdout.decode('utf-8', 'ignore')
        else:
            txt = clean(open(p, 'rb').read())
            if name.lower().endswith('.html'):
                txt = re.sub(r'<[^>]+>', ' ', txt); txt = re.sub(r'[ \t]+', ' ', txt)
        txt = txt.replace('\x02', '-')  # guiones que llegan como carácter de control
        # Si un mismo nombre base existe en varias extensiones, no se sobrescriben entre sí
        if os.path.exists(out):
            out = out[:-4] + '_' + os.path.splitext(name)[1][1:] + '.txt'
        open(out, 'w', encoding='utf-8').write(txt)
        print(f"{name[:70]:70} {t:12} {str(pages):>7} {len(txt):>9}")

if __name__ == '__main__':
    if len(sys.argv) != 3: sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2])
