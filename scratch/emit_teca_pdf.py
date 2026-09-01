"""Render the teca report HTML to a PDF in docs/reportes/ via weasyprint (same engine main.py uses)."""
import sys
sys.path.insert(0, "/app")
from weasyprint import HTML

SRC = "/app/scratch/reporte_teca_2026-09-01.html"
OUT = "/app/docs/reportes/Reporte_TECA_Centinela_2026-09-01.pdf"

body = open(SRC, encoding="utf-8").read()
# the artifact file has no <html>/<head>/<body> wrapper (that's added at publish time) -- wrap it
full = f"<!DOCTYPE html><html lang='es'><head><meta charset='UTF-8'>{body}</head><body></body></html>" \
       if body.lstrip().startswith("<title>") else body
# actually the file is <title>..<style>..</style><div class=wrap>..</div> -- valid enough for weasyprint
# once wrapped in <html><body>
full = f"<!DOCTYPE html><html lang='es'><head><meta charset='UTF-8'>\n{body}\n</body></html>"
pdf = HTML(string=full, base_url=None).write_pdf()
open(OUT, "wb").write(pdf)
print(f"wrote {OUT} ({len(pdf)//1024} KB)")
