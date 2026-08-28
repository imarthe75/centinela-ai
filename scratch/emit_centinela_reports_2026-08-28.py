"""
Re-emit the SIAT / SIDECO security reports in Centinela-AI's own PDF house style
(the same CIVIKA_PDF_STYLES + build_pdf_header + weasyprint pipeline main.py uses for
/api/reports/*), and write the PDFs to docs/reportes/ .

Source: the two combined HTML reports authored this session
  - scratch/... reporte_completo.html          -> Reporte Completo (7 codebases + servidor)
  - scratch/... reporte_citas_solicitud.html   -> Reporte acotado (Citas + Solicitud Web)

They are transformed (class remap) into Centinela's card/kpi/table/badge components,
wrapped in the branded header/footer, and rendered with the same weasyprint engine.
"""
import sys, re, os
sys.path.insert(0, "/app")

from datetime import datetime
import main as centinela   # CIVIKA_PDF_STYLES, build_pdf_header, render_pdf_with_weasyprint

SRC_DIR = "/app/scratch/_report_src"   # HTML sources copied in by the wrapper
OUT_DIR = "/app/docs/reportes"

REPORTS = [
    ("reporte_citas_solicitud.html",
     "Reporte_Citas_SolicitudWeb_Centinela_2026-08-28.pdf",
     "Reporte de Seguridad — Cita en Línea y Solicitud Web",
     "siat-atencion-citas · sideco-solicitud-web (rama develop) · servidor 10.4.2.185"),
    ("reporte_completo.html",
     "Reporte_Completo_SIAT_SIDECO_Centinela_2026-08-28.pdf",
     "Reporte de Seguridad — SIAT y SIDECO (completo)",
     "7 bases de código · servidor 10.4.2.185 · 2 frontends desplegados"),
]

# ---- extra CSS for the classes we keep from the source that Centinela's sheet doesn't define
EXTRA_CSS = """
.eyebrow{display:none;}
.sub{font-size:9.5px;color:#475569;margin:4px 0 8px;line-height:1.6;}
.meta{font-size:8px;color:#64748b;margin:4px 0 2px;}
.meta span{margin-right:14px;}
.conf{display:none;}
.note{background:#f1f5f9;border:1px solid #e2e8f0;border-left:3px solid #1a3a5c;border-radius:4px;padding:8px 12px;font-size:9px;color:#475569;margin:10px 0;}
.blk{margin:6px 0;}
.blk .lbl{display:inline-block;font-size:7.5px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:#1a3a5c;background:#e2e8f0;padding:1px 6px;border-radius:2px;margin-bottom:3px;}
.blk.fix .lbl{background:#1a3a5c;color:#fff;}
.blk p{font-size:9px;margin:2px 0;line-height:1.55;}
.f-head{margin-bottom:2px;}
.rule{font-family:'DM Mono','Consolas',monospace;font-size:7.5px;color:#64748b;}
.loclist{font-family:'DM Mono','Consolas',monospace;font-size:8px;color:#334155;background:#f1f5f9;border:1px solid #e2e8f0;border-radius:3px;padding:6px 8px;margin:4px 0;}
.loclist div{padding:1px 0;}
.loclist code{background:transparent;color:#0f172a;padding:0;font-size:8px;}
.action{background:#f8fafc;border:1px solid #e2e8f0;border-radius:4px;padding:6px 10px;margin:4px 0;font-size:9px;}
.action .p{font-weight:700;font-size:7.5px;letter-spacing:.05em;text-transform:uppercase;color:#1a3a5c;margin-right:8px;}
.action.now .p{color:#dc2626;} .action.soon .p{color:#d97706;} .action.plan .p{color:#1a3a5c;}
.dast-group{background:#f8fafc;border:1px solid #e2e8f0;border-left:3px solid #64748b;border-radius:6px;padding:10px 12px;margin:8px 0;}
.dast-group .gh{font-weight:700;font-size:9.5px;margin-bottom:4px;}
.dast-group .cnt{font-family:'DM Mono','Consolas',monospace;font-size:8px;color:#64748b;font-weight:400;}
.dast-group ul{margin:4px 0 0 14px;font-size:8.5px;line-height:1.5;}
h2 .n{color:#64748b;font-family:'DM Mono','Consolas',monospace;font-size:10px;margin-right:6px;}
.card h4{font-size:10px;font-weight:700;color:#0f172a;margin:3px 0 2px;}
.kpi-grid{grid-template-columns:repeat(5,1fr);}
ul.plain,.card ul{margin:4px 0 4px 16px;font-size:9px;line-height:1.5;}
.card pre, .blk pre{white-space:pre-wrap;}
.tech{font-size:8px;color:#64748b;}
table td code{font-size:8px;background:transparent;color:#0f172a;padding:0;}
"""

# ---- class remap: source classes -> Centinela components
def transform(body: str) -> str:
    # finding cards
    body = body.replace('class="f crit"', 'class="card card-crit"')
    body = body.replace('class="f high"', 'class="card card-warn"')
    body = body.replace('class="f med"',  'class="card card-tech"')
    body = body.replace('class="f low"',  'class="card card-tech"')
    body = body.replace('class="f "', 'class="card"').replace('class="f"', 'class="card"')
    # severity chips -> badges
    body = body.replace('class="sev crit"', 'class="badge badge-critical"')
    body = body.replace('class="sev high"', 'class="badge badge-high"')
    body = body.replace('class="sev med"',  'class="badge badge-medium"')
    body = body.replace('class="sev low"',  'class="badge badge-low"')
    body = body.replace('class="sev ok"',   'class="badge badge-info"')
    body = body.replace('class="sev grade-f"', 'class="badge badge-critical"')
    body = body.replace('class="sev info"', 'class="badge badge-info"')
    # kpi tiles
    body = body.replace('class="kpi-row"', 'class="kpi-grid"')
    body = body.replace('class="kpi c"', 'class="kpi-card kpi-crit"')
    body = body.replace('class="kpi h"', 'class="kpi-card kpi-high"')
    body = body.replace('class="kpi m"', 'class="kpi-card"')
    body = body.replace('class="kpi l2"', 'class="kpi-card"')
    body = body.replace('class="kpi i"', 'class="kpi-card"')
    body = body.replace('<div class="v">', '<div class="kpi-num">')
    body = body.replace('<div class="l">', '<div class="kpi-label">')
    # table wrappers -> plain (Centinela tables are full width already)
    body = body.replace('<div class="table-wrap">', '<div>').replace('</table></div>', '</table></div>')
    # drop the source masthead <header> ... </header> (we add Centinela's own)
    body = re.sub(r'<header class="masthead">.*?</header>', '', body, flags=re.S)
    # section headings: <h2><span class="n">§N</span>Text</h2>
    body = body.replace('<span class="n">', '<span class="n">§').replace('§§', '§')
    return body

def build(src_html: str, title: str, subtitle: str) -> str:
    m = re.search(r'<div class="wrap">(.*)</div>\s*</body>', src_html, flags=re.S)
    body = m.group(1) if m else src_html
    body = transform(body)
    gen_date = datetime.now().strftime("%d/%m/%Y %H:%M")
    return f"""<!DOCTYPE html><html lang='es'><head><meta charset='UTF-8'>
<title>{title} — Centinela-AI</title>
<style>{centinela.CIVIKA_PDF_STYLES}
{EXTRA_CSS}</style></head><body>
{centinela.build_pdf_header(title, subtitle, gen_date)}
{body}
<div class='pdf-footer-bar'>
  Centinela-AI | CASMARTS Ecosistema de Seguridad | Clasificación: CONFIDENCIAL | Estándar CVSS v3 · OWASP · CIS Benchmarks
</div>
</body></html>"""

def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    for src_name, out_name, title, subtitle in REPORTS:
        src_path = os.path.join(SRC_DIR, src_name)
        html = open(src_path, encoding="utf-8").read()
        full = build(html, title, subtitle)
        pdf = centinela.render_pdf_with_weasyprint(full)
        out_path = os.path.join(OUT_DIR, out_name)
        with open(out_path, "wb") as f:
            f.write(pdf)
        print(f"  ✓ {out_name}  ({len(pdf)//1024} KB)")
    print(f"\nGuardados en {OUT_DIR}")


if __name__ == "__main__":
    main()
