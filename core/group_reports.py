"""Reports for a group of assets (a GitLab group/subgroup/project, or any set of assets):

* group_summary() + render_group_general_html(): the consolidated "reporte general del grupo" (one row per asset, totals by effective
  severity, most frequent rules). Replaces the out-of-app scratch/build_group_reports.py for anything reachable from the UI.
* Bundles: a ZIP with the group report, the group comparison and every asset's own report. Building it takes ~20-40 s per asset, longer than
  any HTTP request may last, so it runs in a background thread with its progress in a status file. Files live under data/ (internal, never
  served statically, rule 9) and are downloaded only through the authenticated API.
"""
from __future__ import annotations

import html
import json
import logging
import os
import re
import shutil
import threading
import time
import uuid
import zipfile
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

OPEN_EXCLUDED = ("RESOLVED", "SUPPRESSED")
BUNDLE_DIR = os.getenv("REPORT_BUNDLE_DIR", "/app/data/report_bundles")
BUNDLE_TTL_HOURS = 24
BUNDLE_MAX_ASSETS = 200
STALE_SECONDS = 20 * 60          # a running bundle whose status file has not moved for this long died with its process

_worker_lock = threading.Semaphore(1)   # one bundle at a time: each asset PDF is CPU/memory heavy (WeasyPrint)


# --------------------------------------------------------------------------------------------------------------- group report
def group_summary(cur, asset_ids: List[str]) -> Dict[str, Any]:
    cur.execute("""
        SELECT i.id::text, i.asset_name, i.asset_type, i.last_audit,
               count(*) FILTER (WHERE v.finding_category IS DISTINCT FROM 'INFORMATIONAL' AND v.status NOT IN %(ex)s AND v.id IS NOT NULL) AS vulns,
               count(*) FILTER (WHERE v.finding_category IS DISTINCT FROM 'INFORMATIONAL' AND v.status NOT IN %(ex)s
                                AND upper(COALESCE(v.real_severity, v.severity)) = 'CRITICAL') AS crit,
               count(*) FILTER (WHERE v.finding_category IS DISTINCT FROM 'INFORMATIONAL' AND v.status NOT IN %(ex)s
                                AND upper(COALESCE(v.real_severity, v.severity)) = 'HIGH') AS high,
               count(*) FILTER (WHERE v.finding_category IS DISTINCT FROM 'INFORMATIONAL' AND v.status NOT IN %(ex)s
                                AND upper(COALESCE(v.real_severity, v.severity)) = 'MEDIUM') AS med,
               count(*) FILTER (WHERE v.finding_category IS DISTINCT FROM 'INFORMATIONAL' AND v.status NOT IN %(ex)s
                                AND upper(COALESCE(v.real_severity, v.severity)) = 'LOW') AS low,
               count(*) FILTER (WHERE v.finding_category = 'INFORMATIONAL' AND v.status NOT IN %(ex)s) AS info,
               count(*) FILTER (WHERE v.status = 'RESOLVED') AS resolved,
               count(*) FILTER (WHERE v.status = 'SUPPRESSED') AS suppressed
        FROM public.infra_inventory i
        LEFT JOIN public.vulnerability_log v ON v.asset_id = i.id
        WHERE i.id = ANY(%(ids)s::uuid[])
        GROUP BY i.id, i.asset_name, i.asset_type, i.last_audit
        ORDER BY i.asset_name
    """, {"ex": OPEN_EXCLUDED, "ids": list(asset_ids)})
    cols = [d[0] for d in cur.description]
    rows = [dict(zip(cols, r)) for r in cur.fetchall()]
    cur.execute("""
        SELECT v.cve_id,
               string_agg(DISTINCT upper(COALESCE(v.real_severity, v.severity)), ' / ') AS sev,   -- one row per rule; severities can differ per occurrence
               count(*) AS n, count(DISTINCT v.asset_id) AS assets
        FROM public.vulnerability_log v
        WHERE v.asset_id = ANY(%s::uuid[]) AND v.status NOT IN %s AND v.finding_category IS DISTINCT FROM 'INFORMATIONAL'
        GROUP BY 1 ORDER BY count(*) DESC LIMIT 15
    """, (list(asset_ids), OPEN_EXCLUDED))
    top = [{"cve_id": r[0], "severity": r[1], "count": r[2], "assets": r[3]} for r in cur.fetchall()]
    keys = ("vulns", "crit", "high", "med", "low", "info", "resolved", "suppressed")
    totals = {k: sum(int(r[k] or 0) for r in rows) for k in keys}
    return {"assets": rows, "top_rules": top, "totals": totals}


def _e(s: Any) -> str:
    return html.escape(str(s if s is not None else ""))


def _local_now() -> datetime:
    from zoneinfo import ZoneInfo
    try:
        return datetime.now(ZoneInfo(os.getenv("REPORT_TZ", "America/Mexico_City")))
    except Exception:
        logger.error("invalid REPORT_TZ", exc_info=True)
        return datetime.now()


def common_prefix(names: List[str]) -> str:
    """Longest common path prefix ending at '/', used to show short asset names inside a group report."""
    if not names:
        return ""
    p = os.path.commonprefix(names)
    return p[: p.rfind("/") + 1] if "/" in p else ""


def render_group_general_html(title: str, summary: Dict[str, Any]) -> str:
    t = summary["totals"]
    rows = summary["assets"]
    pre = common_prefix([r["asset_name"] for r in rows])
    now = _local_now().strftime("%Y-%m-%d %H:%M")
    body_rows = "".join(
        f"<tr><td>{_e(r['asset_name'][len(pre):] or r['asset_name'])}</td><td>{_e(str(r['last_audit'] or '—')[:16])}</td>"
        f"<td class='n crit'>{r['crit'] or ''}</td><td class='n high'>{r['high'] or ''}</td><td class='n'>{r['med'] or ''}</td>"
        f"<td class='n'>{r['low'] or ''}</td><td class='n'><b>{r['vulns']}</b></td><td class='n muted'>{r['info']}</td>"
        f"<td class='n'>{r['resolved']}</td></tr>" for r in rows)
    top_rows = "".join(f"<tr><td><code>{_e(x['cve_id'])}</code></td><td>{_e(x['severity'])}</td><td class='n'>{x['count']}</td>"
                       f"<td class='n'>{x['assets']}</td></tr>" for x in summary["top_rules"]) or "<tr><td colspan='4'>Sin vulnerabilidades abiertas.</td></tr>"
    return f"""<!doctype html><html lang="es"><head><meta charset="utf-8"><title>{_e(title)}</title><style>
@page{{size:A4 landscape;margin:12mm}}
body{{font-family:'DejaVu Sans','Segoe UI',Arial,sans-serif;color:#1d2433;font-size:11px;margin:24px}}
@media print{{body{{margin:0}}}}
h1{{color:#1f3a5f;font-size:20px;margin:0 0 4px}} h2{{color:#1f3a5f;font-size:14px;border-bottom:2px solid #1f3a5f;padding-bottom:3px;margin-top:20px}}
.muted{{color:#5b6475}} table{{width:100%;border-collapse:collapse;margin-top:6px}} th,td{{border:1px solid #d9dee7;padding:4px 6px;text-align:left}}
th{{background:#eef2f7}} td.n{{text-align:right;font-variant-numeric:tabular-nums}} .crit{{color:#b42318;font-weight:600}} .high{{color:#c2410c;font-weight:600}}
.kpis{{display:flex;gap:10px;margin:10px 0}} .kpi{{border:1px solid #d9dee7;border-radius:6px;padding:6px 12px}} .kpi b{{display:block;font-size:17px}}
code{{font-size:10px;word-break:break-all}}
</style></head><body>
<h1>{_e(title)}</h1>
<p class="muted">Reporte general del grupo · {len(rows)} activo(s){(' bajo <code>' + _e(pre) + '</code>') if pre else ''} · generado por Centinela-AI el {now} con datos en vivo de centinela_db.</p>
<div class="kpis">
 <div class="kpi">Vulnerabilidades abiertas<b>{t['vulns']}</b></div>
 <div class="kpi">Críticas<b class="crit">{t['crit']}</b></div>
 <div class="kpi">Altas<b class="high">{t['high']}</b></div>
 <div class="kpi">Medias<b>{t['med']}</b></div>
 <div class="kpi">Bajas<b>{t['low']}</b></div>
 <div class="kpi">Resueltas (histórico)<b>{t['resolved']}</b></div>
</div>
<p class="muted">Severidad efectiva (tras el análisis de riesgo real de Centinela). Además hay {t['info']} hallazgos informativos de calidad de código
(SonarQube, ISO 25010, CMMI) que no son vulnerabilidades, y {t['suppressed']} suprimidos por un analista.</p>
<h2>Por activo</h2>
<table><tr><th>Activo</th><th>Último análisis</th><th class="n">Crít.</th><th class="n">Altas</th><th class="n">Medias</th><th class="n">Bajas</th>
<th class="n">Total vuln.</th><th class="n">Informativos</th><th class="n">Resueltas</th></tr>{body_rows}</table>
<h2>Reglas más frecuentes (vulnerabilidades abiertas)</h2>
<table><tr><th>Regla</th><th>Severidad</th><th class="n">Ocurrencias</th><th class="n">Activos</th></tr>{top_rows}</table>
<p class="muted">El detalle de cada hallazgo, su análisis y los pasos de corrección están en el reporte individual de cada activo.</p>
</body></html>"""


# --------------------------------------------------------------------------------------------------------------- bundles
def _safe(s: str, maxlen: int = 150) -> str:
    return re.sub(r"[^A-Za-z0-9._@-]+", "_", s).strip("_")[:maxlen] or "reporte"


def _status_path(bundle_id: str) -> str:
    return os.path.join(BUNDLE_DIR, bundle_id, "status.json")


def _write_status(bundle_id: str, st: Dict[str, Any]) -> None:
    st["updated_at"] = time.time()
    tmp = _status_path(bundle_id) + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(st, f, ensure_ascii=False)
    os.replace(tmp, _status_path(bundle_id))


def get_status(bundle_id: str) -> Optional[Dict[str, Any]]:
    if not re.fullmatch(r"[0-9a-f-]{36}", bundle_id or ""):
        return None
    try:
        with open(_status_path(bundle_id), encoding="utf-8") as f:
            st = json.load(f)
    except FileNotFoundError:
        return None
    if st.get("status") in ("queued", "running") and time.time() - st.get("updated_at", 0) > STALE_SECONDS:
        st["status"] = "interrupted"
        st["error"] = "El proceso que armaba el paquete se detuvo (reinicio del servicio). Vuelva a solicitarlo."
    return st


def zip_path(bundle_id: str) -> Optional[str]:
    st = get_status(bundle_id)
    if not st or st.get("status") != "done":
        return None
    p = os.path.join(BUNDLE_DIR, bundle_id, st["file"])
    return p if os.path.isfile(p) else None


def cleanup_old_bundles() -> int:
    if not os.path.isdir(BUNDLE_DIR):
        return 0
    n = 0
    limit = time.time() - BUNDLE_TTL_HOURS * 3600
    for d in os.listdir(BUNDLE_DIR):
        p = os.path.join(BUNDLE_DIR, d)
        try:
            if os.path.isdir(p) and os.path.getmtime(p) < limit:
                shutil.rmtree(p)
                n += 1
        except Exception:
            logger.error("could not remove old bundle %s", p, exc_info=True)
    return n


def start_bundle(title: str, assets: List[Dict[str, str]],
                 render_group_pdf: Callable[[], bytes],
                 render_comparison_pdf: Callable[[], bytes],
                 render_asset_pdf: Callable[[str], bytes]) -> str:
    """Queue a ZIP build. `assets` = [{id, name}]. The renderers are injected so this module stays free of the API layer."""
    if not assets:
        raise ValueError("Ningún activo coincide")
    if len(assets) > BUNDLE_MAX_ASSETS:
        raise ValueError(f"{len(assets)} activos; el máximo por paquete es {BUNDLE_MAX_ASSETS}")
    cleanup_old_bundles()
    bundle_id = str(uuid.uuid4())
    os.makedirs(os.path.join(BUNDLE_DIR, bundle_id), exist_ok=True)
    stem = _safe(title, 80)
    st = {"id": bundle_id, "title": title, "status": "queued", "total": len(assets) + 2, "done": 0, "failed": [],
          "created_at": time.time(), "file": f"{stem}_{_local_now():%Y-%m-%d}.zip"}
    _write_status(bundle_id, st)
    threading.Thread(target=_build, args=(bundle_id, st, stem, assets, render_group_pdf, render_comparison_pdf, render_asset_pdf),
                     daemon=True, name=f"report-bundle-{bundle_id[:8]}").start()
    return bundle_id


def _build(bundle_id, st, stem, assets, render_group_pdf, render_comparison_pdf, render_asset_pdf):
    while not _worker_lock.acquire(timeout=60):      # waiting behind another bundle: keep the status fresh so it is not taken as dead
        _write_status(bundle_id, st)
    try:
        _build_locked(bundle_id, st, stem, assets, render_group_pdf, render_comparison_pdf, render_asset_pdf)
    finally:
        _worker_lock.release()


def _build_locked(bundle_id, st, stem, assets, render_group_pdf, render_comparison_pdf, render_asset_pdf):
    st["status"] = "running"
    _write_status(bundle_id, st)
    out = os.path.join(BUNDLE_DIR, bundle_id, st["file"])
    pre = common_prefix([a["name"] for a in assets])
    index = []
    try:
        with zipfile.ZipFile(out + ".part", "w", zipfile.ZIP_DEFLATED) as z:
            for fname, label, fn in (("00_REPORTE_GENERAL_GRUPO.pdf", "Reporte general del grupo", render_group_pdf),
                                     ("01_COMPARATIVO_GRUPO.pdf", "Comparativo del grupo (último escaneo vs anterior)", render_comparison_pdf)):
                st["current"] = label
                _write_status(bundle_id, st)
                try:
                    z.writestr(f"{stem}/{fname}", fn())
                    index.append(f"OK     {fname}  ({label})")
                except Exception as e:
                    logger.error("[Report-Bundle] %s failed", label, exc_info=True)
                    st["failed"].append({"item": label, "error": f"{type(e).__name__}: {e}"[:300]})
                    index.append(f"ERROR  {fname}  ({label}): {e}")
                st["done"] += 1
            for a in assets:
                rel = a["name"][len(pre):] or a["name"]
                fname = f"activos/{_safe(rel.replace('/', '__'))}.pdf"
                st["current"] = a["name"]
                _write_status(bundle_id, st)
                try:
                    z.writestr(f"{stem}/{fname}", render_asset_pdf(a["name"]))
                    index.append(f"OK     {fname}  ({a['name']})")
                except Exception as e:
                    logger.error("[Report-Bundle] asset report %s failed", a["name"], exc_info=True)
                    st["failed"].append({"item": a["name"], "error": f"{type(e).__name__}: {e}"[:300]})
                    index.append(f"ERROR  {fname}  ({a['name']}): {e}")
                st["done"] += 1
            head = [f"Paquete de reportes: {st['title']}", f"Generado: {_local_now():%Y-%m-%d %H:%M} (Centinela-AI, datos en vivo)",
                    f"Activos: {len(assets)}" + (f" bajo {pre}" if pre else ""), f"Errores: {len(st['failed'])}", ""]
            z.writestr(f"{stem}/INDICE.txt", "\n".join(head + index) + "\n")
        os.replace(out + ".part", out)
        st["status"] = "done"
        st["current"] = None
        st["size_bytes"] = os.path.getsize(out)
    except Exception as e:
        logger.error("[Report-Bundle] bundle %s failed", bundle_id, exc_info=True)
        st["status"] = "failed"
        st["error"] = f"{type(e).__name__}: {e}"[:500]
    _write_status(bundle_id, st)
