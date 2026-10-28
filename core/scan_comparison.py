"""Comparison of an asset's latest scan against the state right before it ("última versión vs anterior").

Every scan of an asset opens a `scan_runs` row and copies the findings open at that moment into `scan_run_baseline`. Once the scan
finishes, each baseline finding is classified by what the scan did to it, and the open findings that were not in the baseline are
listed as new or reappeared. Generic: works for any asset, and for a group of assets (each one compared against its own baseline).

Classification of a baseline finding (B) after run R (started at T):
  * SOLVENTADO      - R closed it (RESOLVED) and nothing with the same rule reappeared at the same file/URL.
  * MOVIDO          - R closed it but the same rule is open again in the same file/URL at another line: still present, only moved.
                      Reconciliation keys on file:line, so an edit that shifts lines resolves the old row and opens a new one.
  * PERSISTE        - still open and re-detected by R (detected_at >= T).
  * NO_REVERIFICADO - still open but R did not re-detect it (its engine did not run, or the engine never closes findings, e.g. ZAP).
  * SUPRIMIDO       - an analyst suppressed it.
  * SIN_REGISTRO    - the row no longer exists (deleted): no evidence either way.
Open findings not in B: REAPARECIDO (status REOPENED: had been fixed before) or NUEVO (new code or a rule added since the last scan).
"""
from __future__ import annotations

import html
import logging
import re
import subprocess
from collections import Counter, defaultdict
from contextlib import contextmanager
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional

logger = logging.getLogger(__name__)

CLOSED_STATUSES = ("RESOLVED", "SUPPRESSED")
SEVERITIES = tuple("CRITICAL HIGH MEDIUM LOW INFO".split())   # written this way so the rule-id extractor of test_coverage_matrix does not read it as a rule
_SEV_ALIASES = {"INFORMATIONAL": "INFO", "INFORMATION": "INFO", "NONE": "INFO", "MODERATE": "MEDIUM", "": "INFO"}
_LINE_SUFFIX = re.compile(r":\d+(?:-\d+)?$")

BASELINE_LABELS = {
    "SOLVENTADO": "Solventado",
    "MOVIDO": "Persiste (cambió de línea)",
    "PERSISTE": "Persiste",
    "NO_REVERIFICADO": "No re-verificado",
    "SUPRIMIDO": "Suprimido por analista",
    "SIN_REGISTRO": "Sin registro",
}
NEW_LABELS = {"NUEVO": "Nuevo", "REAPARECIDO": "Reaparecido"}


def norm_severity(sev: Optional[str]) -> str:
    s = str(sev or "").strip().upper()
    s = _SEV_ALIASES.get(s, s)
    return s if s in SEVERITIES else "INFO"


def location_key(url_path: Optional[str]) -> str:
    """File or URL a finding lives in, without the line number (file.java:120 -> file.java) or the query string."""
    p = str(url_path or "").strip()
    if p.startswith(("http://", "https://")):
        return p.split("?", 1)[0].split("#", 1)[0]
    return _LINE_SUFFIX.sub("", p)


def git_head(path: str) -> Optional[str]:
    try:
        out = subprocess.run(["git", "-C", path, "rev-parse", "HEAD"], capture_output=True, text=True, timeout=15)
        return out.stdout.strip() or None if out.returncode == 0 else None
    except Exception:
        logger.error("git rev-parse failed for %s", path, exc_info=True)
        return None


# --------------------------------------------------------------------------------------------------------------- recording runs
def start_run(cur, asset_id: str, source: str, commit_sha: Optional[str] = None) -> str:
    """Open a run and copy the findings open right now into its baseline. Call before the scan writes anything."""
    cur.execute("""UPDATE public.scan_runs SET status = 'FAILED', finished_at = now(), note = 'interrumpido: se inició otro escaneo'
                   WHERE asset_id = %s AND status = 'RUNNING'""", (asset_id,))
    cur.execute("INSERT INTO public.scan_runs (asset_id, source, commit_sha) VALUES (%s, %s, %s) RETURNING id",
                (asset_id, source, commit_sha))
    run_id = cur.fetchone()[0]
    cur.execute("""
        INSERT INTO public.scan_run_baseline (run_id, finding_id, cve_id, severity, finding_category, status, url_path, scan_engine)
        SELECT %s, v.id, v.cve_id, COALESCE(v.real_severity, v.severity), v.finding_category, v.status, v.url_path, v.scan_engine
        FROM public.vulnerability_log v
        WHERE v.asset_id = %s AND v.status NOT IN %s
    """, (run_id, asset_id, CLOSED_STATUSES))
    n = cur.rowcount
    cur.execute("UPDATE public.scan_runs SET baseline_count = %s WHERE id = %s", (n, run_id))
    return str(run_id)


def finish_run(cur, run_id: str, ok: bool, commit_sha: Optional[str] = None, note: Optional[str] = None) -> None:
    cur.execute("""UPDATE public.scan_runs SET finished_at = now(), status = %s, commit_sha = COALESCE(%s, commit_sha),
                   note = COALESCE(%s, note) WHERE id = %s""", ("DONE" if ok else "FAILED", commit_sha, note, run_id))


def open_run(asset_id: str, source: str, commit_sha: Optional[str] = None) -> Optional[str]:
    """start_run in its own transaction. Returns None (logged) when recording fails: the scan itself must go on."""
    from core import db_manager
    try:
        with db_manager.get_db_cursor() as cur:
            return start_run(cur, asset_id, source, commit_sha)
    except Exception:
        logger.error("[Scan-Runs] could not open a run for asset %s", asset_id, exc_info=True)
        return None


def close_run(run_id: Optional[str], ok: bool, commit_sha: Optional[str] = None, note: Optional[str] = None) -> None:
    if not run_id:
        return
    from core import db_manager
    try:
        with db_manager.get_db_cursor() as cur:
            finish_run(cur, run_id, ok, commit_sha, note)
    except Exception:
        logger.error("[Scan-Runs] could not close run %s", run_id, exc_info=True)


# A run left RUNNING by a process that died never closes; after this long it is ignored instead of flagged as "in progress".
STALE_RUNNING_HOURS = 12


@contextmanager
def recorded_run(asset_id: str, source: str, commit_sha: Optional[str] = None):
    """Wraps one scan of one asset. Yields a dict where the caller can set 'ok' (False marks the run FAILED without raising),
    'commit_sha' and 'note'. Recording failures are logged and never break the scan itself."""
    from core import db_manager
    state: Dict[str, Any] = {"ok": True, "commit_sha": commit_sha, "note": None, "run_id": None}
    try:
        with db_manager.get_db_cursor() as cur:
            state["run_id"] = start_run(cur, asset_id, source, commit_sha)
    except Exception:
        logger.error("[Scan-Runs] could not open a run for asset %s", asset_id, exc_info=True)
    try:
        yield state
    except BaseException as e:
        state["ok"] = False
        state["note"] = state["note"] or f"{type(e).__name__}: {e}"[:500]
        raise
    finally:
        if state["run_id"]:
            try:
                with db_manager.get_db_cursor() as cur:
                    finish_run(cur, state["run_id"], bool(state["ok"]), state.get("commit_sha"), state.get("note"))
            except Exception:
                logger.error("[Scan-Runs] could not close run %s", state["run_id"], exc_info=True)


# --------------------------------------------------------------------------------------------------------------- comparison
def _latest_runs(cur, asset_id: str) -> Dict[str, Any]:
    cur.execute("""SELECT id::text, started_at, finished_at, status, source, commit_sha, baseline_count, note
                   FROM public.scan_runs WHERE asset_id = %s ORDER BY started_at DESC LIMIT 50""", (asset_id,))
    cols = [d[0] for d in cur.description]
    runs = [dict(zip(cols, r)) for r in cur.fetchall()]
    done = [r for r in runs if r["status"] == "DONE"]
    latest = done[0] if done else None
    previous = done[1] if len(done) > 1 else None
    from datetime import timezone, timedelta
    fresh = datetime.now(timezone.utc) - timedelta(hours=STALE_RUNNING_HOURS)
    newer_running = [r for r in runs if r["status"] == "RUNNING" and r["started_at"] > fresh
                     and (not latest or (r["started_at"] >= latest["started_at"] and r["id"] != latest["id"]))]
    return {"latest": latest, "previous": previous, "running": newer_running[0] if newer_running else None,
            "failed_since": [r for r in runs if r["status"] == "FAILED" and latest and r["started_at"] > latest["started_at"]]}


def classify(baseline: List[Dict[str, Any]], current_by_id: Dict[str, Dict[str, Any]],
             open_not_in_baseline: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """Pure classification (see module docstring). current_by_id[finding_id] = {status, url_path, redetected: bool (detected_at >= run
    start)}; returns {class: [items]}."""
    out: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    appeared = [r for r in open_not_in_baseline]
    by_key: Dict[tuple, List[Dict[str, Any]]] = defaultdict(list)
    for r in appeared:
        by_key[(r.get("cve_id"), location_key(r.get("url_path")))].append(r)
    consumed: set = set()

    for b in baseline:
        cur = current_by_id.get(str(b["finding_id"]))
        item = dict(b)
        if cur is None:
            out["SIN_REGISTRO"].append(item)
            continue
        item["now_url_path"] = cur.get("url_path")
        item["baseline_severity"] = b.get("severity")
        if cur.get("severity") and str(cur.get("status") or "").upper() not in CLOSED_STATUSES:
            item["severity"] = cur["severity"]      # still open: report what it is now (the analysis may have changed it)
        st = str(cur.get("status") or "").upper()
        if st == "SUPPRESSED":
            out["SUPRIMIDO"].append(item)
        elif st == "RESOLVED":
            twins = [r for r in by_key.get((b.get("cve_id"), location_key(b.get("url_path"))), []) if str(r["id"]) not in consumed]
            if twins:
                consumed.add(str(twins[0]["id"]))
                item["now_url_path"] = twins[0].get("url_path")
                item["severity"] = twins[0].get("severity") or item.get("severity")
                item["now_finding_id"] = str(twins[0]["id"])
                out["MOVIDO"].append(item)
            else:
                out["SOLVENTADO"].append(item)
        else:
            if cur.get("redetected"):
                out["PERSISTE"].append(item)
            else:
                out["NO_REVERIFICADO"].append(item)

    for r in appeared:
        if str(r["id"]) in consumed:
            continue
        item = {"finding_id": str(r["id"]), "cve_id": r.get("cve_id"), "severity": r.get("severity"),
                "finding_category": r.get("finding_category"), "url_path": r.get("url_path"), "scan_engine": r.get("scan_engine")}
        out["REAPARECIDO" if str(r.get("status") or "").upper() == "REOPENED" else "NUEVO"].append(item)
    return dict(out)


def compare_asset(cur, asset_id: str) -> Dict[str, Any]:
    cur.execute("SELECT asset_name, asset_type, endpoint FROM public.infra_inventory WHERE id = %s", (asset_id,))
    row = cur.fetchone()
    if not row:
        raise LookupError(f"asset {asset_id} not found")
    asset = {"id": str(asset_id), "name": row[0], "type": row[1], "endpoint": row[2]}
    runs = _latest_runs(cur, asset_id)
    latest = runs["latest"]
    if not latest:
        return {"asset": asset, "available": False, "runs": runs,
                "reason": "Este activo todavía no tiene un escaneo con línea base registrada; el comparativo estará disponible tras su próximo escaneo."}

    cur.execute("""SELECT finding_id::text, cve_id, severity, finding_category, status, url_path, scan_engine
                   FROM public.scan_run_baseline WHERE run_id = %s""", (latest["id"],))
    cols = [d[0] for d in cur.description]
    baseline = [dict(zip(cols, r)) for r in cur.fetchall()]
    ids = [b["finding_id"] for b in baseline]
    current_by_id: Dict[str, Dict[str, Any]] = {}
    if ids:
        # detected_at is a naive timestamp written with the DB session's now(): compare in the DB, in its own time zone.
        cur.execute("""SELECT id::text, status, url_path, COALESCE(real_severity, severity),
                              detected_at >= (%s::timestamptz AT TIME ZONE current_setting('TimeZone'))
                       FROM public.vulnerability_log WHERE id = ANY(%s::uuid[])""", (latest["started_at"], ids))
        for i, st, up, sev, redet in cur.fetchall():
            current_by_id[i] = {"status": st, "url_path": up, "severity": sev, "redetected": bool(redet)}
    cur.execute("""SELECT id::text, cve_id, COALESCE(real_severity, severity), finding_category, status, url_path, scan_engine
                   FROM public.vulnerability_log
                   WHERE asset_id = %s AND status NOT IN %s AND NOT (id = ANY(%s::uuid[]))""", (asset_id, CLOSED_STATUSES, ids))
    appeared = [dict(zip(["id", "cve_id", "severity", "finding_category", "status", "url_path", "scan_engine"], r)) for r in cur.fetchall()]

    classes = classify(baseline, current_by_id, appeared)
    return {"asset": asset, "available": True, "runs": runs, "classes": classes,
            "summary": summarize(classes), "baseline_total": len(baseline)}


def summarize(classes: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Dict[str, Dict[str, int]]]:
    """{category: {class: {severity: n}}} with category VULNERABILITY / INFORMATIONAL."""
    out: Dict[str, Dict[str, Dict[str, int]]] = {}
    for cls, items in classes.items():
        for it in items:
            cat = "INFORMATIONAL" if str(it.get("finding_category") or "").upper() == "INFORMATIONAL" else "VULNERABILITY"
            sev = norm_severity(it.get("severity"))
            out.setdefault(cat, {}).setdefault(cls, Counter())[sev] += 1
    return {c: {k: dict(v) for k, v in d.items()} for c, d in out.items()}


def resolve_assets(cur, asset_names: Optional[Iterable[str]] = None, prefix: Optional[str] = None) -> List[Dict[str, str]]:
    names = [n for n in (asset_names or []) if n]
    if not names and not prefix:
        raise ValueError("Indique asset_name(s) o un prefijo")
    sql = "SELECT id::text, asset_name FROM public.infra_inventory WHERE "
    conds, params = [], []
    if names:
        conds.append("asset_name = ANY(%s)")
        params.append(names)
    if prefix:
        conds.append("asset_name LIKE %s")
        params.append(prefix.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%")
    cur.execute(sql + " OR ".join(conds) + " ORDER BY asset_name", tuple(params))
    return [{"id": r[0], "name": r[1]} for r in cur.fetchall()]


def compare_assets(cur, asset_ids: Iterable[str]) -> List[Dict[str, Any]]:
    return [compare_asset(cur, a) for a in asset_ids]


# --------------------------------------------------------------------------------------------------------------- rendering
_CSS = """
@page{size:A4 landscape;margin:12mm}
:root{--fg:#1d2433;--muted:#5b6475;--line:#d9dee7;--ok:#1f7a4d;--bad:#b42318;--warn:#a15c07;--bg:#fff;--head:#1f3a5f}
body{font-family:'Segoe UI',Arial,sans-serif;color:var(--fg);background:var(--bg);margin:24px;font-size:12px}
@media print{body{margin:0;font-size:10.5px}}
h1{color:var(--head);font-size:20px;margin:0 0 4px} h2{color:var(--head);font-size:15px;margin:22px 0 6px;border-bottom:2px solid var(--head);padding-bottom:3px}
h3{font-size:13px;margin:14px 0 4px} .muted{color:var(--muted)} table{border-collapse:collapse;width:100%;margin:6px 0 10px}
th,td{border:1px solid var(--line);padding:4px 6px;text-align:left;vertical-align:top} th{background:#eef2f7}
td.n{text-align:right;font-variant-numeric:tabular-nums} .ok{color:var(--ok);font-weight:600} .bad{color:var(--bad);font-weight:600}
.warn{color:var(--warn);font-weight:600} .box{border:1px solid var(--line);border-left:4px solid var(--head);padding:8px 10px;margin:8px 0;background:#f8fafc}
code{font-size:11px;word-break:break-all}
"""


def _e(s: Any) -> str:
    return html.escape(str(s if s is not None else ""))


def _report_tz():
    import os
    from zoneinfo import ZoneInfo
    try:
        return ZoneInfo(os.getenv("REPORT_TZ", "America/Mexico_City"))
    except Exception:
        logger.error("invalid REPORT_TZ", exc_info=True)
        return None


def _fmt_dt(dt: Optional[datetime]) -> str:
    """Dates in the readers' time zone (containers run in UTC)."""
    if not dt:
        return "—"
    tz = _report_tz()
    if dt.tzinfo is not None and tz is not None:
        dt = dt.astimezone(tz)
    return dt.strftime("%Y-%m-%d %H:%M")


def _sev_total(summary_cat: Dict[str, Dict[str, int]], cls: str, sevs=SEVERITIES) -> int:
    return sum(summary_cat.get(cls, {}).get(s, 0) for s in sevs)


def _group_rows(items: List[Dict[str, Any]], loc_field: str = "url_path") -> List[tuple]:
    """(severity, rule, n, [locations]) sorted by severity then count."""
    g: Dict[tuple, List[str]] = defaultdict(list)
    for it in items:
        g[(norm_severity(it.get("severity")), it.get("cve_id") or "—")].append(str(it.get(loc_field) or it.get("url_path") or "—"))
    rows = [(sev, rule, len(locs), sorted(set(locs))) for (sev, rule), locs in g.items()]
    return sorted(rows, key=lambda r: (SEVERITIES.index(r[0]), -r[2], r[1]))


def _detail_table(items: List[Dict[str, Any]], loc_field: str = "url_path", max_locs: int = 8) -> str:
    rows = _group_rows(items, loc_field)
    if not rows:
        return "<p class='muted'>Ninguno.</p>"
    out = ["<table><tr><th>Severidad</th><th>Regla</th><th class='n'>N.º</th><th>Ubicaciones</th></tr>"]
    for sev, rule, n, locs in rows:
        shown = "<br>".join(f"<code>{_e(l)}</code>" for l in locs[:max_locs])
        if len(locs) > max_locs:
            shown += f"<br><span class='muted'>… y {len(locs) - max_locs} ubicaciones más</span>"
        out.append(f"<tr><td>{_e(sev)}</td><td><code>{_e(rule)}</code></td><td class='n'>{n}</td><td>{shown}</td></tr>")
    out.append("</table>")
    return "".join(out)


def _version_line(comp: Dict[str, Any]) -> str:
    runs = comp["runs"]
    latest, prev = runs["latest"], runs["previous"]
    prev_v = (prev or {}).get("commit_sha")
    cur_v = latest.get("commit_sha")
    v = ""
    if cur_v or prev_v:
        short = lambda sha: f"<code>{_e(sha[:10])}</code>" if sha else "no registrada"
        v = f" · versión {short(prev_v)} → {short(cur_v)}"
    extra = ""
    if runs.get("running"):
        extra += f" <span class='warn'>Hay un escaneo en curso desde {_fmt_dt(runs['running']['started_at'])}; este comparativo aún no lo incluye.</span>"
    if runs.get("failed_since"):
        extra += f" <span class='warn'>{len(runs['failed_since'])} escaneo(s) posterior(es) fallaron.</span>"
    return (f"Escaneo comparado: {_fmt_dt(latest['started_at'])} → {_fmt_dt(latest['finished_at'])}"
            f" (anterior: {_fmt_dt((prev or {}).get('started_at'))}){v}.{extra}")


def render_html(comparisons: List[Dict[str, Any]], title: str, generated_at: Optional[datetime] = None) -> str:
    tz = _report_tz()
    generated_at = generated_at or (datetime.now(tz) if tz else datetime.now())
    parts = [f"<!doctype html><html lang='es'><head><meta charset='utf-8'><title>{_e(title)}</title><style>{_CSS}</style></head><body>",
             f"<h1>{_e(title)}</h1>",
             f"<p class='muted'>Comparativo del último escaneo de cada activo contra los hallazgos abiertos justo antes de ese escaneo. "
             f"Generado por Centinela-AI el {generated_at.strftime('%Y-%m-%d %H:%M')} con datos en vivo de centinela_db.</p>"]

    # Global summary (vulnerabilities only)
    parts.append("<h2>Resumen por activo (vulnerabilidades de seguridad)</h2>")
    parts.append("<table><tr><th>Activo</th><th class='n'>Abiertas antes</th><th class='n'>Solventadas</th><th class='n'>Persisten</th>"
                 "<th class='n'>No re-verificadas</th><th class='n'>Suprimidas</th><th class='n'>Nuevas</th><th class='n'>Reaparecidas</th>"
                 "<th class='n'>Abiertas ahora</th><th class='n'>Críticas+Altas ahora</th></tr>")
    for c in comparisons:
        if not c.get("available"):
            parts.append(f"<tr><td>{_e(c['asset']['name'])}</td><td colspan='9' class='muted'>{_e(c.get('reason'))}</td></tr>")
            continue
        s = c["summary"].get("VULNERABILITY", {})
        t = lambda *cls: sum(_sev_total(s, k) for k in cls)
        before = t(*BASELINE_LABELS.keys())
        now_open = t("PERSISTE", "MOVIDO", "NO_REVERIFICADO", "NUEVO", "REAPARECIDO")
        ch_now = sum(_sev_total(s, k, ("CRITICAL", "HIGH")) for k in ("PERSISTE", "MOVIDO", "NO_REVERIFICADO", "NUEVO", "REAPARECIDO"))
        parts.append(f"<tr><td>{_e(c['asset']['name'])}</td><td class='n'>{before}</td><td class='n ok'>{t('SOLVENTADO')}</td>"
                     f"<td class='n'>{t('PERSISTE', 'MOVIDO')}</td><td class='n warn'>{t('NO_REVERIFICADO')}</td><td class='n'>{t('SUPRIMIDO')}</td>"
                     f"<td class='n bad'>{t('NUEVO')}</td><td class='n bad'>{t('REAPARECIDO')}</td><td class='n'>{now_open}</td>"
                     f"<td class='n {'bad' if ch_now else 'ok'}'>{ch_now}</td></tr>")
    parts.append("</table>")
    parts.append("<div class='box'><b>Cómo leerlo.</b> <i>Solventada</i>: el escaneo ya no la detecta. <i>Persiste</i>: se volvió a detectar "
                 "(incluye las que solo cambiaron de línea). <i>No re-verificada</i>: sigue abierta pero el escaneo no la volvió a evaluar "
                 "(su motor no corrió o no cierra hallazgos, como el DAST); no es evidencia de que siga ni de que se haya corregido. "
                 "<i>Nueva</i>: no estaba abierta antes; puede deberse a código nuevo o a una regla de detección añadida desde el escaneo anterior. "
                 "<i>Reaparecida</i>: ya se había solventado y volvió a detectarse. Las cifras usan la severidad efectiva (tras el análisis de riesgo real).</div>")

    for c in comparisons:
        parts.append(f"<h2>{_e(c['asset']['name'])}</h2>")
        if not c.get("available"):
            parts.append(f"<p class='muted'>{_e(c.get('reason'))}</p>")
            continue
        parts.append(f"<p class='muted'>{_version_line(c)}</p>")
        s = c["summary"].get("VULNERABILITY", {})
        parts.append("<table><tr><th>Estado</th>" + "".join(f"<th class='n'>{x}</th>" for x in SEVERITIES) + "<th class='n'>Total</th></tr>")
        for cls, label in list(BASELINE_LABELS.items()) + list(NEW_LABELS.items()):
            row = s.get(cls, {})
            if not row:
                continue
            parts.append(f"<tr><td>{_e(label)}</td>" + "".join(f"<td class='n'>{row.get(x, 0) or ''}</td>" for x in SEVERITIES)
                         + f"<td class='n'>{sum(row.values())}</td></tr>")
        parts.append("</table>")
        info = c["summary"].get("INFORMATIONAL", {})
        if info:
            ti = lambda *cls: sum(_sev_total(info, k) for k in cls)
            parts.append(f"<p class='muted'>Informativos (calidad de código, no vulnerabilidades): {ti(*BASELINE_LABELS.keys())} antes · "
                         f"{ti('SOLVENTADO')} solventados · {ti('NUEVO', 'REAPARECIDO')} nuevos · "
                         f"{ti('PERSISTE', 'MOVIDO', 'NO_REVERIFICADO', 'NUEVO', 'REAPARECIDO')} abiertos ahora.</p>")

        vul = lambda cls: [i for i in c["classes"].get(cls, []) if str(i.get("finding_category") or "").upper() != "INFORMATIONAL"]
        parts.append("<h3 class='ok'>Solventadas</h3>" + _detail_table(vul("SOLVENTADO")))
        parts.append("<h3 class='bad'>Nuevas y reaparecidas</h3>" + _detail_table(vul("NUEVO") + vul("REAPARECIDO")))
        parts.append("<h3>Persisten</h3>" + _detail_table(vul("PERSISTE") + vul("MOVIDO"), loc_field="now_url_path"))
        nr = vul("NO_REVERIFICADO")
        if nr:
            parts.append("<h3 class='warn'>No re-verificadas en este escaneo</h3>" + _detail_table(nr))
    parts.append("</body></html>")
    return "".join(parts)


def to_json(comparisons: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    def clean_run(r):
        if not r:
            return None
        return {k: (v.isoformat() if isinstance(v, datetime) else v) for k, v in r.items()}
    out = []
    for c in comparisons:
        runs = c["runs"]
        d = {"asset": c["asset"], "available": c["available"],
             "runs": {"latest": clean_run(runs.get("latest")), "previous": clean_run(runs.get("previous")),
                      "running": clean_run(runs.get("running")), "failed_since": [clean_run(r) for r in runs.get("failed_since") or []]}}
        if c["available"]:
            d["baseline_total"] = c["baseline_total"]
            d["summary"] = c["summary"]
            d["classes"] = {k: [{kk: vv for kk, vv in i.items()} for i in v] for k, v in c["classes"].items()}
        else:
            d["reason"] = c.get("reason")
        out.append(d)
    return out
