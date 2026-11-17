"""Group-level triage report logic: a GitLab group (project + all its sub-projects) -> findings classified by the analyst's root causes.

What is MEASURED here (straight from vulnerability_log / GitLab): counts, severities, engines, file:line, duplicates across engines, outdated
dependencies, SonarQube's own effort estimate, which sub-projects exist in GitLab and whether they were scanned.
What is the ANALYST'S judgement (stored in triage_root_causes / triage_rules, with who/when): Vulnerabilidad / Falso positivo / Calidad, the rationale,
strategy, owner and the work-plan estimate. A finding no rule matches is reported as SIN CLASIFICAR -- never guessed.

The pure functions (parse_*, match_rule, classify, mark_duplicates, compute_plan) take plain dicts so they are testable without a DB.
"""
import logging
import re
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import quote


logger = logging.getLogger(__name__)

UNCLASSIFIED = "SIN CLASIFICAR"
CLASSES = ("Vulnerabilidad", "Falso positivo", "Calidad")
CRIT_ORDER = {"Crítico": 0, "Alto": 1, "Medio": 2, "Bajo": 3}
SEV_TO_CRIT = {"CRITICAL": "Crítico", "HIGH": "Alto", "MEDIUM": "Medio", "LOW": "Bajo"}
# Which finding to keep when several engines report the same line (the others become "Duplicado de").
ENGINE_RANK = {"sonarqube": 0, "semgrep": 1, "sast-native": 2, "authz-static": 3, "sca-native": 4, "standards-audit": 5}
# open = the platform-wide definition used by the group reports (everything not closed or suppressed)
CLOSED_STATUSES = ("RESOLVED", "SUPPRESSED")


def class_of_code(code: Optional[str]) -> str:
    c = code or ""
    if c.startswith("V-"):
        return "Vulnerabilidad"
    if c.startswith("FP-"):
        return "Falso positivo"
    if c.startswith("C-"):
        return "Calidad"
    return "Sin clasificar"


# --------------------------------------------------------------------------------------------- parsing
def parse_location(url_path: Optional[str]) -> Tuple[str, Optional[int]]:
    """'src/Foo.java:57' -> ('src/Foo.java', 57); 'gitlab:group/repo#merge-gate' or no line -> (whole value, None)."""
    up = (url_path or "").strip()
    m = re.match(r"^(.*?):(\d+)$", up)
    if m and not up.startswith("gitlab:"):
        return m.group(1), int(m.group(2))
    return up, None


def parse_effort_minutes(description: Optional[str]) -> Optional[float]:
    """SonarQube's own 'Esfuerzo estimado: 1h30min' -> minutes. None when the finding carries no estimate (only SonarQube does)."""
    m = re.search(r"Esfuerzo estimado:\*{0,2}\s*((?:\d+d)?\s*(?:\d+h)?\s*(?:\d+min)?)", description or "")
    if not m or not m.group(1).strip():
        return None
    txt = m.group(1)
    total = 0.0
    for val, unit in re.findall(r"(\d+)\s*(d|h|min)", txt):
        total += int(val) * {"d": 480, "h": 60, "min": 1}[unit]
    return total or None


def parse_dependency(description: Optional[str]) -> Dict[str, str]:
    d = description or ""
    out = {}
    for key, label in (("package", "Paquete"), ("installed", "Versión instalada"), ("fixed", "Versión segura")):
        m = re.search(r"\*\*%s:\*\*\s*([^\n]+)" % re.escape(label), d)
        out[key] = m.group(1).strip() if m else ""
    return out


def short_title(description: Optional[str], limit: int = 220) -> str:
    """First meaningful line of the finding text, markdown stripped."""
    for line in (description or "").splitlines():
        t = re.sub(r"\*\*|`|^\[[^\]]*\]\s*", "", line).strip()
        if t and not t.lower().startswith(("archivo:", "sonarqube ")):
            return t[:limit]
    return (description or "")[:limit]


# --------------------------------------------------------------------------------------------- rules
_re_cache: Dict[str, "re.Pattern"] = {}


def _rx(p: str) -> "re.Pattern":
    if p not in _re_cache:
        _re_cache[p] = re.compile(p)
    return _re_cache[p]


def match_rule(finding: Dict[str, Any], rules: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Highest-priority rule matching the finding (ties: the most specific, then the most recently added -- rules arrive ordered)."""
    best = None
    # Assets are named "<project>@<branch>" since 2026-10-12. The analyst's rules were written against the project name (e.g. "/fe\-app$"), so they
    # match the project part: otherwise renaming the assets silently un-classified every rule anchored with "$" (53 false-positive decisions lost the first time).
    project_name = finding["asset_name"].split("@", 1)[0]
    for r in rules:
        if r.get("engine") and r["engine"] != finding["engine"]:
            continue
        if not _rx(r["rule_regex"]).search(finding["rule"] or ""):
            continue
        if r.get("asset_regex") and not _rx(r["asset_regex"]).search(project_name):
            continue
        if r.get("path_regex") and not _rx(r["path_regex"]).search(finding["url_path"] or ""):
            continue
        if r.get("line") is not None and r["line"] != finding["line"]:
            continue
        if best is None or r.get("priority", 0) >= best.get("priority", 0):
            best = r
    return best


def classify(findings: List[Dict[str, Any]], rules: List[Dict[str, Any]], causes: Dict[str, Dict[str, Any]]) -> None:
    """Sets finding['cause'] (a catalog code or UNCLASSIFIED), ['classification'], ['note'], ['rule_id']."""
    for f in findings:
        r = match_rule(f, rules)
        if r and r["root_cause_code"] in causes:
            f["cause"], f["note"], f["rule_id"] = r["root_cause_code"], r.get("note") or "", r.get("id")
        else:
            f["cause"], f["note"], f["rule_id"] = UNCLASSIFIED, "", None
        f["classification"] = class_of_code(f["cause"])


def mark_duplicates(findings: List[Dict[str, Any]], causes: Optional[Dict[str, Dict[str, Any]]] = None) -> None:
    """Duplicates inside one root cause of one repo.
    scope 'line' (default): the same file:line reported by DIFFERENT engines -> the best-ranked engine's finding(s) are kept, the others point at
      them. Several findings of one engine on one line are distinct findings.
    scope 'file' (analyst-declared, e.g. a Dockerfile reported by 3 engines on different lines, or two adjacent properties): every finding of the
      cause in the same file collapses onto the first.
    A finding without a real file:line (repo-level checks) is never merged."""
    causes = causes or {}
    groups: Dict[tuple, List[Dict[str, Any]]] = {}
    for f in findings:
        f["duplicate_of"] = ""
        if f["cause"] == UNCLASSIFIED or f["url_path"].startswith("gitlab:") or f["line"] is None:
            continue
        scope = (causes.get(f["cause"]) or {}).get("dedup_scope") or "line"
        k = (f["asset_name"], f["file"], f["cause"], scope) + ((f["line"],) if scope == "line" else ())
        groups.setdefault(k, []).append(f)
    for k, items in groups.items():
        if len(items) < 2:
            continue
        if k[3] == "file":
            items.sort(key=lambda x: (ENGINE_RANK.get(x["engine"], 9), x["line"], x["rule"], x["db_id"]))
            for other in items[1:]:
                other["duplicate_of"] = items[0]["occ_id"]
            continue
        engines = sorted({x["engine"] for x in items}, key=lambda e: (ENGINE_RANK.get(e, 9), e))
        if len(engines) < 2:
            continue
        keeper = min((x for x in items if x["engine"] == engines[0]), key=lambda x: (x["rule"], x["db_id"]))
        for other in items:
            if other["engine"] != engines[0]:
                other["duplicate_of"] = keeper["occ_id"]


def number_occurrences(findings: List[Dict[str, Any]]) -> None:
    findings.sort(key=lambda f: (f["repo"], {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(f["severity_eff"], 4),
                                 f["rule"], f["file"], f["line"] or 0, f["db_id"]))
    for i, f in enumerate(findings, 1):
        f["occ_id"] = f"OC-{i:04d}"


# --------------------------------------------------------------------------------------------- plan
def compute_plan(group: Dict[str, Any], causes: Dict[str, Dict[str, Any]], findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """One row per V-/C- root cause that has a plan estimate AND at least one finding. Pure arithmetic over the analyst's parameters; the
    minutes/extra hours are the analyst's assumptions (flagged by minutes_source), only the SonarQube column is Centinela's own estimate."""
    hpd = float(group.get("hours_per_day") or 8)
    test_pct = float(group.get("test_pct") if group.get("test_pct") is not None else 0.3)
    rows = []
    for code, c in causes.items():
        plan = c.get("plan")
        if not plan or class_of_code(code) == "Falso positivo":
            continue
        mine = [f for f in findings if f["cause"] == code]
        if not mine:
            continue
        uniq = [f for f in mine if not f["duplicate_of"]]
        # normally one work unit per unique occurrence; the analyst can declare a fixed number of units instead (e.g. 5 major-version upgrades),
        # which applies as long as at least one finding remains
        fixed = plan.get("fixed_qty")
        qty = (fixed if fixed is not None else len(uniq)) if uniq else 0
        centinela_h = sum((f["effort_min"] or 0) for f in uniq) / 60.0
        correction = qty * float(plan.get("minutes") or 0) / 60.0
        extra = float(plan.get("extra_hours") or 0)
        confirm = float(plan.get("confirm_hours") or 0)
        tests = (correction + extra) * test_pct if qty > 0 else 0.0
        total = confirm + ((correction + extra + tests) if qty > 0 else 0.0)
        crit = (c.get("severity") if class_of_code(code) == "Vulnerabilidad" else plan.get("default_criticality")) or "Medio"
        rows.append(dict(code=code, classification=class_of_code(code), criticality=crit, phase=plan.get("phase"), activity=plan.get("activity"),
                         unit=plan.get("unit"), qty=qty, fixed_qty=fixed, minutes=float(plan.get("minutes") or 0), minutes_source=plan.get("minutes_source"),
                         centinela_h=centinela_h, correction=correction, extra=extra, extra_text=plan.get("extra_text"), confirm=confirm,
                         tests=tests, total=total, days=(total / hpd if hpd else 0.0),
                         area_pct=list(plan.get("area_pct") or [0, 0, 0, 0]),
                         repos=sorted({f["repo"] for f in mine}), order=plan.get("order", 999)))
    rows.sort(key=lambda r: (CRIT_ORDER.get(r["criticality"], 9), 0 if r["classification"] == "Vulnerabilidad" else 1, r["order"]))
    return rows


# --------------------------------------------------------------------------------------------- GitLab coverage
def list_group_projects(instance, group_path: str, timeout: int = 30) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """Every project under the group INCLUDING sub-groups, straight from that GitLab instance. Returns (projects, error). On any failure the
    report still builds from what Centinela has and says the coverage check could not be done (error text) instead of pretending."""
    import requests  # lazy: the skill bundle uses this module without network access
    projects: List[Dict[str, Any]] = []
    page = 1
    headers = {"PRIVATE-TOKEN": instance.token} if instance.token else {}
    try:
        while True:
            r = requests.get(f"{instance.url}/api/v4/groups/{quote(group_path, safe='')}/projects",
                             params={"include_subgroups": "true", "per_page": 100, "page": page, "simple": "true"},
                             headers=headers, timeout=timeout)
            if r.status_code == 404 and page == 1:   # not a group: maybe a single project
                pr = requests.get(f"{instance.url}/api/v4/projects/{quote(group_path, safe='')}", headers=headers, timeout=timeout)
                if pr.status_code == 200:
                    return [{"path": pr.json()["path_with_namespace"], "archived": bool(pr.json().get("archived"))}], None
            if r.status_code != 200:
                return projects, f"GitLab respondió HTTP {r.status_code} al listar el grupo '{group_path}' en {instance.key}"
            batch = r.json()
            projects += [{"path": p["path_with_namespace"], "archived": bool(p.get("archived"))} for p in batch]
            if len(batch) < 100:
                break
            page += 1
    except Exception as e:  # network / JSON: reported, not hidden
        logger.error("triage: could not list GitLab group %s on %s", group_path, instance.key, exc_info=True)
        return projects, f"No se pudo consultar GitLab ({type(e).__name__}: {e})"
    return projects, None


# --------------------------------------------------------------------------------------------- DB access
def group_key_for(instance_key: str, group_path: str) -> str:
    return f"{instance_key}:{group_path.strip('/')}"


def load_group_catalog(cur, group_key: str) -> Tuple[Optional[Dict[str, Any]], Dict[str, Dict[str, Any]], List[Dict[str, Any]]]:
    cur.execute("SELECT group_key, instance, group_path, title, hours_per_day, test_pct, fp_check_hours, areas FROM triage_groups WHERE group_key=%s",
                (group_key,))
    g = cur.fetchone()
    if not g:
        return None, {}, []
    group = dict(zip(("group_key", "instance", "group_path", "title", "hours_per_day", "test_pct", "fp_check_hours", "areas"), g))
    for k in ("hours_per_day", "test_pct", "fp_check_hours"):
        group[k] = float(group[k])
    cur.execute("""SELECT code, classification, kind, title, severity, certainty, rationale, how_to_confirm, strategy, owner, outdated, dedup_scope,
                          plan, classified_by, classified_at FROM triage_root_causes WHERE group_key=%s ORDER BY code""", (group_key,))
    cols = ("code", "classification", "kind", "title", "severity", "certainty", "rationale", "how_to_confirm", "strategy", "owner", "outdated",
            "dedup_scope", "plan", "classified_by", "classified_at")
    causes = {r[0]: dict(zip(cols, r)) for r in cur.fetchall()}
    cur.execute("""SELECT id::text, rule_regex, engine, asset_regex, path_regex, line, root_cause_code, priority, note
                   FROM triage_rules WHERE group_key=%s ORDER BY priority, created_at, id""", (group_key,))
    rcols = ("id", "rule_regex", "engine", "asset_regex", "path_regex", "line", "root_cause_code", "priority", "note")
    return group, causes, [dict(zip(rcols, r)) for r in cur.fetchall()]


def _match(col: str, asset_prefix: str):
    """SQL + params selecting the assets of a group OR of one single project: the exact name, anything below it ('<path>/...') or one of its branch
    assets ('<path>@branch'). Matching on a bare 'starts with' would pull 'proyecto-cv2/...' into 'proyecto-c'."""
    base = asset_prefix.rstrip("/")
    return f"({col} = %s OR starts_with({col}, %s) OR starts_with({col}, %s))", (base, base + "/", base + "@")


def fetch_group_findings(cur, asset_prefix: str) -> List[Dict[str, Any]]:
    """Open VULNERABILITY- and COMPLIANCE-category (accessibility) findings of every asset whose name starts with the prefix (i.e. the group
    and all its sub-projects). Accessibility stays in the analyst's triage: it is actionable, just not a security vulnerability."""
    cur.execute("""
        SELECT i.asset_name, v.id::text, v.cve_id, v.scan_engine, v.url_path, v.severity,
               COALESCE(v.real_severity, v.severity), v.risk_verdict, v.reachability_status, v.description
        FROM vulnerability_log v JOIN infra_inventory i ON i.id = v.asset_id
        WHERE """ + _match("i.asset_name", asset_prefix)[0] + """ AND v.finding_category IN ('VULNERABILITY', 'COMPLIANCE') AND v.status NOT IN %s
    """, (*_match("i.asset_name", asset_prefix)[1], CLOSED_STATUSES))
    out = []
    for name, vid, rule, engine, up, sev_raw, sev_eff, verdict, reach, desc in cur.fetchall():
        file_, line = parse_location(up)
        dep = parse_dependency(desc) if (rule or "").startswith("SCA-CVE-") else {}
        out.append(dict(db_id=vid, asset_name=name, repo=name.rsplit("/", 1)[-1], rule=rule or "", engine=engine or "", url_path=up or "",
                        file=file_, line=line, severity_raw=sev_raw, severity_eff=sev_eff, no_risk=(verdict == "CONFIRMED_NO_RISK"),
                        reach=reach or "", description=desc or "", title=short_title(desc), effort_min=parse_effort_minutes(desc),
                        outdated=bool(dep), dep=dep))
    return out


def fetch_group_assets(cur, asset_prefix: str) -> Dict[str, Dict[str, Any]]:
    sql, params = _match("asset_name", asset_prefix)
    cur.execute("SELECT asset_name, last_audit FROM infra_inventory WHERE " + sql, params)
    return {n: {"asset_name": n, "last_audit": la} for n, la in cur.fetchall()}


def count_group_informational(cur, asset_prefix: str) -> int:
    cur.execute("""SELECT count(*) FROM vulnerability_log v JOIN infra_inventory i ON i.id=v.asset_id
                   WHERE """ + _match("i.asset_name", asset_prefix)[0] + """ AND v.finding_category NOT IN ('VULNERABILITY', 'COMPLIANCE') AND v.status NOT IN %s""",
                (*_match("i.asset_name", asset_prefix)[1], CLOSED_STATUSES))
    return cur.fetchone()[0]


def build_coverage(instance, group_path: str, assets: Dict[str, Dict[str, Any]], findings: List[Dict[str, Any]],
                   gitlab_projects: List[Dict[str, Any]], gitlab_error: Optional[str]) -> List[Dict[str, Any]]:
    """One row per sub-project: what GitLab has vs what Centinela scanned. 'Sin escanear' (in GitLab, no asset or never audited) is NOT 'clean'."""
    counts: Dict[str, int] = {}
    for f in findings:
        counts[f["asset_name"]] = counts.get(f["asset_name"], 0) + 1
    # Assets are named "<prefix><project path>@<branch>" (one per audited branch); GitLab lists projects, so match on the project part.
    gl = {instance.asset_name(p["path"]): p for p in gitlab_projects}
    def _project(n): return n.split("@", 1)[0]
    scanned_projects = {_project(n) for n in assets}
    names = sorted(set(assets) | {n for n in gl if n not in scanned_projects})
    rows = []
    for n in names:
        a = assets.get(n)
        p = gl.get(_project(n))
        if a and a["last_audit"]:
            status = "Escaneado"
        elif a:
            status = "En inventario, nunca auditado"
        else:
            status = "Sin escanear (no está en el inventario de Centinela)"
        note = ""
        if p and p["archived"]:
            note = "Archivado en GitLab"
        if a and not p and not gitlab_error and gitlab_projects:
            note = "Está en el inventario pero GitLab ya no lo lista en el grupo"
        rows.append(dict(asset_name=n, repo=n.rsplit("/", 1)[-1], path=n[len(instance.asset_prefix):], status=status,
                         last_audit=(a or {}).get("last_audit") or "", findings=counts.get(n, 0), note=note))
    return rows


def assemble_report_data(group, causes, rules, findings, coverage, instance, informational=None, coverage_error=None, now=None, source_text=None):
    """Classifies, dedups and plans an in-memory findings list. Shared by the DB path (build_report_data) and the PDF path (skill bundle)."""
    number_occurrences(findings)
    classify(findings, rules, causes)
    mark_duplicates(findings, causes)
    return dict(group=group, instance=instance, causes=causes, rules=rules, findings=findings, coverage=coverage, coverage_error=coverage_error,
                informational=informational, plan=compute_plan(group, causes, findings), generated_at=now or datetime.now(), source_text=source_text)


def build_report_data(cur, instance, group_path: str, now: Optional[datetime] = None, check_gitlab: bool = True) -> Dict[str, Any]:
    key = group_key_for(instance.key, group_path)
    group, causes, rules = load_group_catalog(cur, key)
    if group is None:
        raise LookupError(f"No hay catálogo de triage para el grupo '{group_path}' ({instance.key}). Siembra o crea uno primero.")
    prefix = instance.asset_prefix + group_path.strip("/") + "/"
    findings = fetch_group_findings(cur, prefix)
    assets = fetch_group_assets(cur, prefix)
    projects, gl_err = list_group_projects(instance, group_path.strip("/")) if check_gitlab else ([], "Consulta a GitLab omitida")
    coverage = build_coverage(instance, group_path, assets, findings, projects, gl_err)
    data = assemble_report_data(group, causes, rules, findings, coverage, instance, count_group_informational(cur, prefix), gl_err, now)
    data["prefix"] = prefix
    return data


# --------------------------------------------------------------------------------------------- seeding
def load_seed(cur, seed: Dict[str, Any], actor: str, replace: bool = False) -> Dict[str, int]:
    """Writes a seed (core/triage_seeds/*.json) into the catalog tables. replace=True first deletes the group's causes/rules."""
    from psycopg2.extras import Json
    g = seed["group"]
    key = group_key_for(g["instance"], g["group_path"])
    if replace:
        cur.execute("DELETE FROM triage_groups WHERE group_key=%s", (key,))
    cur.execute("""INSERT INTO triage_groups (group_key, instance, group_path, title, hours_per_day, test_pct, fp_check_hours, areas)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
                   ON CONFLICT (group_key) DO UPDATE SET title=EXCLUDED.title, hours_per_day=EXCLUDED.hours_per_day, test_pct=EXCLUDED.test_pct,
                        fp_check_hours=EXCLUDED.fp_check_hours, areas=EXCLUDED.areas, updated_at=now()""",
                (key, g["instance"], g["group_path"], g["title"], g["hours_per_day"], g["test_pct"], g["fp_check_hours"], Json(g["areas"])))
    for c in seed["root_causes"]:
        cur.execute("""INSERT INTO triage_root_causes (group_key, code, classification, kind, title, severity, certainty, rationale, how_to_confirm,
                           strategy, owner, outdated, dedup_scope, plan, classified_by) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                       ON CONFLICT (group_key, code) DO UPDATE SET classification=EXCLUDED.classification, kind=EXCLUDED.kind, title=EXCLUDED.title,
                           severity=EXCLUDED.severity, certainty=EXCLUDED.certainty, rationale=EXCLUDED.rationale,
                           how_to_confirm=EXCLUDED.how_to_confirm, strategy=EXCLUDED.strategy, owner=EXCLUDED.owner, outdated=EXCLUDED.outdated, dedup_scope=EXCLUDED.dedup_scope,
                           plan=EXCLUDED.plan, classified_by=EXCLUDED.classified_by, classified_at=now()""",
                    (key, c["code"], c["classification"], c.get("kind"), c["title"], c.get("severity"), c.get("certainty"), c.get("rationale"),
                     c.get("how_to_confirm"), c.get("strategy"), c.get("owner"), bool(c.get("outdated")), c.get("dedup_scope") or "line",
                     Json(c["plan"]) if c.get("plan") else None, actor))
    cur.execute("DELETE FROM triage_rules WHERE group_key=%s AND created_by=%s", (key, actor))
    for r in seed["rules"]:
        cur.execute("""INSERT INTO triage_rules (group_key, rule_regex, engine, asset_regex, path_regex, line, root_cause_code, priority, note, created_by)
                       VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                    (key, r["rule_regex"], r.get("engine"), r.get("asset_regex"), r.get("path_regex"), r.get("line"), r["root_cause_code"],
                     r.get("priority", 0), r.get("note"), actor))
    return {"root_causes": len(seed["root_causes"]), "rules": len(seed["rules"])}
