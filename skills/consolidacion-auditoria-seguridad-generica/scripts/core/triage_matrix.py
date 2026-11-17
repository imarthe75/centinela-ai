"""Triage findings -> records of the consolidation skill's tracking matrix (references/matriz_schema.md): one record per rule x repository.

The classification (Vulnerabilidad / Falso positivo / Calidad) and root cause are the analyst's; everything else is measured. A false positive is
carried as severity «Informativa» with status «Validar falso positivo» (the skill's convention); a group whose every occurrence is a duplicate of
another rule's is Principal = No.
"""
import re
from collections import defaultdict
from typing import Any, Dict, List

GERENCIAS = {
    "programación": "Gerencia de Programación",
    "arquitectura": "Gerencia de Arquitectura y BD",
    "infraestructura": "Gerencia de Infraestructura y Telecomunicaciones",
    "análisis": "Gerencia de Análisis / Calidad",
}
SEV_ES = {"CRITICAL": "Crítica", "HIGH": "Alta", "MEDIUM": "Media", "LOW": "Baja", "INFO": "Informativa"}
SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SECRET_RULES = re.compile(r"CONFIG-SECRET|HARDCODED-SECRET|JWT-HARDCODED|S6437|S2068|jwt-hardcoded-secret|SECRETS-")


def _tipo(f: Dict[str, Any], cause: Dict[str, Any]) -> str:
    rule, eng = f["rule"], f["engine"]
    low = rule.lower()
    if rule.startswith("SCA-CVE-"):
        return "Dependencias (SCA)"
    if eng == "gitlab-config" or rule.startswith(("GITLAB-", "CICD-")):
        return "CI/CD"
    if rule.startswith(("WCAG-", "ACCESSIBILITY-")):
        return "Accesibilidad"
    if "docker" in low or "kubernetes" in low or "k8s" in low:
        return "Infraestructura (IaC)"
    if rule.startswith(("JPA-", "OOM-")):
        return "Arquitectura"
    if cause.get("classification") == "Calidad":
        return "Calidad"
    return "Seguridad"


def _gerencias(owner: str, tipo: str):
    found = []
    for m in re.finditer(r"Gerencia de ([A-Za-zÁÉÍÓÚáéíóúñ/ ]+?)(?=\s+[—\-·(]|$)", owner or ""):
        key = m.group(1).strip().lower()
        for k, name in GERENCIAS.items():
            if key.startswith(k) and name not in found:
                found.append(name)
    if found:
        return found[0], (found[1] if len(found) > 1 else ""), ""
    default = "Gerencia de Infraestructura y Telecomunicaciones" if tipo in ("CI/CD", "Infraestructura (IaC)") else "Gerencia de Programación"
    return default, "", "Gerencia por regla general (el catálogo no declara responsable); confirmar."


def _capa(f: Dict[str, Any], tipo: str) -> str:
    if tipo == "CI/CD":
        return "CI/CD"
    if tipo == "Infraestructura (IaC)":
        return "Contenedor"
    p = f["asset_name"].lower()
    return "Frontend" if "/frontend/" in p or f["repo"].startswith("fe-") else "Backend"


def _slug(repo: str, used: Dict[str, str]) -> str:
    base = "".join(w[0] for w in re.split(r"[-_]", repo) if w).upper() or repo[:3].upper()
    slug, n = base, 1
    while used.get(slug, repo) != repo:
        n += 1
        slug = f"{base}{n}"
    used[slug] = repo
    return slug


def matrix_records(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings, causes = data["findings"], data["causes"]
    date = data["generated_at"].strftime("%Y-%m-%d")
    # one record per rule x repository x root cause: the same rule can be a vulnerability in one file and a false positive in another
    groups: Dict[tuple, List[Dict[str, Any]]] = defaultdict(list)
    for f in findings:
        groups[(f["repo"], f["rule"], f["cause"])].append(f)
    used: Dict[str, str] = {}
    counters: Dict[str, int] = defaultdict(int)
    principal_rule: Dict[str, str] = {}
    by_occ = {f["occ_id"]: f for f in findings}
    records = []
    for (repo, rule, _cause), fs in sorted(groups.items(), key=lambda kv: (kv[0][0], min(SEV_RANK.get(f["severity_eff"], 9) for f in kv[1]), kv[0][1], kv[0][2])):
        cause_code = fs[0]["cause"]
        cause = causes.get(cause_code) or {}
        clasif = fs[0]["classification"]
        tipo = _tipo(fs[0], cause)
        gerencia, apoyo, g_note = _gerencias(cause.get("owner") or "", tipo)
        slug = _slug(repo, used)
        counters[slug] += 1
        sev_eff = min((f["severity_eff"] for f in fs), key=lambda s: SEV_RANK.get(s, 9))
        sev_raw = min((f["severity_raw"] for f in fs), key=lambda s: SEV_RANK.get(s, 9))
        sev = "Informativa" if clasif == "Falso positivo" else SEV_ES.get(sev_eff, "Media")
        locs = []
        for f in fs:
            loc = f["url_path"]
            if not f.get("unlisted") and loc not in locs:
                locs.append(loc)
        unlisted = sum(1 for f in fs if f.get("unlisted"))
        ub = "; ".join(locs[:10]) + (f"; (+{len(locs) - 10} más)" if len(locs) > 10 else "") + (f"; (+{unlisted} no listadas en el PDF)" if unlisted else "")
        dups = [f for f in fs if f["duplicate_of"]]
        principal = "No" if dups and len(dups) == len(fs) else "Sí"
        notas = []
        if cause_code != "SIN CLASIFICAR":
            notas.append(f"Causa raíz {cause_code} ({clasif}); certeza: {cause.get('certainty') or 'no declarada'}.")
        else:
            notas.append("SIN CLASIFICAR: ningún criterio del analista cubre este hallazgo.")
        if clasif == "Falso positivo":
            notas.append(f"Severidad de la herramienta/Centinela: {SEV_ES.get(sev_eff, sev_eff)}; se registra Informativa hasta validar el falso positivo.")
        if any(f["no_risk"] for f in fs):
            notas.append("Centinela lo marca «SIN RIESGO REAL».")
        if principal == "No":
            tgt = by_occ.get(dups[0]["duplicate_of"])
            notas.append(f"Duplicado de {tgt['rule'] if tgt else dups[0]['duplicate_of']} (misma ubicación, otro motor).")
        if g_note:
            notas.append(g_note)
        if unlisted:
            notas.append(f"{unlisted} ocurrencia(s) no aparecen en el PDF (el reporte recorta la lista).")
        records.append(dict(
            ID=f"C-{slug}-{counters[slug]:02d}", Origen="Centinela", Fuente=(data.get("source_label") or "Centinela") + f" · {repo}",
            FechaFuente=date, Repositorio=repo, Modulo=fs[0]["asset_name"].split("/")[-2] if "/" in fs[0]["asset_name"] else "",
            Capa=_capa(fs[0], tipo), Tipo=tipo, IDorig=rule, Titulo=(cause.get("title") or fs[0]["title"] or rule)[:200], Ubicacion=ub,
            Ocurr=len(fs), SevCent=SEV_ES.get(sev_eff, ""), Sev=sev, CWE="; ".join(sorted({c for f in fs for c in f.get("cwe", [])})),
            Regla=rule, EnCatalogo="", Secreto=("Sí" if SECRET_RULES.search(rule) and clasif == "Vulnerabilidad" else "No"),
            Principal=principal, Gerencia=gerencia, Apoyo=apoyo, Estatus=("Validar falso positivo" if clasif == "Falso positivo" else "Abierto"),
            Nota=" ".join(notas), Clasificacion=clasif, CausaRaiz=cause_code, SevHerramienta=SEV_ES.get(sev_raw, "")))
    return records
