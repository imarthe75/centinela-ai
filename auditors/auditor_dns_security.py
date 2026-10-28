"""
Passive DNS / e-mail authentication audit (engine 'dns-security'): SPF, DMARC, MTA-STS, CAA and DNSSEC for a domain.

Nothing is sent to the target: only public DNS queries (a few TXT/MX/CAA/DS lookups). It covers the e-mail-spoofing and certificate-issuance controls that no
other engine looked at (SPF/DMARC/DKIM were listed as uncovered in docs/COBERTURA_FRAMEWORKS.md).

What it deliberately does NOT conclude:
  * DKIM: a selector is needed to look a key up, so absence cannot be proven. It is reported as "no evaluado", never as a finding.
  * A domain that does not resolve, or an internal-only one (.internal/.local/...), is "not evaluable" -- it never produces findings and never counts as clean.
Assets: type 'Domain' (asset_name = the domain), registered by hand or via POST /api/dns/check; URL assets that carry a real host name are audited too.
"""
import ipaddress
import re
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlparse

MARKER_CVE = "DNS-SECURITY-AUDIT"
SCAN_ENGINE = "dns-security"
_INTERNAL_SUFFIXES = (".internal", ".local", ".lan", ".intranet", ".corp", ".home", ".localdomain", ".test", ".example", ".invalid")
_TWO_LEVEL = {"gob.mx", "com.mx", "org.mx", "edu.mx", "net.mx", "co.uk", "org.uk", "com.br", "com.ar", "com.co"}
_LOOKUP_MECH = re.compile(r"^[+\-~?]?(include|a|mx|ptr|exists|redirect)\b", re.IGNORECASE)


# ----------------------------------------------------------------------------------------------------------------- domain handling
def host_of(value: str) -> str:
    raw = (value or "").strip()
    if "://" not in raw:
        raw = "//" + raw
    return (urlparse(raw).hostname or "").lower().rstrip(".")


def registrable_domain(value: str) -> Optional[str]:
    """Registrable domain of a host/URL, or None for an IP, an internal name or something that is not a domain. Heuristic public-suffix handling (the common
    two-level suffixes of this organisation's world); no external list is downloaded."""
    host = host_of(value)
    if not host or "." not in host:
        return None
    try:
        ipaddress.ip_address(host)
        return None
    except ValueError:
        pass
    if host.endswith(_INTERNAL_SUFFIXES):
        return None
    labels = host.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in _TWO_LEVEL:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


# ----------------------------------------------------------------------------------------------------------------- DNS access
def _dns_query(name: str, rdtype: str) -> Optional[List[str]]:
    """List of record texts; [] when the name exists but has no such record; None when the name does not exist or the lookup failed."""
    import dns.exception
    import dns.resolver
    try:
        ans = dns.resolver.resolve(name, rdtype, lifetime=8)
        out = []
        for r in ans:
            out.append("".join(p.decode() if isinstance(p, bytes) else p for p in r.strings) if rdtype == "TXT" else r.to_text())
        return out
    except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return []
    except (dns.resolver.NXDOMAIN, dns.exception.Timeout):
        return None
    except Exception:
        import traceback
        traceback.print_exc()
        return None


# ----------------------------------------------------------------------------------------------------------------- evaluation (pure given a query fn)
def _f(rule, sev, domain, text):
    return {"cve_id": rule, "severity": sev, "url_path": domain, "description": text}


def count_spf_lookups(spf: str, query: Callable, depth: int = 0, seen: Optional[set] = None) -> int:
    """DNS-lookup mechanisms of an SPF record, following include:/redirect= (RFC 7208 limits the total to 10)."""
    seen = seen if seen is not None else set()
    if depth > 10:
        return 99
    total = 0
    for term in spf.split()[1:]:
        if not _LOOKUP_MECH.match(term):
            continue
        total += 1
        m = re.match(r"^[+\-~?]?(?:include:|redirect=)([^\s]+)", term, re.IGNORECASE)
        if m and m.group(1).lower() not in seen:
            seen.add(m.group(1).lower())
            for txt in (query(m.group(1), "TXT") or []):
                if txt.lower().startswith("v=spf1"):
                    total += count_spf_lookups(txt, query, depth + 1, seen)
    return total


def evaluate_domain(domain: str, query: Callable[[str, str], Optional[List[str]]] = _dns_query) -> Dict[str, Any]:
    """{'status': 'ok'|'unresolvable'|'internal', 'findings': [...], 'not_evaluated': [...], 'has_mx': bool}"""
    reg = registrable_domain(domain)
    if reg is None:
        return {"status": "internal", "domain": domain, "findings": [], "not_evaluated": [], "has_mx": False}
    ns, soa, mx, txt = query(reg, "NS"), query(reg, "SOA"), query(reg, "MX"), query(reg, "TXT")
    if ns is None and soa is None and mx is None and txt is None:
        return {"status": "unresolvable", "domain": reg, "findings": [], "not_evaluated": [], "has_mx": False}
    has_mx = bool(mx) and not all(m.strip().endswith(" .") or m.strip().split()[-1] == "." for m in mx)   # a null MX ("0 .") means "no mail"
    findings: List[Dict[str, Any]] = []

    # ---- SPF
    spf_records = [t for t in (txt or []) if t.lower().startswith("v=spf1")]
    dmarc_records = [t for t in (query(f"_dmarc.{reg}", "TXT") or []) if t.lower().startswith("v=dmarc1")]
    dmarc_tags = dict(p.strip().split("=", 1) for p in (dmarc_records[0].split(";") if dmarc_records else []) if "=" in p)
    dmarc_policy = dmarc_tags.get("p", "").strip().lower()
    enforcing = dmarc_policy in ("quarantine", "reject")
    if len(spf_records) > 1:
        findings.append(_f("DNS-SPF-MULTIPLE", "MEDIUM", reg, f"{reg} publica {len(spf_records)} registros SPF: el estándar permite solo uno y los receptores devuelven un error permanente (PermError), "
                                                           f"con lo que SPF deja de proteger. Unirlos en un solo registro TXT."))
    elif not spf_records:
        if has_mx:
            findings.append(_f("DNS-SPF-MISSING", "MEDIUM", reg, f"{reg} recibe correo (tiene MX) pero no publica SPF: cualquiera puede enviar correo haciéndose pasar por el dominio sin que el receptor tenga "
                                                               f"cómo rechazarlo. Publicar un registro TXT 'v=spf1 ... -all' con los remitentes legítimos."))
        else:
            findings.append(_f("DNS-SPF-MISSING", "LOW", reg, f"{reg} no declara servidores de correo pero tampoco publica SPF: se puede suplantar igualmente. Si el dominio no envía correo, publicar "
                                                            f"'v=spf1 -all'."))
    else:
        spf = spf_records[0]
        qual = re.search(r"\s([+\-~?]?)all\s*$", spf.strip() + " ", re.IGNORECASE)
        q = (qual.group(1) or "+") if qual else None
        if q == "+":
            findings.append(_f("DNS-SPF-PERMISSIVE", "HIGH", reg, f"El SPF de {reg} termina en '+all' (o 'all' sin calificador): autoriza a CUALQUIER servidor a enviar como el dominio; equivale a no tener SPF."))
        elif q == "?":
            findings.append(_f("DNS-SPF-PERMISSIVE", "MEDIUM", reg, f"El SPF de {reg} termina en '?all' (neutral): no indica qué hacer con remitentes no autorizados. Usar '-all' (o '~all' con DMARC en cuarentena/rechazo)."))
        elif q == "~" and not enforcing:
            findings.append(_f("DNS-SPF-SOFTFAIL", "LOW", reg, f"El SPF de {reg} usa '~all' (softfail) y no hay DMARC con política quarantine/reject que lo refuerce: los mensajes suplantados suelen entregarse."))
        elif q is None and "redirect=" not in spf.lower():
            findings.append(_f("DNS-SPF-PERMISSIVE", "MEDIUM", reg, f"El SPF de {reg} no termina en 'all' ni usa redirect=: sin una política final los remitentes no listados no se rechazan."))
        lookups = count_spf_lookups(spf, query)
        if lookups > 10:
            findings.append(_f("DNS-SPF-TOO-MANY-LOOKUPS", "MEDIUM", reg, f"El SPF de {reg} requiere {lookups} consultas DNS (límite RFC 7208: 10): los receptores lo evalúan como error y SPF deja de aplicar. "
                                                                           f"Reducir include:/a/mx o aplanar el registro."))

    # ---- DMARC
    if not dmarc_records:
        findings.append(_f("DNS-DMARC-MISSING", "MEDIUM" if has_mx else "LOW", reg,
                           f"{reg} no publica DMARC (_dmarc.{reg}): sin él, SPF y DKIM no se alinean con el remitente visible y no hay informes de intentos de suplantación. "
                           f"Empezar con 'v=DMARC1; p=none; rua=mailto:...' y subir a quarantine/reject."))
    elif dmarc_policy == "none":
        findings.append(_f("DNS-DMARC-MONITOR-ONLY", "MEDIUM" if has_mx else "LOW", reg,
                           f"La política DMARC de {reg} es p=none (solo monitoreo): registra la suplantación pero no la bloquea. Pasar a p=quarantine y luego p=reject cuando los informes estén limpios."))
    elif enforcing and dmarc_tags.get("pct", "100").strip() not in ("100", ""):
        findings.append(_f("DNS-DMARC-PARTIAL", "LOW", reg, f"DMARC de {reg} aplica la política solo a pct={dmarc_tags.get('pct')}% de los mensajes."))

    # ---- MTA-STS (only meaningful when the domain receives mail)
    if has_mx and not [t for t in (query(f"_mta-sts.{reg}", "TXT") or []) if t.lower().startswith("v=stsv1")]:
        findings.append(_f("DNS-MTASTS-MISSING", "LOW", reg, f"{reg} recibe correo pero no publica MTA-STS: los servidores que le envían no pueden exigir TLS y un atacante en la ruta puede degradar la conexión a texto claro."))

    # ---- CAA / DNSSEC
    caa = query(reg, "CAA")
    if caa == []:
        findings.append(_f("DNS-CAA-MISSING", "LOW", reg, f"{reg} no restringe con registros CAA qué autoridades pueden emitir certificados: cualquier CA pública puede emitir uno para el dominio."))
    ds = query(reg, "DS")
    if ds == []:
        findings.append(_f("DNS-DNSSEC-NOT-ENABLED", "LOW", reg, f"{reg} no tiene DNSSEC (sin registro DS en la zona padre): las respuestas DNS no se pueden validar criptográficamente."))

    return {"status": "ok", "domain": reg, "findings": findings, "has_mx": has_mx,
            "not_evaluated": ["DKIM (requiere conocer el selector del remitente; su ausencia no puede demostrarse)"]}


def run_dns_audit(asset_name: str, endpoint: str) -> Dict[str, Any]:
    return evaluate_domain(endpoint or asset_name)


def log_dns_findings(asset_id: str, result: Dict[str, Any]) -> int:
    from core import db_manager, deduplication_engine
    st = result["status"]
    if st == "ok":
        marker = (f"Auditoría DNS/correo de {result['domain']}: {len(result['findings'])} hallazgo(s). "
                  f"No evaluado: {'; '.join(result['not_evaluated'])}.")
    else:
        marker = f"Auditoría DNS no ejecutada ({st}: el dominio {'no resuelve' if st == 'unresolvable' else 'es interno o es una IP'}); ningún control fue evaluado."
    with db_manager.get_db_cursor() as cur:
        deduplication_engine.log_finding_deduplicated(cur, asset_id, MARKER_CVE, "Info", marker, SCAN_ENGINE, url_path=MARKER_CVE,
                                                      open_status="NEW", preserve_status=True)
        if st != "ok":
            return 0
        active = {deduplication_engine.calculate_fingerprint(asset_id, MARKER_CVE, MARKER_CVE)}
        for f in result["findings"]:
            active.add(deduplication_engine.calculate_fingerprint(asset_id, f["cve_id"], f["url_path"]))
            deduplication_engine.log_finding_deduplicated(cur, asset_id, f["cve_id"], f["severity"], f["description"], SCAN_ENGINE,
                                                          url_path=f["url_path"], open_status="OPEN", preserve_status=True)
        deduplication_engine.reconcile_resolved_findings(cur, asset_id, SCAN_ENGINE, active)
    return len(result["findings"])


def audit_url_host(asset_id: str, url: str) -> Optional[int]:
    """Hook for URL assets: audits the registrable domain of the URL's host when it has one. None = nothing to audit (IP / internal name)."""
    dom = registrable_domain(url)
    if dom is None:
        return None
    return log_dns_findings(asset_id, evaluate_domain(dom))
