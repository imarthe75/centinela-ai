"""
OS patch-level & lifecycle auditor (read-only, over SSH).

Closes a real coverage gap found 2026-09-23: Centinela audited repos, web surfaces and CIS
hardening, but nothing told an operator that a SERVER had pending *security* updates, needed a
reboot to activate a kernel fix, had no automatic-update mechanism, or was running an OS release
past end-of-life (a live CentOS 8 host had exactly this profile).

One read-only shell script is sent per host (base64, so quoting can't break it) and returns
KEY=VALUE facts; `evaluate_os_facts()` is a PURE function that turns facts into findings, so the
decision logic is unit-testable without SSH. An unreachable host yields NO findings and an honest
SIN_CONEXION marker -- never a fabricated result (same contract as auditor_cis_benchmarks).
"""
import base64
import re
import time
from datetime import date
from typing import Any, Dict, List, Optional

SCAN_ENGINE = "os-patch"
MARKER_CVE = "OS-PATCH-AUDIT"
PACKAGE_INDEX_STALE_DAYS = 30

# Distro releases whose vendor support has clearly ended. (id, version_prefix) -> (label, EOL date).
# Only entries whose end-of-support date is unambiguous and already past are listed; a release
# missing from this table is simply not judged (no false "EOL" claims).
EOL_RELEASES = {
    ("centos", "7"): ("CentOS Linux 7", date(2024, 6, 30)),
    ("centos", "8"): ("CentOS Linux 8", date(2021, 12, 31)),
    ("rhel", "7"): ("Red Hat Enterprise Linux 7", date(2024, 6, 30)),
    ("ubuntu", "14.04"): ("Ubuntu 14.04 LTS", date(2019, 4, 30)),
    ("ubuntu", "16.04"): ("Ubuntu 16.04 LTS", date(2021, 4, 30)),
    ("ubuntu", "18.04"): ("Ubuntu 18.04 LTS", date(2023, 5, 31)),
    ("ubuntu", "20.04"): ("Ubuntu 20.04 LTS", date(2025, 5, 31)),
    ("debian", "8"): ("Debian 8", date(2018, 6, 17)),
    ("debian", "9"): ("Debian 9", date(2022, 6, 30)),
    ("debian", "10"): ("Debian 10", date(2024, 6, 30)),
}

_PROBE_SCRIPT = r"""
. /etc/os-release 2>/dev/null
echo "OS_ID=${ID:-unknown}"; echo "OS_VERSION=${VERSION_ID:-unknown}"; echo "OS_PRETTY=${PRETTY_NAME:-unknown}"
echo "KERNEL_RUNNING=$(uname -r)"
if command -v apt-get >/dev/null 2>&1; then
  echo "PKG=apt"
  echo "SEC_PENDING=$(apt-get -s upgrade 2>/dev/null | grep -c '^Inst.*-security')"
  echo "ANY_PENDING=$(apt-get -s upgrade 2>/dev/null | grep -c '^Inst')"
  if [ -f /var/run/reboot-required ]; then echo "REBOOT=yes"; else echo "REBOOT=no"; fi
  echo "AUTO_UPDATES=$(systemctl is-enabled unattended-upgrades 2>/dev/null || echo not-installed)"
  STAMP=$(stat -c %Y /var/lib/apt/periodic/update-success-stamp 2>/dev/null || stat -c %Y /var/lib/apt/lists 2>/dev/null || echo 0)
  echo "INDEX_AGE_DAYS=$(( ( $(date +%s) - STAMP ) / 86400 ))"
elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
  echo "PKG=rpm"
  PM=$(command -v dnf || command -v yum)
  echo "SEC_PENDING=$($PM -q updateinfo list security 2>/dev/null | grep -cE '^[A-Z]{2,6}-[0-9]{4}:[0-9]+')"
  if command -v needs-restarting >/dev/null 2>&1; then
    if needs-restarting -r >/dev/null 2>&1; then echo "REBOOT=no"; else echo "REBOOT=yes"; fi
  else echo "REBOOT=unknown"; fi
  if systemctl is-enabled dnf-automatic.timer >/dev/null 2>&1 || systemctl is-enabled yum-cron >/dev/null 2>&1; then
    echo "AUTO_UPDATES=enabled"; else echo "AUTO_UPDATES=disabled"; fi
else
  echo "PKG=unknown"
fi
echo "PROBE_DONE=1"
"""


def _probe_command() -> str:
    b64 = base64.b64encode(_PROBE_SCRIPT.encode()).decode()
    return f"echo {b64} | base64 -d | sh"


def parse_facts(output: str) -> Dict[str, str]:
    facts: Dict[str, str] = {}
    for line in (output or "").splitlines():
        m = re.match(r"^([A-Z_]+)=(.*)$", line.strip())
        if m:
            facts[m.group(1)] = m.group(2).strip()
    return facts


def _int(v: Optional[str]) -> Optional[int]:
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return None


def evaluate_os_facts(facts: Dict[str, str], today: Optional[date] = None) -> List[Dict[str, Any]]:
    """Facts -> findings. Pure; never invents a finding for a fact that was not observed."""
    today = today or date.today()
    out: List[Dict[str, Any]] = []
    if facts.get("PROBE_DONE") != "1":
        return out
    pretty = facts.get("OS_PRETTY", "SO desconocido")
    os_id, os_ver = facts.get("OS_ID", "").lower(), facts.get("OS_VERSION", "")

    for (eid, evprefix), (label, eol) in EOL_RELEASES.items():
        if os_id == eid and (os_ver == evprefix or os_ver.startswith(evprefix + ".")) and eol < today:
            out.append({"cve_id": "OS-EOL", "severity": "CRITICAL", "url_path": f"os:{eid}-{evprefix}",
                        "description": (f"**Sistema operativo fuera de soporte:** {label} ({pretty}) terminó su soporte del "
                                        f"fabricante el {eol.isoformat()}. Ya no recibe parches de seguridad: cualquier "
                                        f"vulnerabilidad nueva del sistema base o de sus paquetes quedará sin corregir.")})
            break

    sec = _int(facts.get("SEC_PENDING"))
    if sec:
        sev = "HIGH" if sec >= 10 else "MEDIUM"
        anyp = _int(facts.get("ANY_PENDING"))
        extra = f" ({anyp} actualizaciones en total)" if anyp else ""
        out.append({"cve_id": "OS-PATCH-SECURITY-UPDATES-PENDING", "severity": sev, "url_path": "os:security-updates",
                    "description": (f"**{sec} actualización(es) de seguridad pendientes** en {pretty}{extra}, según el índice de "
                                    f"paquetes del propio host. Cada una corrige vulnerabilidades ya publicadas.")})

    if facts.get("REBOOT") == "yes":
        out.append({"cve_id": "OS-REBOOT-REQUIRED", "severity": "MEDIUM", "url_path": "os:reboot-required",
                    "description": (f"**Reinicio pendiente en {pretty}:** hay paquetes (típicamente el kernel) actualizados cuyo "
                                    f"parche NO está activo hasta reiniciar; el host sigue ejecutando código vulnerable "
                                    f"(kernel en ejecución: {facts.get('KERNEL_RUNNING', 'N/D')}).")})

    auto = facts.get("AUTO_UPDATES", "")
    if auto in ("not-installed", "disabled", "masked") or (auto and auto not in ("enabled", "static", "alias", "generated", "indirect")):
        out.append({"cve_id": "OS-AUTO-UPDATES-DISABLED", "severity": "LOW", "url_path": "os:auto-updates",
                    "description": (f"**Sin actualizaciones automáticas de seguridad** en {pretty} (estado: {auto}). Los parches "
                                    f"dependen de intervención manual, lo que en la práctica retrasa su aplicación.")})

    age = _int(facts.get("INDEX_AGE_DAYS"))
    if age is not None and age > PACKAGE_INDEX_STALE_DAYS and age < 20000:
        out.append({"cve_id": "OS-PACKAGE-INDEX-STALE", "severity": "MEDIUM", "url_path": "os:package-index",
                    "description": (f"**Índice de paquetes sin refrescar hace {age} días** en {pretty}: el conteo de actualizaciones "
                                    f"pendientes no es confiable (el host ni siquiera conoce los parches recientes).")})
    return out


def run_os_patch_audit(asset_name: str, asset_ip: str) -> Dict[str, Any]:
    """One read-only SSH probe. Returns {"reachable": bool, "facts": {...}, "findings": [...]}."""
    import sys
    sys.path.insert(0, "/app")
    from auditors.auditor_cis_benchmarks import _run_ssh_command
    from sentinel import get_ansible_user, get_ssh_private_key, get_sudo_password

    host = str(asset_ip or "")
    if "://" in host:
        host = host.split("://", 1)[1]
    host = host.split("@")[-1].split("/")[0].split(":")[0]

    ssh_key = get_ssh_private_key(asset_name)
    sudo_pass = get_sudo_password(asset_name) if not ssh_key else ""
    output = _run_ssh_command(host, get_ansible_user(asset_name), ssh_key, sudo_pass, _probe_command())
    if output is None:
        return {"asset_name": asset_name, "reachable": False, "facts": {}, "findings": []}
    facts = parse_facts(output)
    return {"asset_name": asset_name, "reachable": facts.get("PROBE_DONE") == "1", "facts": facts,
            "findings": evaluate_os_facts(facts)}


def log_os_patch_findings(asset_id: str, result: Dict[str, Any]) -> int:
    """Persist findings + always an honest completion marker; reconcile findings that no longer hold."""
    from core import db_manager, deduplication_engine

    facts = result.get("facts", {})
    with db_manager.get_db_cursor() as cur:
        if not result["reachable"]:
            marker = "Auditoría de parches del SO: no se pudo establecer conexión SSH; ningún control fue evaluado."
        else:
            marker = (f"Auditoría de parches del SO completada: {facts.get('OS_PRETTY', 'N/D')}; "
                      f"{len(result['findings'])} hallazgo(s).")
        deduplication_engine.log_finding_deduplicated(
            cur, asset_id, MARKER_CVE, "Info", marker, SCAN_ENGINE, url_path=MARKER_CVE,
            open_status="NEW", preserve_status=True)
        if not result["reachable"]:
            return 0
        active = set()
        for f in result["findings"]:
            active.add(deduplication_engine.calculate_fingerprint(asset_id, f["cve_id"], f["url_path"]))
            deduplication_engine.log_finding_deduplicated(
                cur, asset_id, f["cve_id"], f["severity"], f["description"], SCAN_ENGINE,
                url_path=f["url_path"], open_status="OPEN", preserve_status=True)
        # Marker fingerprint stays active so it is never reconciled away.
        active.add(deduplication_engine.calculate_fingerprint(asset_id, MARKER_CVE, MARKER_CVE))
        deduplication_engine.reconcile_resolved_findings(cur, asset_id, SCAN_ENGINE, active)
    return len(result["findings"])
