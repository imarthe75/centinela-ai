"""
CIS Benchmarks Hardening Auditor (Linux, Level 1 subset)

Runs real, read-only checks over SSH against a live host and scores them against a defensible
subset of CIS Level 1 Linux benchmark items -- NOT the full official CIS benchmark (which runs
to hundreds of items and is distro-version-specific); this covers the ~14 most commonly cited,
distro-general items that apply across the Debian/Ubuntu/RHEL family this org actually runs.
Every check is a single read-only shell command (no state is ever modified) executed via the
same Ansible/Vault credential path sentinel.py already uses for remediation.
"""
import subprocess
import tempfile
import os
import stat
from typing import List, Dict, Any

# (id, CIS-style description, shell command, expected-output substring/pattern that means PASS, severity if failed)
CHECKS = [
    ("CIS-1.1", "SSH root login deshabilitado (PermitRootLogin no)",
     "sshd -T 2>/dev/null | grep -i '^permitrootlogin' || grep -i '^\\s*PermitRootLogin' /etc/ssh/sshd_config",
     "no", "HIGH"),
    ("CIS-1.2", "Autenticación SSH por contraseña deshabilitada (solo llaves)",
     "sshd -T 2>/dev/null | grep -i '^passwordauthentication' || grep -i '^\\s*PasswordAuthentication' /etc/ssh/sshd_config",
     "no", "HIGH"),
    ("CIS-2.1", "/etc/passwd no es escribible por otros",
     "stat -c '%a' /etc/passwd",
     None, "HIGH"),  # special-cased: last digit must not allow write
    ("CIS-2.2", "/etc/shadow no es legible por otros",
     "stat -c '%a' /etc/shadow",
     None, "CRITICAL"),  # special-cased
    ("CIS-3.1", "Longitud mínima de contraseña >= 14 (PASS_MIN_LEN)",
     "grep -E '^PASS_MIN_LEN' /etc/login.defs",
     None, "MEDIUM"),  # special-cased: numeric >= 14
    ("CIS-4.1", "Firewall activo (ufw o firewalld)",
     # Deliberately never lets systemctl's own raw stdout reach the result: `systemctl is-active`
     # prints the literal word "inactive" on failure, which trivially contains "active" as a
     # substring -- confirmed live this produced a false PASS on a host with both ufw and
     # firewalld genuinely off. Always emit an unambiguous ACTIVE/INACTIVE ourselves instead.
     "(ufw status 2>/dev/null | grep -qi 'Status: active' && echo RESULT:ACTIVE) || "
     "(systemctl is-active --quiet firewalld 2>/dev/null && echo RESULT:ACTIVE) || echo RESULT:INACTIVE",
     "result:active", "HIGH"),
    ("CIS-5.1", "Sin cuentas con contraseña vacía",
     "awk -F: '($2==\"\"){print $1}' /etc/shadow 2>/dev/null | wc -l",
     "0", "CRITICAL"),
    ("CIS-5.2", "auditd instalado y activo (registro de auditoría)",
     "systemctl is-active --quiet auditd 2>/dev/null && echo RESULT:ACTIVE || echo RESULT:INACTIVE",
     "result:active", "MEDIUM"),
    ("CIS-6.1", "IP forwarding deshabilitado (no es un router)",
     "sysctl -n net.ipv4.ip_forward 2>/dev/null",
     "0", "LOW"),
    ("CIS-6.2", "Core dumps restringidos (fs.suid_dumpable=0)",
     "sysctl -n fs.suid_dumpable 2>/dev/null",
     "0", "LOW"),
    ("CIS-7.1", "Sincronización de tiempo activa (chrony/ntp)",
     "(systemctl is-active --quiet chrony 2>/dev/null || systemctl is-active --quiet ntp 2>/dev/null || "
     "systemctl is-active --quiet systemd-timesyncd 2>/dev/null) && echo RESULT:ACTIVE || echo RESULT:INACTIVE",
     "result:active", "LOW"),
]


def _run_ssh_command(asset_ip: str, ansible_user: str, ssh_key: str, sudo_pass: str, command: str) -> str:
    """Runs a single read-only shell command over SSH via Ansible, returns stripped stdout."""
    key_file_path = None
    try:
        cmd = [
            "ansible", "all", "-i", f"{asset_ip},", "-m", "shell", "-a", command,
            "-u", ansible_user, "--ssh-common-args=-o StrictHostKeyChecking=no",
        ]
        if ssh_key:
            fd, key_file_path = tempfile.mkstemp(prefix="cis_key_")
            with os.fdopen(fd, "w") as kf:
                kf.write(ssh_key if ssh_key.endswith("\n") else ssh_key + "\n")
            os.chmod(key_file_path, stat.S_IRUSR | stat.S_IWUSR)
            cmd += ["--private-key", key_file_path]
        elif sudo_pass:
            cmd += ["-e", f"ansible_ssh_pass={sudo_pass}"]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30, cwd="/app")
        if result.returncode not in (0,):
            return ""
        # Ansible's shell module output format: "<ip> | CHANGED | rc=0 >>\n<actual output>"
        lines = result.stdout.splitlines()
        out_lines = []
        capture = False
        for line in lines:
            if ">>" in line:
                capture = True
                continue
            if capture:
                out_lines.append(line)
        return "\n".join(out_lines).strip()
    except Exception:
        return ""
    finally:
        if key_file_path and os.path.exists(key_file_path):
            os.remove(key_file_path)


def run_cis_audit(asset_name: str, asset_ip: str) -> Dict[str, Any]:
    """
    Runs the real check subset against a live host over SSH. Returns a dict with per-check
    pass/fail, an overall percentage, and a letter grade -- same scoring shape as
    auditor_quality_gates.py for consistency.
    """
    import sys
    sys.path.insert(0, "/app")
    from sentinel import get_ansible_user, get_ssh_private_key, get_sudo_password

    ansible_user = get_ansible_user(asset_name)
    ssh_key = get_ssh_private_key(asset_name)
    sudo_pass = get_sudo_password(asset_name) if not ssh_key else ""

    results = []
    for check_id, desc, command, expected, severity in CHECKS:
        output = _run_ssh_command(asset_ip, ansible_user, ssh_key, sudo_pass, command)

        if check_id == "CIS-2.1":
            passed = bool(output) and output[-1] in ("0", "2", "4", "6")  # no write bit for "other"
        elif check_id == "CIS-2.2":
            passed = bool(output) and output[-1] in ("0",)  # no read/write for "other"
        elif check_id == "CIS-3.1":
            try:
                num = int(output.split()[-1])
                passed = num >= 14
            except (ValueError, IndexError):
                passed = False
        else:
            passed = expected is not None and expected.lower() in output.lower()

        results.append({
            "id": check_id, "description": desc, "passed": passed,
            "severity": severity, "raw_output": output[:200],
        })

    total = len(results)
    passed_count = sum(1 for r in results if r["passed"])
    pct = round((passed_count / total) * 100, 1) if total else 0.0
    grade = "A" if pct >= 90 else ("B" if pct >= 75 else ("C" if pct >= 50 else "F"))

    return {"asset_name": asset_name, "checks": results, "passed": passed_count,
            "total": total, "percentage": pct, "grade": grade}


def log_cis_findings(asset_id: int, audit_result: Dict[str, Any]):
    """Persists failed CIS checks as real findings via the shared dedup/cross-tool logger."""
    from core import db_manager, deduplication_engine

    with db_manager.get_db_cursor() as cur:
        for check in audit_result["checks"]:
            if check["passed"]:
                continue
            description = (
                f"**Referencia CIS:** {check['id']}\n"
                f"**Control:** {check['description']}\n"
                f"**Resultado observado:** `{check['raw_output'] or '(sin salida / comando no aplicable)'}`"
            )
            # preserve_status=True: a check that keeps failing on every periodic re-run
            # shouldn't bounce an already-CORRELATED/reviewed finding back to OPEN each time --
            # matches every other engine's dedup call (see deduplication_engine.py docstring).
            deduplication_engine.log_finding_deduplicated(
                cur, asset_id, check["id"], check["severity"], description,
                "cis-benchmark", url_path=check["id"], open_status="OPEN", preserve_status=True
            )

        # Always leave a real, honest completion marker (pass or fail) -- unlike the per-check
        # findings above, this fires every run regardless of outcome, so the periodic scheduler
        # in centinela.py can tell "never checked" apart from "checked N days ago, all green"
        # by querying this row's detected_at instead of needing a dedicated schema column.
        marker_desc = f"Auditoría CIS Benchmarks completada. Grade: {audit_result['grade']} ({audit_result['percentage']}%, {audit_result['passed']}/{audit_result['total']} checks aprobados)."
        deduplication_engine.log_finding_deduplicated(
            cur, asset_id, "CIS-BENCHMARK-AUDIT", "Info", marker_desc,
            "cis-benchmark", url_path="CIS-BENCHMARK-AUDIT", open_status="NEW", preserve_status=True
        )
