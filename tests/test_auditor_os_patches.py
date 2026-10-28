from datetime import date

from auditors import auditor_os_patches as op

TODAY = date(2026, 9, 23)


def _facts(**kw):
    base = {"PROBE_DONE": "1", "OS_ID": "ubuntu", "OS_VERSION": "22.04", "OS_PRETTY": "Ubuntu 22.04.5 LTS",
            "PKG": "apt", "SEC_PENDING": "0", "ANY_PENDING": "0", "REBOOT": "no", "AUTO_UPDATES": "enabled",
            "INDEX_AGE_DAYS": "1", "KERNEL_RUNNING": "5.15.0-1"}
    base.update(kw)
    return base


def ids(facts):
    return {f["cve_id"] for f in op.evaluate_os_facts(facts, TODAY)}


def test_clean_host_has_no_findings():
    assert ids(_facts()) == set()


def test_incomplete_probe_yields_nothing():
    assert op.evaluate_os_facts({"OS_ID": "ubuntu"}, TODAY) == []


def test_pending_security_updates_severity_scales():
    f = op.evaluate_os_facts(_facts(SEC_PENDING="3"), TODAY)
    assert f[0]["cve_id"] == "OS-PATCH-SECURITY-UPDATES-PENDING" and f[0]["severity"] == "MEDIUM"
    assert op.evaluate_os_facts(_facts(SEC_PENDING="25"), TODAY)[0]["severity"] == "HIGH"


def test_eol_release_is_critical_and_current_release_is_not():
    assert ids(_facts(OS_ID="centos", OS_VERSION="8", OS_PRETTY="CentOS Linux 8")) == {"OS-EOL"}
    assert "OS-EOL" not in ids(_facts(OS_ID="ubuntu", OS_VERSION="24.04"))
    assert "OS-EOL" not in ids(_facts(OS_ID="ubuntu", OS_VERSION="22.04"))
    assert "OS-EOL" in ids(_facts(OS_ID="debian", OS_VERSION="10"))


def test_reboot_autoupdates_and_stale_index():
    got = ids(_facts(REBOOT="yes", AUTO_UPDATES="not-installed", INDEX_AGE_DAYS="90"))
    assert got == {"OS-REBOOT-REQUIRED", "OS-AUTO-UPDATES-DISABLED", "OS-PACKAGE-INDEX-STALE"}


def test_unknown_reboot_state_is_not_a_finding():
    assert "OS-REBOOT-REQUIRED" not in ids(_facts(REBOOT="unknown"))


def test_parse_facts():
    out = "junk\nOS_ID=debian\nSEC_PENDING=4\nPROBE_DONE=1\n"
    assert op.parse_facts(out) == {"OS_ID": "debian", "SEC_PENDING": "4", "PROBE_DONE": "1"}


def test_probe_script_is_valid_shell(tmp_path):
    import subprocess
    p = tmp_path / "probe.sh"
    p.write_text(op._PROBE_SCRIPT)
    assert subprocess.run(["sh", "-n", str(p)]).returncode == 0
