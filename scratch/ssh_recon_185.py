import sys, subprocess, os
sys.path.insert(0, "/app")
import main
pw = main.get_ansible_credentials("sideco-siat-genesi")["sudo_password"]
if not pw:
    print("NO PASSWORD IN VAULT"); sys.exit(1)
env = dict(os.environ, SSHPASS=pw)
BASE = ["sshpass", "-e", "ssh", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
        "-o", "ConnectTimeout=12", "fsadm@10.4.2.185"]
def run(label, remote):
    print(f"\n### {label}", flush=True)
    try:
        r = subprocess.run(BASE + [remote], capture_output=True, text=True, env=env, timeout=60)
        print((r.stdout or "").strip()[:1800] or "(no stdout)", flush=True)
        if r.returncode != 0 and r.stderr.strip():
            print("STDERR:", r.stderr.strip()[:400], flush=True)
    except Exception as e:
        print("ERR", e, flush=True)
run("OS / kernel / uptime", "cat /etc/redhat-release 2>/dev/null; uname -r; uptime")
run("listening ports", "sudo -S -p '' ss -tlnp </dev/null 2>/dev/null | grep -vE '127.0.0.1|::1'")
run("web/app processes", "ps -eo user,pid,comm,args 2>/dev/null | grep -iE 'httpd|java|tomcat|nginx|node' | grep -v grep")
run("httpd version + sec modules", "httpd -v 2>/dev/null; httpd -M 2>/dev/null | grep -iE 'ssl|security|headers'")
run("firewall", "sudo -S -p '' bash -c 'systemctl is-active firewalld; systemctl is-active iptables; iptables -S 2>/dev/null | head' </dev/null")
run("SELinux", "getenforce 2>/dev/null")
run("pending updates", "sudo -S -p '' bash -c 'yum -q check-update 2>/dev/null | grep -c . ; echo ---sec---; yum -q updateinfo list security 2>/dev/null | tail -20' </dev/null")
run("disk", "df -h / /var /opt 2>/dev/null")
