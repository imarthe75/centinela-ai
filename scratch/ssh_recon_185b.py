import sys, subprocess, os
sys.path.insert(0, "/app")
import main
pw = main.get_ansible_credentials("sideco-siat-genesi")["sudo_password"]
env = dict(os.environ, SSHPASS=pw)
BASE = ["sshpass", "-e", "ssh", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
        "-o", "ConnectTimeout=12", "-o", "LogLevel=ERROR", "fsadm@10.4.2.185"]
def sudo(label, cmd):
    print(f"\n### {label}", flush=True)
    remote = f"sudo -S -p '' bash -lc {subprocess_quote(cmd)}"
    try:
        r = subprocess.run(BASE + [remote], input=pw + "\n", capture_output=True, text=True, env=env, timeout=90)
        out = (r.stdout or "").strip()
        print(out[:2500] or "(no stdout)", flush=True)
        if not out and r.stderr.strip():
            print("STDERR:", r.stderr.strip()[:400], flush=True)
    except Exception as e:
        print("ERR", e, flush=True)
def subprocess_quote(s):
    return "'" + s.replace("'", "'\\''") + "'"
sudo("listening ports (non-loopback)", "ss -tlnp | grep -vE '127.0.0.1|::1' | sort -u")
sudo("firewall + iptables", "systemctl is-active firewalld 2>&1; systemctl is-active nftables 2>&1; iptables -S 2>&1 | head -20; nft list ruleset 2>&1 | head -10")
sudo("all java processes (full args truncated)", "ps -eo user,pid,etime,args | grep -i java | grep -v grep | sed 's/\\(.\\{200\\}\\).*/\\1.../'")
sudo("tomcat / app dirs", "ls -d /opt/tomcat* /usr/share/tomcat* /opt/*siat* /opt/*sideco* /var/www/html/* 2>/dev/null; systemctl list-units --type=service --state=running | grep -iE 'tomcat|siat|sideco|citaonline|solicitud' ")
sudo("pending updates count + security advisories", "yum -q check-update 2>/dev/null | grep -c '^[a-zA-Z0-9]'; echo '--- security ---'; yum -q updateinfo list security 2>/dev/null | tail -25; echo '--- yum repos ---'; yum repolist 2>/dev/null | tail -8")
sudo("apache config: TLS + headers for the two vhosts", "httpd -S 2>&1 | head -30; echo '---'; grep -rniE 'SSLProtocol|SSLCipher|Header (set|always)|ServerTokens|ServerSignature' /etc/httpd/conf /etc/httpd/conf.d 2>/dev/null | head -40")
