import sys, subprocess, os
sys.path.insert(0, "/app")
import main
pw = main.get_ansible_credentials("sideco-siat-genesi")["sudo_password"]
env = dict(os.environ, SSHPASS=pw)
BASE = ["sshpass","-e","ssh","-o","StrictHostKeyChecking=no","-o","UserKnownHostsFile=/dev/null",
        "-o","ConnectTimeout=12","-o","LogLevel=ERROR","fsadm@10.4.2.185"]
def sudo(label, cmd, t=240):
    print(f"\n### {label}", flush=True)
    try:
        r = subprocess.run(BASE + [f"sudo -S -p '' bash -lc {chr(39)+cmd.replace(chr(39), chr(39)+chr(92)+chr(39)+chr(39))+chr(39)}"],
                           input=pw+"\n", capture_output=True, text=True, env=env, timeout=t)
        print((r.stdout or "").strip()[:2000] or "(no stdout)", flush=True)
        if r.stderr.strip(): print("ERR:", r.stderr.strip()[:300], flush=True)
    except Exception as e:
        print("EXC", e, flush=True)
sudo("total pending package updates", "dnf -q check-update 2>/dev/null | grep -cE '^[a-zA-Z0-9]' ; echo done")
sudo("security-relevant advisories", "dnf -q updateinfo --security list 2>/dev/null | tail -30")
sudo("os EOL / repo status", "dnf repolist 2>/dev/null; echo '---'; grep -h baseurl /etc/yum.repos.d/*.repo 2>/dev/null | head")
sudo("apache TLS effective config", "grep -rniE 'SSLProtocol|SSLCipherSuite|SSLHonorCipherOrder|ServerTokens|ServerSignature|Header ' /etc/httpd/conf.d/ssl.conf /etc/httpd/conf.d/sideco.conf /etc/httpd/conf/httpd.conf 2>/dev/null")
sudo("sideco.conf + citaOnline proxy", "cat /etc/httpd/conf.d/sideco.conf 2>/dev/null | head -60")
