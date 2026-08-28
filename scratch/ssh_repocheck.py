import sys, subprocess, os
sys.path.insert(0, "/app")
import main
pw = main.get_ansible_credentials("sideco-siat-genesi")["sudo_password"]
env = dict(os.environ, SSHPASS=pw)
B = ["sshpass", "-e", "ssh", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
     "-o", "ConnectTimeout=10", "-o", "LogLevel=ERROR", "fsadm@10.4.2.185"]
r = subprocess.run(
    B + ['timeout 35 sudo -S -p "" dnf repolist --enabled 2>&1 | tail -20'],
    input=pw + "\n", capture_output=True, text=True, env=env, timeout=55)
print("REPOLIST:\n", (r.stdout or r.stderr).strip()[:2000])
