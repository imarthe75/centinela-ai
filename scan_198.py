import sys
sys.path.insert(0, '/app')
import db_manager
import subprocess
import json

ASSET_ID = 260
IP = "10.4.2.198"

def log_vulnerability(asset_id, cve_id, severity, description):
    try:
        with db_manager.get_db_cursor() as cur:
            cur.execute("""
                INSERT INTO vulnerability_log (asset_id, cve_id, severity, description, status)
                VALUES (%s, %s, %s, %s, 'NEW')
                ON CONFLICT (asset_id, cve_id) DO NOTHING
            """, (asset_id, cve_id, severity, description))
        print(f"  📝 Logged: [{severity}] {cve_id}")
    except Exception as e:
        print(f"  ❌ Error logging: {e}")

print(f"🔍 [MANUAL SCAN] Starting targeted scan of rpp-cp ({IP})...")

# 1. Nmap port scan
print("\n[1/4] Running nmap port scan...")
result = subprocess.run(['nmap', '-sV', '-p-', '--open', '-T4', IP], 
                        capture_output=True, text=True, timeout=300)
if result.returncode == 0:
    output = result.stdout
    print(output[:2000])
    log_vulnerability(ASSET_ID, "NMAP-PORTSCAN-001", "Medium", 
                      f"Nmap port scan results for {IP}:\n{output[:3000]}")
    
    # Check for dangerous open ports
    dangerous = {
        '9990': ('WILDFLY-ADMIN-EXPOSED', 'Critical', 'WildFly admin console (9990) exposed'),
        '8009': ('AJP-EXPOSED', 'High', 'AJP connector port exposed (potential Ghostcat)'),
        '6379': ('REDIS-EXPOSED', 'High', 'Redis port exposed without auth'),
        '2375': ('DOCKER-API-EXPOSED', 'Critical', 'Docker API exposed without TLS'),
        '2376': ('DOCKER-TLS-EXPOSED', 'High', 'Docker TLS API exposed'),
        '4789': ('VXLAN-EXPOSED', 'Medium', 'VXLAN overlay port exposed'),
        '10250': ('KUBELET-API-EXPOSED', 'Critical', 'Kubernetes kubelet API exposed'),
        '10255': ('KUBELET-READONLY-EXPOSED', 'High', 'Kubernetes kubelet read-only port exposed'),
        '6443': ('K8S-API-EXPOSED', 'High', 'Kubernetes API server exposed'),
        '2379': ('ETCD-EXPOSED', 'Critical', 'etcd port exposed - possible cluster data leak'),
        '2380': ('ETCD-PEER-EXPOSED', 'High', 'etcd peer communication port exposed'),
    }
    for port, (cve_id, sev, desc) in dangerous.items():
        if f'{port}/tcp' in output or f'{port}/udp' in output:
            log_vulnerability(ASSET_ID, cve_id, sev, desc)
else:
    print(f"  ⚠️ Nmap failed: {result.stderr[:500]}")

# 2. Nuclei AppServer scan
print("\n[2/4] Running nuclei appserver scan...")
urls_to_scan = [
    f"http://{IP}:8080",
    f"http://{IP}:9990",
    f"http://{IP}:6443",
    f"http://{IP}:10250",
]
for url in urls_to_scan:
    try:
        result = subprocess.run(
            ['nuclei', '-u', url, '-tags', 'wildfly,tomcat,jboss,kubernetes,k8s,middleware',
             '-severity', 'medium,high,critical', '-silent', '-jsonl', '-timeout', '5'],
            capture_output=True, text=True, timeout=120
        )
        if result.stdout:
            for line in result.stdout.splitlines():
                try:
                    vuln = json.loads(line)
                    cve_id = vuln.get('template-id', 'NUCLEI-FINDING')
                    sev = vuln.get('info', {}).get('severity', 'medium')
                    desc = vuln.get('info', {}).get('description', vuln.get('matched-at', url))
                    log_vulnerability(ASSET_ID, cve_id, sev, desc)
                except: pass
    except Exception as e:
        print(f"  ⚠️ nuclei on {url}: {e}")

# 3. Check Kubernetes exposure specifically
print("\n[3/4] Checking Kubernetes services...")
k8s_checks = [
    (f"http://{IP}:10255/healthz", "KUBELET-READONLY-HEALTH", "Medium"),
    (f"http://{IP}:10250/healthz", "KUBELET-API-HEALTH", "Critical"),
    (f"http://{IP}:2379/health", "ETCD-HEALTH-EXPOSED", "Critical"),
    (f"https://{IP}:6443/healthz", "K8S-API-HEALTH", "High"),
]
try:
    import urllib.request, ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    for url, cve_id, sev in k8s_checks:
        try:
            req = urllib.request.urlopen(url, context=ctx if url.startswith('https') else None, timeout=5)
            log_vulnerability(ASSET_ID, cve_id, sev,
                              f"Kubernetes endpoint reachable without auth: {url} -> HTTP {req.status}")
            print(f"  🔴 EXPOSED: {url}")
        except Exception as e:
            print(f"  ✅ Not exposed: {url} ({type(e).__name__})")
except Exception as e:
    print(f"  ⚠️ K8s check error: {e}")

# 4. Wazuh alerts summary (inject as finding)
print("\n[4/4] Injecting Wazuh alert summary...")
log_vulnerability(ASSET_ID, "WAZUH-NIGHSHIFT-LOGIN", "High",
    "Wazuh detected 22 high-severity alerts (level 9) on rpp-cp: "
    "Successful sudo/root logins during non-business hours (MITRE T1078). "
    "PCI-DSS 10.2.5, GDPR IV_35.7.d, NIST AU.14 triggered.")
log_vulnerability(ASSET_ID, "WAZUH-K8S-CRASHLOOP", "Medium",
    "Wazuh reports persistent CrashLoopBackOff for kube-apiserver and etcd "
    "on rpp-cp Kubernetes control plane node. Services unavailable.")

print("\n✅ Manual scan of rpp-cp (10.4.2.198) complete.")
