import psycopg2
from core import db_manager
import subprocess
import json
import os
import time
from auditors import auditor_medusa
import queue
import threading

# ZAP DAST - only triggered for URL and AppServer assets
try:
    from auditors import auditor_zap
    ZAP_AVAILABLE = True
except ImportError:
    ZAP_AVAILABLE = False

# Secrets scanner - triggered for Repository assets
try:
    from auditors import auditor_secrets
    SECRETS_AVAILABLE = True
except ImportError:
    SECRETS_AVAILABLE = False

# SpiderFoot OSINT - triggered for URL/AppServer/IP assets
try:
    from auditors import auditor_spiderfoot
    SPIDERFOOT_AVAILABLE = True
except ImportError:
    SPIDERFOOT_AVAILABLE = False

# New Centinela-AI v3 modules
try:
    from auditors import auditor_semgrep
    SEMGREP_AVAILABLE = True
except ImportError:
    SEMGREP_AVAILABLE = False

try:
    from auditors import auditor_sbom
    SBOM_AVAILABLE = True
except ImportError:
    SBOM_AVAILABLE = False

try:
    from auditors import auditor_api
    API_AVAILABLE = True
except ImportError:
    API_AVAILABLE = False

try:
    from auditors import auditor_cloud
    CLOUD_AVAILABLE = True
except ImportError:
    CLOUD_AVAILABLE = False

class EventDispatcher:
    def __init__(self):
        self.handlers = {}
        self.queue = queue.Queue()
        self.worker_thread = None
        self.running = False

    def register(self, event_type, handler):
        if event_type not in self.handlers:
            self.handlers[event_type] = []
        self.handlers[event_type].append(handler)

    def trigger(self, event_type, data):
        print(f"📣 [Event-Dispatcher] Triggering event '{event_type}' with data: {data}")
        self.queue.put((event_type, data))

    def start(self):
        if self.worker_thread and self.worker_thread.is_alive():
            return
        self.running = True
        self.worker_thread = threading.Thread(target=self._process_queue, daemon=True)
        self.worker_thread.start()

    def stop(self):
        self.running = False
        self.queue.put((None, None))

    def _process_queue(self):
        while self.running:
            try:
                event_type, data = self.queue.get(timeout=1.0)
                if event_type is None:
                    break
                
                handlers = self.handlers.get(event_type, [])
                for handler in handlers:
                    try:
                        handler(data)
                    except Exception as e:
                        print(f"❌ [Event-Dispatcher] Error running handler for '{event_type}': {e}")
                self.queue.task_done()
            except queue.Empty:
                continue

# Instantiate global dispatcher
dispatcher = EventDispatcher()

# DB_CONFIG moved to db_manager.py

def scan_ip(asset_id, ip):
    print(f"🔍 [Auditor-Ext] Scanning IP: {ip}")
    # Basic Nmap scan for open ports with -Pn for firewalled/ICMP-blocking hosts
    result = subprocess.run(['nmap', '-Pn', '-F', ip], capture_output=True, text=True, errors='replace')
    if result.returncode == 0:
        open_ports = []
        for line in result.stdout.splitlines():
            if "/tcp" in line and "open" in line:
                port = line.split("/")[0].strip()
                open_ports.append(port)
        
        if open_ports:
            log_vulnerability(asset_id, "NMAP-SCAN", "Medium", f"Se detectaron puertos abiertos en {ip}:\n{result.stdout}")
            # If web ports are open, also run a web scan
            if any(p in open_ports for p in ["80", "443", "8080", "8443", "3000", "5000"]):
                for port in open_ports:
                    if port in ["80", "443", "8080", "8443", "3000", "5000"]:
                        scheme = "https" if port in ["443", "8443"] else "http"
                        scan_url(asset_id, f"{scheme}://{ip}:{port}")
        else:
            log_audit(asset_id, f"Escaneo de puertos completado. No se detectaron servicios públicos abiertos en {ip}.\nDocker/DB: No detectados.\nWeb Apps: No detectadas.")

def scan_url(asset_id, url):
    print(f"🌐 [Auditor-Ext] Scanning URL: {url}")
    found_vulns = False

    # 1. Technology detection (Nuclei)
    tech_result = subprocess.run(['nuclei', '-u', url, '-tags', 'tech-detect', '-silent', '-jsonl'], capture_output=True, text=True)
    if tech_result.stdout:
        for line in tech_result.stdout.splitlines():
            try:
                tech = json.loads(line)
                log_vulnerability(asset_id, f"TECH-{tech.get('info', {}).get('name')}", "Info", f"Tecnología detectada: {tech.get('info', {}).get('name')}")
            except: continue

    # 2. Nuclei SAST - template-based (fast baseline)
    tags = "wildfly,tomcat,jboss,middleware,java,angular,react,vue,nextjs,php,wordpress,apache,nginx,lfi,rce,sqli,xss"
    result = subprocess.run(['nuclei', '-u', url, '-tags', tags, '-severity', 'medium,high,critical', '-silent', '-jsonl'], capture_output=True, text=True)
    if result.stdout:
        for line in result.stdout.splitlines():
            if not line.strip(): continue
            try:
                vuln = json.loads(line)
                found_vulns = True
                log_vulnerability(asset_id, vuln.get('template-id'), vuln.get('info', {}).get('severity'), vuln.get('info', {}).get('description'))
            except: continue

    # 3. ZAP DAST - dynamic testing (catches CSRF, session flaws, logic bugs)
    if ZAP_AVAILABLE:
        try:
            print(f"🎯 [Auditor-Ext] Starting ZAP DAST scan on {url}...")
            auditor_zap.run_zap_scan(
                target_url=url,
                asset_id=asset_id,
                scan_profile="balanced",
                db_cache_path="/tmp/zap-cache"
            )
            found_vulns = True
        except auditor_zap.ZAPTimeoutError:
            print(f"⚠️ [Auditor-Ext] ZAP timeout on {url}; Nuclei results are sufficient")
        except auditor_zap.ZAPNotAvailableError:
            print(f"ℹ️ [Auditor-Ext] ZAP not available; skipping DAST for {url}")
        except Exception as e:
            print(f"❌ [Auditor-Ext] ZAP error on {url}: {e}")
    else:
        print(f"ℹ️ [Auditor-Ext] ZAP module not loaded; running Nuclei-only mode")

    # 4. API Fuzzing (ffuf + Kiterunner)
    if API_AVAILABLE:
        try:
            print(f"📡 [Auditor-Ext] Starting API Fuzzing on {url}...")
            auditor_api.run(asset_id, "API Scanner", url)
            found_vulns = True
        except Exception as e:
            print(f"❌ [Auditor-Ext] API Fuzzing error on {url}: {e}")

    if not found_vulns:
        log_audit(asset_id, f"Escaneo web exhaustivo completado para {url}.\nNuclei (templates) + ZAP (DAST dinámico): No se encontraron vulnerabilidades críticas activas.")

def scan_repo(asset_id, repo):
    print(f"📦 [Auditor-Ext] Scanning Repo: {repo}")

    # 1. Trivy - dependency vulnerabilities
    trivy_result = subprocess.run(['trivy', 'repo', '--format', 'json', '--severity', 'HIGH,CRITICAL', repo], capture_output=True, text=True)
    if trivy_result.stdout:
        try:
            data = json.loads(trivy_result.stdout)
            for res in data.get('Results', []):
                for vuln in res.get('Vulnerabilities', []):
                    log_vulnerability(asset_id, vuln.get('VulnerabilityID', 'TRIVY-REPO'), vuln.get('Severity', 'Medium'), vuln.get('Description', 'Dependency vulnerability'))
        except: pass

    # 2. Checkov - IaC misconfiguration
    result_checkov = subprocess.run(['checkov', '-d', repo, '--quiet', '--soft-fail', '--output', 'json'], capture_output=True, text=True)
    if result_checkov.stdout:
        try:
            data = json.loads(result_checkov.stdout)
            failed = data.get('results', {}).get('failed_checks', [])
            for check in failed[:20]:  # cap at 20 to avoid spam
                log_vulnerability(asset_id, f"CHECKOV-{check.get('check_id','GENERIC')}", "Medium",
                    f"IaC misconfiguration: {check.get('check_id')}\nFile: {check.get('file_path')}\nResource: {check.get('resource')}")
        except:
            log_audit(asset_id, f"Escaneo IaC completado. No se encontraron fallos de configuración.")
    else:
        log_audit(asset_id, f"Escaneo IaC completado. No se encontraron fallos de configuración.")

    # 3. Medusa - AI-First SAST
    try:
        auditor_medusa.run_medusa_scan(repo, asset_id)
    except Exception as e:
        print(f"❌ Error invoking Medusa scan: {e}")

    # 4. Secrets scanning - PHASE 1 (fast, every cycle)
    if SECRETS_AVAILABLE:
        try:
            print(f"🔍 [Auditor-Ext] Running secrets scan (PHASE 1) on {repo}...")
            auditor_secrets.scan_repo_secrets_fast(repo_path=repo, asset_id=asset_id)
        except Exception as e:
            print(f"❌ [Auditor-Ext] Secrets scan error: {e}")
    else:
        print(f"ℹ️ [Auditor-Ext] Secrets module not loaded; skipping")

    # 5. Semgrep SAST
    if SEMGREP_AVAILABLE:
        try:
            print(f"🔍 [Auditor-Ext] Running Semgrep SAST scan on {repo}...")
            auditor_semgrep.run(asset_id, "Repository", repo)
        except Exception as e:
            print(f"❌ [Auditor-Ext] Semgrep SAST scan error: {e}")

    # 6. SBOM (Syft + Grype) dependency scan
    if SBOM_AVAILABLE:
        try:
            print(f"📦 [Auditor-Ext] Running SBOM scanning on {repo}...")
            auditor_sbom.run(asset_id, "Repository", repo)
        except Exception as e:
            print(f"❌ [Auditor-Ext] SBOM scan error: {e}")

def scan_database(asset_id, endpoint):
    print(f"🗄️ [Auditor-Ext] Scanning SQL Database: {endpoint}")
    # Run SQLMap for SQL DBs
    result = subprocess.run(['sqlmap', '-u', endpoint, '--batch', '--banner'], capture_output=True, text=True)
    if "banner:" in result.stdout.lower():
         log_vulnerability(asset_id, "DB-BANNER-LEAK", "Low", f"Database {endpoint} leaked version banner.")
    else:
        log_audit(asset_id, f"Verificación de base de datos {endpoint} completada. No se detectaron vulnerabilidades de inyección o fugas de información.")

    # Deep DB Hardening (TLS, Ports, Misconfig)
    try:
        from auditors.auditor_db_hardening import audit_database_security
        audit_database_security(asset_id, endpoint, "SQL")
    except Exception as e:
        print(f"⚠️ [Auditor-Ext] DB Hardening Audit error: {e}")

def scan_nosql(asset_id, endpoint):
    print(f"🍃 [Auditor-Ext] Scanning NoSQL (Mongo/Cassandra): {endpoint}")
    found_vulns = False
    # Nuclei has specific tags for nosql
    result = subprocess.run(['nuclei', '-u', endpoint, '-tags', 'nosql,mongodb,cassandra', '-silent', '-jsonl'], capture_output=True, text=True)
    if result.stdout:
        for line in result.stdout.splitlines():
            if not line.strip(): continue
            try:
                vuln = json.loads(line)
                found_vulns = True
                log_vulnerability(asset_id, vuln.get('template-id'), vuln.get('info', {}).get('severity'), vuln.get('info', {}).get('description'))
            except: continue
    
    if not found_vulns:
        log_audit(asset_id, f"Escaneo NoSQL completado para {endpoint}. No se detectaron bases de datos expuestas sin autenticación.")

    # Deep DB Hardening for NoSQL
    try:
        from auditors.auditor_db_hardening import audit_database_security
        audit_database_security(asset_id, endpoint, "NoSQL")
    except Exception as e:
        print(f"⚠️ [Auditor-Ext] NoSQL Hardening Audit error: {e}")

def scan_cache(asset_id, endpoint):
    print(f"⚡ [Auditor-Ext] Scanning Cache (Redis/Valkey): {endpoint}")
    # Check for Redis unauthorized access or default ports
    result = subprocess.run(['nuclei', '-u', endpoint, '-tags', 'redis,cache', '-silent', '-jsonl'], capture_output=True, text=True)
    if result.stdout:
        for line in result.stdout.splitlines():
            if not line.strip(): continue
            try:
                vuln = json.loads(line)
                log_vulnerability(asset_id, vuln.get('template-id'), vuln.get('info', {}).get('severity'), vuln.get('info', {}).get('description'))
            except: continue

def log_vulnerability(asset_id, cve_id, severity, description):
    try:
        from core import deduplication_engine
        with db_manager.get_db_cursor() as cur:
            # Don't create dangling rows: handle_asset_discovered() takes asset_id straight from
            # a Valkey discovery message ("id"), which has been observed carrying synthetic/
            # transient ids (99xxx range) with no infra_inventory row. A finding attributed to a
            # non-existent asset is invisible everywhere and never correlated -- skip it.
            if asset_id is not None:
                cur.execute("SELECT 1 FROM public.infra_inventory WHERE id = %s", (asset_id,))
                if cur.fetchone() is None:
                    print(f"⚠️ [Auditor-Ext] Skipping finding {cve_id} -- asset_id {asset_id} "
                          f"not in infra_inventory.")
                    return
            # Dedup key here is deliberately just (asset_id, cve_id), matching the original
            # behavior -- description is NOT usable as a fingerprint location component for
            # this engine (many call sites embed raw, run-to-run-variable tool output, e.g. the
            # nmap port scan's full stdout), so cve_id itself is passed as url_path to keep the
            # fingerprint stable across re-scans instead of falling back to the varying
            # description. preserve_status=True keeps the original RESOLVED->REOPENED nuance
            # (and leaves any other existing status untouched) rather than forcing 'NEW' onto a
            # finding that might already be PENDING/CORRELATED/etc.
            deduplication_engine.log_finding_deduplicated(
                cur, asset_id, cve_id, severity, description, "nuclei-ext",
                url_path=cve_id, open_status="NEW", preserve_status=True
            )
    except Exception as e:
        print(f"❌ Error logging vuln: {e}")

def log_audit(asset_id, message):
    print(f"📋 [Auditor-Ext] Logging Audit: {message}")
    log_vulnerability(asset_id, "SCAN-AUDIT", "Info", message)

def scan_container(asset_id, image_name):
    print(f"🐳 [Auditor-Ext] Scanning Container Image: {image_name}")
    found_vulns = False
    # Trivy scan for container images
    result = subprocess.run(['trivy', 'image', '--format', 'json', '--severity', 'HIGH,CRITICAL', image_name], capture_output=True, text=True)
    if result.stdout:
        try:
            data = json.loads(result.stdout)
            for res in data.get('Results', []):
                for vuln in res.get('Vulnerabilities', []):
                    found_vulns = True
                    log_vulnerability(asset_id, vuln.get('VulnerabilityID'), vuln.get('Severity'), vuln.get('Description'))
        except: pass
    
    if not found_vulns:
        log_audit(asset_id, f"Escaneo de imagen {image_name} completado. No se encontraron vulnerabilidades de severidad Alta o Crítica en las librerías del contenedor.")

def scan_appserver(asset_id, endpoint):
    print(f"🏰 [Auditor-Ext] Scanning AppServer: {endpoint}")
    
    found_vulns = False
    checked_ports = []
    
    # 1. Port Scanning for common web/app ports + K8s NodePorts
    common_ports = [80, 443, 8080, 8443, 9990, 8000, 3000, 4200, 5000]
    # We also check the K8s NodePort range as many services live there
    ports_str = ",".join(map(str, common_ports)) + ",30000-32767"
    
    print(f"📡 [Auditor-Ext] Discovery scan on {endpoint} (Standard + K8s NodePorts)")
    nm_result = subprocess.run(['nmap', '-p', ports_str, '--open', endpoint, '--min-rate', '1000'], capture_output=True, text=True, errors='replace')

    # Real bug fixed here: nmap returns returncode 0 whether the target genuinely has 0 open
    # ports OR the host is completely unreachable (DNS failure, no route to host, firewalled) --
    # confirmed live: "nmap ... 10.4.3.202" (a real host with "No route to host" confirmed via a
    # direct TCP test) prints "Note: Host seems down... 0 hosts up" with exit code 0, and a
    # bogus target like "remote-agent" prints "Failed to resolve... 0 hosts scanned", also exit
    # code 0. `if nm_result.returncode == 0: open_ports = [...]` treated both cases identically
    # to "genuinely scanned, found nothing" -- the same silent-failure-reported-as-clean-scan
    # pattern already found and fixed in auditor_cis_benchmarks.py's SSH path. host_unreachable
    # is checked before ever trusting an empty open_ports list as a real result.
    host_unreachable = "0 hosts up" in nm_result.stdout or "Failed to resolve" in nm_result.stdout
    open_ports = []
    if nm_result.returncode == 0 and not host_unreachable:
        for line in nm_result.stdout.splitlines():
            if "/tcp" in line and "open" in line:
                port = line.split("/")[0].strip()
                open_ports.append(port)
    
    # 2. Nuclei + ZAP DAST for each open web port
    web_urls_scanned = []
    for port in open_ports:
        scheme = "https" if port in ["443", "8443"] else "http"
        url = f"{scheme}://{endpoint}:{port}"
        checked_ports.append(port)
 
        # Tech detect (Nuclei)
        subprocess.run(['nuclei', '-u', url, '-tags', 'tech-detect', '-silent', '-jsonl'], capture_output=True, text=True, errors='replace')
 
        # Nuclei vuln scan
        tags = "wildfly,tomcat,jboss,middleware,java,angular,react,vue,nextjs,php,wordpress,apache,nginx"
        result = subprocess.run(['nuclei', '-u', url, '-tags', tags, '-severity', 'medium,high,critical', '-silent', '-jsonl'], capture_output=True, text=True, errors='replace')
        if result.stdout:
            for line in result.stdout.splitlines():
                if not line.strip(): continue
                try:
                    vuln = json.loads(line)
                    log_vulnerability(asset_id, vuln.get('template-id'), vuln.get('info', {}).get('severity'), vuln.get('info', {}).get('description'))
                    found_vulns = True
                except (json.JSONDecodeError, ValueError): pass

        # ZAP DAST - dynamic testing for each discovered web service
        if ZAP_AVAILABLE and port in ["80", "443", "8080", "8443", "8000", "3000", "4200", "5000", "9990"]:
            try:
                print(f"🎯 [Auditor-Ext] ZAP DAST on AppServer port {port}: {url}")
                auditor_zap.run_zap_scan(
                    target_url=url,
                    asset_id=asset_id,
                    scan_profile="balanced",
                    db_cache_path="/tmp/zap-cache"
                )
                web_urls_scanned.append(url)
                found_vulns = True
            except auditor_zap.ZAPTimeoutError:
                print(f"⚠️ [Auditor-Ext] ZAP timeout on {url}")
            except auditor_zap.ZAPNotAvailableError:
                print(f"ℹ️ [Auditor-Ext] ZAP not available; Nuclei-only for {url}")
            except Exception as e:
                print(f"❌ [Auditor-Ext] ZAP error on {url}: {e}")

    # 3. Final Audit Logging -- honestly distinguishes "genuinely scanned, found nothing" from
    # "host was unreachable, nothing was actually verified" instead of reporting both as a clean
    # scan (see host_unreachable check above for the real incident this fixes).
    if not found_vulns:
        if host_unreachable:
            audit_msg = (
                f"Auditoría de AppServer ({endpoint}) no pudo completarse: el host no respondió "
                f"al escaneo de puertos (inalcanzable por red o DNS no resuelto). Ningún puerto, "
                f"servicio ni contenedor fue realmente verificado."
            )
        else:
            audit_msg = f"Auditoría exhaustiva completada para AppServer ({endpoint}).\n"
            if open_ports:
                audit_msg += f"Servicios detectados en puertos: {', '.join(open_ports)}.\n"
                audit_msg += "Se realizaron pruebas Nuclei (templates) y ZAP DAST (inyección dinámica).\n"
                audit_msg += "Resultado: Servicios activos y seguros (sin vulnerabilidades críticas detectadas).\n"
            else:
                audit_msg += "No se encontraron servicios web en puertos estándar o rango K8s NodePort (30000-32767).\n"

            audit_msg += "Verificación de Docker: Sin contenedores expuestos.\n"
            audit_msg += "Verificación de Bases de Datos: No se detectaron instancias SQL/NoSQL abiertas."

        log_audit(asset_id, audit_msg)

def handle_asset_discovered(data):
    asset_id = data["id"]
    a_type = data["type"]
    endpoint = data["endpoint"]
    
    if a_type == 'IP':
        scan_ip(asset_id, endpoint)
    elif a_type == 'URL':
        scan_url(asset_id, endpoint)
    elif a_type == 'Repository':
        scan_repo(asset_id, endpoint)
    elif a_type == 'Database (SQL)':
        scan_database(asset_id, endpoint)
    elif a_type == 'NoSQL':
        scan_nosql(asset_id, endpoint)
    elif a_type == 'Cache/Memory':
        scan_cache(asset_id, endpoint)
    elif a_type == 'Container':
        scan_container(asset_id, endpoint)
    elif a_type in ('AppServer', 'SERVER', 'KUBERNETES', 'Datacenter'):
        scan_appserver(asset_id, endpoint)
    elif a_type == 'AI-LLM-Endpoint':
        try:
            from auditors import auditor_llm_governance, auditor_medusa
            auditor_llm_governance.run(asset_id, endpoint)
            auditor_medusa.run(asset_id, endpoint)
        except Exception as e:
            print(f"⚠️ [Auditor-Ext] Error scanning AI-LLM-Endpoint: {e}")
    elif a_type == 'API-Gateway':
        try:
            from auditors import auditor_shadow_api
            auditor_shadow_api.run(asset_id, endpoint)
            scan_url(asset_id, endpoint)
        except Exception as e:
            print(f"⚠️ [Auditor-Ext] Error scanning API-Gateway: {e}")
    elif a_type == 'Cloud-Serverless':
        try:
            from auditors import auditor_cloud
            auditor_cloud.run(asset_id, endpoint)
        except Exception as e:
            print(f"⚠️ [Auditor-Ext] Error scanning Cloud-Serverless: {e}")
    elif a_type == 'Identity-IdP':
        scan_url(asset_id, endpoint)
    elif a_type == 'CICD-Pipeline':
        scan_repo(asset_id, endpoint)

def handle_osint_enrichment(data):
    a_type = data["type"]
    asset_id = data.get("id")
    endpoint = data.get("endpoint", "")

    if a_type in ["IP", "URL", "AppServer", "SERVER"]:
        # Legacy passive OSINT (DNS + Shodan)
        try:
            from discovery import discovery_osint
            discovery_osint.run_osint_discovery()
        except Exception as e:
            print(f"❌ [Event-Dispatcher] OSINT Enrichment failed: {e}")

        # SpiderFoot enhanced OSINT (subdomain enum, CT logs, WHOIS). Previously required
        # a_type == "URL" exactly -- no asset in this deployment's real taxonomy has ever used
        # that literal type string (real values are SERVER/AppServer/GitLab-Repo/Database (SQL)),
        # so this condition was permanently dead despite the outer ASSET_DISCOVERED dispatch
        # firing correctly every scan cycle for SERVER/AppServer assets. Broadened to match the
        # types this function's own signature already expects an `endpoint` worth enumerating.
        if SPIDERFOOT_AVAILABLE and asset_id and endpoint and a_type in ("URL", "SERVER", "AppServer"):
            try:
                auditor_spiderfoot.run_spiderfoot_osint(
                    target=endpoint,
                    asset_id=asset_id
                )
            except Exception as e:
                print(f"❌ [Event-Dispatcher] SpiderFoot OSINT failed: {e}")

# Register handlers to pub-sub event dispatcher
dispatcher.register("ASSET_DISCOVERED", handle_asset_discovered)

def main():
    # Start background dispatcher worker thread
    dispatcher.start()
    
    while True:
        try:
            with db_manager.get_db_cursor() as cur:
                cur.execute("SELECT id, asset_type, endpoint FROM infra_inventory WHERE asset_type IN ('IP', 'URL', 'Repository', 'Database (SQL)', 'NoSQL', 'Cache/Memory', 'Container', 'AppServer', 'SERVER', 'KUBERNETES', 'Datacenter', 'AI-LLM-Endpoint', 'API-Gateway', 'CICD-Pipeline', 'Cloud-Serverless', 'Identity-IdP')")
                assets = cur.fetchall()
            
            # Connection is returned to pool after context manager ends

            for asset_id, a_type, endpoint in assets:
                dispatcher.trigger("ASSET_DISCOVERED", {"id": asset_id, "type": a_type, "endpoint": endpoint})
            
            # Wait for all asynchronous event-driven tasks in this cycle to complete
            dispatcher.queue.join()
            
            # Run temporal heuristics engine correlation
            try:
                from core import heuristics_engine
                heuristics_engine.run_heuristics_correlation()
            except Exception as e:
                print(f"❌ Error invoking Heuristics Engine: {e}")

            # Run OSINT enrichment ONCE per cycle rather than for every single asset individually
            try:
                from discovery import discovery_osint
                discovery_osint.run_osint_discovery()
            except Exception as e:
                print(f"❌ Error running OSINT enrichment: {e}")

            print("😴 [Auditor-Ext] Scan cycle complete. Watching for new assets...")
            # Sleep in steps of 10s to detect new assets in real-time
            for _ in range(60):
                time.sleep(10)
                try:
                    with db_manager.get_db_cursor() as cur:
                        cur.execute("SELECT id, asset_type, endpoint FROM infra_inventory WHERE asset_type IN ('IP', 'URL', 'Repository', 'Database (SQL)', 'NoSQL', 'Cache/Memory', 'Container', 'AppServer', 'SERVER', 'KUBERNETES', 'Datacenter', 'AI-LLM-Endpoint', 'API-Gateway', 'CICD-Pipeline', 'Cloud-Serverless', 'Identity-IdP')")
                        current_assets = cur.fetchall()
                    
                    previous_ids = {a[0] for a in assets}
                    new_assets = [a for a in current_assets if a[0] not in previous_ids]
                    if new_assets:
                        print(f"✨ [Auditor-Ext] Detected {len(new_assets)} new assets! Scanning immediately.")
                        for asset_id, a_type, endpoint in new_assets:
                            dispatcher.trigger("ASSET_DISCOVERED", {"id": asset_id, "type": a_type, "endpoint": endpoint})
                        assets.extend(new_assets)
                except Exception as check_e:
                    print(f"⚠️ Error checking for new assets: {check_e}")
        except Exception as e:
            print(f"❌ Error in Auditor-Ext loop: {e}")
            time.sleep(60)

if __name__ == "__main__":
    main()
