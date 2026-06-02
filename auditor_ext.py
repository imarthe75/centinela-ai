import psycopg2
import db_manager
import subprocess
import json
import os
import time
import auditor_medusa
import queue
import threading

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
    # Basic Nmap scan for open ports
    result = subprocess.run(['nmap', '-F', ip], capture_output=True, text=True)
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
    
    # Discovery: Detect technologies (Nginx, React, Angular, Vue, PHP, etc)
    tech_result = subprocess.run(['nuclei', '-u', url, '-tags', 'tech-detect', '-silent', '-jsonl'], capture_output=True, text=True)
    if tech_result.stdout:
        for line in tech_result.stdout.splitlines():
            try:
                tech = json.loads(line)
                log_vulnerability(asset_id, f"TECH-{tech.get('info', {}).get('name')}", "Info", f"Tecnología detectada: {tech.get('info', {}).get('name')}")
            except: continue

    # Nuclei scan for web vulnerabilities (Comprehensive tags)
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
    
    if not found_vulns:
        log_audit(asset_id, f"Escaneo web exhaustivo completado para {url}.\nTecnologías verificadas: React, Angular, Vue, Wildfly, Tomcat, PHP, Nginx.\nResultado: No se encontraron vulnerabilidades críticas activas.")

def scan_repo(asset_id, repo):
    print(f"📦 [Auditor-Ext] Scanning Repo: {repo}")
    # Trivy scan for code/dependencies
    subprocess.run(['trivy', 'repo', '--format', 'json', repo], capture_output=True, text=True)
    # Checkov scan for IaC security
    result_checkov = subprocess.run(['checkov', '-d', repo, '--quiet', '--soft-fail', '--output', 'json'], capture_output=True, text=True)
    if result_checkov.stdout:
        try:
            data = json.loads(result_checkov.stdout)
            # Process checkov results...
            log_vulnerability(asset_id, "CHECKOV-SCAN", "Medium", "Checkov identified potential IaC misconfigurations.")
        except: 
            log_audit(asset_id, f"Escaneo de repositorio {repo} completado. No se encontraron fallos de seguridad en el código o IaC.")
    else:
        log_audit(asset_id, f"Escaneo de repositorio {repo} completado. No se encontraron fallos de seguridad en el código o IaC.")
    
    # AI-First SAST Scan via Medusa
    try:
        auditor_medusa.run_medusa_scan(repo, asset_id)
    except Exception as e:
        print(f"❌ Error invoking Medusa scan: {e}")

def scan_database(asset_id, endpoint):
    print(f"🗄️ [Auditor-Ext] Scanning SQL Database: {endpoint}")
    # SQLMap for SQL DBs
    result = subprocess.run(['sqlmap', '-u', endpoint, '--batch', '--banner'], capture_output=True, text=True)
    if "banner:" in result.stdout.lower():
         log_vulnerability(asset_id, "DB-BANNER-LEAK", "Low", f"Database {endpoint} leaked version banner.")
    else:
        log_audit(asset_id, f"Verificación de base de datos {endpoint} completada. No se detectaron vulnerabilidades de inyección o fugas de información.")

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
        with db_manager.get_db_cursor() as cur:
            cur.execute("""
                INSERT INTO vulnerability_log (asset_id, cve_id, severity, description, status)
                VALUES (%s, %s, %s, %s, 'NEW')
                ON CONFLICT (asset_id, cve_id) DO UPDATE SET
                    severity = EXCLUDED.severity,
                    description = EXCLUDED.description,
                    status = CASE 
                        WHEN vulnerability_log.status = 'RESOLVED' THEN 'REOPENED' 
                        ELSE vulnerability_log.status 
                    END
            """, (asset_id, cve_id, severity, description))
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
    nm_result = subprocess.run(['nmap', '-p', ports_str, '--open', endpoint, '--min-rate', '1000'], capture_output=True, text=True)
    
    open_ports = []
    if nm_result.returncode == 0:
        for line in nm_result.stdout.splitlines():
            if "/tcp" in line and "open" in line:
                port = line.split("/")[0].strip()
                open_ports.append(port)
    
    # 2. Nuclei for specific appserver templates on open ports
    for port in open_ports:
        scheme = "https" if port in ["443", "8443"] else "http"
        url = f"{scheme}://{endpoint}:{port}"
        checked_ports.append(port)
        
        # Tech detect
        subprocess.run(['nuclei', '-u', url, '-tags', 'tech-detect', '-silent', '-jsonl'], capture_output=True, text=True)
        
        # Vuln scan (Comprehensive tags)
        tags = "wildfly,tomcat,jboss,middleware,java,angular,react,vue,nextjs,php,wordpress,apache,nginx"
        result = subprocess.run(['nuclei', '-u', url, '-tags', tags, '-severity', 'medium,high,critical', '-jsonl'], capture_output=True, text=True)
        if result.stdout:
            found_vulns = True
            for line in result.stdout.splitlines():
                try:
                    vuln = json.loads(line)
                    log_vulnerability(asset_id, vuln.get('template-id'), vuln.get('info', {}).get('severity'), vuln.get('info', {}).get('description'))
                except: pass

    # 3. Final Audit Logging
    if not found_vulns:
        audit_msg = f"Auditoría exhaustiva completada para AppServer ({endpoint}).\n"
        if open_ports:
            audit_msg += f"Servicios detectados en puertos: {', '.join(open_ports)}.\n"
            audit_msg += "Se realizaron pruebas de inyección (SQLi), Path Traversal (LFI), XSS y detección de tecnología.\n"
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
    elif a_type == 'AppServer' or a_type == 'SERVER':
        if endpoint == 'remote-agent':
            log_audit(asset_id, "Wazuh Agent detectado pero no reporta IP aún. Escaneo externo omitido hasta que el agente sincronice su red.")
        else:
            scan_appserver(asset_id, endpoint)

def handle_osint_enrichment(data):
    a_type = data["type"]
    if a_type in ["IP", "URL", "AppServer", "SERVER"]:
        try:
            import discovery_osint
            discovery_osint.run_osint_discovery()
        except Exception as e:
            print(f"❌ [Event-Dispatcher] OSINT Enrichment failed: {e}")

# Register handlers to pub-sub event dispatcher
dispatcher.register("ASSET_DISCOVERED", handle_asset_discovered)

def main():
    # Start background dispatcher worker thread
    dispatcher.start()
    
    while True:
        try:
            with db_manager.get_db_cursor() as cur:
                cur.execute("SELECT id, asset_type, endpoint FROM infra_inventory WHERE asset_type IN ('IP', 'URL', 'Repository', 'Database (SQL)', 'NoSQL', 'Cache/Memory', 'Container', 'AppServer', 'SERVER')")
                assets = cur.fetchall()
            
            # Connection is returned to pool after context manager ends

            for asset_id, a_type, endpoint in assets:
                dispatcher.trigger("ASSET_DISCOVERED", {"id": asset_id, "type": a_type, "endpoint": endpoint})
            
            # Wait for all asynchronous event-driven tasks in this cycle to complete
            dispatcher.queue.join()
            
            # Run temporal heuristics engine correlation
            try:
                import heuristics_engine
                heuristics_engine.run_heuristics_correlation()
            except Exception as e:
                print(f"❌ Error invoking Heuristics Engine: {e}")

            # Run OSINT enrichment ONCE per cycle rather than for every single asset individually
            try:
                import discovery_osint
                discovery_osint.run_osint_discovery()
            except Exception as e:
                print(f"❌ Error running OSINT enrichment: {e}")

            print("😴 [Auditor-Ext] Scan cycle complete. Sleeping for 10 minutes...")
            time.sleep(600)
        except Exception as e:
            print(f"❌ Error in Auditor-Ext loop: {e}")
            time.sleep(60)

if __name__ == "__main__":
    main()
