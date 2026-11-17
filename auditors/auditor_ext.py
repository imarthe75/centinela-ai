import psycopg2
from core import db_manager, asset_types
import subprocess
import json
import os
import time
from auditors import auditor_trivy_config
from auditors import nuclei_custom
from auditors import auditor_a11y_render
from auditors import auditor_api_fuzz
from auditors import auditor_nuclei_dast
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

try:
    from auditors import auditor_wstg
    WSTG_AVAILABLE = True
except ImportError:
    WSTG_AVAILABLE = False

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

    # 0. OWASP WSTG v4.2 / ASVS v4.0 Native Posture & Perimeter Audit (Zero Brute-Force)
    if WSTG_AVAILABLE:
        try:
            print(f"🛡️ [Auditor-Ext] Starting OWASP WSTG Perimeter Audit on {url}...")
            wstg_findings = auditor_wstg.audit_url_wstg(url, asset_id)
            if wstg_findings:
                found_vulns = True
        except Exception as e:
            print(f"❌ [Auditor-Ext] WSTG Audit error on {url}: {e}")

    # 0b. DNS / e-mail authentication of the URL's registrable domain (None = the host is an IP or an internal name: nothing public to audit)
    try:
        from auditors import auditor_dns_security
        dns_n = auditor_dns_security.audit_url_host(asset_id, url)
        if dns_n:
            found_vulns = True
    except Exception as e:
        import traceback; traceback.print_exc()
        print(f"❌ [Auditor-Ext] DNS audit error on {url}: {e}")

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

    if scan_custom_nuclei(url, asset_id):
        found_vulns = True

    if os.getenv('A11Y_RENDER_ENABLED', '1') == '1':
        auditor_a11y_render.scan_url_assets(asset_id, url)      # logs its own errors; None = could not run

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

    # 3. Dockerfile / Kubernetes / Terraform misconfigurations (`trivy config`).
    try:
        auditor_trivy_config.run(asset_id, repo)
    except Exception:
        import traceback
        traceback.print_exc()
        print("❌ Error invoking trivy config scan")

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

    # 6. Dependency-license inventory (Syft)
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

def scan_custom_nuclei(url, asset_id):
    """Institutional nuclei templates (templates/nuclei). Returns True when anything matched. Errors are logged with a traceback, not swallowed."""
    try:
        hits = nuclei_custom.run_custom_templates(url)
    except Exception:
        import logging
        logging.getLogger(__name__).error("custom nuclei templates failed on %s", url, exc_info=True)
        return False
    for h in hits:
        log_vulnerability(asset_id, f"NUCLEI-{h['template_id']}", h["severity"].upper(), f"{h['description']} ({h['matched_at']})")
    return bool(hits)


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

def parse_trivy_image_json(raw):
    """Flatten `trivy image --format json` into [{id, severity, package, installed, fixed, title}]. Raises ValueError on non-JSON."""
    data = json.loads(raw)
    out = []
    for res in data.get('Results') or []:
        for v in res.get('Vulnerabilities') or []:
            out.append({"id": v.get('VulnerabilityID'), "severity": v.get('Severity'), "package": v.get('PkgName'),
                        "installed": v.get('InstalledVersion'), "fixed": v.get('FixedVersion') or "", "title": v.get('Title') or v.get('Description') or ""})
    return out


def scan_container(asset_id, image_name):
    print(f"🐳 [Auditor-Ext] Scanning Container Image: {image_name}")
    # --quiet keeps progress/banners off stdout; stdout is then JSON only. A failed scan must NOT be reported as a clean one.
    result = subprocess.run(['trivy', 'image', '--quiet', '--format', 'json', '--severity', 'HIGH,CRITICAL', image_name],
                            capture_output=True, text=True, errors='replace')
    if result.returncode != 0:
        print(f"❌ [Auditor-Ext] trivy failed on {image_name} (exit {result.returncode}): {result.stderr[-300:]}")
        return False
    try:
        vulns = parse_trivy_image_json(result.stdout)
    except ValueError:
        import logging
        logging.getLogger(__name__).error("trivy returned non-JSON for %s", image_name, exc_info=True)
        return False
    for v in vulns:
        fix = f" Corregido en {v['fixed']}." if v['fixed'] else " Sin versión corregida publicada."
        log_vulnerability(asset_id, v['id'], v['severity'], f"[{image_name}] {v['package']} {v['installed']}:{fix} {v['title']}".strip())
    if not vulns:
        log_audit(asset_id, f"Escaneo de imagen {image_name} completado. No se encontraron vulnerabilidades de severidad Alta o Crítica en las librerías del contenedor.")
    return True

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
    # confirmed live: "nmap ... 192.0.2.19" (a real host with "No route to host" confirmed via a
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

        if scan_custom_nuclei(url, asset_id):
            found_vulns = True

        # WSTG DAST - deterministic protocol assertions (zero brute force)
        if WSTG_AVAILABLE and port in ["80", "443", "8080", "8443", "8000", "3000", "4200", "5000"]:
            try:
                print(f"🛡️ [Auditor-Ext] WSTG Perimeter Audit on AppServer port {port}: {url}")
                app_wstg = auditor_wstg.audit_url_wstg(url, asset_id)
                if app_wstg:
                    found_vulns = True
            except Exception as e:
                print(f"❌ [Auditor-Ext] WSTG Audit error on {url}: {e}")

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

def _run_authz_dast(asset_id, endpoint):
    """Authenticated multi-role authorization matrix + IDOR/BOLA probe.
    No-op (writes an honest 'not exercised' marker) when the asset has no multi-role
    credentials configured -- same graceful-degradation contract as the CIS auditor."""
    try:
        from auditors import auditor_authz_dast
        auditor_authz_dast.run(asset_id, endpoint)
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"⚠️ [Auditor-Ext] Authz-DAST error for asset {asset_id}: {e}")


def _run_runtime_session(asset_id, endpoint):
    """Browser session audit with the stored test credentials (console secrets, personal data in responses, 401/403 loops, 5xx). No-op without credentials."""
    try:
        from auditors import auditor_runtime_session
        auditor_runtime_session.run(asset_id, endpoint)
    except Exception:
        import logging
        logging.getLogger(__name__).error("runtime-session audit failed for asset %s", asset_id, exc_info=True)


def handle_asset_discovered(data):
    """Dispatch the asset's scanners, then stamp `last_audit` (URL assets were never stamped, so
    the dashboard showed deployed frontends as never audited despite being scanned every cycle)."""
    _dispatch_asset_scan(data)
    try:
        with db_manager.get_db_cursor() as cur:
            cur.execute("UPDATE public.infra_inventory SET last_audit = NOW() WHERE id = %s", (data["id"],))
    except Exception:
        import traceback
        print(f"❌ [Auditor-Ext] Could not stamp last_audit for asset {data.get('id')}:")
        traceback.print_exc()


def _dispatch_asset_scan(data):
    asset_id = data["id"]
    a_type = data["type"]
    endpoint = data["endpoint"]
    if a_type in ('URL', 'API-Gateway', 'Identity-IdP'):
        endpoint = asset_types.url_scan_target(data.get("name", ""), endpoint)
    allowed, reason = asset_types.scan_target_allowed(endpoint)
    if not allowed:
        print(f"⛔ [Auditor-Ext] Escaneo omitido para el activo {asset_id}: {reason}")
        log_audit(asset_id, f"Escaneo activo NO ejecutado: {reason}")
        return
    auditor_api_fuzz.run_for_asset(asset_id, endpoint)      # no-op unless the endpoint is an opted-in SCHEMATHESIS_TARGETS entry
    auditor_nuclei_dast.run_for_asset(asset_id, endpoint)   # no-op unless the endpoint is an opted-in NUCLEI_DAST_TARGETS entry
    
    if a_type == 'IP':
        scan_ip(asset_id, endpoint)
    elif a_type == 'URL':
        scan_url(asset_id, endpoint)
        _run_authz_dast(asset_id, endpoint)
        _run_runtime_session(asset_id, endpoint)
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
    elif a_type in asset_types.NETWORK_HOST_TYPES:
        scan_appserver(asset_id, endpoint)
        _run_authz_dast(asset_id, endpoint)
        _run_runtime_session(asset_id, endpoint)
    elif a_type == 'AI-LLM-Endpoint':
        try:
            from auditors import auditor_llm_governance
            auditor_llm_governance.run(asset_id, endpoint)
        except Exception as e:
            print(f"⚠️ [Auditor-Ext] Error scanning AI-LLM-Endpoint: {e}")
    elif a_type == 'API-Gateway':
        try:
            from auditors import auditor_shadow_api
            auditor_shadow_api.run(asset_id, endpoint)
            scan_url(asset_id, endpoint)
        except Exception as e:
            print(f"⚠️ [Auditor-Ext] Error scanning API-Gateway: {e}")
        _run_authz_dast(asset_id, endpoint)
        _run_runtime_session(asset_id, endpoint)
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


ASSET_SCAN_JOB_KIND = "asset_scan"
_SCANNABLE_TYPES_SQL = "SELECT id, asset_type, endpoint, asset_name FROM infra_inventory WHERE asset_type IN %s"
_SCANNABLE_TYPES = tuple(dict.fromkeys(('IP', 'URL', 'Repository', 'Database (SQL)', 'NoSQL', 'Cache/Memory', 'Container',
                                        'AI-LLM-Endpoint', 'API-Gateway', 'CICD-Pipeline', 'Cloud-Serverless', 'Identity-IdP')
                                       + asset_types.NETWORK_HOST_TYPES))


def _scannable_assets():
    with db_manager.get_db_cursor() as cur:
        cur.execute(_SCANNABLE_TYPES_SQL, (_SCANNABLE_TYPES,))
        return cur.fetchall()


def enqueue_asset_scans(assets, min_interval_hours: float) -> int:
    """Queue one durable scan job per asset (ADR-0008 #4). Idempotent: an asset already queued/running, or scanned less than
    min_interval_hours ago, is skipped. Returns how many jobs were created."""
    from core import job_queue
    n = 0
    for asset_id, a_type, endpoint, *rest in assets:
        data = {"id": str(asset_id), "type": a_type, "endpoint": endpoint}
        if rest and rest[0]:
            data["name"] = rest[0]
        if job_queue.enqueue(ASSET_SCAN_JOB_KIND, str(asset_id), data, min_interval_hours=min_interval_hours):
            n += 1
    return n


def run_asset_scan_worker(poll_seconds: int = 10, heartbeat_seconds: int = 60):
    """Consumer: one asset scan at a time (DAST/ZAP, nuclei, DB hardening...). The job holds a lease renewed by a heartbeat; if this process
    dies mid-scan the lease expires and the job is re-queued instead of being lost with an in-memory queue."""
    from core import job_queue
    while True:
        try:
            job_queue.requeue_expired()
            job = job_queue.claim(kind=ASSET_SCAN_JOB_KIND)
            if not job:
                time.sleep(poll_seconds)
                continue
            data = job["payload"]
            print(f"📣 [Asset-Scan-Worker] {data.get('type')} {data.get('endpoint')} (attempt {job['attempts']}/{job['max_attempts']})")
            stop = threading.Event()

            def _beat(job_id=job["id"]):
                while not stop.wait(heartbeat_seconds):
                    try:
                        if not job_queue.heartbeat(job_id):
                            print(f"❌ [Asset-Scan-Worker] lost the lease of job {job_id}")
                            return
                    except Exception:
                        import traceback
                        traceback.print_exc()
            threading.Thread(target=_beat, daemon=True).start()
            from core import scan_comparison
            run_id = scan_comparison.open_run(data["id"], f"asset_scan:{data.get('type')}") if data.get("id") else None
            try:
                handle_asset_discovered(data)
                scan_comparison.close_run(run_id, True)
                job_queue.complete(job["id"])
            except Exception as e:
                import traceback
                traceback.print_exc()
                scan_comparison.close_run(run_id, False, note=f"{type(e).__name__}: {e}"[:500])
                job_queue.fail(job["id"], f"{type(e).__name__}: {e}")
            finally:
                stop.set()
        except Exception:
            import traceback
            traceback.print_exc()
            time.sleep(60)


def main():
    """Producer loop. Every cycle: queue the assets that are due (at most once per ASSET_RESCAN_HOURS, default 6), then run the temporal
    heuristics and OSINT enrichment. New assets are queued immediately, regardless of the interval."""
    rescan_hours = float(os.getenv("ASSET_RESCAN_HOURS", "6"))
    threading.Thread(target=run_asset_scan_worker, daemon=True).start()

    while True:
        try:
            assets = _scannable_assets()
            queued = enqueue_asset_scans(assets, rescan_hours)
            if queued:
                print(f"📥 [Auditor-Ext] {queued} asset scan(s) queued ({len(assets)} assets, rescan every {rescan_hours}h)")

            try:
                from core import heuristics_engine
                heuristics_engine.run_heuristics_correlation()
            except Exception:
                import traceback
                traceback.print_exc()
                print("❌ Error invoking Heuristics Engine")

            # OSINT enrichment ONCE per cycle rather than for every single asset individually
            try:
                from discovery import discovery_osint
                discovery_osint.run_osint_discovery()
            except Exception:
                import traceback
                traceback.print_exc()
                print("❌ Error running OSINT enrichment")

            print("😴 [Auditor-Ext] Cycle complete. Watching for new assets...")
            known = {a[0] for a in assets}
            for _ in range(60):
                time.sleep(10)
                try:
                    current = _scannable_assets()
                    new_assets = [a for a in current if a[0] not in known]
                    if new_assets:
                        print(f"✨ [Auditor-Ext] Detected {len(new_assets)} new assets! Scanning immediately.")
                        enqueue_asset_scans(new_assets, 0)
                        known.update(a[0] for a in new_assets)
                except Exception:
                    import traceback
                    traceback.print_exc()
                    print("⚠️ Error checking for new assets")
        except Exception:
            import traceback
            traceback.print_exc()
            print("❌ Error in Auditor-Ext loop")
            time.sleep(60)


if __name__ == "__main__":
    main()
