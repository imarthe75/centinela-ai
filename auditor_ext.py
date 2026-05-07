import psycopg2
import db_manager
import subprocess
import json
import os
import time

# DB_CONFIG moved to db_manager.py

def scan_ip(asset_id, ip):
    print(f"🔍 [Auditor-Ext] Scanning IP: {ip}")
    # Basic Nmap scan for open ports
    result = subprocess.run(['nmap', '-F', ip], capture_output=True, text=True)
    if result.returncode == 0:
        log_vulnerability(asset_id, "NMAP-SCAN", "Medium", f"Nmap results for {ip}:\n{result.stdout}")

def scan_url(asset_id, url):
    print(f"🌐 [Auditor-Ext] Scanning URL: {url}")
    # Discovery: Detect technologies (Nginx, React, Angular, etc)
    tech_result = subprocess.run(['nuclei', '-u', url, '-tags', 'tech-detect', '-silent', '-jsonl'], capture_output=True, text=True)
    if tech_result.stdout:
        for line in tech_result.stdout.splitlines():
            try:
                tech = json.loads(line)
                log_vulnerability(asset_id, f"TECH-{tech.get('info', {}).get('name')}", "Info", f"Detected technology: {tech.get('info', {}).get('name')}")
            except: continue

    # Nuclei scan for web vulnerabilities
    result = subprocess.run(['nuclei', '-u', url, '-silent', '-jsonl'], capture_output=True, text=True)
    if result.stdout:
        for line in result.stdout.splitlines():
            if not line.strip(): continue
            try:
                vuln = json.loads(line)
                log_vulnerability(asset_id, vuln.get('template-id'), vuln.get('info', {}).get('severity'), vuln.get('info', {}).get('description'))
            except: continue

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
        except: pass

def scan_database(asset_id, endpoint):
    print(f"🗄️ [Auditor-Ext] Scanning SQL Database: {endpoint}")
    # SQLMap for SQL DBs
    result = subprocess.run(['sqlmap', '-u', endpoint, '--batch', '--banner'], capture_output=True, text=True)
    if "banner:" in result.stdout.lower():
         log_vulnerability(asset_id, "DB-BANNER-LEAK", "Low", f"Database {endpoint} leaked version banner.")

def scan_nosql(asset_id, endpoint):
    print(f"🍃 [Auditor-Ext] Scanning NoSQL (Mongo/Cassandra): {endpoint}")
    # Nuclei has specific tags for nosql
    result = subprocess.run(['nuclei', '-u', endpoint, '-tags', 'nosql,mongodb,cassandra', '-silent', '-jsonl'], capture_output=True, text=True)
    if result.stdout:
        for line in result.stdout.splitlines():
            if not line.strip(): continue
            try:
                vuln = json.loads(line)
                log_vulnerability(asset_id, vuln.get('template-id'), vuln.get('info', {}).get('severity'), vuln.get('info', {}).get('description'))
            except: continue

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
                ON CONFLICT (asset_id, cve_id) DO NOTHING
            """, (asset_id, cve_id, severity, description))
    except Exception as e:
        print(f"❌ Error logging vuln: {e}")

def scan_container(asset_id, image_name):
    print(f"🐳 [Auditor-Ext] Scanning Container Image: {image_name}")
    # Trivy scan for container images
    result = subprocess.run(['trivy', 'image', '--format', 'json', '--severity', 'HIGH,CRITICAL', image_name], capture_output=True, text=True)
    if result.stdout:
        try:
            data = json.loads(result.stdout)
            for res in data.get('Results', []):
                for vuln in res.get('Vulnerabilities', []):
                    log_vulnerability(asset_id, vuln.get('VulnerabilityID'), vuln.get('Severity'), vuln.get('Description'))
        except: pass

def scan_appserver(asset_id, endpoint):
    print(f"🏰 [Auditor-Ext] Scanning AppServer: {endpoint}")
    # Use nuclei for specific appserver templates
    # We check common ports 8080 (app), 9990 (wildfly admin), 8009 (ajp)
    urls = [f"http://{endpoint}:8080", f"http://{endpoint}:9990"]
    for url in urls:
        result = subprocess.run(['nuclei', '-u', url, '-tags', 'wildfly,tomcat,jboss,middleware', '-severity', 'medium,high,critical', '-jsonl'], capture_output=True, text=True)
        if result.stdout:
            for line in result.stdout.splitlines():
                try:
                    vuln = json.loads(line)
                    log_vulnerability(asset_id, vuln.get('template-id'), vuln.get('info', {}).get('severity'), vuln.get('info', {}).get('description'))
                except: pass

def main():
    while True:
        try:
            with db_manager.get_db_cursor() as cur:
                cur.execute("SELECT id, asset_type, endpoint FROM infra_inventory WHERE asset_type IN ('IP', 'URL', 'Repository', 'Database (SQL)', 'NoSQL', 'Cache/Memory', 'Container', 'AppServer')")
                assets = cur.fetchall()
            
            # Connection is returned to pool after context manager ends

            for asset_id, a_type, endpoint in assets:
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
                elif a_type == 'AppServer':
                    scan_appserver(asset_id, endpoint)
            
            print("😴 [Auditor-Ext] Scan cycle complete. Sleeping for 10 minutes...")
            time.sleep(600)
        except Exception as e:
            print(f"❌ Error in Auditor-Ext loop: {e}")
            time.sleep(60)

if __name__ == "__main__":
    main()
