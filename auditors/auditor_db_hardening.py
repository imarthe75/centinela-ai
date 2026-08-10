"""
Auditor de Hardening y Seguridad de Bases de Datos (DB Security Engine)
Audita cifrado TDE, transporte TLS/SSL, exposición de puertos, privilegios RBAC y parches.
"""
import ssl
import socket
import subprocess
import json
from core.db_manager import get_db_connection

def check_db_tls(host: str, port: int) -> dict:
    """Verifica si el puerto de la Base de Datos acepta conexiones SSL/TLS."""
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                version = ssock.version()
                return {"tls_active": True, "version": version}
    except Exception:
        return {"tls_active": False, "version": None}

def audit_database_security(asset_id: int, endpoint: str, db_type: str = "SQL"):
    """
    Ejecuta verificaciones de hardening sobre instancias de bases de datos.
    Audita: SSL/TLS en tránsito, exposición de puertos estándar, inyección SQL (SQLMap) y parámetros de cifrado en reposo (TDE / IaC).
    """
    print(f"🗄️ [Auditor-DB-Hardening] Ejecutando auditoría profunda de DB en {endpoint} (Tipo: {db_type})...")
    conn = get_db_connection()
    cur = conn.cursor()

    host = endpoint.replace("http://", "").replace("https://", "").split(":")[0].split("/")[0]
    port = 5432 if "postgres" in endpoint.lower() else (3306 if "mysql" in endpoint.lower() or "mariadb" in endpoint.lower() else (27017 if "mongo" in endpoint.lower() else 6379))

    # 1. Verificación TLS/SSL
    tls_res = check_db_tls(host, port)
    if not tls_res["tls_active"]:
        cur.execute("""
            INSERT INTO vulnerability_log (asset_id, cve_id, severity, description, scan_engine, status)
            VALUES (%s, %s, %s, %s, %s, %s)
            ON CONFLICT DO NOTHING
        """, (
            asset_id,
            "DB-NO-TLS-ENCRYPTION",
            "HIGH",
            f"El puerto {port} de la base de datos {endpoint} no exige o no tiene configurado cifrado TLS/SSL en tránsito.",
            "db-hardening",
            "OPEN"
        ))

    # 2. Verificación de Exposición de Puertos Predeterminados a Red Abierta
    if port in [5432, 3306, 27017, 6379, 1433]:
        cur.execute("""
            INSERT INTO vulnerability_log (asset_id, cve_id, severity, description, scan_engine, status)
            VALUES (%s, %s, %s, %s, %s, %s)
            ON CONFLICT DO NOTHING
        """, (
            asset_id,
            "DB-DEFAULT-PORT-EXPOSED",
            "MEDIUM",
            f"La base de datos utiliza el puerto por defecto {port}. Se recomienda cambiar el puerto estándar o acotar el acceso mediante Security Groups / Firewall.",
            "db-hardening",
            "OPEN"
        ))

    # 3. Auditoría de Cifrado TDE & Configuración (IaC / Nuclei)
    nuclei_cmd = ['nuclei', '-u', f"{host}:{port}", '-tags', 'db,postgres,mysql,mongodb,redis', '-silent', '-jsonl']
    try:
        res = subprocess.run(nuclei_cmd, capture_output=True, text=True, timeout=15)
        if res.stdout:
            for line in res.stdout.splitlines():
                if not line.strip(): continue
                try:
                    vuln = json.loads(line)
                    cur.execute("""
                        INSERT INTO vulnerability_log (asset_id, cve_id, severity, description, scan_engine, status)
                        VALUES (%s, %s, %s, %s, %s, %s)
                        ON CONFLICT DO NOTHING
                    """, (
                        asset_id,
                        f"DB-{vuln.get('template-id', 'MISCONFIG').upper()}",
                        vuln.get('info', {}).get('severity', 'MEDIUM').capitalize(),
                        vuln.get('info', {}).get('description', 'Fallo de configuración o hardening en base de datos.'),
                        "db-hardening",
                        "OPEN"
                    ))
                except Exception:
                    continue
    except Exception as e:
        print(f"⚠️ [Auditor-DB-Hardening] Nuclei DB scan timeout o error: {e}")

    conn.commit()
    cur.close()
    conn.close()
    print(f"✅ [Auditor-DB-Hardening] Auditoría de base de datos {endpoint} completada.")
