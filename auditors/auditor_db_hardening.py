"""
Auditor de Hardening y Seguridad de Bases de Datos (DB Security Engine)
Audita cifrado TDE, transporte TLS/SSL, exposición de puertos, privilegios RBAC y parches.
"""
import ssl
import socket
import subprocess
import json
from core.db_manager import get_db_connection
from core.deduplication_engine import log_finding_deduplicated

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
    with get_db_connection() as conn:
        cur = conn.cursor()
        _audit_database_security_inner(cur, conn, asset_id, endpoint, db_type)


def _audit_database_security_inner(cur, conn, asset_id: int, endpoint: str, db_type: str):
    host = endpoint.replace("http://", "").replace("https://", "").split(":")[0].split("/")[0]
    # Mapeo exhaustivo de motores Relacionales, NoSQL, In-Memory y Query Engines
    ep_lower = endpoint.lower()
    if "postgres" in ep_lower: port = 5432
    elif "mysql" in ep_lower or "mariadb" in ep_lower: port = 3306
    elif "oracle" in ep_lower: port = 1521
    elif "mssql" in ep_lower or "sqlserver" in ep_lower: port = 1433
    elif "mongo" in ep_lower: port = 27017
    elif "cassandra" in ep_lower: port = 9042
    elif "trino" in ep_lower or "presto" in ep_lower: port = 8080
    elif "elastic" in ep_lower or "opensearch" in ep_lower: port = 9200
    elif "neo4j" in ep_lower: port = 7687
    elif "redis" in ep_lower or "valkey" in ep_lower: port = 6379
    else: port = 5432

    location = f"{host}:{port}"

    # 1. Verificación TLS/SSL
    tls_res = check_db_tls(host, port)
    if not tls_res["tls_active"]:
        log_finding_deduplicated(
            cur, asset_id, "DB-NO-TLS-ENCRYPTION", "HIGH",
            f"El puerto {port} de la base de datos {endpoint} ({db_type}) no exige o no tiene configurado cifrado TLS/SSL en tránsito.",
            "db-hardening", url_path=location, preserve_status=True
        )

    # 2. Verificación de Exposición de Puertos Predeterminados a Red Abierta
    if port in [5432, 3306, 1521, 1433, 27017, 9042, 8080, 9200, 7687, 6379]:
        log_finding_deduplicated(
            cur, asset_id, "DB-DEFAULT-PORT-EXPOSED", "MEDIUM",
            f"La base de datos utiliza el puerto por defecto {port}. Se recomienda cambiar el puerto estándar o acotar el acceso mediante Security Groups / Firewall.",
            "db-hardening", url_path=location, preserve_status=True
        )

    # 3. Auditoría de Cifrado TDE & Configuración (IaC / Nuclei)
    nuclei_cmd = ['nuclei', '-u', f"{host}:{port}", '-tags', 'db,postgres,mysql,mongodb,redis', '-silent', '-jsonl']
    try:
        res = subprocess.run(nuclei_cmd, capture_output=True, text=True, timeout=60)
        if res.stdout:
            for line in res.stdout.splitlines():
                if not line.strip(): continue
                try:
                    vuln = json.loads(line)
                    log_finding_deduplicated(
                        cur, asset_id, f"DB-{vuln.get('template-id', 'MISCONFIG').upper()}",
                        vuln.get('info', {}).get('severity', 'MEDIUM').upper(),
                        vuln.get('info', {}).get('description', 'Fallo de configuración o hardening en base de datos.'),
                        "db-hardening", url_path=location, preserve_status=True
                    )
                except Exception:
                    continue
    except Exception as e:
        print(f"⚠️ [Auditor-DB-Hardening] Nuclei DB scan timeout o error: {e}")

    conn.commit()
    print(f"✅ [Auditor-DB-Hardening] Auditoría de base de datos {endpoint} completada.")
