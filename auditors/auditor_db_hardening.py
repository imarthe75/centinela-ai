"""
Auditor de Hardening y Seguridad de Bases de Datos (DB Security Engine).

Comprueba, sin credenciales y sin enviar contraseñas:
  * cifrado TLS en tránsito. PostgreSQL negocia TLS con un mensaje SSLRequest (un handshake TLS directo siempre falla aunque el servidor
    tenga TLS), así que para PostgreSQL se usa ese protocolo; para los demás motores, un handshake TLS directo;
  * PostgreSQL: versión de TLS frente a la línea base de la organización (TLS 1.3, guía de instalación de PostgreSQL 18) y método de
    autenticación que el servidor exige a un usuario inexistente (`trust`, contraseña en claro, MD5 o SCRAM-SHA-256). La sonda solo lee el
    primer mensaje de autenticación y cierra: nunca envía una contraseña ni ejecuta consultas;
  * puerto por defecto expuesto y las plantillas de nuclei para bases de datos.
Un host que no responde no genera hallazgos: no poder conectarse no prueba que falte TLS (misma regla que CIS «SIN_CONEXION»).
"""
import json
import socket
import ssl
import struct
import subprocess
from typing import Dict, Optional, Tuple
from urllib.parse import urlparse

from core.db_manager import get_db_connection
from core.deduplication_engine import log_finding_deduplicated

DEFAULT_PORTS = {"postgres": 5432, "mysql": 3306, "mariadb": 3306, "oracle": 1521, "mssql": 1433, "sqlserver": 1433, "mongo": 27017,
                 "cassandra": 9042, "trino": 8080, "presto": 8080, "elastic": 9200, "opensearch": 9200, "neo4j": 7687, "redis": 6379,
                 "valkey": 6379}
STANDARD_DB_PORTS = {5432, 3306, 1521, 1433, 27017, 9042, 8080, 9200, 7687, 6379}
PG_SSL_REQUEST = 80877103
PG_PROTOCOL_V3 = 196608
PG_AUTH_METHODS = {0: "trust", 3: "password", 5: "md5", 10: "scram"}   # AuthenticationOk / CleartextPassword / MD5Password / SASL
PG_TLS_BASELINE = "TLSv1.3"
PROBE_USER = "centinela_probe"
TIMEOUT = 5


def parse_endpoint(endpoint: str) -> Tuple[str, int, str]:
    """(host, port, engine) from 'host', 'host:port' or 'scheme://host:port/db'. An explicit port wins over the engine's default."""
    raw = (endpoint or "").strip()
    parsed = urlparse(raw if "://" in raw else "tcp://" + raw)
    host = parsed.hostname or ""
    low = raw.lower()
    engine = next((k for k in DEFAULT_PORTS if k in low), "postgres")
    try:
        port = parsed.port or DEFAULT_PORTS[engine]
    except ValueError:
        port = DEFAULT_PORTS[engine]
    return host, port, engine


def check_db_tls(host: str, port: int) -> dict:
    """Direct TLS handshake (engines that speak TLS on connect). reachable=False when nothing answers on the port."""
    try:
        sock = socket.create_connection((host, port), timeout=TIMEOUT)
    except OSError:
        return {"reachable": False, "tls_active": False, "version": None}
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            return {"reachable": True, "tls_active": True, "version": ssock.version()}
    except (ssl.SSLError, OSError):
        return {"reachable": True, "tls_active": False, "version": None}
    finally:
        sock.close()


def _pg_first_auth_message(sock) -> Dict[str, Optional[str]]:
    params = (b"user\x00" + PROBE_USER.encode() + b"\x00database\x00postgres\x00"
              b"application_name\x00centinela-db-hardening\x00\x00")
    body = struct.pack("!I", PG_PROTOCOL_V3) + params
    sock.sendall(struct.pack("!I", len(body) + 4) + body)
    kind = sock.recv(1)
    length = struct.unpack("!I", _recv_exact(sock, 4))[0]
    data = _recv_exact(sock, min(length - 4, 4096))
    if kind == b"R" and len(data) >= 4:
        code = struct.unpack("!I", data[:4])[0]
        return {"auth_method": PG_AUTH_METHODS.get(code, f"other:{code}"), "error": None}
    if kind == b"E":   # e.g. no pg_hba.conf entry for this network: the method cannot be read, which is not a finding
        return {"auth_method": None, "error": data.replace(b"\x00", b" ").decode("utf-8", "replace")[:200]}
    return {"auth_method": None, "error": f"unexpected message {kind!r}"}


def _recv_exact(sock, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed by the server")
        buf += chunk
    return buf


def probe_postgres(host: str, port: int) -> dict:
    """Read-only PostgreSQL probe: TLS support/version (SSLRequest) and the authentication method the server requests. Never sends a password."""
    out = {"reachable": False, "tls_active": False, "version": None, "auth_method": None, "auth_over_tls": None, "error": None}
    try:
        sock = socket.create_connection((host, port), timeout=TIMEOUT)
    except OSError as e:
        out["error"] = str(e)
        return out
    out["reachable"] = True
    try:
        sock.sendall(struct.pack("!II", 8, PG_SSL_REQUEST))
        answer = sock.recv(1)
        if answer == b"S":
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(sock, server_hostname=host)
            out.update(tls_active=True, version=sock.version())
        elif answer != b"N":
            out["error"] = f"not a PostgreSQL server (SSLRequest answer {answer!r})"
            return out
        auth = _pg_first_auth_message(sock)
        out.update(auth_method=auth["auth_method"], auth_over_tls=out["tls_active"], error=auth["error"])
        if out["tls_active"]:
            # The method can differ for non-TLS clients (host vs hostssl lines): check what a plain-text client gets too.
            try:
                with socket.create_connection((host, port), timeout=TIMEOUT) as plain:
                    plain_auth = _pg_first_auth_message(plain)
                out["plain_auth_method"] = plain_auth["auth_method"]
            except (OSError, ConnectionError, struct.error):
                out["plain_auth_method"] = None
    except (OSError, ssl.SSLError, ConnectionError, struct.error) as e:
        out["error"] = str(e)
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return out


def audit_database_security(asset_id: str, endpoint: str, db_type: str = "SQL"):
    """Runs the hardening checks against a database endpoint and persists real findings (deduplicated)."""
    print(f"🗄️ [Auditor-DB-Hardening] Auditoría de base de datos en {endpoint} (Tipo: {db_type})...")
    with get_db_connection() as conn:
        cur = conn.cursor()
        _audit_database_security_inner(cur, conn, asset_id, endpoint, db_type)


def _resolve(cur, asset_id, cve_id: str, location: str, note: str) -> None:
    """Closes a previously open finding that a fresh probe proved fixed (the probe is the evidence)."""
    cur.execute("""UPDATE public.vulnerability_log SET status = 'RESOLVED',
                          description = description || %s
                    WHERE asset_id IS NOT DISTINCT FROM %s AND cve_id = %s AND url_path = %s AND scan_engine = 'db-hardening'
                      AND status IN ('OPEN', 'NEW', 'CORRELATED', 'REOPENED')""",
                (f"\n\n[Cerrado por re-verificación de db-hardening] {note}", asset_id, cve_id, location))


def _audit_postgres(cur, asset_id, host: str, port: int, location: str) -> bool:
    res = probe_postgres(host, port)
    if not res["reachable"] or str(res["error"] or "").startswith("not a PostgreSQL"):
        print(f"⚠️ [Auditor-DB-Hardening] {location}: sin conexión o no es PostgreSQL ({res['error']}); no se registran hallazgos.")
        return False
    if not res["tls_active"]:
        log_finding_deduplicated(
            cur, asset_id, "DB-NO-TLS-ENCRYPTION", "HIGH",
            f"PostgreSQL en {location} rechazó la negociación TLS (respondió 'N' a SSLRequest): credenciales y datos viajan sin cifrar. "
            f"Línea base: ssl = on y ssl_min_protocol_version = '{PG_TLS_BASELINE}'.",
            "db-hardening", url_path=location, preserve_status=True)
    else:
        _resolve(cur, asset_id, "DB-NO-TLS-ENCRYPTION", location, f"el servidor acepta TLS ({res['version']}).")
        if res["version"] != PG_TLS_BASELINE:
            log_finding_deduplicated(
                cur, asset_id, "DB-TLS-BELOW-BASELINE", "LOW",
                f"PostgreSQL en {location} negoció {res['version']}; la línea base de la organización para PostgreSQL 18 es "
                f"ssl_min_protocol_version = '{PG_TLS_BASELINE}'.",
                "db-hardening", url_path=location, preserve_status=True)
    methods = {m for m in (res.get("auth_method"), res.get("plain_auth_method")) if m}
    if "trust" in methods:
        log_finding_deduplicated(
            cur, asset_id, "DB-AUTH-TRUST", "CRITICAL",
            f"PostgreSQL en {location} respondió AuthenticationOk a un usuario inexistente sin pedir contraseña: pg_hba.conf usa 'trust' "
            "para esta red. Cualquiera que alcance el puerto entra como cualquier rol existente (incluido el superusuario).",
            "db-hardening", url_path=location, preserve_status=True)
    if "password" in methods:
        log_finding_deduplicated(
            cur, asset_id, "DB-AUTH-CLEARTEXT-PASSWORD", "HIGH" if not res["tls_active"] else "MEDIUM",
            f"PostgreSQL en {location} pide la contraseña en texto claro (método 'password' en pg_hba.conf). Línea base: scram-sha-256.",
            "db-hardening", url_path=location, preserve_status=True)
    if "md5" in methods:
        log_finding_deduplicated(
            cur, asset_id, "DB-AUTH-MD5", "MEDIUM",
            f"PostgreSQL en {location} autentica con MD5, obsoleto en PostgreSQL 18. Línea base: password_encryption = scram-sha-256 y "
            "scram-sha-256 en pg_hba.conf (las contraseñas guardadas en MD5 deben restablecerse).",
            "db-hardening", url_path=location, preserve_status=True)
    if methods and methods <= {"scram"}:
        for rule in ("DB-AUTH-TRUST", "DB-AUTH-CLEARTEXT-PASSWORD", "DB-AUTH-MD5"):
            _resolve(cur, asset_id, rule, location, "el servidor exige SCRAM-SHA-256.")
    return True


def _audit_database_security_inner(cur, conn, asset_id: str, endpoint: str, db_type: str):
    host, port, engine = parse_endpoint(endpoint)
    location = f"{host}:{port}"
    if not host:
        print(f"⚠️ [Auditor-DB-Hardening] endpoint sin host: {endpoint!r}")
        return

    if engine == "postgres":
        reachable = _audit_postgres(cur, asset_id, host, port, location)
    else:
        tls_res = check_db_tls(host, port)
        reachable = tls_res["reachable"]
        if reachable and not tls_res["tls_active"]:
            log_finding_deduplicated(
                cur, asset_id, "DB-NO-TLS-ENCRYPTION", "HIGH",
                f"El puerto {port} de la base de datos {endpoint} ({db_type}) no completa un handshake TLS: no exige o no tiene configurado cifrado en tránsito.",
                "db-hardening", url_path=location, preserve_status=True)
    if not reachable:
        conn.commit()
        return

    if port in STANDARD_DB_PORTS:
        log_finding_deduplicated(
            cur, asset_id, "DB-DEFAULT-PORT-EXPOSED", "MEDIUM",
            f"La base de datos utiliza el puerto por defecto {port}. Se recomienda acotar el acceso mediante firewall o grupos de seguridad.",
            "db-hardening", url_path=location, preserve_status=True)

    nuclei_cmd = ["nuclei", "-u", location, "-tags", "db,postgres,mysql,mongodb,redis", "-silent", "-jsonl"]
    try:
        res = subprocess.run(nuclei_cmd, capture_output=True, text=True, timeout=60)
        for line in (res.stdout or "").splitlines():
            if not line.strip():
                continue
            try:
                vuln = json.loads(line)
            except json.JSONDecodeError:
                continue
            log_finding_deduplicated(
                cur, asset_id, f"DB-{vuln.get('template-id', 'MISCONFIG').upper()}",
                vuln.get("info", {}).get("severity", "MEDIUM").upper(),
                vuln.get("info", {}).get("description", "Fallo de configuración o hardening en base de datos."),
                "db-hardening", url_path=location, preserve_status=True)
    except (subprocess.TimeoutExpired, OSError) as e:
        print(f"⚠️ [Auditor-DB-Hardening] nuclei no completó contra {location}: {e}")

    conn.commit()
    print(f"✅ [Auditor-DB-Hardening] Auditoría de base de datos {endpoint} completada.")
