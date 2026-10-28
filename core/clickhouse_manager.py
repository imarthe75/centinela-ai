"""
Módulo de Gestión de Telemetría e Ingesta en ClickHouse para Centinela Omni-XDR.
Proporciona almacenamiento y consulta analítica de alto rendimiento para eventos por segundo (EPS).
"""

import os
import requests
import json
from datetime import datetime

CLICKHOUSE_HOST = os.getenv("CLICKHOUSE_HOST", "centinela-clickhouse")
CLICKHOUSE_PORT = int(os.getenv("CLICKHOUSE_PORT", "8123"))
CLICKHOUSE_URL = f"http://{CLICKHOUSE_HOST}:{CLICKHOUSE_PORT}"
# The ClickHouse image's own entrypoint disables network access entirely for the default user
# when no password is configured -- real credentials are required for every request, not just a
# nice-to-have. See CLICKHOUSE_USER/CLICKHOUSE_PASSWORD in .env / docker-compose.yml.
CLICKHOUSE_AUTH = (os.getenv("CLICKHOUSE_USER", ""), os.getenv("CLICKHOUSE_PASSWORD", ""))

def init_clickhouse():
    """
    Inicializa la base de datos y la tabla de telemetría analítica en ClickHouse.
    """
    try:
        # Crear base de datos de telemetría
        q_db = "CREATE DATABASE IF NOT EXISTS centinela_telemetry;"
        requests.post(CLICKHOUSE_URL, data=q_db, auth=CLICKHOUSE_AUTH, timeout=5)

        # Crear tabla de eventos de telemetría optimizada por columnas
        q_tbl = """
        CREATE TABLE IF NOT EXISTS centinela_telemetry.telemetry_events (
            event_id UUID DEFAULT generateUUIDv4(),
            timestamp DateTime DEFAULT now(),
            source String,
            event_type String,
            user_id String,
            username String,
            client_ip String,
            severity String,
            details String,
            confidence_score Float32 DEFAULT 0.0
        ) ENGINE = MergeTree()
        ORDER BY (timestamp, source, event_type);
        """
        requests.post(CLICKHOUSE_URL, data=q_tbl, auth=CLICKHOUSE_AUTH, timeout=5)
        print("✅ [ClickHouse-Manager] Base de datos 'centinela_telemetry' e índice inicializados correctamente.")
        return True
    except Exception as e:
        print(f"⚠️ [ClickHouse-Manager] Error al inicializar ClickHouse: {e}")
        return False

def insert_telemetry_event(source: str, event_type: str, username: str, client_ip: str, severity: str, details: dict, confidence: float = 0.0):
    """
    Inserta un evento de telemetría de alta frecuencia en ClickHouse.

    Uses ClickHouse's native HTTP parameterized-query syntax ({name:Type} in the query body,
    real values passed as param_<name> query-string args) instead of raw f-string interpolation
    into the SQL body. The previous version built the INSERT by directly interpolating
    `username`/`client_ip`/`details` -- all of which originate from external, attacker-reachable
    input (the Authentik webhook payload, eBPF/Falco event fields) -- straight into the query
    string with no escaping at all: a genuine, exploitable SQL injection, not a hypothetical one,
    fixed here before this module is wired to any live webhook.
    """
    try:
        q = """
        INSERT INTO centinela_telemetry.telemetry_events
        (source, event_type, username, client_ip, severity, details, confidence_score)
        VALUES ({source:String}, {event_type:String}, {username:String}, {client_ip:String}, {severity:String}, {details:String}, {confidence_score:Float32})
        """
        params = {
            "param_source": source,
            "param_event_type": event_type,
            "param_username": username or "desconocido",
            "param_client_ip": client_ip or "0.0.0.0",
            "param_severity": severity,
            "param_details": json.dumps(details, ensure_ascii=False),
            "param_confidence_score": str(confidence),
        }
        r = requests.post(CLICKHOUSE_URL, params=params, data=q, auth=CLICKHOUSE_AUTH, timeout=3)
        return r.status_code == 200
    except Exception as e:
        print(f"⚠️ [ClickHouse-Manager] Fallo en inserción de evento de telemetría: {e}")
        return False

def query_recent_events(minutes: int = 15, event_type: str = None):
    """
    Consulta los eventos de telemetría analítica recientes almacenados en ClickHouse.
    Also parameterized -- see insert_telemetry_event()'s docstring for why this matters here too
    (event_type is caller-controlled today, but treating it as trusted was the same class of
    assumption that made the INSERT path genuinely exploitable).
    """
    try:
        params = {"param_minutes": str(minutes)}
        where_clause = "WHERE timestamp >= now() - INTERVAL {minutes:UInt32} MINUTE"
        if event_type:
            where_clause += " AND event_type = {event_type:String}"
            params["param_event_type"] = event_type

        q = f"SELECT timestamp, source, event_type, username, client_ip, severity, details, confidence_score FROM centinela_telemetry.telemetry_events {where_clause} ORDER BY timestamp DESC LIMIT 100 FORMAT JSON;"
        r = requests.post(CLICKHOUSE_URL, params=params, data=q, auth=CLICKHOUSE_AUTH, timeout=5)
        if r.status_code == 200:
            return r.json().get("data", [])
    except Exception as e:
        print(f"⚠️ [ClickHouse-Manager] Error al consultar eventos recientes: {e}")
    return []
