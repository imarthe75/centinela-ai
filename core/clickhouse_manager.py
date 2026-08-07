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

def init_clickhouse():
    """
    Inicializa la base de datos y la tabla de telemetría analítica en ClickHouse.
    """
    try:
        # Crear base de datos de telemetría
        q_db = "CREATE DATABASE IF NOT EXISTS centinela_telemetry;"
        requests.post(CLICKHOUSE_URL, data=q_db, timeout=5)

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
        requests.post(CLICKHOUSE_URL, data=q_tbl, timeout=5)
        print("✅ [ClickHouse-Manager] Base de datos 'centinela_telemetry' e índice inicializados correctamente.")
        return True
    except Exception as e:
        print(f"⚠️ [ClickHouse-Manager] Error al inicializar ClickHouse: {e}")
        return False

def insert_telemetry_event(source: str, event_type: str, username: str, client_ip: str, severity: str, details: dict, confidence: float = 0.0):
    """
    Inserta un evento de telemetría de alta frecuencia en ClickHouse.
    """
    try:
        data = {
            "source": source,
            "event_type": event_type,
            "username": username or "desconocido",
            "client_ip": client_ip or "0.0.0.0",
            "severity": severity,
            "details": json.dumps(details, ensure_ascii=False),
            "confidence_score": confidence
        }
        q = f"""
        INSERT INTO centinela_telemetry.telemetry_events 
        (source, event_type, username, client_ip, severity, details, confidence_score) 
        VALUES ('{data["source"]}', '{data["event_type"]}', '{data["username"]}', '{data["client_ip"]}', '{data["severity"]}', '{data["details"]}', {data["confidence_score"]});
        """
        r = requests.post(CLICKHOUSE_URL, data=q, timeout=3)
        return r.status_code == 200
    except Exception as e:
        print(f"⚠️ [ClickHouse-Manager] Fallo en inserción de evento de telemetría: {e}")
        return False

def query_recent_events(minutes: int = 15, event_type: str = None):
    """
    Consulta los eventos de telemetría analítica recientes almacenados en ClickHouse.
    """
    try:
        where_clause = f"WHERE timestamp >= now() - INTERVAL {minutes} MINUTE"
        if event_type:
            where_clause += f" AND event_type = '{event_type}'"
        
        q = f"SELECT timestamp, source, event_type, username, client_ip, severity, details, confidence_score FROM centinela_telemetry.telemetry_events {where_clause} ORDER BY timestamp DESC LIMIT 100 FORMAT JSON;"
        r = requests.post(CLICKHOUSE_URL, data=q, timeout=5)
        if r.status_code == 200:
            return r.json().get("data", [])
    except Exception as e:
        print(f"⚠️ [ClickHouse-Manager] Error al consultar eventos recientes: {e}")
    return []
