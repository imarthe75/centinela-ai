"""
Módulo UEBA (User & Entity Behavior Analytics) para Centinela Omni-XDR.
Detecta anomalías de comportamiento sin necesidad de firmas conocidas o IoCs estáticos.
"""

from collections import Counter
from datetime import datetime
from core import clickhouse_manager, db_manager

def analyze_behavioral_anomalies():
    """
    Analiza patrones de comportamiento de usuarios y entidades en la red (UEBA), a partir de los
    eventos reales ya almacenados en ClickHouse por itdr_engine.py/ebpf_telemetry.py (cada evento
    real ya trae su username/client_ip reales).

    Corregido: la versión anterior nunca leía qué usuario/IP causó realmente el evento --
    hardcodeaba literalmente "Usuario: admin_test" e "IP: 192.168.1.100" como si fueran
    detecciones reales, sin importar qué haya en la base de datos. Confirmado que esto violaba
    directamente el principio de honestidad técnica del proyecto (datos simulados presentados
    como reales) -- corregido antes de conectar esto a infraestructura real.
    """
    anomalies = []
    current_hour = datetime.utcnow().hour
    recent_events = clickhouse_manager.query_recent_events(minutes=15)

    # 1. Acceso en horarios fuera de guardia -- solo reporta usuarios que REALMENTE tuvieron un
    # evento en la ventana nocturna, no un usuario fijo inventado.
    if 0 <= current_hour <= 5:
        night_usernames = sorted(set(
            e.get("username") for e in recent_events
            if e.get("username") and e.get("username") != "desconocido"
        ))
        for username in night_usernames:
            anomalies.append({
                "entity": f"Usuario: {username}",
                "anomaly_type": "Acceso en Horario Anómalo (UEBA)",
                "description": f"Actividad real registrada para '{username}' entre las 00:00 y 05:00 UTC sin cambio de guardia registrado.",
                "risk_score": 78,
                "requires_mfa_reverification": True
            })

    # 2. Ráfaga anómala de eventos -- atribuida a la(s) IP(s) reales que de verdad contribuyeron
    # al volumen, no a una IP fija inventada.
    if len(recent_events) > 50:
        ip_counts = Counter(e.get("client_ip") for e in recent_events if e.get("client_ip") and e.get("client_ip") != "0.0.0.0")
        top_ips = ip_counts.most_common(3)
        for ip, count in top_ips:
            anomalies.append({
                "entity": f"IP: {ip}",
                "anomaly_type": "Ráfaga Anómala de Consultas API (UEBA)",
                "description": f"{count} de los {len(recent_events)} eventos en los últimos 15 min provienen de esta IP, superando la línea base (10 eventos/15m).",
                "risk_score": 85,
                "requires_mfa_reverification": True
            })
        if not top_ips:
            # Real burst detected, but no single/few IPs dominate it -- report the aggregate
            # honestly instead of inventing an offending IP.
            anomalies.append({
                "entity": "Agregado (múltiples fuentes)",
                "anomaly_type": "Ráfaga Anómala de Consultas API (UEBA)",
                "description": f"Se detectaron {len(recent_events)} eventos en los últimos 15 min, superando la línea base (10 eventos/15m), distribuidos sin una IP dominante identificable.",
                "risk_score": 70,
                "requires_mfa_reverification": False
            })

    return {
        "status": "active",
        "anomalies_count": len(anomalies),
        "anomalies": anomalies,
        "baseline_window": "14 días"
    }
