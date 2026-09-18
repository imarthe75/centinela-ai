"""
Módulo de Grafo de Ataque Neo4j Incremental (Attack Storyline) para Centinela Omni-XDR.
Modela y correlaciona nodos de Identidad, IPs de Origen, Activos de Red y Vulnerabilidades de forma incremental.
"""

import os
try:
    from neo4j import GraphDatabase
except ImportError:
    GraphDatabase = None
from core import db_manager

NEO4J_URI = os.getenv("NEO4J_URI", "bolt://centinela-neo4j:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "password")


def get_neo4j_driver():
    """Establece la conexión con la base de datos de grafos Neo4j."""
    if not GraphDatabase:
        return None
    try:
        driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
        return driver
    except Exception as e:
        print(f"⚠️ [Attack-Graph] Error al conectar con Neo4j: {e}")
        return None


def build_attack_storyline():
    """
    Construye y actualiza de forma INCREMENTAL la historia del ataque (Attack Storyline) en Neo4j:
    (Usuario)-[:AUTENTICADO_DESDE]->(IP:Origen)-[:IMPACTO_SOBRE]->(Activo:Host)-[:AFECTADO_POR]->(CVE:Vulnerabilidad)
    Preserva el historial forense sin wipe destructivo (DETACH DELETE n).
    """
    driver = get_neo4j_driver()
    if not driver:
        return {"nodes": [], "relationships": [], "attack_paths_count": 0}

    nodes = []
    relationships = []

    try:
        with driver.session() as session:
            # 1. Actualización incremental de Hosts desde infra_inventory + vulnerability_log + runtime_alerts
            with db_manager.get_db_cursor() as cur:
                cur.execute("""
                    SELECT i.id, i.asset_name, i.endpoint, i.status, 
                           COALESCE(COUNT(DISTINCT v.id), 0) as vulns,
                           COALESCE(COUNT(DISTINCT r.id), 0) as alerts
                    FROM public.infra_inventory i
                    LEFT JOIN public.vulnerability_log v ON i.id = v.asset_id AND LOWER(v.severity) NOT IN ('info', 'none')
                    LEFT JOIN public.runtime_alerts r ON i.id = r.asset_id
                    GROUP BY i.id, i.asset_name, i.endpoint, i.status;
                """)
                assets = cur.fetchall()

                for a in assets:
                    session.run("""
                        MERGE (h:Host {asset_id: $asset_id})
                        ON CREATE SET h.name = $name, h.endpoint = $endpoint, h.status = $status, h.vulns = $vulns, h.alerts = $alerts, h.created_at = timestamp()
                        ON MATCH SET h.name = $name, h.endpoint = $endpoint, h.status = $status, h.vulns = $vulns, h.alerts = $alerts, h.last_seen = timestamp()
                    """, asset_id=a[0], name=a[1], endpoint=a[2], status=a[3], vulns=a[4], alerts=a[5])

                # 2. Correlación de vulnerabilidades reales de alta severidad por activo
                cur.execute("""
                    SELECT DISTINCT v.asset_id, v.cve_id, v.severity
                    FROM public.vulnerability_log v
                    WHERE v.asset_id IS NOT NULL AND LOWER(v.severity) IN ('critical', 'high')
                    LIMIT 200;
                """)
                vuln_rows = cur.fetchall()

                for v in vuln_rows:
                    session.run("""
                        MERGE (cve:CVE {cve_id: $cve_id})
                        ON CREATE SET cve.severity = $severity, cve.created_at = timestamp()
                        ON MATCH SET cve.severity = $severity, cve.last_seen = timestamp()
                        WITH cve
                        MATCH (h:Host {asset_id: $asset_id})
                        MERGE (h)-[r:AFECTADO_POR]->(cve)
                        ON CREATE SET r.created_at = timestamp()
                    """, asset_id=v[0], cve_id=v[1], severity=v[2])

                # 3. Correlación de alertas runtime (Falco/Wazuh) e IP de origen
                cur.execute("""
                    SELECT r.asset_id, r.rule_name, r.severity, r.client_ip
                    FROM public.runtime_alerts r
                    WHERE r.client_ip IS NOT NULL AND r.client_ip NOT IN ('0.0.0.0', '127.0.0.1')
                    ORDER BY r.created_at DESC
                    LIMIT 100;
                """)
                alert_rows = cur.fetchall()

                for r in alert_rows:
                    session.run("""
                        MERGE (ip:IP {address: $ip})
                        ON CREATE SET ip.created_at = timestamp()
                        ON MATCH SET ip.last_seen = timestamp()
                        WITH ip
                        MATCH (h:Host {asset_id: $asset_id})
                        MERGE (ip)-[rel:IMPACTO_SOBRE]->(h)
                        ON CREATE SET rel.rule = $rule, rel.severity = $severity
                    """, asset_id=r[0], ip=r[3], rule=r[1], severity=r[2])

            # 4. Extraer grafo correlacionado para visualización
            result = session.run("""
                MATCH (a)-[r]->(b)
                RETURN labels(a)[0] as a_type, COALESCE(a.name, a.cve_id, a.address, 'Nodo') as a_name, 
                       type(r) as rel, 
                       labels(b)[0] as b_type, COALESCE(b.name, b.cve_id, b.address, 'Nodo') as b_name
                LIMIT 100
            """)

            for record in result:
                nodes.append({"id": record["a_name"], "type": record["a_type"]})
                nodes.append({"id": record["b_name"], "type": record["b_type"]})
                relationships.append({
                    "source": record["a_name"],
                    "target": record["b_name"],
                    "type": record["rel"]
                })

            driver.close()
    except Exception as e:
        print(f"⚠️ [Attack-Graph] Error en actualización incremental Cypher: {e}")

    return {
        "nodes": list({v['id']: v for v in nodes}.values()),
        "relationships": relationships,
        "attack_paths_count": len(relationships)
    }
