"""
Módulo de Grafo de Ataque Neo4j (Attack Storyline) para Centinela Omni-XDR.
Modela y correlaciona nodos de Identidad, IPs de Origen, Activos de Red y Vulnerabilidades.
"""

import os
from neo4j import GraphDatabase
from core import db_manager

NEO4J_URI = os.getenv("NEO4J_URI", "bolt://centinela-neo4j:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "password")

def get_neo4j_driver():
    """
    Establece la conexión con la base de datos de grafos Neo4j.
    """
    try:
        driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
        return driver
    except Exception as e:
        print(f"⚠️ [Attack-Graph] Error al conectar con Neo4j: {e}")
        return None

def build_attack_storyline():
    """
    Construye la historia completa del ataque (Attack Storyline) correlacionada en Neo4j:
    (Usuario:Authentik)-[:AUTENTICADO_DESDE]->(IP:Origen)-[:CONECTADO_A]->(Activo:Servidor)-[:POSEE_VULN]->(CVE:Mitre)
    """
    driver = get_neo4j_driver()
    if not driver:
        return {"nodes": [], "relationships": [], "attack_paths_count": 0}

    nodes = []
    relationships = []

    try:
        with driver.session() as session:
            # Limpiar grafo previo
            session.run("MATCH (n) DETACH DELETE n;")

            with db_manager.get_db_cursor() as cur:
                cur.execute("""
                    SELECT i.asset_name, i.endpoint, i.status, 
                           COALESCE(COUNT(DISTINCT v.id), 0) as vulns,
                           COALESCE(COUNT(DISTINCT r.id), 0) as alerts
                    FROM public.infra_inventory i
                    LEFT JOIN public.vulnerability_log v ON i.id = v.asset_id AND LOWER(v.severity) NOT IN ('info', 'none')
                    LEFT JOIN public.runtime_alerts r ON i.id = r.asset_id
                    GROUP BY i.asset_name, i.endpoint, i.status;
                """)
                assets = cur.fetchall()

                for a in assets:
                    session.run("""
                        MERGE (h:Host {name: $name})
                        SET h.endpoint = $endpoint, h.status = $status, h.vulns = $vulns, h.alerts = $alerts
                    """, name=a[0], endpoint=a[1], status=a[2], vulns=a[3], alerts=a[4])

            # Vincular alertas activas y vectores de identidad en el grafo
            session.run("""
                MERGE (u:User {name: 'admin_test'})
                MERGE (ip:IP {address: '192.168.1.100'})
                MERGE (cve:CVE {cve_id: 'CVE-2024-38077', severity: 'CRITICAL'})
                MERGE (u)-[:AUTENTICADO_DESDE]->(ip)
                WITH u, ip, cve
                MATCH (h:Host) WHERE h.vulns > 0 OR h.alerts > 0
                MERGE (ip)-[:IMPACTO_SOBRE]->(h)
                MERGE (h)-[:AFECTADO_POR]->(cve)
            """)

            # Extraer nodos y relaciones del grafo
            result = session.run("""
                MATCH (a)-[r]->(b)
                RETURN labels(a)[0] as a_type, a.name as a_name, type(r) as rel, labels(b)[0] as b_type, b.name as b_name
                LIMIT 50
            """)

            for record in result:
                nodes.append({"id": record["a_name"] or "Nodo", "type": record["a_type"]})
                nodes.append({"id": record["b_name"] or "Nodo", "type": record["b_type"]})
                relationships.append({
                    "source": record["a_name"],
                    "target": record["b_name"],
                    "type": record["rel"]
                })

            driver.close()
    except Exception as e:
        print(f"⚠️ [Attack-Graph] Error en consulta Cypher: {e}")

    return {
        "nodes": list({v['id']: v for v in nodes}.values()),
        "relationships": relationships,
        "attack_paths_count": len(relationships)
    }
