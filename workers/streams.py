"""Moved verbatim from centinela.py (ADR-0008 #3)."""
import os
import re
import logging
import threading
import time
import json
import redis
import psycopg2
import concurrent.futures
from psycopg2.extras import RealDictCursor
from core import db_manager
from core import agent_ledger
from core import deduplication_engine

import hvac
import urllib.request
import urllib.error
import ssl


from core.ip_block_script import generate_ip_block_virtual_patch, generate_ip_unblock_script  # noqa: E402  (shared with core/soar_engine.py)
import logging
from core.db_manager import get_secret
logger = logging.getLogger("centinela")



# Falco/Zeek runtime-alert noise. A rule_name here is pure background chatter in this
# deployment -- Falco firing non-stop against Centinela's own ephemeral scanner containers
# (ZAP, trivy, etc.) or Zeek's own liveness heartbeat -- and is not persisted to
# runtime_alerts at all. Kept in sync with core.incident_engine.NOISE_RULES (imported lazily
# to avoid a heavy import at module load).
_RUNTIME_ALERT_NOISE_RULES = {
    "ZEEK-CONN-HEARTBEAT",
    "Drop and execute new binary in container",
    "Read sensitive file untrusted",
    "Falco internal: syscall event drop",
    "PTRACE attached to process",
}


# Falco's own priority vocabulary (syslog-style, mixed case) mapped onto Centinela's
# canonical CRITICAL/HIGH/MEDIUM/LOW/INFO scale so runtime_alerts.priority is consistent
# regardless of which sensor produced the row. Anything unrecognised falls back to INFO.
_FALCO_PRIORITY_MAP = {
    "emergency": "CRITICAL", "alert": "CRITICAL", "critical": "CRITICAL",
    "error": "HIGH",
    "warning": "MEDIUM",
    "notice": "LOW",
    "informational": "INFO", "info": "INFO", "debug": "INFO",
}



def normalize_alert_priority(raw):
    """Map any sensor's priority string onto CRITICAL/HIGH/MEDIUM/LOW/INFO."""
    s = str(raw or "").strip().lower()
    if s in _FALCO_PRIORITY_MAP:
        return _FALCO_PRIORITY_MAP[s]
    if s in ("critical", "high", "medium", "low", "info"):
        return s.upper()
    return "INFO"


# DB_CONFIG moved to db_manager.py

VALKEY_CONFIG = {
    "host": get_secret("VALKEY_HOST", "***REMOVED-SECRET***"),
    "port": 6379,
    "db": 0
}


# get_db_connection moved to db_manager.py

def get_valkey_connection():
    return redis.Redis(**VALKEY_CONFIG)


def process_falco_alerts():
    """Consume Falco alerts from Valkey and store in DB"""
    r = get_valkey_connection()
    while True:
        try:
            # Falcosidekick's REDIS_STORAGEKEY env var does not actually control the list name
            # in the deployed version (confirmed live: set to "centinela:falco", but every event
            # -- verified by manually inspecting Valkey's real keys after real triggered
            # detections -- landed in a plain "falco" list instead). This silently meant zero
            # Falco alerts were ever consumed since Falco was first deployed, despite the whole
            # pipeline (Falco -> Falcosidekick -> Valkey) actually working end-to-end the entire
            # time; the DB backfill of already-queued events on first deploy is intentional (see
            # centinela.py's startup sequence), not an oversight.
            alert_raw = r.lpop("falco")
            if alert_raw:
                alert = json.loads(alert_raw)
                rule_name = alert.get('rule')

                # Drop pure background noise (Falco firing against Centinela's own ephemeral
                # scanner containers, etc.) before it ever reaches the DB -- it was drowning
                # real signal ~1000:1 in the threat-hunting view.
                if rule_name in _RUNTIME_ALERT_NOISE_RULES:
                    time.sleep(1)
                    continue

                print(f"🚨 [Centinela-AI] Falco Alert: {rule_name}")

                with db_manager.get_db_cursor() as cur:
                    container_name = alert.get('output_fields', {}).get('container.name')
                    asset_id = None
                    if container_name:
                        cur.execute("SELECT id FROM infra_inventory WHERE asset_name LIKE %s", (f"%{container_name}%",))
                        res = cur.fetchone()
                        if res:
                            asset_id = res[0]

                    cur.execute("""
                        INSERT INTO runtime_alerts (asset_id, priority, rule_name, alert_text, output_fields)
                        VALUES (%s, %s, %s, %s, %s)
                    """, (
                        asset_id,
                        normalize_alert_priority(alert.get('priority')),
                        rule_name,
                        alert.get('output'),
                        json.dumps(alert.get('output_fields', {}))
                    ))
        except Exception as e:
            print(f"❌ [Centinela-AI] Error processing Falco alert: {e}")
        
        time.sleep(1)


def process_zeek_alerts():
    """Consume Zeek logs or alerts from Valkey and store in DB"""
    r = get_valkey_connection()
    # Check if we also have file logs to tail
    zeek_log_path = "/app/logs/zeek/notice.log"
    
    # Simple tail logic if file exists
    f_log = None
    if os.path.exists(zeek_log_path):
        try:
            f_log = open(zeek_log_path, "r")
            f_log.seek(0, 2)
        except Exception as e:
            print(f"⚠️ [Centinela-AI] Cannot open Zeek log file: {e}")

    while True:
        # 1. Valkey queue check
        try:
            alert_raw = r.lpop("centinela:zeek")
            if alert_raw:
                alert = json.loads(alert_raw)
                print(f"📡 [Centinela-AI] Zeek Alert: {alert.get('msg', 'Notice')}")
                with db_manager.get_db_cursor() as cur:
                    cur.execute("""
                        INSERT INTO runtime_alerts (asset_id, priority, rule_name, alert_text, output_fields)
                        VALUES (NULL, 'MEDIUM', %s, %s, %s)
                    """, (
                        alert.get('note', 'ZEEK_NOTICE'),
                        alert.get('msg', 'Alerta de red detectada por Zeek'),
                        json.dumps(alert)
                    ))
        except Exception as e:
            print(f"❌ [Centinela-AI] Error processing Zeek Valkey alert: {e}")

        # 2. Log file check
        if f_log:
            try:
                line = f_log.readline()
                if line:
                    alert = json.loads(line)
                    print(f"📡 [Centinela-AI] Zeek Log Notice: {alert.get('msg')}")
                    with db_manager.get_db_cursor() as cur:
                        cur.execute("""
                            INSERT INTO runtime_alerts (asset_id, priority, rule_name, alert_text, output_fields)
                            VALUES (NULL, 'MEDIUM', %s, %s, %s)
                        """, (
                            alert.get('note', 'ZEEK_NOTICE'),
                            alert.get('msg', 'Notice logs de red'),
                            json.dumps(alert)
                        ))
            except Exception as e:
                print(f"⚠️ [Centinela-AI] Error processing Zeek notice log line: {e}")

        time.sleep(1)



def process_zeek_conn_log():
    """
    Real Zeek conn.log ingestion, cross-referenced live against the CTI feed
    (core/cti_feed.py). The infrastructure for this was already correct -- centinela-ai has a
    real, working, read-only mount of Zeek's actual log directory (zeek-logs volume at
    /app/logs/zeek) -- but process_zeek_alerts() only ever watched notice.log, which Zeek only
    writes when something already looks notice-worthy by its own built-in policy. conn.log is
    Zeek's real, continuously-written connection log (confirmed live: 108KB and growing,
    updated seconds before this was written) and nothing ever read it, so Zeek's rich
    per-connection data was completely unused despite the working ingestion pipe already being
    there.

    Every new connection's source/destination IP is checked against the live Feodo Tracker
    feed in real time -- a match means this host is *currently* talking to a confirmed C2
    server, not a static/backfilled check. Also logs a periodic real activity heartbeat
    (distinct from a fake "still alive" ping -- it's an honest count of connections actually
    observed) so main.py's Zeek health check reflects genuine pipeline activity, not just
    whether something bad happened to be found in the last 24h.
    """
    from core import cti_feed, deduplication_engine

    conn_log_path = "/app/logs/zeek/conn.log"
    fields = []
    f = None
    conn_count = 0
    last_heartbeat = time.time()

    def open_log():
        nonlocal f, fields
        try:
            f = open(conn_log_path, "r")
            for line in f:
                if line.startswith("#fields"):
                    fields = line.strip().split("\t")[1:]
                    break
            f.seek(0, 2)  # only process new connections from here on
            return True
        except Exception as e:
            print(f"⚠️ [Centinela-AI] Cannot open Zeek conn.log: {e}")
            return False

    if not os.path.exists(conn_log_path) or not open_log():
        print("ℹ️ [Centinela-AI] Zeek conn.log not available -- conn-log ingestion skipped.")
        return

    print(f"📡 [Centinela-AI] Tailing Zeek conn.log for real-time CTI correlation ({len(fields)} fields detected).")

    while True:
        try:
            line = f.readline()
            if not line:
                # Detect rotation (file replaced/truncated) -- reopen from the start of the new file.
                try:
                    if os.path.exists(conn_log_path) and os.path.getsize(conn_log_path) < f.tell():
                        f.close()
                        open_log()
                except Exception as e:
                    print(f"⚠️ [Centinela-AI] Error checking/handling Zeek conn.log rotation: {e}")
                time.sleep(2)

                # Real, honest activity heartbeat every 5 minutes -- not a fake ping, an actual
                # count of connections observed since the last one.
                if time.time() - last_heartbeat > 300:
                    with db_manager.get_db_cursor() as cur:
                        # Keep exactly ONE heartbeat row (replace, don't append). /api/health's
                        # Zeek-ingestion check only cares that a recent one exists; appending a
                        # new row every 5 min was silently piling up thousands of INFO rows that
                        # cluttered the threat-hunting log for no added signal.
                        cur.execute("DELETE FROM runtime_alerts WHERE rule_name = 'ZEEK-CONN-HEARTBEAT'")
                        cur.execute("""
                            INSERT INTO runtime_alerts (asset_id, priority, rule_name, alert_text, output_fields)
                            VALUES (NULL, 'INFO', 'ZEEK-CONN-HEARTBEAT', %s, %s)
                        """, (
                            f"Zeek observó {conn_count} conexiones de red en los últimos 5 minutos.",
                            json.dumps({"connections_observed": conn_count})
                        ))
                    conn_count = 0
                    last_heartbeat = time.time()
                continue

            if line.startswith("#") or not fields:
                continue
            values = line.rstrip("\n").split("\t")
            if len(values) != len(fields):
                continue
            record = dict(zip(fields, values))
            conn_count += 1

            malicious_ips = cti_feed.get_malicious_ips()
            for ip_field in ("id.orig_h", "id.resp_h"):
                ip = record.get(ip_field, "")
                if ip in malicious_ips:
                    ioc = malicious_ips[ip]
                    direction = "hacia" if ip_field == "id.resp_h" else "desde"
                    desc = (
                        f"**Zeek observó una conexión de red real {direction} {ip}, confirmada como servidor C2 "
                        f"activo en Feodo Tracker (abuse.ch).**\n\n"
                        f"**Malware asociado:** {ioc.get('malware', 'desconocido')}\n"
                        f"**Conexión:** {record.get('id.orig_h')}:{record.get('id.orig_p')} -> "
                        f"{record.get('id.resp_h')}:{record.get('id.resp_p')} ({record.get('proto', '?')})"
                    )
                    with db_manager.get_db_cursor() as cur:
                        cur.execute("""
                            INSERT INTO runtime_alerts (asset_id, priority, rule_name, alert_text, output_fields)
                            VALUES (NULL, 'CRITICAL', 'ZEEK-CTI-MATCH', %s, %s)
                        """, (desc, json.dumps(record)))
                        # Best-effort: attribute to a real asset if the non-malicious side of
                        # the connection matches a registered IP; otherwise this still lands in
                        # runtime_alerts for visibility even without a specific asset to pin it to.
                        other_ip = record.get("id.orig_h") if ip_field == "id.resp_h" else record.get("id.resp_h")
                        cur.execute("SELECT id FROM infra_inventory WHERE endpoint ILIKE %s LIMIT 1", (f"%{other_ip}%",))
                        asset = cur.fetchone()
                        if asset:
                            deduplication_engine.log_finding_deduplicated(
                                cur, asset[0], "CTI-IOC-MATCH-RUNTIME", "CRITICAL", desc,
                                "cti-feed", url_path=f"conn-{record.get('uid', ip)}", open_status="PENDING",
                                preserve_status=True
                            )
                    print(f"🚨 [Centinela-AI] Zeek+CTI: real connection to confirmed C2 IP {ip} ({ioc.get('malware')}).")
        except Exception as e:
            print(f"❌ [Centinela-AI] Error processing Zeek conn.log: {e}")
            time.sleep(5)



def process_bloodhound_paths():
    """Query Neo4j for AD attack paths and raise vulnerabilities"""
    from core import modules
    if not modules.enabled("bloodhound"):
        print("ℹ️ [Centinela-AI] Módulo BloodHound apagado (MODULE_BLOODHOUND, ADR-0019): sin datos de Active Directory que analizar.")
        return
    try:
        from neo4j import GraphDatabase
        NEO4J_AVAILABLE = True
    except ImportError:
        NEO4J_AVAILABLE = False

    if not NEO4J_AVAILABLE:
        print("ℹ️ [Centinela-AI] Neo4j library not available, BloodHound path analyzer skipped")
        return

    uri = os.getenv("NEO4J_URI", "bolt://neo4j:7687")
    user = os.getenv("NEO4J_USER", "neo4j")
    password = os.getenv("NEO4J_PASSWORD", "password")

    from core import deduplication_engine

    while True:
        try:
            print("🩸 [Centinela-AI] BloodHound Graph Analyzer querying attack paths...")
            driver = GraphDatabase.driver(uri, auth=(user, password))
            with driver.session() as session:
                # Distinguish "no data has ever been imported" from "data exists and genuinely
                # shows no attack path" -- these previously looked identical (both produced no
                # log line at all), which silently masked the fact this query has likely never
                # found real data to run against (see the CLAUDE.md Attack-Path-Graphing entry:
                # SharpHound/AzureHound collector output is never ingested anywhere in this repo).
                node_count = session.run("MATCH (u:User) RETURN count(u) AS c").single()
                user_count = node_count["c"] if node_count else 0
                if user_count == 0:
                    print("ℹ️ [Centinela-AI] BloodHound graph has no :User nodes -- no collector "
                          "data (SharpHound/AzureHound) has ever been imported into Neo4j. "
                          "Query skipped; nothing to analyze until real AD data is loaded.")
                    driver.close()
                    time.sleep(600)
                    continue

                # Query shortest path from any non-admin user to the Domain Admins group.
                # Was previously hardcoded to the literal group name
                # 'DOMAIN ADMINS@INTERNAL.LOCAL' -- BloodHound suffixes every node name with
                # the real AD domain's FQDN, so this only ever matched a domain literally
                # named INTERNAL.LOCAL and would have silently found nothing against any real
                # domain (verified live against a disposable synthetic Neo4j dataset: the old
                # hardcoded query returned zero rows against a DOMAIN ADMINS@TESTDOMAIN.LOCAL
                # group, the STARTS WITH version below found the path correctly). Matching by
                # prefix instead of the full name makes this work against whatever domain gets
                # imported later without needing a code change.
                query = """
                MATCH p=shortestPath((u:User)-[*1..10]->(g:Group))
                WHERE g.name STARTS WITH 'DOMAIN ADMINS@' AND NOT u.name STARTS WITH 'Administrator'
                RETURN p LIMIT 1
                """
                result = session.run(query)
                record = result.single()
                if record:
                    path = record.get("p")
                    nodes = [n.get("name") for n in path.nodes]
                    desc = (
                        "BloodHound detectó una ruta de ataque de escalada de privilegios hacia "
                        f"el grupo Domain Admins. Ruta: {' -> '.join(nodes)}"
                    )

                    with db_manager.get_db_cursor() as cur:
                        # Real AD domain asset only -- the old fallback ("...OR asset_type =
                        # 'SERVER' LIMIT 1") attributed this to an arbitrary, unrelated SERVER
                        # asset whenever no asset was literally named "Active Directory",
                        # misrepresenting which host the finding is actually about.
                        cur.execute("""
                            SELECT id FROM infra_inventory
                            WHERE asset_name ILIKE '%active directory%' OR asset_type ILIKE '%domain%'
                            LIMIT 1
                        """)
                        res = cur.fetchone()
                        if res:
                            deduplication_engine.log_finding_deduplicated(
                                cur, res[0], "BLOODHOUND-PATH-AD", "CRITICAL", desc,
                                "bloodhound", open_status="PENDING", preserve_status=True
                            )
                            print("🚨 [Centinela-AI] Critical Attack Path logged in DB!")
                        else:
                            print("⚠️ [Centinela-AI] Attack path found but no Active Directory "
                                  "asset is registered in infra_inventory to attribute it to -- "
                                  "not logging against an unrelated asset. Register the AD "
                                  "domain as an asset to enable this.")
            driver.close()
        except Exception as e:
            print(f"⚠️ [Centinela-AI] BloodHound/Neo4j query failed: {e}")

        # Check every 10 minutes
        time.sleep(600)
