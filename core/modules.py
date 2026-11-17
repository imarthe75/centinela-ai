"""Optional platform modules (ADR-0019). A module that has no real data source stays OFF instead of running against empty stores.

Each module is switched with an environment variable `MODULE_<NAME>` = on/off. The default is the decision recorded in ADR-0019 for the
current deployment; turning one on is a configuration change, not a code change.

  clickhouse  ClickHouse telemetry store (identity/EDR events). OFF: it never received an event (0 rows) and used ~700 MB of RAM.
  bloodhound  Neo4j attack-path analyzer. OFF: no Active Directory data has ever been imported (0 :User nodes).
"""
import os

DEFAULTS = {"clickhouse": False, "bloodhound": False}
DESCRIPTIONS = {
    "clickhouse": "Almacén de telemetría de identidad/EDR (ClickHouse)",
    "bloodhound": "Análisis de rutas de ataque de Active Directory (Neo4j/BloodHound)",
}


def enabled(name: str) -> bool:
    """True when the module is switched on (MODULE_<NAME>=on|true|1), else its ADR-0019 default."""
    raw = os.getenv(f"MODULE_{name.upper()}")
    if raw is None or raw.strip() == "":
        return DEFAULTS.get(name, False)
    return raw.strip().lower() in ("1", "true", "on", "yes")


def status() -> dict:
    """{module: {"enabled": bool, "description": str}} for the health view and /api/modules."""
    return {n: {"enabled": enabled(n), "description": DESCRIPTIONS.get(n, n)} for n in DEFAULTS}
