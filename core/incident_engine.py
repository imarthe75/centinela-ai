"""
Item 2 (2026-08-27): incident correlation engine.

Centinela correlates *vulnerabilities* one at a time. It never grouped related *runtime*
signals -- Falco / Zeek / Wazuh alerts, CTI/IoC hits, BloodHound paths -- into a single
incident with a timeline, an ATT&CK kill chain, and a detection->containment clock. KIO's
"The Rock" makes exactly that its headline capability ("automated event classification and
grouping" + an MTTD/dwell-time metric). This module builds it from the signals that already
exist in `runtime_alerts` and `vulnerability_log`.

Design constraints (all verified live against the real DB on 2026-08-27, see DECISIONS/0003):

  * `runtime_alerts` is ~93% self-noise in this deployment -- `ZEEK-CONN-HEARTBEAT`, plus Falco
    rules that fire constantly on Centinela's own scanner containers ("Drop and execute new
    binary in container", "Read sensitive file untrusted", ...). Those are denylisted here.
    Grouping them would produce one garbage incident every couple of minutes.
  * Fail-safe on no data: with nothing worth grouping the loop runs and creates nothing, the
    same way process_bloodhound_paths() no-ops against an empty graph.
  * Deterministic grouping (union-find, no LLM). An optional AI executive summary is layered on
    top of the deterministic narrative and never invents events.

The pure logic here (extract_indicators / classify_tactic / group_signals / incident_fingerprint
/ build_narrative / summarize_group) is unit-tested with no DB. The two DB helpers
(attach_or_create_incidents / reconcile_closed_incidents) take an open cursor.
"""
import hashlib
import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set

try:
    from core import mitre_attack
except Exception:  # pragma: no cover - mitre module is always present in prod
    mitre_attack = None

# ---------------------------------------------------------------- noise / config

# Rule names that are pure background noise in this deployment (see module docstring). A
# runtime_alert whose rule_name is here never seeds or joins an incident.
NOISE_RULES = frozenset({
    "ZEEK-CONN-HEARTBEAT",
    "Drop and execute new binary in container",
    "Read sensitive file untrusted",
    "Falco internal: syscall event drop",
    "PTRACE attached to process",
})

# Rule/prefix patterns that are incident-worthy on their own (a single occurrence justifies an
# incident, no second signal required).
STANDALONE_WORTHY_PREFIXES = ("ITDR-", "CTI-IOC-MATCH", "BLOODHOUND-PATH")
STANDALONE_WORTHY_SUBSTRINGS = ("BRUTE-FORCE", "PASSWORD-SPRAY", "RANSOM", "REVERSE SHELL",
                                "CLEAR LOG", "DISABLE", "EXFIL")

_SEVERITY_RANK = {"INFO": 0, "LOW": 1, "DEBUG": 0, "NOTICE": 1, "WARNING": 2, "MEDIUM": 2,
                  "HIGH": 3, "CRITICAL": 4}
_RANK_SEVERITY = {0: "INFO", 1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_USER_RE = re.compile(
    r"(?:usuario|user|username|account|cuenta)\s*[:=]?\s*['\"]?([A-Za-z0-9._\-\\@]{2,64})['\"]?",
    re.IGNORECASE,
)

# Canonical ATT&CK tactic order for kill-chain sorting.
TACTIC_ORDER = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence",
    "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery",
    "Lateral Movement", "Collection", "Command and Control", "Exfiltration", "Impact",
]
_TACTIC_IDX = {t: i for i, t in enumerate(TACTIC_ORDER)}


@dataclass
class Signal:
    key: str                 # unique, e.g. "runtime_alert:358"
    source: str              # 'runtime_alert' | 'vulnerability' | 'cti' | 'bloodhound'
    source_id: int
    asset_id: Optional[int]
    occurred_at: datetime
    severity: str            # normalized upper (INFO/LOW/MEDIUM/HIGH/CRITICAL)
    rule_name: str
    summary: str
    tactic: Optional[str] = None
    ips: Set[str] = field(default_factory=set)
    users: Set[str] = field(default_factory=set)
    standalone_worthy: bool = False


# ---------------------------------------------------------------- pure helpers

def normalize_severity(raw: Any) -> str:
    s = str(raw or "").strip().upper()
    if s in _SEVERITY_RANK:
        return _RANK_SEVERITY[_SEVERITY_RANK[s]]
    return "MEDIUM"


def _public_or_private_ok(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    # keep private + public, drop obviously-useless ones
    return not (addr.is_loopback or addr.is_unspecified or addr.is_multicast)


def extract_indicators(rule_name: str, alert_text: str,
                       output_fields: Optional[dict]) -> Dict[str, Set[str]]:
    """Pull IPs and usernames out of an alert's text + structured fields."""
    ips: Set[str] = set()
    users: Set[str] = set()
    blob = f"{rule_name or ''} {alert_text or ''}"

    if isinstance(output_fields, dict):
        for k, v in output_fields.items():
            if v is None:
                continue
            lk = str(k).lower()
            sv = str(v)
            if "ip" in lk or "addr" in lk or lk in ("connection", "peer"):
                blob += " " + sv
            if lk in ("user.name", "user", "username", "usr.name", "subject", "actor"):
                if re.fullmatch(r"[A-Za-z0-9._\-\\@]{2,64}", sv):
                    users.add(sv)

    for m in _IPV4_RE.findall(blob):
        if _public_or_private_ok(m):
            ips.add(m)
    for m in _USER_RE.findall(alert_text or ""):
        low = m.lower()
        if low not in ("name", "unknown", "none", "null", "n/a"):
            users.add(m)
    return {"ips": ips, "users": users}


def classify_tactic(rule_name: str, text: str) -> Optional[str]:
    r = (rule_name or "").upper()
    t = (text or "").upper()
    if "BRUTE" in r or "BRUTE" in t or "PASSWORD SPRAY" in t or "SPRAYING" in t:
        return "Credential Access"
    if r.startswith("CTI-IOC-MATCH") or "C2" in t or "COMMAND AND CONTROL" in t:
        return "Command and Control"
    if r.startswith("BLOODHOUND-PATH") or "DOMAIN ADMIN" in t:
        return "Privilege Escalation"
    if "CLEAR LOG" in r or "CLEAR LOG" in t or ("DISABLE" in t and "LOG" in t):
        return "Defense Evasion"
    if "EXFIL" in r or "EXFIL" in t:
        return "Exfiltration"
    if "REVERSE SHELL" in r or "REVERSE SHELL" in t or "SPAWNED SHELL" in t \
       or "EXECUTING BINARY" in t or "NEW BINARY" in t:
        return "Execution"
    if "PTRACE" in r or "INJECT" in t:
        return "Privilege Escalation"
    if mitre_attack is not None:
        m = mitre_attack.map_finding(rule_name or "", text or "")
        if m:
            return m[2]
    return None


def is_noise(rule_name: str) -> bool:
    return (rule_name or "") in NOISE_RULES


def is_standalone_worthy(rule_name: str, text: str) -> bool:
    r = (rule_name or "").upper()
    if any(r.startswith(p) for p in STANDALONE_WORTHY_PREFIXES):
        return True
    hay = f"{r} {(text or '').upper()}"
    return any(s in hay for s in STANDALONE_WORTHY_SUBSTRINGS)


def group_signals(signals: List[Signal], window_minutes: int = 60) -> List[List[Signal]]:
    """
    Union-find grouping. Two signals join iff within `window_minutes` of each other AND
    (same non-null asset_id) OR (share >=1 IP) OR (share >=1 user).
    """
    n = len(signals)
    parent = list(range(n))

    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    win = timedelta(minutes=window_minutes)
    for i in range(n):
        for j in range(i + 1, n):
            si, sj = signals[i], signals[j]
            if abs(si.occurred_at - sj.occurred_at) > win:
                continue
            same_asset = (si.asset_id is not None and si.asset_id == sj.asset_id)
            shares_ip = bool(si.ips & sj.ips)
            shares_user = bool(si.users & sj.users)
            if same_asset or shares_ip or shares_user:
                union(i, j)

    groups: Dict[int, List[Signal]] = {}
    for i in range(n):
        groups.setdefault(find(i), []).append(signals[i])
    return list(groups.values())


def incident_fingerprint(asset_id: Optional[int], first_ts: datetime,
                         core_indicators: Set[str], bucket_hours: int = 6) -> str:
    bucket = int(first_ts.timestamp() // (bucket_hours * 3600))
    inds = ":".join(sorted(core_indicators)) if core_indicators else "-"
    raw = f"{asset_id}:{bucket}:{inds}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


def _kill_chain(signals: List[Signal]) -> List[str]:
    seen = {s.tactic for s in signals if s.tactic}
    return sorted(seen, key=lambda t: _TACTIC_IDX.get(t, 999))


def build_narrative(signals: List[Signal]) -> str:
    lines = []
    for s in sorted(signals, key=lambda x: x.occurred_at):
        ts = s.occurred_at.strftime("%Y-%m-%d %H:%M:%S")
        tac = f" [{s.tactic}]" if s.tactic else ""
        lines.append(f"- {ts} · {s.severity} · `{s.rule_name}`{tac} — {s.summary[:200]}")
    return "\n".join(lines)


def _recommended_containment(signals: List[Signal]) -> str:
    ips = sorted({ip for s in signals for ip in s.ips})
    users = sorted({u for s in signals for u in s.users})
    tactics = _kill_chain(signals)
    parts = []
    if ips:
        parts.append(
            f"Bloquear la(s) IP {', '.join(ips[:5])} en el proxy "
            f"(virtual patch `deny <ip>;`) tras confirmar que no es tráfico legítimo."
        )
    if "Credential Access" in tactics or users:
        who = f" (cuenta(s): {', '.join(users[:5])})" if users else ""
        parts.append(
            f"Rotar credenciales y revocar sesiones activas en Authentik{who}; "
            f"forzar MFA."
        )
    if any(t in tactics for t in ("Execution", "Privilege Escalation", "Persistence", "Impact")):
        parts.append(
            "Evaluar aislamiento del host afectado vía `POST /api/host-containment/{asset}` "
            "(requiere aprobación humana en el SOAR)."
        )
    if not parts:
        parts.append("Investigar y correlacionar manualmente; sin acción de contención "
                     "automática sugerida para este patrón.")
    return " ".join(parts)


def summarize_group(signals: List[Signal]) -> Dict[str, Any]:
    """Deterministic incident fields from a group of signals."""
    asset_ids = {s.asset_id for s in signals if s.asset_id is not None}
    asset_id = next(iter(asset_ids)) if len(asset_ids) == 1 else None

    max_rank = max(_SEVERITY_RANK.get(s.severity, 2) for s in signals)
    kc = _kill_chain(signals)
    if len(kc) >= 3 and max_rank < 4:
        max_rank += 1
    severity = _RANK_SEVERITY[min(max_rank, 4)]

    first_ts = min(s.occurred_at for s in signals)
    last_ts = max(s.occurred_at for s in signals)
    ips = sorted({ip for s in signals for ip in s.ips})
    users = sorted({u for s in signals for u in s.users})
    core_inds = set(ips) | {f"u:{u}" for u in users}

    rules = sorted({s.rule_name for s in signals})
    lead = rules[0] if rules else "actividad sospechosa"
    if len(rules) > 1:
        lead = f"{lead} (+{len(rules) - 1} regla(s))"
    scope = f"activo {asset_id}" if asset_id else (
        f"IP {ips[0]}" if ips else (f"cuenta {users[0]}" if users else "sin activo"))
    title = f"{lead} — {scope}"

    category_code = None
    if "Credential Access" in kc:
        category_code = "A02-CRYPTO-FAIL"
    elif "Execution" in kc:
        category_code = "A03-INJECTION"
    elif "Privilege Escalation" in kc:
        category_code = "A06-VULN-COMPONENTS"
    elif "Defense Evasion" in kc:
        category_code = "A05-MISCONFIG"
    elif "Initial Access" in kc:
        category_code = "A01-BROKEN-ACCESS"

    return {
        "asset_id": asset_id,
        "title": title[:300],
        "severity": severity,
        "category_code": category_code,
        "kill_chain": kc,
        "indicators": {"ips": ips, "users": users, "rules": rules},
        "narrative": build_narrative(signals),
        "recommended_containment": _recommended_containment(signals),
        "first_event_at": first_ts,
        "last_event_at": last_ts,
        "event_count": len(signals),
        "fingerprint": incident_fingerprint(asset_id, first_ts, core_inds),
        "core_indicators": core_inds,
    }


def group_is_materializable(signals: List[Signal], min_events: int = 2) -> bool:
    if any(s.standalone_worthy for s in signals):
        return True
    # distinct source rows (a rule firing 6 times in a burst is still one pattern, but it IS
    # an incident if it's >=2 events regardless -- brute force bursts are the canonical case)
    return len(signals) >= min_events


# ---------------------------------------------------------------- DB helpers

def _sev_rank(s: str) -> int:
    return _SEVERITY_RANK.get(str(s or "").upper(), 2)


def attach_or_create_incidents(cur, groups: List[List[Signal]],
                               window_minutes: int = 60,
                               min_events: int = 2) -> Dict[str, int]:
    """
    For each materializable group: attach its signals to an existing OPEN/INVESTIGATING
    incident when one plausibly matches (same asset or shared indicator, and the incident's
    last_event_at is within `window_minutes` of the group), otherwise create a new incident.
    Idempotent: incident_events PK (incident_id, source, source_id) + incidents.fingerprint
    unique. Returns {'created': n, 'attached': n, 'events_linked': n}.
    """
    stats = {"created": 0, "attached": 0, "events_linked": 0}
    win = timedelta(minutes=window_minutes)

    cur.execute("""
        SELECT id, asset_id, indicators, last_event_at, kill_chain, severity, event_count
        FROM public.incidents
        WHERE status IN ('OPEN', 'INVESTIGATING')
    """)
    open_incidents = [
        {"id": r[0], "asset_id": r[1], "indicators": r[2] or {}, "last_event_at": r[3],
         "kill_chain": r[4] or [], "severity": r[5], "event_count": r[6]}
        for r in cur.fetchall()
    ]

    for group in groups:
        if not group_is_materializable(group, min_events):
            continue
        summ = summarize_group(group)
        g_ips = set(summ["indicators"]["ips"])
        g_users = set(summ["indicators"]["users"])

        target = None
        for inc in open_incidents:
            if inc["last_event_at"] and abs(inc["last_event_at"] - summ["last_event_at"]) > win \
               and abs(inc["last_event_at"] - summ["first_event_at"]) > win:
                continue
            inc_ips = set((inc["indicators"] or {}).get("ips", []))
            inc_users = set((inc["indicators"] or {}).get("users", []))
            if (summ["asset_id"] is not None and summ["asset_id"] == inc["asset_id"]) \
               or (g_ips & inc_ips) or (g_users & inc_users):
                target = inc
                break

        if target:
            inc_id = target["id"]
            linked = _link_events(cur, inc_id, group)
            if linked == 0:
                continue
            stats["attached"] += 1
            stats["events_linked"] += linked
            merged_ips = sorted(set((target["indicators"] or {}).get("ips", [])) | g_ips)
            merged_users = sorted(set((target["indicators"] or {}).get("users", [])) | g_users)
            merged_kc = sorted(set(target["kill_chain"]) | set(summ["kill_chain"]),
                               key=lambda t: _TACTIC_IDX.get(t, 999))
            new_sev = _RANK_SEVERITY[min(max(_sev_rank(target["severity"]),
                                             _sev_rank(summ["severity"])), 4)]
            cur.execute("""
                UPDATE public.incidents
                SET indicators = %s::jsonb,
                    kill_chain = %s,
                    severity = %s,
                    last_event_at = GREATEST(last_event_at, %s),
                    event_count = event_count + %s,
                    narrative = narrative || E'\n' || %s,
                    recommended_containment = %s
                WHERE id = %s
            """, (
                _json({"ips": merged_ips, "users": merged_users,
                       "rules": sorted(set((target["indicators"] or {}).get("rules", []))
                                       | set(summ["indicators"]["rules"]))}),
                merged_kc, new_sev, summ["last_event_at"], linked,
                build_narrative(group), summ["recommended_containment"], inc_id,
            ))
            target["indicators"] = {"ips": merged_ips, "users": merged_users}
            target["kill_chain"] = merged_kc
            target["last_event_at"] = max(target["last_event_at"] or summ["last_event_at"],
                                          summ["last_event_at"])
            target["severity"] = new_sev
        else:
            cur.execute("""
                INSERT INTO public.incidents
                (asset_id, title, category_code, severity, status, kill_chain, indicators,
                 narrative, recommended_containment, first_event_at, last_event_at, event_count,
                 fingerprint)
                VALUES (%s,%s,%s,%s,'OPEN',%s,%s::jsonb,%s,%s,%s,%s,%s,%s)
                ON CONFLICT (fingerprint) DO UPDATE SET
                    last_event_at = GREATEST(public.incidents.last_event_at, EXCLUDED.last_event_at)
                RETURNING id, (xmax = 0) AS was_inserted
            """, (
                summ["asset_id"], summ["title"], summ["category_code"], summ["severity"],
                summ["kill_chain"], _json({"ips": summ["indicators"]["ips"],
                                           "users": summ["indicators"]["users"],
                                           "rules": summ["indicators"]["rules"]}),
                summ["narrative"], summ["recommended_containment"],
                summ["first_event_at"], summ["last_event_at"], 0, summ["fingerprint"],
            ))
            row = cur.fetchone()
            inc_id, was_inserted = row[0], row[1]
            linked = _link_events(cur, inc_id, group)
            # event_count + severity kept consistent whether this was a fresh insert or a
            # same-bucket fingerprint re-hit across two loop runs.
            cur.execute("""
                UPDATE public.incidents SET
                    event_count = event_count + %s,
                    severity = CASE
                        WHEN %s > COALESCE((SELECT r FROM (VALUES
                            ('INFO',0),('LOW',1),('MEDIUM',2),('HIGH',3),('CRITICAL',4))
                            AS s(name,r) WHERE s.name = public.incidents.severity), 2)
                        THEN %s ELSE public.incidents.severity END
                WHERE id = %s
            """, (linked, _sev_rank(summ["severity"]), summ["severity"], inc_id))
            stats["events_linked"] += linked
            if was_inserted:
                stats["created"] += 1
                open_incidents.append({
                    "id": inc_id, "asset_id": summ["asset_id"],
                    "indicators": {"ips": summ["indicators"]["ips"],
                                   "users": summ["indicators"]["users"]},
                    "last_event_at": summ["last_event_at"], "kill_chain": summ["kill_chain"],
                    "severity": summ["severity"], "event_count": linked,
                })
            else:
                stats["attached"] += 1
    return stats


def _link_events(cur, incident_id: int, signals: List[Signal]) -> int:
    linked = 0
    for s in signals:
        cur.execute("""
            INSERT INTO public.incident_events
            (incident_id, source, source_id, occurred_at, tactic, severity, summary)
            VALUES (%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT (incident_id, source, source_id) DO NOTHING
        """, (incident_id, s.source, s.source_id, s.occurred_at, s.tactic, s.severity,
              s.summary[:500]))
        if cur.rowcount:
            linked += 1
    return linked


def reconcile_closed_incidents(cur, idle_hours: int = 72) -> int:
    """Auto-close OPEN/INVESTIGATING incidents idle > idle_hours with no still-open linked
    vulnerability. Returns the count closed."""
    cur.execute("""
        UPDATE public.incidents i
        SET status = 'CLOSED', closed_at = NOW()
        WHERE i.status IN ('OPEN', 'INVESTIGATING')
          AND COALESCE(i.last_event_at, i.detected_at) < NOW() - make_interval(hours => %s)
          AND NOT EXISTS (
              SELECT 1 FROM public.incident_events ie
              JOIN public.vulnerability_log v
                ON ie.source = 'vulnerability' AND ie.source_id = v.id
              WHERE ie.incident_id = i.id
                AND v.status NOT IN ('RESOLVED', 'SUPPRESSED', 'CLOSED')
          )
        RETURNING i.id
    """, (idle_hours,))
    return cur.rowcount


def _json(obj) -> str:
    import json
    return json.dumps(obj, default=list)
