"""
Which CLASS of data may be sent to which external AI provider (ADR-0012 D1; the internal methodology rule 0A-5 "qué no se carga a la IA").

`core/prompt_redaction.py` already removes secret VALUES from every prompt. This module answers the other question: even without secrets, a
prompt carrying a customer's source code must not go to a provider whose plan trains on its prompts.

Classes, from least to most sensitive:
  PUBLIC       generic text: CVE descriptions, rule names, no asset or code
  INTERNAL     asset names, private IPs, internal hostnames, no source code
  CLIENT_CODE  source or configuration excerpts of a repository (fenced blocks, "CONTEXTO DE CÓDIGO", file:line locations, "Repositorio:")
  (SECRET      never leaves; enforced by redact_secrets, not here)

Fail-closed in the classifier: when it cannot rule out CLIENT_CODE it answers CLIENT_CODE.
Fail-OPEN on purpose in the policy table: a tier with no entry keeps today's behaviour (CLIENT_CODE allowed), so shipping this module changes
nothing for providers the owner has not decided about. Only Mistral ships restricted: its free plan trains on prompts and (2026-10-01) it
answers 429 to every call anyway, so the default costs no capacity. Override with
    AI_TIER_MAX_DATA_CLASS="mistral=INTERNAL,google_genai=INTERNAL"   (tier name = label before ':')
    AI_DEFAULT_MAX_DATA_CLASS=CLIENT_CODE                              (for tiers with no entry)
"""
import logging
import os
import re
import time
from typing import Dict, List, Tuple

logger = logging.getLogger(__name__)

PUBLIC, INTERNAL, CLIENT_CODE = "PUBLIC", "INTERNAL", "CLIENT_CODE"
_ORDER = {PUBLIC: 0, INTERNAL: 1, CLIENT_CODE: 2}

_DEFAULT_TIER_LIMITS = {"mistral": INTERNAL}

_CODE_EXT = r"(?:java|py|ts|tsx|js|jsx|mjs|html|htm|xml|yml|yaml|properties|sql|go|cs|php|rb|kt|kts|scala|rs|tf|gradle|sh|json|toml|ini|conf|css|scss)"
_CODE_SIGNALS = [
    re.compile(r"```"),
    re.compile(r"CONTEXTO DE CÓDIGO"),
    re.compile(r"Repositorio:\s*\S"),
    re.compile(r"Ubicaci[oó]n \(archivo:l[ií]nea\):\s*(?!desconocida)\S+"),
    re.compile(r"[\w./\\-]+\." + _CODE_EXT + r":\d+\b"),
    re.compile(r"^\s*(?:import|package|from)\s+[\w.]+", re.MULTILINE),
    re.compile(r"^\s*(?:public|private|protected)\s+(?:static\s+)?[\w<>\[\]]+\s+\w+\s*\(", re.MULTILINE),
    re.compile(r"^\s*(?:def|class|function|const|let|var)\s+\w+", re.MULTILINE),
    re.compile(r"^[-+]{3} [ab]/", re.MULTILINE),            # unified diff headers
]
_INTERNAL_SIGNALS = [
    re.compile(r"\b(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b"),
    re.compile(r"\b[\w-]+\.(?:internal|local|lan|corp)\b", re.IGNORECASE),
    re.compile(r"(?:Activo|Asset|Host|Servidor):\s*\S", re.IGNORECASE),
]


def classify_prompt(text: str) -> str:
    """Highest data class the prompt can contain. Empty/None text is PUBLIC."""
    if not text:
        return PUBLIC
    if any(r.search(text) for r in _CODE_SIGNALS):
        return CLIENT_CODE
    if any(r.search(text) for r in _INTERNAL_SIGNALS):
        return INTERNAL
    return PUBLIC


def _parse_limits(raw: str) -> Dict[str, str]:
    out = {}
    for part in (raw or "").split(","):
        if "=" not in part:
            continue
        tier, cls = (x.strip() for x in part.split("=", 1))
        cls = cls.upper()
        if tier and cls in _ORDER:
            out[tier.lower()] = cls
        elif tier:
            logger.error("AI_TIER_MAX_DATA_CLASS: unknown data class %r for tier %r ignored", cls, tier)
    return out


def tier_limits() -> Dict[str, str]:
    limits = dict(_DEFAULT_TIER_LIMITS)
    limits.update(_parse_limits(os.getenv("AI_TIER_MAX_DATA_CLASS", "")))
    return limits


def tier_max_class(label: str) -> str:
    base = (label or "").split(":", 1)[0].lower()
    default = os.getenv("AI_DEFAULT_MAX_DATA_CLASS", CLIENT_CODE).upper()
    if default not in _ORDER:
        default = CLIENT_CODE
    return tier_limits().get(base, default)


def tier_allowed(label: str, data_class: str) -> bool:
    return _ORDER[data_class] <= _ORDER[tier_max_class(label)]


def filter_tiers(tiers: List[Tuple], prompt_text: str) -> Tuple[List[Tuple], List[str], str]:
    """tiers: [(label, fn, deadline), ...]. Returns (allowed tiers, excluded labels, prompt data class)."""
    data_class = classify_prompt(prompt_text)
    allowed = [t for t in tiers if tier_allowed(t[0], data_class)]
    excluded = [t[0] for t in tiers if not tier_allowed(t[0], data_class)]
    return allowed, excluded, data_class


_last_logged: Dict[str, float] = {}


def should_log_exclusion(label: str, every_s: int = 3600) -> bool:
    """Throttle: one bookkeeping row per tier per hour, otherwise every correlation would write one."""
    now = time.time()
    if now - _last_logged.get(label, 0) >= every_s:
        _last_logged[label] = now
        return True
    return False


def record_ai_data_incident(summary: str, *, provider: str, data_class: str, detail: dict = None) -> None:
    """Procedure for "something was sent that should not have been" (methodology 0A-5). Never raises (ledger writer already guarantees it)."""
    from core import agent_ledger
    d = dict(detail or {})
    d.update({"provider": provider, "data_class": data_class})
    agent_ledger.record_action(agent_ledger.ACTION_AI_DATA_INCIDENT, summary, outcome="failed", detail=d, actor="analyst")
