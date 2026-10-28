"""
Removes secret VALUES from any text before it leaves the platform for an external LLM provider.

Why: the prompts embed real source excerpts (the enclosing function of a flagged line, call sites, descriptions). Measured 2026-10-12 on the
open CONFIG-SECRET-LITERAL / HARDCODED-SECRET findings: the excerpt of an `application-*.properties` finding contained the literal
`spring.datasource.password=...` and `keycloak.credentials.secret=...` lines, and all of it was sent to Groq / Gemini / Mistral / OpenRouter /
NVIDIA. the internal methodology (rule 0A-5, "qué no se carga a la IA") forbids exactly that. The scanners already take care never to write the value
into a finding; this closes the same hole on the way out.

Conservative on purpose: it redacts the VALUE after a secret-looking KEY and a few unmistakable token shapes, and leaves everything else alone so the
analysis (and any `git apply` context) stays useful. A patch whose context lines contained a redacted value will not apply, and is then discarded by
core.patch_validator -- the safe outcome (manual remediation), never a patch built on a secret.
"""
import re
from typing import Tuple

REDACTED = "<REDACTED>"

_KEY = r"(?:pass(?:word|wd)?|pwd|secret|token|api[_-]?key|apikey|private[_-]?key|access[_-]?key|auth(?:orization)?(?![a-z])|credential[s]?|client[_-]?secret|bearer|salt|signing[_-]?key|jwt[_-]?secret)"
# key = value  |  key: value  |  "key": "value"  |  KEY="value"   (key may be a dotted/underscored/camelCase name that CONTAINS the word)
_KV_RE = re.compile(
    r"(?P<k>[\w.\-\[\]]*" + _KEY + r"[\w.\-\]]*[\"']?\s*[:=]\s*)(?P<q>[\"']?)(?P<v>\$\{[^}]*\}|\{\{[^}]*\}\}|<[^>\s]*>|[^\s\"',;)}\]]{4,})(?P=q)", re.IGNORECASE)
# values that are clearly not secrets (references, placeholders, empty-ish)
_SAFE_VALUE_RE = re.compile(r"^(?:\$\{[^}]*\}|\{\{[^}]*\}\}|<[^>]*>|%[sd]|\*{3,}|x{4,}|changeme|true|false|null|none|undefined|string|String|\w+\(.*|process\.env\S*|os\.getenv\S*|System\.getenv\S*)$", re.IGNORECASE)

_TOKEN_SHAPES = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.DOTALL),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgl(?:pat|ptt|rt)-[A-Za-z0-9_\-]{16,}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    re.compile(r"\bxox[abprs]-[A-Za-z0-9\-]{10,}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_\-]{30,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"),     # JWT
    re.compile(r"\$2[aby]\$\d{2}\$[./A-Za-z0-9]{50,}"),                                        # bcrypt hash
]
_URL_CRED_RE = re.compile(r"(?P<p>[a-z][a-z0-9+.\-]*://[^\s/:@]+:)(?P<v>[^\s/@]+)(?=@)", re.IGNORECASE)


# a key that merely MENTIONS a secret word but names a policy / reference / setting, not the secret itself
_NON_SECRET_KEY_SUFFIX_RE = re.compile(
    r"(policy|length|min|max|duration|expir\w*|ttl|url|uri|type|field|label|name|required|enabled|encoder|strength|pattern|regex|hint|placeholder|header|param|prefix|"
    r"endpoint|path|file|location|ref|key_?id|kid|algorithm|alg|provider)$", re.IGNORECASE)


def redact_secrets(text: str) -> Tuple[str, int]:
    """Returns (text_without_secret_values, number_of_redactions)."""
    if not text:
        return text, 0
    count = 0

    def kv(m: "re.Match") -> str:
        nonlocal count
        v = m.group("v")
        key = re.sub(r"[\"'\s:=]+$", "", m.group("k"))
        if _SAFE_VALUE_RE.match(v) or _NON_SECRET_KEY_SUFFIX_RE.search(key):
            return m.group(0)
        count += 1
        return f"{m.group('k')}{m.group('q')}{REDACTED}{m.group('q')}"

    text = _KV_RE.sub(kv, text)

    for rx in _TOKEN_SHAPES:
        text, n = rx.subn(REDACTED, text)
        count += n

    def url(m: "re.Match") -> str:
        nonlocal count
        count += 1
        return f"{m.group('p')}{REDACTED}"

    text = _URL_CRED_RE.sub(url, text)
    return text, count
