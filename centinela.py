from core import org_config
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
try:
    from langchain_core.prompts import ChatPromptTemplate
except Exception:
    ChatPromptTemplate = None

# Providers (optional imports to avoid crash if packages missing in local env)
try:
    from langchain_openai import ChatOpenAI # For Groq / OpenAI-compatible endpoints
except Exception:
    ChatOpenAI = None

try:
    from langchain_community.chat_models import ChatOllama
except Exception:
    ChatOllama = None

try:
    from google import genai
except Exception:
    genai = None

logger = logging.getLogger("centinela")

import hvac
import urllib.request
import urllib.error
import ssl


def get_vault_secrets():
    """Fetch secrets from Vault if configured"""
    vault_addr = os.getenv("VAULT_ADDR")
    vault_token = os.getenv("VAULT_TOKEN")
    
    if not vault_addr or not vault_token:
        print("ℹ️ [Centinela-AI] Vault not configured, using environment variables.")
        return {}
        
    try:
        client = hvac.Client(url=vault_addr, token=vault_token)
        # Try KV v2 path first
        read_response = client.secrets.kv.v2.read_secret_version(path=org_config.vault_path("security"))
        secrets = read_response['data']['data']
        print("🔒 [Centinela-AI] Secrets fetched from Vault successfully.")
        return secrets
    except hvac.exceptions.InvalidPath:
        print("ℹ️ [Centinela-AI] No optional secret at Vault path " + org_config.vault_path("security") + "; using environment variables.")
        return {}
    except Exception as e:
        print(f"⚠️ [Centinela-AI] Could not fetch secrets from Vault: {e}", flush=True)
        return {}

# Load Secrets
VAULT_SECRETS = get_vault_secrets()

def get_secret(key, default=None):
    # Check env first for easier debugging
    env_val = os.getenv(key)
    if env_val:
        return env_val
    return VAULT_SECRETS.get(key, default)

# Initialize AI providers. Each of Groq / NVIDIA NIM / Google Gemini is initialized
# independently (not "first configured one wins") so correlate_vulnerability() can cascade
# through all three at call time, in that order, before falling back to the deterministic
# heuristic engine. Previously only ONE provider was ever initialized for the process's whole
# lifetime (whichever came first in AI_PROVIDER_ORDER with a valid key) -- e.g. once Groq's
# small daily token quota was exhausted mid-day, every single subsequent finding fell straight
# to the heuristic engine for the rest of the day, even though NVIDIA/Gemini keys were also
# configured and never got a chance to try.
#
# Cascade order is Groq -> Gemini -> NVIDIA -> OpenRouter (NOT alphabetical/vendor order),
# chosen and verified live 2026-08-07 against the real correlation prompt: Groq answers in ~3s,
# Gemini (with response_mime_type="application/json" -- a real JSON mode, unlike the other
# three, which rely on prose/fence + regex extraction) in a few seconds too, but NVIDIA's
# currently-configured model took 65s for a real successful reply during testing, and a
# same-class "upgrade" model on the same NVIDIA endpoint never responded at all within 150s.
# OpenRouter's free-tier models are the least predictable of all four -- verified live: one
# candidate free model got instantly 429 rate-limited by OpenRouter's own shared upstream pool
# (unrelated to this account's own quota), and both tested candidates needed 18-60s once
# actually able to answer. NVIDIA and OpenRouter are kept last (in that order, OpenRouter last
# of all) so a request_timeout on either (below) can only ever delay the *last* resorts before
# the heuristic fallback, not stall every single correlation ahead of the two fast, reliable
# tiers.
model_name = get_secret("AI_MODEL", "openai/gpt-oss-20b")
google_model_name = get_secret("AI_MODEL_GOOGLE", "gemini-1.5-flash-latest")
# 2026-10-01: the previous default was the literal text "***REMOVED-SECRET***" (a redaction artifact written
# into the source), so this tier could never answer. Verified live against NVIDIA's /models catalog and a
# real prompt: openai/gpt-oss-20b answers valid JSON in ~12s; deepseek-v4.1-flash and
# nemotron-3.5-lightning timed out at 70s, nemotron-nano-3 is not available to this account.
nvidia_model_name = get_secret("AI_MODEL_NVIDIA", "openai/gpt-oss-20b")
openrouter_model_name = get_secret("AI_MODEL_OPENROUTER", "nvidia/nemotron-3-super-120b-a12b:free")

groq_llm = None
nvidia_llm = None
gemini_client = None
openrouter_llm = None
# 2026-10-01: free-tier quotas are counted PER MODEL on Groq and Gemini, so a second model on the
# same key is a second, independent daily bucket at zero cost. Verified live with the real key:
# Groq `qwen/qwen3.8-27b` answered the real correlation-style prompt with correct JSON in 348
# tokens vs 846 for gpt-oss-20b (which burns tokens on hidden reasoning), and its rate-limit headers
# are separate (1000 req/day, 8000 tok/min each). Gemini `gemini-2.5-flash-lite` answered JSON too.
groq_model_name_2 = get_secret("AI_MODEL_GROQ_2", "qwen/qwen3.8-27b")
google_model_name_2 = get_secret("AI_MODEL_GOOGLE_2", "gemini-2.5-flash-lite")
groq_llm_2 = None
# Extra OpenAI-compatible free-tier providers. Each activates ONLY if its key is in .env; none of
# them was verified live (no keys available when written) -- see _EXTRA_PROVIDERS docs below.
extra_llms = {}

if ChatOpenAI is not None:
    groq_key = get_secret("GROQ_API_KEY")
    if groq_key:
        try:
            groq_llm = ChatOpenAI(
                openai_api_base="https://api.groq.com/openai/v1",
                openai_api_key=groq_key,
                model_name=model_name,
                request_timeout=30,
                max_retries=1,
            )
            print(f"✅ [Centinela-AI] Groq provider initialized (model={model_name}).")
            if groq_model_name_2 and groq_model_name_2 != model_name:
                groq_llm_2 = ChatOpenAI(
                    openai_api_base="https://api.groq.com/openai/v1",
                    openai_api_key=groq_key,
                    model_name=groq_model_name_2,
                    request_timeout=30,
                    max_retries=1,
                )
                print(f"✅ [Centinela-AI] Groq 2nd-model tier initialized (model={groq_model_name_2}, separate daily quota).")
        except Exception as e:
            print(f"⚠️ [Centinela-AI] Groq init failed: {e}")

    nvidia_key = get_secret("NVIDIA_NIM_API_KEY")
    if nvidia_key:
        try:
            nvidia_llm = ChatOpenAI(
                openai_api_base=get_secret("NVIDIA_NIM_BASE_URL", "https://integrate.api.nvidia.com/v1"),
                openai_api_key=nvidia_key,
                model_name=nvidia_model_name,
                # NVIDIA NIM has been observed taking ~65s for a legitimate successful reply
                # (verified live 2026-08-07), so this must stay well above Groq/Gemini's timeout
                # rather than match it -- the point is to bound the *hang* case (150s+, no
                # response), not to penalize this tier's normal latency. max_retries=0 (not the
                # langchain default of 2) because a request_timeout retry multiplies the worst
                # case linearly (verified live: max_retries=1 -> a 90s timeout became a 180.9s
                # real-world failure, not 90s) -- NVIDIA's observed failure mode here is a
                # genuine multi-minute non-response, not a transient blip a retry would fix, so
                # retrying just doubles time wasted before falling through to the next tier.
                request_timeout=90,
                max_retries=0,
            )
            print(f"✅ [Centinela-AI] NVIDIA NIM provider initialized (model={nvidia_model_name}).")
        except Exception as e:
            print(f"⚠️ [Centinela-AI] NVIDIA NIM init failed: {e}")

    openrouter_key = get_secret("OPENROUTER_API_KEY")
    if openrouter_key:
        try:
            openrouter_llm = ChatOpenAI(
                openai_api_base=get_secret("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1"),
                openai_api_key=openrouter_key,
                model_name=openrouter_model_name,
                # Same reasoning as NVIDIA's timeout/retry choice above: OpenRouter's free-tier
                # models are the slowest/least predictable tier in this cascade (verified live,
                # 18-60s for a real reply, plus a real 429 from OpenRouter's own shared upstream
                # pool for a different free model), so max_retries=0 avoids doubling the worst
                # case before falling through to the heuristic engine.
                request_timeout=90,
                max_retries=0,
            )
            print(f"✅ [Centinela-AI] OpenRouter provider initialized (model={openrouter_model_name}).")
        except Exception as e:
            print(f"⚠️ [Centinela-AI] OpenRouter init failed: {e}")

# (name, key env var, base url, default model env var/default). Free tiers (checked 2026-10-01 against
# public comparison pages, NOT against live accounts): Mistral "Experiment" ~1B tokens/month (needs a
# phone-verified key; that plan lets Mistral train on prompts), Cerebras ~1M tokens/day (the account
# used earlier returned payment_required), Cloudflare Workers AI ~10k neurons/day with small context
# windows, SambaNova ~20 req/min & 200k tokens/day per model while no card is linked. Cloudflare needs
# both CLOUDFLARE_API_TOKEN and CLOUDFLARE_ACCOUNT_ID.
# Order = cascade order. VERIFIED LIVE 2026-10-01: Cloudflare Workers AI (token + account id from the user; llama-3.3-70b-fp8-fast,
# llama-3.1-8b and gpt-oss-20b all returned valid JSON; the 70B used 244 tokens). Mistral: key valid (lists models) but every chat call
# returns 429 while the org is on the "Gratis" plan (console asks to upgrade to enable the API) -> kept, it fails fast and starts
# working by itself once the plan is enabled. Cerebras/SambaNova: no key yet, untested.
_EXTRA_PROVIDERS = [
    ("cloudflare", "CLOUDFLARE_API_TOKEN", None, "AI_MODEL_CLOUDFLARE", "@cf/meta/llama-3.3-70b-instruct-fp8-fast"),
    ("mistral", "MISTRAL_API_KEY", "https://api.mistral.ai/v1", "AI_MODEL_MISTRAL", "mistral-small-latest"),
    ("cerebras", "CEREBRAS_API_KEY", "https://api.cerebras.ai/v1", "AI_MODEL_CEREBRAS", "gpt-oss-120b"),
    ("sambanova", "SAMBANOVA_API_KEY", "https://api.sambanova.ai/v1", "AI_MODEL_SAMBANOVA", "Meta-Llama-3.3-70B-Instruct"),
]
if ChatOpenAI is not None:
    for _name, _key_env, _base, _model_env, _model_default in _EXTRA_PROVIDERS:
        _key = get_secret(_key_env)
        if not _key:
            continue
        if _name == "cloudflare":
            _acct = get_secret("CLOUDFLARE_ACCOUNT_ID")
            if not _acct:
                print("⚠️ [Centinela-AI] CLOUDFLARE_API_TOKEN set but CLOUDFLARE_ACCOUNT_ID missing -- skipping Cloudflare tier.")
                continue
            _base = f"https://api.cloudflare.com/client/v4/accounts/{_acct}/ai/v1"
        try:
            extra_llms[_name] = ChatOpenAI(
                openai_api_base=get_secret(f"{_name.upper()}_BASE_URL", _base), openai_api_key=_key,
                model_name=get_secret(_model_env, _model_default), request_timeout=60, max_retries=0,
            )
            print(f"✅ [Centinela-AI] {_name} provider initialized (model={get_secret(_model_env, _model_default)}).")
        except Exception as e:
            print(f"⚠️ [Centinela-AI] {_name} init failed: {e}")

if genai is not None:
    google_key = get_secret("GOOGLE_API_KEY")
    if google_key:
        try:
            from google.genai import types
            gemini_client = genai.Client(api_key=google_key, http_options=types.HttpOptions(timeout=30000))
            print(f"✅ [Centinela-AI] Google Gemini provider initialized (model={google_model_name}).")
        except Exception as e:
            print(f"⚠️ [Centinela-AI] Google Gemini init failed: {e}")

if not (groq_llm or nvidia_llm or gemini_client or openrouter_llm or extra_llms):
    print("⚠️ [Centinela-AI] No AI provider initialized (Groq/Gemini/NVIDIA/OpenRouter all unavailable or missing keys). Correlation will use the heuristic engine only.")


# Shared pool for imposing a true wall-clock deadline on each provider call, on top of
# whatever timeout each client is already configured with. max_workers is generous (I/O-bound
# calls, not CPU-bound) since several independent background loops (correlation, CIS, CTI,
# heuristics) can each call call_ai_cascade() around the same time.
_cascade_executor = concurrent.futures.ThreadPoolExecutor(max_workers=16, thread_name_prefix="ai-cascade")

def _call_with_hard_deadline(fn, timeout_s, provider_name):
    """
    Runs fn() with a true wall-clock deadline via a worker thread, independent of whatever
    idle/read-timeout semantics the underlying HTTP client uses internally.

    Real incident, 2026-08-13: a live OpenRouter call hung for 30+ minutes despite
    request_timeout=90 configured on the ChatOpenAI client. Confirmed live, isolated from any
    external factor, that the client's own timeout DOES fire correctly against a true
    "TCP-connected, server never responds" hang (tested against a real hang-simulating local
    TCP listener -- fired at exactly the configured 15s). That rules out a client
    misconfiguration. The much more likely real cause: OpenRouter's free-tier gateway trickling
    periodic keep-alive/SSE-heartbeat bytes while a backed-up shared model churns, which resets
    httpx's *idle* read-timeout clock on every byte without the response ever completing -- a
    known real failure mode for streaming-capable HTTP APIs, not something any per-request
    `timeout=` kwarg protects against on its own.

    future.result(timeout=...) from a separate worker thread doesn't care whether bytes are
    trickling in or not -- it fires at the wall-clock deadline regardless. The worker thread
    itself is abandoned (not killed -- Python cannot force-kill a thread) if it doesn't finish
    in time; that leaks one thread's resources until the underlying network call eventually
    errors or closes on its own, which is a real but bounded cost, in exchange for never again
    blocking the whole correlation loop for 30+ minutes on a single stuck call.
    """
    future = _cascade_executor.submit(fn)
    try:
        return future.result(timeout=timeout_s)
    except concurrent.futures.TimeoutError:
        raise TimeoutError(f"{provider_name} exceeded hard {timeout_s}s wall-clock deadline (client-level timeout did not fire -- likely a keep-alive/heartbeat trickle)")


# Per-tier cooldown (2026-10-01). When every free tier is out of quota at once (it happens daily), each finding used to
# retry all 8 tiers -- including NVIDIA/OpenRouter's up-to-100s waits -- before falling to the heuristic engine. A tier that
# just answered "quota exhausted"/timed out is now skipped for a while; the cooldown length depends on what kind of failure it was.
MAX_PROMPT_CHARS = int(os.getenv("AI_MAX_PROMPT_CHARS", "24000"))  # ~6k tokens: fits Groq's 8k tokens/min free limit
_tier_cooldown = {}  # label -> epoch seconds until which the tier is skipped
_cascade_state = {"all_unavailable": False, "last_label": None}


def _cooldown_seconds(err_text):
    t = str(err_text).lower()
    # A request that is too big for the model is a problem with THIS prompt, not with the provider: pausing the tier for it
    # (it used to match the generic "invalid" below and pause Groq 30 min) would starve every later, normal-sized request.
    if any(x in t for x in ("reduce the length", "context length", "context window", "maximum context", "max_tokens must be",
                            "input is too long", "prompt is too long")):
        return 0
    if any(x in t for x in ("per day", "tpd", "rpd", "daily", "allocation", "neurons", "free-models-per-day")):
        return 3600       # daily quota gone: no point retrying for an hour
    if any(x in t for x in ("per minute", "tpm", "rpm", "request too large", "too many requests")):
        return 60         # per-minute window
    if any(x in t for x in ("429", "rate limit", "resource_exhausted", "quota")):
        return 900        # quota of unknown window
    if any(x in t for x in ("timed out", "timeout", "exceeded hard", "503", "unavailable", "overloaded")):
        return 180        # slow/overloaded, usually transient
    if any(x in t for x in ("401", "403", "404", "invalid api key", "invalid_api_key", "incorrect api key", "api key not valid",
                            "api_key_invalid", "not found", "unauthorized", "payment")):
        return 1800       # misconfiguration / blocked account
    return 120


_usage_prune_counter = {"n": 0}


def _record_ai_usage(label, ok, usage, started_at, error_text=None, error_kind=None, cooldown_secs=None):
    """Writes one ai_provider_usage row for the "Tokens IA" screen. Never raises (Rule #6: failures are logged with a
    traceback, but the AI cascade must not break because bookkeeping did)."""
    try:
        t = (error_text or "").lower()
        if error_kind is None and not ok:
            error_kind = ("quota_day" if cooldown_secs == 3600 else "quota_minute" if cooldown_secs == 60
                          else "quota" if cooldown_secs == 900 else "timeout" if cooldown_secs == 180
                          else "auth" if cooldown_secs == 1800 else "error")
        model = label.split(":", 1)[1] if ":" in label else {
            "groq": model_name, "google_genai": google_model_name, "nvidia_nim": nvidia_model_name,
            "openrouter": openrouter_model_name}.get(label)
        with db_manager.get_db_cursor() as cur:
            cur.execute(
                """INSERT INTO public.ai_provider_usage
                   (tier, model, ok, prompt_tokens, completion_tokens, latency_ms, error_kind, error_text, cooldown_until)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s, CASE WHEN %s::int IS NULL THEN NULL ELSE NOW() + (%s::int * INTERVAL '1 second') END)""",
                (label, model, ok, usage.get("prompt"), usage.get("completion"), int((time.time() - started_at) * 1000),
                 error_kind, (error_text or "")[:500] or None, cooldown_secs, cooldown_secs))
            _usage_prune_counter["n"] += 1
            if _usage_prune_counter["n"] % 200 == 0:
                cur.execute("DELETE FROM public.ai_provider_usage WHERE ts < NOW() - INTERVAL '30 days'")
    except Exception:
        import traceback
        traceback.print_exc()
        print(f"⚠️ [Centinela-AI] could not record AI usage for tier {label}")


def cascade_all_unavailable():
    """True if the LAST call_ai_cascade() found no tier able to answer because they are all in cooldown or failed
    with quota/availability errors (as opposed to a provider answering with unusable content)."""
    return _cascade_state["all_unavailable"]


def _tiers_avoiding(tiers, avoid_labels):
    """Same tiers, the `avoid_labels` ones moved to the end (kept, not removed): a second opinion prefers another model."""
    if not avoid_labels:
        return tiers
    avoid = set(avoid_labels)
    return [t for t in tiers if t[0] not in avoid] + [t for t in tiers if t[0] in avoid]


def call_ai_cascade(prompt_text, want_json=True, avoid_labels=None):
    """
    Tries each configured LLM tier in order and returns the text of the first one that actually
    responds; None if every tier is unavailable/unconfigured or errors out (invalid key, rate limit,
    timeout...), in which case the caller falls back to the deterministic heuristic engine.

    Order (cheap + fast + reliable first, slow/unpredictable last):
      Groq qwen (2nd model) -> Groq gpt-oss -> Gemini -> Gemini 2nd model -> extra free providers
      (Mistral, Cerebras, SambaNova, Cloudflare; only those with a key) -> NVIDIA NIM -> OpenRouter.
    Groq/Gemini quotas are per model, so each pair is two independent daily buckets.

    Every call runs through _call_with_hard_deadline() with a ceiling above that tier's own client
    timeout -- the second safety net added after the real 2026-08-13 keep-alive-trickle hang.

    `avoid_labels`: tiers to try LAST (not removed). The adversarial verifier (core/ai_verification.py) passes the
    tier that wrote the first analysis, so the second opinion comes from a different model whenever one is available.
    The tier that answered is left in _cascade_state["last_label"].
    """
    # Never send secret VALUES to an external provider (core/prompt_redaction.py; data-handling policy).
    from core.prompt_redaction import redact_secrets
    prompt_text, _n_redacted = redact_secrets(prompt_text)
    if _n_redacted:
        print(f"🔒 [Centinela-AI] {_n_redacted} secret value(s) redacted from the prompt before sending it to an external provider.")
    if len(prompt_text) > MAX_PROMPT_CHARS:
        # Keep the instructions at both ends, drop the middle (usually a runaway code snippet, e.g. a minified bundle).
        head, tail = int(MAX_PROMPT_CHARS * 0.6), int(MAX_PROMPT_CHARS * 0.4)
        print(f"✂️ [Centinela-AI] prompt of {len(prompt_text)} chars truncated to ~{MAX_PROMPT_CHARS} (provider context limits).")
        prompt_text = prompt_text[:head] + "\n[... contenido intermedio omitido por tamaño ...]\n" + prompt_text[-tail:]

    def _openai_like(llm):
        def run(usage):
            response = llm.invoke(prompt_text)
            meta = getattr(response, "usage_metadata", None) or {}
            usage["prompt"], usage["completion"] = meta.get("input_tokens"), meta.get("output_tokens")
            return (response.content if hasattr(response, "content") else str(response)).strip()
        return run

    def _gemini(model):
        def run(usage):
            from google.genai import types
            config = types.GenerateContentConfig(response_mime_type="application/json") if want_json else None
            resp = gemini_client.models.generate_content(model=model, contents=prompt_text, config=config)
            meta = getattr(resp, "usage_metadata", None)
            usage["prompt"] = getattr(meta, "prompt_token_count", None)
            usage["completion"] = getattr(meta, "candidates_token_count", None)
            return resp.text.strip()
        return run

    tiers = []  # (label, callable, hard deadline seconds)
    if groq_llm_2:
        tiers.append((f"groq:{groq_model_name_2}", _openai_like(groq_llm_2), 70))
    if groq_llm:
        tiers.append(("groq", _openai_like(groq_llm), 70))
    if gemini_client:
        tiers.append(("google_genai", _gemini(google_model_name), 40))
        if google_model_name_2 and google_model_name_2 != google_model_name:
            tiers.append((f"google_genai:{google_model_name_2}", _gemini(google_model_name_2), 40))
    for name, llm in extra_llms.items():
        tiers.append((name, _openai_like(llm), 70))
    if nvidia_llm:
        tiers.append(("nvidia_nim", _openai_like(nvidia_llm), 100))
    if openrouter_llm:
        tiers.append(("openrouter", _openai_like(openrouter_llm), 100))

    # ADR-0012 D1: which data class may go to which provider. Excluded tiers are REMOVED (not counted as "unavailable"): a policy exclusion is
    # permanent, so it must never make a finding wait for a quota reset that cannot help; with no allowed tier the caller falls back to the
    # deterministic engine.
    from core import ai_data_policy
    tiers, _excluded, _data_class = ai_data_policy.filter_tiers(tiers, prompt_text)
    tiers = _tiers_avoiding(tiers, avoid_labels)
    _cascade_state["last_label"] = None
    for _label in _excluded:
        if ai_data_policy.should_log_exclusion(_label):
            print(f"🛡️ [Centinela-AI] tier '{_label}' not used: prompt is {_data_class}, above that provider's allowed data class (AI_TIER_MAX_DATA_CLASS).")
            _record_ai_usage(_label, False, {}, time.time(), error_text=f"prompt {_data_class} excede la clase de dato permitida", error_kind="data_policy")

    attempted = 0
    unavailable = 0
    now = time.time()
    for label, fn, deadline in tiers:
        if _tier_cooldown.get(label, 0) > now:
            unavailable += 1
            continue
        attempted += 1
        usage = {}
        t0 = time.time()
        try:
            content = _call_with_hard_deadline(lambda fn=fn, usage=usage: fn(usage), deadline, label)
            if content:
                _cascade_state["all_unavailable"] = False
                _cascade_state["last_label"] = label
                print(f"🧠 [Centinela-AI] Using LLM provider '{label}'...")
                _record_ai_usage(label, True, usage, t0)
                return content
            _record_ai_usage(label, False, usage, t0, error_text="respuesta vacía", error_kind="empty")
        except Exception as e:
            secs = _cooldown_seconds(e)
            if secs:
                _tier_cooldown[label] = time.time() + secs
                unavailable += 1
                print(f"⚠️ [Centinela-AI] {label} call failed (skipping it for {secs}s): {str(e)[:260]}")
                _record_ai_usage(label, False, usage, t0, error_text=str(e), cooldown_secs=secs)
            else:
                print(f"⚠️ [Centinela-AI] {label} rejected this prompt as too large (tier NOT paused): {str(e)[:200]}")
                _record_ai_usage(label, False, usage, t0, error_text=str(e), error_kind="prompt_too_large")

    # "all unavailable" only when there were tiers and every one of them is cooling down / just failed
    _cascade_state["all_unavailable"] = bool(tiers) and unavailable == len(tiers)
    return None


from core import ai_verification  # noqa: E402  (ADR-0021)
from core.ip_block_script import generate_ip_block_virtual_patch, generate_ip_unblock_script  # noqa: E402  (shared with core/soar_engine.py)
# ADR-0008 #3: code moved out of this file (re-exported here so existing imports/tests keep working)
from remediation.heuristics import (
    ZAP_HEADER_FIXES,
    _GITLAB_HYGIENE_GUIDANCE,
    _authz_fix_guidance,
    _gitlab_hygiene_guidance,
    _infra_hygiene_guidance,
    generate_heuristic_analysis,
    generate_heuristic_script,
    generate_wstg_remediation,
    generate_zap_header_fix,
    heuristic_can_automate,
    match_zap_header_entry,
)
from workers.streams import (
    VALKEY_CONFIG,
    _FALCO_PRIORITY_MAP,
    _RUNTIME_ALERT_NOISE_RULES,
    get_valkey_connection,
    normalize_alert_priority,
    process_bloodhound_paths,
    process_falco_alerts,
    process_zeek_alerts,
    process_zeek_conn_log,
)
from workers.periodic import (
    _criticality_weight,
    _due_assets_for_marker,
    _fill_incident_ai_summaries,
    run_cis_benchmark_loop,
    run_cmmi_org_evidence_loop,
    run_cti_correlation_loop,
    run_fleet_enqueue_loop,
    run_gitlab_heads_refresh_loop,
    run_heuristics_loop,
    run_incident_correlation_loop,
    run_os_patch_and_tls_audit_loop,
    run_scan_worker_loop,
    run_secrets_history_worker_loop,
    run_secrets_token_renew_loop,
    run_zap_reaper_loop,
    run_reverify_loop,
    run_soar_expiry_loop,
    run_threat_intel_enrichment_loop,
    run_wazuh_discovery_loop,
)


def _infra_exposure_context(vuln):
    """Verifiable facts about an infrastructure asset that the AI needs to judge REAL risk (is it only reachable on a private
    network?). Only states what can be derived from the inventory row; anything else is declared as unknown, never guessed."""
    import ipaddress
    from urllib.parse import urlparse
    ep = str(vuln.get('endpoint') or '')
    host = (urlparse(ep).hostname if '://' in ep else ep.split('/')[0].split(':')[0]) or ''
    try:
        ip = ipaddress.ip_address(host)
        net = ("IP PRIVADA (RFC1918): solo alcanzable desde la red interna/VPN, salvo que otro componente la publique"
               if ip.is_private else "IP PÚBLICA: potencialmente alcanzable desde Internet")
    except ValueError:
        net = "nombre de host (no se pudo determinar si es red interna o pública)"
    return (f"- Dirección: {host or 'desconocida'} -> {net}\n"
            f"        - Criticidad del activo: {vuln.get('criticality') or 'desconocida'}\n"
            f"        - Motor que lo detectó: {vuln.get('scan_engine') or 'desconocido'}\n"
            f"        - Agente EDR (Wazuh): {'sí' if vuln.get('agent_id') else 'no / desconocido'}\n"
            f"        - Exposición real a Internet, firewall/WAF delante, segmentación: NO VERIFICADOS por Centinela")


def correlate_vulnerability(vuln):
    """
    Use AI to correlate vulnerability data and suggest remediation.
    """
    print(f"🤖 [Centinela-AI] Senior Audit analysis for {vuln['cve_id']} on {vuln['asset_name']}...")

    is_repo_finding = str(vuln.get('asset_type', '')).upper() == 'GITLAB-REPO'

    # Item 5 (2026-08-27): blast-radius / enclosing-scope context. For a GitLab-Repo finding we
    # used to hand the LLM only the one flagged line + the scanner's short description and then
    # ask for a `git apply`-ready diff. gather_repo_context() reads the enclosing function from
    # the clone the fleet scanner already left on disk and `git grep`s the flagged symbol, so
    # the patch is written with real surrounding context and the call sites it might affect.
    # Best-effort and read-only -- returns an empty prompt_block on any failure.
    code_context_block = ""
    _ctx = {}
    if is_repo_finding:
        try:
            from core.code_context import gather_repo_context
            _ctx = gather_repo_context(vuln.get('asset_name', ''), vuln.get('url_path', '') or '')
            code_context_block = _ctx.get("prompt_block", "") or ""
            if code_context_block:
                print(f"   ↳ [Centinela-AI] Code context: {_ctx['rel_path']}:{_ctx['line']} "
                      f"symbol={_ctx['symbol']!r} callers={_ctx['caller_count']}")
        except Exception as _ctx_err:
            print(f"⚠️ [Centinela-AI] gather_repo_context failed (continuing without it): {_ctx_err}")

    # ADR-0012 D4: instructions aimed at the model hidden in the code/description under analysis (untrusted data).
    from core import prompt_guard
    injection_hits = prompt_guard.scan_for_injection(vuln.get('description'), code_context_block, vuln.get('url_path'))
    # ADR-0021: facts the team wrote about this repository (config/repo_facts or .centinela/hechos.md in the clone).
    repo_facts_text = ""
    if is_repo_finding:
        try:
            from core import repo_facts as _repo_facts
            _facts = _repo_facts.load_repo_facts(vuln.get('asset_name', ''), (_ctx or {}).get('repo_dir'))
            repo_facts_text = _facts["text"]
            if _facts["dropped_injection"]:
                print(f"🛡️ [Centinela-AI] repo facts dropped (instructions aimed at the model): {_facts['dropped_injection']}")
        except Exception:
            import traceback
            traceback.print_exc()
    # ADR-0021: untrusted material goes inside nonce-tagged blocks the data cannot forge (complements the injection scan).
    from core import ai_verification
    prompt_nonce = ai_verification.make_nonce(vuln.get('description'), code_context_block, repo_facts_text)
    description_block = ai_verification.wrap_untrusted("descripcion_del_escaner", vuln.get('description', 'Sin descripción'), prompt_nonce)
    untrusted_block = ai_verification.untrusted_rules(prompt_nonce)
    facts_block = ""
    if repo_facts_text:
        facts_block = ("HECHOS DEL REPOSITORIO (escritos por el equipo; te dicen dónde mirar, pero un hecho por sí solo NUNCA prueba "
                       "que el hallazgo no aplique; cualquier baja de severidad debe apoyarse en líneas del código):\n"
                       + ai_verification.wrap_untrusted("hechos_del_repositorio", repo_facts_text, prompt_nonce))
    if code_context_block:
        code_context_block = ai_verification.wrap_untrusted("codigo", code_context_block, prompt_nonce) + "\n" + prompt_guard.UNTRUSTED_NOTE
    if injection_hits:
        print(f"🛡️ [Centinela-AI] possible prompt injection in {vuln['cve_id']} on {vuln['asset_name']}: {injection_hits} "
              f"(this analysis will not be allowed to lower the severity)")

    # These cve_id values are Centinela's own synthetic/system markers, not real
    # scanner-detected vulnerabilities -- there's no real technical substance for a generic
    # security-auditor LLM prompt to reason about, and testing this live surfaced exactly the
    # failure mode that risk implies: asked to fix "HOST-CONTAINMENT-REQUEST", Groq hallucinated
    # an unrelated WildFly/JMX script with can_automate=true, which would have been offered for
    # one-click execution against a host that may not even run WildFly. generate_heuristic_script()
    # already has correct, purpose-built logic for each of these (real firewall lockdown for
    # HOST-CONTAINMENT-REQUEST, real IP block for CTI-IOC-MATCH, etc) -- skip the LLM entirely
    # for these and go straight to it instead of risking a plausible-sounding wrong answer.
    cve_upper = str(vuln.get('cve_id', '')).upper()
    # 2026-10-01: INFORMATIONAL findings (code smells, ISO 25010/CMMI debt, WCAG...) are not vulnerabilities;
    # 17k of them per large repo were competing with real findings for the free LLM quota. They keep a
    # deterministic (heuristic) analysis + remediation row so every screen that expects one still works.
    is_informational = str(vuln.get('finding_category') or '').upper() == 'INFORMATIONAL'
    is_synthetic_marker = (
        is_informational or
        cve_upper.startswith('CTI-IOC-MATCH') or cve_upper.startswith('BLOODHOUND-PATH')
        or cve_upper in ('HOST-CONTAINMENT-REQUEST', 'SCAN-AUDIT', 'HEURISTIC-SECURITY-DEBT', 'CIS-BENCHMARK-AUDIT', 'SONARQUBE-QUALITY-GATE',
                         'OS-PATCH-AUDIT', 'TLS-AUDIT', 'GITLAB-CONFIG-AUDIT')
        # families with fully deterministic guidance (see _infra_hygiene_guidance / _gitlab_hygiene_guidance)
        or cve_upper.startswith(('OS-PATCH-', 'OS-EOL', 'OS-REBOOT-', 'OS-AUTO-UPDATES-', 'OS-PACKAGE-INDEX-', 'TLS-',
                                 'GITLAB-PROJECT-', 'CICD-'))
    )

    if is_repo_finding:
        # A bash "remediation_script" makes no sense here -- there's no live host to SSH into
        # and run hardening commands against; the file it needs to fix is inside the repo this
        # finding came from. Ask for a real unified diff instead, which Sentinel's GitLab
        # auto-fixer (remediation/gitlab_autofix.py) applies with `git apply` and pushes as a
        # Merge Request -- the same mechanism used for the deterministic Docker/SCA patches.
        prompt_text = f"""
        Actúa como un Ingeniero Senior de AppSec de la organización revisando un hallazgo de análisis
        estático de código (SAST/SCA) en un repositorio real.
        
        IMPORTANTE: Responde ÚNICA Y EXCLUSIVAMENTE EN ESPAÑOL LATINOAMERICANO. Queda estrictamente prohibido usar texto en inglés en las descripciones.

        HALLAZGO A CORREGIR:
        - Regla: {vuln['cve_id']}
        - Repositorio: {vuln['asset_name']}
        - Ubicación (archivo:línea): {vuln.get('url_path', 'desconocida')}
        - Severidad: {vuln['severity']}
        - Detalle:
        {description_block}

        {code_context_block}

        {facts_block}

        {untrusted_block}

        REGLAS:
        1. Explica el hallazgo de forma SUMAMENTE CLARA, DETALLADA Y DIDÁCTICA ("paso a paso, para fácil entendimiento").
        2. El campo 'impacto_negocio' debe describir de forma muy explícita el Riesgo al Negocio (consecuencia operacional o de fuga de datos en lenguaje accesible).
        3. El campo 'accion_remediacion' debe detallar las acciones concretas a realizar.
        4. El campo 'fix_patch' DEBE ser un diff unificado válido (formato `git diff`, aplicable con `git apply`),
           con encabezados `--- a/<ruta>` / `+++ b/<ruta>` usando la ruta relativa EXACTA de 'Ubicación', y sus
           líneas de contexto/eliminadas deben copiarse literalmente del fragmento de código real proporcionado.
        5. INTEGRIDAD: si el fragmento disponible es insuficiente para un parche seguro y correcto, NO inventes
           líneas, rutas ni frameworks: deja 'fix_patch' vacío y pon can_automate en false. Un parche que no
           aplique sobre el código real será descartado automáticamente.

        REGLAS DE REDACCIÓN PARA DOBLE AUDIENCIA (añadido 2026-09-30, por retroalimentación directa
        del usuario tras encontrar texto confuso/contradictorio en un reporte real -- un hallazgo
        marcado CRITICAL cuya propia explicación decía "riesgo real NULO" sin aclarar por qué):
        6. Cada campo de texto ('riesgo_detectado', 'evidencia_tecnica', 'impacto_negocio',
           'accion_remediacion') debe poder ser leído y entendido tanto por un analista SOC/pentester
           como por un gerente, líder de proyecto o dueño del producto SIN conocimientos técnicos.
           Evita nombres de funciones/clases/APIs sin explicar en una frase simple qué hacen (ej. no
           escribas solo "DomSanitizer.bypassSecurityTrustResourceUrl()", explica primero en una
           frase llana qué es: "una instrucción que le dice al navegador 'confía en este contenido
           sin revisarlo'"). Nada de "cantinflear" (dar vueltas sin decir nada concreto): cada
           oración debe aportar un hecho o una consecuencia real, no relleno.
        7. REGLA ANTI-PARADOJA: 'nivel_severidad' en este JSON refleja la severidad GENÉRICA que la
           herramienta de escaneo (SonarQube/etc.) ya asignó al TIPO de patrón, no necesariamente el
           riesgo real de ESTE caso específico (la herramienta no analiza el contexto). Si tu propio
           análisis concluye que el riesgo real es menor que esa etiqueta (incluyendo "nulo" quien es
           un patrón seguro y recomendado) -- DEBES decirlo explícitamente y en una sola frase simple
           al INICIO de 'impacto_negocio', con este formato exacto u equivalente: "Aunque la
           herramienta marca esto como {{nivel_severidad}}, en este caso específico el riesgo real es
           [NULO/BAJO/...] porque [razón concreta en una frase]." Nunca dejes que el lector tenga que
           inferir por su cuenta por qué una etiqueta "crítica" y un veredicto "sin riesgo" conviven
           en el mismo hallazgo -- explícalo tú, siempre, en la primera frase.

        FORMATO DE SALIDA (JSON ESTRICTO EN ESPAÑOL):
        {{
            "riesgo_detectado": "Nombre claro y didáctico de la vulnerabilidad en español",
            "nivel_severidad": "Bajo/Medio/Alto/Crítico",
            "severidad_real": "Nulo/Bajo/Medio/Alto/Crítico -- TU veredicto del riesgo real de ESTE caso concreto tras revisar el contexto (puede ser menor que nivel_severidad; 'Nulo' solo si es un patrón seguro/falso positivo confirmado)",
            "depende_de_supuesto": true/false -- true SOLO si tu veredicto de severidad_real depende de una condición que NO pudiste verificar en el código,
            "referencias_evidencia": ["ruta/relativa/archivo:línea", "..."] -- OBLIGATORIO si severidad_real es menor que nivel_severidad: las líneas EXACTAS del código mostrado que demuestran por qué el riesgo es menor (la validación, la constante, la restricción). Se comprueban contra el repositorio real: una referencia inexistente anula la baja,
            "evidencia_tecnica": "Extracto o detalle del código/recurso afectado en español",
            "impacto_negocio": "Explicación clara y comprensible del riesgo operacional o reputacional para la organización",
            "accion_remediacion": "Instrucciones detalladas y comprensibles para resolución por parte del equipo",
            "fix_patch": "Diff unificado real, o cadena vacía si no es seguro generar uno",
            "can_automate": true/false
        }}
        """
    else:
        prompt_text = f"""
        Actúa como el Auditor Senior de Ciberseguridad de la organización. Tu objetivo es redactar un informe altamente didáctico, claro y profesional.
        
        REGLA DE ORO: Responde TOTALMENTE EN ESPAÑOL LATINOAMERICANO. No incluyas frases ni explicaciones en inglés.

        VULNERABILIDAD A ANALIZAR:
        - ID: {vuln['cve_id']}
        - Activo: {vuln['asset_name']}
        - Tipo: {vuln.get('asset_type', 'unknown')}
        - Ubicación: {vuln.get('endpoint', 'unknown')}
        - Descripción inicial:
        {description_block}
        - Severidad reportada: {vuln['severity']}

        {untrusted_block}

        CONTEXTO DE EXPOSICIÓN (solo hechos verificables del inventario):
        {_infra_exposure_context(vuln)}

        CRITERIO DE RIESGO REAL PARA INFRAESTRUCTURA (aplica a 'severidad_real' y 'depende_de_supuesto'):
        - 'Nulo' SOLO si la propia evidencia muestra que no aplica o que ya existe un control compensatorio
          verificable (p. ej. un hallazgo informativo de detección de tecnología, o una cabecera que no tiene
          efecto en una API sin navegador). No lo uses por "es red interna": eso reduce, no elimina.
        - Si el riesgo real depende de algo que NO está en el contexto de arriba (que el servicio no esté
          publicado en Internet, que haya un WAF/firewall delante, que el servicio no se use), pon
          'depende_de_supuesto': true y NO bajes la severidad: un humano debe verificarlo.
        - Nunca asumas protecciones que no se te dieron; nunca subas la severidad por encima de la reportada.

        REGLAS DE ANÁLISIS Y REDACCIÓN:
        1. ¿QUÉ ENCONTRAMOS?: Describe el problema técnico en español con máxima claridad, explicando qué ocurre sin tecnicismos innecesarios.
        2. RIESGO AL NEGOCIO: Explica detalladamente y en lenguaje claro las consecuencias operativas, de seguridad, financieras o de fuga de información si esta vulnerabilidad llega a ser explotada.
        3. PASOS DE RESOLUCIÓN: Proporciona instrucciones paso a paso estructuradas y comprensibles para que cualquier desarrollador o administrador pueda solucionar el problema.
        4. SCRIPT DE REMEDIACIÓN: Incluye un script bash autónomo, seguro e idéntico para aplicar el hardening o la corrección.
        5. DOBLE AUDIENCIA: cada campo de texto debe poder ser leído y entendido tanto por un analista
           SOC como por un gerente o dueño del proyecto sin conocimientos técnicos -- explica cualquier
           término técnico en una frase simple antes de usarlo, sin "cantinflear" (dar vueltas sin decir
           nada concreto).
        6. REGLA ANTI-PARADOJA: si tu análisis concluye que el riesgo real es distinto (mayor o menor,
           incluyendo "nulo") de lo que 'nivel_severidad' sugiere, dilo explícitamente en la primera
           frase de 'impacto_negocio': "Aunque esto se reporta como {{nivel_severidad}}, el riesgo real
           es [...] porque [razón concreta]." Nunca dejes una etiqueta de severidad y un veredicto de
           riesgo real sin explicar por qué parecen contradecirse.

        FORMATO DE SALIDA (JSON ESTRICTO EN ESPAÑOL):
        {{
            "riesgo_detectado": "Título descriptivo y claro de la vulnerabilidad en español",
            "nivel_severidad": "Bajo/Medio/Alto/Crítico",
            "severidad_real": "Nulo/Bajo/Medio/Alto/Crítico -- TU veredicto del riesgo real de ESTE caso concreto (puede ser menor que nivel_severidad; 'Nulo' solo si es un falso positivo confirmado)",
            "depende_de_supuesto": true/false -- true SOLO si tu veredicto depende de una condición que NO pudiste verificar,
            "referencias_evidencia": ["el dato concreto del contexto de exposición o de la descripción que justifica bajar la severidad"],
            "evidencia_tecnica": "Evidencia técnica, puerto o parámetro afectado en español",
            "impacto_negocio": "Análisis explícito y comprensible del riesgo operacional y de negocio",
            "accion_remediacion": "Pasos detallados de resolución punto por punto en español",
            "remediation_script": "Script bash autónomo ejecutable para mitigar la vulnerabilidad",
            "can_automate": true/false
        }}

        REGLAS DE SCRIPTS:
        - El campo 'remediation_script' DEBE contener un script bash completo, autónomo y ejecutable específico para la vulnerabilidad {vuln['cve_id']}. NO utilices scripts genéricos de 'ufw status'.
        - IDEMPOTENCIA: El script debe poder ejecutarse varias veces sin causar errores.
        - VERIFICACIÓN: El script DEBE incluir comandos para verificar que la corrección funcionó.
    """
    
    content = ""
    try:
        if not is_synthetic_marker:
            content = call_ai_cascade(prompt_text) or ""

        if not content and not is_synthetic_marker and cascade_all_unavailable():
            # Every provider is out of quota right now. If the deterministic engine only has its GENERIC catch-all text for this
            # finding ("sin regla determinística" ...), writing it would freeze that text on the row for good (CORRELATED rows
            # are never re-analysed) -- leave it pending and retry once a tier has quota again. Findings the heuristic engine
            # DOES have a specific rule for (SCA version bumps, header fixes, ...) still go through below.
            _r, _i, _a = generate_heuristic_analysis(vuln)
            if any(m in str(_r) for m in ("sin regla determinística", "Hallazgo de código fuente:", "sin regla de remediación específica")):
                return "RATE_LIMIT"

        if not content:
            # Fallback deterministic Security Engine Generator
            print(f"⚙️ [Centinela-AI] Using Native Heuristics AI Engine for {vuln.get('cve_id')} on {vuln.get('asset_name')}...")
            cve = vuln.get('cve_id', 'SECURITY-FINDING')
            asset = vuln.get('asset_name', 'INFRASTRUCTURE-HOST')
            atype = vuln.get('asset_type', 'SERVER')
            ep = vuln.get('endpoint', '0.0.0.0')
            sev = vuln.get('severity', 'Medium')
            
            script_code = generate_heuristic_script(vuln)
            can_automate = heuristic_can_automate(vuln)
            riesgo, impacto, accion = generate_heuristic_analysis(vuln)

            content = json.dumps({
                "riesgo_detectado": riesgo,
                "nivel_severidad": sev,
                "evidencia_tecnica": f"Hallazgo reportado en {ep} ({atype}). {vuln.get('description', 'Parámetros o puertos no endurecidos.')}",
                "impacto_negocio": impacto,
                "accion_remediacion": accion,
                "remediation_script": script_code,
                "can_automate": can_automate
            })
        
        import re

        # ── Strategy 1: strip ```json ... ``` or ``` ... ``` code fences ──
        fence_match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', content, re.DOTALL)
        if fence_match:
            content = fence_match.group(1)

        # ── Strategy 2: find the outermost { ... } block ──
        json_match = re.search(r'(\{.*\})', content, re.DOTALL)
        if json_match:
            content = json_match.group(1)

        # Helper to pick first non-empty value from multiple candidate keys
        def pick(d, *keys, default=''):
            for k in keys:
                v = d.get(k)
                if v is not None and str(v).strip() not in ('', 'null', 'None', 'N/A'):
                    return str(v).strip()
            return default

        # Some LLM responses pass `pick()`'s non-empty check but are lazy/truncated
        # placeholders instead of real content -- confirmed live on real production data,
        # e.g. remediation_script literally containing "... (script proporcionado)" or
        # "... (contenido del script)". pick() only checks for emptiness/null-like strings,
        # so this garbage was silently accepted as a real script and written to disk,
        # sometimes even with can_automate=true (the SOAR UI would offer to auto-execute
        # a file with no real commands in it). Reject anything that, after stripping a
        # leading shebang, is just an ellipsis (optionally with a placeholder parenthetical)
        # or otherwise too short to plausibly be real content.
        def is_placeholder_text(text):
            if not text:
                return True
            body = re.sub(r'^#!.*(\n|$)', '', text.strip(), count=1).strip()
            if not body:
                return True
            if re.fullmatch(r'\.{3,}(\s*\([^)]*\))?', body):
                return True
            if len(body) < 15:
                return True
            return False

        # Defined up front: the prose-fallback path (a provider that answers in free text, not JSON --
        # seen live 2026-10-01 with Cloudflare) never assigns these, and reading them later raised
        # UnboundLocalError, losing the whole analysis. "" / None = "provider gave no structured verdict".
        severidad_real_ai = ''
        depende_supuesto_ai = None
        evidence_refs_ai = []
        try:
            # strict=False allows raw control characters (e.g. literal newlines) inside JSON
            # string values — LLMs routinely write multi-line bash into "remediation_script"
            # with real line breaks instead of escaped \n, which strict JSON parsing rejects
            # outright even though the rest of the document is well-formed.
            analysis = json.loads(content, strict=False)
            if isinstance(analysis, dict) and "error" in analysis:
                print(f"⚠️ [Centinela-AI] AI response contains error: {analysis['error']}")
                return None

            riesgo   = pick(analysis, 'riesgo_detectado', 'vulnerability_name', 'risk', 'title', 'name')
            evidencia = pick(analysis, 'evidencia_tecnica', 'technical_evidence', 'evidence', 'details')
            nivel    = pick(analysis, 'nivel_severidad', 'severity_level', 'severity')
            impacto  = pick(analysis, 'impacto_negocio', 'business_impact', 'impact',
                            default='Sin análisis de impacto disponible.')
            pasos    = pick(analysis, 'accion_remediacion', 'remediation_steps', 'steps', 'solution',
                            default='Sin pasos de remediación disponibles.')
            script   = pick(analysis, 'remediation_script', 'script', 'bash_script',
                            default='# Sin script de remediación')
            fix_patch = pick(analysis, 'fix_patch', 'patch', 'diff', default='')
            can_automate_raw = analysis.get('can_automate') if isinstance(analysis, dict) else None
            severidad_real_ai = pick(analysis, 'severidad_real', 'real_severity', default='')
            depende_supuesto_ai = analysis.get('depende_de_supuesto') if isinstance(analysis, dict) else None
            evidence_refs_ai = ai_verification.parse_evidence_refs(
                analysis.get('referencias_evidencia') or analysis.get('evidence_refs')) if isinstance(analysis, dict) else []

            if not riesgo and script == '# Sin script de remediación' and not fix_patch:
                print("⚠️ [Centinela-AI] AI response has no valid risk, script, or patch.")
                return None

        except json.JSONDecodeError:
            # ── Strategy 3: parse markdown prose as structured text ──
            # AI returned plain text — extract fields from bold/header patterns
            raw = content  # keep the original full response
            def extract_section(text, *labels):
                """Pull text after a bold label or markdown heading."""
                for label in labels:
                    # NOTE: inside an f-string a bare `#{1,3}` is the Python expression (1, 3), which silently turned the
                    # quantifier into a literal group "(1, 3)" -> group(1) was None -> .strip() crashed. Braces must be doubled.
                    pattern = rf'(?:\*\*{label}\*\*|#{{1,3}}\s*{label})[:\s]+(.*?)(?=\n\*\*|\n#{{1,3}}|\Z)'
                    m = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
                    if m:
                        return m.group(1).strip()
                return ''

            riesgo    = extract_section(raw, 'Riesgo detectado', 'Vulnerability', 'Risk') or 'Riesgo identificado'
            nivel     = extract_section(raw, 'Nivel de severidad', 'Severity') or 'MEDIUM'
            evidencia  = extract_section(raw, 'Evidencia técnica', 'Technical evidence', 'Details')
            impacto   = extract_section(raw, 'Impacto negocio', 'Business impact', 'Impact') or \
                        'Sin análisis de impacto disponible.'
            pasos     = extract_section(raw, 'Acción de remediación', 'Remediation steps', 'Solution') or \
                        'Sin pasos de remediación disponibles.'
            # Extract bash script from code fences
            script_m  = re.search(r'```(?:bash|sh)?\s*(.*?)```', raw, re.DOTALL)
            script    = script_m.group(1).strip() if script_m else '# Sin script de remediación'
            diff_m    = re.search(r'```(?:diff|patch)?\s*(---\s*a/.*?)```', raw, re.DOTALL)
            fix_patch = diff_m.group(1).strip() if diff_m else ''
            can_automate_raw = None

            print(f"⚠️ [Centinela-AI] Parsed prose response (non-JSON) successfully.")

        # Reject lazy/placeholder LLM output instead of accepting it as real remediation
        # content (see is_placeholder_text above) -- fall back to the same deterministic
        # heuristic generator used when the LLM never responds at all, rather than writing
        # garbage to script_path or claiming can_automate=true on an empty script.
        if is_repo_finding:
            if is_placeholder_text(fix_patch):
                if fix_patch:
                    print(f"⚠️ [Centinela-AI] Discarding placeholder fix_patch for {vuln['cve_id']}: {fix_patch[:80]!r}")
                fix_patch = ''
            if fix_patch.strip():
                # A patch is only real if it applies to the real file contents (git apply --check).
                # Unverifiable / non-applying LLM diffs are discarded, never stored as remediation.
                from core import patch_validator, code_context
                repo_dir = code_context._resolve_repo_dir(vuln.get('asset_name'), None, "/tmp/centinela_gitlab_scans")
                patch_ok, patch_why = patch_validator.validate_patch(repo_dir, fix_patch)
                if not patch_ok:
                    print(f"⚠️ [Centinela-AI] Discarding unverified fix_patch for {vuln['cve_id']} "
                          f"on {vuln.get('asset_name')}: {patch_why}")
                    fix_patch = ''
                else:
                    fix_patch = patch_validator.clean_patch(fix_patch)
        else:
            if is_placeholder_text(script):
                if script and script != '# Sin script de remediación':
                    print(f"⚠️ [Centinela-AI] Discarding placeholder remediation_script for {vuln['cve_id']}: {script[:80]!r}")
                script = generate_heuristic_script(vuln)
                if can_automate_raw is None:
                    can_automate_raw = heuristic_can_automate(vuln)

        # ── Build executive summary ──
        exec_parts = []
        if riesgo:
            exec_parts.append(f"**Riesgo Detectado:** {riesgo}")
        if nivel:
            exec_parts.append(f"**Nivel de Severidad:** {nivel}")
        if evidencia:
            exec_parts.append(f"**Evidencia Técnica:** {evidencia}")
        exec_summary = '\n\n'.join(exec_parts) if exec_parts else \
            'Análisis de IA completado. Revise los detalles técnicos.'

        # Respect what the LLM actually said about automatability rather than discarding it --
        # but never claim True if we ended up with neither a real script nor a real patch, and
        # for GitLab-Repo findings only trust a "true" if a patch was actually produced (a bash
        # remediation_script alone can't be applied to a repo finding).
        has_real_output = bool(fix_patch.strip()) or (script and script != '# Sin script de remediación')
        if is_repo_finding:
            can_automate = bool(fix_patch.strip())
        elif can_automate_raw is not None:
            can_automate = bool(can_automate_raw) and has_real_output
        else:
            can_automate = has_real_output

        return {
            "executive_summary": exec_summary,
            "business_impact": impacto if impacto and impacto != 'Sin análisis de impacto disponible.' else f"Riesgo evaluado para la infraestructura {vuln.get('asset_name')}. Se recomienda aislar el puerto o aplicar parches de seguridad.",
            "developer_steps": pasos if pasos and pasos != 'Sin pasos de remediación disponibles.' else f"1. Verificar la configuración del servicio en {vuln.get('endpoint')}.\n2. Aplicar parches de actualización y cerrar servicios no autorizados.",
            "remediation_script": script,
            "fix_patch": fix_patch,
            "can_automate": can_automate,
            "ai_real_severity": severidad_real_ai,
            "ai_depends_on_assumption": depende_supuesto_ai,
            "injection_suspected": injection_hits,
            # ADR-0021: what the adversarial verifier needs if this analysis lowers the severity.
            "evidence_refs": evidence_refs_ai,
            "ai_provider": _cascade_state.get("last_label") if content and not is_synthetic_marker else None,
            "verification_context": {
                "repo_dir": (_ctx or {}).get("repo_dir"),
                "code_block": (_ctx or {}).get("enclosing_snippet", ""),
                "callers": (_ctx or {}).get("callers", []),
                "repo_facts": repo_facts_text,
                "exposure": "" if is_repo_finding else _infra_exposure_context(vuln),
            },
        }

    except Exception as e:
        print(f"❌ Error in correlation call: {str(e)}")
        import traceback
        traceback.print_exc()
        return None

def _apply_injection_guard(vuln, analysis, risk_verdict_info, business_impact_text):
    """ADR-0012 D4. If the analysed material contained instructions aimed at the model, its verdict may not lower the severity: the scanner's
    value is kept and the finding is flagged CONDITIONAL (= human review). Returns (risk_verdict_info, business_impact_text)."""
    hits = analysis.get('injection_suspected')
    if not hits:
        return risk_verdict_info, business_impact_text
    agent_ledger.record_action(
        agent_ledger.ACTION_PROMPT_INJECTION,
        f"Posible inyección de instrucciones en {vuln['cve_id']} ({vuln.get('asset_name')})",
        outcome="skipped", entity_type="vulnerability", entity_id=vuln['id'],
        asset_id=vuln.get('asset_id'), detail={"patterns": hits})
    note = ("[Posible inyección de instrucciones detectada en el código/descripción analizados "
            f"({', '.join(hits)}); la severidad no se modificó y requiere revisión humana.]\n")
    return {"real_severity": None, "risk_verdict": "CONDITIONAL"}, note + str(business_impact_text)


def _verify_ai_downgrade(vuln, analysis, risk_verdict_info, business_impact_text):
    """ADR-0021. If the AI's verdict LOWERS the severity, get an adversarial second opinion (from a different model when
    possible) and check every cited line against the clone before the reduction is stored. Non-reducing verdicts pass
    through untouched (no extra provider call). Returns (risk_verdict_info, business_impact_text)."""
    if risk_verdict_info.get("risk_verdict") not in ai_verification.REDUCING_VERDICTS:
        return risk_verdict_info, business_impact_text
    ctx = analysis.get("verification_context") or {}
    first_label = analysis.get("ai_provider")
    used = {}

    def ask(prompt):
        answer = call_ai_cascade(prompt, want_json=True, avoid_labels=[first_label] if first_label else None)
        used["label"] = _cascade_state.get("last_label")
        return answer

    try:
        result = ai_verification.verify_downgrade(
            vuln=vuln, proposed=risk_verdict_info,
            analysis={**analysis, "business_impact": business_impact_text},
            ask=ask, repo_dir=ctx.get("repo_dir"), code_block=ctx.get("code_block", ""), callers=ctx.get("callers") or [],
            exposure_block=ctx.get("exposure", ""), repo_facts=ctx.get("repo_facts", ""))
    except Exception:
        import traceback
        traceback.print_exc()
        result = {"real_severity": None, "risk_verdict": "CONDITIONAL", "outcome": "error_verificacion",
                  "note": "La verificación de la baja de severidad falló; se conserva la severidad de la herramienta.", "detail": {}}
    detail = dict(result.get("detail") or {})
    detail.update({"first_model": first_label, "verifier_model": used.get("label"),
                   "same_model": bool(first_label and used.get("label") == first_label),
                   "final_verdict": result.get("risk_verdict"), "outcome": result.get("outcome")})
    agent_ledger.record_action(
        agent_ledger.ACTION_AI_VERIFICATION,
        f"Verificación de baja de severidad de {vuln['cve_id']} en {vuln.get('asset_name')}: {result.get('outcome')}",
        entity_type="vulnerability", entity_id=vuln['id'], asset_id=vuln.get('asset_id'), detail=detail,
        outcome="success" if result.get("outcome") == "sostiene_baja" else "skipped")
    print(f"🔎 [Centinela-AI] Downgrade check for {vuln['cve_id']}: {result.get('outcome')} -> {result.get('risk_verdict')}")
    note = result.get("note") or ""
    text = (f"[Verificación IA: {note}]\n" + str(business_impact_text)) if note else business_impact_text
    return {"real_severity": result.get("real_severity"), "risk_verdict": result.get("risk_verdict")}, text


def generate_ai_remediation_report(cve_id, log_output):
    """
    Use AI to generate a professional remediation report based on the technical execution log.
    """
    print(f"🤖 [Centinela-AI] Generating final remediation report for {cve_id}...")

    prompt_text = f"""
        Actúa como el CISO de la organización. Redacta un reporte ejecutivo de remediación técnica.
        VULNERABILIDAD: {cve_id}
        LOG TÉCNICO DE EJECUCIÓN:
        {log_output}

        FORMATO DEL REPORTE:
        1. RESUMEN EJECUTIVO: Qué se hizo y por qué.
        2. DETALLE TÉCNICO: Acciones realizadas (iptables, configuración, etc).
        3. ESTADO FINAL: Confirmación de cierre de brecha.
        4. RECOMENDACIÓN: Próximos pasos.

        Mantén un tono profesional, tecnológico y minimalista.
    """

    content = call_ai_cascade(prompt_text, want_json=False)
    if content:
        return content
    return f"Remediation for {cve_id} completed successfully.\n\nTechnical Log:\n{log_output}"


# Rules whose finding is the SAME structural pattern on every occurrence in an asset (a missing
# annotation, a literal secret in config, ...): the explanation, impact and remediation steps do not
# depend on the exact line, so one LLM analysis per (asset, rule) is shared with the other occurrences
# instead of spending one call each (proyecto-a alone had 304 AUTHZ-NO-METHOD-AUTHZ). Deliberately NOT included:
# anything whose real risk depends on the specific code around the line (SONAR-*, ANGULAR-BYPASS,
# HARDCODED-SECRET, injection rules, SCA per-package CVEs) -- those are analysed individually.
PATTERN_LEVEL_RULES = re.compile(
    r"^(AUTHZ-NO-METHOD-AUTHZ|AUTHZ-PREAUTHORIZE-COMMENTED-OUT|AUTHZ-TEST-ENDPOINT-EXPOSED|AUTHZ-PUBLIC-SENSITIVE-READ|"
    r"CONFIG-SECRET-LITERAL|CONFIG-JWT-SECRET-LITERAL|JPA-ENTITY-MISSING-VERSION|JPA-MULTI-WRITE-NO-TRANSACTIONAL|"
    r"FILE-UPLOAD-NO-VALIDATION|BLOCKING-THREAD-SLEEP|TIMING-UNSAFE-SECRET-COMPARISON|PASSWORD-POLICY-NOT-ENFORCED|"
    r"FRONTEND-TEST-ROUTE-EXPOSED|FRONTEND-TOKEN-IN-URL|AUTH-ENDPOINT-NO-RATE-LIMIT|SPRINGBOOT-CSRF-DISABLED|"
    # 2026-10-19: familia «configuración peligrosa de Spring» (CVE-2026-40972 DevTools remoto, consola H2, actuator expuesto);
    # el arreglo es el mismo en cada ocurrencia, no depende de la línea.
    r"SPRING-DEVTOOLS-REMOTE-ENABLED|SPRING-H2-CONSOLE-ENABLED|SPRING-ACTUATOR-SENSITIVE-EXPOSED|"
    # 2026-10-27: ddl-auto peligroso y cliente OIDC sin HTTPS/discovery estricto: misma corrección en cada ocurrencia.
    r"SPRING-JPA-DDL-AUTO-SCHEMA-CHANGE|FRONTEND-OIDC-INSECURE-CONFIG|"
    # 2026-10-28 (auditors/auditor_business_rules.py, catálogo CORE/Starter): corrección idéntica en cada ocurrencia.
    # SEQUENTIAL-FOLIO-FROM-MAX queda fuera: su riesgo depende de si hay bloqueo en otra clase.
    r"PASSWORD-MIN-LENGTH-BELOW-STANDARD|NUMERIC-CODE-STORED-AS-NUMBER|AUDIT-LOG-MUTATION-ENDPOINT|ACCOUNT-ENUMERATION-RESPONSE|"
    r"HTML-TEMPLATE-UNESCAPED-SUBSTITUTION|SVG-UPLOAD-WITHOUT-SANITIZATION|"
    # added 2026-10-01 after measuring where the unanalysed volume really was (proyecto-a/proyecto-l): same structural
    # pattern on every occurrence, fix identical regardless of the line.
    r"WCAG-[0-9.]+-[A-Z0-9-]+|ACCESSIBILITY-WCAG-[A-Z-]+|STD-STRIDE-MISSING-AUDIT-LOG|OOM-BYTE-ARRAY-STREAMING|"
    r"AUTHZ-CLIENT-SIDE-ONLY|AUTHZ-CLIENT-SIDE-UI-GATE|AUTHZ-ADMIN-BUNDLE-EXPOSED|FRONTEND-JWT-LOCALSTORAGE|"
    # 2026-10-12 (auditors/auditor_arch_rules.py): structural patterns whose explanation/fix does not depend on the exact line
    r"REQUESTBODY-WITHOUT-VALID|ENTITY-RETURNED-FROM-CONTROLLER|CONTROLLER-INJECTS-REPOSITORY|JPA-EAGER-FETCH|REPOSITORY-FINDALL-UNPAGINATED|"
    r"TS-EXPLICIT-ANY|ANGULAR-SUBMIT-NO-BUSY-GUARD|ANGULAR-TEMPLATE-METHOD-IN-LOOP|ANGULAR-SETTIMEOUT-WORKAROUND)$"
)


# Assets whose findings go through the AI queue FIRST (set per deployment in the private .env; none by default). Without this the
# queue is newest-first, so a fresh scan of any other project would starve them. Comma-separated ILIKE patterns in
# AI_PRIORITY_ASSET_PATTERNS override the default; an empty value disables priority ordering (matches nothing).
AI_PRIORITY_ASSET_PATTERNS = [p.strip() for p in os.getenv(
    "AI_PRIORITY_ASSET_PATTERNS",
    "").split(",") if p.strip()] or ["__no_priority__"]


def propagate_pattern_analysis(vuln, analysis, verdict, script_path):
    """After one occurrence of a pattern-level rule was analysed, give the other still-unanalysed
    occurrences of the same rule in the same asset the same rule-level analysis. Returns the list of ids
    that were filled (so the caller can skip them in the batch it already fetched).

    Safety rules: (a) never propagate a risk-REDUCING verdict (CONFIRMED_NO_RISK / DOWNGRADED) -- whether
    one occurrence is harmless says nothing about the others, those stay for individual analysis;
    (b) fix_patch is never copied (a diff is only valid for the exact lines it was validated against);
    can_automate=False; (c) the text states it is an inherited pattern-level analysis; (d) rows with a
    human decision in remediation_history are left alone."""
    if not PATTERN_LEVEL_RULES.match(str(vuln.get('cve_id', '')).upper()):
        return []
    if verdict.get("risk_verdict") in ("CONFIRMED_NO_RISK", "DOWNGRADED", "ANALYST_OVERRIDDEN", "NO_RISK_PENDING_REVIEW"):
        return []
    if not vuln.get('asset_id'):
        return []
    note = (f"[Análisis a nivel de patrón: heredado del hallazgo {vuln['id']} (misma regla, mismo activo); "
            f"las demás ocurrencias no se revisaron una por una.]\n")
    try:
        with db_manager.get_db_cursor() as cur:
            cur.execute("""
                SELECT v.id FROM vulnerability_log v
                LEFT JOIN remediation_history r ON r.vuln_id = v.id
                WHERE v.asset_id = %s AND v.cve_id = %s AND v.id <> %s
                  AND v.status IN ('OPEN', 'NEW', 'REOPENED', 'AI_FAILED', 'AI_ERROR', 'PENDING')
                  AND (r.id IS NULL OR r.approval_token IN ('PENDING_APPROVAL') OR r.approval_token IS NULL)
            """, (vuln['asset_id'], vuln['cve_id'], vuln['id']))
            ids = [r[0] for r in cur.fetchall()]
            if not ids:
                return []
            cur.execute("""
                UPDATE vulnerability_log SET status = 'CORRELATED',
                    executive_summary = %s, business_impact = %s, developer_steps = %s,
                    fix_patch = NULL, real_severity = NULL, risk_verdict = %s
                WHERE id = ANY(%s::uuid[])
            """, (analysis.get('executive_summary', ''), note + str(analysis.get('business_impact', '')),
                  analysis.get('developer_steps', ''),
                  "CONDITIONAL" if verdict.get("risk_verdict") == "CONDITIONAL" else None, ids))
            cur.execute("""
                INSERT INTO remediation_history (vuln_id, script_path, approval_token, can_automate)
                SELECT x, %s, 'PENDING_APPROVAL', FALSE FROM unnest(%s::uuid[]) AS x
                WHERE NOT EXISTS (SELECT 1 FROM remediation_history WHERE vuln_id = x)
            """, (script_path, ids))
        agent_ledger.record_action(
            agent_ledger.ACTION_AI_CORRELATION,
            f"Análisis por patrón de {vuln['cve_id']} en {vuln['asset_name']} compartido con {len(ids)} ocurrencia(s) más",
            entity_type="vulnerability", entity_id=vuln['id'], asset_id=vuln.get('asset_id'),
            detail={"propagated_to": len(ids), "pattern_level": True}, outcome="success",
        )
        print(f"♻️  [Centinela-AI] Pattern-level analysis of {vuln['cve_id']} reused for {len(ids)} more occurrence(s) on {vuln['asset_name']} (no extra LLM calls).")
        return [str(i) for i in ids]
    except Exception:
        import traceback
        traceback.print_exc()
        return []


def main_loop():
    print("🚀 [Centinela-AI] Aura-Guard v2026.4.2 active.")

    # Self-heal the tables this codebase owns (finding_suppressions, agent_actions) -- all
    # CREATE ... IF NOT EXISTS, cheap no-op once they exist. See core/schema.py for why this
    # lives in code rather than an untracked one-off script like every prior column add.
    try:
        from core.schema import ensure_core_schema
        with db_manager.get_db_cursor() as _schema_cur:
            ensure_core_schema(_schema_cur)
        print("✅ [Centinela-AI] Core schema ensured (finding_suppressions, agent_actions).")
    except Exception as e:
        print(f"⚠️ [Centinela-AI] ensure_core_schema failed (continuing): {e}")

    # Reap any zap-scan-* sibling containers orphaned by a previous, ungraceful process exit
    # (docker restart mid-scan skips run_zap_scan()'s own finally-block cleanup -- see
    # reap_orphaned_zap_containers()'s own docstring for the real incident this fixes). Age-gated
    # (40min) so it's safe even though centinela-backend can also launch a scan independently.
    try:
        from auditors.auditor_zap import reap_orphaned_zap_containers
        reap_orphaned_zap_containers()
    except Exception as e:
        print(f"⚠️ [Centinela-AI] ZAP container reap at startup failed: {e}")

    import threading
    falco_thread = threading.Thread(target=process_falco_alerts, daemon=True)
    falco_thread.start()
    
    zeek_thread = threading.Thread(target=process_zeek_alerts, daemon=True)
    zeek_thread.start()

    zeek_conn_thread = threading.Thread(target=process_zeek_conn_log, daemon=True)
    zeek_conn_thread.start()

    bloodhound_thread = threading.Thread(target=process_bloodhound_paths, daemon=True)
    bloodhound_thread.start()
    
    # Start real-time Heuristics Engine thread
    heuristics_thread = threading.Thread(target=run_heuristics_loop, daemon=True)
    heuristics_thread.start()

    # Real EPSS/CISA KEV threat-intel enrichment (backfills real risk scores)
    threat_intel_thread = threading.Thread(target=run_threat_intel_enrichment_loop, daemon=True)
    threat_intel_thread.start()

    # Real CTI/IoC correlation (Feodo Tracker C2 IPs)
    cti_thread = threading.Thread(target=run_cti_correlation_loop, daemon=True)
    cti_thread.start()

    # Real CIS Level 1 hardening checks over SSH, previously on-demand only
    cis_thread = threading.Thread(target=run_cis_benchmark_loop, daemon=True)
    cis_thread.start()

    # Wazuh agent discovery -- previously never actually scheduled anywhere (manual-exec only)
    wazuh_discovery_thread = threading.Thread(target=run_wazuh_discovery_loop, daemon=True)
    wazuh_discovery_thread.start()

    # Incident correlation (item 2, 2026-08-27): group related runtime/CTI/BloodHound/KEV
    # signals into incidents with a kill chain + MTTD/MTTC clock. Fail-safe on no data.
    infra_hygiene_thread = threading.Thread(target=run_os_patch_and_tls_audit_loop, daemon=True)
    infra_hygiene_thread.start()
    soar_expiry_thread = threading.Thread(target=run_soar_expiry_loop, daemon=True)
    soar_expiry_thread.start()
    incident_thread = threading.Thread(target=run_incident_correlation_loop, daemon=True)
    incident_thread.start()
    threading.Thread(target=run_cmmi_org_evidence_loop, daemon=True).start()
    threading.Thread(target=run_fleet_enqueue_loop, daemon=True).start()
    threading.Thread(target=run_gitlab_heads_refresh_loop, daemon=True).start()   # latest commit per branch -> change detection
    threading.Thread(target=run_scan_worker_loop, daemon=True).start()
    threading.Thread(target=run_secrets_history_worker_loop, daemon=True).start()   # git-history secrets (weekly per project)
    threading.Thread(target=run_secrets_token_renew_loop, daemon=True).start()      # periodic OpenBao token (daily renew-self)
    threading.Thread(target=run_zap_reaper_loop, daemon=True).start()               # orphaned ZAP containers every 15 min
    threading.Thread(target=run_reverify_loop, daemon=True).start()                 # ADR-0021 second opinion, nightly 06:00

    # External Auditor Thread
    from auditors import auditor_ext
    threading.Thread(target=auditor_ext.main, daemon=True).start()

    while True:
        _quota_blocked = 0
        try:
            with db_manager.get_db_cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT v.id, v.cve_id, v.severity, v.description, v.url_path, v.asset_id, i.asset_name, i.asset_type, i.endpoint,
                           v.finding_category, v.status AS prev_status,
                           v.scan_engine, i.criticality, i.agent_id
                    FROM vulnerability_log v
                    JOIN infra_inventory i ON v.asset_id = i.id
                    LEFT JOIN remediation_history r ON v.id = r.vuln_id
                    WHERE (
                        r.id IS NULL
                        OR v.status IN ('PENDING', 'NEW', 'AI_FAILED', 'AI_ERROR', 'REOPENED')
                    )
                    AND v.status != 'QUEUED_BACKLOG'
                    AND v.status != 'CORRELATED'
                    AND v.status != 'RESOLVED'
                    ORDER BY (CASE WHEN i.asset_name ILIKE ANY(%s) THEN 0 ELSE 1 END),
                             (CASE WHEN COALESCE(v.finding_category, 'VULNERABILITY') = 'INFORMATIONAL' THEN 1 ELSE 0 END),
                             v.id DESC
                    LIMIT 100;
                """, (AI_PRIORITY_ASSET_PATTERNS,))
                
                pending_vulns = cur.fetchall()
                
                if not pending_vulns:
                    # Run native master audits (SAST/SCA/Standards) periodically during idle loop.
                    # Was calling run_master_vulnerability_scan() etc. with no args, which defaults
                    # to target_dir="/opt/centinela-ai" (Centinela's own source, not any of the 66
                    # registered GitLab-Repo customer assets) and asset_id=None -- so this branch
                    # never actually audited a real GitLab project, only ever the platform's own
                    # code. GitLabIntegrator.scan_all_projects() (already used, working, and
                    # auth'd via GITLAB_TOKEN, by the manual POST /api/gitlab/scan endpoint) clones
                    # each real project and calls the same three auditors with the correct
                    # target_dir/asset_id per repo.
                    # 2026-10-05 (ADR-0008 #4): fleet scans no longer run inline here (they were lost on every restart). They are queued in
                    # scan_jobs by run_fleet_enqueue_loop() and executed by run_scan_worker_loop(); this branch only waits for new work.
                    time.sleep(30)
                    continue

                _already_filled = set()
                _quota_blocked = 0
                for vuln in pending_vulns:
                    if str(vuln['id']) in _already_filled:
                        continue  # filled by propagate_pattern_analysis() from a sibling in this batch
                    try:
                        analysis = correlate_vulnerability(vuln)
                        if analysis == "RATE_LIMIT":
                            _quota_blocked += 1   # leave it pending; keep going so rows with a specific rule still advance
                            continue
                        
                        if analysis:
                            script_path = f"/app/data/remediation/{vuln['cve_id']}_{vuln['id']}.sh"
                            os.makedirs(os.path.dirname(script_path), exist_ok=True)
                            fix_patch = analysis.get('fix_patch', '') or ''

                            if fix_patch.strip():
                                # GitLab-Repo finding with a real AI-generated diff: record it as
                                # the human-readable artifact too, but the actual application
                                # happens via `git apply` in remediation/gitlab_autofix.py, not
                                # by executing this file as a shell script.
                                remediation_content = (
                                    f"# Parche generado por IA para {vuln['cve_id']} -- aplicado automáticamente\n"
                                    f"# vía Merge Request por Sentinel (remediation/gitlab_autofix.py), no ejecutado como script.\n\n"
                                    f"{fix_patch}"
                                )
                            else:
                                remediation_content = analysis.get('remediation_script', '# No script provided')

                            with open(script_path, "w") as f:
                                f.write(str(remediation_content))

                            business_impact_text = analysis.get('business_impact', 'No impact analysis available')
                            if str(vuln.get('prev_status') or '').upper() == 'REOPENED':
                                # REOPENED rows used to be skipped forever (never re-analysed). Now they are, and the
                                # status becomes CORRELATED like any analysed finding -- so the regression is stated
                                # in the text instead of being lost with the status.
                                business_impact_text = ("[Hallazgo reabierto: ya se había resuelto y volvió a detectarse en un nuevo escaneo; "
                                                        "análisis actualizado.]\n" + str(business_impact_text))
                            developer_steps_text = analysis.get('developer_steps', 'No steps provided')
                            # Separate AI-determined real-world verdict from the raw scanner
                            # severity (never overwritten) -- see assess_real_risk_verdict()'s own
                            # docstring for why this exists: a scanner's severity describes the
                            # code PATTERN in the abstract, not whether this specific occurrence
                            # is actually reachable by an attacker.
                            risk_verdict_info = deduplication_engine.assess_real_risk_verdict(
                                business_impact_text, developer_steps_text,
                                raw_severity=vuln.get('severity'),
                                ai_real_severity=analysis.get('ai_real_severity'),
                                ai_depends_on_assumption=analysis.get('ai_depends_on_assumption'),
                            )

                            risk_verdict_info, business_impact_text = _apply_injection_guard(
                                vuln, analysis, risk_verdict_info, business_impact_text)
                            # ADR-0021: a severity reduction only stands after an adversarial second opinion with
                            # evidence checked against the real code (never on one model's word).
                            proposed_verdict = dict(risk_verdict_info)
                            risk_verdict_info, business_impact_text = _verify_ai_downgrade(
                                vuln, analysis, risk_verdict_info, business_impact_text)

                            with db_manager.get_db_cursor() as write_cur:
                                write_cur.execute("""
                                    UPDATE vulnerability_log
                                    SET status = 'CORRELATED',
                                        executive_summary = %s,
                                        business_impact = %s,
                                        developer_steps = %s,
                                        fix_patch = %s,
                                        real_severity = %s,
                                        risk_verdict = %s,
                                        sla_due_date = CASE WHEN %s IS NOT NULL THEN detected_at + %s ELSE sla_due_date END
                                    WHERE id = %s
                                """, (
                                    analysis.get('executive_summary', 'No summary available'),
                                    business_impact_text,
                                    developer_steps_text,
                                    fix_patch if fix_patch.strip() else None,
                                    risk_verdict_info["real_severity"],
                                    risk_verdict_info["risk_verdict"],
                                    risk_verdict_info["real_severity"],
                                    deduplication_engine.get_sla_delta(risk_verdict_info["real_severity"]),
                                    vuln['id']
                                ))

                                # Confirmed-zero-real-risk findings get a PROPOSED (inactive)
                                # suppression for a human to review and activate with one click
                                # via the existing /api/suppressions flow -- never auto-activated,
                                # an AI verdict is a recommendation here, not a unilateral dismissal.
                                if risk_verdict_info["risk_verdict"] in ai_verification.PROPOSAL_VERDICTS:
                                    write_cur.execute("""
                                        SELECT 1 FROM finding_suppressions
                                        WHERE asset_id = %s AND cve_id = %s AND created_by = 'centinela-ai'
                                    """, (vuln.get('asset_id'), vuln['cve_id']))
                                    if not write_cur.fetchone():
                                        write_cur.execute("""
                                            INSERT INTO finding_suppressions
                                            (asset_id, cve_id, reason, scope, created_by, active, review_status)
                                            VALUES (%s, %s, %s, 'FALSE_POSITIVE', 'centinela-ai', FALSE, 'PENDING')
                                        """, (vuln.get('asset_id'), vuln['cve_id'],
                                              f"Propuesta automática: {business_impact_text[:400]}"))

                                # Check if a history row already exists for this vuln
                                write_cur.execute("SELECT id, approval_token FROM remediation_history WHERE vuln_id = %s LIMIT 1", (vuln['id'],))
                                existing = write_cur.fetchone()
                                if existing:
                                    # Only update script_path; preserve approval_token if already acted on
                                    new_token = existing[1] if existing[1] not in ('PENDING_APPROVAL', None) else 'PENDING_APPROVAL'
                                    write_cur.execute("""
                                        UPDATE remediation_history
                                        SET script_path = %s, approval_token = %s, can_automate = %s
                                        WHERE id = %s
                                    """, (script_path, new_token, analysis.get('can_automate', True), existing[0]))
                                else:
                                    write_cur.execute("""
                                        INSERT INTO remediation_history (vuln_id, script_path, approval_token, can_automate)
                                        VALUES (%s, %s, %s, %s)
                                    """, (vuln['id'], script_path, "PENDING_APPROVAL", analysis.get('can_automate', True)))
                                
                            # A verdict that started as a reduction is never shared with sibling occurrences, whatever the
                            # verifier decided (each occurrence needs its own evidence) -- propagate the PROPOSED verdict.
                            _already_filled.update(propagate_pattern_analysis(
                                vuln, analysis, proposed_verdict if proposed_verdict.get("risk_verdict") in ai_verification.REDUCING_VERDICTS
                                else risk_verdict_info, script_path))
                            print(f"✅ Analysis complete for {vuln['cve_id']}. Script saved.")
                            agent_ledger.record_action(
                                agent_ledger.ACTION_AI_CORRELATION,
                                f"Correlación IA completada para {vuln['cve_id']} en {vuln['asset_name']}",
                                entity_type="vulnerability", entity_id=vuln['id'],
                                asset_id=vuln.get('asset_id'),
                                detail={
                                    "can_automate": analysis.get('can_automate'),
                                    "has_patch": bool(fix_patch.strip()),
                                    "asset_type": vuln.get('asset_type'),
                                },
                                outcome="success",
                            )
                            # Only LLM-backed analyses need the 429-avoidance pause; informational findings use
                            # the deterministic engine (no provider call) so they must not pay 3s each.
                            if str(vuln.get('finding_category') or '').upper() != 'INFORMATIONAL':
                                time.sleep(3)  # Delay between successful requests to prevent 429
                        else:
                            with db_manager.get_db_cursor() as write_cur:
                                write_cur.execute("UPDATE vulnerability_log SET status = 'AI_FAILED' WHERE id = %s", (vuln['id'],))
                            agent_ledger.record_action(
                                agent_ledger.ACTION_AI_CORRELATION_FAIL,
                                f"Correlación IA sin resultado utilizable para {vuln['cve_id']} en {vuln['asset_name']}",
                                entity_type="vulnerability", entity_id=vuln['id'],
                                asset_id=vuln.get('asset_id'), outcome="failed",
                            )
                    except Exception as e:
                        print(f"❌ Critical error processing vuln {vuln['id']}: {e}")
                        # If it's a connection error or something transient, don't mark as error
                        if "conn" in str(e).lower() or "429" in str(e):
                            continue
                        with db_manager.get_db_cursor() as write_cur:
                            write_cur.execute("UPDATE vulnerability_log SET status = 'AI_ERROR' WHERE id = %s", (vuln['id'],))
        except Exception as e:
            print(f"❌ [Centinela-AI] Error in main loop: {e}")
            time.sleep(10)

        if _quota_blocked:
            print(f"⏳ [Centinela-AI] {_quota_blocked} finding(s) left pending: every LLM tier is out of quota. Retrying in 120s.")
            time.sleep(120)
        time.sleep(10) # Wait 10s between query cycles

if __name__ == "__main__":
    main_loop()
