"""
Estado y consumo de los proveedores de IA de la cascada (pantalla "Tokens IA").

Tres tipos de dato, que la pantalla distingue explícitamente para no aparentar precisión que no hay:
  * MEDIDO por Centinela: llamadas y tokens por proveedor, leídos de public.ai_provider_usage (lo escribe
    centinela.call_ai_cascade en cada intento).
  * MEDIDO por el proveedor (sondeo bajo demanda): cuota restante real que Groq devuelve en cabeceras
    x-ratelimit-* y que OpenRouter devuelve en /auth/key. Cuesta ~1 token por sondeo.
  * REFERENCIA: topes gratuitos publicados por el proveedor. No son una medición de la cuenta.
Los demás proveedores (Gemini, Cloudflare, NVIDIA, Mistral, Cerebras, SambaNova) no exponen la cuota restante por API
en las llamadas que usamos: de ellos solo se muestra lo medido por Centinela y el último error de cuota.
"""
import os
import time

import requests

from core import db_manager

# (label en la cascada, proveedor, variable del modelo, modelo por defecto, variables de llave requeridas)
# Los modelos por defecto repiten los de centinela.py; el modelo real de cada llamada queda en ai_provider_usage.model.
_TIERS = [
    ("groq:{m}", "Groq", "AI_MODEL_GROQ_2", "qwen/qwen3.8-27b", ["GROQ_API_KEY"]),
    ("groq", "Groq", "AI_MODEL", "openai/gpt-oss-20b", ["GROQ_API_KEY"]),
    ("google_genai", "Google Gemini", "AI_MODEL_GOOGLE", "gemini-1.5-flash-latest", ["GOOGLE_API_KEY"]),
    ("google_genai:{m}", "Google Gemini", "AI_MODEL_GOOGLE_2", "gemini-2.5-flash-lite", ["GOOGLE_API_KEY"]),
    ("cloudflare", "Cloudflare Workers AI", "AI_MODEL_CLOUDFLARE", "@cf/meta/llama-3.3-70b-instruct-fp8-fast",
     ["CLOUDFLARE_API_TOKEN", "CLOUDFLARE_ACCOUNT_ID"]),
    ("mistral", "Mistral", "AI_MODEL_MISTRAL", "mistral-small-latest", ["MISTRAL_API_KEY"]),
    ("cerebras", "Cerebras", "AI_MODEL_CEREBRAS", "gpt-oss-120b", ["CEREBRAS_API_KEY"]),
    ("sambanova", "SambaNova", "AI_MODEL_SAMBANOVA", "Meta-Llama-3.3-70B-Instruct", ["SAMBANOVA_API_KEY"]),
    ("nvidia_nim", "NVIDIA NIM", "AI_MODEL_NVIDIA", "openai/gpt-oss-20b", ["NVIDIA_NIM_API_KEY"]),
    ("openrouter", "OpenRouter", "AI_MODEL_OPENROUTER", "nvidia/nemotron-3-super-120b-a12b:free", ["OPENROUTER_API_KEY"]),
]

# Topes gratuitos DOCUMENTADOS (referencia, no medición): ver CLAUDE.md / sesiones 2026-08-07 y 2026-10-01.
# Solo se listan los que tenemos anotados; el resto queda sin referencia en vez de inventar un número.
_REFERENCE = {
    "groq": "100,000 tokens/día (error TPD observado en vivo)",
    "groq:": "1,000 solicitudes/día · 8,000 tokens/min (cabeceras observadas en vivo)",
    "google_genai:": "gemini-2.5-flash-lite: ver AI Studio de la cuenta",
    "cloudflare": "~10,000 neuronas/día compartidas entre modelos (≈70 llamadas con prompts reales, estimación)",
    "openrouter": "50 solicitudes/día en modelos :free (observado en vivo)",
}


def _tier_defs():
    out = []
    for tpl, provider, model_env, model_default, key_envs in _TIERS:
        model = os.getenv(model_env) or model_default
        label = tpl.format(m=model)
        configured = all(os.getenv(k) for k in key_envs)
        out.append({"label": label, "provider": provider, "model": model, "configured": configured})
    return out


def _reference_for(label):
    if label in _REFERENCE:
        return _REFERENCE[label]
    for prefix, text in _REFERENCE.items():
        if prefix.endswith(":") and label.startswith(prefix):
            return text
    return None


def get_status() -> dict:
    """Estado por proveedor a partir de lo medido por Centinela (BD). No hace llamadas de red."""
    tiers = _tier_defs()
    with db_manager.get_db_cursor() as cur:
        cur.execute(
            """
            SELECT tier,
                   COUNT(*) FILTER (WHERE ok AND ts >= date_trunc('day', NOW() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC') AS ok_today,
                   COUNT(*) FILTER (WHERE NOT ok AND ts >= date_trunc('day', NOW() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC') AS fail_today,
                   COALESCE(SUM(prompt_tokens) FILTER (WHERE ts >= date_trunc('day', NOW() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'), 0) AS prompt_today,
                   COALESCE(SUM(completion_tokens) FILTER (WHERE ts >= date_trunc('day', NOW() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'), 0) AS compl_today,
                   COUNT(*) FILTER (WHERE ok AND ts >= date_trunc('day', NOW() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC' AND prompt_tokens IS NULL) AS ok_no_tokens_today,
                   COUNT(*) FILTER (WHERE ok AND ts >= NOW() - INTERVAL '1 hour') AS ok_hour,
                   MAX(ts) FILTER (WHERE ok) AS last_ok
            FROM public.ai_provider_usage WHERE ts >= NOW() - INTERVAL '2 days' GROUP BY tier
            """
        )
        agg = {r[0]: r for r in cur.fetchall()}
        cur.execute(
            """
            SELECT DISTINCT ON (tier) tier, ts, ok, error_kind, error_text, cooldown_until
            FROM public.ai_provider_usage ORDER BY tier, ts DESC
            """
        )
        last = {r[0]: r for r in cur.fetchall()}
        cur.execute(
            """
            SELECT DISTINCT ON (tier) tier, ts, error_kind, error_text FROM public.ai_provider_usage
            WHERE NOT ok AND error_kind IN ('quota','quota_day','quota_minute') ORDER BY tier, ts DESC
            """
        )
        last_quota = {r[0]: r for r in cur.fetchall()}
        cur.execute("SELECT NOW()")
        now = cur.fetchone()[0]

    result = []
    for t in tiers:
        a = agg.get(t["label"])
        l = last.get(t["label"])
        lq = last_quota.get(t["label"])
        state, detail, resume = "sin_uso", "Sin llamadas registradas en las últimas 48 h.", None
        if not t["configured"]:
            state, detail = "sin_llave", "Sin llave configurada en .env: este proveedor no participa en la cascada."
        elif l is not None:
            ts, ok, kind, text, cooldown = l[1], l[2], l[3], l[4], l[5]
            if ok:
                state, detail = "disponible", "Respondió correctamente en su último intento."
            elif cooldown is not None and cooldown > now and kind in ("quota", "quota_day", "quota_minute"):
                state, resume = "agotado", cooldown
                detail = "Cuota agotada; la cascada lo salta hasta que se reinicie."
            elif cooldown is not None and cooldown > now:
                state, resume = "en_pausa", cooldown
                detail = {"auth": "Llave/modelo rechazado (401/403/404).", "timeout": "Lento o sin respuesta."}.get(kind, "Falló su último intento.")
            else:
                state = "disponible" if kind in ("quota", "quota_day", "quota_minute", "timeout", "error", "empty") else "revisar"
                detail = "Su última falla ya venció; se reintentará en la siguiente llamada."
        result.append({
            **t,
            "state": state,
            "detail": detail,
            "resumes_at": resume.isoformat() if resume else None,
            "ok_today": int(a[1]) if a else 0,
            "fail_today": int(a[2]) if a else 0,
            "prompt_tokens_today": int(a[3]) if a else 0,
            "completion_tokens_today": int(a[4]) if a else 0,
            "ok_calls_without_token_data_today": int(a[5]) if a else 0,
            "ok_last_hour": int(a[6]) if a else 0,
            "last_ok": a[7].isoformat() if a and a[7] else None,
            "last_error": ({"at": l[1].isoformat(), "kind": l[3], "text": l[4]} if l and not l[2] else None),
            "last_quota_error_at": lq[1].isoformat() if lq else None,
            "reference_limit": _reference_for(t["label"]),
        })
    return {"generated_at": now.isoformat(), "day_basis": "UTC (los topes diarios de casi todos los proveedores reinician ~00:00 UTC)",
            "tiers": result}


def _groq_probe(model: str) -> dict:
    key = os.getenv("GROQ_API_KEY")
    t0 = time.time()
    r = requests.post(
        "https://api.groq.com/openai/v1/chat/completions",
        headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
        json={"model": model, "messages": [{"role": "user", "content": "ok"}], "max_completion_tokens": 1},
        timeout=25,
    )
    h = r.headers
    keep = {k: h.get(k) for k in ("x-ratelimit-limit-requests", "x-ratelimit-remaining-requests", "x-ratelimit-reset-requests",
                                  "x-ratelimit-limit-tokens", "x-ratelimit-remaining-tokens", "x-ratelimit-reset-tokens",
                                  "retry-after")}
    out = {"http": r.status_code, "latency_ms": int((time.time() - t0) * 1000), "headers": {k: v for k, v in keep.items() if v is not None}}
    if r.status_code != 200:
        try:
            out["error"] = r.json().get("error", {}).get("message", r.text[:300])
        except ValueError:
            out["error"] = r.text[:300]
    return out


def _openrouter_probe() -> dict:
    key = os.getenv("OPENROUTER_API_KEY")
    base = os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")
    r = requests.get(f"{base}/auth/key", headers={"Authorization": f"Bearer {key}"}, timeout=20)
    out = {"http": r.status_code}
    try:
        body = r.json()
    except ValueError:
        body = {}
    out["data"] = body.get("data", body)
    if r.status_code != 200:
        out["error"] = str(body)[:300]
    return out


def probe_live() -> dict:
    """Sondeo bajo demanda de la cuota real (Groq y OpenRouter). Un fallo de un proveedor no impide los demás."""
    import traceback
    results = {}
    for t in _tier_defs():
        if not t["configured"]:
            continue
        try:
            if t["provider"] == "Groq":
                results[t["label"]] = _groq_probe(t["model"])
            elif t["provider"] == "OpenRouter":
                results[t["label"]] = _openrouter_probe()
        except Exception as e:
            traceback.print_exc()
            results[t["label"]] = {"error": f"{type(e).__name__}: {e}"}
    return {"probed_at": time.time(), "results": results,
            "not_probeable": "Gemini, Cloudflare, NVIDIA, Mistral, Cerebras y SambaNova no devuelven la cuota restante por API en las llamadas que usa Centinela."}
