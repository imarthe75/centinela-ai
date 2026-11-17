"""ADR-0012 D1: data class per AI provider. The cascade tests use stand-in LLM clients (isolated: they prove the routing decision, not any
provider's behaviour)."""
import os
import unittest
from unittest import mock

import centinela
from core import ai_data_policy as pol

CODE_PROMPT = """HALLAZGO A CORREGIR:
- Repositorio: GitLab/x/y
- Ubicación (archivo:línea): src/main/java/App.java:42
CONTEXTO DE CÓDIGO (bloque que contiene la línea 42):
```
public void run() { exec(userInput); }
```"""


class TestClassifier(unittest.TestCase):
    def test_empty_and_generic_text_is_public(self):
        self.assertEqual(pol.classify_prompt(""), pol.PUBLIC)
        self.assertEqual(pol.classify_prompt("Explica qué es un XSS reflejado en términos simples."), pol.PUBLIC)

    def test_internal_signals(self):
        self.assertEqual(pol.classify_prompt("El servidor 192.0.2.17 expone el puerto 22"), pol.INTERNAL)
        self.assertEqual(pol.classify_prompt("host auth.example.internal sin HSTS"), pol.INTERNAL)

    def test_code_signals_win_over_internal(self):
        self.assertEqual(pol.classify_prompt(CODE_PROMPT), pol.CLIENT_CODE)
        self.assertEqual(pol.classify_prompt("revisa app/models.py:10 en 192.0.2.2"), pol.CLIENT_CODE)
        self.assertEqual(pol.classify_prompt("def f(x):\n    return x"), pol.CLIENT_CODE)
        self.assertEqual(pol.classify_prompt("--- a/Dockerfile\n+++ b/Dockerfile"), pol.CLIENT_CODE)

    def test_location_desconocida_alone_is_not_code(self):
        self.assertEqual(pol.classify_prompt("Ubicación (archivo:línea): desconocida"), pol.PUBLIC)


class TestPolicyTable(unittest.TestCase):
    def test_default_restricts_only_mistral(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("AI_TIER_MAX_DATA_CLASS", None)
            os.environ.pop("AI_DEFAULT_MAX_DATA_CLASS", None)
            self.assertEqual(pol.tier_max_class("mistral"), pol.INTERNAL)
            for t in ("groq", "groq:qwen/x", "google_genai", "google_genai:gemini-2.5", "nvidia_nim", "openrouter", "cloudflare"):
                self.assertEqual(pol.tier_max_class(t), pol.CLIENT_CODE, t)

    def test_env_override_and_bad_values_ignored(self):
        with mock.patch.dict(os.environ, {"AI_TIER_MAX_DATA_CLASS": "google_genai=INTERNAL, groq=bogus ,openrouter=public"}):
            self.assertEqual(pol.tier_max_class("google_genai:gemini-2.5-flash-lite"), pol.INTERNAL)
            self.assertEqual(pol.tier_max_class("groq"), pol.CLIENT_CODE)       # invalid class ignored, default kept
            self.assertEqual(pol.tier_max_class("openrouter"), pol.PUBLIC)

    def test_filter_tiers(self):
        tiers = [("groq", None, 1), ("mistral", None, 1)]
        allowed, excluded, cls = pol.filter_tiers(tiers, CODE_PROMPT)
        self.assertEqual([t[0] for t in allowed], ["groq"])
        self.assertEqual(excluded, ["mistral"])
        self.assertEqual(cls, pol.CLIENT_CODE)
        allowed, excluded, _ = pol.filter_tiers(tiers, "texto genérico")
        self.assertEqual(len(allowed), 2)
        self.assertEqual(excluded, [])


class TestCascadeEnforcement(unittest.TestCase):
    def setUp(self):
        self._saved = (centinela.groq_llm, centinela.groq_llm_2, centinela.gemini_client, centinela.nvidia_llm,
                       centinela.openrouter_llm, dict(centinela.extra_llms))
        centinela.groq_llm = centinela.groq_llm_2 = centinela.gemini_client = centinela.nvidia_llm = centinela.openrouter_llm = None
        centinela.extra_llms.clear()
        centinela._tier_cooldown.clear()
        pol._last_logged.clear()
        self.addCleanup(self._restore)

    def _restore(self):
        (centinela.groq_llm, centinela.groq_llm_2, centinela.gemini_client, centinela.nvidia_llm,
         centinela.openrouter_llm, extras) = self._saved
        centinela.extra_llms.clear()
        centinela.extra_llms.update(extras)
        centinela._tier_cooldown.clear()

    @staticmethod
    def _llm(text):
        m = mock.Mock()
        m.invoke.return_value = mock.Mock(content=text)
        return m

    def test_code_prompt_never_reaches_a_restricted_tier(self):
        mistral = self._llm("mistral-answer")
        centinela.extra_llms["mistral"] = mistral
        self.assertIsNone(centinela.call_ai_cascade(CODE_PROMPT))
        self.assertFalse(mistral.invoke.called)
        # a policy exclusion is not "quota exhausted": it must not park findings waiting for a reset that cannot help
        self.assertFalse(centinela.cascade_all_unavailable())

    def test_code_prompt_falls_to_allowed_tier(self):
        mistral, groq = self._llm("mistral-answer"), self._llm("groq-answer")
        centinela.extra_llms["mistral"] = mistral
        centinela.groq_llm = groq
        self.assertEqual(centinela.call_ai_cascade(CODE_PROMPT), "groq-answer")
        self.assertFalse(mistral.invoke.called)

    def test_generic_prompt_still_uses_restricted_tier(self):
        mistral = self._llm("mistral-answer")
        centinela.extra_llms["mistral"] = mistral
        self.assertEqual(centinela.call_ai_cascade("explica qué es XSS"), "mistral-answer")

    def test_env_can_restrict_a_main_tier(self):
        groq = self._llm("groq-answer")
        centinela.groq_llm = groq
        with mock.patch.dict(os.environ, {"AI_TIER_MAX_DATA_CLASS": "groq=INTERNAL"}):
            self.assertIsNone(centinela.call_ai_cascade(CODE_PROMPT))
        self.assertFalse(groq.invoke.called)


if __name__ == "__main__":
    unittest.main()
