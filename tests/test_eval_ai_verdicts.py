"""ADR-0012 D3: the metrics of scripts/eval_ai_verdicts.py (pure function; the SQL part was exercised read-only against the live DB)."""
import importlib.util
import pathlib
import unittest

_spec = importlib.util.spec_from_file_location("eval_ai_verdicts", pathlib.Path(__file__).resolve().parents[1] / "scripts" / "eval_ai_verdicts.py")
ev = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ev)


def row(analyst, ai):
    return {"analyst": analyst, "ai": ai}


class TestSummarize(unittest.TestCase):
    def test_empty_is_small_sample_and_has_no_percentages(self):
        r = ev.summarize([])
        self.assertTrue(r["small_sample"])
        self.assertIsNone(r["false_dismissals_pct_of_vulnerabilities"])
        self.assertIsNone(r["false_positives_recognised_pct_of_fp"])

    def test_false_dismissal_and_recognised_fp(self):
        rows = ([row("Vulnerabilidad", "CONFIRMED_NO_RISK")] + [row("Vulnerabilidad", "(sin veredicto)")] * 3
                + [row("Falso positivo", "DOWNGRADED")] + [row("Falso positivo", "CONFIRMED_NO_RISK")] + [row("Falso positivo", "CONDITIONAL")] * 2)
        r = ev.summarize(rows)
        self.assertEqual(r["false_dismissals"], 1)
        self.assertEqual(r["false_dismissals_pct_of_vulnerabilities"], 25.0)
        self.assertEqual(r["false_positives_recognised"], 2)      # CONDITIONAL does not count as recognised
        self.assertEqual(r["false_positives_recognised_pct_of_fp"], 50.0)
        self.assertTrue(r["small_sample"])

    def test_matrix_counts(self):
        r = ev.summarize([row("Calidad", "DOWNGRADED"), row("Calidad", "DOWNGRADED"), row("Calidad", "(sin veredicto)")])
        self.assertEqual(r["matrix"]["Calidad"], {"DOWNGRADED": 2, "(sin veredicto)": 1})


if __name__ == "__main__":
    unittest.main()
