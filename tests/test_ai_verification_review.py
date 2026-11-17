"""Human review of the AI verifier, nightly re-verification schedule, and Semgrep security rules as safety-protected (2026-11-13)."""
import importlib.util
import os
import tempfile
from datetime import datetime, timezone

import xlsxwriter

from core import ai_verification as av
from workers.periodic import seconds_until_next

_spec = importlib.util.spec_from_file_location(
    "ai_verification_review_sample",
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts", "ai_verification_review_sample.py"))
rs = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rs)


def test_semgrep_security_category_is_protected():
    assert av.is_safety_protected("ruby.rails.security.audit.xss.avoid-raw", "", "semgrep")
    assert av.is_safety_protected("generic.secrets.security.detected-bcrypt-hash.detected-bcrypt-hash", "", "semgrep")
    assert not av.is_safety_protected("java.lang.correctness.no-op", "", "semgrep")
    assert not av.is_safety_protected("CONTROLLER-INJECTS-REPOSITORY", "", "sast-native")


def test_seconds_until_next_daily_run():
    # 2026-11-13 05:00 local (UTC-6) = 11:00 UTC -> next 06:00 local is in one hour
    now = datetime(2026, 11, 13, 11, 0, tzinfo=timezone.utc)
    assert seconds_until_next("06:00", "America/Mexico_City", now) == 3600
    # just after 06:00 -> almost a full day
    later = datetime(2026, 11, 13, 12, 0, 1, tzinfo=timezone.utc)
    assert 86000 < seconds_until_next("06:00", "America/Mexico_City", later) < 86400


def test_first_ai_text_strips_verifier_prefix():
    assert rs._first_ai_text("[Verificación IA: x]\n[Verificación IA: y]\nexplicación real") == "explicación real"


def test_pick_is_stratified_capped_per_rule_and_filled():
    rows = ([{"id": f"r{i}", "outcome": "rechaza_baja", "cve_id": f"R{i % 20}"} for i in range(60)] +
            [{"id": f"s{i}", "outcome": "sostiene_baja", "cve_id": "ONE-RULE"} for i in range(10)] +
            [{"id": f"i{i}", "outcome": "inconcluso", "cve_id": f"I{i}"} for i in range(10)])
    chosen = rs.pick(rows, 30, seed=1)
    assert len(chosen) == 30
    assert sum(1 for c in chosen if c["cve_id"] == "ONE-RULE") <= 2        # one noisy rule cannot dominate
    assert len({c["id"] for c in chosen}) == 30


def _filled_workbook(path, rows):
    """A workbook shaped like the generated one, with the reviewer's three columns filled."""
    wb = xlsxwriter.Workbook(path)
    wb.add_worksheet("Instrucciones").write(0, 0, "x")
    ws = wb.add_worksheet("Revisión")
    header = ["id", "Activo", "Regla", "Archivo:línea", "Ver en GitLab", "Severidad de la herramienta", "Qué detectó la herramienta",
              "Severidad propuesta por la 1.ª IA", "Por qué la 1.ª IA propone bajarla", "Decisión del verificador",
              "Razón del verificador", "Líneas que citó el verificador", "SU VEREDICTO", "Severidad que usted pondría", "Comentario"]
    for c, h in enumerate(header):
        ws.write(0, c, h)
    for r, (vid, outcome, human) in enumerate(rows, start=1):
        ws.write(r, 0, vid)
        ws.write(r, 9, rs.OUTCOME_LABEL[outcome])
        if human:
            ws.write(r, 12, human)
            ws.write(r, 13, "LOW")
    wb.close()


def test_score_reads_xlsx_with_stdlib_and_counts_agreement(capture_ledger, capsys):
    yes, no, unknown = rs.HUMAN_CHOICES
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "m.xlsx")
        _filled_workbook(p, [("a", "sostiene_baja", yes), ("b", "sostiene_baja", no), ("c", "rechaza_baja", no),
                             ("d", "rechaza_baja", unknown), ("e", "inconcluso", yes), ("f", "rechaza_baja", "")])
        rows = rs.read_review_sheet(p)
        assert rows[0][0] == "id" and len(rows) == 7
        rs.score(p, "tester")
    out = capsys.readouterr().out
    assert "Casos con veredicto humano: 5 de 6" in out
    assert "2/3 = 67 %" in out                       # a (agree), b (disagree), c (agree); d unknown; e inconclusive
    rec = capture_ledger[-1]
    assert rec["action_type"] == rs.ACTION and rec["actor"] == "tester"
    assert rec["detail"]["per_outcome"]["inconcluso"] == {"humano_si_pudo_decidir": 1}
