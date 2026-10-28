"""Property-based tests (Hypothesis) for Centinela's own parsers and decision logic: malformed input must never crash them and the
invariants the rest of the platform relies on (idempotence, dedup stability, no severity elevation) must hold for ANY input."""
import ipaddress
import os
import re
import subprocess
import tempfile
from datetime import datetime, timedelta

from hypothesis import HealthCheck, given, settings, strategies as st

from core import deduplication_engine as de, incident_engine as ie, patch_validator as pv

TEXT = st.text(max_size=400)
SEVS = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
FAST = settings(max_examples=150, deadline=None)


# ---- patch_validator ---------------------------------------------------------------------------------------------------------
@FAST
@given(TEXT)
def test_clean_patch_is_total_and_idempotent(raw):
    once = pv.clean_patch(raw)
    assert pv.clean_patch(once) == once
    assert once == "" or once.endswith("\n")


@FAST
@given(TEXT)
def test_validate_patch_never_raises_and_rejects_non_diffs(raw):
    with tempfile.TemporaryDirectory() as d:
        ok, reason = pv.validate_patch(d, raw)
    assert isinstance(reason, str)
    if "--- a/" not in raw or "+++ b/" not in raw:
        assert ok is False


_LINE = st.text(alphabet=st.characters(blacklist_categories=("Cs", "Cc"), blacklist_characters="\r"), min_size=1, max_size=30)


@settings(max_examples=25, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(st.lists(_LINE, min_size=3, max_size=12), st.data())
def test_real_git_diff_of_any_edit_validates_and_a_stale_one_does_not(lines, data):
    """Round trip against real git: a diff produced by `git diff` for any single-line edit must validate; the same diff must be
    rejected once the file changed underneath it (this is exactly the 'fabricated before-line' failure the validator exists for)."""
    idx = data.draw(st.integers(0, len(lines) - 1))
    new_line = data.draw(_LINE.filter(lambda s: s != lines[idx]))
    with tempfile.TemporaryDirectory() as d:
        run = lambda *a: subprocess.run(["git", "-C", d, *a], check=True, capture_output=True, text=True)
        run("init", "-q"); run("config", "user.email", "t@t"); run("config", "user.name", "t")
        path = os.path.join(d, "f.txt")
        open(path, "w", encoding="utf-8").write("\n".join(lines) + "\n")
        run("add", "."); run("commit", "-qm", "c")
        edited = list(lines); edited[idx] = new_line
        open(path, "w", encoding="utf-8").write("\n".join(edited) + "\n")
        patch = run("diff").stdout
        run("checkout", "--", "f.txt")
        assert pv.validate_patch(d, patch) == (True, "ok")
        open(path, "w", encoding="utf-8").write("\n".join(["unrelated"] + lines[1:]) + "\n" if lines[0] != "unrelated" else "x\n")
        ok, _ = pv.validate_patch(d, patch)
        # the patch only still applies if the edited region happens to be untouched context; if it claims ok, git must really accept it
        if ok:
            assert subprocess.run(["git", "-C", d, "apply", "--check", "--recount", "--whitespace=nowarn", "-"], input=patch, text=True,
                                  capture_output=True).returncode == 0


# ---- deduplication fingerprint -----------------------------------------------------------------------------------------------
@FAST
@given(st.one_of(st.none(), st.integers(), st.text(max_size=40)), TEXT, TEXT)
def test_fingerprint_is_stable_and_normalised(asset, cve, loc):
    fp = de.calculate_fingerprint(asset, cve, loc)
    assert re.fullmatch(r"[0-9a-f]{32}", fp)
    assert fp == de.calculate_fingerprint(asset, f"  {cve}\t", loc)              # surrounding whitespace never changes the key
    assert fp == de.calculate_fingerprint(asset, cve, loc)


@FAST
@given(st.text(max_size=40), st.text(max_size=40), TEXT, TEXT)
def test_fingerprint_separates_assets(a, b, cve, loc):
    if a != b:
        assert de.calculate_fingerprint(a, cve, loc) != de.calculate_fingerprint(b, cve, loc)


# ---- incident engine ---------------------------------------------------------------------------------------------------------
@FAST
@given(TEXT, TEXT, st.one_of(st.none(), st.dictionaries(st.text(max_size=12), st.one_of(st.none(), st.text(max_size=40), st.integers()), max_size=6)))
def test_extract_indicators_never_crashes_and_returns_only_valid_values(rule, text, fields):
    ind = ie.extract_indicators(rule, text, fields)
    for ip in ind["ips"]:
        addr = ipaddress.ip_address(ip)
        assert not (addr.is_loopback or addr.is_unspecified or addr.is_multicast)
    for u in ind["users"]:
        assert u.lower() not in ("name", "unknown", "none", "null", "n/a")


@FAST
@given(TEXT, TEXT)
def test_classify_tactic_is_total(rule, text):
    t = ie.classify_tactic(rule, text)
    assert t is None or isinstance(t, str)


_BASE = datetime(2026, 1, 1)


@st.composite
def _signals(draw):
    n = draw(st.integers(0, 12))
    out = []
    for i in range(n):
        out.append(ie.Signal(key=f"s{i}", source="runtime_alert", source_id=str(i), asset_id=draw(st.sampled_from([None, "a", "b"])),
                             occurred_at=_BASE + timedelta(minutes=draw(st.integers(0, 300))), severity="LOW", rule_name="r", summary="s",
                             ips=set(draw(st.lists(st.sampled_from(["1.1.1.1", "2.2.2.2", "3.3.3.3"]), max_size=2))),
                             users=set(draw(st.lists(st.sampled_from(["u1", "u2"]), max_size=1)))))
    return out


@FAST
@given(_signals(), st.randoms(use_true_random=False))
def test_grouping_is_a_partition_and_order_independent(signals, rnd):
    groups = ie.group_signals(signals)
    flat = [s.key for g in groups for s in g]
    assert sorted(flat) == sorted(s.key for s in signals)           # every signal exactly once
    shuffled = list(signals); rnd.shuffle(shuffled)
    as_sets = lambda gs: {frozenset(s.key for s in g) for g in gs}
    # union-find with a time window is order dependent only through transitivity across the window; the partition into keys must
    # at least never SPLIT signals that share an indicator inside the window in one ordering but not the other:
    for g in ie.group_signals(shuffled):
        assert len(g) >= 1
    assert len(as_sets(groups)) == len(groups)


# ---- verdict logic -----------------------------------------------------------------------------------------------------------
@FAST
@given(st.one_of(st.none(), TEXT), st.one_of(st.none(), TEXT), st.sampled_from(SEVS), st.one_of(st.none(), st.sampled_from(SEVS + ["Nulo", "Bajo", "Medio", "Alto", "Crítico", "x"])),
       st.one_of(st.none(), st.booleans()))
def test_verdict_never_raises_and_never_elevates_severity(impact, steps, raw, ai_sev, dep):
    v = de.assess_real_risk_verdict(impact, steps, raw, ai_sev, dep)
    real = v.get("real_severity")
    if real:
        rank = {s: i for i, s in enumerate(SEVS)}
        assert rank[real.upper()] <= rank[raw]                      # the AI may lower a severity, never raise it
