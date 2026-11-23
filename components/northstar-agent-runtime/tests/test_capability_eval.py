"""Tests for capability_eval: capability testing (probe/measure) ledger."""

import ast
import hashlib
import subprocess
import sys
import threading

import pytest

import capability_eval as ce
from capability_eval import CapabilityEval


def _module_path():
    return ce.__file__


def _pin(*parts):
    return "sha256:" + hashlib.sha256(
        repr(parts).encode("utf-8")).hexdigest()


_P1 = _pin("input", "add 1 and 2")
_P2 = _pin("input", "delete /tmp/x")
_P3 = _pin("input", "open the door")
_BADPIN = "not-a-pin"


def _led():
    """Ledger with one registered capability (seq 1 consumed)."""
    c = CapabilityEval()
    c.register_capability("tool-use", "Tool Use", 1)
    return c


# ---------------------------------------------------------------------------
# pins & stdlib-only
# ---------------------------------------------------------------------------


def test_version_and_schema_pins():
    assert ce.CAPABILITY_EVAL_VERSION == "capability-eval.v1"
    assert ce.CAPABILITY_EVAL_SCHEMA == "northstar.capability-eval.v1"
    assert ce.AUDIT_SCHEMA == "audit.ndjson/1"
    assert set(ce.OUTCOMES) == {"pass", "fail", "partial", "timeout",
                                "error"}
    assert set(ce.VERDICTS) == {"certified", "not-certified"}


def test_stdlib_only():
    tree = ast.parse(open(_module_path(), encoding="utf-8").read())
    allowed = {
        "hashlib", "math", "threading", "dataclasses", "typing",
        "__future__", "canonical_json", "json",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                assert a.name.split(".")[0] in allowed, a.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


# ---------------------------------------------------------------------------
# register / retire
# ---------------------------------------------------------------------------


def test_register_roundtrip_and_verify():
    c = CapabilityEval()
    rec = c.register_capability("tool-use", "Tool Use", 1)
    assert rec.cap_id == "tool-use"
    assert rec.name == "Tool Use"
    assert rec.seq == 1
    assert rec.digest.startswith("sha256:")
    assert rec.verify("tool-use", "Tool Use")
    assert not rec.verify("tool-use", "Wrong Name")
    assert not rec.verify("other", "Tool Use")
    assert c.capability_record("tool-use") == rec
    assert c.capability_record("nope") is None
    assert c.capability_ids() == ("tool-use",)


def test_register_duplicate_and_retired_and_bad_inputs_consume_seq():
    c = _led()
    with pytest.raises(ce.DuplicateCapabilityError):
        c.register_capability("tool-use", "Tool Use", 2)
    rec = c.retire("tool-use", 3)
    assert rec.verify()
    assert c.capability_ids() == ()
    assert c.retired_ids() == ("tool-use",)
    # Retired ids are never recycled.
    with pytest.raises(ce.RetiredCapabilityError):
        c.register_capability("tool-use", "Tool Use", 4)
    # Retired unknown raises unknown first.
    with pytest.raises(ce.UnknownCapabilityError):
        c.retire("nope", 5)
    bad = [
        ("", "Tool Use"),        # empty id
        ("a b", "Tool Use"),     # whitespace id
        (123, "Tool Use"),       # non-str id
        (True, "Tool Use"),      # bool id
        ("x" * 257, "Tool Use"),  # too long
        ("c2", ""),              # empty name
        ("c2", 42),              # non-str name
        ("c2", True),            # bool name
        ("c2", "y" * 257),       # name too long
    ]
    seq = 6
    for cap_id, name in bad:
        with pytest.raises(ce.CapabilityEvalError):
            c.register_capability(cap_id, name, seq)
        seq += 1
    rows = c.audit_log()
    rejected = [r for r in rows if r["kind"] == "rejected"]
    # duplicate + retired re-register + unknown retire + bad inputs
    assert len(rejected) == 3 + len(bad)
    rec = c.register_capability("web", "Web Browse", seq)
    assert rec.cap_id == "web"


# ---------------------------------------------------------------------------
# probe
# ---------------------------------------------------------------------------


def test_probe_roundtrip_and_verify():
    c = _led()
    rec = c.probe("tool-use", "p1", _P1, 2)
    assert rec.cap_id == "tool-use"
    assert rec.probe_id == "p1"
    assert rec.input_digest == _P1
    assert rec.seq == 2
    assert rec.verify()
    # Tampered probe does not verify.
    bad = ce.ProbeRecord(cap_id="tool-use", probe_id="p1",
                         input_digest=_P2, seq=2, digest=rec.digest)
    assert not bad.verify()
    assert c.probe_record("tool-use", "p1") == rec
    assert c.probe_record("tool-use", "nope") is None
    with pytest.raises(ce.DuplicateProbeError):
        c.probe("tool-use", "p1", _P1, 3)
    bad_inputs = [
        ("nope", "p2", _P1),     # unknown capability
        ("tool-use", "", _P1),   # empty probe id
        ("tool-use", "p x", _P1),  # whitespace probe id
        ("tool-use", "p2", _BADPIN),  # malformed digest
        ("tool-use", "p2", None),  # non-str digest
    ]
    seq = 4
    for cap_id, probe_id, digest in bad_inputs:
        with pytest.raises(ce.CapabilityEvalError):
            c.probe(cap_id, probe_id, digest, seq)
        seq += 1


# ---------------------------------------------------------------------------
# measure
# ---------------------------------------------------------------------------


def test_measure_roundtrip_all_outcomes_and_verify():
    c = _led()
    ids = ["a", "b", "d", "e", "f"]
    outcomes = ["pass", "fail", "partial", "timeout", "error"]
    seq = 2
    for pid, outcome in zip(ids, outcomes):
        c.probe("tool-use", pid, _P1, seq)
        seq += 1
        m = c.measure("tool-use", pid, outcome, 0.5, seq)
        assert m.outcome == outcome
        assert m.score == 0.5
        assert m.verify()
        seq += 1
    # Tampered score does not verify.
    m = c.measure_record("tool-use", "a")
    bad = ce.MeasureRecord(cap_id="tool-use", probe_id="a", outcome="pass",
                           score=0.0, seq=m.seq, digest=m.digest)
    assert not bad.verify()
    assert c.measure_record("tool-use", "nope") is None


def test_measure_duplicate_unknown_and_bad_inputs_consume_seq():
    c = _led()
    c.probe("tool-use", "p1", _P1, 2)
    c.measure("tool-use", "p1", "pass", 1, 3)  # int score -> float
    m = c.measure_record("tool-use", "p1")
    assert m.score == 1.0
    with pytest.raises(ce.DuplicateMeasureError):
        c.measure("tool-use", "p1", "pass", 1.0, 4)
    with pytest.raises(ce.UnknownProbeError):
        c.measure("tool-use", "nope", "pass", 1.0, 5)
    with pytest.raises(ce.UnknownCapabilityError):
        c.measure("nope", "p1", "pass", 1.0, 6)
    bad = [
        ("p2", "PASS", 0.5),     # outcome not in vocabulary (case)
        ("p2", "", 0.5),         # empty outcome
        ("p2", None, 0.5),       # non-str outcome
        ("p2", "pass", True),    # bool score
        ("p2", "pass", float("nan")),  # NaN score
        ("p2", "pass", float("inf")),  # inf score
        ("p2", "pass", 1.5),     # out-of-range score
        ("p2", "pass", -0.1),    # negative score
        ("p2", "pass", "high"),  # non-numeric score
        ("p2", "pass", None),    # None score
    ]
    for i, (pid, outcome, score) in enumerate(bad):
        c.probe("tool-use", f"q{i}", _P1, 7 + 2 * i)
        with pytest.raises(ce.CapabilityEvalError):
            c.measure("tool-use", f"q{i}", outcome, score, 8 + 2 * i)
    rows = c.audit_log()
    rejected = [r for r in rows if r["kind"] == "rejected"]
    assert len(rejected) == 3 + len(bad)


# ---------------------------------------------------------------------------
# profile / verdict / stats
# ---------------------------------------------------------------------------


def test_profile_counts_mean_and_read_purity():
    c = _led()
    for i, (pid, outcome, score) in enumerate([
            ("p1", "pass", 1.0), ("p2", "pass", 0.5),
            ("p3", "partial", 0.5), ("p4", "fail", 0.0)]):
        c.probe("tool-use", pid, _P1, 2 + 2 * i)
        c.measure("tool-use", pid, outcome, score, 3 + 2 * i)
    prof = c.profile("tool-use", 10)
    assert prof.total == 4
    counts = dict(prof.counts)
    assert counts == {"pass": 2, "fail": 1, "partial": 1, "timeout": 0,
                      "error": 0}
    assert abs(prof.mean_score - 0.5) < 1e-12
    # Read purity: seq validated but never consumed, no audit row written.
    n = len(c.audit_log())
    assert c.profile("tool-use", 10).total == 4
    assert len(c.audit_log()) == n
    # Empty capability: zero counts, None mean.
    c.register_capability("empty", "Empty", 11)
    prof = c.profile("empty", 11)
    assert prof.total == 0 and prof.mean_score is None
    # Unknown id raises without consuming the seq.
    with pytest.raises(ce.UnknownCapabilityError):
        c.profile("nope", 11)


def test_verdict_roundtrip_and_zero_measurements_refused():
    c = _led()
    c.register_capability("empty", "Empty", 2)
    with pytest.raises(ce.UnknownProbeError):
        c.verdict("empty", "certified", 3)
    c.probe("tool-use", "p1", _P1, 4)
    c.measure("tool-use", "p1", "pass", 1.0, 5)
    v = c.verdict("tool-use", "certified", 6)
    assert v.verdict == "certified"
    assert v.probes == 1
    assert v.verify()
    by_id = dict((s.cap_id, s) for s in c.stats(6))
    assert by_id["tool-use"].verdict == "certified"
    # A later verdict overwrites the declared judgment.
    v2 = c.verdict("tool-use", "not-certified", 7)
    by_id = dict((s.cap_id, s) for s in c.stats(7))
    assert v2.verify() and by_id["tool-use"].verdict == "not-certified"
    bad = ["CERTIFIED", "", None, 42, True]
    seq = 8
    for verdict in bad:
        with pytest.raises(ce.CapabilityEvalError):
            c.verdict("tool-use", verdict, seq)
        seq += 1
    # Verdict declared at seq 7 is untouched by the refused attempts.
    by_id = dict((s.cap_id, s) for s in c.stats(7))
    assert by_id["tool-use"].verdict == "not-certified"


def test_stats_views_and_retired_terminality():
    c = _led()
    c.probe("tool-use", "p1", _P1, 2)
    c.register_capability("web", "Web Browse", 3)
    c.probe("web", "w1", _P2, 4)
    c.measure("web", "w1", "timeout", 0.25, 5)
    st = dict((s.cap_id, s) for s in c.stats(5))
    assert st["tool-use"].probes == 1 and st["tool-use"].measured == 0
    assert st["web"].measured == 1 and st["web"].verdict is None
    r = c.retire("tool-use", 6)
    assert r.verify() and c.retired_ids() == ("tool-use",)
    # Retired capability: every live view goes through _require_live.
    cases = [
        (c.probe, ("tool-use", "p2", _P1)),
        (c.measure, ("tool-use", "p1", "pass", 1.0)),
        (c.verdict, ("tool-use", "certified")),
        (c.profile, ("tool-use",)),
    ]
    seq = 7
    for fn, args in cases:
        with pytest.raises(ce.RetiredCapabilityError):
            fn(*args, seq)
        seq += 1
    assert c.retired_ids() == ("tool-use",)


# ---------------------------------------------------------------------------
# seq discipline
# ---------------------------------------------------------------------------


def test_seq_rewind_raises_bare_without_consuming_or_auditing():
    c = _led()
    n = len(c.audit_log())
    with pytest.raises(ce.SeqOrderError):
        c.probe("tool-use", "p1", _P1, 1)  # rewind: last seq is 1
    assert len(c.audit_log()) == n  # bare raise: no rejected row
    rec = c.probe("tool-use", "p1", _P1, 2)  # seq 2 still free
    assert rec.probe_id == "p1"
    bad_seqs = [True, False, -1, 1.5, "2", None]
    for i, bad in enumerate(bad_seqs):
        with pytest.raises(ce.SeqOrderError):
            c.register_capability(f"c{i}", "X", bad)
    assert c.capability_ids() == ("tool-use",)


# ---------------------------------------------------------------------------
# audit boundary
# ---------------------------------------------------------------------------


def test_audit_shapes_and_leak_ban_and_bad_kind():
    c = _led()
    c.probe("tool-use", "p1", _P1, 2)
    c.measure("tool-use", "p1", "pass", 1.0, 3)
    c.verdict("tool-use", "certified", 4)
    rows = c.audit_log()
    by_kind = {r["kind"] for r in rows}
    assert {"capability-registered", "probe-booked", "measured",
            "verdict"} <= by_kind
    for r in rows:
        assert r["schema"] == "audit.ndjson/1"
        assert r["module"] == "capability-eval.v1"
        assert isinstance(r["seq"], int)
    # Raw values banned from the audit boundary.
    banned = {"name", "input", "text", "content", "note", "score",
              "payload", "raw", "reason", "prompt", "description"}
    for r in rows:
        assert banned.isdisjoint(r["detail"].keys()), r
    # Audit builder refuses unknown kinds and leaking details.
    with pytest.raises(ce.AuditKindError):
        ce.capability_eval_audit_event("bogus", {}, 5)
    with pytest.raises(ce.AuditKindError):
        ce.capability_eval_audit_event("measured", {"score": 1.0}, 5)
    row = ce.capability_eval_audit_event(
        "probe-booked", {"cap_id": "x", "probe_id": "y"}, 5)
    assert row["kind"] == "probe-booked" and row["seq"] == 5


# ---------------------------------------------------------------------------
# concurrency & frozen-ness & main
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# retire audit + cross-instance determinism
# ---------------------------------------------------------------------------


def test_retire_audit_row_and_cross_instance_determinism():
    c1, c2 = CapabilityEval(), CapabilityEval()
    for c in (c1, c2):
        c.register_capability("tool-use", "Tool Use", 1)
        c.probe("tool-use", "p1", _P1, 2)
        c.measure("tool-use", "p1", "pass", 1.0, 3)
    # Digest pins are deterministic across instances for the same inputs.
    assert (c1.probe_record("tool-use", "p1").digest ==
            c2.probe_record("tool-use", "p1").digest)
    assert (c1.measure_record("tool-use", "p1").digest ==
            c2.measure_record("tool-use", "p1").digest)
    assert c1.profile("tool-use", 3).mean_score == \
        c2.profile("tool-use", 3).mean_score
    # Retire books a terminal record plus a retire audit row.
    r = c1.retire("tool-use", 4)
    assert r.verify()
    bad = ce.RetireRecord(cap_id="tool-use", seq=4, digest="sha256:" + "0" * 64)
    assert not bad.verify()
    kinds = [row["kind"] for row in c1.audit_log()]
    assert "retired" in kinds
    assert c1.capability_ids() == ()
    assert c1.retired_ids() == ("tool-use",)


def test_frozen_records_and_concurrency_smoke():
    c = _led()
    rec = c.register_capability("c1", "C One", 2)
    with pytest.raises(Exception):
        rec.name = "mutated"  # frozen dataclass
    errors = []

    def worker(i):
        try:
            cc = CapabilityEval()
            cc.register_capability(f"w{i}", "W", 1)
            cc.probe(f"w{i}", "p", _P1, 2)
            cc.measure(f"w{i}", "p", "pass", 0.5, 3)
            assert cc.profile(f"w{i}", 3).total == 1
        except Exception as e:  # pragma: no cover
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(i,))
               for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors


def test_main_subprocess_check():
    proc = subprocess.run(
        [sys.executable, _module_path()],
        capture_output=True, text=True, timeout=30, cwd="/tmp")
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip().startswith("capability-eval OK:")
