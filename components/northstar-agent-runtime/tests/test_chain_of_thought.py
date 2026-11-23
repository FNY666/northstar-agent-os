"""Tests for chain_of_thought: reasoning (reason/trace) ledger."""

import ast
import hashlib
import subprocess
import sys
import threading

import pytest

import chain_of_thought as cot
from chain_of_thought import ChainOfThought


def _module_path():
    return cot.__file__


def _pin(*parts):
    return "sha256:" + hashlib.sha256(
        repr(parts).encode("utf-8")).hexdigest()


_Q = _pin("question", "why")
_R1 = _pin("rationale", "step one")
_R2 = _pin("rationale", "step two")
_A = _pin("answer", "the answer")


# ---------------------------------------------------------------------------
# pins & stdlib-only
# ---------------------------------------------------------------------------


def test_version_and_schema_pins():
    assert cot.CHAIN_OF_THOUGHT_VERSION == "chain-of-thought.v1"
    assert cot.CHAIN_OF_THOUGHT_SCHEMA == "northstar.chain-of-thought.v1"
    assert cot.AUDIT_SCHEMA == "audit.ndjson/1"


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
# begin
# ---------------------------------------------------------------------------


def test_begin_roundtrip_and_verify():
    c = ChainOfThought()
    rec = c.begin("chain-1", _Q, 1)
    assert rec.chain_id == "chain-1"
    assert rec.question_digest == _Q
    assert rec.seq == 1
    assert rec.digest.startswith("sha256:")
    assert rec.verify("chain-1", _Q)
    assert not rec.verify("chain-1", _R1)
    assert not rec.verify("chain-2", _Q)
    assert c.chain_record("chain-1") == rec
    assert c.chain_record("nope") is None
    assert c.chain_ids() == ("chain-1",)


def test_begin_duplicate_and_bad_inputs_consume_seq_and_audit_rejected():
    c = ChainOfThought()
    c.begin("chain-1", _Q, 1)
    # Duplicate id refused; the seq is burned.
    with pytest.raises(cot.DuplicateChainError):
        c.begin("chain-1", _Q, 2)
    # Bad input table: every branch must burn its seq.
    bad = [
        ("", _Q),            # empty id
        ("  ", _Q),          # whitespace id
        (123, _Q),           # non-str id
        (True, _Q),          # bool id
        ("x" * 257, _Q),     # too long
        ("c2", "not-a-pin"),  # malformed digest
        ("c2", "sha256:" + "z" * 64),  # non-hex body
        ("c2", None),        # non-str digest
    ]
    seq = 3
    for chain_id, digest in bad:
        with pytest.raises(cot.ChainOfThoughtError):
            c.begin(chain_id, digest, seq)
        seq += 1
    rows = c.audit_log()
    rejected = [r for r in rows if r["kind"] == "rejected"]
    assert len(rejected) == 1 + len(bad)
    # Next legal seq continues after the burned ones.
    rec = c.begin("chain-2", _Q, seq)
    assert rec.chain_id == "chain-2"


# ---------------------------------------------------------------------------
# reason
# ---------------------------------------------------------------------------


def test_reason_roundtrip_and_hash_link():
    c = ChainOfThought()
    ch = c.begin("chain-1", _Q, 1)
    s1 = c.reason("chain-1", _R1, 0.8, 2)
    assert s1.step_no == 1
    assert s1.rationale_digest == _R1
    assert s1.confidence == 0.8
    assert s1.prev_digest == ch.digest
    assert s1.digest.startswith("sha256:")
    assert s1.verify()
    s2 = c.reason("chain-1", _R2, 1, 3)  # int confidence accepted as float
    assert s2.step_no == 2
    assert s2.confidence == 1.0
    assert s2.prev_digest == s1.digest
    assert s2.verify()
    tr = c.trace("chain-1", 3)
    assert [s[0] for s in tr.steps] == [1, 2]
    assert tr.steps[0][1] == _R1 and tr.steps[1][1] == _R2


def test_reason_bad_inputs_consume_seq():
    c = ChainOfThought()
    c.begin("chain-1", _Q, 1)
    c.begin("chain-2", _Q, 2)
    c.conclude  # touch attribute; conclusion comes later on chain-1
    bad = [
        ("nope", _R1, 0.5),          # unknown chain
        ("chain-1", "bad-pin", 0.5),  # malformed digest
        ("chain-1", _R1, True),      # bool confidence
        ("chain-1", _R1, float("nan")),  # non-finite
        ("chain-1", _R1, float("inf")),  # non-finite
        ("chain-1", _R1, 1.5),       # out of range
        ("chain-1", _R1, "high"),    # non-numeric
    ]
    seq = 3
    for chain_id, digest, conf in bad:
        with pytest.raises(cot.ChainOfThoughtError):
            c.reason(chain_id, digest, conf, seq)
        seq += 1
    rejected = [r for r in c.audit_log() if r["kind"] == "rejected"]
    assert len(rejected) == len(bad)
    # Reason on a concluded chain is refused (conclude chain-1 first).
    c.reason("chain-1", _R1, 0.5, seq)
    c.conclude("chain-1", _A, seq + 1)
    with pytest.raises(cot.ConcludedChainError):
        c.reason("chain-1", _R2, 0.5, seq + 2)


# ---------------------------------------------------------------------------
# conclude
# ---------------------------------------------------------------------------


def test_conclude_roundtrip_and_terminality():
    c = ChainOfThought()
    c.begin("chain-1", _Q, 1)
    s = c.reason("chain-1", _R1, 0.7, 2)
    rec = c.conclude("chain-1", _A, 3)
    assert rec.steps == 1
    assert rec.head_digest == s.digest
    assert rec.verify("chain-1", _A, 1, s.digest)
    assert not rec.verify("chain-1", _A, 1, _R1)
    assert c.conclusion_record("chain-1") == rec
    assert c.conclusion_record("chain-2") is None
    assert c.trace("chain-1", 3).concluded
    # A second conclusion is refused and burns its seq.
    with pytest.raises(cot.ConcludedChainError):
        c.conclude("chain-1", _A, 4)
    # Concluding an empty chain is refused.
    c.begin("chain-2", _Q, 5)
    with pytest.raises(cot.EmptyChainError):
        c.conclude("chain-2", _A, 6)
    # Concluding an unknown chain is refused.
    with pytest.raises(cot.UnknownChainError):
        c.conclude("nope", _A, 7)


# ---------------------------------------------------------------------------
# trace / verify (pure reads)
# ---------------------------------------------------------------------------


def test_trace_pure_read_semantics():
    c = ChainOfThought()
    c.begin("chain-1", _Q, 1)
    c.reason("chain-1", _R1, 0.5, 2)
    # Same seq twice is fine; reads consume nothing and book no rows.
    t1 = c.trace("chain-1", 2)
    t2 = c.trace("chain-1", 2)
    assert t1 == t2
    assert len(t1.steps) == 1
    assert not t1.concluded
    kinds = [r["kind"] for r in c.audit_log()]
    assert "chain-begun" in kinds and "step-reasoned" in kinds
    assert len(kinds) == 2  # no audit rows from the reads
    with pytest.raises(cot.UnknownChainError):
        c.trace("nope", 2)
    with pytest.raises(cot.SeqOrderError):
        c.trace("chain-1", "two")


def test_verify_integrity_and_tamper_as_data():
    c = ChainOfThought()
    c.begin("chain-1", _Q, 1)
    s1 = c.reason("chain-1", _R1, 0.8, 2)
    s2 = c.reason("chain-1", _R2, 0.9, 3)
    v = c.verify("chain-1", 3)
    assert v.ok and v.steps == 2 and v.head_digest == s2.digest
    # A forged step (wrong prev link) does not verify: tamper as data.
    forged = cot.StepRecord(
        chain_id="chain-1", step_no=1, rationale_digest=_R1,
        confidence=0.8, prev_digest="sha256:" + "0" * 64,
        seq=2, digest=s1.digest)
    assert not forged.verify()
    # Record-level chain verify catches a wrong question digest.
    ch = c.chain_record("chain-1")
    assert not ch.verify("chain-1", _R2)
    with pytest.raises(cot.UnknownChainError):
        c.verify("nope", 3)


# ---------------------------------------------------------------------------
# seq discipline
# ---------------------------------------------------------------------------


def test_seq_discipline_rewind_bare_no_consumption():
    c = ChainOfThought()
    c.begin("chain-1", _Q, 5)
    # Rewind raises bare and consumes nothing.
    with pytest.raises(cot.SeqOrderError):
        c.begin("chain-2", _Q, 5)
    with pytest.raises(cot.SeqOrderError):
        c.begin("chain-2", _Q, 3)
    assert len([r for r in c.audit_log() if r["kind"] == "rejected"]) == 0
    # Malformed seqs refused on reads too (no consumption concept).
    for bad_seq in (True, -1, 1.5, "7", None):
        with pytest.raises(cot.SeqOrderError):
            c.trace("chain-1", bad_seq)
    # Legal continuation works.
    c.begin("chain-2", _Q, 6)
    assert c.chain_ids() == ("chain-1", "chain-2")


# ---------------------------------------------------------------------------
# audit boundary
# ---------------------------------------------------------------------------


def test_audit_shapes_ban_and_bad_kind():
    c = ChainOfThought()
    c.begin("chain-1", _Q, 1)
    c.reason("chain-1", _R1, 0.5, 2)
    c.conclude("chain-1", _A, 3)
    rows = c.audit_log()
    assert [r["kind"] for r in rows] == [
        "chain-begun", "step-reasoned", "concluded"]
    for r in rows:
        assert r["schema"] == "audit.ndjson/1"
        assert r["module"] == "chain-of-thought.v1"
        assert r["seq"] in (1, 2, 3)
        detail_text = repr(r["detail"])
        # No raw reasoning content may cross the boundary.
        assert "why" not in detail_text.lower()
    # Banned detail keys are refused by the builder.
    with pytest.raises(cot.AuditKindError):
        cot.chain_of_thought_audit_event(
            "chain-begun", {"rationale": "secret"}, 9)
    with pytest.raises(cot.AuditKindError):
        cot.chain_of_thought_audit_event(
            "step-reasoned", {"question": "secret"}, 9)
    # Unknown kind refused.
    with pytest.raises(cot.AuditKindError):
        cot.chain_of_thought_audit_event("nope", {}, 9)


# ---------------------------------------------------------------------------
# determinism / views / concurrency
# ---------------------------------------------------------------------------


def test_cross_instance_determinism():
    def build():
        x = ChainOfThought()
        x.begin("c", _Q, 1)
        x.reason("c", _R1, 0.25, 2)
        x.reason("c", _R2, 0.75, 3)
        x.conclude("c", _A, 4)
        return x

    a, b = build(), build()
    assert a.trace("c", 4).steps == b.trace("c", 4).steps
    assert a.conclusion_record("c").digest == b.conclusion_record("c").digest
    assert a.verify("c", 4).head_digest == b.verify("c", 4).head_digest


def test_views_stats_and_frozen_records():
    c = ChainOfThought()
    c.begin("b-chain", _Q, 1)
    c.begin("a-chain", _Q, 2)
    c.reason("a-chain", _R1, 0.5, 3)
    stats = {s.chain_id: s for s in c.stats(3)}
    assert stats["a-chain"].steps == 1 and not stats["a-chain"].concluded
    assert stats["b-chain"].steps == 0
    assert c.chain_ids() == ("a-chain", "b-chain")
    # Frozen dataclasses.
    rec = c.chain_record("a-chain")
    with pytest.raises(Exception):
        rec.seq = 99  # type: ignore[misc]
    step = c.trace("a-chain", 3).steps[0]
    assert step[2] == 0.5  # confidence survives the roundtrip


def test_concurrency_smoke():
    c = ChainOfThought()
    c.begin("shared", _Q, 1)
    errors = []

    def worker(n):
        try:
            c.reason("shared", _R1, 0.5, 2 + n)
        except Exception as e:  # noqa: BLE001 - smoke test collects
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(n,))
                for n in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    # Exactly one thread wins each seq; no lost updates, no corruption.
    real = c.trace("shared", 100)
    assert len(real.steps) + len(errors) == 8
    assert c.verify("shared", 100).ok


# ---------------------------------------------------------------------------
# main()
# ---------------------------------------------------------------------------


def test_main_subprocess():
    proc = subprocess.run(
        [sys.executable, _module_path()],
        capture_output=True, text=True, timeout=30)
    assert proc.returncode == 0, proc.stderr
    assert "chain-of-thought OK" in proc.stdout
