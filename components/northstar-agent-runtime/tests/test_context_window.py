"""15 targeted tests for context_window (token-budget ledger over message windows)."""

import ast
import subprocess
import sys

import pytest

import context_window as cw
from context_window import ContextWindow


def test_version_and_schema_pins():
    assert cw.CONTEXT_WINDOW_VERSION == "context-window.v1"
    assert cw.CONTEXT_WINDOW_SCHEMA == "northstar.context-window.v1"
    assert cw.AUDIT_SCHEMA == "audit.ndjson/1"
    assert cw.ESTIMATOR_VERSION == "tok-est.v1"
    kinds = {cw.KIND_BUDGET, cw.KIND_APPENDED, cw.KIND_TRIMMED, cw.KIND_CLOSED, cw.KIND_REJECTED}
    assert kinds.issubset(cw._KINDS)


def test_stdlib_only():
    tree = ast.parse(open(cw.__file__).read())
    allowed = {"hashlib", "threading", "dataclasses", "typing", "__future__",
               "canonical_json", "json"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed, alias.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


def test_budget_create_and_update():
    ledger = ContextWindow()
    rec = ledger.budget("chat", 100, 1)
    assert rec.verify()
    assert rec.window_id == "chat" and rec.capacity == 100
    assert rec.estimator_version == cw.ESTIMATOR_VERSION
    assert ledger.window_ids() == ("chat",)
    assert ledger.active_ids() == ("chat",)
    assert ledger.capacity("chat") == 100
    # re-declare books a new record (capacity change history)
    rec2 = ledger.budget("chat", 50, 2)
    assert rec2.verify() and rec2.capacity == 50 and rec2.digest != rec.digest
    assert ledger.capacity("chat") == 50


def test_budget_bad_inputs_fail_closed_and_burn_seq():
    ledger = ContextWindow()
    bad = [
        ("", 10), ("  ", 10), (123, 10), (None, 10), ("w", 0), ("w", -5),
        ("w", True), ("w", 1.5), ("w", "100"), ("w", 2**54), ("w" * 300, 10),
    ]
    seq = 1
    for window_id, capacity in bad:
        with pytest.raises(cw.ContextWindowError):
            ledger.budget(window_id, capacity, seq)
        seq += 1
    rejected = [e for e in ledger.audit_log() if e["kind"] == cw.KIND_REJECTED]
    assert len(rejected) == len(bad)
    # every failed mutation consumed its seq: next fresh seq works
    rec = ledger.budget("good", 10, seq)
    assert rec.verify()


def test_estimator_deterministic():
    assert cw.estimate_tokens("") == 0
    assert cw.estimate_tokens("abcd") == 1      # 4 bytes -> 1 token
    assert cw.estimate_tokens("hello") == 2     # 5 bytes -> 2 tokens
    assert cw.estimate_tokens("x" * 40) == 10
    # multibyte: byte length drives the count
    assert cw.estimate_tokens("é" * 4) == 2     # 8 bytes -> 2 tokens
    # cross-instance determinism
    a, b = ContextWindow(), ContextWindow()
    a.budget("w", 1000, 1); b.budget("w", 1000, 1)
    ra = a.append("w", "m", "same text here", 2)
    rb = b.append("w", "m", "same text here", 2)
    assert ra.token_count == rb.token_count == cw.estimate_tokens("same text here")
    assert ra.text_digest == rb.text_digest
    with pytest.raises(cw.BadTextError):
        cw.estimate_tokens(123)
    with pytest.raises(cw.BadTextError):
        cw.estimate_tokens("x" * (cw._MAX_TEXT_LEN + 1))


def test_append_roundtrip_and_verify():
    ledger = ContextWindow()
    ledger.budget("chat", 100, 1)
    rec = ledger.append("chat", "m1", "hello world", 2, role=cw.ROLE_ASSISTANT)
    assert rec.verify()
    assert rec.token_count == cw.estimate_tokens("hello world")
    assert rec.text_digest.startswith("sha256:")
    assert rec.role == cw.ROLE_ASSISTANT
    # raw text is never retained in the record fields
    for field_value in (rec.window_id, rec.block_id, rec.role, rec.text_digest, rec.digest):
        assert "hello world" not in str(field_value)
    stored = ledger.block_record("chat", "m1")
    assert stored is not None and stored.digest == rec.digest
    assert ledger.block_record("chat", "nope") is None
    assert ledger.block_record("nope", "m1") is None
    assert ledger.live_block_ids("chat") == ("m1",)
    assert ledger.evicted_block_ids("chat") == ()


def test_append_bad_inputs_fail_closed():
    ledger = ContextWindow()
    ledger.budget("chat", 100, 1)
    ledger.append("chat", "m1", "hi", 2)
    seq = 3
    with pytest.raises(cw.UnknownWindowError):
        ledger.append("ghost", "m", "hi", 3)
    with pytest.raises(cw.DuplicateBlockError):
        ledger.append("chat", "m1", "hi again", 4)
    with pytest.raises(cw.BadRoleError):
        ledger.append("chat", "m2", "hi", 5, role="narrator")
    with pytest.raises(cw.BadTextError):
        ledger.append("chat", "m2", None, 6)
    with pytest.raises(cw.BadBlockError):
        ledger.append("chat", "", "hi", 7)
    rejected = [e for e in ledger.audit_log() if e["kind"] == cw.KIND_REJECTED]
    assert len(rejected) == 5
    # seq burn discipline holds: next fresh seq works
    rec = ledger.append("chat", "m2", "hi", 8)
    assert rec.verify()


def test_count_pure_read():
    ledger = ContextWindow()
    ledger.budget("chat", 100, 1)
    ledger.append("chat", "m1", "x" * 40, 2)   # 10 tokens
    ledger.append("chat", "m2", "y" * 39, 3)   # 10 tokens
    rep = ledger.count("chat", 4)
    assert rep.verify()
    assert rep.used == 20 and rep.capacity == 100
    assert rep.remaining == 80 and not rep.over_budget
    assert rep.live_blocks == 2
    # pure read: same seq twice is fine, no audit rows, no seq consumption
    again = ledger.count("chat", 4)
    assert again.digest == rep.digest
    assert ledger.count("chat", 99).used == 20
    assert all(e["kind"] != cw.KIND_REJECTED for e in ledger.audit_log())
    kinds = [e["kind"] for e in ledger.audit_log()]
    assert kinds == [cw.KIND_BUDGET, cw.KIND_APPENDED, cw.KIND_APPENDED]
    # unknown window is data-level refusal, never silent
    with pytest.raises(cw.UnknownWindowError):
        ledger.count("ghost", 5)
    # tiny budget reports over-budget as data
    ledger.budget("small", 5, 6)
    ledger.append("small", "m", "x" * 40, 7)
    small = ledger.count("small", 8)
    assert small.over_budget and small.remaining == -5


def test_trim_evicts_oldest_first():
    ledger = ContextWindow()
    ledger.budget("chat", 25, 1)
    ledger.append("chat", "m1", "a" * 40, 2)  # 10 tokens, oldest
    ledger.append("chat", "m2", "b" * 40, 3)  # 10 tokens
    ledger.append("chat", "m3", "c" * 40, 4)  # 10 tokens -> 30 > 25
    assert ledger.count("chat", 5).over_budget
    trim = ledger.trim("chat", 6)
    assert trim.verify()
    assert trim.evicted_ids == ("m1",), trim.evicted_ids
    assert trim.used_after == 20 and trim.used_after <= 25
    assert ledger.live_block_ids("chat") == ("m2", "m3")
    assert ledger.evicted_block_ids("chat") == ("m1",)
    assert not ledger.count("chat", 7).over_budget


def test_trim_keep_recent_and_pins():
    ledger = ContextWindow()
    ledger.budget("chat", 15, 1)
    ledger.append("chat", "sys", "s" * 20, 2, role=cw.ROLE_SYSTEM)  # 5 tokens
    ledger.append("chat", "m1", "a" * 40, 3)   # 10 tokens
    ledger.append("chat", "m2", "b" * 40, 4)   # 10 tokens -> 25 > 15
    # pin the newest: eviction takes the oldest evictable blocks first
    trim = ledger.trim("chat", 5, pin_ids=("m2",))
    assert trim.verify()
    assert trim.evicted_ids == ("sys", "m1"), trim.evicted_ids
    assert trim.used_after == 10
    assert ledger.live_block_ids("chat") == ("m2",)
    # keep_recent protects the newest even when it is the oldest evictable
    ledger2 = ContextWindow()
    ledger2.budget("w", 15, 1)
    ledger2.append("w", "a", "x" * 40, 2)
    ledger2.append("w", "b", "y" * 40, 3)
    ledger2.append("w", "c", "z" * 40, 4)
    t2 = ledger2.trim("w", 5, keep_recent=1)
    assert t2.evicted_ids == ("a", "b"), t2.evicted_ids
    assert t2.used_after == 10
    # pinning an unknown block fails closed
    with pytest.raises(cw.UnknownBlockError):
        ledger2.trim("w", 6, pin_ids=("ghost",))


def test_trim_noop_when_fits():
    ledger = ContextWindow()
    ledger.budget("chat", 100, 1)
    ledger.append("chat", "m1", "hi", 2)
    trim = ledger.trim("chat", 3)
    assert trim.verify()
    assert trim.evicted_ids == ()
    assert trim.used_after == cw.estimate_tokens("hi")
    assert ledger.live_block_ids("chat") == ("m1",)
    # still booked as a decision row
    kinds = [e["kind"] for e in ledger.audit_log()]
    assert kinds[-1] == cw.KIND_TRIMMED


def test_trim_pinned_over_capacity_fail_closed():
    ledger = ContextWindow()
    ledger.budget("chat", 5, 1)
    ledger.append("chat", "big", "x" * 40, 2)  # 10 tokens > capacity
    with pytest.raises(cw.TrimImpossibleError):
        ledger.trim("chat", 3, pin_ids=("big",))
    # rollback: block is not left half-evicted
    assert ledger.evicted_block_ids("chat") == ()
    assert ledger.live_block_ids("chat") == ("big",)
    rejected = [e for e in ledger.audit_log() if e["kind"] == cw.KIND_REJECTED]
    assert len(rejected) == 1 and rejected[0]["detail"]["error"] == "TrimImpossibleError"
    # seq was consumed: next fresh seq works on a fitting window
    ledger.budget("ok", 50, 4)
    ledger.append("ok", "m", "hi", 5)
    assert ledger.trim("ok", 6).evicted_ids == ()


def test_seq_discipline():
    ledger = ContextWindow()
    ledger.budget("chat", 100, 1)
    # rewind raises bare SeqOrderError without consuming or booking rejection
    before = len(ledger.audit_log())
    with pytest.raises(cw.SeqOrderError):
        ledger.budget("chat", 100, 1)
    with pytest.raises(cw.SeqOrderError):
        ledger.append("chat", "m", "hi", 0)
    assert len(ledger.audit_log()) == before
    for bad_seq in (True, "2", 2.0, None):
        with pytest.raises(cw.SeqOrderError):
            ledger.count("chat", bad_seq)
    # mutation seqs must keep increasing across ops
    ledger.append("chat", "m", "hi", 2)
    with pytest.raises(cw.SeqOrderError):
        ledger.trim("chat", 2)


def test_close_terminal_no_recycle():
    ledger = ContextWindow()
    ledger.budget("chat", 100, 1)
    rec = ledger.close("chat", 2, reason="turn-over")
    assert rec.verify()
    assert rec.reason == "turn-over"
    assert ledger.active_ids() == ()
    assert ledger.window_ids() == ("chat",)
    # every mutation after close refuses; the id is never recycled
    with pytest.raises(cw.RetiredWindowError):
        ledger.budget("chat", 200, 3)
    with pytest.raises(cw.RetiredWindowError):
        ledger.append("chat", "m", "hi", 4)
    with pytest.raises(cw.RetiredWindowError):
        ledger.trim("chat", 5)
    with pytest.raises(cw.RetiredWindowError):
        ledger.close("chat", 6)
    with pytest.raises(cw.UnknownWindowError):
        ledger.close("ghost", 7)
    # reads still work on the retired window
    assert ledger.count("chat", 8).used == 0


def test_audit_shapes_leak_ban_bad_kind_and_main():
    ledger = ContextWindow()
    ledger.budget("chat", 50, 1)
    ledger.append("chat", "m1", "secret text here", 2)
    ledger.trim("chat", 3)
    ledger.close("chat", 4)
    events = ledger.audit_log()
    assert [e["kind"] for e in events] == [
        cw.KIND_BUDGET, cw.KIND_APPENDED, cw.KIND_TRIMMED, cw.KIND_CLOSED,
    ]
    for e in events:
        assert e["schema"] == cw.AUDIT_SCHEMA
        blob = str(e)
        assert "secret text here" not in blob
        assert e["digest"].startswith("sha256:")
    # banned detail keys refused
    with pytest.raises(cw.AuditKindError):
        cw.context_window_audit_event(cw.KIND_BUDGET, 9, text="nope")
    with pytest.raises(cw.AuditKindError):
        cw.context_window_audit_event(cw.KIND_BUDGET, 9, message="nope")
    with pytest.raises(cw.AuditKindError):
        cw.context_window_audit_event("bogus-kind", 9)
    # main() self-check green in a subprocess
    proc = subprocess.run(
        [sys.executable, cw.__file__], capture_output=True, text=True, timeout=60
    )
    assert proc.returncode == 0, proc.stderr
    assert "context-window OK" in proc.stdout
