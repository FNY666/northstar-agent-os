"""Tests for oncall_rotation (PagerDuty-shaped on-call schedule bookkeeping)."""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

import pytest

import oncall_rotation
from oncall_rotation import (
    OverlappingOverrideError,
    OncallRotation,
    OncallRotationError,
    UnknownRotationError,
    oncall_audit_event,
)


def _fresh() -> OncallRotation:
    mgr = OncallRotation()
    mgr.create_rotation("ops", "Ops primary", seq=1)
    mgr.schedule("ops", ["a", "b", "c"], 24, seq=2)
    return mgr


def test_version_pins():
    assert oncall_rotation.ONCALL_ROTATION_VERSION == "oncall-rotation.v1"
    assert oncall_rotation.ONCALL_ROTATION_SCHEMA == "northstar.oncall-rotation.v1"
    assert oncall_rotation.AUDIT_SCHEMA == "audit.ndjson/1"
    assert set(oncall_rotation.HANDOFF_REASONS) == {
        "manual", "scheduled", "incident", "escalation"
    }


def test_stdlib_only():
    tree = ast.parse(Path(oncall_rotation.__file__).read_text())
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            imports.add(node.module.split(".")[0])
    assert imports <= {"__future__", "hashlib", "json", "threading",
                       "dataclasses", "typing"}


def test_create_roundtrip():
    mgr = OncallRotation()
    r = mgr.create_rotation("infra", "Infra", seq=1)
    assert r.verify()
    assert r.rotation_id == "infra" and r.name == "Infra"
    assert mgr.rotation("infra") is r
    assert mgr.rotation_ids() == ("infra",)


def test_create_duplicate_and_bad_inputs():
    mgr = OncallRotation()
    mgr.create_rotation("infra", "Infra", seq=1)
    with pytest.raises(OncallRotationError):
        mgr.create_rotation("infra", "Infra", seq=2)  # duplicate
    for bad in ("", "   ", None, 42):
        with pytest.raises(OncallRotationError):
            mgr.create_rotation(bad, "Infra", seq=3)  # consumed by fail, use fresh later
    # After the failures, seq 3..5 were consumed; a valid call must use a new seq.
    mgr.create_rotation("infra2", "Infra 2", seq=6)
    assert mgr.rotation_ids() == ("infra", "infra2")
    with pytest.raises(UnknownRotationError):
        mgr.rotation("nope")


def test_schedule_roundtrip_and_generation():
    mgr = OncallRotation()
    mgr.create_rotation("infra", "Infra", seq=1)
    s1 = mgr.schedule("infra", ["a", "b"], 10, seq=2)
    assert s1.verify()
    assert s1.generation == 0 and s1.current_index == 0
    assert s1.participants == ("a", "b")
    assert mgr.current("infra", at_seq=3) == "a"
    s2 = mgr.schedule("infra", ["x", "y", "z"], 20, seq=3)
    assert s2.generation == 1 and mgr.current("infra", at_seq=4) == "x"


def test_schedule_bad_inputs():
    mgr = OncallRotation()
    mgr.create_rotation("infra", "Infra", seq=1)
    bad_lists = [
        [],                                   # empty
        "abc",                                # string, not sequence of ids
        ["a", "a"],                           # duplicate
        [""],                                 # empty id
        ["a" * 1 for _ in range(51)],         # over cap
    ]
    seq = 2
    for bad in bad_lists:
        with pytest.raises(OncallRotationError):
            mgr.schedule("infra", bad, 10, seq=seq)
        seq += 1
    for bad_shift in (0, -1, True, 1.5, "10", None):
        with pytest.raises(OncallRotationError):
            mgr.schedule("infra", ["a"], bad_shift, seq=seq)
        seq += 1
    with pytest.raises(UnknownRotationError):
        mgr.schedule("ghost", ["a"], 10, seq=seq)


def test_handoff_round_robin_and_terminal_cycle():
    mgr = _fresh()
    h1 = mgr.handoff("ops", seq=3)
    assert h1.verify() and h1.from_user == "a" and h1.to_user == "b"
    assert h1.reason == "manual"
    assert mgr.current("ops", at_seq=3) == "b"
    mgr.handoff("ops", seq=4, reason="scheduled")
    mgr.handoff("ops", seq=5, reason="incident")   # c -> a wrap
    assert mgr.current("ops", at_seq=5) == "a"
    assert len(mgr.handoffs("ops")) == 3
    # Audit carries the handoff rows.
    kinds = [e["kind"] for e in mgr.audit_log()]
    assert kinds.count(oncall_rotation.KIND_HANDOFF) == 3


def test_handoff_bad_reason_and_no_schedule():
    mgr = _fresh()
    with pytest.raises(OncallRotationError):
        mgr.handoff("ops", seq=3, reason="because")
    mgr2 = OncallRotation()
    mgr2.create_rotation("bare", "Bare", seq=1)
    with pytest.raises(OncallRotationError):
        mgr2.handoff("bare", seq=2)  # no schedule layer
    with pytest.raises(UnknownRotationError):
        mgr2.handoff("ghost", seq=3)


def test_override_roundtrip_and_window_edges():
    mgr = _fresh()
    ov = mgr.override("ops", "ov-1", "dave", start_seq=8, end_seq=12, seq=3)
    assert ov.verify() and ov.user_id == "dave" and not ov.revoked
    assert mgr.current("ops", at_seq=7) == "a"    # before window
    assert mgr.current("ops", at_seq=8) == "dave"  # window start inclusive
    assert mgr.current("ops", at_seq=11) == "dave"
    assert mgr.current("ops", at_seq=12) == "a"   # end exclusive
    # Adjacent (non-overlapping) override is fine.
    ov2 = mgr.override("ops", "ov-2", "erin", start_seq=12, end_seq=20, seq=4)
    assert ov2.verify()
    assert mgr.current("ops", at_seq=12) == "erin"


def test_override_overlap_refused():
    mgr = _fresh()
    mgr.override("ops", "ov-1", "dave", start_seq=8, end_seq=12, seq=3)
    seq = 100
    for start, end in [(10, 20), (5, 9), (8, 12), (6, 20)]:
        with pytest.raises(OverlappingOverrideError):
            mgr.override("ops", f"ov-{start}-{seq}", "erin",
                         start_seq=start, end_seq=end, seq=seq)
        seq += 1
    # Bad windows.
    with pytest.raises(OncallRotationError):
        mgr.override("ops", "ov-bad", "erin", start_seq=10, end_seq=10, seq=200)
    with pytest.raises(OncallRotationError):
        mgr.override("ops", "ov-bad2", "erin", start_seq=12, end_seq=9, seq=201)
    with pytest.raises(OncallRotationError):
        mgr.override("ops", "ov-bad3", "", start_seq=30, end_seq=40, seq=202)


def test_override_revoke_terminality():
    mgr = _fresh()
    mgr.override("ops", "ov-1", "dave", start_seq=8, end_seq=12, seq=3)
    rv = mgr.revoke_override("ops", "ov-1", seq=4)
    assert rv.verify() and rv.revoked
    assert rv.override_id == "ov-1" and rv.user_id == "dave"
    assert mgr.current("ops", at_seq=9) == "a"  # layer restored
    with pytest.raises(OncallRotationError):
        mgr.revoke_override("ops", "ov-1", seq=5)  # already revoked
    with pytest.raises(OncallRotationError):
        mgr.revoke_override("ops", "ov-ghost", seq=6)


def test_seq_ordering_and_failed_mutation_consumes_seq():
    mgr = OncallRotation()
    mgr.create_rotation("infra", "Infra", seq=1)
    # Rewind refused.
    with pytest.raises(OncallRotationError):
        mgr.schedule("infra", ["a"], 10, seq=1)
    # Bool seq refused.
    with pytest.raises(OncallRotationError):
        mgr.schedule("infra", ["a"], 10, seq=True)
    # Failed mutation consumes its seq.
    try:
        mgr.schedule("infra", [], 10, seq=2)
    except OncallRotationError:
        pass
    with pytest.raises(OncallRotationError):
        mgr.schedule("infra", ["a"], 10, seq=2)  # already consumed
    ok = mgr.schedule("infra", ["a"], 10, seq=3)
    assert ok.verify()


def test_current_unknown_rotation_and_no_schedule():
    mgr = OncallRotation()
    with pytest.raises(UnknownRotationError):
        mgr.current("ghost", at_seq=1)
    mgr.create_rotation("bare", "Bare", seq=1)
    with pytest.raises(OncallRotationError):
        mgr.current("bare", at_seq=1)
    with pytest.raises(OncallRotationError):
        mgr.current("bare", at_seq=True)


def test_audit_shapes_and_bad_kind():
    mgr = _fresh()
    kinds = [e["kind"] for e in mgr.audit_log()]
    assert kinds == [oncall_rotation.KIND_ROTATION_CREATED,
                     oncall_rotation.KIND_SCHEDULE_SET]
    assert all(e["schema"] == "audit.ndjson/1" for e in mgr.audit_log())
    ev = oncall_audit_event(oncall_rotation.KIND_HANDOFF, seq=9,
                            rotation_id="ops", to_user="b")
    assert ev["seq"] == 9 and ev["detail"]["to_user"] == "b"
    with pytest.raises(OncallRotationError):
        oncall_audit_event("bogus.kind", seq=1)


def test_record_tamper_detection():
    mgr = _fresh()
    s = mgr.schedule_record("ops")
    tampered = s.__class__(
        rotation_id=s.rotation_id,
        participants=("mallory",),
        shift_length_seqs=s.shift_length_seqs,
        generation=s.generation,
        current_index=0,
        seq=s.seq,
        digest=s.digest,  # stale pin
    )
    assert not tampered.verify()
    assert s.verify()


def test_main_self_check():
    proc = subprocess.run(
        [sys.executable, oncall_rotation.__file__],
        capture_output=True, text=True, timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    assert "oncall-rotation OK" in proc.stdout
