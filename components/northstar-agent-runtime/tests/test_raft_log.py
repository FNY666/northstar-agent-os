"""Tests for raft_log."""

import ast
import subprocess
import sys
from pathlib import Path

import pytest

import raft_log as rl
from raft_log import (
    RaftLog,
    BadDigestError,
    BadIndexError,
    BadNodeError,
    BadTermError,
    ApplyOrderError,
    AlreadyAppliedError,
    CommittedTruncateError,
    IndexOutOfRangeError,
    NoCommitAdvanceError,
    RaftLogError,
    SeqOrderError,
    TermMismatchError,
    TermRegressionError,
    UncommittedApplyError,
    UncommittedSnapshotError,
    raft_log_audit_event,
)

DIGEST_A = "sha256:" + "aa" * 32
DIGEST_B = "sha256:" + "bb" * 32
DIGEST_C = "sha256:" + "cc" * 32


def _log(node_id="n1"):
    return RaftLog(node_id)


def test_version_and_schema_pins():
    assert rl.RAFT_LOG_VERSION == "raft-log.v1"
    assert rl.RAFT_LOG_SCHEMA == "northstar.raft-log.v1"
    assert rl.AUDIT_SCHEMA == "audit.ndjson/1"


def test_stdlib_only():
    src = Path(rl.__file__).read_text()
    tree = ast.parse(src)
    allowed = {
        "hashlib", "threading", "dataclasses", "typing", "json",
        "canonical_json", "__future__",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                assert a.name.split(".")[0] in allowed, a.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


def test_constructor_bad_inputs():
    with pytest.raises(BadNodeError):
        RaftLog("")
    with pytest.raises(BadNodeError):
        RaftLog("   ")
    with pytest.raises(BadNodeError):
        RaftLog(None)


def test_append_roundtrip():
    log = _log()
    log.set_term(1, 1)
    rec = log.append(1, DIGEST_A, 2)
    assert rec.verify()
    assert rec.index == 1
    assert rec.term == 1
    assert rec.payload_digest == DIGEST_A
    entry = log.entry(1, 3)
    assert entry is not None
    assert entry.term == 1
    assert entry.payload_digest == DIGEST_A
    # Indexes are 1-based and contiguous.
    rec2 = log.append(1, DIGEST_B, 4)
    assert rec2.index == 2
    assert log.last_log_index(5) == 2
    assert log.last_log_term(6) == 1


def test_append_bad_inputs():
    log = _log()
    with pytest.raises(BadTermError):
        log.append(-1, DIGEST_A, 1)
    with pytest.raises(BadTermError):
        log.append(True, DIGEST_A, 2)
    with pytest.raises(BadTermError):
        log.append("1", DIGEST_A, 3)
    with pytest.raises(BadDigestError):
        log.append(1, "aa" * 32, 4)
    with pytest.raises(BadDigestError):
        log.append(1, "sha256:xyz", 5)
    log.set_term(2, 6)
    # A node never appends older-term entries.
    with pytest.raises(BadTermError):
        log.append(1, DIGEST_A, 7)
    # Failed mutation consumed seq 7: next valid call needs seq 8.
    rec = log.append(2, DIGEST_A, 8)
    assert rec.index == 1


def test_set_term():
    log = _log()
    r1 = log.set_term(3, 1)
    assert r1.verify()
    assert log.current_term(2) == 3
    # Idempotent advance (same term) is fine; regression is refused.
    log.set_term(3, 3)
    with pytest.raises(TermRegressionError):
        log.set_term(2, 4)
    with pytest.raises(BadTermError):
        log.set_term(False, 5)


def test_commit():
    log = _log()
    log.set_term(2, 1)
    log.append(2, DIGEST_A, 2)
    log.append(2, DIGEST_B, 3)
    rec = log.commit(2, 4)
    assert rec.verify()
    assert rec.term == 2
    assert log.commit_index(5) == 2
    # Commit index never moves backward: no advance is refused.
    with pytest.raises(NoCommitAdvanceError):
        log.commit(2, 6)
    with pytest.raises(NoCommitAdvanceError):
        log.commit(1, 7)
    # Unknown index.
    with pytest.raises(IndexOutOfRangeError):
        log.commit(99, 8)


def test_commit_term_mismatch_542():
    # Raft 5.4.2: a leader may only commit current-term entries.
    log = _log()
    log.set_term(1, 1)
    log.append(1, DIGEST_A, 2)
    log.append(1, DIGEST_B, 3)
    log.set_term(2, 4)
    with pytest.raises(TermMismatchError):
        log.commit(2, 5)
    # Once a current-term entry exists, commit proceeds.
    log.append(2, DIGEST_C, 6)
    rec = log.commit(3, 7)
    assert rec.term == 2
    assert log.commit_index(8) == 3


def test_follower_commit():
    log = _log()
    log.set_term(1, 1)
    log.append(1, DIGEST_A, 2)
    log.append(1, DIGEST_B, 3)
    # No 5.4.2 term rule on the follower side.
    rec = log.follower_commit(2, 4)
    assert rec.verify()
    assert log.commit_index(5) == 2
    # Clamped at last_log_index; never moves backward.
    log2 = _log()
    log2.set_term(1, 1)
    log2.append(1, DIGEST_A, 2)
    rec2 = log2.follower_commit(99, 3)
    assert log2.commit_index(4) == 1
    with pytest.raises(BadIndexError):
        log2.follower_commit(0, 5)


def test_apply_exact_order():
    log = _log()
    log.set_term(1, 1)
    log.append(1, DIGEST_A, 2)
    log.append(1, DIGEST_B, 3)
    log.commit(2, 4)
    p1 = log.apply(1, 5)
    assert p1.verify()
    assert log.last_applied(6) == 1
    # Skip-ahead is refused: state machines apply in exact order.
    with pytest.raises(ApplyOrderError):
        log.apply(3, 7)
    p2 = log.apply(2, 8)
    assert p2.payload_digest == DIGEST_B
    assert log.last_applied(9) == 2
    # Re-apply is refused.
    with pytest.raises(AlreadyAppliedError):
        log.apply(2, 10)
    # Beyond commit index is refused.
    log.append(1, DIGEST_C, 11)
    with pytest.raises(UncommittedApplyError):
        log.apply(3, 12)


def test_truncate_after():
    log = _log()
    log.set_term(1, 1)
    log.append(1, DIGEST_A, 2)
    log.append(1, DIGEST_B, 3)
    log.append(1, DIGEST_C, 4)
    rec = log.truncate_after(1, 5)
    assert rec.verify()
    assert rec.dropped == 2
    assert log.last_log_index(6) == 1
    assert log.entry(2, 7) is None
    # Truncation at or below the commit index is refused.
    log.commit(1, 8)
    with pytest.raises(CommittedTruncateError):
        log.truncate_after(1, 9)


def test_snapshot():
    log = _log()
    log.set_term(1, 1)
    log.append(1, DIGEST_A, 2)
    log.append(1, DIGEST_B, 3)
    log.append(1, DIGEST_C, 4)
    log.commit(3, 5)
    log.apply(1, 6)
    log.apply(2, 7)
    rec = log.snapshot(2, DIGEST_C, 8)
    assert rec.verify()
    assert rec.last_included_index == 2
    assert rec.last_included_term == 1
    assert rec.compacted == 2
    assert log.entry(1, 9) is None
    assert log.entry(3, 10) is not None
    info = log.snapshot_info(11)
    assert info.last_included_index == 2
    assert info.last_included_term == 1
    # Re-snapshot at the same index is refused.
    with pytest.raises(UncommittedSnapshotError):
        log.snapshot(2, DIGEST_C, 12)
    # Snapshot of uncommitted entries is refused.
    log.append(1, DIGEST_A, 13)
    with pytest.raises(UncommittedSnapshotError):
        log.snapshot(4, DIGEST_A, 14)
    with pytest.raises(BadDigestError):
        log.snapshot(3, "not-a-digest", 15)


def test_seq_ordering_and_consumed_on_failure():
    log = _log()
    log.set_term(1, 1)
    log.append(1, DIGEST_A, 2)
    # Rewind is refused.
    with pytest.raises(SeqOrderError):
        log.append(1, DIGEST_B, 2)
    with pytest.raises(SeqOrderError):
        log.append(1, DIGEST_B, 1)
    # Bool / non-int seqs refused.
    with pytest.raises(SeqOrderError):
        log.append(1, DIGEST_B, True)
    with pytest.raises(SeqOrderError):
        log.append(1, DIGEST_B, "3")
    # Failed mutations consume their seq: bad digest burns seq 3,
    # so the next call must use seq 4.
    with pytest.raises(BadDigestError):
        log.append(1, "nope", 3)
    rec = log.append(1, DIGEST_B, 4)
    assert rec.index == 2
    # Read views validate seq shape but never consume it.
    st = log.stats(4)
    assert st.pending_entries == 2
    with pytest.raises(SeqOrderError):
        log.stats(0)
    log.append(1, DIGEST_C, 5)


def test_audit_shapes_and_banned_keys():
    log = _log()
    log.set_term(1, 1)
    log.append(1, DIGEST_A, 2)
    log.commit(1, 3)
    log.apply(1, 4)
    with pytest.raises(BadIndexError):
        log.apply(0, 5)
    rows = log.audit_log()
    kinds = [r["kind"] for r in rows]
    assert kinds == [
        "raft.term-set", "raft.appended", "raft.committed",
        "raft.applied", "raft.rejected",
    ], kinds
    for r in rows:
        assert r["schema"] == "audit.ndjson/1"
        assert r["module"] == "raft_log"
        assert r["module_version"] == "raft-log.v1"
        assert "payload" not in r["detail"]
        assert "value" not in r["detail"]
    with pytest.raises(RaftLogError):
        raft_log_audit_event("raft.bogus", 1)
    with pytest.raises(RaftLogError):
        raft_log_audit_event("raft.appended", 1, payload="x")


def test_main_self_check():
    proc = subprocess.run(
        [sys.executable, rl.__file__],
        capture_output=True, text=True, timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    assert "raft-log OK" in proc.stdout
