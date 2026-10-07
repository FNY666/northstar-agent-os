"""Tests for transactional_messaging (2PC-shaped atomic message send)."""

import ast
import subprocess
import sys
from pathlib import Path

import pytest

import transactional_messaging
from transactional_messaging import (
    TransactionalMessaging,
    TransactionalMessagingError,
    BadTxError,
    DuplicateTxError,
    UnknownTxError,
    TxStateError,
    BadParticipantError,
    DuplicateParticipantError,
    UnknownParticipantError,
    BadVoteError,
    DuplicateVoteError,
    BadDigestError,
    CommitRefusedError,
    IncompleteVotesError,
    BadReasonError,
    SeqOrderError,
    transactional_messaging_audit_event,
    TRANSACTIONAL_MESSAGING_VERSION,
    TRANSACTIONAL_MESSAGING_SCHEMA,
    KIND_BEGAN,
    KIND_ENLISTED,
    KIND_PREPARED,
    KIND_VOTED,
    KIND_COMMITTED,
    KIND_ABORTED,
    KIND_REJECTED,
    STATUS_OPEN,
    STATUS_PREPARED,
    STATUS_COMMITTED,
    STATUS_ABORTED,
    REASON_MANUAL,
    REASON_VOTE_NO,
    REASON_EXPIRED,
)

DIGEST = "sha256:" + "ab" * 32


def fresh():
    return TransactionalMessaging()


def test_version_and_schema_pins():
    assert TRANSACTIONAL_MESSAGING_VERSION == "transactional-messaging.v1"
    assert TRANSACTIONAL_MESSAGING_SCHEMA == "northstar.transactional-messaging.v1"


def test_stdlib_only():
    tree = ast.parse(Path(transactional_messaging.__file__).read_text())
    allowed = {"__future__", "hashlib", "threading", "dataclasses", "typing", "json"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                name = alias.name.split(".")[0]
                if name == "canonical_json":
                    continue  # stdlib-first fallback
                assert name in allowed, name
        elif isinstance(node, ast.ImportFrom):
            if node.module == "canonical_json":
                continue  # stdlib-first fallback
            assert node.module in allowed, node.module


def test_main_self_check():
    proc = subprocess.run(
        [sys.executable, transactional_messaging.__file__],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    assert "transactional-messaging OK" in proc.stdout


def test_begin_roundtrip_and_record_shape():
    ledger = fresh()
    rec = ledger.begin("tx-1", 1)
    assert rec.tx_id == "tx-1"
    assert rec.status == STATUS_OPEN
    assert rec.begin_seq == 1
    assert rec.seq == 1
    assert rec.verify()
    assert ledger.status_of("tx-1") == STATUS_OPEN
    # Duplicate id refused and id never recycled.
    with pytest.raises(DuplicateTxError):
        ledger.begin("tx-1", 2)
    kinds = [row["kind"] for row in ledger.audit_log()]
    assert KIND_REJECTED in kinds


def test_begin_bad_inputs():
    ledger = fresh()
    for bad in ("", "   ", 123, None, True, b"tx"):
        with pytest.raises(BadTxError):
            ledger.begin(bad, ledger._last_seq + 1 if hasattr(ledger, "_last_seq") else 1)
    # Use explicit fresh seqs after each refusal (failed mutations consume seq).
    seq = 100
    ledger2 = fresh()
    for bad in ("", 42, None):
        with pytest.raises((BadTxError, TransactionalMessagingError)):
            ledger2.begin(bad, seq)
            seq += 1


def test_enlist_roundtrip_and_bad_digest():
    ledger = fresh()
    ledger.begin("tx-1", 1)
    rec = ledger.enlist("tx-1", "node-a", DIGEST, 2)
    assert rec.participant_id == "node-a"
    assert rec.message_digest == DIGEST
    assert rec.enlist_seq == 2
    assert rec.verify()
    # Duplicate participant refused.
    with pytest.raises(DuplicateParticipantError):
        ledger.enlist("tx-1", "node-a", DIGEST, 3)
    # Bad digests refused.
    for i, bad in enumerate(("nope", "sha256:" + "zz" * 32, "sha256:" + "ab" * 31, "", None, 42)):
        with pytest.raises(BadDigestError):
            ledger.enlist("tx-1", "node-b", bad, 10 + i)
    # Unknown tx refused.
    with pytest.raises(UnknownTxError):
        ledger.enlist("tx-nope", "node-b", DIGEST, 50)


def test_enlist_only_while_open():
    ledger = fresh()
    ledger.begin("tx-1", 1)
    ledger.enlist("tx-1", "node-a", DIGEST, 2)
    ledger.prepare("tx-1", 3)
    with pytest.raises(TxStateError):
        ledger.enlist("tx-1", "node-b", DIGEST, 4)


def test_prepare_roundtrip_and_state_errors():
    ledger = fresh()
    ledger.begin("tx-1", 1)
    ledger.enlist("tx-1", "node-a", DIGEST, 2)
    rec = ledger.prepare("tx-1", 3)
    assert rec.participant_count == 1
    assert rec.prepare_seq == 3
    assert rec.verify()
    assert ledger.status_of("tx-1") == STATUS_PREPARED
    # Prepare twice refused; unknown tx refused; empty roster refused.
    with pytest.raises(TxStateError):
        ledger.prepare("tx-1", 4)
    with pytest.raises(UnknownTxError):
        ledger.prepare("tx-nope", 5)
    ledger.begin("tx-empty", 6)
    with pytest.raises(TxStateError):
        ledger.prepare("tx-empty", 7)


def test_vote_roundtrip_and_duplicate():
    ledger = fresh()
    ledger.begin("tx-1", 1)
    ledger.enlist("tx-1", "node-a", DIGEST, 2)
    ledger.prepare("tx-1", 3)
    rec = ledger.vote("tx-1", "node-a", "yes", 4)
    assert rec.decision == "yes"
    assert rec.verify()
    # Duplicate vote refused; bad decision refused; unknown participant refused.
    with pytest.raises(DuplicateVoteError):
        ledger.vote("tx-1", "node-a", "yes", 5)
    with pytest.raises(BadVoteError):
        ledger.vote("tx-1", "node-b", "maybe", 6)
    with pytest.raises(UnknownParticipantError):
        ledger.vote("tx-1", "node-zzz", "yes", 7)
    # Voting while still open refused.
    ledger.begin("tx-2", 8)
    ledger.enlist("tx-2", "node-a", DIGEST, 9)
    with pytest.raises(TxStateError):
        ledger.vote("tx-2", "node-a", "yes", 10)


def test_commit_happy_path_terminality():
    ledger = fresh()
    ledger.begin("tx-1", 1)
    ledger.enlist("tx-1", "node-b", DIGEST, 2)
    ledger.enlist("tx-1", "node-a", DIGEST, 3)
    ledger.prepare("tx-1", 4)
    ledger.vote("tx-1", "node-a", "yes", 5)
    ledger.vote("tx-1", "node-b", "yes", 6)
    rec = ledger.commit("tx-1", 7)
    assert rec.participant_ids == ("node-a", "node-b")
    assert rec.verify()
    assert ledger.status_of("tx-1") == STATUS_COMMITTED
    # Terminal: re-commit, vote, enlist, abort all refused.
    with pytest.raises(TxStateError):
        ledger.commit("tx-1", 8)
    with pytest.raises(TxStateError):
        ledger.vote("tx-1", "node-a", "yes", 9)
    with pytest.raises(TxStateError):
        ledger.abort("tx-1", 10)


def test_commit_with_no_vote_refuses_and_aborts():
    ledger = fresh()
    ledger.begin("tx-1", 1)
    ledger.enlist("tx-1", "node-a", DIGEST, 2)
    ledger.enlist("tx-1", "node-b", DIGEST, 3)
    ledger.prepare("tx-1", 4)
    ledger.vote("tx-1", "node-a", "no", 5)
    ledger.vote("tx-1", "node-b", "yes", 6)
    with pytest.raises(CommitRefusedError):
        ledger.commit("tx-1", 7)
    # The coordinator booked the abort automatically: terminal.
    assert ledger.status_of("tx-1") == STATUS_ABORTED
    rows = ledger.audit_log()
    assert rows[-1]["kind"] == KIND_ABORTED
    assert rows[-1]["detail"]["reason"] == REASON_VOTE_NO


def test_commit_with_missing_votes_stays_prepared():
    ledger = fresh()
    ledger.begin("tx-1", 1)
    ledger.enlist("tx-1", "node-a", DIGEST, 2)
    ledger.enlist("tx-1", "node-b", DIGEST, 3)
    ledger.prepare("tx-1", 4)
    ledger.vote("tx-1", "node-a", "yes", 5)
    with pytest.raises(IncompleteVotesError):
        ledger.commit("tx-1", 6)
    # Not terminal: still prepared, can still vote then commit.
    assert ledger.status_of("tx-1") == STATUS_PREPARED
    ledger.vote("tx-1", "node-b", "yes", 7)
    rec = ledger.commit("tx-1", 8)
    assert rec.verify()
    assert ledger.status_of("tx-1") == STATUS_COMMITTED


def test_abort_from_open_and_prepared_terminality():
    ledger = fresh()
    ledger.begin("tx-1", 1)
    rec = ledger.abort("tx-1", 2)
    assert rec.reason == REASON_MANUAL
    assert rec.verify()
    assert ledger.status_of("tx-1") == STATUS_ABORTED
    with pytest.raises(TxStateError):
        ledger.abort("tx-1", 3)
    # From prepared, with a pinned non-default reason.
    ledger.begin("tx-2", 4)
    ledger.enlist("tx-2", "node-a", DIGEST, 5)
    ledger.prepare("tx-2", 6)
    rec2 = ledger.abort("tx-2", 7, reason=REASON_EXPIRED)
    assert rec2.reason == REASON_EXPIRED
    with pytest.raises(BadReasonError):
        ledger.begin("tx-3", 8)
        ledger.abort("tx-3", 9, reason="because-i-said-so")
    with pytest.raises(UnknownTxError):
        ledger.abort("tx-nope", 10)


def test_seq_ordering_and_failed_mutation_consumes_seq():
    ledger = fresh()
    ledger.begin("tx-1", 1)
    # Rewind refused bare (seq never even reached the ledger).
    with pytest.raises(SeqOrderError):
        ledger.begin("tx-2", 1)
    # bool/negative refused.
    with pytest.raises(SeqOrderError):
        ledger.begin("tx-2", True)
    with pytest.raises(SeqOrderError):
        ledger.begin("tx-2", -1)
    # A failed mutation consumes its seq: duplicate begin at 2 books the
    # rejection, so seq 2 can never be reused.
    with pytest.raises(DuplicateTxError):
        ledger.begin("tx-1", 2)
    with pytest.raises(SeqOrderError):
        ledger.begin("tx-2", 2)
    ledger.begin("tx-2", 3)
    # Views never consume seq.
    before = ledger._last_seq
    ledger.tx_ids()
    ledger.stats()
    ledger.audit_log()
    ledger.participants("tx-1")
    ledger.votes("tx-1")
    ledger.status_of("tx-1")
    assert ledger._last_seq == before


def test_audit_shapes_and_banned_keys():
    ledger = fresh()
    ledger.begin("tx-1", 1)
    ledger.enlist("tx-1", "node-a", DIGEST, 2)
    ledger.prepare("tx-1", 3)
    ledger.vote("tx-1", "node-a", "yes", 4)
    ledger.commit("tx-1", 5)
    rows = ledger.audit_log()
    kinds = [r["kind"] for r in rows]
    assert kinds == [
        KIND_BEGAN,
        KIND_ENLISTED,
        KIND_PREPARED,
        KIND_VOTED,
        KIND_COMMITTED,
    ]
    for row in rows:
        assert row["schema"] == "audit.ndjson/1"
        assert row["module"] == TRANSACTIONAL_MESSAGING_VERSION
    # Banned keys refused in the audit builder.
    for banned in ("value", "payload", "message", "raw", "body", "data"):
        with pytest.raises(TransactionalMessagingError):
            transactional_messaging_audit_event(KIND_BEGAN, {banned: "x"}, 9)
    with pytest.raises(TransactionalMessagingError):
        transactional_messaging_audit_event("nope.kind", {}, 9)
    # Views: ids, participants, votes, stats.
    assert ledger.tx_ids() == ("tx-1",)
    parts = ledger.participants("tx-1")
    assert [p.participant_id for p in parts] == ["node-a"]
    ballots = ledger.votes("tx-1")
    assert [v.decision for v in ballots] == ["yes"]
    stats = ledger.stats()
    assert stats["transactions"] == 1
    assert stats[STATUS_COMMITTED] == 1
    assert stats[STATUS_ABORTED] == 0
