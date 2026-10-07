"""Tests for paxos_acceptor: prepare / accept / learn ledger."""

import ast
import subprocess
import sys
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

import paxos_acceptor as pa
from paxos_acceptor import PaxosAcceptor


def _digest(tag: str) -> str:
    return pa._pin(["test", tag])


def test_version_and_schema_pins():
    assert pa.PAXOS_ACCEPTOR_VERSION == "paxos-acceptor.v1"
    assert pa.PAXOS_ACCEPTOR_SCHEMA == "northstar.paxos-acceptor.v1"
    assert pa.AUDIT_SCHEMA == "audit.ndjson/1"
    kinds = {
        pa.EVENT_PROMISED,
        pa.EVENT_PREPARE_REFUSED,
        pa.EVENT_ACCEPTED,
        pa.EVENT_ACCEPT_REFUSED,
        pa.EVENT_REJECTED,
    }
    assert kinds == pa._EVENT_KINDS


def test_stdlib_only():
    src = Path(pa.__file__).read_text()
    tree = ast.parse(src)
    allowed = {
        "hashlib", "hmac", "threading", "dataclasses", "typing", "json",
        "canonical_json", "__future__",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                assert a.name.split(".")[0] in allowed, a.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


def test_prepare_grant_roundtrip():
    acc = PaxosAcceptor("acc-1")
    rec = acc.prepare(1, seq=1)
    assert rec.granted is True
    assert rec.reason == ""
    assert rec.promised_ballot == 1
    assert rec.accepted_ballot == 0
    assert rec.accepted_digest == ""
    assert rec.verify()
    assert acc.promised_ballot() == 1
    assert acc.audit_log()[0]["kind"] == pa.EVENT_PROMISED


def test_prepare_refuses_stale_ballot_as_data():
    acc = PaxosAcceptor("acc-1")
    acc.prepare(3, seq=1)
    rec = acc.prepare(2, seq=2)
    assert rec.granted is False
    assert rec.reason == pa.REASON_STALE_BALLOT
    assert rec.promised_ballot == 3  # state unchanged
    assert rec.verify()
    assert acc.promised_ballot() == 3
    assert acc.audit_log()[-1]["kind"] == pa.EVENT_PREPARE_REFUSED


def test_prepare_same_ballot_is_idempotent_grant():
    acc = PaxosAcceptor("acc-1")
    r1 = acc.prepare(2, seq=1)
    r2 = acc.prepare(2, seq=2)  # re-sent Phase 1a: not a violation
    assert r1.granted and r2.granted
    assert acc.promised_ballot() == 2


def test_prepare_carries_last_accepted():
    acc = PaxosAcceptor("acc-1")
    d = _digest("v1")
    acc.prepare(1, seq=1)
    acc.accept(1, d, seq=2)
    rec = acc.prepare(2, seq=3)
    assert rec.granted
    assert rec.accepted_ballot == 1
    assert rec.accepted_digest == d
    assert rec.verify()


def test_accept_happy_path_moves_promise():
    acc = PaxosAcceptor("acc-1")
    d = _digest("v2")
    rec = acc.accept(5, d, seq=1)  # no prior prepare needed
    assert rec.granted is True
    assert rec.promised_ballot == 5
    assert rec.accepted_ballot == 5
    assert rec.accepted_digest == d
    assert rec.verify()
    assert acc.promised_ballot() == 5
    assert acc.audit_log()[0]["kind"] == pa.EVENT_ACCEPTED


def test_accept_refuses_stale_ballot_state_unchanged():
    acc = PaxosAcceptor("acc-1")
    d = _digest("v3")
    acc.prepare(3, seq=1)
    rec = acc.accept(2, d, seq=2)
    assert rec.granted is False
    assert rec.reason == pa.REASON_STALE_BALLOT
    assert rec.promised_ballot == 3
    assert rec.accepted_ballot == 0  # nothing recorded
    assert rec.verify()
    assert acc.audit_log()[-1]["kind"] == pa.EVENT_ACCEPT_REFUSED


def test_bad_inputs_fail_closed_and_consume_seq():
    acc = PaxosAcceptor("acc-1")
    d = _digest("ok")
    bad_ballots = [0, -1, "1", 1.0, True, None]
    for i, b in enumerate(bad_ballots, start=1):
        with pytest.raises(pa.BadBallotError):
            acc.prepare(b, seq=i)
        assert acc.audit_log()[-1]["kind"] == pa.EVENT_REJECTED
    base = len(bad_ballots)
    bad_digests = ["nope", "sha256:" + "zz" * 32, "sha256:" + "ab" * 31, 123, None]
    for j, dg in enumerate(bad_digests, start=1):
        with pytest.raises(pa.BadDigestError):
            acc.accept(9, dg, seq=base + j)
        assert acc.audit_log()[-1]["kind"] == pa.EVENT_REJECTED
    # failed mutations consumed their seqs: next fresh seq must be > used ones
    acc.prepare(1, seq=base + len(bad_digests) + 1)
    with pytest.raises(pa.BadAcceptorError):
        PaxosAcceptor("")
    with pytest.raises(pa.BadAcceptorError):
        PaxosAcceptor("   ")


def test_learn_is_pure_read_view():
    acc = PaxosAcceptor("acc-1")
    d = _digest("v4")
    acc.prepare(1, seq=1)
    acc.accept(1, d, seq=2)
    rows_before = len(acc.audit_log())
    rep = acc.learn(3)
    assert rep.promised_ballot == 1
    assert rep.accepted_ballot == 1
    assert rep.accepted_digest == d
    assert rep.verify()
    assert len(acc.audit_log()) == rows_before  # no audit row written
    # seq shape validated but not consumed: same seq twice is fine
    rep2 = acc.learn(3)
    assert rep2.seq == 3 and rep2.verify()
    with pytest.raises(pa.SeqOrderError):
        acc.learn("3")
    with pytest.raises(pa.SeqOrderError):
        acc.learn(True)
    # fresh (empty) acceptor view
    fresh = PaxosAcceptor("acc-2").learn(1)
    assert fresh.promised_ballot == 0 and fresh.accepted_ballot == 0
    assert fresh.accepted_digest == "" and fresh.verify()


def test_seq_discipline_rewind_raises_bare():
    acc = PaxosAcceptor("acc-1")
    acc.prepare(1, seq=5)
    rows = len(acc.audit_log())
    with pytest.raises(pa.SeqOrderError):
        acc.prepare(2, seq=5)  # not strictly greater
    with pytest.raises(pa.SeqOrderError):
        acc.prepare(2, seq=4)  # rewind
    assert len(acc.audit_log()) == rows  # rewind consumes nothing, books nothing
    acc.prepare(2, seq=6)  # fresh seq still works
    assert acc.promised_ballot() == 2


def test_audit_shapes_and_banned_keys():
    acc = PaxosAcceptor("acc-1")
    acc.prepare(1, seq=1)
    row = acc.audit_log()[0]
    assert row["schema"] == "audit.ndjson/1"
    assert row["module"] == "paxos_acceptor"
    assert row["module_version"] == pa.PAXOS_ACCEPTOR_VERSION
    assert row["seq"] == 1
    assert "value" not in row["detail"]
    with pytest.raises(pa.PaxosAcceptorError):
        pa.paxos_acceptor_audit_event("bogus-kind", 1)
    with pytest.raises(pa.PaxosAcceptorError):
        pa.paxos_acceptor_audit_event(pa.EVENT_PROMISED, 1, value="raw")
    with pytest.raises(pa.PaxosAcceptorError):
        pa.paxos_acceptor_audit_event(pa.EVENT_PROMISED, 1, payload=b"x")
    # digests are pins, allowed across the boundary
    ev = pa.paxos_acceptor_audit_event(
        pa.EVENT_ACCEPTED, 2, acceptor_id="a", ballot=1, value_digest=_digest("x")
    )
    assert ev["detail"]["value_digest"].startswith("sha256:")


def test_records_frozen_and_verify_detects_tamper():
    acc = PaxosAcceptor("acc-1")
    rec = acc.prepare(1, seq=1)
    with pytest.raises(FrozenInstanceError):
        rec.granted = False  # type: ignore
    acc2 = PaxosAcceptor("acc-2")
    d = _digest("v5")
    arec = acc2.accept(1, d, seq=1)
    with pytest.raises(FrozenInstanceError):
        arec.accepted_digest = "sha256:" + "00" * 32  # type: ignore
    # tampered digest fails verify
    tampered = pa.PromiseRecord(
        acceptor_id=rec.acceptor_id, ballot=rec.ballot, granted=rec.granted,
        reason=rec.reason, promised_ballot=rec.promised_ballot,
        accepted_ballot=rec.accepted_ballot, accepted_digest=rec.accepted_digest,
        seq=rec.seq, digest="sha256:" + "ff" * 32,
    )
    assert not tampered.verify()


def test_stats_and_views():
    acc = PaxosAcceptor("acc-7")
    d = _digest("v6")
    acc.prepare(2, seq=1)
    acc.accept(2, d, seq=2)
    st = acc.stats()
    assert st["acceptor_id"] == "acc-7"
    assert st["promised_ballot"] == 2
    assert st["accepted_ballot"] == 2
    assert st["has_accepted"] is True
    assert st["last_seq"] == 2
    assert st["audit_rows"] == 2
    log = acc.audit_log()
    log.append({"forged": True})
    assert len(acc.audit_log()) == 2  # returns a copy


def test_main_self_check():
    proc = subprocess.run(
        [sys.executable, str(Path(pa.__file__))],
        capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    assert "paxos-acceptor OK: prepare, promise, accept, learn, pins, audit" in proc.stdout
