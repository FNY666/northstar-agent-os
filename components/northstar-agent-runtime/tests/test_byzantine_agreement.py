"""Targeted tests for byzantine_agreement.py (15 tests)."""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

import pytest

import byzantine_agreement as ba
from byzantine_agreement import (
    AuditKindError,
    BadDigestError,
    BadRequestError,
    BadViewError,
    ByzantineAgreement,
    ByzantineAgreementError,
    DigestMismatchError,
    DuplicateRequestError,
    DuplicateVoteError,
    PhaseOrderError,
    SeqOrderError,
    UnknownReplicaError,
    UnknownRequestError,
    byzantine_agreement_audit_event,
)

MODULE_PATH = Path(ba.__file__)
DIGEST = "sha256:" + "ab" * 32
DIGEST2 = "sha256:" + "cd" * 32


def fresh() -> ByzantineAgreement:
    return ByzantineAgreement(replicas=("r0", "r1", "r2", "r3"))


def prepared(agreement: ByzantineAgreement, rid: str = "req-1") -> None:
    agreement.preprepare(rid, view=0, seq=1, request_digest=DIGEST)
    seq = 2
    for replica in ("r1", "r2"):
        agreement.prepare(rid, replica=replica, seq=seq, request_digest=DIGEST)
        seq += 1


def test_01_version_and_schema_pins():
    assert ba.BYZANTINE_AGREEMENT_VERSION == "byzantine-agreement.v1"
    assert ba.SCHEMA_PIN == "northstar.byzantine-agreement.v1"
    rec = fresh().preprepare("req-1", view=0, seq=1, request_digest=DIGEST)
    assert rec.version == "byzantine-agreement.v1"
    assert rec.schema == "northstar.byzantine-agreement.v1"


def test_02_stdlib_only():
    tree = ast.parse(MODULE_PATH.read_text(encoding="utf-8"))
    allowed = {"hashlib", "re", "threading", "dataclasses", "typing", "__future__"}
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert imported <= allowed, imported - allowed


def test_03_replica_math_and_bad_member_sets():
    agreement = fresh()
    assert agreement.f == 1
    assert agreement.quorum == 3
    assert agreement.prepare_quorum == 2
    big = ByzantineAgreement(
        replicas=("a", "b", "c", "d", "e", "f", "g")
    )
    assert big.f == 2 and big.quorum == 5 and big.prepare_quorum == 4
    with pytest.raises(ByzantineAgreementError):
        ByzantineAgreement(replicas=("a", "b", "c"))  # n < 4
    with pytest.raises(ByzantineAgreementError):
        ByzantineAgreement(replicas=("a", "b", "c", "d", "e"))  # n != 3f+1
    with pytest.raises(ByzantineAgreementError):
        ByzantineAgreement(replicas=("a", "a", "b", "c"))  # duplicate
    with pytest.raises(ByzantineAgreementError):
        ByzantineAgreement(replicas=("a", "", "b", "c"))  # empty


def test_04_preprepare_roundtrip_and_verify():
    agreement = fresh()
    rec = agreement.preprepare("req-1", view=3, seq=1, request_digest=DIGEST)
    assert rec.request_id == "req-1" and rec.view == 3
    assert rec.request_digest == DIGEST
    same = agreement.preprepare_record("req-1", seq=2)
    assert same == rec
    with pytest.raises(UnknownRequestError):
        agreement.preprepare_record("nope", seq=3)


def test_05_preprepare_duplicate_and_seq_burn():
    agreement = fresh()
    agreement.preprepare("req-1", view=0, seq=1, request_digest=DIGEST)
    with pytest.raises(DuplicateRequestError):
        agreement.preprepare("req-1", view=0, seq=2, request_digest=DIGEST)
    # Failed mutation consumed seq 2: reuse is refused, next fresh seq works.
    with pytest.raises(SeqOrderError):
        agreement.preprepare("req-2", view=0, seq=2, request_digest=DIGEST)
    agreement.preprepare("req-2", view=0, seq=3, request_digest=DIGEST)
    rejected = [
        row
        for row in agreement.audit_log()
        if row["kind"] == "byzantine-agreement.rejected"
    ]
    assert len(rejected) == 1
    assert rejected[0]["detail"]["reason"] == "DuplicateRequestError"


def test_06_bad_preprepare_inputs():
    agreement = fresh()
    bad_ids = ["", "  ", "x" * 257, 123, None, True]
    seq = 1
    for bad in bad_ids:
        with pytest.raises(BadRequestError):
            agreement.preprepare(bad, view=0, seq=seq, request_digest=DIGEST)
        seq += 1
    for bad_view in (-1, 1.5, "0", True):
        with pytest.raises(BadViewError):
            agreement.preprepare("v", view=bad_view, seq=seq, request_digest=DIGEST)
        seq += 1
    for bad_digest in ["", "sha256:xyz", "md5:" + "a" * 32, 42, True, "SHA256:" + "a" * 64]:
        with pytest.raises(BadDigestError):
            agreement.preprepare("d", view=0, seq=seq, request_digest=bad_digest)
        seq += 1
    # Rejections were all audited (6 + 4 + 6 rows).
    assert len(agreement.audit_log()) == 16


def test_07_prepare_votes_and_digest_mismatch():
    agreement = fresh()
    agreement.preprepare("req-1", view=0, seq=1, request_digest=DIGEST)
    vote = agreement.prepare("req-1", replica="r1", seq=2, request_digest=DIGEST)
    assert vote.replica == "r1"
    assert agreement.prepare_votes("req-1", seq=3) == ("r1",)
    with pytest.raises(DuplicateVoteError):
        agreement.prepare("req-1", replica="r1", seq=4, request_digest=DIGEST)
    with pytest.raises(DigestMismatchError):
        agreement.prepare("req-1", replica="r2", seq=5, request_digest=DIGEST2)
    with pytest.raises(UnknownReplicaError):
        agreement.prepare("req-1", replica="zz", seq=6, request_digest=DIGEST)
    with pytest.raises(UnknownRequestError):
        agreement.prepare("ghost", replica="r1", seq=7, request_digest=DIGEST)


def test_08_prepare_quorum_certificates():
    agreement = fresh()
    prepared(agreement)
    assert agreement.status("req-1", seq=9) == "prepared"
    cert = agreement.certificate("req-1", "prepared", seq=10)
    assert cert is not None
    assert cert.votes == ("r1", "r2")
    assert agreement.certificate("req-1", "committed", seq=11) is None
    assert agreement.prepare_votes("req-1", seq=12) == ("r1", "r2")


def test_09_commit_quorum_and_certificate():
    agreement = fresh()
    prepared(agreement)
    seq = 4
    for replica in ("r0", "r1", "r2"):
        agreement.commit("req-1", replica=replica, seq=seq, request_digest=DIGEST)
        seq += 1
    assert agreement.status("req-1", seq=seq) == "committed"
    cert = agreement.certificate("req-1", "committed", seq=seq + 1)
    assert cert is not None and cert.votes == ("r0", "r1", "r2")
    assert agreement.commit_votes("req-1", seq=seq + 2) == ("r0", "r1", "r2")


def test_10_commit_phase_order_fail_closed():
    agreement = fresh()
    agreement.preprepare("req-1", view=0, seq=1, request_digest=DIGEST)
    # Only one prepare: not yet prepared -> commit refused.
    agreement.prepare("req-1", replica="r1", seq=2, request_digest=DIGEST)
    with pytest.raises(PhaseOrderError):
        agreement.commit("req-1", replica="r1", seq=3, request_digest=DIGEST)
    with pytest.raises(UnknownRequestError):
        agreement.commit("ghost", replica="r1", seq=4, request_digest=DIGEST)
    with pytest.raises(DigestMismatchError):
        agreement.commit("req-1", replica="r2", seq=5, request_digest=DIGEST2)
    agreement.prepare("req-1", replica="r2", seq=6, request_digest=DIGEST)
    assert agreement.status("req-1", seq=7) == "prepared"
    agreement.commit("req-1", replica="r1", seq=8, request_digest=DIGEST)
    with pytest.raises(DuplicateVoteError):
        agreement.commit("req-1", replica="r1", seq=9, request_digest=DIGEST)


def test_11_seq_strictly_increasing_and_views_do_not_consume():
    agreement = fresh()
    agreement.preprepare("req-1", view=0, seq=5, request_digest=DIGEST)
    for bad_seq in (5, 4, 0, -1, "6", 6.0, True):
        with pytest.raises(SeqOrderError):
            agreement.preprepare("req-2", view=0, seq=bad_seq, request_digest=DIGEST)
    # Pure views validate the seq shape but do not consume it.
    assert agreement.status("req-1", seq=9) == "pre-prepared"
    assert agreement.prepare_votes("req-1", seq=9) == ()
    assert agreement.commit_votes("req-1", seq=9) == ()
    stats = agreement.stats()
    assert stats["requests"] == 1 and stats["prepared"] == 0 and stats["committed"] == 0
    agreement.preprepare("req-2", view=0, seq=6, request_digest=DIGEST)
    # status itself raises on malformed inputs.
    with pytest.raises(BadRequestError):
        agreement.status("", seq=7)
    with pytest.raises(UnknownRequestError):
        agreement.status("ghost", seq=7)


def test_12_audit_shapes_and_banned_keys():
    agreement = fresh()
    prepared(agreement)
    seq = 4
    for replica in ("r0", "r1", "r2"):
        agreement.commit("req-1", replica=replica, seq=seq, request_digest=DIGEST)
        seq += 1
    kinds = [row["kind"] for row in agreement.audit_log()]
    assert kinds == [
        "byzantine-agreement.preprepared",
        "byzantine-agreement.prepared",
        "byzantine-agreement.committed",
    ]
    for row in agreement.audit_log():
        assert row["schema"] == "audit.ndjson/1"
        assert row["module"] == "byzantine_agreement"
        assert row["module_version"] == "byzantine-agreement.v1"
        assert not (
            set(row["detail"]) & {"payload", "value", "data", "votes", "request", "message"}
        )
    with pytest.raises(AuditKindError):
        byzantine_agreement_audit_event("nope", 1)
    with pytest.raises(AuditKindError):
        byzantine_agreement_audit_event(
            "byzantine-agreement.preprepared", 1, payload=b"raw"
        )
    with pytest.raises(AuditKindError):
        byzantine_agreement_audit_event(
            "byzantine-agreement.prepared", 1, votes=["r1"]
        )
    row = byzantine_agreement_audit_event(
        "byzantine-agreement.committed", 42, request_id="req-1"
    )
    assert row["seq"] == 42


def test_13_multi_request_independence_and_stats():
    agreement = fresh()
    prepared(agreement, rid="a")  # consumes seqs 1-3
    agreement.preprepare("b", view=0, seq=4, request_digest=DIGEST2)
    stats = agreement.stats()
    assert stats["requests"] == 2
    assert stats["prepared"] == 1
    assert stats["committed"] == 0
    assert agreement.status("b", seq=9) == "pre-prepared"
    assert agreement.prepare_votes("b", seq=9) == ()


def test_14_thread_safety_smoke():
    import itertools
    import threading

    agreement = fresh()
    prepared(agreement)  # preprepare seq=1, prepares seq=2,3
    seq_source = itertools.count(4)
    gate = threading.Lock()

    def worker(replica: str) -> None:
        # Assign the seq and issue the commit under one lock so the
        # strictly-increasing seq discipline is never violated by
        # thread scheduling.
        with gate:
            seq = next(seq_source)
            agreement.commit(
                "req-1", replica=replica, seq=seq, request_digest=DIGEST
            )

    threads = [threading.Thread(target=worker, args=(f"r{i}",)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert agreement.status("req-1", seq=100) == "committed"
    assert len(agreement.commit_votes("req-1", seq=101)) == 4


def test_15_main_self_check():
    result = subprocess.run(
        [sys.executable, str(MODULE_PATH)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert "byzantine-agreement OK" in result.stdout
