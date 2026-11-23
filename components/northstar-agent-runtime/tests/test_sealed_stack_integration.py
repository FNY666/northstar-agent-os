"""End-to-end integration: the full sealed stack with REAL modules.

This is the test a senior dev writes: not another unit, but proof
that forward_seal_ledger + seal_merkle_batch + sealed_attestation +
observer_verdict_ledger + safr_checkpoint actually compose.  All
modules are loaded for real (importlib, no stubs); any API mismatch
between the pieces fails here.

Scenario: an agent declares an action via SAFR, an observer adjudicates
it, both streams land in one forward-seal ledger, records are batched
into a Merkle tree, and in-toto attestations are emitted for a record
(with inclusion proof) and for the batch root.  The full chain then
verifies from the initial keys.
"""

import hashlib
import importlib.util
import os
import sys
from pathlib import Path

import pytest

RUNTIME = Path(__file__).resolve().parent.parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


fsl = _load("forward_seal_ledger")
smb = _load("seal_merkle_batch")
sat = _load("sealed_attestation")
ovl = _load("observer_verdict_ledger")
safr = _load("safr_checkpoint")

PIN = "sha256:" + "ab" * 32
PIN2 = "sha256:" + "cd" * 32


def _safr_event(cp, declaration_id):
    return cp.to_sealed_event(declaration_id)


def _observer_event(ledger, verdict_id):
    return ledger.to_sealed_event(verdict_id)


def test_full_stack_end_to_end():
    initial_key = os.urandom(32)
    checkpoint_key = os.urandom(32)
    ledger = fsl.ForwardSealLedger(initial_key, checkpoint_key)

    # 1. SAFR: agent declares, gets authorized, assessed, audited.
    cp = safr.SafrCheckpoint()
    d = cp.declare(1, "deploy", "restart-service", "prod-api", PIN)
    cp.authorize(2, d.declaration_id, "allow", "policy-engine", PIN)
    cp.assess(3, d.declaration_id, "pass", PIN)
    cp.audit(4, d.declaration_id, "executed", PIN2)

    # 2. Observer: independent verdict on the action.
    obs = ovl.ObserverVerdictLedger()
    v = obs.verdict("watcher-1", 1, PIN, "allow", PIN2, severity=5)

    # 3. Both streams land in ONE forward-seal ledger (shared ordering).
    r1 = ledger.append(**_safr_event(cp, d.declaration_id))
    r2 = ledger.append(**_observer_event(obs, v.verdict_id))
    assert r1.seq == 1
    assert r2.seq == 2
    assert r2.prev_hash == r1.record_hash  # hash-chained

    # 4. Seal the batch -> Merkle root + inclusion proofs.
    hashes = [ledger.record(1).record_hash, ledger.record(2).record_hash]
    batch = smb.seal_batch(hashes, first_seq=1)
    assert batch.depth == 1
    proof = batch.proof(0)
    assert smb.verify_proof(hashes[0], proof, batch.root) is True
    assert smb.verify_proof(hashes[1], batch.proof(1), batch.root) is True

    # 5. In-toto attestations: record (with proof) + batch root.
    event = _safr_event(cp, d.declaration_id)
    rec_att = sat.attest_sealed_record(
        record_hash=r1.record_hash,
        seq=r1.seq,
        event=event,
        input_fingerprint=r1.input_fingerprint,
        logic_fingerprint=r1.logic_fingerprint,
        execution_fingerprint=r1.execution_fingerprint,
        seal=r1.seal,
        prev_hash=r1.prev_hash,
        merkle_proof={
            "leaf_index": proof.leaf_index,
            "siblings": list(proof.siblings),
            "root": proof.root,
        },
    )
    assert sat.verify_envelope(rec_att)["envelope_ok"] is True

    batch_att = sat.attest_sealed_batch(
        batch_root=batch.root,
        first_seq=1,
        record_count=2,
        batch_depth=batch.depth,
    )
    assert sat.verify_envelope(batch_att)["envelope_ok"] is True

    # 6. Checkpoint the ledger head, attest the checkpoint.
    chk = ledger.checkpoint()
    chk_att = sat.attest_checkpoint(
        checkpoint_seq=chk.seq,
        head_hash=chk.head_hash,
        records_sealed=chk.records_sealed,
        checkpoint_seal=chk.seal,
    )
    assert sat.verify_envelope(chk_att)["envelope_ok"] is True

    # 7. Full verification from the initial keys.
    report = ledger.verify(initial_key, checkpoint_key)
    assert report["records_verified"] == 2
    assert report["checkpoints_verified"] == 1
    assert report["forward_secure"] is True
    assert report["head_hash"] == r2.record_hash


def test_observer_and_agent_streams_interleave():
    """Many SAFR declarations + observer verdicts interleave in one ledger."""
    initial_key = os.urandom(32)
    checkpoint_key = os.urandom(32)
    ledger = fsl.ForwardSealLedger(initial_key, checkpoint_key)
    cp = safr.SafrCheckpoint()
    obs = ovl.ObserverVerdictLedger()

    seq = 1
    for i in range(5):
        d = cp.declare(seq, f"intent-{i}", f"action-{i}", f"subject-{i}", PIN)
        seq += 1
        decision = "deny" if i % 2 else "allow"
        cp.authorize(seq, d.declaration_id, decision, "policy", PIN)
        seq += 1
        if decision == "allow":
            cp.assess(seq, d.declaration_id, "pass", PIN)
            seq += 1
            cp.audit(seq, d.declaration_id, "executed", PIN)
            seq += 1
        # Observer verdict on every declaration.
        v = obs.verdict("watcher-1", i + 1, PIN, "allow" if decision == "allow" else "flag", PIN)
        # Append both to the ledger.
        ledger.append(**cp.to_sealed_event(d.declaration_id))
        ledger.append(**obs.to_sealed_event(v.verdict_id))

    # 10 records, hash-chained.
    assert len(ledger) == 10
    for s in range(2, 11):
        assert ledger.record(s).prev_hash == ledger.record(s - 1).record_hash

    # Batch all 10, every proof verifies.
    hashes = [ledger.record(s).record_hash for s in range(1, 11)]
    batch = smb.seal_batch(hashes, first_seq=1)
    for i, h in enumerate(hashes):
        assert smb.verify_proof(h, batch.proof(i), batch.root) is True

    # Ledger verifies end-to-end.
    report = ledger.verify(initial_key, checkpoint_key)
    assert report["records_verified"] == 10


def test_tamper_anywhere_breaks_verification():
    """Tampering with a sealed record breaks ledger verification."""
    initial_key = os.urandom(32)
    checkpoint_key = os.urandom(32)
    ledger = fsl.ForwardSealLedger(initial_key, checkpoint_key)
    cp = safr.SafrCheckpoint()
    d = cp.declare(1, "x", "y", "z", PIN)
    r1 = ledger.append(**cp.to_sealed_event(d.declaration_id))
    d2 = cp.declare(2, "a", "b", "c", PIN)
    ledger.append(**cp.to_sealed_event(d2.declaration_id))

    # Corrupt the first record's seal in place (simulating disk tamper).
    import dataclasses

    corrupted = dataclasses.replace(ledger._records[0], seal="00" * 32)
    ledger._records[0] = corrupted

    with pytest.raises(fsl.ForwardSealError):
        ledger.verify(initial_key, checkpoint_key)


def test_attestation_envelope_roundtrip_through_dict():
    """to_dict() output re-hashes to the statement digest (spec compliance)."""
    initial_key = os.urandom(32)
    checkpoint_key = os.urandom(32)
    ledger = fsl.ForwardSealLedger(initial_key, checkpoint_key)
    cp = safr.SafrCheckpoint()
    d = cp.declare(1, "deploy", "run", "svc", PIN)
    r1 = ledger.append(**cp.to_sealed_event(d.declaration_id))

    event = cp.to_sealed_event(d.declaration_id)
    att = sat.attest_sealed_record(
        record_hash=r1.record_hash,
        seq=r1.seq,
        event=event,
        input_fingerprint=r1.input_fingerprint,
        logic_fingerprint=r1.logic_fingerprint,
        execution_fingerprint=r1.execution_fingerprint,
        seal=r1.seal,
        prev_hash=r1.prev_hash,
    )
    d_dict = att.to_dict()
    # The dict is the standard in-toto shape.
    assert d_dict["_type"] == "https://in-toto.io/Statement/v1"
    assert d_dict["predicateType"] == sat.PREDICATE_SEALED_RECORD
    # Re-derive the digest from the canonical dict form.
    import json

    canonical = json.dumps(d_dict, sort_keys=True, separators=(",", ":")).encode()
    assert "sha256:" + hashlib.sha256(canonical).hexdigest() == att.statement_digest
