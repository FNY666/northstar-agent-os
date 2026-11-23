"""Sealed pipeline: ledger + Merkle batches + attestations, Simulated.

Wires the P0/P1 pieces into one coherent sealed pipeline without
sibling imports (dependency injection: the host passes the ledger
instance and the pure functions; this module holds only the
coordination logic).

Pipeline::

    ledger      = ForwardSealLedger(initial_key, checkpoint_key)
    pipeline    = SealedPipeline(ledger=ledger,
                                 seal_batch_fn=seal_batch,
                                 verify_proof_fn=verify_proof,
                                 attest_record_fn=attest_sealed_record,
                                 attest_batch_fn=attest_sealed_batch,
                                 batch_interval=64)
    rec         = pipeline.append(intent=..., action=..., ...)
    # every batch_interval appends the pipeline automatically:
    #   1. seals the batch of record_hashes into a Merkle tree
    #   2. emits an in-toto batch attestation over the root
    #   3. takes a forward-seal checkpoint
    batch_att   = pipeline.batch_attestation(batch_id)
    record_att  = pipeline.record_attestation(seq)  # with Merkle proof

What this module IS: the coordination layer that turns three
independent primitives into one auditable pipeline.  Batch boundaries
align with forward-seal checkpoints so every batch root is itself
sealed in the ledger's checkpoint chain.

What this module IS NOT (honest scope):

* It does not hold keys and does not seal anything itself -- the
  ledger seals records, the batch function seals batches, the attest
  functions build envelopes.  This module only calls them in the
  right order.
* It does not solve multi-writer coordination: one pipeline, one
  writer, one key lineage.  (Raft-style seq allocation is P2.)
* It does not publish batch roots anywhere -- external anchoring
  (OpenTimestamps / transparency log) remains the host's job.

House style: frozen dataclasses for reports, no wall-clock,
RLock-guarded, fail-closed, stdlib-only, version/schema pins,
``stdlib_only()`` + ``main()`` self-check.
"""

from __future__ import annotations

import ast
import threading
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Tuple

#: Module version pin.
SEALED_PIPELINE_VERSION = "sealed-pipeline.v1"

#: Schema pin for reports produced by this module.
SCHEMA_PIN = "northstar.sealed-pipeline.v1"


class SealedPipelineError(Exception):
    """Fail-closed: pipeline misuse raises, never silently misorders."""


@dataclass(frozen=True)
class BatchRecord:
    """One sealed batch within the pipeline (immutable)."""

    batch_id: int  # 1-based
    first_seq: int
    last_seq: int
    merkle_root: str  # sha256: pin
    depth: int
    attestation: Any  # in-toto Attestation (opaque here)


class SealedPipeline:
    """Coordinate ledger + Merkle batches + attestations.

    All collaborators are injected; this module imports nothing
    beyond stdlib.
    """

    def __init__(
        self,
        *,
        ledger: Any,
        seal_batch_fn: Callable[..., Any],
        verify_proof_fn: Callable[..., bool],
        attest_record_fn: Callable[..., Any],
        attest_batch_fn: Callable[..., Any],
        batch_interval: int = 64,
    ) -> None:
        if ledger is None:
            raise SealedPipelineError("ledger is required")
        for name, fn in (
            ("seal_batch_fn", seal_batch_fn),
            ("verify_proof_fn", verify_proof_fn),
            ("attest_record_fn", attest_record_fn),
            ("attest_batch_fn", attest_batch_fn),
        ):
            if not callable(fn):
                raise SealedPipelineError(f"{name} must be callable")
        if isinstance(batch_interval, bool) or not isinstance(batch_interval, int):
            raise SealedPipelineError("batch_interval must be int")
        if batch_interval < 1:
            raise SealedPipelineError("batch_interval must be >= 1")
        self._lock = threading.RLock()
        self._ledger = ledger
        self._seal_batch = seal_batch_fn
        self._verify_proof = verify_proof_fn
        self._attest_record = attest_record_fn
        self._attest_batch = attest_batch_fn
        self._batch_interval = batch_interval
        self._batches: List[BatchRecord] = []
        self._pending_hashes: List[str] = []
        self._pending_first_seq: int = 1

    # -- mutation ---------------------------------------------------

    def append(self, **event_fields: Any) -> Any:
        """Append one event via the ledger; auto-batch at the interval.

        ``event_fields`` are passed straight through to
        ``ledger.append()`` (the 8 fields + none else -- the ledger
        validates).  Returns the sealed record.  Every
        ``batch_interval`` appends, the pending batch is sealed and a
        checkpoint is taken.
        """
        with self._lock:
            record = self._ledger.append(**event_fields)
            self._pending_hashes.append(record.record_hash)
            if len(self._pending_hashes) >= self._batch_interval:
                self._seal_pending_batch_locked()
            return record

    def flush(self) -> BatchRecord | None:
        """Seal any pending partial batch (manual; idempotent)."""
        with self._lock:
            if not self._pending_hashes:
                return None
            return self._seal_pending_batch_locked()

    def _seal_pending_batch_locked(self) -> BatchRecord:
        hashes = tuple(self._pending_hashes)
        first_seq = self._pending_first_seq
        last_seq = first_seq + len(hashes) - 1
        batch = self._seal_batch(hashes, first_seq=first_seq)
        attestation = self._attest_batch(
            batch_root=batch.root,
            first_seq=first_seq,
            record_count=len(hashes),
            batch_depth=batch.depth,
        )
        # Anchor the batch root in the ledger's checkpoint chain.
        self._ledger.checkpoint()
        record = BatchRecord(
            batch_id=len(self._batches) + 1,
            first_seq=first_seq,
            last_seq=last_seq,
            merkle_root=batch.root,
            depth=batch.depth,
            attestation=attestation,
        )
        self._batches.append(record)
        self._pending_hashes = []
        self._pending_first_seq = last_seq + 1
        return record

    # -- reads ------------------------------------------------------

    def batches(self) -> Tuple[BatchRecord, ...]:
        with self._lock:
            return tuple(self._batches)

    def pending_count(self) -> int:
        with self._lock:
            return len(self._pending_hashes)

    def record_attestation(self, seq: int) -> Any:
        """Build an in-toto record attestation with Merkle proof.

        Finds the batch containing ``seq``, builds the inclusion
        proof, and wraps the record + proof in an envelope.  Raises
        SealedPipelineError if ``seq`` is not in a sealed batch yet
        (flush first).
        """
        with self._lock:
            batches = list(self._batches)
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 1:
            raise SealedPipelineError("seq must be int >= 1")
        target = None
        for b in batches:
            if b.first_seq <= seq <= b.last_seq:
                target = b
                break
        if target is None:
            raise SealedPipelineError(f"seq {seq} not in any sealed batch")
        record = self._ledger.record(seq)
        # Rebuild the batch's Merkle tree to get the proof.
        hashes = [self._ledger.record(s).record_hash for s in range(target.first_seq, target.last_seq + 1)]
        batch = self._seal_batch(tuple(hashes), first_seq=target.first_seq)
        proof = batch.proof(seq - target.first_seq)
        if not self._verify_proof(record.record_hash, proof, target.merkle_root):
            raise SealedPipelineError("internal: proof failed to verify")
        event_dict = {k: v for k, v in record.event}
        merkle_proof_dict = {
            "leaf_index": proof.leaf_index,
            "siblings": list(proof.siblings),
            "sibling_is_left": list(proof.sibling_is_left),
            "root": proof.root,
        }
        return self._attest_record(
            record_hash=record.record_hash,
            seq=record.seq,
            event=event_dict,
            input_fingerprint=record.input_fingerprint,
            logic_fingerprint=record.logic_fingerprint,
            execution_fingerprint=record.execution_fingerprint,
            seal=record.seal,
            prev_hash=record.prev_hash,
            merkle_proof=merkle_proof_dict,
        )

    def verify_pipeline(self, initial_key: bytes, checkpoint_key: bytes) -> Dict[str, Any]:
        """Verify ledger chain + all batch roots (pure read).

        Verifies the forward-seal chain, then re-derives every batch
        root from the ledger's record hashes and compares with the
        sealed batch records.  Returns a report; raises on any
        failure (fail-closed).
        """
        ledger_report = self._ledger.verify(initial_key, checkpoint_key)
        with self._lock:
            batches = list(self._batches)
        for b in batches:
            hashes = tuple(
                self._ledger.record(s).record_hash
                for s in range(b.first_seq, b.last_seq + 1)
            )
            rebuilt = self._seal_batch(hashes, first_seq=b.first_seq)
            if rebuilt.root != b.merkle_root:
                raise SealedPipelineError(
                    f"batch {b.batch_id} root mismatch: log tampered"
                )
        return {
            "version": SEALED_PIPELINE_VERSION,
            "ledger": ledger_report,
            "batches_verified": len(batches),
            "pipeline_ok": True,
        }


def stdlib_only() -> bool:
    """AST check: this module imports stdlib modules only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {
        "__future__",
        "ast",
        "dataclasses",
        "hashlib",
        "pathlib",
        "threading",
        "typing",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    """Self-check with stub collaborators (no sibling imports)."""
    import hashlib

    # Minimal stubs shaped like the real collaborators.
    class _Rec:
        def __init__(self, seq, rh):
            self.seq = seq
            self.record_hash = rh
            self.event = tuple((k, f"{k}-{seq}") for k in (
                "intent", "action", "subject", "authorization",
                "inputs_digest", "logic_digest", "execution_digest", "outcome"))
            self.input_fingerprint = rh
            self.logic_fingerprint = rh
            self.execution_fingerprint = rh
            self.seal = "de" * 32
            self.prev_hash = rh

    class _Ledger:
        def __init__(self):
            self._recs = []

        def append(self, **kw):
            seq = len(self._recs) + 1
            rh = "sha256:" + hashlib.sha256(f"rec-{seq}".encode()).hexdigest()
            # Fix event digests to pins.
            rec = _Rec(seq, rh)
            rec.event = tuple(
                (k, rh if k.endswith("_digest") else f"{k}-{seq}")
                for k in ("intent", "action", "subject", "authorization",
                          "inputs_digest", "logic_digest", "execution_digest", "outcome")
            )
            self._recs.append(rec)
            return rec

        def record(self, seq):
            return self._recs[seq - 1]

        def checkpoint(self):
            return ("cp", len(self._recs))

        def verify(self, a, b):
            return {"records_verified": len(self._recs)}

    class _Batch:
        def __init__(self, root, depth):
            self.root = root
            self.depth = depth

        def proof(self, index):
            class _P:
                leaf_index = index
                siblings = ()
                sibling_is_left = ()
                root = self.root
            return _P()

    def _seal_batch(hashes, first_seq=1):
        root = "sha256:" + hashlib.sha256(b"|".join(h.encode() for h in hashes)).hexdigest()
        return _Batch(root, 0)

    def _verify_proof(rh, proof, root):
        return True

    def _attest_record(**kw):
        return ("record-att", kw["seq"])

    def _attest_batch(**kw):
        return ("batch-att", kw["batch_root"])

    ledger = _Ledger()
    pipe = SealedPipeline(
        ledger=ledger,
        seal_batch_fn=_seal_batch,
        verify_proof_fn=_verify_proof,
        attest_record_fn=_attest_record,
        attest_batch_fn=_attest_batch,
        batch_interval=4,
    )
    for i in range(10):
        pipe.append(intent=f"i-{i}")
    assert len(pipe.batches()) == 2  # 8 batched, 2 pending
    assert pipe.pending_count() == 2
    flushed = pipe.flush()
    assert flushed is not None and flushed.last_seq == 10
    assert len(pipe.batches()) == 3
    assert pipe.flush() is None  # idempotent
    rep = pipe.verify_pipeline(b"k1", b"k2")
    assert rep["pipeline_ok"] is True
    assert rep["batches_verified"] == 3
    assert stdlib_only()
    print("sealed-pipeline OK: append, batch, flush, attest, verify, stdlib")


if __name__ == "__main__":
    main()
