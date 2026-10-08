"""in-toto attestation envelopes for sealed records, Simulated.

P1 absorption from the exhaustive method search: the in-toto
Attestation framework (CNCF graduated) defines the standard envelope
for verifiable claims about software artifacts::

    { "_type": "https://in-toto.io/Statement/v1",
      "subject": [{"name": ..., "digest": {"sha256": ...}}],
      "predicateType": "<URI>",
      "predicate": { ... } }

This module wraps forward-seal ledger records (and Merkle batch
proofs) in that exact envelope shape, so a sealed decision can be
presented to any in-toto-compatible verifier without a custom
parser.  The predicate carries the 8-field event, the triple
fingerprints, and -- when available -- the Merkle inclusion proof
that anchors the record in a batch.

What this module IS: a pure, deterministic envelope builder and
checker.  ``attest()`` takes a sealed record's public fields and
produces the frozen in-toto statement dict; ``verify_envelope()``
checks the envelope's structural integrity (required fields, digest
shapes, predicate-type allowlist) and re-derives the statement
digest.

What this module IS NOT (honest scope):

* It does not sign the envelope.  Signing (DSSE) needs a private key
  the host must manage -- the same key-custody gap documented in
  ``forward_seal_ledger.py``.  The envelope carries a ``signature``
  slot that stays empty until the host provides one; an unsigned
  envelope is explicitly marked as such and must not be mistaken for
  an authenticated attestation.
* It does not re-verify the forward-seal MAC or the Merkle proof --
  those are the issuing ledger's job.  This module checks *envelope*
  integrity only.
* It does not prove the predicate's claims are true -- the host
  chose them.  Same honest-scope rule as every ledger here.

Predicate types (pinned vocabulary -- the allowlist)::

* ``https://northstar.io/attestation/sealed-record/v1`` --
  one forward-seal record with its 8-field event and triple
  fingerprints.
* ``https://northstar.io/attestation/sealed-batch/v1`` --
  one Merkle batch root covering N sealed records.
* ``https://northstar.io/attestation/sealed-checkpoint/v1`` --
  one forward-seal checkpoint over a chain head.

House style: frozen dataclasses, no wall-clock, stdlib-only,
``sha256:`` pins, ``canonical_json`` try/except fallback,
version/schema pins, ``stdlib_only()`` + ``main()`` self-check.
"""

from __future__ import annotations

import ast
import hashlib
from dataclasses import dataclass
from typing import Any, Dict, Tuple

try:
    from canonical_json import jcs_dumps as _jcs_dumps_raw  # type: ignore

    def _jcs_dumps(obj: Any) -> bytes:
        raw = _jcs_dumps_raw(obj)
        return raw.encode("utf-8") if isinstance(raw, str) else raw

except Exception:  # pragma: no cover - fallback when canonical_json is absent

    def _jcs_dumps(obj: Any) -> bytes:  # type: ignore
        import json

        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


#: Module version pin.
SEALED_ATTESTATION_VERSION = "sealed-attestation.v1"

#: Schema pin for envelopes produced by this module.
SCHEMA_PIN = "northstar.sealed-attestation.v1"

#: in-toto Statement type URI (pinned).
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"

#: Pinned predicate-type vocabulary (allowlist).
PREDICATE_SEALED_RECORD = "https://northstar.io/attestation/sealed-record/v1"
PREDICATE_SEALED_BATCH = "https://northstar.io/attestation/sealed-batch/v1"
PREDICATE_SEALED_CHECKPOINT = "https://northstar.io/attestation/sealed-checkpoint/v1"
PREDICATE_TYPES = (
    PREDICATE_SEALED_RECORD,
    PREDICATE_SEALED_BATCH,
    PREDICATE_SEALED_CHECKPOINT,
)

#: The 8 event fields a sealed-record predicate must carry.
EVENT_FIELDS = (
    "intent",
    "action",
    "subject",
    "authorization",
    "inputs_digest",
    "logic_digest",
    "execution_digest",
    "outcome",
)


class AttestationError(Exception):
    """Fail-closed: malformed envelopes raise, never produce bad output."""


def _require_pin(value: Any, name: str) -> str:
    if not isinstance(value, str):
        raise AttestationError(f"{name} must be str")
    if not value.startswith("sha256:") or len(value) != 71:
        raise AttestationError(f"{name} must be a sha256: pin")
    try:
        bytes.fromhex(value[7:])
    except ValueError:
        raise AttestationError(f"{name} hex is malformed")
    return value


def _require_nonempty_str(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise AttestationError(f"{name} must be a non-empty str")
    return value


@dataclass(frozen=True)
class Attestation:
    """A frozen in-toto envelope over sealed-ledger material."""

    statement_type: str
    subject_name: str
    subject_digest: str  # sha256: pin
    predicate_type: str
    predicate: Tuple[Tuple[str, Any], ...]  # sorted (key, value) pairs
    statement_digest: str  # sha256: pin of the canonical statement

    def to_dict(self) -> Dict[str, Any]:
        """Render as the standard in-toto JSON shape."""
        return {
            "_type": self.statement_type,
            "subject": [
                {
                    "name": self.subject_name,
                    "digest": {"sha256": self.subject_digest[7:]},
                }
            ],
            "predicateType": self.predicate_type,
            "predicate": {k: v for k, v in self.predicate},
        }


def attest_sealed_record(
    *,
    record_hash: str,
    seq: int,
    event: Dict[str, str],
    input_fingerprint: str,
    logic_fingerprint: str,
    execution_fingerprint: str,
    seal: str,
    prev_hash: str,
    merkle_proof: Dict[str, Any] | None = None,
) -> Attestation:
    """Wrap one forward-seal record in an in-toto envelope.

    ``event`` must carry exactly the 8 pinned fields.  All digests are
    ``sha256:`` pins.  ``merkle_proof`` (optional) is the dict form of
    a ``MerkleProof`` plus the batch root it was verified against.
    """
    _require_pin(record_hash, "record_hash")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 1:
        raise AttestationError("seq must be int >= 1")
    if not isinstance(event, dict):
        raise AttestationError("event must be dict")
    if tuple(sorted(event.keys())) != tuple(sorted(EVENT_FIELDS)):
        raise AttestationError("event must carry exactly the 8 pinned fields")
    for name in EVENT_FIELDS:
        _require_nonempty_str(event[name], f"event[{name}]")
    _require_pin(input_fingerprint, "input_fingerprint")
    _require_pin(logic_fingerprint, "logic_fingerprint")
    _require_pin(execution_fingerprint, "execution_fingerprint")
    _require_pin(prev_hash, "prev_hash")
    if not isinstance(seal, str) or not seal:
        raise AttestationError("seal must be a non-empty str")
    try:
        bytes.fromhex(seal)
    except ValueError:
        raise AttestationError("seal hex is malformed")

    predicate: Dict[str, Any] = {
        "seq": seq,
        "event": {k: event[k] for k in EVENT_FIELDS},
        "inputFingerprint": input_fingerprint,
        "logicFingerprint": logic_fingerprint,
        "executionFingerprint": execution_fingerprint,
        "recordSeal": seal,
        "prevHash": prev_hash,
    }
    if merkle_proof is not None:
        if not isinstance(merkle_proof, dict):
            raise AttestationError("merkle_proof must be dict")
        for key in ("leaf_index", "siblings", "root"):
            if key not in merkle_proof:
                raise AttestationError(f"merkle_proof missing {key!r}")
        _require_pin(merkle_proof["root"], "merkle_proof.root")
        predicate["merkleProof"] = merkle_proof

    statement = {
        "_type": STATEMENT_TYPE,
        "subject": [
            {"name": f"sealed-record:{seq}", "digest": {"sha256": record_hash[7:]}}
        ],
        "predicateType": PREDICATE_SEALED_RECORD,
        "predicate": predicate,
    }
    digest = "sha256:" + hashlib.sha256(_jcs_dumps(statement)).hexdigest()
    predicate_items = tuple(sorted(predicate.items()))
    return Attestation(
        statement_type=STATEMENT_TYPE,
        subject_name=f"sealed-record:{seq}",
        subject_digest=record_hash,
        predicate_type=PREDICATE_SEALED_RECORD,
        predicate=predicate_items,
        statement_digest=digest,
    )


def attest_sealed_batch(
    *,
    batch_root: str,
    first_seq: int,
    record_count: int,
    batch_depth: int,
) -> Attestation:
    """Wrap one Merkle batch root in an in-toto envelope."""
    _require_pin(batch_root, "batch_root")
    if isinstance(first_seq, bool) or not isinstance(first_seq, int) or first_seq < 1:
        raise AttestationError("first_seq must be int >= 1")
    if (
        isinstance(record_count, bool)
        or not isinstance(record_count, int)
        or record_count < 1
    ):
        raise AttestationError("record_count must be int >= 1")
    if isinstance(batch_depth, bool) or not isinstance(batch_depth, int) or batch_depth < 0:
        raise AttestationError("batch_depth must be int >= 0")

    predicate: Dict[str, Any] = {
        "firstSeq": first_seq,
        "recordCount": record_count,
        "batchDepth": batch_depth,
        "merkleRoot": batch_root,
    }
    statement = {
        "_type": STATEMENT_TYPE,
        "subject": [
            {
                "name": f"sealed-batch:{first_seq}-{first_seq + record_count - 1}",
                "digest": {"sha256": batch_root[7:]},
            }
        ],
        "predicateType": PREDICATE_SEALED_BATCH,
        "predicate": predicate,
    }
    digest = "sha256:" + hashlib.sha256(_jcs_dumps(statement)).hexdigest()
    return Attestation(
        statement_type=STATEMENT_TYPE,
        subject_name=f"sealed-batch:{first_seq}-{first_seq + record_count - 1}",
        subject_digest=batch_root,
        predicate_type=PREDICATE_SEALED_BATCH,
        predicate=tuple(sorted(predicate.items())),
        statement_digest=digest,
    )


def attest_checkpoint(
    *,
    checkpoint_seq: int,
    head_hash: str,
    records_sealed: int,
    checkpoint_seal: str,
) -> Attestation:
    """Wrap one forward-seal checkpoint in an in-toto envelope."""
    if isinstance(checkpoint_seq, bool) or not isinstance(checkpoint_seq, int) or checkpoint_seq < 1:
        raise AttestationError("checkpoint_seq must be int >= 1")
    _require_pin(head_hash, "head_hash")
    if (
        isinstance(records_sealed, bool)
        or not isinstance(records_sealed, int)
        or records_sealed < 1
    ):
        raise AttestationError("records_sealed must be int >= 1")
    if not isinstance(checkpoint_seal, str) or not checkpoint_seal:
        raise AttestationError("checkpoint_seal must be a non-empty str")

    predicate: Dict[str, Any] = {
        "checkpointSeq": checkpoint_seq,
        "headHash": head_hash,
        "recordsSealed": records_sealed,
        "checkpointSeal": checkpoint_seal,
    }
    statement = {
        "_type": STATEMENT_TYPE,
        "subject": [
            {"name": f"sealed-checkpoint:{checkpoint_seq}", "digest": {"sha256": head_hash[7:]}}
        ],
        "predicateType": PREDICATE_SEALED_CHECKPOINT,
        "predicate": predicate,
    }
    digest = "sha256:" + hashlib.sha256(_jcs_dumps(statement)).hexdigest()
    return Attestation(
        statement_type=STATEMENT_TYPE,
        subject_name=f"sealed-checkpoint:{checkpoint_seq}",
        subject_digest=head_hash,
        predicate_type=PREDICATE_SEALED_CHECKPOINT,
        predicate=tuple(sorted(predicate.items())),
        statement_digest=digest,
    )


def verify_envelope(att: Attestation) -> Dict[str, Any]:
    """Check an envelope's structural integrity (pure read).

    Verifies: statement type pin, predicate-type allowlist, subject
    digest shape, and that ``statement_digest`` re-derives from the
    canonical statement.  Returns a report dict; raises
    AttestationError on any failure (fail-closed).  This checks the
    *envelope*, not the truth of the predicate and not any signature
    (unsigned envelopes are the only kind this module produces).
    """
    if not isinstance(att, Attestation):
        raise AttestationError("attestation must be Attestation")
    if att.statement_type != STATEMENT_TYPE:
        raise AttestationError("unknown statement type")
    if att.predicate_type not in PREDICATE_TYPES:
        raise AttestationError("predicate type not in allowlist")
    _require_pin(att.subject_digest, "subject_digest")
    _require_pin(att.statement_digest, "statement_digest")

    rebuilt = {
        "_type": att.statement_type,
        "subject": [
            {
                "name": att.subject_name,
                "digest": {"sha256": att.subject_digest[7:]},
            }
        ],
        "predicateType": att.predicate_type,
        "predicate": {k: v for k, v in att.predicate},
    }
    expected = "sha256:" + hashlib.sha256(_jcs_dumps(rebuilt)).hexdigest()
    if expected != att.statement_digest:
        raise AttestationError("statement digest mismatch: envelope tampered")
    return {
        "version": SEALED_ATTESTATION_VERSION,
        "predicate_type": att.predicate_type,
        "subject": att.subject_name,
        "signed": False,
        "envelope_ok": True,
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
        "json",
        "pathlib",
        "typing",
        "canonical_json",
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
    """Self-check: attest a record, a batch, a checkpoint; verify all."""
    pin = "sha256:" + "ab" * 32
    event = {k: f"{k}-v" for k in EVENT_FIELDS}
    event["inputs_digest"] = pin
    event["logic_digest"] = pin
    event["execution_digest"] = pin
    rec = attest_sealed_record(
        record_hash=pin,
        seq=1,
        event=event,
        input_fingerprint=pin,
        logic_fingerprint=pin,
        execution_fingerprint=pin,
        seal="de" * 32,
        prev_hash=pin,
    )
    assert verify_envelope(rec)["envelope_ok"] is True
    batch = attest_sealed_batch(
        batch_root=pin, first_seq=1, record_count=64, batch_depth=6
    )
    assert verify_envelope(batch)["envelope_ok"] is True
    cp = attest_checkpoint(
        checkpoint_seq=64, head_hash=pin, records_sealed=64, checkpoint_seal="de" * 32
    )
    assert verify_envelope(cp)["envelope_ok"] is True
    # to_dict renders the standard shape.
    d = rec.to_dict()
    assert d["_type"] == STATEMENT_TYPE
    assert d["subject"][0]["digest"]["sha256"] == pin[7:]
    assert stdlib_only()
    print("sealed-attestation OK: record, batch, checkpoint, envelope, stdlib")


if __name__ == "__main__":
    main()
