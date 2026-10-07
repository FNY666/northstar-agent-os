"""zero_knowledge.py — zero-knowledge proving-system lifecycle bookkeeping.

Research context: ZK proving systems (Groth16 / Plonk / STARK families) let
a prover convince a verifier that a computation was performed correctly
without revealing private inputs. In an agent runtime the natural use is
attested computation: "I ran circuit C on public inputs X and got output Y",
with a proof the gate layer checks before acting on Y.

This module is deliberately distinct from the sibling ZK layers already on
the tree, per the additive sibling pattern:

- ``zk_verifier.py`` owns the *plumbing*: statement binding
  (``bind_statement``), the proof wire format, and the fail-closed verify
  contract. It is stateless and knows nothing of setups or history.
- ``zk_interface.py`` owns the *prover*: a ``ZKProver`` bound to one
  ``circuit_id`` at construction, minting deterministic proofs and
  re-checking them against the caller's statement (statement-substitution
  defense).
- ``stark_hash.py`` owns the *algebraic mechanics*: a Poseidon-style sponge
  over a toy field for in-circuit hashing.

This module owns the *lifecycle* neither sibling covers — the ceremony and
the ledger:

1. ``setup()`` — declares a circuit and books a (simulated) trusted-setup
   ceremony: constraint-system pin, proving-key digest pin, verification-key
   digest pin, and the ceremony transcript digest. Raw circuit text, toxic
   waste, and ceremony secrets never enter a record.
2. ``prove()`` — books one minted proof record for a registered circuit.
   The witness is pinned by digest only; raw witness bytes never enter a
   record and never cross the audit boundary.
3. ``verify()`` — a pure-read verification view: recomputes the statement
   binding and proof pin from the *booked* ingredients and reports the
   verdict as data.
4. ``retire()`` — terminal retirement of a circuit's setup; later ``prove``
   calls for it refuse fail-closed, and the id is never recycled.

Simulated cryptography: the digest algebra is genuine, but anyone who can
compute SHA-256 can mint these proofs. This module provides no soundness
and no zero-knowledge property. A booked ``valid=True`` means "the proof is
bound to this booked statement and its pins recompute", never "the
computation was correct" and never "the witness is valid" — witness
validity is not checked, only witness-pin well-formedness (the same GIGO
boundary every bookkeeping module in this repo shares).
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

try:  # pragma: no cover
    from canonical_json import jcs_dumps as _jcs_dumps  # type: ignore
except Exception:  # pragma: no cover
    _jcs_dumps = None  # type: ignore

VERSION = "zero-knowledge.v1"
SCHEMA = "northstar.zero-knowledge.v1"
AUDIT_SCHEMA = "audit.ndjson/1"

_DIGEST_PREFIX = "sha256:"
_MAX_INT = 2 ** 53
_MAX_ID_LEN = 128

# Pinned setup-ceremony vocabulary. "transparent" needs no trusted party
# (STARK-shaped); the rest book a ceremony whose toxic waste the host
# declares destroyed.
CEREMONIES = (
    "trusted-setup",
    "powers-of-tau",
    "mpc-ceremony",
    "transparent",
    "test-only",
)

# Host-declared toxic-waste disposition, pinned. Transparent ceremonies
# have no toxic waste ("n/a"); every other ceremony must declare it
# destroyed, fail-closed otherwise.
TOXIC_WASTE = (
    "destroyed",
    "n/a",
)

RETIRE_REASONS = (
    "manual",
    "superseded",
    "compromised",
    "invalidated",
)

AUDIT_KINDS = (
    "setup-completed",
    "proved",
    "retired",
    "zero-knowledge.rejected",
)


class ZeroKnowledgeError(Exception):
    """Base for all zero-knowledge ledger errors."""


class BadIdError(ZeroKnowledgeError):
    pass


class DuplicateCircuitError(ZeroKnowledgeError):
    pass


class UnknownCircuitError(ZeroKnowledgeError):
    pass


class RetiredCircuitError(ZeroKnowledgeError):
    pass


class BadDigestError(ZeroKnowledgeError):
    pass


class BadCeremonyError(ZeroKnowledgeError):
    pass


class BadWasteError(ZeroKnowledgeError):
    pass


class BadInputError(ZeroKnowledgeError):
    pass


class BadWitnessError(ZeroKnowledgeError):
    pass


class DuplicateProofError(ZeroKnowledgeError):
    pass


class UnknownProofError(ZeroKnowledgeError):
    pass


class BadReasonError(ZeroKnowledgeError):
    pass


class SeqOrderError(ZeroKnowledgeError):
    pass


class AuditKindError(ZeroKnowledgeError):
    pass


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError(f"seq must be an int, got {type(seq).__name__}")
    return seq


def _check_id(value: Any, what: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadIdError(f"{what} must be a str, got {type(value).__name__}")
    if not value or len(value) > _MAX_ID_LEN:
        raise BadIdError(f"{what} must be a non-empty str of <= {_MAX_ID_LEN} chars")
    return value


def _check_ceremony(value: Any) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadCeremonyError(f"ceremony must be a str, got {type(value).__name__}")
    if value not in CEREMONIES:
        raise BadCeremonyError(f"ceremony {value!r} not in pinned vocabulary")
    return value


def _check_waste(value: Any, ceremony: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadWasteError(f"toxic_waste must be a str, got {type(value).__name__}")
    if value not in TOXIC_WASTE:
        raise BadWasteError(f"toxic_waste {value!r} not in pinned vocabulary")
    # Consistency rule, fail-closed: transparent ceremonies have no toxic
    # waste; every other ceremony must declare it destroyed.
    want = "n/a" if ceremony == "transparent" else "destroyed"
    if value != want:
        raise BadWasteError(
            f"ceremony {ceremony!r} requires toxic_waste {want!r}, got {value!r}"
        )
    return value


def _check_reason(value: Any) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadReasonError(f"reason must be a str, got {type(value).__name__}")
    if value not in RETIRE_REASONS:
        raise BadReasonError(f"reason {value!r} not in pinned vocabulary")
    return value


def _check_digest_pin(value: Any, what: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadDigestError(f"{what} must be a str, got {type(value).__name__}")
    if len(value) != len(_DIGEST_PREFIX) + 64 or not value.startswith(_DIGEST_PREFIX):
        raise BadDigestError(f"{what} must be a {_DIGEST_PREFIX}<64hex> pin")
    body = value[len(_DIGEST_PREFIX) :]
    if any(c not in "0123456789abcdef" for c in body):
        raise BadDigestError(f"{what} must be lowercase hex")
    return value


def _check_mapping(value: Any, what: str, exc: type) -> Dict[str, Any]:
    if isinstance(value, bool) or not isinstance(value, dict):
        raise exc(f"{what} must be a mapping, got {type(value).__name__}")
    for key in value:
        if isinstance(key, bool) or not isinstance(key, str):
            raise exc(f"{what} keys must be str, got {type(key).__name__}")
    return value


def _check_participants(value: Any) -> Tuple[str, ...]:
    if isinstance(value, bool) or not isinstance(value, (list, tuple)):
        raise BadCeremonyError(
            f"participants must be a list/tuple, got {type(value).__name__}"
        )
    seen: set = set()
    out: List[str] = []
    for item in value:
        name = _check_id(item, "participant")
        if name in seen:
            raise BadCeremonyError(f"duplicate participant {name!r}")
        seen.add(name)
        out.append(name)
    return tuple(sorted(out))


# ---------------------------------------------------------------------------
# Canonical encoding and digest pins
# ---------------------------------------------------------------------------


def _canonical(payload: Any) -> bytes:
    if _jcs_dumps is not None:
        return _jcs_dumps(payload).encode("utf-8")  # type: ignore

    def _tag(v: Any) -> Any:
        if isinstance(v, bool):
            return {"t": "bool", "v": v}
        if isinstance(v, int):
            if abs(v) > _MAX_INT:
                raise ZeroKnowledgeError("integer outside safe range")
            return {"t": "int", "v": v}
        if isinstance(v, float):
            if v != v or v in (float("inf"), float("-inf")):
                raise ZeroKnowledgeError("non-finite float refused")
            return {"t": "float", "v": repr(v)}
        if isinstance(v, str):
            return {"t": "str", "v": v}
        if isinstance(v, (list, tuple)):
            return {"t": "list", "v": [_tag(i) for i in v]}
        if isinstance(v, dict):
            return {"t": "dict", "v": [[k, _tag(v[k])] for k in sorted(v)]}
        if v is None:
            return {"t": "null"}
        raise ZeroKnowledgeError(f"unencodable type: {type(v).__name__}")

    import json

    return json.dumps(_tag(payload), sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


def _digest_pin(payload: Any, tag: str) -> str:
    return _DIGEST_PREFIX + hashlib.sha256(
        tag.encode("utf-8") + b"\x1f" + _canonical(payload)
    ).hexdigest()


def _binding_digest(circuit_id: str, inputs_hex: str) -> str:
    """Deterministic statement binding: the proof is about *this* circuit
    and *these* public inputs. Statement substitution across proofs fails
    because the binding is recomputed at verify time from booked pins."""
    return _digest_pin((circuit_id, inputs_hex), "statement")


def _proof_pin(proving_key_digest: str, statement_digest: str, witness_pin: str) -> str:
    """Deterministic proof pin over the setup's proving key, the statement
    binding, and the witness pin. Simulated: no soundness, see module doc."""
    return _digest_pin(
        (proving_key_digest, statement_digest, witness_pin), "proof"
    )


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SetupRecord:
    """One booked trusted-setup ceremony for a circuit."""

    circuit_id: str
    ceremony: str
    constraint_digest: str
    participants: Tuple[str, ...]
    toxic_waste: str
    proving_key_digest: str
    verification_key_digest: str
    digest: str
    seq: int
    schema: str = SCHEMA
    version: str = VERSION

    def as_dict(self) -> Dict[str, Any]:
        return {
            "circuit_id": self.circuit_id,
            "ceremony": self.ceremony,
            "constraint_digest": self.constraint_digest,
            "participants": list(self.participants),
            "toxic_waste": self.toxic_waste,
            "proving_key_digest": self.proving_key_digest,
            "verification_key_digest": self.verification_key_digest,
            "digest": self.digest,
            "seq": self.seq,
            "schema": self.schema,
            "version": self.version,
        }

    def verify(self) -> bool:
        expect = _digest_pin(
            (
                self.circuit_id,
                self.ceremony,
                self.constraint_digest,
                self.participants,
                self.toxic_waste,
            ),
            "setup",
        )
        return self.digest == expect


@dataclass(frozen=True)
class ProofRecord:
    """One booked proof for a registered circuit.

    The witness is pinned by digest only — raw witness bytes never enter a
    record. Public inputs travel as the canonical-bytes hex digest.
    """

    proof_id: str
    circuit_id: str
    statement_digest: str
    inputs_digest: str
    witness_pin: str
    proof_pin: str
    digest: str
    seq: int
    schema: str = SCHEMA
    version: str = VERSION

    def as_dict(self) -> Dict[str, Any]:
        return {
            "proof_id": self.proof_id,
            "circuit_id": self.circuit_id,
            "statement_digest": self.statement_digest,
            "inputs_digest": self.inputs_digest,
            "witness_pin": self.witness_pin,
            "proof_pin": self.proof_pin,
            "digest": self.digest,
            "seq": self.seq,
            "schema": self.schema,
            "version": self.version,
        }

    def verify(self) -> bool:
        expect = _digest_pin(
            (
                self.proof_id,
                self.circuit_id,
                self.statement_digest,
                self.inputs_digest,
                self.witness_pin,
                self.proof_pin,
            ),
            "proof-record",
        )
        return self.digest == expect


@dataclass(frozen=True)
class VerifyReport:
    """One verification of a booked proof. Verdicts are data, never raised.

    ``valid`` is True only when every pin recomputes *and* the circuit is
    still live. An unknown proof reports ``valid=False`` as data.
    """

    proof_id: str
    circuit_id: str
    statement_digest: str
    valid: bool
    integrity_ok: bool
    circuit_retired: bool
    digest: str
    seq: int
    schema: str = SCHEMA
    version: str = VERSION

    def as_dict(self) -> Dict[str, Any]:
        return {
            "proof_id": self.proof_id,
            "circuit_id": self.circuit_id,
            "statement_digest": self.statement_digest,
            "valid": self.valid,
            "integrity_ok": self.integrity_ok,
            "circuit_retired": self.circuit_retired,
            "digest": self.digest,
            "seq": self.seq,
            "schema": self.schema,
            "version": self.version,
        }

    def verify(self) -> bool:
        expect = _digest_pin(
            (
                self.proof_id,
                self.circuit_id,
                self.statement_digest,
                self.valid,
                self.integrity_ok,
                self.circuit_retired,
            ),
            "verification",
        )
        return self.digest == expect


@dataclass(frozen=True)
class RetireRecord:
    """Terminal retirement of a circuit's setup; the id is never recycled."""

    circuit_id: str
    reason: str
    digest: str
    seq: int
    schema: str = SCHEMA
    version: str = VERSION

    def as_dict(self) -> Dict[str, Any]:
        return {
            "circuit_id": self.circuit_id,
            "reason": self.reason,
            "digest": self.digest,
            "seq": self.seq,
            "schema": self.schema,
            "version": self.version,
        }

    def verify(self) -> bool:
        expect = _digest_pin((self.circuit_id, self.reason), "retire")
        return self.digest == expect


# ---------------------------------------------------------------------------
# Audit event builder
# ---------------------------------------------------------------------------


def zero_knowledge_audit_event(audit_kind: str, seq: int, **detail: Any) -> Dict[str, Any]:
    """Build one audit.ndjson/1 event.

    Raw witness material, ceremony secrets, and key bytes never cross this
    boundary — only ids, vocabulary labels, and digest pins.
    """
    if audit_kind not in AUDIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {audit_kind!r}")
    banned = (
        "witness",
        "secret",
        "toxic",
        "transcript",
        "key",
        "payload",
        "raw",
        "content",
        "value",
        "plaintext",
        "private",
        "constraint",
        "inputs",
    )
    for bad in banned:
        if bad in detail:
            raise AuditKindError(f"audit detail bans {bad!r}")
    _check_seq(seq)
    event = {
        "schema": AUDIT_SCHEMA,
        "module": "zero-knowledge",
        "kind": audit_kind,
        "seq": seq,
        "detail": detail,
    }
    event["digest"] = _digest_pin(
        (audit_kind, seq, tuple(sorted(detail))), "audit-event"
    )
    return event


# ---------------------------------------------------------------------------
# Zero-knowledge lifecycle ledger
# ---------------------------------------------------------------------------


class ZeroKnowledge:
    """ZK proving-system lifecycle: setup(), prove(), verify(), retire()."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        # circuit_id -> SetupRecord (insertion ordered)
        self._setups: Dict[str, SetupRecord] = {}
        # proof_id -> ProofRecord (insertion ordered)
        self._proofs: Dict[str, ProofRecord] = {}
        # circuit_id -> RetireRecord
        self._retirements: Dict[str, RetireRecord] = {}
        # retired circuit ids
        self._retired: set = set()
        self._audit_events: List[Dict[str, Any]] = []

    # -- seq discipline ----------------------------------------------------

    def _claim(self, seq: Any) -> int:
        seq = _check_seq(seq)
        if seq <= self._seq:
            raise SeqOrderError(f"seq {seq} not strictly greater than {self._seq}")
        self._seq = seq
        return seq

    def _emit(self, audit_kind: str, seq: int, **detail: Any) -> None:
        self._audit_events.append(
            zero_knowledge_audit_event(audit_kind, seq, **detail)
        )

    def _fail(self, seq: int, exc: ZeroKnowledgeError, **detail: Any) -> None:
        self._emit(AUDIT_KINDS[-1], seq, error=type(exc).__name__, **detail)
        raise exc

    # -- mutations ----------------------------------------------------------

    def setup(
        self,
        circuit_id: str,
        seq: int,
        ceremony: str = "transparent",
        constraint_digest: str = "",
        participants: Tuple[str, ...] = (),
        toxic_waste: str = "n/a",
    ) -> SetupRecord:
        """Book a trusted-setup ceremony for one circuit.

        The constraint system (arithmetization) travels as a digest pin only;
        raw circuit text never enters a record. The ceremony transcript and
        any toxic waste are declared, never stored.
        """
        with self._lock:
            seq = self._claim(seq)
            try:
                circuit_id = _check_id(circuit_id, "circuit_id")
                ceremony = _check_ceremony(ceremony)
                constraint_digest = _check_digest_pin(constraint_digest, "constraint_digest")
                participants = _check_participants(participants)
                toxic_waste = _check_waste(toxic_waste, ceremony)
                if circuit_id in self._retired:
                    raise RetiredCircuitError(f"circuit {circuit_id!r} retired")
                if circuit_id in self._setups:
                    raise DuplicateCircuitError(
                        f"circuit {circuit_id!r} already has a setup"
                    )
            except ZeroKnowledgeError as exc:
                self._fail(seq, exc, circuit_id=str(circuit_id))
            proving_key_digest = _digest_pin(
                (circuit_id, constraint_digest, ceremony), "proving-key"
            )
            verification_key_digest = _digest_pin(
                (circuit_id, ceremony, "verification-key"), "verification-key"
            )
            record = SetupRecord(
                circuit_id=circuit_id,
                ceremony=ceremony,
                constraint_digest=constraint_digest,
                participants=participants,
                toxic_waste=toxic_waste,
                proving_key_digest=proving_key_digest,
                verification_key_digest=verification_key_digest,
                digest=_digest_pin(
                    (
                        circuit_id,
                        ceremony,
                        constraint_digest,
                        participants,
                        toxic_waste,
                    ),
                    "setup",
                ),
                seq=seq,
            )
            self._setups[circuit_id] = record
            self._emit(
                "setup-completed",
                seq,
                circuit_id=circuit_id,
                ceremony=ceremony,
                participant_count=len(participants),
            )
            return record

    def prove(
        self,
        circuit_id: str,
        proof_id: str,
        public_inputs: Dict[str, Any],
        witness: Dict[str, Any],
        seq: int,
    ) -> ProofRecord:
        """Book one proof for a registered circuit.

        The witness is pinned by digest only — raw witness bytes never enter
        a record and never cross the audit boundary. The statement binding
        is recomputed at verify time, so a proof bound to statement A
        verifies False against statement B.
        """
        with self._lock:
            seq = self._claim(seq)
            try:
                circuit_id = _check_id(circuit_id, "circuit_id")
                proof_id = _check_id(proof_id, "proof_id")
                public_inputs = _check_mapping(public_inputs, "public_inputs", BadInputError)
                witness = _check_mapping(witness, "witness", BadWitnessError)
                if circuit_id in self._retired:
                    raise RetiredCircuitError(f"circuit {circuit_id!r} retired")
                setup = self._setups.get(circuit_id)
                if setup is None:
                    raise UnknownCircuitError(f"circuit {circuit_id!r} has no setup")
                if proof_id in self._proofs:
                    raise DuplicateProofError(f"proof {proof_id!r} already booked")
                try:
                    inputs_bytes = _canonical(public_inputs)
                except Exception as exc:
                    raise BadInputError(f"public_inputs unencodable: {exc}")
                try:
                    witness_bytes = _canonical(witness)
                except Exception as exc:
                    raise BadWitnessError(f"witness unencodable: {exc}")
            except ZeroKnowledgeError as exc:
                self._fail(
                    seq, exc, circuit_id=str(circuit_id), proof_id=str(proof_id)
                )
            inputs_hex = inputs_bytes.hex()
            witness_pin = _digest_pin((witness_bytes.hex(),), "witness")
            statement_digest = _binding_digest(circuit_id, inputs_hex)
            proof_pin = _proof_pin(
                setup.proving_key_digest, statement_digest, witness_pin
            )
            record = ProofRecord(
                proof_id=proof_id,
                circuit_id=circuit_id,
                statement_digest=statement_digest,
                inputs_digest=inputs_hex,
                witness_pin=witness_pin,
                proof_pin=proof_pin,
                digest=_digest_pin(
                    (
                        proof_id,
                        circuit_id,
                        statement_digest,
                        inputs_hex,
                        witness_pin,
                        proof_pin,
                    ),
                    "proof-record",
                ),
                seq=seq,
            )
            self._proofs[proof_id] = record
            self._emit(
                "proved",
                seq,
                proof_id=proof_id,
                circuit_id=circuit_id,
                statement_digest=statement_digest,
            )
            return record

    def retire(self, circuit_id: str, seq: int, reason: str = "manual") -> RetireRecord:
        """Terminal retirement of a circuit's setup; the id is never recycled.

        Booked proofs stay verifiable — retirement blocks new proves, not
        verification of history.
        """
        with self._lock:
            seq = self._claim(seq)
            try:
                circuit_id = _check_id(circuit_id, "circuit_id")
                reason = _check_reason(reason)
                if circuit_id in self._retired:
                    raise RetiredCircuitError(f"circuit {circuit_id!r} already retired")
                if circuit_id not in self._setups:
                    raise UnknownCircuitError(f"circuit {circuit_id!r} has no setup")
            except ZeroKnowledgeError as exc:
                self._fail(seq, exc, circuit_id=str(circuit_id))
            record = RetireRecord(
                circuit_id=circuit_id,
                reason=reason,
                digest=_digest_pin((circuit_id, reason), "retire"),
                seq=seq,
            )
            self._retired.add(circuit_id)
            self._retirements[circuit_id] = record
            self._emit("retired", seq, circuit_id=circuit_id, reason=reason)
            return record

    # -- views (pure reads: validate seq shape, never consume, no audit rows) --

    def verify(self, proof_id: str, seq: int) -> VerifyReport:
        """Verify one booked proof. Verdicts are data: an unknown proof
        reports ``valid=False``; tampered pins report ``integrity_ok=False``.
        Nothing is raised for absent proofs."""
        with self._lock:
            _check_seq(seq)
            _check_id(proof_id, "proof_id")
            proof = self._proofs.get(proof_id)
            if proof is None:
                return VerifyReport(
                    proof_id=proof_id,
                    circuit_id="",
                    statement_digest="",
                    valid=False,
                    integrity_ok=True,
                    circuit_retired=False,
                    digest=_digest_pin(
                        (proof_id, "", "", False, True, False),
                        "verification",
                    ),
                    seq=seq,
                )
            setup = self._setups.get(proof.circuit_id)
            integrity_ok = proof.verify()
            expected_statement = _binding_digest(proof.circuit_id, proof.inputs_digest)
            expected_proof = _proof_pin(
                setup.proving_key_digest if setup is not None else "",
                expected_statement,
                proof.witness_pin,
            )
            pins_recompute = (
                expected_statement == proof.statement_digest
                and expected_proof == proof.proof_pin
            )
            integrity_ok = integrity_ok and pins_recompute and setup is not None
            circuit_retired = proof.circuit_id in self._retired
            valid = integrity_ok and not circuit_retired
            report = VerifyReport(
                proof_id=proof_id,
                circuit_id=proof.circuit_id,
                statement_digest=proof.statement_digest,
                valid=valid,
                integrity_ok=integrity_ok,
                circuit_retired=circuit_retired,
                digest=_digest_pin(
                    (
                        proof_id,
                        proof.circuit_id,
                        proof.statement_digest,
                        valid,
                        integrity_ok,
                        circuit_retired,
                    ),
                    "verification",
                ),
                seq=seq,
            )
            return report

    def setup_record(self, circuit_id: str, seq: int) -> SetupRecord:
        _check_seq(seq)
        _check_id(circuit_id, "circuit_id")
        if circuit_id not in self._setups:
            raise UnknownCircuitError(f"circuit {circuit_id!r} has no setup")
        return self._setups[circuit_id]

    def circuit_ids(self, seq: int) -> Tuple[str, ...]:
        _check_seq(seq)
        return tuple(self._setups)

    def proof_record(self, proof_id: str, seq: int) -> ProofRecord:
        _check_seq(seq)
        _check_id(proof_id, "proof_id")
        if proof_id not in self._proofs:
            raise UnknownProofError(f"proof {proof_id!r} not booked")
        return self._proofs[proof_id]

    def proof_ids(self, seq: int) -> Tuple[str, ...]:
        _check_seq(seq)
        return tuple(self._proofs)

    def retired_ids(self, seq: int) -> Tuple[str, ...]:
        _check_seq(seq)
        return tuple(sorted(self._retired))

    def stats(self, seq: int) -> Dict[str, int]:
        _check_seq(seq)
        return {
            "circuits": len(self._setups),
            "proofs": len(self._proofs),
            "retired": len(self._retired),
            "seq": self._seq,
        }

    def audit_log(self, seq: int) -> Tuple[Dict[str, Any], ...]:
        _check_seq(seq)
        return tuple(self._audit_events)


# ---------------------------------------------------------------------------
# Self-check
# ---------------------------------------------------------------------------


def main() -> None:
    zk = ZeroKnowledge()
    cd = "sha256:" + "ab" * 32
    rec = zk.setup("range-proof", 1, ceremony="transparent", constraint_digest=cd)
    assert rec.verify() and rec.ceremony == "transparent"
    assert rec.digest.startswith(_DIGEST_PREFIX)
    assert rec.toxic_waste == "n/a"
    # trusted-setup ceremony books destroyed toxic waste
    rec2 = zk.setup(
        "groth16-circuit", 2, ceremony="trusted-setup", constraint_digest=cd,
        participants=("alice",), toxic_waste="destroyed",
    )
    assert rec2.verify() and rec2.toxic_waste == "destroyed"
    try:
        zk.setup("range-proof", 3, ceremony="transparent", constraint_digest=cd)
    except DuplicateCircuitError:
        pass
    else:
        raise AssertionError("duplicate setup accepted")
    try:
        zk.setup("bad-ceremony", 4, ceremony="trusted-setup",
                 constraint_digest=cd, toxic_waste="n/a")
    except BadWasteError:
        pass
    else:
        raise AssertionError("toxic-waste mismatch accepted")
    proof = zk.prove("range-proof", "proof-1",
                     {"x": 3, "limit": 10},
                     {"secret_note": "correct-horse-battery-staple"}, 5)
    assert proof.verify() and proof.proof_pin.startswith(_DIGEST_PREFIX)
    # witness never enters the record: only its digest pin
    as_text = repr(proof.as_dict())
    assert "correct-horse-battery-staple" not in as_text
    assert "secret_note" not in as_text
    rep = zk.verify("proof-1", 6)
    assert rep.verify() and rep.valid is True and rep.integrity_ok is True
    assert rep.circuit_retired is False
    # unknown proof reports valid=False as data
    rep2 = zk.verify("never-seen", 7)
    assert rep2.verify() and rep2.valid is False
    try:
        zk.prove("range-proof", "proof-1", {"x": 1}, {"y": 2}, 8)
    except DuplicateProofError:
        pass
    else:
        raise AssertionError("duplicate proof accepted")
    try:
        zk.prove("no-circuit", "proof-9", {"x": 1}, {"y": 2}, 9)
    except UnknownCircuitError:
        pass
    else:
        raise AssertionError("prove for unknown circuit accepted")
    ret = zk.retire("range-proof", 10, reason="superseded")
    assert ret.verify()
    rep3 = zk.verify("proof-1", 11)
    assert rep3.verify() and rep3.valid is False and rep3.circuit_retired is True
    assert rep3.integrity_ok is True
    try:
        zk.prove("range-proof", "proof-10", {"x": 1}, {"y": 2}, 12)
    except RetiredCircuitError:
        pass
    else:
        raise AssertionError("prove after retire accepted")
    try:
        zk.setup("range-proof", 13, ceremony="transparent", constraint_digest=cd)
    except RetiredCircuitError:
        pass
    else:
        raise AssertionError("re-setup of retired circuit accepted")
    zk2 = ZeroKnowledge()
    zk2.setup("c", 1, ceremony="transparent", constraint_digest=cd)
    assert zk2.stats(2)["circuits"] == 1
    print("zero-knowledge OK: setup, prove, verify, retire, refusals")


if __name__ == "__main__":
    main()
