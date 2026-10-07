"""Zero-knowledge proof prover interface for verifiable computation.

The prover-side complement to :mod:`zk_verifier`. Where ``zk_verifier``
checks that a presented proof is bound to a claimed statement,
this module is the *minting* half: given a statement (circuit + public
inputs) and a private witness, it produces a ``ZKProof`` the verifier
accepts, and exposes ``verify`` that re-checks a proof against the
*caller's* statement - not the proof's claimed statement. The latter is
the load-bearing statement-substitution defense: a valid proof for
statement A verifies ``False`` against statement B even though it is a
perfectly well-formed ``ZKProof`` for A.

Research basis (second-hand):
- Groth16 / Plonk / STARK families let a prover convince a verifier that
  a computation was done correctly without revealing private inputs.
- The prover-side hazards that matter to a runtime are: (a) proving for
  the wrong statement (mismatched public inputs), (b) witness leakage
  through the proof or its metadata, (c) proof reuse across statements.

Design (simulated cryptography, deterministic):
1. ``ZKProver`` is bound to one ``circuit_id`` at construction; ``prove``
   refuses a statement for any other circuit fail-closed.
2. ``prove(statement, witness)`` builds proof bytes as
   ``binding_digest || witness_pin`` where ``binding_digest`` is
   ``zk_verifier.bind_statement(circuit_id, public_inputs)`` (32 bytes)
   and ``witness_pin = sha256(domain || binding_digest || canonical(witness))``
   (32 bytes). The witness is *never* emitted raw - only its digest.
   Proofs are deterministic: same statement + witness always yields the
   same proof (a real scheme is randomized; determinism here is pinned so
   audits are replayable).
3. Optional key seal: if the prover was constructed with a
   ``verification_key``, the proof is sealed via
   ``zk_verifier.seal_with_key`` (trailing 32-byte HMAC), modelling the
   Groth16 verification-key binding.
4. ``verify(statement, proof, verification_key=None)`` recomputes the
   binding from the *given* statement and compares against the proof's
   first 32 bytes; it also rejects proofs whose claimed ``circuit_id``
   or ``public_inputs`` differ from the given statement. Policy failures
   return ``False`` (never raise); ``TypeError`` is only for programming
   errors (non-``Statement``, non-``ZKProof`` arguments).

Honest scope: interface, not real zero-knowledge. This provides no
soundness and no zero-knowledge property; anyone who can compute
sha256/HMAC can mint these proofs. A True verdict means "the proof is
bound to this statement (and this key) and claims knowledge of a
witness", never "the computation was correct" and never "the witness is
valid" - witness *validity* is not checked here, only witness *pin
well-formedness*. Do not use as a cryptographic commitment scheme.

No wall-clock anywhere. All functions are pure over the arguments given.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Any, Mapping, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except Exception:  # pragma: no cover - module must stay importable standalone
    import json as _json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("utf-8")


try:  # verifier-side construction this module stays compatible with
    from zk_verifier import (
        ZKProof,
        bind_statement,
        seal_with_key,
    )
except Exception:  # pragma: no cover - standalone fallback, same wire shape

    @dataclass(frozen=True)
    class ZKProof:  # type: ignore[no-redef]
        proof_bytes: bytes
        public_inputs: Mapping[str, Any]
        circuit_id: str
        schema: str = "northstar.zk-verifier.v1"

    def bind_statement(circuit_id: str,  # type: ignore[misc]
                       public_inputs: Mapping[str, Any]) -> bytes:
        h = hashlib.sha256()
        h.update(b"northstar-zk-binding.v1")
        h.update(b"\x00")
        h.update(circuit_id.encode("utf-8"))
        h.update(b"\x00")
        h.update(jcs_canonical_json(dict(public_inputs)))
        return h.digest()

    def seal_with_key(proof_bytes: bytes,  # type: ignore[misc]
                      verification_key: bytes) -> bytes:
        return (proof_bytes + hmac.new(verification_key, proof_bytes,
                                       hashlib.sha256).digest())


#: Version pin for the prover interface described here.
ZK_INTERFACE_VERSION = "zk-interface.v1"

#: Schema pin stamped on structured outputs.
SCHEMA_PIN = "northstar.zk-interface.v1"

#: Domain separator for the witness-commitment pin.
_WITNESS_DOMAIN = b"northstar-zk-prover-witness.v1"

#: Length of the statement binding digest (sha256, mirrors zk_verifier).
_BINDING_LEN = 32

#: Length of the witness-commitment pin (sha256).
_WITNESS_PIN_LEN = 32

#: Length of the key-seal MAC (HMAC-SHA256, mirrors zk_verifier).
_MAC_LEN = 32

#: Fail-closed upper bound on circuit id length.
_MAX_CIRCUIT_ID_LEN = 256

#: Fail-closed upper bound on verification key length.
_MAX_KEY_LEN = 256


class ZKInterfaceError(Exception):
    """Base error for the ZK prover interface (fail-closed misuse)."""


def _check_circuit_id(circuit_id: Any) -> str:
    if isinstance(circuit_id, bool) or not isinstance(circuit_id, str):
        raise TypeError("circuit_id must be a string")
    if not circuit_id:
        raise ValueError("circuit_id must be non-empty")
    if len(circuit_id) > _MAX_CIRCUIT_ID_LEN:
        raise ValueError("circuit_id exceeds maximum length")
    return circuit_id


def _check_public_inputs(public_inputs: Any) -> Mapping[str, Any]:
    if isinstance(public_inputs, bool) or not isinstance(public_inputs, Mapping):
        raise TypeError("public_inputs must be a mapping")
    for key in public_inputs.keys():
        if not isinstance(key, str) or not key:
            raise TypeError("public_inputs keys must be non-empty strings")
    try:
        jcs_canonical_json(dict(public_inputs))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"public_inputs must be JSON-canonicalizable: {exc}") from exc
    return public_inputs


def _check_key(key: Any) -> bytes:
    if isinstance(key, bool) or not isinstance(key, bytes):
        raise TypeError("verification_key must be bytes")
    if not key:
        raise ValueError("verification_key must be non-empty")
    if len(key) > _MAX_KEY_LEN:
        raise ValueError("verification_key exceeds maximum length")
    return key


def _check_witness(witness: Any) -> Mapping[str, Any]:
    """Witnesses are private inputs: canonicalizable mappings, never raw.

    The witness must be a mapping so its digest is well-defined; anything
    else (or anything non-canonicalizable, e.g. NaN) is fail-closed at the
    API boundary, never partially minted.
    """
    if isinstance(witness, bool) or not isinstance(witness, Mapping):
        raise TypeError("witness must be a mapping")
    for key in witness.keys():
        if not isinstance(key, str) or not key:
            raise TypeError("witness keys must be non-empty strings")
    try:
        jcs_canonical_json(dict(witness))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"witness must be JSON-canonicalizable: {exc}") from exc
    return witness


@dataclass(frozen=True)
class Statement:
    """The public half of a proof: circuit plus its public inputs.

    Frozen so a statement cannot drift between proving and verification
    on the same object.
    """

    circuit_id: str
    public_inputs: Mapping[str, Any]
    schema: str = SCHEMA_PIN

    def __post_init__(self) -> None:
        _check_circuit_id(self.circuit_id)
        _check_public_inputs(self.public_inputs)
        if self.schema != SCHEMA_PIN:
            raise ValueError(f"schema must be {SCHEMA_PIN!r}")

    def binding(self) -> bytes:
        """Deterministic 32-byte digest pinning this exact statement."""
        return bind_statement(self.circuit_id, self.public_inputs)

    def as_dict(self) -> dict:
        return {
            "circuit_id": self.circuit_id,
            "public_inputs": dict(self.public_inputs),
            "binding": "sha256:" + self.binding().hex(),
            "schema": self.schema,
            "version": ZK_INTERFACE_VERSION,
        }


def witness_pin(statement: Statement, witness: Mapping[str, Any]) -> bytes:
    """Digest committing a witness to a statement, without revealing it.

    ``sha256(domain || binding || canonical(witness))``: the pin is
    statement-bound (a witness pin for statement A is useless for
    statement B) and the witness itself never appears in the proof.
    """
    if not isinstance(statement, Statement):
        raise TypeError("statement must be a Statement")
    _check_witness(witness)
    h = hashlib.sha256()
    h.update(_WITNESS_DOMAIN)
    h.update(b"\x00")
    h.update(statement.binding())
    h.update(b"\x00")
    h.update(jcs_canonical_json(dict(witness)))
    return h.digest()


@dataclass(frozen=True)
class StatementVerifyReport:
    """Structured verdict from :func:`verify_detailed`."""

    valid: bool
    reasons: Tuple[str, ...]
    circuit_id: str
    schema: str = SCHEMA_PIN

    def as_dict(self) -> dict:
        return {
            "valid": self.valid,
            "reasons": list(self.reasons),
            "circuit_id": self.circuit_id,
            "schema": self.schema,
            "version": ZK_INTERFACE_VERSION,
        }


@dataclass(frozen=True)
class ZKProver:
    """Prover bound to one circuit; mints and re-checks proofs.

    Constructed once per deployment circuit; ``prove`` refuses any
    statement for a different circuit fail-closed, so a prover cannot be
    talked into minting proofs for a statement it does not own.
    """

    circuit_id: str
    verification_key: Optional[bytes] = None
    schema: str = SCHEMA_PIN

    def __post_init__(self) -> None:
        _check_circuit_id(self.circuit_id)
        if self.verification_key is not None:
            _check_key(self.verification_key)
        if self.schema != SCHEMA_PIN:
            raise ValueError(f"schema must be {SCHEMA_PIN!r}")

    def prove(self, statement: Statement, witness: Mapping[str, Any]) -> ZKProof:
        """Mint a proof for ``statement`` claiming knowledge of ``witness``.

        Proof bytes = ``binding || witness_pin`` (32 + 32 bytes),
        sealed with the construction key when one was configured. The
        witness is digested only; its raw bytes never enter the proof.
        Deterministic: same statement + witness always yields the same
        proof.
        """
        if not isinstance(statement, Statement):
            raise TypeError("statement must be a Statement")
        if statement.circuit_id != self.circuit_id:
            raise ZKInterfaceError(
                f"prover is bound to circuit {self.circuit_id!r}, "
                f"cannot prove for {statement.circuit_id!r}"
            )
        _check_witness(witness)
        body = statement.binding() + witness_pin(statement, witness)
        if self.verification_key is not None:
            body = seal_with_key(body, self.verification_key)
        return ZKProof(
            proof_bytes=body,
            public_inputs=dict(statement.public_inputs),
            circuit_id=statement.circuit_id,
        )

    def verify(
        self,
        statement: Statement,
        proof: ZKProof,
        verification_key: Optional[bytes] = None,
    ) -> bool:
        """Re-check ``proof`` against the caller's ``statement``.

        Returns True only when the proof's first 32 bytes equal the
        binding recomputed from ``statement`` (statement substitution
        fails here), the claimed statement matches, and the optional key
        MAC verifies.
        """
        return verify(statement, proof, verification_key)


def verify_detailed(
    statement: Statement,
    proof: ZKProof,
    verification_key: Optional[bytes] = None,
) -> StatementVerifyReport:
    """Verify ``proof`` against the given (not the claimed) statement.

    Checks, in order:
    - ``circuit-match`` / ``circuit-mismatch``: the proof's claimed
      circuit is the caller's circuit.
    - ``inputs-match`` / ``inputs-mismatch``: the proof's claimed public
      inputs canonicalize to the caller's.
    - ``binding-ok`` / ``binding-mismatch``: first 32 proof bytes equal
      the binding recomputed from the given statement.
    - ``witness-pin-ok`` / ``witness-pin-malformed``: the witness-commit
      slot is present and well-formed (32 bytes).
    - When ``verification_key`` is given: ``mac-ok`` / ``mac-mismatch``
      / ``mac-absent``.
    """
    if not isinstance(statement, Statement):
        raise TypeError("statement must be a Statement")
    if not isinstance(proof, ZKProof):
        raise TypeError("proof must be a ZKProof")
    if verification_key is not None:
        _check_key(verification_key)

    reasons: list[str] = []
    circuit_ok = proof.circuit_id == statement.circuit_id
    reasons.append("circuit-match" if circuit_ok else "circuit-mismatch")
    inputs_ok = (
        jcs_canonical_json(dict(proof.public_inputs))
        == jcs_canonical_json(dict(statement.public_inputs))
    )
    reasons.append("inputs-match" if inputs_ok else "inputs-mismatch")

    expected = statement.binding()
    binding_ok = len(proof.proof_bytes) >= _BINDING_LEN and hmac.compare_digest(
        proof.proof_bytes[:_BINDING_LEN], expected
    )
    reasons.append("binding-ok" if binding_ok else "binding-mismatch")

    pin_ok = len(proof.proof_bytes) >= _BINDING_LEN + _WITNESS_PIN_LEN
    reasons.append("witness-pin-ok" if pin_ok else "witness-pin-malformed")

    mac_ok = True
    if verification_key is not None:
        if len(proof.proof_bytes) >= _BINDING_LEN + _MAC_LEN:
            body, tag = proof.proof_bytes[:-_MAC_LEN], proof.proof_bytes[-_MAC_LEN:]
            if hmac.compare_digest(
                hmac.new(verification_key, body, hashlib.sha256).digest(), tag
            ):
                reasons.append("mac-ok")
            else:
                reasons.append("mac-mismatch")
                mac_ok = False
        else:
            reasons.append("mac-absent")
            mac_ok = False

    valid = circuit_ok and inputs_ok and binding_ok and pin_ok and mac_ok
    return StatementVerifyReport(
        valid=valid, reasons=tuple(reasons), circuit_id=statement.circuit_id
    )


def verify(
    statement: Statement,
    proof: ZKProof,
    verification_key: Optional[bytes] = None,
) -> bool:
    """Boolean verdict: does ``proof`` bind to ``statement``?

    Never raises on policy: malformed or mismatched proofs verify False.
    """
    return verify_detailed(statement, proof, verification_key).valid


def zk_audit_event(kind: str, circuit_id: str, seq: int) -> dict:
    """Shape a ZK prover lifecycle event as an ``audit.ndjson/1`` record.

    The witness never appears in audit records - only circuit identity
    and sequence numbers.
    """
    valid = ("proved", "verified", "verification-failed", "rejected")
    if kind not in valid:
        raise ValueError(f"unknown audit kind {kind!r}")
    _check_circuit_id(circuit_id)
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise ValueError("seq must be a non-negative int")
    return {
        "schema": "audit.ndjson/1",
        "kind": f"zk-interface.{kind}",
        "module": SCHEMA_PIN,
        "version": ZK_INTERFACE_VERSION,
        "circuit_id": circuit_id,
        "seq": seq,
    }


def main() -> None:
    prover = ZKProver("kyc-check.v1")
    stmt = Statement("kyc-check.v1", {"age_over": 18, "country": "CN"})
    proof = prover.prove(stmt, {"birth_year": 1990, "name": "secret"})
    assert isinstance(proof, ZKProof)
    assert proof.proof_bytes[:32] == stmt.binding()
    # The witness is never emitted raw.
    assert b"secret" not in proof.proof_bytes
    assert verify(stmt, proof) is True
    # Statement substitution fails.
    other = Statement("kyc-check.v1", {"age_over": 21, "country": "CN"})
    assert verify(other, proof) is False
    # Keyed prover: seal binds to the deployment key.
    keyed = ZKProver("kyc-check.v1", verification_key=b"deployment-key")
    sealed = keyed.prove(stmt, {"birth_year": 1990})
    assert verify(stmt, sealed, verification_key=b"deployment-key") is True
    assert verify(stmt, sealed, verification_key=b"wrong-key") is False
    print("zk-interface OK: prove, verify, statement-substitution defense, key seal")


if __name__ == "__main__":
    main()
