"""Vector commitment: stateless position-bound opening proofs.

Research motivation: a vector commitment (Catalano-Fiore) pins an ordered
vector with a short digest. Later anyone can *open* one position and hand
the opener a proof that a stateless verifier checks against the digest --
the verifier never holds the vector. That is the shape needed for audit
checkpoints and replicated state: one pinned root, per-position evidence.

This module is the hash-based construction (Merkle tree, RFC 6962-style
domain separation): position binding comes from hashing the index into
the leaf preimage, so a proof cannot be replayed at a different index.

Public API:

- ``VectorCommitment`` -- commits at construction. ``commit()`` returns
  the frozen ``Commitment`` record (root ``sha256:`` pin + size). ``open(
  index)`` returns a frozen ``OpeningProof`` for one position.
- ``verify(commitment, index, value, proof)`` -- recomputes the leaf hash
  and walks the proof path; returns ``True`` iff the recomputed root
  matches the commitment root. Malformed *types* raise; a proof that does
  not verify returns ``False``.
- ``vector_commitment_audit_event(kind, seq, ...)`` -- shapes
  ``audit.ndjson/1`` records for committed / opened / verified decisions.

Honest scope:

- Hash-based, not algebraic: proofs are O(log n), updates require a
  full re-commit (there is no position-binding *update* proof here).
  Pair with ``merkle_tree``-style audit trees for append-only logs.
- The commitment pins *integrity*, not *freshness*: a stale commitment
  still verifies. Recency is the host's job (seqs, epochs).
- ``verify`` checks the proof the host hands it -- it cannot prove the
  host did not commit to a different vector off-camera.
- Values must be JCS-canonicalizable (str/int/float/bool/None/list/dict
  with str keys). Non-canonicalizable values are rejected at commit time
  so every leaf can be pinned deterministically.
- In-memory state machine: no disk I/O, no persistence, no network. The
  host owns durability of the vector and transport of the proofs.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Dict, List, Sequence, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json, jcs_sha256_hex
except Exception:  # pragma: no cover - module must stay importable standalone
    import json as _json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("utf-8")

    def jcs_sha256_hex(obj: Any) -> str:  # type: ignore[no-redef]
        return hashlib.sha256(jcs_canonical_json(obj)).hexdigest()


#: Version pin for this module's record shape.
VECTOR_COMMITMENT_VERSION = "vector-commitment.v1"

#: Schema pin carried by records and audit events.
SCHEMA_PIN = "northstar.vector-commitment.v1"

#: Domain-separation prefixes (RFC 6962 style): leaf vs internal node.
_LEAF_PREFIX = b"\x00"
_NODE_PREFIX = b"\x01"

#: Guardrail: refuse to commit vectors larger than this (DoS bound).
MAX_VECTOR_SIZE = 1_048_576

#: Audit event kinds.
_COMMITTED = "committed"
_OPENED = "opened"
_VERIFIED = "verified"
_REJECTED = "rejected"


class VectorCommitmentError(Exception):
    """Base error for the vector commitment layer (programming errors)."""


class VerificationError(VectorCommitmentError):
    """Raised for malformed verification inputs (not a failed proof)."""


def _check_seq(value: object, name: str = "seq") -> int:
    """Validate a caller-supplied ordering seq: int, not bool, >= 0."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be int, got {type(value).__name__}")
    if value < 0:
        raise ValueError(f"{name} must be >= 0, got {value}")
    return value


def _check_digest(value: object, name: str = "digest") -> str:
    """Validate a ``sha256:<64 hex>`` digest pin."""
    if not isinstance(value, str):
        raise TypeError(f"{name} must be str, got {type(value).__name__}")
    if not value.startswith("sha256:") or len(value) != 71:
        raise ValueError(f"{name} must look like 'sha256:<64 hex>', "
                         f"got {value!r}")
    try:
        int(value[7:], 16)
    except ValueError:
        raise ValueError(f"{name} has non-hex body: {value!r}")
    return value


def _check_canonicalizable(value: Any, name: str) -> None:
    """Fail-closed: the value must survive canonical JSON round-trip."""
    try:
        raw = jcs_canonical_json(value)
    except (TypeError, ValueError) as exc:
        raise TypeError(f"{name} must be JCS-canonicalizable: {exc}")
    # A canonicalization that drops type information is not allowed:
    # e.g. tuple keys or non-str dict keys would silently change shape.
    if isinstance(value, dict):
        for key in value:
            if not isinstance(key, str):
                raise TypeError(
                    f"{name} dict keys must be str, got "
                    f"{type(key).__name__}")
    _ = raw


def _leaf_hash(index: int, value: Any) -> bytes:
    """Position-bound leaf hash: ``H(0x00 || index_be64 || canonical(value))``.

    Binding the index into the leaf preimage means a proof for position
    *i* cannot be replayed as evidence for position *j*.
    """
    index_bytes = index.to_bytes(8, "big", signed=False)
    return hashlib.sha256(_LEAF_PREFIX + index_bytes
                          + jcs_canonical_json(value)).digest()


def _node_hash(left: bytes, right: bytes) -> bytes:
    """Internal node hash: ``H(0x01 || left || right)``."""
    return hashlib.sha256(_NODE_PREFIX + left + right).digest()


def _root_and_levels(leaves: List[bytes]) -> Tuple[bytes, List[List[bytes]]]:
    """Build the tree; return (root, levels) with levels[0] = leaves.

    Odd levels duplicate the last node (standard Merkle padding).
    """
    if not leaves:
        raise VectorCommitmentError("cannot build a tree over zero leaves")
    levels = [list(leaves)]
    current = list(leaves)
    while len(current) > 1:
        nxt: List[bytes] = []
        for i in range(0, len(current), 2):
            left = current[i]
            right = current[i + 1] if i + 1 < len(current) else current[i]
            nxt.append(_node_hash(left, right))
        levels.append(nxt)
        current = nxt
    return current[0], levels


@dataclass(frozen=True)
class ProofStep:
    """One hop of an opening proof: the sibling hash and its side."""

    sibling: str  # "sha256:<hex>" pin of the sibling node
    sibling_is_left: bool  # True iff the sibling is the left child

    def __post_init__(self) -> None:
        _check_digest(self.sibling, "sibling")
        if not isinstance(self.sibling_is_left, bool):
            raise TypeError("sibling_is_left must be bool, got "
                            f"{type(self.sibling_is_left).__name__}")

    def as_dict(self) -> Dict[str, Any]:
        return {"sibling": self.sibling,
                "sibling_is_left": self.sibling_is_left,
                "schema": SCHEMA_PIN}


@dataclass(frozen=True)
class OpeningProof:
    """Frozen inclusion proof for one committed position."""

    index: int
    leaf: str  # "sha256:<hex>" pin of the leaf hash
    steps: Tuple[ProofStep, ...]  # bottom-up, leaf level first
    size: int  # committed vector size the proof was built against

    def __post_init__(self) -> None:
        if isinstance(self.index, bool) or not isinstance(self.index, int):
            raise TypeError(f"index must be int, got "
                            f"{type(self.index).__name__}")
        if self.index < 0:
            raise ValueError(f"index must be >= 0, got {self.index}")
        _check_digest(self.leaf, "leaf")
        if not isinstance(self.steps, tuple):
            raise TypeError(f"steps must be tuple, got "
                            f"{type(self.steps).__name__}")
        for step in self.steps:
            if not isinstance(step, ProofStep):
                raise TypeError(f"steps must hold ProofStep, got "
                                f"{type(step).__name__}")
        _check_seq(self.size, "size")
        if self.size == 0:
            raise ValueError("size must be > 0")
        if self.index >= self.size:
            raise ValueError(f"index {self.index} out of range for size "
                             f"{self.size}")

    def as_dict(self) -> Dict[str, Any]:
        return {"index": self.index,
                "leaf": self.leaf,
                "steps": [s.as_dict() for s in self.steps],
                "size": self.size,
                "schema": SCHEMA_PIN}


@dataclass(frozen=True)
class Commitment:
    """Frozen pin of a committed vector: root digest + size."""

    root: str  # "sha256:<hex>" pin of the Merkle root
    size: int  # number of committed positions
    version: str = VECTOR_COMMITMENT_VERSION

    def __post_init__(self) -> None:
        _check_digest(self.root, "root")
        _check_seq(self.size, "size")
        if self.size == 0:
            raise ValueError("size must be > 0")
        if self.version != VECTOR_COMMITMENT_VERSION:
            raise ValueError(f"version must be {VECTOR_COMMITMENT_VERSION!r}, "
                             f"got {self.version!r}")

    def as_dict(self) -> Dict[str, Any]:
        return {"root": self.root,
                "size": self.size,
                "version": self.version,
                "schema": SCHEMA_PIN}


class VectorCommitment:
    """Commit to an ordered vector; open positions with proofs.

    The vector is canonicalized and hashed at construction -- the
    ``Commitment`` pins it. ``open(index)`` builds the Merkle inclusion
    proof; ``verify`` (module-level) checks proofs without the vector.
    """

    def __init__(self, vector: Sequence[Any]) -> None:
        if not isinstance(vector, (list, tuple)):
            raise TypeError(f"vector must be list or tuple, got "
                            f"{type(vector).__name__}")
        if len(vector) == 0:
            raise ValueError("vector must be non-empty")
        if len(vector) > MAX_VECTOR_SIZE:
            raise ValueError(f"vector size {len(vector)} exceeds guardrail "
                             f"{MAX_VECTOR_SIZE}")
        for i, value in enumerate(vector):
            _check_canonicalizable(value, f"vector[{i}]")
        self._values: Tuple[Any, ...] = tuple(vector)
        leaves = [_leaf_hash(i, v) for i, v in enumerate(self._values)]
        root, levels = _root_and_levels(leaves)
        self._levels = levels
        self._commitment = Commitment(
            root="sha256:" + root.hex(), size=len(self._values))

    @property
    def size(self) -> int:
        """Number of committed positions."""
        return len(self._values)

    def commit(self) -> Commitment:
        """Return the frozen commitment pin for this vector."""
        return self._commitment

    def open(self, index: int) -> OpeningProof:
        """Build the inclusion proof for one position (fail-closed)."""
        if isinstance(index, bool) or not isinstance(index, int):
            raise TypeError(f"index must be int, got "
                            f"{type(index).__name__}")
        if index < 0 or index >= len(self._values):
            raise ValueError(f"index {index} out of range for size "
                             f"{len(self._values)}")
        steps: List[ProofStep] = []
        level_index = index
        for level in self._levels[:-1]:
            if level_index % 2 == 0:
                sibling_index = (level_index + 1
                                 if level_index + 1 < len(level)
                                 else level_index)
                sibling_is_left = False
            else:
                sibling_index = level_index - 1
                sibling_is_left = True
            steps.append(ProofStep(
                sibling="sha256:" + level[sibling_index].hex(),
                sibling_is_left=sibling_is_left))
            level_index //= 2
        return OpeningProof(
            index=index,
            leaf="sha256:" + self._levels[0][index].hex(),
            steps=tuple(steps),
            size=len(self._values))


def verify(commitment: Commitment, index: int, value: Any,
           proof: OpeningProof) -> bool:
    """Check an opening proof against a commitment (stateless).

    Returns ``True`` iff the leaf hash recomputed from ``(index, value)``
    walks the proof path up to the commitment root. Malformed *types*
    raise :class:`VerificationError` / ``TypeError``; a proof that simply
    does not verify returns ``False``.
    """
    if not isinstance(commitment, Commitment):
        raise TypeError(f"commitment must be Commitment, got "
                        f"{type(commitment).__name__}")
    if not isinstance(proof, OpeningProof):
        raise TypeError(f"proof must be OpeningProof, got "
                        f"{type(proof).__name__}")
    if isinstance(index, bool) or not isinstance(index, int):
        raise TypeError(f"index must be int, got {type(index).__name__}")
    if proof.size != commitment.size:
        raise VerificationError(
            f"proof size {proof.size} != commitment size {commitment.size}")
    if proof.index != index:
        # Position mismatch is a verification failure, not a type error.
        return False
    _check_canonicalizable(value, "value")
    current = _leaf_hash(index, value)
    for step in proof.steps:
        sibling = bytes.fromhex(step.sibling[7:])
        if step.sibling_is_left:
            current = _node_hash(sibling, current)
        else:
            current = _node_hash(current, sibling)
    return "sha256:" + current.hex() == commitment.root


def vector_commitment_audit_event(kind: str, seq: int,
                                  commitment: Commitment | None = None,
                                  index: int | None = None,
                                  verified: bool | None = None
                                  ) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for commitment decisions."""
    if kind not in (_COMMITTED, _OPENED, _VERIFIED, _REJECTED):
        raise ValueError(f"unknown kind: {kind!r}")
    _check_seq(seq, "seq")
    event: Dict[str, Any] = {
        "schema": "audit.ndjson/1",
        "module": SCHEMA_PIN,
        "kind": kind,
        "audit_seq": seq,
    }
    if commitment is not None:
        if not isinstance(commitment, Commitment):
            raise TypeError(f"expected Commitment, got "
                            f"{type(commitment).__name__}")
        event["root"] = commitment.root
        event["size"] = commitment.size
    if index is not None:
        if isinstance(index, bool) or not isinstance(index, int):
            raise TypeError(f"index must be int, got "
                            f"{type(index).__name__}")
        event["index"] = index
    if verified is not None:
        if not isinstance(verified, bool):
            raise TypeError(f"verified must be bool, got "
                            f"{type(verified).__name__}")
        event["verified"] = verified
    return event


def main() -> None:
    """Self-check: commit, open, verify, tamper detection."""
    vc = VectorCommitment(["alpha", "beta", "gamma", "delta"])
    commitment = vc.commit()
    for i in range(vc.size):
        proof = vc.open(i)
        assert verify(commitment, i, ["alpha", "beta", "gamma",
                                     "delta"][i], proof), f"index {i}"
    tampered = vc.open(1)
    assert not verify(commitment, 1, "BETA", tampered), "tamper not caught"
    assert not verify(commitment, 2, "beta", vc.open(1)), \
        "index shift not caught"
    print("vector-commitment OK: commit, open, verify, tamper detection")


if __name__ == "__main__":
    main()
