"""Secure aggregation verifier: federated-learning sums without revealing individuals.

Research basis (second-hand):
- Bonawitz et al. secure aggregation: clients mask updates so the server
  learns only the sum, never any individual update. The verification problem
  here is narrower: given a claimed aggregate and a set of per-client
  commitments, check the arithmetic *without ever seeing individual updates*.
- Byzantine-robust FL literature (Krum, trimmed mean, etc.): aggregation is
  the attack surface. This module does NOT do robust aggregation - it
  verifies a claimed sum against homomorphic commitments. Detecting clients
  that commit to malicious values is the byzantine layer's job
  (see federated_attack_detector).

Construction (teaching-grade, NOT production MPC):
- Field P = 2**127 - 1 (Mersenne prime); G is a fixed public constant.
- Additive secret sharing: split_update deterministically expands the
  caller-supplied seed with SHA-256 into n-1 masks; the final share carries
  the remainder, so the shares always sum to the value mod P. Any proper
  subset of a client's shares is uniformly random mod P, so one share (or
  all-but-one) reveals nothing about the client's value.
- Homomorphic commitments (Pedersen-style, additive group):
  C_i = G * v_i + r_i (mod P). Summing over clients:
  sum(C_i) = G * sum(v_i) + sum(r_i) (mod P).
  The aggregator publishes (total, blinding_sum). Publishing the SUM of the
  blindings reveals nothing about any individual blinding.
- verify_aggregation checks the homomorphic equation plus structural
  invariants: distinct clients, well-formed commitments, count match.

The aggregator only ever handles shares (aggregate_shares takes shares, not
values); the verifier only ever handles commitments and the published
(total, blinding_sum). Individual updates appear in neither function.

Honest scope: verifies that a claimed (total, blinding_sum) is *consistent*
with the published commitments. It does NOT check that commitments bind the
clients' true updates (a client can commit to a lie - the byzantine layer's
job), does not hide the total (the total is the intended output), is not
constant-time, and offers no protection against hash collisions beyond
SHA-256. A True verdict means "the arithmetic checks out", never "the
updates were honest".

No wall-clock anywhere. Masking is deterministic from the caller-supplied
seed (hashlib expansion - no random module, no global RNG state). All
functions are pure over their inputs.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Mapping, Sequence

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except Exception:  # pragma: no cover - module must stay importable standalone
    import json as _json

    def jcs_canonical_json(obj: object) -> bytes:  # type: ignore[no-redef]
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("utf-8")


#: Version pin for the construction described here.
SECURE_AGGREGATION_VERSION = "secure-aggregation.v1"

#: Schema pin for records emitted by this module.
SECURE_AGGREGATION_SCHEMA = "northstar.secure-aggregation.v1"

#: Mersenne prime field for shares and commitments.
FIELD_PRIME = 2**127 - 1

#: Fixed public generator constant (arbitrary, pinned for determinism).
GENERATOR = 0x9E3779B97F4A7C15


def _int_to_bytes(value: int) -> bytes:
    return value.to_bytes(16, "big", signed=False)


def _expand_seed(seed: bytes, client_id: str, index: int) -> int:
    """Deterministically derive a field element from (seed, client_id, index)."""
    digest = hashlib.sha256(
        seed + b"|" + client_id.encode("utf-8") + b"|" + str(index).encode("utf-8")
    ).digest()
    return int.from_bytes(digest, "big") % FIELD_PRIME


def _pin(body: Mapping[str, object]) -> str:
    return "sha256:" + hashlib.sha256(jcs_canonical_json(body)).hexdigest()


def _hexint(value: int) -> str:
    """Encode a field element as fixed-width hex.

    JCS (RFC 8785) serializes integers outside +/-2**53 as IEEE 754 doubles,
    which is lossy for 127-bit field elements. Hex-encoding keeps the pin
    body deterministic *and* injective.
    """
    return format(value, "032x")


def _check_client_id(client_id: object) -> str:
    if not isinstance(client_id, str) or not client_id:
        raise ValueError("client_id must be a non-empty str")
    return client_id


def _check_value(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an int")
    if not 0 <= value < FIELD_PRIME:
        raise ValueError(f"{name} must be in [0, FIELD_PRIME)")
    return value


@dataclass(frozen=True)
class Share:
    """One additive share of a client's update. A single share reveals nothing."""

    client_id: str
    share_index: int
    n_shares: int
    value: int
    digest: str  # sha256 pin over the canonical body (tamper-evident)

    def as_dict(self) -> dict:
        return {
            "client_id": self.client_id,
            "share_index": self.share_index,
            "n_shares": self.n_shares,
            "value": self.value,
            "digest": self.digest,
            "schema": SECURE_AGGREGATION_SCHEMA,
            "version": SECURE_AGGREGATION_VERSION,
        }


def _share_body(client_id: str, share_index: int, n_shares: int, value: int) -> dict:
    return {
        "client_id": client_id,
        "share_index": share_index,
        "n_shares": n_shares,
        "value": _hexint(value),
        "schema": SECURE_AGGREGATION_SCHEMA,
        "version": SECURE_AGGREGATION_VERSION,
    }


def split_update(client_id: str, value: int, n_shares: int, seed: bytes) -> tuple:
    """Split a client's update into n_shares additive shares (deterministic).

    The first n_shares-1 shares are SHA-256-derived masks; the last share is
    the remainder, so the shares always sum to ``value`` mod FIELD_PRIME.
    """
    client_id = _check_client_id(client_id)
    value = _check_value(value, "value")
    if isinstance(n_shares, bool) or not isinstance(n_shares, int):
        raise TypeError("n_shares must be an int")
    if n_shares < 2:
        raise ValueError("n_shares must be >= 2")
    if not isinstance(seed, (bytes, bytearray)) or not seed:
        raise ValueError("seed must be non-empty bytes")

    seed = bytes(seed)
    masks = [_expand_seed(seed, client_id, i) for i in range(n_shares - 1)]
    last = (value - sum(masks)) % FIELD_PRIME
    values = masks + [last]

    out = []
    for i, v in enumerate(values):
        body = _share_body(client_id, i, n_shares, v)
        out.append(Share(client_id=client_id, share_index=i, n_shares=n_shares,
                         value=v, digest=_pin(body)))
    return tuple(out)


@dataclass(frozen=True)
class AggregationResult:
    """Published output of an aggregation round: the total and blinding sum."""

    total: int
    blinding_sum: int
    n_clients: int
    digest: str  # sha256 pin over the canonical body

    def as_dict(self) -> dict:
        return {
            "total": self.total,
            "blinding_sum": self.blinding_sum,
            "n_clients": self.n_clients,
            "digest": self.digest,
            "schema": SECURE_AGGREGATION_SCHEMA,
            "version": SECURE_AGGREGATION_VERSION,
        }


def _result_body(total: int, blinding_sum: int, n_clients: int) -> dict:
    return {
        "total": _hexint(total),
        "blinding_sum": _hexint(blinding_sum),
        "n_clients": n_clients,
        "schema": SECURE_AGGREGATION_SCHEMA,
        "version": SECURE_AGGREGATION_VERSION,
    }


def aggregate_shares(shares: Sequence[Share]) -> AggregationResult:
    """Sum shares mod FIELD_PRIME. Only shares are handled - never raw values.

    Verifies each share's digest before including it (fail-closed: a tampered
    share aborts the round rather than corrupting the total). ``n_clients`` is
    the number of distinct client_ids observed.
    """
    if not isinstance(shares, Sequence) or isinstance(shares, (str, bytes)):
        raise TypeError("shares must be a sequence of Share")
    shares = list(shares)
    if not shares:
        raise ValueError("shares must be non-empty")

    total = 0
    clients = set()
    for s in shares:
        if not isinstance(s, Share):
            raise TypeError("every share must be a Share")
        body = _share_body(s.client_id, s.share_index, s.n_shares, s.value)
        if s.digest != _pin(body):
            raise ValueError(f"share digest mismatch for client {s.client_id!r}")
        total = (total + s.value) % FIELD_PRIME
        clients.add(s.client_id)

    # The aggregator of shares does not learn blindings; blinding_sum is
    # filled in by the commitment layer (aggregate_commitments). A raw
    # share-aggregation round carries blinding_sum = 0.
    result_body = _result_body(total, 0, len(clients))
    return AggregationResult(total=total, blinding_sum=0, n_clients=len(clients),
                             digest=_pin(result_body))


@dataclass(frozen=True)
class Commitment:
    """Homomorphic commitment C = G*value + blinding (mod P) for one client."""

    client_id: str
    commitment: int
    blinding_digest: str  # sha256 pin of the blinding (binding, not revealing)

    def as_dict(self) -> dict:
        return {
            "client_id": self.client_id,
            "commitment": self.commitment,
            "blinding_digest": self.blinding_digest,
            "schema": SECURE_AGGREGATION_SCHEMA,
            "version": SECURE_AGGREGATION_VERSION,
        }


def commit_update(client_id: str, value: int, blinding: int) -> Commitment:
    """Publish a homomorphic commitment to a client's update."""
    client_id = _check_client_id(client_id)
    value = _check_value(value, "value")
    blinding = _check_value(blinding, "blinding")
    commitment = (GENERATOR * value + blinding) % FIELD_PRIME
    blinding_digest = "sha256:" + hashlib.sha256(_int_to_bytes(blinding)).hexdigest()
    return Commitment(client_id=client_id, commitment=commitment,
                      blinding_digest=blinding_digest)


def open_aggregate(total: int, blinding_sum: int, n_clients: int) -> AggregationResult:
    """Build the published aggregation record from the round's outputs."""
    total = _check_value(total, "total")
    blinding_sum = _check_value(blinding_sum, "blinding_sum")
    if isinstance(n_clients, bool) or not isinstance(n_clients, int) or n_clients < 1:
        raise ValueError("n_clients must be a positive int")
    body = _result_body(total, blinding_sum, n_clients)
    return AggregationResult(total=total, blinding_sum=blinding_sum,
                             n_clients=n_clients, digest=_pin(body))


def verify_aggregation(result: object, commitments: object) -> bool:
    """Check the homomorphic equation: G*total + blinding_sum == sum(C_i).

    Never raises: anything unverifiable (wrong types, malformed records,
    count mismatch, duplicate clients, equation failure) returns False.
    """
    try:
        if not isinstance(result, AggregationResult):
            return False
        body = _result_body(result.total, result.blinding_sum, result.n_clients)
        if result.digest != _pin(body):
            return False
        if not isinstance(commitments, Sequence) or isinstance(commitments, (str, bytes)):
            return False
        commitments = list(commitments)
        if not commitments or len(commitments) != result.n_clients:
            return False
        seen = set()
        total_c = 0
        for c in commitments:
            if not isinstance(c, Commitment):
                return False
            if not c.client_id or c.client_id in seen:
                return False
            if not 0 <= c.commitment < FIELD_PRIME:
                return False
            if not (isinstance(c.blinding_digest, str)
                    and c.blinding_digest.startswith("sha256:")
                    and len(c.blinding_digest) == 7 + 64):
                return False
            seen.add(c.client_id)
            total_c = (total_c + c.commitment) % FIELD_PRIME
        expected = (GENERATOR * result.total + result.blinding_sum) % FIELD_PRIME
        return total_c == expected
    except Exception:
        return False


def main() -> None:
    # End-to-end honest round: 3 clients, split -> aggregate -> commit -> verify.
    clients = [("alice", 100), ("bob", 250), ("carol", 175)]
    all_shares = []
    commitments = []
    blindings = []
    for i, (cid, val) in enumerate(clients):
        all_shares.extend(split_update(cid, val, 3, seed=f"seed-{i}".encode()))
        blinding = _expand_seed(b"blinding-seed", cid, 0)
        blindings.append(blinding)
        commitments.append(commit_update(cid, val, blinding))
    agg = aggregate_shares(all_shares)
    assert agg.total == sum(v for _, v in clients) % FIELD_PRIME, "share sum wrong"
    result = open_aggregate(agg.total, sum(blindings) % FIELD_PRIME, len(clients))
    assert verify_aggregation(result, commitments), "honest round must verify"
    tampered = open_aggregate((agg.total + 1) % FIELD_PRIME,
                              sum(blindings) % FIELD_PRIME, len(clients))
    assert not verify_aggregation(tampered, commitments), "tampered total must fail"
    print("secure-aggregation OK: 3-client round verified, tampered total rejected")


if __name__ == "__main__":
    main()
