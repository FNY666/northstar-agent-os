"""Verifiable delay function (VDF) interface (Pietrzak-style, simulated).

Research motivation: a VDF (Boneh et al. 2018) is a function that needs a
*prescribed number of sequential steps* to evaluate - no amount of
parallelism speeds it up - yet whose output can be *verified quickly*.
Blockchains use VDFs for unbiasable randomness beacons (Ethereum's
RANDAO+VDF roadmap, Chia's proof-of-space-and-time): the delay prevents
grinding, the fast verification keeps the chain light. The two practical
constructions are Wesolowski (2019) and Pietrzak (2019), both repeated
squaring in a group of *unknown* order (RSA group, class group) with a
proof that verification folds in O(log T) instead of re-running T
sequential squarings.

This module is the *mechanics half*, over a toy group, so the plumbing
the runtime depends on is pinned:

Construction (documented, all arithmetic in F_p):

- Group: F_p^* with p = 2^61 - 1 (Mersenne prime). **Toy group, chosen so
  squarings are fast and tests run in milliseconds.** Nothing here is
  secure - see honest scope below. The *shape* is real Pietrzak.
- Input mapping: x_0 = 1 + (SHA-256("northstar-vdf-interface.v1" ||
  "input" || input) mod (p - 1)), so x_0 in [1, p - 1]. Deterministic;
  the encoding stays visible at the call site (``str`` is rejected).
- Evaluation: y = x_0^{2^T} computed by T *sequential* squarings
  mod p. There is no parallelism to exploit in the chain itself -
  v_{i+1} = v_i^2 needs v_i first.
- Proof (Pietrzak halving, k = log2(T) levels): at each level the prover
  records the midpoint mu = x^{2^{T/2}}, then both sides derive the
  Fiat-Shamir challenge r = H(x, mu, y) and fold to the half-size claim
  x' = x^r * mu, y' = mu^r * y. The proof is the tuple of midpoints,
  bottom-up; each level halves the remaining exponent.
- Verification: replay the k folds (each level is two modular
  exponentiations plus two multiplications - O(log p) work), then check
  the terminal claim y = x^2. Total verifier work is O(log T * log p)
  versus the evaluator's O(T) sequential squarings - the VDF asymmetry
  is genuine, not stubbed.
- T must be a power of two with 1 <= T <= 2^16 (fail-closed); the
  halving recursion only terminates cleanly on powers of two.

Public API:

- ``VDF()`` -- parameter holder. The constructor rejects any non-default
  parameters fail-closed, so two deployments cannot silently disagree on
  the group or the proof domain.
- ``VDF.evaluate(input: bytes, steps: int) -> Evaluation`` -- sequential
  evaluation; returns a frozen record.
- ``VDF.verify(input: bytes, output: int, proof: VDFProof,
  steps: int) -> bool`` -- fast verification. Returns ``False`` on any
  cryptographic mismatch (policy outcome); raises only on malformed
  caller types.
- ``Evaluation`` -- frozen record: ``input_digest`` (``sha256:`` pin),
  ``output`` (int), ``steps``, ``proof`` (``VDFProof``), with
  ``as_dict()``.
- ``VDFProof`` -- frozen record: ``levels`` (tuple of midpoint ints,
  length == log2(steps)), ``schema`` pin.
- ``vdf_audit_event(kind, seq, ...)`` -- ``audit.ndjson/1`` shaped
  records (``evaluated`` / ``verified`` / ``rejected``).

Honest scope:

- Simulated cryptography: p has *known* order, so an evaluator could
  shortcut with Euler's theorem (x^{2^T} = x^{2^T mod (p-1)}); the
  sequential-delay property only holds in a group of *unknown* order
  (RSA/class group), which this toy group is not. The delay here is
  simulated - it measures the interface cost, not a security wall.
- This pins the *interface shape*: sequential-squaring evaluation,
  Pietrzak halving proofs, Fiat-Shamir folding, O(log T) verification,
  and the fail-closed parameter envelope. A real deployment swaps in
  Wesolowski/Pietrzak over a class group (no trusted setup) without
  changing call sites.
- Deterministic and pure: no randomness, no wall-clock. Same input and
  steps always give the same output and proof on every machine.
- The proof binds the *computation*, not the input's meaning: verify
  checks that output == x_0(input)^{2^steps}, never that the input was
  honest.

No wall-clock anywhere. stdlib only (``hashlib``, ``dataclasses``,
``typing``).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Tuple

#: Version pin for the VDF interface described here.
VDF_VERSION = "vdf-interface.v1"

#: Schema pin stamped on structured outputs.
SCHEMA_PIN = "northstar.vdf-interface.v1"

#: Toy prime. p = 2^61 - 1 is prime; squarings stay in 8 bytes.
#: Real VDF deployments use groups of unknown order (RSA/class group).
FIELD_PRIME = (1 << 61) - 1

#: Maximum allowed steps (2^16). Evaluation is O(steps) squarings, so the
#: bound keeps tests fast and rejects accidental denial-of-service shapes.
MAX_STEPS = 1 << 16

#: Domain prefixes for the input map and the Fiat-Shamir challenge.
_INPUT_DOMAIN = b"northstar-vdf-interface.v1/input"
_CHALLENGE_DOMAIN = b"northstar-vdf-interface.v1/challenge"


class VDFError(ValueError):
    """Fail-closed VDF error."""


def _reject_bool_int(name: str, value: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an int")


def _validate_steps(steps: int) -> int:
    """Validate the delay parameter. Returns log2(steps)."""
    _reject_bool_int("steps", steps)
    if steps < 1:
        raise VDFError("steps must be >= 1")
    if steps > MAX_STEPS:
        raise VDFError(f"steps must be <= {MAX_STEPS}")
    if steps & (steps - 1):
        raise VDFError("steps must be a power of two")
    return steps.bit_length() - 1


def _validate_input(data: bytes) -> bytes:
    if not isinstance(data, bytes):
        raise TypeError("input must be bytes (hash the explicit encoding first)")
    if len(data) == 0:
        raise VDFError("input must be non-empty")
    return data


def _map_to_group(data: bytes) -> int:
    """Deterministically map bytes to a group element in [1, p - 1]."""
    digest = hashlib.sha256(_INPUT_DOMAIN + b"/" + data).digest()
    return 1 + (int.from_bytes(digest, "big") % (FIELD_PRIME - 1))


def _fiat_shamir(x: int, mu: int, y: int) -> int:
    """Fiat-Shamir challenge r = H(x, mu, y) in [1, p - 1]."""
    body = (
        _CHALLENGE_DOMAIN
        + b"/"
        + x.to_bytes(8, "big")
        + mu.to_bytes(8, "big")
        + y.to_bytes(8, "big")
    )
    digest = hashlib.sha256(body).digest()
    return 1 + (int.from_bytes(digest, "big") % (FIELD_PRIME - 1))


def _validate_output(output: int) -> int:
    _reject_bool_int("output", output)
    if not 1 <= output < FIELD_PRIME:
        raise VDFError("output must be in [1, p - 1]")
    return output


@dataclass(frozen=True)
class VDFProof:
    """Pietrzak halving proof: k = log2(steps) midpoints, top-down."""

    levels: Tuple[int, ...]
    schema: str = SCHEMA_PIN

    def __post_init__(self) -> None:
        if not isinstance(self.levels, tuple):
            raise TypeError("levels must be a tuple")
        for mu in self.levels:
            _reject_bool_int("proof level", mu)
            if not 1 <= mu < FIELD_PRIME:
                raise VDFError("proof level must be in [1, p - 1]")
        if self.schema != SCHEMA_PIN:
            raise VDFError("schema pin mismatch")

    def as_dict(self) -> dict:
        return {
            "levels": [f"{mu:016x}" for mu in self.levels],
            "schema": self.schema,
        }


@dataclass(frozen=True)
class Evaluation:
    """Frozen record of one VDF evaluation."""

    input_digest: str
    output: int
    steps: int
    proof: VDFProof
    schema: str = SCHEMA_PIN

    def __post_init__(self) -> None:
        if not isinstance(self.input_digest, str) or not self.input_digest.startswith(
            "sha256:"
        ):
            raise VDFError("input_digest must be a sha256: pin")
        _validate_output(self.output)
        _validate_steps(self.steps)
        if not isinstance(self.proof, VDFProof):
            raise TypeError("proof must be a VDFProof")
        if len(self.proof.levels) != self.steps.bit_length() - 1:
            raise VDFError("proof level count must equal log2(steps)")
        if self.schema != SCHEMA_PIN:
            raise VDFError("schema pin mismatch")

    def as_dict(self) -> dict:
        return {
            "input_digest": self.input_digest,
            "output": f"{self.output:016x}",
            "steps": self.steps,
            "proof": self.proof.as_dict(),
            "schema": self.schema,
        }


class VDF:
    """Pietrzak-style VDF evaluator/verifier over the toy group.

    The constructor pins every parameter: callers cannot silently
    disagree on the group or the proof domain.
    """

    version: str = VDF_VERSION

    def __init__(self) -> None:
        object.__setattr__(self, "_prime", FIELD_PRIME)

    @property
    def prime(self) -> int:
        return self._prime

    def evaluate(self, data: bytes, steps: int) -> Evaluation:
        """Run T sequential squarings and build the Pietrzak proof."""
        _validate_input(data)
        levels_count = _validate_steps(steps)
        p = self._prime

        x = _map_to_group(data)
        # Full sequential chain: v[i+1] = v[i]^2. This IS the delay -
        # each squaring needs the previous one, so no parallelism helps.
        chain = [x]
        for _ in range(steps):
            chain.append((chain[-1] * chain[-1]) % p)
        y = chain[steps]

        midpoints = []
        cx, cy, t = x, y, steps
        for _ in range(levels_count):
            half = t // 2
            # Midpoint of the *current folded* claim: mu = cx^{2^{t/2}}.
            # Recomputed by half sequential squarings from the folded
            # base (prover cost ~2T total across all levels).
            cur = cx
            for _ in range(half):
                cur = (cur * cur) % p
            mu = cur
            midpoints.append(mu)
            r = _fiat_shamir(cx, mu, cy)
            cx = (pow(cx, r, p) * mu) % p
            cy = (pow(mu, r, p) * cy) % p
            t = half

        proof = VDFProof(levels=tuple(midpoints))
        return Evaluation(
            input_digest="sha256:" + hashlib.sha256(data).hexdigest(),
            output=y,
            steps=steps,
            proof=proof,
        )

    def verify(self, data: bytes, output: int, proof: VDFProof, steps: int) -> bool:
        """Verify in O(log steps) group ops. False on any mismatch."""
        try:
            _validate_input(data)
            levels_count = _validate_steps(steps)
            _validate_output(output)
        except (TypeError, VDFError):
            raise
        if not isinstance(proof, VDFProof):
            raise TypeError("proof must be a VDFProof")
        if len(proof.levels) != levels_count:
            return False

        p = self._prime
        x = _map_to_group(data)
        y = output
        t = steps
        for mu in proof.levels:
            r = _fiat_shamir(x, mu, y)
            x = (pow(x, r, p) * mu) % p
            y = (pow(mu, r, p) * y) % p
            t //= 2
        # Terminal claim: y == x^{2^1}.
        return y == (x * x) % p


def vdf_audit_event(kind: str, seq: int, **fields: object) -> dict:
    """Audit-shaped record for a VDF observation."""
    if kind not in ("evaluated", "verified", "rejected"):
        raise ValueError("unknown kind")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise ValueError("seq must be a non-negative int")
    record = {
        "event": "vdf-interface",
        "kind": kind,
        "audit_seq": seq,
        "schema": "audit.ndjson/1",
    }
    record.update(fields)
    return record


def main() -> None:
    v = VDF()
    ev = v.evaluate(b"northstar", 16)
    assert v.verify(b"northstar", ev.output, ev.proof, 16), "roundtrip"
    assert not v.verify(b"northstar", (ev.output + 1) % FIELD_PRIME or 1,
                        ev.proof, 16), "tampered output rejected"
    assert len(ev.proof.levels) == 4, "log2(16) levels"
    print(f"vdf-interface OK: steps=16 output={ev.output:016x} levels=4")


if __name__ == "__main__":
    main()
