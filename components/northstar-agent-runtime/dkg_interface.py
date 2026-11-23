"""Distributed key generation interface: Pedersen DKG bookkeeping (simulated).

Research motivation: Pedersen DKG (Pedersen 1991) lets ``n`` agents jointly
generate a threshold key pair -- a group public key with no single dealer
ever knowing the group secret -- so fleet-level keys (audit-head anchors,
budget-release signing keys, fleet kill authorizations) need no trusted
third party. Each dealer ``d`` picks a random degree-``t`` polynomial
``f_d(x) = a_{d,0} + a_{d,1} x + ... + a_{d,t} x^t`` over a prime field,
broadcasts Pedersen commitments ``C_{d,j} = a_{d,j} * G + b_{d,j} * H``
to its coefficients, and privately sends each participant ``i`` the share
pair ``(f_d(i), g_d(i))`` where ``g_d`` is the blinding polynomial.
Anyone can verify a received share against the broadcast commitments:

    s_i * G + s'_i * H == sum_j C_j * i^j        (mod p)

because both sides expand to ``f(i) * G + g(i) * H`` -- the additive
homomorphism is what this bookkeeping pins. The group secret is
``sum_d a_{d,0}``; any ``t+1`` final shares ``F(i) = sum_d f_d(i)``
recover it by Lagrange interpolation at 0.

This module pins the *mechanical bookkeeping* of one DKG run as seen by
one participant (the network-free half):

- ``round1(coeffs, blinding_coeffs, seq)`` -- as dealer: commit to a
  degree-``t`` polynomial, mint the broadcast ``DealerCommitment`` and
  one ``SharePacket`` per participant. Returns ``(commitment, packets)``.
- ``receive_commitment(commitment)`` -- record another dealer's
  broadcast commitment (validated, fail-closed).
- ``round2(packet, seq)`` -- verify *my* share packet against the
  recorded commitment of its dealer; returns a frozen
  ``ShareVerification`` (valid/invalid with a reason -- a verdict, not
  an error). An invalid share means the host should ``complaint()``.
- ``complaint(dealer_id, seq)`` -- disqualify a dealer (complaint
  phase); its shares no longer count toward finalization.
- ``finalize(seq)`` -- aggregate every qualified dealer's commitments
  into the group public key and my final secret share; returns a frozen
  ``DKGResult``. Fails closed when no dealer qualified.
- ``lagrange_recover(indexed_shares)`` -- module-level primitive that
  recovers ``F(0)`` from ``t+1`` final shares (verification primitive
  for tests and audit, not a production reconstruction path).

Honest scope:

- This is a *simulation of the interface*, not real cryptography. The
  commitment arithmetic is genuine addition over the prime field
  ``p = 2**255 - 19`` (the verification equation really holds), but the
  hiding argument of true Pedersen commitments rests on the
  discrete-logarithm problem in an elliptic-curve group, which an
  additive field simulation does not have. Binding here rests on the
  ``sha256:`` digest pins over canonical encodings, and share
  confidentiality rests on the *transport*: ``SharePacket`` records
  carry share values in the clear so the ledger can verify them, which
  means a production host must encrypt packets to the recipient's key
  (e.g. ECIES) before they leave the node. Do not treat this module as
  a cryptographic DKG.
- Single run per instance: one ``DKG`` object is one DKG run. The host
  creates a fresh instance per epoch/run; there is no re-run or
  epoch bookkeeping here.
- The qualified set is whatever the host verified: ``finalize`` uses
  exactly the dealers whose commitments were received and whose shares
  passed ``round2`` and were not complained about. Complaint *adjudication*
  (who is right) is the host's job; this ledger only records.
- No wall-clock anywhere: all seqs are caller-supplied ints (logical
  clock). Randomness is the host's job: ``round1`` takes explicit
  coefficient sequences and never samples.
- Canonical-encoding note: field elements are serialized as fixed-width
  64-hex-char strings in every digest body and ``as_dict()`` -- never as
  raw JSON ints -- so the ``>2**53`` canonical-JSON precision-loss
  caveat (see ``secure_aggregation``) does not apply here.
- ``round2`` returning an invalid verdict and ``finalize`` raising
  ``NoQualifiedDealerError`` are protocol outcomes surfaced
  fail-closed; malformed inputs raise ``TypeError`` / ``ValueError`` /
  ``DKGError``.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, field
from typing import Mapping, Sequence

#: Module version pin.
DKG_INTERFACE_VERSION = "dkg-interface.v1"

#: Schema pin carried by records and audit events.
DKG_INTERFACE_SCHEMA = "northstar.dkg-interface.v1"

#: Audit event kinds.
EVENT_ROUND1 = "dkg-round1"
EVENT_SHARE_ISSUED = "dkg-share-issued"
EVENT_COMMITMENT_RECEIVED = "dkg-commitment-received"
EVENT_SHARE_VERIFIED = "dkg-share-verified"
EVENT_SHARE_REJECTED = "dkg-share-rejected"
EVENT_COMPLAINT = "dkg-complaint"
EVENT_FINALIZED = "dkg-finalized"
EVENT_REFUSED = "dkg-refused"

_EVENT_KINDS = frozenset(
    {
        EVENT_ROUND1,
        EVENT_SHARE_ISSUED,
        EVENT_COMMITMENT_RECEIVED,
        EVENT_SHARE_VERIFIED,
        EVENT_SHARE_REJECTED,
        EVENT_COMPLAINT,
        EVENT_FINALIZED,
        EVENT_REFUSED,
    }
)

#: Digest prefix for pinned values.
_DIGEST_PREFIX = "sha256:"

#: Arithmetic field: 2**255 - 19 (a real prime; the simulation's
#: commitment arithmetic lives here).
FIELD_PRIME = 2**255 - 19


def _domain_scalar(tag: bytes) -> int:
    """Nothing-up-my-sleeve field element from a domain tag (non-zero)."""
    x = int.from_bytes(
        hashlib.sha256(b"northstar.dkg-interface.v1/" + tag).digest(), "big"
    ) % FIELD_PRIME
    return x if x != 0 else 1


#: Simulated Pedersen generators (fixed, domain-separated, non-zero).
_GENERATOR_G = _domain_scalar(b"G")
_GENERATOR_H = _domain_scalar(b"H")


class DKGError(Exception):
    """Base error for DKG bookkeeping (fail-closed)."""


class NoQualifiedDealerError(DKGError):
    """Raised by finalize() when no dealer qualified."""


class DuplicateCommitmentError(DKGError):
    """Raised when a second commitment arrives from the same dealer."""


def _check_node_id(value: object, name: str = "node_id") -> str:
    """Validate a node id: non-empty string, whitespace-stripped."""
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a string, got {type(value).__name__}")
    node_id = value.strip()
    if not node_id:
        raise ValueError(f"{name} must be non-empty")
    return node_id


def _check_seq(value: object, name: str = "seq") -> int:
    """Validate a caller-supplied logical seq: non-negative int, bool rejected."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an int, got {type(value).__name__}")
    if value < 0:
        raise ValueError(f"{name} must be >= 0")
    return value


def _check_threshold(value: object, n: int) -> int:
    """Validate the DKG threshold degree: int with 0 <= t < n, bool rejected."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"t must be an int, got {type(value).__name__}")
    if value < 0:
        raise ValueError("t must be >= 0")
    if value >= n:
        raise ValueError(f"t ({value}) must be < n ({n})")
    return value


def _check_felt(value: object, name: str) -> int:
    """Validate a field element: int in [0, FIELD_PRIME), bool rejected."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an int, got {type(value).__name__}")
    if not 0 <= value < FIELD_PRIME:
        raise ValueError(f"{name} must be in [0, FIELD_PRIME)")
    return value


def _felt_hex(value: int) -> str:
    """Fixed-width 64-hex-char encoding of a field element (no float loss)."""
    return format(value, "064x")


def _canonical(value: object) -> str:
    """Canonical JSON encoding (sorted keys, compact separators)."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _pin(body: Mapping[str, object]) -> str:
    """Return ``sha256:<hex>`` over the canonical encoding of a body."""
    return _DIGEST_PREFIX + hashlib.sha256(
        _canonical(body).encode("utf-8")
    ).hexdigest()


def _check_digest(value: object, name: str = "digest") -> str:
    """Validate a ``sha256:<64 hex>`` digest pin."""
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a string, got {type(value).__name__}")
    if not value.startswith(_DIGEST_PREFIX) or len(value) != len(_DIGEST_PREFIX) + 64:
        raise ValueError(f"{name} must be a sha256 digest pin")
    hexpart = value[len(_DIGEST_PREFIX):]
    if any(c not in "0123456789abcdef" for c in hexpart):
        raise ValueError(f"{name} must be lowercase hex")
    return value


def _poly_eval(coeffs: Sequence[int], x: int) -> int:
    """Evaluate a polynomial (coeffs constant-term first) at x mod FIELD_PRIME."""
    acc = 0
    power = 1
    for c in coeffs:
        acc = (acc + c * power) % FIELD_PRIME
        power = (power * x) % FIELD_PRIME
    return acc


def _pedersen_commit(a: int, b: int) -> int:
    """Simulated Pedersen commitment: ``a*G + b*H`` mod FIELD_PRIME."""
    return (a * _GENERATOR_G + b * _GENERATOR_H) % FIELD_PRIME


@dataclass(frozen=True)
class DealerCommitment:
    """A dealer's round-1 broadcast: commitments to its polynomial coefficients."""

    dealer_id: str
    threshold: int
    commitments: tuple
    commitment_seq: int
    digest: str
    schema: str = DKG_INTERFACE_SCHEMA

    def __post_init__(self) -> None:
        _check_node_id(self.dealer_id, "dealer_id")
        if isinstance(self.threshold, bool) or not isinstance(self.threshold, int):
            raise TypeError("threshold must be an int")
        if self.threshold < 0:
            raise ValueError("threshold must be >= 0")
        if not isinstance(self.commitments, tuple):
            raise TypeError("commitments must be a tuple")
        if len(self.commitments) != self.threshold + 1:
            raise ValueError("commitments must have threshold + 1 entries")
        for c in self.commitments:
            _check_felt(c, "commitment")
        _check_seq(self.commitment_seq, "commitment_seq")
        _check_digest(self.digest, "digest")
        if self.schema != DKG_INTERFACE_SCHEMA:
            raise ValueError(f"unknown schema pin: {self.schema!r}")

    def as_dict(self) -> dict:
        return {
            "dealer_id": self.dealer_id,
            "threshold": self.threshold,
            "commitments": [_felt_hex(c) for c in self.commitments],
            "commitment_seq": self.commitment_seq,
            "digest": self.digest,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class SharePacket:
    """A dealer's round-2 private share for one recipient.

    The share values are carried in the clear so the ledger can verify
    them; a production transport must encrypt packets to the recipient.
    """

    dealer_id: str
    recipient_id: str
    recipient_index: int
    share: int
    share_blinding: int
    packet_seq: int
    digest: str
    schema: str = DKG_INTERFACE_SCHEMA

    def __post_init__(self) -> None:
        _check_node_id(self.dealer_id, "dealer_id")
        _check_node_id(self.recipient_id, "recipient_id")
        if isinstance(self.recipient_index, bool) or not isinstance(
            self.recipient_index, int
        ):
            raise TypeError("recipient_index must be an int")
        if self.recipient_index < 1:
            raise ValueError("recipient_index is 1-based and must be >= 1")
        # Field elements are validated structurally here (int-ness) and
        # range-checked via _check_felt.
        object.__setattr__(self, "share", _check_felt(self.share, "share"))
        object.__setattr__(
            self, "share_blinding", _check_felt(self.share_blinding, "share_blinding")
        )
        _check_seq(self.packet_seq, "packet_seq")
        _check_digest(self.digest, "digest")
        if self.schema != DKG_INTERFACE_SCHEMA:
            raise ValueError(f"unknown schema pin: {self.schema!r}")

    def as_dict(self) -> dict:
        return {
            "dealer_id": self.dealer_id,
            "recipient_id": self.recipient_id,
            "recipient_index": self.recipient_index,
            "share": _felt_hex(self.share),
            "share_blinding": _felt_hex(self.share_blinding),
            "packet_seq": self.packet_seq,
            "digest": self.digest,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class ShareVerification:
    """The verdict of round2 on one share packet (a verdict, not an error)."""

    dealer_id: str
    recipient_id: str
    valid: bool
    reason: str
    schema: str = DKG_INTERFACE_SCHEMA

    def __post_init__(self) -> None:
        _check_node_id(self.dealer_id, "dealer_id")
        _check_node_id(self.recipient_id, "recipient_id")
        if not isinstance(self.valid, bool):
            raise TypeError("valid must be a bool")
        if not isinstance(self.reason, str) or not self.reason.strip():
            raise ValueError("reason must be a non-empty string")
        if self.schema != DKG_INTERFACE_SCHEMA:
            raise ValueError(f"unknown schema pin: {self.schema!r}")

    def as_dict(self) -> dict:
        return {
            "dealer_id": self.dealer_id,
            "recipient_id": self.recipient_id,
            "valid": self.valid,
            "reason": self.reason,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class DKGResult:
    """Finalization output: the group public key and my final secret share."""

    group_key: int
    my_share: int
    my_share_blinding: int
    qualified_dealers: tuple
    finalize_seq: int
    digest: str
    schema: str = DKG_INTERFACE_SCHEMA

    def __post_init__(self) -> None:
        object.__setattr__(self, "group_key", _check_felt(self.group_key, "group_key"))
        object.__setattr__(self, "my_share", _check_felt(self.my_share, "my_share"))
        object.__setattr__(
            self,
            "my_share_blinding",
            _check_felt(self.my_share_blinding, "my_share_blinding"),
        )
        if not isinstance(self.qualified_dealers, tuple):
            raise TypeError("qualified_dealers must be a tuple")
        if not self.qualified_dealers:
            raise ValueError("qualified_dealers must be non-empty")
        for d in self.qualified_dealers:
            _check_node_id(d, "qualified dealer")
        _check_seq(self.finalize_seq, "finalize_seq")
        _check_digest(self.digest, "digest")
        if self.schema != DKG_INTERFACE_SCHEMA:
            raise ValueError(f"unknown schema pin: {self.schema!r}")

    def as_dict(self) -> dict:
        return {
            "group_key": _felt_hex(self.group_key),
            "my_share": _felt_hex(self.my_share),
            "my_share_blinding": _felt_hex(self.my_share_blinding),
            "qualified_dealers": list(self.qualified_dealers),
            "finalize_seq": self.finalize_seq,
            "digest": self.digest,
            "schema": self.schema,
        }


def lagrange_recover(indexed_shares: Sequence[tuple]) -> int:
    """Recover ``F(0)`` from ``t+1`` shares ``(index, F(index))`` mod FIELD_PRIME.

    Verification primitive for tests and audit; production reconstruction
    is the host's job. Fail-closed on malformed input.
    """
    if not isinstance(indexed_shares, Sequence) or isinstance(indexed_shares, (str, bytes)):
        raise TypeError("indexed_shares must be a sequence of (index, share) pairs")
    pairs = list(indexed_shares)
    if not pairs:
        raise ValueError("indexed_shares must be non-empty")
    xs = []
    for pair in pairs:
        if not isinstance(pair, (tuple, list)) or len(pair) != 2:
            raise TypeError("each entry must be an (index, share) pair")
        x, y = pair
        if isinstance(x, bool) or not isinstance(x, int):
            raise TypeError("index must be an int")
        if x < 1:
            raise ValueError("index is 1-based and must be >= 1")
        xs.append(x)
        _check_felt(y, "share")
    if len(set(xs)) != len(xs):
        raise ValueError("share indices must be distinct")
    secret = 0
    for i, (xi, yi) in enumerate(pairs):
        num = 1
        den = 1
        for j, (xj, _) in enumerate(pairs):
            if i == j:
                continue
            num = (num * xj) % FIELD_PRIME
            den = (den * (xj - xi)) % FIELD_PRIME
        # den != 0 because indices are distinct and FIELD_PRIME is prime.
        lagrange_at_zero = num * pow(den, FIELD_PRIME - 2, FIELD_PRIME) % FIELD_PRIME
        secret = (secret + yi * lagrange_at_zero) % FIELD_PRIME
    return secret


class DKG:
    """One participant's view of a single Pedersen DKG run.

    ``participants`` are sorted for determinism; the 1-based position in
    the sorted list is the participant's share index.
    """

    def __init__(self, node_id: str, t: int, participants: Sequence[str]) -> None:
        self._node_id = _check_node_id(node_id)
        if not isinstance(participants, Sequence) or isinstance(
            participants, (str, bytes)
        ):
            raise TypeError("participants must be a sequence of node ids")
        cleaned = [_check_node_id(p, "participant") for p in participants]
        if len(set(cleaned)) != len(cleaned):
            raise ValueError("participants must be unique")
        if not cleaned:
            raise ValueError("participants must be non-empty")
        self._participants = tuple(sorted(cleaned))
        if self._node_id not in self._participants:
            raise ValueError("node_id must be one of the participants")
        self._t = _check_threshold(t, len(self._participants))
        self._my_index = self._participants.index(self._node_id) + 1
        # Run state.
        self._commitments: dict = {}
        self._verified_shares: dict = {}
        self._disqualified: set = set()
        self._my_deal: tuple = ()
        self._events: list = []

    @property
    def node_id(self) -> str:
        return self._node_id

    @property
    def threshold(self) -> int:
        return self._t

    @property
    def participants(self) -> tuple:
        return self._participants

    @property
    def my_index(self) -> int:
        return self._my_index

    def _log(self, kind: str, seq: int, summary: Mapping[str, object]) -> None:
        self._events.append({"kind": kind, "seq": seq, "summary": dict(summary)})

    def events(self) -> tuple:
        """Append-only event log (kind, seq, summary)."""
        return tuple(self._events)

    def round1(
        self,
        coeffs: Sequence[int],
        blinding_coeffs: Sequence[int],
        seq: int,
    ) -> tuple:
        """Dealer step: commit to a degree-t polynomial and mint share packets.

        ``coeffs`` / ``blinding_coeffs`` are host-supplied randomness
        (t+1 field elements each; ``coeffs[0]`` is this dealer's secret
        contribution). Returns ``(DealerCommitment, tuple[SharePacket])``.
        """
        seq = _check_seq(seq, "seq")
        for name, values in (("coeffs", coeffs), ("blinding_coeffs", blinding_coeffs)):
            if not isinstance(values, Sequence) or isinstance(values, (str, bytes)):
                raise TypeError(f"{name} must be a sequence of field elements")
            values = list(values)
            if len(values) != self._t + 1:
                raise ValueError(
                    f"{name} must have t+1 = {self._t + 1} entries, "
                    f"got {len(values)}"
                )
            for v in values:
                _check_felt(v, name)
        coeffs = list(coeffs)
        blinding_coeffs = list(blinding_coeffs)

        commitments = tuple(
            _pedersen_commit(a, b) for a, b in zip(coeffs, blinding_coeffs)
        )
        commitment_body = {
            "dealer_id": self._node_id,
            "threshold": self._t,
            "commitments": [_felt_hex(c) for c in commitments],
            "commitment_seq": seq,
        }
        commitment = DealerCommitment(
            dealer_id=self._node_id,
            threshold=self._t,
            commitments=commitments,
            commitment_seq=seq,
            digest=_pin(commitment_body),
        )
        packets = []
        for idx, pid in enumerate(self._participants, start=1):
            share = _poly_eval(coeffs, idx)
            blinding = _poly_eval(blinding_coeffs, idx)
            body = {
                "dealer_id": self._node_id,
                "recipient_id": pid,
                "recipient_index": idx,
                "share": _felt_hex(share),
                "share_blinding": _felt_hex(blinding),
                "packet_seq": seq,
            }
            packets.append(
                SharePacket(
                    dealer_id=self._node_id,
                    recipient_id=pid,
                    recipient_index=idx,
                    share=share,
                    share_blinding=blinding,
                    packet_seq=seq,
                    digest=_pin(body),
                )
            )
        packets = tuple(packets)
        # The dealer implicitly trusts its own dealing: record the
        # commitment and mark its own share verified.
        self._commitments[self._node_id] = commitment
        own = packets[self._my_index - 1]
        self._verified_shares[self._node_id] = (own.share, own.share_blinding)
        self._my_deal = (commitment, packets)
        self._log(EVENT_ROUND1, seq, {"dealer": self._node_id, "t": self._t})
        for p in packets:
            self._log(
                EVENT_SHARE_ISSUED,
                seq,
                {"dealer": self._node_id, "recipient": p.recipient_id},
            )
        return commitment, packets

    def receive_commitment(self, commitment: DealerCommitment) -> bool:
        """Record another dealer's broadcast commitment. Fail-closed."""
        if not isinstance(commitment, DealerCommitment):
            raise TypeError(
                f"commitment must be a DealerCommitment, got {type(commitment).__name__}"
            )
        if commitment.dealer_id not in self._participants:
            raise DKGError(f"unknown dealer: {commitment.dealer_id!r}")
        if commitment.threshold != self._t:
            raise DKGError(
                "commitment threshold does not match this run's threshold"
            )
        if commitment.dealer_id in self._commitments:
            raise DuplicateCommitmentError(
                f"duplicate commitment from {commitment.dealer_id!r}"
            )
        self._commitments[commitment.dealer_id] = commitment
        self._log(
            EVENT_COMMITMENT_RECEIVED,
            commitment.commitment_seq,
            {"dealer": commitment.dealer_id},
        )
        return True

    def round2(self, packet: SharePacket, seq: int) -> ShareVerification:
        """Verify *my* share packet against its dealer's recorded commitment.

        Returns a frozen verdict; an invalid verdict means the host should
        call ``complaint()``. Never raises on a bad share -- only on
        malformed input or protocol violations.
        """
        seq = _check_seq(seq, "seq")
        if not isinstance(packet, SharePacket):
            raise TypeError(
                f"packet must be a SharePacket, got {type(packet).__name__}"
            )
        if packet.recipient_id != self._node_id:
            raise DKGError("packet is not addressed to this node")
        if packet.recipient_index != self._my_index:
            raise DKGError("packet recipient index does not match this node")
        commitment = self._commitments.get(packet.dealer_id)
        if commitment is None:
            raise DKGError(
                f"no commitment recorded for dealer {packet.dealer_id!r}"
            )
        if packet.dealer_id in self._disqualified:
            verdict = ShareVerification(
                dealer_id=packet.dealer_id,
                recipient_id=self._node_id,
                valid=False,
                reason="dealer already disqualified",
            )
            self._log(EVENT_SHARE_REJECTED, seq, {"dealer": packet.dealer_id,
                                                 "reason": verdict.reason})
            return verdict
        # Recompute the packet digest pin: the values must be exactly what
        # the dealer minted.
        body = {
            "dealer_id": packet.dealer_id,
            "recipient_id": packet.recipient_id,
            "recipient_index": packet.recipient_index,
            "share": _felt_hex(packet.share),
            "share_blinding": _felt_hex(packet.share_blinding),
            "packet_seq": packet.packet_seq,
        }
        if not hmac.compare_digest(_pin(body), packet.digest):
            verdict = ShareVerification(
                dealer_id=packet.dealer_id,
                recipient_id=self._node_id,
                valid=False,
                reason="packet digest mismatch (values not dealer-minted)",
            )
            self._log(EVENT_SHARE_REJECTED, seq, {"dealer": packet.dealer_id,
                                                 "reason": verdict.reason})
            return verdict
        # Pedersen verification equation:
        #   s*G + s'*H == sum_j C_j * i^j   (mod p)
        lhs = (packet.share * _GENERATOR_G + packet.share_blinding * _GENERATOR_H)
        lhs %= FIELD_PRIME
        rhs = 0
        for j, c in enumerate(commitment.commitments):
            rhs = (rhs + c * pow(packet.recipient_index, j, FIELD_PRIME)) % FIELD_PRIME
        if not hmac.compare_digest(_felt_hex(lhs), _felt_hex(rhs)):
            verdict = ShareVerification(
                dealer_id=packet.dealer_id,
                recipient_id=self._node_id,
                valid=False,
                reason="share fails Pedersen verification against commitments",
            )
            self._log(EVENT_SHARE_REJECTED, seq, {"dealer": packet.dealer_id,
                                                 "reason": verdict.reason})
            return verdict
        self._verified_shares[packet.dealer_id] = (packet.share, packet.share_blinding)
        verdict = ShareVerification(
            dealer_id=packet.dealer_id,
            recipient_id=self._node_id,
            valid=True,
            reason="share verifies against dealer commitments",
        )
        self._log(EVENT_SHARE_VERIFIED, seq, {"dealer": packet.dealer_id})
        return verdict

    def complaint(self, dealer_id: str, seq: int) -> bool:
        """Disqualify a dealer (complaint phase). Its shares no longer count."""
        seq = _check_seq(seq, "seq")
        dealer_id = _check_node_id(dealer_id, "dealer_id")
        if dealer_id not in self._participants:
            raise DKGError(f"unknown dealer: {dealer_id!r}")
        self._disqualified.add(dealer_id)
        self._verified_shares.pop(dealer_id, None)
        self._log(EVENT_COMPLAINT, seq, {"dealer": dealer_id})
        return True

    def qualified_dealers(self) -> tuple:
        """Dealers whose commitments were received, shares verified, not complained."""
        return tuple(
            sorted(
                d
                for d in self._verified_shares
                if d not in self._disqualified and d in self._commitments
            )
        )

    def finalize(self, seq: int) -> DKGResult:
        """Aggregate qualified dealers into the group key and my final share.

        Group public key = sum of qualified dealers' constant-term
        commitments (a commitment to the group secret ``sum_d a_{d,0}``);
        my final share = sum of my verified shares. Fails closed when no
        dealer qualified.
        """
        seq = _check_seq(seq, "seq")
        qualified = self.qualified_dealers()
        if not qualified:
            raise NoQualifiedDealerError("no dealer qualified; cannot finalize")
        group_key = 0
        my_share = 0
        my_blinding = 0
        for d in qualified:
            commitment = self._commitments[d]
            group_key = (group_key + commitment.commitments[0]) % FIELD_PRIME
            s, b = self._verified_shares[d]
            my_share = (my_share + s) % FIELD_PRIME
            my_blinding = (my_blinding + b) % FIELD_PRIME
        # Defense in depth: the aggregate must satisfy the verification
        # equation against the summed commitments.
        lhs = (my_share * _GENERATOR_G + my_blinding * _GENERATOR_H) % FIELD_PRIME
        rhs = 0
        for d in qualified:
            commitment = self._commitments[d]
            for j, c in enumerate(commitment.commitments):
                rhs = (rhs + c * pow(self._my_index, j, FIELD_PRIME)) % FIELD_PRIME
        if lhs != rhs:
            raise DKGError("final aggregate failed verification (internal error)")
        body = {
            "group_key": _felt_hex(group_key),
            "my_share": _felt_hex(my_share),
            "my_share_blinding": _felt_hex(my_blinding),
            "qualified_dealers": list(qualified),
            "finalize_seq": seq,
        }
        result = DKGResult(
            group_key=group_key,
            my_share=my_share,
            my_share_blinding=my_blinding,
            qualified_dealers=qualified,
            finalize_seq=seq,
            digest=_pin(body),
        )
        self._log(
            EVENT_FINALIZED,
            seq,
            {"dealers": list(qualified), "group_key": _felt_hex(group_key)},
        )
        return result


def dkg_audit_event(kind: str, record: object, seq: int) -> dict:
    """Shape an ``audit.ndjson/1`` record for a DKG event. Fail-closed."""
    if kind not in _EVENT_KINDS:
        raise ValueError(f"unknown DKG event kind: {kind!r}")
    seq = _check_seq(seq, "audit_seq")
    body = record.as_dict() if hasattr(record, "as_dict") else {"record": str(record)}
    return {
        "schema": "audit.ndjson/1",
        "kind": kind,
        "seq": seq,
        "body": body,
    }


def main() -> None:
    """Self-check: 3 participants, t=1, two dealers, full pipeline + recovery."""
    participants = ["n0", "n1", "n2"]
    nodes = {p: DKG(p, 1, participants) for p in participants}

    # Dealer n0: f(x) = 5 + 7x, blinding g(x) = 11 + 13x.
    c0, pkts0 = nodes["n0"].round1([5, 7], [11, 13], seq=1)
    # Dealer n1: f(x) = 3 + 17x, blinding g(x) = 19 + 23x.
    c1, pkts1 = nodes["n1"].round1([3, 17], [19, 23], seq=2)

    by_dealer = {c0.dealer_id: (c0, pkts0), c1.dealer_id: (c1, pkts1)}
    assert len(pkts0) == 3 and len(pkts1) == 3

    for p, node in nodes.items():
        for dealer_id, (commitment, packets) in by_dealer.items():
            if dealer_id != p:
                assert node.receive_commitment(commitment) is True
            mine = next(q for q in packets if q.recipient_id == p)
            verdict = node.round2(mine, seq=3)
            assert verdict.valid, verdict.reason

    results = {p: nodes[p].finalize(seq=4) for p in participants}
    # Group secret = 5 + 3 = 8; group key must equal sum of C0 commitments.
    expected_key = (c0.commitments[0] + c1.commitments[0]) % FIELD_PRIME
    assert all(r.group_key == expected_key for r in results.values())
    # Any t+1 = 2 final shares recover the group secret 8.
    shares = [(nodes[p].my_index, results[p].my_share) for p in ("n0", "n2")]
    assert lagrange_recover(shares) == 8
    print("dkg-interface OK: round1 -> round2 -> finalize, group secret 8 recovered")


if __name__ == "__main__":
    main()
