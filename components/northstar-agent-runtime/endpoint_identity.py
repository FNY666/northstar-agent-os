"""Destination identity by state epoch, for endpoint-switch idempotency.

Source: neo_konsi_s2bw, "An endpoint switch resets your agent's definition of
'already done'" (Moltbook, 2026-11), paired with the same author's "An
idempotency key without a payload fingerprint is a data-corruption interface".
The mechanism the source names (quoted verbatim in ``docs/design/endpoint-
identity.md``) is that *changing an agent's API endpoint is an idempotency
boundary even when the SDK call is identical*: the new destination has no
obligation to possess the old destination's dedup record, so replaying a
"sent, outcome unknown" operation with the same key becomes a duplicate
execution.  The source's own rule: "Treat endpoint configuration as part of
execution state", and martys': "An idempotency key is a claim about the past,
and only the destination can ratify it."

What this module adds (Northstar extension, not source text):

* ``DestinationIdentity`` -- a destination is identified by the *state epoch*
  it serves, not by its address.  The address is a label only and never
  participates in identity decisions.  Equality is over the epoch alone:
  same address + different epoch is a *different* destination; same epoch +
  different address is the *same* destination (the address merely changed
  spelling, the state did not change).
* ``bind_key`` -- the operation's bound digest, over (operation key,
  destination epoch, payload fingerprint), canonicalised exactly like
  ``idempotency_manager.py`` does (sorted keys, compact separators, UTF-8,
  ``sha256:`` prefix).
* ``classify_replay`` -- REPLAY / CONFLICT / NEW_DESTINATION.
* ``AcceptanceLedger`` -- a minimal per-operation ledger of which destination
  accepted what, so a mixed replay can be explained.
* ``prove_at_effect`` -- the epoch a caller presents must be the epoch the
  destination itself attested, otherwise the identity is unproven and the
  operation is refused fail-closed.

House style: frozen dataclasses, no wall-clock, fail-closed validation,
stdlib-only, deterministic, version and schema pins, ``main()`` self-check.

Scope: this slice defines only the *identity + binding + verdict + acceptance
ledger* layer.  It does not change ``GrantPin``, ``IdempotencyManager``, or any
existing ledger module.

Version pin: endpoint-identity.v1
Schema pin: northstar.endpoint-identity.v1
"""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from typing import Any, Optional, Tuple

ENDPOINT_IDENTITY_VERSION = "endpoint-identity.v1"
SCHEMA_PIN = "northstar.endpoint-identity.v1"

REPLAY = "REPLAY"
CONFLICT = "CONFLICT"
NEW_DESTINATION = "NEW_DESTINATION"

ACCEPTED = "accepted"
PENDING = "pending"

_MAX_LABEL_LEN = 1024


class EndpointIdentityError(Exception):
    """Base class for endpoint-identity failures."""


class UnprovenIdentityError(EndpointIdentityError, ValueError):
    """Raised when a destination identity cannot be proven.

    An identity that was not attested is not an identity: the fail-closed
    refusal is the point, not a bug.
    """


def _canonical(value: Any) -> bytes:
    """Canonical JSON bytes; same rules as ``idempotency_manager._canonical``."""
    if value is None or isinstance(value, bool):
        pass
    elif isinstance(value, int):
        pass
    elif isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise TypeError("value must not contain NaN or infinity")
    elif isinstance(value, str):
        pass
    elif isinstance(value, (list, tuple)):
        for item in value:
            _canonical(item)
    elif isinstance(value, dict):
        for k, v in value.items():
            if not isinstance(k, str):
                raise TypeError("dict keys must be str for canonicalization")
            _canonical(v)
    else:
        raise TypeError(
            "value of type %s is not JSON-canonicalizable" % type(value).__name__
        )
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def payload_fingerprint(payload: Any) -> str:
    """The canonical digest of a payload -- never the payload text itself."""
    return _digest(payload)


def _require_epoch(epoch: Any) -> str:
    if not isinstance(epoch, str):
        raise UnprovenIdentityError(
            "epoch must be a str, got %s" % type(epoch).__name__
        )
    if not epoch.strip():
        raise UnprovenIdentityError("epoch must be a non-empty str")
    return epoch


def _require_address(address: Any) -> str:
    if address is None:
        return ""
    if not isinstance(address, str):
        raise TypeError("address must be a str or None")
    if len(address) > _MAX_LABEL_LEN:
        raise ValueError("address must be at most %d chars" % _MAX_LABEL_LEN)
    return address


@dataclass(frozen=True, eq=False)
class DestinationIdentity:
    """The identity of a destination: the state epoch it serves.

    ``epoch`` is the load-bearing field: a state-root hash (``"sha256:..."``)
    or a store-issued epoch string.  ``address`` is a *label* -- the host
    name or URL the caller happens to reach.  The address never participates
    in identity: a hostname can be re-pointed at a brand-new store, so the
    address can stay the same while the state (and therefore the identity)
    is entirely different.  Conversely the same store can be reached under
    two addresses, so the address can change while the state -- and the
    identity -- is unchanged.

    Equality is therefore over ``epoch`` alone:

    * same address, different epoch -> two *different* identities;
    * same epoch, different address -> the *same* identity.

    ``from_dict`` refuses a missing or empty epoch: an identity that was
    not attested is not an identity (fail closed).
    """

    epoch: str
    address: str = ""
    schema: str = SCHEMA_PIN

    def __post_init__(self) -> None:
        object.__setattr__(self, "epoch", _require_epoch(self.epoch))
        object.__setattr__(self, "address", _require_address(self.address))

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, DestinationIdentity):
            return NotImplemented
        return self.epoch == other.epoch

    def __hash__(self) -> int:
        return hash(self.epoch)

    def to_dict(self) -> dict:
        return {
            "epoch": self.epoch,
            "address": self.address,
            "schema": self.schema,
        }

    @classmethod
    def from_dict(cls, value: Any) -> "DestinationIdentity":
        """Build an identity from a mapping; refuses an absent/empty epoch."""
        if not isinstance(value, dict):
            raise UnprovenIdentityError("identity must be a mapping")
        unknown = sorted(set(value) - {"epoch", "address", "schema"})
        if unknown:
            raise UnprovenIdentityError(
                "identity carries unknown fields: " + ", ".join(unknown)
            )
        epoch = value.get("epoch")
        if epoch is None or (isinstance(epoch, str) and not epoch.strip()):
            raise UnprovenIdentityError(
                "identity epoch is missing or empty: the identity is unproven"
            )
        return cls(epoch=epoch, address=value.get("address", "") or "")

    def is_proven(self) -> bool:
        """True when this identity carries a non-empty epoch."""
        return bool(self.epoch and self.epoch.strip())

    def same_state_as(self, other: "DestinationIdentity") -> bool:
        """True when both identities name the same destination *state*."""
        if not isinstance(other, DestinationIdentity):
            raise TypeError("other must be a DestinationIdentity")
        return self.epoch == other.epoch


def bind_key(operation_key: str, destination: DestinationIdentity, payload: Any) -> str:
    """The bound digest of an operation: key + destination epoch + payload.

    The digest covers the destination's **epoch**, never its address: two
    different addresses serving the same state produce the same bound key,
    and the same address serving a different state produces a different
    one.  The payload enters as its canonical *fingerprint* (a digest), not
    as its text.

    Any one of the three inputs changing changes the digest.
    """
    if not isinstance(operation_key, str) or not operation_key:
        raise ValueError("operation_key must be a non-empty str")
    if not isinstance(destination, DestinationIdentity):
        raise TypeError("destination must be a DestinationIdentity")
    return _digest(
        {
            "operation_key": operation_key,
            "epoch": destination.epoch,
            "payload_fingerprint": payload_fingerprint(payload),
        }
    )


def classify_replay(
    recorded_destination: DestinationIdentity,
    current_destination: DestinationIdentity,
    recorded_fingerprint: str,
    presented_fingerprint: str,
) -> str:
    """Classify a replay attempt against a recorded operation.

    * ``REPLAY`` -- same destination identity and same payload fingerprint:
      the destination can ratify this key, the operation already happened
      there, and the effect must not be applied twice.
    * ``CONFLICT`` -- same destination identity, different payload
      fingerprint: the same key with different arguments.  The first
      result must *not* be returned.
    * ``NEW_DESTINATION`` -- the destination identity changed (a different
      epoch).  The new destination has no obligation to possess the old
      destination's dedup record, so this is neither a replay nor an
      ordinary conflict: the caller must reconcile, the operation stays
      ``outcome_unknown``, and nothing is silently re-executed.
    """
    for name, value in (
        ("recorded_destination", recorded_destination),
        ("current_destination", current_destination),
    ):
        if not isinstance(value, DestinationIdentity):
            raise TypeError("%s must be a DestinationIdentity" % name)
    for name, value in (
        ("recorded_fingerprint", recorded_fingerprint),
        ("presented_fingerprint", presented_fingerprint),
    ):
        if not isinstance(value, str) or not value:
            raise ValueError("%s must be a non-empty str" % name)

    if recorded_destination.epoch != current_destination.epoch:
        return NEW_DESTINATION
    if recorded_fingerprint == presented_fingerprint:
        return REPLAY
    return CONFLICT


def prove_at_effect(
    presented: DestinationIdentity, attested_epoch: Any
) -> DestinationIdentity:
    """Prove the destination identity *at effect time*.

    The epoch the caller presents must be the epoch the destination itself
    attested.  A destination that only offers an address -- no epoch -- has
    not proven anything, and the operation is refused fail-closed.
    """
    if not isinstance(presented, DestinationIdentity):
        raise TypeError("presented must be a DestinationIdentity")
    if attested_epoch is None or not isinstance(attested_epoch, str) or not attested_epoch.strip():
        raise UnprovenIdentityError(
            "destination attested no epoch: the identity is unproven"
        )
    if presented.epoch != attested_epoch:
        raise UnprovenIdentityError(
            "presented epoch does not match the attested epoch: "
            "the identity is unproven"
        )
    return presented


@dataclass(frozen=True)
class Acceptance:
    """What one destination accepted for one operation."""

    operation_key: str
    destination: DestinationIdentity
    outcome: str
    bound_digest: str
    payload_fingerprint: str = ""
    schema: str = SCHEMA_PIN

    def to_dict(self) -> dict:
        return {
            "operation_key": self.operation_key,
            "destination": self.destination.to_dict(),
            "outcome": self.outcome,
            "bound_digest": self.bound_digest,
            "payload_fingerprint": self.payload_fingerprint,
            "schema": self.schema,
        }


class AcceptanceLedger:
    """A minimal per-operation ledger of which destination accepted what.

    The ledger records *who accepted what* -- nothing more.  It does not
    retry, does not seal, and does not touch any existing ledger module.  A
    mixed replay (some operations landed on the old destination, some are
    still pending) can be explained from it: which operation landed where,
    and which operation no destination has accepted yet.
    """

    def __init__(self) -> None:
        self._accepted: dict[str, Acceptance] = {}
        self._pending: dict[str, DestinationIdentity] = {}

    def record_acceptance(
        self,
        operation_key: str,
        destination: DestinationIdentity,
        outcome: str = ACCEPTED,
        bound_digest: str = "",
        payload_fingerprint: str = "",
    ) -> Acceptance:
        """Record that ``destination`` accepted ``operation_key``."""
        if not isinstance(operation_key, str) or not operation_key:
            raise ValueError("operation_key must be a non-empty str")
        if not isinstance(destination, DestinationIdentity):
            raise TypeError("destination must be a DestinationIdentity")
        if not isinstance(outcome, str) or not outcome:
            raise ValueError("outcome must be a non-empty str")
        if bound_digest and not bound_digest.startswith("sha256:"):
            raise ValueError("bound_digest must look like 'sha256:' + 64 hex chars")
        if payload_fingerprint and not payload_fingerprint.startswith("sha256:"):
            raise ValueError(
                "payload_fingerprint must look like 'sha256:' + 64 hex chars"
            )
        acceptance = Acceptance(
            operation_key=operation_key,
            destination=destination,
            outcome=outcome,
            bound_digest=bound_digest,
            payload_fingerprint=payload_fingerprint,
        )
        self._accepted[operation_key] = acceptance
        self._pending.pop(operation_key, None)
        return acceptance

    def record_pending(
        self, operation_key: str, destination: DestinationIdentity
    ) -> None:
        """Record that an operation was dispatched to a destination, outcome unknown."""
        if not isinstance(operation_key, str) or not operation_key:
            raise ValueError("operation_key must be a non-empty str")
        if not isinstance(destination, DestinationIdentity):
            raise TypeError("destination must be a DestinationIdentity")
        self._pending[operation_key] = destination

    def accepted_by(self, operation_key: str) -> Optional[Acceptance]:
        """The acceptance for ``operation_key``, or None if nobody accepted it."""
        if not isinstance(operation_key, str) or not operation_key:
            raise ValueError("operation_key must be a non-empty str")
        return self._accepted.get(operation_key)

    def pending_at(self, operation_key: str) -> Optional[DestinationIdentity]:
        """The destination an operation is pending at, or None."""
        if not isinstance(operation_key, str) or not operation_key:
            raise ValueError("operation_key must be a non-empty str")
        return self._pending.get(operation_key)

    def accepted_operations(self) -> Tuple[str, ...]:
        """Accepted operation keys, in first-acceptance order."""
        return tuple(self._accepted.keys())

    def pending_operations(self) -> Tuple[str, ...]:
        """Pending operation keys, in first-dispatch order."""
        return tuple(self._pending.keys())

    def acceptance_count(self) -> int:
        """How many operations some destination has accepted."""
        return len(self._accepted)

    def __len__(self) -> int:
        return len(self._accepted) + len(self._pending)


def main() -> None:
    a = DestinationIdentity(epoch="sha256:" + "a" * 64, address="https://a.example")
    b = DestinationIdentity(epoch="sha256:" + "b" * 64, address="https://b.example")
    a_again = DestinationIdentity(epoch=a.epoch, address="https://alias.example")
    assert a != b
    assert a == a_again  # same state, different address spelling
    assert classify_replay(a, a, "sha256:" + "c" * 64, "sha256:" + "c" * 64) == REPLAY
    assert classify_replay(a, a, "sha256:" + "c" * 64, "sha256:" + "d" * 64) == CONFLICT
    assert classify_replay(a, b, "sha256:" + "c" * 64, "sha256:" + "c" * 64) == NEW_DESTINATION
    assert bind_key("op-1", a, {"x": 1}) == bind_key("op-1", a, {"x": 1})
    assert bind_key("op-1", a, {"x": 1}) != bind_key("op-1", b, {"x": 1})
    ledger = AcceptanceLedger()
    ledger.record_acceptance("op-1", a, bound_digest=bind_key("op-1", a, {"x": 1}))
    assert ledger.accepted_by("op-1") is not None
    assert ledger.accepted_by("op-2") is None
    try:
        prove_at_effect(a, None)
    except UnprovenIdentityError:
        pass
    else:
        raise AssertionError("unattested epoch should refuse")
    print("endpoint-identity OK: identity, bind, replay verdicts, ledger")


if __name__ == "__main__":
    main()
