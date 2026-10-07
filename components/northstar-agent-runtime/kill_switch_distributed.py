"""Distributed kill switch: 2-of-3 host quorum variant.

Alternative method to the centralized ``kill_switch.py`` host emergency
brake. Instead of one host deciding alone, the fleet-level trigger requires
a quorum: 2 of 3 known hosts must cast authenticated trigger votes. One
malicious (or compromised) host cannot kill the agent alone, and one
withholding host cannot stop a legitimate kill — either direction takes two
honest hosts.

* **Known host set** — three host identities pinned at construction
  (``host_id`` -> 32-byte Ed25519 public key). Membership is fixed; adding
  or removing a host is a configuration change, not a runtime operation.
* **Authenticated votes** — every vote is signed by the voting host's key
  over (schema pin, host_id, vote, seq). Unverifiable, duplicate, or
  unknown-host votes are rejected *before* counting and never contribute to
  quorum.
* **Quorum rule** — ``trigger(votes)`` is True when at least ``quorum``
  valid votes from *distinct* known hosts say ``"trigger"``. A single vote
  — even from a malicious host — never crosses a 2-of-3 quorum.
* **Sticky** — once the switch records a trigger, ``check()`` denies until
  a quorum-signed stand-down (or the centralized host-level rollback, which
  is the host's own job — see ``kill_switch.py``).
* **Fail-closed, no wall-clock** — ``seq`` is a caller-supplied integer
  sequence number (the fleet's own monotonic counter); malformed votes
  refuse instead of counting.

Honest scope: this is the *quorum decision rule* over authenticated votes,
not a full consensus protocol — no leader election, no view changes, no
liveness guarantee under network partition (a partitioned host simply can't
vote, so a kill needs the two reachable hosts). 2-of-3 tolerates exactly
one Byzantine host: one liar can't forge the second vote (it has no key),
and one saboteur withholding its vote still leaves two honest votes to
reach quorum. It does not survive two colluding hosts — no 2-of-3 scheme
can, and the docstring says so instead of implying otherwise.

When is distributed better than centralized (``kill_switch.py``)?
- Centralized wins when the binding constraint is latency or single
  accountability: one keystroke kills, and the WAAL liability chain names
  exactly one actor.
- Distributed wins when the binding constraint is *unilateral action*:
  stopping a lone compromised host (or lone rogue operator) from killing
  a fleet, or stopping a lone host failure from silently disarming the
  brake. Recommended composition: each host runs the centralized switch
  locally (crash durability, atomic file persistence); the fleet-level
  trigger is this quorum gate over the hosts' votes.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterable, Mapping, Sequence

import ed25519

#: Module version.
KILL_SWITCH_DISTRIBUTED_VERSION = "kill-switch-distributed.v1"

#: Schema pin stamped into every signed vote body (cross-schema replay fails).
SCHEMA_PIN = "northstar.kill-switch-distributed.v1"

_DIGEST_PREFIX = "sha256:"
_HEX64_RE = __import__("re").compile(r"^[0-9a-f]{64}$")

# Fixed vote vocabulary.
VOTE_TRIGGER = "trigger"
VOTE_STAND_DOWN = "stand-down"
_VOTE_VALUES = (VOTE_TRIGGER, VOTE_STAND_DOWN)

# Fixed basis vocabulary for check().
BASIS_ALLOW = "allow"
BASIS_TRIGGERED = "distributed-kill-switch-triggered"

# Default fleet shape this module is tuned for.
DEFAULT_HOSTS = 3
DEFAULT_QUORUM = 2


class Vote(str, Enum):
    """The two things a host may vote for."""

    TRIGGER = VOTE_TRIGGER
    STAND_DOWN = VOTE_STAND_DOWN


class QuorumError(ValueError):
    """Raised when a vote batch cannot reach quorum (fail-closed refusal)."""


def _canonical_json(obj: Any) -> bytes:
    """Canonical JSON bytes: sorted keys, no whitespace, UTF-8.

    Local copy (no dependency on ``audit_chain``) so this module stays
    standalone-importable.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def _check_seq(seq: Any, name: str = "seq") -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise TypeError(f"{name} must be an int")
    if seq < 0:
        raise ValueError(f"{name} must be >= 0")
    return seq


def _check_host_id(host_id: Any) -> str:
    if not isinstance(host_id, str):
        raise TypeError("host_id must be a str")
    if not host_id:
        raise ValueError("host_id must be non-empty")
    return host_id


def _check_vote_value(vote: Any) -> str:
    if isinstance(vote, Vote):
        return vote.value
    if not isinstance(vote, str):
        raise TypeError("vote must be a str or Vote")
    if vote not in _VOTE_VALUES:
        raise ValueError(f"vote must be one of {_VOTE_VALUES}")
    return vote


def _check_pubkey(pubkey: Any, host_id: str) -> bytes:
    if not isinstance(pubkey, (bytes, bytearray)):
        raise TypeError(f"pubkey for host {host_id!r} must be bytes")
    if len(pubkey) != 32:
        raise ValueError(f"pubkey for host {host_id!r} must be 32 bytes")
    return bytes(pubkey)


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class HostVote:
    """One host's authenticated vote.

    ``signature`` covers the canonical JSON of the vote body (schema pin,
    host_id, vote, seq) signed by the host's Ed25519 key. ``repr=False``
    keeps the raw signature out of logs.
    """

    host_id: str
    vote: str
    seq: int
    signature: bytes = b""

    def __post_init__(self) -> None:
        _check_host_id(self.host_id)
        object.__setattr__(self, "vote", _check_vote_value(self.vote))
        _check_seq(self.seq)
        if not isinstance(self.signature, (bytes, bytearray)):
            raise TypeError("signature must be bytes")
        # Empty signature is allowed at construction so callers can build
        # the body first; cast_vote always fills it. verify_vote rejects
        # empty/malformed signatures without raising.

    def body(self) -> dict[str, Any]:
        """The signed body (everything except the signature itself)."""
        return {
            "schema": SCHEMA_PIN,
            "host_id": self.host_id,
            "vote": self.vote,
            "seq": self.seq,
        }

    def as_dict(self) -> dict[str, Any]:
        d = self.body()
        d["signature"] = bytes(self.signature).hex()
        return d

    def __repr__(self) -> str:  # keep raw signatures out of logs
        return (f"HostVote(host_id={self.host_id!r}, vote={self.vote!r}, "
                f"seq={self.seq})")


# ---------------------------------------------------------------------------
# Vote casting / verification
# ---------------------------------------------------------------------------


def cast_vote(host_id: str, vote: str | Vote, seq: int, secret: bytes) -> HostVote:
    """Sign a vote with the host's 32-byte Ed25519 secret key."""
    _check_host_id(host_id)
    vote_value = _check_vote_value(vote)
    _check_seq(seq)
    if not isinstance(secret, (bytes, bytearray)) or len(secret) != 32:
        raise ValueError("secret must be a 32-byte Ed25519 secret key")
    body = {
        "schema": SCHEMA_PIN,
        "host_id": host_id,
        "vote": vote_value,
        "seq": seq,
    }
    sig = ed25519.sign(bytes(secret), _canonical_json(body))
    return HostVote(host_id=host_id, vote=vote_value, seq=seq,
                    signature=bytes(sig))


def verify_vote(vote: Any, host_pubkeys: Mapping[str, bytes]) -> bool:
    """Verify one vote against the known host set. Never raises.

    Returns True only when: the vote is a well-formed HostVote, its
    host_id is a known host, and its signature verifies under that host's
    key. Everything else — malformed objects, unknown hosts, bad
    signatures — is False (fail-closed).
    """
    try:
        if not isinstance(vote, HostVote):
            return False
        pubkey = host_pubkeys.get(vote.host_id)
        if pubkey is None:
            return False
        pubkey = _check_pubkey(pubkey, vote.host_id)
        sig = vote.signature
        if not isinstance(sig, (bytes, bytearray)) or len(sig) != 64:
            return False
        return bool(ed25519.verify(pubkey, _canonical_json(vote.body()),
                                   bytes(sig)))
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Quorum gate
# ---------------------------------------------------------------------------


class DistributedKillSwitch:
    """2-of-3 (configurable) quorum gate over authenticated host votes.

    ``host_pubkeys`` maps host_id -> 32-byte Ed25519 public key. ``quorum``
    defaults to 2 with 3 hosts; any 1 <= quorum <= len(hosts) is accepted,
    but only quorum > n/2 tolerates a Byzantine host — the constructor does
    not enforce that, the docstring states it.
    """

    def __init__(self, host_pubkeys: Mapping[str, bytes], quorum: int = DEFAULT_QUORUM) -> None:
        if not isinstance(host_pubkeys, Mapping) or not host_pubkeys:
            raise ValueError("host_pubkeys must be a non-empty mapping")
        self._pubkeys: dict[str, bytes] = {}
        for host_id, pubkey in host_pubkeys.items():
            _check_host_id(host_id)
            self._pubkeys[host_id] = _check_pubkey(pubkey, host_id)
        if isinstance(quorum, bool) or not isinstance(quorum, int):
            raise TypeError("quorum must be an int")
        if not 1 <= quorum <= len(self._pubkeys):
            raise ValueError("quorum must satisfy 1 <= quorum <= len(host_pubkeys)")
        self._quorum = quorum
        self._triggered = False
        self._trigger_seq: int | None = None

    @property
    def quorum(self) -> int:
        return self._quorum

    @property
    def host_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._pubkeys))

    @property
    def triggered(self) -> bool:
        return self._triggered

    def _valid_votes(self, votes: Iterable[Any]) -> dict[str, HostVote]:
        """Verify a batch; return {host_id: vote}, first valid vote wins.

        Duplicates from the same host count once (replay of one host's vote
        can never manufacture quorum). Invalid votes are dropped silently —
        they refuse, they don't raise, so a poisoned batch can't DoS the
        gate into an exception.
        """
        valid: dict[str, HostVote] = {}
        for v in votes:
            if not isinstance(v, HostVote):
                continue
            if v.host_id in valid:
                continue  # one host, one vote
            if verify_vote(v, self._pubkeys):
                valid[v.host_id] = v
        return valid

    def count_trigger_votes(self, votes: Iterable[Any]) -> int:
        """Number of distinct known hosts with a valid ``trigger`` vote."""
        return sum(1 for v in self._valid_votes(votes).values()
                   if v.vote == VOTE_TRIGGER)

    def trigger(self, votes: Iterable[Any]) -> bool:
        """Quorum decision rule: True iff >= quorum valid trigger votes.

        Pure function of the vote batch — no state change. One malicious
        host, acting alone, can never return True under a 2-of-3 quorum:
        its forged vote fails verification (no key), and its single valid
        vote is only 1 < 2.
        """
        return self.count_trigger_votes(votes) >= self._quorum

    def record_trigger(self, votes: Iterable[Any], seq: int, reason: str) -> None:
        """Record a quorum trigger; sticky until a quorum stand-down.

        Raises :class:`QuorumError` when the batch does not reach quorum
        (fail-closed — the switch does not move). ``reason`` names why, for
        the audit trail.
        """
        _check_seq(seq)
        if not isinstance(reason, str) or not reason:
            raise ValueError("reason must be a non-empty str")
        if not self.trigger(votes):
            raise QuorumError(
                f"quorum not reached: need {self._quorum}, "
                f"got {self.count_trigger_votes(votes)} valid trigger votes"
            )
        self._triggered = True
        self._trigger_seq = seq

    def record_stand_down(self, votes: Iterable[Any], seq: int, reason: str) -> None:
        """Clear a trigger on a quorum of ``stand-down`` votes.

        Symmetric with ``record_trigger``: a lone host cannot quietly
        disarm the fleet brake either.
        """
        _check_seq(seq)
        if not isinstance(reason, str) or not reason:
            raise ValueError("reason must be a non-empty str")
        stand_downs = sum(1 for v in self._valid_votes(votes).values()
                          if v.vote == VOTE_STAND_DOWN)
        if stand_downs < self._quorum:
            raise QuorumError(
                f"quorum not reached: need {self._quorum}, "
                f"got {stand_downs} valid stand-down votes"
            )
        self._triggered = False
        self._trigger_seq = seq

    def check(self) -> tuple[bool, str]:
        """Gate hook: ``(True, "allow")`` normally, ``(False, basis)`` once
        triggered. Never raises."""
        if self._triggered:
            return (False, BASIS_TRIGGERED)
        return (True, BASIS_ALLOW)

    def as_dict(self) -> dict[str, Any]:
        return {
            "version": KILL_SWITCH_DISTRIBUTED_VERSION,
            "schema": SCHEMA_PIN,
            "hosts": self.host_ids,
            "quorum": self._quorum,
            "triggered": self._triggered,
            "trigger_seq": self._trigger_seq,
        }


def main() -> None:
    """Self-check smoke: 2-of-3 quorum behavior on generated keys."""
    import os

    secrets = {f"host-{i}": os.urandom(32) for i in range(3)}
    pubkeys = {h: ed25519.public_key(s) for h, s in secrets.items()}
    gate = DistributedKillSwitch(pubkeys)
    votes = [cast_vote(h, VOTE_TRIGGER, 1, secrets[h]) for h in ("host-0", "host-1")]
    assert gate.trigger(votes) is True
    assert gate.trigger(votes[:1]) is False
    gate.record_trigger(votes, 1, "smoke")
    assert gate.check() == (False, BASIS_TRIGGERED)
    print("kill-switch-distributed OK: 2-of-3 quorum, single host refused")


if __name__ == "__main__":
    main()
