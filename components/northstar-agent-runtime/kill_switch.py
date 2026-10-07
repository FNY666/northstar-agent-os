"""Host kill switch with rollback points (WAAL liability).

The host's emergency brake over the agent. Two cooperating pieces:

* **Kill switch** — ``arm()`` declares the brake is ready, ``trigger()``
  slams it shut, ``disarm()`` stands it down. Once triggered, every action
  is denied (fail closed) until the host rolls back to a pinned safe state.
  Triggering is sticky: ``disarm()`` is refused while triggered, so a kill
  cannot be quietly walked back — recovery goes through ``rollback()``.

* **Rollback points** — content-addressed snapshots of host state
  (``state_hash = sha256(canonical_json(state))``). ``rollback()`` restores
  the switch to a chosen point and logs the rollback; the returned record
  pins the exact state hash the host must restore, so "rolled back" is a
  checkable claim, not a vibe.

**Persistence.** All switch state lives in one JSON file, written atomically
(temp file + fsync + rename + directory fsync) after every mutation, so a
kill survives a host restart. On load the file's ``state_digest`` is
verified; a corrupt or tampered file is treated as **triggered** (fail
closed) with a loud warning — an unreadable brake is a brake that is on.

**WAAL liability.** WAAL = "We Are All Liable". Every arm / trigger /
disarm / rollback appends a digest-chained ``LiabilityRecord`` naming the
actor (host identity), the reason, and the resulting state digest. The
chain lets a later auditor prove *who* killed the agent, *why*, and *what
state* the system was left in — liability is a record, not an assertion.

House rules, as everywhere: frozen dataclasses, ``sha256:`` digest pins,
``hmac.compare_digest`` for digest comparisons, fail-closed, no wall-clock
(``seq`` is a caller-supplied integer sequence number — the host's own
monotonic counter).

Honest scope: this is the switch and the rollback *ledger*, not the
restoration mechanism — actually restoring application state from
``state_hash`` is the host's job. A hostile operator with write access to
the state file can rewrite it; the digest only detects that on the next
load (fail closed), it does not prevent it. Crash durability of the state
file itself follows the same atomic-write pattern as ``audit_chain``'s
``DurableAuditWriter``.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import warnings
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

#: Module version.
KILL_SWITCH_VERSION = "kill-switch.v1"

#: Schema pin stamped on the persisted state file.
SCHEMA_PIN = "northstar.kill-switch.v1"

_DIGEST_PREFIX = "sha256:"
_HEX64_RE = __import__("re").compile(r"^[0-9a-f]{64}$")

# Fixed event vocabulary for liability records.
EVENT_ARMED = "armed"
EVENT_TRIGGERED = "triggered"
EVENT_DISARMED = "disarmed"
EVENT_ROLLBACK = "rollback"

# Fixed basis vocabulary for check().
BASIS_ALLOW = "allow"
BASIS_TRIGGERED = "kill-switch-triggered"


def _canonical_json(obj: Any) -> bytes:
    """Canonical JSON bytes: sorted keys, no whitespace, UTF-8.

    Local copy (no dependency on ``audit_chain``) so this module stays
    standalone-importable.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _digest(data: bytes) -> str:
    """``sha256:``-prefixed hex digest of ``data``."""
    return _DIGEST_PREFIX + hashlib.sha256(data).hexdigest()


def _digest_equal(a: str, b: str) -> bool:
    """Constant-time digest comparison."""
    return hmac.compare_digest(a, b)


def _check_seq(seq: Any, name: str = "seq") -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise TypeError(f"{name} must be an int")
    if seq < 0:
        raise ValueError(f"{name} must be >= 0")
    return seq


def _check_reason(reason: Any, name: str = "reason") -> str:
    if not isinstance(reason, str):
        raise TypeError(f"{name} must be a str")
    if not reason:
        raise ValueError(f"{name} must be non-empty")
    return reason


def _check_state_hash(value: Any) -> str:
    if not isinstance(value, str):
        raise TypeError("state_hash must be a str")
    if not value.startswith(_DIGEST_PREFIX) or not _HEX64_RE.match(value[len(_DIGEST_PREFIX):]):
        raise ValueError("state_hash must be a sha256: hex digest")
    return value


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RollbackPoint:
    """A content-addressed snapshot of host state.

    ``state_hash`` pins the exact bytes the host must restore; ``seq`` is
    the host's own sequence number (no wall-clock); ``prev_point_id``
    chains points in creation order.
    """

    point_id: str
    state_hash: str
    seq: int
    created_reason: str
    prev_point_id: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "point_id": self.point_id,
            "state_hash": self.state_hash,
            "seq": self.seq,
            "created_reason": self.created_reason,
            "prev_point_id": self.prev_point_id,
        }


@dataclass(frozen=True)
class RollbackRecord:
    """One executed rollback: from-state pinned, to-state pinned, chained."""

    rollback_id: str
    from_state_hash: str | None
    to_state_hash: str
    to_point_id: str
    seq: int
    reason: str
    prev_digest: str
    digest: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "rollback_id": self.rollback_id,
            "from_state_hash": self.from_state_hash,
            "to_state_hash": self.to_state_hash,
            "to_point_id": self.to_point_id,
            "seq": self.seq,
            "reason": self.reason,
            "prev_digest": self.prev_digest,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class LiabilityRecord:
    """WAAL liability entry: who did what to the switch, and the digest of
    the state that resulted. Chained via ``prev_digest``."""

    event: str
    actor: str
    reason: str
    seq: int
    state_digest: str
    prev_digest: str
    digest: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "event": self.event,
            "actor": self.actor,
            "reason": self.reason,
            "seq": self.seq,
            "state_digest": self.state_digest,
            "prev_digest": self.prev_digest,
            "digest": self.digest,
        }


# ---------------------------------------------------------------------------
# Persistence helpers
# ---------------------------------------------------------------------------


def _atomic_write_json(path: Path, payload: Mapping[str, Any]) -> None:
    """Write ``payload`` as JSON atomically: temp file + fsync + rename +
    directory fsync. Short writes are retried; a zero-byte write raises."""
    data = _canonical_json(dict(payload))
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        view = memoryview(data)
        while view:
            n = os.write(fd, view)
            if n == 0:
                raise OSError("short write returned zero bytes")
            view = view[n:]
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)
    dir_fd = os.open(path.parent, os.O_DIRECTORY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def _state_digest(state: Mapping[str, Any]) -> str:
    body = {k: v for k, v in state.items() if k != "state_digest"}
    return _digest(_canonical_json(body))


# ---------------------------------------------------------------------------
# Kill switch
# ---------------------------------------------------------------------------


class KillSwitch:
    """The host's emergency brake, persisted to ``path``.

    Typical incident flow::

        ks = KillSwitch("/var/lib/northstar/kill-switch.json")
        ks.arm("scheduled model upgrade window", seq=41)
        point = ks.create_rollback_point(app_state, reason="pre-upgrade", seq=42)
        ...
        ks.trigger(reason="upgrade misbehaving", seq=43)
        ks.check()          # -> (False, "kill-switch-triggered")
        ...
        ks.rollback(point.point_id, reason="restore pre-upgrade", seq=44)
        ks.check()          # -> (True, "allow")
        ks.arm("post-incident monitoring", seq=45)
    """

    def __init__(self, path: str | os.PathLike[str], *, actor: str = "host") -> None:
        if not isinstance(actor, str) or not actor:
            raise ValueError("actor must be a non-empty str")
        self._path = Path(path)
        self._actor = actor
        self._armed = False
        self._armed_reason = ""
        self._triggered = False
        self._trigger_reason = ""
        self._trigger_seq: int | None = None
        self._current_state_hash: str | None = None
        self._points: dict[str, dict[str, Any]] = {}
        self._point_order: list[str] = []
        self._rollback_log: list[dict[str, Any]] = []
        self._liability_log: list[dict[str, Any]] = []
        self._load()

    # -- persistence ------------------------------------------------------

    def _snapshot(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "version": KILL_SWITCH_VERSION,
            "armed": self._armed,
            "armed_reason": self._armed_reason,
            "triggered": self._triggered,
            "trigger_reason": self._trigger_reason,
            "trigger_seq": self._trigger_seq,
            "current_state_hash": self._current_state_hash,
            "rollback_points": [self._points[pid] for pid in self._point_order],
            "rollback_log": list(self._rollback_log),
            "liability_log": list(self._liability_log),
        }

    def _persist(self) -> None:
        state = self._snapshot()
        state["state_digest"] = _state_digest(state)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        _atomic_write_json(self._path, state)

    def _load(self) -> None:
        try:
            raw = self._path.read_bytes()
        except FileNotFoundError:
            return  # fresh switch: disarmed, no points
        except OSError as exc:
            warnings.warn(f"kill-switch state unreadable ({exc}); treating as TRIGGERED", UserWarning, stacklevel=3)
            self._fail_closed("state file unreadable")
            return
        try:
            state = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            warnings.warn(f"kill-switch state corrupt ({exc}); treating as TRIGGERED", UserWarning, stacklevel=3)
            self._fail_closed("state file corrupt")
            return
        if not isinstance(state, dict) or state.get("schema") != SCHEMA_PIN:
            warnings.warn("kill-switch state has unknown schema; treating as TRIGGERED", UserWarning, stacklevel=3)
            self._fail_closed("state file has unknown schema")
            return
        claimed = state.get("state_digest")
        if not isinstance(claimed, str) or not _digest_equal(claimed, _state_digest(state)):
            warnings.warn("kill-switch state_digest mismatch (tampered?); treating as TRIGGERED", UserWarning, stacklevel=3)
            self._fail_closed("state digest mismatch")
            return
        # Verified: restore.
        self._armed = bool(state.get("armed", False))
        self._armed_reason = str(state.get("armed_reason", ""))
        self._triggered = bool(state.get("triggered", False))
        self._trigger_reason = str(state.get("trigger_reason", ""))
        self._trigger_seq = state.get("trigger_seq")
        self._current_state_hash = state.get("current_state_hash")
        points = state.get("rollback_points", [])
        for p in points:
            if isinstance(p, dict) and isinstance(p.get("point_id"), str):
                self._points[p["point_id"]] = p
                self._point_order.append(p["point_id"])
        self._rollback_log = [r for r in state.get("rollback_log", []) if isinstance(r, dict)]
        self._liability_log = [r for r in state.get("liability_log", []) if isinstance(r, dict)]

    def _fail_closed(self, reason: str) -> None:
        """Enter the triggered state without persisting (the file itself is
        suspect, so we do not overwrite it yet)."""
        self._triggered = True
        self._trigger_reason = reason
        self._trigger_seq = None
        self._armed = False

    # -- liability ----------------------------------------------------------

    def _log_liability(self, event: str, reason: str, seq: int) -> LiabilityRecord:
        prev = self._liability_log[-1]["digest"] if self._liability_log else ""
        body = {
            "event": event,
            "actor": self._actor,
            "reason": reason,
            "seq": seq,
            "state_digest": _state_digest(self._snapshot()),
            "prev_digest": prev,
        }
        record = LiabilityRecord(
            event=event,
            actor=self._actor,
            reason=reason,
            seq=seq,
            state_digest=body["state_digest"],
            prev_digest=prev,
            digest=_digest(_canonical_json(body)),
        )
        self._liability_log.append(record.as_dict())
        return record

    # -- state --------------------------------------------------------------

    @property
    def is_armed(self) -> bool:
        return self._armed

    @property
    def is_triggered(self) -> bool:
        return self._triggered

    @property
    def current_state_hash(self) -> str | None:
        """The state hash the switch currently pins (None until the first
        rollback point is created)."""
        return self._current_state_hash

    def check(self) -> tuple[bool, str]:
        """Gate hook: ``(True, "allow")`` normally, ``(False,
        "kill-switch-triggered")`` once triggered. Never raises."""
        if self._triggered:
            return (False, BASIS_TRIGGERED)
        return (True, BASIS_ALLOW)

    # -- arm / trigger / disarm ----------------------------------------------

    def arm(self, reason: str, *, seq: int) -> bool:
        """Arm the switch. Returns True on transition, False if already
        armed. Refuses (ValueError) while triggered — recovery goes through
        ``rollback()``."""
        _check_reason(reason)
        _check_seq(seq)
        if self._triggered:
            raise ValueError("kill switch is triggered; rollback before re-arming")
        if self._armed:
            return False
        self._armed = True
        self._armed_reason = reason
        self._log_liability(EVENT_ARMED, reason, seq)
        self._persist()
        return True

    def trigger(self, *, reason: str = "", seq: int = 0) -> bool:
        """Slam the brake shut. Idempotent: returns True on the transition,
        False if already triggered. Works from armed *or* disarmed — an
        emergency brake must always fire."""
        _check_seq(seq)
        if reason != "" and not isinstance(reason, str):
            raise TypeError("reason must be a str")
        if self._triggered:
            return False
        self._triggered = True
        self._trigger_reason = reason or "host trigger"
        self._trigger_seq = seq
        self._armed = False
        self._log_liability(EVENT_TRIGGERED, self._trigger_reason, seq)
        self._persist()
        return True

    def disarm(self, *, reason: str = "", seq: int = 0) -> bool:
        """Stand the switch down. Returns True on armed -> disarmed, False
        if already disarmed. Refuses (ValueError) while triggered."""
        _check_seq(seq)
        if reason != "" and not isinstance(reason, str):
            raise TypeError("reason must be a str")
        if self._triggered:
            raise ValueError("kill switch is triggered; rollback before disarming")
        if not self._armed:
            return False
        self._armed = False
        self._armed_reason = ""
        self._log_liability(EVENT_DISARMED, reason or "host disarm", seq)
        self._persist()
        return True

    # -- rollback points -----------------------------------------------------

    def create_rollback_point(self, state: Mapping[str, Any], *, reason: str, seq: int) -> RollbackPoint:
        """Snapshot ``state``: pin ``sha256(canonical_json(state))`` as a
        rollback point. Allowed in any switch state (a snapshot is never an
        action)."""
        _check_reason(reason)
        _check_seq(seq)
        if not isinstance(state, Mapping):
            raise TypeError("state must be a mapping")
        state_hash = _digest(_canonical_json(dict(state)))
        prev_point_id = self._point_order[-1] if self._point_order else None
        point_id = "rp-" + _digest(
            _canonical_json({"h": state_hash, "seq": seq, "prev": prev_point_id})
        )[len(_DIGEST_PREFIX):len(_DIGEST_PREFIX) + 16]
        point = RollbackPoint(
            point_id=point_id,
            state_hash=state_hash,
            seq=seq,
            created_reason=reason,
            prev_point_id=prev_point_id,
        )
        self._points[point_id] = point.as_dict()
        self._point_order.append(point_id)
        self._current_state_hash = state_hash
        self._persist()
        return point

    def rollback_points(self) -> list[RollbackPoint]:
        """All rollback points, oldest first."""
        return [
            RollbackPoint(
                point_id=p["point_id"],
                state_hash=p["state_hash"],
                seq=p["seq"],
                created_reason=p["created_reason"],
                prev_point_id=p.get("prev_point_id"),
            )
            for p in (self._points[pid] for pid in self._point_order)
        ]

    # -- rollback ------------------------------------------------------------

    def rollback(self, point_id: str, *, reason: str, seq: int) -> RollbackRecord:
        """Recover from a triggered kill switch by rolling back to ``point_id``.

        Requires the switch to be triggered (ValueError otherwise) and the
        point to exist (KeyError otherwise). Restores the pinned state hash,
        clears the trigger, and leaves the switch *disarmed* — the host must
        deliberately re-arm. The rollback itself is logged (append-only,
        digest-chained) and emits a liability record.
        """
        _check_reason(reason)
        _check_seq(seq)
        if not isinstance(point_id, str):
            raise TypeError("point_id must be a str")
        if not self._triggered:
            raise ValueError("rollback requires a triggered kill switch")
        if point_id not in self._points:
            raise KeyError(f"unknown rollback point: {point_id!r}")
        point = self._points[point_id]
        from_hash = self._current_state_hash
        to_hash = point["state_hash"]
        prev = self._rollback_log[-1]["digest"] if self._rollback_log else ""
        rollback_id = "rb-" + _digest(
            _canonical_json({"to": point_id, "seq": seq, "prev": prev})
        )[len(_DIGEST_PREFIX):len(_DIGEST_PREFIX) + 16]
        record = RollbackRecord(
            rollback_id=rollback_id,
            from_state_hash=from_hash,
            to_state_hash=to_hash,
            to_point_id=point_id,
            seq=seq,
            reason=reason,
            prev_digest=prev,
            digest=_digest(_canonical_json({
                "rollback_id": rollback_id,
                "from_state_hash": from_hash,
                "to_state_hash": to_hash,
                "to_point_id": point_id,
                "seq": seq,
                "reason": reason,
                "prev_digest": prev,
            })),
        )
        self._rollback_log.append(record.as_dict())
        # Restore: the switch now pins the rolled-back state, the trigger is
        # cleared, and the switch is left disarmed for deliberate re-arming.
        self._current_state_hash = to_hash
        self._triggered = False
        self._trigger_reason = ""
        self._trigger_seq = None
        self._armed = False
        self._armed_reason = ""
        self._log_liability(EVENT_ROLLBACK, f"{reason} -> {point_id}", seq)
        self._persist()
        return record

    def rollback_log(self) -> list[RollbackRecord]:
        """All executed rollbacks, oldest first."""
        return [
            RollbackRecord(
                rollback_id=r["rollback_id"],
                from_state_hash=r["from_state_hash"],
                to_state_hash=r["to_state_hash"],
                to_point_id=r["to_point_id"],
                seq=r["seq"],
                reason=r["reason"],
                prev_digest=r["prev_digest"],
                digest=r["digest"],
            )
            for r in self._rollback_log
        ]

    def liability_log(self) -> list[LiabilityRecord]:
        """WAAL liability chain, oldest first."""
        return [
            LiabilityRecord(
                event=r["event"],
                actor=r["actor"],
                reason=r["reason"],
                seq=r["seq"],
                state_digest=r["state_digest"],
                prev_digest=r["prev_digest"],
                digest=r["digest"],
            )
            for r in self._liability_log
        ]

    def verify_liability_chain(self) -> tuple[bool, str]:
        """Recompute every liability digest and link. Never raises on
        well-formed input; returns ``(True, "ok")`` or ``(False, reason)``."""
        prev = ""
        for raw in self._liability_log:
            try:
                rec = LiabilityRecord(
                    event=raw["event"], actor=raw["actor"], reason=raw["reason"],
                    seq=raw["seq"], state_digest=raw["state_digest"],
                    prev_digest=raw["prev_digest"], digest=raw["digest"],
                )
            except (KeyError, TypeError):
                return (False, "malformed liability record")
            if not _digest_equal(rec.prev_digest, prev):
                return (False, "liability chain link broken")
            expect = _digest(_canonical_json({
                "event": rec.event, "actor": rec.actor, "reason": rec.reason,
                "seq": rec.seq, "state_digest": rec.state_digest,
                "prev_digest": rec.prev_digest,
            }))
            if not _digest_equal(rec.digest, expect):
                return (False, "liability digest mismatch")
            prev = rec.digest
        return (True, "ok")
