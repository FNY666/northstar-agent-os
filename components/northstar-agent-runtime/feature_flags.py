"""Feature flags for safe rollout: deterministic per-subject gating.

A ``FeatureFlag`` is a named, master-switched gate with a ``rollout_pct`` in
[0, 100]. ``is_enabled(flag, subject_id)`` is a pure, deterministic function:
the subject is hashed (sha256) into one of 10_000 buckets and the flag is on
iff ``bucket < rollout_pct * 100``. The same ``(flag.name, subject_id)`` pair
always yields the same verdict -- stable across restarts, no randomness, no
wall-clock.

``FlagManager`` is a small mutable registry owning the flag records: register,
enable/disable, change rollout, remove, evaluate one flag or all flags for a
subject, plus ``flag_audit_event()`` for caller-sequenced change records.

House style: frozen dataclasses, fail-closed validation (``TypeError`` on
wrong types -- bool is not a number, ``ValueError`` on out-of-range values),
stdlib-only, deterministic, version/schema pins, ``main()`` self-check. No
wall-clock anywhere.

Honest scope: deterministic hashing is a *stable rollout* mechanism, not a
security boundary -- any subject can compute their own bucket, and a hashed
subject cannot be un-hashed by the operator but tells nothing about the
feature itself. A flag being on is never an authorization: ``is_enabled``
answers "is this subject in the rollout cohort", never "may this action run".
Gates still decide.

Version pin: feature-flags.v1
Schema pin: northstar.feature-flags.v1
"""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass
from typing import Dict, Tuple

FEATURE_FLAGS_VERSION = "feature-flags.v1"
SCHEMA_PIN = "northstar.feature-flags.v1"

#: Hash buckets per flag; rollout_pct * 100 of them are "on".
BUCKETS = 10_000

_HASH_DOMAIN = "northstar.feature-flags.v1"


def _require_name(name: object) -> str:
    if not isinstance(name, str):
        raise TypeError(f"name must be a str, got {type(name).__name__}")
    if not name:
        raise ValueError("name must be non-empty")
    if "\x00" in name:
        raise ValueError("name must not contain NUL")
    return name


def _require_bool(name: str, value: object) -> bool:
    if not isinstance(value, bool):
        raise TypeError(f"{name} must be a bool, got {type(value).__name__}")
    return value


def _require_rollout_pct(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(
            f"rollout_pct must be a number in [0, 100], got {type(value).__name__}"
        )
    if not math.isfinite(value):
        raise ValueError("rollout_pct must be finite")
    if value < 0 or value > 100:
        raise ValueError("rollout_pct must be in [0, 100]")
    return float(value)


def _require_subject_id(subject_id: object) -> str:
    if not isinstance(subject_id, str):
        raise TypeError(f"subject_id must be a str, got {type(subject_id).__name__}")
    if not subject_id:
        raise ValueError("subject_id must be non-empty")
    if "\x00" in subject_id:
        raise ValueError("subject_id must not contain NUL")
    return subject_id


def _require_flag(flag: object) -> "FeatureFlag":
    if not isinstance(flag, FeatureFlag):
        raise TypeError(f"flag must be a FeatureFlag, got {type(flag).__name__}")
    return flag


@dataclass(frozen=True)
class FeatureFlag:
    """One named rollout gate (frozen record).

    ``enabled`` is the master switch: when False the flag is off for every
    subject regardless of ``rollout_pct``. ``rollout_pct`` in [0, 100] is the
    share of subjects in the cohort when enabled.
    """

    name: str
    enabled: bool
    rollout_pct: float
    description: str = ""
    schema: str = SCHEMA_PIN

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", _require_name(self.name))
        object.__setattr__(self, "enabled", _require_bool("enabled", self.enabled))
        object.__setattr__(self, "rollout_pct", _require_rollout_pct(self.rollout_pct))
        if not isinstance(self.description, str):
            raise TypeError(
                f"description must be a str, got {type(self.description).__name__}"
            )
        if self.schema != SCHEMA_PIN:
            raise ValueError(f"schema must be {SCHEMA_PIN!r}")

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "enabled": self.enabled,
            "rollout_pct": self.rollout_pct,
            "description": self.description,
            "schema": self.schema,
        }


def _bucket(flag_name: str, subject_id: str) -> int:
    """Deterministic bucket in [0, BUCKETS) for one (flag, subject) pair."""
    digest = hashlib.sha256(
        f"{_HASH_DOMAIN}\x00{flag_name}\x00{subject_id}".encode("utf-8")
    ).digest()
    return int.from_bytes(digest[:4], "big") % BUCKETS


def is_enabled(flag: FeatureFlag, subject_id: str) -> bool:
    """Pure, deterministic rollout verdict for one subject.

    Master switch off -> False for everyone. Otherwise on iff the subject's
    deterministic bucket is below ``rollout_pct * 100``. Never raises on
    policy (``TypeError``/``ValueError`` only on malformed input).
    """
    _require_flag(flag)
    _require_subject_id(subject_id)
    if not flag.enabled:
        return False
    return _bucket(flag.name, subject_id) < flag.rollout_pct * 100


class FlagManager:
    """Mutable registry owning ``FeatureFlag`` records.

    Registration order is irrelevant: every view is deterministic (name
    sorted). Flag records stay frozen; ``set_enabled`` / ``set_rollout``
    replace the record in place.
    """

    #: Change-event kinds accepted by flag_audit_event().
    EVENT_KINDS = ("registered", "enabled", "disabled", "rollout-changed", "removed")

    def __init__(self) -> None:
        self._flags: Dict[str, FeatureFlag] = {}

    def register(self, flag: FeatureFlag) -> FeatureFlag:
        """Add a flag; duplicate names are refused fail-closed."""
        _require_flag(flag)
        if flag.name in self._flags:
            raise ValueError(f"flag already registered: {flag.name!r}")
        self._flags[flag.name] = flag
        return flag

    def get(self, name: str) -> FeatureFlag:
        _require_name(name)
        try:
            return self._flags[name]
        except KeyError:
            raise KeyError(f"unknown flag: {name!r}") from None

    def set_enabled(self, name: str, enabled: bool) -> FeatureFlag:
        """Flip the master switch; returns the replacement record."""
        _require_bool("enabled", enabled)
        old = self.get(name)
        new = FeatureFlag(
            name=old.name,
            enabled=enabled,
            rollout_pct=old.rollout_pct,
            description=old.description,
        )
        self._flags[name] = new
        return new

    def set_rollout(self, name: str, rollout_pct: object) -> FeatureFlag:
        """Change the cohort share; returns the replacement record."""
        pct = _require_rollout_pct(rollout_pct)
        old = self.get(name)
        new = FeatureFlag(
            name=old.name,
            enabled=old.enabled,
            rollout_pct=pct,
            description=old.description,
        )
        self._flags[name] = new
        return new

    def remove(self, name: str) -> None:
        _require_name(name)
        try:
            del self._flags[name]
        except KeyError:
            raise KeyError(f"unknown flag: {name!r}") from None

    def flag_names(self) -> Tuple[str, ...]:
        return tuple(sorted(self._flags))

    def snapshot(self) -> Tuple[FeatureFlag, ...]:
        """All flag records in deterministic name order."""
        return tuple(self._flags[name] for name in self.flag_names())

    def is_enabled(self, name: str, subject_id: str) -> bool:
        """Convenience: evaluate one registered flag for one subject."""
        return is_enabled(self.get(name), subject_id)

    def evaluate_all(self, subject_id: str) -> Dict[str, bool]:
        """Verdict for every registered flag, in deterministic name order."""
        _require_subject_id(subject_id)
        return {name: is_enabled(self._flags[name], subject_id) for name in self.flag_names()}

    def flag_audit_event(self, kind: str, flag: FeatureFlag, seq: int) -> dict:
        """Caller-sequenced change record shaped for ``audit.ndjson/1``."""
        if kind not in self.EVENT_KINDS:
            raise ValueError(f"kind must be one of {self.EVENT_KINDS}")
        _require_flag(flag)
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise TypeError(f"seq must be an int, got {type(seq).__name__}")
        if seq < 0:
            raise ValueError("seq must be non-negative")
        return {
            "type": "feature-flag",
            "kind": kind,
            "flag": flag.as_dict(),
            "audit_seq": seq,
            "schema": SCHEMA_PIN,
        }


def main() -> None:
    mgr = FlagManager()
    mgr.register(FeatureFlag(name="dark-launch", enabled=True, rollout_pct=100))
    mgr.register(FeatureFlag(name="killed", enabled=False, rollout_pct=100))
    mgr.register(FeatureFlag(name="cohort", enabled=True, rollout_pct=50))

    assert mgr.is_enabled("dark-launch", "user-1") is True
    assert mgr.is_enabled("killed", "user-1") is False
    # Determinism: same pair, same verdict, every time.
    a = mgr.is_enabled("cohort", "user-1")
    b = mgr.is_enabled("cohort", "user-1")
    assert a == b
    # Both outcomes occur across a large subject set at 50%.
    outcomes = {mgr.is_enabled("cohort", f"user-{i}") for i in range(2000)}
    assert outcomes == {True, False}
    # Master switch overrides rollout.
    mgr.set_enabled("dark-launch", False)
    assert mgr.is_enabled("dark-launch", "user-1") is False
    mgr.set_rollout("dark-launch", 0)
    mgr.set_enabled("dark-launch", True)
    assert mgr.is_enabled("dark-launch", "user-1") is False
    print("feature-flags OK: deterministic rollout, master switch, audit")


if __name__ == "__main__":
    main()
