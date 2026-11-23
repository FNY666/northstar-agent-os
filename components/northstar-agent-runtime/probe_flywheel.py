"""Probe flywheel from production failures.

P0 production wiring: production failure -> failure bundle -> incident
state -> recovery -> probe flywheel. The flywheel closes the loop: when
a production failure repeats, the repeated pattern is turned into a
probe so the gate can refuse the same shape before it fails again. A
failure that happens once is an incident; a failure that happens three
times is a missing gate.

How it works::

    flywheel = Flywheel()
    flywheel.record_failure(bundle)      # for each FailureBundle
    probes = flywheel.get_probes()        # patterns with count >= 3
    # each probe is a dict with name/description/expected/gate_interaction

Rules:

* Patterns are keyed by (``failed_action``, ``error``) exactly as the
  ``failure_bundle.FailureBundle`` records them — the flywheel counts
  occurrences, it does not diagnose. Two failures with the same action
  but different errors are two patterns.
* A pattern becomes a probe at **three** occurrences
  (``PROBE_THRESHOLD = 3``). Below the threshold the pattern is only
  tracked, never emitted — one incident is not a trend.
* Probes are ``expected: "deny"``: the gate refuses actions matching
  the pattern until the underlying cause is remediated. Remediation is
  the host's job; the flywheel only records the refusal shape.
* Deterministic: no wall-clock, callers supply sequence numbers. Probe
  names are derived from the pattern with a fixed sanitizer, so the
  same pattern always yields the same probe name.

Honest scope:

* The flywheel is a *counter*, not a diagnosis engine. It notices that
  "db.delete keeps failing with permission-denied" happened three
  times; it does not know *why* and does not fix it.
* A generated probe is a record of a repeated failure, not proof the
  failure will repeat — the gate still adjudicates each action on its
  own facts.
* In-memory only: patterns survive only as long as the ``Flywheel``
  object. Persisting the pattern counts across restarts (for example
  through ``audit_chain.DurableAuditWriter``) is the caller's job.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

try:  # sibling import when the package is installed
    from failure_bundle import FailureBundle
except Exception:  # pragma: no cover - standalone import must keep working
    FailureBundle = None  # type: ignore[assignment]

#: Version of the flywheel construction described here.
PROBE_FLYWHEEL_VERSION = "northstar.probe-flywheel.v1"

#: Schema pin stamped on generated probes.
SCHEMA_PIN = "northstar.probe-flywheel.v1"

#: Occurrences needed before a pattern becomes a probe.
PROBE_THRESHOLD = 3

_NAME_TOKEN_RE = re.compile(r"[^a-z0-9]+")


def _sanitize_token(value: str) -> str:
    """Lowercase ``value`` and replace non-alphanumeric runs with ``-``."""
    token = _NAME_TOKEN_RE.sub("-", value.lower()).strip("-")
    return token or "unknown"


def _check_nonempty_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field_name} must be a non-empty str")
    return value


def _check_seq(value: Any, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{field_name} must be a non-negative int")
    return value


def _check_count(value: Any, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{field_name} must be a positive int")
    return value


@dataclass(frozen=True)
class FailurePattern:
    """One repeated failure shape: (action type, error type) with a count.

    ``first_seen_seq`` / ``last_seen_seq`` are caller-supplied integer
    sequence numbers bounding when the pattern was observed. ``count``
    is the number of recorded occurrences.
    """

    action_type: str
    error_type: str
    count: int
    first_seen_seq: int
    last_seen_seq: int

    def __post_init__(self) -> None:
        _check_nonempty_str(self.action_type, "action_type")
        _check_nonempty_str(self.error_type, "error_type")
        _check_count(self.count, "count")
        _check_seq(self.first_seen_seq, "first_seen_seq")
        _check_seq(self.last_seen_seq, "last_seen_seq")
        if self.last_seen_seq < self.first_seen_seq:
            raise ValueError(
                "last_seen_seq must be >= first_seen_seq"
            )

    def probe_ready(self) -> bool:
        """True when the pattern has crossed the probe threshold."""
        return self.count >= PROBE_THRESHOLD

    def probe_name(self) -> str:
        """Deterministic probe name derived from the pattern."""
        return (
            "failure-flywheel-"
            f"{_sanitize_token(self.action_type)}-"
            f"{_sanitize_token(self.error_type)}"
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "action_type": self.action_type,
            "error_type": self.error_type,
            "count": self.count,
            "first_seen_seq": self.first_seen_seq,
            "last_seen_seq": self.last_seen_seq,
            "probe_ready": self.probe_ready(),
            "probe_name": self.probe_name(),
        }


@dataclass(frozen=True)
class _PatternState:
    """Mutable bookkeeping is held in the Flywheel dict, not here."""

    action_type: str
    error_type: str
    count: int
    first_seen_seq: int
    last_seen_seq: int


class Flywheel:
    """Counts failure patterns and emits probes for repeated ones.

    ``record_failure`` accepts a ``failure_bundle.FailureBundle`` (or any
    mapping with ``failed_action`` / ``error`` / ``created_seq``) and
    folds it into the pattern keyed by ``(failed_action, error)``.
    ``get_probes`` returns one probe dict per pattern whose count has
    reached ``PROBE_THRESHOLD``.
    """

    def __init__(self) -> None:
        # key: (action_type, error_type) -> _PatternState
        self._patterns: dict[tuple[str, str], _PatternState] = {}
        # probe names already emitted; get_probes stays idempotent
        self._emitted: set[str] = set()

    @staticmethod
    def _coerce_bundle(bundle: Any) -> tuple[str, str, int]:
        """Extract (action_type, error_type, seq) from a bundle or mapping."""
        if bundle is None or isinstance(bundle, bool):
            raise ValueError("bundle must be a FailureBundle or a mapping")
        if FailureBundle is not None and isinstance(bundle, FailureBundle):
            return (bundle.failed_action, bundle.error, bundle.created_seq)
        if isinstance(bundle, Mapping):
            try:
                action = bundle["failed_action"]
                error = bundle["error"]
                seq = bundle["created_seq"]
            except KeyError as exc:
                raise ValueError(
                    f"bundle mapping is missing key: {exc.args[0]}"
                ) from exc
            return (
                _check_nonempty_str(action, "failed_action"),
                _check_nonempty_str(error, "error"),
                _check_seq(seq, "created_seq"),
            )
        raise ValueError(
            "bundle must be a FailureBundle or a mapping with "
            "failed_action/error/created_seq"
        )

    def record_failure(self, bundle: Any) -> FailurePattern:
        """Fold one failure into its pattern; return the updated pattern."""
        action_type, error_type, seq = self._coerce_bundle(bundle)
        key = (action_type, error_type)
        prior = self._patterns.get(key)
        if prior is None:
            state = _PatternState(
                action_type=action_type,
                error_type=error_type,
                count=1,
                first_seen_seq=seq,
                last_seen_seq=seq,
            )
        else:
            state = _PatternState(
                action_type=action_type,
                error_type=error_type,
                count=prior.count + 1,
                first_seen_seq=min(prior.first_seen_seq, seq),
                last_seen_seq=max(prior.last_seen_seq, seq),
            )
        self._patterns[key] = state
        return self.pattern_for(action_type, error_type)

    def record_failures(self, bundles: Iterable[Any]) -> None:
        """Fold many failures; fail-closed on the first malformed bundle."""
        for bundle in bundles:
            self.record_failure(bundle)

    def pattern_for(self, action_type: str, error_type: str) -> FailurePattern | None:
        """Return the pattern for (action_type, error_type), or None."""
        _check_nonempty_str(action_type, "action_type")
        _check_nonempty_str(error_type, "error_type")
        state = self._patterns.get((action_type, error_type))
        if state is None:
            return None
        return FailurePattern(
            action_type=state.action_type,
            error_type=state.error_type,
            count=state.count,
            first_seen_seq=state.first_seen_seq,
            last_seen_seq=state.last_seen_seq,
        )

    def patterns(self) -> tuple[FailurePattern, ...]:
        """All tracked patterns, in deterministic (action, error) order."""
        return tuple(
            FailurePattern(
                action_type=state.action_type,
                error_type=state.error_type,
                count=state.count,
                first_seen_seq=state.first_seen_seq,
                last_seen_seq=state.last_seen_seq,
            )
            for key in sorted(self._patterns)
            for state in (self._patterns[key],)
        )

    def __len__(self) -> int:
        return len(self._patterns)

    def __contains__(self, key: object) -> bool:
        return isinstance(key, tuple) and key in self._patterns

    @staticmethod
    def generate_probe(pattern: FailurePattern) -> dict[str, Any]:
        """Build the probe dict for one repeated failure pattern.

        Raises ``ValueError`` when the pattern is below
        ``PROBE_THRESHOLD`` — sub-threshold patterns are tracked, not
        emitted.
        """
        if not isinstance(pattern, FailurePattern):
            raise ValueError("pattern must be a FailurePattern")
        if not pattern.probe_ready():
            raise ValueError(
                f"pattern has count {pattern.count}, below threshold "
                f"{PROBE_THRESHOLD}: tracked, not emitted"
            )
        name = pattern.probe_name()
        description = (
            f"The action '{pattern.action_type}' failed with error "
            f"'{pattern.error_type}' {pattern.count} times "
            f"(seq {pattern.first_seen_seq}..{pattern.last_seen_seq}). "
            "A production failure that repeats is a missing gate: refuse "
            "actions of this shape until the underlying cause is "
            "remediated."
        )
        gate_interaction = (
            f"the flywheel observed {pattern.count} occurrences of "
            f"'{pattern.action_type}' failing with '{pattern.error_type}'; "
            "the gate refuses further actions of this shape and routes "
            "them to incident review instead of executing"
        )
        return {
            "schema": SCHEMA_PIN,
            "name": name,
            "family": "failure-flywheel",
            "description": description,
            "expected": "deny",
            "gate_interaction": gate_interaction,
            "pattern": pattern.as_dict(),
        }

    def get_probes(self) -> tuple[dict[str, Any], ...]:
        """All probes for patterns at or above the threshold.

        Idempotent: repeated calls return the same probes in the same
        order; each pattern emits exactly one probe.
        """
        probes: list[dict[str, Any]] = []
        for pattern in self.patterns():
            if pattern.probe_ready():
                name = pattern.probe_name()
                if name not in self._emitted:
                    self._emitted.add(name)
                probes.append(self.generate_probe(pattern))
        return tuple(probes)

    def probe_names(self) -> tuple[str, ...]:
        """Names of the currently emitted probes, in order."""
        return tuple(p["name"] for p in self.get_probes())


def main() -> None:
    flywheel = Flywheel()
    seq = 0
    for _ in range(PROBE_THRESHOLD):
        seq += 1
        flywheel.record_failure(
            {
                "failed_action": "db.delete",
                "error": "permission-denied",
                "created_seq": seq,
            }
        )
    probes = flywheel.get_probes()
    assert len(probes) == 1, f"expected 1 probe, got {len(probes)}"
    assert probes[0]["expected"] == "deny"
    print(
        f"probe-flywheel OK: {len(flywheel.patterns())} pattern(s), "
        f"{len(probes)} probe(s), threshold={PROBE_THRESHOLD}"
    )


if __name__ == "__main__":
    main()
