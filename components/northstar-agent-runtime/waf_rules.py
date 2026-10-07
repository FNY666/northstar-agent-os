"""Web-application-firewall rule bookkeeping (OWASP CRS-shaped).

An ``WAFRules`` ledger books WAF rule definitions and host-reported match
evaluations as a deterministic single-host state machine:

- ``rule(rule_id, category, severity, seq, patterns=())`` pins a rule.
  Categories follow the OWASP Core Rule Set shape (request-method,
  protocol, request-headers, request-cookies, args, body, file-upload,
  response-headers, response-body, scanner-detection); severities map to
  CRS anomaly scores (critical=5, error=4, warning=3, notice=2). Patterns
  are host-supplied regex strings: they are validated to compile at
  definition time but are never executed by this module -- matches are
  host-reported (see "Honest scope").
- ``block(rule_id, seq, reason)`` / ``unblock(rule_id, seq, reason)``
  move a rule between ``detect`` (log-only) and ``blocking`` (enforced)
  modes. Rules are pinned in ``detect`` mode at definition; ``block()``
  is the explicit escalation step, like flipping a CRS rule from
  detection-only to blocking in production.
- ``set_threshold(threshold, seq)`` pins the anomaly-score threshold
  (default 5, the CRS inbound default at paranoia level 1).
- ``evaluate(request_ref, seq, matches=())`` books an evaluation of a
  host-reported match list ``((rule_id, count), ...)`` and returns a
  frozen ``EvaluationReport``: the summed anomaly score, the threshold,
  a ``verdict`` of ``"block"``/``"pass"`` (data, never raised), and
  ``enforced`` -- whether the blocking verdict is actually enforced.
  A threshold-crossing trip with no matched rule in ``blocking`` mode
  yields ``verdict="block", enforced=False``: CRS-faithful
  detection-only behavior.

House style: frozen dataclasses, caller-supplied strictly increasing int
seqs for mutations (no wall-clock), RLock-guarded, fail-closed
taxonomy, stdlib-only plus the standard ``canonical_json`` try/except
fallback, type-tagged ``sha256:`` digest pins, ``audit.ndjson/1``
events, version pin ``waf-rules.v1``, schema pin
``northstar.waf-rules.v1``, ``main()`` self-check.

Honest scope: this module books *host-reported* rule matches and
performs anomaly-score arithmetic; it never executes patterns, never
observes the request wire, and cannot distinguish a true attack from a
benign payload that trips a heuristic. A ``"block"`` verdict means
"the anomaly budget is spent", never "the request is an attack".
Pattern execution and false-positive tuning live with the host; pair
with ``secret_scanner`` / ``sast_scanner`` / ``abuse_reporter`` for
concrete detection and response.
"""

from __future__ import annotations

import hashlib
import re
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except ImportError:  # pragma: no cover - fallback for standalone import
    import json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


#: Version pin for this module's record shape.
WAF_RULES_VERSION = "waf-rules.v1"

#: Schema pin carried by records and audit events.
WAF_RULES_SCHEMA = "northstar.waf-rules.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: CRS-shaped rule categories (digest-pinned so vocabulary drift is detectable).
CATEGORIES: Tuple[str, ...] = (
    "request-method",
    "protocol",
    "request-headers",
    "request-cookies",
    "args",
    "body",
    "file-upload",
    "response-headers",
    "response-body",
    "scanner-detection",
)

#: CRS anomaly scores per severity (digest-pinned).
SEVERITY_SCORES: Mapping[str, int] = {
    "critical": 5,
    "error": 4,
    "warning": 3,
    "notice": 2,
}

#: Rule enforcement modes.
MODES: Tuple[str, ...] = ("detect", "blocking")

#: CRS inbound anomaly-score default (paranoia level 1).
DEFAULT_THRESHOLD = 5

#: Verdicts returned as data by evaluate().
VERDICTS: Tuple[str, ...] = ("block", "pass")

KIND_RULE_DEFINED = "waf-rule.defined"
KIND_RULE_BLOCKED = "waf-rule.blocked"
KIND_RULE_UNBLOCKED = "waf-rule.unblocked"
KIND_THRESHOLD_SET = "waf-rule.threshold-set"
KIND_EVALUATED = "waf-rule.evaluated"
KIND_REJECTED = "waf-rule.rejected"

_KINDS = (
    KIND_RULE_DEFINED,
    KIND_RULE_BLOCKED,
    KIND_RULE_UNBLOCKED,
    KIND_THRESHOLD_SET,
    KIND_EVALUATED,
    KIND_REJECTED,
)


# ---------------------------------------------------------------------------
# Errors (fail-closed taxonomy)
# ---------------------------------------------------------------------------


class WAFRulesError(ValueError):
    """Base for all waf-rules structural problems and refused transitions."""


class BadRuleError(WAFRulesError):
    """Rule definition is malformed (bad id, category, severity, pattern)."""


class DuplicateRuleError(WAFRulesError):
    """A rule id is already pinned."""


class UnknownRuleError(WAFRulesError):
    """No rule is pinned for the requested rule id."""


class AlreadyBlockingError(WAFRulesError):
    """The rule is already in blocking mode."""


class NotBlockingError(WAFRulesError):
    """The rule is not in blocking mode."""


class BadThresholdError(WAFRulesError):
    """The threshold is malformed (not a positive int)."""


class BadMatchError(WAFRulesError):
    """A match entry is malformed (unknown rule, bad count)."""


class SeqOrderError(WAFRulesError):
    """A caller seq did not strictly increase (or was not a plain int)."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _check_seq(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise SeqOrderError(f"{name} must be a non-negative int")
    return value


def _check_nonempty_str(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise BadRuleError(f"{name} must be a non-empty str")
    return value.strip()


def _tag(value: Any) -> Any:
    # Type-tagged so bool != int and None != 0 in pins.
    if isinstance(value, bool):
        return ["bool", value]
    if value is None:
        return ["none", 0]
    if isinstance(value, int):
        return ["int", value]
    if isinstance(value, str):
        return ["str", value]
    if isinstance(value, dict):
        return ["dict", [[k, _tag(v)] for k, v in
                         sorted(value.items(), key=lambda kv: kv[0])]]
    if isinstance(value, (list, tuple)):
        return ["list", [_tag(v) for v in value]]
    raise WAFRulesError(f"cannot encode {type(value).__name__}")


def _pin(*parts: Any) -> str:
    digest = hashlib.sha256(
        jcs_canonical_json([WAF_RULES_VERSION, *[_tag(p) for p in parts]])
    ).hexdigest()
    return "sha256:" + digest


def _check_patterns(patterns: Sequence[Any]) -> Tuple[str, ...]:
    if isinstance(patterns, (str, bytes)):
        raise BadRuleError("patterns must be a sequence of str, not a str")
    pinned: List[str] = []
    for pat in patterns:
        if not isinstance(pat, str) or not pat:
            raise BadRuleError("each pattern must be a non-empty str")
        try:
            re.compile(pat)
        except re.error as exc:
            raise BadRuleError(f"pattern does not compile: {exc}") from exc
        pinned.append(pat)
    return tuple(pinned)


# ---------------------------------------------------------------------------
# Records (frozen, digest-pinned, self-verifying)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RuleRecord:
    """A pinned WAF rule. Mode starts at "detect"."""

    rule_id: str
    category: str
    severity: str
    patterns: Tuple[str, ...]
    mode: str
    seq: int
    digest: str

    def verify(self) -> bool:
        """Re-derive the digest pin; False means tampered."""
        return self.digest == _pin(
            "rule", self.rule_id, self.category, self.severity,
            list(self.patterns), self.mode, self.seq,
        )


@dataclass(frozen=True)
class ThresholdRecord:
    """A pinned anomaly-score threshold."""

    threshold: int
    seq: int
    digest: str

    def verify(self) -> bool:
        return self.digest == _pin("threshold", self.threshold, self.seq)


@dataclass(frozen=True)
class ModeChangeRecord:
    """A terminal-friendly log of a detect <-> blocking transition."""

    rule_id: str
    from_mode: str
    to_mode: str
    reason: str
    seq: int
    digest: str

    def verify(self) -> bool:
        return self.digest == _pin(
            "mode-change", self.rule_id, self.from_mode, self.to_mode,
            self.reason, self.seq,
        )


@dataclass(frozen=True)
class MatchBooked:
    """One host-reported (rule_id, count) match, score-pinned."""

    rule_id: str
    count: int
    score: int


@dataclass(frozen=True)
class EvaluationReport:
    """A booked evaluation: score, verdict as data, enforcement flag."""

    eval_id: str
    request_ref: str
    seq: int
    matches: Tuple[MatchBooked, ...]
    score: int
    threshold: int
    verdict: str
    enforced: bool
    digest: str

    def verify(self) -> bool:
        return self.digest == _pin(
            "evaluate", self.eval_id, self.request_ref, self.seq,
            [(m.rule_id, m.count, m.score) for m in self.matches],
            self.score, self.threshold, self.verdict, self.enforced,
        )


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def waf_rules_audit_event(
    kind: str, detail: Mapping[str, Any], seq: int
) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for the waf-rules module."""
    if kind not in _KINDS:
        raise WAFRulesError(f"unknown audit kind: {kind!r}")
    _check_seq(seq, "seq")
    if not isinstance(detail, Mapping):
        raise WAFRulesError("detail must be a mapping")
    # Raw patterns never cross the audit boundary; ids + pins only.
    banned = {"patterns", "payload", "request_body", "grounds"}
    if any(k in detail for k in banned):
        raise WAFRulesError("detail carries banned keys")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": WAF_RULES_VERSION,
        "detail": dict(detail),
        "seq": seq,
    }


# ---------------------------------------------------------------------------
# The ledger
# ---------------------------------------------------------------------------


class WAFRules:
    """Deterministic WAF rule / anomaly-score ledger.

    Mutations take a caller-supplied strictly increasing ``seq``
    (logical time); no wall-clock is read anywhere. Failed mutations
    consume their seq (fail-closed ledger position). ``evaluate()`` is a
    read view: it validates the seq shape but does not consume it.
    """

    def __init__(self, seed: str = "waf-rules") -> None:
        self._lock = threading.RLock()
        self._seed = seed
        self._last_seq = -1
        self._rules: Dict[str, RuleRecord] = {}
        self._threshold = ThresholdRecord(
            threshold=DEFAULT_THRESHOLD, seq=0,
            digest=_pin("threshold", DEFAULT_THRESHOLD, 0),
        )
        self._eval_seq = 0
        self._audit: List[Dict[str, Any]] = []

    # -- internals ------------------------------------------------------

    def _claim_seq(self, seq: int) -> int:
        _check_seq(seq, "seq")
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq {seq} did not strictly increase (last={self._last_seq})"
            )
        self._last_seq = seq
        return seq

    def _audit_locked(self, kind: str, detail: Mapping[str, Any]) -> None:
        self._audit.append(waf_rules_audit_event(kind, detail, self._last_seq))

    def _reject_locked(self, reason: str) -> None:
        self._audit_locked(KIND_REJECTED, {"reason": reason})

    # -- rules ----------------------------------------------------------

    def rule(
        self,
        rule_id: str,
        category: str,
        severity: str,
        seq: int,
        patterns: Sequence[str] = (),
    ) -> RuleRecord:
        """Pin a WAF rule in ``detect`` (log-only) mode."""
        with self._lock:
            rule_id = _check_nonempty_str(rule_id, "rule_id")
            if not isinstance(category, str) or category not in CATEGORIES:
                raise BadRuleError(
                    f"category must be one of {sorted(CATEGORIES)}"
                )
            if not isinstance(severity, str) or severity not in SEVERITY_SCORES:
                raise BadRuleError(
                    f"severity must be one of {sorted(SEVERITY_SCORES)}"
                )
            pinned = _check_patterns(patterns)
            self._claim_seq(seq)
            if rule_id in self._rules:
                self._reject_locked("duplicate-rule")
                raise DuplicateRuleError(f"rule {rule_id!r} already pinned")
            record = RuleRecord(
                rule_id=rule_id, category=category, severity=severity,
                patterns=pinned, mode="detect", seq=seq,
                digest=_pin(
                    "rule", rule_id, category, severity,
                    list(pinned), "detect", seq,
                ),
            )
            self._rules[rule_id] = record
            self._audit_locked(
                KIND_RULE_DEFINED,
                {"rule_id": rule_id, "category": category,
                 "severity": severity, "digest": record.digest},
            )
            return record

    def block(self, rule_id: str, seq: int, reason: str) -> ModeChangeRecord:
        """Escalate a rule from ``detect`` to ``blocking`` mode."""
        with self._lock:
            if not isinstance(reason, str) or not reason.strip():
                raise BadRuleError("reason must be a non-empty str")
            self._claim_seq(seq)
            current = self._rules.get(rule_id)
            if current is None:
                self._reject_locked("unknown-rule")
                raise UnknownRuleError(f"no rule pinned for {rule_id!r}")
            if current.mode == "blocking":
                self._reject_locked("already-blocking")
                raise AlreadyBlockingError(f"rule {rule_id!r} already blocking")
            self._rules[rule_id] = RuleRecord(
                rule_id=current.rule_id, category=current.category,
                severity=current.severity, patterns=current.patterns,
                mode="blocking", seq=seq,
                digest=_pin(
                    "rule", current.rule_id, current.category,
                    current.severity, list(current.patterns),
                    "blocking", seq,
                ),
            )
            change = ModeChangeRecord(
                rule_id=rule_id, from_mode="detect", to_mode="blocking",
                reason=reason.strip(), seq=seq,
                digest=_pin(
                    "mode-change", rule_id, "detect", "blocking",
                    reason.strip(), seq,
                ),
            )
            self._audit_locked(
                KIND_RULE_BLOCKED,
                {"rule_id": rule_id, "digest": change.digest},
            )
            return change

    def unblock(self, rule_id: str, seq: int, reason: str) -> ModeChangeRecord:
        """Return a rule from ``blocking`` to ``detect`` mode."""
        with self._lock:
            if not isinstance(reason, str) or not reason.strip():
                raise BadRuleError("reason must be a non-empty str")
            self._claim_seq(seq)
            current = self._rules.get(rule_id)
            if current is None:
                self._reject_locked("unknown-rule")
                raise UnknownRuleError(f"no rule pinned for {rule_id!r}")
            if current.mode != "blocking":
                self._reject_locked("not-blocking")
                raise NotBlockingError(f"rule {rule_id!r} is not blocking")
            self._rules[rule_id] = RuleRecord(
                rule_id=current.rule_id, category=current.category,
                severity=current.severity, patterns=current.patterns,
                mode="detect", seq=seq,
                digest=_pin(
                    "rule", current.rule_id, current.category,
                    current.severity, list(current.patterns),
                    "detect", seq,
                ),
            )
            change = ModeChangeRecord(
                rule_id=rule_id, from_mode="blocking", to_mode="detect",
                reason=reason.strip(), seq=seq,
                digest=_pin(
                    "mode-change", rule_id, "blocking", "detect",
                    reason.strip(), seq,
                ),
            )
            self._audit_locked(
                KIND_RULE_UNBLOCKED,
                {"rule_id": rule_id, "digest": change.digest},
            )
            return change

    def set_threshold(self, threshold: int, seq: int) -> ThresholdRecord:
        """Pin the anomaly-score threshold (positive int)."""
        with self._lock:
            if (isinstance(threshold, bool) or not isinstance(threshold, int)
                    or threshold <= 0):
                raise BadThresholdError("threshold must be a positive int")
            self._claim_seq(seq)
            record = ThresholdRecord(
                threshold=threshold, seq=seq,
                digest=_pin("threshold", threshold, seq),
            )
            self._threshold = record
            self._audit_locked(
                KIND_THRESHOLD_SET,
                {"threshold": threshold, "digest": record.digest},
            )
            return record

    # -- evaluation (read view) ------------------------------------------

    def evaluate(
        self,
        request_ref: str,
        seq: int,
        matches: Sequence[Tuple[str, Any]] = (),
    ) -> EvaluationReport:
        """Book a host-reported match list and compute the anomaly verdict.

        ``matches`` is ``((rule_id, count), ...)`` as reported by the
        host's pattern engine. The verdict is *data* (``"block"`` /
        ``"pass"``); ``enforced`` is True only when the verdict is
        ``"block"`` and at least one matched rule is in ``blocking``
        mode. This is a read view: ``seq`` is validated but not consumed,
        and no audit row is appended.
        """
        with self._lock:
            if not isinstance(request_ref, str) or not request_ref.strip():
                raise BadMatchError("request_ref must be a non-empty str")
            _check_seq(seq, "seq")
            booked: List[MatchBooked] = []
            for entry in matches:
                if (not isinstance(entry, (list, tuple)) or len(entry) != 2):
                    raise BadMatchError(
                        "matches must be (rule_id, count) pairs"
                    )
                rid, count = entry
                if not isinstance(rid, str) or rid not in self._rules:
                    raise UnknownRuleError(
                        f"no rule pinned for {rid!r}"
                    )
                if (isinstance(count, bool) or not isinstance(count, int)
                        or count <= 0):
                    raise BadMatchError(
                        "match count must be a positive int"
                    )
                rule = self._rules[rid]
                booked.append(MatchBooked(
                    rule_id=rid, count=count,
                    score=SEVERITY_SCORES[rule.severity] * count,
                ))
            booked.sort(key=lambda m: (m.rule_id, m.count))
            score = sum(m.score for m in booked)
            threshold = self._threshold.threshold
            verdict = "block" if score >= threshold else "pass"
            enforced = verdict == "block" and any(
                self._rules[m.rule_id].mode == "blocking" for m in booked
            )
            self._eval_seq += 1
            report = EvaluationReport(
                eval_id=f"ev-{self._eval_seq}",
                request_ref=request_ref.strip(), seq=seq,
                matches=tuple(booked), score=score, threshold=threshold,
                verdict=verdict, enforced=enforced,
                digest=_pin(
                    "evaluate", f"ev-{self._eval_seq}",
                    request_ref.strip(), seq,
                    [(m.rule_id, m.count, m.score) for m in booked],
                    score, threshold, verdict, enforced,
                ),
            )
            return report

    # -- views ------------------------------------------------------------

    def rule_record(self, rule_id: str) -> RuleRecord:
        with self._lock:
            record = self._rules.get(rule_id)
            if record is None:
                raise UnknownRuleError(f"no rule pinned for {rule_id!r}")
            return record

    def rule_ids(self) -> List[str]:
        with self._lock:
            return sorted(self._rules)

    def threshold(self) -> ThresholdRecord:
        with self._lock:
            return self._threshold

    def audit_log(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [dict(e) for e in self._audit]

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            modes: Dict[str, int] = {"detect": 0, "blocking": 0}
            for record in self._rules.values():
                modes[record.mode] += 1
            return {
                "rules": len(self._rules),
                "modes": modes,
                "threshold": self._threshold.threshold,
                "audit_events": len(self._audit),
            }

    def as_dict(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "version": WAF_RULES_VERSION,
                "schema": WAF_RULES_SCHEMA,
                "rules": {rid: r.digest for rid, r in self._rules.items()},
                "threshold": self._threshold.threshold,
                "stats": self.stats(),
            }


# ---------------------------------------------------------------------------
# Self-check
# ---------------------------------------------------------------------------


def main() -> None:
    waf = WAFRules()
    waf.rule("R-930100", "body", "critical", 1, patterns=(r"(?i)union\s+select",))
    waf.rule("R-941100", "args", "error", 2, patterns=(r"(?i)<script",))
    waf.set_threshold(5, 3)
    waf.block("R-930100", 4, "confirmed true positive")
    report = waf.evaluate("req-1", 0, [("R-930100", 1)])
    assert report.verdict == "block" and report.enforced, report
    report2 = waf.evaluate("req-2", 0, [("R-941100", 1)])
    assert report2.verdict == "pass", report2
    print("waf-rules OK: rule, block, threshold, evaluate, pins")


if __name__ == "__main__":
    main()
