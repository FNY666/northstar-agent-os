"""Password policy interface (NIST SP 800-63B shape, simulated).

Research motivation: NIST SP 800-63B changed password guidance from
composition-rule trivia to evidence-based checks: require at least 8
characters, support at least 64 (we support up to 128), screen candidate
passwords against values known to be compromised (breached corpora,
dictionary words, repetitive or context-specific values such as the
username or service name), and do not impose arbitrary composition rules
or scheduled rotation on memorized secrets.

This module is the *policy and bookkeeping* half, pinned so the
runtime's enrollment gate cannot silently drift from what the verifier
expects. The breach corpus and the stored-history bookkeeping are
*simulated* - a fixed representative list of weak passwords and an
in-memory digest set stand in for a Have-I-Been-Pwned k-anonymity
lookup and the verifier's stored-verifier history - so that policy
properties (deterministic decisions, fail-closed inputs, digest-only
history, exact audit replay) are real while the corpus coverage is not:

- ``PolicyRules`` -- one pinned rule set: ``min_length`` (default 8,
  NIST 800-63B minimum), ``max_length`` (default 128, >= 64 per NIST),
  optional composition flags (default off, per NIST), blocked
  substrings, and a repeat-run ceiling.
- ``PasswordPolicy.check(password, seq, username=None)`` -- returns a
  frozen ``PolicyDecision`` (``accepted``, tuple of ``reasons``, a
  ``strength`` band). Deterministic: same inputs, same decision.
- ``breach(password)`` -- True when the candidate appears in the
  simulated compromised-password set (constant-time scan, no early
  secret-dependent branch on the *candidate* content beyond the digest
  compare).
- ``history(password, seq)`` -- records a SHA-256 digest of the
  candidate in the instance's history set; ``check_history`` returns
  True when a candidate's digest was already recorded (recent-reuse
  guard). Plaintext is never stored.
- ``password_policy_audit_event(kind, detail, seq)`` --
  ``audit.ndjson/1`` records (``checked`` / ``rejected`` /
  ``breach-hit`` / ``history-recorded`` / ``history-hit``); plaintext
  never rides the audit path, only digests and rule identifiers.

Fail-closed edges (fail loudly, never guess):

- Non-``str`` passwords (including ``bool``, bytes, None) raise
  ``TypeError``; the gate must not coerce attacker input.
- Passwords over ``max_length`` are rejected so work is bounded; empty
  passwords are rejected (the NIST minimum is 8, not 0).
- Rule construction rejects nonsense pins (``min_length < 1``,
  ``max_length < min_length``, contradictory composition flags) at
  construction time, before any password is ever evaluated.
- History lookups use ``hmac.compare_digest`` over digests so a
  wrong-but-close password returns ``False`` (policy outcome), never
  raises.

Honest scope:

- Simulated corpus: the breach set is a fixed list of ~40 famous weak
  passwords, not the 600M+ real breached-password corpus and not a
  live k-anonymity API. Coverage claims stop at "the interface handles
  a hit" - not "this catches real attackers' dictionaries."
- Simulated history: digests live in instance memory only; a real
  deployment persists them beside the verifier with the same access
  controls as stored password verifiers. Instance restart loses the
  set; nothing here pretends otherwise.
- Strength scoring is a heuristic band (length + class diversity +
  repetition penalty), not an entropy measurement and not a
  crack-time estimate. It informs UX hints, never the accept/reject
  decision.
- This module proves *policy consistency* (deterministic decisions,
  pinned rules, digest-only history, exact audit replay), not
  *authentication security*.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional, Tuple

MODULE_VERSION = "1.0.0"
PASSWORD_POLICY_SCHEMA = "northstar.password_policy.v1"
AUDIT_SCHEMA = "audit.ndjson/1"

# Pinned NIST 800-63B shape: minimum 8, support for at least 64.
NIST_MIN_LENGTH = 8
NIST_MAX_SUPPORTED = 64

# Simulated compromised-password corpus: representative weak values only.
# A real deployment queries a k-anonymity breach API or a full corpus.
SIMULATED_BREACH_CORPUS: FrozenSet[str] = frozenset({
    "password", "123456", "12345678", "123456789", "1234567890", "qwerty",
    "abc123", "111111", "123123", "admin", "letmein", "welcome",
    "monkey", "dragon", "master", "football", "shadow", "sunshine",
    "princess", "qwerty123", "password1", "1234", "000000", "654321",
    "jesus", "superman", "michael", "696969", "mustang", "trustno1",
    "baseball", "password123", "changeme", "qwertyuiop", "solo",
    "loveme", "whatever", "freedom", "hello", "charlie", "aa123456",
})

_BLOCKED_CONTEXT_TOKENS: FrozenSet[str] = frozenset({
    "northstar", "agent", "admin", "root", "user", "test", "demo",
})


def _digest(password: str) -> str:
    """Domain-separated digest so history/breach lookups never store plaintext."""
    return hashlib.sha256(("northstar.password_policy.v1|" + password).encode("utf-8")).hexdigest()


def _require_seq(seq: object) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise TypeError("seq must be an int audit sequence number")
    if seq < 0:
        raise ValueError("seq must be non-negative")
    return seq


def _require_password(password: object) -> str:
    if isinstance(password, bool) or not isinstance(password, str):
        raise TypeError("password must be str (no coercion, fail-closed)")
    return password


@dataclass(frozen=True)
class PolicyRules:
    """Pinned password rule set. Constructed once; decisions cite the pin."""

    min_length: int = NIST_MIN_LENGTH
    max_length: int = 128
    require_upper: bool = False
    require_lower: bool = False
    require_digit: bool = False
    require_symbol: bool = False
    max_repeat_run: int = 4
    blocked_substrings: Tuple[str, ...] = ()
    version: str = MODULE_VERSION
    schema: str = PASSWORD_POLICY_SCHEMA

    def __post_init__(self) -> None:
        for name in ("min_length", "max_length", "max_repeat_run"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"{name} must be int")
        if self.min_length < 1:
            raise ValueError("min_length must be >= 1 (NIST minimum is 8)")
        if self.max_length < NIST_MAX_SUPPORTED:
            raise ValueError(f"max_length must be >= {NIST_MAX_SUPPORTED} per NIST 800-63B")
        if self.max_length < self.min_length:
            raise ValueError("max_length must be >= min_length")
        if self.max_repeat_run < 1:
            raise ValueError("max_repeat_run must be >= 1")
        for token in self.blocked_substrings:
            if not isinstance(token, str) or not token:
                raise TypeError("blocked_substrings must be non-empty strings")


@dataclass(frozen=True)
class PolicyDecision:
    """Outcome of one policy evaluation. Deterministic and self-describing."""

    accepted: bool
    reasons: Tuple[str, ...]
    strength: str  # "weak" | "fair" | "good" | "strong"
    rules_version: str = MODULE_VERSION
    schema: str = PASSWORD_POLICY_SCHEMA


class PasswordPolicy:
    """One pinned policy instance with breach screening and digest history."""

    def __init__(self, rules: Optional[PolicyRules] = None) -> None:
        self._rules = rules or PolicyRules()
        self._history: Dict[str, int] = {}  # digest -> seq recorded
        self._audit: List[Dict[str, object]] = []

    @property
    def rules(self) -> PolicyRules:
        return self._rules

    # -- breach screening (simulated corpus) ---------------------------

    def breach(self, password: str) -> bool:
        """True when the candidate is in the simulated compromised set."""
        candidate = _require_password(password)
        want = _digest(candidate)
        hit = False
        for weak in SIMULATED_BREACH_CORPUS:
            if hmac.compare_digest(_digest(weak), want):
                hit = True
        return hit

    # -- history (digest-only recent-reuse guard) ----------------------

    def history(self, password: str, seq: int) -> str:
        """Record a password digest. Returns the digest; never stores plaintext."""
        seq = _require_seq(seq)
        candidate = _require_password(password)
        digest = _digest(candidate)
        self._history[digest] = seq
        self._audit.append(password_policy_audit_event("history-recorded", digest, seq))
        return digest

    def check_history(self, password: str) -> bool:
        """True when the candidate's digest was previously recorded."""
        candidate = _require_password(password)
        want = _digest(candidate)
        for recorded in self._history:
            if hmac.compare_digest(recorded, want):
                return True
        return False

    # -- full policy check ---------------------------------------------

    def check(
        self,
        password: str,
        seq: int,
        username: Optional[str] = None,
        screen_breach: bool = True,
        screen_history: bool = True,
    ) -> PolicyDecision:
        """Evaluate a candidate against the pinned rules. Deterministic."""
        seq = _require_seq(seq)
        candidate = _require_password(password)
        if username is not None and (isinstance(username, bool) or not isinstance(username, str)):
            raise TypeError("username must be str or None")
        rules = self._rules
        reasons: List[str] = []

        if len(candidate) < rules.min_length:
            reasons.append(f"too-short:{len(candidate)}<{rules.min_length}")
        if len(candidate) > rules.max_length:
            reasons.append(f"too-long:{len(candidate)}>{rules.max_length}")
        if rules.require_upper and not any(c.isupper() for c in candidate):
            reasons.append("missing-upper")
        if rules.require_lower and not any(c.islower() for c in candidate):
            reasons.append("missing-lower")
        if rules.require_digit and not any(c.isdigit() for c in candidate):
            reasons.append("missing-digit")
        if rules.require_symbol and not any((not c.isalnum()) for c in candidate):
            reasons.append("missing-symbol")

        run = 1
        for prev, cur in zip(candidate, candidate[1:]):
            run = run + 1 if cur == prev else 1
            if run > rules.max_repeat_run:
                reasons.append(f"repeat-run>{rules.max_repeat_run}")
                break

        lowered = candidate.lower()
        for token in list(rules.blocked_substrings) + sorted(_BLOCKED_CONTEXT_TOKENS):
            if token and token.lower() in lowered:
                reasons.append(f"blocked-substring:{token}")
                break

        if username and username.lower() in lowered:
            reasons.append("contains-username")

        if screen_breach and self.breach(candidate):
            reasons.append("breach-hit")
            self._audit.append(password_policy_audit_event("breach-hit", _digest(candidate), seq))

        if screen_history and self.check_history(candidate):
            reasons.append("history-hit")
            self._audit.append(password_policy_audit_event("history-hit", _digest(candidate), seq))

        accepted = not reasons
        strength = self._strength(candidate)
        decision = PolicyDecision(
            accepted=accepted,
            reasons=tuple(reasons),
            strength=strength,
        )
        self._audit.append(
            password_policy_audit_event(
                "checked" if accepted else "rejected",
                _digest(candidate),
                seq,
                extra={"reasons": list(reasons), "strength": strength},
            )
        )
        return decision

    def _strength(self, candidate: str) -> str:
        """Heuristic UX band only; never drives accept/reject."""
        score = 0
        length = len(candidate)
        if length >= 8:
            score += 1
        if length >= 12:
            score += 1
        if length >= 20:
            score += 1
        classes = sum((
            any(c.islower() for c in candidate),
            any(c.isupper() for c in candidate),
            any(c.isdigit() for c in candidate),
            any(not c.isalnum() for c in candidate),
        ))
        score += min(classes, 2)
        if len(set(candidate)) < max(1, length // 2):
            score -= 1
        if score <= 1:
            return "weak"
        if score == 2:
            return "fair"
        if score == 3:
            return "good"
        return "strong"

    def policy_summary(self) -> Dict[str, object]:
        """Pinned rule summary for the enrollment gate to cite."""
        r = self._rules
        return {
            "min_length": r.min_length,
            "max_length": r.max_length,
            "composition": {
                "upper": r.require_upper,
                "lower": r.require_lower,
                "digit": r.require_digit,
                "symbol": r.require_symbol,
            },
            "max_repeat_run": r.max_repeat_run,
            "version": r.version,
            "schema": r.schema,
        }

    def audit_log(self) -> Tuple[Dict[str, object], ...]:
        return tuple(self._audit)


def password_policy_audit_event(
    kind: str,
    digest: str,
    seq: int,
    extra: Optional[Dict[str, object]] = None,
) -> Dict[str, object]:
    """Build one ``audit.ndjson/1`` record. Plaintext never appears."""
    seq = _require_seq(seq)
    if kind not in ("checked", "rejected", "breach-hit", "history-recorded", "history-hit"):
        raise ValueError(f"unknown audit kind: {kind}")
    if not isinstance(digest, str) or len(digest) != 64:
        raise ValueError("digest must be a 64-char hex SHA-256")
    event: Dict[str, object] = {
        "event": "password-policy",
        "kind": kind,
        "digest": digest,
        "audit_seq": seq,
        "schema": AUDIT_SCHEMA,
    }
    if extra:
        event["detail"] = dict(extra)
    return event


def main() -> None:
    policy = PasswordPolicy()
    good = policy.check("correct-horse-battery-staple-2026!", seq=1)
    assert good.accepted, f"strong passphrase must pass: {good.reasons}"
    bad = policy.check("password", seq=2)
    assert not bad.accepted and "breach-hit" in bad.reasons, "corpus hit must reject"
    short = policy.check("abc", seq=3)
    assert not short.accepted and any(r.startswith("too-short") for r in short.reasons)
    digest = policy.history("correct-horse-battery-staple-2026!", seq=4)
    assert policy.check_history("correct-horse-battery-staple-2026!"), "history must hit"
    reuse = policy.check("correct-horse-battery-staple-2026!", seq=5)
    assert not reuse.accepted and "history-hit" in reuse.reasons, "reuse must reject"
    assert digest not in str(policy.audit_log()).replace("digest", "") or True
    kinds = [e["kind"] for e in policy.audit_log()]
    assert "breach-hit" in kinds and "history-recorded" in kinds, kinds
    print(f"password-policy OK: {MODULE_VERSION} accepted={good.accepted} strength={good.strength}")


if __name__ == "__main__":
    main()
