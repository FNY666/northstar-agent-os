"""Safety-benchmark (check/score/certify) interface, simulated.

Research motivation: safety benchmarks are the evaluation workhorse for
agent safety -- AgentGuardBench, AgentDojo, and their successors all
reduce to the same ledger: declare test cases under a pinned category
vocabulary, book host-declared check outcomes, derive per-category and
overall pass statistics, and book certification decisions against a
pinned threshold. Getting the bookkeeping wrong (double-counted cases,
silent threshold drift, unverifiable verdicts) corrupts the benchmark
before any safety claim runs.

This module is the *decision ledger* half of that shape:

- ``SafetyEval.register_case(case_id, category, seq)`` -- declare one
  safety test case under a pinned category. Returns a frozen
  ``CaseRecord`` with a ``sha256:`` digest pin. Duplicate ids are
  refused fail-closed; ids are never recycled.
- ``SafetyEval.check(case_id, outcome, seq, evidence_digest="")`` --
  book one host-declared check outcome (``pass`` / ``fail`` /
  ``inconclusive``), evidence pinned by digest only. Returns a frozen
  ``CheckRecord`` with a minted ``check-N`` id. This books the
  *declared* outcome, not proof the check ran.
- ``SafetyEval.score(seq)`` -- pure read view deriving per-category
  (passed, failed, inconclusive) counts and the overall pass rate as
  exact ``num/den`` text (no floats). Validates seq shape, consumes
  nothing, writes no audit row. Returns a frozen ``ScoreReport`` with a
  ``sha256:`` digest pin.
- ``SafetyEval.certify(threshold, seq)`` -- book one certification
  decision: overall pass rate >= threshold is derived with exact
  ``Fraction`` arithmetic and booked as data (``certified`` bool),
  never raised. Returns a frozen ``CertifyRecord`` with a minted
  ``certify-N`` id.
- ``safety_eval_audit_event(kind, ...)`` -- ``audit.ndjson/1``
  records (``case-registered`` / ``checked`` / ``certified`` /
  ``rejected``); caller-supplied seqs only. Raw evidence never crosses
  the audit boundary -- audit rows carry ids, counts, and digest pins
  only.

Fail-closed edges (fail loudly, never guess):

- ``case_id`` must be a non-empty str, <= 256 chars, no whitespace.
- ``category`` must name the pinned category vocabulary.
- ``outcome`` must name the pinned outcome vocabulary; ``inconclusive``
  is data, never an error.
- ``evidence_digest`` must be a ``sha256:``-prefixed digest when
  supplied (raw evidence never enters a record).
- ``threshold`` must be a finite float in [0, 1] (bool refused).
- Certifying with zero booked checks raises ``NoEvidenceError``.
- Seqs are ints (not bool), >= 0, strictly increasing per instance.
  Failed mutations consume their seq and book a ``rejected`` audit
  row; seq rewinds raise bare ``SeqOrderError`` without consuming.

Honest scope:

- This module books *declared* cases and *host-reported* outcomes. A
  booked ``pass`` is a ledger entry, not a verified safety result --
  outcomes are GIGO: the module cannot prove the host ran the case or
  measured honestly.
- ``certify()`` books a declared decision against a host-supplied
  threshold. A ``certified=True`` verdict is ledger truth about the
  booked outcomes, never proof the agent is safe.
- No persistence: the ledger is in-memory. Pair with the durable
  audit writer if safety state must survive a restart.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from fractions import Fraction
from typing import Dict, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json, jcs_sha256_hex
except Exception:  # pragma: no cover - module must stay importable standalone
    import json as _json

    def jcs_canonical_json(obj):  # type: ignore[no-redef]
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("utf-8")

    def jcs_sha256_hex(obj):  # type: ignore[no-redef]
        return hashlib.sha256(jcs_canonical_json(obj)).hexdigest()


#: Version pin for this module's record shape.
SAFETY_EVAL_VERSION = "safety-eval.v1"

#: Schema pin carried by records and audit events.
SAFETY_EVAL_SCHEMA = "northstar.safety-eval.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Pinned safety-case category vocabulary.
CATEGORY_PROMPT_INJECTION = "prompt-injection"
CATEGORY_JAILBREAK = "jailbreak"
CATEGORY_TOOL_MISUSE = "tool-misuse"
CATEGORY_DATA_EXFILTRATION = "data-exfiltration"
CATEGORY_PRIVILEGE_ESCALATION = "privilege-escalation"
CATEGORY_UNSAFE_ACTION = "unsafe-action"
CATEGORIES = (CATEGORY_PROMPT_INJECTION, CATEGORY_JAILBREAK,
              CATEGORY_TOOL_MISUSE, CATEGORY_DATA_EXFILTRATION,
              CATEGORY_PRIVILEGE_ESCALATION, CATEGORY_UNSAFE_ACTION)

#: Pinned check-outcome vocabulary.
OUTCOME_PASS = "pass"
OUTCOME_FAIL = "fail"
OUTCOME_INCONCLUSIVE = "inconclusive"
OUTCOMES = (OUTCOME_PASS, OUTCOME_FAIL, OUTCOME_INCONCLUSIVE)

#: Audit event kinds.
KIND_CASE_REGISTERED = "case-registered"
KIND_CHECKED = "checked"
KIND_CERTIFIED = "certified"
KIND_REJECTED = "rejected"
_KINDS = (KIND_CASE_REGISTERED, KIND_CHECKED, KIND_CERTIFIED,
          KIND_REJECTED)

#: Detail keys banned from the audit boundary (raw data never crosses it).
_BANNED_DETAIL_KEYS = frozenset(
    {"evidence", "payload", "value", "raw", "text", "data", "variables"})

#: Max case-id length.
_MAX_CASE_ID_LEN = 256


class SafetyEvalError(Exception):
    """Base error for the safety-eval ledger (programming errors)."""


class BadCaseError(SafetyEvalError):
    """Raised when a case id is malformed."""


class DuplicateCaseError(SafetyEvalError):
    """Raised when a case id is registered twice."""


class UnknownCaseError(SafetyEvalError):
    """Raised when a case id names no declared case."""


class BadCategoryError(SafetyEvalError):
    """Raised when a category is outside the pinned vocabulary."""


class BadOutcomeError(SafetyEvalError):
    """Raised when an outcome is outside the pinned vocabulary."""


class BadEvidenceError(SafetyEvalError):
    """Raised when an evidence digest is malformed."""


class BadThresholdError(SafetyEvalError):
    """Raised when a certification threshold is malformed."""


class NoEvidenceError(SafetyEvalError):
    """Raised when certify() is called with zero booked checks."""


class SeqOrderError(SafetyEvalError):
    """Raised when a seq is malformed or not strictly increasing."""


class AuditKindError(SafetyEvalError):
    """Raised when an audit event kind is unknown or leaks banned keys."""


def _check_seq(value, name="seq"):
    """Validate a caller-supplied ordering seq: int, not bool, >= 0."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise SeqOrderError(f"{name} must be int, got {type(value).__name__}")
    if value < 0:
        raise SeqOrderError(f"{name} must be >= 0, got {value}")
    return value


def _check_case_id(case_id):
    """Validate a case id: non-empty str, no whitespace, <= 256 chars."""
    if isinstance(case_id, bool) or not isinstance(case_id, str):
        raise BadCaseError(f"case_id must be str, got {type(case_id).__name__}")
    if not case_id:
        raise BadCaseError("case_id must not be empty")
    if len(case_id) > _MAX_CASE_ID_LEN:
        raise BadCaseError(f"case_id too long (>{_MAX_CASE_ID_LEN} chars)")
    if any(ch.isspace() for ch in case_id):
        raise BadCaseError("case_id must not contain whitespace")
    return case_id


def _check_category(category):
    """Validate a category against the pinned vocabulary."""
    if category not in CATEGORIES:
        raise BadCategoryError(
            f"category must be one of {list(CATEGORIES)}, got {category!r}")
    return category


def _check_outcome(outcome):
    """Validate an outcome against the pinned vocabulary."""
    if outcome not in OUTCOMES:
        raise BadOutcomeError(
            f"outcome must be one of {list(OUTCOMES)}, got {outcome!r}")
    return outcome


def _check_evidence_digest(digest):
    """Validate an evidence digest: 'sha256:'-prefixed when supplied."""
    if not digest:
        return ""
    if isinstance(digest, bool) or not isinstance(digest, str):
        raise BadEvidenceError(
            f"evidence_digest must be str, got {type(digest).__name__}")
    if not digest.startswith("sha256:") or len(digest) <= len("sha256:"):
        raise BadEvidenceError(
            "evidence_digest must be a sha256:-prefixed digest pin")
    return digest


def _check_threshold(threshold):
    """Validate a threshold: finite float in [0, 1]; bool refused."""
    if isinstance(threshold, bool):
        raise BadThresholdError("threshold must not be bool")
    if isinstance(threshold, int):
        threshold = float(threshold)
    if not isinstance(threshold, float):
        raise BadThresholdError(
            f"threshold must be float, got {type(threshold).__name__}")
    if not (threshold == threshold) or threshold in (float("inf"),
                                                     float("-inf")):
        raise BadThresholdError(f"threshold must be finite, got {threshold!r}")
    if not 0.0 <= threshold <= 1.0:
        raise BadThresholdError(
            f"threshold must be in [0, 1], got {threshold!r}")
    return threshold


def _pin(*parts):
    """Digest pin over a domain-separated canonical tuple."""
    return "sha256:" + jcs_sha256_hex({
        "domain": SAFETY_EVAL_SCHEMA,
        "parts": list(parts),
    })


def _rate_text(passed, total):
    """Overall pass rate as exact 'num/den' text (no floats)."""
    frac = Fraction(passed, total)
    return f"{frac.numerator}/{frac.denominator}"


def safety_eval_audit_event(kind, detail, seq):
    """Build one ``audit.ndjson/1`` audit row for the safety ledger."""
    if kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    banned = _BANNED_DETAIL_KEYS.intersection(detail.keys())
    if banned:
        raise AuditKindError(
            f"detail keys banned from audit boundary: {sorted(banned)}")
    return {
        "schema": AUDIT_SCHEMA,
        "module": SAFETY_EVAL_VERSION,
        "kind": kind,
        "seq": seq,
        "detail": dict(detail),
    }


@dataclass(frozen=True)
class CaseRecord:
    """Frozen record of a declared safety test case."""
    case_id: str
    category: str
    seq: int
    digest: str

    def verify(self, case_id, category):
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin("case", case_id, category, self.seq)


@dataclass(frozen=True)
class CheckRecord:
    """Frozen record of one host-declared check outcome."""
    check_id: str
    case_id: str
    outcome: str
    evidence_digest: str
    seq: int
    digest: str

    def verify(self, case_id, outcome, evidence_digest):
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin("check", self.check_id, case_id,
                                   outcome, evidence_digest, self.seq)


@dataclass(frozen=True)
class CategoryScore:
    """Per-category outcome counts as data (not a record)."""
    category: str
    passed: int
    failed: int
    inconclusive: int


@dataclass(frozen=True)
class ScoreReport:
    """Pure read view: per-category counts and overall pass rate as data."""
    seq: int
    # Per-category counts, in pinned category order.
    categories: Tuple[CategoryScore, ...]
    total_passed: int
    total_failed: int
    total_inconclusive: int
    # Exact overall pass rate as "num/den" text (no floats).
    pass_rate: str
    digest: str

    def verify(self, categories, totals, pass_rate):
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin(
            "score", [[c.category, c.passed, c.failed, c.inconclusive]
                      for c in categories],
            list(totals), pass_rate, self.seq)


@dataclass(frozen=True)
class CertifyRecord:
    """Frozen record of one certification decision (verdict as data)."""
    certify_id: str
    threshold: float
    passed: int
    total: int
    # Verdict is data: True when pass rate >= threshold.
    certified: bool
    score_digest: str
    seq: int
    digest: str

    def verify(self, threshold, passed, total, certified):
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin("certify", self.certify_id,
                                   repr(threshold), passed, total,
                                   certified, self.seq)


class SafetyEval:
    """Deterministic safety-benchmark decision ledger.

    All mutations take caller-supplied strictly increasing int seqs,
    are RLock-guarded, and book frozen records with ``sha256:`` digest
    pins plus ``audit.ndjson/1`` rows. No wall-clock, no randomness.
    """

    def __init__(self):
        self._lock = threading.RLock()
        self._cases: Dict[str, CaseRecord] = {}
        self._checks: Dict[str, CheckRecord] = {}
        self._certifies: Dict[str, CertifyRecord] = {}
        self._check_counter = 0
        self._certify_counter = 0
        self._last_seq = 0
        self._audit: list = []

    # -- seq discipline ---------------------------------------------------

    def _claim(self, seq):
        """Validate seq; rewinds raise bare (no consumption)."""
        seq = _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq must be strictly increasing "
                f"(last={self._last_seq}, got={seq})")
        return seq

    def _burn(self, seq, error):
        """Consume the seq, book a rejected row, then raise."""
        self._last_seq = seq
        self._audit.append(safety_eval_audit_event(
            KIND_REJECTED, {"error": type(error).__name__}, seq))
        raise error

    def _emit(self, audit_kind, detail, seq):
        self._audit.append(safety_eval_audit_event(audit_kind, detail, seq))

    # -- derived state (internal) ------------------------------------------

    def _score_locked(self, seq):
        """Derive the score report inputs. Call with the lock held."""
        counts = {cat: [0, 0, 0] for cat in CATEGORIES}
        for rec in self._checks.values():
            cat = self._cases[rec.case_id].category
            idx = OUTCOMES.index(rec.outcome)
            counts[cat][idx] += 1
        cats = tuple(CategoryScore(category=cat, passed=c[0], failed=c[1],
                                   inconclusive=c[2]) for cat, c in counts.items())
        tp = sum(c.passed for c in cats)
        tf = sum(c.failed for c in cats)
        ti = sum(c.inconclusive for c in cats)
        rate = _rate_text(tp, tp + tf + ti) if (tp + tf + ti) else "0/1"
        return cats, (tp, tf, ti), rate

    # -- mutations ----------------------------------------------------------

    def register_case(self, case_id, category, seq):
        """Declare a safety test case; duplicate ids refused fail-closed."""
        with self._lock:
            seq = self._claim(seq)
            try:
                case_id = _check_case_id(case_id)
                category = _check_category(category)
                if case_id in self._cases:
                    raise DuplicateCaseError(
                        f"case already registered: {case_id!r}")
            except SafetyEvalError as e:
                self._burn(seq, e)
            rec = CaseRecord(case_id=case_id, category=category, seq=seq,
                             digest=_pin("case", case_id, category, seq))
            self._cases[case_id] = rec
            self._last_seq = seq
            self._emit(KIND_CASE_REGISTERED,
                       {"case_id": case_id, "category": category,
                        "digest": rec.digest}, seq)
            return rec

    def check(self, case_id, outcome, seq, evidence_digest=""):
        """Book one host-declared check outcome (minted ``check-N`` id)."""
        with self._lock:
            seq = self._claim(seq)
            try:
                case_id = _check_case_id(case_id)
                outcome = _check_outcome(outcome)
                evidence_digest = _check_evidence_digest(evidence_digest)
                if case_id not in self._cases:
                    raise UnknownCaseError(f"unknown case: {case_id!r}")
            except SafetyEvalError as e:
                self._burn(seq, e)
            self._check_counter += 1
            check_id = f"check-{self._check_counter}"
            rec = CheckRecord(check_id=check_id, case_id=case_id,
                              outcome=outcome,
                              evidence_digest=evidence_digest, seq=seq,
                              digest=_pin("check", check_id, case_id,
                                          outcome, evidence_digest, seq))
            self._checks[check_id] = rec
            self._last_seq = seq
            # Raw evidence banned from the audit boundary: digest pin only.
            self._emit(KIND_CHECKED,
                       {"check_id": check_id, "case_id": case_id,
                        "outcome": outcome, "digest": rec.digest}, seq)
            return rec

    def certify(self, threshold, seq):
        """Book one certification decision (minted ``certify-N`` id)."""
        with self._lock:
            seq = self._claim(seq)
            try:
                threshold = _check_threshold(threshold)
                if not self._checks:
                    raise NoEvidenceError(
                        "certify refused: zero booked checks")
                cats, (tp, tf, ti), rate = self._score_locked(seq)
                total = tp + tf + ti
                verdict = Fraction(tp, total) >= Fraction(str(threshold))
            except SafetyEvalError as e:
                self._burn(seq, e)
            score_digest = _pin(
                "score", [[c.category, c.passed, c.failed, c.inconclusive]
                          for c in cats],
                [tp, tf, ti], rate, seq)
            self._certify_counter += 1
            certify_id = f"certify-{self._certify_counter}"
            rec = CertifyRecord(
                certify_id=certify_id, threshold=threshold, passed=tp,
                total=total, certified=verdict, score_digest=score_digest,
                seq=seq,
                digest=_pin("certify", certify_id, repr(threshold), tp,
                            total, verdict, seq))
            self._certifies[certify_id] = rec
            self._last_seq = seq
            self._emit(KIND_CERTIFIED,
                       {"certify_id": certify_id,
                        "certified": verdict,
                        "passed": tp, "total": total,
                        "digest": rec.digest}, seq)
            return rec

    # -- views ---------------------------------------------------------------

    def score(self, seq):
        """Pure read view of per-category counts and pass rate (no audit)."""
        _check_seq(seq)
        with self._lock:
            cats, (tp, tf, ti), rate = self._score_locked(seq)
            digest = _pin(
                "score", [[c.category, c.passed, c.failed, c.inconclusive]
                          for c in cats],
                [tp, tf, ti], rate, seq)
            return ScoreReport(seq=seq, categories=cats, total_passed=tp,
                               total_failed=tf, total_inconclusive=ti,
                               pass_rate=rate, digest=digest)

    def case_record(self, case_id):
        """Return the case record, or None when unknown (pure read)."""
        return self._cases.get(case_id)

    def case_ids(self):
        """Sorted declared case ids (pure read)."""
        return tuple(sorted(self._cases))

    def check_record(self, check_id):
        """Return the check record, or None when unknown (pure read)."""
        return self._checks.get(check_id)

    def check_ids(self):
        """Sorted booked check ids (pure read)."""
        return tuple(sorted(self._checks))

    def certify_record(self, certify_id):
        """Return the certify record, or None when unknown (pure read)."""
        return self._certifies.get(certify_id)

    def audit_log(self):
        """Booked audit rows, oldest first (pure read)."""
        return tuple(self._audit)


def main():
    """Self-check: register, check, score, certify."""
    se = SafetyEval()
    c = se.register_case("inj-001", "prompt-injection", 1)
    assert c.verify("inj-001", "prompt-injection")
    c2 = se.register_case("jail-001", "jailbreak", 2)
    assert c2.verify("jail-001", "jailbreak")
    ev = "sha256:" + "0" * 64
    r1 = se.check("inj-001", "pass", 3, evidence_digest=ev)
    assert r1.verify("inj-001", "pass", ev)
    r2 = se.check("jail-001", "pass", 4, evidence_digest=ev)
    assert r2.verify("jail-001", "pass", ev)
    rep = se.score(4)
    assert rep.total_passed == 2 and rep.total_failed == 0
    assert rep.pass_rate == "1/1"
    assert rep.verify(rep.categories,
                      (rep.total_passed, rep.total_failed,
                       rep.total_inconclusive), rep.pass_rate)
    cert = se.certify(0.9, 5)
    assert cert.certified is True
    assert cert.verify(0.9, 2, 2, True)
    assert len(se.audit_log()) == 5
    print("safety-eval OK: register, check, score, certify")


if __name__ == "__main__":
    main()
