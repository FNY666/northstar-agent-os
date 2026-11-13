"""Scorer disagreement: a contested verdict is a verdict, not an average.

Source (inspect_ai, "Multiple Scorers"; the excerpt carried by the slice
brief is the source -- verbatim as briefed):

* one Task may carry several scorers, each keeping its own score; a single
  scorer may return a multi-valued score;
* ``multi_scorer(scorers, reducer)`` aggregates with a reducer -- ``mode`` /
  ``majority`` / ``collect``; ``collect`` keeps each scorer's original value
  so that inter-rater agreement (e.g. ``krippendorff_alpha``) can be computed;
* ``cascade()`` runs cheapest-first and stops at the first settled scorer;
* the key point: inspect_ai itself only aggregates or preserves scores and
  **never turns "the scorers disagree" into a verdict** -- disagreement
  detection is the gap.

Northstar gap this closes (read from the code, not assumed):

* ``evaluation_harness.py`` books exactly one host-declared score per case
  per run (missing / extra / unknown cases are refused fail-closed); the
  word ``scorer`` occurs zero times in that file, so there is no multi-scorer
  shape and no disagreement concept at all;
* ``ai_ensemble.py``'s "disagree" is an ensemble-**member** composition
  declaration ledger (postures ``divided -> contested -> plural ->
  consensus``, declared values booked as data); its object is the ensemble
  member, not an eval scorer, and it never compares per-case scores.

So today a judge disagreement is not merely unrepresented: it cannot be
represented at all, and a host that wants a second opinion has nowhere to
put it. Anything that reduces several judgements to one number is a
majority vote, and a majority vote silently erases the case where the
minority was right.

Design invariants this module enforces:

* **every scorer keeps its own value** -- registering a verdict never
  overwrites another scorer's verdict for the same case, and no aggregation
  drops a raw value (``collect`` semantics, always available),
* **disagreement is computed, then compared to a threshold** -- the primary
  metric is the minority share (the size of the smaller side of the
  split), the auxiliary metric is the score spread; the two are reported
  side by side and never conflated,
* **contested is a verdict**: over the threshold, the case verdict is
  ``contested`` and the case is booked into the human-review queue (a
  ledger, not a notification -- nothing is sent anywhere),
* **majority masking is recorded explicitly**: when the aggregate verdict
  is the opposite of the minority verdict and the disagreement is over the
  threshold, the case is booked as masked,
* **one scorer is never contested** -- a single judgement cannot disagree
  with itself,
* **the threshold is a Northstar choice**, pinned in one place
  (:data:`DISAGREEMENT_THRESHOLD`), and it is *not* a number taken from the
  source.

Honest scope: this module books *declared* scorer verdicts and derives
disagreement arithmetic from them. A booked ``contested`` case is a
statement that the declared verdicts disagree -- it is not proof that any
judge was right, and it is not proof that the disagreement is meaningful
(a flaky judge and a broken judge look identical here).
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass
from fractions import Fraction
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

#: Module version pin.
VERSION = "scorer-disagreement.v1"

#: Schema pin for the records this module produces.
SCHEMA = "northstar.scorer-disagreement.v1"

#: The verdict vocabulary a single scorer may declare (Northstar choice --
#: the source says a scorer returns a score, not that it returns pass/fail).
VERDICTS: Tuple[str, ...] = ("pass", "fail")

#: The reducer names (verbatim from the inspect_ai source excerpt):
#: ``mode`` / ``majority`` / ``collect``.
REDUCERS: Tuple[str, ...] = ("mode", "majority", "collect")

#: The default reducer used to derive the aggregate verdict.
DEFAULT_REDUCER = "majority"

#: The primary disagreement metric: the share of scorers on the smaller
#: side of the split (the "minority share"). A Northstar definition.
MINORITY_SHARE = "minority-share"

#: The auxiliary disagreement metric: the spread between the largest and
#: the smallest declared score of a case. A Northstar definition.
SCORE_SPREAD = "score-spread"

#: The disagreement threshold, as an exact fraction.
#:
#: **This number is a Northstar choice, not a number from the source.**
#: The source excerpt names no threshold. The chosen value means: a case
#: is contested only when *more than* a quarter of the scorers sit on the
#: minority side. Consequences (binary pass/fail verdicts):
#:
#: * 3-1 split -> minority share exactly 1/4 -> **not** contested (the
#:   documented boundary: strictly greater than the threshold contests),
#: * 2-1 split -> minority share 1/3 -> contested, and the aggregate
#:   verdict is booked as majority-masked,
#: * 2-2 tie -> minority share 1/2 -> contested (no majority exists),
#: * 1-1 tie -> minority share 1/2 -> contested.
DISAGREEMENT_THRESHOLD = Fraction(1, 4)

#: Case verdicts this module may derive.
CASE_VERDICTS: Tuple[str, ...] = ("pass", "fail", "contested")


# ---------------------------------------------------------------------------
# errors
# ---------------------------------------------------------------------------


class ScorerDisagreementError(Exception):
    """Base error for the scorer-disagreement ledger."""


class BadCaseIdError(ScorerDisagreementError):
    pass


class BadScorerIdError(ScorerDisagreementError):
    pass


class BadVerdictError(ScorerDisagreementError):
    pass


class BadScoreError(ScorerDisagreementError):
    pass


class DuplicateScorerError(ScorerDisagreementError):
    """The same scorer already registered a verdict for this case."""


class UnknownCaseError(ScorerDisagreementError):
    pass


class BadThresholdError(ScorerDisagreementError):
    pass


class BadReducerError(ScorerDisagreementError):
    pass


class AuditKindError(ScorerDisagreementError):
    pass


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def minority_share(pass_count: int, fail_count: int) -> Fraction:
    """The primary disagreement metric: the smaller side's share.

    A Northstar definition (the source names no metric). Unanimity gives
    0; a 2-1 split gives 1/3; a 2-2 tie gives 1/2.
    """
    total = pass_count + fail_count
    if total == 0:
        return Fraction(0)
    return Fraction(min(pass_count, fail_count), total)


def score_spread(scores: Sequence[Optional[float]]) -> Optional[float]:
    """The auxiliary metric: the spread of the declared scores.

    ``None`` when fewer than two scorers declared a score -- the spread of
    one number is not a disagreement measure.
    """
    present = [s for s in scores if s is not None]
    if len(present) < 2:
        return None
    return max(present) - min(present)


def agreement_alpha(verdicts: Sequence[str]) -> Optional[Fraction]:
    """Nominal Krippendorff-style alpha over one case's scorer verdicts.

    ``collect`` keeps the raw values so that an agreement coefficient can
    be recomputed from them; this is the recomputation. The coefficient is
    computed per case over that case's scorer set: ``Do`` is the observed
    disagreeing-pair share, ``De`` the expected disagreement implied by
    the case's own marginal distribution, and ``alpha = 1 - Do/De``.

    Honest scope: with one case as the unit this is a per-case nominal
    coefficient, not a corpus-level inter-rater reliability. ``None`` when
    fewer than two scorers declared a verdict (nothing to disagree about).
    """
    n = len(verdicts)
    if n < 2:
        return None
    pairs = 0
    disagree = 0
    for i in range(n):
        for j in range(i + 1, n):
            pairs += 1
            if verdicts[i] != verdicts[j]:
                disagree += 1
    if pairs == 0:
        return None
    if disagree == 0:
        return Fraction(1)
    do = Fraction(disagree, pairs)
    p_pass = Fraction(sum(1 for v in verdicts if v == "pass"), n)
    p_fail = Fraction(sum(1 for v in verdicts if v == "fail"), n)
    de = 2 * p_pass * p_fail
    if de == 0:
        return None
    return Fraction(1) - do / de


def aggregate_verdict(verdicts: Sequence[str],
                       reducer: str) -> Tuple[Optional[str], bool]:
    """Aggregate one case's verdicts. Returns ``(verdict, tie_resolved)``.

    ``mode`` / ``majority`` / ``collect`` are the reducer names of the
    inspect_ai source excerpt (verbatim). Their semantics **here** are
    Northstar's, chosen so that the two binary reducers differ exactly on
    the case that matters -- a tie:

    * ``majority``: a *strict* majority (more than half) is required. On a
      tie there is no aggregate verdict (``None``, ``tie_resolved=True``).
    * ``mode``: the most frequent verdict. On a tie the pinned order
      ``pass`` before ``fail`` decides, and the tie is flagged
      (``tie_resolved=True``) -- never silently.
    * ``collect``: no single verdict at all; the raw values are kept and
      returned by :meth:`ScorerDisagreement.collect`.
    """
    if reducer not in REDUCERS:
        raise BadReducerError(f"bad reducer: {reducer!r}")
    if reducer == "collect":
        return None, False
    n = len(verdicts)
    if n == 0:
        return None, False
    passes = sum(1 for v in verdicts if v == "pass")
    fails = sum(1 for v in verdicts if v == "fail")
    if reducer == "majority":
        if passes * 2 > n:
            return "pass", False
        if fails * 2 > n:
            return "fail", False
        return None, True
    # mode
    if passes > fails:
        return "pass", False
    if fails > passes:
        return "fail", False
    return "pass", True  # pinned order: pass before fail


# ---------------------------------------------------------------------------
# records
# ---------------------------------------------------------------------------


def _check_id(value: Any, error: Any, what: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 256:
        raise error(f"bad {what}: {value!r}")
    if any(ch.isspace() for ch in value):
        raise error(f"bad {what}: {value!r}")
    return value


def _check_verdict(value: Any) -> str:
    if value not in VERDICTS:
        raise BadVerdictError(f"bad verdict: {value!r}")
    return value


def _check_score(value: Any) -> Optional[float]:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise BadScoreError(f"score must be a number or None, got {value!r}")
    f = float(value)
    if f != f or f in (float("inf"), float("-inf")):
        raise BadScoreError(f"score must be finite, got {value!r}")
    return f


def _canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def _digest_pin(tag: str, *payload: Any) -> str:
    return "sha256:" + hashlib.sha256(
        _canonical([tag, list(payload)])).hexdigest()


# ---------------------------------------------------------------------------
# pure computation (no state, no I/O)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ScorerVerdict:
    """One scorer's declared verdict for one case.

    Every scorer keeps its own value: two scorers on the same case are two
    records, never one overwritten record.
    """

    case_id: str
    scorer_id: str
    verdict: str
    score: Optional[float]
    digest: str
    schema: str = SCHEMA

    def as_dict(self) -> Dict[str, Any]:
        return {
            "case_id": self.case_id,
            "scorer_id": self.scorer_id,
            "verdict": self.verdict,
            "score": self.score,
            "digest": self.digest,
            "schema": self.schema,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            "verdict", self.case_id, self.scorer_id, self.verdict, self.score)


@dataclass(frozen=True)
class Disagreement:
    """The derived disagreement view of one case.

    ``minority_share`` is the **primary** metric: the share of scorers on
    the smaller side of the split. ``score_spread`` is the **auxiliary**
    metric: the spread between the largest and the smallest declared score.
    The two are never conflated -- a case can have a zero minority share and
    a wide spread, or vice versa.
    """

    case_id: str
    scorer_count: int
    pass_count: int
    fail_count: int
    minority_share: Fraction
    score_spread: Optional[float]
    threshold: Fraction
    exceeded: bool
    aggregate_verdict: Optional[str]
    aggregate_reducer: str
    minority_verdict: Optional[str]
    masked: bool
    agreement_alpha: Optional[Fraction]
    verdicts: Tuple[ScorerVerdict, ...]
    digest: str
    schema: str = SCHEMA

    @property
    def minority_share_text(self) -> str:
        return f"{self.minority_share.numerator}/{self.minority_share.denominator}"

    @property
    def threshold_text(self) -> str:
        return f"{self.threshold.numerator}/{self.threshold.denominator}"

    @property
    def agreement_alpha_text(self) -> Optional[str]:
        if self.agreement_alpha is None:
            return None
        return (f"{self.agreement_alpha.numerator}/"
                f"{self.agreement_alpha.denominator}")

    @property
    def contested(self) -> bool:
        return self.exceeded

    def as_dict(self) -> Dict[str, Any]:
        return {
            "case_id": self.case_id,
            "scorer_count": self.scorer_count,
            "pass_count": self.pass_count,
            "fail_count": self.fail_count,
            "minority_share": self.minority_share_text,
            "score_spread": self.score_spread,
            "threshold": self.threshold_text,
            "exceeded": self.exceeded,
            "aggregate_verdict": self.aggregate_verdict,
            "aggregate_reducer": self.aggregate_reducer,
            "minority_verdict": self.minority_verdict,
            "masked": self.masked,
            "agreement_alpha": self.agreement_alpha_text,
            "verdicts": [v.as_dict() for v in self.verdicts],
            "digest": self.digest,
            "schema": self.schema,
        }

    def verify(self) -> bool:
        if self.scorer_count != len(self.verdicts):
            return False
        if self.pass_count + self.fail_count != self.scorer_count:
            return False
        return self.digest == _digest_pin(
            "disagreement", self.case_id, self.scorer_count, self.pass_count,
            self.fail_count, self.minority_share.numerator,
            self.minority_share.denominator, self.score_spread,
            self.exceeded, self.aggregate_verdict,
            self.aggregate_reducer, self.minority_verdict, self.masked,
            None if self.agreement_alpha is None
            else [self.agreement_alpha.numerator, self.agreement_alpha.denominator],
            self.threshold.numerator, self.threshold.denominator,
            [v.digest for v in self.verdicts])


@dataclass(frozen=True)
class ReviewItem:
    """One case booked into the human-review queue.

    The queue is **bookkeeping**: nothing is notified, no reviewer is
    contacted, no external system is touched. A review item is a record
    that a human *could* pick up.
    """

    case_id: str
    reason: str
    minority_verdict: Optional[str]
    aggregate_verdict: Optional[str]
    masked: bool
    digest: str
    schema: str = SCHEMA

    def as_dict(self) -> Dict[str, Any]:
        return {
            "case_id": self.case_id,
            "reason": self.reason,
            "minority_verdict": self.minority_verdict,
            "aggregate_verdict": self.aggregate_verdict,
            "masked": self.masked,
            "digest": self.digest,
            "schema": self.schema,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            "review", self.case_id, self.reason, self.minority_verdict,
            self.aggregate_verdict, self.masked)


class ScorerDisagreement:
    """Ledger of per-scorer verdicts plus the derived disagreement view.

    One instance holds one evaluation's cases. Every scorer's value is
    kept; nothing is averaged away at registration time.
    """

    def __init__(self, threshold: Any = DISAGREEMENT_THRESHOLD,
                 reducer: str = DEFAULT_REDUCER) -> None:
        if not isinstance(threshold, Fraction):
            if isinstance(threshold, bool) or not isinstance(
                    threshold, (int, float)):
                raise BadThresholdError(
                    f"threshold must be a Fraction, got {threshold!r}")
            threshold = Fraction(threshold).limit_denominator(10 ** 9)
        if threshold < 0:
            raise BadThresholdError(f"threshold must be >= 0: {threshold!r}")
        if reducer not in REDUCERS:
            raise BadReducerError(f"bad reducer: {reducer!r}")
        self._lock = threading.RLock()
        self._threshold = threshold
        self._reducer = reducer
        self._verdicts: Dict[str, List[ScorerVerdict]] = {}
        self._review: List[ReviewItem] = []
        self._masked: List[str] = []
        self._audit: List[Dict[str, Any]] = []

    # -- registration ------------------------------------------------------

    def register(self, case_id: str, scorer_id: str, verdict: str,
                 score: Optional[float] = None) -> ScorerVerdict:
        """Register one scorer's verdict for one case.

        A second scorer on the same case is **added**, never merged over
        the first one. The same scorer registering twice for the same case
        is refused (fail-closed): a re-registration would silently replace
        a judged value.
        """
        case_id = _check_id(case_id, BadCaseIdError, "case_id")
        scorer_id = _check_id(scorer_id, BadScorerIdError, "scorer_id")
        verdict = _check_verdict(verdict)
        score = _check_score(score)
        with self._lock:
            existing = self._verdicts.setdefault(case_id, [])
            if any(v.scorer_id == scorer_id for v in existing):
                raise DuplicateScorerError(
                    f"scorer {scorer_id!r} already registered for {case_id!r}")
            record = ScorerVerdict(
                case_id=case_id, scorer_id=scorer_id, verdict=verdict,
                score=score, digest="")
            digest = _digest_pin("verdict", case_id, scorer_id, verdict, score)
            record = ScorerVerdict(
                case_id=case_id, scorer_id=scorer_id, verdict=verdict,
                score=score, digest=digest)
            existing.append(record)
        return record

    # -- derivation --------------------------------------------------------

    def disagreement(self, case_id: str) -> Disagreement:
        """Derive the disagreement view of one case (pure read)."""
        case_id = _check_id(case_id, BadCaseIdError, "case_id")
        with self._lock:
            verdicts = tuple(self._verdicts.get(case_id, ()))
            if not verdicts:
                raise UnknownCaseError(f"no verdicts for case: {case_id!r}")
            return self._derive(case_id, verdicts)

    def _derive(self, case_id: str,
                verdicts: Tuple[ScorerVerdict, ...]) -> Disagreement:
        values = [v.verdict for v in verdicts]
        pass_count = sum(1 for v in values if v == "pass")
        fail_count = sum(1 for v in values if v == "fail")
        share = minority_share(pass_count, fail_count)
        spread = score_spread([v.score for v in verdicts])
        # A single scorer cannot disagree with itself: never contested.
        exceeded = len(verdicts) > 1 and share > self._threshold
        agg, tie = aggregate_verdict(values, self._reducer)
        minority = None
        if pass_count and fail_count:
            # The minority side is the *smaller* side; on an exact tie there
            # is no minority, and the tie is visible in the counts.
            if pass_count < fail_count:
                minority = "pass"
            elif fail_count < pass_count:
                minority = "fail"
        # Majority masking: the aggregate is the opposite of the minority
        # verdict, and the case is over the threshold.
        masked = bool(
            exceeded and agg is not None and minority is not None
            and agg != minority)
        alpha = agreement_alpha(values)
        provisional = Disagreement(
            case_id=case_id, scorer_count=len(verdicts),
            pass_count=pass_count, fail_count=fail_count,
            minority_share=share, score_spread=spread,
            threshold=self._threshold, exceeded=exceeded,
            aggregate_verdict=agg, aggregate_reducer=self._reducer,
            minority_verdict=minority, masked=masked, agreement_alpha=alpha,
            verdicts=verdicts, digest="")
        digest = _digest_pin(
            "disagreement", case_id, len(verdicts), pass_count, fail_count,
            share.numerator, share.denominator, spread, exceeded, agg,
            self._reducer, minority, masked,
            None if alpha is None else [alpha.numerator, alpha.denominator],
            self._threshold.numerator, self._threshold.denominator,
            [v.digest for v in verdicts])
        return Disagreement(
            case_id=case_id, scorer_count=len(verdicts),
            pass_count=pass_count, fail_count=fail_count,
            minority_share=share, score_spread=spread,
            threshold=self._threshold, exceeded=exceeded,
            aggregate_verdict=agg, aggregate_reducer=self._reducer,
            minority_verdict=minority, masked=masked, agreement_alpha=alpha,
            verdicts=verdicts, digest=digest)

    def adjudicate(self, case_id: str) -> Disagreement:
        """Derive the case verdict and book contested cases for review.

        The case verdict is ``contested`` when the disagreement is over the
        threshold, otherwise the reducer's aggregate verdict. A contested
        case is booked into the review queue; a masked case is booked into
        the masked list as well.
        """
        view = self.disagreement(case_id)
        if not view.exceeded:
            return view
        with self._lock:
            if not any(item.case_id == case_id for item in self._review):
                reason = "majority-masked" if view.masked else "disagreement"
                item = ReviewItem(
                    case_id=case_id, reason=reason,
                    minority_verdict=view.minority_verdict,
                    aggregate_verdict=view.aggregate_verdict,
                    masked=view.masked, digest="")
                digest = _digest_pin(
                    "review", case_id, reason, view.minority_verdict,
                    view.aggregate_verdict, view.masked)
                item = ReviewItem(
                    case_id=case_id, reason=reason,
                    minority_verdict=view.minority_verdict,
                    aggregate_verdict=view.aggregate_verdict,
                    masked=view.masked, digest=digest)
                self._review.append(item)
                if view.masked and case_id not in self._masked:
                    self._masked.append(case_id)
        return view

    def collect(self, case_id: str) -> Tuple[ScorerVerdict, ...]:
        """``collect`` semantics: the raw per-scorer values, kept forever."""
        case_id = _check_id(case_id, BadCaseIdError, "case_id")
        with self._lock:
            if case_id not in self._verdicts:
                raise UnknownCaseError(f"no verdicts for case: {case_id!r}")
            return tuple(self._verdicts[case_id])

    # -- views -------------------------------------------------------------

    def review_queue(self) -> Tuple[ReviewItem, ...]:
        with self._lock:
            return tuple(self._review)

    def masked_cases(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(self._masked)

    def case_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._verdicts))

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "case_count": len(self._verdicts),
                "verdict_count": sum(len(v) for v in self._verdicts.values()),
                "review_count": len(self._review),
                "masked_count": len(self._masked),
                "threshold": (f"{self._threshold.numerator}/"
                              f"{self._threshold.denominator}"),
                "reducer": self._reducer,
            }

    # -- cascade (optional extension, never the default) -------------------

    def run_cascade(self, case_id: str,
                    scorers: Sequence[Tuple[str, float, Callable[[], Any]]]
                    ) -> "CascadeResult":
        """Run scorers cheapest-first and stop at the first settled one.

        **Optional extension, not the default behaviour.** The default is
        that *every* scorer runs to completion and the disagreement is
        judged afterwards -- that is the only way a disagreement can be
        detected at all. ``cascade()`` (the name and the
        cheapest-first/first-settled rule come from the inspect_ai source
        excerpt, verbatim) trades detection for cost: once a scorer
        settles the case, the remaining scorers are *not run*, so their
        verdict never exists and no disagreement can be seen.

        Each scorer entry is ``(scorer_id, cost, fn)``; ``fn()`` returns
        ``None`` (not settled) or ``(verdict, score)``.
        """
        case_id = _check_id(case_id, BadCaseIdError, "case_id")
        if not isinstance(scorers, (list, tuple)) or not scorers:
            raise ScorerDisagreementError("scorers must be a non-empty list")
        ordered = sorted(scorers, key=lambda s: s[1])
        ran: List[str] = []
        skipped: List[str] = []
        settled_by: Optional[str] = None
        for scorer_id, _cost, fn in ordered:
            if settled_by is not None:
                skipped.append(scorer_id)
                continue
            ran.append(scorer_id)
            outcome = fn()
            if outcome is None:
                continue
            verdict, score = outcome
            self.register(case_id, scorer_id, verdict, score)
            settled_by = scorer_id
        return CascadeResult(
            case_id=case_id, ran=tuple(ran), skipped=tuple(skipped),
            settled_by=settled_by)

    # -- audit -------------------------------------------------------------

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            return tuple(self._audit)


@dataclass(frozen=True)
class CascadeResult:
    """What a cascade run did: who ran, who was skipped, who settled."""

    case_id: str
    ran: Tuple[str, ...]
    skipped: Tuple[str, ...]
    settled_by: Optional[str]

    def as_dict(self) -> Dict[str, Any]:
        return {
            "case_id": self.case_id,
            "ran": list(self.ran),
            "skipped": list(self.skipped),
            "settled_by": self.settled_by,
        }


# ---------------------------------------------------------------------------
# stdlib self-check and CLI
# ---------------------------------------------------------------------------


def stdlib_only() -> bool:
    """AST self-check: the module imports stdlib names only."""
    import ast

    with open(__file__, encoding="utf-8") as handle:
        tree = ast.parse(handle.read())
    allowed = {"__future__", "hashlib", "json", "threading", "dataclasses",
               "fractions", "typing", "ast"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module is None:
                continue
            if node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    led = ScorerDisagreement()
    led.register("c1", "s1", "pass", 0.9)
    led.register("c1", "s2", "pass", 0.8)
    led.register("c1", "s3", "pass", 0.7)
    led.register("c2", "s1", "pass", 0.7)
    led.register("c2", "s2", "pass", 0.6)
    led.register("c2", "s3", "fail", 0.4)
    led.register("c3", "s1", "fail", 0.2)
    view = led.adjudicate("c2")
    assert view.exceeded is True
    assert view.aggregate_verdict == "pass"
    assert view.minority_verdict == "fail"
    assert view.masked is True
    assert led.masked_cases() == ("c2",)
    assert led.review_queue()[0].case_id == "c2"
    assert led.collect("c2")[2].score == 0.4
    print("scorer-disagreement OK: register, disagree, contested, masked, collect")


if __name__ == "__main__":
    main()
