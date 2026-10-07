"""RLAIF: reinforcement learning from AI feedback, simulated.

Research motivation: human preference labels are the scarcest input in
RLHF. RLAIF (Lee et al., 2023) replaces the human rater with a strong
AI judge: the judge critiques outputs, labels pairwise preferences,
and the resulting preference signal trains a reward model that a
policy optimizer can consume. The same idea powers Constitutional AI
(Bai et al., 2022) self-critique pipelines.

This module is the *decision ledger* half of that shape:

- ``RLAIF.sample(sample_id, prompt_digest, output_digest, seq)`` --
  declare one (prompt, output) pair pinned by ``sha256:`` digest only.
  Raw text never enters a record. Returns a frozen ``SampleRecord``.
  Duplicate ids refused fail-closed; ids never recycled.
- ``RLAIF.critique(sample_id, seq, issues=(), feedback_digest="",
  verdict="needs-revision")`` -- book one AI-declared critique with
  the pinned issue vocabulary, sorted/deduped; the fail-closed
  consistency rule is: empty issues require ``accept``, non-empty
  issues forbid ``accept``. Returns a frozen ``CritiqueRecord`` with a
  minted ``crit-N`` id.
- ``RLAIF.prefer(sample_a, sample_b, winner, seq)`` -- book one
  AI-declared pairwise preference; ``winner`` in ``{"a", "b", "tie"}``.
  Self-pairs and duplicate (unordered) pairs refused fail-closed.
  Returns a frozen ``PreferenceRecord`` with a minted ``pref-N`` id.
- ``RLAIF.reward(sample_id, score, seq, source="ai-judge")`` -- book
  one scalar reward decision, a finite float in [-1, 1] (ints
  accepted, bool refused), ``source`` naming the pinned vocabulary.
  Returns a frozen ``RewardRecord`` with a minted ``rew-N`` id.
- ``RLAIF.train(seq)`` -- book one reward-model training step,
  derived as data from the booked preferences and rewards: number of
  scored pairs, agreement of the current reward ordering with the
  AI preferences as exact ``num/den`` text, and the mean reward
  margin. Requires at least one scored non-tie preference pair, else
  ``NoTrainingSignalError``. Returns a frozen ``TrainingRecord``
  with a minted ``step-N`` id.
- ``rlaif_audit_event(kind, ...)`` -- ``audit.ndjson/1`` records
  (``sample-declared`` / ``critiqued`` / ``preference-labeled`` /
  ``reward-booked`` / ``trained`` / ``rejected``); caller-supplied
  seqs only. Raw text never crosses the audit boundary -- audit rows
  carry ids, counts, verdicts, and digest pins only.

This module is deliberately distinct from ``recursive_reward.py``:
that module models *human* feedback over feature decompositions with a
fixed linear update; this module models the *AI-feedback* layer
(critiques, AI-labeled preferences, reward-model training steps) and
performs no parameter updates of its own.

Fail-closed edges (fail loudly, never guess):

- ``sample_id`` must be a non-empty str, <= 256 chars, no whitespace.
- ``prompt_digest`` / ``output_digest`` / ``feedback_digest`` must be
  ``sha256:``-prefixed digest pins when supplied (raw text never
  enters a record).
- ``issues`` must name the pinned issue vocabulary, sorted and
  deduped; an empty issue list requires verdict ``accept`` and
  forbids ``needs-revision`` / ``reject``.
- ``winner`` must name the pinned vocabulary ``{"a", "b", "tie"}``;
  self-pairs and already-booked unordered pairs are refused.
- ``score`` must be a finite float in [-1, 1] (bool refused, ints
  accepted as floats); ``source`` must name the pinned vocabulary.
- ``train()`` with zero scored non-tie preference pairs raises
  ``NoTrainingSignalError``.
- Seqs are ints (not bool), >= 0, strictly increasing per instance.
  Failed mutations consume their seq and book a ``rejected`` audit
  row; seq rewinds raise bare ``SeqOrderError`` without consuming.

Honest scope:

- This module books *declared* AI critiques, *declared* AI preference
  labels, and *host-reported* rewards. A booked preference is a
  ledger entry, not proof an AI judge actually compared the outputs --
  the judge is GIGO: the module cannot verify the rater was competent
  or honest.
- ``train()`` books derived summary statistics over the ledger; it
  runs no gradient descent and improves nothing. An
  ``agreement="1/1"`` training step is ledger truth about the booked
  rewards, never proof the reward model is good.
- No persistence: the ledger is in-memory. Pair with the durable
  audit writer if RLAIF state must survive a restart.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from fractions import Fraction
from typing import Dict, Optional, Sequence, Tuple

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
RLAIF_VERSION = "rlaif.v1"

#: Schema pin carried by records and audit events.
RLAIF_SCHEMA = "northstar.rlaif.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Pinned critique-issue vocabulary (same taxonomy as reflection probes).
ISSUE_HALLUCINATION = "hallucination"
ISSUE_FACTUAL_ERROR = "factual-error"
ISSUE_POLICY_VIOLATION = "policy-violation"
ISSUE_INCOMPLETE = "incomplete"
ISSUE_OFF_TASK = "off-task"
ISSUE_FORMATTING = "formatting"
ISSUE_REASONING_GAP = "reasoning-gap"
ISSUES = (ISSUE_HALLUCINATION, ISSUE_FACTUAL_ERROR, ISSUE_POLICY_VIOLATION,
          ISSUE_INCOMPLETE, ISSUE_OFF_TASK, ISSUE_FORMATTING,
          ISSUE_REASONING_GAP)

#: Pinned critique-verdict vocabulary.
VERDICT_ACCEPT = "accept"
VERDICT_NEEDS_REVISION = "needs-revision"
VERDICT_REJECT = "reject"
VERDICTS = (VERDICT_ACCEPT, VERDICT_NEEDS_REVISION, VERDICT_REJECT)

#: Pinned preference-winner vocabulary.
WINNER_A = "a"
WINNER_B = "b"
WINNER_TIE = "tie"
WINNERS = (WINNER_A, WINNER_B, WINNER_TIE)

#: Pinned reward-source vocabulary.
SOURCE_AI_JUDGE = "ai-judge"
SOURCE_PREFERENCE_MODEL = "preference-model"
SOURCE_HEURISTIC = "heuristic"
SOURCES = (SOURCE_AI_JUDGE, SOURCE_PREFERENCE_MODEL, SOURCE_HEURISTIC)

#: Audit event kinds.
KIND_SAMPLE_DECLARED = "sample-declared"
KIND_CRITIQUED = "critiqued"
KIND_PREFERENCE_LABELED = "preference-labeled"
KIND_REWARD_BOOKED = "reward-booked"
KIND_TRAINED = "trained"
KIND_REJECTED = "rejected"
_KINDS = (KIND_SAMPLE_DECLARED, KIND_CRITIQUED, KIND_PREFERENCE_LABELED,
          KIND_REWARD_BOOKED, KIND_TRAINED, KIND_REJECTED)

#: Detail keys banned from the audit boundary (raw data never crosses it).
_BANNED_DETAIL_KEYS = frozenset(
    {"prompt", "output", "feedback", "text", "raw", "payload", "value",
     "data", "variables", "scores"})

#: Max id length.
_MAX_ID_LEN = 256

#: Reward scores are kept on this bounded interval.
_SCORE_MIN = -1.0
_SCORE_MAX = 1.0


class RLAIFError(Exception):
    """Base error for the RLAIF ledger (programming errors)."""


class BadSampleError(RLAIFError):
    """Raised when a sample id or digest is malformed."""


class DuplicateSampleError(RLAIFError):
    """Raised when a sample id is declared twice."""


class UnknownSampleError(RLAIFError):
    """Raised when a sample id names no declared sample."""


class BadDigestError(RLAIFError):
    """Raised when a digest pin is malformed."""


class BadIssueError(RLAIFError):
    """Raised when an issue is outside the pinned vocabulary."""


class BadVerdictError(RLAIFError):
    """Raised when a verdict is outside the pinned vocabulary."""


class InconsistentVerdictError(RLAIFError):
    """Raised when issues and verdict contradict the consistency rule."""


class BadWinnerError(RLAIFError):
    """Raised when a preference winner is outside the pinned vocabulary."""


class SelfPairError(RLAIFError):
    """Raised when a preference pairs a sample with itself."""


class DuplicatePreferenceError(RLAIFError):
    """Raised when the unordered sample pair is already labeled."""


class BadScoreError(RLAIFError):
    """Raised when a reward score is malformed or out of range."""


class BadSourceError(RLAIFError):
    """Raised when a reward source is outside the pinned vocabulary."""


class NoTrainingSignalError(RLAIFError):
    """Raised when train() has no scored non-tie preference pairs."""


class SeqOrderError(RLAIFError):
    """Raised when a seq is malformed or not strictly increasing."""


class AuditKindError(RLAIFError):
    """Raised when an audit event kind is unknown or leaks banned keys."""


def _check_seq(value, name="seq"):
    """Validate a caller-supplied ordering seq: int, not bool, >= 0."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise SeqOrderError(f"{name} must be int, got {type(value).__name__}")
    if value < 0:
        raise SeqOrderError(f"{name} must be >= 0, got {value}")
    return value


def _check_id(value, name):
    """Validate an id: non-empty str, no whitespace, <= 256 chars."""
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadSampleError(
            f"{name} must be str, got {type(value).__name__}")
    if not value:
        raise BadSampleError(f"{name} must not be empty")
    if len(value) > _MAX_ID_LEN:
        raise BadSampleError(f"{name} too long (>{_MAX_ID_LEN} chars)")
    if any(ch.isspace() for ch in value):
        raise BadSampleError(f"{name} must not contain whitespace")
    return value


def _check_digest(digest, name, allow_empty=False):
    """Validate a digest pin: 'sha256:'-prefixed when supplied."""
    if not digest:
        if allow_empty:
            return ""
        raise BadDigestError(f"{name} must not be empty")
    if isinstance(digest, bool) or not isinstance(digest, str):
        raise BadDigestError(
            f"{name} must be str, got {type(digest).__name__}")
    if not digest.startswith("sha256:") or len(digest) <= len("sha256:"):
        raise BadDigestError(f"{name} must be a sha256:-prefixed digest pin")
    return digest


def _check_issues(issues):
    """Validate issues: pinned vocabulary, returned sorted+deduped."""
    if issues is None:
        issues = ()
    if isinstance(issues, (str, bytes)):
        raise BadIssueError("issues must be a sequence of issue names")
    try:
        items = list(issues)
    except TypeError:
        raise BadIssueError("issues must be a sequence of issue names")
    cleaned = []
    for item in items:
        if item not in ISSUES:
            raise BadIssueError(
                f"issue must be one of {list(ISSUES)}, got {item!r}")
        if item not in cleaned:
            cleaned.append(item)
    return tuple(sorted(cleaned))


def _check_verdict(verdict):
    """Validate a verdict against the pinned vocabulary."""
    if verdict not in VERDICTS:
        raise BadVerdictError(
            f"verdict must be one of {list(VERDICTS)}, got {verdict!r}")
    return verdict


def _check_winner(winner):
    """Validate a winner against the pinned vocabulary."""
    if winner not in WINNERS:
        raise BadWinnerError(
            f"winner must be one of {list(WINNERS)}, got {winner!r}")
    return winner


def _check_score(score):
    """Validate a reward score: finite float in [-1, 1]; bool refused."""
    if isinstance(score, bool):
        raise BadScoreError("score must not be bool")
    if isinstance(score, int):
        score = float(score)
    if not isinstance(score, float):
        raise BadScoreError(
            f"score must be float, got {type(score).__name__}")
    if score != score or score in (float("inf"), float("-inf")):
        raise BadScoreError(f"score must be finite, got {score!r}")
    if not _SCORE_MIN <= score <= _SCORE_MAX:
        raise BadScoreError(
            f"score must be in [{_SCORE_MIN}, {_SCORE_MAX}], got {score!r}")
    return score


def _check_source(source):
    """Validate a reward source against the pinned vocabulary."""
    if source not in SOURCES:
        raise BadSourceError(
            f"source must be one of {list(SOURCES)}, got {source!r}")
    return source


def _pin(*parts):
    """Digest pin over a domain-separated canonical tuple."""
    return "sha256:" + jcs_sha256_hex({
        "domain": RLAIF_SCHEMA,
        "parts": list(parts),
    })


def _rate_text(matched, total):
    """Agreement rate as exact 'num/den' text (no floats)."""
    frac = Fraction(matched, total)
    return f"{frac.numerator}/{frac.denominator}"


def rlaif_audit_event(kind, detail, seq):
    """Build one ``audit.ndjson/1`` audit row for the RLAIF ledger."""
    if kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    banned = _BANNED_DETAIL_KEYS.intersection(detail.keys())
    if banned:
        raise AuditKindError(
            f"detail keys banned from audit boundary: {sorted(banned)}")
    return {
        "schema": AUDIT_SCHEMA,
        "module": RLAIF_VERSION,
        "kind": kind,
        "seq": seq,
        "detail": dict(detail),
    }


@dataclass(frozen=True)
class SampleRecord:
    """Frozen record of one declared (prompt, output) pair (digests only)."""
    sample_id: str
    prompt_digest: str
    output_digest: str
    seq: int
    digest: str

    def verify(self, sample_id, prompt_digest, output_digest):
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin("sample", sample_id, prompt_digest,
                                   output_digest, self.seq)


@dataclass(frozen=True)
class CritiqueRecord:
    """Frozen record of one AI-declared critique."""
    critique_id: str
    sample_id: str
    # Issues, sorted and deduped.
    issues: Tuple[str, ...]
    verdict: str
    feedback_digest: str
    seq: int
    digest: str

    def verify(self, sample_id, issues, verdict):
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin("critique", self.critique_id, sample_id,
                                   list(issues), verdict, self.seq)


@dataclass(frozen=True)
class PreferenceRecord:
    """Frozen record of one AI-declared pairwise preference label."""
    preference_id: str
    sample_a: str
    sample_b: str
    # Winner in {"a", "b", "tie"}.
    winner: str
    seq: int
    digest: str

    def verify(self, sample_a, sample_b, winner):
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin("preference", self.preference_id,
                                   sample_a, sample_b, winner, self.seq)


@dataclass(frozen=True)
class RewardRecord:
    """Frozen record of one scalar reward decision."""
    reward_id: str
    sample_id: str
    score: float
    source: str
    seq: int
    digest: str

    def verify(self, sample_id, score, source):
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin("reward", self.reward_id, sample_id,
                                   repr(score), source, self.seq)


@dataclass(frozen=True)
class TrainingRecord:
    """Frozen record of one reward-model training step (derived as data)."""
    step_id: str
    # Scored non-tie preference pairs consumed by this step.
    pairs_scored: int
    # Agreement of reward ordering with AI preferences, "num/den" text.
    agreement: str
    # Mean (winner - loser) reward margin, fixed 6-decimal text.
    mean_margin: str
    seq: int
    digest: str

    def verify(self, pairs_scored, agreement, mean_margin):
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin("train", self.step_id, pairs_scored,
                                   agreement, mean_margin, self.seq)


class RLAIF:
    """Deterministic RLAIF (RL from AI feedback) decision ledger.

    All mutations take caller-supplied strictly increasing int seqs,
    are RLock-guarded, and book frozen records with ``sha256:`` digest
    pins plus ``audit.ndjson/1`` rows. No wall-clock, no randomness.
    """

    def __init__(self):
        self._lock = threading.RLock()
        self._samples: Dict[str, SampleRecord] = {}
        self._critiques: Dict[str, CritiqueRecord] = {}
        self._preferences: Dict[str, PreferenceRecord] = {}
        self._rewards: Dict[str, RewardRecord] = {}
        self._trainings: Dict[str, TrainingRecord] = {}
        # Unordered labeled pairs, to refuse duplicate orientations.
        self._labeled_pairs: set = set()
        # Latest reward per sample (max reward counter wins).
        self._latest_reward: Dict[str, str] = {}
        self._critique_counter = 0
        self._preference_counter = 0
        self._reward_counter = 0
        self._train_counter = 0
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
        self._audit.append(rlaif_audit_event(
            KIND_REJECTED, {"error": type(error).__name__}, seq))
        raise error

    def _emit(self, audit_kind, detail, seq):
        self._audit.append(rlaif_audit_event(audit_kind, detail, seq))

    # -- mutations ----------------------------------------------------------

    def sample(self, sample_id, prompt_digest, output_digest, seq):
        """Declare one (prompt, output) pair; digests pin the content."""
        with self._lock:
            seq = self._claim(seq)
            try:
                sample_id = _check_id(sample_id, "sample_id")
                prompt_digest = _check_digest(prompt_digest, "prompt_digest")
                output_digest = _check_digest(output_digest, "output_digest")
                if sample_id in self._samples:
                    raise DuplicateSampleError(
                        f"sample already declared: {sample_id!r}")
            except RLAIFError as e:
                self._burn(seq, e)
            rec = SampleRecord(sample_id=sample_id,
                               prompt_digest=prompt_digest,
                               output_digest=output_digest, seq=seq,
                               digest=_pin("sample", sample_id,
                                           prompt_digest, output_digest,
                                           seq))
            self._samples[sample_id] = rec
            self._last_seq = seq
            # Digests are pins, not raw text: safe on the audit boundary.
            self._emit(KIND_SAMPLE_DECLARED,
                       {"sample_id": sample_id, "digest": rec.digest}, seq)
            return rec

    def critique(self, sample_id, seq, issues=(), feedback_digest="",
                 verdict=VERDICT_NEEDS_REVISION):
        """Book one AI-declared critique (minted ``crit-N`` id)."""
        with self._lock:
            seq = self._claim(seq)
            try:
                sample_id = _check_id(sample_id, "sample_id")
                issues = _check_issues(issues)
                verdict = _check_verdict(verdict)
                feedback_digest = _check_digest(
                    feedback_digest, "feedback_digest", allow_empty=True)
                if sample_id not in self._samples:
                    raise UnknownSampleError(f"unknown sample: {sample_id!r}")
                if not issues and verdict != VERDICT_ACCEPT:
                    raise InconsistentVerdictError(
                        "empty issues require verdict 'accept'")
                if issues and verdict == VERDICT_ACCEPT:
                    raise InconsistentVerdictError(
                        "non-empty issues forbid verdict 'accept'")
            except RLAIFError as e:
                self._burn(seq, e)
            self._critique_counter += 1
            critique_id = f"crit-{self._critique_counter}"
            rec = CritiqueRecord(critique_id=critique_id, sample_id=sample_id,
                                 issues=issues, verdict=verdict,
                                 feedback_digest=feedback_digest, seq=seq,
                                 digest=_pin("critique", critique_id,
                                             sample_id, list(issues),
                                             verdict, seq))
            self._critiques[critique_id] = rec
            self._last_seq = seq
            self._emit(KIND_CRITIQUED,
                       {"critique_id": critique_id, "sample_id": sample_id,
                        "issue_count": len(issues), "verdict": verdict,
                        "digest": rec.digest}, seq)
            return rec

    def prefer(self, sample_a, sample_b, winner, seq):
        """Book one AI-declared pairwise preference (minted ``pref-N``)."""
        with self._lock:
            seq = self._claim(seq)
            try:
                sample_a = _check_id(sample_a, "sample_a")
                sample_b = _check_id(sample_b, "sample_b")
                winner = _check_winner(winner)
                if sample_a == sample_b:
                    raise SelfPairError(
                        f"preference pairs a sample with itself: "
                        f"{sample_a!r}")
                if sample_a not in self._samples:
                    raise UnknownSampleError(
                        f"unknown sample: {sample_a!r}")
                if sample_b not in self._samples:
                    raise UnknownSampleError(
                        f"unknown sample: {sample_b!r}")
                pair = frozenset((sample_a, sample_b))
                if pair in self._labeled_pairs:
                    raise DuplicatePreferenceError(
                        f"pair already labeled: {sample_a!r}, {sample_b!r}")
            except RLAIFError as e:
                self._burn(seq, e)
            self._preference_counter += 1
            preference_id = f"pref-{self._preference_counter}"
            rec = PreferenceRecord(preference_id=preference_id,
                                   sample_a=sample_a, sample_b=sample_b,
                                   winner=winner, seq=seq,
                                   digest=_pin("preference", preference_id,
                                               sample_a, sample_b, winner,
                                               seq))
            self._preferences[preference_id] = rec
            self._labeled_pairs.add(frozenset((sample_a, sample_b)))
            self._last_seq = seq
            self._emit(KIND_PREFERENCE_LABELED,
                       {"preference_id": preference_id,
                        "sample_a": sample_a, "sample_b": sample_b,
                        "winner": winner, "digest": rec.digest}, seq)
            return rec

    def reward(self, sample_id, score, seq, source=SOURCE_AI_JUDGE):
        """Book one scalar reward decision (minted ``rew-N`` id)."""
        with self._lock:
            seq = self._claim(seq)
            try:
                sample_id = _check_id(sample_id, "sample_id")
                score = _check_score(score)
                source = _check_source(source)
                if sample_id not in self._samples:
                    raise UnknownSampleError(f"unknown sample: {sample_id!r}")
            except RLAIFError as e:
                self._burn(seq, e)
            self._reward_counter += 1
            reward_id = f"rew-{self._reward_counter}"
            rec = RewardRecord(reward_id=reward_id, sample_id=sample_id,
                               score=score, source=source, seq=seq,
                               digest=_pin("reward", reward_id, sample_id,
                                           repr(score), source, seq))
            self._rewards[reward_id] = rec
            self._latest_reward[sample_id] = reward_id
            self._last_seq = seq
            self._emit(KIND_REWARD_BOOKED,
                       {"reward_id": reward_id, "sample_id": sample_id,
                        "source": source, "digest": rec.digest}, seq)
            return rec

    def train(self, seq):
        """Book one training step, derived as data (minted ``step-N``).

        Agreement is the fraction of scored non-tie preference pairs
        whose reward ordering matches the AI label; the mean margin
        is the mean (winner - loser) reward difference. Both are
        ledger data about booked values -- no gradient step runs.
        """
        with self._lock:
            seq = self._claim(seq)
            scored = []
            for pref in self._preferences.values():
                if pref.winner == WINNER_TIE:
                    continue
                winner_id = (pref.sample_a if pref.winner == WINNER_A
                             else pref.sample_b)
                loser_id = (pref.sample_b if pref.winner == WINNER_A
                            else pref.sample_a)
                if (winner_id not in self._latest_reward
                        or loser_id not in self._latest_reward):
                    continue
                r_w = self._rewards[self._latest_reward[winner_id]].score
                r_l = self._rewards[self._latest_reward[loser_id]].score
                scored.append((r_w, r_l))
            if not scored:
                self._burn(seq, NoTrainingSignalError(
                    "train() needs at least one scored non-tie "
                    "preference pair"))
            matched = sum(1 for r_w, r_l in scored if r_w > r_l)
            agreement = _rate_text(matched, len(scored))
            mean_margin = sum(r_w - r_l for r_w, r_l in scored) / len(scored)
            mean_margin_text = f"{mean_margin:.6f}"
            self._train_counter += 1
            step_id = f"step-{self._train_counter}"
            rec = TrainingRecord(step_id=step_id, pairs_scored=len(scored),
                                 agreement=agreement,
                                 mean_margin=mean_margin_text, seq=seq,
                                 digest=_pin("train", step_id, len(scored),
                                             agreement, mean_margin_text,
                                             seq))
            self._trainings[step_id] = rec
            self._last_seq = seq
            self._emit(KIND_TRAINED,
                       {"step_id": step_id,
                        "pairs_scored": len(scored),
                        "agreement": agreement,
                        "mean_margin": mean_margin_text,
                        "digest": rec.digest}, seq)
            return rec

    # -- pure read views ------------------------------------------------------

    def sample_record(self, sample_id, seq):
        """Pure read: one sample record (seq validated, never consumed)."""
        with self._lock:
            _check_seq(seq)
            sample_id = _check_id(sample_id, "sample_id")
            return self._samples.get(sample_id)

    def critique_record(self, critique_id, seq):
        """Pure read: one critique record (seq validated, never consumed)."""
        with self._lock:
            _check_seq(seq)
            return self._critiques.get(critique_id)

    def preference_record(self, preference_id, seq):
        """Pure read: one preference record (seq validated, never consumed)."""
        with self._lock:
            _check_seq(seq)
            return self._preferences.get(preference_id)

    def reward_record(self, reward_id, seq):
        """Pure read: one reward record (seq validated, never consumed)."""
        with self._lock:
            _check_seq(seq)
            return self._rewards.get(reward_id)

    def training_record(self, step_id, seq):
        """Pure read: one training record (seq validated, never consumed)."""
        with self._lock:
            _check_seq(seq)
            return self._trainings.get(step_id)

    def sample_ids(self, seq):
        """Pure read: declared sample ids in declaration order."""
        with self._lock:
            _check_seq(seq)
            return tuple(self._samples.keys())

    def latest_reward_id(self, sample_id, seq):
        """Pure read: latest reward id for a sample (or None)."""
        with self._lock:
            _check_seq(seq)
            _check_id(sample_id, "sample_id")
            return self._latest_reward.get(sample_id)

    def stats(self, seq):
        """Pure read: ledger counts as data."""
        with self._lock:
            _check_seq(seq)
            return {
                "samples": len(self._samples),
                "critiques": len(self._critiques),
                "preferences": len(self._preferences),
                "rewards": len(self._rewards),
                "training_steps": len(self._trainings),
                "audit_rows": len(self._audit),
                "last_seq": self._last_seq,
            }

    def audit_log(self, seq):
        """Pure read: the audit rows booked so far (seq validated only)."""
        with self._lock:
            _check_seq(seq)
            return tuple(self._audit)


def main():
    """Self-check: declare, critique, prefer, reward, train."""
    import hashlib as _hashlib

    def _d(tag):
        return "sha256:" + _hashlib.sha256(tag.encode("utf-8")).hexdigest()

    r = RLAIF()
    seq = 0

    def nxt():
        nonlocal seq
        seq += 1
        return seq

    a = r.sample("a", _d("prompt-a"), _d("out-a"), nxt())
    b = r.sample("b", _d("prompt-b"), _d("out-b"), nxt())
    assert a.verify("a", _d("prompt-a"), _d("out-a"))
    c = r.critique("a", nxt(), issues=("factual-error",),
                   feedback_digest=_d("fb-1"))
    assert c.verify("a", ("factual-error",), "needs-revision")
    p = r.prefer("a", "b", "a", nxt())
    assert p.verify("a", "b", "a")
    r1 = r.reward("a", 0.8, nxt())
    r2 = r.reward("b", -0.2, nxt(), source="preference-model")
    assert r1.verify("a", 0.8, "ai-judge")
    assert r2.verify("b", -0.2, "preference-model")
    t = r.train(nxt())
    assert t.verify(1, "1/1", "1.000000")
    # fail-closed spot checks
    for bad in ("", "a b", 123, True):
        try:
            r.sample(bad, _d("x"), _d("y"), nxt())
        except RLAIFError:
            pass
        else:  # pragma: no cover
            raise AssertionError(f"bad sample id accepted: {bad!r}")
    try:
        r.prefer("a", "a", "a", nxt())
    except SelfPairError:
        pass
    else:  # pragma: no cover
        raise AssertionError("self-pair accepted")
    r2 = RLAIF()  # fresh ledger: train() has no signal
    try:
        r2.train(nxt())
    except NoTrainingSignalError:
        pass
    else:  # pragma: no cover
        raise AssertionError("no-signal train accepted")
    assert r.stats(999)["training_steps"] == 1
    print("rlaif OK: sample, critique, prefer, reward, train, pins, audit")


if __name__ == "__main__":  # pragma: no cover
    main()
