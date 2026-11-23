"""Heuristic + learned spam detection: features, scores, classification, training.

Research basis (second-hand, classic literature):
- Paul Graham, "A Plan for Spam" (2002): per-token Naive Bayes with
  Laplace smoothing over a bag-of-words; tokens never seen before are
  ignored; the posterior is built from summed log-odds through a sigmoid.
  Graham's corpus showed ~99.5% accuracy with < 0.5% false positives.
- SpamAssassin-style heuristic pipelines: fixed, pinned rule sets score
  individual features (ALL-CAPS ratio, punctuation bursts, lure phrases,
  URLs, money symbols, obfuscation tricks) and sum weighted contributions.
  Rules are versioned so drift is detectable.
- Modern consensus (2024-2026): production filters blend the two — a
  learned token model plus a pinned heuristic backstop. Neither proves a
  message is spam in any absolute sense; both are bookkeeping over
  host-reported text.

Design: this is a detector, not a policy. ``train()`` books labeled
examples into a deterministic ledger and updates token statistics;
``score()`` returns a pinned, explainable ``[0, 1]`` score with per-feature
contributions; ``classify()`` applies a caller-supplied threshold and
returns the label as *data*. The gate layer decides what to do.

House style: frozen dataclasses, caller-supplied strictly increasing int
seqs (no wall-clock), RLock-guarded, fail-closed, stdlib-only.

Honest scope: this is deterministic single-host bookkeeping over
host-reported text — a simulated token model plus pinned heuristics, not a
trained production filter. A score means "the pinned features and the
host-supplied training ledger say so", never "this message is objectively
spam" (GIGO boundary). Novel phrasing outside the feature vocabulary is
invisible to the heuristic channel; the Naive Bayes channel only knows the
tokens it was trained on. Scores are not calibrated probabilities.
"""

from __future__ import annotations

import hashlib
import math
import re
import threading
from dataclasses import dataclass
from typing import Any, Mapping, Optional, Sequence

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except Exception:  # pragma: no cover - module must stay importable standalone
    import json as _json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("utf-8")


#: Module version.
SPAM_DETECTOR_VERSION = "spam-detector.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.spam-detector.v1"

#: Fixed audit vocabulary.
_AUDIT_KINDS = (
    "detector-created",
    "scored",
    "classified",
    "trained",
    "rejected",
)

#: Guardrail: max text bytes accepted by score/classify/train (1 MiB).
_MAX_TEXT_BYTES = 1024 * 1024

#: Guardrail: max distinct tokens processed per text.
_MAX_TOKENS = 10_000

#: Guardrail: tokens longer than this are dropped from the token stream.
_MAX_TOKEN_LEN = 64

#: Pinned class labels.
_LABELS = ("spam", "ham")

#: Pinned blend: learned token model vs heuristic backstop.
_NB_WEIGHT = 0.5
_HEURISTIC_WEIGHT = 0.5

#: Pinned heuristic feature weights (sum to 1.0).
_FEATURE_WEIGHTS = {
    "caps-ratio": 0.15,
    "punct-burst": 0.15,
    "lure-words": 0.30,
    "urls": 0.15,
    "money-symbols": 0.10,
    "obfuscation": 0.15,
}

#: Pinned lure-word vocabulary (single tokens, high precision).
_LURE_WORDS = (
    "viagra", "cialis", "lottery", "casino", "pharmacy", "pills",
    "mortgage", "refinance", "bitcoin", "nigerian", "inheritance",
    "congratulations", "guaranteed", "unsubscribe", "xxx", "sweepstakes",
)

#: Pinned lure-phrase vocabulary (case-insensitive substrings).
_LURE_PHRASES = (
    "click here", "act now", "limited time", "lose weight",
    "make money", "work from home", "no credit check", "risk free",
    "double your", "million dollars", "dear friend", "urgent response",
)

_URL_RE = re.compile(r"https?://[^\s<>\"']+|www\.[^\s<>\"']+", re.IGNORECASE)
_MONEY_RE = re.compile(r"[$€£¥]\s?\d|\d+\s?(?:usd|dollars?)\b", re.IGNORECASE)
_TOKEN_RE = re.compile(r"[a-z0-9]+")
_ZW_RE = re.compile(r"[\u200b-\u200d\ufeff]")
_SPACED_RE = re.compile(r"\b(?:[A-Za-z]\s){2,}[A-Za-z]\b")
_PUNCT_BURST_RE = re.compile(r"[!?]{2,}")


class SpamError(Exception):
    """Base fail-closed error for the spam detector."""


class BadTextError(SpamError):
    """Raised for malformed text input (not a string, empty, over guardrail)."""


class BadLabelError(SpamError):
    """Raised for labels outside the pinned vocabulary."""


class BadThresholdError(SpamError):
    """Raised for thresholds outside the open interval (0, 1)."""


class UnknownExampleError(SpamError):
    """Raised when a training example id is not in the ledger."""


class SeqOrderError(SpamError):
    """Raised when a caller seq does not strictly increase."""


def _check_seq(value: Any, name: str = "seq") -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise SpamError(f"{name} must be an int, got {type(value).__name__}")
    if value < 0:
        raise SpamError(f"{name} must be non-negative")
    return value


def _check_text(text: Any) -> str:
    if not isinstance(text, str):
        raise BadTextError(f"text must be a str, got {type(text).__name__}")
    if not text.strip():
        raise BadTextError("text must not be empty or whitespace-only")
    if len(text.encode("utf-8")) > _MAX_TEXT_BYTES:
        raise BadTextError("text exceeds 1 MiB guardrail")
    return text


def _check_label(label: Any) -> str:
    if label not in _LABELS:
        raise BadLabelError(
            f"label must be one of {_LABELS}, got {label!r}"
        )
    return label


def _check_threshold(value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise BadThresholdError(
            f"threshold must be a number, got {type(value).__name__}"
        )
    if not math.isfinite(value) or not 0.0 < value < 1.0:
        raise BadThresholdError(
            f"threshold must be in the open interval (0, 1), got {value!r}"
        )
    return float(value)


def _digest(obj: Any) -> str:
    return "sha256:" + hashlib.sha256(jcs_canonical_json(obj)).hexdigest()


def _text_digest(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def _tokenize(text: str) -> tuple:
    """Lowercase alphanumeric token stream (deterministic, length-capped)."""
    tokens = _TOKEN_RE.findall(text.lower())
    kept = [t for t in tokens if len(t) <= _MAX_TOKEN_LEN]
    if len(set(kept)) > _MAX_TOKENS:
        raise BadTextError("distinct token count exceeds guardrail")
    return tuple(kept)


def _clamp01(value: float) -> float:
    return max(0.0, min(1.0, value))


def _sigmoid(x: float) -> float:
    if x >= 700.0:
        return 1.0
    if x <= -700.0:
        return 0.0
    return 1.0 / (1.0 + math.exp(-x))


# --------------------------------------------------------------------------
# Heuristic features. Each returns a value in [0, 1]; the heuristic score is
# the pinned-weight dot product. Features are deterministic and cheap.
# --------------------------------------------------------------------------

def _f_caps_ratio(text: str) -> float:
    letters = [c for c in text if c.isalpha()]
    if not letters:
        return 0.0
    ratio = sum(1 for c in letters if c.isupper()) / len(letters)
    return _clamp01((ratio - 0.30) / 0.70)


def _f_punct_burst(text: str) -> float:
    runs = [len(m.group(0)) for m in _PUNCT_BURST_RE.finditer(text)]
    longest = max(runs, default=0)
    return _clamp01((longest - 2) / 4.0)


def _f_lure_words(text: str, tokens: tuple) -> float:
    lowered = text.lower()
    token_set = set(tokens)
    word_hits = sum(1 for w in _LURE_WORDS if w in token_set)
    phrase_hits = sum(1 for p in _LURE_PHRASES if p in lowered)
    return _clamp01((word_hits + phrase_hits) / 5.0)


def _f_urls(text: str) -> float:
    return _clamp01(len(_URL_RE.findall(text)) / 3.0)


def _f_money_symbols(text: str) -> float:
    return _clamp01(len(_MONEY_RE.findall(text)) / 4.0)


def _f_obfuscation(text: str, tokens: tuple) -> float:
    signals = len(_ZW_RE.findall(text))
    signals += len(_SPACED_RE.findall(text))
    signals += sum(
        1
        for t in set(tokens)
        if len(t) > 3
        and re.search(r"[a-z]", t)
        and re.search(r"[0-9]", t)
    )
    return _clamp01(signals / 3.0)


@dataclass(frozen=True)
class Contribution:
    """One pinned score contribution."""

    component: str  # "heuristic" or "naive-bayes"
    feature: str
    value: float
    weight: float

    def as_dict(self) -> dict:
        return {
            "component": self.component,
            "feature": self.feature,
            "value": self.value,
            "weight": self.weight,
        }


@dataclass(frozen=True)
class ScoreReport:
    """Pinned result of score(): explainable [0, 1] spam score."""

    text_digest: str
    score: float
    naive_bayes: float
    heuristic_score: float
    trained: bool
    contributions: tuple
    seq: int
    report_digest: str
    version: str = SPAM_DETECTOR_VERSION
    schema: str = SCHEMA_PIN

    def verify(self) -> bool:
        """Re-derive the report digest from its contents."""
        body = {
            "report_seq": self.seq,
            "text_digest": self.text_digest,
            "version": self.version,
            "score": self.score,
            "naive_bayes": self.naive_bayes,
            "heuristic_score": self.heuristic_score,
            "trained": self.trained,
            "contributions": [c.as_dict() for c in self.contributions],
        }
        return _digest(body) == self.report_digest

    def as_dict(self) -> dict:
        return {
            "text_digest": self.text_digest,
            "score": self.score,
            "naive_bayes": self.naive_bayes,
            "heuristic_score": self.heuristic_score,
            "trained": self.trained,
            "contributions": [c.as_dict() for c in self.contributions],
            "seq": self.seq,
            "report_digest": self.report_digest,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class Classification:
    """Pinned result of classify(): threshold-applied label as data."""

    label: str
    score: float
    threshold: float
    text_digest: str
    seq: int
    report_digest: str
    version: str = SPAM_DETECTOR_VERSION
    schema: str = SCHEMA_PIN

    def verify(self) -> bool:
        """Re-derive the report digest from its contents."""
        body = {
            "report_seq": self.seq,
            "text_digest": self.text_digest,
            "version": self.version,
            "label": self.label,
            "score": self.score,
            "threshold": self.threshold,
        }
        return _digest(body) == self.report_digest

    def as_dict(self) -> dict:
        return {
            "label": self.label,
            "score": self.score,
            "threshold": self.threshold,
            "text_digest": self.text_digest,
            "seq": self.seq,
            "report_digest": self.report_digest,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class TrainingRecord:
    """Pinned ledger entry for one train() call."""

    example_id: str
    text_digest: str
    label: str
    tokens: tuple
    seq: int
    record_digest: str
    version: str = SPAM_DETECTOR_VERSION
    schema: str = SCHEMA_PIN

    def verify(self) -> bool:
        """Re-derive the record digest from its contents."""
        body = {
            "record_seq": self.seq,
            "example_id": self.example_id,
            "text_digest": self.text_digest,
            "version": self.version,
            "label": self.label,
            "tokens": list(self.tokens),
        }
        return _digest(body) == self.record_digest

    def as_dict(self) -> dict:
        return {
            "example_id": self.example_id,
            "text_digest": self.text_digest,
            "label": self.label,
            "tokens": list(self.tokens),
            "seq": self.seq,
            "record_digest": self.record_digest,
            "version": self.version,
            "schema": self.schema,
        }


class SpamDetector:
    """Heuristic + learned spam scoring over host-reported text.

    ``train()`` books labeled examples and updates the token ledger;
    ``score()`` blends the Naive Bayes token posterior with the pinned
    heuristic features; ``classify()`` applies a caller threshold.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq = -1
        self._example_count = 0
        self._spam_examples = 0
        self._ham_examples = 0
        self._spam_tokens: dict = {}
        self._ham_tokens: dict = {}
        self._records: dict = {}

    # -- views ------------------------------------------------------------

    def stats(self) -> dict:
        """Return training-ledger stats (pure view, no seq consumed)."""
        with self._lock:
            return {
                "examples": self._example_count,
                "spam_examples": self._spam_examples,
                "ham_examples": self._ham_examples,
                "vocab_size": len(
                    set(self._spam_tokens) | set(self._ham_tokens)
                ),
                "last_seq": self._last_seq,
                "version": SPAM_DETECTOR_VERSION,
                "schema": SCHEMA_PIN,
            }

    def token_stats(self, token: Any) -> Optional[dict]:
        """Return Laplace-smoothed P(spam | token), or None if unseen."""
        with self._lock:
            if not isinstance(token, str) or not token:
                raise BadTextError("token must be a non-empty str")
            key = token.lower()
            spam_c = self._spam_tokens.get(key, 0)
            ham_c = self._ham_tokens.get(key, 0)
            if spam_c + ham_c == 0:
                return None
            return {
                "token": key,
                "spam_count": spam_c,
                "ham_count": ham_c,
                "p_spam_given_token": (spam_c + 1) / (spam_c + ham_c + 2),
            }

    def training_record(self, example_id: Any) -> TrainingRecord:
        """Return one training record by id (pure view)."""
        with self._lock:
            if example_id not in self._records:
                raise UnknownExampleError(
                    f"unknown example id {example_id!r}"
                )
            return self._records[example_id]

    def _monotonic(self, seq: int) -> int:
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq must strictly increase (last={self._last_seq}, got={seq})"
            )
        self._last_seq = seq
        return seq

    # -- internals --------------------------------------------------------

    def _heuristic(self, text: str, tokens: tuple) -> tuple:
        """Return (heuristic_score, contributions) for pinned features."""
        values = {
            "caps-ratio": _f_caps_ratio(text),
            "punct-burst": _f_punct_burst(text),
            "lure-words": _f_lure_words(text, tokens),
            "urls": _f_urls(text),
            "money-symbols": _f_money_symbols(text),
            "obfuscation": _f_obfuscation(text, tokens),
        }
        contributions = tuple(
            Contribution(
                component="heuristic",
                feature=name,
                value=values[name],
                weight=_FEATURE_WEIGHTS[name],
            )
            for name in sorted(values)
        )
        score = sum(
            _FEATURE_WEIGHTS[name] * values[name] for name in values
        )
        return _clamp01(score), contributions

    def _naive_bayes(self, tokens: tuple) -> tuple:
        """Return (posterior, trained_flag) via summed log-odds + sigmoid."""
        if self._example_count == 0:
            return 0.5, False
        log_odds = 0.0
        for token in set(tokens):
            spam_c = self._spam_tokens.get(token, 0)
            ham_c = self._ham_tokens.get(token, 0)
            if spam_c + ham_c == 0:
                continue
            p = (spam_c + 1) / (spam_c + ham_c + 2)
            log_odds += math.log(p / (1.0 - p))
        return _clamp01(_sigmoid(log_odds)), True

    def _evaluate(self, text: str) -> tuple:
        """Compute (score, nb, heuristic, contributions, trained)."""
        tokens = _tokenize(text)
        hscore, hcontribs = self._heuristic(text, tokens)
        nb, trained = self._naive_bayes(tokens)
        nb_contrib = Contribution(
            component="naive-bayes",
            feature="token-log-odds",
            value=nb,
            weight=_NB_WEIGHT,
        )
        all_contribs = tuple(sorted(
            (nb_contrib,) + hcontribs, key=lambda c: c.feature
        ))
        score = _clamp01(_NB_WEIGHT * nb + _HEURISTIC_WEIGHT * hscore)
        return score, nb, hscore, trained, all_contribs

    # -- training ----------------------------------------------------------

    def train(self, text: Any, label: Any, seq: Any) -> TrainingRecord:
        """Book a labeled example; update token statistics; pin a record."""
        with self._lock:
            text = _check_text(text)
            seq = _check_seq(seq)
            self._monotonic(seq)
            label = _check_label(label)
            tokens = _tokenize(text)
            self._example_count += 1
            example_id = f"ex-{self._example_count}"
            if label == "spam":
                self._spam_examples += 1
                for token in set(tokens):
                    self._spam_tokens[token] = (
                        self._spam_tokens.get(token, 0) + 1
                    )
            else:
                self._ham_examples += 1
                for token in set(tokens):
                    self._ham_tokens[token] = (
                        self._ham_tokens.get(token, 0) + 1
                    )
            unique_tokens = tuple(sorted(set(tokens)))
            body = {
                "record_seq": seq,
                "example_id": example_id,
                "text_digest": _text_digest(text),
                "version": SPAM_DETECTOR_VERSION,
                "label": label,
                "tokens": list(unique_tokens),
            }
            record = TrainingRecord(
                example_id=example_id,
                text_digest=_text_digest(text),
                label=label,
                tokens=unique_tokens,
                seq=seq,
                record_digest=_digest(body),
            )
            self._records[example_id] = record
            return record

    # -- scoring / classification -------------------------------------------

    def score(self, text: Any, seq: Any) -> ScoreReport:
        """Score host-reported text; return a pinned, explainable report."""
        with self._lock:
            text = _check_text(text)
            seq = _check_seq(seq)
            self._monotonic(seq)
            score, nb, hscore, trained, contribs = self._evaluate(text)
            body = {
                "report_seq": seq,
                "text_digest": _text_digest(text),
                "version": SPAM_DETECTOR_VERSION,
                "score": score,
                "naive_bayes": nb,
                "heuristic_score": hscore,
                "trained": trained,
                "contributions": [c.as_dict() for c in contribs],
            }
            return ScoreReport(
                text_digest=_text_digest(text),
                score=score,
                naive_bayes=nb,
                heuristic_score=hscore,
                trained=trained,
                contributions=contribs,
                seq=seq,
                report_digest=_digest(body),
            )

    def classify(
        self, text: Any, seq: Any, threshold: Any = 0.5
    ) -> Classification:
        """Classify text against a caller-supplied threshold; label is data."""
        with self._lock:
            text = _check_text(text)
            seq = _check_seq(seq)
            self._monotonic(seq)
            threshold = _check_threshold(threshold)
            score, _nb, _hscore, _trained, _contribs = self._evaluate(text)
            label = "spam" if score >= threshold else "ham"
            body = {
                "report_seq": seq,
                "text_digest": _text_digest(text),
                "version": SPAM_DETECTOR_VERSION,
                "label": label,
                "score": score,
                "threshold": threshold,
            }
            return Classification(
                label=label,
                score=score,
                threshold=threshold,
                text_digest=_text_digest(text),
                seq=seq,
                report_digest=_digest(body),
            )


def spam_detector_audit_event(kind: str, seq: int, **detail: Any) -> dict:
    """Shape an ``audit.ndjson/1`` record for spam detector activity.

    The audit boundary carries ids, digests, scores, and labels only —
    message text never crosses it.
    """
    if kind not in _AUDIT_KINDS:
        raise SpamError(f"unknown audit kind {kind!r}")
    seq = _check_seq(seq)
    event: dict = {
        "schema": "audit.ndjson/1",
        "event": kind,
        "audit_seq": seq,
        "module_version": SPAM_DETECTOR_VERSION,
        "module_schema": SCHEMA_PIN,
    }
    for key, value in detail.items():
        if isinstance(value, (str, bool)) or value is None:
            event[key] = value
        elif isinstance(value, int):
            if abs(value) > 2 ** 53:
                raise SpamError(
                    "int magnitude beyond 2**53 refused (JCS float-loss caveat)"
                )
            event[key] = value
        elif isinstance(value, float):
            if not math.isfinite(value):
                raise SpamError("non-finite float refused in audit detail")
            event[key] = value
        else:
            event[key] = jcs_canonical_json({"v": value}).decode("utf-8")
    return event


def main() -> None:
    """Self-check: train, score, classify, pins, refusals, audit."""
    detector = SpamDetector()
    assert detector.stats()["examples"] == 0
    assert detector.stats()["last_seq"] == -1

    spam_a = "WINNER! You won the lottery! Claim your FREE prize now!!!"
    spam_b = "Cheap viagra cialis pharmacy pills, click here for discount!"
    ham_a = "Hi, are we still on for lunch tomorrow? Let me know."
    ham_b = "The meeting notes are attached. Please review when you can."

    r1 = detector.train(spam_a, "spam", 0)
    r2 = detector.train(spam_b, "spam", 1)
    r3 = detector.train(ham_a, "ham", 2)
    r4 = detector.train(ham_b, "ham", 3)
    for rec, eid in ((r1, "ex-1"), (r2, "ex-2"), (r3, "ex-3"), (r4, "ex-4")):
        assert rec.verify(), rec.as_dict()
        assert rec.example_id == eid, rec.as_dict()
    stats = detector.stats()
    assert stats["examples"] == 4, stats
    assert stats["spam_examples"] == 2, stats
    assert stats["ham_examples"] == 2, stats
    assert stats["vocab_size"] > 0, stats

    ts = detector.token_stats("viagra")
    assert ts is not None and ts["p_spam_given_token"] > 0.5, ts
    assert detector.token_stats("meeting")["p_spam_given_token"] < 0.5
    assert detector.token_stats("never-seen-token") is None

    loud = (
        "CONGRATULATIONS!!! You are a WINNER! Claim your FREE lottery "
        "prize now!!! Click here http://spam.example/win $$$1000000"
    )
    report = detector.score(loud, 4)
    assert report.verify(), report.as_dict()
    assert report.trained is True
    assert 0.0 <= report.score <= 1.0
    assert report.score >= 0.5, report.as_dict()
    feats = [c.feature for c in report.contributions]
    assert feats == sorted(feats), feats
    assert any(
        c.component == "naive-bayes" for c in report.contributions
    )

    cls = detector.classify(loud, 5)
    assert cls.verify(), cls.as_dict()
    assert cls.label == "spam", cls.as_dict()
    assert cls.threshold == 0.5

    cls_ham = detector.classify(
        "Thanks for the update, I'll check the report tonight.", 6
    )
    assert cls_ham.verify()
    assert cls_ham.label == "ham", cls_ham.as_dict()

    # A very high threshold flips the spam label: threshold is policy.
    cls_strict = detector.classify(loud, 7, threshold=0.99)
    assert cls_strict.label == "ham", cls_strict.as_dict()

    # Refusals (failed calls burn their seq, per ledger discipline).
    try:
        detector.train(spam_a, "junk", 8)
        raise AssertionError("bad label must raise")
    except BadLabelError:
        pass
    try:
        detector.train("", "spam", 9)
        raise AssertionError("empty text must raise")
    except BadTextError:
        pass
    try:
        detector.score(ham_a, 7)  # rewind: last consumed seq is 9
        raise AssertionError("seq rewind must raise")
    except SeqOrderError:
        pass
    try:
        detector.classify(ham_a, 10, threshold=0.0)
        raise AssertionError("threshold 0 must raise")
    except BadThresholdError:
        pass
    try:
        detector.classify(ham_a, 11, threshold=1.5)
        raise AssertionError("threshold >1 must raise")
    except BadThresholdError:
        pass
    try:
        detector.classify(ham_a, 12, threshold=True)
        raise AssertionError("bool threshold must raise")
    except BadThresholdError:
        pass
    try:
        detector.training_record("ex-999")
        raise AssertionError("unknown example must raise")
    except UnknownExampleError:
        pass

    # Audit shapes.
    ev = spam_detector_audit_event(
        "scored", 0, text_digest=report.text_digest, score=report.score
    )
    assert ev["schema"] == "audit.ndjson/1"
    assert ev["module_version"] == SPAM_DETECTOR_VERSION
    assert ev["score"] == report.score
    try:
        spam_detector_audit_event("nope", 1)
        raise AssertionError("unknown audit kind must raise")
    except SpamError:
        pass

    # Determinism across instances with identical training.
    other = SpamDetector()
    other.train(spam_a, "spam", 0)
    other.train(spam_b, "spam", 1)
    other.train(ham_a, "ham", 2)
    other.train(ham_b, "ham", 3)
    rep2 = other.score(loud, 4)
    assert rep2.score == report.score, (rep2.score, report.score)
    assert rep2.report_digest == report.report_digest

    print(
        "spam-detector OK: train, score, classify, pins, refusals, audit, "
        "determinism"
    )


if __name__ == "__main__":
    main()
