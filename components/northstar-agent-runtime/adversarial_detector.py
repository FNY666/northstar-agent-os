"""Adversarial example detector: statistical tripwires for perturbed inputs.

Sits in front of any input the agent did not author itself — tool outputs,
retrieved documents, sensor streams, numeric telemetry — and flags statistical
signatures of adversarial perturbation. Anything that matches is *flagged*,
never silently rewritten: the caller (a gate, an approval queue, the audit
trail) decides what to do with the flag.

Three signal families:

* **HIGH_FREQUENCY_NOISE** — abrupt, decorrelated irregularities. In text:
  control characters (``Cc`` except tab/newline/CR) at suspicious density.
  In numeric sequences: first-difference variance dominating total variance
  (``Var(d)/Var(x) >= 1.5``) — a smooth benign signal has correlated samples;
  adversarial jitter does not.
* **GRADIENT_PATTERN** — coordinated small changes pointing one direction.
  In numeric sequences: sign coherence of first differences ``>= 0.8`` while
  the median step stays tiny relative to the data range (a targeted nudge,
  not a benign ramp). Text has no ordered samples, so this signal is
  sequence-only.
* **IMPERCEPTIBLE_PERTURBATION** — changes invisible to a human reader. In
  text: zero-width / format characters (Unicode ``Cf``: ZWSP, ZWNJ, ZWJ,
  soft hyphen, …) and confusable script-mixing (Cyrillic/Greek look-alikes
  inside Latin text). In numeric sequences: second differences with strong
  negative lag-1 autocorrelation (``< -0.5``) at small RMS (``<= 10%`` of the
  data range) — the fingerprint of tiny alternating perturbations, the
  classic "imperceptible noise" shape. Perturbations below ~0.1% of the
  range are statistically indistinguishable from discretization and are a
  documented blind spot.

API:

* :func:`detect_adversarial` — ``True`` when any signal fires.
* :func:`scan_adversarial` — all findings, in fixed signal order.
* :func:`classify_adversarial` — the most severe signal present
  (gradient > noise > imperceptible), or ``None`` when clean.
* :func:`analyze_input` — full frozen report.
* :func:`adversarial_audit_event` — audit-shaped record for the report.

Inputs: ``str`` (text path) or a list/tuple of real numbers (sequence path).
``detect_adversarial`` never raises on valid input; non-string, non-sequence
input — or a sequence containing bools, NaN, infinities, or non-numbers — is
a programming error and raises ``TypeError``. Empty input is clean by
definition. Sequences shorter than 8 samples are reported clean: the
statistics need a minimum sample to mean anything (documented, not silent).

No wall-clock, no network, no model calls — pure functions of the input.
Deterministic: identical input always yields identical findings.

Honest scope: statistical heuristics are a *tripwire*, not a proof of
adversarial intent. RTL text legitimately uses ``Cf`` marks; scientific
notation and noisy-but-benign sensors can trip the jitter check; a novel
perturbation family passes through. A clean verdict means "no known
perturbation shape", never "input is benign".
"""

from __future__ import annotations

import math
import unicodedata
from collections.abc import Sequence as _Sequence
from dataclasses import dataclass, field
from enum import Enum
from typing import Tuple, Union

#: Version pin for the signal vocabulary, thresholds, and severity precedence.
ADVERSARIAL_DETECTOR_VERSION = "adversarial-detector.v1"

#: Schema pin stamped on findings for audit logging.
SCHEMA_PIN = "northstar.adversarial-detector.v1"


class AdversarialSignal(str, Enum):
    """The three perturbation signal families."""

    HIGH_FREQUENCY_NOISE = "high-frequency-noise"
    GRADIENT_PATTERN = "gradient-pattern"
    IMPERCEPTIBLE_PERTURBATION = "imperceptible-perturbation"


#: Fixed finding order used by :func:`scan_adversarial` (deterministic).
_SIGNAL_ORDER = (
    AdversarialSignal.HIGH_FREQUENCY_NOISE,
    AdversarialSignal.GRADIENT_PATTERN,
    AdversarialSignal.IMPERCEPTIBLE_PERTURBATION,
)

#: Severity precedence used by :func:`classify_adversarial`. A coordinated
#: gradient nudge is the strongest evidence of a *targeted* attack, so it
#: outranks raw noise; imperceptible perturbation is the weakest standalone
#: evidence (highest false-positive surface).
_SEVERITY = (
    AdversarialSignal.GRADIENT_PATTERN,
    AdversarialSignal.HIGH_FREQUENCY_NOISE,
    AdversarialSignal.IMPERCEPTIBLE_PERTURBATION,
)

# ---------------------------------------------------------------------------
# Thresholds (documented constants; see module docstring for rationale)
# ---------------------------------------------------------------------------

_INVISIBLE_DENSITY_THRESHOLD = 0.01   # Cf-char density in text
_CONFUSABLE_RATIO_THRESHOLD = 0.05    # non-ASCII alpha ratio in Latin text
_CONTROL_DENSITY_THRESHOLD = 0.01     # control-char density in text
_MIN_SEQUENCE_SAMPLES = 8             # statistics need a minimum sample
_JITTER_RATIO_THRESHOLD = 1.5         # Var(d)/Var(x) for noise
_COHERENCE_THRESHOLD = 0.8            # |mean(sign(d))| for gradient pattern
_TINY_FRACTION = 0.02                 # "tiny step" as fraction of data range
_D2_RMS_MAX_FRACTION = 0.1            # second-diff RMS ceiling (imperceptible)
_D2_RMS_MIN_FRACTION = 1e-6           # … and floor (excludes float dust)
_D2_AUTOCORR_THRESHOLD = -0.5         # lag-1 autocorrelation of second diffs

# Control characters that are ordinary text formatting, never suspicious.
_FORMAT_CONTROLS = frozenset(("\t", "\n", "\r"))


@dataclass(frozen=True)
class AdversarialFinding:
    """One fired perturbation signal."""

    signal: AdversarialSignal
    score: float  # 0.0-1.0, higher = stronger evidence
    detail: str

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "signal": self.signal.value,
            "score": self.score,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class AdversarialReport:
    """Full scan report for one input."""

    input_kind: str  # "text" or "sequence"
    sample_count: int
    findings: Tuple[AdversarialFinding, ...] = field(default_factory=tuple)

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "detector_version": ADVERSARIAL_DETECTOR_VERSION,
            "input_kind": self.input_kind,
            "sample_count": self.sample_count,
            "flagged": bool(self.findings),
            "findings": [f.as_dict() for f in self.findings],
        }


class AdversarialDetectorError(ValueError):
    """Base class for adversarial-detector input errors. Never raised directly."""


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------

def _validate_sequence(values: _Sequence) -> Tuple[float, ...]:
    """Validate a numeric sequence; raise TypeError on bad elements."""
    out = []
    for i, v in enumerate(values):
        if isinstance(v, bool) or not isinstance(v, (int, float)):
            raise TypeError(
                "sequence element %d must be a real number, got %r" % (i, type(v).__name__)
            )
        if not math.isfinite(v):
            raise TypeError("sequence element %d is not finite: %r" % (i, v))
        out.append(float(v))
    return tuple(out)


def _coerce_input(input_data: Union[str, _Sequence]) -> Tuple[str, Union[str, Tuple[float, ...]]]:
    """Return (kind, normalized value); raise TypeError on bad input."""
    if isinstance(input_data, str):
        return "text", input_data
    if isinstance(input_data, (bytes, bytearray)):
        raise TypeError("bytes input must be decoded to str by the caller")
    if isinstance(input_data, _Sequence):
        return "sequence", _validate_sequence(input_data)
    raise TypeError(
        "input_data must be str or a sequence of real numbers, got %s"
        % type(input_data).__name__
    )


# ---------------------------------------------------------------------------
# Text path
# ---------------------------------------------------------------------------

def _scan_text(text: str) -> Tuple[AdversarialFinding, ...]:
    findings = []
    n = len(text)
    if n == 0:
        return ()

    invisible = sum(1 for ch in text if unicodedata.category(ch) == "Cf")
    inv_density = invisible / n
    if inv_density >= _INVISIBLE_DENSITY_THRESHOLD:
        findings.append(AdversarialFinding(
            signal=AdversarialSignal.IMPERCEPTIBLE_PERTURBATION,
            score=min(1.0, inv_density / 0.05),
            detail="invisible format-char density %.3f (%d/%d); "
                   "zero-width/confusable unicode present" % (inv_density, invisible, n),
        ))

    latin = sum(1 for ch in text if "a" <= ch <= "z" or "A" <= ch <= "Z")
    other_alpha = sum(1 for ch in text if ch.isalpha() and not ("a" <= ch <= "z" or "A" <= ch <= "Z"))
    alpha_total = latin + other_alpha
    if latin >= 10 and alpha_total > 0:
        ratio = other_alpha / alpha_total
        if ratio >= _CONFUSABLE_RATIO_THRESHOLD:
            findings.append(AdversarialFinding(
                signal=AdversarialSignal.IMPERCEPTIBLE_PERTURBATION,
                score=min(1.0, ratio / 0.25),
                detail="script-mixing ratio %.3f (%d non-Latin alpha of %d); "
                       "possible homoglyph substitution" % (ratio, other_alpha, alpha_total),
            ))

    control = sum(
        1 for ch in text
        if unicodedata.category(ch) == "Cc" and ch not in _FORMAT_CONTROLS
    )
    ctrl_density = control / n
    if ctrl_density >= _CONTROL_DENSITY_THRESHOLD:
        findings.append(AdversarialFinding(
            signal=AdversarialSignal.HIGH_FREQUENCY_NOISE,
            score=min(1.0, ctrl_density / 0.05),
            detail="control-char density %.3f (%d/%d); abrupt non-text bytes" % (
                ctrl_density, control, n),
        ))

    return tuple(findings)


# ---------------------------------------------------------------------------
# Sequence path
# ---------------------------------------------------------------------------

def _variance(values: Tuple[float, ...]) -> float:
    mean = sum(values) / len(values)
    return sum((v - mean) ** 2 for v in values) / len(values)


def _lag1_autocorr(values: Tuple[float, ...]) -> float:
    """Lag-1 autocorrelation in [-1, 1]; 0.0 when the series is all zeros."""
    denom = sum(v * v for v in values)
    if denom == 0.0:
        return 0.0
    return sum(values[i] * values[i - 1] for i in range(1, len(values))) / denom


def _rms(values: Tuple[float, ...]) -> float:
    return math.sqrt(sum(v * v for v in values) / len(values))


def _scan_sequence(values: Tuple[float, ...]) -> Tuple[AdversarialFinding, ...]:
    findings = []
    n = len(values)
    if n < _MIN_SEQUENCE_SAMPLES:
        return ()  # documented: statistics need a minimum sample

    data_range = max(values) - min(values)
    if data_range == 0:
        return ()  # constant signal: nothing to perturb

    diffs = tuple(values[i + 1] - values[i] for i in range(n - 1))

    # 1. High-frequency noise: decorrelated jitter.
    var_x = _variance(values)
    if var_x > 0:
        jitter_ratio = _variance(diffs) / var_x
        if jitter_ratio >= _JITTER_RATIO_THRESHOLD:
            findings.append(AdversarialFinding(
                signal=AdversarialSignal.HIGH_FREQUENCY_NOISE,
                score=min(1.0, jitter_ratio / 4.0),
                detail="jitter ratio Var(d)/Var(x)=%.2f >= %.2f; "
                       "samples decorrelated" % (jitter_ratio, _JITTER_RATIO_THRESHOLD),
            ))

    # 2. Gradient pattern: coordinated tiny pushes in one direction.
    signs = tuple(1.0 if d > 0 else -1.0 if d < 0 else 0.0 for d in diffs)
    coherence = abs(sum(signs)) / len(signs)
    median_step = sorted(abs(d) for d in diffs)[len(diffs) // 2]
    if coherence >= _COHERENCE_THRESHOLD and median_step <= _TINY_FRACTION * data_range:
        findings.append(AdversarialFinding(
            signal=AdversarialSignal.GRADIENT_PATTERN,
            score=coherence,
            detail="sign coherence %.2f >= %.2f with median step %.4g "
                   "(tiny vs range %.4g); targeted nudge shape" % (
                       coherence, _COHERENCE_THRESHOLD, median_step, data_range),
        ))

    # 3. Imperceptible perturbation: tiny alternating second differences.
    #    A smooth signal has positively autocorrelated second differences;
    #    small alternating perturbations flip the sign every sample
    #    (lag-1 autocorrelation -> -1) while staying small in RMS.
    if n >= _MIN_SEQUENCE_SAMPLES + 2:
        second = tuple(
            values[i + 1] - 2.0 * values[i] + values[i - 1]
            for i in range(1, n - 1)
        )
        rms_d2 = _rms(second)
        autocorr = _lag1_autocorr(second)
        if (_D2_RMS_MIN_FRACTION * data_range <= rms_d2
                <= _D2_RMS_MAX_FRACTION * data_range
                and autocorr < _D2_AUTOCORR_THRESHOLD):
            findings.append(AdversarialFinding(
                signal=AdversarialSignal.IMPERCEPTIBLE_PERTURBATION,
                score=min(1.0, -autocorr),
                detail="second-diff lag-1 autocorrelation %.2f (< %.2f), "
                       "RMS %.4g (%.1f%% of range); tiny alternating "
                       "perturbation shape" % (
                           autocorr, _D2_AUTOCORR_THRESHOLD, rms_d2,
                           100.0 * rms_d2 / data_range),
            ))

    return tuple(findings)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze_input(input_data: Union[str, _Sequence]) -> AdversarialReport:
    """Scan one input and return the full frozen report."""
    kind, value = _coerce_input(input_data)
    if kind == "text":
        findings = _scan_text(value)  # type: ignore[arg-type]
        count = len(value)  # type: ignore[arg-type]
    else:
        findings = _scan_sequence(value)  # type: ignore[arg-type]
        count = len(value)  # type: ignore[arg-type]
    ordered = tuple(sorted(findings, key=lambda f: _SIGNAL_ORDER.index(f.signal)))
    return AdversarialReport(input_kind=kind, sample_count=count, findings=ordered)


def scan_adversarial(input_data: Union[str, _Sequence]) -> Tuple[AdversarialFinding, ...]:
    """All fired signals, in fixed signal order."""
    return analyze_input(input_data).findings


def detect_adversarial(input_data: Union[str, _Sequence]) -> bool:
    """``True`` when any perturbation signal fires."""
    return bool(scan_adversarial(input_data))


def classify_adversarial(input_data: Union[str, _Sequence]) -> Union[AdversarialSignal, None]:
    """The most severe signal present, or ``None`` when clean."""
    present = {f.signal for f in scan_adversarial(input_data)}
    for signal in _SEVERITY:
        if signal in present:
            return signal
    return None


def adversarial_audit_event(report: AdversarialReport, *, seq: int) -> dict:
    """Audit-shaped record for a scan report. ``seq`` is caller-supplied."""
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise TypeError("seq must be a non-negative int")
    event = report.as_dict()
    event["event"] = "adversarial-scan"
    event["seq"] = seq
    return event


def main() -> None:
    """Self-check: known-bad samples flag, known-good samples pass."""
    zwsp = "price is \u200b\u200b\u200bfinal"
    homoglyph = "admin\u0430ccess granted"  # Cyrillic 'а' inside Latin
    control = "hello\x00\x01world"
    bad = [
        (zwsp, AdversarialSignal.IMPERCEPTIBLE_PERTURBATION),
        (homoglyph, AdversarialSignal.IMPERCEPTIBLE_PERTURBATION),
        (control, AdversarialSignal.HIGH_FREQUENCY_NOISE),
    ]
    # Deterministic pseudo-noise: multiplicative hash -> ~uniform in [0,1).
    noisy = tuple(((i * 2654435761) % 1000) / 1000.0 for i in range(64))
    drift = tuple(100.0 + 0.001 * i for i in range(64))  # tiny monotonic nudge
    import math as _math
    smooth = tuple(_math.sin(2 * _math.pi * i / 32) for i in range(64))
    # Realistic imperceptible attack: +/-1.5% of range alternating noise.
    # (Perturbations below ~0.1% of range are a documented blind spot:
    # statistically indistinguishable from discretization.)
    tiny_noise = tuple(
        _math.sin(2 * _math.pi * i / 32) + (0.03 if i % 2 == 0 else -0.03)
        for i in range(64)
    )
    bad_seq = [
        (noisy, AdversarialSignal.HIGH_FREQUENCY_NOISE),
        (drift, AdversarialSignal.GRADIENT_PATTERN),
        (tiny_noise, AdversarialSignal.IMPERCEPTIBLE_PERTURBATION),
    ]
    good_text = [
        "Please summarize the quarterly report.",
        "Café prices rose 3% this quarter, analysts say.",  # sparse accents
        "line one\nline two\ttabbed",  # formatting controls are fine
    ]
    good_seq = [
        smooth,                      # smooth benign signal
        tuple(float(i) for i in range(32)),  # benign ramp: steps not tiny
        tuple(5.0 for _ in range(16)),       # constant
        (1.0, 2.0, 3.0),                     # too short: insufficient data
    ]
    for text, expected in bad:
        found = classify_adversarial(text)
        assert found is expected, (text.encode("unicode_escape"), found, expected)
        assert detect_adversarial(text)
    for seq_vals, expected in bad_seq:
        found = classify_adversarial(seq_vals)
        assert found is expected, (expected, found)
        assert detect_adversarial(seq_vals)
    for text in good_text:
        assert not detect_adversarial(text), text.encode("unicode_escape")
        assert classify_adversarial(text) is None
    for seq_vals in good_seq:
        assert not detect_adversarial(seq_vals), seq_vals[:4]
        assert classify_adversarial(seq_vals) is None
    print("adversarial-detector OK: %d text / %d sequence attack, %d benign" % (
        len(bad), len(bad_seq), len(good_text) + len(good_seq)))


if __name__ == "__main__":
    main()
