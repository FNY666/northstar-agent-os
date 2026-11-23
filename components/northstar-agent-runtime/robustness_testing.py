"""Robustness testing (perturb/stress/score) interface, simulated.

Research motivation: robustness evaluation -- TextFooler-style
adversarial perturbations, CheckList-style behavioral probes,
stress tests with synthetic noise -- asks one question: how much
does declared performance degrade when the input is perturbed?
The discipline that keeps this honest is bookkeeping: declare the
target, declare each perturbation op deterministically, book the
host-reported scores for base and perturbed runs as data, and
derive the drop statistics as data too. A robustness "score" is
ledger arithmetic on host-reported numbers, never a measured
certificate.

This module is the *decision ledger* half of that shape:

- ``RobustnessTesting.target(target_id, seq)`` -- declare the model
  or system under test. Returns a frozen ``TargetRecord`` with a
  ``sha256:`` digest pin. Duplicate ids are refused fail-closed;
  ids are never recycled.
- ``RobustnessTesting.perturb(target_id, op, seq, magnitude=0.1, mapping=None)``
  -- declare one perturbation op against a target. Returns a
  frozen ``PerturbationRecord`` with a minted ``pert-N`` id. The
  op vocabulary is pinned (``typo`` / ``synonym`` / ``truncate`` /
  ``shuffle`` / ``noise`` / ``case``); magnitude is a float in
  (0, 1]; ``synonym`` requires a host-supplied word mapping
  (host-reported, digest-pinned).
- ``apply_perturbation(text, op, magnitude, mapping=None)`` -- pure
  deterministic transform implementing the op recipe on text (no
  ledger, no seq): the *recipe* is pinned so any host can replay
  the same perturbation byte-identically.
- ``RobustnessTesting.stress(pert_id, base, perturbed, seq)`` --
  book one stress trial: the host-reported base score and the
  host-reported perturbed score (floats in [0, 1]). The drop
  (``base - perturbed``) is derived as *data* -- negative drops
  (perturbation helped) are data too, never raised.
- ``RobustnessTesting.score(target_id, seq)`` -- aggregate all
  booked trials for the target into a frozen ``ScoreReport``:
  per-op mean drops, worst drop, and a ``robustness`` index of
  ``1 - mean_drop`` with a verdict (``robust`` / ``borderline`` /
  ``fragile``) as data. Refuses fail-closed when no trials exist.
- ``robustness_testing_audit_event(kind, ...)`` --
  ``audit.ndjson/1`` records (``target-registered`` / ``perturbed``
  / ``stressed`` / ``scored`` / ``rejected``); caller-supplied
  seqs only. Raw scores, texts, and mappings never cross the
  audit boundary -- audit rows carry ids, counts, and digest
  pins only.

Fail-closed edges (fail loudly, never guess):

- ``target_id`` / ``pert_id`` must be non-empty str, <= 256 chars,
  no whitespace.
- ``op`` must name the pinned vocabulary; unknown ops raise
  ``BadOpError``.
- ``magnitude`` must be a finite float with 0 < magnitude <= 1
  (bool refused).
- ``synonym`` requires ``mapping``: a non-empty dict of non-empty
  str -> non-empty str; other ops refuse a non-empty mapping.
- ``base`` / ``perturbed`` must be finite floats in [0, 1] (ints
  0/1 accepted as float; bool, NaN, inf, out-of-range refused).
- ``score()`` on a target with no booked trials raises
  ``NoTrialsError``.
- Seqs are ints (not bool), >= 0, strictly increasing per
  instance. Failed mutations consume their seq and book a
  ``rejected`` audit row; seq rewinds raise bare ``SeqOrderError``
  without consuming.

Honest scope:

- This module books *declared* targets, *declared* perturbation
  configs, and *host-reported* scores. A booked score is a ledger
  entry, not a verified measurement -- scores are GIGO: the
  module cannot prove the host ran the target or measured
  honestly.
- ``apply_perturbation()`` is a deterministic text recipe
  (truncate, hash-keyed shuffle, seeded typo swaps, case flips,
  filler noise, host-mapping substitution). It is bookkeeping
  fidelity, not a claim that these perturbations are realistic
  adversarial examples.
- ``score()`` derives arithmetic (mean/worst drop, robustness
  index) from booked trials; the verdict thresholds are pinned
  constants, documented as ledger policy, not safety claims.
- No persistence: the ledger is in-memory. Pair with the durable
  audit writer if robustness state must survive a restart.
"""

from __future__ import annotations

import hashlib
import math
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json, jcs_sha256_hex
except Exception:  # pragma: no cover - module must stay importable standalone
    import json as _json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("utf-8")

    def jcs_sha256_hex(obj: Any) -> str:  # type: ignore[no-redef]
        return hashlib.sha256(jcs_canonical_json(obj)).hexdigest()


#: Version pin for this module's record shape.
ROBUSTNESS_TESTING_VERSION = "robustness-testing.v1"

#: Schema pin carried by records and audit events.
ROBUSTNESS_TESTING_SCHEMA = "northstar.robustness-testing.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Audit event kinds.
KIND_TARGET_REGISTERED = "target-registered"
KIND_PERTURBED = "perturbed"
KIND_STRESSED = "stressed"
KIND_SCORED = "scored"
KIND_REJECTED = "rejected"
_KINDS = (KIND_TARGET_REGISTERED, KIND_PERTURBED, KIND_STRESSED,
          KIND_SCORED, KIND_REJECTED)

#: Detail keys banned from the audit boundary (raw data never crosses it).
_BANNED_DETAIL_KEYS = frozenset(
    {"base", "perturbed", "score", "text", "mapping", "value",
     "payload", "raw", "drop", "output"})

#: Max id length.
_MAX_ID_LEN = 256

#: Pinned perturbation-op vocabulary.
_OPS = ("typo", "synonym", "truncate", "shuffle", "noise", "case")

#: Verdict thresholds on the robustness index (ledger policy, not a claim).
_ROBUST_AT = 0.90
_BORDERLINE_AT = 0.75

#: Filler words for the ``noise`` op recipe.
_NOISE_FILLERS = ("um", "uh", "like", "you-know")


class RobustnessTestingError(Exception):
    """Base error for the robustness testing ledger (programming errors)."""


class BadTargetError(RobustnessTestingError):
    """Raised when a target id is malformed."""


class DuplicateTargetError(RobustnessTestingError):
    """Raised when a target id is registered twice."""


class UnknownTargetError(RobustnessTestingError):
    """Raised when a target id names no declared target."""


class BadOpError(RobustnessTestingError):
    """Raised when a perturbation op is not in the pinned vocabulary."""


class BadMagnitudeError(RobustnessTestingError):
    """Raised when magnitude is not a finite float in (0, 1]."""


class BadMappingError(RobustnessTestingError):
    """Raised when a synonym mapping is malformed or misplaced."""


class UnknownPerturbationError(RobustnessTestingError):
    """Raised when a pert id names no booked perturbation."""


class BadScoreError(RobustnessTestingError):
    """Raised when a host-reported score is not a finite float in [0, 1]."""


class NoTrialsError(RobustnessTestingError):
    """Raised when score() finds no booked stress trials for the target."""


class SeqOrderError(RobustnessTestingError):
    """Raised when a seq is malformed or not strictly increasing."""


class AuditKindError(RobustnessTestingError):
    """Raised when an audit event kind is unknown or leaks banned keys."""


def _check_seq(value: object, name: str = "seq") -> int:
    """Validate a caller-supplied ordering seq: int, not bool, >= 0."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise SeqOrderError(f"{name} must be int, got {type(value).__name__}")
    if value < 0:
        raise SeqOrderError(f"{name} must be >= 0, got {value}")
    return value


def _check_id(value: object, name: str) -> str:
    """Validate an id: non-empty str, no whitespace, <= 256 chars."""
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadTargetError(f"{name} must be str, got {type(value).__name__}")
    if not value:
        raise BadTargetError(f"{name} must not be empty")
    if len(value) > _MAX_ID_LEN:
        raise BadTargetError(f"{name} too long (>{_MAX_ID_LEN} chars)")
    if any(ch.isspace() for ch in value):
        raise BadTargetError(f"{name} must not contain whitespace")
    return value


def _check_op(op: object) -> str:
    """Validate a perturbation op against the pinned vocabulary."""
    if isinstance(op, bool) or not isinstance(op, str):
        raise BadOpError(f"op must be str, got {type(op).__name__}")
    if op not in _OPS:
        raise BadOpError(f"unknown op {op!r}; pinned vocabulary: {list(_OPS)}")
    return op


def _check_magnitude(value: object) -> float:
    """Validate magnitude: finite float with 0 < magnitude <= 1."""
    if isinstance(value, bool):
        raise BadMagnitudeError("magnitude must not be bool")
    if isinstance(value, int):
        value = float(value)
    if not isinstance(value, float):
        raise BadMagnitudeError(
            f"magnitude must be float, got {type(value).__name__}")
    if not math.isfinite(value):
        raise BadMagnitudeError(f"magnitude must be finite, got {value!r}")
    if not 0.0 < value <= 1.0:
        raise BadMagnitudeError(
            f"magnitude must satisfy 0 < m <= 1, got {value!r}")
    return value


def _check_mapping(mapping: object, op: str) -> Optional[Tuple[Tuple[str, str], ...]]:
    """Validate the host-supplied synonym mapping (pinned, digest-only).

    ``synonym`` requires a non-empty dict of non-empty str -> non-empty
    str. All other ops refuse a non-empty mapping fail-closed.
    """
    if op == "synonym":
        if not isinstance(mapping, dict) or not mapping:
            raise BadMappingError(
                "synonym requires a non-empty dict mapping")
        pairs = []
        for key, val in mapping.items():
            if (isinstance(key, bool) or not isinstance(key, str)
                    or not key):
                raise BadMappingError("mapping keys must be non-empty str")
            if (isinstance(val, bool) or not isinstance(val, str)
                    or not val):
                raise BadMappingError("mapping values must be non-empty str")
            pairs.append((key, val))
        return tuple(sorted(pairs))
    if mapping:
        raise BadMappingError(
            f"mapping only valid for synonym, not {op!r}")
    return None


def _check_score(value: object, name: str) -> float:
    """Validate a host-reported score: finite float in [0, 1]."""
    if isinstance(value, bool):
        raise BadScoreError(f"{name} must not be bool")
    if isinstance(value, int):
        value = float(value)
    if not isinstance(value, float):
        raise BadScoreError(
            f"{name} must be float, got {type(value).__name__}")
    if not math.isfinite(value):
        raise BadScoreError(f"{name} must be finite, got {value!r}")
    if not 0.0 <= value <= 1.0:
        raise BadScoreError(f"{name} must be in [0, 1], got {value!r}")
    return value


def _pin(*parts: object) -> str:
    """Digest pin over a domain-separated canonical tuple."""
    return "sha256:" + jcs_sha256_hex({
        "domain": ROBUSTNESS_TESTING_SCHEMA,
        "parts": list(parts),
    })


def _mapping_pin(pairs: Optional[Tuple[Tuple[str, str], ...]]) -> str:
    """Pin the (possibly absent) synonym mapping by digest."""
    if pairs is None:
        return _pin("mapping", None)
    return _pin("mapping", [[k, v] for k, v in pairs])


def robustness_testing_audit_event(kind: str, detail: Dict[str, object],
                                   seq: object) -> Dict[str, object]:
    """Build one ``audit.ndjson/1`` audit row for the robustness ledger."""
    if kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    banned = _BANNED_DETAIL_KEYS.intersection(detail.keys())
    if banned:
        raise AuditKindError(
            f"detail keys banned from audit boundary: {sorted(banned)}")
    return {
        "schema": AUDIT_SCHEMA,
        "module": ROBUSTNESS_TESTING_VERSION,
        "kind": kind,
        "seq": seq,
        "detail": dict(detail),
    }


def _det_ints(seed: str, count: int) -> List[int]:
    """Deterministic pseudo-random ints from a sha256 seed stream."""
    out: List[int] = []
    ctr = 0
    while len(out) < count:
        block = hashlib.sha256(f"{seed}:{ctr}".encode("utf-8")).digest()
        for i in range(0, len(block), 4):
            out.append(int.from_bytes(block[i:i + 4], "big"))
            if len(out) >= count:
                break
        ctr += 1
    return out


def apply_perturbation(text: str, op: str,
                       magnitude: float = 0.1,
                       mapping: Optional[Dict[str, str]] = None) -> str:
    """Apply the deterministic op recipe to text (pure, no ledger).

    This is the *recipe* behind a booked perturbation: given the same
    inputs it always returns the same output, so any host can replay
    a booked perturbation byte-identically. It makes no claim that
    these perturbations are realistic adversarial examples.
    """
    op = _check_op(op)
    magnitude = _check_magnitude(magnitude)
    if not isinstance(text, str):
        raise BadOpError(f"text must be str, got {type(text).__name__}")
    seed = f"robustness:{op}:{magnitude!r}:{text}"
    if op == "truncate":
        keep = max(1, math.ceil(len(text) * (1.0 - magnitude)))
        return text[:keep]
    if op == "case":
        rnd = _det_ints(seed, len(text))
        return "".join(
            ch.swapcase() if (r % 100) < int(magnitude * 100) else ch
            for ch, r in zip(text, rnd))
    if op == "typo":
        chars = list(text)
        n = max(1, int(len(chars) * magnitude))
        rnd = _det_ints(seed, n)
        for r in rnd:
            i = r % len(chars)
            j = (r >> 16) % len(chars)
            chars[i], chars[j] = chars[j], chars[i]
        return "".join(chars)
    words = text.split(" ")
    if op == "shuffle":
        keys = _det_ints(seed, len(words))
        return " ".join(
            w for _, w in sorted(zip(keys, words), key=lambda p: p[0]))
    if op == "noise":
        n = max(1, int(len(words) * magnitude))
        rnd = _det_ints(seed, n)
        out = list(words)
        for k, r in enumerate(rnd):
            pos = r % (len(out) + 1)
            out.insert(pos, _NOISE_FILLERS[(r >> 8) % len(_NOISE_FILLERS)])
        return " ".join(out)
    # op == "synonym": host-supplied mapping, applied deterministically.
    pairs = _check_mapping(mapping, "synonym")
    table = dict(pairs or ())
    return " ".join(table.get(w, w) for w in words)


@dataclass(frozen=True)
class TargetRecord:
    """Frozen record of a declared test target."""
    target_id: str
    seq: int
    digest: str

    def verify(self, target_id: str) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin("target", target_id, self.seq)


@dataclass(frozen=True)
class PerturbationRecord:
    """Frozen record of one declared perturbation op."""
    pert_id: str
    target_id: str
    op: str
    magnitude: float
    # Sorted (src, dst) synonym pairs; None when op != synonym.
    mapping: Optional[Tuple[Tuple[str, str], ...]]
    seq: int
    digest: str

    def verify(self, target_id: str, op: str,
               magnitude: float) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin(
            "perturb", self.pert_id, target_id, op,
            repr(magnitude), _mapping_pin(self.mapping), self.seq)


@dataclass(frozen=True)
class StressRecord:
    """Frozen record of one booked stress trial (host-reported scores)."""
    trial_id: str
    pert_id: str
    target_id: str
    # Derived as data: base - perturbed (may be negative).
    drop: float
    seq: int
    digest: str

    def verify(self, target_id: str, base: float,
               perturbed: float) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin(
            "stress", self.trial_id, target_id, self.pert_id,
            repr(base), repr(perturbed), self.seq)


@dataclass(frozen=True)
class OpDropStats:
    """Per-op derived drop statistics as data (not a record)."""
    op: str
    trials: int
    mean_drop: float
    worst_drop: float


@dataclass(frozen=True)
class ScoreReport:
    """Frozen aggregate robustness report for a target."""
    target_id: str
    trials: int
    mean_drop: float
    worst_drop: float
    best_drop: float
    # 1 - mean_drop, as ledger arithmetic on host-reported scores.
    robustness: float
    # One of: robust / borderline / fragile (pinned thresholds).
    verdict: str
    per_op: Tuple[OpDropStats, ...]
    seq: int
    digest: str

    def verify(self, target_id: str, trials: int,
               mean_drop: float) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin(
            "score", target_id, trials, repr(mean_drop), self.seq)


class RobustnessTesting:
    """Deterministic robustness-testing decision ledger.

    All mutations take caller-supplied strictly increasing int seqs,
    are RLock-guarded, and book frozen records with ``sha256:``
    digest pins plus ``audit.ndjson/1`` rows. No wall-clock, no
    randomness.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._targets: Dict[str, TargetRecord] = {}
        self._perts: Dict[str, PerturbationRecord] = {}
        self._trials: Dict[str, StressRecord] = {}
        self._pert_counter = 0
        self._trial_counter = 0
        self._last_seq = 0
        self._audit: list = []

    # -- seq discipline ---------------------------------------------------

    def _claim(self, seq: object) -> int:
        """Validate seq; rewinds raise bare (no consumption)."""
        seq = _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq must be strictly increasing "
                f"(last={self._last_seq}, got={seq})")
        return seq

    def _burn(self, seq: int, error: Exception) -> None:
        """Consume the seq, book a rejected row, then raise."""
        self._last_seq = seq
        self._audit.append(robustness_testing_audit_event(
            KIND_REJECTED, {"error": type(error).__name__}, seq))
        raise error

    def _emit(self, kind: str, detail: Dict[str, object], seq: int) -> None:
        self._audit.append(
            robustness_testing_audit_event(kind, detail, seq))

    # -- mutations ---------------------------------------------------------

    def target(self, target_id: object, seq: object) -> TargetRecord:
        """Declare the system under test; duplicate ids refused fail-closed."""
        with self._lock:
            seq = self._claim(seq)
            try:
                target_id = _check_id(target_id, "target_id")
                if target_id in self._targets:
                    raise DuplicateTargetError(
                        f"target already registered: {target_id!r}")
            except RobustnessTestingError as e:
                self._burn(seq, e)
            rec = TargetRecord(target_id=target_id, seq=seq,
                               digest=_pin("target", target_id, seq))
            self._targets[target_id] = rec
            self._last_seq = seq
            self._emit(KIND_TARGET_REGISTERED,
                       {"target_id": target_id, "digest": rec.digest}, seq)
            return rec

    def perturb(self, target_id: object, op: object, seq: object,
                magnitude: object = 0.1,
                mapping: object = None) -> PerturbationRecord:
        """Declare one perturbation op for a target (minted ``pert-N`` id)."""
        with self._lock:
            seq = self._claim(seq)
            try:
                target_id = _check_id(target_id, "target_id")
                if target_id not in self._targets:
                    raise UnknownTargetError(
                        f"unknown target: {target_id!r}")
                op = _check_op(op)
                magnitude = _check_magnitude(magnitude)
                pairs = _check_mapping(mapping, op)
            except RobustnessTestingError as e:
                self._burn(seq, e)
            self._pert_counter += 1
            pert_id = f"pert-{self._pert_counter}"
            rec = PerturbationRecord(
                pert_id=pert_id, target_id=target_id, op=op,
                magnitude=magnitude, mapping=pairs, seq=seq,
                digest=_pin("perturb", pert_id, target_id, op,
                            repr(magnitude), _mapping_pin(pairs), seq))
            self._perts[pert_id] = rec
            self._last_seq = seq
            # Raw mapping never crosses the audit boundary: digest pin only.
            self._emit(KIND_PERTURBED,
                       {"pert_id": pert_id, "target_id": target_id,
                        "op": op, "digest": rec.digest}, seq)
            return rec

    def stress(self, pert_id: object, base: object, perturbed: object,
               seq: object) -> StressRecord:
        """Book one stress trial: host-reported base vs perturbed scores.

        The drop (``base - perturbed``) is derived as data -- a
        negative drop (the perturbation helped) is booked, not raised.
        """
        with self._lock:
            seq = self._claim(seq)
            try:
                if (isinstance(pert_id, bool) or not isinstance(pert_id, str)
                        or pert_id not in self._perts):
                    raise UnknownPerturbationError(
                        f"unknown perturbation: {pert_id!r}")
                base = _check_score(base, "base")
                perturbed = _check_score(perturbed, "perturbed")
            except RobustnessTestingError as e:
                self._burn(seq, e)
            pert = self._perts[pert_id]
            drop = base - perturbed
            self._trial_counter += 1
            trial_id = f"stress-{self._trial_counter}"
            rec = StressRecord(
                trial_id=trial_id, pert_id=pert_id,
                target_id=pert.target_id, drop=drop, seq=seq,
                digest=_pin("stress", trial_id, pert.target_id,
                            pert_id, repr(base), repr(perturbed), seq))
            self._trials[trial_id] = rec
            self._last_seq = seq
            # Raw scores banned from the audit boundary: ids and pin only.
            self._emit(KIND_STRESSED,
                       {"trial_id": trial_id, "pert_id": pert_id,
                        "target_id": pert.target_id,
                        "digest": rec.digest}, seq)
            return rec

    def score(self, target_id: object, seq: object) -> ScoreReport:
        """Aggregate booked trials for a target into a robustness report.

        ``robustness`` is ``1 - mean_drop``; the verdict is data over
        the pinned thresholds (robust >= 0.90, borderline >= 0.75,
        else fragile). Refuses fail-closed with no booked trials.
        """
        with self._lock:
            seq = self._claim(seq)
            try:
                target_id = _check_id(target_id, "target_id")
                if target_id not in self._targets:
                    raise UnknownTargetError(
                        f"unknown target: {target_id!r}")
                trials = [t for t in self._trials.values()
                          if t.target_id == target_id]
                if not trials:
                    raise NoTrialsError(
                        f"no stress trials booked for {target_id!r}")
            except RobustnessTestingError as e:
                self._burn(seq, e)
            drops = [t.drop for t in trials]
            mean_drop = sum(drops) / len(drops)
            worst_drop = max(drops)
            best_drop = min(drops)
            robustness = 1.0 - mean_drop
            if robustness >= _ROBUST_AT:
                verdict = "robust"
            elif robustness >= _BORDERLINE_AT:
                verdict = "borderline"
            else:
                verdict = "fragile"
            by_op: Dict[str, List[float]] = {}
            for t in trials:
                by_op.setdefault(self._perts[t.pert_id].op, []).append(t.drop)
            per_op = tuple(
                OpDropStats(op=op, trials=len(ds),
                            mean_drop=sum(ds) / len(ds),
                            worst_drop=max(ds))
                for op, ds in sorted(by_op.items()))
            report = ScoreReport(
                target_id=target_id, trials=len(trials),
                mean_drop=mean_drop, worst_drop=worst_drop,
                best_drop=best_drop, robustness=robustness,
                verdict=verdict, per_op=per_op, seq=seq,
                digest=_pin("score", target_id, len(trials),
                            repr(mean_drop), seq))
            self._last_seq = seq
            self._emit(KIND_SCORED,
                       {"target_id": target_id, "trials": len(trials),
                        "verdict": verdict, "digest": report.digest}, seq)
            return report

    # -- pure read views ----------------------------------------------------

    def target_record(self, target_id: str) -> Optional[TargetRecord]:
        """Return the target record, or None (pure read)."""
        return self._targets.get(target_id)

    def target_ids(self) -> Tuple[str, ...]:
        """Declared target ids, sorted (pure read)."""
        return tuple(sorted(self._targets))

    def perturbation_record(self, pert_id: str) -> Optional[PerturbationRecord]:
        """Return the perturbation record, or None (pure read)."""
        return self._perts.get(pert_id)

    def perturbation_ids(self) -> Tuple[str, ...]:
        """Booked perturbation ids, sorted (pure read)."""
        return tuple(sorted(self._perts))

    def trial_ids(self) -> Tuple[str, ...]:
        """Booked stress-trial ids, sorted (pure read)."""
        return tuple(sorted(self._trials))

    def trials(self, target_id: object, seq: object) -> Tuple[StressRecord, ...]:
        """Stress trials for a target (pure read: seq validated, not consumed)."""
        _check_seq(seq)
        with self._lock:
            return tuple(sorted(
                (t for t in self._trials.values()
                 if t.target_id == target_id),
                key=lambda t: t.trial_id))

    def stats(self, seq: object) -> Dict[str, int]:
        """Ledger counts as data (pure read: seq validated, not consumed)."""
        _check_seq(seq)
        return {"targets": len(self._targets),
                "perturbations": len(self._perts),
                "trials": len(self._trials)}

    def audit_log(self) -> Tuple[Dict[str, object], ...]:
        """Booked audit rows, oldest first (pure read)."""
        return tuple(self._audit)


def main() -> None:
    """Self-check: target, perturb, stress, score."""
    rt = RobustnessTesting()
    t = rt.target("model-a", 1)
    assert t.verify("model-a")
    p1 = rt.perturb("model-a", "typo", 2, magnitude=0.2)
    assert p1.verify("model-a", "typo", 0.2), p1
    p2 = rt.perturb("model-a", "shuffle", 3)
    assert p2.pert_id == "pert-2"
    s1 = rt.stress(p1.pert_id, 0.9, 0.7, 4)
    assert s1.verify("model-a", 0.9, 0.7)
    assert abs(s1.drop - 0.2) < 1e-12, s1
    rt.stress(p2.pert_id, 0.9, 0.85, 5)
    report = rt.score("model-a", 6)
    # mean_drop = (0.2 + 0.05) / 2 = 0.125 -> robustness 0.875 borderline.
    assert abs(report.mean_drop - 0.125) < 1e-12, report
    assert report.verdict == "borderline", report
    assert report.verify("model-a", 2, report.mean_drop)
    assert len(rt.audit_log()) == 6
    # Deterministic recipe: same input -> same output.
    a = apply_perturbation("hello world foo", "shuffle", 0.5)
    b = apply_perturbation("hello world foo", "shuffle", 0.5)
    assert a == b and sorted(a.split()) == sorted("hello world foo".split())
    print("robustness-testing OK: target, perturb, stress, score, recipe")


if __name__ == "__main__":
    main()
