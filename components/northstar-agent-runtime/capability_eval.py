"""Capability testing (probe/measure/profile) interface, simulated.

Research motivation: capability evaluations are how an agent's declared
abilities get stress-tested -- a capability under test, a set of probes
(test items) aimed at it, and measured outcomes. Without the ledger,
"the agent scored 0.9 on tool-use" is an unfalsifiable claim.

This module is the *capability-measurement ledger* half of that shape.
It does not run an agent, grade answers, or prove any capability; it
books declared capability-probing decisions and their host-reported
outcomes:

- ``CapabilityEval.register_capability(cap_id, name, seq)`` -- declare
  a capability under test (e.g. ``"tool-use"``). The name is a label,
  not a measurement. Duplicate ids refused fail-closed; ids never
  recycled. Returns a frozen ``CapabilityRecord``.
- ``CapabilityEval.probe(cap_id, probe_id, input_digest, seq)`` -- book
  one probe against the capability. The probe input is pinned by its
  ``sha256:`` digest only -- raw probe text never enters a record or
  crosses the audit boundary. Returns a frozen ``ProbeRecord``.
- ``CapabilityEval.measure(cap_id, probe_id, outcome, score, seq)`` --
  book the host-declared outcome of a probe over the pinned vocabulary
  ``pass`` / ``fail`` / ``partial`` / ``timeout`` / ``error``, plus a
  host-reported ``score`` in [0, 1]. One measurement per probe --
  re-measuring is refused fail-closed. Returns a frozen
  ``MeasureRecord``.
- ``CapabilityEval.profile(cap_id, seq)`` -- pure read view: aggregate
  counts per outcome and the mean score as data, never as a claim
  about the agent. The seq is validated but never consumed; no audit
  row is written.
- ``capability_eval_audit_event(kind, ...)`` -- ``audit.ndjson/1``
  records (``capability-registered`` / ``probe-booked`` / ``measured``
  / ``rejected``); caller-supplied seqs only. Probe names, inputs,
  scores, and notes are banned from the audit boundary -- audit rows
  carry ids, digests, outcome labels, and counts only.

Fail-closed edges (fail loudly, never guess):

- ``cap_id`` / ``probe_id`` must be non-empty str, <= 256 chars, no
  whitespace.
- ``name`` must be a non-empty str, <= 256 chars.
- ``input_digest`` must be a ``sha256:``-prefixed 71-char pin.
- ``outcome`` must be one of ``pass`` / ``fail`` / ``partial`` /
  ``timeout`` / ``error`` (no coercion).
- ``score`` must be a finite float in [0, 1] (ints 0/1 accepted and
  stored as float; bool, NaN, inf, out-of-range refused).
- ``probe`` on an unknown capability raises ``UnknownCapabilityError``;
  on a retired capability raises ``RetiredCapabilityError``.
- ``measure`` on an unknown probe raises ``UnknownProbeError``; a
  second measurement of the same probe raises ``DuplicateMeasureError``.
- Seqs are ints (not bool), >= 0, strictly increasing per instance.
  Failed mutations consume their seq and book a ``rejected`` audit
  row; seq rewinds raise bare ``SeqOrderError`` without consuming.

Honest scope:

- This module books *declared* measurements: a booked ``pass`` means
  the host declared this probe passed with this score, never that the
  capability is real, that the probe is valid, or that anything actually
  ran. Scores and outcomes are GIGO -- the module cannot inspect,
  reproduce, or independently verify any real capability evaluation.
- ``profile()`` is arithmetic over booked rows: counts and a mean of
  host-reported scores. It is descriptive ledger math, never a
  capability claim, a benchmark result, or safety evidence.
- A terminal verdict (``certified`` / ``not-certified``) is booked as
  declared host judgment only -- it proves nothing on its own.
- No persistence: the ledger is in-memory. Pair with the durable
  audit writer if evals must survive a restart.
"""

from __future__ import annotations

import hashlib
import math
import threading
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json, jcs_sha256_hex
except Exception:  # pragma: no cover - module must stay importable standalone
    import json as _json

    def jcs_canonical_json(obj):  # type: ignore[no-redef]
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("utf-8")

    def jcs_sha256_hex(obj) -> str:  # type: ignore[no-redef]
        return hashlib.sha256(jcs_canonical_json(obj)).hexdigest()


#: Version pin for this module's record shape.
CAPABILITY_EVAL_VERSION = "capability-eval.v1"

#: Schema pin carried by records and audit events.
CAPABILITY_EVAL_SCHEMA = "northstar.capability-eval.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Audit event kinds.
KIND_CAPABILITY_REGISTERED = "capability-registered"
KIND_PROBE_BOOKED = "probe-booked"
KIND_MEASURED = "measured"
KIND_RETIRED = "retired"
KIND_VERDICT = "verdict"
KIND_REJECTED = "rejected"
_KINDS = (KIND_CAPABILITY_REGISTERED, KIND_PROBE_BOOKED, KIND_MEASURED,
          KIND_RETIRED, KIND_VERDICT, KIND_REJECTED)

#: Detail keys banned from the audit boundary (raw data never crosses it).
_BANNED_DETAIL_KEYS = frozenset(
    {"name", "input", "text", "content", "note", "score", "payload",
     "raw", "reason", "prompt", "description"})

#: Pinned measurement outcome vocabulary.
OUTCOMES = ("pass", "fail", "partial", "timeout", "error")

#: Pinned verdict vocabulary.
VERDICTS = ("certified", "not-certified")

#: Max id length.
_MAX_ID_LEN = 256

#: Expected length of a "sha256:<64 hex>" pin.
_PIN_LEN = len("sha256:") + 64


class CapabilityEvalError(Exception):
    """Base error for the capability-eval ledger (programming errors)."""


class BadCapabilityError(CapabilityEvalError):
    """Raised when a capability id is malformed."""


class BadNameError(CapabilityEvalError):
    """Raised when a capability name is malformed."""


class DuplicateCapabilityError(CapabilityEvalError):
    """Raised when a capability id is registered twice."""


class RetiredCapabilityError(CapabilityEvalError):
    """Raised when an id names a retired capability."""


class UnknownCapabilityError(CapabilityEvalError):
    """Raised when a capability id names no registered capability."""


class BadProbeError(CapabilityEvalError):
    """Raised when a probe id is malformed."""


class DuplicateProbeError(CapabilityEvalError):
    """Raised when a probe id is booked twice."""


class UnknownProbeError(CapabilityEvalError):
    """Raised when a probe id names no booked probe."""


class BadDigestError(CapabilityEvalError):
    """Raised when a digest pin is malformed."""


class BadOutcomeError(CapabilityEvalError):
    """Raised when a measurement outcome is not in the vocabulary."""


class BadScoreError(CapabilityEvalError):
    """Raised when a score is malformed."""


class DuplicateMeasureError(CapabilityEvalError):
    """Raised when a probe is measured twice."""


class BadVerdictError(CapabilityEvalError):
    """Raised when a verdict is not in the vocabulary."""


class SeqOrderError(CapabilityEvalError):
    """Raised when a seq is malformed or not strictly increasing."""


class AuditKindError(CapabilityEvalError):
    """Raised when an audit event kind is unknown or leaks banned keys."""


def _check_seq(value: object, name: str = "seq") -> int:
    """Validate a caller-supplied ordering seq: int, not bool, >= 0."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise SeqOrderError(f"{name} must be int, got {type(value).__name__}")
    if value < 0:
        raise SeqOrderError(f"{name} must be >= 0, got {value}")
    return value


def _check_id(value: object, what: str, error: type) -> str:
    """Validate an id: non-empty str, no whitespace, <= 256 chars."""
    if isinstance(value, bool) or not isinstance(value, str):
        raise error(f"{what} must be str, got {type(value).__name__}")
    if not value:
        raise error(f"{what} must not be empty")
    if len(value) > _MAX_ID_LEN:
        raise error(f"{what} too long (>{_MAX_ID_LEN} chars)")
    if any(ch.isspace() for ch in value):
        raise error(f"{what} must not contain whitespace")
    return value


def _check_name(name: object) -> str:
    """Validate a capability name: non-empty str, <= 256 chars."""
    if isinstance(name, bool) or not isinstance(name, str):
        raise BadNameError(f"name must be str, got {type(name).__name__}")
    if not name:
        raise BadNameError("name must not be empty")
    if len(name) > _MAX_ID_LEN:
        raise BadNameError(f"name too long (>{_MAX_ID_LEN} chars)")
    return name


def _check_digest(pin: object, name: str) -> str:
    """Validate a sha256: digest pin (71 chars, hex body)."""
    if isinstance(pin, bool) or not isinstance(pin, str):
        raise BadDigestError(f"{name} must be str, got {type(pin).__name__}")
    if len(pin) != _PIN_LEN or not pin.startswith("sha256:"):
        raise BadDigestError(f"{name} must be a sha256: pin, got {pin!r}")
    body = pin[len("sha256:"):]
    if not all(c in "0123456789abcdef" for c in body):
        raise BadDigestError(f"{name} has a non-hex digest body: {pin!r}")
    return pin


def _check_outcome(outcome: object) -> str:
    """Validate a measurement outcome against the pinned vocabulary."""
    if outcome not in OUTCOMES:
        raise BadOutcomeError(
            f"outcome must be one of {OUTCOMES}, got {outcome!r}")
    return outcome  # type: ignore[return-value]


def _check_score(value: object) -> float:
    """Validate a host-reported score: finite float in [0, 1]."""
    if isinstance(value, bool):
        raise BadScoreError("score must not be bool")
    if isinstance(value, int):
        value = float(value)
    if not isinstance(value, float):
        raise BadScoreError(
            f"score must be float, got {type(value).__name__}")
    if not math.isfinite(value):
        raise BadScoreError(f"score must be finite, got {value!r}")
    if not 0.0 <= value <= 1.0:
        raise BadScoreError(f"score must be in [0, 1], got {value!r}")
    return value


def _check_verdict(verdict: object) -> str:
    """Validate a declared verdict against the pinned vocabulary."""
    if verdict not in VERDICTS:
        raise BadVerdictError(
            f"verdict must be one of {VERDICTS}, got {verdict!r}")
    return verdict  # type: ignore[return-value]


def _pin(*parts: object) -> str:
    """Digest pin over a domain-separated canonical tuple."""
    return "sha256:" + jcs_sha256_hex({
        "domain": CAPABILITY_EVAL_SCHEMA,
        "parts": list(parts),
    })


def _safe_score(score: float) -> object:
    """Make a score JSON-encodable for digest input."""
    if math.isnan(score) or math.isinf(score):
        return repr(score)
    return score


def capability_eval_audit_event(kind: str, detail: Dict[str, object],
                                seq: object) -> Dict[str, object]:
    """Build one ``audit.ndjson/1`` audit row for the capability ledger."""
    if kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    banned = _BANNED_DETAIL_KEYS.intersection(detail.keys())
    if banned:
        raise AuditKindError(
            f"detail keys banned from audit boundary: {sorted(banned)}")
    return {
        "schema": AUDIT_SCHEMA,
        "module": CAPABILITY_EVAL_VERSION,
        "kind": kind,
        "seq": seq,
        "detail": dict(detail),
    }


@dataclass(frozen=True)
class CapabilityRecord:
    """Frozen record of a declared capability under test."""
    cap_id: str
    name: str
    seq: int
    digest: str

    def verify(self, cap_id: str, name: str) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin("capability", cap_id, name, self.seq)


@dataclass(frozen=True)
class ProbeRecord:
    """Frozen record of one booked probe against a capability."""
    cap_id: str
    probe_id: str
    input_digest: str
    seq: int
    digest: str

    def verify(self) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin(
            "probe", self.cap_id, self.probe_id, self.input_digest,
            self.seq)


@dataclass(frozen=True)
class MeasureRecord:
    """Frozen record of a probe's host-declared measurement."""
    cap_id: str
    probe_id: str
    outcome: str
    score: float
    seq: int
    digest: str

    def verify(self) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin(
            "measure", self.cap_id, self.probe_id, self.outcome,
            repr(_safe_score(self.score)), self.seq)


@dataclass(frozen=True)
class RetireRecord:
    """Frozen terminal record: a capability id retired forever."""
    cap_id: str
    seq: int
    digest: str

    def verify(self) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin("retire", self.cap_id, self.seq)


@dataclass(frozen=True)
class VerdictRecord:
    """Frozen record of a declared host verdict (as data, never proof)."""
    cap_id: str
    verdict: str
    probes: int  # number of measured probes at verdict time.
    seq: int
    digest: str

    def verify(self) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin(
            "verdict", self.cap_id, self.verdict, self.probes, self.seq)


@dataclass(frozen=True)
class ProfileReport:
    """Pure read view: per-outcome counts and mean score as data."""
    cap_id: str
    total: int
    counts: Tuple[Tuple[str, int], ...]  # (outcome, count) in vocabulary order.
    mean_score: object  # float mean of host-reported scores, or None when empty.
    seq: int  # seq of the read, validated, never consumed.


@dataclass(frozen=True)
class EvalStats:
    """Per-capability summary as data (not a record)."""
    cap_id: str
    probes: int
    measured: int
    verdict: Optional[str]


class CapabilityEval:
    """Deterministic capability-testing measurement ledger.

    All mutations take caller-supplied strictly increasing int seqs,
    are RLock-guarded, and book frozen records with ``sha256:`` digest
    pins plus ``audit.ndjson/1`` rows. No wall-clock, no model calls:
    probes, outcomes, and scores are host-declared and pinned by
    digest only.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._capabilities: Dict[str, CapabilityRecord] = {}
        self._retired: set = set()
        self._probes: Dict[str, Dict[str, ProbeRecord]] = {}
        self._measures: Dict[str, Dict[str, MeasureRecord]] = {}
        self._verdicts: Dict[str, VerdictRecord] = {}
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
        self._audit.append(capability_eval_audit_event(
            KIND_REJECTED, {"error": type(error).__name__}, seq))
        raise error

    def _emit(self, audit_kind: str, detail: Dict[str, object],
              seq: int) -> None:
        self._audit.append(capability_eval_audit_event(
            audit_kind, detail, seq))

    def _require_live(self, cap_id: str) -> None:
        """Raise unless cap_id names a live (registered, unretired) cap."""
        if cap_id in self._retired:
            raise RetiredCapabilityError(
                f"capability retired: {cap_id!r}")
        if cap_id not in self._capabilities:
            raise UnknownCapabilityError(
                f"unknown capability: {cap_id!r}")

    # -- mutations ---------------------------------------------------------

    def register_capability(self, cap_id: object, name: object,
                            seq: object) -> CapabilityRecord:
        """Declare a capability under test; duplicate ids refused."""
        with self._lock:
            seq = self._claim(seq)
            try:
                cap_id = _check_id(cap_id, "cap_id", BadCapabilityError)
                name = _check_name(name)
                if cap_id in self._capabilities:
                    raise DuplicateCapabilityError(
                        f"capability already registered: {cap_id!r}")
                if cap_id in self._retired:
                    raise RetiredCapabilityError(
                        f"capability id retired forever: {cap_id!r}")
            except CapabilityEvalError as e:
                self._burn(seq, e)
            rec = CapabilityRecord(
                cap_id=cap_id, name=name, seq=seq,
                digest=_pin("capability", cap_id, name, seq))
            self._capabilities[cap_id] = rec
            self._probes[cap_id] = {}
            self._measures[cap_id] = {}
            self._last_seq = seq
            self._emit(KIND_CAPABILITY_REGISTERED,
                       {"cap_id": cap_id, "digest": rec.digest}, seq)
            return rec

    def retire(self, cap_id: object, seq: object) -> RetireRecord:
        """Terminal: retire a capability id forever."""
        with self._lock:
            seq = self._claim(seq)
            try:
                cap_id = _check_id(cap_id, "cap_id", BadCapabilityError)
                self._require_live(cap_id)
            except CapabilityEvalError as e:
                self._burn(seq, e)
            rec = RetireRecord(
                cap_id=cap_id, seq=seq,
                digest=_pin("retire", cap_id, seq))
            self._retired.add(cap_id)
            del self._capabilities[cap_id]
            del self._probes[cap_id]
            del self._measures[cap_id]
            self._last_seq = seq
            self._emit(KIND_RETIRED, {"cap_id": cap_id}, seq)
            return rec

    def probe(self, cap_id: object, probe_id: object,
              input_digest: object, seq: object) -> ProbeRecord:
        """Book one probe against a live capability."""
        with self._lock:
            seq = self._claim(seq)
            try:
                cap_id = _check_id(cap_id, "cap_id", BadCapabilityError)
                self._require_live(cap_id)
                probe_id = _check_id(probe_id, "probe_id", BadProbeError)
                input_digest = _check_digest(input_digest, "input_digest")
                if probe_id in self._probes[cap_id]:
                    raise DuplicateProbeError(
                        f"probe already booked: {probe_id!r}")
            except CapabilityEvalError as e:
                self._burn(seq, e)
            rec = ProbeRecord(
                cap_id=cap_id, probe_id=probe_id, input_digest=input_digest,
                seq=seq,
                digest=_pin("probe", cap_id, probe_id, input_digest, seq))
            self._probes[cap_id][probe_id] = rec
            self._last_seq = seq
            self._emit(KIND_PROBE_BOOKED,
                       {"cap_id": cap_id, "probe_id": probe_id,
                        "input_digest": input_digest,
                        "digest": rec.digest}, seq)
            return rec

    def measure(self, cap_id: object, probe_id: object,
                outcome: object, score: object,
                seq: object) -> MeasureRecord:
        """Book one host-declared measurement of a probe."""
        with self._lock:
            seq = self._claim(seq)
            try:
                cap_id = _check_id(cap_id, "cap_id", BadCapabilityError)
                self._require_live(cap_id)
                probe_id = _check_id(probe_id, "probe_id", BadProbeError)
                if probe_id not in self._probes[cap_id]:
                    raise UnknownProbeError(
                        f"unknown probe: {probe_id!r}")
                if probe_id in self._measures[cap_id]:
                    raise DuplicateMeasureError(
                        f"probe already measured: {probe_id!r}")
                outcome = _check_outcome(outcome)
                score = _check_score(score)
            except CapabilityEvalError as e:
                self._burn(seq, e)
            rec = MeasureRecord(
                cap_id=cap_id, probe_id=probe_id, outcome=outcome,
                score=score, seq=seq,
                digest=_pin("measure", cap_id, probe_id, outcome,
                            repr(_safe_score(score)), seq))
            self._measures[cap_id][probe_id] = rec
            self._last_seq = seq
            self._emit(KIND_MEASURED,
                       {"cap_id": cap_id, "probe_id": probe_id,
                        "outcome": outcome,
                        "digest": rec.digest}, seq)
            return rec

    def verdict(self, cap_id: object, verdict: object,
                seq: object) -> VerdictRecord:
        """Book a declared host verdict for a capability (as data)."""
        with self._lock:
            seq = self._claim(seq)
            try:
                cap_id = _check_id(cap_id, "cap_id", BadCapabilityError)
                self._require_live(cap_id)
                verdict = _check_verdict(verdict)
                probes = len(self._measures[cap_id])
                if probes == 0:
                    raise UnknownProbeError(
                        f"cannot book a verdict with zero measurements: "
                        f"{cap_id!r}")
            except CapabilityEvalError as e:
                self._burn(seq, e)
            rec = VerdictRecord(
                cap_id=cap_id, verdict=verdict, probes=probes, seq=seq,
                digest=_pin("verdict", cap_id, verdict, probes, seq))
            self._verdicts[cap_id] = rec
            self._last_seq = seq
            self._emit(KIND_VERDICT,
                       {"cap_id": cap_id, "verdict": verdict,
                        "probes": probes, "digest": rec.digest}, seq)
            return rec

    # -- views --------------------------------------------------------------

    def capability_record(self, cap_id: str) -> Optional[CapabilityRecord]:
        """Return the capability record, or None (pure read)."""
        return self._capabilities.get(cap_id)

    def probe_record(self, cap_id: str,
                     probe_id: str) -> Optional[ProbeRecord]:
        """Return the probe record, or None (pure read)."""
        return self._probes.get(cap_id, {}).get(probe_id)

    def measure_record(self, cap_id: str,
                       probe_id: str) -> Optional[MeasureRecord]:
        """Return the measurement, or None (pure read)."""
        return self._measures.get(cap_id, {}).get(probe_id)

    def capability_ids(self) -> Tuple[str, ...]:
        """Sorted live capability ids (pure read)."""
        return tuple(sorted(self._capabilities))

    def retired_ids(self) -> Tuple[str, ...]:
        """Sorted retired capability ids (pure read)."""
        return tuple(sorted(self._retired))

    def profile(self, cap_id: object, seq: object) -> ProfileReport:
        """Pure read view: per-outcome counts and mean score as data.

        The seq is validated but never consumed and no audit row is
        written. Unknown ids raise ``UnknownCapabilityError``.
        """
        _check_seq(seq)
        cap_id = _check_id(cap_id, "cap_id", BadCapabilityError)
        with self._lock:
            self._require_live(cap_id)
            measures = self._measures[cap_id]
            counts = {o: 0 for o in OUTCOMES}
            total_score = 0.0
            den = 0
            for m in measures.values():
                counts[m.outcome] += 1
                # Descriptive ledger math over host-reported scores:
                # a plain float mean, never a capability claim.
                total_score += m.score
                den += 1
            mean: object = (total_score / den) if den else None
            return ProfileReport(
                cap_id=cap_id, total=den,
                counts=tuple((o, counts[o]) for o in OUTCOMES),
                mean_score=mean, seq=seq)

    def stats(self, seq: object) -> Tuple[EvalStats, ...]:
        """Per-capability summary as data: seq validated, never consumed."""
        _check_seq(seq)
        with self._lock:
            return tuple(
                EvalStats(
                    cap_id=cid, probes=len(self._probes[cid]),
                    measured=len(self._measures[cid]),
                    verdict=(self._verdicts[cid].verdict
                             if cid in self._verdicts else None))
                for cid in sorted(self._capabilities))

    def audit_log(self) -> Tuple[Dict[str, object], ...]:
        """Booked audit rows, oldest first (pure read)."""
        return tuple(self._audit)


def main() -> None:
    """Self-check: register, probe, measure, profile, verdict."""
    ce = CapabilityEval()
    cap = ce.register_capability("tool-use", "Tool Use", 1)
    assert cap.verify("tool-use", "Tool Use")
    p1 = _pin("input", "add 1 and 2")
    p2 = _pin("input", "delete /tmp/x")
    pr1 = ce.probe("tool-use", "p1", p1, 2)
    assert pr1.verify()
    pr2 = ce.probe("tool-use", "p2", p2, 3)
    assert pr2.verify()
    m1 = ce.measure("tool-use", "p1", "pass", 1.0, 4)
    assert m1.verify() and m1.score == 1.0
    m2 = ce.measure("tool-use", "p2", "partial", 0.5, 5)
    assert m2.verify() and m2.score == 0.5
    prof = ce.profile("tool-use", 5)
    assert prof.total == 2
    assert dict(prof.counts)["pass"] == 1
    assert dict(prof.counts)["partial"] == 1
    assert abs(prof.mean_score - 0.75) < 1e-12
    v = ce.verdict("tool-use", "certified", 6)
    assert v.verify() and v.probes == 2
    st = ce.stats(6)
    assert len(st) == 1 and st[0].measured == 2
    assert st[0].verdict == "certified"
    assert len(ce.audit_log()) == 6
    # Tampered measure does not verify.
    bad = MeasureRecord(cap_id="tool-use", probe_id="p1", outcome="pass",
                        score=0.0, seq=4, digest=m1.digest)
    assert not bad.verify()
    print("capability-eval OK: register, probe, measure, profile, verdict")


if __name__ == "__main__":
    main()
