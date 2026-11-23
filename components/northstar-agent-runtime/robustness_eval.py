"""Robustness evaluation as a deterministic single-host decision ledger.

Research note: robustness evaluation is the governance loop around model
fragility under perturbation -- declared evaluation designs over a
pinned robustness taxonomy, host-declared evaluation runs with
host-reported outcomes and scores, and ledger-derived robustness
posture. This module is the bookkeeping layer for that loop. It runs
no evaluations, measures no robustness itself, executes no attacks,
perturbs no inputs, and proves nothing about real-world resilience.

Distinct-layer rationale: ``adversarial_robustness.py`` owns robustness
*scoring* mechanics, ``robustness_testing.py`` owns robustness *testing*
execution mechanics, and ``eval_registry.py`` owns evaluation bookkeeping
generically. Per the additive sibling pattern, this module is the
robustness-*evaluation* decision ledger none of them own: declared
evaluation designs over the pinned kind/dimension vocabulary, declared
runs with pinned outcomes and host-reported scores, and derived score
reports -- all booked as data, never evidence.

House style: frozen dataclasses, caller int seqs strictly increasing
with claim-then-burn (failed mutations consume their seq + book
``robustness-eval.rejected``; rewinds raise bare without consuming), no
wall-clock, RLock-guarded, fail-closed, stdlib-only +
``canonical_json`` try/except fallback, ``sha256:`` digest pins with
``verify()``, ``audit.ndjson/1`` events.

Honest scope: a booked ``brittle`` outcome means "the host declared the
system brittle on this run", never that the system is brittle. A booked
score is a host-reported number, never a measured fact. ``score()``
derives posture from the ledger; it never proves real-world robustness.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

try:  # Prefer the in-repo canonicalizer when installed.
    from canonical_json import jcs_sha256_hex  # noqa: F401
except Exception:  # pragma: no cover - fallback path
    import hashlib
    import json

    def jcs_sha256_hex(obj) -> str:
        raw = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()


#: Module version.
ROBUSTNESS_EVAL_VERSION = "robustness-eval.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.robustness-eval.v1"

#: Pinned evaluation-kind vocabulary (declared evaluation designs).
EVAL_KINDS = (
    "adversarial",
    "distribution-shift",
    "corruption",
    "perturbation",
    "stress",
)

#: Pinned robustness-dimension vocabulary (declared coverage axes).
ROBUSTNESS_DIMS = (
    "adversarial-perturbations",
    "natural-shift",
    "common-corruptions",
    "edge-cases",
    "prompt-variants",
    "multi-modal-noise",
    "tool-noise",
    "time-drift",
)

#: Pinned run-outcome vocabulary. Outcomes are booked as data.
RUN_OUTCOMES = (
    "robust",
    "degraded",
    "brittle",
    "inconclusive",
)

#: Pinned derived-posture vocabulary (ledger truth, never proof).
POSTURES = (
    "untested",
    "brittle-detected",
    "degraded",
    "robust",
    "inconclusive",
)

#: Keys banned from audit details (raw eval material must not cross).
_BANNED_AUDIT_KEYS = frozenset({
    "description", "text", "content", "details_raw", "notes",
    "evidence", "payload", "raw", "secret", "scenario",
    "transcript", "prompt", "response", "weights", "attack",
    "perturbation", "sample", "dataset", "corruption",
})


# ---------------------------------------------------------------------------
# Error taxonomy
# ---------------------------------------------------------------------------

class RobustnessEvalError(Exception):
    """Base error for robustness-eval misuse."""


class SeqOrderError(RobustnessEvalError):
    """Raised when a caller seq does not strictly increase."""


class BadIdError(RobustnessEvalError):
    """Raised on a malformed system, design, or run id."""


class UnknownSystemError(RobustnessEvalError):
    """Raised when a system id has no booked rows (pure-read lookups)."""


class UnknownRecordError(RobustnessEvalError):
    """Raised when a design or run id is unknown."""


class BadKindError(RobustnessEvalError):
    """Raised on an eval kind outside the pinned vocabulary."""


class BadDimError(RobustnessEvalError):
    """Raised on a robustness dimension outside the pinned vocabulary."""


class BadOutcomeError(RobustnessEvalError):
    """Raised on a run outcome outside the pinned vocabulary."""


class BadScoreError(RobustnessEvalError):
    """Raised on a score outside int [0, 100] (bool refused)."""


class BadDigestError(RobustnessEvalError):
    """Raised on a malformed sha256: digest pin."""


class AuditKindError(RobustnessEvalError):
    """Raised on an unknown audit kind or a banned audit key."""


# ---------------------------------------------------------------------------
# Digest helpers
# ---------------------------------------------------------------------------

def _record_digest(body: dict) -> str:
    # The in-repo jcs_sha256_hex returns bare hex; pin it explicitly.
    return "sha256:" + jcs_sha256_hex(body)


def _check_digest(value: str) -> str:
    if not isinstance(value, str):
        raise BadDigestError("digest must be a str")
    if value and not (value.startswith("sha256:") and len(value) == 71):
        raise BadDigestError("digest must be a sha256: pin or ''")
    return value


def _check_id(value: str) -> str:
    if not isinstance(value, str) or not value:
        raise BadIdError("id must be a non-empty str")
    if len(value) > 128:
        raise BadIdError("id too long")
    return value


def _check_score(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BadScoreError("score must be an int in [0, 100]")
    if not 0 <= value <= 100:
        raise BadScoreError("score must be in [0, 100]")
    return value


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class DesignRecord:
    """One declared robustness evaluation design for a system."""

    design_id: str
    system_id: str
    eval_kind: str
    robustness_dim: str
    eval_digest: str
    seq: int
    digest: str

    def verify(self) -> bool:
        return self.digest == _record_digest(self.as_dict(include_digest=False))

    def as_dict(self, include_digest: bool = True) -> dict:
        d = {
            "schema": SCHEMA_PIN,
            "design_id": self.design_id,
            "system_id": self.system_id,
            "eval_kind": self.eval_kind,
            "robustness_dim": self.robustness_dim,
            "eval_digest": self.eval_digest,
            "seq": self.seq,
        }
        if include_digest:
            d["digest"] = self.digest
        return d


@dataclass(frozen=True)
class RunRecord:
    """One host-declared robustness evaluation run."""

    run_id: str
    design_id: str
    system_id: str
    outcome: str
    score: int
    run_digest: str
    seq: int
    digest: str

    def verify(self) -> bool:
        return self.digest == _record_digest(self.as_dict(include_digest=False))

    def as_dict(self, include_digest: bool = True) -> dict:
        d = {
            "schema": SCHEMA_PIN,
            "run_id": self.run_id,
            "design_id": self.design_id,
            "system_id": self.system_id,
            "outcome": self.outcome,
            "score": self.score,
            "run_digest": self.run_digest,
            "seq": self.seq,
        }
        if include_digest:
            d["digest"] = self.digest
        return d


@dataclass(frozen=True)
class ScoreReport:
    """Derived robustness posture report (pure read)."""

    seq: int
    system_id: str
    n_systems: int
    n_designs: int
    n_runs: int
    outcome_tallies: tuple
    mean_score: object
    posture: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _record_digest(self.as_dict(include_digest=False))

    def as_dict(self, include_digest: bool = True) -> dict:
        d = {
            "schema": SCHEMA_PIN,
            "seq": self.seq,
            "system_id": self.system_id,
            "n_systems": self.n_systems,
            "n_designs": self.n_designs,
            "n_runs": self.n_runs,
            "outcome_tallies": [list(p) for p in self.outcome_tallies],
            "mean_score": self.mean_score,
            "posture": self.posture,
        }
        if include_digest:
            d["digest"] = self.digest
        return d


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------

_AUDIT_KINDS = (
    "designed",
    "run",
    "robustness-eval.rejected",
)


def robustness_eval_audit_event(kind: str, details: dict) -> dict:
    """Build one ``audit.ndjson/1`` event. Raw eval keys are banned."""
    if kind not in _AUDIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    if not isinstance(details, dict):
        raise AuditKindError("details must be a dict")
    for key in details:
        if key in _BANNED_AUDIT_KEYS:
            raise AuditKindError(f"raw eval key banned from audit: {key!r}")
    return {"kind": "robustness-eval." + kind if "." not in kind else kind,
            "details": dict(details)}


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------

class RobustnessEval:
    """Robustness-eval decision ledger: design -> run -> score."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._designs: dict[str, DesignRecord] = {}
        self._design_ids: list[str] = []
        self._runs: dict[str, RunRecord] = {}
        self._run_ids: list[str] = []
        self._audit: list[dict] = []
        self._n_rejected = 0

    # -- seq ------------------------------------------------------------
    def _claim(self, seq: int) -> None:
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise SeqOrderError("seq must be an int")
        if seq <= self._seq:
            raise SeqOrderError("seq must strictly increase")
        self._seq = seq

    def _emit(self, audit_kind: str, details: dict) -> None:
        self._audit.append(robustness_eval_audit_event(audit_kind, details))

    def _reject(self, seq: int, reason: str) -> None:
        self._n_rejected += 1
        self._emit("robustness-eval.rejected", {"seq": seq, "reason": reason})

    # -- mutations ------------------------------------------------------
    def design(self, system_id: str, seq: int,
               eval_kind: str = "adversarial",
               robustness_dim: str = "adversarial-perturbations",
               eval_digest: str = "") -> DesignRecord:
        """Book one declared robustness evaluation design (minted dsg-N).

        Books the *declaration*, never an evaluation plan's contents:
        raw eval material travels as a ``sha256:`` pin only.
        """
        with self._lock:
            self._claim(seq)
            try:
                _check_id(system_id)
                if eval_kind not in EVAL_KINDS:
                    raise BadKindError(f"bad eval kind: {eval_kind!r}")
                if robustness_dim not in ROBUSTNESS_DIMS:
                    raise BadDimError(f"bad robustness dim: {robustness_dim!r}")
                _check_digest(eval_digest)
                design_id = f"dsg-{len(self._design_ids) + 1}"
                body = {
                    "schema": SCHEMA_PIN,
                    "design_id": design_id,
                    "system_id": system_id,
                    "eval_kind": eval_kind,
                    "robustness_dim": robustness_dim,
                    "eval_digest": eval_digest,
                    "seq": seq,
                }
                rec = DesignRecord(
                    design_id=design_id,
                    system_id=system_id,
                    eval_kind=eval_kind,
                    robustness_dim=robustness_dim,
                    eval_digest=eval_digest,
                    seq=seq,
                    digest=_record_digest(body),
                )
                self._designs[design_id] = rec
                self._design_ids.append(design_id)
                self._emit("designed", {
                    "design_id": design_id,
                    "system_id": system_id,
                    "eval_kind": eval_kind,
                    "robustness_dim": robustness_dim,
                    "seq": seq,
                })
                return rec
            except RobustnessEvalError as exc:
                self._reject(seq, type(exc).__name__)
                raise

    def run(self, design_id: str, seq: int,
            outcome: str = "robust",
            score: int = 0,
            run_digest: str = "") -> RunRecord:
        """Book one host-declared evaluation run (minted run-N).

        The outcome is booked *as data*: a ``brittle`` outcome means the
        host declared the system brittle on this run, never that it is.
        ``score`` is a host-reported int in [0, 100].
        """
        with self._lock:
            self._claim(seq)
            try:
                _check_id(design_id)
                try:
                    design = self._designs[design_id]
                except KeyError:
                    raise UnknownRecordError(f"unknown design: {design_id!r}")
                if outcome not in RUN_OUTCOMES:
                    raise BadOutcomeError(f"bad outcome: {outcome!r}")
                _check_score(score)
                _check_digest(run_digest)
                run_id = f"run-{len(self._run_ids) + 1}"
                body = {
                    "schema": SCHEMA_PIN,
                    "run_id": run_id,
                    "design_id": design_id,
                    "system_id": design.system_id,
                    "outcome": outcome,
                    "score": score,
                    "run_digest": run_digest,
                    "seq": seq,
                }
                rec = RunRecord(
                    run_id=run_id,
                    design_id=design_id,
                    system_id=design.system_id,
                    outcome=outcome,
                    score=score,
                    run_digest=run_digest,
                    seq=seq,
                    digest=_record_digest(body),
                )
                self._runs[run_id] = rec
                self._run_ids.append(run_id)
                self._emit("run", {
                    "run_id": run_id,
                    "design_id": design_id,
                    "system_id": design.system_id,
                    "outcome": outcome,
                    "score": score,
                    "seq": seq,
                })
                return rec
            except RobustnessEvalError as exc:
                self._reject(seq, type(exc).__name__)
                raise

    # -- pure-read views --------------------------------------------------
    def _view_seq(self, seq: int) -> None:
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 1:
            raise SeqOrderError("seq must be a positive int")

    def _known_systems(self) -> set[str]:
        return {r.system_id for r in self._designs.values()} | \
               {r.system_id for r in self._runs.values()}

    def design_record(self, design_id: str, seq: int) -> DesignRecord:
        with self._lock:
            self._view_seq(seq)
            try:
                return self._designs[design_id]
            except KeyError:
                raise UnknownRecordError(f"unknown design: {design_id!r}")

    def run_record(self, run_id: str, seq: int) -> RunRecord:
        with self._lock:
            self._view_seq(seq)
            try:
                return self._runs[run_id]
            except KeyError:
                raise UnknownRecordError(f"unknown run: {run_id!r}")

    def designs_for(self, system_id: str, seq: int) -> tuple:
        with self._lock:
            self._view_seq(seq)
            return tuple(d for d in self._design_ids
                         if self._designs[d].system_id == system_id)

    def runs_for(self, system_id: str, seq: int) -> tuple:
        with self._lock:
            self._view_seq(seq)
            return tuple(r for r in self._run_ids
                         if self._runs[r].system_id == system_id)

    def system_ids(self, seq: int) -> tuple:
        with self._lock:
            self._view_seq(seq)
            return tuple(sorted(self._known_systems()))

    def score(self, seq: int, system_id: str = "") -> ScoreReport:
        """Derive a robustness posture report (pure read).

        ``system_id`` scopes to one system with booked rows; ``""``
        aggregates the whole ledger. Posture is ledger truth, never proof
        of real-world robustness:

        - ``untested``: no runs in scope
        - ``brittle-detected``: any run outcome ``brittle``
        - ``degraded``: any run outcome ``degraded``
        - ``inconclusive``: any run outcome ``inconclusive``
        - ``robust``: otherwise (all runs ``robust``)

        ``mean_score`` is the arithmetic mean of host-reported scores
        (rounded to 2 decimals) or ``None`` when no runs are in scope.
        """
        with self._lock:
            self._view_seq(seq)
            if system_id:
                _check_id(system_id)
                if system_id not in self._known_systems():
                    raise UnknownSystemError(f"unknown system: {system_id!r}")
                dids = self.designs_for(system_id, seq)
                rids = self.runs_for(system_id, seq)
                n_systems = 1
            else:
                dids = tuple(self._design_ids)
                rids = tuple(self._run_ids)
                n_systems = len(self._known_systems())
            tallies: dict[str, int] = {}
            scores: list[int] = []
            for rid in rids:
                r = self._runs[rid]
                tallies[r.outcome] = tallies.get(r.outcome, 0) + 1
                scores.append(r.score)
            if not rids:
                posture = "untested"
                mean_score = None
            elif tallies.get("brittle", 0) > 0:
                posture = "brittle-detected"
                mean_score = round(sum(scores) / len(scores), 2)
            elif tallies.get("degraded", 0) > 0:
                posture = "degraded"
                mean_score = round(sum(scores) / len(scores), 2)
            elif tallies.get("inconclusive", 0) > 0:
                posture = "inconclusive"
                mean_score = round(sum(scores) / len(scores), 2)
            else:
                posture = "robust"
                mean_score = round(sum(scores) / len(scores), 2)
            outcome_tallies = tuple(sorted(tallies.items()))
            body = {
                "schema": SCHEMA_PIN,
                "seq": seq,
                "system_id": system_id,
                "n_systems": n_systems,
                "n_designs": len(dids),
                "n_runs": len(rids),
                "outcome_tallies": [list(p) for p in outcome_tallies],
                "mean_score": mean_score,
                "posture": posture,
            }
            return ScoreReport(
                seq=seq,
                system_id=system_id,
                n_systems=n_systems,
                n_designs=len(dids),
                n_runs=len(rids),
                outcome_tallies=outcome_tallies,
                mean_score=mean_score,
                posture=posture,
                digest=_record_digest(body),
            )

    def stats(self, seq: int) -> dict:
        with self._lock:
            self._view_seq(seq)
            return {
                "systems": len(self._known_systems()),
                "designs": len(self._designs),
                "runs": len(self._runs),
                "rejected": self._n_rejected,
                "audit_rows": len(self._audit),
                "seq": self._seq,
            }

    def audit_log(self, seq: int) -> tuple:
        with self._lock:
            self._view_seq(seq)
            return tuple(self._audit)


def main() -> None:
    r = RobustnessEval()
    d = r.design("sys-1", 1, eval_kind="adversarial",
                 robustness_dim="adversarial-perturbations",
                 eval_digest="sha256:" + "a" * 64)
    assert d.verify() and d.design_id == "dsg-1"
    run = r.run("dsg-1", 2, outcome="robust", score=92)
    assert run.verify() and run.run_id == "run-1"
    rep = r.score(3, "sys-1")
    assert rep.verify() and rep.posture == "robust"
    assert rep.mean_score == 92.0 and rep.n_runs == 1
    print("robustness-eval OK: design, run, score, pins, audit")


if __name__ == "__main__":
    main()
