"""Superalignment research governance as a deterministic single-host decision ledger.

Research note: superalignment is the effort to solve the alignment of
superintelligent systems while they are still being built -- the loop of
running alignment research programs (scalable oversight, weak-to-strong
generalization, automated alignment research, evaluation of successor
models), booking declared evaluations of their progress, and deriving a
posture from the ledger. This module is the bookkeeping layer for that
loop. It runs no research, performs no evaluation, and proves nothing
about real alignment progress.

Distinct-layer rationale: ``scalable_oversight.py`` owns oversight
decomposition mechanics, ``weak_to_strong.py`` owns weak-to-strong training
mechanics, ``alignment_eval.py`` owns domain-specific eval mechanics,
``corrigibility.py`` owns corrigibility compliance checks. Per the
additive sibling pattern, this module is the superalignment
*governance decision* ledger none of them own: declared research
programs over a pinned research-area vocabulary, declared progress
evaluations with host-declared verdicts, and a derived posture report --
all booked as data, never evidence.

House style: frozen dataclasses, caller int seqs strictly increasing
with claim-then-burn (failed mutations consume their seq + book
``superalignment.rejected``; rewinds raise bare without consuming),
no wall-clock, RLock-guarded, fail-closed, stdlib-only +
``canonical_json`` try/except fallback, ``sha256:`` digest pins with
``verify()``, ``audit.ndjson/1`` events.

Honest scope: a booked ``progressing`` verdict means "the host declared
progress on this program", never that progress happened. ``report()``
derives posture from the ledger; it never proves real-world alignment.
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
SUPERALIGNMENT_VERSION = "superalignment.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.superalignment.v1"

#: Pinned research-area vocabulary (declared programs).
RESEARCH_AREAS = (
    "scalable-oversight",
    "weak-to-strong-generalization",
    "automated-alignment-research",
    "successor-model-evaluation",
    "alignment-interpretability",
    "corrigibility-foundation",
    "preference-learning",
    "evaluation-science",
)

#: Pinned evaluation-method vocabulary (declared methods).
EVAL_METHODS = (
    "human-review",
    "automated-eval",
    "red-team",
    "replication",
    "external-audit",
    "successor-judge",
    "sandbagging-check",
    "corrigibility-check",
)

#: Pinned evaluation-verdict vocabulary. Verdicts are booked as data.
EVAL_VERDICTS = (
    "progressing",
    "promising",
    "stalled",
    "regressed",
    "inconclusive",
    "not-evaluated",
)

#: Pinned report-posture vocabulary (derived from the ledger, never proof).
POSTURES = (
    "unevaluated",
    "at-risk",
    "stalled",
    "advancing",
    "inconclusive",
)

#: Keys banned from audit details (raw research material must not cross).
_BANNED_AUDIT_KEYS = frozenset({
    "description", "text", "content", "details_raw", "notes",
    "evidence", "payload", "raw", "secret", "plan",
    "manuscript", "codebase", "weights", "data", "prompt",
})


# ---------------------------------------------------------------------------
# Error taxonomy
# ---------------------------------------------------------------------------

class SuperalignmentError(Exception):
    """Base error for superalignment misuse."""


class SeqOrderError(SuperalignmentError):
    """Raised when a caller seq does not strictly increase."""


class BadIdError(SuperalignmentError):
    """Raised on a malformed program or evaluation id."""


class DuplicateProgramError(SuperalignmentError):
    """Raised when a program id is already registered."""


class UnknownProgramError(SuperalignmentError):
    """Raised when a program id has no booked rows."""


class UnknownRecordError(SuperalignmentError):
    """Raised when an evaluation id is unknown."""


class BadAreaError(SuperalignmentError):
    """Raised on a research area outside the pinned vocabulary."""


class BadMethodError(SuperalignmentError):
    """Raised on an evaluation method outside the pinned vocabulary."""


class BadVerdictError(SuperalignmentError):
    """Raised on an evaluation verdict outside the pinned vocabulary."""


class BadDigestError(SuperalignmentError):
    """Raised on a malformed sha256: digest pin."""


class AuditKindError(SuperalignmentError):
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


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ResearchRecord:
    """One declared superalignment research program."""

    program_id: str
    research_area: str
    program_digest: str
    seq: int
    digest: str

    def verify(self) -> bool:
        return self.digest == _record_digest(self.as_dict(include_digest=False))

    def as_dict(self, include_digest: bool = True) -> dict:
        d = {
            "schema": SCHEMA_PIN,
            "program_id": self.program_id,
            "research_area": self.research_area,
            "program_digest": self.program_digest,
            "seq": self.seq,
        }
        if include_digest:
            d["digest"] = self.digest
        return d


@dataclass(frozen=True)
class EvaluationRecord:
    """One declared progress evaluation of a research program."""

    evaluation_id: str
    program_id: str
    method: str
    verdict: str
    evidence_digest: str
    seq: int
    digest: str

    def verify(self) -> bool:
        return self.digest == _record_digest(self.as_dict(include_digest=False))

    def as_dict(self, include_digest: bool = True) -> dict:
        d = {
            "schema": SCHEMA_PIN,
            "evaluation_id": self.evaluation_id,
            "program_id": self.program_id,
            "method": self.method,
            "verdict": self.verdict,
            "evidence_digest": self.evidence_digest,
            "seq": self.seq,
        }
        if include_digest:
            d["digest"] = self.digest
        return d


@dataclass(frozen=True)
class SuperalignmentReport:
    """Derived superalignment posture report (pure read)."""

    seq: int
    program_id: str
    n_programs: int
    n_evaluations: int
    verdict_tallies: tuple
    posture: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _record_digest(self.as_dict(include_digest=False))

    def as_dict(self, include_digest: bool = True) -> dict:
        d = {
            "schema": SCHEMA_PIN,
            "seq": self.seq,
            "program_id": self.program_id,
            "n_programs": self.n_programs,
            "n_evaluations": self.n_evaluations,
            "verdict_tallies": [list(p) for p in self.verdict_tallies],
            "posture": self.posture,
        }
        if include_digest:
            d["digest"] = self.digest
        return d


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------

_AUDIT_KINDS = (
    "researched",
    "evaluated",
    "superalignment.rejected",
)


def superalignment_audit_event(kind: str, details: dict) -> dict:
    """Build one ``audit.ndjson/1`` event. Raw research keys are banned."""
    if kind not in _AUDIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    if not isinstance(details, dict):
        raise AuditKindError("details must be a dict")
    for key in details:
        if key in _BANNED_AUDIT_KEYS:
            raise AuditKindError(f"raw research key banned from audit: {key!r}")
    return {"kind": "superalignment." + kind if "." not in kind else kind,
            "details": dict(details)}


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------

class Superalignment:
    """Superalignment governance decision ledger: research -> evaluate -> report."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._programs: dict[str, ResearchRecord] = {}
        self._program_ids: list[str] = []
        self._evaluations: dict[str, EvaluationRecord] = {}
        self._evaluation_ids: list[str] = []
        self._program_evaluations: dict[str, list[str]] = {}
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
        self._audit.append(superalignment_audit_event(audit_kind, details))

    def _reject(self, seq: int, reason: str) -> None:
        self._n_rejected += 1
        self._emit("superalignment.rejected", {"seq": seq, "reason": reason})

    # -- mutations ------------------------------------------------------
    def research(self, program_id: str, seq: int,
                 research_area: str = "scalable-oversight",
                 program_digest: str = "") -> ResearchRecord:
        """Declare one superalignment research program.

        The research area is booked *as data*: the ledger runs no research
        and a booked program proves nothing about real alignment progress.
        Raw program material travels as digest pins only.
        """
        with self._lock:
            self._claim(seq)
            try:
                _check_id(program_id)
                if program_id in self._programs:
                    raise DuplicateProgramError(
                        f"program already registered: {program_id!r}"
                    )
                if research_area not in RESEARCH_AREAS:
                    raise BadAreaError(f"bad research area: {research_area!r}")
                _check_digest(program_digest)
                body = {
                    "schema": SCHEMA_PIN,
                    "program_id": program_id,
                    "research_area": research_area,
                    "program_digest": program_digest,
                    "seq": seq,
                }
                rec = ResearchRecord(
                    program_id=program_id,
                    research_area=research_area,
                    program_digest=program_digest,
                    seq=seq,
                    digest=_record_digest(body),
                )
                self._programs[program_id] = rec
                self._program_ids.append(program_id)
                self._program_evaluations[program_id] = []
                self._emit("researched", {
                    "program_id": program_id,
                    "research_area": research_area,
                    "seq": seq,
                })
                return rec
            except SuperalignmentError as exc:
                self._reject(seq, type(exc).__name__)
                raise

    def evaluate(self, program_id: str, seq: int,
                 method: str = "human-review",
                 verdict: str = "progressing",
                 evidence_digest: str = "") -> EvaluationRecord:
        """Book one declared progress evaluation (minted evl-N).

        The verdict is booked *as data*, never proof: a booked
        ``progressing`` means the host declared progress, never that
        progress happened.
        """
        with self._lock:
            self._claim(seq)
            try:
                _check_id(program_id)
                if program_id not in self._programs:
                    raise UnknownProgramError(
                        f"unknown program: {program_id!r}"
                    )
                if method not in EVAL_METHODS:
                    raise BadMethodError(f"bad method: {method!r}")
                if verdict not in EVAL_VERDICTS:
                    raise BadVerdictError(f"bad verdict: {verdict!r}")
                _check_digest(evidence_digest)
                evaluation_id = f"evl-{len(self._evaluation_ids) + 1}"
                body = {
                    "schema": SCHEMA_PIN,
                    "evaluation_id": evaluation_id,
                    "program_id": program_id,
                    "method": method,
                    "verdict": verdict,
                    "evidence_digest": evidence_digest,
                    "seq": seq,
                }
                rec = EvaluationRecord(
                    evaluation_id=evaluation_id,
                    program_id=program_id,
                    method=method,
                    verdict=verdict,
                    evidence_digest=evidence_digest,
                    seq=seq,
                    digest=_record_digest(body),
                )
                self._evaluations[evaluation_id] = rec
                self._evaluation_ids.append(evaluation_id)
                self._program_evaluations[program_id].append(evaluation_id)
                self._emit("evaluated", {
                    "evaluation_id": evaluation_id,
                    "program_id": program_id,
                    "method": method,
                    "verdict": verdict,
                    "seq": seq,
                })
                return rec
            except SuperalignmentError as exc:
                self._reject(seq, type(exc).__name__)
                raise

    # -- pure-read views --------------------------------------------------
    def _view_seq(self, seq: int) -> None:
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 1:
            raise SeqOrderError("seq must be a positive int")

    def research_record(self, program_id: str, seq: int) -> ResearchRecord:
        """Return one research record (pure read)."""
        with self._lock:
            self._view_seq(seq)
            _check_id(program_id)
            if program_id not in self._programs:
                raise UnknownProgramError(f"unknown program: {program_id!r}")
            return self._programs[program_id]

    def evaluation_record(self, evaluation_id: str, seq: int) -> EvaluationRecord:
        """Return one evaluation record (pure read)."""
        with self._lock:
            self._view_seq(seq)
            _check_id(evaluation_id)
            if evaluation_id not in self._evaluations:
                raise UnknownRecordError(f"unknown evaluation: {evaluation_id!r}")
            return self._evaluations[evaluation_id]

    def research_ids(self, seq: int) -> tuple:
        """All registered program ids in registration order (pure read)."""
        with self._lock:
            self._view_seq(seq)
            return tuple(self._program_ids)

    def evaluation_ids(self, seq: int) -> tuple:
        """All evaluation ids in mint order (pure read)."""
        with self._lock:
            self._view_seq(seq)
            return tuple(self._evaluation_ids)

    def evaluations_for(self, program_id: str, seq: int) -> tuple:
        """Evaluation ids booked against one program, in mint order (pure read)."""
        with self._lock:
            self._view_seq(seq)
            _check_id(program_id)
            if program_id not in self._programs:
                raise UnknownProgramError(f"unknown program: {program_id!r}")
            return tuple(self._program_evaluations[program_id])

    def report(self, program_id: str, seq: int) -> SuperalignmentReport:
        """Derive a posture report for one program (pure read).

        Posture rules (ledger data, never measured truth):
        - ``unevaluated`` when no evaluation is booked
        - ``at-risk`` when any booked verdict is ``regressed``
        - ``stalled`` when any booked verdict is ``stalled``
        - ``advancing`` when every booked verdict is ``progressing``
          or ``promising``
        - ``inconclusive`` otherwise
        """
        with self._lock:
            self._view_seq(seq)
            _check_id(program_id)
            if program_id not in self._programs:
                raise UnknownProgramError(f"unknown program: {program_id!r}")
            evl_ids = self._program_evaluations[program_id]
            verdicts = [self._evaluations[e].verdict for e in evl_ids]
            tallies = tuple(
                (v, verdicts.count(v)) for v in EVAL_VERDICTS if v in verdicts
            )
            if not verdicts:
                posture = "unevaluated"
            elif "regressed" in verdicts:
                posture = "at-risk"
            elif "stalled" in verdicts:
                posture = "stalled"
            elif all(v in ("progressing", "promising") for v in verdicts):
                posture = "advancing"
            else:
                posture = "inconclusive"
            body = {
                "schema": SCHEMA_PIN,
                "seq": seq,
                "program_id": program_id,
                "n_programs": len(self._programs),
                "n_evaluations": len(evl_ids),
                "verdict_tallies": [list(p) for p in tallies],
                "posture": posture,
            }
            return SuperalignmentReport(
                seq=seq,
                program_id=program_id,
                n_programs=len(self._programs),
                n_evaluations=len(evl_ids),
                verdict_tallies=tallies,
                posture=posture,
                digest=_record_digest(body),
            )

    def stats(self, seq: int) -> dict:
        """Ledger counters (pure read)."""
        with self._lock:
            self._view_seq(seq)
            return {
                "programs": len(self._programs),
                "evaluations": len(self._evaluations),
                "rejected": self._n_rejected,
            }

    def audit_log(self, seq: int) -> tuple:
        """All audit rows so far (pure read)."""
        with self._lock:
            self._view_seq(seq)
            return tuple(self._audit)

    @staticmethod
    def stdlib_only() -> bool:
        """AST self-check: the module imports only stdlib (+canonical_json)."""
        import ast
        import pathlib

        allow = {"hashlib", "json", "threading", "dataclasses", "typing",
                 "__future__", "canonical_json", "ast", "pathlib"}
        tree = ast.parse(pathlib.Path(__file__).read_text())
        found = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                found.update(n.name.split(".")[0] for n in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                found.add(node.module.split(".")[0])
        return found <= allow


def main() -> None:
    """Self-check: exercise the superalignment ledger end to end."""
    sa = Superalignment()
    sa.research("p-1", 1, research_area="scalable-oversight")
    sa.evaluate("p-1", 2, method="human-review", verdict="progressing")
    sa.evaluate("p-1", 3, method="red-team", verdict="promising")
    assert sa.research_record("p-1", 4).verify()
    assert sa.report("p-1", 5).posture == "advancing"
    assert sa.stats(6) == {"programs": 1, "evaluations": 2, "rejected": 0}
    print("superalignment OK: research, evaluate, report, pins, audit")


if __name__ == "__main__":
    main()
