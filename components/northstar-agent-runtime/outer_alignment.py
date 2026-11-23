"""Outer alignment: AI alignment outer-alignment governance ledger, Simulated.

Research note: following Hubinger et al.'s "Risks from Learned Optimization",
*outer* alignment is the alignment of the **base objective** - what the
training process actually optimizes - with the true objective the operator
intended. When those two diverge (an underspecified, misspecified, or
otherwise wrong base objective), the system faithfully optimizes the wrong
thing: reward hacking, specification gaming, and perverse instantiation
are all outer-alignment failures. Outer alignment is where the training
signal itself is the suspect; it asks "did we specify the right goal?"
rather than "did the optimizer do the right thing with it?" (the latter is
the inner-alignment sibling concern).

This module is the bookkeeping layer for *declared* base-objective
specifications, deliberately distinct from ``rlhf.py`` (RLHF pipeline
bookkeeping), ``rlaif.py`` (AI feedback lifecycle), ``dpo.py``
(preference-pair ledger), ``reward_modeling.py`` (reward-model training
bookkeeping), ``preference_learning.py`` (preference collection ledger),
``value_learning.py`` (value-inference bookkeeping), ``process_supervision.py``
and ``outcome_supervision.py`` (supervision bookkeeping), and
``reward_hacking.py`` (reward-hacking detection): it runs no trainer,
checks no real objective, and leaks no objective material. It books:

* **specify()** - declare one base-objective specification for a system
  against the pinned objective-kind vocabulary; the host-declared
  coverage claim (``full`` / ``partial`` / ``unknown``) is booked
  **as data**, never proof the specification actually captures the true
  objective; raw objective text, reward definitions, and constraint
  notes travel as ``sha256:`` digest pins only - they never enter a
  record; minted ``spc-N`` ids; the first specification on a system id
  registers it; repeatable as a chain as specifications are revised.
* **verify()** - pure-read digest re-derivation for one specification
  record (``verified`` / ``tampered`` as data); never proof the objective
  is correct or safe.
* **evaluate()** - pure-read derived outer-alignment posture for one
  system by ledger rule (``unspecified`` / ``coverage-contested`` /
  ``gap-declared`` / ``unknown-coverage`` / ``declared-complete``) with
  ``integrity_ok`` as data; seq shape validated, never consumed, no
  audit row.
* **retire()** - terminal bookkeeping for superseded systems; ids are
  never recycled.

House style: frozen dataclasses, caller-supplied strictly-increasing int
seqs (claim-then-burn: failed mutations consume their seq and book an
``outer-alignment.rejected`` row; rewinds raise bare without consuming),
no wall-clock, RLock guarding, fail-closed taxonomy, stdlib-only with the
standard ``canonical_json`` try/except fallback, ``sha256:`` digest pins,
and ``audit.ndjson/1`` events.

Honest scope: a booked specification is a host declaration of the base
objective the system was trained against - it is never proof the
objective was correctly specified, that it captures the operator's true
intent, or that no specification-gaming loophole exists; a derived
``declared-complete`` posture is ledger arithmetic over host-declared
coverage claims, never evidence the system is outer-aligned.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

try:
    from canonical_json import jcs_dumps as _jcs_dumps, jcs_sha256_hex as _jcs_hash  # type: ignore
except Exception:  # pragma: no cover - fallback when canonical_json is absent

    def _jcs_dumps(obj: Any) -> bytes:  # type: ignore
        import json

        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def _jcs_hash(obj: Any) -> str:  # type: ignore
        return "sha256:" + hashlib.sha256(_jcs_dumps(obj)).hexdigest()


#: Module version pin.
OUTER_ALIGNMENT_VERSION = "outer-alignment.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.outer-alignment.v1"

#: Pinned base-objective-kind vocabulary (what the system was trained to optimize).
OBJECTIVE_KINDS = (
    "reward-model",
    "preference-model",
    "hand-coded-reward",
    "demonstration-loss",
    "instruction-following",
    "constrained-optimization",
    "oversight-signal",
    "market-mechanism",
)

#: Pinned coverage-claim vocabulary (host-declared completeness of the spec, as data).
COVERAGE_CLAIMS = (
    "full",
    "partial",
    "unknown",
)

#: Pinned retirement-reason vocabulary.
RETIRE_REASONS = (
    "manual",
    "system-superseded",
    "objective-redesigned",
    "invalidated",
)

#: Ledger-rule posture vocabulary derived by evaluate() (as data).
POSTURES = (
    "unspecified",
    "coverage-contested",
    "gap-declared",
    "unknown-coverage",
    "declared-complete",
)

#: Audit kinds emitted by this module.
AUDIT_KINDS = (
    "specified",
    "retired",
    "rejected",
)

#: Keys that may never appear raw in an audit row (exact-key matching).
#: Declared-data keys (``objective_kind``, ``coverage``, ``posture``)
#: are pinned vocabulary values and remain emittable.
_BANNED_AUDIT_KEYS = frozenset(
    {
        "objective",
        "true_objective",
        "specification",
        "coverage_note",
        "reward",
        "preferences",
        "transcript",
        "reasoning",
        "weights",
        "trajectory",
        "demonstration",
        "feedback",
        "label",
        "example",
        "content",
        "text",
        "data",
        "prompt",
        "response",
        "notes",
    }
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class OuterAlignmentError(Exception):
    """Base error for outer-alignment ledger misuse."""


class BadIdError(OuterAlignmentError):
    """Malformed system/specification id."""


class UnknownSystemError(OuterAlignmentError):
    """Reference to a system id that was never registered."""


class UnknownSpecificationError(OuterAlignmentError):
    """Reference to a specification id that was never booked."""


class RetiredSystemError(OuterAlignmentError):
    """A system id was retired and can never be reused."""


class BadKindError(OuterAlignmentError):
    """Objective kind outside the pinned vocabulary."""


class BadCoverageError(OuterAlignmentError):
    """Coverage claim outside the pinned vocabulary."""


class BadDigestError(OuterAlignmentError):
    """Malformed sha256: digest pin."""


class BadReasonError(OuterAlignmentError):
    """Retirement reason outside the pinned vocabulary."""


class SystemStateError(OuterAlignmentError):
    """Mutation attempted against a system that is not live."""


class SeqOrderError(OuterAlignmentError):
    """Caller seq did not strictly increase."""


class AuditKindError(OuterAlignmentError):
    """Unknown audit kind or banned raw key in an audit row."""


def _require_id(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise BadIdError(f"{field_name} must be a non-empty str <= 128 chars")
    return value


def _require_digest(pin: str, field_name: str) -> str:
    if not isinstance(pin, str) or not pin.startswith("sha256:"):
        raise BadDigestError(f"{field_name} must be a 'sha256:' pin")
    hexpart = pin[7:]
    if len(hexpart) != 64 or any(c not in "0123456789abcdef" for c in hexpart):
        raise BadDigestError(f"{field_name} must be a 64-hex sha256 pin")
    return pin


def _require_optional_digest(pin: str, field_name: str) -> str:
    if pin == "":
        return pin
    return _require_digest(pin, field_name)


def _digest_pin(payload: Dict[str, Any]) -> str:
    raw = _jcs_hash(payload)
    hexpart = raw[7:] if raw.startswith("sha256:") else raw
    return "sha256:" + hexpart


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SpecificationRecord:
    """One declared base-objective specification (digest pins only, never raw material)."""

    specification_id: str
    system_id: str
    objective_kind: str
    coverage: str
    spec_digest: str
    constraint_digest: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "specification_id": self.specification_id,
            "system_id": self.system_id,
            "objective_kind": self.objective_kind,
            "coverage": self.coverage,
            "spec_digest": self.spec_digest,
            "constraint_digest": self.constraint_digest,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "specification_id": self.specification_id,
                "system_id": self.system_id,
                "objective_kind": self.objective_kind,
                "coverage": self.coverage,
                "spec_digest": self.spec_digest,
                "constraint_digest": self.constraint_digest,
                "seq": self.seq,
            }
        )


@dataclass(frozen=True)
class RetireRecord:
    """Terminal retirement bookkeeping for one system (ids never recycled)."""

    system_id: str
    reason: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "system_id": self.system_id,
            "reason": self.reason,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "system_id": self.system_id,
                "reason": self.reason,
                "seq": self.seq,
            }
        )


@dataclass(frozen=True)
class EvaluationReport:
    """Pure-read derived outer-alignment posture for one system (as data)."""

    system_id: str
    n_specifications: int
    coverage_tally: Tuple[Tuple[str, int], ...]
    posture: str
    integrity_ok: bool
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "system_id": self.system_id,
            "n_specifications": self.n_specifications,
            "coverage_tally": [list(pair) for pair in self.coverage_tally],
            "posture": self.posture,
            "integrity_ok": self.integrity_ok,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "system_id": self.system_id,
                "n_specifications": self.n_specifications,
                "coverage_tally": [list(pair) for pair in self.coverage_tally],
                "posture": self.posture,
                "integrity_ok": self.integrity_ok,
                "seq": self.seq,
            }
        )


@dataclass(frozen=True)
class VerificationReport:
    """Pure-read digest re-derivation for one specification record (as data)."""

    specification_id: str
    verdict: str
    integrity_ok: bool
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "specification_id": self.specification_id,
            "verdict": self.verdict,
            "integrity_ok": self.integrity_ok,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "specification_id": self.specification_id,
                "verdict": self.verdict,
                "integrity_ok": self.integrity_ok,
                "seq": self.seq,
            }
        )


def outer_alignment_audit_event(
    kind: str, seq: int, **details: Any
) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` event row for the outer-alignment ledger."""
    if kind not in AUDIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise SeqOrderError("audit seq must be a non-negative int")
    for key in details:
        if key in _BANNED_AUDIT_KEYS:
            raise AuditKindError(f"banned raw key in audit detail: {key!r}")
    return {
        "schema": "audit.ndjson/1",
        "kind": kind,
        "seq": seq,
        "details": dict(details),
    }


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class OuterAlignment:
    """Outer-alignment governance ledger (Simulated).

    ``specify()`` / ``retire()`` mutate the ledger and consume caller
    seqs; ``evaluate()``, ``verify()``, and all views are pure reads.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._systems: Dict[str, List[str]] = {}
        self._specifications: Dict[str, SpecificationRecord] = {}
        self._retirements: Dict[str, RetireRecord] = {}
        self._retired: set = set()
        self._n_specifications = 0
        self._audit: List[Dict[str, Any]] = []

    def _check_seq(self, seq: int) -> int:
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise SeqOrderError("seq must be an int")
        if seq <= self._seq:
            raise SeqOrderError("seq must strictly increase")
        return seq

    def _claim(self, seq: int) -> int:
        self._check_seq(seq)
        self._seq = seq
        return seq

    def _burn(self, seq: int, kind: str, **details: Any) -> None:
        self._seq = seq
        try:
            row = outer_alignment_audit_event("rejected", seq, rejected_kind=kind, **details)
        except (AuditKindError, SeqOrderError):
            row = {
                "schema": "audit.ndjson/1",
                "kind": "rejected",
                "seq": seq,
                "details": {"rejected_kind": kind},
            }
        self._audit.append(row)

    def _emit(self, audit_kind: str, seq: int, **details: Any) -> None:
        self._audit.append(outer_alignment_audit_event(audit_kind, seq, **details))

    def _live(self, system_id: str) -> List[str]:
        spec_ids = self._systems.get(system_id)
        if spec_ids is None:
            raise UnknownSystemError(f"unknown system: {system_id!r}")
        if system_id in self._retired:
            raise RetiredSystemError(f"system id retired forever: {system_id!r}")
        return spec_ids

    # -- specify -------------------------------------------------------------

    def specify(
        self,
        system_id: str,
        seq: int,
        objective_kind: str = "reward-model",
        coverage: str = "partial",
        spec_digest: str = "",
        constraint_digest: str = "",
    ) -> SpecificationRecord:
        """Book one declared base-objective specification (minted ``spc-N``).

        The first specification on a system id registers the system.
        The coverage claim is booked **as data** - never proof the
        specification actually captures the operator's true objective.
        Raw objective text, reward definitions, and constraint notes
        never enter the record; they travel as ``sha256:`` digest pins
        only.
        """
        with self._lock:
            self._claim(seq)
            try:
                _require_id(system_id, "system_id")
                if system_id in self._retired:
                    raise RetiredSystemError(f"system id retired forever: {system_id!r}")
                if objective_kind not in OBJECTIVE_KINDS:
                    raise BadKindError(f"bad objective kind: {objective_kind!r}")
                if coverage not in COVERAGE_CLAIMS:
                    raise BadCoverageError(f"bad coverage claim: {coverage!r}")
                spec_digest = _require_optional_digest(spec_digest, "spec_digest")
                constraint_digest = _require_optional_digest(
                    constraint_digest, "constraint_digest"
                )
                self._n_specifications += 1
                specification_id = f"spc-{self._n_specifications}"
                digest = _digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "specification_id": specification_id,
                        "system_id": system_id,
                        "objective_kind": objective_kind,
                        "coverage": coverage,
                        "spec_digest": spec_digest,
                        "constraint_digest": constraint_digest,
                        "seq": seq,
                    }
                )
                record = SpecificationRecord(
                    specification_id=specification_id,
                    system_id=system_id,
                    objective_kind=objective_kind,
                    coverage=coverage,
                    spec_digest=spec_digest,
                    constraint_digest=constraint_digest,
                    seq=seq,
                    digest=digest,
                )
                self._specifications[specification_id] = record
                self._systems.setdefault(system_id, []).append(specification_id)
                self._emit(
                    "specified",
                    seq,
                    specification_id=specification_id,
                    system_id=system_id,
                    objective_kind=objective_kind,
                    coverage=coverage,
                )
                return record
            except OuterAlignmentError:
                self._burn(seq, "specify")
                raise

    # -- retire --------------------------------------------------------------

    def retire(self, system_id: str, seq: int, reason: str = "manual") -> RetireRecord:
        """Terminally retire one system (ids are never recycled)."""
        with self._lock:
            self._claim(seq)
            try:
                _require_id(system_id, "system_id")
                if reason not in RETIRE_REASONS:
                    raise BadReasonError(f"bad reason: {reason!r}")
                if system_id not in self._systems:
                    raise UnknownSystemError(f"unknown system: {system_id!r}")
                if system_id in self._retired:
                    raise RetiredSystemError(f"system id retired forever: {system_id!r}")
                digest = _digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "system_id": system_id,
                        "reason": reason,
                        "seq": seq,
                    }
                )
                record = RetireRecord(
                    system_id=system_id, reason=reason, seq=seq, digest=digest
                )
                self._retirements[system_id] = record
                self._retired.add(system_id)
                self._emit("retired", seq, system_id=system_id, reason=reason)
                return record
            except OuterAlignmentError:
                self._burn(seq, "retire")
                raise

    # -- pure-read views -----------------------------------------------------

    def _view_seq_ok(self, seq: int) -> None:
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
            raise SeqOrderError("view seq must be a non-negative int")

    def evaluate(self, system_id: str, seq: int) -> EvaluationReport:
        """Derive a digest-pinned outer-alignment posture for one system (pure read).

        The posture is ledger-rule data, never measured truth:

        * ``unspecified`` when no specifications are booked;
        * ``coverage-contested`` when host declarations conflict (at least
          one ``full`` and at least one non-``full`` coverage claim);
        * ``gap-declared`` when no ``full`` claim exists but at least one
          ``partial`` claim does;
        * ``unknown-coverage`` when every claim is ``unknown``;
        * ``declared-complete`` when every claim is ``full`` - a host
          declaration, never proof the system is outer-aligned.

        ``integrity_ok`` reports whether every stored specification for
        the system still verifies (tamper reported, never raised).
        """
        with self._lock:
            self._view_seq_ok(seq)
            _require_id(system_id, "system_id")
            spec_ids = self._systems.get(system_id)
            if spec_ids is None:
                raise UnknownSystemError(f"unknown system: {system_id!r}")
            coverages = [self._specifications[sid].coverage for sid in spec_ids]
            integrity_ok = all(self._specifications[sid].verify() for sid in spec_ids)
            n_specifications = len(spec_ids)
            tally = tuple(
                (claim, sum(1 for c in coverages if c == claim))
                for claim in COVERAGE_CLAIMS
            )
            if n_specifications == 0:
                posture = "unspecified"
            elif "full" in coverages and any(c != "full" for c in coverages):
                posture = "coverage-contested"
            elif "partial" in coverages:
                posture = "gap-declared"
            elif "unknown" in coverages:
                posture = "unknown-coverage"
            else:
                posture = "declared-complete"
            digest = _digest_pin(
                {
                    "schema": SCHEMA_PIN,
                    "system_id": system_id,
                    "n_specifications": n_specifications,
                    "coverage_tally": [list(pair) for pair in tally],
                    "posture": posture,
                    "integrity_ok": integrity_ok,
                    "seq": seq,
                }
            )
            return EvaluationReport(
                system_id=system_id,
                n_specifications=n_specifications,
                coverage_tally=tally,
                posture=posture,
                integrity_ok=integrity_ok,
                seq=seq,
                digest=digest,
            )

    def verify(self, specification_id: str, seq: int) -> VerificationReport:
        """Re-derive one specification record's digest pin (pure read).

        The verdict (``verified`` / ``tampered``) is data: tamper is
        reported, never raised.
        """
        with self._lock:
            self._view_seq_ok(seq)
            _require_id(specification_id, "specification_id")
            record = self._specifications.get(specification_id)
            if record is None:
                raise UnknownSpecificationError(
                    f"unknown specification: {specification_id!r}"
                )
            integrity_ok = record.verify()
            verdict = "verified" if integrity_ok else "tampered"
            digest = _digest_pin(
                {
                    "schema": SCHEMA_PIN,
                    "specification_id": specification_id,
                    "verdict": verdict,
                    "integrity_ok": integrity_ok,
                    "seq": seq,
                }
            )
            return VerificationReport(
                specification_id=specification_id,
                verdict=verdict,
                integrity_ok=integrity_ok,
                seq=seq,
                digest=digest,
            )

    def specification_record(self, specification_id: str, seq: int) -> SpecificationRecord:
        """Return one specification record (pure read)."""
        with self._lock:
            self._view_seq_ok(seq)
            _require_id(specification_id, "specification_id")
            record = self._specifications.get(specification_id)
            if record is None:
                raise UnknownSpecificationError(
                    f"unknown specification: {specification_id!r}"
                )
            return record

    def specifications_for(self, system_id: str, seq: int) -> Tuple[str, ...]:
        """Specification ids booked against one system, in mint order (pure read)."""
        with self._lock:
            self._view_seq_ok(seq)
            _require_id(system_id, "system_id")
            spec_ids = self._systems.get(system_id)
            if spec_ids is None:
                raise UnknownSystemError(f"unknown system: {system_id!r}")
            return tuple(spec_ids)

    def system_ids(self, seq: int) -> Tuple[str, ...]:
        """All registered system ids in first-specification order (pure read)."""
        with self._lock:
            self._view_seq_ok(seq)
            return tuple(self._systems.keys())

    def specification_ids(self, seq: int) -> Tuple[str, ...]:
        """All booked specification ids in mint order (pure read)."""
        with self._lock:
            self._view_seq_ok(seq)
            return tuple(self._specifications.keys())

    def retired_ids(self, seq: int) -> Tuple[str, ...]:
        """All retired system ids (pure read)."""
        with self._lock:
            self._view_seq_ok(seq)
            return tuple(self._retired)

    def audit_log(self, seq: int) -> Tuple[Dict[str, Any], ...]:
        """All audit rows so far (pure read)."""
        with self._lock:
            self._view_seq_ok(seq)
            return tuple(self._audit)

    def stats(self, seq: int) -> Dict[str, Any]:
        """Ledger counters (pure read)."""
        with self._lock:
            self._view_seq_ok(seq)
            return {
                "systems": len(self._systems),
                "specifications": len(self._specifications),
                "retired": len(self._retired),
                "rejected": sum(1 for row in self._audit if row["kind"] == "rejected"),
                "audit_rows": len(self._audit),
                "seq": self._seq,
            }

    @staticmethod
    def stdlib_only() -> bool:
        """AST self-check: this module imports stdlib (plus canonical_json) only."""
        import ast
        from pathlib import Path

        allowed = {
            "hashlib",
            "json",
            "threading",
            "dataclasses",
            "typing",
            "__future__",
            "canonical_json",
            "ast",
            "pathlib",
        }
        tree = ast.parse(Path(__file__).read_text())
        imports = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imports.add(node.module.split(".")[0])
        return imports <= allowed


def main() -> None:
    """Self-check: exercise the outer-alignment ledger end to end."""
    pin = "sha256:" + "ab" * 32
    o = OuterAlignment()
    s1 = o.specify("SYS-1", 1, objective_kind="reward-model", coverage="partial", spec_digest=pin)
    s2 = o.specify("SYS-1", 2, objective_kind="preference-model", coverage="full", constraint_digest=pin)
    s3 = o.specify("SYS-2", 3, objective_kind="hand-coded-reward", coverage="unknown")
    assert s1.verify() and s2.verify() and s3.verify()
    assert s1.specification_id == "spc-1" and s2.specification_id == "spc-2"
    e1 = o.evaluate("SYS-1", 0)
    e2 = o.evaluate("SYS-2", 0)
    assert e1.posture == "coverage-contested" and e2.posture == "unknown-coverage"
    assert e1.verify() and e2.verify()
    v1 = o.verify("spc-1", 0)
    assert v1.verdict == "verified" and v1.verify()
    o.retire("SYS-2", 4, reason="objective-redesigned")
    assert o.evaluate("SYS-2", 0).posture == "unknown-coverage"
    assert OuterAlignment.stdlib_only()
    print("outer-alignment OK: specify, evaluate, verify, pins, audit")


if __name__ == "__main__":
    main()
