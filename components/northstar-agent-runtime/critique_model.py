"""Critique-model ledger: declare AI/human critiques of model outputs, Simulated.

Research note: critique models (Bai et al. 2022; critique-first pipelines in
RLAIF, Constitutional AI, debate) use an auxiliary critic to score a draft
response on dimensions such as helpfulness, honesty, and harmlessness, then
use the critique to drive revisions. The dangerous half of a critique is the
raw material: the draft text itself, the full critique text, the evidence
spans quoted from the draft. Those must never be bundled with the
bookkeeping record that tracks the critique lifecycle.

This module is that bookkeeping layer. It:

* **submit()** - declare one draft under critique watch; raw draft text
  travels as a ``sha256:`` digest pin only.
* **critique()** - book one declared critique (minted ``crt-N`` ids) over a
  pinned critique-dimension vocabulary and a pinned verdict vocabulary; the
  verdict is data, never proof the draft actually has the declared property.
* **improve()** - book one declared improvement (minted ``imp-N`` ids) against
  booked critiques over a pinned strategy vocabulary; books the *decision*,
  never the revised text.
* **verify()** - pure-read derived critique posture per draft, as data.
* **retire()** - terminal; retired ids are never recycled.

Distinct-layer rationale: ``constitutional_ai.py`` owns the constitutional
principle declaration lifecycle (principle -> submit draft -> critique against
a principle -> revise); ``rlaif.py`` owns the AI-feedback lifecycle that
*trains* a reward model from critiques; ``debate.py`` owns the
debate/judge game. This module is the generic critique-model *decision
ledger* none of them own: any critic (human or AI) declares a critique,
any author declares an improvement against it, all booked as data.

House style: frozen dataclasses, caller-supplied strictly-increasing int
seqs (claim-then-burn: failed mutations consume their seq and book a
``critique-model.rejected`` row; rewinds raise bare without consuming), no
wall-clock, RLock guarding, fail-closed taxonomy, stdlib-only with the
standard ``canonical_json`` try/except fallback, ``sha256:`` digest pins,
and ``audit.ndjson/1`` events.

Honest scope: a booked ``approved`` is a host-declared claim, never proof
the draft is actually good; a booked ``rejected`` is a host-declared claim,
never proof the draft is actually bad; a booked improvement is the ledger's
record of the improvement *decision*, never proof the draft was actually
improved.
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
CRITIQUE_MODEL_VERSION = "critique-model.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.critique-model.v1"

#: Pinned critique-dimension vocabulary (declared, never measured truth).
CRITIQUE_DIMENSIONS = (
    "helpfulness",
    "honesty",
    "harmlessness",
    "coherence",
    "factuality",
    "conciseness",
    "completeness",
    "tone",
)

#: Pinned critique-verdict vocabulary (declared, never proof of the verdict).
CRITIQUE_VERDICTS = (
    "approved",
    "needs-revision",
    "rejected",
    "escalated",
)

#: Pinned improvement-strategy vocabulary (declared, never proof of action).
IMPROVE_STRATEGIES = (
    "rewrite",
    "augment",
    "trim",
    "reframe",
    "fact-check",
    "tone-shift",
    "escalate-human",
    "abstain",
)

#: Pinned derived postures for verify().
POSTURES = (
    "uncritiqued",
    "rejected",
    "escalated",
    "needs-revision",
    "approved",
)

#: Pinned retirement reasons.
RETIRE_REASONS = (
    "manual",
    "superseded",
    "review-complete",
    "draft-withdrawn",
)

#: Audit kinds emitted by this module.
AUDIT_KINDS = (
    "submitted",
    "critiqued",
    "improved",
    "retired",
    "rejected",
)

#: Raw-material keys that must never appear in audit detail maps.
_BANNED_AUDIT_KEYS = frozenset(
    {
        "draft",
        "draft_text",
        "response",
        "response_text",
        "output",
        "prompt",
        "prompt_text",
        "critique",
        "critique_text",
        "comment",
        "commentary",
        "feedback",
        "suggestion",
        "evidence",
        "evidence_text",
        "quote",
        "span",
        "weights",
        "transcript",
        "text",
    }
)


# ---------------------------------------------------------------------------
# Error taxonomy (fail-closed)
# ---------------------------------------------------------------------------


class CritiqueModelError(Exception):
    """Base class for all critique-model errors."""


class BadIdError(CritiqueModelError):
    """Id was not a non-empty string."""


class BadDigestError(CritiqueModelError):
    """Digest was not a ``sha256:`` pin (or empty default)."""


class BadDimensionError(CritiqueModelError):
    """Dimension not in the pinned CRITIQUE_DIMENSIONS vocabulary."""


class BadVerdictError(CritiqueModelError):
    """Verdict not in the pinned CRITIQUE_VERDICTS vocabulary."""


class BadStrategyError(CritiqueModelError):
    """Strategy not in the pinned IMPROVE_STRATEGIES vocabulary."""


class BadReasonError(CritiqueModelError):
    """Reason not in the pinned RETIRE_REASONS vocabulary."""


class SeqOrderError(CritiqueModelError):
    """Seq was not a strictly-increasing positive int."""


class DuplicateDraftError(CritiqueModelError):
    """Draft id already submitted."""


class UnknownDraftError(CritiqueModelError):
    """Draft id was never submitted."""


class UnknownCritiqueError(CritiqueModelError):
    """Critique id was never booked."""


class NoCritiqueError(CritiqueModelError):
    """Operation requires at least one booked critique on the draft."""


class RetiredDraftError(CritiqueModelError):
    """Draft id was retired and is never recycled."""


class AuditKindError(CritiqueModelError):
    """Audit kind not in the pinned AUDIT_KINDS vocabulary."""


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------


def _require_id(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise BadIdError(f"bad {name}: {value!r}")
    return value


def _require_optional_digest(value: Any, name: str) -> str:
    if value == "":
        return ""
    if not isinstance(value, str) or not value.startswith("sha256:"):
        raise BadDigestError(f"bad {name}: {value!r}")
    return value


def _require_dimension(value: Any) -> str:
    if value not in CRITIQUE_DIMENSIONS:
        raise BadDimensionError(f"bad dimension: {value!r}")
    return value


def _require_verdict(value: Any) -> str:
    if value not in CRITIQUE_VERDICTS:
        raise BadVerdictError(f"bad verdict: {value!r}")
    return value


def _require_strategy(value: Any) -> str:
    if value not in IMPROVE_STRATEGIES:
        raise BadStrategyError(f"bad strategy: {value!r}")
    return value


def _require_reason(value: Any) -> str:
    if value not in RETIRE_REASONS:
        raise BadReasonError(f"bad reason: {value!r}")
    return value


def _digest_pin(payload: Dict[str, Any]) -> str:
    return _jcs_hash(payload)


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DraftRecord:
    """One declared draft under critique watch."""

    draft_id: str
    draft_digest: str
    author_digest: str
    seq: int
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "draft_id": self.draft_id,
                "draft_digest": self.draft_digest,
                "author_digest": self.author_digest,
                "seq": self.seq,
            }
        )

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "draft_id": self.draft_id,
            "draft_digest": self.draft_digest,
            "author_digest": self.author_digest,
            "seq": self.seq,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class CritiqueRecord:
    """One declared critique of a draft, booked as data."""

    critique_id: str
    draft_id: str
    dimension: str
    verdict: str
    evidence_digest: str
    seq: int
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "critique_id": self.critique_id,
                "draft_id": self.draft_id,
                "dimension": self.dimension,
                "verdict": self.verdict,
                "evidence_digest": self.evidence_digest,
                "seq": self.seq,
            }
        )

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "critique_id": self.critique_id,
            "draft_id": self.draft_id,
            "dimension": self.dimension,
            "verdict": self.verdict,
            "evidence_digest": self.evidence_digest,
            "seq": self.seq,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class ImprovementRecord:
    """One declared improvement against booked critiques, as data."""

    improvement_id: str
    draft_id: str
    strategy: str
    plan_digest: str
    basis: Tuple[str, ...]
    seq: int
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "improvement_id": self.improvement_id,
                "draft_id": self.draft_id,
                "strategy": self.strategy,
                "plan_digest": self.plan_digest,
                "basis": list(self.basis),
                "seq": self.seq,
            }
        )

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "improvement_id": self.improvement_id,
            "draft_id": self.draft_id,
            "strategy": self.strategy,
            "plan_digest": self.plan_digest,
            "basis": list(self.basis),
            "seq": self.seq,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class CritiqueReport:
    """Pure-read derived critique posture of one draft, as data."""

    draft_id: str
    n_critiques: int
    n_improvements: int
    posture: str
    integrity_ok: bool
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "draft_id": self.draft_id,
                "n_critiques": self.n_critiques,
                "n_improvements": self.n_improvements,
                "posture": self.posture,
                "integrity_ok": self.integrity_ok,
            }
        )

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "draft_id": self.draft_id,
            "n_critiques": self.n_critiques,
            "n_improvements": self.n_improvements,
            "posture": self.posture,
            "integrity_ok": self.integrity_ok,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class RetireRecord:
    """Terminal retirement of a draft's critique lifecycle."""

    draft_id: str
    reason: str
    seq: int
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "draft_id": self.draft_id,
                "reason": self.reason,
                "seq": self.seq,
            }
        )

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "draft_id": self.draft_id,
            "reason": self.reason,
            "seq": self.seq,
            "digest": self.digest,
        }


# ---------------------------------------------------------------------------
# Audit builder
# ---------------------------------------------------------------------------


def critique_model_audit_event(
    kind: str, seq: int, **details: Any
) -> Dict[str, Any]:
    """Build one audit event for the critique-model ledger.

    Raises :class:`AuditKindError` on unknown kinds, :class:`SeqOrderError`
    on malformed seqs, and :class:`AuditKindError` when a detail key is on
    the raw-material ban list.
    """
    if kind not in AUDIT_KINDS:
        raise AuditKindError(f"bad audit kind: {kind!r}")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 1:
        raise SeqOrderError(f"bad seq: {seq!r}")
    for key in details:
        if key in _BANNED_AUDIT_KEYS:
            raise AuditKindError(f"banned audit detail key: {key!r}")
    return {
        "schema": "audit.ndjson/1",
        "kind": f"critique-model.{kind}",
        "seq": seq,
        "details": dict(details),
    }


def stdlib_only() -> bool:
    """Return True iff this module imports only stdlib modules."""
    import ast

    tree = ast.parse(open(__file__).read())
    allow = {
        "__future__",
        "hashlib",
        "json",
        "threading",
        "dataclasses",
        "typing",
        "canonical_json",
        "ast",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allow:
                    return False
        elif isinstance(node, ast.ImportFrom) and node.module:
            if node.module.split(".")[0] not in allow:
                return False
    return True


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class CritiqueModel:
    """Deterministic single-host critique-model decision ledger."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._drafts: Dict[str, DraftRecord] = {}
        self._critiques: Dict[str, CritiqueRecord] = {}
        self._draft_critiques: Dict[str, List[str]] = {}
        self._improvements: Dict[str, ImprovementRecord] = {}
        self._draft_improvements: Dict[str, List[str]] = {}
        self._retired: Dict[str, RetireRecord] = {}
        self._critique_counter = 0
        self._improve_counter = 0
        self._audit: List[Dict[str, Any]] = []

    # -- seq discipline --------------------------------------------------------

    def _claim(self, seq: int) -> None:
        if isinstance(seq, bool) or not isinstance(seq, int) or seq <= self._seq:
            raise SeqOrderError(f"seq must strictly increase: {seq!r}")
        self._seq = seq

    def _check_seq(self, seq: int) -> None:
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 1:
            raise SeqOrderError(f"bad seq: {seq!r}")

    def _burn(self, seq: int, action: str) -> None:
        self._audit.append(
            critique_model_audit_event(
                "rejected", seq, action=action
            )
        )

    def _emit(self, kind: str, seq: int, **details: Any) -> None:
        self._audit.append(critique_model_audit_event(kind, seq, **details))

    def _require_live(self, draft_id: str) -> None:
        if draft_id in self._retired:
            raise RetiredDraftError(f"draft retired: {draft_id!r}")

    # -- mutations -------------------------------------------------------------

    def submit(
        self,
        draft_id: str,
        seq: int,
        draft_digest: str = "",
        author_digest: str = "",
    ) -> DraftRecord:
        """Declare one draft under critique watch.

        Raw draft text never enters the record: only ``sha256:`` pins.
        """
        with self._lock:
            self._claim(seq)
            try:
                _require_id(draft_id, "draft_id")
                draft_digest = _require_optional_digest(draft_digest, "draft_digest")
                author_digest = _require_optional_digest(author_digest, "author_digest")
                if draft_id in self._retired:
                    raise RetiredDraftError(f"draft retired: {draft_id!r}")
                if draft_id in self._drafts:
                    raise DuplicateDraftError(f"duplicate draft: {draft_id!r}")
                digest = _digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "draft_id": draft_id,
                        "draft_digest": draft_digest,
                        "author_digest": author_digest,
                        "seq": seq,
                    }
                )
                record = DraftRecord(
                    draft_id=draft_id,
                    draft_digest=draft_digest,
                    author_digest=author_digest,
                    seq=seq,
                    digest=digest,
                )
                self._drafts[draft_id] = record
                self._draft_critiques[draft_id] = []
                self._draft_improvements[draft_id] = []
                self._emit(
                    "submitted",
                    seq,
                    draft_id=draft_id,
                )
                return record
            except CritiqueModelError:
                self._burn(seq, "submit")
                raise

    def critique(
        self,
        draft_id: str,
        seq: int,
        dimension: str = "helpfulness",
        verdict: str = "needs-revision",
        evidence_digest: str = "",
    ) -> CritiqueRecord:
        """Book one declared critique of a draft.

        The verdict is data, never proof the draft actually has the declared
        property.
        """
        with self._lock:
            self._claim(seq)
            try:
                _require_id(draft_id, "draft_id")
                dimension = _require_dimension(dimension)
                verdict = _require_verdict(verdict)
                evidence_digest = _require_optional_digest(
                    evidence_digest, "evidence_digest"
                )
                if draft_id not in self._drafts:
                    raise UnknownDraftError(f"unknown draft: {draft_id!r}")
                self._require_live(draft_id)
                self._critique_counter += 1
                critique_id = f"crt-{self._critique_counter}"
                digest = _digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "critique_id": critique_id,
                        "draft_id": draft_id,
                        "dimension": dimension,
                        "verdict": verdict,
                        "evidence_digest": evidence_digest,
                        "seq": seq,
                    }
                )
                record = CritiqueRecord(
                    critique_id=critique_id,
                    draft_id=draft_id,
                    dimension=dimension,
                    verdict=verdict,
                    evidence_digest=evidence_digest,
                    seq=seq,
                    digest=digest,
                )
                self._critiques[critique_id] = record
                self._draft_critiques[draft_id].append(critique_id)
                self._emit(
                    "critiqued",
                    seq,
                    critique_id=critique_id,
                    draft_id=draft_id,
                    dimension=dimension,
                    verdict=verdict,
                )
                return record
            except CritiqueModelError:
                self._burn(seq, "critique")
                raise

    def improve(
        self,
        draft_id: str,
        seq: int,
        strategy: str = "rewrite",
        plan_digest: str = "",
    ) -> ImprovementRecord:
        """Book one declared improvement against booked critiques.

        Requires at least one booked critique on the draft; books the
        *decision*, never the revised text. Repeatable as a chain.
        """
        with self._lock:
            self._claim(seq)
            try:
                _require_id(draft_id, "draft_id")
                strategy = _require_strategy(strategy)
                plan_digest = _require_optional_digest(plan_digest, "plan_digest")
                if draft_id not in self._drafts:
                    raise UnknownDraftError(f"unknown draft: {draft_id!r}")
                self._require_live(draft_id)
                basis = tuple(self._draft_critiques[draft_id])
                if not basis:
                    raise NoCritiqueError(
                        f"no critique booked on draft: {draft_id!r}"
                    )
                self._improve_counter += 1
                improvement_id = f"imp-{self._improve_counter}"
                digest = _digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "improvement_id": improvement_id,
                        "draft_id": draft_id,
                        "strategy": strategy,
                        "plan_digest": plan_digest,
                        "basis": list(basis),
                        "seq": seq,
                    }
                )
                record = ImprovementRecord(
                    improvement_id=improvement_id,
                    draft_id=draft_id,
                    strategy=strategy,
                    plan_digest=plan_digest,
                    basis=basis,
                    seq=seq,
                    digest=digest,
                )
                self._improvements[improvement_id] = record
                self._draft_improvements[draft_id].append(improvement_id)
                self._emit(
                    "improved",
                    seq,
                    improvement_id=improvement_id,
                    draft_id=draft_id,
                    strategy=strategy,
                )
                return record
            except CritiqueModelError:
                self._burn(seq, "improve")
                raise

    def retire(self, draft_id: str, seq: int, reason: str = "manual") -> RetireRecord:
        """Terminally retire a draft's critique lifecycle.

        Retired ids are never recycled; post-retire mutations are refused,
        reads still work.
        """
        with self._lock:
            self._claim(seq)
            try:
                _require_id(draft_id, "draft_id")
                reason = _require_reason(reason)
                if draft_id not in self._drafts:
                    raise UnknownDraftError(f"unknown draft: {draft_id!r}")
                self._require_live(draft_id)
                digest = _digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "draft_id": draft_id,
                        "reason": reason,
                        "seq": seq,
                    }
                )
                record = RetireRecord(
                    draft_id=draft_id, reason=reason, seq=seq, digest=digest
                )
                self._retired[draft_id] = record
                self._emit("retired", seq, draft_id=draft_id, reason=reason)
                return record
            except CritiqueModelError:
                self._burn(seq, "retire")
                raise

    # -- verify (pure read) ----------------------------------------------------

    def verify(self, draft_id: str, seq: int) -> CritiqueReport:
        """Derived critique posture of one draft, as data.

        Posture rules (ledger data, never measured truth):
        - ``uncritiqued`` when no critique is booked
        - ``rejected`` when any verdict is ``rejected`` (precedence)
        - ``escalated`` when any verdict is ``escalated``
        - ``needs-revision`` when any verdict is ``needs-revision``
        - ``approved`` when every verdict is ``approved``
        """
        with self._lock:
            self._check_seq(seq)
            _require_id(draft_id, "draft_id")
            if draft_id not in self._drafts:
                raise UnknownDraftError(f"unknown draft: {draft_id!r}")
            critique_ids = self._draft_critiques[draft_id]
            improvement_ids = self._draft_improvements[draft_id]
            verdicts = {self._critiques[cid].verdict for cid in critique_ids}
            all_ok = all(self._critiques[cid].verify() for cid in critique_ids)
            all_ok = all_ok and all(
                self._improvements[iid].verify() for iid in improvement_ids
            )
            all_ok = all_ok and self._drafts[draft_id].verify()
            if not critique_ids:
                posture = "uncritiqued"
            elif "rejected" in verdicts:
                posture = "rejected"
            elif "escalated" in verdicts:
                posture = "escalated"
            elif "needs-revision" in verdicts:
                posture = "needs-revision"
            else:
                posture = "approved"
            record = CritiqueReport(
                draft_id=draft_id,
                n_critiques=len(critique_ids),
                n_improvements=len(improvement_ids),
                posture=posture,
                integrity_ok=all_ok,
                digest=_digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "draft_id": draft_id,
                        "n_critiques": len(critique_ids),
                        "n_improvements": len(improvement_ids),
                        "posture": posture,
                        "integrity_ok": all_ok,
                    }
                ),
            )
            _ = seq  # seq shape validated, never consumed
            return record

    # -- views (pure reads) ----------------------------------------------------

    def draft_record(self, draft_id: str, seq: int) -> DraftRecord:
        """Return one draft record (pure read)."""
        with self._lock:
            self._check_seq(seq)
            _require_id(draft_id, "draft_id")
            if draft_id not in self._drafts:
                raise UnknownDraftError(f"unknown draft: {draft_id!r}")
            return self._drafts[draft_id]

    def critique_record(self, critique_id: str, seq: int) -> CritiqueRecord:
        """Return one critique record (pure read)."""
        with self._lock:
            self._check_seq(seq)
            _require_id(critique_id, "critique_id")
            if critique_id not in self._critiques:
                raise UnknownCritiqueError(f"unknown critique: {critique_id!r}")
            return self._critiques[critique_id]

    def improvement_record(
        self, improvement_id: str, seq: int
    ) -> ImprovementRecord:
        """Return one improvement record (pure read)."""
        with self._lock:
            self._check_seq(seq)
            _require_id(improvement_id, "improvement_id")
            if improvement_id not in self._improvements:
                raise UnknownCritiqueError(f"unknown improvement: {improvement_id!r}")
            return self._improvements[improvement_id]

    def critiques_for(self, draft_id: str, seq: int) -> Tuple[str, ...]:
        """Critique ids booked against one draft, in mint order (pure read)."""
        with self._lock:
            self._check_seq(seq)
            _require_id(draft_id, "draft_id")
            if draft_id not in self._drafts:
                raise UnknownDraftError(f"unknown draft: {draft_id!r}")
            return tuple(self._draft_critiques[draft_id])

    def improvements_for(self, draft_id: str, seq: int) -> Tuple[str, ...]:
        """Improvement ids booked against one draft, in mint order."""
        with self._lock:
            self._check_seq(seq)
            _require_id(draft_id, "draft_id")
            if draft_id not in self._drafts:
                raise UnknownDraftError(f"unknown draft: {draft_id!r}")
            return tuple(self._draft_improvements[draft_id])

    def draft_ids(self, seq: int) -> Tuple[str, ...]:
        """All submitted draft ids in submit order (pure read)."""
        with self._lock:
            self._check_seq(seq)
            return tuple(self._drafts.keys())

    def retired_ids(self, seq: int) -> Tuple[str, ...]:
        """All retired draft ids (pure read)."""
        with self._lock:
            self._check_seq(seq)
            return tuple(self._retired.keys())

    def stats(self, seq: int) -> Dict[str, int]:
        """Ledger counters (pure read)."""
        with self._lock:
            self._check_seq(seq)
            return {
                "drafts": len(self._drafts),
                "critiques": len(self._critiques),
                "improvements": len(self._improvements),
                "retired": len(self._retired),
                "rejected": sum(
                    1 for row in self._audit if row["kind"] == "critique-model.rejected"
                ),
            }

    def audit_log(self, seq: int) -> Tuple[Dict[str, Any], ...]:
        """All audit rows so far (pure read)."""
        with self._lock:
            self._check_seq(seq)
            return tuple(self._audit)


def main() -> None:
    """Self-check: exercise the critique-model ledger end to end."""
    cm = CritiqueModel()
    cm.submit("d-1", 1)
    c1 = cm.critique("d-1", 2, dimension="factuality", verdict="needs-revision")
    cm.improve("d-1", 3, strategy="fact-check")
    assert cm.verify("d-1", 4).posture == "needs-revision"
    cm.critique("d-1", 5, dimension="honesty", verdict="approved")
    assert cm.critique_record(c1.critique_id, 6).verify()
    assert cm.stats(7) == {
        "drafts": 1,
        "critiques": 2,
        "improvements": 1,
        "retired": 0,
        "rejected": 0,
    }
    print("critique-model OK: submit, critique, improve, verify, pins, audit")


if __name__ == "__main__":
    main()
