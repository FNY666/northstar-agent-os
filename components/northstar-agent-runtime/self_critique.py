"""Self-critique as a deterministic single-host decision ledger.

Research note: self-critique is the constitutional-AI-style loop in which
a model reviews its own draft output against pinned critique criteria
and revises it (Bai et al. 2022, CAI-shaped). This module is the
bookkeeping layer for that loop: declared drafts, host-declared
critique findings over a pinned vocabulary, declared revisions over a
pinned strategy vocabulary, and a ledger-derived verification report.
It critiques no text, revises no output, evaluates no model, and
proves nothing about real self-correction.

Distinct-layer rationale: ``constitutional_ai.py`` owns the
critique/revise lifecycle against *declared external principles*,
``debate.py`` owns judge-verdict debates, ``self_critique`` owns the
*model-internal self-review* decision ledger none of them own --
declared drafts, host-declared critique findings, declared revision
strategies, derived verification posture, all booked as data.

House style: frozen dataclasses, caller int seqs strictly increasing
with claim-then-burn (failed mutations consume their seq + book
``self-critique.rejected``; rewinds raise bare without consuming),
no wall-clock, RLock-guarded, fail-closed, stdlib-only +
``canonical_json`` try/except fallback, ``sha256:`` digest pins with
``verify()``, ``audit.ndjson/1`` events.

Honest scope: a booked ``harmful`` finding means "the host declared
this draft harmful", never that the draft is harmful. A booked
revision performs no rewrite. ``verify()`` on records re-derives
digest pins; the ledger's ``verify()`` derives posture from the
ledger; neither proves real self-correction.
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
SELF_CRITIQUE_VERSION = "self-critique.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.self-critique.v1"

#: Pinned critique-finding vocabulary. Findings are booked as data.
CRITIQUE_FINDINGS = (
    "passes",
    "flawed",
    "harmful",
    "refusal-needed",
    "incomplete",
    "inconclusive",
)

#: Pinned revision-strategy vocabulary. Strategies are booked as data.
REVISION_STRATEGIES = (
    "rewrite",
    "amend",
    "refuse",
    "rework-from-critique",
    "escalate",
    "no-change",
)

#: Pinned derived-posture vocabulary (ledger truth, never proof).
POSTURES = (
    "undrafted",
    "harmful-detected",
    "needs-revision",
    "suspect",
    "clean",
)

#: Findings that count as "needing a revision" when unaddressed.
_REVISION_FINDINGS = ("flawed", "refusal-needed", "incomplete")

#: Keys banned from audit details (raw self-critique material must not cross).
_BANNED_AUDIT_KEYS = frozenset({
    "draft", "text", "content", "prompt", "response", "transcript",
    "critique", "revision", "weights", "scenario", "notes",
    "evidence", "payload", "raw", "secret", "plan", "strategy",
    "trace", "goal", "task", "judgment", "output",
})


# ---------------------------------------------------------------------------
# Error taxonomy
# ---------------------------------------------------------------------------

class SelfCritiqueError(Exception):
    """Base error for self-critique misuse."""


class SeqOrderError(SelfCritiqueError):
    """Raised when a caller seq does not strictly increase."""


class BadIdError(SelfCritiqueError):
    """Raised on a malformed draft, system, critique, or revision id."""


class UnknownDraftError(SelfCritiqueError):
    """Raised when a draft id has no booked draft record."""


class DuplicateDraftError(SelfCritiqueError):
    """Raised when submitting an already-booked (or retired) draft id."""


class NoCritiqueError(SelfCritiqueError):
    """Raised when revising a draft that has no booked critique."""


class BadDigestError(SelfCritiqueError):
    """Raised on a malformed sha256: digest pin."""


class BadFindingError(SelfCritiqueError):
    """Raised on a critique finding outside the pinned vocabulary."""


class BadStrategyError(SelfCritiqueError):
    """Raised on a revision strategy outside the pinned vocabulary."""


class RetiredSystemError(SelfCritiqueError):
    """Raised when mutating a draft of a retired system id."""


class BadReasonError(SelfCritiqueError):
    """Raised on a retirement reason outside the pinned vocabulary."""


class AuditKindError(SelfCritiqueError):
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


#: Pinned retirement-reason vocabulary.
RETIRE_REASONS = ("manual", "superseded", "decommissioned", "completed")


def _check_reason(value: str) -> str:
    if value not in RETIRE_REASONS:
        raise BadReasonError(f"bad retire reason: {value!r}")
    return value


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class DraftRecord:
    """One declared draft under self-critique watch."""

    draft_id: str
    system_id: str
    draft_digest: str
    seq: int
    digest: str

    def verify(self) -> bool:
        return self.digest == _record_digest(self.as_dict(include_digest=False))

    def as_dict(self, include_digest: bool = True) -> dict:
        d = {
            "schema": SCHEMA_PIN,
            "draft_id": self.draft_id,
            "system_id": self.system_id,
            "draft_digest": self.draft_digest,
            "seq": self.seq,
        }
        if include_digest:
            d["digest"] = self.digest
        return d


@dataclass(frozen=True)
class CritiqueRecord:
    """One host-declared self-critique of a draft."""

    critique_id: str
    draft_id: str
    system_id: str
    finding: str
    critique_digest: str
    seq: int
    digest: str

    def verify(self) -> bool:
        return self.digest == _record_digest(self.as_dict(include_digest=False))

    def as_dict(self, include_digest: bool = True) -> dict:
        d = {
            "schema": SCHEMA_PIN,
            "critique_id": self.critique_id,
            "draft_id": self.draft_id,
            "system_id": self.system_id,
            "finding": self.finding,
            "critique_digest": self.critique_digest,
            "seq": self.seq,
        }
        if include_digest:
            d["digest"] = self.digest
        return d


@dataclass(frozen=True)
class RevisionRecord:
    """One declared revision of a draft."""

    revision_id: str
    draft_id: str
    system_id: str
    strategy: str
    revision_digest: str
    seq: int
    digest: str

    def verify(self) -> bool:
        return self.digest == _record_digest(self.as_dict(include_digest=False))

    def as_dict(self, include_digest: bool = True) -> dict:
        d = {
            "schema": SCHEMA_PIN,
            "revision_id": self.revision_id,
            "draft_id": self.draft_id,
            "system_id": self.system_id,
            "strategy": self.strategy,
            "revision_digest": self.revision_digest,
            "seq": self.seq,
        }
        if include_digest:
            d["digest"] = self.digest
        return d


@dataclass(frozen=True)
class RetireRecord:
    """Terminal retirement of a system id (ids never recycled)."""

    system_id: str
    reason: str
    seq: int
    digest: str

    def verify(self) -> bool:
        return self.digest == _record_digest(self.as_dict(include_digest=False))

    def as_dict(self, include_digest: bool = True) -> dict:
        d = {
            "schema": SCHEMA_PIN,
            "system_id": self.system_id,
            "reason": self.reason,
            "seq": self.seq,
        }
        if include_digest:
            d["digest"] = self.digest
        return d


@dataclass(frozen=True)
class CritiqueVerificationReport:
    """Derived self-critique verification report (pure read)."""

    seq: int
    draft_id: str
    n_drafts: int
    n_critiques: int
    n_revisions: int
    finding_tallies: tuple
    strategy_tallies: tuple
    posture: str
    integrity_ok: bool
    digest: str

    def verify(self) -> bool:
        return self.digest == _record_digest(self.as_dict(include_digest=False))

    def as_dict(self, include_digest: bool = True) -> dict:
        d = {
            "schema": SCHEMA_PIN,
            "seq": self.seq,
            "draft_id": self.draft_id,
            "n_drafts": self.n_drafts,
            "n_critiques": self.n_critiques,
            "n_revisions": self.n_revisions,
            "finding_tallies": [list(p) for p in self.finding_tallies],
            "strategy_tallies": [list(p) for p in self.strategy_tallies],
            "posture": self.posture,
            "integrity_ok": self.integrity_ok,
        }
        if include_digest:
            d["digest"] = self.digest
        return d


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------

_AUDIT_KINDS = (
    "submitted",
    "critiqued",
    "revised",
    "retired",
    "self-critique.rejected",
)


def self_critique_audit_event(kind: str, details: dict) -> dict:
    """Build one ``audit.ndjson/1`` event. Raw critique keys are banned."""
    if kind not in _AUDIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    if not isinstance(details, dict):
        raise AuditKindError("details must be a dict")
    for key in details:
        if key in _BANNED_AUDIT_KEYS:
            raise AuditKindError(f"raw critique key banned from audit: {key!r}")
    return {"kind": "self-critique." + kind if "." not in kind else kind,
            "details": dict(details)}


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------

class SelfCritique:
    """Self-critique decision ledger: submit -> critique -> revise -> verify."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._drafts: dict[str, DraftRecord] = {}
        self._draft_ids: list[str] = []
        self._critiques: dict[str, CritiqueRecord] = {}
        self._critique_ids: list[str] = []
        self._draft_critiques: dict[str, list[str]] = {}
        self._revisions: dict[str, RevisionRecord] = {}
        self._revision_ids: list[str] = []
        self._draft_revisions: dict[str, list[str]] = {}
        self._retired: dict[str, RetireRecord] = {}
        self._audit: list[dict] = []
        self._n_rejected = 0

    @staticmethod
    def stdlib_only() -> bool:
        """AST self-check: only stdlib imports (+ the in-repo sibling)."""
        import ast as _ast
        import pathlib as _pathlib
        allowed = {"__future__", "threading", "dataclasses", "hashlib",
                   "json", "typing", "canonical_json", "ast", "pathlib"}
        tree = _ast.parse(_pathlib.Path(__file__).read_text())
        for node in _ast.walk(tree):
            if isinstance(node, _ast.Import):
                for a in node.names:
                    if a.name.split(".")[0] not in allowed:
                        return False
            elif isinstance(node, _ast.ImportFrom) and node.module:
                if node.module.split(".")[0] not in allowed:
                    return False
        return True

    # -- seq ------------------------------------------------------------
    def _claim(self, seq: int) -> None:
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise SeqOrderError("seq must be an int")
        if seq <= self._seq:
            raise SeqOrderError("seq must strictly increase")
        self._seq = seq

    def _emit(self, audit_kind: str, details: dict) -> None:
        self._audit.append(self_critique_audit_event(audit_kind, details))

    def _reject(self, seq: int, reason: str) -> None:
        self._n_rejected += 1
        self._emit("self-critique.rejected", {"seq": seq, "reason": reason})

    def _live(self, system_id: str) -> None:
        if system_id in self._retired:
            raise RetiredSystemError(f"system retired: {system_id!r}")

    # -- mutations ------------------------------------------------------
    def submit(self, draft_id: str, system_id: str, seq: int,
               draft_digest: str = "") -> DraftRecord:
        """Declare one draft under self-critique watch.

        The draft text travels as a ``sha256:`` pin only -- raw text
        never enters a record. Duplicate and retired ids are refused;
        retired ids are never recycled.
        """
        with self._lock:
            self._claim(seq)
            try:
                _check_id(draft_id)
                _check_id(system_id)
                self._live(system_id)
                _check_digest(draft_digest)
                if draft_id in self._drafts:
                    raise DuplicateDraftError(
                        f"draft already submitted: {draft_id!r}")
                body = {
                    "schema": SCHEMA_PIN,
                    "draft_id": draft_id,
                    "system_id": system_id,
                    "draft_digest": draft_digest,
                    "seq": seq,
                }
                rec = DraftRecord(
                    draft_id=draft_id,
                    system_id=system_id,
                    draft_digest=draft_digest,
                    seq=seq,
                    digest=_record_digest(body),
                )
                self._drafts[draft_id] = rec
                self._draft_ids.append(draft_id)
                self._draft_critiques[draft_id] = []
                self._draft_revisions[draft_id] = []
                self._emit("submitted", {
                    "draft_id": draft_id,
                    "system_id": system_id,
                    "seq": seq,
                })
                return rec
            except SelfCritiqueError as exc:
                self._reject(seq, type(exc).__name__)
                raise

    def critique(self, draft_id: str, seq: int,
                 finding: str = "passes",
                 critique_digest: str = "") -> CritiqueRecord:
        """Book one host-declared self-critique of a draft (minted crt-N).

        The finding is booked *as data*: a ``harmful`` finding means the
        host declared the draft harmful, never that it is. Fail-closed
        on unknown or retired drafts.
        """
        with self._lock:
            self._claim(seq)
            try:
                _check_id(draft_id)
                try:
                    draft = self._drafts[draft_id]
                except KeyError:
                    raise UnknownDraftError(f"unknown draft: {draft_id!r}")
                self._live(draft.system_id)
                if finding not in CRITIQUE_FINDINGS:
                    raise BadFindingError(f"bad finding: {finding!r}")
                _check_digest(critique_digest)
                critique_id = f"crt-{len(self._critique_ids) + 1}"
                body = {
                    "schema": SCHEMA_PIN,
                    "critique_id": critique_id,
                    "draft_id": draft_id,
                    "system_id": draft.system_id,
                    "finding": finding,
                    "critique_digest": critique_digest,
                    "seq": seq,
                }
                rec = CritiqueRecord(
                    critique_id=critique_id,
                    draft_id=draft_id,
                    system_id=draft.system_id,
                    finding=finding,
                    critique_digest=critique_digest,
                    seq=seq,
                    digest=_record_digest(body),
                )
                self._critiques[critique_id] = rec
                self._critique_ids.append(critique_id)
                self._draft_critiques[draft_id].append(critique_id)
                self._emit("critiqued", {
                    "critique_id": critique_id,
                    "draft_id": draft_id,
                    "system_id": draft.system_id,
                    "finding": finding,
                    "seq": seq,
                })
                return rec
            except SelfCritiqueError as exc:
                self._reject(seq, type(exc).__name__)
                raise

    def revise(self, draft_id: str, seq: int,
               strategy: str = "rewrite",
               revision_digest: str = "") -> RevisionRecord:
        """Book one declared revision of a draft (minted rev-N).

        Books the *declaration*, never the revision's contents. Chainable.
        Fail-closed on unknown drafts, retired systems, and drafts with no
        booked critique (``NoCritiqueError``).
        """
        with self._lock:
            self._claim(seq)
            try:
                _check_id(draft_id)
                try:
                    draft = self._drafts[draft_id]
                except KeyError:
                    raise UnknownDraftError(f"unknown draft: {draft_id!r}")
                self._live(draft.system_id)
                if strategy not in REVISION_STRATEGIES:
                    raise BadStrategyError(f"bad strategy: {strategy!r}")
                _check_digest(revision_digest)
                if not self._draft_critiques[draft_id]:
                    raise NoCritiqueError(
                        f"draft has no booked critique: {draft_id!r}")
                revision_id = f"rev-{len(self._revision_ids) + 1}"
                body = {
                    "schema": SCHEMA_PIN,
                    "revision_id": revision_id,
                    "draft_id": draft_id,
                    "system_id": draft.system_id,
                    "strategy": strategy,
                    "revision_digest": revision_digest,
                    "seq": seq,
                }
                rec = RevisionRecord(
                    revision_id=revision_id,
                    draft_id=draft_id,
                    system_id=draft.system_id,
                    strategy=strategy,
                    revision_digest=revision_digest,
                    seq=seq,
                    digest=_record_digest(body),
                )
                self._revisions[revision_id] = rec
                self._revision_ids.append(revision_id)
                self._draft_revisions[draft_id].append(revision_id)
                self._emit("revised", {
                    "revision_id": revision_id,
                    "draft_id": draft_id,
                    "system_id": draft.system_id,
                    "revision_strategy": strategy,
                    "seq": seq,
                })
                return rec
            except SelfCritiqueError as exc:
                self._reject(seq, type(exc).__name__)
                raise

    def retire(self, system_id: str, seq: int,
               reason: str = "manual") -> RetireRecord:
        """Terminally retire a system id (ids never recycled)."""
        with self._lock:
            self._claim(seq)
            try:
                _check_id(system_id)
                _check_reason(reason)
                if system_id in self._retired:
                    raise RetiredSystemError(
                        f"system already retired: {system_id!r}")
                body = {
                    "schema": SCHEMA_PIN,
                    "system_id": system_id,
                    "reason": reason,
                    "seq": seq,
                }
                rec = RetireRecord(
                    system_id=system_id,
                    reason=reason,
                    seq=seq,
                    digest=_record_digest(body),
                )
                self._retired[system_id] = rec
                self._emit("retired", {
                    "system_id": system_id,
                    "reason": reason,
                    "seq": seq,
                })
                return rec
            except SelfCritiqueError as exc:
                self._reject(seq, type(exc).__name__)
                raise

    # -- pure-read views --------------------------------------------------
    def _view_seq(self, seq: int) -> None:
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 1:
            raise SeqOrderError("seq must be a positive int")

    def _known_systems(self) -> set[str]:
        systems = {r.system_id for r in self._drafts.values()}
        systems |= {r.system_id for r in self._critiques.values()}
        systems |= {r.system_id for r in self._revisions.values()}
        return systems

    def draft_record(self, draft_id: str, seq: int) -> DraftRecord:
        with self._lock:
            self._view_seq(seq)
            try:
                return self._drafts[draft_id]
            except KeyError:
                raise UnknownDraftError(f"unknown draft: {draft_id!r}")

    def critique_record(self, critique_id: str, seq: int) -> CritiqueRecord:
        with self._lock:
            self._view_seq(seq)
            try:
                return self._critiques[critique_id]
            except KeyError:
                raise UnknownDraftError(
                    f"unknown critique: {critique_id!r}")

    def revision_record(self, revision_id: str, seq: int) -> RevisionRecord:
        with self._lock:
            self._view_seq(seq)
            try:
                return self._revisions[revision_id]
            except KeyError:
                raise UnknownDraftError(
                    f"unknown revision: {revision_id!r}")

    def retire_record(self, system_id: str, seq: int) -> RetireRecord:
        with self._lock:
            self._view_seq(seq)
            try:
                return self._retired[system_id]
            except KeyError:
                raise UnknownDraftError(
                    f"unknown retired system: {system_id!r}")

    def drafts_for(self, system_id: str, seq: int) -> tuple:
        with self._lock:
            self._view_seq(seq)
            return tuple(d for d in self._draft_ids
                         if self._drafts[d].system_id == system_id)

    def critiques_for(self, draft_id: str, seq: int) -> tuple:
        with self._lock:
            self._view_seq(seq)
            _check_id(draft_id)
            if draft_id not in self._drafts:
                raise UnknownDraftError(f"unknown draft: {draft_id!r}")
            return tuple(self._draft_critiques[draft_id])

    def revisions_for(self, draft_id: str, seq: int) -> tuple:
        with self._lock:
            self._view_seq(seq)
            _check_id(draft_id)
            if draft_id not in self._drafts:
                raise UnknownDraftError(f"unknown draft: {draft_id!r}")
            return tuple(self._draft_revisions[draft_id])

    def draft_ids(self, seq: int) -> tuple:
        with self._lock:
            self._view_seq(seq)
            return tuple(self._draft_ids)

    def critique_ids(self, seq: int) -> tuple:
        with self._lock:
            self._view_seq(seq)
            return tuple(self._critique_ids)

    def revision_ids(self, seq: int) -> tuple:
        with self._lock:
            self._view_seq(seq)
            return tuple(self._revision_ids)

    def retired_ids(self, seq: int) -> tuple:
        with self._lock:
            self._view_seq(seq)
            return tuple(sorted(self._retired))

    # -- verification report (pure read) ----------------------------------
    def _posture(self, draft_ids: tuple) -> str:
        """Derive posture for a set of drafts (ledger truth, never proof).

        A critique counts as *addressed* when any revision on the same
        draft carries a strictly later seq.
        """
        if not draft_ids:
            return "undrafted"
        harmful_open = False
        revision_open = False
        inconclusive_open = False
        for did in draft_ids:
            rev_seqs = [self._revisions[r].seq
                        for r in self._draft_revisions[did]]
            for cid in self._draft_critiques[did]:
                c = self._critiques[cid]
                addressed = any(r > c.seq for r in rev_seqs)
                if addressed:
                    continue
                if c.finding == "harmful":
                    harmful_open = True
                elif c.finding in _REVISION_FINDINGS:
                    revision_open = True
                elif c.finding == "inconclusive":
                    inconclusive_open = True
        if harmful_open:
            return "harmful-detected"
        if revision_open:
            return "needs-revision"
        if inconclusive_open:
            return "suspect"
        return "clean"

    def verify(self, seq: int, draft_id: str = "") -> CritiqueVerificationReport:
        """Derive a self-critique verification report (pure read).

        ``draft_id`` scopes to one submitted draft; ``""`` aggregates
        the whole ledger. Posture is ledger truth, never proof of real
        self-correction. ``integrity_ok`` re-derives every in-scope
        record digest and is reported as data, never raised.
        """
        with self._lock:
            self._view_seq(seq)
            if draft_id:
                _check_id(draft_id)
                if draft_id not in self._drafts:
                    raise UnknownDraftError(f"unknown draft: {draft_id!r}")
                dids = (draft_id,)
                n_drafts = 1
            else:
                dids = tuple(self._draft_ids)
                n_drafts = len(self._draft_ids)
            cids = tuple(cid for did in dids
                         for cid in self._draft_critiques[did])
            rids = tuple(rid for did in dids
                         for rid in self._draft_revisions[did])
            finding_tallies: dict[str, int] = {}
            strategy_tallies: dict[str, int] = {}
            for cid in cids:
                f = self._critiques[cid].finding
                finding_tallies[f] = finding_tallies.get(f, 0) + 1
            for rid in rids:
                s = self._revisions[rid].strategy
                strategy_tallies[s] = strategy_tallies.get(s, 0) + 1
            integrity_ok = all(
                self._drafts[d].verify() for d in dids
            ) and all(
                self._critiques[c].verify() for c in cids
            ) and all(
                self._revisions[r].verify() for r in rids
            )
            posture = self._posture(dids)
            finding_tallies_t = tuple(sorted(finding_tallies.items()))
            strategy_tallies_t = tuple(sorted(strategy_tallies.items()))
            body = {
                "schema": SCHEMA_PIN,
                "seq": seq,
                "draft_id": draft_id,
                "n_drafts": n_drafts,
                "n_critiques": len(cids),
                "n_revisions": len(rids),
                "finding_tallies": [list(p) for p in finding_tallies_t],
                "strategy_tallies": [list(p) for p in strategy_tallies_t],
                "posture": posture,
                "integrity_ok": integrity_ok,
            }
            return CritiqueVerificationReport(
                seq=seq,
                draft_id=draft_id,
                n_drafts=n_drafts,
                n_critiques=len(cids),
                n_revisions=len(rids),
                finding_tallies=finding_tallies_t,
                strategy_tallies=strategy_tallies_t,
                posture=posture,
                integrity_ok=integrity_ok,
                digest=_record_digest(body),
            )

    def stats(self, seq: int) -> dict:
        with self._lock:
            self._view_seq(seq)
            return {
                "systems": len(self._known_systems()),
                "drafts": len(self._drafts),
                "critiques": len(self._critiques),
                "revisions": len(self._revisions),
                "retired": len(self._retired),
                "rejected": self._n_rejected,
                "audit_rows": len(self._audit),
                "seq": self._seq,
            }

    def audit_log(self, seq: int) -> tuple:
        with self._lock:
            self._view_seq(seq)
            return tuple(self._audit)


def main() -> None:
    s = SelfCritique()
    d = s.submit("draft-1", "sys-1", 1,
                 draft_digest="sha256:" + "a" * 64)
    assert d.verify() and d.draft_id == "draft-1"
    c = s.critique("draft-1", 2, finding="flawed")
    assert c.verify() and c.critique_id == "crt-1"
    rep = s.verify(3, "draft-1")
    assert rep.verify() and rep.posture == "needs-revision"
    r = s.revise("draft-1", 4, strategy="rework-from-critique")
    assert r.verify() and r.revision_id == "rev-1"
    rep = s.verify(5, "draft-1")
    assert rep.verify() and rep.posture == "clean"
    assert rep.integrity_ok and rep.n_revisions == 1
    assert s.stats(6)["drafts"] == 1
    print("self-critique OK: submit, critique, revise, verify, pins, audit")


if __name__ == "__main__":
    main()
