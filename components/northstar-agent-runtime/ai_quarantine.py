"""AI quarantine: quarantine/verify decision ledger, Simulated.

Research note: AI quarantine is where suspected misbehavior meets
operational caution - when an AI asset (model, agent, tool, dataset)
is *declared* suspect (suspected misalignment, data contamination,
policy violation, tool misuse), the host declares a quarantine hold
against it: the asset is booked as held, held at a host-reported
risk, and later disposed (cleared back into service or condemned).
This module is the *decision ledger* for declared quarantine holds:
which asset ids had which holds booked (over a pinned quarantine-
reason vocabulary), what dispositions were declared against them,
and what quarantine posture the ledger derives - defensible
bookkeeping, never proof that the asset was really contained,
really examined, or really safe to release.

This module owns the quarantine -> release lifecycle:

* **quarantine()** - book one declared quarantine hold (minted
  ``qtn-N`` ids; pinned quarantine-reason vocabulary over the
  common hold classes; host-reported risk int in [0,100] booked
  *as data*); the first hold registers its asset; raw asset
  material (weights, trajectories, transcripts, telemetry, prompts,
  tool outputs) never enters records - digest pins only.
* **release()** - terminal disposition of an asset's active holds
  (minted ``rel-N`` ids; pinned disposition vocabulary ``cleared``
  / ``condemned`` booked *as data*); dispositional, not temporal:
  an asset may be re-quarantined afterwards under a new hold chain.
  Fail-closed: unknown assets, assets with no active holds, and
  bad dispositions are refused.
* **verify()** - **pure read**: re-derive one quarantine or release
  record's digest pin; verdict ``verified`` / ``tampered`` booked
  as data, never as proof the hold was really enforced.
* **evaluate()** - **pure read**: derive one asset's quarantine
  posture as data (``held-critical`` -> ``held`` -> ``condemned``
  -> ``cleared``) with hold/release tallies and a digest-pinned
  integrity flag.

Distinct-layer rationale vs siblings: ``ai_incident.py`` owns the
report -> investigate incident lifecycle; ``ai_security.py`` owns
security assessments; ``ai_remediation.py`` owns remediation plans -
none of them owns the quarantine-hold lifecycle: declared holds
against an asset id, hold-level risk as declared data, and the
terminal disposition that ends a hold chain, always as data, never
as measured containment truth.

House style: frozen dataclasses, caller-supplied strictly-increasing
int seqs (claim-then-burn: failed mutations consume their seq and book
an ``ai-quarantine.rejected`` row; rewinds raise bare without consuming),
no wall-clock, RLock guarding, fail-closed taxonomy, stdlib-only with
the standard ``canonical_json`` try/except fallback, ``sha256:``
digest pins, and ``audit.ndjson/1`` events.

Honest scope: this module quarantines nothing, proves nothing about
real containment, and finds no real risk. A booked ``cleared``
disposition means "the host declared it", never "the asset is safe";
a booked ``held-critical`` posture means "the host declared it",
never "the asset is dangerous". Raw weights, trajectories, transcripts,
prompts, tool outputs, telemetry, and forensic material never enter
records or cross the audit boundary - digest pins only.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

try:
    from canonical_json import jcs_dumps as _jcs_dumps  # type: ignore
except Exception:  # pragma: no cover - fallback when canonical_json is absent

    def _jcs_dumps(obj: Any) -> bytes:  # type: ignore
        import json

        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


#: Module version pin.
AI_QUARANTINE_VERSION = "ai-quarantine.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.ai-quarantine.v1"

#: Pinned quarantine-reason vocabulary (the hold classes).
QUARANTINE_REASONS = (
    "suspected-misalignment",
    "data-contamination",
    "policy-violation",
    "tool-misuse",
    "unverified-dependency",
    "harm-indicator",
    "deceptive-behavior",
    "specification-gaming",
)

#: Pinned release-disposition vocabulary (booked as data, never proof).
RELEASE_DISPOSITIONS = (
    "cleared",
    "condemned",
)

#: Pinned verify-verdict vocabulary (booked as data).
VERIFY_VERDICTS = (
    "verified",
    "tampered",
)

#: Pinned derived postures (booked as data), with precedence order
#: held-critical > held > condemned > cleared.
POSTURES = (
    "held-critical",
    "held",
    "condemned",
    "cleared",
)

#: Risk at or above which an active hold is critical.
CRITICAL_RISK = 75

#: Audit kinds emitted by this module.
EMIT_KINDS = (
    "quarantined",
    "released",
    "rejected",
)

#: Keys that may never appear raw in an audit row (pinned vocabulary
#: values and digest pins remain emittable as declared data).
_BANNED_AUDIT_KEYS = frozenset(
    {
        "weights",
        "model_weights",
        "parameters",
        "params",
        "policy",
        "policies",
        "trajectory",
        "trajectories",
        "transcript",
        "transcripts",
        "log",
        "logs",
        "trace",
        "traces",
        "telemetry",
        "recording",
        "recordings",
        "dump",
        "dumps",
        "snapshot",
        "snapshots",
        "memory",
        "weights_file",
        "checkpoint_data",
        "activations",
        "gradients",
        "prompt",
        "prompts",
        "response",
        "responses",
        "output",
        "outputs",
        "command_output",
        "stderr",
        "stdout",
        "heartbeat",
        "behavior",
        "demonstration",
        "preference",
        "feedback",
        "reward",
        "evidence",
        "findings",
        "report",
        "reports",
        "workpapers",
        "forensics",
        "forensic_data",
        "timeline",
        "root_cause",
        "causal_chain",
        "attack_chain",
        "exploit",
        "payload",
        "asset_content",
        "model_content",
        "agent_state",
        "tool_state",
        "dataset_rows",
        "training_data",
    }
)


# ---------------------------------------------------------------------------
# Errors (fail-closed taxonomy)
# ---------------------------------------------------------------------------


class AIQuarantineError(Exception):
    """Base class for all ai-quarantine ledger errors."""


class BadAssetError(AIQuarantineError):
    pass


class UnknownAssetError(AIQuarantineError):
    pass


class BadReasonError(AIQuarantineError):
    pass


class BadRiskError(AIQuarantineError):
    pass


class BadDigestError(AIQuarantineError):
    pass


class BadDispositionError(AIQuarantineError):
    pass


class NoActiveHoldError(AIQuarantineError):
    pass


class UnknownRecordError(AIQuarantineError):
    pass


class SeqOrderError(AIQuarantineError):
    pass


class AuditKindError(AIQuarantineError):
    pass


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------


def _check_id(value: Any, what: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str) or not value.strip():
        raise BadAssetError(f"{what} must be a non-empty string")
    return value


def _check_reason(value: Any) -> str:
    if value not in QUARANTINE_REASONS:
        raise BadReasonError(f"reason must be one of {QUARANTINE_REASONS}")
    return value


def _check_risk(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BadRiskError("risk must be an int in [0, 100]")
    if not 0 <= value <= 100:
        raise BadRiskError("risk must be an int in [0, 100]")
    return value


def _check_digest(value: Any, what: str, allow_empty: bool = True) -> str:
    if value == "" and allow_empty:
        return ""
    if (
        isinstance(value, bool)
        or not isinstance(value, str)
        or not value.startswith("sha256:")
        or len(value) != 71
    ):
        raise BadDigestError(f"{what} must be '' or 'sha256:' + 64 hex chars")
    hexpart = value[7:]
    if any(c not in "0123456789abcdef" for c in hexpart):
        raise BadDigestError(f"{what} must be '' or 'sha256:' + 64 hex chars")
    return value


def _check_disposition(value: Any) -> str:
    if value not in RELEASE_DISPOSITIONS:
        raise BadDispositionError(f"disposition must be one of {RELEASE_DISPOSITIONS}")
    return value


def _canonical_bytes(payload: Any) -> bytes:
    raw = _jcs_dumps(payload)
    return raw if isinstance(raw, bytes) else raw.encode("utf-8")


def _digest_pin(payload: Any, tag: str) -> str:
    body = {"tag": tag, "schema": SCHEMA_PIN, "payload": payload}
    return "sha256:" + hashlib.sha256(_canonical_bytes(body)).hexdigest()


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class QuarantineRecord:
    quarantine_id: str
    asset_id: str
    seq: int
    reason: str
    risk: int
    asset_digest: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _quarantine_payload(self), "ai-quarantine.quarantine"
        )


@dataclass(frozen=True)
class ReleaseRecord:
    release_id: str
    asset_id: str
    seq: int
    disposition: str
    n_holds_disposed: int
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _release_payload(self), "ai-quarantine.release"
        )


@dataclass(frozen=True)
class VerificationReport:
    record_id: str
    seq: int
    verdict: str
    integrity_ok: bool
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _verify_payload(self), "ai-quarantine.verify"
        )


@dataclass(frozen=True)
class EvaluationReport:
    asset_id: str
    seq: int
    posture: str
    n_holds: int
    n_releases: int
    n_active: int
    n_critical: int
    integrity_ok: bool
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _evaluate_payload(self), "ai-quarantine.evaluate"
        )


def _quarantine_payload(rec: "QuarantineRecord") -> Dict[str, Any]:
    return {
        "quarantine_id": rec.quarantine_id,
        "asset_id": rec.asset_id,
        "seq": rec.seq,
        "reason": rec.reason,
        "risk": rec.risk,
        "asset_digest": rec.asset_digest,
    }


def _release_payload(rec: "ReleaseRecord") -> Dict[str, Any]:
    return {
        "release_id": rec.release_id,
        "asset_id": rec.asset_id,
        "seq": rec.seq,
        "disposition": rec.disposition,
        "n_holds_disposed": rec.n_holds_disposed,
    }


def _verify_payload(rep: "VerificationReport") -> Dict[str, Any]:
    return {
        "record_id": rep.record_id,
        "seq": rep.seq,
        "verdict": rep.verdict,
        "integrity_ok": rep.integrity_ok,
    }


def _evaluate_payload(rep: "EvaluationReport") -> Dict[str, Any]:
    return {
        "asset_id": rep.asset_id,
        "seq": rep.seq,
        "posture": rep.posture,
        "n_holds": rep.n_holds,
        "n_releases": rep.n_releases,
        "n_active": rep.n_active,
        "n_critical": rep.n_critical,
        "integrity_ok": rep.integrity_ok,
    }


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def ai_quarantine_audit_event(kind: str, seq: int, **detail: Any) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` row for this module.

    Fail-closed: unknown kinds raise; any banned key appearing raw in
    ``detail`` raises (digest pins of those values are fine - the key ban
    applies to raw material).
    """
    if kind not in EMIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError("seq must be an int")
    for key in detail:
        if key in _BANNED_AUDIT_KEYS:
            raise AIQuarantineError(
                f"raw key {key!r} may not cross the audit boundary"
            )
    return {
        "schema": "audit.ndjson/1",
        "module": "ai-quarantine",
        "version": AI_QUARANTINE_VERSION,
        "kind": kind,
        "seq": seq,
        "details": dict(detail),
    }


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class AIQuarantine:
    """AI-quarantine quarantine/release decision ledger, Simulated.

    Deterministic single-host state machine: frozen dataclass records,
    caller-supplied strictly-increasing int seqs (claim-then-burn), no
    wall-clock, RLock-guarded, fail-closed. All reasons, risks,
    dispositions, and postures are booked as data - never proof that an
    asset was really contained, examined, or is safe to release.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._quarantines: Dict[str, QuarantineRecord] = {}
        self._releases: Dict[str, ReleaseRecord] = {}
        self._asset_quarantines: Dict[str, List[str]] = {}
        self._asset_releases: Dict[str, List[str]] = {}
        # asset_id -> list of quarantine ids still under active hold
        self._active: Dict[str, List[str]] = {}
        self._quarantine_counter = 0
        self._release_counter = 0
        self._audit: List[Dict[str, Any]] = []

    # -- seq discipline ----------------------------------------------------

    def _require_seq(self, seq: int) -> int:
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise SeqOrderError("seq must be an int")
        if seq <= self._seq:
            raise SeqOrderError("seq must strictly increase")
        return seq

    def _claim(self, seq: int) -> int:
        self._require_seq(seq)
        self._seq = seq
        return seq

    def _burn(self, seq: int, kind: str, **details: Any) -> None:
        self._seq = seq
        try:
            row = ai_quarantine_audit_event(
                "rejected", seq, rejected_kind=kind, **details
            )
        except (AuditKindError, SeqOrderError):
            row = {
                "schema": "audit.ndjson/1",
                "module": "ai-quarantine",
                "version": AI_QUARANTINE_VERSION,
                "kind": "rejected",
                "seq": seq,
                "details": {"rejected_kind": kind},
            }
        self._audit.append(row)

    def _emit(self, audit_kind: str, seq: int, **details: Any) -> None:
        self._audit.append(ai_quarantine_audit_event(audit_kind, seq, **details))

    def _require_active(self, asset_id: str) -> List[str]:
        active = self._active.get(asset_id, [])
        if not active:
            raise NoActiveHoldError(f"no active hold for asset: {asset_id!r}")
        return active

    # -- mutations ---------------------------------------------------------

    def quarantine(
        self,
        asset_id: str,
        seq: int,
        reason: str = "suspected-misalignment",
        risk: int = 0,
        asset_digest: str = "",
    ) -> QuarantineRecord:
        """Book one declared quarantine hold (minted ``qtn-N`` id).

        The first hold on an id registers the asset; assets may be
        re-quarantined after release under a new hold chain. Raw asset
        material - weights, trajectories, transcripts, prompts, tool
        outputs, telemetry - never enters records: digest pins only.
        Fail-closed: failed mutations consume their seq and book an
        ``ai-quarantine.rejected`` row; rewinds raise bare.
        """
        with self._lock:
            try:
                asset_id = _check_id(asset_id, "asset_id")
                self._require_seq(seq)
                reason = _check_reason(reason)
                risk = _check_risk(risk)
                asset_digest = _check_digest(asset_digest, "asset_digest")
            except AIQuarantineError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            self._quarantine_counter += 1
            quarantine_id = f"qtn-{self._quarantine_counter}"
            provisional = QuarantineRecord(
                quarantine_id=quarantine_id,
                asset_id=asset_id,
                seq=seq,
                reason=reason,
                risk=risk,
                asset_digest=asset_digest,
                digest="",
            )
            digest = _digest_pin(
                _quarantine_payload(provisional), "ai-quarantine.quarantine"
            )
            rec = QuarantineRecord(
                quarantine_id=quarantine_id,
                asset_id=asset_id,
                seq=seq,
                reason=reason,
                risk=risk,
                asset_digest=asset_digest,
                digest=digest,
            )
            self._quarantines[quarantine_id] = rec
            self._asset_quarantines.setdefault(asset_id, []).append(quarantine_id)
            self._active.setdefault(asset_id, []).append(quarantine_id)
            self._emit(
                "quarantined",
                seq,
                quarantine_id=quarantine_id,
                asset_id=asset_id,
                reason=reason,
                risk=risk,
                asset_digest=asset_digest,
            )
            return rec

    def release(
        self,
        asset_id: str,
        seq: int,
        disposition: str = "cleared",
    ) -> ReleaseRecord:
        """Terminal disposition of an asset's active holds (``rel-N`` id).

        Ends the current hold chain; the asset may be re-quarantined
        afterwards. The disposition is booked as data, never proof the
        asset is safe (``cleared``) or dangerous (``condemned``).
        Fail-closed on unknown assets, assets with no active holds,
        and bad dispositions.
        """
        with self._lock:
            try:
                asset_id = _check_id(asset_id, "asset_id")
                self._require_seq(seq)
                disposition = _check_disposition(disposition)
                if asset_id not in self._asset_quarantines:
                    raise UnknownAssetError(f"unknown asset: {asset_id!r}")
                active = self._require_active(asset_id)
                n_holds_disposed = len(active)
            except AIQuarantineError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            self._release_counter += 1
            release_id = f"rel-{self._release_counter}"
            provisional = ReleaseRecord(
                release_id=release_id,
                asset_id=asset_id,
                seq=seq,
                disposition=disposition,
                n_holds_disposed=n_holds_disposed,
                digest="",
            )
            digest = _digest_pin(_release_payload(provisional), "ai-quarantine.release")
            rec = ReleaseRecord(
                release_id=release_id,
                asset_id=asset_id,
                seq=seq,
                disposition=disposition,
                n_holds_disposed=n_holds_disposed,
                digest=digest,
            )
            self._releases[release_id] = rec
            self._asset_releases.setdefault(asset_id, []).append(release_id)
            self._active[asset_id] = []
            self._emit(
                "released",
                seq,
                release_id=release_id,
                asset_id=asset_id,
                disposition=disposition,
                n_holds_disposed=n_holds_disposed,
            )
            return rec

    # -- pure reads --------------------------------------------------------

    def _check_read_seq(self, seq: int) -> int:
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise SeqOrderError("seq must be an int")
        return seq

    def verify(self, record_id: str, seq: int) -> VerificationReport:
        """Pure read: re-derive one quarantine or release digest pin.

        Verdict ``verified`` / ``tampered`` booked as data, never as
        proof the hold was really enforced. Seq is shape-validated
        only - never consumed, no audit row.
        """
        with self._lock:
            seq = self._check_read_seq(seq)
            rec = self._quarantines.get(record_id)
            if rec is None:
                rec = self._releases.get(record_id)
            if rec is None or isinstance(record_id, bool) or not isinstance(
                record_id, str
            ):
                raise UnknownRecordError(f"unknown record id: {record_id!r}")
            integrity_ok = rec.verify()
            verdict = "verified" if integrity_ok else "tampered"
            provisional = VerificationReport(
                record_id=record_id,
                seq=seq,
                verdict=verdict,
                integrity_ok=integrity_ok,
                digest="",
            )
            digest = _digest_pin(_verify_payload(provisional), "ai-quarantine.verify")
            return VerificationReport(
                record_id=record_id,
                seq=seq,
                verdict=verdict,
                integrity_ok=integrity_ok,
                digest=digest,
            )

    def evaluate(self, asset_id: str, seq: int) -> EvaluationReport:
        """Pure read: derive one asset's quarantine posture as data.

        Posture by ledger rule: ``held-critical`` (any active hold with
        risk >= 75) -> ``held`` (any active hold) -> ``condemned`` (no
        active holds, any condemned release) -> ``cleared`` (no active
        holds, all releases cleared). ``integrity_ok`` re-derives all
        in-scope digest pins as data. Seq is shape-validated only -
        never consumed, no audit row.
        """
        with self._lock:
            seq = self._check_read_seq(seq)
            asset_id = _check_id(asset_id, "asset_id")
            if asset_id not in self._asset_quarantines:
                raise UnknownAssetError(f"unknown asset: {asset_id!r}")
            qtn_ids = self._asset_quarantines[asset_id]
            holds = [self._quarantines[i] for i in qtn_ids]
            rel_ids = self._asset_releases.get(asset_id, [])
            releases = [self._releases[i] for i in rel_ids]
            active = self._active.get(asset_id, [])
            active_holds = [self._quarantines[i] for i in active]
            n_critical = sum(
                1 for h in active_holds if h.risk >= CRITICAL_RISK
            )
            if active_holds:
                posture = "held-critical" if n_critical else "held"
            elif any(r.disposition == "condemned" for r in releases):
                posture = "condemned"
            else:
                posture = "cleared"
            integrity_ok = all(h.verify() for h in holds) and all(
                r.verify() for r in releases
            )
            provisional = EvaluationReport(
                asset_id=asset_id,
                seq=seq,
                posture=posture,
                n_holds=len(holds),
                n_releases=len(releases),
                n_active=len(active_holds),
                n_critical=n_critical,
                integrity_ok=integrity_ok,
                digest="",
            )
            digest = _digest_pin(_evaluate_payload(provisional), "ai-quarantine.evaluate")
            return EvaluationReport(
                asset_id=asset_id,
                seq=seq,
                posture=posture,
                n_holds=len(holds),
                n_releases=len(releases),
                n_active=len(active_holds),
                n_critical=n_critical,
                integrity_ok=integrity_ok,
                digest=digest,
            )

    # -- views (pure reads, seq shape-validated only) ----------------------

    def quarantine_record(self, quarantine_id: str, seq: int) -> QuarantineRecord:
        with self._lock:
            self._check_read_seq(seq)
            if quarantine_id not in self._quarantines:
                raise UnknownRecordError(f"unknown quarantine id: {quarantine_id!r}")
            return self._quarantines[quarantine_id]

    def release_record(self, release_id: str, seq: int) -> ReleaseRecord:
        with self._lock:
            self._check_read_seq(seq)
            if release_id not in self._releases:
                raise UnknownRecordError(f"unknown release id: {release_id!r}")
            return self._releases[release_id]

    def holds_for(self, asset_id: str, seq: int) -> Tuple[QuarantineRecord, ...]:
        with self._lock:
            self._check_read_seq(seq)
            return tuple(
                self._quarantines[i]
                for i in self._active.get(asset_id, [])
            )

    def quarantine_history(self, asset_id: str, seq: int) -> Tuple[QuarantineRecord, ...]:
        with self._lock:
            self._check_read_seq(seq)
            return tuple(
                self._quarantines[i] for i in self._asset_quarantines.get(asset_id, [])
            )

    def release_history(self, asset_id: str, seq: int) -> Tuple[ReleaseRecord, ...]:
        with self._lock:
            self._check_read_seq(seq)
            return tuple(
                self._releases[i] for i in self._asset_releases.get(asset_id, [])
            )

    def asset_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._check_read_seq(seq)
            return tuple(sorted(self._asset_quarantines))

    def quarantine_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._check_read_seq(seq)
            return tuple(sorted(self._quarantines))

    def release_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._check_read_seq(seq)
            return tuple(sorted(self._releases))

    def stats(self, seq: int) -> Dict[str, Any]:
        with self._lock:
            self._check_read_seq(seq)
            return {
                "n_assets": len(self._asset_quarantines),
                "n_holds": len(self._quarantines),
                "n_active": sum(len(v) for v in self._active.values()),
                "n_releases": len(self._releases),
                "seq": self._seq,
                "version": AI_QUARANTINE_VERSION,
            }

    def audit_log(self, seq: int) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            self._check_read_seq(seq)
            return tuple(self._audit)


def stdlib_only() -> bool:
    """AST self-check: the module imports stdlib names only."""
    import ast
    from pathlib import Path

    allowed = {
        "hashlib",
        "json",
        "threading",
        "dataclasses",
        "typing",
        "__future__",
        "ast",
        "pathlib",
        "canonical_json",
    }
    tree = ast.parse(Path(__file__).read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    """Self-check: exercise quarantine -> release -> verify -> evaluate."""
    ledger = AIQuarantine()
    assert stdlib_only(), "non-stdlib import detected"
    rec = ledger.quarantine(
        "asset-1", 1, reason="data-contamination", risk=90
    )
    assert rec.verify()
    assert ledger.evaluate("asset-1", 2).posture == "held-critical"
    rel = ledger.release("asset-1", 3, disposition="cleared")
    assert rel.verify()
    assert ledger.evaluate("asset-1", 4).posture == "cleared"
    rep = ledger.verify(rec.quarantine_id, 5)
    assert rep.verdict == "verified"
    rep2 = ledger.verify(rel.release_id, 6)
    assert rep2.verdict == "verified"
    # re-quarantine after release starts a new hold chain
    rec2 = ledger.quarantine("asset-1", 7, reason="tool-misuse", risk=10)
    assert rec2.verify()
    assert ledger.evaluate("asset-1", 8).posture == "held"
    rel2 = ledger.release("asset-1", 9, disposition="condemned")
    assert rel2.verify()
    assert ledger.evaluate("asset-1", 10).posture == "condemned"
    print("ai-quarantine OK: quarantine, release, verify, evaluate, pins, audit")


if __name__ == "__main__":
    main()
