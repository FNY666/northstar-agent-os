"""Observer verdict ledger: independent oversight as first-class events, Simulated.

P1 absorption from the exhaustive method search (the "observer stream"
pattern: DeepMind AI Control / OpenAI trajectory monitoring / Meta
AlignmentCheck): a monitor watches an agent's trajectory and its
verdicts must be booked as *first-class events in the same sealed
stream* as the agent's actions -- not as side-channel logs.  The key
architectural point the search surfaced: **the caller-seq must be
supplied by the independent observer, not by the agent itself.**
Otherwise a compromised agent controls the ordering of the evidence
against it.

Design:

* The observer books one verdict per observed agent action.  Each
  verdict references the action via its ``sha256:`` digest pin
  (``action_digest``) -- the raw action never enters this ledger.
* The observer supplies its own strictly-increasing int seq
  (``observer_seq``), independent of any agent-side seq.  Two
  observers watching the same agent produce two independent,
  interleaving-proof orderings; a verifier can check that no
  verdict was reordered or dropped *within* one observer's stream.
* Verdicts are booked over a pinned vocabulary: ``allow`` /
  ``deny`` / ``flag`` / ``escalate`` / ``abstain``, plus a
  ``reason_digest`` pin (the observer's rationale, digest-only).
* Each verdict is shaped as an 8-field event compatible with
  ``forward_seal_ledger`` (intent/action/subject/authorization/
  inputs/logic/execution/outcome), so verdicts can be appended
  straight into a sealed pipeline -- the observer stream and the
  agent stream share one ordering domain.

What this module IS: the decision ledger for *declared* observer
verdicts, with observer-owned seq discipline.

What this module IS NOT (honest scope):

* It does not run the observer model -- verdicts are host-declared,
  booked as data, never proof the observer really judged anything.
* It does not prevent an observer from lying; it makes the observer's
  *claimed* ordering tamper-evident (via the sealed pipeline's
  forward integrity when wired in).
* It does not correlate agent seqs with observer seqs -- that join is
  the host's job (via ``action_digest`` pins).
* Single observer per ledger instance; multi-observer quorum is P2
  (FROST).

House style: frozen dataclasses, caller (observer) int seqs strictly
increasing with claim-then-burn (failed bookings consume seq + book
``observer-verdict-ledger.rejected``; rewinds raise bare), no
wall-clock, RLock-guarded, fail-closed taxonomy, stdlib-only with
``canonical_json`` try/except fallback, ``sha256:`` digest pins,
``audit.ndjson/1`` events, ``stdlib_only()`` + ``main()`` self-check.
"""

from __future__ import annotations

import ast
import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

try:
    from canonical_json import jcs_dumps as _jcs_dumps_raw  # type: ignore

    def _jcs_dumps(obj: Any) -> bytes:
        raw = _jcs_dumps_raw(obj)
        return raw.encode("utf-8") if isinstance(raw, str) else raw

except Exception:  # pragma: no cover - fallback when canonical_json is absent

    def _jcs_dumps(obj: Any) -> bytes:  # type: ignore
        import json

        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


#: Module version pin.
OBSERVER_VERDICT_LEDGER_VERSION = "observer-verdict-ledger.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.observer-verdict-ledger.v1"

#: Pinned verdict vocabulary (booked as data, never proof).
VERDICTS = (
    "allow",
    "deny",
    "flag",
    "escalate",
    "abstain",
)

#: The 8 event fields (forward-seal compatible).
EVENT_FIELDS = (
    "intent",
    "action",
    "subject",
    "authorization",
    "inputs_digest",
    "logic_digest",
    "execution_digest",
    "outcome",
)

#: Audit event kinds.
AUDIT_KINDS = (
    "verdict",
    "retired",
    "rejected",
    "committed",
)


class ObserverVerdictError(Exception):
    """Fail-closed: bad bookings raise, never produce bad records."""


def _require_pin(value: Any, name: str) -> str:
    if not isinstance(value, str):
        raise ObserverVerdictError(f"{name} must be str")
    if not value.startswith("sha256:") or len(value) != 71:
        raise ObserverVerdictError(f"{name} must be a sha256: pin")
    try:
        bytes.fromhex(value[7:])
    except ValueError:
        raise ObserverVerdictError(f"{name} hex is malformed")
    return value


@dataclass(frozen=True)
class CriteriaCommitment:
    """Observer's pre-commitment to assessment criteria (Hubinger defense).

    The observer commits to its assessment criteria (as a digest) BEFORE
    the agent acts.  The agent sees only the commitment hash, not the
    criteria -- it cannot model the observer's exact checks and game
    them.  After the verdict, the observer reveals the criteria; anyone
    can verify they match the commitment.

    This is the cryptographic commitment scheme applied to governance:
    hide the evaluation, bind the evaluator.
    """

    commitment_id: str  # obc-N
    observer_seq: int  # observer-owned seq at commitment time
    observer_id: str  # which observer committed
    criteria_digest: str  # sha256: pin of the assessment criteria
    digest: str  # sha256: pin of the canonical commitment


@dataclass(frozen=True)
class VerdictRecord:
    """One observer verdict (immutable)."""

    verdict_id: str  # obv-N
    observer_seq: int  # observer-owned seq, strictly increasing
    observer_id: str  # which observer booked this
    action_digest: str  # sha256: pin of the observed agent action
    verdict: str  # pinned vocabulary
    reason_digest: str  # sha256: pin of the observer's rationale
    severity: int  # host-declared int [0, 100]
    digest: str  # sha256: pin of the canonical record
    commitment_id: str = ""  # obc-N if pre-committed, else "" (legacy)


@dataclass(frozen=True)
class RetireRecord:
    """Terminal retirement of an observer id (immutable)."""

    observer_id: str
    seq: int
    reason: str
    digest: str


class ObserverVerdictLedger:
    """Ledger for independent observer verdicts.

    The *observer* supplies ``observer_seq`` -- strictly increasing
    ints owned by the observer, independent of any agent-side
    ordering.  Failed bookings consume their seq and book a rejected
    row; rewinds raise without consuming.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._verdicts: Dict[str, VerdictRecord] = {}
        self._by_observer: Dict[str, List[str]] = {}
        self._retired: Dict[str, RetireRecord] = {}
        self._next_seq: Dict[str, int] = {}  # observer_id -> next expected seq
        self._counter = 0
        self._commitment_counter = 0
        self._commitments: Dict[str, CriteriaCommitment] = {}
        self._audit_log: List[Dict[str, Any]] = []
        self._rejected = 0

    # -- internal helpers -------------------------------------------

    def _mint(self) -> str:
        self._counter += 1
        return f"obv-{self._counter}"

    def _mint_commitment(self) -> str:
        self._commitment_counter += 1
        return f"obc-{self._commitment_counter}"

    def _audit(self, kind: str, seq: int, ref: str) -> None:
        if kind not in AUDIT_KINDS:
            raise ObserverVerdictError(f"bad audit kind {kind!r}")
        self._audit_log.append(
            {"kind": kind, "seq": seq, "ref": ref, "schema": "audit.ndjson/1"}
        )

    def _claim_seq(self, observer_id: str, seq: Any) -> None:
        """Claim-then-burn: validate and advance the observer's seq."""
        if isinstance(seq, bool) or not isinstance(seq, int):
            self._rejected += 1
            self._audit("rejected", -1, observer_id)
            raise ObserverVerdictError("observer_seq must be int")
        expected = self._next_seq.get(observer_id, 1)
        if seq < expected:
            # Rewind: raise bare, do NOT consume, do NOT book rejected.
            raise ObserverVerdictError(
                f"observer_seq rewind: got {seq}, expected >= {expected}"
            )
        if seq > expected:
            # Gap: allowed (observer may skip), but the seq is consumed.
            pass
        # Failed validations after this point burn the seq.
        self._next_seq[observer_id] = seq + 1

    # -- mutation ----------------------------------------------------

    def commit_criteria(
        self,
        observer_id: str,
        observer_seq: int,
        criteria_digest: str,
    ) -> CriteriaCommitment:
        """Book an observer's pre-commitment to assessment criteria.

        Call BEFORE the agent acts.  The ``criteria_digest`` is a
        ``sha256:`` pin of the observer's assessment criteria -- the
        agent sees the commitment hash, not the criteria.  When the
        verdict is later booked with this ``commitment_id``, the
        ledger proves the criteria were fixed before the action.

        Hubinger defense: the agent cannot model the observer's exact
        checks because the criteria are hidden behind the commitment.
        """
        if not isinstance(observer_id, str) or not observer_id:
            raise ObserverVerdictError("observer_id must be non-empty str")
        with self._lock:
            if observer_id in self._retired:
                raise ObserverVerdictError("observer is retired")
            self._claim_seq(observer_id, observer_seq)
            # Validate the digest pin.
            if (
                not isinstance(criteria_digest, str)
                or not criteria_digest.startswith("sha256:")
                or len(criteria_digest) != 71
            ):
                raise ObserverVerdictError("criteria_digest must be sha256: pin")
            commitment_id = self._mint_commitment()
            # Canonical digest of the commitment.
            import hashlib as _hl
            import json as _js

            canonical = _js.dumps(
                {
                    "commitment_id": commitment_id,
                    "observer_seq": observer_seq,
                    "observer_id": observer_id,
                    "criteria_digest": criteria_digest,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
            digest = "sha256:" + _hl.sha256(canonical).hexdigest()
            commitment = CriteriaCommitment(
                commitment_id=commitment_id,
                observer_seq=observer_seq,
                observer_id=observer_id,
                criteria_digest=criteria_digest,
                digest=digest,
            )
            self._commitments[commitment_id] = commitment
            self._audit("committed", observer_seq, commitment_id)
            return commitment

    def verdict(
        self,
        observer_id: str,
        observer_seq: int,
        action_digest: str,
        verdict: str,
        reason_digest: str,
        severity: int = 0,
        commitment_id: str = "",
    ) -> VerdictRecord:
        """Book one observer verdict.

        ``observer_seq`` is owned by the observer and must be strictly
        increasing per ``observer_id``.  ``action_digest`` pins the
        observed agent action; ``reason_digest`` pins the rationale.

        ``commitment_id`` (optional): if the observer pre-committed its
        criteria via ``commit_criteria()``, pass the commitment ID here.
        The ledger verifies the commitment exists, belongs to this
        observer, and was booked at an earlier seq -- proving the
        criteria were fixed before the action (Hubinger defense).
        """
        if not isinstance(observer_id, str) or not observer_id:
            raise ObserverVerdictError("observer_id must be non-empty str")
        with self._lock:
            if observer_id in self._retired:
                self._rejected += 1
                self._audit("rejected", observer_seq if isinstance(observer_seq, int) else -1, observer_id)
                raise ObserverVerdictError("observer is retired")
            # Claim the seq first (burns on later failure, bare on rewind).
            self._claim_seq(observer_id, observer_seq)

            def _fail() -> None:
                self._rejected += 1
                self._audit("rejected", observer_seq, observer_id)

            try:
                _require_pin(action_digest, "action_digest")
                if verdict not in VERDICTS:
                    raise ObserverVerdictError(f"bad verdict {verdict!r}")
                _require_pin(reason_digest, "reason_digest")
                if isinstance(severity, bool) or not isinstance(severity, int):
                    raise ObserverVerdictError("severity must be int")
                if not 0 <= severity <= 100:
                    raise ObserverVerdictError("severity must be in [0, 100]")
                # Verify commitment if provided.
                if commitment_id:
                    if commitment_id not in self._commitments:
                        raise ObserverVerdictError(
                            f"unknown commitment {commitment_id!r}"
                        )
                    comm = self._commitments[commitment_id]
                    if comm.observer_id != observer_id:
                        raise ObserverVerdictError(
                            "commitment belongs to different observer"
                        )
                    if comm.observer_seq >= observer_seq:
                        raise ObserverVerdictError(
                            "commitment must precede verdict (seq)"
                        )
            except ObserverVerdictError:
                _fail()
                raise

            verdict_id = self._mint()
            payload = _jcs_dumps(
                {
                    "verdict_id": verdict_id,
                    "observer_seq": observer_seq,
                    "observer_id": observer_id,
                    "action_digest": action_digest,
                    "verdict": verdict,
                    "reason_digest": reason_digest,
                    "severity": severity,
                    "commitment_id": commitment_id,
                }
            )
            digest = "sha256:" + hashlib.sha256(payload).hexdigest()
            record = VerdictRecord(
                verdict_id=verdict_id,
                observer_seq=observer_seq,
                observer_id=observer_id,
                action_digest=action_digest,
                verdict=verdict,
                reason_digest=reason_digest,
                severity=severity,
                digest=digest,
                commitment_id=commitment_id,
            )
            self._verdicts[verdict_id] = record
            self._by_observer.setdefault(observer_id, []).append(verdict_id)
            self._audit("verdict", observer_seq, verdict_id)
            return record

    def retire(self, observer_id: str, observer_seq: int, reason: str = "manual") -> RetireRecord:
        """Terminally retire an observer id."""
        if not isinstance(observer_id, str) or not observer_id:
            raise ObserverVerdictError("observer_id must be non-empty str")
        if reason not in ("manual", "compromised", "superseded"):
            raise ObserverVerdictError(f"bad retire reason {reason!r}")
        with self._lock:
            if observer_id in self._retired:
                raise ObserverVerdictError("observer already retired")
            self._claim_seq(observer_id, observer_seq)
            payload = _jcs_dumps(
                {"observer_id": observer_id, "seq": observer_seq, "reason": reason}
            )
            digest = "sha256:" + hashlib.sha256(payload).hexdigest()
            record = RetireRecord(
                observer_id=observer_id, seq=observer_seq, reason=reason, digest=digest
            )
            self._retired[observer_id] = record
            self._audit("retired", observer_seq, observer_id)
            return record

    # -- reads ---------------------------------------------------------

    def verdict_record(self, verdict_id: str) -> VerdictRecord:
        with self._lock:
            try:
                return self._verdicts[verdict_id]
            except KeyError:
                raise ObserverVerdictError(f"unknown verdict {verdict_id!r}")

    def verdicts_for(self, observer_id: str) -> Tuple[VerdictRecord, ...]:
        with self._lock:
            return tuple(
                self._verdicts[vid] for vid in self._by_observer.get(observer_id, [])
            )

    def to_sealed_event(self, verdict_id: str) -> Dict[str, str]:
        """Render a verdict as an 8-field sealed-pipeline event.

        Maps the verdict into the forward-seal 8-field schema so it
        can be appended straight into a ``ForwardSealLedger`` -- the
        observer stream joins the agent stream in one ordering domain.
        All digest fields are ``sha256:`` pins; the verdict itself
        travels in ``outcome``.
        """
        record = self.verdict_record(verdict_id)
        return {
            "intent": f"observer-verdict:{record.verdict}",
            "action": "adjudicate",
            "subject": record.observer_id,
            "authorization": f"observer-seq:{record.observer_seq}",
            "inputs_digest": record.action_digest,
            "logic_digest": record.reason_digest,
            "execution_digest": record.digest,
            "outcome": record.verdict,
        }

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "verdicts": len(self._verdicts),
                "observers": len(self._by_observer),
                "retired": len(self._retired),
                "rejected": self._rejected,
                "audit_rows": len(self._audit_log),
            }

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            return tuple(self._audit_log)


def stdlib_only() -> bool:
    """AST check: this module imports stdlib modules only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {
        "__future__",
        "ast",
        "dataclasses",
        "hashlib",
        "json",
        "pathlib",
        "threading",
        "typing",
        "canonical_json",
    }
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
    """Self-check: verdicts, seq discipline, sealed-event mapping."""
    ledger = ObserverVerdictLedger()
    pin = "sha256:" + "ab" * 32
    r1 = ledger.verdict("obs-1", 1, pin, "allow", pin, severity=10)
    assert r1.verdict_id == "obv-1"
    r2 = ledger.verdict("obs-1", 2, pin, "deny", pin, severity=90)
    assert r2.verdict_id == "obv-2"
    # Rewind raises bare.
    try:
        ledger.verdict("obs-1", 1, pin, "allow", pin)
        raise AssertionError("rewind should raise")
    except ObserverVerdictError:
        pass
    # Sealed-event mapping carries the 8 fields.
    event = ledger.to_sealed_event("obv-1")
    assert set(event.keys()) == {
        "intent", "action", "subject", "authorization",
        "inputs_digest", "logic_digest", "execution_digest", "outcome",
    }
    assert event["outcome"] == "allow"
    assert ledger.stats()["verdicts"] == 2
    assert stdlib_only()
    print("observer-verdict-ledger OK: verdict, seq, sealed-event, stdlib")


if __name__ == "__main__":
    main()
