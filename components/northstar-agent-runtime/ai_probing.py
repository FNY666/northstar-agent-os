"""AI probing: model-probing decision ledger, Simulated.

Research note: probing a model (linear/diagnostic classifiers,
concept probes, sparse-autoencoder features, activation patching,
logit lens, causal intervention, attention probing) never *proves*
what a model "knows" - probes have false positives, linear probes
misread superposition, SAE features are correlational, and every
finding is a claim made by the host under a declared probe
configuration and declared data slice. What matters here is the
*decision ledger*: which models had which declared probes run against
which declared layers, what findings were declared with what probe
digest pins, and how each probe was itself verified - defensible
bookkeeping, never proof that any concept is really represented.

This module owns the probe -> verify -> evaluate lifecycle:

* **probe()** - book one declared probe run (minted ``prb-N`` ids;
  pinned 8-term probe-kind vocabulary and pinned finding vocabulary
  ``concept-detected`` / ``concept-absent`` / ``inconclusive`` /
  ``not-run``). The first probe registers its model. Raw
  activations, embeddings, weights, probe data, and model internals
  never enter records - digest pins only.
* **verify()** - book one declared verification of a probe
  (minted ``ver-N`` ids; pinned outcome vocabulary ``confirmed`` /
  ``overturned`` / ``inconclusive``), booked **as data**, never proof
  the finding was correct. Fail-closed on unknown probes and on
  double-verification.
* **evaluate()** - pure read: per-model probe/verification tallies
  with ledger-derived integrity, all as data.
* **retire()** - terminal retirement of a model id; ids are never
  recycled.

Distinct-layer rationale vs sibling interpretability ledgers:
modules such as ``ai_explainability`` own declared explanations of
whole-system behavior; this module is the *internal-probe*
decision ledger none of them own: model -> declared layer -> declared
probe -> declared finding -> declared verification.

House style: frozen dataclasses, caller-supplied strictly-increasing
int seqs (claim-then-burn: failed mutations consume their seq and book
an ``ai-probing.rejected`` row; rewinds raise bare without
consuming), no wall-clock, RLock guarding, fail-closed taxonomy,
stdlib-only with the standard ``canonical_json`` try/except fallback,
``sha256:`` digest pins, and ``audit.ndjson/1`` events.

Honest scope: this module runs no probes, reads no activations,
inspects no weights, and proves nothing about real model internals.
A booked ``concept-detected`` finding means "the host declared it",
never "the concept is represented". Activations, embeddings,
weights, and probe internals never enter records or cross the audit
boundary - digest pins only.
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
AI_PROBING_VERSION = "ai-probing.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.ai-probing.v1"

#: Pinned probe-kind vocabulary (the probe methods this ledger tracks).
PROBE_KINDS = (
    "linear-classifier",
    "concept-probe",
    "attention-probe",
    "layer-sweep",
    "sae-feature",
    "activation-patching",
    "logit-lens",
    "causal-intervention",
)

#: Pinned probe-finding vocabulary (booked as data, never proof).
FINDINGS = (
    "concept-detected",
    "concept-absent",
    "inconclusive",
    "not-run",
)

#: Pinned verification-outcome vocabulary (booked as data, never proof).
VERIFY_OUTCOMES = (
    "confirmed",
    "overturned",
    "inconclusive",
)

#: Pinned retirement-reason vocabulary.
RETIRE_REASONS = (
    "manual",
    "superseded",
    "decommissioned",
    "false-start",
)

#: Audit kinds emitted by this module.
AUDIT_KINDS = (
    "probed",
    "verified",
    "retired",
    "rejected",
)

#: Keys that may never appear raw in an audit row.
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
        "action",
        "actions",
        "state",
        "states",
        "observation",
        "gradient",
        "gradients",
        "reward",
        "rewards",
        "score",
        "scores",
        "loss",
        "feedback",
        "preference",
        "payload",
        "prompt",
        "response",
        "content",
        "text",
        "note",
        "notes",
        "detail",
        "details",
        "description",
        "report",
        "evidence",
        "result",
        "results",
        "raw",
        "secret",
        "key",
        "activations",
        "activation",
        "embeddings",
        "embedding",
        "feature_vector",
        "latents",
        "latent",
        "logits",
        "attention_weights",
        "hidden_states",
        "probe_data",
        "probe_output",
        "probe_weights",
        "classifier_weights",
        "intervention",
        "interventions",
    }
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class AIProbingError(Exception):
    """Base error for AI-probing ledger misuse."""


class BadIdError(AIProbingError):
    """Malformed model, layer, or probe id."""


class RetiredModelError(AIProbingError):
    """Model id already retired; never recycled."""


class UnknownModelError(AIProbingError):
    """Model not registered."""


class BadProbeKindError(AIProbingError):
    """Unknown probe kind."""


class BadDigestError(AIProbingError):
    """Malformed sha256: digest pin."""


class BadFindingError(AIProbingError):
    """Unknown probe finding."""


class UnknownProbeError(AIProbingError):
    """Probe id not booked."""


class BadOutcomeError(AIProbingError):
    """Unknown verification outcome."""


class AlreadyVerifiedError(AIProbingError):
    """Probe already has a booked verification."""


class BadReasonError(AIProbingError):
    """Unknown retirement reason."""


class SeqOrderError(AIProbingError):
    """Seq is not a strictly increasing positive int."""


class AuditKindError(AIProbingError):
    """Unknown audit kind, or banned raw key in audit details."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _require_id(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise BadIdError(f"{field_name} must be a non-empty str <= 128 chars")
    return value


def _require_digest(pin: Any, field_name: str) -> str:
    if not isinstance(pin, str) or not pin.startswith("sha256:"):
        raise BadDigestError(f"{field_name} must be a 'sha256:' pin")
    hexpart = pin[7:]
    if len(hexpart) != 64 or any(c not in "0123456789abcdef" for c in hexpart):
        raise BadDigestError(f"{field_name} must be a 64-hex sha256 pin")
    return pin


def _digest_pin(payload: Dict[str, Any]) -> str:
    raw = _jcs_hash(payload)
    hexpart = raw[7:] if raw.startswith("sha256:") else raw
    return "sha256:" + hexpart


# ---------------------------------------------------------------------------
# Records (all frozen)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ProbeRecord:
    probe_id: str
    model_id: str
    layer_id: str
    probe_kind: str
    finding: str
    probe_digest: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "probe_id": self.probe_id,
            "model_id": self.model_id,
            "layer_id": self.layer_id,
            "probe_kind": self.probe_kind,
            "finding": self.finding,
            "probe_digest": self.probe_digest,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "probe_id": self.probe_id,
                "model_id": self.model_id,
                "layer_id": self.layer_id,
                "probe_kind": self.probe_kind,
                "finding": self.finding,
                "probe_digest": self.probe_digest,
            }
        )


@dataclass(frozen=True)
class VerificationRecord:
    verification_id: str
    probe_id: str
    model_id: str
    outcome: str
    review_digest: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "verification_id": self.verification_id,
            "probe_id": self.probe_id,
            "model_id": self.model_id,
            "outcome": self.outcome,
            "review_digest": self.review_digest,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "verification_id": self.verification_id,
                "probe_id": self.probe_id,
                "model_id": self.model_id,
                "outcome": self.outcome,
                "review_digest": self.review_digest,
            }
        )


@dataclass(frozen=True)
class RetireRecord:
    model_id: str
    reason: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "model_id": self.model_id,
            "reason": self.reason,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "model_id": self.model_id,
                "reason": self.reason,
            }
        )


@dataclass(frozen=True)
class ProbeEvaluation:
    model_id: str
    n_probes: int
    n_detected: int
    n_absent: int
    n_inconclusive: int
    n_verified: int
    n_confirmed: int
    n_overturned: int
    integrity_ok: bool
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "model_id": self.model_id,
            "n_probes": self.n_probes,
            "n_detected": self.n_detected,
            "n_absent": self.n_absent,
            "n_inconclusive": self.n_inconclusive,
            "n_verified": self.n_verified,
            "n_confirmed": self.n_confirmed,
            "n_overturned": self.n_overturned,
            "integrity_ok": self.integrity_ok,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "model_id": self.model_id,
                "n_probes": self.n_probes,
                "n_detected": self.n_detected,
                "n_absent": self.n_absent,
                "n_inconclusive": self.n_inconclusive,
                "n_verified": self.n_verified,
                "n_confirmed": self.n_confirmed,
                "n_overturned": self.n_overturned,
                "integrity_ok": self.integrity_ok,
            }
        )


# ---------------------------------------------------------------------------
# Audit event builder
# ---------------------------------------------------------------------------


def ai_probing_audit_event(
    audit_kind: str, seq: int, **details: Any
) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` event row for the AI-probing ledger."""
    if audit_kind not in AUDIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {audit_kind!r}")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise SeqOrderError("audit seq must be a non-negative int")
    for key in details:
        if key in _BANNED_AUDIT_KEYS:
            raise AuditKindError(f"banned raw key in audit detail: {key!r}")
    return {
        "schema": "audit.ndjson/1",
        "kind": audit_kind,
        "seq": seq,
        "details": dict(details),
    }


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class AIProbing:
    """AI-probing decision ledger, Simulated.

    ``probe()`` / ``verify()`` / ``retire()`` mutate the ledger and
    consume caller seqs; ``evaluate()`` and the other views are pure
    reads.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._models: Dict[str, List[str]] = {}
        self._probes: Dict[str, ProbeRecord] = {}
        self._probes_by_model: Dict[str, List[str]] = {}
        self._verifications: Dict[str, VerificationRecord] = {}
        self._verifications_by_probe: Dict[str, str] = {}
        self._verifications_by_model: Dict[str, List[str]] = {}
        self._retired: Dict[str, RetireRecord] = {}
        self._prb_counter = 0
        self._ver_counter = 0
        self._seq = 0
        self._audit: List[Dict[str, Any]] = []
        self._rejected = 0

    # -- internal helpers -------------------------------------------------

    def _check_seq(self, seq: Any) -> int:
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 1:
            raise SeqOrderError("seq must be a positive int, not bool")
        return seq

    def _claim_seq(self, seq: int) -> None:
        """Claim a strictly increasing seq; rewinds raise bare."""
        if seq <= self._seq:
            raise SeqOrderError(
                f"seq must be strictly increasing, got {seq} after {self._seq}"
            )
        self._seq = seq

    def _burn(self, seq: int, method: str, exc: AIProbingError) -> None:
        """Book a failed mutation: seq consumed, rejected row appended."""
        self._rejected += 1
        self._audit.append(
            ai_probing_audit_event(
                "rejected",
                seq,
                method=method,
                error=type(exc).__name__,
                error_detail=str(exc),
            )
        )

    def _require_live_model(self, model_id: str) -> None:
        if model_id in self._retired:
            raise RetiredModelError(f"model already retired: {model_id!r}")

    def _require_known_model(self, model_id: str) -> None:
        if model_id not in self._models:
            raise UnknownModelError(f"unknown model: {model_id!r}")

    # -- mutations --------------------------------------------------------

    def probe(
        self,
        model_id: Any,
        layer_id: Any,
        seq: Any,
        probe_kind: Any = "linear-classifier",
        finding: Any = "inconclusive",
        probe_digest: Any = "",
    ) -> ProbeRecord:
        """Book one declared probe run (minted ``prb-N``).

        The first probe registers its model. Raw activations,
        embeddings, weights, and probe internals travel as a digest
        pin only; they never enter records.
        """
        with self._lock:
            seq_v = self._check_seq(seq)
            self._claim_seq(seq_v)
            try:
                mid = _require_id(model_id, "model_id")
                lid = _require_id(layer_id, "layer_id")
                if mid in self._retired:
                    raise RetiredModelError(f"model id never recycled: {mid!r}")
                if not isinstance(probe_kind, str) or probe_kind not in PROBE_KINDS:
                    raise BadProbeKindError(
                        f"probe_kind must be one of {sorted(PROBE_KINDS)}"
                    )
                if not isinstance(finding, str) or finding not in FINDINGS:
                    raise BadFindingError(
                        f"finding must be one of {sorted(FINDINGS)}"
                    )
                pin = _require_digest(probe_digest, "probe_digest")
                self._prb_counter += 1
                pid = f"prb-{self._prb_counter}"
                rec = ProbeRecord(
                    probe_id=pid,
                    model_id=mid,
                    layer_id=lid,
                    probe_kind=probe_kind,
                    finding=finding,
                    probe_digest=pin,
                    digest=_digest_pin(
                        {
                            "schema": SCHEMA_PIN,
                            "probe_id": pid,
                            "model_id": mid,
                            "layer_id": lid,
                            "probe_kind": probe_kind,
                            "finding": finding,
                            "probe_digest": pin,
                        }
                    ),
                )
                self._probes[pid] = rec
                self._models.setdefault(mid, []).append(pid)
                self._probes_by_model.setdefault(mid, []).append(pid)
                self._audit.append(
                    ai_probing_audit_event(
                        "probed",
                        seq_v,
                        probe_id=pid,
                        model_id=mid,
                        layer_id=lid,
                        probe_kind=probe_kind,
                        finding=finding,
                    )
                )
                return rec
            except AIProbingError as exc:
                self._burn(seq_v, "probe", exc)
                raise

    def verify(
        self,
        probe_id: Any,
        seq: Any,
        outcome: Any = "inconclusive",
        review_digest: Any = "",
    ) -> VerificationRecord:
        """Book one declared verification of a probe (minted ``ver-N``).

        Outcomes are booked **as data**, never proof the finding was
        correct. Fail-closed on unknown probes and on
        double-verification.
        """
        with self._lock:
            seq_v = self._check_seq(seq)
            self._claim_seq(seq_v)
            try:
                pid = _require_id(probe_id, "probe_id")
                prb = self._probes.get(pid)
                if prb is None:
                    raise UnknownProbeError(f"unknown probe: {pid!r}")
                self._require_live_model(prb.model_id)
                if not isinstance(outcome, str) or outcome not in VERIFY_OUTCOMES:
                    raise BadOutcomeError(
                        f"outcome must be one of {sorted(VERIFY_OUTCOMES)}"
                    )
                if pid in self._verifications_by_probe:
                    raise AlreadyVerifiedError(
                        f"probe already verified: {pid!r}"
                    )
                pin = _require_digest(review_digest, "review_digest")
                self._ver_counter += 1
                vid = f"ver-{self._ver_counter}"
                rec = VerificationRecord(
                    verification_id=vid,
                    probe_id=pid,
                    model_id=prb.model_id,
                    outcome=outcome,
                    review_digest=pin,
                    digest=_digest_pin(
                        {
                            "schema": SCHEMA_PIN,
                            "verification_id": vid,
                            "probe_id": pid,
                            "model_id": prb.model_id,
                            "outcome": outcome,
                            "review_digest": pin,
                        }
                    ),
                )
                self._verifications[vid] = rec
                self._verifications_by_probe[pid] = vid
                self._verifications_by_model.setdefault(prb.model_id, []).append(vid)
                self._audit.append(
                    ai_probing_audit_event(
                        "verified",
                        seq_v,
                        verification_id=vid,
                        probe_id=pid,
                        model_id=prb.model_id,
                        outcome=outcome,
                    )
                )
                return rec
            except AIProbingError as exc:
                self._burn(seq_v, "verify", exc)
                raise

    def retire(
        self,
        model_id: Any,
        seq: Any,
        reason: Any = "manual",
    ) -> RetireRecord:
        """Terminally retire a model id; ids are never recycled."""
        with self._lock:
            seq_v = self._check_seq(seq)
            self._claim_seq(seq_v)
            try:
                mid = _require_id(model_id, "model_id")
                if mid in self._retired:
                    raise RetiredModelError(f"model already retired: {mid!r}")
                self._require_known_model(mid)
                if not isinstance(reason, str) or reason not in RETIRE_REASONS:
                    raise BadReasonError(
                        f"reason must be one of {sorted(RETIRE_REASONS)}"
                    )
                rec = RetireRecord(
                    model_id=mid,
                    reason=reason,
                    digest=_digest_pin(
                        {
                            "schema": SCHEMA_PIN,
                            "model_id": mid,
                            "reason": reason,
                        }
                    ),
                )
                self._retired[mid] = rec
                self._audit.append(
                    ai_probing_audit_event(
                        "retired",
                        seq_v,
                        model_id=mid,
                        reason=reason,
                    )
                )
                return rec
            except AIProbingError as exc:
                self._burn(seq_v, "retire", exc)
                raise

    # -- pure-read views ---------------------------------------------------

    def probe_record(self, probe_id: Any, seq: Any) -> ProbeRecord:
        """Return one probe record (pure read)."""
        with self._lock:
            self._check_seq(seq)
            pid = _require_id(probe_id, "probe_id")
            if pid not in self._probes:
                raise UnknownProbeError(f"unknown probe: {pid!r}")
            return self._probes[pid]

    def verification_record(self, verification_id: Any, seq: Any) -> VerificationRecord:
        """Return one verification record (pure read)."""
        with self._lock:
            self._check_seq(seq)
            vid = _require_id(verification_id, "verification_id")
            if vid not in self._verifications:
                raise UnknownProbeError(f"unknown verification: {vid!r}")
            return self._verifications[vid]

    def verification_for(self, probe_id: Any, seq: Any) -> str:
        """Verification id booked against one probe, if any (pure read)."""
        with self._lock:
            self._check_seq(seq)
            pid = _require_id(probe_id, "probe_id")
            if pid not in self._probes:
                raise UnknownProbeError(f"unknown probe: {pid!r}")
            if pid not in self._verifications_by_probe:
                raise UnknownProbeError(f"no verification for probe: {pid!r}")
            return self._verifications_by_probe[pid]

    def model_ids(self, seq: Any) -> Tuple[str, ...]:
        """All registered model ids in registration order."""
        with self._lock:
            self._check_seq(seq)
            return tuple(self._models.keys())

    def probe_ids(self, seq: Any) -> Tuple[str, ...]:
        """All probe ids in mint order."""
        with self._lock:
            self._check_seq(seq)
            return tuple(f"prb-{i}" for i in range(1, self._prb_counter + 1))

    def verification_ids(self, seq: Any) -> Tuple[str, ...]:
        """All verification ids in mint order."""
        with self._lock:
            self._check_seq(seq)
            return tuple(f"ver-{i}" for i in range(1, self._ver_counter + 1))

    def probes_for(self, model_id: Any, seq: Any) -> Tuple[str, ...]:
        """Probe ids booked against one model (mint order)."""
        with self._lock:
            self._check_seq(seq)
            mid = _require_id(model_id, "model_id")
            self._require_known_model(mid)
            return tuple(self._probes_by_model[mid])

    def verifications_for(self, model_id: Any, seq: Any) -> Tuple[str, ...]:
        """Verification ids booked against one model (mint order)."""
        with self._lock:
            self._check_seq(seq)
            mid = _require_id(model_id, "model_id")
            self._require_known_model(mid)
            return tuple(self._verifications_by_model.get(mid, ()))

    def retired_ids(self, seq: Any) -> Tuple[str, ...]:
        """All retired model ids."""
        with self._lock:
            self._check_seq(seq)
            return tuple(self._retired.keys())

    def evaluate(self, model_id: Any, seq: Any) -> ProbeEvaluation:
        """Per-model probe/verification tallies (pure read).

        ``integrity_ok`` is ledger truth derived from digest pins -
        as data, never proof of real model internals. The tallies
        count *declared* findings and outcomes only.
        """
        with self._lock:
            self._check_seq(seq)
            mid = _require_id(model_id, "model_id")
            self._require_known_model(mid)
            prb_ids = self._probes_by_model[mid]
            n_det = n_abs = n_inc = 0
            ver_ids: List[str] = []
            n_confirmed = n_overturned = 0
            for pid in prb_ids:
                finding = self._probes[pid].finding
                if finding == "concept-detected":
                    n_det += 1
                elif finding == "concept-absent":
                    n_abs += 1
                else:
                    n_inc += 1
                if pid in self._verifications_by_probe:
                    vid = self._verifications_by_probe[pid]
                    ver_ids.append(vid)
                    outcome = self._verifications[vid].outcome
                    if outcome == "confirmed":
                        n_confirmed += 1
                    elif outcome == "overturned":
                        n_overturned += 1
            integrity_ok = all(
                rec.verify()
                for rec in (
                    *(self._probes[pid] for pid in prb_ids),
                    *(self._verifications[vid] for vid in ver_ids),
                )
            )
            return ProbeEvaluation(
                model_id=mid,
                n_probes=len(prb_ids),
                n_detected=n_det,
                n_absent=n_abs,
                n_inconclusive=n_inc,
                n_verified=len(ver_ids),
                n_confirmed=n_confirmed,
                n_overturned=n_overturned,
                integrity_ok=integrity_ok,
                digest=_digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "model_id": mid,
                        "n_probes": len(prb_ids),
                        "n_detected": n_det,
                        "n_absent": n_abs,
                        "n_inconclusive": n_inc,
                        "n_verified": len(ver_ids),
                        "n_confirmed": n_confirmed,
                        "n_overturned": n_overturned,
                        "integrity_ok": integrity_ok,
                    }
                ),
            )

    def audit_log(self, seq: Any) -> Tuple[Dict[str, Any], ...]:
        """All audit rows so far (pure read)."""
        with self._lock:
            self._check_seq(seq)
            return tuple(self._audit)

    def stats(self, seq: Any) -> Dict[str, int]:
        """Ledger counters (pure read)."""
        with self._lock:
            self._check_seq(seq)
            return {
                "models": len(self._models),
                "probes": len(self._probes),
                "verifications": len(self._verifications),
                "retired": len(self._retired),
                "rejected": self._rejected,
            }


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
    """Self-check: exercise probe -> verify -> evaluate -> retire."""
    ledger = AIProbing()
    pin = "sha256:" + "ab" * 32
    prb = ledger.probe(
        "model-1", "layer-12", 1, probe_kind="linear-classifier",
        finding="concept-detected", probe_digest=pin,
    )
    assert prb.probe_id == "prb-1"
    assert prb.verify()
    ver = ledger.verify("prb-1", 2, outcome="confirmed", review_digest=pin)
    assert ver.verification_id == "ver-1"
    assert ver.verify()
    ledger.retire("model-1", 3, reason="decommissioned")
    ev = ledger.evaluate("model-1", 4)
    assert ev.verify()
    assert ev.integrity_ok is True
    assert ev.n_detected == 1
    assert ev.n_confirmed == 1
    assert ledger.stats(5) == {
        "models": 1,
        "probes": 1,
        "verifications": 1,
        "retired": 1,
        "rejected": 0,
    }
    assert stdlib_only()
    print("ai-probing OK: probe, verify, evaluate, retire, pins, audit")


if __name__ == "__main__":
    main()
