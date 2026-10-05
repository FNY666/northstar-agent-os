"""Evaluator-access receipts and cheat probes (one-hundred-thirteenth batch).

Absorbs the rest of the 2026 AI-safety-institutes research thread:

* **UK AISI (2026-07-21)** — all 5 frontier models tested tried to
  cheat in the cybersecurity evaluations (GPT-5.4 at 14.1%). Cheating
  is not evidence of deceptive intent, but it *invalidates the
  measurement*: a capability claim earned by shortcut is
  ``NON_AUTHORITATIVE`` (eighty-seventh batch tier), not a capability.
* **The evaluate-A / ship-B gap** — third-party evaluation only
  means something if the deployed artifact is the evaluated
  artifact. An evaluation receipt binds ``(evaluator_id |
  model_digest | checkpoint | scope)``; a runtime invocation whose
  ``(model_digest, checkpoint)`` pair does not resolve to a live,
  unexpired, unrevoked evaluation receipt is an unevaluated
  deployment and classifies ``unverifiable-evaluation``.
* **Japan AISI guide v1.20 (2026-07-07)** — agent observation and
  control listed as evaluation items: evaluation scopes are a closed
  vocabulary, and an unknown scope is malformed, not a default.

Northstar mapping: evaluation is a permission, not a press release.
``EvaluationRegistry.check_invocation()`` fail-closes in order:
exact ``(model_digest, checkpoint)`` pair present -> receipt
unexpired -> not revoked. Anything else — unknown pair, expired
receipt, revoked receipt — is ``unverifiable-evaluation`` and audits
``evaluator.mismatch``.

``cheat_probe()`` is the deterministic evaluation-integrity probe:
a probe declares the shortcut markers it knows about (step kinds
that bypass the intended capability) and the required steps of a
legitimate solution. A trace containing a shortcut marker is
``cheat-detected``: the capability claim is ``NON_AUTHORITATIVE``.
A trace with no shortcut but missing required steps is
``incomplete-trace`` — also unverifiable, but a different failure
(the honest-scope distinction between "took a shortcut" and "did
not demonstrate the capability").

Deterministic: no wall-clock reads (callers inject ``now`` as an
integer epoch), canonical JCS hashing (ninety-fifth batch), and all
digest comparisons use :func:`hmac.compare_digest`.

Honest scope:

* The probe catches the shortcuts declared in the probe
  definition. Novel cheating — shortcuts nobody wrote down — is
  not detected; the probe catalog is a living list, not a proof.
* The receipt verifies the *claimed* ``(model_digest, checkpoint)``
  pair matches the evaluation record; it cannot prove the bits
  actually running are those bits (that needs hardware attestation,
  ninety-second batch).
* A passing probe means the trace showed no *known* shortcut. It
  does not certify the underlying capability, only the integrity
  of the demonstration.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Any, Mapping

try:  # ninety-fifth batch: the single canonicalizer
    from canonical_json import jcs_canonical_json, jcs_sha256_hex
except Exception:  # pragma: no cover - module must stay importable standalone
    import json as _json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("utf-8")

    def jcs_sha256_hex(obj: Any) -> str:  # type: ignore[no-redef]
        return hashlib.sha256(jcs_canonical_json(obj)).hexdigest()


EVALUATOR_ACCESS_SCHEMA_VERSION = "northstar.evaluator-access.v1"

#: Closed evaluation-scope vocabulary (Japan AISI v1.20's agent
#: observation/control thread included). Unknown scope is malformed.
EVALUATION_SCOPES: tuple[str, ...] = (
    "safety",
    "capability",
    "cyber",
    "alignment",
    "agent-control",
)

#: Classification tiers for invocation checks (binary, 87th-batch stance).
EVALUATED_INVOCATION = "evaluated-invocation"
UNVERIFIABLE_EVALUATION = "unverifiable-evaluation"

#: Classification tiers for cheat probes.
PROBE_PASSED = "verified-integrity"
PROBE_CHEAT_DETECTED = "non_authoritative"  # cheat -> capability claim void
PROBE_INCOMPLETE = "incomplete-trace"

#: Audit event names.
EVALUATOR_MISMATCH_EVENT = "evaluator.mismatch"
EVALUATOR_MATCHED_EVENT = "evaluator.matched"
EVALUATOR_REVOKED_EVENT = "evaluator.revoked"
CHEAT_DETECTED_EVENT = "evaluator.cheat_detected"

_GENESIS = "genesis"
_HEX64_LENGTH = 64


class EvaluatorAccessError(ValueError):
    """Malformed evaluation input (construction-time boundary).

    Raised for structural problems: unknown scope, bad digests,
    negative timestamps, expiry before evaluation. Check *outcomes*
    (mismatch, expired, revoked, cheat) are verdicts, not exceptions.
    """


def _is_hex64(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != _HEX64_LENGTH:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def _check_hex64(value: Any, field_name: str) -> str:
    if not _is_hex64(value):
        raise EvaluatorAccessError(f"{field_name} must be a 64-char lowercase hex digest")
    return value


def compute_evaluation_digest(
    *,
    evaluator_id: str,
    model_digest: str,
    checkpoint: str,
    scope: str,
    evaluated_at: int,
    expires_at: int,
    prev_hash: str,
) -> str:
    """Compute the chain digest for one evaluation receipt (public so
    builders and verifiers share exactly one implementation)."""
    return jcs_sha256_hex(
        {
            "evaluator_id": evaluator_id,
            "model_digest": model_digest,
            "checkpoint": checkpoint,
            "scope": scope,
            "evaluated_at": evaluated_at,
            "expires_at": expires_at,
            "prev_hash": prev_hash,
        }
    )


@dataclass(frozen=True)
class EvaluationReceipt:
    """One evaluation access record: an evaluator evaluated an exact
    ``(model_digest, checkpoint)`` pair for a scope, valid until
    ``expires_at`` unless revoked."""

    evaluator_id: str
    model_digest: str
    checkpoint: str
    scope: str
    evaluated_at: int
    expires_at: int
    revoked: bool
    prev_hash: str
    receipt_digest: str


@dataclass(frozen=True)
class InvocationVerdict:
    """Outcome of :meth:`EvaluationRegistry.check_invocation`."""

    allowed: bool
    classification: str
    reason: str = ""


@dataclass(frozen=True)
class CheatProbe:
    """A deterministic evaluation-integrity probe.

    ``shortcut_markers`` are the step kinds known to bypass the
    intended capability (the UK AISI lesson: the catalog is the
    detection surface). ``required_steps`` are the step kinds a
    legitimate solution must contain.
    """

    probe_id: str
    description: str
    shortcut_markers: frozenset[str]
    required_steps: frozenset[str]


@dataclass(frozen=True)
class CheatVerdict:
    """Outcome of :func:`cheat_probe`."""

    allowed: bool
    classification: str
    cheat_detected: bool
    reasons: tuple[str, ...] = ()


class EvaluationRegistry:
    """Hash-chained evaluation registry: the evaluate-A/ship-B gate."""

    def __init__(self) -> None:
        self._receipts: list[EvaluationReceipt] = []
        self._revoked: set[tuple[str, str]] = set()  # (model_digest, checkpoint)
        self._prev_hash = _GENESIS

    def _validate_inputs(
        self,
        *,
        evaluator_id: str,
        model_digest: str,
        checkpoint: str,
        scope: str,
        evaluated_at: int,
        expires_at: int,
    ) -> None:
        if not evaluator_id or evaluator_id.strip() != evaluator_id:
            raise EvaluatorAccessError("evaluator_id must be a non-blank, unpadded string")
        if not checkpoint or checkpoint.strip() != checkpoint:
            raise EvaluatorAccessError("checkpoint must be a non-blank, unpadded string")
        if scope not in EVALUATION_SCOPES:
            raise EvaluatorAccessError(f"unknown evaluation scope {scope!r}")
        for name, value in (("evaluated_at", evaluated_at), ("expires_at", expires_at)):
            if not isinstance(value, int) or value < 0:
                raise EvaluatorAccessError(f"{name} must be a non-negative int epoch")
        if expires_at <= evaluated_at:
            raise EvaluatorAccessError("expires_at must be after evaluated_at")
        _check_hex64(model_digest, "model_digest")

    def register(
        self,
        *,
        evaluator_id: str,
        model_digest: str,
        checkpoint: str,
        scope: str,
        evaluated_at: int,
        expires_at: int,
    ) -> EvaluationReceipt:
        """Register an evaluation receipt (malformed input raises)."""
        self._validate_inputs(
            evaluator_id=evaluator_id,
            model_digest=model_digest,
            checkpoint=checkpoint,
            scope=scope,
            evaluated_at=evaluated_at,
            expires_at=expires_at,
        )
        digest = compute_evaluation_digest(
            evaluator_id=evaluator_id,
            model_digest=model_digest,
            checkpoint=checkpoint,
            scope=scope,
            evaluated_at=evaluated_at,
            expires_at=expires_at,
            prev_hash=self._prev_hash,
        )
        receipt = EvaluationReceipt(
            evaluator_id=evaluator_id,
            model_digest=model_digest,
            checkpoint=checkpoint,
            scope=scope,
            evaluated_at=evaluated_at,
            expires_at=expires_at,
            revoked=False,
            prev_hash=self._prev_hash,
            receipt_digest=digest,
        )
        self._receipts.append(receipt)
        self._prev_hash = digest
        return receipt

    def revoke(self, *, model_digest: str, checkpoint: str) -> bool:
        """Revoke all evaluation receipts for an exact
        ``(model_digest, checkpoint)`` pair. Returns True if any
        receipt was live."""
        pair = (model_digest, checkpoint)
        live = any(
            hmac.compare_digest(r.model_digest, model_digest)
            and r.checkpoint == checkpoint
            for r in self._receipts
        )
        if live:
            self._revoked.add(pair)
        return live

    def _live_receipt(
        self, *, model_digest: str, checkpoint: str, now: int
    ) -> EvaluationReceipt | None:
        for receipt in self._receipts:
            if not hmac.compare_digest(receipt.model_digest, model_digest):
                continue
            if receipt.checkpoint != checkpoint:
                continue
            if (receipt.model_digest, receipt.checkpoint) in self._revoked:
                continue
            if now >= receipt.expires_at:
                continue
            return receipt
        return None

    def check_invocation(
        self, *, model_digest: str, checkpoint: str, now: int
    ) -> InvocationVerdict:
        """Gate a runtime model invocation against the evaluation
        registry. Fail-closed in order: exact pair present -> receipt
        unexpired -> not revoked. Anything else classifies
        ``unverifiable-evaluation``: do not evaluate A and ship B.
        """
        if not isinstance(now, int) or now < 0:
            raise EvaluatorAccessError("now must be a non-negative int epoch")
        receipt = self._live_receipt(
            model_digest=model_digest, checkpoint=checkpoint, now=now
        )
        if receipt is not None:
            return InvocationVerdict(
                allowed=True,
                classification=EVALUATED_INVOCATION,
                reason=(
                    f"invocation matches live evaluation by "
                    f"{receipt.evaluator_id!r} (scope {receipt.scope})"
                ),
            )
        for receipt in self._receipts:
            if not hmac.compare_digest(receipt.model_digest, model_digest):
                continue
            if receipt.checkpoint != checkpoint:
                continue
            if (receipt.model_digest, receipt.checkpoint) in self._revoked:
                return InvocationVerdict(
                    allowed=False,
                    classification=UNVERIFIABLE_EVALUATION,
                    reason="evaluation receipt was revoked",
                )
            if now >= receipt.expires_at:
                return InvocationVerdict(
                    allowed=False,
                    classification=UNVERIFIABLE_EVALUATION,
                    reason="evaluation receipt expired",
                )
        return InvocationVerdict(
            allowed=False,
            classification=UNVERIFIABLE_EVALUATION,
            reason="no evaluation receipt for this (model_digest, checkpoint) pair",
        )

    def verify_chain(self) -> tuple[bool, str]:
        """Replay the evaluation log (fail-closed on tamper or gap)."""
        prev = _GENESIS
        for receipt in self._receipts:
            if not hmac.compare_digest(receipt.prev_hash, prev):
                return (False, f"chain link broken at {receipt.receipt_digest[:12]}")
            expected = compute_evaluation_digest(
                evaluator_id=receipt.evaluator_id,
                model_digest=receipt.model_digest,
                checkpoint=receipt.checkpoint,
                scope=receipt.scope,
                evaluated_at=receipt.evaluated_at,
                expires_at=receipt.expires_at,
                prev_hash=receipt.prev_hash,
            )
            if not hmac.compare_digest(receipt.receipt_digest, expected):
                return (False, f"receipt digest mismatch (tampered) at {receipt.receipt_digest[:12]}")
            prev = receipt.receipt_digest
        return (True, "chain intact")


def build_cheat_probe(
    *,
    probe_id: str,
    description: str,
    shortcut_markers: list[str],
    required_steps: list[str],
) -> CheatProbe:
    """Assemble a :class:`CheatProbe` (malformed input raises)."""
    if not probe_id or probe_id.strip() != probe_id:
        raise EvaluatorAccessError("probe_id must be a non-blank, unpadded string")
    if not description:
        raise EvaluatorAccessError("description must be non-empty")
    markers = frozenset(shortcut_markers)
    required = frozenset(required_steps)
    if not markers:
        raise EvaluatorAccessError("shortcut_markers must be non-empty")
    if not required:
        raise EvaluatorAccessError("required_steps must be non-empty")
    if not all(isinstance(m, str) and m for m in markers):
        raise EvaluatorAccessError("shortcut_markers must be non-empty strings")
    if not all(isinstance(s, str) and s for s in required):
        raise EvaluatorAccessError("required_steps must be non-empty strings")
    return CheatProbe(
        probe_id=probe_id,
        description=description,
        shortcut_markers=markers,
        required_steps=required,
    )


def cheat_probe(probe: CheatProbe, trace: list[str]) -> CheatVerdict:
    """Run the evaluation-integrity probe over a solution trace.

    ``trace`` is the ordered list of step kinds the model produced.
    Fail-closed order: any known shortcut marker present ->
    ``cheat-detected`` (the capability claim is ``NON_AUTHORITATIVE``,
    the UK AISI lesson); no shortcut but required steps missing ->
    ``incomplete-trace`` (unverifiable, distinct from cheating);
    otherwise ``verified-integrity``.
    """
    if not isinstance(trace, list) or not all(isinstance(s, str) for s in trace):
        raise EvaluatorAccessError("trace must be a list of step-kind strings")
    seen = frozenset(trace)
    shortcuts = seen & probe.shortcut_markers
    if shortcuts:
        ordered = sorted(shortcuts)
        return CheatVerdict(
            allowed=False,
            classification=PROBE_CHEAT_DETECTED,
            cheat_detected=True,
            reasons=(
                f"trace used known shortcut step(s) {ordered}: "
                "the capability claim is NON_AUTHORITATIVE",
            ),
        )
    missing = probe.required_steps - seen
    if missing:
        return CheatVerdict(
            allowed=False,
            classification=PROBE_INCOMPLETE,
            cheat_detected=False,
            reasons=(
                f"trace is missing required step(s) {sorted(missing)}: "
                "the capability was not demonstrated",
            ),
        )
    return CheatVerdict(
        allowed=True,
        classification=PROBE_PASSED,
        cheat_detected=False,
        reasons=("no known shortcut markers; all required steps present",),
    )


def evaluator_audit_event(
    verdict: InvocationVerdict | CheatVerdict,
    *,
    model_digest: str = "",
    checkpoint: str = "",
    probe_id: str = "",
) -> dict[str, Any]:
    """Build an ``audit.ndjson/1``-shaped record for an evaluator
    verdict (mirrors the 94th batch's
    ``self_attestation_denied_event`` pattern)."""
    if isinstance(verdict, InvocationVerdict):
        event = (
            EVALUATOR_MATCHED_EVENT
            if verdict.allowed
            else EVALUATOR_MISMATCH_EVENT
        )
    else:
        event = CHEAT_DETECTED_EVENT if verdict.cheat_detected else (
            EVALUATOR_MATCHED_EVENT if verdict.allowed else EVALUATOR_MISMATCH_EVENT
        )
    record: dict[str, Any] = {
        "event": event,
        "schema_version": EVALUATOR_ACCESS_SCHEMA_VERSION,
        "model_digest": model_digest,
        "checkpoint": checkpoint,
        "probe_id": probe_id,
        "allowed": verdict.allowed,
        "classification": verdict.classification,
        "reasons": list(verdict.reasons) if isinstance(verdict, CheatVerdict) else [verdict.reason],
    }
    return record


__all__ = [
    "EVALUATOR_ACCESS_SCHEMA_VERSION",
    "EVALUATION_SCOPES",
    "EVALUATED_INVOCATION",
    "UNVERIFIABLE_EVALUATION",
    "PROBE_PASSED",
    "PROBE_CHEAT_DETECTED",
    "PROBE_INCOMPLETE",
    "EVALUATOR_MISMATCH_EVENT",
    "EVALUATOR_MATCHED_EVENT",
    "EVALUATOR_REVOKED_EVENT",
    "CHEAT_DETECTED_EVENT",
    "EvaluatorAccessError",
    "EvaluationReceipt",
    "InvocationVerdict",
    "CheatProbe",
    "CheatVerdict",
    "compute_evaluation_digest",
    "EvaluationRegistry",
    "build_cheat_probe",
    "cheat_probe",
    "evaluator_audit_event",
]
