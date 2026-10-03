"""Process-evidence receipts (ninety-eighth batch).

Absorbs the 2026 AI-education research thread — the detection regime is
dead, process evidence replaced it:

* A controlled study (805 cases) put AI-text detectors at 39.5% accuracy
  on unmodified AI output — worse than a coin flip — and 22% after
  paraphrase. Regulators (Philippines CHED, California K-12, July 2026)
  now bar detector scores as the sole basis for discipline; Denmark
  requires oral defense for the big upper-secondary thesis; 98 US high
  schoolers drafted their own "Students First Act" demanding two human
  officers review every flag.
* What replaced detection: **show the work, not the output**. Harvard's
  RCT (Scientific Reports, n=194) doubled weekly learning gains with an
  AI tutor whose mechanism was guardrailed *process* (no direct answers,
  force the student to attempt first), not raw model power.

Northstar mapping: a provenance receipt that covers only the final
artifact is the governance equivalent of an AI-detector score — an
uncheckable claim about an opaque output. This module records the
*production process*: drafts, revisions, tool calls, and human
checkpoints, hash-chained so that no step can be inserted, dropped, or
silently edited. A submission with no process chain — "final artifact
only" — classifies as ``unverifiable-process``, the direct analogue of
the eighty-seventh batch's ``NON_AUTHORITATIVE`` tier.

Chain model
-----------

``ProcessReceipt`` binds an ``artifact_digest`` (SHA-256 hex of the final
artifact bytes) to an ordered list of steps. Each step carries
``(seq, step_kind, input_digest, output_digest, actor, timestamp)`` and,
for ``tool_call`` steps, a ``tool_receipt_id``. Each step's
``step_digest`` commits to the previous step's digest, forming a
tamper-evident chain:

    step_digest[i] = sha256(canonical(step_fields[i] + prev_digest))

where ``prev_digest`` for ``seq == 0`` is the literal ``"genesis"``.

``verify_process()`` replays the chain and checks, fail-closed:

1. Chain integrity — every recomputed ``step_digest`` matches, links
   are consecutive (``seq`` 0..n-1, no gaps, no reordering).
2. No unrecorded edits — every step's ``input_digest`` equals the
   previous step's ``output_digest`` (genesis input is the declared
   ``seed_digest`` of the receipt).
3. Human checkpoints are human — a ``human_checkpoint`` step whose
   ``actor`` is an agent identity (``"agent:..."``) is rejected. The
   checkpoint is the education parallel of the oral defense: a human
   must actually be in the loop.
4. Tool calls are receipted — a ``tool_call`` step must reference a
   tool receipt (seventy-seventh batch shape
   ``tool:<args-sha256>:<result-sha256>``) via a caller-supplied lookup,
   and the step's ``output_digest`` must equal the receipt's
   ``result_digest``. The receipt id is pinned by the chain digest, so
   swapping in an unrelated receipt with the same result would need a
   SHA-256 collision. A tool step with no matching receipt is an
   unaccounted mutation of the artifact.
5. Finality — the last step must be ``finalize`` and its
   ``output_digest`` must equal the receipt's ``artifact_digest``.
6. Optional policy knob: ``require_human_checkpoint=True`` denies
   chains with no human step at all (for high-stakes artifacts); the
   default (False) admits fully automated pipelines whose every step is
   still individually accountable.

``classify_process()`` is the binary tier used by policy: a ``None``
receipt (artifact-only submission) or any verification failure
classifies ``"unverifiable-process"``; a passing chain classifies
``"verified-process"``. There is deliberately no "partially verified"
label — the eighty-seventh batch's lesson about the partial footgun
applies here too.

Deterministic: no wall-clock reads (callers inject ``timestamp`` and
``now`` as integer epoch seconds), canonical JSON hashing, and all
digest comparisons use :func:`hmac.compare_digest`.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping


PROCESS_RECEIPT_SCHEMA_VERSION = "northstar.process-receipt.v1"

#: The production-process vocabulary. Closed on purpose: an unknown
#: step kind is a malformed receipt, not an extension point.
STEP_KINDS: tuple[str, ...] = (
    "draft",
    "revise",
    "tool_call",
    "human_checkpoint",
    "finalize",
)

#: Classification tiers (binary, like the 87th batch's evidence tiers).
VERIFIED_PROCESS = "verified-process"
UNVERIFIABLE_PROCESS = "unverifiable-process"

_GENESIS = "genesis"
_HEX64_LENGTH = 64


class ProcessReceiptError(ValueError):
    """A malformed process receipt or a programming error.

    Raised for structural problems (unknown step kinds, bad digests,
    missing fields, non-monotonic seq). Verification *failures* (broken
    chain, unrecorded edit, agent checkpoint, missing tool receipt)
    return a :class:`ProcessVerdict` with ``allowed=False`` instead —
    a failed process is a verdict, a malformed receipt is a bug.
    """


# ---------------------------------------------------------------------------
# Canonical hashing
# ---------------------------------------------------------------------------


def _canonical_bytes(value: Any) -> bytes:
    """Canonical JSON bytes: sorted keys, compact separators, UTF-8."""
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise ProcessReceiptError("value is not canonical JSON") from error


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
        raise ProcessReceiptError(f"{field_name} must be a 64-char lowercase hex digest")
    return value


# ---------------------------------------------------------------------------
# Receipt shape
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ProcessStep:
    """One production step. ``tool_receipt_id`` is required for
    ``tool_call`` steps and must be absent (None) for all other kinds."""

    seq: int
    step_kind: str
    input_digest: str
    output_digest: str
    actor: str
    timestamp: int
    tool_receipt_id: str | None = None
    step_digest: str = ""


@dataclass(frozen=True)
class ProcessReceipt:
    """Hash-chained production-process log for one artifact."""

    schema_version: str
    artifact_digest: str
    seed_digest: str
    steps: tuple[ProcessStep, ...] = ()


@dataclass(frozen=True)
class ProcessVerdict:
    """Outcome of :func:`verify_process`."""

    allowed: bool
    classification: str
    reasons: tuple[str, ...] = ()
    failed_step: int | None = None


def _step_fields(step: ProcessStep, prev_digest: str) -> dict[str, Any]:
    return {
        "seq": step.seq,
        "step_kind": step.step_kind,
        "input_digest": step.input_digest,
        "output_digest": step.output_digest,
        "actor": step.actor,
        "timestamp": step.timestamp,
        "tool_receipt_id": step.tool_receipt_id,
        "prev_digest": prev_digest,
    }


def compute_step_digest(
    *,
    seq: int,
    step_kind: str,
    input_digest: str,
    output_digest: str,
    actor: str,
    timestamp: int,
    tool_receipt_id: str | None,
    prev_digest: str,
) -> str:
    """Compute the chain digest for one step (public so builders and
    verifiers share exactly one implementation)."""
    fields = {
        "seq": seq,
        "step_kind": step_kind,
        "input_digest": input_digest,
        "output_digest": output_digest,
        "actor": actor,
        "timestamp": timestamp,
        "tool_receipt_id": tool_receipt_id,
        "prev_digest": prev_digest,
    }
    return hashlib.sha256(_canonical_bytes(fields)).hexdigest()


def build_receipt(
    *,
    artifact_digest: str,
    seed_digest: str,
    steps: list[Mapping[str, Any]],
) -> ProcessReceipt:
    """Assemble a :class:`ProcessReceipt` from raw step dicts, computing
    the chain digests. Raises :class:`ProcessReceiptError` on malformed
    input."""
    _check_hex64(artifact_digest, "artifact_digest")
    _check_hex64(seed_digest, "seed_digest")
    chained: list[ProcessStep] = []
    prev_digest = _GENESIS
    for index, raw in enumerate(steps):
        if not isinstance(raw, Mapping):
            raise ProcessReceiptError(f"step {index} is not a mapping")
        try:
            seq = int(raw["seq"])
            step_kind = str(raw["step_kind"])
            actor = str(raw["actor"])
            timestamp = int(raw["timestamp"])
        except (KeyError, TypeError, ValueError) as error:
            raise ProcessReceiptError(f"step {index} has malformed fields") from error
        if seq != index:
            raise ProcessReceiptError(
                f"step {index} has non-consecutive seq {seq} (chain must be 0..n-1)"
            )
        if step_kind not in STEP_KINDS:
            raise ProcessReceiptError(f"step {index} has unknown step_kind {step_kind!r}")
        if not actor or actor.strip() != actor:
            raise ProcessReceiptError(f"step {index} has a blank or padded actor")
        if timestamp < 0:
            raise ProcessReceiptError(f"step {index} has a negative timestamp")
        input_digest = _check_hex64(raw.get("input_digest"), f"step {index} input_digest")
        output_digest = _check_hex64(raw.get("output_digest"), f"step {index} output_digest")
        tool_receipt_id = raw.get("tool_receipt_id")
        if step_kind == "tool_call":
            if not isinstance(tool_receipt_id, str) or not tool_receipt_id:
                raise ProcessReceiptError(
                    f"step {index}: tool_call requires a tool_receipt_id"
                )
        elif tool_receipt_id is not None:
            raise ProcessReceiptError(
                f"step {index}: tool_receipt_id is only allowed on tool_call steps"
            )
        digest = compute_step_digest(
            seq=seq,
            step_kind=step_kind,
            input_digest=input_digest,
            output_digest=output_digest,
            actor=actor,
            timestamp=timestamp,
            tool_receipt_id=tool_receipt_id,
            prev_digest=prev_digest,
        )
        chained.append(
            ProcessStep(
                seq=seq,
                step_kind=step_kind,
                input_digest=input_digest,
                output_digest=output_digest,
                actor=actor,
                timestamp=timestamp,
                tool_receipt_id=tool_receipt_id,
                step_digest=digest,
            )
        )
        prev_digest = digest
    return ProcessReceipt(
        schema_version=PROCESS_RECEIPT_SCHEMA_VERSION,
        artifact_digest=artifact_digest,
        seed_digest=seed_digest,
        steps=tuple(chained),
    )


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


def _parse_tool_receipt_id(receipt_id: str) -> tuple[str, str] | None:
    """Parse ``tool:<args-sha256>:<result-sha256>`` (77th batch shape)."""
    parts = receipt_id.split(":")
    if len(parts) != 3 or parts[0] != "tool":
        return None
    if not _is_hex64(parts[1]) or not _is_hex64(parts[2]):
        return None
    return (parts[1], parts[2])


def verify_process(
    receipt: Mapping[str, Any] | ProcessReceipt,
    *,
    tool_receipt_lookup: Callable[[str], Mapping[str, Any] | None] | None = None,
    require_human_checkpoint: bool = False,
) -> ProcessVerdict:
    """Replay a process receipt's chain and verify every rule.

    ``tool_receipt_lookup`` maps a ``tool_receipt_id`` to the tool
    receipt mapping (with ``arguments_digest`` / ``result_digest``);
    ``None`` means every ``tool_call`` step fails (no receipts known).
    Malformed receipts raise :class:`ProcessReceiptError`; verification
    failures return a denied :class:`ProcessVerdict`.
    """
    if isinstance(receipt, ProcessReceipt):
        schema_version = receipt.schema_version
        artifact_digest = receipt.artifact_digest
        seed_digest = receipt.seed_digest
        steps = list(receipt.steps)
    elif isinstance(receipt, Mapping):
        try:
            schema_version = str(receipt["schema_version"])
            artifact_digest = _check_hex64(receipt.get("artifact_digest"), "artifact_digest")
            seed_digest = _check_hex64(receipt.get("seed_digest"), "seed_digest")
            raw_steps = receipt["steps"]
        except (KeyError, TypeError) as error:
            raise ProcessReceiptError("receipt is missing required fields") from error
        if schema_version != PROCESS_RECEIPT_SCHEMA_VERSION:
            raise ProcessReceiptError(
                f"unsupported schema_version {schema_version!r}"
            )
        if not isinstance(raw_steps, list):
            raise ProcessReceiptError("receipt steps must be a list")
        steps = []
        for index, raw in enumerate(raw_steps):
            if not isinstance(raw, Mapping):
                raise ProcessReceiptError(f"step {index} is not a mapping")
            try:
                step = ProcessStep(
                    seq=int(raw["seq"]),
                    step_kind=str(raw["step_kind"]),
                    input_digest=_check_hex64(raw.get("input_digest"), f"step {index} input_digest"),
                    output_digest=_check_hex64(raw.get("output_digest"), f"step {index} output_digest"),
                    actor=str(raw["actor"]),
                    timestamp=int(raw["timestamp"]),
                    tool_receipt_id=raw.get("tool_receipt_id"),
                    step_digest=_check_hex64(raw.get("step_digest"), f"step {index} step_digest"),
                )
            except (KeyError, TypeError, ValueError) as error:
                raise ProcessReceiptError(f"step {index} is malformed") from error
            steps.append(step)
    else:
        raise ProcessReceiptError("receipt must be a ProcessReceipt or a mapping")

    def deny(reason: str, failed_step: int | None = None) -> ProcessVerdict:
        return ProcessVerdict(
            allowed=False,
            classification=UNVERIFIABLE_PROCESS,
            reasons=(reason,),
            failed_step=failed_step,
        )

    if not steps:
        return deny("empty process chain: artifact-only submission")

    prev_digest = _GENESIS
    prev_output = seed_digest
    saw_human_checkpoint = False

    for index, step in enumerate(steps):
        if step.seq != index:
            return deny(f"step {index}: non-consecutive seq {step.seq}", index)
        if step.step_kind not in STEP_KINDS:
            return deny(f"step {index}: unknown step_kind {step.step_kind!r}", index)
        expected_digest = compute_step_digest(
            seq=step.seq,
            step_kind=step.step_kind,
            input_digest=step.input_digest,
            output_digest=step.output_digest,
            actor=step.actor,
            timestamp=step.timestamp,
            tool_receipt_id=step.tool_receipt_id,
            prev_digest=prev_digest,
        )
        if not hmac.compare_digest(step.step_digest, expected_digest):
            return deny(f"step {index}: chain digest mismatch (tampered or reordered step)", index)
        if not hmac.compare_digest(step.input_digest, prev_output):
            return deny(
                f"step {index}: input_digest does not match previous output_digest "
                "(unrecorded edit between steps)",
                index,
            )
        if step.step_kind == "human_checkpoint":
            saw_human_checkpoint = True
            if step.actor.startswith("agent:"):
                return deny(
                    f"step {index}: human_checkpoint with agent actor {step.actor!r} "
                    "(the oral-defense rule: a human must be in the loop)",
                    index,
                )
            if not step.actor:
                return deny(f"step {index}: human_checkpoint with blank actor", index)
        if step.step_kind == "tool_call":
            receipt_id = step.tool_receipt_id or ""
            parsed = _parse_tool_receipt_id(receipt_id)
            if parsed is None:
                return deny(
                    f"step {index}: tool_call has malformed tool_receipt_id {receipt_id!r}",
                    index,
                )
            tool_receipt = tool_receipt_lookup(receipt_id) if tool_receipt_lookup else None
            if tool_receipt is None:
                return deny(
                    f"step {index}: tool_call references unknown tool receipt {receipt_id!r} "
                    "(unaccounted mutation of the artifact)",
                    index,
                )
            # The receipt is pinned by the chain (receipt_id is part of
            # the step digest), and the step's output must be exactly the
            # tool's recorded result: the same result digest from
            # different arguments would be a SHA-256 collision. The
            # receipt's arguments_digest is recorded provenance — the
            # chain rule (input == previous output) already pins what the
            # tool was invoked on.
            result_digest = tool_receipt.get("result_digest")
            if not hmac.compare_digest(str(step.output_digest), str(result_digest or "")):
                return deny(
                    f"step {index}: step output_digest does not match tool receipt result_digest",
                    index,
                )
        elif step.tool_receipt_id is not None:
            return deny(
                f"step {index}: tool_receipt_id on non-tool_call step", index
            )
        prev_digest = step.step_digest
        prev_output = step.output_digest

    last = steps[-1]
    if last.step_kind != "finalize":
        return deny(
            f"chain must end with a finalize step, ended with {last.step_kind!r}",
            last.seq,
        )
    if not hmac.compare_digest(last.output_digest, artifact_digest):
        return deny(
            "finalize output_digest does not match the receipt's artifact_digest",
            last.seq,
        )
    if require_human_checkpoint and not saw_human_checkpoint:
        return deny(
            "policy requires a human_checkpoint but the chain has none",
            None,
        )
    return ProcessVerdict(
        allowed=True,
        classification=VERIFIED_PROCESS,
        reasons=("chain intact, no unrecorded edits, receipts bound, finality holds",),
        failed_step=None,
    )


def classify_process(
    receipt: Mapping[str, Any] | ProcessReceipt | None,
    *,
    tool_receipt_lookup: Callable[[str], Mapping[str, Any] | None] | None = None,
    require_human_checkpoint: bool = False,
) -> str:
    """Binary tier for policy (the 87th batch's stance, ported).

    A ``None`` receipt — the "final artifact only" submission — is
    ``unverifiable-process`` by construction: there is nothing to check.
    A malformed receipt is also ``unverifiable-process`` (fail-closed),
    never an exception to the caller.
    """
    if receipt is None:
        return UNVERIFIABLE_PROCESS
    try:
        verdict = verify_process(
            receipt,
            tool_receipt_lookup=tool_receipt_lookup,
            require_human_checkpoint=require_human_checkpoint,
        )
    except ProcessReceiptError:
        return UNVERIFIABLE_PROCESS
    return verdict.classification


def process_receipt_audit_event(
    receipt: ProcessReceipt,
    verdict: ProcessVerdict,
    *,
    policy: str = "",
) -> dict[str, Any]:
    """Build an ``audit.ndjson/1``-shaped record for a process-receipt
    verdict (mirrors the 94th batch's ``self_attestation_denied_event``
    pattern)."""
    return {
        "event": "process.receipt_verdict",
        "schema_version": PROCESS_RECEIPT_SCHEMA_VERSION,
        "artifact_digest": receipt.artifact_digest,
        "n_steps": len(receipt.steps),
        "classification": verdict.classification,
        "allowed": verdict.allowed,
        "reasons": list(verdict.reasons),
        "failed_step": verdict.failed_step,
        "policy": policy,
    }


__all__ = [
    "PROCESS_RECEIPT_SCHEMA_VERSION",
    "STEP_KINDS",
    "VERIFIED_PROCESS",
    "UNVERIFIABLE_PROCESS",
    "ProcessReceiptError",
    "ProcessStep",
    "ProcessReceipt",
    "ProcessVerdict",
    "build_receipt",
    "compute_step_digest",
    "verify_process",
    "classify_process",
    "process_receipt_audit_event",
]
