"""Per-call tool receipts: ``tool:<args-sha256>:<result-sha256>``.

Absorbed from the ACI (Agent-Computer Interface) per-request signed-receipt
convention — the de-facto ``model:sha256(req):sha256(resp)`` shape with an
attested keyset: one tamper-evident receipt per call, binding the exact
request bytes to the exact response bytes. This module ports only the *format
layer* (a small idea, honestly labelled): the receipt pins the canonical
arguments digest the durable approval already vouches for, plus the canonical
digest of the tool's actual result, so a third party can recompute both
hashes independently and check the receipt against them.

This is NOT an ACI conformance claim: ACI's model-side convention is
referenced for the shape only; Northstar's receipt is produced by
:class:`action_gateway.ActionGateway` at execution time and anchored by the
gateway's own approval token (the "attested keyset" here is the approval
secret's HMAC).

Receipt format (v1):

* ``receipt_id = "tool:" + args_hex + ":" + result_hex`` where each ``_hex``
  is ``sha256`` (hex, lowercase) of the canonical JSON of the value:
  ``json.dumps(value, ensure_ascii=False, sort_keys=True,
  separators=(",", ":")).encode("utf-8")``.
* The arguments digest uses the *same* canonicalization as
  :func:`action_gateway.digest_arguments` (which renders it as
  ``"sha256:" + hex``); the hex segments are identical, so the receipt's
  arguments segment can be compared directly against an approval's
  ``arguments_digest`` after stripping the ``"sha256:"`` prefix.
* ``approval_id`` / ``approval_digest`` link the receipt to the approval
  that authorized the call (high-risk tools). Low-risk calls carry no
  approval, so both are ``None`` — the absence is explicit, not implied.
* ``result`` is the executor's output dict as returned to the caller. A
  receipt is minted only on success: a failed execution produces no receipt
  (the failure is the tool ledger's ``tool.failed`` event, not evidence of
  an outcome).

Third-party recomputation recipe (no Northstar code needed):

1. Take the arguments dict and the result dict exactly as observed.
2. Canonicalize each: UTF-8 JSON, keys sorted, no whitespace, non-ASCII
   unescaped.
3. ``sha256`` each, lowercase hex; check ``receipt_id ==
   "tool:{args}:{result}"``.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from audit import new_record, rfc3339_from_epoch

COMPONENT = "northstar-durable-run"
TOOL_RECEIPT_SCHEMA_VERSION = "northstar.tool-receipt.v1"
RECEIPT_EVENT = "tool.receipt"
_RECEIPT_ID_RE = re.compile(r"^tool:[0-9a-f]{64}:[0-9a-f]{64}$")
_MAX_ARGUMENT_BYTES = 256_000
_MAX_RESULT_BYTES = 1_000_000


def canonical_sha256_hex(value: Any, *, max_bytes: int = _MAX_RESULT_BYTES) -> str:
    """SHA-256 hex of the canonical JSON encoding of ``value``.

    Canonicalization matches :func:`action_gateway.digest_arguments` exactly
    (sorted keys, compact separators, UTF-8, non-ASCII unescaped), so an
    arguments digest computed here equals the hex half of the gateway's
    ``"sha256:"``-prefixed digest.
    """
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise ValueError("value is not canonical JSON") from error
    if len(encoded) > max_bytes:
        raise ValueError("value exceeds the maximum canonical size")
    return hashlib.sha256(encoded).hexdigest()


def make_tool_receipt(
    *,
    tool_name: str,
    task_id: str,
    thread_id: str,
    run_id: str,
    call_id: str,
    actor_id: str,
    workspace_id: str,
    idempotency_key: str,
    arguments: dict[str, Any],
    result: dict[str, Any],
    approval: dict[str, Any] | None = None,
    issued_at: int,
) -> dict[str, Any]:
    """Mint one tool receipt for a completed tool call.

    ``approval`` is the verified approval dict that authorized this call
    (high-risk tools); pass ``None`` for calls that need no approval. The
    approval digest binds the receipt to the exact approval record, so the
    approval → execution link survives in the audit trail.
    """
    if not isinstance(issued_at, int) or isinstance(issued_at, bool):
        raise ValueError("issued_at must be an integer")
    for field, value in (
        ("tool_name", tool_name),
        ("task_id", task_id),
        ("thread_id", thread_id),
        ("run_id", run_id),
        ("call_id", call_id),
        ("actor_id", actor_id),
        ("workspace_id", workspace_id),
        ("idempotency_key", idempotency_key),
    ):
        if not isinstance(value, str) or not value:
            raise ValueError(f"{field} must be a non-empty string")
    if not isinstance(arguments, dict):
        raise ValueError("arguments must be an object")
    if not isinstance(result, dict):
        raise ValueError("result must be an object")
    if approval is not None and not isinstance(approval, dict):
        raise ValueError("approval must be an object or None")
    args_hex = canonical_sha256_hex(arguments, max_bytes=_MAX_ARGUMENT_BYTES)
    result_hex = canonical_sha256_hex(result)
    approval_id = None
    approval_digest = None
    if approval is not None:
        approval_id = approval.get("approval_id")
        if not isinstance(approval_id, str) or not approval_id:
            raise ValueError("approval must carry a non-empty approval_id")
        approval_digest = canonical_sha256_hex(approval)
    return {
        "schema_version": TOOL_RECEIPT_SCHEMA_VERSION,
        "receipt_id": f"tool:{args_hex}:{result_hex}",
        "tool_name": tool_name,
        "task_id": task_id,
        "thread_id": thread_id,
        "run_id": run_id,
        "call_id": call_id,
        "actor_id": actor_id,
        "workspace_id": workspace_id,
        "arguments_digest": args_hex,
        "result_digest": result_hex,
        "approval_id": approval_id,
        "approval_digest": approval_digest,
        "idempotency_key": idempotency_key,
        "issued_at": issued_at,
    }


def verify_tool_receipt(
    receipt: dict[str, Any],
    arguments: dict[str, Any],
    result: dict[str, Any],
    *,
    approval: dict[str, Any] | None = None,
) -> bool:
    """Verify a receipt against the observed arguments and result.

    Recomputes both canonical digests and the receipt id; any inconsistency
    — tampered arguments, tampered result, malformed receipt id, or an
    approval link that does not match the approval presented — raises
    ``ValueError``. Returns ``True`` only when everything checks out.
    """
    if not isinstance(receipt, dict):
        raise ValueError("receipt must be an object")
    if receipt.get("schema_version") != TOOL_RECEIPT_SCHEMA_VERSION:
        raise ValueError(
            f"schema_version must be {TOOL_RECEIPT_SCHEMA_VERSION}"
        )
    receipt_id = receipt.get("receipt_id")
    if not isinstance(receipt_id, str) or not _RECEIPT_ID_RE.fullmatch(receipt_id):
        raise ValueError("receipt_id is malformed")
    args_hex = canonical_sha256_hex(arguments, max_bytes=_MAX_ARGUMENT_BYTES)
    result_hex = canonical_sha256_hex(result)
    expected = f"tool:{args_hex}:{result_hex}"
    if receipt_id != expected:
        raise ValueError(
            "receipt hash does not match the observed arguments/result"
        )
    if receipt.get("arguments_digest") != args_hex:
        raise ValueError("receipt arguments_digest field is inconsistent")
    if receipt.get("result_digest") != result_hex:
        raise ValueError("receipt result_digest field is inconsistent")
    expected_approval_id = receipt.get("approval_id")
    expected_approval_digest = receipt.get("approval_digest")
    if expected_approval_id is None:
        if approval is not None:
            raise ValueError("receipt claims no approval but one was presented")
    else:
        if approval is None:
            raise ValueError("receipt links an approval but none was presented")
        if approval.get("approval_id") != expected_approval_id:
            raise ValueError("receipt approval_id does not match the approval")
        if canonical_sha256_hex(approval) != expected_approval_digest:
            raise ValueError("receipt approval_digest does not match the approval")
    return True


def receipt_audit_record(
    receipt: dict[str, Any], *, seq: int | None = None
) -> dict[str, Any]:
    """Render a receipt as an audit v1 record (event ``tool.receipt``).

    The record's ``ts`` is derived from the receipt's ``issued_at`` so the
    audit feed stays deterministic for offline fixtures; the full receipt
    dict is the payload, so the chain carries everything a verifier needs.
    """
    if not isinstance(receipt, dict):
        raise ValueError("receipt must be an object")
    issued_at = receipt.get("issued_at")
    ts = None
    if isinstance(issued_at, int) and not isinstance(issued_at, bool):
        ts = rfc3339_from_epoch(issued_at)
    return new_record(
        COMPONENT,
        RECEIPT_EVENT,
        seq=seq,
        ts=ts,
        level="info",
        payload=dict(receipt),
        run_id=receipt.get("run_id"),
    )
