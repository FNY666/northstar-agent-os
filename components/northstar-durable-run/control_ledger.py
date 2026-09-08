"""Bounded local replay index for authenticated durable control receipts.

The EventStore remains the lifecycle authority.  This file only remembers a
completed transport command's fingerprint and its already-derived
:class:`ControlReceipt`, so a caller that retries the same request ID after a
lost response can receive the same evidence without applying the control a
second time.  It is deliberately not a distributed exactly-once ledger: a
process crash between the EventStore append and this sidecar append remains a
recovery boundary that must be handled by a higher-level operator.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any

from _durable_lock import file_lock
from control_receipt import ControlReceipt, validate_identity

CONTROL_LEDGER_SCHEMA_VERSION = "northstar.durable-control-ledger.v1"
MAX_LEDGER_RECORDS = 10_000
MAX_LEDGER_BYTES = 16 * 1024 * 1024
_FINGERPRINT_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise ValueError("control command fingerprint input must be JSON serializable") from error


def command_fingerprint(
    *,
    run_id: str,
    actor_id: str,
    workspace_id: str,
    policy_revision: str,
    operation: str,
    payload: dict[str, Any],
) -> str:
    """Digest the signed command claims that make a request replay-compatible."""
    validate_identity(run_id, "run_id")
    validate_identity(actor_id, "actor_id")
    validate_identity(workspace_id, "workspace_id")
    validate_identity(policy_revision, "policy_revision")
    if operation not in {"pause", "resume", "cancel"}:
        raise ValueError("control operation is invalid")
    if not isinstance(payload, dict):
        raise ValueError("control payload must be an object")
    value = {
        "run_id": run_id,
        "actor_id": actor_id,
        "workspace_id": workspace_id,
        "policy_revision": policy_revision,
        "operation": operation,
        "payload": payload,
    }
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def command_marker(command_id: str, fingerprint: str) -> str:
    """Return a stable event-key prefix for crash recovery before ledger commit."""
    validate_identity(command_id, "command_id")
    if not isinstance(fingerprint, str) or not _FINGERPRINT_RE.fullmatch(fingerprint):
        raise ValueError("control command fingerprint is invalid")
    material = f"{command_id}\x00{fingerprint}".encode("utf-8")
    return "control-" + hashlib.sha256(material).hexdigest()


def _record_to_dict(command_id: str, fingerprint: str, receipt: ControlReceipt) -> dict[str, Any]:
    return {
        "schema_version": CONTROL_LEDGER_SCHEMA_VERSION,
        "command_id": command_id,
        "fingerprint": fingerprint,
        "receipt": receipt.to_dict(),
    }


def _parse_record(value: Any) -> tuple[str, str, ControlReceipt]:
    if not isinstance(value, dict):
        raise ValueError("control ledger record must be an object")
    expected = {"schema_version", "command_id", "fingerprint", "receipt"}
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        unknown = sorted(actual - expected)
        detail = []
        if missing:
            detail.append(f"missing: {', '.join(missing)}")
        if unknown:
            detail.append(f"unknown: {', '.join(unknown)}")
        raise ValueError("control ledger record fields are invalid" + (" (" + "; ".join(detail) + ")" if detail else ""))
    if value["schema_version"] != CONTROL_LEDGER_SCHEMA_VERSION:
        raise ValueError(f"schema_version must be {CONTROL_LEDGER_SCHEMA_VERSION}")
    command_id = validate_identity(value["command_id"], "command_id")
    fingerprint = value["fingerprint"]
    if not isinstance(fingerprint, str) or not _FINGERPRINT_RE.fullmatch(fingerprint):
        raise ValueError("control ledger fingerprint is invalid")
    receipt = ControlReceipt.from_dict(value["receipt"])
    if receipt.command_id != command_id:
        raise ValueError("control ledger command_id does not match receipt")
    return command_id, fingerprint, receipt


class ControlReceiptLedger:
    """Append-only, POSIX-locked replay index for completed control commands."""

    def __init__(self, path: str | Path):
        self.path = Path(path).absolute()
        self.lock_path = self.path.with_name(self.path.name + ".lock")

    def _read_unlocked(self) -> dict[str, tuple[str, ControlReceipt]]:
        if not self.path.exists():
            return {}
        try:
            if self.path.stat().st_size > MAX_LEDGER_BYTES:
                raise ValueError("control ledger exceeds the maximum size")
            lines = self.path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError) as error:
            raise ValueError("control ledger could not be read") from error
        if len(lines) > MAX_LEDGER_RECORDS:
            raise ValueError("control ledger has too many records")
        records: dict[str, tuple[str, ControlReceipt]] = {}
        for line_number, line in enumerate(lines, start=1):
            if not line.strip():
                raise ValueError(f"control ledger contains a blank line {line_number}")
            try:
                command_id, fingerprint, receipt = _parse_record(json.loads(line))
            except (TypeError, ValueError, json.JSONDecodeError) as error:
                raise ValueError(f"control ledger record {line_number} is invalid") from error
            if command_id in records:
                raise ValueError("control ledger contains a duplicate command_id")
            records[command_id] = (fingerprint, receipt)
        return records

    def lookup(self, command_id: str, fingerprint: str) -> ControlReceipt | None:
        """Return a matching receipt, or fail closed on command ID reuse."""
        validate_identity(command_id, "command_id")
        if not isinstance(fingerprint, str) or not _FINGERPRINT_RE.fullmatch(fingerprint):
            raise ValueError("control command fingerprint is invalid")
        with file_lock(self.lock_path, exclusive=False):
            record = self._read_unlocked().get(command_id)
        if record is None:
            return None
        stored_fingerprint, receipt = record
        if stored_fingerprint != fingerprint:
            raise ValueError("control command_id was reused with different claims")
        return receipt

    def record(
        self,
        command_id: str,
        fingerprint: str,
        receipt: ControlReceipt,
    ) -> ControlReceipt:
        """Persist a receipt, returning the canonical existing receipt on replay."""
        validate_identity(command_id, "command_id")
        if not isinstance(fingerprint, str) or not _FINGERPRINT_RE.fullmatch(fingerprint):
            raise ValueError("control command fingerprint is invalid")
        if not isinstance(receipt, ControlReceipt):
            raise ValueError("receipt must be a ControlReceipt")
        if receipt.command_id != command_id:
            raise ValueError("receipt command_id does not match ledger command_id")
        with file_lock(self.lock_path, exclusive=True):
            records = self._read_unlocked()
            existing = records.get(command_id)
            if existing is not None:
                stored_fingerprint, stored_receipt = existing
                if stored_fingerprint != fingerprint:
                    raise ValueError("control command_id was reused with different claims")
                if stored_receipt.canonical_json() != receipt.canonical_json():
                    raise ValueError("control command_id maps to conflicting receipts")
                return stored_receipt
            if len(records) >= MAX_LEDGER_RECORDS:
                raise ValueError("control ledger has too many records")
            self.path.parent.mkdir(parents=True, exist_ok=True)
            record = _record_to_dict(command_id, fingerprint, receipt)
            line = _canonical(record) + b"\n"
            current_size = self.path.stat().st_size if self.path.exists() else 0
            if current_size + len(line) > MAX_LEDGER_BYTES:
                raise ValueError("control ledger exceeds the maximum size")
            fd, temporary = tempfile.mkstemp(
                prefix=self.path.name + ".",
                dir=str(self.path.parent),
            )
            try:
                os.fchmod(fd, 0o600)
                with os.fdopen(fd, "wb") as stream:
                    if self.path.exists():
                        stream.write(self.path.read_bytes())
                    stream.write(line)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary, self.path)
                try:
                    os.chmod(self.path, 0o600)
                except OSError:
                    pass
            except OSError as error:
                try:
                    os.unlink(temporary)
                except OSError:
                    pass
                raise ValueError("control ledger could not be persisted") from error
            return receipt


__all__ = [
    "CONTROL_LEDGER_SCHEMA_VERSION",
    "ControlReceiptLedger",
    "MAX_LEDGER_BYTES",
    "MAX_LEDGER_RECORDS",
    "command_fingerprint",
    "command_marker",
]
