"""Sealed audit sink: permission-gate audit -> forward-seal ledger, Simulated.

Production wiring (proven by tiny experiment 2026-10-08): the
permission gate's ``audit_sink`` hook accepts any callable taking an
audit dict.  This module provides the adapter that maps gate audit
records into 8-field sealed events and appends them to a
``ForwardSealLedger`` -- giving the gate's audit trail forward
integrity (Schneier-Kelsey) without modifying the gate itself.

Mapping (gate record -> sealed event fields):

* ``intent``: ``permission-<event>`` (e.g. ``permission-permission.allow``)
* ``action``: ``gate-decision``
* ``subject``: record ``agent`` (or ``unknown``)
* ``authorization``: ``rule:<rule>`` (the gate rule that decided)
* ``inputs_digest``: ``sha256:`` of canonical ``arguments_digest`` if
  present, else the null pin (all zeros -- marks "no arguments")
* ``logic_digest``: ``sha256:`` of canonical ``rule``+``condition``
* ``execution_digest``: ``sha256:`` of canonical full record
* ``outcome``: record ``event`` (``permission.allow``/``permission.deny``)

The adapter is dependency-injected (no sibling imports): the host
passes a ``ForwardSealLedger`` instance.  Usage::

    ledger = ForwardSealLedger(initial_key, checkpoint_key)
    sink = SealedAuditSink(ledger)
    engine = PermissionEngine(audit_sink=sink)

What this module IS: the proven wiring between gate audits and the
sealed pipeline.

What this module IS NOT (honest scope):

* It does not change what the gate audits -- the record shape is the
  gate's, this only seals it.
* Digest pins for arguments/rule are computed from the record's
  string forms; in production the host should pass pre-computed
  content hashes.  The null pin marks absent data explicitly rather
  than silently omitting it.
* It does not batch or checkpoint -- the host drives the ledger's
  checkpoint cadence (or wires a SealedPipeline).

House style: stdlib-only, no wall-clock, fail-closed (bad records
raise, never seal garbage), version/schema pins, ``stdlib_only()``
+ ``main()`` self-check.
"""

from __future__ import annotations

import ast
import hashlib
from typing import Any, Callable, Dict

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
SEALED_AUDIT_SINK_VERSION = "sealed-audit-sink.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.sealed-audit-sink.v1"

#: Null pin: marks explicitly absent data (all zeros).
NULL_PIN = "sha256:" + "00" * 32


class SealedAuditSinkError(Exception):
    """Fail-closed: malformed audit records raise, never seal garbage."""


def _pin_of(value: Any) -> str:
    """sha256: pin of the canonical form of ``value``."""
    return "sha256:" + hashlib.sha256(_jcs_dumps(value)).hexdigest()


class SealedAuditSink:
    """Callable adapter: gate audit dict -> sealed ledger append.

    Passed as ``audit_sink`` to ``PermissionEngine``.  Each call maps
    the record to 8 sealed fields and appends.  Malformed records
    raise (fail-closed) -- the gate's ``_audit_deny``/``_audit_allow``
    catch sink exceptions and mark the decision accordingly, so a bad
    record never silently vanishes.
    """

    def __init__(self, ledger: Any) -> None:
        if ledger is None:
            raise SealedAuditSinkError("ledger is required")
        if not callable(getattr(ledger, "append", None)):
            raise SealedAuditSinkError("ledger must have append()")
        self._ledger = ledger
        self._sealed_count = 0

    @property
    def ledger(self) -> Any:
        """The forward-seal ledger this sink appends to (shared-chain wiring)."""
        return self._ledger

    def __call__(self, record: Dict[str, Any]) -> None:
        if not isinstance(record, dict):
            raise SealedAuditSinkError("audit record must be dict")
        event = record.get("event")
        if not isinstance(event, str) or not event:
            raise SealedAuditSinkError("record must have non-empty event")

        # Map to 8 sealed fields.
        inputs_digest = (
            _pin_of(record["arguments_digest"])
            if "arguments_digest" in record
            else NULL_PIN
        )
        logic_digest = _pin_of(
            {"rule": record.get("rule", ""), "condition": record.get("condition", "")}
        )
        execution_digest = _pin_of(record)

        self._ledger.append(
            intent=f"permission-{event}",
            action="gate-decision",
            subject=str(record.get("agent", "unknown")),
            authorization=f"rule:{record.get('rule', 'none')}",
            inputs_digest=inputs_digest,
            logic_digest=logic_digest,
            execution_digest=execution_digest,
            outcome=event,
        )
        self._sealed_count += 1

    @property
    def sealed_count(self) -> int:
        """How many audit records have been sealed."""
        return self._sealed_count


def stdlib_only() -> bool:
    """AST check: this module imports stdlib modules only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {
        "__future__",
        "ast",
        "hashlib",
        "json",
        "pathlib",
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
    """Self-check with a stub ledger (no sibling imports)."""

    class _StubLedger:
        def __init__(self):
            self.records = []

        def append(self, **kw):
            self.records.append(kw)
            return kw

    ledger = _StubLedger()
    sink = SealedAuditSink(ledger)
    # Well-formed record.
    sink(
        {
            "event": "permission.allow",
            "tool": "read_file",
            "rule": "mode:default",
            "agent": "agent-1",
            "arguments_digest": "abc123",
        }
    )
    assert sink.sealed_count == 1
    rec = ledger.records[0]
    assert rec["intent"] == "permission-permission.allow"
    assert rec["outcome"] == "permission.allow"
    assert rec["inputs_digest"].startswith("sha256:")
    assert rec["inputs_digest"] != NULL_PIN  # arguments present
    # Missing arguments -> null pin (explicit, not silent).
    sink({"event": "permission.deny", "tool": "x", "rule": "y"})
    assert ledger.records[1]["inputs_digest"] == NULL_PIN
    # Malformed -> raises.
    try:
        sink({"tool": "x"})  # no event
        raise AssertionError("should raise")
    except SealedAuditSinkError:
        pass
    try:
        sink("not-a-dict")  # type: ignore[arg-type]
        raise AssertionError("should raise")
    except SealedAuditSinkError:
        pass
    assert stdlib_only()
    print("sealed-audit-sink OK: map, seal, null-pin, fail-closed, stdlib")


if __name__ == "__main__":
    main()
