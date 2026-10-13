"""Host-declared command checks for the programming-agent completion boundary.

These commands are configuration, not model output.  They run only after the model
asks to finish, inside the same workspace sandbox and resource envelope as ``Shell``.
The model cannot edit the list, suppress a failing exit code, or turn a failed check
into a successful run.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Iterable, Sequence

from tools import ToolContext
from tools.shell import shell_handler

MAX_VERIFICATION_COMMANDS = 32
MAX_VERIFICATION_COMMAND_CHARS = 4096
MAX_RECORDED_OUTPUT_CHARS = 8192


class VerificationError(ValueError):
    """A host-declared verification command is malformed or unbounded."""


def validate_commands(commands: Iterable[str]) -> tuple[str, ...]:
    """Return a stable, validated command tuple.

    Empty commands and duplicates are refused.  Silently discarding either would make
    the evidence claim a different verification plan from the one the operator supplied.
    """
    values = tuple(commands)
    if len(values) > MAX_VERIFICATION_COMMANDS:
        raise VerificationError(
            f"at most {MAX_VERIFICATION_COMMANDS} verification commands are allowed"
        )
    seen: set[str] = set()
    for index, command in enumerate(values):
        if not isinstance(command, str) or not command.strip():
            raise VerificationError(f"verification command {index} must be non-empty text")
        if command != command.strip():
            raise VerificationError(
                f"verification command {index} must not have leading or trailing whitespace"
            )
        if len(command) > MAX_VERIFICATION_COMMAND_CHARS:
            raise VerificationError(
                f"verification command {index} exceeds {MAX_VERIFICATION_COMMAND_CHARS} characters"
            )
        if command in seen:
            raise VerificationError(f"verification command {index} duplicates an earlier check")
        seen.add(command)
    return values


@dataclass(frozen=True)
class VerificationReceipt:
    """One check result obtained from the sandbox executor."""

    index: int
    command: str
    ok: bool
    exit_code: int | None
    timed_out: bool
    truncated: bool
    duration_ms: int
    output_sha256: str
    output_excerpt: str
    error: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "command": self.command,
            "ok": self.ok,
            "exit_code": self.exit_code,
            "timed_out": self.timed_out,
            "truncated": self.truncated,
            "duration_ms": self.duration_ms,
            "output_sha256": self.output_sha256,
            "output_excerpt": self.output_excerpt,
            "error": self.error or None,
        }


def run_commands(
    commands: Sequence[str],
    *,
    context: ToolContext,
    timeout_ms: int = 120_000,
) -> tuple[VerificationReceipt, ...]:
    """Run host-owned checks serially and return receipts for every attempted check.

    Checks stop after the first failure.  Later commands are not reported as passing or
    failing because they did not run; the aggregate summary records the declared count.
    """
    checked = validate_commands(commands)
    receipts: list[VerificationReceipt] = []
    for index, command in enumerate(checked):
        phases = context.service("code_phase_machine")
        effect_id = phases.begin_check(index=index) if phases is not None and phases.state == "verifying" else None
        try:
            result = shell_handler(
                {
                    "command": command,
                    "timeout_ms": timeout_ms,
                    "network": False,
                },
                context,
            )
        except BaseException as error:
            if effect_id is not None:
                phases.complete_execution(effect_id, status="unknown", error_class=type(error).__name__)
            raise
        if effect_id is not None:
            phases.complete_execution(effect_id, status="completed")
        data = dict(result.data or {})
        raw = str(result.content or "")
        exit_code = data.get("exit_code")
        if isinstance(exit_code, bool) or not isinstance(exit_code, int):
            exit_code = None
        timed_out = bool(data.get("timed_out", False))
        ok = not result.is_error and not timed_out and exit_code == 0
        receipt = VerificationReceipt(
            index=index,
            command=command,
            ok=ok,
            exit_code=exit_code,
            timed_out=timed_out,
            truncated=bool(result.truncated),
            duration_ms=int(data.get("duration_ms", 0) or 0),
            output_sha256=hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest(),
            output_excerpt=raw[:MAX_RECORDED_OUTPUT_CHARS],
            error=raw if result.is_error and not raw.startswith("---") else "",
        )
        receipts.append(receipt)
        if not ok:
            break
    return tuple(receipts)


def summarise(
    commands: Sequence[str], receipts: Sequence[VerificationReceipt]
) -> dict[str, Any]:
    """Stable audit payload for a verification run."""
    declared = len(commands)
    passed = sum(1 for receipt in receipts if receipt.ok)
    failed = sum(1 for receipt in receipts if not receipt.ok)
    return {
        "declared": declared,
        "ran": len(receipts),
        "passed": passed,
        "failed": failed,
        "skipped": declared - len(receipts),
        "ok": declared == len(receipts) and failed == 0,
        "network": "denied",
        "results": [receipt.as_dict() for receipt in receipts],
    }
