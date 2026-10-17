"""Host-side verification of policy-required Shell commands.

This module never executes configured commands. It matches their identity against
the current run's governed Shell receipts and accepts only a reported exit code 0.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Mapping, Sequence


def command_digest(spec: Mapping[str, Any]) -> str:
    payload = {key: spec[key] for key in ("command", "argv") if key in spec}
    encoded = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def evaluate_required_shell(
    checks: Sequence[Mapping[str, Any]], tool_calls: Sequence[Any], transcript: Sequence[Any]
) -> list[dict[str, Any]]:
    """Match each named requirement to a successful Shell call in this run."""
    results: dict[str, Any] = {}
    for event in transcript:
        if type(event).__name__ != "UserMessage":
            continue
        for block in getattr(event, "content", ()):
            if type(block).__name__ == "ToolResultBlock":
                results[str(getattr(block, "tool_use_id", ""))] = block
    shell_calls = [call for call in tool_calls if getattr(call, "name", "") == "Shell"]
    verdicts: list[dict[str, Any]] = []
    for check in checks:
        digest = command_digest(check)
        matched = False
        for call in shell_calls:
            if getattr(call, "input_digest", "") != digest or getattr(call, "denied", False):
                continue
            result = results.get(str(getattr(call, "call_id", "")))
            text = result.text() if result is not None and callable(getattr(result, "text", None)) else ""
            first_line = text.splitlines()[0] if text else ""
            metadata_line = text.splitlines()[1] if len(text.splitlines()) > 1 else ""
            if (
                re.fullmatch(r"exit=0 timed_out=false", first_line) is not None
                and re.fullmatch(r"backend=[^\s]+ isolation=[^\s]+", metadata_line) is not None
                and not getattr(call, "is_error", False)
            ):
                matched = True
                break
        verdicts.append({
            "kind": "shell_command",
            "name": str(check["name"]),
            "ok": matched,
            "detail": "required command exited 0 in this run" if matched else "required command was not observed with exit code 0",
            "structural": False,
            "command_digest": digest,
        })
    return verdicts
