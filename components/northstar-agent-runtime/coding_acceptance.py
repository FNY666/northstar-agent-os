"""Shared, bounded repair feedback for independent coding acceptance checks."""
from __future__ import annotations

import json
from typing import Any, Mapping, Sequence


MAX_REPAIR_ATTEMPTS = 2


def failed_shell_checks(results: Sequence[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    return [
        item for item in results
        if item.get("kind") == "shell_command" and not item.get("ok")
    ]


def repair_message(
    *,
    shell_results: Sequence[Mapping[str, Any]],
    security_gate: Mapping[str, Any] | None,
    attempt: int,
) -> str:
    """Build bounded, actionable feedback without exposing command text or source."""
    lines = [
        "Independent coding acceptance checks blocked completion.",
        f"Repair attempt {attempt} of {MAX_REPAIR_ATTEMPTS}.",
    ]
    for item in failed_shell_checks(shell_results):
        name = json.dumps(str(item.get("name", "required command")), ensure_ascii=True)
        lines.append(f"- Required command {name}: {item.get('detail', 'not confirmed successful')}.")
    if security_gate is not None and not security_gate.get("ok", False):
        lines.append(
            f"- Security scan: {security_gate.get('status', 'failed')}; "
            f"{security_gate.get('detail', 'new findings or incomplete coverage')}."
        )
        for item in security_gate.get("new", ())[:20]:
            path = json.dumps(str(item.get("path", "?")), ensure_ascii=True)
            lines.append(
                f"  - {item.get('severity', 'unknown')} {path}:{item.get('line', '?')} "
                f"[{item.get('rule', '?')}]: {item.get('message', 'new finding')}; "
                f"remediation: {item.get('remediation', 'review the affected flow')}"
            )
        for path in security_gate.get("unverified_paths", ())[:20]:
            lines.append(f"  - Scan coverage needs review for {json.dumps(str(path), ensure_ascii=True)}.")
    lines.append("Address every listed failure and finish again so the host can recheck the workspace.")
    if failed_shell_checks(shell_results):
        lines.append("Run every required command through the governed Shell tool before finishing.")
    lines.append("All edits and commands still require their usual permission decisions.")
    return "\n".join(lines)
