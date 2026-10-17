"""Heuristic GitHub Actions checks for two untrusted pull-request flows.

This is a bounded text scanner, not a YAML parser or workflow evaluator. It
intentionally reports only direct expression interpolation in ``run`` blocks
and privileged PR-head checkout followed by a workflow ``run`` step.
"""
from __future__ import annotations

import re
from typing import Any


_UNTRUSTED_CONTEXT = re.compile(
    r"\$\{\{\s*github\.(?:event\.)?"
    r"(?:pull_request|issue|comment|discussion|review)\."
    r"(?:title|body|head_ref|ref|label|message|name|email)\s*\}\}"
    r"|\$\{\{\s*github\.(?:head_ref|ref|event\.ref|event\.head_commit\.message)\s*\}\}",
    re.IGNORECASE,
)
_UNTRUSTED_REF = re.compile(
    r"(?:github\.event\.pull_request\.(?:head\.(?:sha|ref)|number)|"
    r"refs/pull/[^\s]+/merge)",
    re.IGNORECASE,
)


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _without_comment(line: str) -> str:
    # Keep the original expression syntax but remove ordinary YAML comments.
    return re.split(r"\s+#", line, maxsplit=1)[0]


def _run_blocks(lines: list[str]) -> list[tuple[int, int, str]]:
    blocks: list[tuple[int, int, str]] = []
    index = 0
    while index < len(lines):
        line = _without_comment(lines[index])
        match = re.match(r"^(\s*)(?:-\s+)?run\s*:\s*(.*)$", line)
        if not match:
            index += 1
            continue
        base_indent = len(match.group(1))
        body = [match.group(2)] if match.group(2).strip() not in {"", "|", ">", "|-", ">-", "|+", ">+"} else []
        end = index + 1
        while end < len(lines):
            candidate = lines[end]
            if candidate.strip() and _indent(candidate) <= base_indent:
                break
            body.append(candidate)
            end += 1
        blocks.append((index + 1, base_indent, "\n".join(body)))
        index = end
    return blocks


def scan_workflow(relative: str, source: str) -> list[dict[str, Any]]:
    lines = source.splitlines()
    clean_lines = [_without_comment(line) for line in lines]
    findings: list[dict[str, Any]] = []

    def add(line: int, rule: str, message: str, remediation: str) -> None:
        findings.append({
            "path": relative,
            "line": line,
            "column": 1,
            "tool": "github-actions-sast-scanner",
            "rule": rule,
            "severity": "high",
            "message": message,
            "remediation": remediation,
        })

    pull_request_target = bool(
        re.search(r"(?m)^\s*on\s*:\s*[^\n]*\bpull_request_target\b", "\n".join(clean_lines))
        or re.search(r"(?m)^\s{2,}['\"]?pull_request_target['\"]?\s*:", "\n".join(clean_lines))
    )
    if pull_request_target:
        checkout_lines = [
            index for index, line in enumerate(clean_lines)
            if re.search(r"(?i)\buses\s*:\s*actions/checkout(?:@|\s)", line)
        ]
        risky_checkout: int | None = None
        for checkout in checkout_lines:
            checkout_indent = _indent(clean_lines[checkout])
            step_end = checkout + 1
            ref_line: int | None = None
            while step_end < len(clean_lines):
                candidate = clean_lines[step_end]
                same_indent_next_step = (
                    _indent(candidate) == checkout_indent
                    and re.match(r"^\s*-\s+", candidate) is not None
                )
                if candidate.strip() and (_indent(candidate) < checkout_indent or same_indent_next_step):
                    break
                if re.match(r"^\s{0,}" + r"ref\s*:", candidate) and _UNTRUSTED_REF.search(candidate):
                    ref_line = step_end
                step_end += 1
            if ref_line is None:
                continue
            job_start = next((
                index for index in range(checkout - 1, -1, -1)
                if _indent(clean_lines[index]) == 2
                and re.match(r"^\s{2}[A-Za-z0-9_-]+\s*:", clean_lines[index])
            ), 0)
            job_end = next((
                index for index in range(checkout + 1, len(clean_lines))
                if _indent(clean_lines[index]) == 2
                and re.match(r"^\s{2}[A-Za-z0-9_-]+\s*:", clean_lines[index])
            ), len(clean_lines))
            # Running any checked-out project script in the workflow makes this
            # checkout security-relevant; a checkout by itself only inspects data.
            has_run = any(
                job_start + start - 1 > checkout
                for start, _, _ in _run_blocks(clean_lines[job_start:job_end])
            )
            if has_run:
                risky_checkout = ref_line
                break
        if risky_checkout is not None:
            add(
                risky_checkout + 1,
                "CFG008_PULL_REQUEST_TARGET_UNTRUSTED_CHECKOUT",
                "privileged pull_request_target workflow checks out pull-request code and later runs workflow commands",
                "Do not build or run pull-request code in pull_request_target. Use an unprivileged pull_request workflow, or keep privileged automation limited to metadata operations.",
            )

    for start_line, _, body in _run_blocks(clean_lines):
        match = _UNTRUSTED_CONTEXT.search(body)
        if match:
            # Point to the run block, not the untrusted value itself; findings
            # never include source fragments or attacker-controlled text.
            add(
                start_line,
                "CFG009_ACTIONS_UNTRUSTED_RUN_EXPRESSION",
                "untrusted GitHub event text is interpolated directly into a shell run block",
                "Pass event data through an environment variable and validate it as data; never interpolate attacker-controlled context directly into run script source.",
            )
    return findings
