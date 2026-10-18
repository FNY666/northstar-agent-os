"""Heuristic GitHub Actions checks for untrusted pull-request flows.

This is a bounded text scanner, not a YAML parser or workflow evaluator. It
intentionally reports direct expression interpolation in ``run`` blocks,
privileged PR checkout/fetch followed by workflow commands, and
workflow_run artifact handling.
"""
from __future__ import annotations

import re
from typing import Any


_UNTRUSTED_CONTEXT = re.compile(
    r"\$\{\{\s*github\.(?:event\.)?"
    r"(?:pull_request|issue|comment|discussion|review)\."
    r"(?:title|body|head_ref|ref|label|message|name|email)\s*\}\}"
    r"|\$\{\{\s*github\.event\.pull_request\.head\.(?:ref|label)\s*\}\}"
    r"|\$\{\{\s*github\.event\.workflow_run\."
    r"(?:head_branch|head_commit\.message)\s*\}\}"
    r"|\$\{\{\s*github\.(?:head_ref|ref|event\.ref|event\.head_commit\.message)\s*\}\}",
    re.IGNORECASE,
)
_UNTRUSTED_REF = re.compile(
    r"(?:github\.event\.pull_request\.(?:head\.(?:sha|ref)|number)|"
    r"refs/pull/[^\s]+/merge)",
    re.IGNORECASE,
)
_UNTRUSTED_REPOSITORY = re.compile(
    r"github\.event\.pull_request\.head\.repo\.full_name",
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


def _job_bounds(lines: list[str], index: int) -> tuple[int, int]:
    """Approximate the YAML job block containing a workflow line."""
    job_header = re.compile(r"^\s{2}[A-Za-z0-9_-]+\s*:")
    start = next((
        row for row in range(index - 1, -1, -1)
        if _indent(lines[row]) == 2 and job_header.match(lines[row])
    ), 0)
    end = next((
        row for row in range(index + 1, len(lines))
        if _indent(lines[row]) == 2 and job_header.match(lines[row])
    ), len(lines))
    return start, end


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
    workflow_run = bool(
        re.search(r"(?m)^\s*on\s*:\s*[^\n]*\bworkflow_run\b", "\n".join(clean_lines))
        or re.search(r"(?m)^\s{2,}['\"]?workflow_run['\"]?\s*:", "\n".join(clean_lines))
    )
    issue_comment = bool(
        re.search(r"(?m)^\s*on\s*:\s*[^\n]*\bissue_comment\b", "\n".join(clean_lines))
        or re.search(r"(?m)^\s{2,}['\"]?issue_comment['\"]?\s*:", "\n".join(clean_lines))
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
            untrusted_checkout_line: int | None = None
            while step_end < len(clean_lines):
                candidate = clean_lines[step_end]
                same_indent_next_step = (
                    _indent(candidate) == checkout_indent
                    and re.match(r"^\s*-\s+", candidate) is not None
                )
                if candidate.strip() and (_indent(candidate) < checkout_indent or same_indent_next_step):
                    break
                if (
                    re.match(r"^\s{0,}(?:ref|repository)\s*:", candidate)
                    and (
                        _UNTRUSTED_REF.search(candidate)
                        or _UNTRUSTED_REPOSITORY.search(candidate)
                    )
                ) or re.match(
                    r"(?i)^\s*allow-unsafe-pr-checkout\s*:\s*true\b", candidate
                ):
                    untrusted_checkout_line = step_end
                step_end += 1
            if untrusted_checkout_line is None:
                continue
            job_start, job_end = _job_bounds(clean_lines, checkout)
            # Running any checked-out project script in the workflow makes this
            # checkout security-relevant; a checkout by itself only inspects data.
            has_run = any(
                job_start + start - 1 > checkout
                for start, _, _ in _run_blocks(clean_lines[job_start:job_end])
            )
            if has_run:
                risky_checkout = untrusted_checkout_line
                break
        if risky_checkout is not None:
            add(
                risky_checkout + 1,
                "CFG008_PULL_REQUEST_TARGET_UNTRUSTED_CHECKOUT",
                "privileged pull_request_target workflow selects or explicitly enables pull-request code checkout and later runs workflow commands",
                "Do not build or run pull-request code in pull_request_target. Use an unprivileged pull_request workflow, or keep privileged automation limited to metadata operations.",
            )

    if workflow_run:
        artifact_downloads = [
            index for index, line in enumerate(clean_lines)
            if re.search(r"(?i)\buses\s*:\s*actions/download-artifact(?:@|\s)", line)
        ]
        for download in artifact_downloads:
            job_start, job_end = _job_bounds(clean_lines, download)
            if any(
                job_start + start - 1 > download
                for start, _, _ in _run_blocks(clean_lines[job_start:job_end])
            ):
                add(
                    download + 1,
                    "CFG010_WORKFLOW_RUN_ARTIFACT_EXECUTION",
                    "privileged workflow_run job downloads an upstream artifact and later runs commands in the same job",
                    "Treat workflow_run artifacts as untrusted data. Validate and inspect contents; do not execute scripts or binaries from the downloaded artifact in a privileged job.",
                )
                break

    if pull_request_target or workflow_run or issue_comment:
        run_blocks = _run_blocks(clean_lines)
        risky_fetch: int | None = None
        for start_line, _, body in run_blocks:
            commands = body.splitlines()
            fetch_line: int | None = None
            for offset, command in enumerate(commands):
                if re.search(r"(?i)(?:\bgh\s+pr\s+checkout\b)", command):
                    fetch_line = start_line + offset
                    break
                if re.search(r"(?i)\bgit\s+fetch\b", command):
                    has_pr_ref = bool(re.search(
                        r"(?i)(?:github\.event\.(?:pull_request|workflow_run)|refs/pull/|pull_request\.head)",
                        "\n".join(commands[offset:]),
                    ))
                    has_checkout = any(
                        re.search(r"(?i)\bgit\s+(?:checkout|switch)\b", later)
                        for later in commands[offset + 1:]
                    )
                    if has_pr_ref and has_checkout:
                        fetch_line = start_line + offset
                        break
            if fetch_line is None:
                continue
            run_index = start_line - 1
            job_start, job_end = _job_bounds(clean_lines, run_index)
            later_run = any(
                later_start - 1 > run_index
                and later_start - 1 < job_end
                for later_start, _, _ in run_blocks
            )
            runs_retrieved_code = any(
                re.search(r"(?i)(?:\b(?:make|npm|npx|pnpm|yarn|pytest|cargo|go\s+test|bash|sh|python3?|node)\b|\./\S+)", command)
                for command in commands[fetch_line - start_line + 1:]
            )
            if later_run or runs_retrieved_code:
                risky_fetch = fetch_line
                break
        if risky_fetch is not None:
            add(
                risky_fetch,
                "CFG011_PRIVILEGED_PR_CODE_FETCH",
                "privileged workflow fetches pull-request code through a shell command and later runs workflow commands",
                "Do not fetch, build, or run untrusted pull-request code in pull_request_target, workflow_run, or issue_comment. Use an unprivileged pull_request workflow or keep privileged automation limited to metadata operations.",
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
