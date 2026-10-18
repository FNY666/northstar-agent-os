"""Heuristic GitHub Actions checks for untrusted pull-request flows.

This is a bounded structural text scanner, not a general YAML parser or
workflow evaluator. It indexes common block-style jobs and steps without
evaluating expressions, then reports untrusted inputs reaching ``run`` blocks,
privileged PR checkout/fetch flows, and ``workflow_run`` artifact handling.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
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
_WORKFLOW_RUN_REVISION = re.compile(
    r"github\.event\.workflow_run\.(?:head_sha|head_branch|"
    r"head_repository\.full_name|pull_requests\[[^\]]+\]\.head\.(?:sha|ref))",
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


@dataclass(frozen=True)
class _YamlField:
    key: str
    value: str
    line: int  # zero-based source index
    indent: int


@dataclass(frozen=True)
class _WorkflowStep:
    start: int
    end: int
    fields: tuple[_YamlField, ...]
    runs: tuple[tuple[int, int, str], ...]

    def values(self, key: str) -> tuple[_YamlField, ...]:
        return tuple(field for field in self.fields if field.key.casefold() == key.casefold())


@dataclass(frozen=True)
class _WorkflowJob:
    name: str
    start: int
    end: int
    steps: tuple[_WorkflowStep, ...]


@dataclass(frozen=True)
class _PermissionGrant:
    permission: str
    scope: str
    line: int


@dataclass(frozen=True)
class _Workflow:
    triggers: frozenset[str]
    jobs: tuple[_WorkflowJob, ...]
    write_permissions: tuple[_PermissionGrant, ...]


def _key_value(line: str) -> tuple[str, str] | None:
    match = re.match(r"^\s*([^:#][^:]*?)\s*:\s*(.*)$", line)
    if not match:
        return None
    return match.group(1).strip().strip("'\""), match.group(2).strip().strip("'\"")


def _explicit_write_permissions(
    lines: list[str], start: int, end: int, header_indent: int, scope: str
) -> list[_PermissionGrant]:
    grants: list[_PermissionGrant] = []
    for index in range(start, end):
        if _indent(lines[index]) != header_indent:
            continue
        pair = _key_value(lines[index])
        if not pair or pair[0] != "permissions":
            continue
        if re.search(r"(?i)\b[A-Za-z][A-Za-z0-9-]*\s*:\s*write\b", pair[1]):
            grants.append(_PermissionGrant("write", scope, index))
        if pair[1].casefold() in {"write-all", "read-all", "none"}:
            continue
        cursor = index + 1
        while cursor < end and (not lines[cursor].strip() or _indent(lines[cursor]) > header_indent):
            if _indent(lines[cursor]) == header_indent + 2:
                permission = _key_value(lines[cursor].lstrip())
                if permission and permission[1].casefold() == "write":
                    grants.append(_PermissionGrant(permission[0], scope, cursor))
            cursor += 1
    return grants


def _workflow_index(lines: list[str]) -> _Workflow:
    """Index common GitHub Actions YAML structure while retaining source lines.

    This deliberately handles block style workflow/job/step structure only; it
    is not a general YAML implementation and never evaluates expressions.
    """
    clean = [_without_comment(line) for line in lines]
    triggers: set[str] = set()
    event_names = {"pull_request_target", "workflow_run", "issue_comment"}
    for index, line in enumerate(clean):
        if _indent(line) != 0:
            continue
        pair = _key_value(line)
        if not pair or pair[0] != "on":
            continue
        inline = pair[1]
        triggers.update(event for event in event_names if re.search(rf"\b{event}\b", inline))
        if inline:
            continue
        cursor = index + 1
        while cursor < len(clean) and (not clean[cursor].strip() or _indent(clean[cursor]) > 0):
            if _indent(clean[cursor]) == 2:
                event_pair = _key_value(clean[cursor].lstrip())
                if event_pair and event_pair[0].strip("'\"") in event_names:
                    triggers.add(event_pair[0].strip("'\""))
            cursor += 1

    jobs_key = next((i for i, line in enumerate(clean) if _indent(line) == 0 and _key_value(line) == ("jobs", "")), None)
    if jobs_key is None:
        return _Workflow(frozenset(triggers), (), ())
    jobs_end = next((
        i for i in range(jobs_key + 1, len(clean))
        if clean[i].strip() and _indent(clean[i]) == 0
    ), len(clean))
    permissions = _explicit_write_permissions(clean, 0, jobs_key, 0, "workflow")
    job_headers = [
        i for i in range(jobs_key + 1, jobs_end)
        if _indent(clean[i]) == 2 and re.match(r"^\s{2}[A-Za-z0-9_-]+\s*:", clean[i])
    ]
    jobs: list[_WorkflowJob] = []
    for job_number, start in enumerate(job_headers):
        end = job_headers[job_number + 1] if job_number + 1 < len(job_headers) else jobs_end
        header = _key_value(clean[start].strip())
        name = header[0] if header else "unknown"
        permissions.extend(_explicit_write_permissions(clean, start + 1, end, 4, f"job:{name}"))
        steps_key = next((
            i for i in range(start + 1, end)
            if _indent(clean[i]) == 4 and _key_value(clean[i]) == ("steps", "")
        ), None)
        steps: list[_WorkflowStep] = []
        if steps_key is not None:
            step_headers = [
                i for i in range(steps_key + 1, end)
                if _indent(clean[i]) == 6 and re.match(r"^\s{6}-\s*", clean[i])
            ]
            for step_number, step_start in enumerate(step_headers):
                step_end = step_headers[step_number + 1] if step_number + 1 < len(step_headers) else end
                fields: list[_YamlField] = []
                in_run_block_indent: int | None = None
                for row in range(step_start, step_end):
                    current = clean[row]
                    if in_run_block_indent is not None:
                        if current.strip() and _indent(current) <= in_run_block_indent:
                            in_run_block_indent = None
                        else:
                            continue
                    content = re.sub(r"^\s*-\s*", "", current, count=1) if row == step_start else current.strip()
                    pair = _key_value(content)
                    if not pair:
                        continue
                    key, value = pair
                    indent = _indent(current)
                    fields.append(_YamlField(key, value, row, indent))
                    if key.casefold() == "run" and value in {"", "|", ">", "|-", ">-", "|+", ">+"}:
                        in_run_block_indent = indent
                step_runs = tuple(
                    (line_no, base_indent, body)
                    for line_no, base_indent, body in _run_blocks(clean[step_start:step_end])
                )
                steps.append(_WorkflowStep(step_start, step_end, tuple(fields), step_runs))
        jobs.append(_WorkflowJob(name, start, end, tuple(steps)))
    return _Workflow(frozenset(triggers), tuple(jobs), tuple(permissions))


def scan_workflow(relative: str, source: str) -> list[dict[str, Any]]:
    lines = source.splitlines()
    workflow = _workflow_index(lines)
    findings: list[dict[str, Any]] = []

    def add(
        line: int,
        rule: str,
        message: str,
        remediation: str,
        severity: str = "high",
    ) -> None:
        findings.append({
            "path": relative,
            "line": line,
            "column": 1,
            "tool": "github-actions-sast-scanner",
            "rule": rule,
            "severity": severity,
            "message": message,
            "remediation": remediation,
        })

    pull_request_target = "pull_request_target" in workflow.triggers
    workflow_run = "workflow_run" in workflow.triggers
    issue_comment = "issue_comment" in workflow.triggers
    if (pull_request_target or workflow_run or issue_comment) and workflow.write_permissions:
        for grant in workflow.write_permissions:
            add(
                grant.line + 1,
                "CFG013_PRIVILEGED_TRIGGER_WRITE_PERMISSION",
                f"{grant.scope} explicitly grants a GITHUB_TOKEN write permission in a privileged-event workflow",
                "Keep the token read-only by default and grant only the exact write scope required to a narrowly scoped job; separate untrusted-code handling from jobs that can write to the repository.",
                severity="medium",
            )
    if pull_request_target:
        risky_checkout: int | None = None
        for job in workflow.jobs:
            for step in job.steps:
                uses = next((field for field in step.values("uses") if re.match(r"(?i)actions/checkout(?:@|$)", field.value)), None)
                if uses is None:
                    continue
                untrusted_fields = [
                    field for field in step.fields
                    if field.key.casefold() in {"ref", "repository"}
                    and (_UNTRUSTED_REF.search(field.value) or _UNTRUSTED_REPOSITORY.search(field.value))
                ]
                unsafe_opt_in = [
                    field for field in step.values("allow-unsafe-pr-checkout")
                    if field.value.casefold() == "true"
                ]
                if not untrusted_fields and not unsafe_opt_in:
                    continue
                if any(later.start > step.start and later.runs for later in job.steps):
                    evidence = (untrusted_fields or unsafe_opt_in)[0]
                    risky_checkout = evidence.line
                    break
            if risky_checkout is not None:
                break
        if risky_checkout is not None:
            add(
                risky_checkout + 1,
                "CFG008_PULL_REQUEST_TARGET_UNTRUSTED_CHECKOUT",
                "privileged pull_request_target workflow selects or explicitly enables pull-request code checkout and later runs workflow commands",
                "Do not build or run pull-request code in pull_request_target. Use an unprivileged pull_request workflow, or keep privileged automation limited to metadata operations.",
            )

    if workflow_run:
        risky_checkout: int | None = None
        for job in workflow.jobs:
            for step in job.steps:
                uses = next((
                    field for field in step.values("uses")
                    if re.match(r"(?i)actions/checkout(?:@|$)", field.value)
                ), None)
                if uses is None:
                    continue
                revision_fields = [
                    field for field in step.fields
                    if field.key.casefold() in {"ref", "repository"}
                    and _WORKFLOW_RUN_REVISION.search(field.value)
                ]
                if revision_fields and any(later.start > step.start and later.runs for later in job.steps):
                    risky_checkout = revision_fields[0].line + 1
                    break
            if risky_checkout is not None:
                break
        if risky_checkout is not None:
            add(
                risky_checkout,
                "CFG012_WORKFLOW_RUN_REVISION_EXECUTION",
                "workflow_run checks out an upstream workflow revision and later runs commands in the same job",
                "Verify the upstream run's source event and repository before checkout; keep downstream privileged jobs from executing untrusted pull-request code.",
                severity="medium",
            )
        for job in workflow.jobs:
            risky_download = next((
                step for step in job.steps
                if any(re.match(r"(?i)actions/download-artifact(?:@|$)", field.value) for field in step.values("uses"))
                and any(later.start > step.start and later.runs for later in job.steps)
            ), None)
            if risky_download is not None:
                add(
                    next(field.line + 1 for field in risky_download.values("uses")),
                    "CFG010_WORKFLOW_RUN_ARTIFACT_EXECUTION",
                    "privileged workflow_run job downloads an upstream artifact and later runs commands in the same job",
                    "Treat workflow_run artifacts as untrusted data. Validate and inspect contents; do not execute scripts or binaries from the downloaded artifact in a privileged job.",
                )
                break

    if pull_request_target or workflow_run or issue_comment:
        risky_fetch: int | None = None
        for job in workflow.jobs:
            for step in job.steps:
                for relative_line, _, body in step.runs:
                    commands = body.splitlines()
                    fetch_offset: int | None = None
                    for offset, command in enumerate(commands):
                        if re.search(r"(?i)\bgh\s+pr\s+checkout\b", command):
                            fetch_offset = offset
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
                                fetch_offset = offset
                                break
                    if fetch_offset is None:
                        continue
                    later_run = any(later.start > step.start and later.runs for later in job.steps)
                    runs_retrieved_code = any(
                        re.search(r"(?i)(?:\b(?:make|npm|npx|pnpm|yarn|pytest|cargo|go\s+test|bash|sh|python3?|node)\b|\./\S+)", command)
                        for command in commands[fetch_offset + 1:]
                    )
                    if later_run or runs_retrieved_code:
                        risky_fetch = step.start + relative_line + fetch_offset
                        break
                if risky_fetch is not None:
                    break
            if risky_fetch is not None:
                break
        if risky_fetch is not None:
            add(
                risky_fetch,
                "CFG011_PRIVILEGED_PR_CODE_FETCH",
                "privileged workflow fetches pull-request code through a shell command and later runs workflow commands",
                "Do not fetch, build, or run untrusted pull-request code in pull_request_target, workflow_run, or issue_comment. Use an unprivileged pull_request workflow or keep privileged automation limited to metadata operations.",
            )

    for job in workflow.jobs:
        for step in job.steps:
            for relative_line, _, body in step.runs:
                if _UNTRUSTED_CONTEXT.search(body):
                    # Report the run block, not attacker-controlled text.
                    add(
                        step.start + relative_line,
                        "CFG009_ACTIONS_UNTRUSTED_RUN_EXPRESSION",
                        "untrusted GitHub event text is interpolated directly into a shell run block",
                        "Pass event data through an environment variable and validate it as data; never interpolate attacker-controlled context directly into run script source.",
                    )
    return findings
