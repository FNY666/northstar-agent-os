"""Heuristic GitHub Actions checks for untrusted pull-request flows.

This is a bounded structural text scanner, not a general YAML parser or
workflow evaluator. It indexes common block-style jobs and steps without
evaluating expressions, then reports untrusted inputs reaching ``run`` blocks,
privileged PR checkout/fetch flows, and ``workflow_run`` artifact handling.
It also treats later local actions as executable workflow content after an
untrusted checkout or artifact download.
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
_DYNAMIC_CODE_SINK = re.compile(
    r"(?P<eval>\beval\b)"
    r"|(?P<shell>\b(?:bash|sh|zsh|dash)\s+(?:-[A-Za-z]*c\b|--command\b))"
    r"|(?P<code>\b(?:python\d*|node)\s+(?:-c\b|-e\b))"
    r"|(?P<source>\bsource\b|(?:^|[;&|]\s*)\.\s+)"
    r"|(?P<iex>\bInvoke-Expression\b)",
    re.IGNORECASE,
)


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _without_comment(line: str) -> str:
    """Remove a YAML comment marker outside simple quoted text."""
    quote: str | None = None
    escaped = False
    index = 0
    while index < len(line):
        char = line[index]
        if quote == '"':
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quote = None
        elif quote == "'":
            if char == "'" and index + 1 < len(line) and line[index + 1] == "'":
                index += 1
            elif char == "'":
                quote = None
        elif char in {'"', "'"} and (
            index == 0 or line[index - 1].isspace() or line[index - 1] in ":[([{"
        ):
            quote = char
        elif char == "#" and (index == 0 or line[index - 1].isspace()):
            return line[:index]
        index += 1
    return line


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
    env_sources: tuple[_YamlField, ...]
    output_fields: tuple[_YamlField, ...]


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
    env_sources: tuple[_YamlField, ...]


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


def _environment_fields(
    lines: list[str], start: int, end: int, header_indent: int
) -> list[_YamlField]:
    sources: list[_YamlField] = []
    for index in range(start, end):
        if _indent(lines[index]) != header_indent:
            continue
        pair = _key_value(lines[index])
        if not pair or pair[0] != "env":
            continue
        cursor = index + 1
        while cursor < end and (not lines[cursor].strip() or _indent(lines[cursor]) > header_indent):
            if _indent(lines[cursor]) == header_indent + 2:
                assignment = _key_value(lines[cursor].lstrip())
                if assignment:
                    sources.append(_YamlField(assignment[0], assignment[1], cursor, _indent(lines[cursor])))
            cursor += 1
    return sources


def _mapping_fields(
    lines: list[str], start: int, end: int, header_indent: int, mapping: str
) -> list[_YamlField]:
    fields: list[_YamlField] = []
    for index in range(start, end):
        if _indent(lines[index]) != header_indent:
            continue
        pair = _key_value(lines[index])
        if not pair or pair[0] != mapping:
            continue
        cursor = index + 1
        while cursor < end and (not lines[cursor].strip() or _indent(lines[cursor]) > header_indent):
            if _indent(lines[cursor]) == header_indent + 2:
                item = _key_value(lines[cursor].lstrip())
                if item:
                    fields.append(_YamlField(item[0], item[1], cursor, _indent(lines[cursor])))
            cursor += 1
    return fields


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
        return _Workflow(frozenset(triggers), (), (), tuple(_environment_fields(clean, 0, len(clean), 0)))
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
        job_env = tuple(_environment_fields(clean, start + 1, end, 4))
        job_outputs = tuple(_mapping_fields(clean, start + 1, end, 4, "outputs"))
        jobs.append(_WorkflowJob(name, start, end, tuple(steps), job_env, job_outputs))
    workflow_env = tuple(_environment_fields(clean, 0, len(clean), 0))
    return _Workflow(frozenset(triggers), tuple(jobs), tuple(permissions), workflow_env)


def _untrusted_fields(fields: tuple[_YamlField, ...] | list[_YamlField]) -> set[str]:
    return {
        field.key for field in fields
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", field.key)
        and _UNTRUSTED_CONTEXT.search(field.value)
    }


def _needs_output_refs(value: str) -> set[tuple[str, str]]:
    """Read needs outputs even when wrapped by format/fromJSON expressions."""
    return set(re.findall(
        r"\bneeds\.([A-Za-z0-9_-]+)\.outputs\.([A-Za-z_][A-Za-z0-9_-]*)\b",
        value,
    ))


def _output_references(fields: tuple[_YamlField, ...] | list[_YamlField]) -> set[str]:
    return {field.key for field in fields if _needs_output_refs(field.value)}


def _untrusted_env_names(
    step: _WorkflowStep, job_outputs: dict[str, set[str]] | None = None
) -> set[str]:
    names: set[str] = set()
    for env_field in step.values("env"):
        for field in step.fields:
            if field.line <= env_field.line:
                continue
            if field.indent <= env_field.indent:
                break
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", field.key) and _UNTRUSTED_CONTEXT.search(field.value):
                names.add(field.key)
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", field.key) and job_outputs:
                if any(output in job_outputs.get(job, set()) for job, output in _needs_output_refs(field.value)):
                    names.add(field.key)
    return names


def _uses_local_action(step: _WorkflowStep) -> bool:
    return any(
        field.value.startswith("./")
        for field in step.values("uses")
    )


def _later_executes_job_content(job: _WorkflowJob, step: _WorkflowStep) -> bool:
    return any(
        later.start > step.start and (later.runs or _uses_local_action(later))
        for later in job.steps
    )


def _multiline_file_flow(
    body: str, tainted_names: set[str], target: str
) -> tuple[set[str], set[int]]:
    lines = body.splitlines()
    refs = re.compile(r"(?:\$([A-Za-z_][A-Za-z0-9_]*)|\$\{([A-Za-z_][A-Za-z0-9_]*)\})")
    exports: set[str] = set()
    unsafe_lines: set[int] = set()
    opener = re.compile(r"^\s*echo\s+['\"]?([A-Za-z_][A-Za-z0-9_]*)<<([A-Za-z0-9_.-]+)['\"]?\s*$")
    for index, line in enumerate(lines):
        match = opener.match(line)
        if not match:
            continue
        name, delimiter = match.groups()
        terminator = re.compile(rf"^\s*echo\s+['\"]?{re.escape(delimiter)}['\"]?\s*$")
        close = next((i for i in range(index + 1, len(lines)) if terminator.match(lines[i])), None)
        if close is None or not any(
            re.search(rf"\$GITHUB_{target}\b", tail, re.IGNORECASE)
            and re.search(r"(?:>>|tee\s+-a)", tail)
            for tail in lines[close + 1:close + 5]
        ):
            continue
        payload = lines[index + 1:close]
        tainted = any(_UNTRUSTED_CONTEXT.search(item) for item in payload) or any(
            (ref.group(1) or ref.group(2)) in tainted_names
            for item in payload for ref in refs.finditer(item)
        )
        if tainted:
            exports.add(name)
            # Fixed delimiters can be injected as a line in attacker-controlled data.
            unsafe_lines.add(index + 1)
    return exports, unsafe_lines


def _env_exports(body: str, tainted_names: set[str]) -> set[str]:
    if not tainted_names:
        return set()
    refs = re.compile(r"(?:\$([A-Za-z_][A-Za-z0-9_]*)|\$\{([A-Za-z_][A-Za-z0-9_]*)\})")
    exported: set[str] = set()
    for line in body.splitlines():
        if not re.search(r"\$GITHUB_ENV\b", line, re.IGNORECASE):
            continue
        if not re.search(r"(?:>>|tee\s+-a)\s*\"?\$GITHUB_ENV\b", line, re.IGNORECASE):
            continue
        variable = re.search(r"\b([A-Za-z_][A-Za-z0-9_]*)=", line)
        if not variable:
            continue
        if any((match.group(1) or match.group(2)) in tainted_names for match in refs.finditer(line)):
            exported.add(variable.group(1))
    multiline_exports, _ = _multiline_file_flow(body, tainted_names, "ENV")
    exported.update(multiline_exports)
    return exported


def _output_exports(body: str, tainted_names: set[str]) -> set[str]:
    refs = re.compile(r"(?:\$([A-Za-z_][A-Za-z0-9_]*)|\$\{([A-Za-z_][A-Za-z0-9_]*)\})")
    exported: set[str] = set()
    for line in body.splitlines():
        if not re.search(r"\$GITHUB_OUTPUT\b", line, re.IGNORECASE):
            continue
        if not re.search(r"(?:>>|tee\s+-a)\s*\"?\$GITHUB_OUTPUT\b", line, re.IGNORECASE):
            continue
        variable = re.search(r"\b([A-Za-z_][A-Za-z0-9_]*)=", line)
        if not variable:
            continue
        context_is_untrusted = bool(_UNTRUSTED_CONTEXT.search(line))
        env_is_untrusted = any(
            (match.group(1) or match.group(2)) in tainted_names
            for match in refs.finditer(line)
        )
        if context_is_untrusted or env_is_untrusted:
            exported.add(variable.group(1))
    multiline_exports, _ = _multiline_file_flow(body, tainted_names, "OUTPUT")
    exported.update(multiline_exports)
    return exported


def _unsafe_env_file_lines(body: str, tainted_names: set[str]) -> set[int]:
    """Find one-line shell writes that let untrusted newlines add file commands."""
    variable_refs = re.compile(
        r"(?<![A-Za-z0-9_])(?:"
        + "|".join(
            rf"\${name}\b|\$\{{{name}\}}"
            for name in sorted(tainted_names)
        )
        + r")",
        re.IGNORECASE,
    ) if tainted_names else None
    findings: set[int] = set()
    for target in ("ENV", "OUTPUT"):
        _, multiline_unsafe = _multiline_file_flow(body, tainted_names, target)
        findings.update(multiline_unsafe)
    for line_number, line in enumerate(body.splitlines(), start=1):
        if not re.search(r"\$GITHUB_(?:ENV|OUTPUT)\b", line, re.IGNORECASE):
            continue
        if not re.search(r"(?:>>|tee\s+-a)\s*\"?\$GITHUB_(?:ENV|OUTPUT)\b", line, re.IGNORECASE):
            continue
        if not re.search(r"\b(?:echo|printf)\b", line, re.IGNORECASE):
            continue
        if not re.search(r"\b[A-Za-z_][A-Za-z0-9_]*=", line):
            continue
        if _UNTRUSTED_CONTEXT.search(line):
            findings.add(line_number)
            continue
        # Base64 followed by newline removal produces a single safe file value.
        if re.search(r"\bbase64\b.*\btr\s+-d\s+['\"]?\\?n", line):
            continue
        if variable_refs:
            for reference in variable_refs.finditer(line):
                if _shell_quote_at(line, reference.start()) != "'":
                    findings.add(line_number)
                    break
    return findings


def _job_output_taint(workflow: _Workflow) -> dict[str, set[str]]:
    """Propagate simple step outputs through declared job outputs to needs.* env."""
    tainted_outputs: dict[str, set[str]] = {job.name: set() for job in workflow.jobs}
    for _ in range(max(1, len(workflow.jobs))):
        changed = False
        for job in workflow.jobs:
            persistent = (
                _untrusted_fields(workflow.env_sources)
                | _untrusted_fields(job.env_sources)
            )
            for field in job.env_sources:
                if any(output in tainted_outputs.get(source, set()) for source, output in _needs_output_refs(field.value)):
                    persistent.add(field.key)

            step_outputs: dict[str, set[str]] = {}
            for step in job.steps:
                step_env = persistent | _untrusted_env_names(step, tainted_outputs)
                exported: set[str] = set()
                for _, _, body in step.runs:
                    aliases = _local_aliases(body, step_env)
                    exported.update(_output_exports(body, aliases))
                    persistent.update(_env_exports(body, aliases))
                step_id = next((field.value for field in step.values("id")), None)
                if step_id and exported:
                    step_outputs[step_id] = exported
            for output_field in job.output_fields:
                source = re.search(
                    r"\$\{\{\s*steps\.([A-Za-z0-9_-]+)\.outputs\.([A-Za-z_][A-Za-z0-9_-]*)\s*\}\}",
                    output_field.value,
                )
                if source and source.group(2) in step_outputs.get(source.group(1), set()):
                    if output_field.key not in tainted_outputs[job.name]:
                        tainted_outputs[job.name].add(output_field.key)
                        changed = True
        if not changed:
            break
    return tainted_outputs


def _local_aliases(body: str, tainted_names: set[str]) -> set[str]:
    aliases = set(tainted_names)
    refs = re.compile(r"(?:\$([A-Za-z_][A-Za-z0-9_]*)|\$\{([A-Za-z_][A-Za-z0-9_]*)\})")
    for line in body.splitlines():
        assignment = re.match(r"\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)", line)
        if assignment and any((match.group(1) or match.group(2)) in aliases for match in refs.finditer(assignment.group(2))):
            aliases.add(assignment.group(1))
    return aliases


def _dynamic_execution_line(body: str, tainted_names: set[str]) -> int | None:
    aliases = set(tainted_names)
    shell_refs = re.compile(r"(?:\$([A-Za-z_][A-Za-z0-9_]*)|\$\{([A-Za-z_][A-Za-z0-9_]*)\})")
    for line_number, line in enumerate(body.splitlines(), start=1):
        references = re.compile(
            r"(?<![A-Za-z0-9_])(?:"
            + "|".join(
                rf"\${name}\b|\$\{{{name}\}}|\$env:{name}\b|%{name}%"
                for name in sorted(aliases)
            )
            + r")",
            re.IGNORECASE,
        ) if aliases else None
        for sink in _DYNAMIC_CODE_SINK.finditer(line):
            reference = references.search(line[sink.end():]) if references else None
            if not reference:
                continue
            reference_start = sink.end() + reference.start()
            quote = _shell_quote_at(line, reference_start)
            if sink.lastgroup == "eval" or quote != "'":
                return line_number
            if sink.lastgroup == "shell":
                prefix = line[sink.end():reference_start]
                suffix = line[reference_start + len(reference.group(0)):]
                if not prefix.strip(" \t'\"") and not suffix.strip(" \t'\";#"):
                    return line_number
                if re.search(r"\b(?:eval|source)\b", prefix, re.IGNORECASE):
                    return line_number
        assignment = re.match(r"\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)", line)
        if assignment and any((match.group(1) or match.group(2)) in aliases for match in shell_refs.finditer(assignment.group(2))):
            aliases.add(assignment.group(1))
    return None


def _shell_quote_at(line: str, position: int) -> str | None:
    quote: str | None = None
    escaped = False
    for char in line[:position]:
        if quote == "'":
            if char == "'":
                quote = None
        elif quote == '"':
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quote = None
        elif char in {"'", '"'}:
            quote = char
    return quote


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
                if _later_executes_job_content(job, step):
                    evidence = (untrusted_fields or unsafe_opt_in)[0]
                    risky_checkout = evidence.line
                    break
            if risky_checkout is not None:
                break
        if risky_checkout is not None:
            add(
                risky_checkout + 1,
                "CFG008_PULL_REQUEST_TARGET_UNTRUSTED_CHECKOUT",
                "privileged pull_request_target workflow selects or explicitly enables pull-request code checkout and later runs commands or a local action",
                "Do not execute pull-request code in pull_request_target, including through uses: ./... local actions. Use an unprivileged pull_request workflow, or keep privileged automation limited to metadata operations.",
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
                if revision_fields and _later_executes_job_content(job, step):
                    risky_checkout = revision_fields[0].line + 1
                    break
            if risky_checkout is not None:
                break
        if risky_checkout is not None:
            add(
                risky_checkout,
                "CFG012_WORKFLOW_RUN_REVISION_EXECUTION",
                "workflow_run checks out an upstream workflow revision and later runs commands or a local action in the same job",
                "Verify the upstream run's source event and repository before checkout; keep downstream privileged jobs from executing untrusted pull-request code.",
                severity="medium",
            )
        for job in workflow.jobs:
            risky_download = next((
                step for step in job.steps
                if any(re.match(r"(?i)actions/download-artifact(?:@|$)", field.value) for field in step.values("uses"))
                and _later_executes_job_content(job, step)
            ), None)
            if risky_download is not None:
                add(
                    next(field.line + 1 for field in risky_download.values("uses")),
                    "CFG010_WORKFLOW_RUN_ARTIFACT_EXECUTION",
                    "privileged workflow_run job downloads an upstream artifact and later runs commands or a local action in the same job",
                    "Treat workflow_run artifacts as untrusted data. Validate and inspect contents; do not execute scripts or binaries from the downloaded artifact in a privileged job.",
                )
                break

    # actions/checkout persists its token in local Git configuration by
    # default. If that checkout selects an untrusted PR/upstream revision and
    # the same privileged job later executes repository content, the token is
    # available to that content. Report the credential exposure separately
    # from the execution finding so the remediation is actionable.
    risky_persisted_token: int | None = None
    persisted_token_severity = "high"
    for job in workflow.jobs:
        for step in job.steps:
            uses = next((
                field for field in step.values("uses")
                if re.match(r"(?i)actions/checkout(?:@|$)", field.value)
            ), None)
            if uses is None:
                continue
            if not _later_executes_job_content(job, step):
                continue
            credential_setting = next(iter(step.values("persist-credentials")), None)
            # Omitted and unresolved values retain an effective credential
            # persistence risk. Only an explicit YAML false disables it.
            if credential_setting is not None and credential_setting.value.casefold() == "false":
                continue
            for field in step.fields:
                key = field.key.casefold()
                if key not in {"ref", "repository"}:
                    continue
                if "pull_request_target" in workflow.triggers and (
                    _UNTRUSTED_REF.search(field.value) or _UNTRUSTED_REPOSITORY.search(field.value)
                ):
                    risky_persisted_token = uses.line
                    persisted_token_severity = "high"
                    break
                if "workflow_run" in workflow.triggers and _WORKFLOW_RUN_REVISION.search(field.value):
                    risky_persisted_token = uses.line
                    persisted_token_severity = "medium"
                    break
            if risky_persisted_token is None and "pull_request_target" in workflow.triggers:
                if any(
                    field.value.casefold() == "true"
                    for field in step.values("allow-unsafe-pr-checkout")
                ):
                    risky_persisted_token = uses.line
                    persisted_token_severity = "high"
            if risky_persisted_token is not None:
                break
        if risky_persisted_token is not None:
            break
    if risky_persisted_token is not None:
        add(
            risky_persisted_token + 1,
            "CFG016_ACTIONS_PERSISTED_TOKEN_WITH_UNTRUSTED_CHECKOUT",
            "privileged workflow persists the checkout token while later executing content from an untrusted revision",
            "Set persist-credentials: false on the checkout and avoid executing untrusted pull-request content in a privileged workflow; grant only the minimum token permissions needed.",
            severity=persisted_token_severity,
        )

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
                    later_run = _later_executes_job_content(job, step)
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
                "privileged workflow fetches pull-request code through a shell command and later runs commands or a local action",
                "Do not fetch or execute untrusted pull-request code in pull_request_target, workflow_run, or issue_comment, including through uses: ./... local actions. Use an unprivileged pull_request workflow or keep privileged automation limited to metadata operations.",
            )

    job_output_taint = _job_output_taint(workflow)
    for job in workflow.jobs:
        persistent_taint = (
            _untrusted_fields(workflow.env_sources)
            | _untrusted_fields(job.env_sources)
        )
        for field in job.env_sources:
            if any(output in job_output_taint.get(source, set()) for source, output in _needs_output_refs(field.value)):
                persistent_taint.add(field.key)
        for step in job.steps:
            tainted_env = persistent_taint | _untrusted_env_names(step, job_output_taint)
            for relative_line, _, body in step.runs:
                if _UNTRUSTED_CONTEXT.search(body):
                    # Report the run block, not attacker-controlled text.
                    add(
                        step.start + relative_line,
                        "CFG009_ACTIONS_UNTRUSTED_RUN_EXPRESSION",
                        "untrusted GitHub event text is interpolated directly into a shell run block",
                        "Pass event data through an environment variable and validate it as data; never interpolate attacker-controlled context directly into run script source.",
                    )
                aliases = _local_aliases(body, tainted_env)
                for relative_sink_line in _unsafe_env_file_lines(body, aliases):
                    add(
                        step.start + relative_line + relative_sink_line - 1,
                        "CFG015_ACTIONS_UNTRUSTED_ENV_FILE_INJECTION",
                        "untrusted multiline data is written as a single-line GitHub environment or output file entry",
                        "Reject or encode CR/LF before writing untrusted values to GITHUB_ENV or GITHUB_OUTPUT; use GitHub's documented delimiter format for multiline data with a delimiter that cannot occur in the value.",
                    )
                if tainted_env and _dynamic_execution_line(body, tainted_env) is not None:
                    add(
                        step.start + relative_line,
                        "CFG014_ACTIONS_UNTRUSTED_ENV_TO_CODE_EXECUTION",
                        "untrusted event data passed through an environment variable is reparsed by a dynamic code-execution command",
                        "Keep untrusted values as data. Remove eval or shell -c reparsing; use fixed commands and validated arguments, and avoid sourcing paths derived from event input.",
                    )
                persistent_taint.update(_env_exports(body, aliases))
    return findings
