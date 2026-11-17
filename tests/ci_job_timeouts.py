"""CI job timeouts: every job in the CI workflow must declare one.

A GitHub Actions job without an explicit ``timeout-minutes`` inherits the
platform default of **360 minutes**.  A step that hangs -- a ``pip install``
that stalls on a dead index, a test suite that blocks on a socket, a
``node --test`` that never returns -- therefore burns six hours of CI
before GitHub cancels the job and reports anything.  On a runner fleet
that is six hours of paid capacity spent on a job that will fail anyway.

The repository already has the convention and the precedent:  the
``egress-sidecar`` job declares ``timeout-minutes: 5`` and
``tests/test_egress_ci.py`` pins it.  This module generalises that to
every job.

This module holds the DETECTOR, deliberately outside the test file:  the
mutant probe mutates a module and reruns the slice's tests, and a test
file is excluded from the probe by name, so a guard whose logic lives
entirely inside a test file cannot be mutation-probed at all.

The measurement the limits are chosen against is recorded in
``docs/design/ci-job-timeouts.md`` and in the slice report.  In short:
the ``agent-runtime`` job runs a 21,352-test pytest suite (measured
6m52s on this host) plus a 13-guard invariant verification (measured
5m06s), so its limit is set well above the measured workload rather
than at it.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "test.yml"

#: GitHub's default when a job declares no `timeout-minutes`.
GITHUB_DEFAULT_TIMEOUT_MINUTES = 360

#: A YAML key with no value on its line: `steps:`.
_KEY_ONLY = re.compile(r"^([ \t]*)([A-Za-z0-9_.-]+):[ \t]*$")
#: A YAML list item: `- name: Compile`.
_ITEM = re.compile(r"^([ \t]*)-[ \t]")
#: `timeout-minutes: 30`.  The value is SIGNED, so that a negative timeout
#: is read as a declared (and nonsensical) limit rather than as no limit
#: at all.
_TIMEOUT = re.compile(r"^([ \t]*)timeout-minutes:[ \t]*(-?\d+)[ \t]*$")


def _indent_of(line: str) -> int:
    """The column a line's content starts at."""
    return len(line) - len(line.lstrip(" \t"))


def _jobs_region(source: str) -> list[str]:
    """The lines of the workflow's `jobs:` mapping.

    The region starts after the top-level `jobs:` key and ends at the
    next top-level key, if any.  Scoping it this way is what keeps the
    workflow's `on:` block -- whose `push:` and `pull_request:` keys are
    indented exactly like job names -- from being read as jobs.
    """
    lines = source.splitlines()
    start = None
    for index, line in enumerate(lines):
        if _indent_of(line) == 0 and line.strip().startswith("jobs:"):
            start = index + 1
            break
    if start is None:
        return []
    region = []
    for line in lines[start:]:
        if line.strip() and _indent_of(line) == 0:
            break
        region.append(line)
    return region


def _job_headers(region: list[str]) -> list[tuple[str, int, int, int]]:
    """The job headers in a `jobs:` region.

    Each entry is (name, indent, first line of the job's body, last line
    of the job's body).  A job header is a key at the SHALLOWEST
    indentation of the region -- the job names are the keys of the
    `jobs:` mapping, and everything deeper belongs to a job.
    """
    entries: list[tuple[int, int, str]] = []
    for index, line in enumerate(region):
        match = _KEY_ONLY.match(line)
        if match is None:
            continue
        entries.append((index, len(match.group(1)), match.group(2)))
    if not entries:
        return []
    shallowest = min(entry[1] for entry in entries)
    headers = [entry for entry in entries if entry[1] == shallowest]
    result: list[tuple[str, int, int, int]] = []
    for position, (index, indent, name) in enumerate(headers):
        end = headers[position + 1][0] if position + 1 < len(headers) else len(region)
        result.append((name, indent, index + 1, end))
    return result


def _job_bodies(text: str | None = None) -> dict[str, tuple[int, list[str]]]:
    """Every job in the workflow, as (name -> (indent, the job's lines)).

    The lines are the job's OWN lines: the header is excluded, and so is
    everything from the next job's header onwards.
    """
    source = WORKFLOW.read_text(encoding="utf-8") if text is None else text
    region = _jobs_region(source)
    bodies: dict[str, tuple[int, list[str]]] = {}
    for name, indent, start, end in _job_headers(region):
        bodies[name] = (indent, region[start:end])
    return bodies


def job_blocks(text: str | None = None) -> dict[str, str]:
    """Every job in the workflow, as (name -> the job's own YAML text).

    The text of a job is everything from its header up to the next job
    header.  Only the job's OWN keys are returned -- a
    ``timeout-minutes`` belonging to some other job must not be
    attributed to it.
    """
    return {
        name: "\n".join(lines)
        for name, (_indent, lines) in _job_bodies(text).items()
    }


def job_names(text: str | None = None) -> list[str]:
    """The names of every job in the workflow."""
    return list(_job_bodies(text))


def _direct_child_indent(indent: int, lines: list[str]) -> int:
    """The indentation of a job's own keys.

    A job's own keys sit one level below its header; everything deeper
    belongs to a nested mapping or to a step.  A STEP-level
    ``timeout-minutes`` is therefore not a job-level one, and the
    difference between the two is exactly this indentation.
    """
    deeper = [
        _indent_of(line)
        for line in lines
        if line.strip() and _indent_of(line) > indent
    ]
    return min(deeper) if deeper else indent + 2


def job_timeout(text: str | None = None) -> dict[str, int | None]:
    """Each job's declared timeout in minutes, or None when it declares none.

    ``None`` means the job inherits GitHub's 360-minute default, which is
    the defect this guard exists to catch.
    """
    timeouts: dict[str, int | None] = {}
    for name, (indent, lines) in _job_bodies(text).items():
        child_indent = _direct_child_indent(indent, lines)
        value: int | None = None
        for line in lines:
            match = _TIMEOUT.match(line)
            if match is None:
                continue
            if len(match.group(1)) == child_indent:
                value = int(match.group(2))
                break
        timeouts[name] = value
    return timeouts


def effective_timeout(text: str | None = None) -> dict[str, int]:
    """Each job's timeout as CI will actually apply it."""
    return {
        name: (value if value is not None else GITHUB_DEFAULT_TIMEOUT_MINUTES)
        for name, value in job_timeout(text).items()
    }


def jobs_without_timeout(text: str | None = None) -> list[str]:
    """The jobs that declare no timeout, and so inherit the 360-minute default.

    This is the list the guard names when it fails.
    """
    return [
        name
        for name, value in job_timeout(text).items()
        if value is None
    ]


def jobs_with_nonsensical_timeout(text: str | None = None) -> list[str]:
    """The jobs whose declared timeout cannot be a real limit.

    A timeout of zero cancels the job before its first step runs;  a
    negative one is not a valid value at all.  Either makes the job
    unusable rather than bounded.
    """
    bad = []
    for name, value in job_timeout(text).items():
        if value is not None and value <= 0:
            bad.append(name)
    return bad


def job_step_count(text: str | None = None) -> dict[str, int]:
    """How many steps each job declares.

    Used by the report to show what a job's limit has to cover.
    """
    counts: dict[str, int] = {}
    for name, (indent, lines) in _job_bodies(text).items():
        child_indent = _direct_child_indent(indent, lines)
        steps_at = None
        for index, line in enumerate(lines):
            if _indent_of(line) == child_indent and line.strip() == "steps:":
                steps_at = index
                break
        if steps_at is None:
            counts[name] = 0
            continue
        item_indent = None
        for line in lines[steps_at + 1:]:
            match = _ITEM.match(line)
            if match is None:
                continue
            item_indent = len(match.group(1))
            break
        if item_indent is None:
            counts[name] = 0
            continue
        counts[name] = sum(
            1
            for line in lines[steps_at + 1:]
            if _ITEM.match(line) is not None
            and len(_ITEM.match(line).group(1)) == item_indent
        )
    return counts
