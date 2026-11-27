"""Tell a task that is broken from a machine that broke.

A probe that dies of a segmentation fault says nothing about the task: the
evaluation images are built for one architecture, and on another one they
run under emulation, where the compiled extensions of numpy and pandas
crash the test process. Counting that as a rejected reference patch would
condemn a sound task on the strength of the host it ran on.

This module finds the exit status the upstream runner records and names the
failure, so that such a task is reported as inconclusive -- neither a
trustworthy task nor a broken one.
"""

from __future__ import annotations

import re
from pathlib import Path

#: Exit statuses that mean the run itself broke, not the code under test.
INFRA_EXIT_CODES = {
    139: "Segmentation fault",
    134: "Aborted",
    137: "Killed",
    135: "Bus error",
}

#: Fallback for a run that died before it could write an exit status.
INFRA_MARKERS = (
    "Segmentation fault",
    "Bus error",
    "Cannot allocate memory",
)


def infra_failure(log_root: Path | str, run_id: str, probe: str, instance_id: str) -> str:
    """A description of the infrastructure failure, or an empty string.

    The exit status is the exact signal, so it is preferred over a text
    match: a test that merely prints "Killed" would otherwise be mistaken
    for a run that was killed.
    """
    base = Path(log_root) / "logs" / "run_evaluation" / run_id / probe / instance_id
    text = ""
    for name in ("run_instance.log", "test_output.txt"):
        try:
            text += (base / name).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
    if not text:
        return ""
    for raw in re.findall(r"SWEBENCH_TEST_EXIT_CODE=(\d+)", text):
        reason = INFRA_EXIT_CODES.get(int(raw))
        if reason:
            return reason
    for marker in INFRA_MARKERS:
        if marker in text:
            return marker
    return ""


def probe_infra_failure(
    log_root: Path | str,
    run_id: str,
    probe: str,
    instance_id: str,
) -> str:
    """The failure of one probe, if the run broke rather than the code."""
    return infra_failure(log_root, run_id, probe, instance_id)
