"""Account for tests that already fail before the patch is applied.

A pass-to-pass test that fails on the untouched checkout did not break
because of the patch: the environment does not satisfy it (no network
access, a newer dependency, a different timezone).  Counting such a test
against the patch hides a correct fix.

This module takes the upstream report of a *baseline* run -- the same
instance evaluated with no patch applied -- and says which pass-to-pass
tests must be left out of the verdict.  The exclusion is never silent:
the caller records the excluded test names alongside the verdict.

The upstream formulas are reproduced here rather than imported so that
the rule can be tested without the ``swebench`` package installed.
"""
from __future__ import annotations

from typing import Any

FAIL_TO_PASS = "FAIL_TO_PASS"
PASS_TO_PASS = "PASS_TO_PASS"

RESOLVED_FULL = "RESOLVED_FULL"
RESOLVED_PARTIAL = "RESOLVED_PARTIAL"
RESOLVED_NO = "RESOLVED_NO"


def _tests(entry: dict[str, Any], key: str) -> tuple[list[str], list[str]]:
    """Return the (success, failure) test lists of one report section."""
    detail = entry.get("tests_status")
    if not isinstance(detail, dict):
        return [], []
    section = detail.get(key)
    if not isinstance(section, dict):
        return [], []
    success = section.get("success")
    failure = section.get("failure")
    return (
        list(success) if isinstance(success, list) else [],
        list(failure) if isinstance(failure, list) else [],
    )


def baseline_p2p_failures(baseline_entry: dict[str, Any]) -> set[str]:
    """Pass-to-pass tests that already failed without the patch."""
    _, failure = _tests(baseline_entry, PASS_TO_PASS)
    return set(failure)


def excluded_p2p(
    current_entry: dict[str, Any], baseline_entry: dict[str, Any] | None
) -> list[str]:
    """Pass-to-pass tests that failed now and already failed at baseline.

    A test that the patch *fixed* is not excluded: it was expected to pass
    and it now does.  A test that failed now but passed at baseline is
    not excluded either: that one is the patch's doing.
    """
    if not baseline_entry:
        return []
    _, current_failure = _tests(current_entry, PASS_TO_PASS)
    baseline_failed = baseline_p2p_failures(baseline_entry)
    return sorted(name for name in current_failure if name in baseline_failed)


def _status(
    f2p_success: list[str],
    f2p_failure: list[str],
    p2p_success: list[str],
    p2p_failure: list[str],
) -> str:
    """The upstream resolution formula, on the numbers given."""
    f2p_total = len(f2p_success) + len(f2p_failure)
    f2p = 1.0 if f2p_total == 0 else len(f2p_success) / f2p_total
    p2p_total = len(p2p_success) + len(p2p_failure)
    p2p = 1.0 if p2p_total == 0 else len(p2p_success) / p2p_total
    if f2p == 1 and p2p == 1:
        return RESOLVED_FULL
    if f2p < 1 and f2p > 0 and p2p == 1:
        return RESOLVED_PARTIAL
    return RESOLVED_NO


def rejudge(
    current_entry: dict[str, Any], baseline_entry: dict[str, Any] | None
) -> dict[str, Any]:
    """Re-judge one instance with the baseline-failing tests removed.

    Returns the verdict plus the list of excluded tests, so the caller
    can record what was left out and why.
    """
    f2p_success, f2p_failure = _tests(current_entry, FAIL_TO_PASS)
    p2p_success, p2p_failure = _tests(current_entry, PASS_TO_PASS)
    excluded = excluded_p2p(current_entry, baseline_entry)
    dropped = set(excluded)
    kept_failure = [name for name in p2p_failure if name not in dropped]
    kept_success = [name for name in p2p_success if name not in dropped]
    return {
        "status": _status(f2p_success, f2p_failure, kept_success, kept_failure),
        "excluded_p2p": excluded,
        "p2p_success": kept_success,
        "p2p_failure": kept_failure,
        "fail_to_pass_success": f2p_success,
        "fail_to_pass_failure": f2p_failure,
    }


def load_baseline(path: Any) -> dict[str, dict[str, Any]]:
    """Read a baseline report file: ``{instance_id: report entry}``."""
    import json
    from pathlib import Path

    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("a baseline report must be a mapping of instance id to report")
    out: dict[str, dict[str, Any]] = {}
    for instance_id, entry in raw.items():
        if isinstance(entry, dict) and "tests_status" in entry:
            out[instance_id] = entry
        elif isinstance(entry, dict) and instance_id in entry:
            # The upstream report file is keyed by instance id as well.
            nested = entry[instance_id]
            if isinstance(nested, dict):
                out[instance_id] = nested
    return out
