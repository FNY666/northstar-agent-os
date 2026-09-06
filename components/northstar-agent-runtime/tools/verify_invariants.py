#!/usr/bin/env python3
"""Revert each core guard in a throwaway copy of the component and confirm the
matching test goes red. A green test that survives removing the guard is not a
test of the guard.

    python3 tools/verify_invariants.py

Nothing in the checked-out tree is modified: each guard is reverted in a private
copy under /tmp, its test module is run there, and the result is reported. The
untouched tree is run as a baseline at the end, because a mutation only means
something when the unmutated suite was green to begin with.
"""
from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

COMPONENT = Path(__file__).resolve().parents[1]
REPO = COMPONENT.parents[1]
SIDECAR = REPO / "components/northstar-codex-sidecar"

# guard -> (mutated file, [(old, new), ...], test module glob)
GUARDS: list[tuple[str, str, list[tuple[str, str]], str, str]] = [
    (
        "compaction may only cut at a boundary with no pending tool call",
        "compaction.py",
        [("    prefix = transcript[:cut]\n    suffix = transcript[cut:]\n    if pending_tool_uses(prefix):\n        return False",
          "    prefix = transcript[:cut]\n    suffix = transcript[cut:]\n    if False and pending_tool_uses(prefix):\n        return False")],
        "test_compaction*",
        "test_the_loop_never_sends_a_dangling_tool_use_after_compacting",
    ),
    (
        "tool paths are contained in the workspace after resolving symlinks",
        "tools.py",
        [("    def _within(self, resolved: Path) -> bool:\n        try:",
          "    def _within(self, resolved: Path) -> bool:\n        return True\n        try:")],
        "test_tools*",
        "test_absolute_paths_outside_are_refused",
    ),
    (
        "the cost ceiling is checked before every generation",
        "loop.py",
        [('        if config.max_budget_usd is not None and self.budget.exhausted:',
          '        if False and config.max_budget_usd is not None and self.budget.exhausted:')],
        "test_budget*",
        "test_budget_ceiling_stops_before_the_next_generation",
    ),
    (
        "a hook deny is terminal and cannot be overturned",
        "hooks.py",
        [("""                outcome.skipped.extend(other.name for other in registrations[registrations.index(registration) + 1 :])
                return outcome
            if result.decision == \"modify_input\":""",
          """                outcome.skipped.extend(other.name for other in registrations[registrations.index(registration) + 1 :])
                # MUTATION: a deny no longer ends the chain.
                outcome.denied = False
                outcome.denied_by = ""
            if result.decision == \"modify_input\":""")],
        "test_hooks*",
        "test_a_deny_stops_the_chain_and_cannot_be_overturned",
    ),
    (
        "usage and cost are recorded before the generation span ends",
        "loop.py",
        [("                            generation_span.record_usage(",
          "                            generation_span.end()  # MUTATION: write after end\n                            generation_span.record_usage(")],
        "test_tracing*",
        "test_no_attribute_anywhere_was_dropped_because_a_span_had_ended",
    ),
]


def prepare(root: Path) -> Path:
    target = root / "components/northstar-agent-runtime"
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(COMPONENT, target)
    shutil.copytree(SIDECAR, root / "components/northstar-codex-sidecar")
    for cached in target.rglob("__pycache__"):
        shutil.rmtree(cached, ignore_errors=True)
    return target


def run(component: Path, pattern: str) -> tuple[int, str]:
    proc = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", pattern],
        cwd=str(component),
        capture_output=True,
        text=True,
        check=False,
        timeout=300,
    )
    return proc.returncode, proc.stdout + proc.stderr


def main() -> int:
    failures: list[str] = []
    for title, filename, edits, pattern, marker in GUARDS:
        with tempfile.TemporaryDirectory(prefix="nsar-guard-") as tmp:
            component = prepare(Path(tmp))
            source = component / filename
            text = source.read_text(encoding="utf-8")
            for old, new in edits:
                if text.count(old) != 1:
                    failures.append(f"{title}: mutation anchor not found exactly once in {filename}")
                    break
                text = text.replace(old, new)
            else:
                source.write_text(text, encoding="utf-8")
                code, output = run(component, pattern)
                red = code != 0
                names = [line for line in output.splitlines() if line.startswith(("FAIL:", "ERROR:"))]
                hit = any(marker in line for line in names) if marker else bool(names)
                status = "RED" if red else "STILL GREEN"
                print(f"[{status:>11}] {title}")
                print(f"            tests: {pattern} -> {len(names)} failing: {'; '.join(name.split(' ')[1] for name in names[:3]) or output.strip()[-200:]}")
                if not red:
                    failures.append(f"{title}: removing the guard did NOT fail any test")
                elif not hit:
                    print(f"            note: the expected test id ({marker}) was not among them")
    # Sanity: the untouched tree must be green, or the mutations prove nothing.
    with tempfile.TemporaryDirectory(prefix="nsar-baseline-") as tmp:
        component = prepare(Path(tmp))
        code, output = run(component, "test_*.py")
        tail = [line for line in output.splitlines() if line.startswith(("Ran ", "OK", "FAILED"))]
        print(f"\n[baseline copy] {'OK' if code == 0 else 'BROKEN'}: {' | '.join(tail)}")
        if code != 0:
            failures.append("baseline copy of the untouched component is not green")
    if failures:
        print("\nGUARD VERIFICATION PROBLEMS:")
        for item in failures:
            print(f"  - {item}")
        return 1
    print("\nall five guards verified: reverting each one turns its test red")
    return 0


if __name__ == "__main__":
    sys.exit(main())
