"""Mutation-check the completion guards.

A guard that cannot fail is not a guard. Every declaration below weakens one
security property inside a scratch copy of this component and asserts that the
named guard tests then fail. A neutral declaration asserts they still pass, so
the harness cannot appear to work by failing everything. The baseline run
asserts the guards pass unmutated, so a broken environment cannot masquerade as
a set of working guards either.
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

COMPONENT = Path(__file__).resolve().parent
SIBLINGS = ("northstar-run-contract", "northstar-host")


@dataclass(frozen=True)
class Mutation:
    """One declared weakening: replace ``old`` with ``new`` and expect ``expect``."""

    name: str
    target: str
    old: str
    new: str
    guard: str
    expect: str


MUTATIONS = (
    Mutation(
        name="executor-bypasses-the-path-guard",
        target="agent_entry.py",
        old="return self._write_tool(arguments).as_output()",
        new=(
            'target = self.workspace_root / arguments["path"]; '
            "target.parent.mkdir(parents=True, exist_ok=True); "
            'content = arguments.get("content", ""); '
            'target.write_text(content, encoding="utf-8"); '
            'return {"path": arguments["path"], "bytes_written": len(content)}'
        ),
        guard="tests.test_completion_guarantee_scope",
        expect="fail",
    ),
    Mutation(
        name="write-tool-allows-parent-traversal",
        target="workspace_write.py",
        old='p in {"", ".", ".."}',
        new='p in {"", "."}',
        guard="tests.test_completion_trust_boundary",
        expect="fail",
    ),
    Mutation(
        name="observer-skips-symlinks-instead-of-refusing",
        target="completion_workspace_snapshot.py",
        old='raise WorkspaceObservationRefused(f"symlink refused: {name}")',
        new="continue",
        guard="tests.test_completion_workspace_snapshot",
        expect="fail",
    ),
    Mutation(
        name="replay-skips-chain-verification",
        target="completion_replay.py",
        old="if verify_evidence_chain(events) is not None:",
        new="if False:",
        guard="tests.test_completion_evidence_integrity",
        expect="fail",
    ),
    Mutation(
        name="advisory-decides-the-exit-code",
        target="live_run.py",
        old=(
            "    # The production gate alone decides this; the advisory is recorded, never read.\n"
            "    return 0 if outcome.ok else 1"
        ),
        new=(
            '    advisory_ok = report.get("shadow_advisory", {}).get("layered_verdict", "verified") == "verified"\n'
            "    return 0 if (outcome.ok and advisory_ok) else 1"
        ),
        guard="tests.test_completion_advisory",
        expect="fail",
    ),
    Mutation(
        name="advisory-contract-allows-undeclared-mutations",
        target="completion_advisory.py",
        old='allowed_mutations=tuple(item["path"] for item in spec["artifacts"]),',
        new=(
            'allowed_mutations=tuple(item["path"] for item in spec["artifacts"]) '
            '+ ("out/notes.txt",),'
        ),
        guard="tests.test_completion_advisory",
        expect="fail",
    ),
    Mutation(
        name="advisory-ignores-the-evidence-journal",
        target="completion_advisory.py",
        old="    status = _evidence_status(journal)",
        new='    status = "finished"',
        guard="tests.test_completion_advisory",
        expect="fail",
    ),
    Mutation(
        name="distribution-invents-a-missing-verdict",
        target="advisory_report.py",
        old=(
            "    if not isinstance(value, str) or not value.strip():\n"
            "        return UNKNOWN"
        ),
        new=(
            "    if not isinstance(value, str) or not value.strip():\n"
            '        return "verified"'
        ),
        guard="tests.test_advisory_report",
        expect="fail",
    ),
    Mutation(
        name="neutral-docstring-change",
        target="completion_replay.py",
        old='"""Return an independently derived terminal status, or empty on uncertainty."""',
        new='"""Return a terminal status."""',
        guard="tests.test_completion_evidence_integrity",
        expect="pass",
    ),
)


def _scratch_copy(destination: Path) -> Path:
    """Copy this component and its import siblings so guards run unmodified."""
    components = COMPONENT.parent
    for name in (COMPONENT.name,) + SIBLINGS:
        shutil.copytree(components / name, destination / name)
    return destination / COMPONENT.name


def apply_mutation(mutation: Mutation, component_root: Path) -> None:
    """Replace the declared fragment, refusing when it is not unique."""
    path = component_root / mutation.target
    text = path.read_text(encoding="utf-8")
    occurrences = text.count(mutation.old)
    if occurrences != 1:
        raise ValueError(
            f"{mutation.target}: fragment occurs {occurrences} times, expected 1"
        )
    path.write_text(text.replace(mutation.old, mutation.new), encoding="utf-8")


def run_guard(component_root: Path, guard: str, timeout: int = 900) -> bool:
    """Return True when the named guard tests pass."""
    environment = dict(os.environ)
    paths = [component_root] + [component_root.parent / name for name in SIBLINGS]
    environment["PYTHONPATH"] = os.pathsep.join(str(item) for item in paths)
    completed = subprocess.run(
        [sys.executable, "-m", "unittest", guard],
        cwd=str(component_root),
        env=environment,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return completed.returncode == 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Mutation-check the completion guards.")
    parser.add_argument("--only", action="append", default=[], help="run only these mutations")
    parser.add_argument("--list", action="store_true", help="list declarations and exit")
    arguments = parser.parse_args(argv)

    if arguments.list:
        for mutation in MUTATIONS:
            print(f"{mutation.name}\t{mutation.target}\texpect={mutation.expect}")
        return 0

    selected = [item for item in MUTATIONS if not arguments.only or item.name in arguments.only]
    failures: list[str] = []

    with tempfile.TemporaryDirectory(prefix="northstar-mutation-") as temporary:
        scratch = Path(temporary)
        guards = sorted({item.guard for item in selected})

        baseline_root = _scratch_copy(scratch / "baseline")
        for guard in guards:
            passed = run_guard(baseline_root, guard)
            mark = "PASS" if passed else "FAIL"
            print(f"[{mark}] baseline: {guard} unmutated")
            if not passed:
                failures.append(f"baseline:{guard}")

        for index, mutation in enumerate(selected):
            root = _scratch_copy(scratch / f"mutation-{index}")
            try:
                apply_mutation(mutation, root)
            except ValueError as error:
                print(f"[FAIL] {mutation.name}: declaration does not match code ({error})")
                failures.append(mutation.name)
                continue
            observed = "pass" if run_guard(root, mutation.guard) else "fail"
            ok = observed == mutation.expect
            mark = "PASS" if ok else "FAIL"
            print(f"[{mark}] {mutation.name}: guard {observed}, expected {mutation.expect}")
            if not ok:
                failures.append(mutation.name)

    print(f"mutations={len(selected)} failures={len(failures)}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
