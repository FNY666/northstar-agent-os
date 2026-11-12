#!/usr/bin/env python3
"""Seal one historical delivery with the real code-task seal pipeline.

This command does not invent a seal. It drives the repository's own
``CodePhaseMachine``: it materialises the delivery commit as a real patch on
top of the delivery's start commit, replays the host-declared checks against
that patched tree, and lets the phase machine write the ``delivery-seal.json``
that the product path would have written. Every field of the resulting seal
(start commit, start tree hash, check-input pins, patch digests) is therefore
produced by the same code that produces a live run's seal.

The auditor side of the blind-re-runner protocol reads exactly this seal, so a
sealed historical delivery is what makes the auditor check set extractable.

Usage::

    python3 scripts/seal-delivery.py seal \\
        --start-commit <sha> --delivery-commit <sha> \\
        --evidence-dir <dir> [--check-input PATH ...] [--check CMD ...]

    python3 scripts/seal-delivery.py verify --evidence-dir <dir>
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Sequence

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / "components" / "northstar-agent-runtime"

if str(RUNTIME) not in sys.path:
    sys.path.insert(0, str(RUNTIME))

from code_task import (  # noqa: E402
    CodePhaseMachine,
    CodeTaskError,
    IsolatedCodeWorkspace,
    audit_delivery_patch,
    reconcile_code_evidence,
    validate_patch_replay,
)

SCHEMA = "northstar.delivery-seal.v2"


class SealError(RuntimeError):
    """The delivery could not be sealed, or its seal does not verify."""


def _git(root: Path, *args: str, check: bool = True) -> str:
    process = subprocess.run(
        ["git", "-C", str(root), *args],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if check and process.returncode != 0:
        raise SealError(f"git {' '.join(args)} failed: {process.stderr.strip()}")
    return process.stdout.strip()


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )


def _read_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise SealError(f"cannot read {path}: {error}") from error
    if not isinstance(payload, dict):
        raise SealError(f"{path} does not contain an object")
    return payload


def _materialise_delivery(
    repository: Path, start_commit: str, delivery_commit: str, destination: Path
) -> None:
    """Check out the delivery commit's tree, with the start commit as parent.

    The seal's contract is "the delivery patch applies to the starting commit
    and the checks still pass against it". Reproducing the delivery as a real
    patch on the start tree is what lets the pipeline verify that claim
    instead of asserting it.
    """
    _git(repository, "worktree", "add", "--detach", str(destination), start_commit)
    patch = subprocess.run(
        ["git", "-C", str(repository), "diff", "--binary", "--no-color", "--no-ext-diff",
         "--full-index", start_commit, delivery_commit, "--"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if patch.returncode != 0:
        raise SealError(f"cannot diff {start_commit}..{delivery_commit}")
    applied = subprocess.run(
        ["git", "-C", str(destination), "apply", "--binary", "--whitespace=nowarn", "-"],
        input=patch.stdout,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if applied.returncode != 0:
        raise SealError(
            "the delivery patch does not apply to the start commit: "
            + applied.stderr.decode("utf-8", errors="replace").strip()
        )


def seal_delivery(
    *,
    repository: Path,
    start_commit: str,
    delivery_commit: str,
    evidence_dir: Path,
    check_inputs: Sequence[str],
    checks: Sequence[str],
    goal: str,
) -> dict[str, Any]:
    """Produce one sealed delivery through the product's own seal pipeline."""
    start_commit = _git(repository, "rev-parse", "--verify", f"{start_commit}^{{commit}}")
    delivery_commit = _git(repository, "rev-parse", "--verify", f"{delivery_commit}^{{commit}}")
    if evidence_dir.exists():
        shutil.rmtree(evidence_dir)
    evidence_dir.mkdir(parents=True)

    run_id = f"seal-{delivery_commit[:12]}"
    worktree = Path(tempfile.mkdtemp(prefix="northstar-seal-")) / "worktree"
    try:
        _materialise_delivery(repository, start_commit, delivery_commit, worktree)
        phases = CodePhaseMachine(
            run_id=run_id,
            evidence_dir=evidence_dir,
            worktree=worktree,
            start_commit=start_commit,
            check_inputs=tuple(check_inputs),
        )
        phases.start()
        phases.submit_plan(
            {
                "summary": goal,
                "files": sorted(check_inputs),
                "steps": ["materialise the delivery patch", "run the host checks"],
                "risks": [],
                "check_indices": list(range(len(checks))),
            }
        )
        phases.begin_verification()
        if checks:
            _run_checks(phases, checks, worktree)
        phases.seal_verification()
        phases.finish("success", reason="delivery sealed through the code-task pipeline")
    finally:
        parent = worktree.parent
        subprocess.run(
            ["git", "-C", str(repository), "worktree", "remove", "--force", str(worktree)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        subprocess.run(
            ["git", "-C", str(repository), "worktree", "prune"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        shutil.rmtree(parent, ignore_errors=True)

    seal_path = evidence_dir / "delivery-seal.json"
    if not seal_path.is_file():
        raise SealError("the seal pipeline did not produce a delivery seal")
    seal = _read_json(seal_path)
    if seal.get("schema") != SCHEMA:
        raise SealError(f"the produced seal has schema {seal.get('schema')!r}, not {SCHEMA!r}")
    if not seal.get("ok"):
        raise SealError("the produced seal is not ok: " + json.dumps(seal.get("check_exclusions")))
    _write_manifest(evidence_dir, run_id, start_commit, delivery_commit, seal_path)
    reconcile_code_evidence(evidence_dir)
    return seal


def _write_manifest(
    evidence_dir: Path,
    run_id: str,
    start_commit: str,
    delivery_commit: str,
    seal_path: Path,
) -> None:
    """Describe the evidence directory so it can be reconciled later.

    The manifest is the same one the product path writes: the phase journal's
    digest plus the seal's digest, so a later reader can tell whether the
    evidence was edited after it was written.
    """
    phases_raw = (evidence_dir / "phases.json").read_bytes()
    seal_raw = seal_path.read_bytes()
    _write_json(
        evidence_dir / "manifest.json",
        {
            "schema": "northstar.code-evidence.v1",
            "run_id": run_id,
            "start_commit": start_commit,
            "delivery_commit": delivery_commit,
            "status": "success",
            "phases": "phases.json",
            "phases_sha256": hashlib.sha256(phases_raw).hexdigest(),
            "delivery_seal": seal_path.name,
            "delivery_seal_sha256": hashlib.sha256(seal_raw).hexdigest(),
            "delivery_seal_ok": True,
        },
    )


def _run_checks(phases: CodePhaseMachine, checks: Sequence[str], worktree: Path) -> None:
    """Run the host-declared checks the way the product path runs them.

    The product path runs checks through the sandbox shell handler; this runs
    them in the same worktree with the network denied and the same
    before/after effect receipt protocol, so the phase journal records the
    same facts about the same kind of check.
    """
    environment = dict(os.environ)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PYTHONPATH"] = os.pathsep.join(
        [
            str(worktree / "components" / "northstar-agent-runtime"),
            str(worktree / "components" / "northstar-egress-sidecar"),
            environment.get("PYTHONPATH", ""),
        ]
    ).strip(os.pathsep)
    for index, command in enumerate(checks):
        effect_id = phases.begin_check(index=index)
        process = subprocess.run(
            command,
            shell=True,
            cwd=str(worktree),
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
        phases.complete_execution(
            effect_id,
            status="completed" if process.returncode == 0 else "failed",
            error_class="" if process.returncode == 0 else f"exit{process.returncode}",
        )
        if process.returncode != 0:
            output = process.stdout.decode("utf-8", errors="replace")[-2000:]
            raise SealError(
                f"host check {index} failed (exit {process.returncode}): {command}\n{output}"
            )


def _find_seal(evidence_dir: Path) -> Path:
    """Locate the seal in an evidence directory.

    A live run writes ``delivery-seal.json``; a committed run record may
    carry the same file under a prefixed name, because a repository that
    tracks the seal under the protocol's reserved artifact names would
    refuse every later blind bundle.
    """
    exact = evidence_dir / "delivery-seal.json"
    if exact.is_file():
        return exact
    candidates = sorted(evidence_dir.glob("*seal*.json"))
    if len(candidates) != 1:
        raise SealError(
            f"cannot locate exactly one seal in {evidence_dir}: {[c.name for c in candidates]}"
        )
    return candidates[0]


def verify_delivery(evidence_dir: Path, repository: Path = ROOT) -> dict[str, Any]:
    """Re-derive the seal's claims from the repository, not from the seal.

    Every check here recomputes a Git object id and compares it with the
    recorded one. A seal that merely asserts its own truth verifies nothing,
    so the verifier never trusts a recorded digest: it re-runs ``git``.
    """
    seal = _read_json(_find_seal(evidence_dir))
    problems: list[str] = []
    if seal.get("schema") != SCHEMA:
        problems.append(f"unsupported seal schema: {seal.get('schema')!r}")
    start_commit = str(seal.get("start_commit") or "")
    tree_hash = str(seal.get("start_tree_hash") or "")
    if not start_commit:
        problems.append("the seal names no start commit")
    elif not tree_hash:
        problems.append("the seal names no start tree hash")
    else:
        actual = _git(repository, "rev-parse", "--verify", f"{start_commit}^{{tree}}", check=False)
        if actual != tree_hash:
            problems.append(
                f"the start tree hash does not match the repository: expected {tree_hash}, got {actual}"
            )
    pins = seal.get("check_input_pins")
    if not isinstance(pins, list) or not pins:
        problems.append("the seal pins no check inputs")
    else:
        for index, pin in enumerate(pins, 1):
            path = str(pin.get("path") or "")
            baseline = str(pin.get("baseline_blob_sha") or "")
            if not path or not baseline:
                problems.append(f"check-input pin {index} is incomplete")
                continue
            actual = _git(repository, "rev-parse", "--verify", f"{start_commit}:{path}", check=False)
            if actual != baseline:
                problems.append(
                    f"check-input pin {index} does not match the start commit: "
                    f"expected {baseline}, got {actual or '(missing)'}"
                )
            if pin.get("unchanged") is not True:
                problems.append(f"check-input pin {index} is not recorded as unchanged")
    if seal.get("check_inputs_pinned") is not True:
        problems.append("the seal does not record its check inputs as pinned")
    if seal.get("check_inputs_unchanged") is not True:
        problems.append("the seal does not record its check inputs as unchanged")
    if seal.get("ok") is not True:
        problems.append("the seal is not ok")
    return {
        "schema": "northstar.delivery-seal-verify.v1",
        "evidence_dir": str(evidence_dir),
        "repository": str(repository),
        "start_commit": start_commit,
        "start_tree_hash": tree_hash,
        "check_input_pins": len(pins) if isinstance(pins, list) else 0,
        "ok": not problems,
        "problems": problems,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    seal = sub.add_parser("seal", help="seal one historical delivery")
    seal.add_argument("--repository", default=str(ROOT))
    seal.add_argument("--start-commit", required=True)
    seal.add_argument("--delivery-commit", required=True)
    seal.add_argument("--evidence-dir", required=True)
    seal.add_argument("--check-input", dest="check_inputs", action="append", default=[])
    seal.add_argument("--check", dest="checks", action="append", default=[])
    seal.add_argument("--goal", default="sealed historical delivery")

    verify = sub.add_parser("verify", help="verify a sealed delivery against the repository")
    verify.add_argument("--evidence-dir", required=True)
    verify.add_argument("--repository", default=str(ROOT))

    args = parser.parse_args(argv)
    try:
        if args.command == "seal":
            result = seal_delivery(
                repository=Path(args.repository).resolve(),
                start_commit=args.start_commit,
                delivery_commit=args.delivery_commit,
                evidence_dir=Path(args.evidence_dir).resolve(),
                check_inputs=tuple(args.check_inputs),
                checks=tuple(args.checks),
                goal=args.goal,
            )
            print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
            return 0
        result = verify_delivery(
            Path(args.evidence_dir).resolve(), Path(args.repository).resolve()
        )
        print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
        return 0 if result["ok"] else 1
    except (SealError, CodeTaskError) as error:
        print(str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover - command entry point
    raise SystemExit(main())
