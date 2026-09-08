"""``cli skills check`` - the operator-facing half of :mod:`skill_audit`.

Three modes, one exit-code contract:

* review what is in the workspace (or any checkout, including a foreign
  ``.claude/skills`` or ``.agents/skills`` tree, so a bundle can be vetted *before*
  it is adopted);
* ``--write-lock`` records the reviewed content addresses, which turns "I looked at
  it" into something a machine can check later;
* ``--lock`` compares against that record and reports drift.

``--fail-on`` decides the gate: ``error`` (the default) fails only on the rules whose
meaning is "this file is an execution or escalation channel", ``warn`` fails on
anything a human should read first, ``info`` additionally fails on advice, and
``never`` reports without a gate. Exit codes: ``0`` clean, ``1`` at or above the
threshold, ``64`` usage or configuration error.

Nothing here reads anything outside the directories named on the command line, and
nothing is executed: reviewing a skill must not require running it.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any, Sequence

import skill_audit
from skill_audit import SEVERITY_ORDER, SkillAuditError, SkillAudit

USAGE_ERROR = 64
_CHECK_ICON = {"error": "✗", "warn": "!", "info": "·", "clean": "✓"}


def add_skills_arguments(parser: argparse.ArgumentParser) -> None:
    sub = parser.add_subparsers(dest="skills_command", metavar="ACTION")
    check = sub.add_parser("check", help="audit SKILL.md files and compare against the reviewed lockfile")
    check.add_argument("--workspace", default=".", help="project whose .northstar/skills to audit (default: current directory)")
    check.add_argument(
        "--root",
        action="append",
        default=[],
        metavar="DIR",
        help="extra checkout to audit (its .northstar/.claude/.agents skills trees); repeatable",
    )
    check.add_argument("--only", action="append", default=[], metavar="NAME", help="audit only these skill names; repeatable")
    check.add_argument("--json", action="store_true", help="emit one JSON object instead of the report")
    check.add_argument(
        "--fail-on",
        choices=("error", "warn", "info", "never"),
        default="error",
        help="severity that fails the check (default: error)",
    )
    check.add_argument("--lock", default="", metavar="PATH", help="lockfile to compare against (default: <workspace>/.northstar/skills.lock)")
    check.add_argument("--no-lock", action="store_true", help="skip the lockfile comparison entirely")
    check.add_argument(
        "--write-lock",
        action="store_true",
        help="write the audited digests to the lockfile path after reviewing (the review, made durable)",
    )
    check.set_defaults(handler=run_skills_command)


def _audits(args: argparse.Namespace) -> tuple[list[SkillAudit], Path]:
    workspace = Path(args.workspace or ".").resolve()
    audits: list[SkillAudit] = []
    for root in [workspace, *[Path(item).resolve() for item in args.root or ()]]:
        audits.extend(skill_audit.audit_tree(root))
    if args.only:
        wanted = {str(name).strip() for name in args.only}
        # Match either the frontmatter name or the folder name: before a skill is
        # adopted, the folder is often the only identifier that exists.
        audits = [
            audit
            for audit in audits
            if audit.name in wanted or Path(audit.relative_path).parent.name in wanted
        ]
    # --root may overlap --workspace; the same file must be reported once, and the
    # content address plus its position is what makes two entries "the same file".
    deduped: dict[tuple[str, str], SkillAudit] = {(audit.digest, audit.relative_path): audit for audit in audits}
    return list(deduped.values()), workspace


def run_skills_command(args: argparse.Namespace) -> int:
    audits, workspace = _audits(args)
    lock_path = Path(args.lock) if args.lock else skill_audit.lock_path_for(workspace)
    status: skill_audit.LockStatus | None = None
    if not args.no_lock and lock_path.is_file():
        try:
            status = skill_audit.check_lock(audits, skill_audit.load_lock(lock_path))
        except SkillAuditError as error:
            print(f"configuration error: {error}", file=sys.stderr)
            return USAGE_ERROR
    elif args.lock:
        # An explicitly named lockfile that is absent is a mistake, not a pass.
        print(f"configuration error: no lockfile at {lock_path}", file=sys.stderr)
        return USAGE_ERROR

    summary = skill_audit.summarise(audits)
    # --write-lock is the act of reviewing: the drift half of the gate is meaningless
    # while the record is being created, so only the finding threshold applies.
    drift = bool(status and not status.clean) and not args.write_lock
    failed = skill_audit.threshold_met(audits, args.fail_on) or drift
    payload: dict[str, Any] = {
        "type": "skills-check",
        "rules": skill_audit.RULES_VERSION,
        "lock": str(lock_path) if lock_path.is_file() else "",
        "summary": summary,
        "drift": status.as_dict() if status else None,
        "fail_on": args.fail_on,
        "ok": not failed,
        "skills": [audit.as_dict() for audit in audits],
    }

    if args.write_lock:
        try:
            skill_audit.write_lock(lock_path, audits, source=str(workspace))
        except OSError as error:
            print(f"configuration error: cannot write {lock_path}: {error}", file=sys.stderr)
            return USAGE_ERROR
        payload["lock_written"] = str(lock_path)

    if args.json:
        import json

        print(json.dumps(payload, sort_keys=True))
    else:
        _report(audits, summary, status, lock_path, fail_on=args.fail_on)
        if args.write_lock:
            print(f"lockfile written: {lock_path} ({len(audits)} skill(s) pinned)")
    return 1 if failed else 0


def _report(audits: Sequence[SkillAudit], summary: dict[str, Any], status: Any, lock_path: Path, *, fail_on: str) -> None:
    print(f"skills check - rules {skill_audit.RULES_VERSION}")
    if not audits:
        print("  no SKILL.md found in the audited trees (nothing to review - this is not a pass)")
    for audit in audits:
        head = f"{audit.name}"
        if audit.findings:
            counts = {severity: 0 for severity in SEVERITY_ORDER}
            for finding in audit.findings:
                counts[finding.severity] += 1
            head += (
                f"  ({counts['error']} error, {counts['warn']} warn, {counts['info']} info)"
                if any(counts.values())
                else ""
            )
        else:
            head += "  (no findings)"
        print(f"{_CHECK_ICON.get(audit.worst, '?')} {head}")
        print(f"    {audit.relative_path}  digest {audit.digest[:12]}  {audit.size_bytes}B  body {audit.body_lines} lines")
        for finding in audit.findings:
            marker = _CHECK_ICON.get(finding.severity, "?")
            print(f"    {marker} {finding.rule} (line {finding.line}): {finding.detail}")
            if finding.excerpt:
                print(f"        > {finding.excerpt}")
    if status is not None:
        icon = "✓" if status.clean else "!"
        print(f"{icon} lockfile {lock_path.name}: {status.summary()}")
    else:
        print("· no lockfile: run `skills check --write-lock` after reviewing, then `run --require-skill-lock`")
    print(
        f"summary: {summary['skills']} skill(s), {summary['flagged']} flagged "
        f"({summary['findings']['error']} error, {summary['findings']['warn']} warn, {summary['findings']['info']} info)"
    )
    if fail_on != "never":
        print(f"failing on: {fail_on} and above")


def run_lock_status(workspace: str | Path) -> tuple[bool, str]:
    """The one-liner ``run --require-skill-lock`` and ``doctor`` share.

    Returns ``(ok, detail)``. ``ok`` is False only for a real problem - a missing
    lockfile, a changed digest, an unreviewed skill - never for an unreadable rule.
    """
    root = Path(workspace)
    audits = list(skill_audit.audit_tree(root))
    lock_path = skill_audit.lock_path_for(root)
    if not audits:
        return True, "no skills to review"
    if not lock_path.is_file():
        return False, f"{len(audits)} skill(s) installed with no lockfile at {skill_audit.LOCK_FILE_NAME}: never reviewed"
    try:
        status = skill_audit.check_lock(audits, skill_audit.load_lock(lock_path))
    except SkillAuditError as error:
        return False, str(error)
    return status.clean, status.summary()


__all__ = ["add_skills_arguments", "run_skills_command", "run_lock_status"]
