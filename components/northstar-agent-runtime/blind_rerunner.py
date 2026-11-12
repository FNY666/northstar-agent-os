"""Blind re-runner bundle and check-set comparison helpers.

The blind input is intentionally small: a Git repository snapshot reference
and one delivery claim.  It is not an evidence bundle.  In particular, this
module refuses evidence-like attachments and evidence artifacts tracked at
the requested start commit before issuing a bundle.

Blind and auditor checks are compared as sets of (command, assertion).  A
description is the assertion in plain language; command tokenization and
description whitespace/case normalization are documented in
``docs/design/blind-rerunner-protocol.md``.  No comparison result is a
pass/fail verdict.
"""

from __future__ import annotations

import argparse
import json
import re
import shlex
import subprocess
import sys
import unicodedata
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


class BlindRerunnerError(ValueError):
    """Malformed input or a fail-closed bundle/evidence error."""


class AuditorChecksUnavailable(BlindRerunnerError):
    """A delivery seal does not contain a usable pinned check-input set."""


@dataclass(frozen=True)
class BlindCheck:
    """One named, runnable check and the assertion it makes."""

    id: str
    description: str
    command: str

    def __post_init__(self) -> None:
        for name, value in (("id", self.id), ("description", self.description), ("command", self.command)):
            if not isinstance(value, str) or not value.strip() or "\n" in value or "\r" in value:
                raise BlindRerunnerError(f"{name} must be a non-empty single-line string")
        try:
            tokens = shlex.split(self.command, posix=True)
        except ValueError as error:
            raise BlindRerunnerError("command must be a valid shell command") from error
        if not tokens:
            raise BlindRerunnerError("command must be runnable")

    def as_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass(frozen=True)
class BlindBundle:
    """A minimal repository reference plus the caller's one-sentence claim."""

    start_commit: str
    claim: str
    repo_path: str

    def as_dict(self) -> dict[str, str]:
        return {
            "schema": "northstar.blind-rerunner-bundle.v1",
            "start_commit": self.start_commit,
            "claim": self.claim,
            "repo_path": self.repo_path,
        }


@dataclass(frozen=True)
class DivergenceReport:
    """Structured comparison; ``None`` auditor availability is not an empty set."""

    blind_only: tuple[BlindCheck, ...]
    auditor_only: tuple[BlindCheck, ...]
    both: tuple[dict[str, BlindCheck], ...]
    auditor_available: bool = True
    unassessed_blind: tuple[BlindCheck, ...] = ()
    findings: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": "northstar.blind-rerunner-divergence.v1",
            "judgment": "operator_review_required",
            "auditor_available": self.auditor_available,
            "blind_only": [check.as_dict() for check in self.blind_only],
            "auditor_only": [check.as_dict() for check in self.auditor_only],
            "both": [
                {"blind": pair["blind"].as_dict(), "auditor": pair["auditor"].as_dict()}
                for pair in self.both
            ],
            "unassessed_blind": [check.as_dict() for check in self.unassessed_blind],
            "findings": list(self.findings),
        }


_COMMIT_RE = re.compile(r"\A[0-9a-fA-F]{40}(?:[0-9a-fA-F]{24})?\Z")
_EVIDENCE_NAMES = {
    "delivery-seal.json",
    "delivery_seal.json",
    "receipt.json",
    "delivery-receipt.json",
    "delivery_receipt.json",
    "patch.diff",
    "delivery.patch",
    "delivery.patch.diff",
    "delivery-summary.md",
    "delivery_summary.md",
    "delivery-summary.txt",
    "delivery_summary.txt",
}
_SUMMARY_MARKERS = (
    "delivery summary:",
    "delivery-summary:",
    "delivery_summary:",
    "<!-- delivery-summary",
    "<!-- delivery_summary",
    '"schema": "northstar.delivery-seal.v',
)
_EVIDENCE_PATH_RE = re.compile(
    r"(?i)(?:^|[\s\"'`])[^\s\"'`]*(?:delivery[-_]?(?:seal|receipt|summary)|"
    r"(?:^|[/._-])(?:seal|receipt|patch)|(?:^|[/._-])delivery-summary)[^\s\"'`]*"
    r"\.(?:json|md|txt|diff|patch)(?:$|[\s\"'`])"
)


def _git(root: Path, *args: str) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), *args],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise BlindRerunnerError(f"cannot verify repository snapshot: {args[0]}") from error
    return result.stdout.strip()


def _reject_evidence_text(value: str, *, label: str) -> None:
    lowered = value.casefold()
    if any(marker in lowered for marker in _SUMMARY_MARKERS) or _EVIDENCE_PATH_RE.search(value):
        raise BlindRerunnerError(f"excluded delivery evidence detected in {label}")


def _is_evidence_path(path: str) -> bool:
    normalized = path.replace("\\", "/").casefold()
    basename = normalized.rsplit("/", 1)[-1]
    if basename in _EVIDENCE_NAMES:
        return True
    # Evidence directories are artifact-only locations; ordinary source files
    # such as sealed_attestation.py and test_attested_receipts.py are allowed.
    if any(part in {"delivery-evidence", "delivery_evidence", "evidence-bundle", "evidence_bundle"}
           for part in normalized.split("/")):
        return True
    return False


def build_blind_bundle(
    start_commit: str,
    claim: str,
    *,
    repo_root: str | Path = ".",
    candidate_material: Mapping[str, str] | None = None,
) -> BlindBundle:
    """Build only ``{repo snapshot reference, claim}``; reject evidence inputs.

    ``candidate_material`` represents any additional material a caller might
    have attempted to attach.  It is never emitted.  Evidence-like paths,
    delivery-summary markers, and *any* otherwise-safe attachment are rejected
    because this protocol permits no third bundle component.
    """
    if not isinstance(start_commit, str) or not _COMMIT_RE.fullmatch(start_commit):
        raise BlindRerunnerError("start_commit must be a full Git object id")
    if not isinstance(claim, str) or not claim.strip() or claim != claim.strip() or "\n" in claim or "\r" in claim:
        raise BlindRerunnerError("claim must be a non-empty, trimmed, single-line sentence")
    if re.search(r"[.!?]\s+\S", claim):
        raise BlindRerunnerError("claim must contain exactly one sentence")

    root = Path(repo_root).resolve()
    resolved = _git(root, "rev-parse", "--verify", f"{start_commit}^{{commit}}")
    if resolved.lower() != start_commit.lower():
        raise BlindRerunnerError("start_commit did not resolve to the exact requested commit")

    paths = _git(root, "ls-tree", "-r", "--name-only", "--full-tree", start_commit).splitlines()
    excluded = [path for path in paths if _is_evidence_path(path)]
    if excluded:
        raise BlindRerunnerError("start commit contains excluded delivery artifacts: " + ", ".join(excluded[:8]))

    if candidate_material:
        for path, content in candidate_material.items():
            if not isinstance(path, str) or not isinstance(content, str):
                raise BlindRerunnerError("candidate material paths and contents must be strings")
            if _is_evidence_path(path):
                raise BlindRerunnerError(f"excluded delivery evidence path in candidate material: {path}")
            _reject_evidence_text(path, label="candidate material path")
            _reject_evidence_text(content, label=f"candidate material {path}")
        raise BlindRerunnerError("additional bundle material is not permitted")

    _reject_evidence_text(claim, label="delivery claim")
    return BlindBundle(start_commit=resolved, claim=claim, repo_path=str(root))


def extract_auditor_checks(delivery: Mapping[str, Any] | str | Path) -> tuple[BlindCheck, ...]:
    """Derive integrity checks from the existing delivery-seal check-input pins.

    This intentionally does not synthesize functional test commands: the
    seal pins input files, not a command manifest.  Each returned command
    recomputes the tracked Git blob id and asserts it equals the recorded
    baseline blob id.  Missing/unpinned/empty or malformed pins are findings
    surfaced as ``AuditorChecksUnavailable``.
    """
    if isinstance(delivery, (str, Path)):
        try:
            raw = json.loads(Path(delivery).read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise AuditorChecksUnavailable("delivery seal could not be loaded") from error
    else:
        raw = delivery
    if not isinstance(raw, Mapping):
        raise AuditorChecksUnavailable("delivery seal must be a mapping")
    if raw.get("schema") != "northstar.delivery-seal.v2":
        raise AuditorChecksUnavailable("delivery seal has no supported check-input pin schema")
    if raw.get("check_inputs_pinned") is not True or raw.get("check_inputs_unchanged") is not True:
        raise AuditorChecksUnavailable("delivery seal does not establish unchanged pinned check inputs")
    start_commit = raw.get("start_commit")
    tree_hash = raw.get("start_tree_hash")
    pins = raw.get("check_input_pins")
    if not isinstance(start_commit, str) or not _COMMIT_RE.fullmatch(start_commit):
        raise AuditorChecksUnavailable("delivery seal has no valid start commit")
    if not isinstance(tree_hash, str) or not re.fullmatch(r"[0-9a-fA-F]{40,64}", tree_hash):
        raise AuditorChecksUnavailable("delivery seal has no usable pinned start-tree hash")
    if not isinstance(pins, list) or not pins:
        raise AuditorChecksUnavailable("delivery seal contains no usable check-input pin list")

    checks: list[BlindCheck] = [
        BlindCheck(
            id="pinned-start-tree",
            description=f"Assert the start commit tree has the pinned Git tree id {tree_hash}.",
            command=(
                f"test \"$(git rev-parse --verify {shlex.quote(start_commit + '^{tree}')})\" "
                f"= {shlex.quote(tree_hash)}"
            ),
        )
    ]
    for index, pin in enumerate(pins, 1):
        if not isinstance(pin, Mapping):
            raise AuditorChecksUnavailable(f"check-input pin {index} is not an object")
        path = pin.get("path")
        blob = pin.get("baseline_blob_sha")
        if (
            not isinstance(path, str)
            or not path
            or "\n" in path
            or "\r" in path
            or Path(path).is_absolute()
            or ".." in Path(path).parts
            or not isinstance(blob, str)
            or not re.fullmatch(r"[0-9a-fA-F]{40,64}", blob)
            or pin.get("unchanged") is not True
        ):
            raise AuditorChecksUnavailable(f"check-input pin {index} is incomplete or changed")
        command = f"test \"$(git hash-object -- {shlex.quote(path)})\" = {shlex.quote(blob)}"
        checks.append(
            BlindCheck(
                id=f"pinned-input-{index}:{path}",
                description=f"Assert {path} has the pinned baseline Git blob {blob}.",
                command=command,
            )
        )
    return tuple(checks)


def _identity(check: BlindCheck) -> tuple[str, str]:
    """Canonicalize quoting/token spacing and the assertion's textual form."""
    try:
        command = shlex.join(shlex.split(check.command, posix=True))
    except ValueError as error:
        raise BlindRerunnerError(f"invalid command for check {check.id!r}") from error
    assertion = " ".join(unicodedata.normalize("NFKC", check.description).casefold().split())
    return command, assertion


def _stable_unique(checks: Iterable[BlindCheck]) -> list[BlindCheck]:
    result: list[BlindCheck] = []
    seen: set[tuple[str, str]] = set()
    for check in checks:
        if not isinstance(check, BlindCheck):
            raise BlindRerunnerError("check sets must contain BlindCheck records")
        identity = _identity(check)
        if identity not in seen:
            result.append(check)
            seen.add(identity)
    return result


def compare_check_sets(
    blind_checks: Sequence[BlindCheck], auditor_checks: Sequence[BlindCheck]
) -> DivergenceReport:
    """Return set divergence; do not turn divergence into an automatic verdict."""
    blind = _stable_unique(blind_checks)
    auditor = _stable_unique(auditor_checks)
    blind_by_id = {_identity(check): check for check in blind}
    auditor_by_id = {_identity(check): check for check in auditor}
    shared = blind_by_id.keys() & auditor_by_id.keys()
    return DivergenceReport(
        blind_only=tuple(check for check in blind if _identity(check) not in auditor_by_id),
        auditor_only=tuple(check for check in auditor if _identity(check) not in blind_by_id),
        both=tuple(
            {"blind": blind_by_id[key], "auditor": auditor_by_id[key]}
            for key in sorted(shared)
        ),
    )


def run_blind_rerun(
    *,
    start_commit: str,
    claim: str,
    repo_root: str | Path,
    blind_checks: Sequence[BlindCheck],
    delivery: Mapping[str, Any] | str | Path | None,
    report_path: str | Path | None = None,
) -> tuple[BlindBundle, DivergenceReport]:
    """Issue the blind bundle, then compare submitted blind checks to seal pins."""
    bundle = build_blind_bundle(start_commit, claim, repo_root=repo_root)
    try:
        if delivery is None:
            raise AuditorChecksUnavailable("delivery seal was not supplied")
        auditor_checks = extract_auditor_checks(delivery)
    except AuditorChecksUnavailable as error:
        report = DivergenceReport(
            blind_only=(),
            auditor_only=(),
            both=(),
            auditor_available=False,
            unassessed_blind=tuple(_stable_unique(blind_checks)),
            findings=(str(error),),
        )
    else:
        report = compare_check_sets(blind_checks, auditor_checks)
    if report_path is not None:
        Path(report_path).write_text(
            json.dumps(report.as_dict(), ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
    return bundle, report


def _load_checks(path: str | Path) -> tuple[BlindCheck, ...]:
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise BlindRerunnerError("blind-check file could not be loaded") from error
    if not isinstance(raw, list):
        raise BlindRerunnerError("blind-check file must contain a JSON array")
    if any(not isinstance(item, dict) for item in raw):
        raise BlindRerunnerError("each blind check must be a JSON object")
    try:
        return tuple(BlindCheck(**item) for item in raw)
    except (TypeError, BlindRerunnerError) as error:
        raise BlindRerunnerError("each blind check needs id, description, and command") from error


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--start-commit", required=True)
    parser.add_argument("--claim", required=True)
    parser.add_argument("--repo", default=".")
    parser.add_argument("--emit-bundle", action="store_true", help="issue only the blind input bundle")
    parser.add_argument("--bundle-out", help="write an emitted bundle to this path")
    parser.add_argument("--blind-checks", help="JSON array completed by the blind re-runner")
    parser.add_argument("--delivery-seal", help="auditor-side delivery-seal.json")
    parser.add_argument("--report", help="write the structured divergence report to this path")
    args = parser.parse_args(argv)
    try:
        if args.emit_bundle:
            bundle = build_blind_bundle(args.start_commit, args.claim, repo_root=args.repo)
            payload = json.dumps(bundle.as_dict(), ensure_ascii=False, sort_keys=True, indent=2) + "\n"
            if args.bundle_out:
                Path(args.bundle_out).write_text(payload, encoding="utf-8")
            print(payload, end="")
            return 0
        if not args.blind_checks:
            parser.error("--blind-checks is required unless --emit-bundle is selected")
        checks = _load_checks(args.blind_checks)
        bundle, report = run_blind_rerun(
            start_commit=args.start_commit,
            claim=args.claim,
            repo_root=args.repo,
            blind_checks=checks,
            delivery=args.delivery_seal,
            report_path=args.report,
        )
    except BlindRerunnerError as error:
        print(str(error), file=sys.stderr)
        return 2
    print(json.dumps({"bundle": bundle.as_dict(), "divergence": report.as_dict()}, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":  # pragma: no cover - command entry point
    raise SystemExit(main())
