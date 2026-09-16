"""Summarise stored reports into a difference distribution.

This tool answers one question for the shadow program: across every run we have
recorded, where do the production gate and the layered contract disagree? It
deliberately does not answer the question that matters next — whether to let the
layered result influence production — because that decision needs a sample size
this tool cannot manufacture.

Two rules keep it honest:

* a missing verdict is reported as ``unknown``; it is never filled in with the
  value that would look consistent with its neighbours;
* the summary carries the sample count and states that it is not a decision, so
  a small corpus cannot be read as a result.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SCHEMA = "northstar.advisory-distribution.v1"

# Reasons a scanned file was left out that a reader can act on. Noise-level reasons
# (a checkpoint or evidence file that was never a report) are counted, not listed.
ACTIONABLE_SKIP_REASONS = frozenset({"unreadable", "no_comparable_verdicts"})
UNKNOWN = "unknown"

SHADOW_SOURCE = "harness-shadow"
PRODUCTION_SOURCE = "production-run"


@dataclass(frozen=True)
class Sample:
    """One observed run, reduced to the verdicts that can be compared."""

    source: str
    label: str
    production: str
    contract: str
    layered: str

    def as_dict(self) -> dict[str, str]:
        return {
            "source": self.source,
            "label": self.label,
            "production": self.production,
            "contract": self.contract,
            "layered": self.layered,
        }


def _verdict(value: Any) -> str:
    """Read a verdict without inventing one."""
    if not isinstance(value, str) or not value.strip():
        return UNKNOWN
    return value.strip()


def sample_from_shadow(report: dict[str, Any], label: str) -> Sample:
    """Normalise the shadow harness report (production/contract/layered)."""
    def nested(key: str) -> str:
        block = report.get(key)
        if not isinstance(block, dict):
            return UNKNOWN
        return _verdict(block.get("verdict"))

    return Sample(SHADOW_SOURCE, label, nested("production"), nested("contract"), nested("layered"))


def sample_from_production(report: dict[str, Any], label: str) -> Sample | None:
    """Normalise a production run report, or None when it carries no advisory."""
    advisory = report.get("shadow_advisory")
    if not isinstance(advisory, dict):
        return None
    if not advisory.get("available"):
        # The advisory recorded a reason instead of an opinion. Keeping the
        # sample would let an unavailable advisory masquerade as a verdict.
        return None
    production = _verdict(advisory.get("production_verdict"))
    if production == UNKNOWN:
        # Fall back to the gate's own boolean without overstating a failure.
        confirmed = report.get("ok")
        production = "verified" if confirmed is True else "not-verified"
    return Sample(
        PRODUCTION_SOURCE,
        label,
        production,
        _verdict(advisory.get("contract_verdict")),
        _verdict(advisory.get("layered_verdict")),
    )


def load_samples(paths: list[Path]) -> tuple[list[Sample], list[str]]:
    """Load every readable report; return the samples and the skipped paths."""
    samples: list[Sample] = []
    skipped: list[str] = []
    for path in paths:
        try:
            report = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            skipped.append(f"{path}: unreadable")
            continue
        # Label with the containing directory too: report files share a name, and a
        # label that does not identify the sample cannot be acted on.
        label = f"{path.parent.name}/{path.name}"
        if "shadow_advisory" in report:
            sample = sample_from_production(report, label)
        elif "layered" in report:
            sample = sample_from_shadow(report, label)
        elif "ok" in report:
            # A real production run that simply did not enable the advisory.
            skipped.append(f"{path}: advisory_not_enabled")
            continue
        else:
            skipped.append(f"{path}: not_a_report")
            continue
        if sample is None:
            skipped.append(f"{path}: no_comparable_verdicts")
        else:
            samples.append(sample)
    return samples, skipped


def summarize(samples: list[Sample], skipped: list[str] | None = None) -> dict[str, Any]:
    """Count the observed combinations and name the disagreements."""
    distribution: dict[tuple[str, str, str], int] = {}
    by_source: dict[str, int] = {}
    for sample in samples:
        key = (sample.production, sample.contract, sample.layered)
        distribution[key] = distribution.get(key, 0) + 1
        by_source[sample.source] = by_source.get(sample.source, 0) + 1

    rows = [
        {
            "production": key[0],
            "contract": key[1],
            "layered": key[2],
            "count": count,
        }
        for key, count in sorted(distribution.items())
    ]
    # The class that matters: the gate accepted what the contract did not.
    disagreements = [
        sample.as_dict()
        for sample in samples
        if sample.production == "verified" and sample.layered != "verified"
    ]
    skipped_by_reason: dict[str, int] = {}
    skipped_detail: list[str] = []
    for entry in skipped or []:
        path, _, reason = entry.rpartition(": ")
        skipped_by_reason[reason] = skipped_by_reason.get(reason, 0) + 1
        if reason in ACTIONABLE_SKIP_REASONS:
            skipped_detail.append(f"{path}: {reason}")
    return {
        "schema_version": SCHEMA,
        "authoritative": False,
        "is_a_decision": False,
        "sample_count": len(samples),
        "by_source": by_source,
        "distribution": rows,
        "gate_accepted_contract_disagreed": disagreements,
        "skipped_by_reason": skipped_by_reason,
        "skipped_detail": skipped_detail,
        "skipped": list(skipped or []),
        "caveats": [
            "the advisory is non-authoritative and never changes a run's outcome",
            "this count is evidence about the contract, not about task truth",
            f"sample_count={len(samples)}: too small to justify a production change",
        ],
    }


def render_markdown(summary: dict[str, Any]) -> str:
    lines = [
        "| production | contract | layered | count |",
        "| --- | --- | --- | --- |",
    ]
    for row in summary["distribution"]:
        lines.append(
            f"| {row['production']} | {row['contract']} | {row['layered']} | {row['count']} |"
        )
    lines.append("")
    lines.append(f"sample_count: {summary['sample_count']}")
    lines.append(f"is_a_decision: {str(summary['is_a_decision']).lower()}")
    lines.append(f"by_source: {summary['by_source']}")
    for label in summary["gate_accepted_contract_disagreed"]:
        lines.append(
            f"disagreement: {label['source']} {label['label']} "
            f"(contract={label['contract']}, layered={label['layered']})"
        )
    for path in summary["skipped_detail"]:
        lines.append(f"skipped_detail: {path}")
    lines.append(f"skipped_by_reason: {summary['skipped_by_reason']}")
    lines.append("")
    lines.append("caveats:")
    for caveat in summary["caveats"]:
        lines.append(f"- {caveat}")
    return "\n".join(lines)


def collect_paths(roots: list[str]) -> list[Path]:
    paths: list[Path] = []
    for root in roots:
        candidate = Path(root)
        if candidate.is_dir():
            paths.extend(sorted(candidate.rglob("*.json")))
        else:
            paths.append(candidate)
    return paths


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("roots", nargs="+", help="report files or directories to scan")
    parser.add_argument("--format", choices=("json", "markdown"), default="markdown")
    parser.add_argument("--output")
    arguments = parser.parse_args(argv)

    samples, skipped = load_samples(collect_paths(arguments.roots))
    summary = summarize(samples, skipped)
    rendered = (
        json.dumps(summary, indent=2)
        if arguments.format == "json"
        else render_markdown(summary)
    )
    if arguments.output:
        Path(arguments.output).write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
