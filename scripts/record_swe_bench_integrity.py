"""Write an integrity check result into the benchmark record.

The check is a measurement of the sample, so it is stored the same way a
score is: with the sample it was run on, the conditions, and the verdict
per instance. A task that fails the check is named rather than dropped, so
the sample that the score was computed on can be reconstructed.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def build_record(
    payload: dict[str, Any],
    sample_path: str,
    sample_sha256: str,
    conditions: dict[str, Any] | None = None,
    run_at: str | None = None,
) -> dict[str, Any]:
    """Build the stored form of one integrity check.

    The conditions are taken from the caller when it has them, and otherwise
    from the check itself. A record that ends up without them is a record of
    a result whose origin is unknown, so the check's own conditions are
    never dropped silently.
    """
    if conditions is None:
        conditions = payload.get("conditions", {}) or {}
    return {
        "schema": "northstar.swe-bench.integrity.v1",
        "sample": sample_path,
        "sample_sha256": sample_sha256,
        "run_at": run_at or datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "conditions": conditions or {},
        "summary": payload.get("summary", {}),
        "instances": payload.get("instances", []),
    }


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", required=True, help="the integrity check output")
    parser.add_argument("--sample", required=True, help="the frozen sample the check ran on")
    parser.add_argument("--output", required=True, help="where to write the record")
    parser.add_argument(
        "--conditions",
        default="",
        help="a JSON file with the conditions the check ran under; when absent, "
             "the conditions recorded in the check output are used",
    )
    arguments = parser.parse_args()

    payload = json.loads(Path(arguments.check).read_text(encoding="utf-8"))
    sample_path = Path(arguments.sample)
    sample_sha256 = ""
    if sample_path.exists():
        import hashlib

        sample_sha256 = hashlib.sha256(sample_path.read_bytes()).hexdigest()

    conditions = payload.get("conditions", {}) or {}
    if arguments.conditions:
        conditions = json.loads(Path(arguments.conditions).read_text(encoding="utf-8"))

    record = build_record(payload, str(sample_path), sample_sha256, conditions=conditions)
    Path(arguments.output).write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(record["summary"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
