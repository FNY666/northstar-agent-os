"""Normalise a baseline receipt into a record that may live in the repository.

The receipt produced by ``run-code-task-baseline.py`` is a working artifact:
it points at temporary directories and at the provider endpoint that was
used.  A record that ships with the pack must be reproducible, so this
script keeps the fingerprints and the outcome of every task and drops
everything that only describes one local run.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path


def _endpoint_note(base_url: str) -> str:
    """Say plainly where the model ran.

    A third-party relay is not the vendor's own endpoint, and a reader who
    assumes it is would draw the wrong conclusion about the measurement.
    """
    if not base_url or "(provider default)" in base_url:
        return "provider default endpoint"
    host = base_url.split("//", 1)[-1].split("/", 1)[0]
    if host.endswith("openai.com"):
        return "OpenAI official endpoint"
    if host.endswith("anthropic.com"):
        return "Anthropic official endpoint"
    return f"third-party relay ({host}); not a vendor endpoint"


def build_record(receipt: dict) -> dict:
    conditions = receipt["conditions"]
    summary = receipt["summary"]
    return {
        "schema": "northstar.code-task-measurement.v1",
        "pack_id": conditions["pack"]["pack_id"],
        "pack_manifest_sha256": conditions["pack"]["manifest_sha256"],
        "measurement": receipt["measurement"],
        "real_model_evaluated": receipt["real_model_evaluated"],
        "release_eligible": receipt["release_eligible"],
        "release_gate": receipt["release_gate"],
        "summary": summary,
        "model": {
            "provider": conditions["provider"],
            "model": conditions["model"],
            "base_url": conditions["base_url"],
            "endpoint_note": _endpoint_note(conditions["base_url"]),
        },
        "limits": conditions["limits"],
        "sandbox": conditions["sandbox"],
        "toolchain": conditions.get("toolchain", {}),
        "tasks": [
            {
                "task_id": row["task_id"],
                "outcome": row["outcome"],
                "evaluation_ok": row["evaluation_ok"],
                "patch_sha256": row["patch_sha256"],
                "patch_bytes": row["patch_bytes"],
                "elapsed_seconds": row["elapsed_seconds"],
            }
            for row in receipt["tasks"]
        ],
    }


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print("usage: record_measurement.py <receipt.json> <record.json>", file=sys.stderr)
        return 2
    receipt = json.loads(Path(argv[1]).read_text(encoding="utf-8"))
    record = build_record(receipt)
    Path(argv[2]).write_text(
        json.dumps(record, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(f"wrote {argv[2]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
