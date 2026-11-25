"""Normalise a baseline receipt into a record that may live in the repository.

The receipt produced by ``run-code-task-baseline.py`` is a working artifact:
it points at temporary directories and at the provider endpoint that was
used.  A record that ships with the pack must be reproducible, so this
script keeps the fingerprints and the outcome of every task and drops
everything that only describes one local run.
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

_REDACTED_PATH_PREFIX = "/_redacted-path-sha256/"
_REDACTED_PATH = re.compile(r"/_redacted-path-sha256/[0-9a-f]{64}\Z")


def _record_base_url(base_url: str) -> str:
    """Sanitize old and new receipts before their endpoint enters an archive."""
    if not base_url or base_url == "(provider default)":
        return base_url or "(provider default)"
    if base_url == "(custom endpoint; URL details redacted)":
        return base_url
    try:
        parts = urlsplit(base_url)
    except ValueError:
        return "(custom endpoint; URL details redacted)"
    netloc = parts.netloc.rsplit("@", 1)[-1]
    if _REDACTED_PATH.fullmatch(parts.path):
        path = parts.path
    elif parts.path:
        digest = hashlib.sha256(parts.path.encode("utf-8")).hexdigest()
        path = f"{_REDACTED_PATH_PREFIX}{digest}"
    else:
        path = ""
    return urlunsplit((parts.scheme, netloc, path, "", ""))


def _endpoint_note(base_url: str) -> str:
    """Say plainly where the model ran.

    A third-party relay is not the vendor's own endpoint, and a reader who
    assumes it is would draw the wrong conclusion about the measurement.
    """
    if not base_url or "(provider default)" in base_url:
        return "provider default endpoint"
    # Parse the hostname so userinfo, ports, paths, and suffix-lookalike
    # domains cannot turn an unrelated endpoint into a vendor endpoint.
    candidate = base_url if "://" in base_url else f"//{base_url}"
    try:
        host = (urlsplit(candidate).hostname or "").rstrip(".").lower()
    except ValueError:
        host = ""
    if host == "openai.com" or host.endswith(".openai.com"):
        return "OpenAI official endpoint"
    if host == "anthropic.com" or host.endswith(".anthropic.com"):
        return "Anthropic official endpoint"
    return f"third-party relay ({host or base_url}); not a vendor endpoint"


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
            "base_url": _record_base_url(conditions["base_url"]),
            "endpoint_note": _endpoint_note(_record_base_url(conditions["base_url"])),
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
