"""Freeze a reproducible 50-task sample of SWE-bench Verified.

The blueprint asks for a frozen SWE-bench Verified sample with a pinned
runtime environment.  "Frozen" has to mean more than "here is a list of
ids":  the same ids must select the same tasks next time, and the
environment that grades them must be pinned to an exact image digest so a
later run cannot quietly measure a different machine.

This script therefore records, for every selected task, the upstream
instance id, the base commit, the grading test lists, the container image
name, and that image's digest.  Nothing here runs a model.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

HF_DATASET = "https://huggingface.co/datasets/princeton-nlp/SWE-bench_Verified/resolve/main/data/test-00000-of-00001.parquet"
IMAGE_PREFIX = "swebench/sweb.eval.x86_64"
# The upstream images are published under a fixed build number; it is not
# derived from the instance and every image in a release carries the same.
IMAGE_BUILD = "1776"


def _read_parquet(path: Path) -> list[dict[str, Any]]:
    """Read the frozen dataset into plain dicts.

    pandas is only needed here, at freeze time; the runtime never reads
    parquet.
    """
    import pandas as pd

    frame = pd.read_parquet(path)
    rows: list[dict[str, Any]] = []
    for record in frame.to_dict(orient="records"):
        rows.append(
            {
                "repo": record["repo"],
                "instance_id": record["instance_id"],
                "base_commit": record["base_commit"],
                "version": record["version"],
                "difficulty": record.get("difficulty"),
                # The grading lists are long and belong to the frozen dataset,
                # not to the sample manifest: the manifest records their
                # fingerprints so a later run can prove it graded the same
                # tests without carrying thousands of test ids around.
                "fail_to_pass": list(record["FAIL_TO_PASS"] or []),
                "pass_to_pass": list(record["PASS_TO_PASS"] or []),
                "problem_statement_sha256": _sha256_text(record["problem_statement"] or ""),
            }
        )
    return rows


def _sha256_text(text: str) -> str:
    import hashlib

    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def image_name(repo: str, version: Any, instance_id: str) -> str:
    """Build the upstream environment image name for an instance.

    Upstream publishes ``sweb.eval.x86_64.<repo-name>_<build>_<instance>``,
    where the repo name is the last path segment and the build number is
    the same for every image in a release.
    """
    # Upstream names the image after the instance id's organisation
    # segment: "pytest-dev__pytest-10051" becomes "pytest-dev", and the
    # instance itself keeps only its "<repo>-<number>" half.
    org = instance_id.split("__", 1)[0]
    short_id = instance_id.split("__")[-1]
    return f"{IMAGE_PREFIX}.{org}_{IMAGE_BUILD}_{short_id}:latest"


def image_digest(name: str) -> str | None:
    """Resolve an image to its manifest digest without pulling the layers.

    The registry is asked directly: the docker CLI serialises on its
    credential store, and fifty sequential lookups take minutes.
    """
    repository, _, tag = name.partition(":")
    tag = tag or "latest"
    registry = "registry-1.docker.io"
    if "/" not in repository:
        return None
    namespace, _, short = repository.partition("/")
    if namespace != "swebench":
        return None
    token = _registry_token(registry, repository)
    if token is None:
        return None
    request = urllib.request.Request(
        f"https://{registry}/v2/{repository}/manifests/{tag}",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": ", ".join(
                [
                    "application/vnd.oci.image.index.v1+json",
                    "application/vnd.docker.distribution.manifest.list.v2+json",
                    "application/vnd.docker.distribution.manifest.v2+json",
                    "application/vnd.oci.image.manifest.v1+json",
                ]
            ),
        },
    )
    response = None
    for attempt in range(3):
        try:
            response = urllib.request.urlopen(request, timeout=60)
            payload = json.loads(response.read().decode("utf-8"))
            break
        except (urllib.error.URLError, OSError, json.JSONDecodeError, ValueError):
            time.sleep(1.5 * (attempt + 1))
    if response is None:
        return None
    digest = response.headers.get("Docker-Content-Digest")
    if digest:
        return digest
    if isinstance(payload, dict) and payload.get("manifests"):
        for entry in payload["manifests"]:
            if entry.get("platform", {}).get("architecture") == "amd64":
                return entry.get("digest")
    return None


def _registry_token(registry: str, repository: str) -> str | None:
    """Get an anonymous pull token for a public repository."""
    url = (
        "https://auth.docker.io/token?service=registry.docker.io"
        f"&scope=repository:{repository}:pull"
    )
    for attempt in range(3):
        try:
            with urllib.request.urlopen(url, timeout=60) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except (urllib.error.URLError, OSError, json.JSONDecodeError, ValueError):
            time.sleep(1.5 * (attempt + 1))
            continue
        token = payload.get("token") or payload.get("access_token")
        return token if isinstance(token, str) else None
    return None


def select_tasks(rows: list[dict[str, Any]], count: int) -> list[dict[str, Any]]:
    """Pick a deterministic, repo-diverse sample.

    Round-robin over the repos by instance id: the same dataset always
    yields the same sample, and no single repository can dominate the
    measurement.
    """
    by_repo: dict[str, list[dict[str, Any]]] = {}
    for row in sorted(rows, key=lambda item: item["instance_id"]):
        by_repo.setdefault(row["repo"], []).append(row)
    repos = sorted(by_repo)
    selected: list[dict[str, Any]] = []
    position = 0
    while len(selected) < count:
        progressed = False
        for repo in repos:
            candidates = by_repo[repo]
            if position < len(candidates):
                selected.append(candidates[position])
                progressed = True
                if len(selected) == count:
                    break
        if not progressed:
            break
        position += 1
    return selected


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", required=True, help="path to the Verified parquet file")
    parser.add_argument("--output", required=True, help="where to write the frozen sample")
    parser.add_argument("--count", type=int, default=50)
    parser.add_argument(
        "--no-digest",
        action="store_true",
        help="skip image digest resolution (offline use; digests stay null)",
    )
    args = parser.parse_args(argv)

    rows = _read_parquet(Path(args.dataset))
    selected = select_tasks(rows, args.count)
    if len(selected) != args.count:
        print(f"only {len(selected)} tasks available", file=sys.stderr)
        return 1

    names = [image_name(row["repo"], row["version"], row["instance_id"]) for row in selected]
    digests: list[str | None]
    if args.no_digest:
        digests = [None] * len(names)
    else:
        # The registry throttles bursts of anonymous token requests, so the
        # lookups run one at a time.  Fifty of them cost under a minute and
        # the result is complete rather than mostly empty.
        digests = [image_digest(name) for name in names]

    tasks = []
    for row, name, digest in zip(selected, names, digests):
        tasks.append(
            {
                "instance_id": row["instance_id"],
                "repo": row["repo"],
                "version": row["version"],
                "base_commit": row["base_commit"],
                "difficulty": row["difficulty"],
                "fail_to_pass_count": len(row["fail_to_pass"]),
                "fail_to_pass_sha256": _sha256_text("\n".join(row["fail_to_pass"])),
                "pass_to_pass_count": len(row["pass_to_pass"]),
                "pass_to_pass_sha256": _sha256_text("\n".join(row["pass_to_pass"])),
                "problem_statement_sha256": row["problem_statement_sha256"],
                "environment_image": name,
                "environment_digest": digest,
            }
        )

    payload = {
        "schema": "northstar.swe-bench-sample.v1",
        "source": "princeton-nlp/SWE-bench_Verified",
        "source_url": HF_DATASET,
        "selection": "round-robin over repositories, ordered by instance id",
        "task_count": len(tasks),
        "repos": sorted({row["repo"] for row in tasks}),
        "digests_resolved": sum(1 for row in tasks if row["environment_digest"]),
        "tasks": tasks,
    }
    Path(args.output).write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    # A second, deliberately small file pins the digests on their own so a
    # later change to the sample has to be argued for against this lock.
    lock_path = Path(args.output).with_name(Path(args.output).stem + ".digests.json")
    lock_path.write_text(
        json.dumps(
            {
                "schema": "northstar.swe-bench-digest-lock.v1",
                "source_url": HF_DATASET,
                "digests": {
                    row["instance_id"]: row["environment_digest"]
                    for row in tasks
                    if row["environment_digest"]
                },
            },
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"wrote {args.output}: {len(tasks)} tasks, {payload['digests_resolved']} digests")
    print(f"wrote {lock_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
