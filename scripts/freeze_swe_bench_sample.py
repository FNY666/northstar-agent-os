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
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlencode

HF_DATASET = "https://huggingface.co/datasets/princeton-nlp/SWE-bench_Verified/resolve/main/data/test-00000-of-00001.parquet"
IMAGE_PREFIX = "swebench/sweb.eval.x86_64"
# The upstream images are published under a fixed build number; it is not
# derived from the instance and every image in a release carries the same.
IMAGE_BUILD = "1776"
SAFE_IMAGE_COMPONENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*")
IMAGE_NAME = re.compile(
    rf"^{re.escape(IMAGE_PREFIX)}\."
    rf"[A-Za-z0-9][A-Za-z0-9_.-]*_{IMAGE_BUILD}_"
    r"[A-Za-z0-9][A-Za-z0-9_.-]*:latest$"
)


def _read_parquet(path: Path) -> list[dict[str, Any]]:
    """Read the frozen dataset into plain dicts.

    pyarrow is only needed here, at freeze time; the runtime never reads
    parquet.
    """
    import pyarrow.parquet as pq

    table = pq.read_table(path).to_pydict()
    columns = list(table)
    rows: list[dict[str, Any]] = []
    for index in range(len(table[columns[0]])):
        record = {name: table[name][index] for name in columns}
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
                # The integrity check runs the reference patch and the empty
                # patch through the same grader; without its fingerprint the
                # check could not prove which patch it graded.
                "gold_patch_sha256": _sha256_text(record.get("patch") or ""),
                # The upstream harness needs these to build a test spec and
                # to grade the run; the sample carries them so that the
                # evaluation needs nothing but the frozen file.
                "image": record.get("image"),
                "eval_type": record.get("eval_type"),
                "log_parser": record.get("log_parser"),
                "eval_script": record.get("eval_script"),
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
    # instance itself keeps only its "<repo>-<number>" half. Restrict both
    # parts to one safe path/tag alphabet before they reach registry URLs.
    if not isinstance(instance_id, str):
        raise ValueError("instance_id must be a safe '<org>__<repo-instance>' identifier")
    org, separator, short_id = instance_id.partition("__")
    if (
        not separator
        or not SAFE_IMAGE_COMPONENT.fullmatch(org)
        or not SAFE_IMAGE_COMPONENT.fullmatch(short_id)
    ):
        raise ValueError("instance_id must be a safe '<org>__<repo-instance>' identifier")
    return f"{IMAGE_PREFIX}.{org}_{IMAGE_BUILD}_{short_id}:latest"


def image_digest(name: str) -> str | None:
    """Resolve an image to its manifest digest without pulling the layers.

    The registry is asked directly: the docker CLI serialises on its
    credential store, and fifty sequential lookups take minutes.
    """
    if not isinstance(name, str) or not IMAGE_NAME.fullmatch(name):
        return None
    repository, _, tag = name.partition(":")
    tag = tag or "latest"
    registry = "registry-1.docker.io"
    token = _registry_token(repository)
    if token is None:
        return None
    request = urllib.request.Request(
        f"https://{registry}/v2/{quote(repository, safe='/')}/manifests/{quote(tag, safe='')}",
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


def _registry_token(repository: str) -> str | None:
    """Get an anonymous pull token for a public repository."""
    query = urlencode(
        {
            "service": "registry.docker.io",
            "scope": f"repository:{repository}:pull",
        },
        safe="/:",
    )
    url = f"https://auth.docker.io/token?{query}"
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
                "fail_to_pass": row["fail_to_pass"],
                "pass_to_pass": row["pass_to_pass"],
                "fail_to_pass_sha256": _sha256_text("\n".join(row["fail_to_pass"])),
                "pass_to_pass_sha256": _sha256_text("\n".join(row["pass_to_pass"])),
                "problem_statement_sha256": row["problem_statement_sha256"],
                "gold_patch_sha256": row.get("gold_patch_sha256")
                or _sha256_text(""),
                "environment_image": name,
                "environment_digest": digest,
                "image": row.get("image") or name,
                "eval_type": row.get("eval_type"),
                "log_parser": row.get("log_parser"),
                "eval_script": row.get("eval_script"),
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
