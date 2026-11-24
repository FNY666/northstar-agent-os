# Frozen SWE-bench Verified sample

`verified-50.json` is a frozen sample of 50 tasks from
[princeton-nlp/SWE-bench_Verified](https://huggingface.co/datasets/princeton-nlp/SWE-bench_Verified).
It exists so that the blueprint's SWE-bench gate -- "50 Verified tasks,
at least five more resolved than the baseline, taking the lower of two
runs" -- can be measured against a fixed set of tasks rather than a set
that drifts with the dataset.

## What "frozen" means here

Each task records:

* the upstream instance id and the base commit it starts from;
* the fingerprints of the grading test lists (`FAIL_TO_PASS`,
  `PASS_TO_PASS`) and of the problem statement, so a later run can prove
  it graded the same tests without carrying thousands of test ids around;
* the container image that provides the environment, and that image's
  manifest digest.

The digest is the load-bearing part.  The upstream images are published
as `swebench/sweb.eval.x86_64.<org>_<build>_<instance>` and they are
rebuilt over time; without a digest, two runs of the same task could
grade different environments and the comparison would mean nothing.

`verified-50.digests.json` pins the digests on their own.  Changing a
digest is therefore a visible, deliberate act rather than something that
can slip into a manifest unnoticed.

## Selection

Tasks are picked round-robin over repositories, ordered by instance id:
the same dataset always yields the same sample, and no single
repository can dominate the measurement.  The current sample covers
twelve repositories, with at most five tasks from any one of them.

## Regenerating

    python3 scripts/freeze_swe_bench_sample.py \
        --dataset <path to the Verified parquet file> \
        --output benchmarks/swe-bench/verified-50.json \
        --count 50

Regenerating requires network access to the Docker Hub registry to
resolve image digests.  Pass `--no-digest` to freeze the sample without
resolving digests, which is useful offline but leaves the environment
unpinned.

## Running it

The upstream environment images are `linux/amd64` only.  On an arm64
host the images cannot be pulled, so a SWE-bench run needs an amd64
machine; the digest recorded here is what makes that machine's
environment the same one this sample was frozen against.
