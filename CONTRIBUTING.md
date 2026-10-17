# Contributing to Northstar Agent OS

Northstar is built around evidence, explicit security boundaries, and reproducible verification.

## Before opening a change

1. Explain the threat model and the operational boundary.
2. Add or update deterministic tests before implementation changes.
3. Do not include credentials, private prompts, production transcripts, or host-specific secrets.
4. Keep OpenBot compatibility claims precise; compatibility does not imply affiliation.
5. Test process, signal, and systemd behavior on native Linux when relevant.

## Pull requests

A pull request should include:

- the user-visible or operational goal;
- files changed and why;
- test commands and complete results;
- known environment limitations;
- rollback or migration notes for service changes.

Claims of completion should be supported by fresh command output. Static inspection alone is not evidence of runtime correctness.

## Releasing

Five components have `pyproject.toml` and share `0.1.0.dev0`; the runtime's
`_version.py` must match. The sixth component, Codex Sidecar, is installed with
shell/systemd scripts and is not a pip package. See [current status](docs/current-status.md).

Development checks do not publish anything:

```sh
make test
make release-check
make install-smoke
python3 tests/docbuild.py verify
```

Only when a release is separately authorized, follow the
[release guide](docs/guides/releasing-and-versioning.md). All five package versions
and the runtime version change together. Install dependencies from local paths
or the same wheel set; publishing them to an index is not required for local use.
The tag-triggered workflow creates a GitHub Release, so pushing a tag is a
publishing action. Do not treat building wheels as permission to publish them.

## Documentation changes

Update the root README, affected component/guide pages and language entries when
behavior changes. Record verification in [current status](docs/current-status.md),
including skipped tests and environment limitations. Keep historical reports dated;
do not replace their original test counts with today's counts. Generated API pages
come from `python3 tests/docbuild.py build`; verify their freshness afterwards.

Contractual components (run-contract, host, interop, durable-run) prefer
semantic-version majors for breaking schema or trust-boundary changes, because
bindings and receipts outlive the processes that signed them.
