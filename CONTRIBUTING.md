# Contributing to Northstar Agent OS

Northstar is built around evidence, explicit security boundaries, and reproducible verification.

## Before opening a change

1. Explain the threat model and the operational boundary.
2. Add or update deterministic tests before implementation changes.
3. Run `make compatibility` before any clean-install or release-readiness claim; it is the dependency-free pre-install gate.
4. Do not include credentials, private prompts, production transcripts, or host-specific secrets.
5. Keep OpenBot compatibility claims precise; compatibility does not imply affiliation.
6. Test process, signal, and systemd behavior on native Linux when relevant.

## Pull requests

A pull request should include:

- the user-visible or operational goal;
- files changed and why;
- test commands and complete results;
- known environment limitations;
- rollback or migration notes for service changes.

Claims of completion should be supported by fresh command output. Static inspection alone is not evidence of runtime correctness.

## Releasing

All six components are unreleased (`0.1.0.dev0`) and each carries its version in
`pyproject.toml` (`components/*/pyproject.toml`); the agent runtime mirrors it in
`_version.py` and the test suite asserts the two match.

To publish a component version `X.Y.Z`:

1. Confirm `make test` is green from a clean checkout (all component suites run
   offline and without `PYTHONPATH`).
2. Decide the release order by the dependency graph:
   `northstar-run-contract` → `northstar-host` → `northstar-durable-run` and
   `northstar-agent-interop` → `northstar-agent-runtime`. A component must be on
   an index before any package that declares it as a dependency.
3. Bump the version in that component's `pyproject.toml` (and `_version.py` for
   the runtime), note the change under the matching heading in `CHANGELOG.md`,
   and add a short "Install (pip)" verification: build the wheel, install it in
   a clean virtualenv from an empty directory, and run the documented import or
   console-script command.
4. Tag the repository `vX.Y.Z` at the merge commit and open a GitHub Release
   from the tag with the changelog entry. Releases are immutable: if a wheel is
   broken, release `X.Y.Z+1`, never rewrite `X.Y.Z`.

Contractual components (run-contract, host, interop, durable-run) prefer
semantic-version majors for breaking schema or trust-boundary changes, because
bindings and receipts outlive the processes that signed them.
