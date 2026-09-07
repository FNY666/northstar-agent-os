# Guide: releasing and versioning

How a Northstar Agent OS release is cut — and the **readiness gate** that
keeps premature releases from happening. Northstar is released only when it
is ready, never on a schedule: between releases the components carry a
`.devN` version, and a plain version is set *only* when the checklist below
is fully green.

## The version rule

The five pip-installable components (`northstar-run-contract`,
`northstar-host`, `northstar-durable-run`, `northstar-agent-interop`,
`northstar-agent-runtime`) are **released together from one tag and carry one
version**. `tests/test_release.py` enforces it:

- every `components/<name>/pyproject.toml` `project.version` parses as
  `major.minor.patch[.devN]`;
- all five are identical;
- the runtime's `_version.py` `__version__` equals them (it is what the CLI
  prints and what the MCP handshake advertises);
- **between releases the aligned version must be dev-suffixed**
  (`0.1.0.dev0`): the working tree is never mistaken for a shipped release.

The `northstar-codex-sidecar` is not pip-packaged (shell + systemd), so it is
not versioned here; the run-contract's *schema* versions (`northstar.run.v1`,
`audit.ndjson/1`, ...) are versioned independently of software releases by
design.

## The release readiness gate ("only when it is ready")

A tag push is refused by `.github/workflows/release.yml` unless **all** of
these hold. Work through the checklist; only then drop the `.dev` suffix:

- [ ] Full suite green: `make test` (all components + repository tests) and
      `python3 tests/docbuild.py verify` (fresh API pages, no broken links).
- [ ] Guard harness green: `python3
      components/northstar-agent-runtime/tools/verify_invariants.py`.
- [ ] Demo and examples run: `make demo`, `examples/sdk/run_sdk_demo.py`.
- [ ] Wheel-install smoke passes for every component from a clean venv
      (import each public module from `/tmp`, run `--version` and one
      offline `sdk.run()`).
- [ ] Version alignment: all five `pyproject.toml` + `_version.py` carry the
      same **plain** `major.minor.patch` (no `.dev` suffix) — the gate
      refuses dev-suffixed tags outright.
- [ ] `CHANGELOG.md` has a release section for this version describing what
      changed since the previous release.
- [ ] The public embedding surface (`sdk.py`, `events.py`, CLI exit codes)
      has been reviewed for accidental breakage since the last release.
- [ ] Release notes drafted (what is in, what is still alpha/limited).

Automated backstop in `release.yml`: dev-suffix → refuse; tag name ≠
`v<aligned version>` → refuse; stale docs → refuse.

## Cutting a release (only after the checklist is green)

1. **Bump**: change all five `pyproject.toml` versions and the runtime
   `_version.py` from `0.1.0.dev0` to the plain new version; write the
   `CHANGELOG.md` release section.
2. **Verify locally**:

   ```sh
   make test
   python3 tests/docbuild.py verify
   ```

3. **Tag and push** (tag name = version with a `v` prefix):

   ```sh
   git tag v0.1.0
   git push origin v0.1.0
   ```

4. **Publish**: `release.yml` runs the readiness gate, builds wheels for all
   five components and creates the GitHub Release with them attached
   (idempotent — an existing release is left untouched). After the release,
   bump back to `0.1.1.dev0` (next dev iteration).

## Manual fallback (no CI, or a release that predates the workflow)

```sh
# Only after the checklist above is green.
mkdir -p dist
for component in northstar-run-contract northstar-host northstar-durable-run \
                 northstar-agent-interop northstar-agent-runtime; do
  python -m pip wheel --no-deps --wheel-dir dist "components/$component"
done
gh release create v0.1.0 dist/*.whl --title "Northstar Agent OS v0.1.0" --generate-notes
```

## Installing a release

```sh
pip install northstar-run-contract northstar-host northstar-durable-run \
            northstar-agent-interop northstar-agent-runtime
# or, from the release assets:
pip install northstar-agent-runtime-0.1.0-py3-none-any.whl
```

Until the components are on an index, install them from the release wheel
assets or from local paths (`pip install ./components/northstar-agent-runtime`).

## Versioning policy

- Between releases: aligned `.devN` version everywhere; the working tree is
  explicitly *not* a release.
- A breaking change to a contract component (`northstar-run-contract`) should
  raise its **schema** version in the same release, so a mismatch between an
  old and a new component stays a loud failure.
- A tag is the only thing that publishes: pushing a tag runs the readiness
  gate, and the gate refuses anything dev-suffixed or misaligned.
