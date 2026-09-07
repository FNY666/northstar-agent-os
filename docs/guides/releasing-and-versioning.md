# Guide: releasing and versioning

How a Northstar Agent OS release is cut — the version rule, the automation,
and the manual fallback.

## The version rule

The five pip-installable components (`northstar-run-contract`,
`northstar-host`, `northstar-durable-run`, `northstar-agent-interop`,
`northstar-agent-runtime`) are **released together from one tag and carry one
version**. `tests/test_release.py` enforces it:

- every `components/<name>/pyproject.toml` `project.version` is a plain
  `major.minor.patch` (no `.dev`/local suffix);
- all five are identical;
- the runtime's `_version.py` `__version__` equals them (it is what the CLI
  prints and what the MCP handshake advertises).

The `northstar-codex-sidecar` is not pip-packaged (shell + systemd), so it is
not versioned here; the run-contract's *schema* versions (`northstar.run.v1`,
`audit.ndjson/1`, ...) are versioned independently of software releases by
design.

## Cutting a release

1. **Bump**: change all five `pyproject.toml` versions and the runtime
   `_version.py` to the new version (the aligned-version test fails until they
   match). Update `CHANGELOG.md` with the release section.
2. **Verify locally**:

   ```sh
   make test                       # full suite, including tests/test_release.py
   python3 tests/docbuild.py verify
   ```

3. **Tag and push** (the tag name must be the version with a `v` prefix):

   ```sh
   git tag v0.1.0
   git push origin v0.1.0
   ```

4. **Publish**: `.github/workflows/release.yml` runs on `v*` tags: it builds
   wheels for all five components and creates the GitHub Release with them
   attached (idempotent — an existing release is left untouched).

## Manual fallback (no CI, or a release that predates the workflow)

```sh
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

- **0.1.x** — first public increments; anything may change, but the aligned
  version and the changelog keep consumers oriented.
- A breaking change to a contract component (`northstar-run-contract`) should
  raise its **schema** version in the same release, so a mismatch between an
  old and a new component stays a loud failure.
- Pre-release suffixes (`.dev0`) belong between releases; a pushed tag must
  always carry a plain release version (the CI test suite refuses otherwise).
