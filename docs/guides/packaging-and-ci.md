# Guide: packaging and CI for the Northstar components

How this repository builds, tests and packages its six components — the recipe
a consumer or a fork should copy.

## Repository layout

- `components/<name>/` — six independent components. Most are
  `pyproject.toml`-packaged, pure standard-library modules installed as
  top-level names (no `PYTHONPATH` tricks); the sidecar additionally ships an
  `install.sh`/`rollback.sh` pair and a systemd unit.
- `tests/` (root) — repository-wide documentation structure, build and link
  checks (`tests/docbuild.py` + `tests/test_documentation.py`).
- `examples/` — self-contained recipes (`demo` = offline governed run,
  `ci-readonly-review` = consumer CI template); index in
  [examples/README.md](../../examples/README.md).
- `docs/` — four-layer documentation: per-component READMEs (quick start),
  [concepts](../concepts/governance.md), [guides](../guides/governed-run-cookbook.md),
  and the docstring-generated [API reference](../api/northstar-agent-runtime.md).

## Testing: `make test`

Runs each component's unit suite from its own directory, then the root
repository-documentation tests:

```sh
make test
```

The runtime component adds **guard verification**
(`components/northstar-agent-runtime/tools/verify_invariants.py`): it reverts
each core guard in a throwaway copy and asserts the corresponding test turns
red — the RED tests stay honest. The copy is the whole `components/` tree, not
just the runtime: several of the runtime's own tests deliberately import the
real sibling components (the bridges validate against the definitions they
mirror), so a runtime-only copy has a red baseline, and a mutation judged
against a broken baseline proves nothing. `tests/test_tools_verify_invariants.py`
pins that copy step, and `make ts-test` is guarded the same way the harness is
honest — the TypeScript face is *skipped* (exit 0, printed reason) where node is
older than 22.6, never quietly passed.

## CI: `.github/workflows/test.yml`

Three jobs:

1. **test** — sidecar, run-contract, host, durable-run, agent-interop:
   `py_compile`, unit tests, then a packaging smoke that `pip install`s the
   component, `cd /tmp`s and imports it, proving the wheel carries everything.
2. **agent-runtime** — installs test requirements, `py_compile` of every
   module (by glob, so a new module cannot escape the compile step), offline
   unit tests, the **TypeScript face** (`actions/setup-node@v4` with node 22,
   then `node --test` in `sdk-ts` — no `npm install`, no registry contact), CLI
   smoke (version / doctor / dry-run / demo script), the packaging smoke, and the
   guard verification.
3. **documentation** — repository structure tests (which include the
   Python-side drift gate for the TypeScript mirror,
   `tests/test_typescript_sdk.py`, so the contract is checked even in a job that
   never runs node), then
   `python3 tests/docbuild.py verify`:
   - *structure* (unit tests): component READMEs expose
     "Concepts, guides and API reference" link sections; the examples index
     covers every example; API pages are fresh;
   - *build*: API pages are regenerated from docstrings by the same stdlib
     generator, so drift is a failed check, not a stale page;
   - *links*: every internal markdown link in the repository resolves.

## Doc tooling

```sh
python3 tests/docbuild.py build     # regenerate docs/api/*.md
python3 tests/docbuild.py verify    # freshness + broken-link check (exit 1 on drift)
```

The generator is pure `ast` — it never imports the modules it documents, so it
stays hermetic and offline-safe.

## Consumer take-aways

- Pin the run contract: it is the versioned structural boundary — a
  `SCHEMA_VERSION` mismatch is a loud failure by design.
- Treat packaging smoke (`pip install .` then import from `/tmp`) as
  mandatory: top-level module names are a deliberate trade-off and the smoke
  is what catches a missing module in `py-modules`.
- For a governed review loop in your own CI, copy
  [examples/ci-readonly-review](../../examples/ci-readonly-review/README.md),
  not this workflow (it would need your API key).
- Cutting a release: see
  [releasing-and-versioning](releasing-and-versioning.md) — one aligned
  version across all components, one `v*` tag, wheels built and attached by
  `.github/workflows/release.yml`.
