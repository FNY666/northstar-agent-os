# Runtime module inventory

This document records the first conservative static inventory used to split
the agent runtime into Core and Labs. It is evidence for review, not permission
to move or delete code.

## Reproduce it

From the repository root, run:

```bash
python3 scripts/classify-runtime-modules.py \
  --write /tmp/northstar-runtime-module-inventory-v2.json
```

The command parses local Python imports from the production roots `cli`, `sdk`,
`loop`, `events`, `code_task`, `verification`, `providers`, and `tools`. For
each reachable module it records a deterministic root-to-module import path. It
also records literal and non-literal dynamic import sites. Build output, tests,
caches, and package metadata are excluded.

## Baseline captured on 2026-10-13

| Measure | Result |
|---|---:|
| Discovered Python modules | 1,569 |
| Statically reachable from production roots | 178 |
| Held for manual review | 1,391 |
| Dynamic import sites | 24 |
| Parse errors | 0 |

Portable inventory SHA-256:
`96f8ee23f9a668f0e44390fb96dae9ccddc8c9b2603508bc1268231d1e38cdbb`.
The digest omits the absolute checkout location, so identical source trees
produce the same value on different machines.

| First production root | Reachable modules |
|---|---:|
| `cli` | 142 |
| `loop` | 21 |
| `tools` | 6 |
| `sdk` | 5 |
| `events`, `code_task`, `verification`, `providers` | 1 each |

The reachable set is larger than the intended product kernel and already
contains domain, benchmark, and research modules. Reachability therefore means
"currently coupled to a production entry point" rather than "approved for
Core." The largest coupling is the top-level `cli -> governance_bench` import,
which pulls domain agents, corpora, and governance experiments into 142 modules
reachable from `cli`. Each reachable module still needs dependency-path and
runtime-trace review. Every unreachable module remains `review_required`;
static absence from the graph is not evidence that a module is unused.

## Promotion rules

A module may enter Core only when a supported CLI or SDK path needs it, its
transitive dependencies fit the default wheel, and its permissions, budget,
audit, and recovery behavior have tests. Attack corpora, probes, benchmark
adapters, research defenses, and vertical examples belong in Labs once their
imports are isolated. Import shims must be labeled compatibility code and carry
a removal version.

Before any move, combine this inventory with runtime import traces from the
offline task pack. Review non-literal dynamic imports manually, then regenerate
the inventory and compare both the module lists and digest.

## 2026-11-25 parser revalidation

The inventory parser now recognizes common aliases for `importlib.import_module`,
`builtins.__import__`, and `importlib.util.spec_from_file_location`, including
literal module names passed as positional or `name=` arguments. It resolves
relative `import_module(".child", package=...)` names when the package is literal
or inferable from `__package__`. This closes static-analysis blind spots where
`from importlib import import_module as load` was recorded as an ordinary import
but the actual dynamic target was omitted from the graph. Computed module or
package names are still reported as dynamic sites and are not guessed.
Regression coverage is in `tests/test_runtime_module_inventory.py`.

Re-run on the current checkout:

| Measure | Result |
|---|---:|
| Discovered Python modules | 1,579 |
| Statically reachable from production roots | 189 |
| Held for manual review | 1,390 |
| Dynamic import sites | 29 |
| Parse errors | 0 |

Inventory schema v2 includes a SHA-256 for every module's source bytes as
well as its import edges and classification. Inventory SHA-256:
`533ad0d4d3d633399fb64809936b9049ee11f9224205c03074cab4cde89b315f`.
This digest covers the emitted inventory payload (including source digests),
not the analyzer source or its rule version. The October 13 table above is
retained as a dated historical snapshot.

The analyzer also recognizes `importlib.util.spec_from_file_location` aliases.
This arose from a real trace: `governed_action_runner.py` loads `bash_parser.py`
by a file-location spec, which the earlier import-function patterns did not
include in the static graph. The literal module name is now included as a
conservative edge; dynamic path selection remains unresolved for human review.

## Opt-in trace smoke (2026-11-25)

The new `scripts/trace-runtime-imports.py` executes an explicit command with a
temporary `sitecustomize` hook and compares observed runtime files against the
static graph. It is not a sandbox: the command runs with the caller's current
privileges and environment. Child Python processes that inherit `PYTHONPATH`
are traced separately. Python launched with `-S` / `-I`, embedded interpreters,
or descendants that discard `PYTHONPATH` may be missed; `capture_completed`
means the observed hooks exited normally, not that every child or product path
was captured. The trace contains module names and paths under the selected
runtime only; the command itself is represented by a SHA-256 digest. Use only
with a reviewed, bounded command. The timeout defaults to 300 seconds and must
be finite and no greater than 86,400 seconds; missing static roots or parse
errors prevent the command from running.

```bash
python3 scripts/trace-runtime-imports.py \\
  --output /tmp/northstar-runtime-import-trace.json --timeout 90 \\
  -- python3 -m cli bench
```

This offline governance-bench run passed its 169/169 checks and observed 161
runtime files in one Python process: 0 observed files were outside static
reachability, while 28 statically reachable files were not imported by this
particular command. Those 28 are not evidence of dead code; a single command
cannot cover all supported paths. The generated trace remains in `/tmp`, not
Git. Trace digest: `a5274865184906023c2599f1491d0eb8c2a341fad40a7354a00ba9205c761f87`.
