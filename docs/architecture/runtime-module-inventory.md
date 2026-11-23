# Runtime module inventory

This document records the first conservative static inventory used to split
the agent runtime into Core and Labs. It is evidence for review, not permission
to move or delete code.

## Reproduce it

From the repository root, run:

```bash
python3 scripts/classify-runtime-modules.py \
  --write /tmp/northstar-runtime-module-inventory-v1.json
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
