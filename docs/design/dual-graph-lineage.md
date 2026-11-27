# Dual-graph lineage: an exploration chain and a shared asset truth

**Slice:** `wsartex-dual-graph-lineage`
**Module:** `components/northstar-agent-runtime/exploration_graph.py`
**Tests:** `components/northstar-agent-runtime/tests/test_exploration_graph.py`
**Date:** 2026-11-27

---

## 1. What this slice is

Northstar could say *what* it concluded and it could say *how much* it did.
It could not say **which conclusion came from which facts, and which assets
those facts were collected against** — and that is the question a red-team
run is actually judged on.

Three gaps, measured against the runtime as it stood:

* **The exploration side was flat.** Goals, intents, facts and findings
  existed as records, but a finding named its subject rather than the
  chain that produced it. "Is this conclusion supported?" was a question
  about prose rather than about structure, so nothing in the runtime could
  answer it mechanically.
* **The asset side had no program-owned identity.** A caller named an
  asset, so `API.example.com` and `api.example.com` were two assets, and
  the coverage denominator was whatever the caller's spelling produced.
* **The two sides could not be joined.** There was no anchor, so
  "which of the in-scope assets did we actually exercise, and what did we
  conclude about them?" had no answer at all — not a rough one, not an
  approximate one: none.

This slice adds the object that answers it: **two graphs and the anchors
between them**.

---

## 2. Source and licence basis

**This section is the licence red line, and it was settled before any code
was written.**

### 2.1 The source

**WSARTEX** — <https://github.com/willsurpass/WSARTEX>. An AI autonomous
penetration-testing system (Go backend, PostgreSQL, multi-agent). Its
`README.detailed.md` documents the architecture under the heading
**「双图架构」** (dual-graph architecture); the implementation lives in
`agent/` (`planner.go`, `tools.go`, `coldgraph.go`) and `db/`
(`exploration.go`, `assets.go`, `task_scope.go`, `schema.sql`).

What was learned from it is the **shape** of the idea:

> the system splits "what is the target" and "how far did we get" into two
> mutually independent graphs joined by anchors; the asset graph is a global
> shared truth whose node kinds are root_domain / subdomain / ip / service /
> app / endpoint, whose parent-child relations and dedup keys are **all
> computed by the program**, and where the agent only submits raw
> information; the exploration graph is per-task, with node kinds goal /
> intent / fact / finding / hint joined by spawns / derived_from / yields /
> proves into a lineage chain; `exploration_anchors(node_id, asset_id)` ties
> the two together, which is what makes asset test coverage computable.

### 2.2 The licence, and what it forces

WSARTEX is **AGPL-3.0-or-later**. Its `NOTICE.md` records that it is
itself a derivative of ARTEX (`Autumn-27/ARTEX`, later `mhtsec/ARTEX`),
that the core penetration machinery comes from ARTEX and the bundled
`third_party/norma` SDK rather than from WSARTEX itself, and that
`third_party/norma/noa/` carries derived `acp-kernel` code under its own
copyright (`Copyright (c) 2026 ranxianglei`).

Northstar's own `LICENSE` is **MIT** (`Copyright (c) 2026 Northstar Agent
OS contributors`).

**MIT is not compatible with AGPL-3.0.** The compatibility runs one way:
MIT-licensed code can be incorporated into an AGPL-3.0 project, but
AGPL-3.0-or-later code cannot be incorporated into an MIT project without
the whole work becoming AGPL-3.0. So the AGPL source is **not
reusable here**, and the task book's instruction — "only if Northstar is
AGPL-compatible AND you record the license basis in the slice may you reuse
snippets — otherwise rewrite everything" — resolves to:

> **Northstar is not AGPL-compatible. Everything is rewritten. No WSARTEX
> code, identifiers, table definitions, schema, comments or text are
> reused.**

### 2.3 What was therefore *not* taken

Read literally, these are all WSARTEX's own artefacts, and none of them
appears in the module:

| WSARTEX artefact | Northstar |
|---|---|
| `exploration_nodes` / `exploration_edges` / `exploration_anchors` tables | in-memory `ExplorationGraph` / `AssetGraph` / anchors |
| `db.KindGoal` / `KindIntent` / `KindFact` / `KindFinding` / `KindHint` | `NodeKind` with Northstar's own members |
| `db.RelSpawns` / `RelDerivedFrom` / `RelYields` / `RelProves` | `Relation` with Northstar's own members |
| `assets` table columns and its `ON CONFLICT` partial indexes | `_compute_key` over a normalised observation |
| `assets.go`'s `DomainKey` / `RootDomain` / `normalizeURL` / `calcCSegment` | `_normalise_domain` / `_normalise_endpoint` / `_normalise_ip` |
| `task_scope.go`'s `covTargetCTE` and `TaskCoverage` | `ExplorationGraph.coverage` |
| `agent/coldgraph.go`'s hot/cold classification | not implemented (a later slice's concern) |

The *words* `goal`, `intent`, `fact`, `finding`, `hint`, `spawns`,
`derived_from`, `yields`, `proves`, `root_domain`, `subdomain`, `ip`,
`service`, `app` and `endpoint` are the ordinary English names of the
concepts the idea describes; they are not code, and a different
implementation of the same idea needs the same nouns. The **module's
identifier names, its function names, its data structures, its key
derivation, its edge-direction rules, its coverage rule and its lineage
walk are all Northstar's own.**

### 2.4 Northstar extensions (explicitly *not* from the source)

* **The key derivation.** The source computes a key from the raw columns
  of its own schema and lets the database enforce it with a partial
  unique index. Northstar derives a kind-specific canonical key from a
  *normalised observation* and refuses a caller-supplied one outright
  (§4). Northstar's key is a domain-separated digest, so it cannot collide
  with any other digest the runtime computes.
* **The relation vocabulary is enforced, not merely recorded.** The
  source's `exploration_edges` table has a `CHECK` on the relation *name*
  but none on which node kinds a relation may join. Northstar refuses an
  edge whose endpoints do not fit: a `yields` edge from a goal to a goal
  claims a production that never happened, and it is refused rather than
  stored.
* **The coverage rule.** The source's coverage counts assets anchored to
  *any* fact node in the exploration. Northstar's rule is the same in
  spirit and stricter in effect: **only a `fact` is evidence that an
  asset was exercised**, so an intent anchored to an asset is a plan and
  does not count, and a finding anchored to an asset is a conclusion and
  does not count. The scope the caller asserts is the denominator, and an
  asset tested but *outside* the scope is not counted.
* **The lineage walk.** Northstar's is explicit about a subtlety the
  source leaves to the reader: **a fact and the finding drawn from it are
  siblings** — both were produced by the same intent — so a finding's
  lineage is not only the ancestors but also the facts the upstream
  intents yielded. A lineage that stopped at the ancestors would report a
  finding with no facts behind it even though the graph holds the facts
  that produced it. Northstar's walk is iterative and bounded, so a cyclic
  graph terminates.
* **The normalisation.** Northstar normalises a dotted quad by decimal
  octet, so `192.168.001.001` and `192.168.1.1` are one address; the
  source's Go `net.ParseIP` rejects the former.

---

## 3. The two graphs

### 3.1 The exploration graph

Nodes are `goal`, `intent`, `fact`, `finding` and `hint`. Edges are
`spawns`, `derived_from`, `yields` and `proves`.

**Every edge points downstream: the source is the parent and the
destination is the child.** That convention is what makes the lineage
walk well defined — "up" always means "came from".

| Relation | Source → destination | Reads as |
|---|---|---|
| `spawns` | goal → intent | the goal spawned this direction |
| `yields` | intent → fact / finding / hint | the intent produced this |
| `derived_from` | fact / finding / hint / intent → intent | this was derived from that intent |
| `proves` | intent → finding | this intent proved that finding |

The relation's endpoints are **checked**, not just named:

```
spawns       (goal)                          -> (intent)
yields       (intent)                        -> (fact, finding, hint)
derived_from (fact, finding, hint, intent)  -> (intent)
proves       (intent)                        -> (finding)
```

An edge whose endpoints do not fit is refused, and a refused edge leaves
the graph unchanged — a half-recorded edge would read as a relation that
happened.

### 3.2 The asset graph

Nodes are `root_domain`, `subdomain`, `ip`, `service`, `app` and
`endpoint`. The graph computes three things the caller does not supply:

* **the key** (§4),
* **the normalised value** — the domain lowercased and stripped of its
  trailing dot, the address in its canonical compressed form, the
  endpoint URL with a lowercased scheme and host and the default port
  dropped, the method uppercased;
* **the parent** — a subdomain sits under the registrable domain it ends
  with; a service or endpoint sits under the host it names (an IP address
  if the host is one); a root domain, an IP and an app sit under nothing.

The registrable domain is computed as the last two labels. That is the
right answer for the common two-label public suffix, and it is never
*worse* than guessing: an over-deep split produces a parent that exists,
where a public-suffix table that is absent would produce none at all.
**This is a stated limitation, not a hidden one** — a run against
`a.b.example.co.uk` will place the subdomain under `example.co.uk` rather
than `example.co.uk`'s registrable parent `example.co.uk`'s parent. A
public-suffix table would fix it and is out of scope for this slice.

### 3.3 The anchors

An anchor says *this exploration node is about this asset*. It is named by
the key the asset graph computed, and it is refused if either end is
unknown — an anchor that points at nothing is a silent no-op that reads
as coverage.

From the exploration side, an anchor says *what we did to which asset*.
From the asset side, it says *how this asset was tested*.

---

## 4. The rule the whole slice stands on

> **The dedup key is computed by the program. The agent never chooses it.**

A caller submits a raw observation — a kind, a value, and whatever fields
that kind carries — and the program derives the key, the normalised value
and the parent. An observation that carries a `key` field is **refused**:

```python
>>> AssetGraph().upsert_asset({"kind": "root_domain", "value": "example.com",
...                             "key": "agent-chosen"})
ExplorationGraphError: the dedup key is computed by the program; remove
'key' from the observation
```

This is not a stylistic preference. A caller-chosen key is a **claim about
identity**, and an agent permitted to make identity claims makes them
inconsistently: `API.example.com` and `api.example.com` become two
assets, and the coverage denominator quietly doubles while the report
still reads 100%. The program owns identity because identity is a property
of the *observation*, not of the observer.

The key is a domain-separated digest:

```
key = "asset:" + sha256(
    "northstar.exploration-graph.asset.v1" \x1f
    kind \x1f value \x1f detail...
)
```

The body is built in a fixed field order, so the same observation always
yields the same key; and the domain separator keeps these digests from
being comparable with any other digest the runtime computes over
unrelated content.

---

## 5. The two queries

### 5.1 Lineage — from a finding back to its facts

`lineage(finding_key)` returns the facts the conclusion rests on, the
intents that produced them, and the goals those intents served.

The walk is upward from the finding, plus the facts the upstream chain
produced (see §2.4 on why the upward walk alone is not enough). It is
iterative and bounded by the node count, so a cyclic graph terminates
rather than hanging.

### 5.2 Coverage — which in-scope assets were tested

`coverage(scope)` takes the scope the caller asserts — the denominator —
and reports which of its members a **fact** is anchored to.

The rules, each of which is a test:

* only a `fact` is evidence (§2.4);
* an asset tested but **outside** the scope is not counted, so the figure
  can never exceed 100%;
* the scope is a **set**: a member listed twice is one member, so the
  denominator cannot be grown under the caller's hand by repeating an
  untested entry;
* a scope member that is not a known asset is refused — the denominator
  cannot be padded with keys that mean nothing;
* an **empty scope has no percentage**: "everything was tested" would be a
  claim about nothing.

The report also groups by asset kind, because "we tested 3 of 5 assets"
and "we tested 3 of 5 assets, none of them the services" are different
answers.

---

## 6. Verification

### 6.1 The tests

`components/northstar-agent-runtime/tests/test_exploration_graph.py` —
**78 tests**, each driving a behaviour rather than a line:

* the key is the program's, and a caller-supplied one is refused;
* the key is injective across kinds, stable across spellings, and
  sensitive to the kind-specific detail (a service's port, an endpoint's
  method);
* the normalisation: domain case and trailing dot, IPv4 octets, IPv6
  compression, endpoint method case, the default port;
* the graph computes its own parent/child relations, and a root domain,
  an IP and an app have no parent;
* the relation vocabulary is enforced in **both** directions, a refused
  edge leaves the graph unchanged, and a self-edge is refused;
* the anchors: an unknown asset or node is refused, and a duplicate
  anchor is one anchor;
* the lineage: the fact chain, the goal, the intents, an unrelated
  finding, a non-finding refused, a cyclic graph terminating, and
  determinism;
* the coverage: tested and untested assets, the denominator, the empty
  scope, the non-fact anchors, the out-of-scope asset, the repeated scope
  member, the per-kind rows, and the refusal of an unknown scope member;
* purity: the module imports nothing outside the standard library and
  reads no clock.

### 6.2 The mutant probe

The suite was measured against **25 planted faults**, one per
behaviour the module claims. The probe lives outside the repository
(`/tmp/mut-probe-s1/probe.py`) and plants each fault in a *copy* of the
module, so the shared tree is never mutated.

The first run left **7 survivors**, and every one of them was a real gap
in the suite rather than a defect in the module:

| Survivor | What it exposed | The test that closed it |
|---|---|---|
| key domain separator dropped | the key was not domain-separated | `test_the_key_carries_the_module_s_own_domain_separator` |
| endpoint method not uppercased | `get` and `GET` were two endpoints | `test_an_endpoint_method_is_normalised_to_upper_case` |
| root domain given a parent | the root domain could sit under something | `test_a_root_domain_has_no_parent_at_all` |
| relation endpoints not checked | the *source* half of the endpoint check was unpinned | `test_a_yields_edge_from_a_goal_is_refused` (and five siblings) |
| self-edge allowed | the self-edge test used a pair that failed the endpoint check first, so it passed for the wrong reason | `test_a_self_edge_is_refused_even_when_the_kinds_would_fit` |
| lineage not cycle-safe | the cycle test asserted only "did not hang", which a bounded-but-wrong walk also satisfies | `test_a_cyclic_graph_terminates_quickly` |
| coverage ignored the scope | a tested asset outside the scope was counted | `test_a_tested_asset_outside_the_scope_is_not_counted` |

Two of those are worth naming as *method* findings rather than test
findings:

* the self-edge test **passed for the wrong reason** — it used
  `goal → goal`, which the endpoint check refuses anyway, so it would have
  kept passing if the self-edge check were deleted. The fix chose
  `intent → intent`, which fits `derived_from`, so the refusal can only
  come from the self-edge check.
* the cycle test asserted only `assertIsNotNone(chain)`, which is
  satisfied by a walk that returns an empty chain. The fix asserts that
  all three nodes of the cycle are reachable **exactly once**.

### 6.3 A defect the probe could not find

The eighth defect was found by *reading* the module against its own
claims, not by the probe — and the probe then confirmed it.

**A repeated scope member inflated the denominator.** The scope was taken
as a list, so a caller could list the same untested asset twice and the
denominator would grow from 3 to 4 while the tested count stayed at 1. The
coverage figure would fall without a single asset going untested — a
caller could depress the figure with a repetition, which is the same class
of defect as the caller-chosen dedup key (§4) wearing a different hat.

The fix deduplicates the scope, and two tests now pin it:
`test_a_repeated_scope_member_does_not_inflate_the_denominator` and
`test_a_repeated_scope_member_is_listed_once`. The probe's mutant
`coverage-counts-a-repeated-scope-member` confirms the first of them fails
for the right reason when the deduplication is removed.

The second run: **0 survivors / 25 mutants**. Every planted fault is
caught, and each is caught by a test that fails for the right reason.

### 6.3 The lineage semantics, measured

The sibling-fact rule (§2.4) is not a detail — it is the difference
between a lineage that answers the question and one that does not. With
the sibling rule removed, the mutant `lineage-ignores-sibling-facts`
survives until
`test_a_finding_traces_back_to_its_fact_chain` is present, and that test
fails because the chain reports one fact where the graph holds two.

### 6.4 A repo guard this slice broke, and the fix

The slice's own commit subject is `wsartex-dual-graph-lineage: …`. It is
not a `B173 ` commit — it is a **WSARTEX** slice — and
`tests/test_delivery_bundle_hygiene.py` reported it as an offender:

```
AssertionError: Lists differ: [('739e03b7…', 'wsartex-dual-graph-lineage:
the exploration chain and the asset truth, joined by anchors')] != []
```

The commit was not the offender. The **guard** was, and the reason is
that the guard hardcoded one batch prefix in five places
(`subject.startswith("B173 ")`). A prefix that names a batch *is* a
name; the guard only knew one, so it called a correctly-named commit
an offender.

The fix declares the prefixes once, in `BATCH_PREFIXES`, and every
predicate reads them through `_names_a_slice()`. Widening a predicate is
exactly the change that can turn a guard into a rubber stamp, so two
controls were added, and **each was shown able to fail**:

| control | what it holds | mutant that kills it |
| --- | --- | --- |
| `test_the_batch_prefix_predicate_can_refuse` | the predicate refuses `"c1"`, `""`, `"B173"` (no slug), `"B173x …"`, `"wsartex"`, and a subject that *mentions* a prefix mid-subject | the predicate rewritten to `return True` |
| `test_every_declared_batch_prefix_names_a_real_slice` | every prefix in the set is one some commit actually uses, so the set cannot grow into a vacuity | a prefix added that no commit uses |

Measured: 3/3 mutants killed, each by the control that names it.

The range boundary did not move: `_batch_commits()` finds the first
**named** commit in the history, and that is still the first `B173 ` one,
so the WSARTEX commit descends from the B173 chain and is inside the
range — which is why it must name its slice.

---

## 7. What this slice does NOT do

Stated plainly, because the gap is real and someone will otherwise assume
it is closed:

* **No persistence.** Both graphs are in-process. A durable writer is the
  caller's job.
* **No public-suffix table.** §3.2.
* **No scope *derivation*.** The module computes coverage **against a
  scope the caller asserts**; it does not decide what is in scope. A
  later slice may want the program to own that too, and the same argument
  applies — but it is not this slice's claim.
* **No connection to the runtime's existing records.** The module is a
  pure library with no callers yet. Wiring it into the agent loop, the
  bench and the evidence store is a separate slice, and a slice that
  wires an unwired module is a slice that cannot tell whether the wiring
  or the module is at fault.
* **No cold/hot classification.** WSARTEX's `coldgraph.go` folds cold
  nodes into digests; Northstar's runtime has its own context-budget
  machinery, and folding is a different question from lineage.

---

## 8. The registration, and the counts that moved

The module is registered in both halves of the packaging registration
(`runtime_registration.py` `REGISTRY`, `pyproject.toml` `py-modules`) and
published in the documentation manifest (`tests/docbuild.py` `MANIFEST`).

Adding a runtime module moves pinned counts in **eight** places (the six
the repo's own notes name, plus two this slice found):

| Site | Before | After |
|---|---|---|
| `tests/test_component_packaging_closure.py` (installed) | 1642 | 1643 |
| `tests/test_component_packaging_closure.py` (flat on disk) | 1619 | 1620 |
| `tests/test_package_member_publication.py` (flat declared) | 1619 | 1620 |
| `tests/test_package_member_publication.py` (installed) | 1642 | 1643 |
| `tests/test_digest_pin_census.py` (current tree) | 1619 | 1620 |
| `tests/test_census_scope.py` | 1620 | 1621 |
| `components/.../tests/test_installed_surface_registration.py` (flat / installed) | 1619 / 1642 | 1620 / 1643 |
| `components/.../tests/test_runtime_data_files.py` | 1619 | 1620 |
| `components/.../tests/test_py_modules_list.py` | 1642 | 1643 |

Two of these need care, and both were got wrong on the first attempt:

* **The pre-fix tree's count does not move.** `test_digest_pin_census.py`
  rebuilds the tree at `66e6ccd4~1` from git and re-runs the census on it.
  That tree has 1619 modules and always will; the assertion there names
  *that tree*, and moving it to 1620 would have made the test describe a
  tree that does not exist.
* **The five digest-pin design docs quote the current tree's module
  count.** They read 1619 and now read 1620, because they describe the
  tree as it stands. The other numbers they quote — 687 canonicalizer
  users, 629 fallback importers, 628 candidate sites across 201 modules —
  do **not** move, because this module uses `hashlib` directly rather than
  the `canonical_json` sibling helper, so it is not a canonicalizer user
  at all. Measured, not assumed:

  ```
  modules 1620   canonicalizer_users 687   fallback_importers 629
  candidate_sites 628   candidate_modules 201
  ```

---

## 9. Sources and references

* **WSARTEX** — <https://github.com/willsurpass/WSARTEX>. AGPL-3.0-or-later.
  Read for: `README.detailed.md` §「双图架构」, `agent/planner.go`,
  `agent/tools.go`, `agent/coldgraph.go`, `db/exploration.go`,
  `db/assets.go`, `db/task_scope.go`, `db/schema.sql`, `NOTICE.md`.
* **Northstar's own licence** — `LICENSE` (MIT).
* **The task book** — `wsartex-absorption-2026-11-27.md` (slice 1 of 5).
* **House precedents for this kind of slice** —
  `docs/design/bughunter-finding-gate.md` (a gate learned from an MIT
  source, with the licence basis recorded in §2),
  `docs/design/memory-provenance-axis.md` (a Northstar object with a
  documented source basis and an explicit scope).
