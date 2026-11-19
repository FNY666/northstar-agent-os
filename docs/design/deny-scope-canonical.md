# Deny scope's canonical key (slice: deny-scope-canonical)

**Source:** slice 21, following `scope-verb-canonical.md` §"The neighbour
defect: measured, named, and NOT fixed here", open item 6.

## The defect (measured, not assumed)

The deny hot path is the runtime's **fail-closed precondition**: every
dispatch consults the sealed deny *before* the gate decides, so a revoked
scope never reaches the gate at all. Its scope is `<subject>/<tool>`:

```python
# governed_action_runner.py:258
@staticmethod
def _deny_scope(subject: str, tool: str) -> str:
    return f"{subject}/{tool}"
```

and the store reads it as an **exact-key seek** on the primary key:

```python
# deny_hotpath.py:232
LOOKUP_SQL = (
    f"SELECT counter, denied, reason FROM {COUNTER_TABLE} WHERE scope = ?"
)
```

So the whole revocation record was keyed by the **spelling** of a string
the host wrote and the runtime built.

### Measured, at the store level

`DenyStore.revoke(revoked)` then `DenyStore.lookup(called)`:

| revoked | called | denied? |
|---|---|---|
| `main/Bash` | `main/Bash` | **yes** |
| `main/Bash` | `main/bash` | **NO** |
| `main/Bash` | `main/BASH` | **NO** |
| `main/Bash` | `Main/Bash` | **NO** |
| `main/lookup` | `main/Lookup` | **NO** |
| `main/lookup` | `main/lookup` | **yes** |
| `main/lookup` | `main/Lookup ` | **NO** |

And the store kept **two** rows for one revocation:

```
scope            counter  denied
main/Bash             1       1
main/bash             1       1
```

### Measured, end-to-end, on the runtime's own dispatch path

A real `AgentRuntime`, a real `ToolRegistry`, the real `deny_store_path`
wiring, the real `GovernedActionRunner`:

| revoked | tool called | handler ran? | denied? |
|---|---|---|---|
| `main/Lookup` | `Lookup` | no | yes |
| `main/lookup` | `Lookup` | **YES** | no |
| `main/Lookup` | `lookup` | **YES** | no |
| `main/lookup` | `lookup` | no | yes |

**The second row is the sharp one.** The host revoked the scope using the
runtime's *own* canonical spelling of the action (`lookup`, the spelling
`sessions.canonical_action` produces), and the dispatch of `Lookup` **ran**.
That is not a host's typo: it is the host using the identity the runtime
itself defines, and the runtime not recognising it.

### Why the miss was not fail-closed

`docs/design/deny-hotpath.md` says the store fails closed: *"I could not
check" is never "allowed"*. But a scope that is **missed** is not an
unreadable counter — it is **no row at all**, which the store read as:

```python
# deny_hotpath.py:415
return DenyLookup(
    scope=scope, denied=False, counter=None, source=SOURCE_INDEX,
    reason="no revocation recorded for scope",
)
```

So the miss was the cleanest possible allow: the scope is not revoked, the
counter is `None`, the source says the indexed counter answered, and the
refusal row was finalized with outcome `allowed`. A revocation that was
never found left a row saying it was allowed.

That is the same shape `scope-verb-canonical.md` closed on the other gate:
**a missed denial is read as absent, and absent is read as allowed.**

### The asymmetry that makes this a defect and not a design choice

The runtime states the rule about spelling twice, for the same reason:

> *"Strips whitespace and casefolds, so `"  Bash "`, `"bash"` and `"BASH"`
> all resolve to the same identity. A forbidden action can't slip through
> via spelling variants."*
> — `permissions.canonical_tool_name`, `permissions.py:1255`

> *"Whitespace is stripped and the name is casefolded, so `"  Write "` and
> `"write"` are the same action. A forbidden action must not be able to
> slip through via a spelling variant."*
> — `sessions.canonical_action`, `sessions.py:186`

and

> *"The gate must deny the **action**, not just the **spelling**."*
> — `tests/test_naming_variants.py:15`

The **permission engine** applies that rule to its allow/deny lists, its
kind map and its argument policies. The **scope-qualifier gate** did not —
slice 20 fixed that. The **deny hot path** did not — this slice fixes it.

The `naming_variants` probes are the repo's own instrument for this class
of bug, and they exercise `allowed_tools` / `disallowed_tools` /
`argument_policies` / `offensive` — **not** the deny hot path. The gap was
measurable and named.

## The scope's two halves get different treatment

A deny scope is `<subject>/<tool>`. The two halves are **not** the same
kind of thing.

### The tool half: an ACTION NAME — canonicalise it

* `sessions.canonical_action` defines the tool-call identity.
* `permissions.canonical_tool_name` is the same rule.
* `loop.py` dispatches `tool=spec.name` — the **registered** tool name.

### The subject half: an AGENT NAME — do NOT canonicalise it

`AgentRegistry.get()` is case-**sensitive**:

```python
# agents.py:401
def get(self, name: str) -> AgentDefinition | None:
    return self._definitions.get(name)
```

Two agents whose names differ only in case are **two agents**. Merging them
would merge two authorities — the error slice 20 avoided by keeping the
grant id verbatim.

So: **canonicalise the last half, keep the first half verbatim.** The same
split slice 20 made for `<grant id>/<verb>` (`canonical_scope_key`).

### The split point

The tool half is the part after the **last** `/`. Measured: no tool-name
literal in the runtime's tree contains a `/` (147 literals, 0 with a
slash), so the split is unambiguous in practice. A scope with **no** `/` is
kept verbatim — it is not a compound scope, and guessing at it would be
worse than reading it as written.

## What the slice builds

### 1. One canonical deny-scope key, defined once

`canonical_deny_scope()` in `deny_hotpath.py`:

* non-string / empty / over-long → refused (the existing `_check_scope`
  rules, unchanged);
* split on the **last** `/`;
* the **first half is kept verbatim** (an agent name — an identifier);
* the **second half is canonicalised** (strip + casefold — an action name);
* a scope with no `/` is kept **verbatim**;
* the canonical form is length-checked **again**, because casefolding can
  *lengthen* a string (`"ß"` folds to `"ss"`), so a scope within the cap
  can canonicalise past it.

It reuses the rule the runtime already states twice and does not invent a
third one.

**It lives in `deny_hotpath.py`, not in `permissions.py` or
`scope_qualifier.py`.** The module carries a stdlib-only self-check whose
allowlist is `{"__future__", "ast", "dataclasses", "hashlib", "json",
"pathlib", "sqlite3", "threading", "time", "typing"}` — importing the
helper from another module would make the self-check fail. The rule is
shared; the *implementation* is local, and that is stated rather than
hidden.

### 2. The key is canonical on BOTH sides

The scope is a **key written by one side and read by the other**:

| # | where | now | after |
|---|---|---|---|
| 1 | `DenyStore.set_state` (the write side: `revoke`, `clear`) | `WHERE scope = ?` with the raw scope | the row is filed under the canonical key |
| 2 | `DenyStore.lookup` (the read side) | `WHERE scope = ?` with the raw scope | the lookup uses the canonical key |
| 3 | `DenyStore.counter` (the reporting read) | raw | canonical |
| 4 | `DenyStore.explain_lookup` | raw | canonical |

Both sides go through **one** function, so they cannot drift — the
argument `refusal-hold-wiring.md` §2 makes about the refusal hold's key.

### 3. The RECORD keeps the host's verbatim scope

Slice 20 established the shape and this slice follows it: **the key is
canonical; the record is verbatim.**

The `deny_log.scope` column keeps the scope **exactly as the caller wrote
it**, because it is the audit trail: a reader must see what the host wrote
and what the dispatch actually asked for, not a normalised form of it. The
`revocation_counter` row is the **decision state** — the thing a lookup
seeks — so its key is canonical.

### 4. The lookup stays ONE indexed read

The coordinator's decision (`deny-hotpath.md`) is not to be re-litigated:
*"the deny lookup must be a single indexed read, and that fact belongs in
the acceptance tests."* Canonicalisation must not change the **shape** of
the SQL.

Measured, on SQLite, for each candidate shape:

| shape | query plan |
|---|---|
| `scope` is the PRIMARY KEY, `WHERE scope = ?` | `SEARCH ... USING INDEX sqlite_autoindex (scope=?)` |
| a separate column with a UNIQUE index, `WHERE scope_key = ?` | `SEARCH ... USING INDEX i (scope_key=?)` |
| a separate column with **no** index | `SCAN` |
| the key wrapped in a function, `WHERE lower(scope) = ?` | `SCAN` |

So the canonicalisation happens in **Python**, before the parameter is
bound. The SQL keeps its shape: one statement, one primary-key equality,
one `SEARCH`. The four existing acceptance tests
(`test_lookup_executes_exactly_one_statement`,
`test_lookup_query_plan_is_a_seek_not_a_scan`,
`test_lookup_does_not_touch_the_deny_log`,
`test_the_lookup_stays_a_single_indexed_read_on_the_dispatch_path`) keep
passing **unmodified**.

### 5. The store's file format: a migration, because the key moves

The counter table's key is the thing that moves. An **existing** store file
has rows under the host's verbatim spelling, so the key must be migrated at
open time or those revocations would be **silently lost** — and a lost
revocation is exactly the failure this slice exists to close.

The migration:

* reads every row of `revocation_counter`;
* for each row whose key is not already canonical, re-files it under the
  canonical key;
* if two rows collapse onto one canonical key, the **denied** one wins (a
  revocation must never be weakened by a migration) and the surviving
  counter is the **higher** one (the counter is monotonic — a migration
  must not move it backwards);
* runs **once**, at open, inside the same lock as the schema.

The migration is an **open-time** statement, so the acceptance tests that
count statements after `reset_statements()` are unaffected — **provided**
the migration does not call `store.lookup()` or `store.write_refusal()`,
because `events` is never reset and `test_the_refusal_row_comes_first`
pins `events[0] == "refusal"`. The migration reads the counter table
directly, not through the store's own API, and it does not touch the deny
log (the joined statements are pinned by
`test_lookup_does_not_touch_the_deny_log`).

## What is **not** touched

* The **subject half** is not canonicalised. Two agents differing only in
  case are two agents.
* The **fail-closed** behaviour is unchanged: an unreadable counter still
  denies, and a refusal row that cannot be written still denies.
* The **dispatch order** is unchanged: refusal row, then lookup, then
  finalize.
* The **refusal log's** `scope` column keeps the verbatim scope.
* The **permission engine**, the **scope-qualifier gate**, the
  **cancellation gate**, and the **refusal hold** are untouched.
* The **host's vocabulary** is not narrowed: a host may still revoke the
  exact string it looks up. The slice changes which strings *collide*, not
  which strings are accepted.
* **No new module** — the six pinned module counts (flat 1614, installed
  1637) do not move. The module's version pin and schema pin are
  unchanged.

## The neighbour defects, stated and NOT fixed here

### 1. The refusal hold's ACTION half is verbatim

`refusal_hold_wiring.refusal_hold_key("g1", "Lookup")` produces the identity
`task:g1:Lookup`, while `sessions.canonical_action("Lookup")` is `lookup`.
Measured on the seal path: a refusal recorded for `Lookup` blocks the seal
of `Lookup`, and the seal of `lookup` **SEALED**. Same shape, different
module — and the refusal hold's key is a three-part identity with its own
design doc.

### 2. `forward_seal_ledger.set_tombstones` has NO production caller

Measured by AST import scan: `refusal_hold` is imported only by
`refusal_hold_wiring.py` and two test files; `refusal_hold_wiring` is
imported only by its own test file. Neither the cancellation registry nor
the refusal registry is reachable from production, and
`forward_seal_ledger.append_grant` likewise has no production caller (the
runner uses `ledger.append`). So a recorded refusal does not yet block a
seal in production **at all**, whatever its spelling.

**Why not here:** fixing (1) alone would close a bypass in a gate that is
not wired into production; fixing (2) is a **wiring** change with a much
larger blast radius than a key canonicalisation, and it is a different
defect class (a record that is never consulted) from this one (a record
that is consulted under the wrong key). Both are measured, and neither is
hidden.

## The honest ceiling

* The canonicalisation is **case and whitespace**. It does **not** fold
  shell aliases (`Shell` vs `Bash`), neutral renames (`DataExport` for an
  exfiltration tool), or any other semantic synonym. The permission engine
  does not fold those either — it has a separate, explicit `tool_kinds` map
  for the alias case — and this slice does not invent a synonym vocabulary.
* Two **registered** tools whose names differ only in case are two tools to
  the registry, and after this slice one revocation covers both. That is
  the safe direction (over-blocking), and it is the same trade the
  permission engine already makes for `allowed_tools` / `disallowed_tools`.
* The deny store is **off by default** (`deny_store_path` is opt-in), so
  the defect only bites a host that wires it. This slice does not change
  that default.
* A deny scope whose **subject half** is not an agent name (a host that
  revokes `svc/Write` against a *service* rather than an agent) is
  canonicalised in the **tool** half only — so `svc/Write` and `svc/write`
  are one scope, and `Svc/Write` is a different one. That is the intended
  split, and it is stated rather than assumed.
* The migration handles the rows it finds. A store file that is corrupt in
  a way `sqlite3` cannot read is still a store that cannot answer, and
  the lookup fails closed.

## Open items

Carried forward from `scope-qualifier-check.md` §6, through
`scope-verb-canonical.md`:

1. **Prompt-level restrictions are not yet structured.** A user prompt
   that says "only touch folder X" does not become a `GrantRecord` unless
   the host puts it there.
2. **The source can be gone.** The check fails closed when the source line
   is missing, which is safe but means a long-running agent whose sidecar
   was pruned blocks rather than narrows.
3. **The wildcard vocabulary is closed.** `all` / `every` / `any` / `*` /
   `everything` mean unbounded.
4. **The check is per-verb.** The registry keys the denial row by
   `grant_id/verb`. A grant that authorizes several verbs needs a row per
   verb; there is no wildcard verb yet.
5. **The fallback ledger is in the host's JSON file.** Enough for one
   process family; a multi-host deployment needs a shared transactional
   store.
6. **The grant id is case-sensitive on purpose.** Two ids that differ only
   in case are two grants. A host that mints ids by case-folding a name
   must fold it itself, at the point of minting.

Added by this slice:

7. **The refusal hold's action half is still verbatim.**
   `refusal_hold_key("g1", "Lookup")` is `task:g1:Lookup` while
   `sessions.canonical_action("Lookup")` is `lookup`. Measured: the seal
   of `lookup` SEALED while a refusal was recorded for `Lookup`.
8. **`forward_seal_ledger.set_tombstones` has no production caller.**
   Measured by AST import scan: neither the cancellation registry nor the
   refusal registry is reachable from production, and
   `forward_seal_ledger.append_grant` has no production caller either. So
   a recorded refusal does not yet block a seal in production at all. This
   is a **wiring** gap, not a key gap.
9. **`SourceStore` keys by `source_ref` verbatim.**
   `SourceLine.__post_init__` validates but does not strip, so a
   `source_ref` written as `" src-1 "` is stored under that spelling and
   is invisible to a gate asking for `"src-1"`. Measured: `fetch("src-1")`
   returns `None`. The same "the key is written by one side and read by
   the other" shape, in a module this slice did not touch.
10. **The deny hot path's own `stdlib_only()` guard read only its own
    clean source**, so its branches were unreachable from any test and a
    planted fault in it survived every probe. This slice made the guard
    take the source to check, and a crafted input found a real hole in it:
    a **relative import** (`from . import sibling`) parses with
    `module=None`, so the guard's "not in allowed" test never ran on it
    and the import passed. The guard now refuses relative imports. The
    same pattern is almost certainly present in the other 1349 modules
    that carry the same guard.
