# A verb must have one identity, or the gate never looks

**Batch 173, slice `scope-verb-canonical`.**

## The defect

The runtime has a rule about spelling, stated in its own code and in its
own naming-variant probes:

> *"The gate must deny the **action**, not just the **spelling**."*
> — `tests/test_naming_variants.py:15`

and

> *"Strips whitespace and casefolds, so `"  Bash "`, `"bash"` and `"BASH"`
> all resolve to the same identity. A forbidden action can't slip through
> via spelling variants."*
> — `permissions.canonical_tool_name`, `permissions.py:1255`

The **permission engine** applies that rule.  The **scope-qualifier gate**
did not — and the scope-qualifier gate is the one that decides whether a
grant's *fence* still holds.

### Measured, on the runtime's own dispatch path

A real `AgentRuntime`, a real `ToolRegistry`, a real scope-registry
sidecar.  The grant's fence is **dropped** in every row of the table —
that is the case the gate exists to catch.

| the grant's verb | the tool called | handler ran? | denied? | `permission_source` |
|---|---|---|---|---|
| `"Lookup"`  | `Lookup` | **no**  | yes | `deny:scope` |
| `"lookup"`  | `Lookup` | **YES** | no  | `allowed_tools` |

Same grant.  Same dropped fence.  Same tool.  The only difference is the
**case of the verb string in the host's registry JSON**.

The gate never looked.  `GovernedActionRunner._check_scope` does:

```python
grants = registry.presented_for(tool)     # tool = spec.name = "Lookup"
if not grants:
    return None                            # <- the gate is SKIPPED entirely
```

and `ScopeGrantRegistry.presented_for` compared the verb **verbatim**:

```python
def presented_for(self, verb: str) -> Tuple[GrantRecord, ...]:
    return tuple(
        grant for grant in self._presented.values() if grant.verb == verb
    )
```

So the grant that says `"verb": "lookup"` is not the grant that authorizes
`Lookup`.  The gate finds no presented grant, returns `None`, and the
dispatch proceeds.

### The second measured bypass: the denial row's scope

The denial row is keyed by `f"{grant_id}/{verb}"`.  The row is the
*authority* — conclusion 96 says the gate must get a row or a signed proof
of no-denial.  Measured:

| the grant's verb | the row's scope | the row says | handler ran? | denied? |
|---|---|---|---|---|
| `"Lookup"` | `grant-1/Lookup` | `denied` | **no** | yes |
| `"lookup"` | `grant-1/Lookup` | `denied` | **YES** | no |
| `"Lookup"` | `grant-1/lookup` | `denied` | **YES** | no |

The second and third rows are the sharp ones: **the row says `denied`, and
the action runs.**  A row that explicitly refuses the scope is read as
absent because the scope string differs by one letter of case — and "no
row" is not a clean read either (the gate would have called it
`outcome_unknown` if it *had* looked), so the refusal row simply
evaporates.

### The asymmetry that makes this a defect and not a design choice

Inside the **same module**, the fence's *resources* are already compared
case-insensitively:

```python
def _scope_atoms(qualifiers):
    return frozenset(f"{q.kind}:{q.resource.lower()}" for q in qualifiers)
```

and the qualifier's `kind` is lowercased at construction
(`scope_qualifier.py:198`), and `permitted_targets` lowercases the resource
(`scope_qualifier.py:522`), and `scope_tokens` lowercases
(`scope_qualifier.py:783`).

So the module said: *"the resource `Folder X` and the resource `folder x`
are one resource"* — but *"the verb `Lookup` and the verb `lookup` are two
different verbs"*.  **The fence is case-insensitive and the verb was not.**
That is not a policy; it is an inconsistency, and the inconsistency is the
hole.

## The decision

Three changes, in one module, with one rule.

### 1. One canonical verb, in one place

`scope_qualifier.canonical_verb(verb)` — whitespace stripped, casefolded,
the **same** rule `permissions.canonical_tool_name` already applies to a
tool name, for the **same** stated reason (a spelling variant must not
escape a gate).

The rule already exists in the repository; this slice does not invent a
second one.  It gives the scope-qualifier gate the treatment the
permission engine has had since the naming-sensitivity finding (~Oct
2026).

A malformed verb is **refused**, not normalised into something: an empty
verb would name *every* action.

### 2. The grant's own verb is normalised at construction

`GrantRecord.__post_init__` sets `verb = canonical_verb(verb)`, so a
grant has **one** verb identity from the moment it is built.  The
presented-grant lookup is then true *by construction*, not by a comparison
rule someone has to remember.

The **grant id** is **not** canonicalised.  It is an identifier minted by
whatever declared the grant, and two ids that differ only in case are two
grants.  (Verified: `presented_for` returns two grants for two ids that
differ only in case, and one grant for two verbs that differ only in case.)

### 3. One canonical scope key, used by **both** sides

`canonical_scope_key(scope)` splits a denial-row scope into
`<grant id>/<verb>` and canonicalises **only the verb half**:

* the **grant id** half is an identifier — kept verbatim;
* the **verb** half is an action name — canonicalised.

`DenialRowStore.put()` files a row under that key and
`DenialRowStore.fetch()` looks it up under the same function, so the
recording side and the checking side cannot drift apart — the same
argument `refusal-hold-wiring.md` §2 makes about the refusal hold's key.
The row's own `scope` string stays verbatim.

A scope with no `/` is kept verbatim: it is not a grant/verb scope, and
guessing at it would be worse than reading it as written.

## What is **not** touched

* The **fence** comparison.  It was already case-insensitive;
  `scope_relation`, `permitted_targets`, `_scope_atoms` and the
  source/presented comparison are unchanged.
* The **source store**, the **source ref** and the **source line**.  A
  source ref is an opaque identifier, compared verbatim, as it must be.
* The **grant id**.
* The **permission engine**.  It already canonicalises.
* The **deny hot path**.  See below: measured, named, left open.
* **No new module** — the six pinned module counts (flat 1614, installed
  1637) do not move.

## The neighbour defect: measured, named, and NOT fixed here

The **deny hot path** has the same shape.  Measured on the same runtime:

```
store.revoke("main/Bash", reason="revoked by operator", seq=1)

call 'Bash'   -> ran=False denied=True  source='deny:hotpath'
call 'bash'   -> ran=True  denied=False source='allowed_tools'
```

`GovernedActionRunner._deny_scope(subject, tool)` builds
`f"{subject}/{tool}"` from the **raw** tool name, and `DenyStore.lookup` is
an exact-key seek.  So a revoked scope is bypassed by a case variant —
**provided the variant is also a registered tool** (with only `Bash`
registered, `bash` is refused earlier by the permission engine's
`unknown_tool` rule, which is the correct answer for a different reason).

**This slice does not fix the deny hot path.**  Two reasons, both measured:

1. The deny store's scope is a **compound** string (`<subject>/<tool>`)
   whose subject half is the agent name and whose tool half is the tool
   name.  Canonicalising it means deciding what the *subject* half's
   spelling rules are — and the subject is not a tool name.  The compound
   scope needs its own design; bolting a tool-name canonicaliser onto
   half of it would be a guess.
2. The deny hot path's scope vocabulary is **closed by the host**, not
   derived: the host revokes the exact string it will look up.  A
   canonicalisation there changes which strings a host may revoke, which
   is a semantic change to a module with its own design doc
   (`docs/design/deny-hotpath.md`) and its own acceptance coverage.

The bypass is measured, named, and left as an open item.  It is not
hidden, and it is not half-fixed.

## The honest ceiling

* The canonicalisation is **case and whitespace**.  It does NOT fold shell
  aliases (`Shell` vs `Bash`), neutral renames (`DataExport` for an
  exfiltration tool), or any other semantic synonym.  The permission
  engine does not fold those either — it has a separate, explicit
  `tool_kinds` map for the alias case — and this slice does not invent a
  synonym vocabulary.
* The gate is a **pre-execution** check.  A call already in flight is not
  recalled.
* A grant that a host *intends* to be about a different verb — two
  genuinely different tools whose names differ only in case — would be
  treated as one.  The tool registry is case-sensitive
  (`tools/__init__.py:1143`), so `Bash` and `bash` are two registered
  tools; after this slice, a scope grant naming one of them covers both.
  That is the safe direction (over-blocking), it is the same trade the
  permission engine already makes for `allowed_tools`/`disallowed_tools`,
  and it is stated here so no reader has to infer it.

## Open items

Carried forward from `scope-qualifier-check.md` §6:

1. **Prompt-level restrictions are not yet structured.**  A user prompt
   that says "only touch folder X" does not become a `GrantRecord`
   unless the host puts it there.
2. **The source can be gone.**  The check fails closed when the source
   line is missing, which is safe but means a long-running agent whose
   sidecar was pruned blocks rather than narrows.
3. **The wildcard vocabulary is closed.**  `all` / `every` / `any` / `*`
   / `everything` mean unbounded.
4. **The check is per-verb.**  The registry keys the denial row by
   `grant_id/verb`.  A grant that authorizes several verbs needs a row
   per verb; there is no wildcard verb yet.
5. **The fallback ledger is in the host's JSON file.**  Enough for one
   process family; a multi-host deployment needs a shared transactional
   store.

Added by this slice:

6. **The deny hot path's scope spelling is still uncanonicalised.**
   Measured above: `store.revoke("main/Bash")` does not stop a call to
   `bash` when both are registered tools.  The fix needs a decision about
   the *subject* half's spelling rules — a compound scope's vocabulary is
   not the tool-name vocabulary — and a change to the set of strings a
   host may revoke.  It is a slice of its own.
7. **The grant id is case-sensitive on purpose.**  Two ids that differ
   only in case are two grants.  A host that mints ids by case-folding a
   name must fold it itself, at the point of minting; the gate cannot
   tell "the same grant spelled twice" from "two grants".
