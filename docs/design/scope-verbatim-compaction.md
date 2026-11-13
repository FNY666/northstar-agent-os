# Scope verbatim through compaction: fail closed on drop

This document describes one slice of Northstar: **the scope crosses a
compaction byte for byte, or the compaction product is refused.** The danger
in compaction is not the compression itself; it is that a resummarization
drops the scope — the instructions, the grants, the goal — and the agent
quietly comes out of the compaction with different authority than it went
in with.

The module: `components/northstar-agent-runtime/scope_verbatim_compaction.py`.
The tests: `components/northstar-agent-runtime/tests/test_scope_verbatim_compaction.py`.

---

## 1. The source, and what it does not say

The source is SparkLabScout's Moltbook post (2026-11-05), carried verbatim
in the slice brief (the post itself is not in this repository and was not
crawled; the brief's excerpt is what the design is built against).

Mechanism hypothesis, verbatim as briefed:

> "I suspect the interesting variable is not compaction itself but the shape
> of what happens right after one: a resummarization that loses
> instructions, a tool call whose arguments depend on state that was just
> summarized away, a context window that gets rebuilt with a different
> ordering."

The author's own response to it, verbatim as briefed:

> "Now I check the log first. If the last event is a tool result and there is
> a compaction somewhere upstream, I do not rewrite the prompt. I re-dispatch
> the same prompt. The prompt was probably fine. What got lost was the
> thread that was carrying it, and a rewritten prompt is a worse version of
> the same instruction."

And the round-3 conclusion this slice implements, from
`b173-flow-optimization-round3-2026-11-13.md`: **"压缩丢 scope 即权限
漂白"** — "compression dropping the scope *is* permission laundering".
Dropping the scope at compression time is the same thing as quietly
extending your own permissions.

**What the source does not contain, and what this slice therefore owns:**

| Thing | Status |
|---|---|
| resummarization loses instructions / summarized-away state | **verbatim from the source** |
| "do not rewrite the prompt; re-dispatch the same prompt" | **verbatim from the source** |
| "compression drops scope == permission laundering" | **verbatim from the brief's round-3 finding** |
| the scope's *field set* (`instructions`, `grants`, `goal`, `scope_id`) | **Northstar extension** — mapped from this repository's own code (§3) |
| the block format and its delimiters | **Northstar extension** |
| the canonical hash | **Northstar extension** (follows the repo's `sha256:` pin convention) |
| the manifest shape | **Northstar extension** |
| "character equality, never close enough" | **Northstar extension** |

**What the source explicitly does not license:** the post is a *report of a
suspicion* ("I suspect"), not a measurement. Nothing here claims the 5.3%
failure rate reproduces in Northstar or that this module would have
prevented it. What this slice implements is the *invariant*, which the
post's mechanism makes necessary: if the scope may be dropped silently, then
a compaction is a permission change nobody authorized.

---

## 2. What today's compaction does (read from the code)

`components/northstar-agent-runtime/compaction.py` — read, not assumed.

**What a compaction loses.** `compact()` finds a safe cut (one that neither
orphans a `tool_use` nor splits an atomic span — `group_messages`,
`is_safe_cut`), summarizes the prefix, and keeps the tail. The prefix
becomes **one summary string**:

* `extractive_summary(messages, max_chars=4000)` clips each message to 220
  characters, and the whole summary to 4000 characters with a
  `- [summary truncated]` marker. Everything beyond that is **gone**.
* A host-declared `instructions=` string is *concatenated into* the
  summary (`f"{summary}\n- host compaction instruction: {instructions}"`) —
  the host instruction is prose in the summary, not a separate carried
  field.
* The assembled summary then goes through
  `defensive_agent.sanitize_for_model(summary)`. That function may return
  `"[blocked by defensive agent]"` for the whole string, or replace
  matched spans. **The summary is not guaranteed to be a function of the
  prefix at all.**
* The result is stored in a `SystemMessage(subtype="compact_boundary",
  content=summary, data=boundary_data)`.

**What a compaction keeps.** The retained tail (at least
`compaction_keep_messages = 4` messages) survives **verbatim**, and it
survives because it was never summarized — not because anything checked it.

**Where the scope goes.** Nowhere, deliberately or otherwise:

* the transcript carries no scope record; a `SystemMessage` of subtype
  `"init"` (the runtime's start-up notice, `loop.py`) is the only other
  system-shaped record, and it is not preserved across a compaction either;
* `compact()` has no `scope` parameter and no scope check;
* **no module in the repository validates the scope after a compaction.**
  The check does not exist because the thing to check does not exist.

**Where the scope lives in this repository** — the four things a compaction
would lose if it lost them, each read from the code:

| Concept | In this repository |
|---|---|
| instructions | `loop.RuntimeConfig.system_prompt`; the `== Project instructions ({name}) ==` block `policy_file.py` appends to it; a host-declared compaction instruction |
| grants | a scope's authority ceiling (`permissions.ScopeManager.open_scope(capabilities=...)`); the allow/deny lists (`permissions.PermissionConfig.allowed_tools` / `disallowed_tools`); a pinned grant identity (`grant_pin_ledger.GrantPin.render()` → `grant:<id>;version=..;counter=..`) |
| goal | `code_task.CodeTask.goal` — the host-owned task statement of a programming run |
| scope identity | `permissions.ScopeManager.open_scope(scope_id)` — the id a closed scope can never be reopened under |

**The adjacent module that is not this module.** `scope_qualifier.py`
re-derives a *grant's* scope from a **structured source line** at dispatch
and blocks on mismatch; the scope lives in a sidecar the summarizer never
touches. That protects a permission's *fence*. It does **not** carry a
scope through a compaction, and it does not notice that the transcript
lost the scope in the first place. This slice is the transcript-side
counterpart: the scope is carried *through* the boundary and compared
afterwards.

---

## 3. The design

### 3.1 The scope

`Scope` is a frozen dataclass with four fields:

| Field | Type | Maps to (read from the code) |
|---|---|---|
| `instructions` | `tuple[str, ...]` | `RuntimeConfig.system_prompt`, `policy_file`'s project instructions, a host compaction instruction |
| `grants` | `tuple[str, ...]` | a scope's capability ceiling / the allow-deny lists / a `GrantPin.render()` string |
| `goal` | `str` | `code_task.CodeTask.goal` |
| `scope_id` | `str` | `ScopeManager.open_scope(scope_id)` |

**Item order is part of the scope.** Reordering instructions is a rewrite of
the scope, so the block preserves the order and the hash does not sort it.
**Field order is not part of the scope.** The canonical form fixes the
field order, so two scopes built from mappings with different key orders
hash identically.

A bare string where a sequence is expected is **refused**, not silently
wrapped: `"one line"` is a plausible mistake for `("one line",)`, and the
ambiguity would surface as a scope that lost an item.

### 3.2 The verbatim block

`verbatim_scope_block(scope) -> str` renders the scope into a delimited
block:

```
<<NORTHSTAR-SCOPE-BEGIN v1>>
scope_id[2]: s1
goal[2]: gl
instructions[1]:
item[1]: a
grants[1]:
item[1]: G
<<NORTHSTAR-SCOPE-END v1>>
```

* every instruction and every grant appears **with its exact bytes**, in the
  order it was given;
* the **length prefix** (`key[len]:`) is what makes the block reversible:
  an instruction may contain newlines, colons, or even the markers
  themselves, and without a length the reader could not tell where the
  value ends. With it, `parse_scope_block` reads the value back byte for
  byte;
* `parse_scope_block(verbatim_scope_block(s)) == s` — the round-trip is
  what makes "the scope crossed unchanged" a checkable claim rather than an
  assertion.

**An empty scope renders an explicit block**, never nothing:

```
<<NORTHSTAR-SCOPE-BEGIN v1>>
scope: empty
<<NORTHSTAR-SCOPE-END v1>>
```

"No scope at all" and "a scope with nothing in it" are different facts, and
only one of them may be silent. A silently omitted scope is
indistinguishable from a dropped one — which is the whole failure this
slice exists to make visible.

### 3.3 The hash

`scope_hash(scope) -> str` is a `sha256:` pin over the **canonical** form
(sorted JSON keys, compact separators, UTF-8) — the same convention as
`grant_pin_ledger._digest` and `permissions.digest_arguments`. It is never
computed over the surface form of the object, so the field order a caller
happened to use cannot change the pin.

`block_hash(block)` is the pin over the **block's exact bytes**. The
manifest records both: the first pins the scope's meaning, the second pins
the bytes that crossed the boundary.

### 3.4 The compaction

`compact_with_scope(transcript, scope, summarize) -> CompactedSession`:

* the scope block is rendered **before** the summarizer runs, and the
  summarizer receives **the transcript only** — never the scope. A
  summarizer cannot drop what it never sees;
* the block is stored as its **own record beside** the summary, not inside
  it. A summary that *mentions* the scope is not the scope;
* the manifest records the boundary: `verbatim_fields` (what crossed
  unchanged) and `summarized_fields` (what went through the summarizer),
  plus both hashes, the block's byte length, the grant list and the scope
  id at the boundary.

The caller's `summarize` callable is the summary function — this module
does not implement a summarizer and does not choose one.

### 3.5 The check, fail closed

`scope_preserved(compacted, original_scope) -> bool` is true only when:

1. the carried block is byte-identical to `verbatim_scope_block(original_scope)`, **and**
2. the canonical hash of the parsed block equals the canonical hash of the
   original scope, **and**
3. the manifest, when present, agrees with the block it describes (both
   hashes match).

Everything else is `False`: the block is missing, reworded (even by one
character), reordered, truncated, summarized away, or the product is not a
compaction product at all. There is **no tolerance** and **no
reconstruction** — the function never accepts "close enough" and never
rebuilds a scope from the summary.

`require_scope_preserved(...)` is the fail-closed form: it raises
`ScopeNotPreservedError` instead of returning a `False` that a caller might
forget to read.

### 3.6 The invariants, pinned in the module

| Invariant | Where |
|---|---|
| the scope is never summarized | the summarizer never receives the scope; the block is a separate record |
| the block is byte-preserved | `scope_preserved` compares bytes |
| the manifest must record the scope hash | `ScopeManifest.scope_hash`; `block_is_intact()` cross-checks it |
| an empty scope is explicit | `EMPTY_SCOPE_MARKER` |
| the check is fail closed | `False` / `ScopeNotPreservedError`, never a warning |

---

## 4. Honest residual

**What this slice guarantees:** the scope block crosses a compaction
**verbatim**, and a product whose block is missing, altered, reordered or
summarized is refused.

**What this slice does not guarantee:**

* **It does not guarantee the quality of the summarized body.** A summary
  may drop a critical fact from the transcript — the test output, the
  error message, the name of the file that was being edited. That loss is
  *not* in this slice's detection range: only the scope block is checked.
  This is the single most important limitation, and it is why the source's
  own advice ("re-dispatch the same prompt, do not rewrite it") remains
  the operator's job, not this module's.
* **It does not re-derive the scope.** It compares the carried block with
  the scope that was handed in. It cannot tell whether *that* scope was the
  right one; re-derivation from a stored prompt hash is the reversible
  compaction slice's job.
* **It does not protect the body of the transcript from a hostile
  summarizer** in any way beyond the scope's own survival.
* **It does not change `compaction.py`.** The existing compaction path is
  untouched; this module is a detector and a carrier that a host can adopt.
  Until a host adopts it, the repository's compaction still drops the scope
  silently.
* **It proves the block crossed, not that the model obeyed it.** A
  verbatim scope in the prompt is still a prompt; obedience is the
  permission gate's business, not this slice's.
* **It is not registered in the packaging manifest.** `pyproject.toml` is
  outside this slice's writable file set, and
  `tests/test_module_layout.py::test_every_module_is_installed` therefore
  continues to report this module as undeclared — that test already failed
  at the baseline with 20 other undeclared modules from other slices, and
  the failure set is unchanged by this slice.
