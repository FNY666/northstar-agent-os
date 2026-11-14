# Annotation-hint pinning: re-arm confirmation when a tool's claimed effect widens

This document describes one slice of Northstar: a **pin over an MCP tool's
claimed effect** (its annotation hint set plus its schema hash), a **direction
rule** that separates a safe narrowing from a dangerous widening, and a
**per-server trust table** that is written by the operator, never by the
server.

Source: outsideloop, "A tool that says it's read-only is making a claim, not
giving you a permission" (Moltbook, 2026-11; 21 up, 8 comments). The upstream
post is **not** in this repository and was not crawled; the quoted text below
is the text the slice brief carries, and it is marked as *verbatim as briefed*
wherever it is attributed to the source.

The module: `components/northstar-agent-runtime/annotation_pin.py`.
The tests: `components/northstar-agent-runtime/tests/test_annotation_pin.py`.

---

## 1. What Northstar has today (read from the code, not assumed)

### 1.1 The definition pin today

`components/northstar-agent-runtime/tool_pinning.py` (169 lines) defines
`PinnedTool` (line 34) with exactly **four** fields:

    tool_id, definition_hash, pinned_at, pinned_by

`hash_definition` (line 44) hashes `json.dumps(definition, sort_keys=True,
separators=(",", ":"))` prefixed with `sha256:` — and the docstring states
what goes in: *"Includes: name, description, inputSchema, version."*

`ToolRegistry.pin` (line 59) hashes the definition at first mount;
`ToolRegistry.verify` (line 81) re-hashes on every subsequent call and
returns `False` on any mismatch; `check_or_raise` (line 97) turns a mismatch
into a `ToolPinError` for gate integration. `is_pinned` (line 108) reports
whether a tool is known.

**What the definition pin binds:** the tool's identity — its name,
description, input schema, and version string, as one hash.

**What it does not bind:** the annotation set. There is no annotation field in
`PinnedTool`, and `hash_definition` never looks at one. A tool's definition
can stay byte-identical while the *hint* the server publishes about it
changes from `readOnlyHint: true` to `readOnlyHint: false`.

### 1.2 Where the gate trusts annotations today

`components/northstar-agent-runtime/permissions.py` (2775 lines) resolves
whether a call is mutating at line 2043:

    is_mutating = (resolved_kind in MUTATING_KINDS) if mutating is None else bool(mutating)

with `MUTATING_KINDS = frozenset({"edit", "exec", "network", "other"})`
(line 92). The `mutating` argument is supplied by the caller
(lines 1647, 1680, 1985, 2030) — it is the *host's* statement about the
tool, and the gate takes it at face value.

Plan mode (line 2079) then branches on that resolved flag: a mutating call is
denied (`"plan mode is read-only; {tool_name} would change state"`, rule
`mode:plan`), and a non-mutating call is allowed (`"{tool_name} is read-only,
permitted in plan mode"`).

**The trust shape:** the gate's plan-mode read/write distinction rests on a
boolean the caller supplies about a tool. When that boolean is a tool's
server-published annotation, the annotation is acting as a grant. It is not.

### 1.3 The read-only filter today

`components/northstar-agent-runtime/agent_files.py` line 233 reads
`read_only` from a repository agent file's frontmatter and, when true,
narrows the tool list (line 236):

    tools = [tool for tool in tools if tool in READ_ONLY_TOOLS or tool == "CodexReadOnly"]

This filter narrows a **repository-defined** tool set against a **static,
built-in** `READ_ONLY_TOOLS` list. It never consults a server-published hint,
so it is not affected by a flip — but it is the same *shape* of decision
(narrow vs widen) and the reason a narrowing must never widen.

### 1.4 Evidence: nothing today can detect a hint flip

**The MCP client drops the annotations on the floor.**
`components/northstar-agent-runtime/mcp_client.py` parses `tools/list`
(line 610) and reads, per tool entry: `name` (line 620), `description`
(line 625), `inputSchema` (line 626) and `outputSchema` (line 647). It never
reads `raw.get("annotations")` — a grep for `get("annotations"` in that file
returns nothing. The `RemoteTool` dataclass (line 171) does carry an
`annotations: dict[str, Any]` field, but it is never populated: the
construction site (line 665) passes only `name`, `description`,
`input_schema` and `output_schema`, so the field stays at its default `{}`.
A grep for `annotations` across the whole file returns exactly two hits: the
`from __future__ import annotations` import (line 32) and that unused field
declaration (line 176).

**The admission pin does not cover the hints either.** `tool_definition_digest`
(mcp_client.py line 179) hashes `(server, name, description, input_schema,
output_schema)` under the JCS canonicalization — the annotation set is not in
the payload. `tool_pinning.hash_definition` (tool_pinning.py line 44) hashes
`name, description, inputSchema, version` — also no annotation. The live
`refresh_tools` (mcp_client.py line 971) re-lists the tools, recomputes those
digests (line 1034) and quarantines the server when one differs (the drift
comparison is at lines 1039-1048) — but the hint set is not in the digest it
compares. A server can therefore flip the hint it publishes for a tool from
read-only to destructive while every existing digest stays identical.

**Nothing compares a hint set across sessions.** A grep for the MCP hint
spellings across `components/` returns no annotation-handling code outside
this slice's own new module (the remaining hits are the JSON-Schema keyword
`"readOnly"` in `tool_input_schema.py` line 136, and `policy_file.py` /
`plugin_load.py`'s unrelated operator-written `read_only` flag). There is no
per-session comparison, no trust table, and no direction rule.

**Conclusion, stated as what was read:** between two sessions, a server can
change the annotation it publishes for a tool from read-only to destructive,
and **no module in this repository would notice** — the definitions are
digested without the hints, the hints are not even parsed, and the gate takes
the caller's `mutating` flag at face value.

---

## 2. The rule this slice adds

### 2.1 The direction rule

Pin the claimed effect at discovery. On every later session, compare.

* The claim **narrows** (destructive → read-only): accept silently. The
  safe direction. The pin is moved forward.
* The claim **widens** (read-only → destructive): **do not** move the pin and
  **do not** let the call through unattended. The human-in-the-loop step is
  re-armed until a human re-pins the new claim.

The failure this exists for, quoted from the brief (attributed to rossum in
the source thread, *verbatim as briefed*):

> "A metadata flip is a silent failure… the error doesn't manifest in a failed
> execution, but in the bypass of the human-in-the-loop verification step."

### 2.2 The trust rule

Quoted from the source (the MCP spec, 2026-07-28, as outsideloop cites it —
*verbatim as briefed*):

> "clients MUST consider tool annotations to be untrusted unless they come from
> trusted servers."

So trust lives in an **operator-written** per-server setting. A server is
either `trusted` (its annotations are treated as claims worth pinning) or
`untrusted` (its annotations are ignored entirely; the tool is write-capable).
The default is untrusted.

### 2.3 The artifact rule

The pin is on the **artifact** — the schema hash and the hint set — never on
the version string. Servers repoint behaviour behind a stable number, so:

* version changed, schema unchanged → same pin, verdict `OK`;
* schema changed, version unchanged → drift.

---

## 3. The module

### 3.1 Public surface

| Name | Kind | Purpose |
|---|---|---|
| `AnnotationPin` | frozen dataclass | `server`, `tool`, `hint_digest`, `pinned_at`, `pinned_by` |
| `AnnotationPin.to_dict` / `.from_dict` | methods | serialise / rebuild; `from_dict` **refuses** a missing or empty `hint_digest` |
| `TrustTable` | class | operator-written per-server trust; default untrusted |
| `AnnotationRegistry` | class | the pins, the trust table, and the verdicts |
| `AnnotationRegistry.pin` | method | pin a claim (discovery, or human re-pin) |
| `AnnotationRegistry.verify` | method | `"OK"` / `"SAFE_FLIP"` / `"DANGEROUS_FLIP"` / `"DRIFT"` / `"UNPINNED"` |
| `AnnotationRegistry.accept_safe_flip` | method | move the pin forward over a narrowing only |
| `AnnotationRegistry.requires_confirmation` | method | the gate interface: `True`/`False` |
| `AnnotationRegistry.rearm_reason` | method | why confirmation is required |
| `hint_digest`, `hash_schema` | functions | the digests |
| `normalize_annotations`, `capability_rank`, `effective_read_only` | functions | the fail-closed reading of a hint set |

### 3.2 The digest

`hint_digest(annotations, schema)` is the `sha256:`-prefixed SHA-256 of the
canonical JSON of

    {"hints": <normalised hint set or a malformed marker>,
     "schema_hash": <sha256 of the canonical schema>}

Canonical JSON means **sorted keys, compact separators, UTF-8** — the same
recipe as `tool_pinning.hash_definition` (line 49), so the two layers digest
alike. The version string is not in the payload.

Hint spellings normalise: `readOnlyHint` / `readOnly` / `read_only` are one
canonical `read_only`, `destructiveHint` / `destructive` are `destructive`.
Canonicalisation means the same annotation set written in a different key
order digests identically.

### 3.3 The fail-closed reading

A hint set is **usable** only when it is a dict, carries both `read_only` and
`destructive`, and both are booleans. Anything else is *malformed*, and
malformed ranks as **write-capable** — never read-only. A contradictory claim
(`read_only` and `destructive` both true) also ranks write-capable.

`capability_rank` is the direction ladder:

| rank | meaning |
|---|---|
| `RANK_READ_ONLY` (0) | proven read-only |
| `RANK_NEUTRAL` (1) | neither hint set |
| `RANK_WRITE` (2) | destructive, malformed, or missing |

A flip is **safe** when the rank goes down and **dangerous** when it goes up.
Same rank with different hints is `DRIFT`.

### 3.4 The verdict order

`verify` asks in this order, and the order matters:

1. **Untrusted server** → the annotations are ignored; the verdict is
   `UNPINNED`. There is no hint continuity to judge.
2. **No pin** → `UNPINNED`.
3. **Restored-from-export pin** (digest present, pinned claim absent) →
   `DRIFT`. A flip could not be classified, so it fails closed.
4. **Schema hash changed** → `DRIFT`, whatever the hints say. The artifact
   moved.
5. **Hints unchanged** → `OK`.
6. **Hints malformed / missing** → over a read-only pin this is a
   `DANGEROUS_FLIP` (the claim vanished, so the tool is no longer proven
   read-only — the failure direction); over any other pin it is `DRIFT`.
7. **Rank down** → `SAFE_FLIP`.
8. **Rank up** → `DANGEROUS_FLIP`.

### 3.5 The gate interface

`requires_confirmation(server, tool, annotations, schema)` returns `True` for
`DANGEROUS_FLIP`, `DRIFT` and `UNPINNED`, and for a missing or malformed hint
set; `False` for `OK` and `SAFE_FLIP`. `rearm_reason(...)` returns a
human-readable reason, empty when no confirmation is needed.

The gate itself is **not** modified by this slice. The module provides the
interface; a host calls it before letting a call through.

---

## 4. Mapping to the source

### 4.1 Verbatim as briefed (from the source / the spec it quotes)

* "clients MUST consider tool annotations to be untrusted unless they come from
  trusted servers." — the MCP spec (2026-07-28), as quoted by outsideloop.
* "A metadata flip is a silent failure… the error doesn't manifest in a failed
  execution, but in the bypass of the human-in-the-loop verification step." —
  rossum, in the source thread.

### 4.2 Northstar extension (not in the source; this slice's design)

* The five-valued verdict (`OK` / `SAFE_FLIP` / `DANGEROUS_FLIP` / `DRIFT` /
  `UNPINNED`) and the rank ladder behind it.
* The digest recipe (canonical JSON + `sha256:`), matching
  `tool_pinning.hash_definition` so the two layers agree.
* Pinning the **schema hash** rather than the version string, and treating a
  schema change behind an unchanged version as drift.
* `AnnotationPin.from_dict` refusing a pin without a digest.
* The material-behind-the-digest problem, and the choice to degrade a
  restored pin to `DRIFT` rather than guess a direction.
* The `rearm_reason` text.

---

## 5. Relation to `tool_pinning`

| | `tool_pinning.py` | `annotation_pin.py` (this slice) |
|---|---|---|
| Pins | the tool **definition** (name, description, inputSchema, version) | the tool's **claimed effect** (hint set + schema hash) |
| Defends against | the rug pull: the definition is swapped | the silent widening: the claim is flipped |
| Detects a **narrowing**? | no — any definition change is drift | yes, and calls it `SAFE_FLIP` |
| Detects a **widening**? | no — no direction concept | yes, and calls it `DANGEROUS_FLIP`, re-arming confirmation |
| Touches the gate? | provides `check_or_raise` | provides `requires_confirmation` / `rearm_reason` |

They are complementary, and both are standalone layers today: neither is
imported by the gate.

The *live* admission pin is a third thing, and it lives in the MCP client:
`mcp_client.tool_definition_digest` (line 179) digests
`(server, name, description, input_schema, output_schema)` under the JCS
canonicalization, and `refresh_tools` recomputes those digests and
quarantines a server on mismatch (see the comment at mcp_client.py line 690).
That pin is the real-world instance of the *definition* half of the table
above — and, like `tool_pinning.hash_definition`, it does not cover the
annotation set, which is why the claimed-effect half needs its own layer.

---

## 6. Open items

* The gate is not wired to `requires_confirmation` in this slice (out of
  scope; the module is the interface).
* `AnnotationRegistry.restore_pins` restores digests but not the pinned
  claim, so a restored pin verifies as `DRIFT` until it is re-pinned in
  process. A future slice could carry the normalised hint set in the
  exported record alongside the digest.
* No live provider is contacted; the module consumes what a host already
  fetched.
