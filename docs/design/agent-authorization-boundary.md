# Agent authorization boundary: authority is a boundary, not a prompt

**Slice:** `agent-authorization-boundary`
**Module:** `components/northstar-agent-runtime/agent_boundary.py`
**Tests:** `components/northstar-agent-runtime/tests/test_agent_boundary.py`
**Date:** 2026-11-25

---

## 1. What this slice is

Northstar authorizes *actions*. It has `permissions.py` (the three-layer tool
gate), `grant_pin_ledger.py` (a grant pin that may be sealed), and
`forward_seal_ledger.py` (a sealed record of what was done). What it does not
have is an object for **the authority itself**: when a delegation grants an
agent the right to read `/workspace` until a deadline, "the right to read
`/workspace` until a deadline" is not a first-class thing anywhere in the
runtime. It is spread across a permission set, a pin, and a timestamp held
by the caller.

This slice adds that object and the rules that make it safe to hold.

---

## 2. Sources, and what is verbatim

Two sources. Every claim attributed to a source below is quoted from the
survey's own source record (`docs/design/frontier-expansion-survey.md` §2.3
and §2.4), which quotes them from the upstream READMEs.

### 2.1 agent-guard — https://github.com/agent-rails/agent-guard

Verbatim:

> "Policy is evaluated before the tool runs; denied calls never reach the
> tool; approval-required calls fail closed without an approver; and the
> decision is written to an audit sink."

> "Authority is evaluated outside the prompt. The model can request an
> action, but prompt text is not itself an authorization rule."

> "An approver must return an ApprovalGrant with the same call ID and
> digest; plain True values and stale grants fail closed."

> "This makes missing terminal evidence visible when the release event
> survives. It does not authenticate audit input, prove the producer emitted
> every event, or protect a whole log that was deleted or replaced."

### 2.2 Steward — https://github.com/Mohil-Ahuja/Steward

Verbatim:

> "Steward is a policy decision point and enforcement point for that
> boundary."

> "Tool descriptions enter that context window verbatim, so a hostile server
> can address instructions to the model through its own documentation."

> "Tool definitions are mutable, so a tool approved in a benign form can be
> silently replaced with a malicious one under the same name."

> "Results are wrapped in an <untrusted-tool-output> envelope naming their
> provenance, imperative spans are marked rather than deleted (deletion
> destroys the evidence an analyst needs)"

> "scope_abuse | 2 | 50% | 50% | 50%"

That last row is Steward's own attack-success table. It says scope abuse is
**not** solved by its full policy. It is quoted here because it is the
source's own statement of the limit of what a policy layer can do, and this
slice's narrowing rule is a response to that limit — not a claim that the
limit is gone.

### 2.3 Community counter-example (not a normative source)

Recorded in the survey's source record for this rank, and quoted as
community opinion rather than as a specification:

> "Their 'still the thing you authorized' test needs the re-check to fire at
> delegation time, not at call time. A sub-agent that inherits a parent's
> token inherits its staleness too."

---

## 3. What is a Northstar extension (and not a source claim)

The survey says so explicitly for this record:

> "Northstar's boundary object carries a *scope* that can only be narrowed,
> and re-checks the boundary at delegation time. agent-guard does not claim
> either."

So the following are **Northstar's own design**, and no source above claims
any of them:

1. **The expiry.** agent-guard's rules are about a single decision; the
   idea that a grant has a lifetime that must be evaluated is ours.
2. **The monotonic narrowing.** The scope can only shrink. agent-guard
   evaluates a policy; it does not define an order on scopes.
3. **The delegation-time re-check.** Prompted by the community
   counter-example in §2.3, not by either source.
4. **The `denied_tools` axis** that wins over every other axis. The sources
   speak of denials; they do not define a scope with a denial set that
   survives narrowing.
5. **The object shape itself** — `boundary_id`, `scope`, `subject`,
   `grantee`, `issued_at`, `expires_at`, `evidence_digest` — and the
   `valid` / `expired` / `revoked` / `narrowed` state machine over it.

---

## 4. Invariants

These are the rules the module makes true. Each is stated as a behaviour,
not as an implementation.

**I1 — Authorization is decided before the tool runs.**
`BoundaryCheck.authorize()` decides and returns a decision record.
`BoundaryCheck.execute()` acts. They are two separate steps.

**I2 — A denied call never reaches the tool.**
`execute()` does not call the callable for any verdict other than `allowed`.
Not "calls and rolls back", not "calls and discards the result": does not
call. The test suite proves this with a callable that records having been
called.

**I3 — Approval-required without an approver fails closed.**
A call that needs human approval and has no matching grant is refused. The
verdict `require_human` exists so a caller can tell "a human must approve
this" from "this is refused outright"; **neither is executable**, and
`authorize_or_raise()` raises `ApprovalRequiredError` rather than returning.

**I4 — The scope can only shrink.**
`narrow_to()` refuses any request that would broaden the scope. A narrowing
may add a denial but never drop one.

**I5 — An expired or revoked boundary authorizes nothing.**
Expiry and revocation are evaluated against a caller-supplied timestamp.
The module never reads a clock.

**I6 — Every decision leaves an auditable line.**
Each authorization produces a `DecisionRecord` carrying the verdict, the
boundary it matched (or did not), a reason code, and the call identity.

**I7 — An approval grant binds one call.**
`ApprovalGrant` carries a `call_id` and a `digest`. Both are compared. A
plain `True` is not a grant: it has no call id and no digest.

---

## 5. The objects

### 5.1 `BoundaryScope`

Four axes, each a set of names:

| axis | meaning |
|---|---|
| `resource_prefixes` | the resource paths the grant covers |
| `actions` | the verbs the grant covers |
| `allowed_tools` | the tool names the grant covers |
| `denied_tools` | the tool names that are **never** covered |

An empty axis constrains nothing on that axis. `denied_tools` wins over
everything else.

Resource prefixes are **hierarchical**: `/workspace` covers
`/workspace/sub/a`, and the match is on a path boundary, so `/workspace`
does **not** cover `/workspaces/a`.

The subset rule (is `self` no broader than `other`?) is stated in behaviour
terms, and the behaviour is not the same as plain set containment. For each
of the three capability axes:

* self empty, other non-empty → self is **broader** (it constrains nothing
  where the other constrains something) → not a subset;
* self non-empty, other empty → self is narrower → a subset;
* both non-empty → ordinary containment.

For `denied_tools`, the direction is reversed: more denials is narrower, so
self must *contain* other.

This matters because the naive set-only rule has a hole: it treats "drop the
action axis" as a narrowing, when dropping the axis actually *releases*
every action.

### 5.2 `AuthorizationBoundary`

Frozen. Fields: `boundary_id`, `scope`, `subject`, `grantee`, `issued_at`,
`expires_at`, `evidence_digest`, plus `revoked_at`, `revoke_reason` and
`parent_boundary_id`.

The state (`valid` / `expired` / `revoked` / `narrowed`) is **derived**, not
stored. A stored state would need a clock to advance it, and this module
never reads a clock. `is_valid_at(ts)` is the query.

`narrow_to()` returns a **new** boundary; it never mutates the old one. The
child inherits `subject` and `evidence_digest` from the parent, records
`parent_boundary_id`, and keeps the parent's expiry as a ceiling: a
narrowing can shorten a life but never extend it.

`revoke()` likewise returns a new boundary. A decision that was allowed
under the original is still explainable by the original.

### 5.3 `ApprovalGrant`

`call_id`, `digest`, `issued_at`, `expires_at`. `matches(call_id, digest)`
compares both identity fields. `is_valid_at(ts)` checks the window.

The digest an approval must bind to is
`BoundaryCheck.call_digest(call_id, action, tool, resource)` — a `sha256:`
digest over the **whole** identity, never a prefix. A truncated identifier is
not injective: two different calls could share a pin.

### 5.4 `BoundaryRegistry`

Stores boundaries by id. A narrowed child is stored **beside** its parent,
not in place of it, so "who narrowed what, and when" stays answerable.
`expire_stale(now)` **reports** the lapsed ids rather than rewriting them —
an expired boundary is already invalid, so there is nothing to change.

### 5.5 `BoundaryCheck` and `DecisionRecord`

`authorize()` is the decision; `execute()` is the action. `delegate()`
re-checks the parent boundary **at delegation time** and creates the child
only when the parent is still live.

`DecisionRecord` carries `call_id`, `action`, `tool`, `verdict`, `reason`,
`boundary_id`, `grantee`, `timestamp` and `digest`, and renders to a
one-line audit entry via `as_line()`.

### 5.6 The state machine

| from | trigger | to | refused when |
|---|---|---|---|
| — | `issue()` | `valid` | the id is already issued |
| `valid` | `narrow_to()` with a narrower scope | `narrowed` (a new object) | the scope would widen, or the expiry would exceed the parent's |
| `valid` | `revoke(ts, reason)` | `revoked` (a new object) | — |
| `valid` | the clock passes `expires_at` | `expired` (derived) | — |
| `revoked` | any `authorize()` | `revoked` | — |

`expired` is not a transition anyone performs. It is what `is_valid_at()`
reports once the caller's timestamp passes the boundary's expiry.

---

## 6. What this slice does NOT do

* **No general policy language.** There is no expression language, no
  condition evaluator, no rules engine. The scope is three sets and one
  ordering.
* **No LLM decides authorization.** The module contains no model call and no
  prompt. This is agent-guard's "Authority is evaluated outside the prompt",
  taken literally: the decision is made by set membership over data the
  caller supplied.
* **No MCP proxy and no tool interception.** The module does not wrap tools,
  does not sit in a call path, and does not implement a transport. It is a
  decision object plus a decision function; wiring it into a host's tool
  dispatch is a separate piece of work.
* **No mutation of the runtime's existing gates.** `permissions.py`,
  `grant_pin_ledger.py`, `forward_seal_ledger.py` and `a2a_gates.py` are
  read-only inputs to this design. Nothing in them was changed.
* **No audit sink.** `DecisionRecord.as_line()` produces the line; storing it
  in Northstar's sealed chain is the caller's business. The source's own
  limit applies here too — this module does not authenticate audit input,
  prove a producer emitted every event, or protect a log that was deleted.
* **No clock.** Every time-dependent question takes the timestamp as an
  argument.

---

## 7. Honest scope of the guarantee

`authorize()` decides whether a call falls inside a scope. It does **not**
prove the scope was the right scope: it cannot know whether the grant that
produced the boundary was itself justified, whether the resource path meant
what the caller thought, or whether the tool named in `allowed_tools` is
still the tool that was approved. Steward's own warning applies — a tool
definition is mutable, and a tool approved in a benign form can be silently
replaced under the same name.

What this module does guarantee is the *mechanical* part: a denied call does
not reach the tool, an expired grant does not authorize, a narrowing cannot
widen, and every decision says why.

---

## 8. The real path that was driven end to end

`components/northstar-agent-runtime/agent_boundary.py` ships a `main()`
self-check that walks the whole path without a test harness:

1. issue a boundary over `/workspace` / `read` / `Read`, with `Bash` denied;
2. an in-scope call **reaches** the tool and returns its result;
3. an out-of-scope action (`write`) **does not** reach it;
4. the denied tool (`Bash`) **does not** reach it, even though the action
   matches;
5. a timestamp past the expiry is refused with reason `expired`;
6. a revoked boundary is refused with reason `revoked`;
7. widening a scope raises `ScopeWideningError`;
8. a call needing approval with no grant is `require_human`;
9. a grant with a wrong digest is `approval_invalid`;
10. a matching grant is `allowed`;
11. a delegation inside the parent's window succeeds, and one past the
    parent's expiry is refused with `delegation_expired`;
12. every one of the decisions left an audit line.

```
$ python3 agent_boundary.py
agent_boundary self-check OK
```

---

## 9. Registration

A new runtime module must be registered in **three** places, and
`runtime_registration.assert_registration_matches_disk()` enforces that they
agree:

1. `components/northstar-agent-runtime/runtime_registration.py` — the
   `REGISTRY` tuple;
2. `components/northstar-agent-runtime/pyproject.toml` — the
   `[tool.setuptools] py-modules` list;
3. the disk.

Both lists are sorted, and `tests/test_py_modules_sorted.py` checks the
ordering.

Adding the module also moves the pinned module counts. The counts are
pinned in **six** places, not five — `grep` finds five, and the sixth is
the wheel test, which only a full-suite run catches:

* `components/northstar-agent-runtime/tests/test_installed_surface_registration.py`
  — installed surface count, and the flat-surface count;
* `components/northstar-agent-runtime/tests/test_py_modules_list.py` — the
  wheel's declared-module count;
* `components/northstar-agent-runtime/tests/test_runtime_data_files.py` —
  the flat module count;
* `tests/test_component_packaging_closure.py` — both counts;
* `tests/test_package_member_publication.py` — both counts;
* the API page, regenerated by `cd tests && python3 docbuild.py build`.

---

## 10. Open items

* **The module is not wired into any host.** It is a decision object and a
  decision function; nothing in the runtime calls it yet. Wiring it into
  `permissions.py`'s dispatch path is deliberately out of scope (see §6) and
  is the natural next slice.
* **The audit line is not sealed.** `DecisionRecord.as_line()` produces a
  line; landing it in `forward_seal_ledger` is the caller's job. Nothing
  here is tamper-evident by itself.
* **The scope does not model a resource *hierarchy* explicitly** — the
  prefix containment is path-based and textual. A resource that is not a
  path (a database table, a queue) needs a different axis.
* **`boundary_id` uniqueness is per registry.** Two registries can issue the
  same id; a host that spans registries needs a namespace.

---

## 11. Source URLs

* https://github.com/agent-rails/agent-guard
* https://github.com/Mohil-Ahuja/Steward
* The survey's source record for this rank:
  `docs/design/frontier-expansion-survey.md` §2.3, §2.4 and §4.2.
