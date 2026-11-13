# Destination identity by state epoch, for endpoint-switch idempotency

This document describes one slice of Northstar: a **destination identity** that
follows the destination's *state* (an epoch) rather than its *address*, an
operation **bound key** that carries that identity, a three-way **replay
verdict**, and a minimal **acceptance ledger** that can explain a mixed
replay.

Source: neo_konsi_s2bw, "An endpoint switch resets your agent's definition of
'already done'" (Moltbook, 2026-11), paired with the same author's "An
idempotency key without a payload fingerprint is a data-corruption interface".
The upstream posts are **not** in this repository and were not crawled; the
quoted text below is the text the slice brief carries, and it is marked as
*verbatim as briefed* wherever it is attributed to the source.

The module: `components/northstar-agent-runtime/endpoint_identity.py`.
The tests: `components/northstar-agent-runtime/tests/test_endpoint_identity.py`.

---

## 1. What Northstar has today (read from the code, not assumed)

### 1.1 The grant pin today

`components/northstar-agent-runtime/grant_pin_ledger.py` defines `GrantPin`
(line 163) with exactly **three** fields:

    grant_id, version, counter

`PIN_COLUMNS` drives the type check; `version` and `counter` are nullable;
`grant_id` is the only field that must be non-empty. `SealedGrantRow`
(line 284) carries `seq`, `pin`, `outcome`, `digest`, `schema`. The row
digest is `_digest({"seq", "pin": pin.to_dict(), "outcome", "schema"})`
(`SealedGrantRow.verify`, line 310) — a `sha256:` digest of canonical JSON.

**What the pin binds:** *which grant* it is asking about, its version, and
its counter. **What it does not bind:** any destination, endpoint, host,
address, or epoch. There is no field to put one in, and the digest of the
row therefore cannot cover a destination either. A pin is a *question about
a grant*, not a statement about where the question was sent.

### 1.2 The dedup key today

`components/northstar-agent-runtime/idempotency_manager.py` defines
`IdempotencyManager.check_or_store(key, result, payload=None, seq=0)`
(line 217). The key is an opaque caller-supplied string; the manager keys
its in-memory records by that string alone (`self._records: dict[str, ...]`,
line 216). The key is bound to the payload it was first stored with: a retry
with a different payload raises `PayloadMismatchError` (line 247).

The module docstring states the limit itself, verbatim from the repo
(lines 21-25):

    It records that a key was seen and what result was stored; it cannot prove the host
    actually executed the operation exactly once (that is the executor's job),
    and it cannot see operations the host never reports. A cache hit means
    "this key was already stored", never "the world changed exactly once".

**What the key binds:** an opaque string, plus the payload digest.
**What it does not bind:** the destination. There is no destination notion in
the module at all.

### 1.3 What happens when the endpoint changes today

Nothing detects it. The dedup record lives in the *caller's* process, keyed
by an opaque string; it is not portable to a new destination, and it is not
checked against one. The same `key` replayed against a different endpoint is
indistinguishable, from the manager's point of view, from a retry against the
same endpoint — so it returns the cached result (`hit=True`, line 251) and
the caller sees a success that the *new* destination never performed. The
manager cannot even see the switch: it has no destination to compare.

The repo's own vocabulary already has the state this situation leaves
behind: `outcome_unknown` ("dispatched, but the outcome could not be
resolved"), as used by `grant_pin_ledger.py` (line 66) and
`scope_qualifier.py` (line 108). Nothing today connects an
`outcome_unknown` operation to the destination it went to.

### 1.4 Baseline

* Runtime suite: `Ran 19419 tests ... FAILED (failures=17, errors=10, skipped=13)` —
  **27** failing items, all pre-existing (sandbox/landlock/seccomp/tool-input
  schema/doctor/packaging items in this environment).
* Governance bench: `summary: 161/169 passed, 8 failed` — the 8 failures are
  the live-leg items this environment cannot run (seccomp, landlock, capdrop)
  plus `redteam.context_stale_approval_not_replayable` and
  `redteam.shell_backend_host_owned`.

---

## 2. The source's claim, and what this slice makes of it

### 2.1 Verbatim as briefed

* (neo_konsi_s2bw) "A familiar key is just a string until the receiver recognizes it… Treat endpoint configuration as part of execution state."
* (martys) "An idempotency key is a claim about the past, and only the destination can ratify it."
* (neo_konsi_s2bw, core mechanism) "Changing an agent's API endpoint is an idempotency boundary even when the SDK call is identical: the new destination has no obligation to possess the old destination's dedup record, so replaying a 'sent, outcome unknown' operation with the same key becomes a duplicate execution."

### 2.2 Northstar extension (not source text)

The source says *treat endpoint configuration as part of execution state*; it
does not say how to name that state. This slice's extension is the rule the
brief's comments (pennyworthatyourservice / seeragent) sharpen: **a hostname
can be re-pointed at a brand-new store, so identity must follow the backend
state, not the address.** A destination's identity is therefore an *epoch* —
a state-root hash or a store-issued epoch string — proven by the destination
itself at effect time.

The rest of the extension is mechanical: the epoch goes into the bound key,
the replay verdict becomes three-valued (the source's "duplicate execution"
case is neither a replay nor an ordinary payload conflict), and a small
per-operation ledger records which destination accepted what so that a mixed
replay can be explained rather than guessed at.

**This slice does not change** `GrantPin`, `IdempotencyManager`, or any
existing ledger module. It defines the identity + binding + verdict +
acceptance-ledger layer only.

---

## 3. The module

### 3.1 `DestinationIdentity`

A frozen dataclass with two fields:

    epoch: str      # the load-bearing one: state-root hash or store epoch
    address: str    # a label only; never part of an identity decision

Equality is over `epoch` alone (`__eq__`/`__hash__` are hand-written, the
class is `eq=False`):

* same address, **different epoch** → two different identities. The address
  was re-pointed at a new store; the state changed.
* same epoch, **different address** → the same identity. The same store was
  reached under another spelling; the state did not change.

`from_dict` refuses a missing or empty epoch with `UnprovenIdentityError`:
an identity that was not attested is not an identity. `to_dict` writes the
epoch, the address and the schema pin.

### 3.2 `bind_key(operation_key, destination, payload)`

The bound digest of an operation:

    sha256( canonical({operation_key, epoch, payload_fingerprint}) )

The canonicalisation is the same shape `idempotency_manager._canonical` uses
(line 79): sorted keys, compact separators, `ensure_ascii=True`, UTF-8 bytes,
`sha256:` prefix. The payload enters as its **fingerprint** (a digest of the
canonical payload), never as its text.

The epoch — not the address — is what enters the digest. So a bound key is
stable across an address change and changes across a state change. Any one
of the three inputs changing changes the digest.

### 3.3 `classify_replay(recorded_destination, current_destination, recorded_fingerprint, presented_fingerprint)`

| verdict | condition | meaning |
|---|---|---|
| `REPLAY` | same epoch, same fingerprint | the destination can ratify this key; the effect already happened there and must not happen again |
| `CONFLICT` | same epoch, different fingerprint | the same key with different arguments; the first result must **not** be returned |
| `NEW_DESTINATION` | different epoch | the new destination has no obligation to hold the old dedup record; the caller must reconcile, the operation stays `outcome_unknown`, and nothing is silently re-executed |

The epoch check comes first: a new destination outranks a payload difference,
because the new destination cannot ratify the key at all — it is not in a
position to say "conflict".

### 3.4 `AcceptanceLedger`

A minimal per-operation ledger. It records **who accepted what**:

    record_acceptance(operation_key, destination, outcome, bound_digest, payload_fingerprint)
    record_pending(operation_key, destination)
    accepted_by(operation_key)      # -> Acceptance | None
    pending_at(operation_key)        # -> DestinationIdentity | None
    accepted_operations() / pending_operations() / acceptance_count()

It does not retry, does not seal, and does not touch any existing ledger
module. Its job is to make a mixed replay explainable: after an endpoint
switch, `accepted_by("op-1")` says op-1 landed at the old destination and
`accepted_by("op-2")` is `None` — op-2 was accepted by nobody.

### 3.5 `prove_at_effect(presented, attested_epoch)`

At effect time the epoch the caller presents must be the epoch the
*destination itself* attested. A destination that offers only an address —
no epoch — has proven nothing, and the operation is refused fail-closed with
`UnprovenIdentityError`. This is the "only the destination can ratify it"
rule made executable.

---

## 4. The paths that are driven end to end

`tests/test_endpoint_identity.py::TestEndToEndPaths` drives four paths
against a modelled dispatcher that applies an effect exactly once and records
it in the acceptance ledger:

1. **Replay to the same destination.** The operation is sent to A and
   accepted; the same key with the same payload to A is `REPLAY`; the effect
   list still has one entry and the ledger has one acceptance.
2. **Endpoint switch.** The operation is sent to A with outcome unknown; the
   endpoint moves to B; the replay to B is `NEW_DESTINATION`; no effect is
   applied at B; the operation is not accepted anywhere and stays pending —
   `outcome_unknown`, awaiting reconciliation.
3. **Same key, different payload.** Against the same destination, the
   verdict is `CONFLICT`; the first effect stands and no second is applied.
4. **Mixed replay.** op-1 was accepted by A, op-2 was pending; after the
   switch, the ledger shows op-1 accepted at A, op-2 accepted by nobody, and
   op-2's replay to B is `NEW_DESTINATION`.

---

## 5. Open items

* `GrantPin` still has no destination field. This slice defines the identity
  and the binding; wiring a destination epoch into the pin (and into the
  sealed row digest) is a separate slice and would change
  `grant_pin_ledger.py`.
* The acceptance ledger is in-memory and unsealed, like
  `IdempotencyManager` itself. Persistence and sealing are the host's job.
* Nothing in the runtime *calls* `classify_replay` yet — this slice ships the
  mechanism and its tests, not an integration into the dispatch path.

---

## 6. Provenance

| Claim | Origin |
|---|---|
| "A familiar key is just a string until the receiver recognizes it… Treat endpoint configuration as part of execution state." | verbatim as briefed (neo_konsi_s2bw) |
| "An idempotency key is a claim about the past, and only the destination can ratify it." | verbatim as briefed (martys) |
| "Changing an agent's API endpoint is an idempotency boundary even when the SDK call is identical: …" | verbatim as briefed (neo_konsi_s2bw) |
| Epoch-over-address identity | Northstar extension (this slice) |
| `bind_key` / `classify_replay` / `AcceptanceLedger` / `prove_at_effect` | Northstar extension (this slice) |
| Canonical JSON shape | borrowed from `idempotency_manager._canonical` (repo code) |
| Pin fields, dedup semantics, `outcome_unknown` | read from repo code (see §1) |
