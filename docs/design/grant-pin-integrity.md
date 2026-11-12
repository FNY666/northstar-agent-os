# Grant pin integrity at the seal layer

Status: **FINAL** (B173 conclusion 52, 2026-11-12).
Implemented on `batch-173-moltbook-absorb`.

## 1. The gap

Conclusion 52 (Moltbook post `41d46080`, comment `47902c54`): the
authorization pin only had to be a *non-empty string*, and the ledger
layer did not validate its content. So `"approved by operator"` sealed
just as validly as a real grant reference — and after the fact nobody
could tell what a sealed row had been asking about.

The point of a record existing is to name what it is asking about. A
ledger row that says "approved by operator" says nothing about which
grant was authorized; it is a row that looks like evidence and is not.

## 2. The decision

Coordinator decision (not to be re-litigated): **the grant id is NOT NULL
at the seal layer; the version and the counter are nullable.**

That split is the whole design:

* An **unnamed grant** — empty string or missing — is refused by the
  seal. The seal fails and **no row lands**. A refused seal must not
  leave an unnamed hole: a row that names nothing is worse than no row,
  because it looks like evidence.
* A **named grant whose counter is null** still lands. Its outcome is
  recorded as `outcome_unknown` and the pin is preserved verbatim. This
  is a *parseable refusal* — "dispatched, grant unresolvable" — and it is
  categorically different from "nothing happened": the ledger says the
  dispatch happened and the grant could not be resolved to a state.
* The pin keeps its **three-field shape** — `grant_id`, `version`,
  `counter`. No fourth field is invented. The shape is consistent with
  conclusion 43's typed columns and conclusion 62's operation-id
  convention.

The counter is the ordering key: it is what places a grant in its
version/counter order, so it is what makes a grant *resolvable*. A
missing version does not make a grant unresolvable on its own.

## 3. The mechanism

**`grant_pin_ledger.py`** (new) holds the rule in one place.

* `GrantPin` — the three-field pin. `PIN_COLUMNS` declares the columns
  with their types *and their nullability*, so conclusion 43's typed-
  column discipline is the source of truth for validation rather than
  decoration: `grant_id` is `text NOT NULL`, `version` is `text NULL`,
  `counter` is `int NULL`.
* `resolve_seal_outcome(pin, outcome)` — the single home of the rule.
  Raises `MissingGrantIdError` for an unnamed grant; rewrites the outcome
  to `outcome_unknown` for an unresolvable one.
* `GrantPinLedger.seal(...)` — the seal layer. An unnamed grant is
  refused before any row is written.
* `GrantPin.render()` / `GrantPin.parse(...)` — the pin's rendering into
  the ledger's `authorization` field
  (`grant:<id>;version=<v|null>;counter=<n|null>`) and its inverse. This
  is the archaeology: a sealed record still says what it was asking
  about, and the rendering round-trips back into the same pin.

**`forward_seal_ledger.py`** gains `append_grant(...)`, the rule applied
on the real seal layer. The grant id is checked before the event is
built, so a refused grant seal never reaches the chain — the chain's
integrity is untouched and `verify()` still passes over what came
before.

## 4. Honest scope

The ledger books what the host reported. It cannot prove that a grant
existed, that the counter was the right one, or that the dispatch reached
anything. Sealing proves integrity and order, never truth — the same
honest gap every ledger in this repo carries. The change makes an
existing hole *named and refused*; it does not close the gap between "a
grant was reported" and "a grant existed".
