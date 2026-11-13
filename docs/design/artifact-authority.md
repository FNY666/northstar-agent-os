# Artifact authority: the artifact carries the authority it was granted

Status: **implemented** (B173 vina slice, 2026-11-13). Implemented on
`batch-173-moltbook-absorb`.

## 1. The position this answers

Slice 6 settled **epoch-CAS-at-dispatch**: re-check the grant when the
write is dispatched, and pin the epoch with a compare-and-swap
(`docs/design/live-socket-revocation.md`, `docs/design/grant-pin-integrity.md`).
Vina's counter-position challenges exactly that shape. Verbatim from the
post quoted in the slice brief (Moltbook post `737eade5`):

> "A checksum is a witness that never expires, and a grant is a witness
> that always does. The mismatch is structural, not a scheduling bug.
> Checking later is not authorization. It is integrity with extra steps."

The point is not that re-checking is useless. It is that a re-check
answers a question about **the grant**, while what an artifact needs is a
statement about **itself**: what permitted this, and when. Re-checking
happens at one instant, in one place, and is then gone — the artifact
that was produced carries no trace of it. The stamp-to-use gap is the
hole.

The design that came out of the thread (as recorded in the slice brief):
**the receipt travels with the bytes.** The receipt reads
*"permitted at T, check the list for now"* (spiritofthefleet's phrasing,
as carried in the slice brief), the grant carries a revocation epoch, and
a read-time tombstone check (vina) is added on top.

## 2. The decision

Both, and the receipt is explicitly past tense.

* **Embed** (this slice): the artifact carries the grant that permitted
  it, the revocation epoch that grant was read at, the seq it was
  permitted at, the clock that produced the epoch, and the issuer.
* **Re-check** (slice 6, unchanged): the dispatch path still re-checks
  the grant and still pins the epoch at commit.
* The receipt never claims to *be* the authorization. It is a witness
  about the past; the revocation list is what says something about the
  present. That is the whole of "permitted at T, check the list for now".

The module: `components/northstar-agent-runtime/artifact_authority.py`.
The tests: `components/northstar-agent-runtime/tests/test_artifact_authority.py`.

## 3. The mechanism

**`ArtifactReceipt`** — a frozen dataclass carrying:

| field | meaning |
|---|---|
| `artifact_digest` | `sha256:` pin of the artifact's bytes |
| `grant` | the three-field `grant_pin_ledger.GrantPin`, reused verbatim (nulls included) |
| `permitted_at` | the seq at which the write was permitted (never a wall clock) |
| `revocation_epoch` | the grant's revocation epoch as read at that moment |
| `clock_id` | the clock that produced the epoch and the seq |
| `issuer_id` | the body that issued the grant |
| `action`, `subject` | the grant-pin identity the receipt permits — the identity a tombstone covers |

**`bind(bytes, pin, permitted_at_seq, epoch, clock_id, issuer_id)`** —
writes the receipt. It fails closed:

* an **unnamed grant** is refused and *nothing lands*. The rule is
  applied through `grant_pin_ledger.resolve_seal_outcome`, so there is
  one home for it, not two;
* an unresolved pin (null counter) is carried **verbatim**, nulls
  included — the receipt never rewrites the pin to hide the absence;
* `clock_id == issuer_id` is refused: the epoch must come from a clock
  the issuer does not own;
* the receipt's own text is past tense, always.

**`render()` / `parse()`** — the receipt's text is
`receipt:<digest>;grant:<id>;version=…;counter=…;permitted at T;epoch=…;clock=…;issuer=…;action=…;subject=…;check the list for now`.
It contains the literal `permitted at T` and the literal
`check the list for now`, and it contains **no** present-tense
authorization claim. The forbidden tokens (`authorized`, `permitted now`,
`valid`, …) are refused at render *and* at parse: a receipt that was
tampered with into claiming to authorize *now* cannot be opened.

**`seal_bytes` / `open_sealed`** — the container that makes the receipt
travel with the bytes. `open_sealed` checks the payload against the
receipt's digest, so a container whose bytes were changed after the seal
does not open.

**`verify(receipt, epoch_now, tombstone_set, …)`** — the read-time
check. The verdicts:

| verdict | when |
|---|---|
| `UNNAMED` | the receipt's grant was never named |
| `UNBOUND` | the bytes no longer match the receipt's digest |
| `REVOKED` | a live tombstone names the action the receipt permits |
| `STALE` | the grant's revocation epoch has moved on, or the grant was re-issued (its counter advanced) |
| `VALID` | none of the above |

Three properties the tests pin:

* the tombstone check is a **read-time** check, not only a seal-time
  one: a cancellation declared *after* the seal still catches the
  receipt;
* the epoch is bound to the **grant**, not to a grant id string: a grant
  that was re-issued (counter advanced) makes an old receipt `STALE`
  even though the epoch has not moved and the grant id is unchanged;
* a `STALE` or `REVOKED` receipt never silently becomes `VALID` again —
  the verdict is re-derived from the receipt and the present on every
  read, and the epoch only moves forward.

## 4. Honest scope

Sealing proves integrity and order, never truth. The receipt records
what the host reported; it cannot prove that a grant existed, that the
counter was the right one, or that the epoch was read from the clock it
names.

**The gap this module does not close:** it **cannot prove that the clock
is independent of the issuer**. It records `clock_id` and `issuer_id` and
refuses them being the same identity — that is the whole of the
guarantee. A host that lies about both, or that runs the clock it names
under the issuer's control, is out of scope. The module does not pretend
otherwise, and the design does not claim to.

## 5. Relations to the existing layers

* **`grant_pin_ledger.py`** — the pin's shape is reused, never copied.
  The unnamed-grant rule is applied through its `resolve_seal_outcome`,
  so the receipt and the sealed ledger refuse an unnamed grant the same
  way. The receipt carries the pin verbatim, nulls included, exactly as
  the sealed row does.
* **`cancellation_tombstone.py`** — read-only. The tombstone set is
  consulted at read time and the question asked is the grant-pin
  identity (`grant_id` + `action` + `subject`), the same identity the
  sealed ledger and the tombstone set use. Nothing here decides
  anything on prose.
* **`forward_seal_ledger.py`** — read-only, unchanged. Its
  `append_grant` still enforces the conclusion-52 pin rule and still
  consults the tombstone registry at commit (CAS at commit). This slice
  does not rewire it; the receipt is a second, artifact-side witness
  that stands on its own.
* **`docs/design/live-socket-revocation.md`** — the lease table fences
  an admitted *network session*; the receipt fences the *artifact*. They
  answer different questions and both are kept.
* **`docs/design/cancellation-tombstone.md`** — the tombstone survives
  compaction; the receipt survives the artifact.

## 6. Mapping to the source

Verbatim, as carried in the slice brief (the post itself is not in this
repo; these are the quotes the brief records, and they are marked as
such):

* vina: *"A checksum is a witness that never expires, and a grant is a
  witness that always does. The mismatch is structural, not a scheduling
  bug. Checking later is not authorization. It is integrity with extra
  steps."* — the reason the receipt is bound to the artifact instead of
  being a re-check at dispatch.
* spiritofthefleet: the receipt's shape — *"permitted at T, check the
  list for now"* — is the literal text of the receipt, and the reason
  the receipt is past tense.
* vina: the revocation epoch on the grant, plus the read-time tombstone
  check — implemented as `revocation_epoch` and the `REVOKED` verdict.

Northstar extensions (ours, not the source's):

* the *container* format (a receipt line followed by the payload) and
  the `open_sealed` digest check;
* the requirement that `clock_id != issuer_id`, and the fail-closed
  refusal when they are equal;
* the counter rule — the epoch is bound to the grant's *state*, so a
  re-issued grant makes an old receipt stale even without an epoch
  change;
* the `UNBOUND` verdict for bytes changed after the seal.

## 7. Open items

* **Independence of the clock is asserted, not proven.** The module
  refuses `clock_id == issuer_id`; it cannot establish that the named
  clock is outside the issuer's control. Closing this needs a source of
  epoch truth the issuer cannot mint — an external ledger, a hardware
  counter — which no component in this repo provides yet.
* **Who re-reads the receipt.** The read-time check is a library call;
  the dispatch path is not yet wired to it (this slice does not modify
  `forward_seal_ledger` or the host). Until it is, the receipt is a
  witness that can be consulted, not a gate that fires.
* **Which list is "the list".** The receipt says "check the list for
  now" but does not name a list. The tombstone set is the list consulted
  here; the lease table's `revocation_epoch` is a different one, and the
  two are not yet unified.
* **Verbatim source text.** The post is not in this repository and was
  not fetched during the slice; the quotes above are the ones the slice
  brief carries and are marked as verbatim-as-briefed, not
  independently re-verified against the live post.
* **Identifier text is checked too.** The present-tense refusal scans the
  whole receipt text, including the grant id, the clock id, the issuer id
  and the subject. The tokens are matched on word boundaries, so an
  identifier that merely contains a word (`validation-clock`) is not
  mistaken for a claim, while a word that stands on its own (`valid`,
  `authorized`) is refused. The scan covers the whole text on purpose: a
  claim smuggled into a free-text field is still a claim.
