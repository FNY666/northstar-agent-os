# Key custody: agent-held ed25519, policy-sealed, with a pre-sign rollback gate

Module: `components/northstar-agent-runtime/key_custody.py`
Tests: `components/northstar-agent-runtime/tests/test_key_custody.py`
Absorption slice: B173 asinhhc (Moltbook).

---

## 1. What the source says (verbatim, and what it does not say)

**Source.** Moltbook post by *asinhhc*, "The key-custody layer we kept conceding
was missing is now live — with its limits stated"
(<https://www.moltbook.com/post/39049a95-73b8-460b-b1a3-aa2261b3d146>, rank 6,
`m/builds`, 7 up / 24 comments).

> **Status of the source: a first-party demo with unverified numbers.** Its
> "demo 14/14 passed, independently re-run" and "chain head anchored at mesh
> ledger seq 545" are *unverified claims by the author*, reproduced here only
> as design reference. This slice does **not** attempt to reproduce those
> numbers and does **not** treat them as a verified result. What is verified
> here is the **mechanism** (custody, policy seal, pre-sign rollback gate),
> by Northstar's own tests.

**Verbatim quotes from the source thread** (as copied into the task book; they
are the source's words, not Northstar's):

* asinhhc: *"This is a custody step, not a custody proof."*
* agenthaven (the sharpest line in the thread): *"The hole in a sealed policy
  hash is rollback. An old vault with a looser policy still has a valid seal,
  so signing accepts it."*

**The source author's own stated limits** (from the frontier round's retelling
of the post):

* sealing protects the policy **at rest** only;
* the caps constrain an **honest agent**, not a host takeover;
* the v1 anchoring cadence is **manual**.

**The gap the source itself names:** the policy hash is mutable state *inside*
the vault, so a rolled-back vault with a looser policy still carries a valid
seal. The source's v1 detects the mismatch (a dated ledger row records it) but
**does not refuse to sign**; the real fix is a **pre-sign gate** that re-reads
the anchored hash before signing.

---

## 2. The gap in Northstar before this slice

Northstar's receipt chain proved *integrity*, not *signer independence*: the
verification key was held by the operator. The gossip audit-head's open
conclusion 2 states it: *"no signature field — the public board must define the
signature envelope"*. This slice supplies that layer.

The repository already had the primitives, and this slice **reuses** them
rather than duplicating them:

| Concern | Existing module (read-only here) | What this slice uses |
| --- | --- | --- |
| ed25519 primitive | `ed25519.py` (vendored, RFC 8032; `public_key`, `sign`, `verify`) | the **same** module `message_signing.py` signs with |
| message signing | `message_signing.py` (`SignedMessage`, `sign_message`, `verify_message`) | read for its signing/verification rules; **not** rewritten |
| vault | `pii_vault.py` (`Vault.mask` / `Vault.demask`) | read for the vault/seal shape; the policy seal here is a *different* thing (see §4) |
| append-only ledger | `forward_seal_ledger.py` (`ForwardSealLedger.append`, `.record`, `.record_hash`) | the anchor sink; its code is **not** modified |
| grants ledger | `grant_pin_ledger.py` (`GrantPinLedger.seal_into`, `SealedGrantRow`) | read for the "seal into both ledgers" pattern; not modified |
| receipts | `attested_receipts.py` (`attach_attestation`, `verify_attestation`) | read for the receipt shape; not modified |
| identity | `agent_identity.py` (`AgentIdentity`, `did_of`) | read for how identity is represented; not modified |

`key_custody.py` touches none of those modules' code; it only calls
`ForwardSealLedger.append` / `.record` through the public API.

---

## 3. The mechanism

### 3.1 `CustodyPolicy` — the policy the identity is bound to

Fields: `allowed_ops` (permitted operation kinds), `max_signatures_per_epoch`
(the per-epoch cap), `expires_at` (expiry, unix seconds), `epoch_seconds`
(epoch width), `policy_id`.

`policy_hash` is **canonical**: the hash is taken over a canonical JSON body
(`canonical_form()` — sorted keys, compact separators, UTF-8) prefixed with the
domain tag `northstar-key-custody:v1:policy`. Same policy → same hash, every
time, regardless of field order or dict insertion order; changing one field
changes the hash. `tests/test_key_custody.py::test_policy_hash_is_canonical`
pins both directions.

### 3.2 `VaultSeal` — the policy hash sealed into the vault

`VaultSeal.create(vault_version=…, policy_hash=…, sealed_at=…, key_id=…)`
binds the policy hash to a **monotonically increasing vault version** and
carries a `sha256:` seal digest over the canonical seal body
(`verify_self()` re-derives it).

The seal is *self-consistent but not sufficient*: `seal_is_valid(seal)` is the
old, weak check — "the seal verifies against itself". A rolled-back vault with
a looser policy passes it. That is exactly agenthaven's sentence, and the
slice keeps the weak check **as a named function** so the difference between
"seal valid" and "gate passes" is executable rather than rhetorical.

### 3.3 The anchor — the vault version published outside the vault

`anchor_vault(ledger, seal)` appends one 8-field event to the
`ForwardSealLedger` (read-only use):

* `intent = "key-custody-anchor"`, `action = "anchor-vault"`,
  `subject = <key id>`;
* `authorization = "vault_version=<v>;policy_hash=<h>"` — the pair the gate
  needs, carried in the ledger's own field;
* the three digest pins are derived from the seal body.

`read_anchored(ledger)` reads the newest anchor back out of the ledger
(scanning `record(seq).event`). The anchored **version only moves forward**:
re-anchoring at an equal or older version is refused.

### 3.4 The pre-sign gate — the Northstar extension, and the headline fix

`KeyCustody.pre_sign_gate(op)` runs **before** anything is signed and reads
the anchored state *from the ledger at gate time* (not from a cached copy).
Refusals are structured (`CustodyRefusal`, carrying a `RefusalReason` enum and
a `detail` dict) and happen in this order:

| Order | Reason | Condition |
| --- | --- | --- |
| 1 | `NOT_SEALED` | no policy is sealed |
| 2 | `NOT_ANCHORED` | the vault state was never published to the ledger |
| 3 | `ROLLBACK` | sealed `vault_version` < anchored `vault_version` |
| 4 | `POLICY_TAMPER` | the current/sealed policy hash ≠ the anchored policy hash |
| 5 | `EXPIRED` | the policy is past `expires_at` |
| 6 | `CAP_EXCEEDED` | the per-epoch signature count ≥ the cap |
| 7 | `OP_NOT_ALLOWED` | the operation kind is not in `allowed_ops` |

**The version check deliberately precedes the hash check.** An old vault
carries an old policy hash too, so checking the hash first would report the
rollback as `POLICY_TAMPER` and hide it. The version is the monotonic clock;
a vault older than the anchored one is a rollback whatever its policy says.

**Ordering within the tamper check.** `POLICY_TAMPER` fires in two distinct
ways, and the detail dict distinguishes them:

* the *policy object* changed after sealing (current hash ≠ sealed hash) —
  the detail carries `current_policy_hash`, `sealed_policy_hash` and
  `anchored_policy_hash`;
* the *seal* no longer matches what was anchored (sealed hash ≠ anchored
  hash) — the detail carries the two hashes.

### 3.5 `KeyCustody` — the custody object

`KeyCustody(agent_id=…, ledger=…, seed=…)` generates (or takes) a 32-byte
ed25519 seed, derives the public key, and derives the key id as
`"ed25519:" + sha256(canonical({agent_id, public_key}))[:32]`. The private
seed never leaves the object: the public surface is `public_key`, `key_id`,
`seal`, `policy`, `sign()` and `anchored_state()`.

`sign(payload, op=…)`:

1. runs the pre-sign gate — **on refusal, no signature is produced** and the
   caller sees the reason enum;
2. computes `payload_hash = sha256(canonical(payload))`;
3. builds the envelope body and signs it with the vendored `ed25519` module
   (the same primitive `message_signing.py` uses — no second signing stack);
4. increments the epoch counter.

### 3.6 `SignatureEnvelope` — the envelope the public board can define

Fields: `schema`, `key_id`, `public_key`, `signature`, `policy_hash`,
`vault_version`, `anchored_policy_hash`, `anchored_vault_version`,
`anchor_seq`, `payload_hash`, `payload`, `op`, `seq`, `timestamp`.

`verify_envelope(envelope, public_key, anchored_policy_hash=…)` verifies the
signature over the canonical body **and** (when the anchored hash is supplied)
that the envelope claims exactly that policy hash.

This is the signer-independence property: a stranger holding only the public
key and the anchored policy hash learns *who* signed, not merely that the
bytes are intact. It is the envelope the audit-head conclusion 2 asks the
public board to define — with the Northstar additions (`policy_hash`,
`vault_version`, `anchored_policy_hash`, `anchored_vault_version`, `anchor_seq`)
over the source's description.

---

## 4. Northstar extensions vs. the source (kept separate)

**From the source (design reference):** agent-held ed25519 signing identity;
the policy hash sealed into the vault; policy change → signing refused; a
detected-but-not-blocked rollback in v1; the limits (at-rest only, honest-agent
caps, manual anchoring).

**Northstar extensions (this slice):**

1. **The pre-sign gate** — the source's v1 *detects* a rollback (a dated
   ledger row) but does not refuse; the gate re-reads the anchored state
   before signing and **refuses** with a structured reason.
2. **The envelope field set** — `anchored_policy_hash`, `anchored_vault_version`,
   `anchor_seq` and `payload_hash` are Northstar's; the source describes the
   concept ("the public board must define the signature envelope") without
   fixing the fields.
3. **The monotonic vault version** as the anchor's ordering key — the source
   names "publish the vault version outside the host" as the fix direction;
   the concrete versioned anchor row is Northstar's.
4. **Structured refusals** (`RefusalReason` enum + detail dict) instead of a
   bare exception — Northstar's house style.

**Deliberately different:** the source's vault is a host-side store of
sealed policies. Northstar's `pii_vault.py` is a PII mask/demask store — a
different thing entirely, so this slice adds its own `VaultSeal` rather than
misusing the PII vault. The only reuse of a ledger is as the **anchor sink**.

---

## 5. What this slice does NOT claim

* It does not claim a custody *proof* — asinhhc's own words: *"This is a
  custody step, not a custody proof."*
* It does not defeat a **host takeover**: the caps constrain an honest agent;
  a host that replaces the custody object can still forge envelopes.
* The seal protects the policy **at rest** only; a policy changed *and*
  re-anchored by an authorized anchorer is a legitimate new state, not a
  tamper.
* Anchoring here is **manual** (the caller calls `anchor()`); nothing
  publishes the vault version off-host automatically.
* It does not claim the source's demo numbers (14/14, seq 545) — those are
  unverified first-party claims and are not reproduced.
* It does not prove **truth** of a receipt — only integrity, ordering, and
  signer attribution.
* The ledger is in-memory: persistence, WORM archiving and off-host anchoring
  remain the host's job (the same honest scope `forward_seal_ledger.py`
  states).

---

## 6. Verification map (acceptance rule → named test)

| Acceptance rule | Test |
| --- | --- |
| happy path: seal → sign → stranger verifies | `test_seal_anchor_sign_and_stranger_verifies` |
| envelope fields complete | `test_envelope_carries_every_field` |
| canonical policy hash (same → same, changed → changed) | `test_policy_hash_is_canonical` |
| policy tamper → `POLICY_TAMPER`, no signature | `test_policy_tamper_after_seal_is_refused` |
| rollback → `ROLLBACK`, no signature, **and** the seal-only check would have let it through | `test_rollback_to_old_vault_is_refused_though_its_seal_is_valid` |
| cap exceeded → `CAP_EXCEEDED` | `test_cap_exceeded_is_refused` |
| expired policy → `EXPIRED` | `test_expired_policy_is_refused` |
| vault version monotonic | `test_vault_version_is_monotonic` |
| unsealed / unanchored → structured refusal | `test_unsealed_and_unanchored_are_refused` |
| wrong public key → verification fails | `test_wrong_public_key_fails_verification` |
| tampered signature → verification fails | `test_tampered_signature_fails_verification` |
| tampered envelope fields → verification fails | `test_tampered_envelope_fields_fail_verification` |
| envelope dict round trip | `test_envelope_round_trips_through_dict` |
| refusal is structured, not silent | `test_refusal_is_structured_not_a_bare_exception` |
| signature primitive is reused, not duplicated | `test_module_reuses_the_repository_ed25519_primitive`, `test_signature_is_verifiable_with_the_vendored_primitive` |
| end-to-end driven path | `test_full_driven_path`, `test_anchor_is_readable_from_the_ledger_afterwards` |
