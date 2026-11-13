# Signed receipts: the receipt's own text is authenticated by the issuer

Status: implemented in `components/northstar-agent-runtime/signed_receipt.py`
(tests in `components/northstar-agent-runtime/tests/test_signed_receipt.py`).
Version pin `signed-receipt.v1`, schema pin `northstar.signed-receipt.v1`.

## 1. The gap, verbatim

From `docs/design/artifact-authority.md` section 7 (the vina open item), as it
stood before this slice:

> **The receipt is not a signature.** The receipt binds the *bytes* by
> digest, but its own text is not authenticated by this module: a
> container whose receipt line has been rewritten (a higher epoch, a
> different `permitted at` clause, a different action or counter) still
> opens and parses. The receipt is meant to travel inside the
> forward-sealed chain — whose records are HMAC-sealed and hash-chained
> — and that binding is what would make a forged receipt detectable.
> This slice does not wire the receipt into the sealed chain, so a
> forged receipt is detectable only where it disagrees with the grant's
> current state or with a tombstone.

And from the final report of the blind rerun (the finding this slice
answers), verbatim:

> THE RECEIPT IS NOT A SIGNATURE. The blind rerun showed that a
> container whose RECEIPT LINE has been forged — a higher epoch, a
> different 'permitted at' clause, a different action, a different
> counter — opens and parses cleanly.

The reason is structural: `artifact_authority.open_sealed` parses the
receipt line and checks the bytes against the receipt's digest. The
receipt's *text* is never authenticated by anything, so a rewritten
receipt line — one that claims a higher epoch, a later `permitted at`, a
different action, a different counter — opens and parses. Nothing in
the container says "the issuer wrote this line".

The receipt was meant to travel inside the forward-sealed chain (whose
records are HMAC-sealed and hash-chained). That wiring does not exist.
This slice closes the gap the other way round: it makes the receipt
line itself carry a signature, so the receiver can decide *without*
trusting the chain.

## 2. The signing scheme

**What is signed.** The receipt's canonical bytes — the receipt's own
past-tense rendering, UTF-8 encoded. The canonical form is pinned in
`signed_receipt.py`:

* field order (`CANONICAL_FIELD_ORDER`):
  `receipt:<digest>`, `grant:<grant_id>`, `version=<v>`,
  `counter=<c>`, `permitted at <seq>`, `epoch=<n>`, `clock=<id>`,
  `issuer=<id>`, `action=<a>`, `subject=<s>`;
* separator (`CANONICAL_SEPARATOR`): `;`;
* trailing clause: `check the list for now`;
* encoding (`CANONICAL_ENCODING`): UTF-8.

`canonical_receipt_text()` additionally requires the canonical text to
equal `ArtifactReceipt.render()` byte for byte. If upstream ever drifts
from this module, signing **fails closed** instead of signing something
ambiguous.

**Who signs.** The issuer: the body that issued the grant, holding an
Ed25519 seed. `sign_receipt(receipt, issuer_seed)` calls
`message_signing.sign_message` — the existing primitive — with the
canonical receipt bytes carried verbatim in the signed message's
payload (hex-encoded under the key `receipt_bytes`). The Ed25519
primitive is **reused, not reimplemented**: this module does not
implement Ed25519 itself, and it does not reimplement a signature
format.

**Who verifies.** Whoever reads the receipt, with the issuer's public
key. `verify_signed_receipt(signed, issuer_pubkey)`:

1. refuses a non-`SignedReceipt` input (an unsigned receipt cannot enter
   the signed path);
2. verifies the signature over the signed body under the issuer's public
   key — a failure raises `SignatureMismatchError`;
3. requires the signed body to carry exactly this receipt's canonical
   bytes — otherwise `CanonicalReceiptError`;
4. requires the canonical bytes to parse back into exactly this receipt
   — otherwise `CanonicalReceiptError`;
5. requires the receipt's issuer key identifier to be the digest of the
   key it was verified under — otherwise `IssuerKeyError`;
6. only then returns the receipt.

Order matters: the signature is checked **before** the receipt is
accepted. Every defect is an explicit exception. There is no code path
in which a mismatching signature is silently accepted, and no path in
which an unsigned receipt is accepted by the signed path.

**What the caller gets.** The receipt, as it was signed. The receipt is
parsed out of the signed canonical bytes, so what comes back is exactly
what was signed — not what the caller happened to hand in.

## 3. What it proves, and what it does not

It **proves**:

* the holder of the issuer's Ed25519 seed wrote **this exact receipt
  text**. A receipt line rewritten in any of the four ways the design
  doc names — a higher epoch, a different `permitted at` clause, a
  different action, a different counter — no longer verifies;
* a tampered signature, a signature made by another key, and a receipt
  with no signature are all refused.

It **does not prove**:

* **clock independence.** The receipt still only *names* a clock. The
  signature says "the issuer wrote this"; it does not say the epoch was
  read off a clock the issuer does not control. `artifact_authority`
  refuses `clock_id == issuer_id`, and that refusal is unchanged — but
  refusal is not proof, and this slice does not upgrade it.
* **that the grant was real.** The signature authenticates the issuer's
  statement, not the truth of the statement. A grant that never existed
  can be signed. The grant's truth is still the seal layer's and the
  tombstone set's business, and those checks are unchanged.
* **that the counter or the epoch was the right one.** The signed
  receipt says what the issuer said; it does not say the counter was
  current.
* **that the receipt is still in force.** A valid signature does not
  make a revoked receipt valid. The read-time check
  (`artifact_authority.verify`, epoch and tombstone) is a separate gate
  and is unchanged; the signed path adds a gate *before* it, it does not
  replace it.

The unsigned path is deliberately left exactly as it was:
`artifact_authority.verify` still takes an unsigned receipt, and
`open_sealed` still opens a container whose receipt line was rewritten.
This slice adds a signed path; it does not change the old one. Callers
who need forgery detection use the signed path.

## 4. Relationship to the key-custody slice

**No dependency, in either direction.** The key-custody module (the
asinhhc slice) is a separate concern — where a long-term key lives and
who may use it. This module holds **no key material**: it signs with a
seed the caller hands it and stores only the issuer's public key and
its `sha256:` identifier alongside the receipt.

Both reuse the same primitive, `message_signing`, which is the point:
the signing format is the repo's, not a per-slice invention. A caller
that wants the issuer's key to come from the key-custody module can
fetch the seed from there and pass it in; this module neither requires
nor forbids that.

`artifact_authority.py` and `message_signing.py` are **read-only reused**:
both files are unchanged by this slice (diff empty). The receipt type,
its rendering and its parsing all come from `artifact_authority`.

## 5. Open items

* **The signed path is not wired into the dispatch path.** It is a
  library call, like `artifact_authority.verify` before it. Nothing in
  the host consults it yet; a reader must call it explicitly.
* **No trust anchor management.** The verifier is handed the issuer's
  public key by the caller. Where that key comes from — a directory, a
  configuration, a chain of delegation — is not settled here, and the
  key-custody slice is the natural place for it.
* **No key rotation story.** A receipt signed by a retired key verifies
  only under that key. Whether an issuer's old receipts stay verifiable
  is a policy question this slice does not answer.
* **The receipt is not yet inside the forward-sealed chain.** The
  original design intended the chain to authenticate the receipt; this
  slice authenticates the receipt directly instead. Both would be
  compatible, but the chain wiring still does not exist.
* **No revocation of signatures.** A signature is not revocable: an
  issuer key that is known-compromised needs a policy, not a code path.
* **The packaging declaration is owed.** The runtime component's
  `test_module_layout` test asserts that every module on disk appears in
  `[tool.setuptools] py-modules`; that test already fails at this
  slice's parent commit, and `signed_receipt` joins the same list. This
  slice's writable-file set covers only the module, its tests and this
  design doc, so the declaration is left to the slice that owns the
  packaging metadata.
* **Verbatim source text.** The gap quote above is from
  `docs/design/artifact-authority.md` §7 in this repository, quoted
  verbatim; the underlying vina post is not in this repository and was
  not fetched during this slice, so the gap is carried
  verbatim-as-briefed, not independently re-verified against the live
  post.
