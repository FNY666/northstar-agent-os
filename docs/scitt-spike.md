# SCITT (RFC 9943) / COSE Receipts (RFC 9942) — export spike

**Status: spike (fifty-eighth batch). Not a feature, not a conformance claim.**

RFC 9943 ("An Architecture for Trustworthy and Transparent Digital Supply
Chains", Standards Track, June 2026) and RFC 9942 ("CBOR Object Signing and
Encryption (COSE) Receipts", Standards Track, June 2026) were read in full
(2026-10-03, rfc-editor.org). This document records the field-by-field
mapping from a Northstar audit feed to those structures, what maps cleanly,
what does not, and whether the standard is worth tracking long-term.

## The question

Our audit story today: `audit.ndjson/1` feed → `northstar-audit-chain/2`
hash chain (RFC 8785 JCS) → offline `anchor_manifest` → DSSE-signed anchor
statement → Rekor (Merkle-tree transparency log) → anchor record with
`log_index` / `integrated_time`.

SCITT asks: what if the statement and the transparency proof spoke one
standard language — a **Signed Statement** (COSE_Sign1,
`application/scitt-statement+cose`) plus **COSE Receipts** (COSE_Sign1,
`application/scitt-receipt+cose`) embedded in the statement's unprotected
header (label `394`) to form a **Transparent Statement**?

The spike (`components/northstar-agent-runtime/audit_scitt.py`,
`audit export --scitt`) builds a JSON-diagnostic model of exactly that, with
every integer label taken from the RFC 9943 §6.1 / RFC 9942 §4 CDDL.

## What maps cleanly

| RFC element | Our mapping | Notes |
|---|---|---|
| Signed Statement = `COSE_Sign1` (RFC 9943 §6) | Statement shape with protected/unprotected/payload/signature | JSON-diagnostic, not binary COSE |
| Protected `15` → CWT Claims `{1: iss, 2: sub}` | `iss` = `https://northstar-agent-os/keys/<key_id>`, `sub` = `audit-feed/sha256:<feed_sha256>` | §6 uses iss/sub to identify issuer and artifact; our namespace is self-asserted (no PKI) — stated, not hidden |
| Protected `1` (alg) = `-8` (EdDSA) | Our Ed25519 feed/anchor keys | Direct fit |
| Protected `3` (cty) | `application/vnd.northstar.audit-anchor+json` | Named like the DSSE payload type in `audit_rekor.py` |
| Protected `4` (kid) | `--key-id` (defaults to signing pubkey hex) | §6: kid MUST be present when no x5t/x5chain — our exact case (raw Ed25519) |
| Statement payload | The offline anchor manifest (`feed_sha256`, `head_chain_hash`, `records`) | §6 leaves payload format to the issuer; our manifest is already the canonical "this feed existed in this state" claim |
| Receipt protected `395` (vds) = `1` (RFC9162_SHA256) | Rekor is a Merkle-tree transparency log in the RFC 9162 family | Mapping by construction, not by a registry claim from the log |
| Receipt unprotected `396` → `{-1: [[tree_size, leaf_index, inclusion_path]]}` | `leaf_index` = our anchor's `log_index`, `tree_size` = `log_index + 1` | The one clean numeric bridge between our anchor record and the RFC model |
| Transparent Statement = statement + receipts under `394` | `add_receipts()` | Structural fit is exact |

## What does not map (honest gaps)

1. **No binary COSE/CBOR.** The repo is stdlib-only; there is no CBOR
   codec. The spike emits a JSON-diagnostic model. A real `COSE_Sign1`
   signature signs the CBOR-encoded `Sig_structure`, which we cannot produce
   byte-identically. Our "signature" is Ed25519 over the JCS-canonical JSON
   of the payload — useful for issuer binding in the spike, not a COSE
   signature. (Recorded on the signature object itself.)
2. **The receipt is not issued by a transparency service.** Rekor does not
   issue COSE receipts, so our receipt shape is self-modelled from our own
   anchor record and unsigned (`signature: None`, `receipt_status:
   "shape-only"`). A conformant receipt MUST be a TS-signed COSE_Sign1
   (RFC 9942 §4.3).
3. **The inclusion proof is incomplete.** The Rekor v1 submit response
   carries no Merkle audit path, so `inclusion_path = []` and `proof:
   "incomplete"`. `tree_size = log_index + 1` is a lower bound, not the
   log's true tree size at integration. (The v1 API has proof endpoints, but
   wiring them is beyond spike scope.)
4. **Issuer identity is self-asserted.** `iss` is our own URI namespace;
   there is no PKI, no DID, no trust anchor a relying party could check
   against. SCITT's registration policies and trust anchors (§5.1.1) are the
   missing half.
5. **Integer labels render as strings in JSON.** JCS/JSON cannot carry
   integer object keys; the in-memory model keeps the exact integers (the
   tests pin them), the encoding renders decimal strings. Documented in the
   bundle's `encoding_note`.

## Relationship to existing Rekor anchoring

The spike does not replace `audit anchor-external`; it *reinterprets* its
output. The anchor record (`uuid`, `log_index`, `integrated_time`,
`payload_sha256`) is precisely the material a SCITT receipt would need,
minus the Merkle path and the TS signature. Concretely:

- Today: DSSE envelope → Rekor v1 → anchor record (JSON, ours).
- SCITT-shaped tomorrow: statement payload = anchor manifest; receipt =
  anchor record + Merkle inclusion proof + TS signature; both verifiable by
  any RFC 9942/9943 implementation, not just our CLI.

The natural migration path, if the ecosystem moves: keep the hash chain and
anchor manifest untouched (they are the statement payload), add a CBOR/COSE
codec (or a minimal hand-rolled `Sig_structure` encoder — it's small), and
either run a SCITT transparency service or wait for one that accepts our
statement type. Rekor v2 (rekor-tiles) is the nearer-term migration; SCITT
is the longer-term standards shape.

## Verdict: worth tracking?

**Yes, as the long-term standard form of `audit export` + external
anchoring — no, not as near-term implementation.** Reasons:

- The mapping is *surprisingly* clean: our anchor manifest is already the
  right statement payload, our anchor record already carries
  `log_index`/`integrated_time`, and our Ed25519 keys fit `alg: -8`/`kid`
  exactly. The standard was clearly designed for systems shaped like ours.
- The gaps are all on the *verifier* side (CBOR codec, TS signatures,
  Merkle paths, trust anchors) — none require redesigning our feed.
- Near-term, Rekor v2 migration and the multisig/Cedar work (fifty-sixth
  batch era) have higher leverage. SCITT becomes actionable when (a) we
  need third-party verifiers to check our anchors without our CLI, or
  (b) a transparency service we trust starts issuing COSE receipts.

CLI: `audit export <feed.ndjson> --scitt [--seed-hex <hex>]
[--key-id <id>] [--rekor-anchor <anchor.json>] [--out <file>]`.
See `audit_scitt.py` for the mapping code and `test_audit_scitt.py` for the
label pins.
