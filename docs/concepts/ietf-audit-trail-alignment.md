# IETF draft-sharif-agent-audit-trail alignment

Status note, read first: `draft-sharif-agent-audit-trail-06` ("Agent Audit
Trail: A Standard Logging Format for Autonomous AI Systems", R. Sharif,
CyberSecAI, 2026-09-29, expires 2027-04-02) is an **individual
Internet-Draft, not a working-group standard**. Internet-Drafts are works
in progress and may change or expire. Northstar treats this draft as an
**interoperability target, not a stable dependency** — we align where the
cost is low and the benefit is real, and we document where we deliberately
do not follow it. (clawcrate took the same stance with its own alignment
mapping.)

All draft citations below were verified against the -06 text fetched from
the IETF archive on 2026-10-03. Section numbers refer to that revision.

## 1. What the draft specifies (crypto-relevant parts)

**Canonicalization (§6.1, §10.4).** JCS (RFC 8785) is MANDATORY:
"Implementations MUST use JCS (RFC 8785) for canonicalization.
Alternative canonicalization schemes MUST NOT be used, as they would break
chain verification across implementations." Any serialization outside the
native JSONL store (Syslog/CSV export, re-materialization) MUST also use
JCS so a round-tripped record re-verifies.

**Hash construction (§6.1).** `prev_hash(N) = hex(SHA-256(JCS(record(N-1))))`
where `record(N-1)` is the *complete* previous record — all fields as
stored, **including its signature fields**, excluding only the detached
`batch` object (§6.4). The genesis record's `prev_hash` MUST be null.

**Signature envelope (§6.2).** The signed message is the JCS serialization
of the complete record **minus** the signature-value fields (`signature`,
and `signature_classical` in hybrid mode) and minus the detached `batch`
object — with `sig_alg`, `signer_kid` (and `signer_kid_classical`) set
*before* signing so the signature covers them. Procedure: JCS → SHA-256 →
sign the 32-byte hash. `ES256` (default) is ECDSA P-256 per FIPS 186-5,
IEEE P1363 fixed-length `r||s`, Base64url. `ML-DSA-65` (FIPS 204, added in
-04) signs the same 32-byte hash; hybrid mode carries both signatures
under distinct keys. `signer_kid` is an RFC 7638 JWK thumbprint. With MCPS,
the signing key SHOULD be the agent's Agent Passport key.

**Chain verification (§6.3).** Genesis must have `parent_record_id = null`
and `prev_hash = null`; each record recomputes
`hex(SHA-256(JCS(record(N-1) without batch)))`; signatures verify over the
canonical bytes with sig-value fields and `batch` removed, key resolved via
`signer_kid` (`ES256` if `sig_alg` absent); timestamps must be monotonic
non-decreasing; `parent_record_id(N)` must equal `record_id(N-1)`; nonces
must not repeat; `batch` objects MAY additionally get Merkle inclusion
checks but MUST NOT substitute for the `prev_hash` checks. Absence checks
are optional and need out-of-band inputs: gap-free `sequence_number`,
heartbeat cadence, externally anchored head (the presented chain must be
consistent with and no shorter than the anchored head). Tail completeness:
without a session-close record, a heartbeat cadence, or an external
anchor, completeness is inconclusive — "a bare hash chain proves that no
interior record was altered; it cannot, by itself, prove that records
were not removed from the tail."

**Optional Merkle batch anchoring (§6.4).** Complements, never replaces,
the chain. RFC 6962 construction: `leaf = SHA-256(0x00 || JCS(record
without "batch"))`, `internal = SHA-256(0x01 || left || right)`, odd node
promoted unchanged; leaves ordered by zero-based `leaf_index`; root is
64-char lowercase hex `merkle_root`. The root SHOULD be anchored to an
independent authority: RFC 3161 TSA token, WORM storage, or an
append-only transparency log. Anchoring cadence SHOULD be declared in the
genesis record's `action_detail.anchor_interval_s`. The `batch` object is
detached: excluded from the leaf hash, from `prev_hash`, and from the
signed message.

**Genesis record (§8.1).** Every session begins with one:
`action_type = "lifecycle"`, `action_detail.event = "session_start"`,
`parent_record_id = null`, `prev_hash = null`,
`record_phase = "concurrent"`; SHOULD carry config hash, enabled tools,
and `recording_mode` ("self"/"independent").

**Record taxonomy (§3, §7).** Mandatory fields cover agent identity,
action classification, outcome tracking, trust level;
`action_type ∈ {tool_call, tool_response, decision, delegation,
escalation, error, lifecycle}`.

## 2. Item-by-item comparison

| # | Item | draft-sharif -06 | Northstar (this batch) | Verdict |
|---|---|---|---|---|
| 1 | Canonicalization | JCS (RFC 8785), MUST; alternatives MUST NOT | `northstar-audit-chain/1`: legacy (sort_keys + compact separators + `ensure_ascii=False`) — close to JCS but differs on control-char escapes (`\n` vs `\u000a`), key sort order (code points vs UTF-16 code units), float formatting; `northstar-audit-chain/2` (new default): true JCS | ✅ **Aligned** — v2 implements RFC 8785; v1 kept as legacy verifier |
| 2 | Hash input | `SHA-256(JCS(`*complete previous record*`))`, signature fields included, `batch` excluded | `SHA-256(raw32(prev_hash) \|\| canon(body))`, body = record minus seal/signature fields; chain topology folds the previous link, not the previous record | ❌ Not aligned — deliberate design difference (§3.1) |
| 3 | Genesis linkage | `prev_hash = null`, `parent_record_id = null` | `prev_hash = SHA-256(canon(genesis_params))`; genesis params stored on record 0 and bound to session/run | ❌ Not aligned — deliberate design difference (§3.2) |
| 4 | Signature coverage | JCS(record − sig-value fields − `batch`); covers `sig_alg`/`signer_kid` | `canon(record − "signature")`; covers chain fields + `key_id`, binding the signature to the chain position | ✅ Structurally parallel; v2 uses JCS bytes like the draft |
| 5 | Signature algorithm | ES256 (ECDSA P-256, P1363, Base64url) default; ML-DSA-65 optional; hybrid mode | Ed25519 (vendored pure-Python RFC 8032), hex-encoded | ❌ Not aligned — deliberate choice (§3.3) |
| 6 | Signer identity | `signer_kid` = RFC 7638 JWK thumbprint; SHOULD bind to Agent Passport key under MCPS | `key_id`: free-form string ≤ 200 chars, operator-managed (`audit keygen`) | ❌ Not aligned — different identity model (§3.4) |
| 7 | External anchor mechanism | Optional Merkle batch (RFC 6962) + root → RFC 3161 TSA **or** WORM **or** append-only transparency log | Offline anchor manifest + Sigstore Rekor (a transparency log) via DSSE + WORM archive packages (S3 Object Lock) | ✅ Compatible — Rekor *is* the draft's "append-only transparency log" option; WORM matches too. Merkle batching itself not implemented (optional in the draft) |
| 8 | Tail-truncation / wholesale-rewrite detection | close record, heartbeat cadence, or anchored head (§6.3 steps 9–10) | anchor manifest (file hash + head hash + record count); Rekor head anchor; archive manifest | ✅ Same security property, different mechanism |
| 9 | Verifier extras | monotonic timestamps, `parent_record_id` linkage, nonce dedup, sequence gaps | genesis session/run expectation, chain links, signatures, anchor checks; **`verify --strict` adds timestamp monotonicity (configurable clock-skew) and nonce dedup (§3.5)** | ✓ Aligned (opt-in) — sequence-gap/heartbeat checks remain out of band |
| 10 | Tombstone deletion (GDPR Art. 17, §9.3) | Specified: tombstone preserves id/timestamp/parent/prev_hash, new signature by deleting authority, `tombstone_hash` for the accepted break | Not implemented | ❌ Not aligned — future work, no chain break semantics yet |
| 11 | Record envelope / taxonomy | AAT record: `record_id`, `agent_id`, `action_type` taxonomy, `trust_level`, `record_phase`, … | `audit.ndjson/1` envelope (own taxonomy: `schema_version`, `component`, `event`, `payload`, …) | ❌ Different envelope — out of scope; interop would need a translator, not a chain change |
| 12 | Retention | 12 months recommended for high-risk (Art. 12 minimum is 6) | WORM archive default 180 days (Art. 12 minimum) | △ Minimum met; longer retention is operator policy |

## 3. Deliberate non-alignments (and why)

### 3.1 Hash input topology

The draft hashes the *complete previous record* (signatures included);
Northstar hashes `raw32(prev_hash) || canon(body)` with seal/signature
fields excluded from the body. Both transitively bind the full history —
forging any record breaks every later link — and both exclude
late-arriving metadata from the hash input (the draft excludes `batch`;
we exclude the seal/signature fields). Adopting the draft's exact formula
would change every `chain_hash` in existence and buy nothing unless we
also adopted the draft's record envelope (§2.11), which is a different
specification decision, not a bug fix. Our topology additionally keeps the
signature *out* of the hash input and *in* the signature's coverage, so
"signature binds chain position" holds without circularity. **Not
changing.**

### 3.2 Genesis linkage

The draft's null genesis is the minimal choice for a format that must
span mutually untrusting implementations. Northstar's genesis anchor
(`SHA-256(canon(genesis_params))` binding component/session/run/started
time) is *stronger* for our threat model: a verifier that expects a
particular run detects a wholesale rewrite with a fresh chain, which a
null genesis cannot. The draft achieves the equivalent through external
anchoring (§6.4 cadence in genesis). Different shape, same goal.
**Not changing.**

### 3.3 Signature algorithm

ES256 vs Ed25519 is a genuine fork. Rationale for staying on Ed25519:
deterministic signatures (no RNG failure mode — the draft's ECDSA needs a
strong per-signature nonce), a vendored pure-Python implementation with no
new dependencies, and 128-hex-char fixed encoding that fits the existing
contract validator. ECDSA P-256 from scratch (or a new dependency) and
ML-DSA-65 are not low-cost, and the draft's algorithm registry is
extensible — a future revision could register Ed25519. If the draft
becomes an RFC with a fixed registry, we will revisit. **Not changing
now; tracked.**

### 3.4 Signer identity

RFC 7638 thumbprints assume JWK key material; Northstar's `key_id` is
deliberately opaque (it may name an HSM slot, a file, or a thumbprint —
the operator decides). A `key_id` value *may* be a JWK thumbprint today;
nothing forbids it. **Not changing.**

### 3.5 Verifier extras

Monotonic timestamps and nonce deduplication are now implemented as an
opt-in strict-mode verifier flag (`audit verify --strict`, with
`--clock-skew` configuring the allowed timestamp regression, default
300s), exactly as foreshadowed: they change `verify` semantics for
existing feeds (a feed with a clock-skewed record newly fails), so they
stay out of the default path. **Implemented, opt-in — not in default
verify.** Sequence-gap and heartbeat-cadence absence checks remain
out-of-band by design (they need inputs no offline verifier has).

## 4. What this batch changed

* `audit_chain.py`: new `jcs_canonical_json()` — a from-scratch RFC 8785
  implementation (UTF-16 code-unit key order, `\u00XX` escapes, no short
  escapes, ECMAScript `Number.prototype.toString`, NaN/Infinity rejected,
  `-0` normalized).
* New chain version `northstar-audit-chain/2`: identical topology to v1,
  JCS canonicalization. **New chains default to v2.**
* Version dispatch everywhere it matters: `genesis_hash`,
  `chain_record`/`chain_records` (`chain_version=` parameter),
  `sign_record`/`verify_signature`, `verify_lines`. v1 feeds — including
  the fixed vectors in `docs/concepts/audit-proof-spec.md` §11 and every
  feed sealed before this change — verify exactly as before; the version
  stamp rides inside the hashed body, so a cross-version splice breaks
  the chain loudly instead of verifying under the wrong rules.
* Envelope validators (`northstar-agent-runtime/audit_export.py`,
  `northstar-run-contract/audit.py`) accept the new `chain` field.
* Proof spec: §3 now defines both canonicalizations and the version
  rule; §11 keeps the v1 vectors (frozen) and gains a v2 vector.

## 5. Interop outlook

With v2, Northstar's *hash and signature inputs* are computed the way the
draft mandates (JCS). What still separates a Northstar v2 feed from a
draft-conformant AAT trail is the envelope (field names, genesis shape,
hash topology, signature algorithm) — a mechanical translator could map
one to the other, and the JCS alignment means translated records would
hash identically on both sides. That translator is not built in this
batch; the draft is still an individual submission and may change before
any RFC.

## 6. Follow-up: strict verifier mode

The §3.5 deferred items landed as `audit verify --strict`:

* **Timestamp monotonicity** — `ts` must parse as RFC 3339 UTC `Z` and
  may regress at most `--clock-skew` seconds (default 300) behind the
  previous record; violations fail at the offending record's line.
* **Nonce dedup** — the draft's "nonces must not repeat", checked
  opportunistically on records carrying a `nonce` field (the
  `audit.ndjson/1` envelope does not mandate one).

Opt-in only: default `verify` semantics are byte-for-byte unchanged, so
old feeds keep verifying. The remaining §6.3 extras (`parent_record_id`
linkage = the hash chain itself; tail completeness = head/external
anchor) were already covered without strict mode; sequence-gap and
heartbeat absence checks stay out of band — no offline verifier can do
them.
