# Audit proof spec: tamper-evident `audit.ndjson/1` feeds

**Status:** normative for the chain/signature/anchor formats described here.
**Version:** `northstar-audit-chain/1`.
**Applies to:** every `audit.ndjson/1` feed, regardless of producer
(`northstar-agent-runtime`, `northstar-durable-run`, `northstar-host`).

This document is written so that a third party who has never read Northstar
code can implement an independent verifier. §10 gives fixed test vectors:
if your verifier reproduces them byte-for-byte, it interoperates.

## 1. Vocabulary (read this first)

* **Integrity seal** (hash chain): proves *this exact byte sequence has not
  been modified* since sealing, **provided the verifier already trusts the
  genesis anchor**. It is **not** a digital signature and must never be
  called one.
* **Digital signature** (Ed25519, optional): proves *this key holder
  produced this record* (non-repudiation). It is layered **on top of** the
  chain, never instead of it.
* **Head anchor**: an external pin of the chain head (hash + record count),
  stored where the feed operator cannot rewrite it. The chain alone cannot
  detect a wholesale rewrite with a fresh chain, or tail truncation — the
  anchor exists exactly for those two attacks.

## 2. Envelope extension

The chain fields are **optional envelope fields within `audit.ndjson/1`**
(legacy feeds without them still validate; a verifier reports them as
*unprotected*, never as corrupt):

| field | type | rule |
|---|---|---|
| `prev_hash` | string | 64 lowercase hex chars (32 raw bytes) |
| `chain_hash` | string | 64 lowercase hex chars |
| `genesis` | object | anchor params; present on the first chained record only |
| `signature` | string | 128 lowercase hex chars (Ed25519), optional |
| `key_id` | string | non-empty, ≤ 200 chars; names the signing key |

## 3. Canonical JSON

Every hash and every signature is computed over **canonical JSON**. Two
chain versions exist (see also
`docs/concepts/ietf-audit-trail-alignment.md`):

* `northstar-audit-chain/1` (legacy): `sort_keys = true`, separators
  `(",", ":")` (no whitespace), UTF-8 encoding, `ensure_ascii = false`
  (non-ASCII is emitted raw, then UTF-8 encoded — never `\uXXXX`
  escapes), numbers as JSON numbers, no NaN/Infinity. This is
  byte-identical to one NDJSON feed line for the same record. It is *close
  to* JCS but not JCS (control characters use short escapes, keys sort by
  code point, floats follow the host language's formatting).
* `northstar-audit-chain/2` (current default): the JSON Canonicalization
  Scheme, **JCS (RFC 8785)** — the canonicalization mandated by
  draft-sharif-agent-audit-trail §6.1. UTF-16 code-unit key order,
  `\u00XX` escapes (no short escapes), ECMAScript
  `Number.prototype.toString`, NaN/Infinity rejected, `-0` normalized to
  `0`. Implemented from scratch in `audit_chain.jcs_canonical_json`
  (stdlib only, no new dependencies).

The version is stamped on the genesis anchor (`genesis.chain`) and on
every v2 record's hashed body (`record.chain`); verifiers dispatch on it,
so v1 feeds verify forever under the legacy rules. A v1 feed and a v2
feed over identical payloads produce *different* hashes — the version
stamp is part of the hashed body, and a cross-version splice breaks the
chain loudly rather than verifying under the wrong rules.

## 4. Chain construction

Definitions:

* `canon(x)` = canonical JSON bytes of `x` (§3) — legacy form for
  `northstar-audit-chain/1`, JCS for `northstar-audit-chain/2`.
* `body(record)` = the record **minus** `prev_hash`, `chain_hash`,
  `signature`. (`genesis`, `key_id`, and the v2 `chain` version stamp stay
  **inside** the hashed body.)
* `raw(h)` = the 32 bytes decoded from 64 hex chars.

Genesis:

```
genesis_params = {
  "chain":          "northstar-audit-chain/1",
  "schema_version": "audit.ndjson/1",
  "component":      <producer, e.g. "northstar-agent-runtime">,
  "session_id":     <optional>,
  "run_id":         <optional>,
  "started_ts":     <optional RFC 3339 UTC>
}
genesis_hash = sha256(canon(genesis_params))          # hex, lowercase
```

The anchor binds the chain to the run/session the feed *claims* to
describe. A verifier that expects a particular run compares the stored
`genesis` object against its expectation (`--expect-session-id`); a
rewritten history with a fresh chain fails that comparison.

Per record `i` (0-based):

```
prev_hash_0 = genesis_hash
record_0["genesis"] = genesis_params        # before hashing
chain_hash_i = sha256(raw(prev_hash_i) || canon(body(record_i)))   # hex
prev_hash_{i+1} = chain_hash_i
```

If the feed is later signed, `key_id` must be baked into the body **at
chain time** (it is part of `body(record)`); adding it afterwards changes
the sealed bytes.

## 5. Verification algorithm

Input: the feed's lines in order. Blank lines are skipped (but physical
line numbers are used for error positions).

1. Parse each non-blank line as JSON; a non-JSON line or non-object line is
   `INVALID`.
2. If **no** record carries `chain_hash`: the feed is `UNPROTECTED`
   (legacy). Report, do not error.
3. If **some** records lack `chain_hash`: `BROKEN` at the first unchained
   line — a chain with a hole is not a chain.
4. For each record `i`:
   a. `prev_hash`/`chain_hash` must be 64 lowercase hex, else `BROKEN`.
   b. If `i == 0`: `genesis` must be an object and
      `sha256(canon(genesis)) == prev_hash`, else `BROKEN`. Optionally
      compare `genesis.session_id` / `genesis.run_id` to expectations.
   c. If `i > 0`: `prev_hash_i == chain_hash_{i-1}`, else `BROKEN`
      (reorder or splice).
   d. Recompute `sha256(raw(prev_hash) || canon(body(record)))`; mismatch
      with `chain_hash` → `BROKEN` at this line (modified after sealing).
5. Signatures (only when the verifier was given a public key):
   a. A signed record with no public key given → `BROKEN` (refuse to
      silently skip).
   b. `ed25519_verify(pubkey, canon(record minus signature), signature)`
      must hold, else `BROKEN` at this line.

Result shape: `ok`, `broken_at` (1-based line or null), `records`,
`chained`, `unprotected`, `reason`.

## 6. Signatures

* Algorithm: Ed25519, pure (no prehash, no context), RFC 8032.
* Signed bytes: `canon(record minus "signature")` — the chain fields are
  covered, binding the signature to the chain position.
* `signature` = 64-byte signature as 128 lowercase hex chars.
* Key management is the operator's responsibility: `northstar audit keygen`
  mints a seed/public pair; the seed never leaves the signing host.
* A verifier with no public key ignores unsigned records but **refuses**
  signed ones (§5.5a) — a signature that nobody checks is decoration.

## 7. Head anchor manifest (offline half)

`northstar audit anchor feed.ndjson --out manifest.json` writes:

```json
{
  "anchor": "northstar-audit-anchor/1",
  "chain": "northstar-audit-chain/1",
  "feed_sha256": "<sha256 of the whole file bytes, hex>",
  "head_chain_hash": "<chain_hash of the last chained record or null>",
  "records": <non-blank line count>,
  "anchored_at": "<optional RFC 3339>"
}
```

`audit verify --anchor manifest.json` additionally requires: file bytes
hash equal, head hash equal, record count equal. This detects the two
attacks the bare chain cannot see: wholesale rewrite and tail truncation.

## 8. External anchoring via Rekor (implemented)

`northstar audit anchor-external <feed> --out anchor.json --seed-hex <hex>`
submits the head chain hash to the Sigstore Rekor transparency log and
writes the anchor record (`northstar-rekor-anchor/1`):

* The anchored statement is canonical JSON — `feed_sha256`,
  `head_chain_hash`, `records`, `anchored_at` — wrapped in a DSSE envelope
  (`application/vnd.northstar.audit-anchor+json`) and signed with the
  operator's Ed25519 key. The PAE follows secure-systems-lab/dsse v1.0.0.
* The entry is submitted as a Rekor v1 `dsse` entry
  (`POST /api/v1/log/entries`, no account, no registration). The record
  keeps `uuid`, `log_index`, `integrated_time`, the payload, its sha256,
  the signature and the public key — everything a verifier needs.
* `northstar audit verify --external-anchor anchor.json` checks, in order:
  the local chain, that the anchor pins the feed's current head, the
  anchor's DSSE signature (offline), then re-fetches the canonical entry
  from the public log by log index and compares `payloadHash` and the
  verifier key. Exit 5 means the external anchor could not be confirmed
  (mismatch, or the log was unreachable) — never a silent pass.

Trust assumptions (read before relying on this):

1. You trust the Sigstore public-good Rekor operators not to equivocate.
   A compromised log could backdate `integratedTime`; the ecosystem runs
   witnesses/monitors, but this client does not verify them.
2. The anchor proves *the key holder* pinned *this head* no later than
   `integratedTime`. It does **not** prove the feed is complete — an
   operator can anchor a truncated feed. The archive's record count and
   the hash chain mitigate that; the log cannot.
3. `integratedTime` is the log's claim, not a qualified timestamp. Where
   eIDAS-style legal weight is needed, use an RFC 3161 TSA instead
   (documented alternative; not implemented — it needs hand-rolled
   ASN.1 DER and CMS verification, a larger change for the same
   "existed at T" property).
4. Only hashes and counts enter the public log — no feed content, no PII.
5. Pinned to the Rekor **v1** API (verified live 2026-10-03). Sigstore is
   migrating to a v2 (rekor-tiles) API; if v1 is retired, `audit_rekor.py`
   needs a v2 port. The anchor record stores `rekor_api: "v1"`.

## 9. WORM archiving (implemented)

`northstar sessions export <id> --chain --archive <dir>` writes a
`northstar-audit-archive/1` package:

```
<dir>/
  feed.ndjson            # the chained audit feed
  anchor-manifest.json   # offline head anchor (§7)
  external-anchor.json   # Rekor anchor record (§8), only with --with-external-anchor
  archive-manifest.json  # sha256 of every file, head hash, record count,
                         # retention window (default 180 days, EU AI Act Art. 12)
```

`northstar audit verify-archive <dir>` re-checks file hashes, the feed
chain, the offline anchor and the external anchor's signature — all
offline. `--online` additionally re-fetches the Rekor entry.

The package is storage-agnostic. For WORM semantics upload it with
`scripts/s3-worm-upload.sh <dir> s3://bucket/prefix`, which verifies the
package first, then `put-object`s every file with S3 Object Lock
`COMPLIANCE` mode retained until the archive's own `retain_until`
(manifest uploaded last, so a reader that finds it sees a complete
package). The bucket must have Object Lock enabled at creation time.

## 10. CLI reference

* `northstar audit verify <feed>` — exit 0 `OK`, 1 `BROKEN`, 2
  `UNPROTECTED`, 3 `INVALID`, 5 external anchor unconfirmed. Flags:
  `--pubkey <hex>`, `--expect-session-id`, `--expect-run-id`,
  `--anchor <manifest>`, `--external-anchor <record>`, `--rekor-url`, `--json`.
* `northstar audit anchor <feed> --out <manifest>` — offline, no network.
* `northstar audit anchor-external <feed> --out <record> --seed-hex <hex>`
  — needs network; exit 4 on any failure (never a silent non-anchor).
* `northstar audit verify-archive <dir> [--online]` — verify a WORM package.
* `northstar audit keygen [--json]` — mint an Ed25519 pair.
* `northstar sessions export --session-dir <dir> --chain <id>` — export a
  transcript as a chained feed (genesis anchored to the session).
* `northstar sessions export --session-dir <dir> --chain --archive <dir> <id>`
  — write a WORM archive package instead of printing the feed.

## 11. Test vectors

The three-line feed below is fixed. A conforming verifier must reproduce
every hash shown, report `OK` over the 3 records, report `BROKEN at line 3`
after changing `"hello"` to anything else in line 2's payload, and report
`UNPROTECTED` for the same records without the chain fields.

Genesis params canonical form:

```
{"chain":"northstar-audit-chain/1","component":"northstar-agent-runtime","schema_version":"audit.ndjson/1","session_id":"ns-vector-fixture","started_ts":"2026-10-03T10:00:00.000Z"}
```

`genesis_hash = sha256(canon(above)) = 0223006af268e483502c3c2fe7cc3e9900727a8c73e87cf35f5ab613f8093fc2`

Feed (each line is one record; line breaks added for readability):

```
{"chain_hash":"89b21d688c05fb86a9325d3d578d08ded59fabab2d057b1900ff8233ffd2cbf1","component":"northstar-agent-runtime","event":"session_start","genesis":{"chain":"northstar-audit-chain/1","component":"northstar-agent-runtime","schema_version":"audit.ndjson/1","session_id":"ns-vector-fixture","started_ts":"2026-10-03T10:00:00.000Z"},"level":"info","payload":{},"prev_hash":"0223006af268e483502c3c2fe7cc3e9900727a8c73e87cf35f5ab613f8093fc2","schema_version":"audit.ndjson/1","seq":0,"ts":"2026-10-03T10:00:00.000Z"}
{"chain_hash":"8664b5c3cf5742583d793f627d2bc8cc6989dc40d59ed7d6f966d7380cc393d6","component":"northstar-agent-runtime","event":"assistant","level":"info","payload":{"text":"hello"},"prev_hash":"89b21d688c05fb86a9325d3d578d08ded59fabab2d057b1900ff8233ffd2cbf1","schema_version":"audit.ndjson/1","seq":1,"ts":"2026-10-03T10:00:01.000Z"}
{"chain_hash":"9de14bf3d0d0738b86c7c6d0daf983766236119e0bc31beb0050dd180f31ea6a","component":"northstar-agent-runtime","event":"denial","level":"error","payload":{"reason":"read-only","tool":"Write"},"prev_hash":"8664b5c3cf5742583d793f627d2bc8cc6989dc40d59ed7d6f966d7380cc393d6","schema_version":"audit.ndjson/1","seq":2,"ts":"2026-10-03T10:00:02.000Z"}
```

Check line 1 by hand: `body` = the record minus `prev_hash`/`chain_hash`
(`genesis` stays in); `chain_hash_0 = sha256(raw(0223006a…) || canon(body))`
must equal `89b21d68…`.

Ed25519 vectors: RFC 8032 §7.1 TEST 1–3 (empty message, `0x72`,
`0xaf82`; see `tests/test_audit_chain.py`).

### v2 vectors (JCS, `northstar-audit-chain/2`)

Same fixture shape, sealed under chain v2 (the current default). Note the
per-record `"chain": "northstar-audit-chain/2"` stamp inside the hashed
body, and that the genesis JCS bytes here coincide with the legacy form
(all keys are BMP, no control characters) — the hashes still differ from
v1 because the version stamp is part of the body.

Genesis params JCS form:

```
{"chain":"northstar-audit-chain/2","component":"northstar-agent-runtime","schema_version":"audit.ndjson/1","session_id":"ns-vector-fixture-v2","started_ts":"2026-10-03T10:00:00.000Z"}
```

`genesis_hash = sha256(JCS(above)) = b50ca8ab0f7039b433351e1051db519fb1eceb71d71f708cf0b53cd0a2442eed`

Feed:

```
{"chain":"northstar-audit-chain/2","chain_hash":"1508b8f95aa46e9a02bd1b3a03e09ed5712fb0a32d9fdaab61d5bdc1f5321921","component":"northstar-agent-runtime","event":"session_start","genesis":{"chain":"northstar-audit-chain/2","component":"northstar-agent-runtime","schema_version":"audit.ndjson/1","session_id":"ns-vector-fixture-v2","started_ts":"2026-10-03T10:00:00.000Z"},"level":"info","payload":{},"prev_hash":"b50ca8ab0f7039b433351e1051db519fb1eceb71d71f708cf0b53cd0a2442eed","schema_version":"audit.ndjson/1","seq":0,"ts":"2026-10-03T10:00:00.000Z"}
{"chain":"northstar-audit-chain/2","chain_hash":"88e7b1294e3b4aa5d8670c7b75e93b53177faae4b48dbebeed2ef881cfb3beca","component":"northstar-agent-runtime","event":"assistant","level":"info","payload":{"text":"hello"},"prev_hash":"1508b8f95aa46e9a02bd1b3a03e09ed5712fb0a32d9fdaab61d5bdc1f5321921","schema_version":"audit.ndjson/1","seq":1,"ts":"2026-10-03T10:00:01.000Z"}
```

A conforming verifier must reproduce every hash shown and report `OK`
over the 2 records.

## 12. Honest limitations

* The chain detects *modification*; without an external anchor it does not
  detect a *wholesale rewrite* (fresh chain, fresh genesis) — §7 exists for
  exactly this.
* Tail truncation is invisible to the bare chain; the anchor manifest's
  record count covers it.
* Signatures prove key-holder origin, not record truthfulness: a signer can
  still seal a lie. Non-repudiation ≠ correctness.
* The vendored Ed25519 is variable-time and audit-only; it is not suitable
  for online signing oracles.
* `genesis.session_id`/`run_id` are *claims* by the producer; they only
  bind when the verifier cross-checks them against independent knowledge.
