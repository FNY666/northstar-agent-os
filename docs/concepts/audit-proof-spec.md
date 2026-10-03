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

Every hash and every signature is computed over **canonical JSON**:

* `sort_keys = true`, separators `(",", ":")` (no whitespace),
* UTF-8 encoding, `ensure_ascii = false` (non-ASCII is emitted raw, then
  UTF-8 encoded — never `\uXXXX` escapes),
* numbers as JSON numbers, no NaN/Infinity (feeds never contain them).

This is byte-identical to one NDJSON feed line for the same record.

## 4. Chain construction

Definitions:

* `canon(x)` = canonical JSON bytes of `x` (§3).
* `body(record)` = the record **minus** `prev_hash`, `chain_hash`,
  `signature`. (`genesis` and `key_id` stay **inside** the hashed body.)
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

**External anchoring (recommended, network-dependent, not in the default
path):** ship the manifest — or just its `feed_sha256` — to an RFC 3161
timestamp authority or a transparency log (Sigstore Rekor). The manifest is
designed so the external step is a dumb timestamp over 32 bytes; no
Northstar-specific protocol is needed. Until that step runs, the manifest
is only as trustworthy as its storage: keep it in WORM storage (below) or
hand it to a second party.

## 8. WORM archiving (design)

For regulated retention (e.g. EU AI Act Art. 12, 6 months): periodically
(e.g. at run end) package the feed **plus its anchor manifest** and write
the package to WORM storage — S3 Object Lock (`COMPLIANCE` mode) or any
equivalent. The package is the "immutable archive point": the manifest
inside pins the exact bytes, the Object Lock retention pins the manifest.
No Northstar code writes to S3 in this change; the manifest format (§7) is
the integration contract an archiving job needs.

## 9. CLI reference

* `northstar audit verify <feed>` — exit 0 `OK`, 1 `BROKEN`, 2
  `UNPROTECTED`, 3 `INVALID`. Flags: `--pubkey <hex>`,
  `--expect-session-id`, `--expect-run-id`, `--anchor <manifest>`, `--json`.
* `northstar audit anchor <feed> --out <manifest>` — offline, no network.
* `northstar audit keygen [--json]` — mint an Ed25519 pair.
* `northstar sessions export --session-dir <dir> --chain <id>` — export a
  transcript as a chained feed (genesis anchored to the session).

## 10. Test vectors

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

## 11. Honest limitations

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
