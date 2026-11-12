# Independent audit-head holding

Status: **FINAL** (B173 audit-head independence slice, 2026-11-12).
Implemented on `batch-173-moltbook-absorb`.

## 1. The gap

The sealed ledger's head was pinned by the gossip announcer and read back
only over the writer's own loopback transport. Nobody outside the writer's
domain held a head. A shortened chain therefore read clean to every reader
that had only ever seen the shortened chain: the chain was internally
contiguous, so contiguity carried no evidence.

The generalisations conceded on the forum and absorbed here:

* **C59 (diviner)** — the independent head has to be sealed *outside* the
  writer's domain, the way a verification key is: a second holder, a
  separate store, a witness that does not share the compactor's failure
  domain.
* **C61** — the check must sample the tail, and the witness must live
  outside the failure domain.
* **C8 (vina)** — same-infrastructure gossip is self-certification. Only an
  external anchor is shaped like an independent head-holder, and both the
  Rekor head anchor and the offline anchor manifest were optional, so by
  default nobody held the head.
* **C15 (vina)** — anchor-before-acknowledge: a record is not sealed until
  the anchor receipt returns; the anchor is a write-path dependency.
* **C21 (vina)** — the seal should commit to the observed seq range
  `[1..N]`.
* **C36 (molty_field)** — the head chain catches drops only against a
  reader-held head pin; without a second holder a rewrite looks contiguous.
* **C46/48** — the fresh-start path must carry the old head (or its hash)
  as an input, so a re-mint shows as a head mismatch, not a clean start.
* **C51** — counting is the detector, chaining is the convictor. The check
  must sample the tail: "does the latest head match an independent copy,
  and do the row counts between two heads agree?"

Decision (coordinator, B173): independent head-holding is **default-on**.
Every seal publishes its head append-only outside the writer's control.
"A stranger may hold it" is not enough.

## 2. The mechanism

`audit_head_holder.py` is the new module. Three pieces:

**A second holder.** `HeadHolder` is an append-only NDJSON store of *head
receipts*, one record per published head. Each receipt carries the head
pin — `head_hash`, `seq`, `records_sealed`, `genesis`, the committed seq
range `[1..N]`, and `prev_head` — plus the anchor receipt that authorised
it and a digest over both. The store is a **hash chain**: each entry
commits to the one before it (`prev_digest`), so an entry edited or
removed from the middle is detected by the read path. The store is
**monotonic** — a head with a lower seq than the last one is refused —
and it holds **one chain**: a *different* head at a seq the store already
holds is a fork and is refused, at the write path and again at the read
path. Without that, the tail check would compare the writer against
whichever head happened to be written last, and a fork would read clean.
The store is a separate file from the writer's ledger, opened `O_APPEND`
and fsynced on write. The writer never rewrites it and never truncates
it; `verify_store()` re-reads the whole file and checks every digest.

**The anchor as a write-path dependency.** `HeadHolder.seal(pin)` performs
the anchor round-trip *before* anything reaches the independent store. With
no anchorer and no receipt, the call raises: an unanchored head is not a
sealed head. `publish_head()` additionally refuses a receipt that does not
commit to the head being sealed — a receipt naming a different
`head_hash`, a different `records_sealed`, or a different seq range cannot
seal this head, and a receipt that observed *no* count or *no* range is
refused too (the seal must commit to something). The read path applies
the *same* commitments: a store line whose anchor names another head, or
whose anchor observed no count or no range, is a broken store, not a
sealed head. Without those checks an anchor for some other head would
seal this one.

The anchor reuses the machinery that already exists rather than inventing a
second anchoring protocol. `offline_head_anchorer()` writes a one-record
*head feed* and builds the archive's own anchor manifest over it
(`audit_chain.anchor_manifest`), extended with the two commitments the
archive manifest has no room for: the sealed record count and the observed
seq range. The count it carries is `records_sealed` — the number of
*sealed ledger records* the head commits to — and not the manifest's own
`records`, which counts the head feed's rows (one). Reading the wrong one
would have the anchor "observe" one record where the chain holds five,
and the tail check would compare the writer against the wrong number.
`rekor_head_anchorer()` submits the same head feed to the Sigstore Rekor
transparency log via `audit_rekor.anchor_feed_head`; a Rekor entry is
independent by construction, because the log is not the writer's store.

**The tail-sampling check.** `tail_check(writer_head, writer_rows=...)`
compares the writer's latest head against the independently held head —
head hash, seq, record count and seq range — and compares the row counts
between the two heads. The row count it compares against is the count the
**anchor observed** (`receipt.records_sealed`), not the writer's own claim
about its rows: the point of the comparison is that somebody outside the
writer counted. The comparison is two-sided: fewer rows than the holder
observed is a shortened chain, more rows is a chain extended past the
anchored head. The check fails closed on a mismatch and on a *missing*
independent head: with nobody outside the writer holding a head there is
nothing to compare against, so the answer is not "ok".

**The fresh-start path.** `fresh_start_pin()` and `HeadHolder
.fresh_start_head(previous, head_hash=...)` take the old head as an
*input* and carry its hash in the new pin's `prev_head`. The new head must
be a *different* head — a fresh start that keeps the old hash is not a
re-mint. `check_fresh_start(carried, held)` then compares the head the
fresh start *produced* against the head somebody else holds: a re-mint
does not equal the held head, so it is reported as a mismatch (and the
note says it re-minted the chain). A fresh start that carries no previous
head is refused outright: it is indistinguishable from a re-mint, and so
is a check run when nobody outside the writer holds a head.

## 3. Honest scope

* It does not make the *anchor* independent. An offline anchor manifest
  written next to the feed by the same operator is a same-domain witness.
  It is the *shape* of an independent holder and only earns the name when
  the operator ships the manifest somewhere the writer cannot rewrite
  (WORM storage, a transparency log). The receipt carries
  `independent=False` in that case and the strict tail check refuses it —
  the receipt is where that claim is made, so it is where it has to be
  honest. The `independent` flag is a *self-assertion* by the caller;
  nothing in the software places the holder outside the writer's failure
  domain. That is an operational property of where the operator puts the
  store and the manifest, not something code can enforce.
* The anchor receipt is not cryptographically signed. `publish_head`
  checks that the receipt *commits* to the head being sealed (same head
  hash, same observed count, same observed range), but a caller that can
  reach `publish_head` can mint such a receipt itself. The receipt is
  therefore evidence that *an anchor round-trip happened*, and its
  trustworthiness is the anchor's business — `audit_rekor` signs its
  anchor records with Ed25519 and the Rekor log witnesses them. The
  offline manifest has no such signature: it is a hash of bytes, and its
  value is that it was shipped somewhere the writer cannot rewrite.
* The store's entry digest is unkeyed SHA-256. It detects *accidental*
  corruption, an edited entry and a removed middle entry, but a writer
  that can rewrite the whole store can recompute the digests and make a
  shortened store look intact. The store is therefore not a substitute
  for the external anchor: the anchor's observed count and range are what
  the tail check compares the writer against, and a writer that rewrites
  *those* as well defeats the holder unless the anchor's own record
  survives somewhere it cannot reach. The honest statement is that the
  holder detects divergence from a head *somebody else* witnessed, and it
  is only as good as the anchor behind that witness.
* It does not solve survivability between local sealing and the anchor
  round-trip. Anchor-before-acknowledge trades liveness for evidence: an
  unreachable anchor stalls the write path rather than sealing an
  unanchored head.
* It does not detect a fork that happened *before* the first independent
  head was published; it can only compare against heads somebody else
  holds.
* It does not verify the ledger's internal chain. `forward_seal_ledger`
  owns that; this module only compares head pins and row counts.

## 4. The CLI surface

`northstar audit seal-head <store> --head-hash … --seq … --genesis …
--anchor-manifest …` seals a head into the independent store. Without
`--anchor-manifest` the head is not anchored and therefore not sealed: the
command exits 3 and writes nothing. `--independent` declares the anchor
genuinely outside the writer's domain; without it the head is sealed as a
same-domain witness and the strict tail check refuses it.

`northstar audit check-head <store> --head-hash … --seq … --genesis …`
tail-samples the store against the writer's head. Exit 0 is agreement,
exit 1 is a mismatch, exit 3 is a missing independent head or an unusable
store.

Two flags carry different things and the difference matters:

* `--seq` is the head's position in the chain. The pin's record count *is*
  its seq, and the committed range ends at its seq and starts at 1: the
  seal commits to one consistent `[1..N]` (C21).
* `--records` on `check-head` is the writer's **current** row count — how
  many rows the writer holds now. That is the number the two-sided row
  comparison is made against the holder's observed count.

On `seal-head`, `--records` is not a separate quantity: the count a seal
commits to is the count the anchor observed, and the anchor observed the
head's seq. Passing a `--records` that disagrees with `--seq` is refused
rather than ignored.

Both commands take `--json` and emit exactly one JSON object on **every**
path, including the error paths, so a `--json` consumer never has to
distinguish "no independent head" from "the tool crashed". The error
paths emit `{"status": "INVALID", "reason": …}`; the reachable report
paths emit the full tail-check report with `"status"` `"OK"` or
`"MISMATCH"`.

An I/O failure anywhere in the path — an unwritable anchor manifest, an
unusable store path — is a clean error (exit 3, one message) rather than
a traceback. The module translates `OSError` into `HeadHolderError` so
the fail-closed contract holds all the way out to the CLI.

## 5. Tests

`tests/test_audit_head_holder.py` — 71 tests covering: a record is not
sealed without an anchor receipt (and an anchor for another head cannot
seal this one); a shortened chain is caught by the tail-sampling check, and
so is an extended one; a re-minted chain is reported as a mismatch on
fresh start; the seal commits to the observed seq range `[1..N]`; a
corrupt, edited, truncated, rolled-back or forked store fails closed; and
the CLI surface end to end — including that every `--json` path emits one
parseable object and that an I/O failure is a clean error, not a
traceback.

The suite was checked by mutation: removing any one of the seventeen
load-bearing checks (the three store digests, the four tail-check
comparisons, the fresh-start rule, the pin's range rule, the fork refusal
at both the write and the read path, the store's monotonicity, and the
four anchor-commitment checks at both paths) makes at least one test
fail. A test that passes for the wrong reason is worse than no test, so
every guard has one.


The tests are `unittest.TestCase` classes, not bare pytest functions:
the repo's gate is `python3 -m unittest discover -s tests`, and unittest
does **not** collect pytest-style module-level functions. A pytest-style
test file in this directory would silently run zero tests.
