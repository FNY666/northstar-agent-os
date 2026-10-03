# TRACE v0.2 export (fiftieth batch)

`northstar audit export <feed.ndjson> --trace` reads a chained audit feed
and emits one **TRACE v0.2-shaped Trust Record** (JCS JSON) that commits
the audit chain head by hash. Pure software, offline, off the hot path —
no TEE involved.

## What it is

TRACE (Trust, Runtime Attestation, and Compliance Evidence) is the Linux
Foundation-hosted open specification (v0.2, Draft/RFC, pre-ratification)
for portable governance evidence about an AI agent execution. The spec
itself reserves the slot this export fills:

- §3.3.2 "External execution evidence": *"The TRACE Trust Record commits
  the audit chain by hash; the receipts live inside that chain, not
  inside the Trust Record itself."*
- §3.1.1 `origin.kind = "log-import"`: *"assembled from a log or export
  whose producer is not a control plane: a SIEM export, **an audit
  trail**, a batch job"* — which MUST carry
  `runtime.platform = "software-only"`.

Northstar's audit hash chain is the *behavior trace*; the exported Trust
Record is the *environment evidence* for it. Complementary, not
overlapping: TRACE answers "where, under what policy, which tools";
Northstar's bench and gate decisions answer "was each decision correct".

## Honesty rules (enforced in code and docs)

1. The export is described as a "**TRACE v0.2-shaped evidence record
   (software-only/log-import)**" — never "TRACE conformant".
2. TRACE v0.2 is a **Developer Preview**: fields, wire formats and
   conformance requirements may change before v1.0.
3. A software-only log-import record "does not launder assurance"
   (§3.1.1): it must never be presented as hardware-attested evidence.
4. Fields Northstar cannot honestly fill (model identity, SLSA build
   provenance, SCITT transparency receipt) are **omitted, never
   fabricated**. The record points at the feed via
   `references[].rel = "behavior-trace"` instead.
5. `policy.enforcement_mode` is `"enforce"` because Northstar really runs
   a policy gate (a producer that merely evaluates policy MUST NOT use
   `"declared"`).

## Field mapping

| Trust Record field | Value |
|---|---|
| `eat_profile` | `tag:agentrust-io.com,2026:trace-v0.2` |
| `tool_transcript.hash` | `sha256:<audit chain head hash>` |
| `tool_transcript.call_count` | count of `tool_result` records in the feed |
| `references[]` | `{rel: "behavior-trace", id, resolver: "northstar-audit-export", digest: "sha256:<feed bytes>"}` |
| `policy.enforcement_mode` | `enforce` (+ `bundle_hash` only via `--policy-bundle-hash`) |
| `origin` | `{kind: "log-import", producer: "northstar-audit-export", source_event_id, ingested_at}` |
| `runtime` | `{platform: "software-only", measurement: "sha256:<exporter identity digest>"}` (recomputable; makes no hardware claim) |
| `subject` | `did:northstar:run/<run-id>` (or session; Northstar-local DID) |
| `signature` / `cnf` | only with `--seed-hex`: embedded Ed25519 over JCS with `signature` absent (§3.2.2); unsigned records carry neither |

The export refuses unchained feeds (`UNPROTECTED`, exit 2) and broken
feeds (`BROKEN`, exit 3): there is no head worth committing otherwise.

## JCS cross-validation

Northstar's hand-written RFC 8785 implementation
(`audit_chain.jcs_canonical_json`) is cross-validated against the TRACE
spec's own conformance vectors in `tests/test_trace_export.py`:

- `examples/delegation-link/24-parent-key-supplementary-plane.json`
  (TRACE-DELEG-024): the root record's `cnf.jwk` carries a BMP
  private-use key (U+E000) and a supplementary-plane key (U+1F600); the
  spec publishes the leaf's `parent_record_hash` as the root's digest
  under UTF-16 code-unit key order. Northstar reproduces it exactly —
  and code-point order (`sorted()`) demonstrably gives a different
  digest, which is the shortcut the spec warns about.

## Next step (B): anchoring the Trust Record (design, not implemented)

The `transparency` field is left empty. To fill it:

1. Emit the Trust Record (`audit export --trace --out record.json`).
2. Anchor it in an append-only transparency log. The existing
   `audit anchor-external` flow (Sigstore Rekor DSSE) already anchors the
   *feed head*; pointing the same flow at the Trust Record file and
   writing the returned inclusion-proof URI into `transparency` is the
   minimal implementation.
3. Alternatively, register the record in the public TRACE Registry
   (append-only repo + PyPI verifier, no hosted query service).

Caveat (spec §7, open question): the long-term semantics of the
transparency-log operator (canonical vs federated vs BYO) are undecided
before v1.0 — anything anchored now should be treated as
point-in-time evidence, not a permanent settlement.

Deliberately out of scope: TEE quote anchoring (needs the v0.3 runtime
evidence profile, still proposed) and stuffing gate decisions into
TRACE (the spec fixes TRACE's remit to environment evidence; decision
correctness stays in the bench).
