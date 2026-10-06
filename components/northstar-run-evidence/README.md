# northstar-run-evidence

Dependency-free core data structures and hash-chain primitives for Northstar run evidence. Python 3.10+.

## Current scope

This component contains:

- strict, versioned `EvidenceRef` and `EvidenceEntry` data structures;
- deterministic canonical JSON (ASCII object keys, safe-range integers, no floating-point values) and domain-separated SHA-256 subject/entry digests;
- an append-only in-memory `EvidenceChain` with sequence, run identity, previous-digest and idempotency checks;
- `verify_chain()` for structured offline integrity results;
- `evidence_store.EvidenceStore`: a file-backed JSONL ledger (canonical entries, bounded strict parsing, POSIX `flock`, directory-fd pinning, fsynced same-directory copy-on-write replacement, and full chain verification on open; tampering fails closed);
- legacy sealed manifests: `EvidenceStore.seal(signer)` attests to the chain head; `verify_manifest()` / `verify_seal()` remain schema v1 and backward-compatible;
- `sealed_receipt`: a separate domain-separated `SealedRunReceipt` v1 binding explicit terminal completion claims, capture-policy identity, required/observed evidence sources, and per-source ledger tails to one validated chain snapshot;
- `verify_run_receipt()` with layered integrity, completeness, authenticity, and run verdicts. Verifying without the corresponding ledger deliberately leaves integrity and the overall run verdict unknown;
- `audit_adapter`: seals the runtime's canonical audit NDJSON feed (`audit.ndjson/1`) into an evidence store — one entry per audit record, strict RFC 3339 timestamps, idempotent re-seals — without the runtime depending on this component;
- `evidence_cli`: operator commands `seal` / `verify` over a store file and an HMAC key file (local test-grade sealing; not non-repudiation).

## Sealed run receipt

A receipt is sealed only when:

1. the evidence ledger loads and verifies as a non-empty chain;
2. the completion claim points to an entry in that exact snapshot;
3. all caller-declared required sources are present; and
4. the host-injected signer successfully signs the canonical receipt body.

The receipt records a terminal status (`finished`, `failed`, or `cancelled`), completion time, independent verifier verdict, optional observed test exit code, capture-policy revision/digest, ledger entry count and roots, and signer key ID/algorithm. The receipt signature uses a dedicated `northstar.sealed-run-receipt.v1` domain separator; the existing manifest v1 format is not changed.

The signed global `head_digest` commits to the ordered chain: every entry digest covers its canonical entry body, including the previous-entry digest, and verification recomputes each entry and link. No separate Merkle root is used. Receipt decoding is bounded to 256 source labels, 16 KiB raw signatures, and 256 KiB canonical JSON; signer key IDs and algorithm labels are ASCII-only.

Verification distinguishes:

- **integrity** — whether the supplied ledger matches the receipt's signed snapshot;
- **completeness** — whether all required sources are represented;
- **authenticity** — whether a trusted key resolver verifies the signature; and
- **run verdict** — verified only when those checks pass, the run finished, and the independent verifier passed.

A valid signature over a receipt does not prove that its signer or the reported verifier was honest. The signer is an attester; production key rotation, expiry/revocation policy, and key storage belong to the host/deployment trust infrastructure. No production signer or key management is included here. The bundled `HmacTestSigner` is test-only: a shared-secret MAC is not non-repudiation, and test keys must never seal real evidence. There is no trusted timestamp: `sealed_at` is signed caller-supplied time.

Example (the host supplies `host_signer` and `trusted_keys`):

```python
from sealed_receipt import CompletionEvidence, seal_run_receipt, verify_run_receipt

terminal = store.append(
    source="verifier",
    kind="run.verified",
    occurred_at=1_800_000_020,
    subject={"verdict": "passed"},
    source_id="verification-1",
)
completion = CompletionEvidence(
    status="finished",
    completed_at=1_800_000_030,
    evidence_entry_digest=terminal.entry_digest,
    verifier_verdict="passed",
    test_exit_code=0,
)
receipt = seal_run_receipt(
    store,
    completion=completion,
    required_sources=("verifier",),
    signer=host_signer,
    capture_policy_revision="policy-v1",
    capture_policy_digest="sha256:" + "a" * 64,
)
report = verify_run_receipt(receipt, trusted_keys, store=store)
assert report.run_verdict == "verified"
```

A receipt alone, with no ledger supplied to verification, can have verified authenticity but has `integrity="unknown"` and `run_verdict="unknown"`. Unknown keys are never treated as trusted. An incomplete capture cannot be sealed as complete.

## Concepts, guides and API reference

- Concepts: [Governance](../../docs/concepts/governance.md)
- Guide: [Governed run cookbook](../../docs/guides/governed-run-cookbook.md)
- API reference: [northstar-run-evidence](../../docs/api/northstar-run-evidence.md)

## Example

```python
from evidence_chain import EvidenceChain, verify_chain
from evidence_contract import EvidenceRef

chain = EvidenceChain("run-001")
source = chain.append(
    source="runtime",
    kind="session.started",
    occurred_at=1_800_000_000,
    subject={"session_id": "session-001", "policy_revision": "policy-7"},
    source_id="session-start-001",
)
chain.append(
    source="verifier",
    kind="artifact.verified",
    occurred_at=1_800_000_001,
    subject={"verdict": "verified"},
    refs=(EvidenceRef("session", "session-001", source.subject_digest),),
    source_id="artifact-check-001",
)

report = verify_chain([entry.to_dict() for entry in chain.entries], expected_run_id="run-001")
assert report.ok
```

Run component tests from this directory:

```sh
python3 -m unittest discover -s tests
```
