# northstar-run-evidence

Dependency-free core data structures and in-memory hash-chain primitives for Northstar run evidence. Python 3.10+.

## Current scope

This initial component contains:

- strict, versioned `EvidenceRef` and `EvidenceEntry` data structures;
- deterministic canonical JSON (ASCII object keys, safe-range integers, no floating-point values) and domain-separated SHA-256 subject/entry digests;
- an append-only in-memory `EvidenceChain` with sequence, run identity, previous-digest and idempotency checks;
- `verify_chain()` for structured offline integrity results;
- `evidence_store.EvidenceStore`: a file-backed JSONL store (one canonical-JSON entry per line, fsync on append, full chain re-verified at every open so tampering fails closed);
- sealed manifests: `EvidenceStore.seal(signer)` attests to the chain head with a host-injected `SealSigner`; `verify_manifest()` / `verify_seal()` check the seal, with unknown `key_id` reported as *unknown authenticity*, never as ok.

Key management, CLI commands, and runtime/host/durable-run adapters are not implemented yet. The bundled `HmacTestSigner` is test-only: a shared-secret MAC is not non-repudiation, and test keys must never seal real evidence.

A valid hash chain only detects inconsistencies relative to its entries. It does **not** prove who created the chain or prevent an attacker from replacing the entire chain. Authenticity requires a trusted external signature over a sealed manifest/head digest.

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
