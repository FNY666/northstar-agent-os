# northstar-run-evidence

Dependency-free core data structures, hash-chain primitives, and local persistence for Northstar run evidence. Python 3.10+.

## Current scope

This component contains:

- strict, versioned `EvidenceRef` and `EvidenceEntry` data structures;
- deterministic canonical JSON (ASCII object keys, safe-range integers, no floating-point values) and domain-separated SHA-256 subject/entry digests;
- an append-only in-memory `EvidenceChain` with sequence, run identity, previous-digest and idempotency checks;
- `verify_chain()` for structured offline integrity results;
- `EvidenceStore` for a run-scoped canonical JSONL ledger with atomic append, cross-process locking, fsync, and strict integrity checks.

`EvidenceStore(root, run_id)` writes to `root/<run_id>/ledger.jsonl`. The root must be owned by the current user and not group/world writable; directory components are opened with `O_NOFOLLOW`, and operations stay relative to a pinned run-directory file descriptor to prevent path-swap redirection. It uses a POSIX `flock` lock and same-directory temporary-file replacement; each append rewrites the bounded ledger (up to 64 MiB), fsyncs the file, atomically replaces it, and fsyncs the directory. The per-run directory is mode `0700`; lock, ledger, and temporary files are mode `0600`. Symlinks, special files, non-canonical JSONL, broken links, an empty existing ledger, excessive JSON nesting, and a missing final newline fail closed. There is no automatic repair of a damaged/torn ledger. Use a local POSIX filesystem that honors `flock`, `fsync`, and atomic rename semantics.

Persisted `append()` and `append_entry()` require a stable `source_id`; retry a logical event with the same ID after any uncertain outcome. If the atomic rename succeeds but directory `fsync` fails, the store raises `EvidenceCommitUncertainError`; the entry may already be visible, and retrying the same ID will return the existing entry rather than append a duplicate.

Bundle manifests, signatures, key management, CLI commands, and runtime/host/durable-run adapters are not implemented yet.

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

For local persistence, construct `EvidenceStore` with a dedicated evidence root and append while it owns sequence allocation under the run lock:

```python
from evidence_store import EvidenceStore

store = EvidenceStore(".northstar/evidence", "run-001")
entry = store.append(
    source="runtime",
    kind="session.started",
    occurred_at=1_800_000_000,
    subject={"session_id": "session-001"},
    source_id="session-start-001",
)
assert store.verify().ok
assert store.load()[-1] == entry
```

Atomic replacement prevents readers from observing a partially appended JSONL row, but it is not a transaction across other Northstar stores. A hash chain detects internal changes; it does **not** authenticate its producer or prevent replacement of the complete ledger. Authenticity requires a trusted external signature over a sealed manifest/head digest.

Run component tests from this directory:

```sh
python3 -m unittest discover -s tests
```
