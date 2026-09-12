# Checkpoint Chain Witness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or **superpowers:executing-plans** to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Export a complete, digest-bound checkpoint-chain witness so an offline verifier can validate every predecessor instead of trusting only a portable head record.

**Architecture:** Add `checkpoint_chain_witness.py` over the existing immutable `EvidenceCheckpoint` records. The witness carries the complete ordered checkpoint list and a canonical chain digest. Verification recomputes every checkpoint digest and continuity edge, then optionally pins the final evidence root and the chain digest supplied out of band. The existing `EvidenceChain` and envelope v1 remain unchanged.

**Tech Stack:** Python 3.10+, standard library, existing `evidence_chain`, `unittest`. No network and no new dependency.

## Global Constraints

- Research worktree only; no local-only, main, integration-next, arena, runtime, merge, cherry-pick, or remote push changes.
- Existing checkpoint and envelope v1 schemas remain unchanged.
- A self-carried chain digest is integrity evidence, not a trust anchor; missing external pins return `verified-unpinned`.
- A witness proves the supplied checkpoint history is internally coherent; it does not prove the producer's facts or authorization.
- Empty, reordered, truncated, malformed, or tampered checkpoint histories fail closed.

---

### Task 1: Complete checkpoint witness (RED first)

**Files:**
- Create: `components/northstar-agent-interop/checkpoint_chain_witness.py`
- Create: `components/northstar-agent-interop/tests/test_checkpoint_chain_witness.py`

**Interfaces:**
- `CheckpointChainWitness(schema_version, checkpoints, chain_digest)`
- `make_witness(chain) -> CheckpointChainWitness`
- `verify_witness(witness, expected_head_root=None, expected_chain_digest=None) -> WitnessVerdict`

- [x] Test complete-chain creation, deterministic wire form, strict parsing, and empty-chain refusal.
- [x] Test recomputed checkpoint digests, sequence continuity, predecessor roots, and chain digest.
- [x] Test external head-root/chain-digest pins and explicit `verified-unpinned` when absent.
- [x] Run focused tests RED before implementation.

### Task 2: Adversarial history handling

**Files:**
- Modify: `components/northstar-agent-interop/checkpoint_chain_witness.py`
- Modify: `components/northstar-agent-interop/tests/test_checkpoint_chain_witness.py`

- [x] Reject reordered, truncated, missing, malformed, tampered, and mismatched-root witnesses.
- [x] Keep a valid historical prefix independently verifiable as a witness while making its scope explicit through `checkpoint_count` and `head_root`.
- [x] Ensure no raw event, prompt, secret, or provider output is added to the witness.

### Task 3: Documentation and local regression

**Files:**
- Modify: `components/northstar-agent-interop/ROUTE_JOURNAL_REVIEW.md`
- Create: `docs/superpowers/plans/2026-09-12-checkpoint-chain-witness.md`

- [x] Document why a checkpoint head is insufficient and what the witness does and does not prove.
- [x] Run focused tests, full Interop regression, `py_compile`, `git diff --check`, and sensitive scan.
- [x] Commit locally only; do not push or notify other sessions.
