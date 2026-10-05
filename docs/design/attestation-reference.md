# Attestation Reference Design (E.3)

How Phala's TEE attestation pattern maps to Northstar without a TEE.

## The pattern: measure — bind — endorse

Phala's verifiable TEE attestation decomposes into three steps that do not
require a TEE to be useful as a design:

1. **Measure**: hash the code and config that will run
   (`code_hash`, `config_hash`). The measurement covers *what runs*, not who
   signed it — in TDX this happens inside the CPU (RTMR3 compose-hash); in
   Northstar it is a SHA-256 over the agent bundle + governance config,
   recorded with an event log so a third party can recompute it.
2. **Bind**: commit the measurement together with the agent's action public
   key (and the verifier's nonce) into one signed structure. In TDX this is
   `report_data` inside the quote; in Northstar it is the `bindings` section
   of the attestation, signed by the endorser. The binding says: "this key
   was endorsed while these measurements held."
3. **Endorse**: a trusted party signs the whole thing. In TDX the endorser
   is Intel (hardware root). In Northstar the endorser is replaceable: the
   user's key, a CI witness key (SLSA-style build attestation), or the
   governance chain itself. The *pattern* is identical; only the trust root
   differs.

## Interface shape (mirrors `attested_receipts.py`)

- **Produce**: `attest(challenge: bytes) -> Attestation`
  (`challenge` = verifier nonce, 32 bytes; binds freshness).
- **Measure**: `measure() -> {code_hash, config_hash, event_log}`.
- **Verify** (cheap first, expensive last):
  1. structure complete (`format`, `subject`, `measurements`, `bindings`,
     `endorser`, `signature` present);
  2. `bindings.nonce` equals the challenge we sent;
  3. `issued_at`/`expires_at` within the acceptance window (short-lived;
     10-minute default, borrowed from DCAP practice);
  4. `endorser` is in the verifier's trust list;
  5. `measurements` match the expected baseline (recompute from
     `event_log` where feasible — independent recomputation, not trust);
  6. Ed25519 signature verifies under the endorser key.

If any step fails, the attestation is rejected — never downgraded to
"software". (This is the same fail-closed rule `attested_receipts.py`
already enforces for `evidence_kind`.)

## Wiring to identity

An Identity Manifest's `keys[]` entry for an action key may carry
`attested_by: <attestation id>`: "this action key was endorsed under
code_hash X". This mirrors Phala's `ITEERegistry` five-tuple
(agent → arch → measurement → pubkey → verifier), with the audit chain
as the registry instead of an EVM contract.

## What we deliberately do NOT do

- No TEE quotes, no DCAP chain, no SGX/TDX/SNP dependency.
- No new crypto: Ed25519 + SHA-256 + canonical JSON only.
- The software-emulated attestor in `attested_receipts.py` remains
  clearly labelled `emulated: True` and may only claim
  `evidence_kind == "software"`.
