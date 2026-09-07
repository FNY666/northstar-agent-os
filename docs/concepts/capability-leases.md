# Capability-first approval leases and action receipts

Northstar has two different authorization horizons:

1. a host may approve one capability for a bounded part of a run; and
2. the runtime must leave a claim that can be checked after the tool call.

`components/northstar-agent-runtime/receipts.py` provides both primitives without
replacing the existing permission engine, host authorization grant, or durable
run action gateway.

## Approval lease

An `ApprovalLease` is a small, in-memory authorization claim:

| Field | Meaning |
| --- | --- |
| `lease_id` | unique non-wildcard lease identity |
| `session_id` | exact runtime session that may consume it |
| `workspace` | exact resolved workspace root, not a pattern |
| `capabilities` | stable names such as `workspace.write`, `process.exec`, or `network.access` |
| `issued_at` / `expires_at` | absolute Unix-second validity window; expiry is exclusive |
| `max_uses` / `uses` | bounded consumption counter |

A lease is not a prompt instruction and it is not a wildcard tool allowlist. The
permission order is:

1. `disallowed_tools` remains an unconditional deny;
2. `allowed_tools` and the existing hard `plan` boundary retain their existing
   semantics;
3. a matching, unexpired, non-exhausted capability lease is consumed once;
4. only when no lease applies does the runtime use `acceptEdits`,
   `bypassPermissions`, or the host callback.

A lease never widens plan mode or defeats a deny list. Session, workspace,
capability, expiry and use count are all checked at consumption time. The ledger
keeps expired entries for inspection but does not select them; a host can
explicitly `revoke(lease_id)` before expiry. This local ledger does not persist
or renew leases.

```python
from loop import AgentRuntime, RuntimeConfig
from receipts import ApprovalLease

runtime = AgentRuntime(
    provider=provider,
    config=RuntimeConfig(workspace="/srv/workspaces/run-42", session_id="run-42"),
    approval_leases=[ApprovalLease(
        lease_id="lease-42",
        session_id="run-42",
        workspace="/srv/workspaces/run-42",
        capabilities=("workspace.write",),
        issued_at=1_800_000_000,
        expires_at=1_800_000_060,
        max_uses=3,
    )],
    receipt_secret=b"host-owned-secret-at-least-16",
)
```

`northstar-host.authorization.issue_approval_lease` is the host adapter for
turning an already verified `northstar.authorization.v1` grant into this shape.
It checks the binding and policy again, narrows capabilities rather than adding
them, and caps the lease expiry at the signed grant. The opaque contract
`workspace_id` and a local filesystem workspace are separate values and must not
be conflated.

The durable-run `ActionGateway` remains the stricter per-call boundary for its
own `northstar.tool-call.v1` / `northstar.approval.v1` protocol. A runtime lease
is an in-process approval cache; it is not a replacement for that gateway's
argument digest, resource binding, idempotency, high-risk approval, or executor
checks.

## Action receipt

Each attempted runtime tool call yields an `ActionReceipt` in
`RunReport.receipts`, whether the result is `completed`, `failed`, or `denied`.
The receipt contains:

- stable session/action/tool identity and the required capability;
- canonical SHA-256 digests of input and, when available, output;
- optional before/after digests of the selected workspace file-state metadata;
- an optional bounded `northstar.artifact-manifest.v1` for tool-reported
  external or non-path outputs;
- an optional `northstar.receipt-binding.v1` projection of a host-verified
  authorization grant, including the exact grant-token digest and narrowed
  capability scope;
- the consumed `lease_id`, if a lease authorized the call;
- issued/completed timestamps and an explicit status;
- an optional HMAC-SHA256 signature over canonical JSON with the signature
  excluded from the signed bytes.

```python
receipt = report.receipts[0]
assert receipt.verify(host_secret)
wire = receipt.as_dict()                 # signed action-receipt.v1
run_wire = receipt.to_contract_receipt() # northstar.receipt.v1 projection
```

`ActionReceipt.from_dict` validates shape, field bounds, digest syntax and
signature syntax. `verify` then checks the HMAC with a host-provided secret and
constant-time comparison. Changing a status, digest, lease id or workspace
observation invalidates the signature. An unsigned receipt is inspectable but
`verify` returns `False`.

The projection uses the existing run-contract statuses (`accepted`, `rejected`,
`ok`, `internal_error`) and explicit `verified`/`failed`/`unknown`
postconditions. It deliberately drops runtime-specific fields and the signature
because `northstar.receipt.v1` has no extension slot; consumers that need
cryptographic verification should retain and verify the signed action receipt.

A signed receipt is also mirrored into the append-only session as an
`informational` record with `subtype: "action_receipt"`. The host secret is
never written. Without a configured secret, receipts remain in the in-memory
report and the existing `workspace_change` record behavior is unchanged for
legacy transcript readers.

## Honest boundary

The receipt authenticates what this runtime instance canonicalized and observed;
it does not prove that an arbitrary hostile process did not change the machine.
Workspace observations are bounded to the paths a mutating tool declares through
`path`/`paths`. A custom tool with hidden side effects must declare an impact set
before a future runtime can claim complete reversibility. Checkpoints remain
local bounded snapshots, and receipt signatures are not a release, compliance
store, or remote attestation protocol.
