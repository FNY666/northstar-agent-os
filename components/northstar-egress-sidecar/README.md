# northstar-egress-sidecar

## Concepts, guides and API reference

- Concepts: [governance and the permission gate](../../docs/concepts/governance.md) ·
  [threat model](../../docs/concepts/threat-model.md)
- Guides: [packaging and CI](../../docs/guides/packaging-and-ci.md)
- API reference: [generated from docstrings](../../docs/api/northstar-egress-sidecar.md)

The enforcement half of the Northstar egress gateway. This daemon is the
**only** process that may open outbound network connections on behalf of
governed agents: it holds every external credential, resolves DNS itself,
authorizes each request against the real resolved destination at CONNECT
time, and returns a signed egress receipt for the audit chain.

## Why a separate process

Tool handlers run in-process and MCP server subprocesses inherit the main
process's network, so an in-process "gateway" the agent calls voluntarily is
a convention, not a chokepoint. The boundary that holds is the OS one:

- the agent processes get **no direct network route** (netns / firewall;
  verified by `doctor`),
- this sidecar gets `AF_UNIX` (control socket) + `AF_INET`/`AF_INET6`
  (dialing authorized destinations) and nothing else,
- every external credential lives in **this** process's environment, never
  in the agent's.

This mirrors the `northstar-codex-sidecar` privilege-separation template,
with the address families inverted: the codex sidecar is denied the network,
the egress sidecar *is* the network path.

## Layout

- `egress_socket.py` -- AF_UNIX JSON-lines server (entry point).
- `egress_sidecar.py` -- request validation, DNS, authorization via
  `egress_enforcer`, upstream dial with pinned IP + SNI, credential
  injection, credential-reflection scrubbing.
- `transport.py` -- bounded JSONL encode/decode.
- `egress-sidecar.service` -- systemd unit.

## Configuration

- Policy: `NORTHSTAR_EGRESS_POLICY_DIR/northstar-egress.toml`
  (see `egress_enforcer.load_egress_policy`). Credential *references* only;
  the file is rejected at load if a reference looks like a secret value.
- Credentials: `NORTHSTAR_EGRESS_CRED_<NAME>` in the sidecar's environment
  (root-only `EnvironmentFile`), one per credential reference in the policy.
  The sidecar refuses to start when a referenced credential is missing.
- Approver keys: passed to `build_context(approver_keys=...)` by the
  embedding; the systemd path reads them from a root-only config when
  approval-bound destinations are used.
- Receipt signing: the production socket entry point requires
  `NORTHSTAR_EGRESS_SIGNING_SEED` (32 bytes hex) and `NORTHSTAR_EGRESS_KEY_ID`;
  it refuses to start if either is missing or malformed. The systemd unit reads
  them from `/etc/northstar-egress/signing.env`; provision that file as
  `root:root` mode `0600`, with one assignment per line. The unit intentionally
  fails to start if the file is missing. Never commit the secret to the unit
  or repository. `build_context()`
  keeps the seed optional for library use and tests. Hash chains detect
  accidental edits; signatures authenticate the feed against deliberate
  rewriting. Migrating a legacy unsigned feed preserves its chain history but
  does not retroactively authenticate those old entries.
- Key rotation: the service automatically trusts the current seed's public key
  under its configured key ID. Before rotating, add every retained old signer
  to `/etc/northstar-egress/trusted-public-keys.json` as a JSON object mapping
  key IDs to 64-character public-key hex strings. For example:
  `{"ops-2026-10":"<old-public-key-hex>"}`. Then update the seed and key ID
  together and restart. Startup verifies each existing record using its own
  `key_id`; unlisted or invalid signatures stop startup. For historical signed
  records without a key ID, register their public key as
  `"__legacy_default__"`. Keep old public keys for as long as their feed records
  must remain verifiable; the file contains public keys, never private seeds.
- Persistent receipts: systemd stores the feed at
  `/var/lib/northstar-egress/receipts.jsonl` in its private state directory,
  so rebooting does not silently reset the audit chain. Back up the feed and
  signing key under separate controls; losing the key prevents verification
  of signed records, while replacing it requires an explicit key-rotation plan.

## Protocol (agent -> sidecar, one JSON object per line)

```json
{
  "request_id": "r-1",
  "agent_id": "main",
  "run_id": "run-1",
  "host": "rekor.sigstore.dev",
  "port": 443,
  "method": "POST",
  "path": "/api/v1/log/entries",
  "headers": {"content-type": "application/json"},
  "body_b64": "e30=",
  "timeout_ms": 30000,
  "call_id": "call-9",
  "arguments": {"target": "prod"},
  "card": { /* action_card.as_dict() */ },
  "approval_receipt": { /* ApprovalReceipt.as_dict() */ }
}
```

Response:

```json
{
  "request_id": "r-1",
  "status": "ok",
  "http_status": 200,
  "headers": {"content-type": "application/json"},
  "body_b64": "...",
  "truncated": false,
  "receipt": { /* chained (+signed) egress receipt */ }
}
```

Denials return `"status": "denied"` with a stable `deny_code`
(`egress.destination_denied`, `egress.unresolved_destination`,
`egress.shape_violation`, `egress.approval_binding_invalid`,
`egress.dlp_hit`, `egress.budget_exceeded`,
`egress.credentialless_bypass_attempt`) and the receipt. The agent-side
client is `egress_client.py` in `northstar-agent-runtime`.
