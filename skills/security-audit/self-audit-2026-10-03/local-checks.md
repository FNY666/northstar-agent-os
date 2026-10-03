# Local checks — self-audit 2026-10-03 (quick profile)

Target: northstar-agent-os @ c2ec7a9 (worktree clean).

## LC-1 — approval digest binding sensitivity (unit: approval-replay)

Ran in `components/northstar-agent-runtime`:

```
from permissions import digest_arguments
digest_arguments({"path": "a.txt", "content": "x"}) != digest_arguments({"path": "a.txt", "content": "y"})  # True
digest_arguments({"path": "a.txt", "content": "x"}) == digest_arguments({"content": "x", "path": "a.txt"})  # True (key order stable)
digest_arguments([1, 2]) == digest_arguments({})   # True (non-dict coerces to {})
digest_arguments(None) == digest_arguments({})     # True
digest_arguments({"n": 1.0}) != digest_arguments({"n": 1})  # True (fail-closed direction)
```

Result: the binding is sensitive to argument changes and stable under key
reordering. Non-dict payloads coerce to the `{}` digest, but every production
path fails closed on non-dict before the digest matters
(`ActionGateway.execute` raises on non-dict; `PermissionEngine.evaluate`
`dict(payload or {})` raises inside the fail-closed `except Exception`).

## LC-2 — source traces (all units, method: source)

- approval-binding: `permissions.py:106-124` (`digest_arguments`),
  `permissions.py:349-356` (digest pinned before host callback),
  `action_gateway.py:455-456` (non-dict rejected), `action_gateway.py:486-488`
  (execution-time digest compared), `loop.py:1850-1858` (call id + digest pinned).
- consent: `grep consent` over `permissions.py` and `loop.py` returns nothing;
  mutating calls always re-invoke `config.can_use_tool` (`permissions.py:356`).
- budget: `loop.py:1544-1549` (`_ceiling_stop`), `loop.py:2222-2224`
  (delegation blocked on exhaustion), `budget.py:197-206`.
- audit-chain: `audit_chain.py:277-280` (chain seal), `audit_chain.py:646-700`
  (anchor manifest detects truncation; bare chain honestly documented as unable,
  `audit_chain.py:24-26`).
- os-sandbox: `tools/os_sandbox.py:5-17` (bwrap preferred, no net ns),
  `tools/os_sandbox.py:212-219` (`auto` resolves to `process` when bwrap
  unavailable — documented downgrade), `tools/seccomp.py:11-23` (denylist,
  documented; unknown arch allows).
- mcp-client: `mcp_client.py:187-192` (env allowlist), `mcp_client.py:9-16`
  (elicitation through the approval gate).
- skill-scripts: `tools/skill_scripts.py:1-16` (never auto-run; via os_sandbox).
- session-lease: `session_lease.py:105-114` (`validate_owner_id` rejects `/`),
  `session_lease.py:270-273` (path derived only after validation),
  `session_lease.py:221` (kernel `flock`).
- provider-retry: `provider_retry.py:46-48` (MAX_ATTEMPTS=8, delay/deadline caps),
  `provider_retry.py:214-218` (config validated against caps).
- plugin-load: `plugin_load.py:152-153` (sha256 pin required),
  `plugin_load.py:539-547` (re-hash compared), `plugin_load.py:641-674`
  (unpinned install refused).
- checkpoints: `checkpoints.py:206-239` (`prepare_resume` verifies transcript
  digest; refuses on mismatch).
