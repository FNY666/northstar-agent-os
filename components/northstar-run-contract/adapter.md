# Sidecar adapter boundary

The adapter is a pure translation layer. It requires a successful `BindingValidation` from the host-issued HMAC binding verifier and checks that `run_id`, `actor_id`, and `workspace_id` match the versioned run request.

Only these three fields cross into the legacy Codex Sidecar:

```json
{"request_id":"run-001","prompt":"...","timeout_ms":10000}
```

Capabilities, workspace identifiers, parent-run metadata, and arbitrary fields are never forwarded to the Sidecar request. An unknown Run Contract field rejects the request; it is not silently ignored.

Sidecar statuses are translated into versioned receipts. `codex_error` becomes `business_error`; it must not be treated as a transport failure. `protocol_error`, `internal_error`, and cancellation-related outcomes remain visible to the orchestrator. The adapter does not create or select workspaces, and it does not claim workspace isolation by itself.

This component is a local adapter candidate only. It is not a production deployment, caller-authentication service, or authorization policy engine.
