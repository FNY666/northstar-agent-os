# Northstar Run Contract

This component defines the versioned structural boundary between an Agent OS orchestrator and a controlled worker such as the Codex Sidecar.

## Trust boundary

`validate_run_request()` checks shape, size, identifiers, task kind, timeout, and requested capability syntax. It does **not** authenticate the caller and it does **not** grant any requested capability. `actor_id` and `workspace_id` are declarations until a host-provided authenticated binding is verified.

The contract deliberately keeps these concerns separate:

1. **Validation** — is the request structurally safe to parse?
2. **Authentication** — does the caller possess a host-issued binding?
3. **Authorization** — may this actor use this workspace and capability set?
4. **Execution** — does the worker perform the bounded task?
5. **Postcondition verification** — did the claimed outcome actually hold?

## Run request

A request uses `schema_version: "northstar.run.v1"` and contains a bounded `run_id`, declared `actor_id`, declared `workspace_id`, one supported `task_kind`, a prompt, a bounded timeout, requested capability names, and an optional parent run ID.

Requested capabilities are not permissions. A later authenticated policy layer must reduce them to an explicit grant set before execution.

## Run receipt

Receipts use `schema_version: "northstar.receipt.v1"`. Every receipt contains a status and a list of explicit postcondition verdicts: `verified`, `failed`, or `unknown`. Unknown must not be presented as success.

Only `timeout` and `transport_unavailable` are fallback-eligible. `cancelled`, `protocol_error`, `business_error`, and `internal_error` must remain visible to the orchestrator and must not be silently retried as another worker.

## Current scope

This is a pure standard-library contract component. It does not create workspaces, authenticate users, run commands, store secrets, or claim production isolation. The signed binding and Sidecar adapter are separate layers.
