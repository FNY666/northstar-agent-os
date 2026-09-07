# Reversible execution: checkpoint, inspect, rewind and fork

Northstar's runtime now has a small local contract for reversible workspace
execution. It is deliberately narrower than a VM snapshot: the checkpoint is a
bounded, content-addressed manifest plus copied regular files. The contract is
useful to a CLI, SDK or future app-server without hiding the limits of local
filesystem operations.

## The checkpoint contract

`northstar-agent-runtime/checkpoints.py` stores a checkpoint under:

```text
<session-dir>/checkpoints/<session-id>/<checkpoint-id>/
  manifest.json
  files/<workspace-relative-paths...>
```

The manifest records:

- a schema version, checkpoint id, session id and transcript `session_index`;
- the absolute workspace used to create it and a creation timestamp;
- a label and the previous checkpoint id, forming a per-session chain;
- each regular file's relative path, SHA-256, byte count and permission mode;
- a deterministic workspace digest over the file entries.

The default limits are 10,000 files, 8 MiB per file and 64 MiB total. `.git`,
`__pycache__`, `node_modules` and `.venv` are not traversed. Symlinks in the
checkpointed tree are rejected rather than followed or copied. A malformed
manifest, duplicate path, digest mismatch,
symlinked checkpoint tree or limit violation is an error, not a best-effort
recovery.

## Operator flow

A checkpoint is explicit and inspectable:

```sh
python3 -m cli sessions checkpoint --session-dir S --workspace W SESSION
python3 -m cli sessions inspect --session-dir S SESSION
python3 -m cli sessions diff --session-dir S --workspace W SESSION CHECKPOINT
```

`diff` reports added, modified and deleted paths and the current workspace
digest. It does not change the workspace. The checkpoint bytes are verified
again before every diff or rewind, so a copied or edited snapshot cannot be
silently treated as truth.

Rewind is intentionally two-phase:

```sh
python3 -m cli sessions rewind --session-dir S --workspace W \
  --force SESSION CHECKPOINT
```

The operator must pass `--force` after reviewing `diff`. The runtime creates a
`before-rewind:<checkpoint>` safety checkpoint first. It restores checkpoint
files atomically, rejects symlink traversal, and keeps files added after the
checkpoint by default. `--delete-added` is a separate destructive opt-in. A
post-restore diff verifies that all checkpoint files match; a remaining added
file is reported rather than accidentally removed.

A fork materialises a new workspace without overwriting an existing target:

```sh
python3 -m cli sessions fork --session-dir S --workspace W2 \
  --new-session-id CHILD SESSION CHECKPOINT
```

The target is assembled in a sibling temporary directory and renamed into
place. The child receives an initial checkpoint and a `fork.json` lineage
record naming the source session and checkpoint. This is a local workspace
fork, not a process, database or remote-worker fork.

## Current boundary

The first slice snapshots workspace state at explicit control-plane boundaries
and emits `workspace_change` session records with pre/post hashes for built-in
and path-shaped mutating tool calls. The receipt is metadata, not a copy of the
file bytes; checkpoint contents remain the recovery mechanism. Built-ins use the
legacy `path`/`paths` convention. A custom mutating `ToolSpec` may declare
bounded top-level `affected_input_keys`, for example
`("output_path",)`, and the session record marks that impact set as declared.
This covers only the declared input paths; a tool may additionally return a
versioned bounded `artifact_manifest` for external or non-path outputs, which
is validated and carried by the signed action receipt. The manifest is an
observation, not host attestation, and hidden side effects are never inferred.

The slice does not sign manifests, enforce OS-level isolation, coordinate remote
workers, or replace the durable-run event store. Those are subsequent layers:
a future runtime should make checkpoint creation part of the common `Run / Turn /
Action / Checkpoint / Artifact / Receipt` event contract.

See the runtime [API reference](../api/northstar-agent-runtime.md) and the
[audit trail concept](audit-trail.md) for the relationship between checkpoint
state and append-only session history.
