# ACP Editor Integration Examples (Zed, Neovim & Offline Smoke)

Copy-paste-ready client configurations and an offline end-to-end smoke script
for `northstar acp` (Agent Client Protocol v1 over JSON-RPC 2.0 NDJSON stdio).

See [`docs/guides/acp-adapter.md`](../../docs/guides/acp-adapter.md) for the full
protocol surface and security invariants.

## Files in this directory

| File | Purpose |
| --- | --- |
| [`zed-settings.json`](zed-settings.json) | Zed `agent_servers` configuration with two governed profiles: daily isolated worktree (`camel`) and untrusted-repo strict (`camel-strict`). |
| [`neovim-acp.lua`](neovim-acp.lua) | Neovim ACP adapter template (`codecompanion.nvim` / generic stdio ACP client). |
| [`smoke_offline.py`](smoke_offline.py) | Self-contained offline smoke test (no API key, no network) exercising `initialize` → `session/new` (`--code-worktree` + `admission.json`) → `session/prompt` → CaMeL taint → bidirectional `session/request_permission` → `reject_once` → clean checkout. |

## Run the offline smoke test

From the repository root:

```sh
python3 examples/acp/smoke_offline.py
```

The script creates a temporary Git fixture under `/tmp`, spawns `bin/northstar acp`
with `--provider scripted --code-worktree --interactive-permissions --dataflow-policy camel-strict`,
rejects the tainted `Write` call over `session/request_permission`, verifies the
source repository stays untouched, and exits `0` only if every check passes.

## Using with a real provider in Zed or Neovim

1. Replace `/path/to/northstar-agent-os/bin/northstar` with either your checkout's
   `bin/northstar` path or `northstar` if installed on `PATH`.
2. Export your provider credential in your editor's environment (`ANTHROPIC_API_KEY`
   or `OPENAI_API_KEY`); never embed keys in `settings.json` or Lua configs.
3. Verify your flags locally without starting stdio using `--dry-run`:

```sh
bin/northstar acp --dry-run \
  --permission-mode acceptEdits \
  --interactive-permissions \
  --code-worktree \
  --dataflow-policy camel \
  --provider anthropic
```
