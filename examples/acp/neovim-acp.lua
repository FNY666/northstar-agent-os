-- Neovim ACP client template for Northstar Agent OS (`northstar acp`).
--
-- Works with ACP-capable Neovim plugins (for example `codecompanion.nvim` ACP
-- adapters) or any custom Neovim jobstart() JSON-RPC 2.0 NDJSON stdio client.
-- Keep API credentials in your shell environment (ANTHROPIC_API_KEY /
-- OPENAI_API_KEY); never hardcode secrets in your Neovim config.

local M = {}

M.northstar_bin = vim.fn.expand("/path/to/northstar-agent-os/bin/northstar")

-- Daily governed coding: detached git worktree + per-call approval + CaMeL
-- external-source taint (`Fetch` / `mcp__*`).
M.governed_worktree_cmd = {
  M.northstar_bin,
  "acp",
  "--provider",
  "anthropic",
  "--permission-mode",
  "acceptEdits",
  "--interactive-permissions",
  "--permission-timeout-seconds",
  "60",
  "--code-worktree",
  "--dataflow-policy",
  "camel",
  "--max-turns",
  "25",
  "--max-tool-calls",
  "50",
}

-- Untrusted repository profile: every Read/Grep/SearchCode taints the session
-- so subsequent privileged writes or shell calls require explicit allow_once.
M.untrusted_repo_strict_cmd = {
  M.northstar_bin,
  "acp",
  "--provider",
  "anthropic",
  "--permission-mode",
  "default",
  "--interactive-permissions",
  "--permission-timeout-seconds",
  "45",
  "--code-worktree",
  "--dataflow-policy",
  "camel-strict",
  "--no-workspace-agents",
  "--max-turns",
  "15",
  "--max-tool-calls",
  "30",
}

-- Example wiring for `codecompanion.nvim` (ACP adapter):
-- require("codecompanion").setup({
--   adapters = {
--     acp = {
--       northstar = function()
--         return require("codecompanion.adapters").extend("acp", {
--           name = "northstar",
--           formatted_name = "Northstar (Governed Worktree)",
--           commands = {
--             default = M.governed_worktree_cmd,
--             strict = M.untrusted_repo_strict_cmd,
--           },
--         })
--       end,
--     },
--   },
-- })

return M
