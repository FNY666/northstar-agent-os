# Sources — Gemini CLI S2

All sources are first-party public documentation/raw files from `google-gemini/gemini-cli` GitHub, retrieved 2026-09-22. Branch: `main`; URLs are exact public endpoints.

1. https://raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/cli/plan-mode.md — Plan Mode read-only boundary, allowed tools, approvals, policy customization.
2. https://raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/tools/planning.md — `enter_plan_mode` and `exit_plan_mode` behavior, confirmation and formal approval.
3. https://raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/reference/policy-engine.md — decisions, priority, approval modes, MCP policy syntax, trust propagation, tiers.
4. https://raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/tools/mcp-server.md — MCP transports, configuration, include/exclude/trust, environment sanitization, OAuth, connection lifecycle, statuses and diagnostics.
5. https://raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/reference/configuration.md — settings reference for MCP allow/exclude, server timeout/trust/tool lists, shell inactivity timeout, env loading/redaction, admin MCP.
6. https://raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/cli/model-steering.md — experimental Model Steering lifecycle and next-turn context injection.
7. https://raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/tools/shell.md — shell return fields, error handling, command restrictions and inactivity timeout.
8. https://api.github.com/repos/google-gemini/gemini-cli/contents/docs/tools — public GitHub API directory listing used to verify the official planning/MCP document paths.

## Retrieval notes

- Browser was not needed; direct `curl` and GitHub API retrieval succeeded.
- No private account, cookies, credentials, protected project directories, real service, or shared/P0/accident/D10/L12/D14/canonical/staging/140/tri-line/systemd target was accessed.
- A source is not treated as evidence for claims beyond its directly quoted/documented scope. Official docs are primary but normative/vendor documentation; they do not independently prove production outcomes.
