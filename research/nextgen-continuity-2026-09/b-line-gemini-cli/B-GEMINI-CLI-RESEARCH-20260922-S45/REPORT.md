# B-S45 Official Gemini CLI MCP lifecycle and runtime-boundary study

- Research/access date: 2026-09-22 (Asia/Shanghai).
- Sources: first-party Google Gemini CLI public repository and raw source URLs only; local read-only snapshot, repository commit `d5b3e3accb26000d273abf16e0f1dd83aa5428a9`.
- This slice continues S44 by narrowing the lifecycle boundary: discovery, configuration, reload, resource reads, trust/filter controls, timeout, and what these records cannot establish about remote effects.

## Verified

1. The official MCP guide says discovery iterates configured `settings.json` servers, connects over Stdio/SSE/Streamable HTTP, fetches and validates tool schemas, registers tools with conflict resolution, and fetches/registers resources where exposed. It says discovered tools maintain connection state and handle timeouts.
2. The documented global `mcp.allowed` and `mcp.excluded` controls filter which configured servers connect. Per-server `includeTools` acts as an allowlist; `excludeTools` takes precedence, including on overlap. `trust: true` bypasses all tool-call confirmations for that server; default is false.
3. The documented MCP request timeout default is 600,000 ms. The configuration supports explicit environment-variable references; the docs state undefined references resolve to an empty string. Sensitive inherited variables are redacted by default, while explicitly configured variables are trusted and exempt from automatic redaction.
4. The resources documentation describes `resources/list` discovery, `/mcp` display, URI references using `@server://resource/path`, and `resources/read` injection into conversation context. The setup documentation describes restart/reload as configuration/application operations.

## Inferred / unknown

- Inferred: a client-side “connected/discovered/allowed/trusted/tool-returned” record is not the same evidence as a target-side business commit. An acceptance design should preserve server/config revision, tool allow/exclude decision, trust/approval state, request identity, transport outcome, and an independent authoritative read-back.
- Unknown: whether a timeout means the remote call was never received, was partially executed, or committed; cancellation-after-timeout; exactly-once behavior; remote server durability; complete audit coverage; resource freshness/completeness; safety of arbitrary MCP server code; and whether explicitly shared credentials are logged or misused.

## Boundary

No real MCP server, credentials, account, remote service, production environment, or Gemini CLI process was accessed. Official documentation demonstrates documented configuration/integration semantics only; it does not prove production success or external-effect correctness.
