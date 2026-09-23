# B-S44 Official Gemini CLI MCP Integration and Secret-Boundary Research

- Research date/access date: 2026-09-22 (Asia/Shanghai).
- Official snapshot: `https://github.com/google-gemini/gemini-cli`, local commit `d5b3e3accb26000d273abf16e0f1dd83aa5428a9`, fetched/read-only from the public repository.
- Scope: MCP discovery, tool/resource exposure, trust and allowlists, timeout, environment expansion/sanitization, and documented setup behavior.

## Verified conclusions

1. The official MCP reference defines an MCP server as exposing tools/resources to Gemini CLI; the discovery layer connects configured servers over Stdio, SSE, or Streamable HTTP, fetches and validates tool schemas, registers tools, and may register resources. The execution layer handles confirmation logic according to trust settings/user preferences, executes calls, processes responses, maintains connection state, and handles timeouts.
2. Global `mcp.allowed` limits connections to named configured servers, while `mcp.excluded` prevents listed servers from connecting. Per-server `includeTools` is an allowlist; `excludeTools` overrides it, including when a tool appears in both lists.
3. The documented per-server `trust: true` bypasses all tool-call confirmations for that server; default is false. This is a documented configuration bypass, not proof that the remote tool is safe or that its external effect is correct.
4. The documented request timeout default is 600,000 ms (10 minutes). A timeout/connection-state mechanism is documented, but the cited page does not establish whether a timed-out remote call was not received, partly executed, committed, or safe to retry.
5. MCP server environment values can reference host environment variables. The docs state that absent variables resolve to an empty string. By default sensitive variables inherited from the host are redacted; explicitly listed `env` variables are trusted and exempt from automatic redaction. This is a boundary against accidental inheritance, not a guarantee that an explicitly shared secret cannot be logged or misused by the server.
6. The setup tutorial tells users to place credentials in the environment and map them explicitly into the MCP server configuration; it also says restarting causes configured servers to be started and `/mcp reload` can re-query a server. These are documented setup/reload actions, not durable execution or business-success receipts.
7. MCP resources are discovered via `resources/list`; a URI reference causes `resources/read` and injects content into conversation context. Resource retrieval is not independently documented as a proof of freshness, completeness, authorization correctness, or downstream effect.

## Inferred and unknown boundaries

- Inferred: a safe MCP acceptance protocol must record server identity/config revision, tool allow/exclude decision, approval/trust state, request ID, transport result, timeout state, and an independent target read-back. The official docs support separate discovery/execution/connection states but do not provide an external-effect receipt.
- Unknown: exactly-once semantics, cancellation after timeout, crash recovery, remote server durability, complete audit coverage, and whether a server side effect occurred after a client timeout.
- Unknown: security of arbitrary MCP server code and any credentials explicitly shared with it; the docs warn about arbitrary third-party servers but do not prove their behavior.

No real MCP server, credential, account, remote service, or Gemini CLI process was used.
