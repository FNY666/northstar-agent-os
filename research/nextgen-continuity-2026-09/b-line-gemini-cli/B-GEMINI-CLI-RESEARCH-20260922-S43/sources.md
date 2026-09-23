# S43 official source matrix

Research date/access date: 2026-09-22 (Asia/Shanghai). All sources are first-party Google Gemini CLI repository documents, accessed through the public GitHub repository and raw GitHub URLs. Evidence window: the cited sections/lines in the local snapshot at commit `d5b3e3accb26000d273abf16e0f1dd83aa5428a9`.

| ID | Official URL | Evidence window | Status | Supports | Cannot prove |
|---|---|---|---|---|---|
| S43-1 | https://github.com/google-gemini/gemini-cli/blob/main/docs/reference/tools.md | Automatic execution and security; tool discovery/configuration; available tools | verified | manual approval for mutators, diff/exact-command review, sandbox/trusted-folder separation, tool discovery | approval does not prove execution or external postcondition |
| S43-2 | https://raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/reference/tools.md | same document, raw bytes HTTP 200 on 2026-09-22 | verified | reproducible first-party text source | future-main may change; no release immutability claim |
| S43-3 | https://github.com/google-gemini/gemini-cli/blob/main/docs/tools/shell.md | command execution, interactive commands, background processes, environment variables, command restrictions | verified | shell confirmation, background process behavior, `tools.core`/`tools.exclude` command-prefix semantics and blocklist precedence | background completion, process liveness after crash, desired target state |
| S43-4 | https://raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/tools/shell.md | raw bytes HTTP 200 on 2026-09-22 | verified | same shell semantics in directly retrievable official source | production behavior under all OS/shells |
| S43-5 | https://github.com/google-gemini/gemini-cli/blob/main/docs/tools/file-system.md | `write_file`, `replace`, rootDirectory, confirmation | verified | file mutators require manual approval and are rootDirectory-scoped | durability, visibility to another process, rollback of non-file effects |
| S43-6 | https://github.com/google-gemini/gemini-cli/blob/main/docs/tools/ask-user.md | tool definition and confirmation | verified | interactive question/yes-no gate exists | answer persistence, authorization beyond the interaction, effect completion |
| S43-7 | https://github.com/google-gemini/gemini-cli/blob/main/docs/tools/activate-skill.md | description and behavior | verified | skill activation loads instructions and may grant task-specific tools | trustworthiness of skill content or authorization for side effects |
| S43-8 | https://github.com/google-gemini/gemini-cli/blob/main/docs/reference/commands.md | `/restore`, `/rewind`, `/resume`, `/permissions`, `/skills` entries | verified | documented session/file recovery and permission/skill controls | universal shell rollback, external-effect rollback, crash recovery, exactly-once |

## Scope limitations

No real Gemini CLI invocation, account, MCP server, shell command, workspace mutation, network service, or credential was used. All claims are documentation-level. Production continuity, complete audit coverage, exactly-once external effects, and rollback of already-running/background processes remain unknown.
