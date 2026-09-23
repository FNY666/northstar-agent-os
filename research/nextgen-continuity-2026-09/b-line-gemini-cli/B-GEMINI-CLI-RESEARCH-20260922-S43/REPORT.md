# B-S43 Official Gemini CLI tool, permission, and recovery boundaries

- Research date: 2026-09-22 (Asia/Shanghai).
- Evidence level: official Gemini CLI repository documentation, public and read-only. Snapshot source: `https://github.com/google-gemini/gemini-cli`, local commit `d5b3e3accb26000d273abf16e0f1dd83aa5428a9` (2026-09-21T20:36:40Z).
- This slice does not access a live Gemini CLI process, a real workspace, credentials, or production services.

## Verified findings

1. `docs/reference/tools.md` says tool execution is evaluated by the CLI; mutating file tools and shell commands require manual user approval, and the CLI shows a diff or exact command before confirmation. Sandboxing and trusted-folder controls are separate controls.
2. `run_shell_command` can execute arbitrary shell commands and requires confirmation. The shell documentation states that background commands return immediately while the process continues; this is not a completion receipt for the background process.
3. `tools.core` is an allowlist for all built-in tools when populated, not only shell. Shell command entries use command-prefix matching; command chaining is split and a disallowed part blocks the whole chain. The documented blocklist is checked before the allowlist, so a matching excluded prefix is denied even if allowed too. These are configuration semantics, not proof that an external command produced a desired effect.
4. File `write_file` and `replace` require manual approval. The file-system documentation scopes tools to a `rootDirectory`; it does not establish that an approved write is durable, externally visible, or successfully consumed by another process.
5. `/restore` is documented as listing or restoring tool changes, and `/rewind`/checkpoint commands provide session/file-edit recovery functions. The docs do not establish universal rollback of shell side effects, third-party effects, already-running background processes, or external services.
6. `ask_user` is an inherently interactive tool and supports one to four questions including yes/no confirmation. This proves an interaction gate exists, not that a user answered, that the answer was persisted, or that a requested external effect completed.
7. `activate_skill` loads specialized instructions and may grant task-specific tools; activation is agent-driven. The documentation does not prove that skill instructions are trusted, that their tools are harmless, or that activation alone grants authorization for external side effects.

## Inferred / unknown boundaries

- Inferred: a safe acceptance design should separate request/approval, tool invocation, process completion, target read-back, and business postcondition. A tool approval or process exit is not equivalent to the last two.
- Unknown: exactly-once behavior, crash recovery, durable audit completeness, cancellation of already-running background commands, and external-effect rollback are not established by these pages.
- Unknown: whether every policy/configuration path has identical precedence in every release; the cited docs describe the documented settings but are not a compatibility guarantee for all future versions.

## Sources and windows

See `sources.md` and `research-manifest.json`; copied source snapshots preserve the cited evidence window. No claim is based on search snippets or third-party documentation.
