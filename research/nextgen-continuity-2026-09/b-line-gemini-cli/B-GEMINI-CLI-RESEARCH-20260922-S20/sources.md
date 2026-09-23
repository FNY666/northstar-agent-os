# S20 sources (official background only; not behavioral evidence)

Research date: 2026-09-22. Network access was limited to the public URLs below. No prior research directories, local research artifacts, shared/P0, incident directories, D10, L12, D14, canonical, staging, 140, tri-line, systemd, real service, or credentials were accessed.

1. Google Gemini CLI repository README (official project repository): https://github.com/google-gemini/gemini-cli/blob/main/README.md
   - Accessed 2026-09-22; primary, public project background.
   - Supports only project identity/context. It does not establish crash durability, exactly-once delivery, remote rollback, retry semantics, or production safety.
2. Gemini CLI official documentation landing page: https://geminicli.com/docs/
   - Accessed 2026-09-22; primary, public documentation background.
   - Documentation landing page only; no claim here about the synthetic harness's rules.
3. Google Gemini API function calling documentation: https://ai.google.dev/gemini-api/docs/function-calling
   - Accessed 2026-09-22; primary official API background.
   - Function/tool concepts are contextual only; it does not prove Gemini CLI persistence or remote side-effect semantics.
4. Google Gemini API troubleshooting documentation: https://ai.google.dev/gemini-api/docs/troubleshooting
   - Accessed 2026-09-22; primary official troubleshooting background.
   - Failure terminology is contextual only; it does not validate this fixture against production.

Evidence boundary: The executable results in this package are generated exclusively from local synthetic inputs and deterministic local rules. Official URLs are background sources, not execution evidence. Any claim about actual Gemini CLI behavior is `unverified` or `inaccessible` under this slice.
