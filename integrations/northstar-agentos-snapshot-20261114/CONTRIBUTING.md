# Contributing to Northstar Agent OS

Northstar is built around evidence, explicit security boundaries, and reproducible verification.

## Before opening a change

1. Explain the threat model and the operational boundary.
2. Add or update deterministic tests before implementation changes.
3. Do not include credentials, private prompts, production transcripts, or host-specific secrets.
4. Keep OpenBot compatibility claims precise; compatibility does not imply affiliation.
5. Test process, signal, and systemd behavior on native Linux when relevant.

## Pull requests

A pull request should include:

- the user-visible or operational goal;
- files changed and why;
- test commands and complete results;
- known environment limitations;
- rollback or migration notes for service changes.

Claims of completion should be supported by fresh command output. Static inspection alone is not evidence of runtime correctness.
