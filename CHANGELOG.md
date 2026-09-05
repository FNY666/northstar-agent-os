# Northstar Agent OS — initial public component

This repository establishes the Northstar Agent OS name and publishes the first independently maintained component: Northstar Codex Sidecar.

## Scope of this release

- restricted Unix-socket transport;
- bounded request validation;
- read-only, ephemeral Codex execution;
- structured errors and redaction;
- process-group timeout cleanup;
- systemd hardening template;
- deterministic Python tests.

## Explicit non-goals

This is not yet a complete multi-agent operating system, hosted service, or endorsement of the upstream OpenBot project. Runtime identity binding, per-run workspace authorization, native Linux E2E, and production deployment integration remain host-level responsibilities.

See [README.md](README.md) for installation and security boundaries.
