# Security Audit Report — Northstar AgentOS self-audit 2026-10-03

Profile: **quick** (bounded pass; 10 coverage units, one wave). This report
presents partial coverage — it does not claim to exhaust the target.

- Target: northstar-agent-os @ `c2ec7a9` (worktree clean at audit time)
- Method: Northstar `security-audit` skill (six-phase method absorbed from
  cloudflare/security-audit-skill, MIT)
- Units: 10 covered, 1 candidate (downgraded to informational on verification),
  0 blocked, 0 deferred

## Findings

**Confirmed: 2, both informational (no severity above informational).**

1. `northstar/sandbox-auto-backend-downgrade` — sandbox backend `auto`
   silently resolves to the weaker `process` backend on hosts without bwrap.
   Documented tradeoff; explicit `bwrap` fails closed. Recommendation: emit an
   auditable notice on downgrade.
2. `northstar/digest-arguments-silent-coercion` — `digest_arguments` coerces
   non-dict payloads to the `{}` digest instead of raising. Unreachable with
   divergence in all current production callers (fail-closed guards adjacent),
   but a latent footgun. Recommendation: raise on non-dict.

**Rejected: 1.**

- `northstar/approval-replay-nondict-payload` — hypothesis that non-dict
  payloads could replay approvals onto different arguments. Refuted by source
  trace: every binding/check path type-checks or fails closed first.

## Coverage statement

Covered units (surface::boundary::subsystem::attack_class):

- approval::agent-to-gate::consent::consent-bypass — gate never treats payload
  declarations as authority; mutating calls always re-invoke the host callback.
- approval::gate-to-host-callback::approval-binding::approval-replay —
  per-call (call_id, arguments_digest) binding verified by source trace and
  local execution.
- tool-call::agent-to-gate::budget::budget-bypass — ceilings enforced in the
  run loop; subagent spend rolls up to the parent.
- audit::audit-writer-to-verifier::audit-chain::audit-tampering — hash chain
  plus anchor manifests; bare-chain truncation limit honestly documented.
- tool-call::tool-to-effect::os-sandbox::sandbox-escape — bwrap preferred with
  seccomp denylist; two documented limitations (auto downgrade, denylist
  posture).
- mcp::mcp-server-to-client::mcp-client::mcp-server-impersonation — env
  allowlist; elicitation through the approval gate.
- skill::skill-to-loader::skill-scripts::skill-script-escape — never auto-run;
  sandbox-only execution.
- session::session-to-lease-holder::session-lease::lease-bypass — kernel
  flock; session-id validated before path derivation.
- provider::provider-to-retry-policy::provider-retry::transient-amplifier —
  hard ceilings (8 attempts, delay/deadline caps).
- plugin::plugin-to-host::plugin-load::supply-chain — sha256 pinning required;
  unpinned installs refused.

No prior ledger existed for this target; this run seeds the first one.
