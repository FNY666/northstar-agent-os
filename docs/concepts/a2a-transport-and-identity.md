# A2A transport and identity boundary

This is a design record for a possible A2A client. It is not an implementation
claim: Northstar does not currently discover remote Agent Cards, open A2A
connections, or send credentials to an A2A service. The accompanying fixtures
are offline trust-boundary cases for a future implementation.

## Protocol facts

The A2A v1.0.1 Agent Card is a self-described manifest. It can name ordered
`supportedInterfaces`, capabilities, skills, extensions, security schemes and
security requirements. Cards may also carry optional JWS signatures. Those
fields describe what the remote party claims; they do not establish a Northstar
principal or grant a local capability. An Agent Card signature is useful only
when its signing key is independently bound to a configured trust anchor.

The card's `AgentCapabilities` are protocol features such as streaming, push
notifications, extensions and extended-card support. `AgentSkill` describes
the kinds of work an agent says it can perform. Neither is the same namespace
as Northstar's `workspace:read`, `workspace:write`, `process:spawn` or other
host permissions. A required A2A extension means the A2A client must understand
that extension to interoperate; it cannot add a Northstar permission.

## Transport decision for a first client

- Use only a host-configured A2A v1.0.1 `JSONRPC` interface over HTTPS in the
  first increment. Do not choose an endpoint, protocol binding, tenant, or
  version solely from a fetched card. Do not silently downgrade to another
  interface or A2A version. Fetch a public card only from the fixed
  `/.well-known/agent-card.json` path at the host-configured origin; do not
  follow a card-supplied discovery URL.
- Treat discovery as an outbound network operation. The host must configure an
  allowed origin before a card is fetched. Apply the allowlist to the resolved
  connection destination as well as the URL; by default reject loopback,
  private, link-local, multicast, unspecified, reserved and cloud-metadata
  addresses. A private service requires a separate explicit host allowlist and
  egress policy; link-local and metadata ranges remain blocked. Re-resolve and
  re-check at connection time to narrow DNS-rebinding windows.
- Require HTTPS with normal hostname and certificate validation. Disable
  redirects for card and RPC requests in the initial client. If redirects are
  later required, every hop must remain within the configured origin and pass
  the same destination checks. Enforce egress restrictions outside the agent
  process too.
- Bound card and response bytes, JSON depth, connect/read timeouts, task count,
  stream duration, retries and total cost. Validate the selected protocol
  binding and schema before use. Never fetch card icons, documentation URLs,
  extension URLs, artifact URLs or webhook URLs as a side effect of parsing a
  card.
- Use an idempotency key for retried task creation and keep a local run budget
  across all remote rounds. Push notifications and callbacks are out of scope
  until their receiver identity, URL policy, replay defense and credentials
  have a separate design.

The remote Agent Card is data, never an instruction to perform another fetch.
In particular, `supportedInterfaces[].url`, OAuth metadata URLs, extension
URIs, `iconUrl`, provider documentation URLs, artifact URLs and push-notice
URLs all need separate policy before any request is made.

## Identity and credential binding

1. An operator or host policy creates the local `agent_id` and registers an
   allowed origin, A2A binding/version, expected service identity, auth profile,
   and approval state. The remote card's `name`, provider, URL, skills and
   optional signature do not choose that identity.
2. TLS authenticates the configured hostname. If the deployment needs a
   stronger service identity, pin or verify the expected signing key or
   organization identity through an independent trust store. A key ID or public
   key supplied only by the same card is not a trust anchor.
3. `securitySchemes` and `securityRequirements` describe what the peer asks
   callers to use. The host selects a compatible, preconfigured credential
   profile for that exact principal and origin; a mismatch pauses discovery
   for review. Never forward ambient credentials, accept a card-provided token,
   or send a secret to a new origin because an OAuth URL or API-key location
   appears in a card.
4. Record the canonical card digest, configured origin, selected interface,
   verification result, policy revision and credential profile identifier in
   the audit event. The digest detects drift; it does not authorize the card.
   A material card or key change pauses calls until policy re-admits it.
5. A2A task/context IDs belong to the remote service. Store them as opaque,
   principal-scoped remote references and map them to fresh local run/trace IDs.
   Never accept a remote ID as a local `run_id`, `workspace_id`, authorization
   subject or durable-store key shared with another principal.

## Capability and result boundary

An executable handoff is authorized by the intersection of:

```text
current host authorization
∩ source AgentAttestation
∩ host-registered target profile
∩ operator/policy allowlist
∩ exact HandoffRequest capabilities
```

The current `authorize_handoff` path enforces parent, source and registered
target ceilings, current policy revision, identity binding, expiry and exact
scope. A card cannot register itself or widen those ceilings. No automatic
mapping from skill names, examples, extension parameters, security schemes,
remote task state or output text to Northstar capabilities is allowed. Unknown
or wildcard capability names fail closed.

Remote messages, task states, artifacts and file references remain untrusted
input. They must pass bounded schema validation and the normal tool/permission
gate. Do not auto-download an artifact or let a remote agent choose a host path,
callback URL, workspace, shell command or secret destination. A successful A2A
response is not a verified postcondition; the host must independently check the
requested result before reporting completion.

## Offline attack fixtures

`components/northstar-agent-interop/tests/fixtures/a2a/` contains:

| Fixture | Attack represented | Expected boundary |
| --- | --- | --- |
| `agent_card_ssrf.json` | Agent Card interface targets the link-local metadata address. | Do not fetch it; a future transport must reject before connecting. |
| `agent_card_overclaim.json` | Skills/extensions claim write and secret access; signature key is attacker supplied. | Card remains untrusted metadata; neither skills nor signature create a registered identity or grant. |
| `handoff_over_scope.json` | A syntactically valid handoff asks for capabilities beyond the host grant. | Existing handoff authorization rejects it. |

The tests do not mock a network client because none exists. They check that
cards cannot be used as `AgentProfile` registry entries and that the existing
handoff gate rejects out-of-scope requests. The URL fixture is checked locally
to ensure it still represents a link-local target. This is not URL-validation
coverage for a future transport; that transport must add resolver, redirect,
TLS, credential-audience and egress tests before it can ship.

## Gate before implementing network access

Before adding a client, provide a host-owned trust/configuration API; an
origin-and-resolution guard with redirect policy; audience-bound auth and
rotation; card schema/version pinning and change review; bounded streaming,
task polling and cancellation; remote-ID isolation; output/artifact handling;
audit events; and offline adversarial tests for DNS rebinding, redirect chains,
credential exfiltration, forged signatures, oversized cards, malformed
extensions, duplicate task delivery and capability widening. Only then run a
separate canary against an explicitly approved test agent. No production client
is implied by completing this design or its local fixtures.

## References

- [A2A v1.0.1 specification](https://a2a-protocol.org/v1.0.1/specification/)
- [Agent Card and fields, §4.4.1–4.4.7](https://a2a-protocol.org/v1.0.1/specification/#441-agentcard)
- [Discovery mechanisms and protocol declaration, §8.2–8.3](https://a2a-protocol.org/v1.0.1/specification/#82-discovery-mechanisms)
- [Agent Card signing, §8.4](https://a2a-protocol.org/v1.0.1/specification/#84-agent-card-signing)
- [Authorization scoping and extended-card access, §13.1–13.3](https://a2a-protocol.org/v1.0.1/specification/#131-data-access-and-authorization-scoping)
- [General security best practices, §13.4](https://a2a-protocol.org/v1.0.1/specification/#134-general-security-best-practices)
