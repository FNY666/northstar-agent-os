# Northstar Host Authorization and Workspace Broker

This component is a local, standard-library host candidate for the boundary
between a verified Northstar run and a host-owned private workspace.

## Install (pip)

```sh
pip install ../northstar-run-contract   # declared dependency, from this repository
pip install .                            # resolves northstar-run-contract
# or, once published:
pip install northstar-host
```

The wheel installs `authorization` and `workspace` as top-level modules; the
version (`0.1.0.dev0`, unreleased) is declared in `pyproject.toml`.

## Boundary order

The component keeps four decisions separate:

1. **Structural validation** — `validate_run_request()` checks the Run Request
   schema and bounds.
2. **Binding authentication** — `verify_binding()` checks an expiring HMAC
   binding made with a host-held binding secret.
3. **Policy authorization** — `authorize_run()` requires an explicitly listed
   actor and checks every requested capability against a `HostPolicy` allowlist.
4. **Workspace allocation** — `WorkspaceBroker.allocate()` re-verifies both
   signed tokens and the Run Request before creating one private directory.

This component does not execute a Sidecar request, run a shell, write prompts
or credentials, or verify task postconditions. Passing these local tests is not
proof of a complete Agent OS or production isolation.

## Default-deny policy

`HostPolicy.from_mapping(revision, actor_capabilities)` creates an immutable
actor-to-capability allowlist. An actor must be explicitly present, even for an
empty capability request. An unlisted capability, wildcard actor, wildcard
capability, duplicate entry, or invalid policy identifier is rejected.

`requested_capabilities` remains a request until `authorize_run()` issues a
signed `northstar.authorization.v1` grant. The grant binds:

- `actor_id`, `run_id`, and `workspace_id`;
- the exact requested capability set;
- the policy revision; and
- an expiry no later than the verified binding expiry.

Authorization verification uses HMAC-SHA256 and constant-time signature
comparison. It returns no claims when verification fails. Binding and
authorization secrets are supplied by the host and never placed in tokens.

## Opaque workspace allocation

`WorkspaceBroker` requires separate host-held binding, authorization, and
workspace-derivation secrets. It accepts no caller-provided workspace path.
The path is:

```text
<host-root>/runs/<64-lowercase-hex-HMAC-key>
```

The key is derived from canonical `actor_id`, `run_id`, and `workspace_id`
claims. Those identifiers are not directly used as directory names. The host
root, `runs` directory, and run directory must all be ordinary directories
with exact mode `0700`. Existing symlinks, files, or non-private directories
are rejected; the broker does not silently `chmod` an unsafe path.

Allocation is idempotent for the same verified claims and current policy
revision: it returns the same opaque path while preserving its existing
permissions. It does not place run input or credentials in that directory.

## Example boundary

```python
from authorization import HostPolicy, authorize_run
from binding import sign_binding, verify_binding
from workspace import WorkspaceBroker

binding_token = sign_binding(binding_claims, binding_secret)
verified = verify_binding(binding_token, binding_secret, now=now)
policy = HostPolicy.from_mapping("policy-1", {"actor-001": ["search"]})
grant_token = authorize_run(
    run, verified, policy, now=now, secret=authorization_secret
)
allocation = WorkspaceBroker(
    "/var/lib/northstar-host",
    binding_secret=binding_secret,
    authorization_secret=authorization_secret,
    derivation_secret=derivation_secret,
).allocate(
    run,
    binding_token,
    grant_token,
    current_policy_revision="policy-1",
    now=now + 1,
)
```

The example assumes the host has already constructed valid Run Contract
claims. It intentionally omits secret values and does not show Sidecar
execution.

## Current scope and limitations

This is a local implementation candidate only. It has not been deployed to
103, 104, a dormitory host, or a production OpenBot instance. It is not a
sandbox, network policy, lease manager, cleanup service, or complete workspace
broker. Native Linux validation is still required for concurrency, filesystem
races, process boundaries, service permissions, and deployment integration.

The host must keep secrets outside the repository and provide rotation,
revocation, policy storage, audit minimization, lifecycle cleanup, and any
additional approval or execution boundaries. Never commit API keys, OAuth
tokens, private keys, production `.env` files, or user transcripts.
