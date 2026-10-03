# SLSA v1.0 Provenance → Northstar audit chain: field mapping

**Source:** [SLSA v1.0 Provenance](https://slsa.dev/spec/v1.0/provenance)
(in-toto Statement, predicate type `https://slsa.dev/provenance/v1`),
read 2026-10-03. Only the *field semantics* are absorbed; the trust model
is explicitly **not** — see "Honest limitations" below. Nothing here claims
SLSA conformance or a SLSA level.

## Why borrow SLSA's shape

SLSA provenance answers four questions about a build: *what was built*
(subject), *who built it* (builder.id), *under what conditions*
(buildDefinition), and *from what* (resolvedDependencies). An agent run has
the same four questions — *what happened* (the audit event), *who ran it*
(the runtime), *under what conditions* (approval tiers, modes), and *from
what* (tool definitions, skills, plugins). The audit chain already answers
"what happened" with tamper evidence; the `provenance` envelope field adds
the other three in a vocabulary verifiers already know how to read.

## Field-by-field mapping

| SLSA v1.0 field | Northstar `provenance` field | Meaning in the audit setting |
|---|---|---|
| `buildDefinition.buildType` | `buildType` | URI naming the run-type profile the evidence claims to follow (default `https://northstar.dev/agent-run/v1`). Like the build type, it selects the verifier's expectations for which evidence fields must be present. |
| `buildDefinition.externalParameters` | `externalParameters` | Externally-controlled inputs: user-supplied tool arguments, prompt text, anything the runtime did not author. **Kept verbatim:** the verifier MUST NOT trust them. |
| *(SLSA's verifier obligation)* | `externalParametersTrust` | Northstar addition, not a SLSA field. SLSA says externalParameters are untrusted *by definition*; Northstar requires the producer to say so out loud: `"untrusted"` (default) or `"verified"` (the builder checked the inputs against a policy). A record carrying non-empty `externalParameters` without this marking fails envelope validation *and* `audit verify` — unmarked external input is untrusted input, never a silent pass. |
| `buildDefinition.internalParameters` | `internalParameters` | Builder-set parameters: approval-tier thresholds, mode, policy bundle digest in effect. Trusted only as far as the builder is. |
| `buildDefinition.resolvedDependencies` | `resolvedDependencies` | Materials the run resolved: tool definitions, skill versions, plugin manifests, MCP server versions. Each entry is `{"uri": ..., "digest": {algo: value}}`, exactly SLSA's `ResourceDescriptor` shape. |
| `runDetails.builder.id` | `builder.id` | URI identifying the builder — the runtime component that executed the run (default `https://northstar.dev/runtime/northstar-agent-runtime`). **Self-asserted** (see limitations): it names the claimant, not a proven identity. |
| `runDetails.metadata.invocationId` | `invocationId` | Unique id of this run invocation. Must equal the envelope's `run_id` when both are present; a mismatch fails validation (evidence attached to the wrong run). |
| — | `selfAsserted` | Honesty marker (Northstar addition). `true` means `builder.id` is a self-report; integrity comes from the hash chain + optional Ed25519 signature + external anchor, not from a hardened build platform. |

## SLSA fields deliberately NOT mapped

* **`subject`** — SLSA's subject is the artifact the provenance is about.
  Here the chained audit record *is* the subject; `chain_hash` already
  identifies it uniquely. Duplicating a digest would add nothing.
* **`runDetails.metadata.startedOn` / `finishedOn`** — the envelope `ts`
  already timestamps every event; build-level timing is derived, not
  duplicated.
* **`runDetails.builder.version` / `builderDependencies`** — the runtime
  does not pin its own build version in evidence yet. Honest gap: adding
  it is future work (would need a reproducible runtime build identifier).
* **`runDetails.byproducts`** — no equivalent; not needed for verification.
* **DSSE envelope / in-toto Statement** — the `provenance` object rides
  inside the chained, optionally Ed25519-signed audit envelope instead of
  a separate DSSE envelope. One seal, one format.

## Honest limitations

1. **No SLSA level claim.** SLSA levels 2–4 require a hardened,
   non-falsifiable builder and (at L4) hermetic reproducible builds with
   two-person review. Northstar's runtime is self-asserting software, not a
   hardened builder. This mapping borrows SLSA's *field semantics* so audit
   evidence is readable with SLSA-trained eyes; it is not a conformance
   claim.
2. **`builder.id` is self-reported.** A malicious runtime can claim any
   builder id. Trust in the id comes from the Ed25519 `key_id` binding and
   the external anchor (Rekor/WORM), not from the string itself.
3. **`externalParametersTrust: "verified"` is only as strong as the
   builder's check.** The marking records *that* a check happened; the
   policy bundle digest in `internalParameters` is how a verifier judges
   whether the check meant anything.

## Construction and verification

* Build with `audit_export.build_provenance(...)`; it validates before
  returning and defaults `externalParametersTrust` to an *explicit*
  `"untrusted"`.
* Envelope validation: `audit_export.validate_audit_record` and the
  normative `northstar-run-contract/audit.py::validate_record` (kept in
  lockstep; the parity test pins them).
* `audit verify` additionally enforces the trust marking on every chained
  record carrying non-empty `externalParameters`, so hand-crafted feeds
  cannot dodge the rule.
