"""Trust tiers for plugin bundles: which claims carry evidence, and what happens when they don't.

The model is borrowed from ERC-8004 ("Trustless Agents", EIP draft; Identity and
Reputation reference contracts deployed to Ethereum mainnet 2026-01-29): three registries
with deliberately different meanings.

- The *identity* registry holds **self-asserted** claims: the registration file, the
  ``supportedTrust`` array (``["reputation", "crypto-economic", "tee-attestation"]``).
  Anyone can write anything there; it is a declaration, not a proof.
- The *reputation* registry holds **subjective** feedback: an on-chain audit trail of
  who said what about an agent. (The June 2026 Imperial College London / CSIRO Data61
  audit found 59-91% of reviewers exhibiting coordinated Sybil behaviour across three
  chains - raw reputation does not function as a trust signal, which is why this runtime
  has no reputation input at all.)
- The *validation* registry holds **objective** proof: an independent validator records
  a verifiable outcome for a specific piece of work, keyed by a content commitment
  (``requestHash``) rather than the payload.

The offline analogue - and the only part this module implements:

- ``plugin.toml`` self-assertions (``publisher``, ``compatibility.platforms``,
  ``policy``) are the identity registry: declarations.
- ``plugins.lock`` pin + seal + host-compatibility check are independent verification.
- ``[[evidence]]`` items (parsed by :mod:`plugin_manifest`) are the validation records:
  each one binds one manifest claim to one verifiable evidence pointer, with a
  ``sha256:`` commitment to the evidence content - the ``requestHash`` analogue, a
  commitment, never the payload.

Honest limits, stated once:

- ERC-8004 is an EIP *Draft*; at the time of writing the Validation Registry was not
  deployed on any mainnet chain (still under revision with the TEE community). Nothing
  here touches a chain - this is the *semantics* ("a claim without evidence is a
  declaration, not a proof") ported to an offline gate, not an integration.
- Evidence ``ref`` values are pointers with commitments. This runtime never fetches them:
  the offline guarantee means a trust decision cannot depend on a network read. What is
  checked is the *shape* (known kind, coverable claim, well-formed commitment); what is
  *recorded* is the binding, so a human reviewer can follow the pointer. An evidence
  item proves the author *named* their evidence, not that the evidence is true - exactly
  the gap a ``plugins.lock`` review exists to close.
"""
from __future__ import annotations

from typing import FrozenSet

#: The kinds of verifiable evidence a ``[[evidence]]`` item may cite. ``seal`` is the
#: manifest's own HMAC (``integrity.seal``) cited as evidence for the publisher claim;
#: ``rekor`` is a transparency-log entry for the bundle; ``attestation`` is a signed
#: statement by a third party; ``bench`` is a reproducible benchmark run;
#: ``review`` is a recorded human review distinct from the lockfile pin.
EVIDENCE_KINDS: tuple[str, ...] = ("seal", "attestation", "bench", "review", "rekor")

#: Manifest claims that *imply trust* and therefore need evidence to count toward the
#: top tier. ``publisher`` is the impersonation target (any string today);
#: ``compatibility.platforms`` is a test claim ("works on windows") no machine here has
#: run; ``policy`` ceilings are security promises. Everything else in the manifest is
#: either already mechanically checked (paths, hooks, tighten-only ceilings) or inert
#: (``description``), so evidence for it would be theatre.
COVERABLE_CLAIMS: tuple[str, ...] = ("publisher", "compatibility.platforms", "policy")

#: Trust tiers, weakest first. A tier is a property of (review state, evidence coverage)
#: - never of the bundle alone, because "trustworthy" without saying "on what basis"
#: is the sentence every supply-chain incident starts with.
TIER_REFUSED = "refused"  # failed a decisive check: not a tier, a refusal
TIER_DECLARED = "declared"  # parses and loads (lock not required here); nothing reviewed
TIER_REVIEWED = "reviewed"  # pinned in plugins.lock: a human reviewed this exact digest
TIER_EVIDENCED = "evidenced"  # reviewed AND every coverable claim carries evidence

TIERS: tuple[str, ...] = (TIER_REFUSED, TIER_DECLARED, TIER_REVIEWED, TIER_EVIDENCED)


def trust_tier(
    *,
    loadable: bool,
    pinned: bool,
    covered_claims: FrozenSet[str],
) -> tuple[str, tuple[str, ...]]:
    """The trust tier of one bundle, plus the evidence gaps that capped it.

    Deterministic and total: the same (loadable, pinned, covered) triple always yields
    the same tier. Missing evidence *downgrades* rather than refuses - a declaration
    without proof is still a declaration, and ERC-8004's registries are likewise separate
    from execution. What is load-bearing is the cap: a bundle whose ``publisher`` claim
    carries no evidence can never be ``evidenced``, however loudly it asserts the name.
    """
    if not loadable:
        return TIER_REFUSED, ("not loadable: a decisive check (integrity, host, parse) failed",)
    gaps = tuple(claim for claim in COVERABLE_CLAIMS if claim not in covered_claims)
    if pinned and not gaps:
        return TIER_EVIDENCED, ()
    if pinned:
        return TIER_REVIEWED, gaps
    return TIER_DECLARED, gaps


__all__ = [
    "COVERABLE_CLAIMS",
    "EVIDENCE_KINDS",
    "TIER_DECLARED",
    "TIER_EVIDENCED",
    "TIER_REFUSED",
    "TIER_REVIEWED",
    "TIERS",
    "trust_tier",
]
