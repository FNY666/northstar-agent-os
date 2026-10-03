"""DID-based agent identity, delegation chains with depth limits, and
permission-combination prohibition.

Absorbs the *mechanism ideas* of three 2026 identity/governance patterns
(honest scope at the end of this docstring):

1. **RaonSecure (Korea)** — DID-based agent identity issuance + delegation
   tracking + audit. Each agent gets a unique digital identity ("ID card");
   who delegated what to whom, and to what scope, is recorded as policy;
   execution history is recorded for post-hoc audit and accountability.
   (it.chosun.com 2023092170131 / etnews 20260930000271 / sedaily 20096666,
   read 2026-10-04 — **no code or spec text was available**; only the
   mechanism idea — per-agent DID, delegation relationship tracking,
   activity audit — is absorbed.)
2. **Korean agent-gateway pattern** — policy-derived *combination*
   prohibition: a gateway denies dangerous permission *combinations*
   ("read secrets" + "network egress" together) even when each permission
   alone is allowed. The prohibition list is derived from policy, not
   hardcoded per tool.
3. **AstraCipher** (github.com/acumenix/astracipher, BSL 1.1, W3C-DID
   compliant, read 2026-10-04) — trust chains with depth limits:
   ``Creator -> Authorizer -> Agent -> Sub-agent``. Delegated authority
   carries an explicit depth ceiling; a chain that exceeds it fails closed.
   (Mechanism borrowed: depth-limited trust chains. NOT borrowed: the
   ``did:astracipher`` method, the ML-DSA-65 hybrid suite, the W3C VC
   envelope, on-chain anchoring.)

What this module is
--------------------
* **Identity issuance**: the run's root authority mints one Ed25519-bound
  identity per agent. The DID is ``did:northstar:<hex(pubkey)>`` — a
  lightweight DID method where the method-specific identifier *is* the
  public key, so identity resolves and verifies offline without a registry
  or a ledger. It is not a full W3C DID implementation (no resolution
  protocol, no service endpoints, no key rotation documents).
* **Delegation chains**: each delegation records delegator DID,
  delegatee DID, the granted permission set, an expiry, and its depth.
  Two structural rules, evaluated at verify time:
  - *attenuation*: a delegatee's permissions must be a subset of the
    delegator's effective permissions (a child can never hold more than
    its parent — the same narrowing direction as
    :mod:`delegation_credentials`);
  - *depth ceiling*: the chain length may not exceed the policy's
    ``max_depth``. Depth 0 is the root-issued identity; each delegation
    adds one. A chain longer than ``max_depth`` fails closed at the
    *verifying* hop, exactly like AstraCipher's depth limits and the AWS
    Cedar L2 "depth of six exceeds the hard limit of five" layer.
* **Combination prohibition**: policy declares forbidden permission
  *combinations* (frozensets of permission names). An agent holding every
  permission of a combination — even when each permission was granted
  individually — is denied the *use* of the combined set. This closes the
  "each permission is innocent, the combination is exfiltration" hole the
  Korean gateway pattern names. Unknown/malformed combination specs fail
  closed, never open.

Every issuance, delegation, revocation, and denial emits an audit event
(see :func:`identity_audit_events`); feeding those into the
``audit.ndjson/1`` hash chain anchors "who was whom, delegated what, to
whom, and when" in the audit trail, so a verifier can later prove which
identity carried which rights at each hop.

Honest scope: this is the DID-as-key-binding + depth-limited delegation +
combination-prohibition *subset*. It is not W3C DID resolution, not
AstraCipher's verifiable-credential envelope, not RaonSecure's OneAccess
product, and not a policy language — combinations and ceilings are plain
data structures the host owns.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Sequence

import ed25519
from audit_chain import canonical_json

#: Wire version of this identity format.
IDENTITY_VERSION = "northstar.agent-identity/1"

#: DID method this module implements.
DID_METHOD = "northstar"

#: Default delegation-depth ceiling when the host names none.
#: AstraCipher's documented chain is Creator -> Authorizer -> Agent ->
#: Sub-agent (4 roles); the default ceiling of 4 mirrors that shape.
DEFAULT_MAX_DEPTH = 4


class IdentityError(Exception):
    """Raised when an identity or delegation cannot be built (caller bug)."""


def _hex(raw: bytes) -> str:
    return raw.hex()


def _raw(hexed: str, length: int) -> bytes | None:
    try:
        raw = bytes.fromhex(hexed)
    except (TypeError, ValueError):
        return None
    return raw if len(raw) == length else None


def did_of(public_key: bytes) -> str:
    """Derive the DID for a 32-byte Ed25519 public key.

    ``did:northstar:<hex(pubkey)>`` — the method-specific identifier *is*
    the key, so the DID is self-describing and needs no registry lookup to
    verify against.
    """
    if len(public_key) != 32:
        raise IdentityError("public key must be 32 bytes")
    return f"did:{DID_METHOD}:{_hex(public_key)}"


def parse_did(did: str) -> bytes | None:
    """Extract the public key from a ``did:northstar:<hex>`` DID.

    Returns ``None`` (never raises) for anything that is not a well-formed
    northstar DID: wrong method, wrong length, non-hex.
    """
    if not isinstance(did, str):
        return None
    parts = did.split(":")
    if len(parts) != 3 or parts[0] != "did" or parts[1] != DID_METHOD:
        return None
    return _raw(parts[2], 32)


@dataclass(frozen=True)
class AgentIdentity:
    """One issued agent identity: a DID bound to an Ed25519 key.

    The ``document`` is the canonical, signable payload — the thing a
    counterparty checks before trusting the identity.
    """

    did: str
    agent: str
    role: str
    public_key_hex: str
    issued_by: str
    issued_at: str = ""
    revoked: bool = False

    def document(self) -> dict[str, Any]:
        return {
            "version": IDENTITY_VERSION,
            "did": self.did,
            "agent": self.agent,
            "role": self.role,
            "public_key": self.public_key_hex,
            "issued_by": self.issued_by,
            "issued_at": self.issued_at,
            "revoked": self.revoked,
        }

    def as_dict(self) -> dict[str, Any]:
        return self.document()


@dataclass(frozen=True)
class DelegationRecord:
    """One delegation hop: delegator DID -> delegatee DID.

    ``permissions`` is the *maximum* the delegatee may exercise through
    this hop; ``depth`` counts the hop (the root-issued identity is depth
    0, its first delegatee is depth 1). ``signature`` is the delegator's
    Ed25519 signature over ``canonical_json(envelope)`` — offline
    verifiable by anyone holding the delegator's DID.
    """

    delegator_did: str
    delegatee_did: str
    permissions: tuple[str, ...]
    depth: int
    expires_at: str = ""
    purpose: str = ""
    signature: str = ""

    def envelope(self) -> dict[str, Any]:
        return {
            "version": IDENTITY_VERSION,
            "delegator": self.delegator_did,
            "delegatee": self.delegatee_did,
            "permissions": list(self.permissions),
            "depth": self.depth,
            "expires_at": self.expires_at,
            "purpose": self.purpose,
        }

    def as_dict(self) -> dict[str, Any]:
        payload = self.envelope()
        payload["signature"] = self.signature
        return payload


@dataclass(frozen=True)
class IdentityVerdict:
    """Result of verifying an identity document or a delegation chain."""

    allowed: bool
    reason: str = ""
    failed_rule: str = ""
    depth: int = 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "failed_rule": self.failed_rule,
            "depth": self.depth,
        }


@dataclass(frozen=True)
class CombinationRule:
    """One forbidden permission combination.

    ``permissions`` is the set that must never be held together;
    ``name`` is the audit label (e.g. ``"secret-exfiltration"``);
    ``why`` records the policy rationale for the audit trail.
    """

    name: str
    permissions: frozenset[str]
    why: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "permissions": sorted(self.permissions),
            "why": self.why,
        }


def combination_rule(
    name: str, permissions: Iterable[str], *, why: str = ""
) -> CombinationRule:
    """Build a combination rule, failing closed on malformed input.

    A rule needs a non-empty name and at least *two* distinct permissions —
    a single-permission "combination" is a plain denial and belongs in the
    permission gate, not here. Anything malformed raises ``IdentityError``
    (a policy-authoring bug), never a silently-ignored rule.
    """
    label = str(name).strip()
    if not label:
        raise IdentityError("combination rule needs a non-empty name")
    perms = frozenset(str(p).strip() for p in permissions if str(p).strip())
    if len(perms) < 2:
        raise IdentityError(
            f"combination rule {label!r} needs at least two distinct "
            "permissions; a single permission belongs in the gate"
        )
    return CombinationRule(name=label, permissions=perms, why=str(why))


class IdentityIssuer:
    """Root authority: mints agent identities and records delegations.

    Mirrors the trust root role in :mod:`delegation_credentials` — the
    same host/supervisor key that signs the audit feed. The secret never
    leaves this object.
    """

    def __init__(self, root_secret: bytes) -> None:
        if len(root_secret) != 32:
            raise IdentityError("root secret must be 32 bytes")
        self._root_secret = bytes(root_secret)
        self._root_pub = ed25519.public_key(root_secret)

    @classmethod
    def generate(cls) -> "IdentityIssuer":
        return cls(os.urandom(32))

    @property
    def root_public_key(self) -> bytes:
        return self._root_pub

    @property
    def root_did(self) -> str:
        return did_of(self._root_pub)

    def issue(
        self,
        agent: str,
        *,
        role: str = "agent",
        issued_at: str = "",
        issued_by: str = "supervisor",
    ) -> tuple[AgentIdentity, bytes]:
        """Mint an identity: fresh keypair, DID, and the agent's secret.

        Returns ``(identity, secret)`` — the secret is handed to the agent
        (or its key store) exactly once; the issuer keeps no copy.
        """
        name = str(agent).strip()
        if not name:
            raise IdentityError("agent name must be non-empty")
        secret = os.urandom(32)
        pub = ed25519.public_key(secret)
        identity = AgentIdentity(
            did=did_of(pub),
            agent=name,
            role=str(role),
            public_key_hex=_hex(pub),
            issued_by=str(issued_by),
            issued_at=str(issued_at),
        )
        return identity, secret

    def delegate(
        self,
        delegator_secret: bytes,
        delegator_did: str,
        delegatee_did: str,
        permissions: Iterable[str],
        *,
        depth: int,
        expires_at: str = "",
        purpose: str = "",
    ) -> DelegationRecord:
        """Record one delegation hop, signed by the delegator's key.

        ``depth`` is the hop number the *delegatee* sits at (1 for the
        root's first delegatee). The signature binds the whole envelope, so
        a verifier can check the hop offline from the delegator's DID.
        """
        if len(delegator_secret) != 32:
            raise IdentityError("delegator secret must be 32 bytes")
        perms = tuple(sorted({str(p).strip() for p in permissions if str(p).strip()}))
        if not perms:
            raise IdentityError("delegation with an empty permission set is meaningless")
        if parse_did(delegator_did) is None:
            raise IdentityError(f"malformed delegator DID {delegator_did!r}")
        if parse_did(delegatee_did) is None:
            raise IdentityError(f"malformed delegatee DID {delegatee_did!r}")
        if not isinstance(depth, int) or depth < 1:
            raise IdentityError("delegation depth must be a positive integer")
        record = DelegationRecord(
            delegator_did=delegator_did,
            delegatee_did=delegatee_did,
            permissions=perms,
            depth=depth,
            expires_at=str(expires_at),
            purpose=str(purpose),
        )
        signature = ed25519.sign(delegator_secret, canonical_json(record.envelope()))
        return DelegationRecord(
            delegator_did=record.delegator_did,
            delegatee_did=record.delegatee_did,
            permissions=record.permissions,
            depth=record.depth,
            expires_at=record.expires_at,
            purpose=record.purpose,
            signature=_hex(signature),
        )


def verify_identity(
    identity: AgentIdentity,
    *,
    revoked_dids: Iterable[str] = (),
) -> IdentityVerdict:
    """Check an identity document: DID/key binding and revocation.

    The DID *is* the public key, so "binding" is a pure parse check — a
    document whose DID does not name its own key is malformed, not merely
    untrusted.
    """
    key = _raw(identity.public_key_hex, 32)
    if key is None:
        return IdentityVerdict(False, "identity public key is malformed", "key_malformed")
    if did_of(key) != identity.did:
        return IdentityVerdict(
            False,
            "DID does not name the identity's own public key",
            "did_key_mismatch",
        )
    if identity.did in set(revoked_dids) or identity.revoked:
        return IdentityVerdict(False, "identity is revoked", "revoked")
    return IdentityVerdict(True, "identity valid: DID binds its key, not revoked")


def verify_delegation_chain(
    chain: Sequence[DelegationRecord],
    root_did: str,
    root_permissions: Iterable[str],
    *,
    max_depth: int = DEFAULT_MAX_DEPTH,
    time_iso: str = "",
) -> IdentityVerdict:
    """Verify a whole delegation chain against the root.

    Evaluated per hop, in order — every hop must hold:

    1. the hop's signature verifies against the *delegator's* DID key
       (offline, no registry);
    2. the hop's delegator is the previous hop's delegatee (chain
       continuity; the first hop's delegator is the root);
    3. depth increases by exactly one per hop and never exceeds
       ``max_depth`` (AstraCipher-style depth ceiling);
    4. the hop's permission set is a subset of the *effective* permissions
       so far (attenuation: a child never holds more than its parent);
    5. the hop has not expired (``expires_at`` is ISO-8601; an empty
       ``expires_at`` means no expiry — the verifier never reads a clock,
       ``time_iso`` is caller-supplied like everywhere else in this repo).

    One failure denies the whole chain. ``max_depth`` must be a positive
    integer; anything else fails closed.
    """
    if not isinstance(max_depth, int) or isinstance(max_depth, bool) or max_depth < 1:
        return IdentityVerdict(False, "max_depth must be a positive integer", "max_depth_malformed")
    hops = list(chain)
    if not hops:
        return IdentityVerdict(False, "delegation chain is empty", "empty_chain")
    effective = {str(p) for p in root_permissions}
    expected_delegator = root_did
    for index, hop in enumerate(hops):
        if not isinstance(hop, DelegationRecord):
            return IdentityVerdict(False, f"hop {index} is not a DelegationRecord", "hop_malformed")
        # -- continuity ------------------------------------------------
        if hop.delegator_did != expected_delegator:
            return IdentityVerdict(
                False,
                f"hop {index}: delegator {hop.delegator_did} does not continue "
                f"the chain (expected {expected_delegator})",
                "chain_discontinuity",
                depth=index,
            )
        # -- depth ------------------------------------------------------
        if hop.depth != index + 1:
            return IdentityVerdict(
                False,
                f"hop {index}: depth {hop.depth} does not follow the chain "
                f"(expected {index + 1})",
                "depth_skew",
                depth=index,
            )
        if hop.depth > max_depth:
            return IdentityVerdict(
                False,
                f"hop {index}: depth {hop.depth} exceeds the ceiling "
                f"max_depth={max_depth}",
                "depth_exceeded",
                depth=hop.depth,
            )
        # -- signature ---------------------------------------------------
        delegator_key = parse_did(hop.delegator_did)
        signature = _raw(hop.signature, 64)
        if delegator_key is None or signature is None:
            return IdentityVerdict(
                False, f"hop {index}: malformed DID or signature", "hop_malformed", depth=index
            )
        if not ed25519.verify(delegator_key, canonical_json(hop.envelope()), signature):
            return IdentityVerdict(
                False,
                f"hop {index}: delegation signature invalid (forged or tampered)",
                "signature_invalid",
                depth=index,
            )
        # -- attenuation --------------------------------------------------
        granted = set(hop.permissions)
        if not granted <= effective:
            excess = sorted(granted - effective)
            return IdentityVerdict(
                False,
                f"hop {index}: delegation grants {excess} beyond the "
                "delegator's effective permissions (amplification rejected)",
                "attenuation_violated",
                depth=index,
            )
        # -- expiry --------------------------------------------------------
        if hop.expires_at:
            if not time_iso:
                return IdentityVerdict(
                    False,
                    f"hop {index}: delegation expires at {hop.expires_at} but no "
                    "reference time was supplied; failing closed",
                    "expiry_uncheckable",
                    depth=index,
                )
            if not time_iso < hop.expires_at:
                return IdentityVerdict(
                    False,
                    f"hop {index}: delegation expired at {hop.expires_at}",
                    "delegation_expired",
                    depth=index,
                )
        effective = granted
        expected_delegator = hop.delegatee_did
    return IdentityVerdict(
        True,
        f"delegation chain valid: {len(hops)} hops, depth {hops[-1].depth} "
        f"within max_depth={max_depth}, permissions attenuated at every hop",
        depth=hops[-1].depth,
    )


def check_combination_prohibition(
    held_permissions: Iterable[str],
    rules: Sequence[CombinationRule],
) -> tuple[bool, CombinationRule | None]:
    """Deny when the held permission set completes a forbidden combination.

    Returns ``(True, None)`` when no rule fires, ``(False, rule)`` naming
    the first firing rule otherwise. A held set that contains *every*
    permission of a rule's combination is denied — even when each
    permission was granted individually and innocently. Rules are
    evaluated in order; the first firing rule is reported.
    """
    held = {str(p).strip() for p in held_permissions if str(p).strip()}
    for rule in rules:
        if not isinstance(rule, CombinationRule):
            # A malformed policy list fails closed: an unreadable rule is a
            # deny, not a skip.
            return False, None
        if rule.permissions <= held:
            return False, rule
    return True, None


def evaluate_request(
    *,
    identity: AgentIdentity,
    chain: Sequence[DelegationRecord],
    root_did: str,
    root_permissions: Iterable[str],
    requested_permissions: Iterable[str],
    combination_rules: Sequence[CombinationRule] = (),
    max_depth: int = DEFAULT_MAX_DEPTH,
    time_iso: str = "",
    revoked_dids: Iterable[str] = (),
) -> IdentityVerdict:
    """One-call evaluation: identity + chain + depth + combinations.

    The full RaonSecure-style gate in one function: the caller's identity
    must be valid, the delegation chain from the root to the caller must
    verify (depth ceiling + attenuation at every hop), and the caller's
    *effective* permission set — chain grants plus the permissions this
    request would exercise — must not complete any forbidden combination.
    The first failing layer denies; layers never compensate for each
    other.
    """
    identity_verdict = verify_identity(identity, revoked_dids=revoked_dids)
    if not identity_verdict.allowed:
        return identity_verdict
    chain_verdict = verify_delegation_chain(
        chain,
        root_did,
        root_permissions,
        max_depth=max_depth,
        time_iso=time_iso,
    )
    if not chain_verdict.allowed:
        return chain_verdict
    last_hop = list(chain)[-1]
    if last_hop.delegatee_did != identity.did:
        return IdentityVerdict(
            False,
            "delegation chain does not terminate at the caller's identity",
            "chain_identity_mismatch",
            depth=chain_verdict.depth,
        )
    effective = set(last_hop.permissions) | {
        str(p).strip() for p in requested_permissions if str(p).strip()
    }
    ok, rule = check_combination_prohibition(effective, combination_rules)
    if not ok:
        label = rule.name if rule is not None else "<malformed rule>"
        return IdentityVerdict(
            False,
            f"permission combination prohibited by rule {label!r}: "
            f"{sorted(rule.permissions) if rule else '?'}",
            "combination_prohibited",
            depth=chain_verdict.depth,
        )
    return IdentityVerdict(
        True,
        "identity, delegation chain, depth ceiling and permission "
        "combinations all hold",
        depth=chain_verdict.depth,
    )


def identity_audit_events(
    *,
    identity: AgentIdentity | None = None,
    chain: Sequence[DelegationRecord] = (),
    verdict: IdentityVerdict | None = None,
    note: str = "",
) -> list[dict[str, Any]]:
    """Audit events for identity issuance/delegation/verification.

    Each event pins the DID and the chain depth, so the ``audit.ndjson/1``
    hash chain anchors who-was-whom, who-delegated-what-to-whom, and which
    rule decided. Feed these into ``audit_chain.chain_record`` /
    ``chain_records`` in order.
    """
    events: list[dict[str, Any]] = []
    if identity is not None:
        events.append(
            {
                "event": "agent_identity.issued",
                "did": identity.did,
                "agent": identity.agent,
                "role": identity.role,
                "issued_by": identity.issued_by,
                "issued_at": identity.issued_at,
                "identity_version": IDENTITY_VERSION,
                "note": note,
            }
        )
    for hop in chain:
        if not isinstance(hop, DelegationRecord):
            continue
        events.append(
            {
                "event": "agent_identity.delegated",
                "delegator": hop.delegator_did,
                "delegatee": hop.delegatee_did,
                "permissions": list(hop.permissions),
                "depth": hop.depth,
                "expires_at": hop.expires_at,
                "purpose": hop.purpose,
                "signature": hop.signature,
                "note": note,
            }
        )
    if verdict is not None:
        events.append(
            {
                "event": (
                    "agent_identity.verified"
                    if verdict.allowed
                    else "agent_identity.denied"
                ),
                "reason": verdict.reason,
                "failed_rule": verdict.failed_rule,
                "depth": verdict.depth,
                "note": note,
            }
        )
    return events


__all__ = [
    "DEFAULT_MAX_DEPTH",
    "DID_METHOD",
    "IDENTITY_VERSION",
    "AgentIdentity",
    "CombinationRule",
    "DelegationRecord",
    "IdentityError",
    "IdentityIssuer",
    "IdentityVerdict",
    "check_combination_prohibition",
    "combination_rule",
    "did_of",
    "evaluate_request",
    "identity_audit_events",
    "parse_did",
    "verify_delegation_chain",
    "verify_identity",
]
