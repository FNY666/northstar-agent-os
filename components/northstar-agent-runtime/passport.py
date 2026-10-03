"""Capability passports: minting, mandatory-intersection delegation, real revocation.

Absorbs the *mechanism ideas* of MCPS (anakintano/langchain-mcp-secure,
read 2026-10-04 — actual code, not docs):

1. **Passport fields** (``mcp_secure.create_passport`` / ``sign_passport``):
   ``sub``, ``public_key``, ``capabilities``, ``iat``, ``exp``, ``jti``
   (unique), ``signature`` over a canonical payload. MCPS signs with
   ECDSA P-256 via the ``cryptography`` package; this repo is stdlib-only
   with a vendored Ed25519, so passports here are Ed25519-signed over
   :func:`audit_chain.canonical_json` — the same envelope convention as
   :mod:`agent_identity`.
2. **Mandatory intersection on delegation**
   (``DelegationToken.create`` / ``intersect_capabilities``): the delegatee's
   capabilities are computed *at mint time* as
   ``delegator_caps ∩ requested_scope`` and carried inside the token, so
   privilege escalation is prevented at the protocol level, not by
   convention. Constraint merge is delegator-wins (most restrictive):
   set intersection for list constraints (MCPS's ``allowed_tables``),
   ``min`` for numeric constraints (MCPS's ``rate_limit``), recursive
   merge for nested dicts, delegator's value otherwise.
3. **Verification gate** (``DelegationTokenValidator.verify`` 6 steps):
   format → signature → TTL → replay/revocation → capability check →
   chain validation. Here: format → signature → expiry → revocation →
   chain (parent-JTI continuity, depth ceiling, intersection invariant).
4. **Revocation — real, not stubbed**: MCPS's passport-level
   ``revoke_jti`` is a no-op and ``is_jti_revoked`` always returns
   ``False`` (``mcp_secure.py``: "In real implementation, would ...").
   This module implements real revocation: a caller-owned
   :class:`RevocationList`; any revoked JTI fails closed at verify time,
   and revoking a parent JTI invalidates its whole delegation subtree
   (every hop's JTI is checked, so the subtree dies with the parent).

What this module is
-------------------
* **Minting**: :class:`PassportIssuer` mints root capability passports
  (signed by the authority key); :func:`delegate_passport` mints a child
  passport signed by the *delegator's* key, with capabilities narrowed by
  mandatory intersection.
* **Wiring into agent_identity**: passports bind an
  :class:`agent_identity.AgentIdentity` (DID + Ed25519 key) via
  :func:`passport_for_identity`; the delegation chain mirrors
  :func:`agent_identity.verify_delegation_chain` (continuity, attenuation
  via intersection, depth ceiling) but carries *capability constraints*,
  not just permission names.
* **Verification never reads a clock**: ``time_iso`` is caller-supplied
  (ISO-8601, UTC, ``...Z``), exactly like the rest of this repo. A
  passport with an expiry and no reference time fails closed.

Honest scope: this is the passport-mint/verify + intersection +
revocation *subset*. It is not JWT (no ``cryptography``/PyJWT here), not
W3C Verifiable Credentials, not MCPS's LangChain callback handler, quota
pools, anomaly detectors, or trust-authority network revocation — the
revocation list is caller-owned data, like everything else in this repo.
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Mapping, Sequence

import ed25519
from audit_chain import canonical_json

#: Wire version of this passport format.
PASSPORT_VERSION = "northstar.capability-passport/1"

#: Default passport lifetime, mirroring MCPS's 30-minute delegation TTL.
DEFAULT_PASSPORT_TTL_SECONDS = 1800

#: Default delegation-depth ceiling, mirroring agent_identity (AstraCipher's
#: Creator -> Authorizer -> Agent -> Sub-agent chain shape).
DEFAULT_MAX_DEPTH = 4

#: Trust levels, mirroring MCPS's TRUST_LEVELS.
TRUST_LEVELS = {
    "UNIDENTIFIED": 0,
    "IDENTIFIED": 1,
    "VERIFIED": 2,
    "TRUSTED": 3,
}


class PassportError(Exception):
    """Raised when a passport cannot be built (caller/policy bug).

    Mint-time problems raise; verify-time problems return a
    :class:`PassportVerdict` with ``allowed=False`` (fail-closed denial,
    never an exception, at the gate).
    """


def _utcnow_iso() -> str:
    # Only used to *default* documentation examples; mint/verify paths
    # require caller-supplied time_iso and never call this.
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _iso_plus(base_iso: str, seconds: int) -> str:
    try:
        base = datetime.strptime(base_iso, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except (TypeError, ValueError):
        raise PassportError(f"malformed time_iso {base_iso!r}; want YYYY-MM-DDTHH:MM:SSZ")
    return (base + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _new_jti() -> str:
    # MCPS used "dt-{token_hex(16)}" for delegation tokens; passports here
    # use the "pp-" prefix. 128 bits of entropy per mint.
    return f"pp-{secrets.token_hex(16)}"


def _check_capabilities(caps: Any, *, where: str) -> dict[str, Any]:
    """Validate the capability-dict shape, failing closed.

    Shape (mirrors MCPS's capability dicts)::

        {tool_name: {"allowed": bool, "constraints": {...optional...}}}
    """
    if not isinstance(caps, dict) or not caps:
        # An empty capability set is meaningless at mint time: a passport
        # that authorises nothing should not exist. (MCPS permitted empty
        # intersections; here mint refuses and the gate would deny anyway.)
        raise PassportError(f"{where}: capabilities must be a non-empty dict")
    cleaned: dict[str, Any] = {}
    for tool, spec in caps.items():
        if not isinstance(tool, str) or not tool.strip():
            raise PassportError(f"{where}: capability name must be a non-empty string")
        if not isinstance(spec, dict):
            raise PassportError(
                f"{where}: capability {tool!r} must be a dict with 'allowed'"
            )
        allowed = spec.get("allowed")
        if not isinstance(allowed, bool):
            raise PassportError(
                f"{where}: capability {tool!r} 'allowed' must be a bool"
            )
        constraints = spec.get("constraints", {})
        if not isinstance(constraints, dict):
            raise PassportError(
                f"{where}: capability {tool!r} 'constraints' must be a dict"
            )
        cleaned[tool.strip()] = {"allowed": allowed, "constraints": dict(constraints)}
    return cleaned


# ── Mandatory intersection ──────────────────────────────────────────────


def _intersect_values(delegator: Any, requested: Any) -> Any:
    """Merge one constraint value — the delegator's side always wins ties.

    * both lists → sorted set intersection (MCPS's ``allowed_tables``);
    * both numbers (not bool) → ``min`` (MCPS's ``rate_limit`` value);
    * both dicts → recursive merge;
    * otherwise → the delegator's value (most restrictive by authority).
    """
    if isinstance(delegator, list) and isinstance(requested, list):
        try:
            return sorted(set(delegator) & set(requested))
        except TypeError:
            # Unhashable elements: fall back to delegator's list.
            return list(delegator)
    if (
        isinstance(delegator, (int, float))
        and not isinstance(delegator, bool)
        and isinstance(requested, (int, float))
        and not isinstance(requested, bool)
    ):
        return min(delegator, requested)
    if isinstance(delegator, dict) and isinstance(requested, dict):
        merged: dict[str, Any] = {}
        for key in delegator:
            if key in requested:
                merged[key] = _intersect_values(delegator[key], requested[key])
            else:
                merged[key] = delegator[key]
        # Requested-only keys are *narrowings* the delegator explicitly
        # signed into the child token; keeping them can only restrict.
        for key in requested:
            if key not in delegator:
                merged[key] = requested[key]
        return merged
    return delegator


def _intersect_constraints(
    delegator: Mapping[str, Any],
    requested: Mapping[str, Any],
) -> dict[str, Any]:
    """Merge two constraint dicts — the delegator's constraints win."""
    merged: dict[str, Any] = {}
    for key, del_val in delegator.items():
        if key in requested:
            merged[key] = _intersect_values(del_val, requested[key])
        else:
            merged[key] = del_val
    for key, req_val in requested.items():
        if key not in delegator:
            merged[key] = req_val
    return merged


def intersect_capabilities(
    delegator_caps: Mapping[str, Any],
    requested_caps: Mapping[str, Any],
) -> dict[str, Any]:
    """Mandatory capability intersection: ``requested ∩ delegator``.

    Rules (from MCPS's ``intersect_capabilities``, generalised):

    * a requested tool must exist in the delegator's capabilities with
      ``allowed=True`` — otherwise :class:`PassportError` (a policy bug at
      mint time; the escalation is refused before any token exists);
    * a requested tool with ``allowed=False`` is simply not delegated;
    * constraints merge via :func:`_intersect_constraints` (delegator wins).

    The returned dict is the *exact* capability set the child passport
    carries — the narrowing happens here, at creation, not at use.
    """
    result: dict[str, Any] = {}
    for tool, req_spec in requested_caps.items():
        del_spec = delegator_caps.get(tool)
        if del_spec is None:
            raise PassportError(
                f"delegator not authorised for tool {tool!r} — cannot delegate it"
            )
        if not isinstance(del_spec, dict) or not del_spec.get("allowed", False):
            raise PassportError(
                f"delegator's tool {tool!r} is denied — cannot delegate a denied tool"
            )
        if not isinstance(req_spec, dict) or not req_spec.get("allowed", False):
            # Requested as denied — skip (not delegating it).
            continue
        merged = _intersect_constraints(
            del_spec.get("constraints", {}),
            req_spec.get("constraints", {}),
        )
        result[tool] = {"allowed": True, "constraints": merged}
    if not result:
        raise PassportError(
            "capability intersection is empty — nothing to delegate; "
            "refusing to mint a passport that authorises nothing"
        )
    return result


def _value_within(child: Any, parent: Any) -> bool:
    """Is the child's constraint value no broader than the parent's?"""
    if isinstance(parent, list) and isinstance(child, list):
        try:
            return set(child) <= set(parent)
        except TypeError:
            return child == parent
    if (
        isinstance(parent, (int, float))
        and not isinstance(parent, bool)
        and isinstance(child, (int, float))
        and not isinstance(child, bool)
    ):
        return child <= parent
    if isinstance(parent, dict) and isinstance(child, dict):
        for key, child_val in child.items():
            if key not in parent:
                continue  # extra narrowing, explicitly granted at mint
            if not _value_within(child_val, parent[key]):
                return False
        return True
    return child == parent


def capabilities_within(
    child_caps: Mapping[str, Any], parent_caps: Mapping[str, Any]
) -> tuple[bool, str]:
    """Check the attenuation invariant: child caps ⊆ parent caps.

    Every tool the child holds must exist in the parent with
    ``allowed=True``; every constraint the child carries must be no
    broader than the parent's. Returns ``(True, "")`` or
    ``(False, reason)``.
    """
    for tool, child_spec in child_caps.items():
        parent_spec = parent_caps.get(tool)
        if not isinstance(parent_spec, dict) or not parent_spec.get("allowed", False):
            return False, f"tool {tool!r} not held (or denied) by the parent"
        if not isinstance(child_spec, dict):
            return False, f"tool {tool!r} has a malformed child spec"
        child_constraints = child_spec.get("constraints", {})
        parent_constraints = parent_spec.get("constraints", {})
        if not isinstance(child_constraints, dict) or not isinstance(
            parent_constraints, dict
        ):
            return False, f"tool {tool!r} has malformed constraints"
        for key, child_val in child_constraints.items():
            if key not in parent_constraints:
                continue  # extra narrowing, explicitly granted at mint
            if not _value_within(child_val, parent_constraints[key]):
                return (
                    False,
                    f"tool {tool!r} constraint {key!r} is broader than the parent's",
                )
    return True, ""

# ── Passport document ───────────────────────────────────────────────────


@dataclass(frozen=True)
class CapabilityPassport:
    """One capability passport: identity + capabilities + delegation lineage.

    ``jti`` is unique per mint (``pp-<32 hex>``); ``signature`` is the
    *issuer's* Ed25519 signature over :meth:`envelope` — the root
    authority's key for root passports, the delegator's key for delegated
    ones. ``parent_jti``/``delegation_depth`` carry the MCPS delegation
    lineage (root passport: ``parent_jti=""``, ``delegation_depth=0``).
    """

    jti: str
    sub: str
    did: str
    public_key_hex: str
    capabilities: Mapping[str, Any]
    iat: str
    exp: str
    trust_level: int = TRUST_LEVELS["IDENTIFIED"]
    issued_by: str = ""
    parent_jti: str = ""
    delegation_depth: int = 0
    purpose: str = ""
    signature: str = ""

    def envelope(self) -> dict[str, Any]:
        return {
            "version": PASSPORT_VERSION,
            "jti": self.jti,
            "sub": self.sub,
            "did": self.did,
            "public_key": self.public_key_hex,
            "capabilities": {k: dict(v) for k, v in self.capabilities.items()},
            "iat": self.iat,
            "exp": self.exp,
            "trust_level": self.trust_level,
            "issued_by": self.issued_by,
            "parent_jti": self.parent_jti,
            "delegation_depth": self.delegation_depth,
            "purpose": self.purpose,
        }

    def as_dict(self) -> dict[str, Any]:
        payload = self.envelope()
        payload["signature"] = self.signature
        return payload


@dataclass(frozen=True)
class PassportVerdict:
    """Result of verifying a passport or a passport chain."""

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


# ── Real revocation ───────────────────────────────────────────────────
#
# MCPS's passport-level revocation is a stub (revoke_jti is a no-op,
# is_jti_revoked always returns False). This is the real thing: an
# explicit, caller-owned revocation list. The verifier checks every
# passport's JTI against it, so revoking a parent JTI invalidates the
# whole delegation subtree below it.


@dataclass
class RevocationEntry:
    jti: str
    reason: str = ""
    revoked_at: str = ""


class RevocationList:
    """Caller-owned revocation list for passport JTIs.

    ``revoke`` is idempotent; ``is_revoked`` is the check the verifier
    runs. There is no un-revoke: revocation is one-way, exactly like the
    receipt invalidation in :mod:`receipt_gate` (``valid → revoked``,
    never back).
    """

    def __init__(self) -> None:
        self._entries: dict[str, RevocationEntry] = {}

    def revoke(self, jti: str, *, reason: str = "", revoked_at: str = "") -> None:
        label = str(jti).strip()
        if not label:
            raise PassportError("cannot revoke an empty JTI")
        if label not in self._entries:
            self._entries[label] = RevocationEntry(
                jti=label, reason=str(reason), revoked_at=str(revoked_at)
            )

    def is_revoked(self, jti: Any) -> bool:
        return isinstance(jti, str) and jti in self._entries

    def entry(self, jti: str) -> RevocationEntry | None:
        return self._entries.get(jti)

    def __len__(self) -> int:
        return len(self._entries)


# ── Minting ───────────────────────────────────────────────────────────


def _hex_key(hexed: str, length: int, *, where: str) -> bytes:
    try:
        raw = bytes.fromhex(hexed)
    except (TypeError, ValueError):
        raise PassportError(f"{where}: public key is not hex")
    if len(raw) != length:
        raise PassportError(f"{where}: public key must be {length} bytes")
    return raw


class PassportIssuer:
    """Root authority: mints root capability passports.

    Mirrors :class:`agent_identity.IdentityIssuer` — the same
    host/supervisor key that signs the audit feed. The secret never
    leaves this object.
    """

    def __init__(self, authority_secret: bytes) -> None:
        if len(authority_secret) != 32:
            raise PassportError("authority secret must be 32 bytes")
        self._secret = bytes(authority_secret)
        self._pub = ed25519.public_key(authority_secret)

    @classmethod
    def generate(cls) -> "PassportIssuer":
        return cls(os.urandom(32))

    @property
    def public_key_hex(self) -> str:
        return self._pub.hex()

    def mint(
        self,
        *,
        sub: str,
        public_key_hex: str,
        capabilities: Mapping[str, Any],
        did: str = "",
        trust_level: int = TRUST_LEVELS["IDENTIFIED"],
        issued_by: str = "supervisor",
        ttl_seconds: int = DEFAULT_PASSPORT_TTL_SECONDS,
        time_iso: str = "",
        jti: str = "",
    ) -> CapabilityPassport:
        """Mint a root capability passport, signed by the authority key.

        ``time_iso`` is required (no clock reads); ``exp`` is
        ``iat + ttl_seconds``. ``jti`` is generated when not supplied
        (tests may pin it for determinism).
        """
        name = str(sub).strip()
        if not name:
            raise PassportError("passport subject must be non-empty")
        _hex_key(public_key_hex, 32, where="mint")
        caps = _check_capabilities(capabilities, where="mint")
        if not isinstance(trust_level, int) or trust_level not in TRUST_LEVELS.values():
            raise PassportError(f"mint: trust_level {trust_level!r} is not a known level")
        if not time_iso:
            raise PassportError("mint: time_iso is required (no clock reads)")
        if not isinstance(ttl_seconds, int) or ttl_seconds < 1:
            raise PassportError("mint: ttl_seconds must be a positive integer")
        iat = str(time_iso)
        exp = _iso_plus(iat, ttl_seconds)  # raises PassportError on malformed time_iso
        passport_id = str(jti).strip() or _new_jti()
        unsigned = CapabilityPassport(
            jti=passport_id,
            sub=name,
            did=str(did),
            public_key_hex=str(public_key_hex),
            capabilities=caps,
            iat=iat,
            exp=exp,
            trust_level=trust_level,
            issued_by=str(issued_by),
        )
        signature = ed25519.sign(self._secret, canonical_json(unsigned.envelope()))
        return replace(unsigned, signature=signature.hex())


def delegate_passport(
    parent: CapabilityPassport,
    delegator_secret: bytes,
    *,
    delegatee_sub: str,
    delegatee_public_key_hex: str,
    requested_capabilities: Mapping[str, Any],
    delegatee_did: str = "",
    trust_level: int = TRUST_LEVELS["IDENTIFIED"],
    issued_by: str = "",
    ttl_seconds: int = DEFAULT_PASSPORT_TTL_SECONDS,
    time_iso: str = "",
    purpose: str = "",
    jti: str = "",
) -> CapabilityPassport:
    """Mint a child passport: capabilities = parent ∩ requested (mandatory).

    The intersection is computed *here*, at creation — the child passport
    carries exactly the narrowed set, so a verifier never has to trust
    the delegatee's word about what was granted (MCPS's protocol-level
    guarantee). Signed by the *delegator's* key, chained via
    ``parent_jti`` with ``delegation_depth = parent.depth + 1``.
    """
    if not isinstance(parent, CapabilityPassport):
        raise PassportError("delegate_passport: parent must be a CapabilityPassport")
    if len(delegator_secret) != 32:
        raise PassportError("delegate_passport: delegator secret must be 32 bytes")
    name = str(delegatee_sub).strip()
    if not name:
        raise PassportError("delegate_passport: delegatee subject must be non-empty")
    _hex_key(delegatee_public_key_hex, 32, where="delegate_passport")
    requested = _check_capabilities(requested_capabilities, where="delegate_passport")
    # Mandatory intersection — escalation attempts raise here, before any
    # token exists.
    narrowed = intersect_capabilities(parent.capabilities, requested)
    if not isinstance(trust_level, int) or trust_level not in TRUST_LEVELS.values():
        raise PassportError(
            f"delegate_passport: trust_level {trust_level!r} is not a known level"
        )
    if not time_iso:
        raise PassportError("delegate_passport: time_iso is required (no clock reads)")
    if not isinstance(ttl_seconds, int) or ttl_seconds < 1:
        raise PassportError("delegate_passport: ttl_seconds must be a positive integer")
    # A child passport must not outlive its parent: clamp the TTL.
    iat = str(time_iso)
    child_exp = _iso_plus(iat, ttl_seconds)
    if parent.exp and child_exp > parent.exp:
        child_exp = parent.exp
    passport_id = str(jti).strip() or _new_jti()
    unsigned = CapabilityPassport(
        jti=passport_id,
        sub=name,
        did=str(delegatee_did),
        public_key_hex=str(delegatee_public_key_hex),
        capabilities=narrowed,
        iat=iat,
        exp=child_exp,
        trust_level=trust_level,
        issued_by=str(issued_by) or parent.sub,
        parent_jti=parent.jti,
        delegation_depth=parent.delegation_depth + 1,
        purpose=str(purpose),
    )
    signature = ed25519.sign(delegator_secret, canonical_json(unsigned.envelope()))
    return replace(unsigned, signature=signature.hex())


def passport_for_identity(
    identity: Any,
    issuer: PassportIssuer,
    capabilities: Mapping[str, Any],
    *,
    time_iso: str = "",
    ttl_seconds: int = DEFAULT_PASSPORT_TTL_SECONDS,
    trust_level: int = TRUST_LEVELS["IDENTIFIED"],
) -> CapabilityPassport:
    """Bind an :class:`agent_identity.AgentIdentity` to a capability passport.

    The explicit wiring between the eighty-fifth batch (DID identity) and
    this batch (capability passports): the passport's ``did``/``public_key``
    are the identity's, so a verifier that trusts the identity key can
    check the passport without a second key exchange.
    """
    did = getattr(identity, "did", "")
    public_key_hex = getattr(identity, "public_key_hex", "")
    agent = getattr(identity, "agent", "")
    if not did or not public_key_hex or not agent:
        raise PassportError(
            "passport_for_identity: identity needs did, public_key_hex and agent"
        )
    return issuer.mint(
        sub=str(agent),
        public_key_hex=str(public_key_hex),
        capabilities=capabilities,
        did=str(did),
        trust_level=trust_level,
        ttl_seconds=ttl_seconds,
        time_iso=time_iso,
    )

# ── Verification ────────────────────────────────────────────────────


def verify_passport(
    passport: Any,
    *,
    signer_public_key_hex: str,
    time_iso: str = "",
    revocation: RevocationList | None = None,
) -> PassportVerdict:
    """Verify one passport: format → signature → expiry → revocation.

    * format: required fields present with the right types; ``jti``
      non-empty; capabilities well-formed;
    * signature: the issuer's Ed25519 signature over the canonical
      envelope verifies against ``signer_public_key_hex``;
    * expiry: ``time_iso < exp`` must hold; a passport that expires with
      no reference time supplied fails closed (the verifier never reads
      a clock); a future-dated ``iat`` is rejected;
    * revocation: a JTI on the caller-owned :class:`RevocationList` is
      denied — this is the real revocation MCPS stubbed out.

    The first failing step denies; steps never compensate for each other.
    """
    if not isinstance(passport, CapabilityPassport):
        return PassportVerdict(False, "not a CapabilityPassport", "passport_malformed")
    if not passport.jti or not isinstance(passport.jti, str):
        return PassportVerdict(False, "passport JTI is missing", "jti_missing")
    try:
        _check_capabilities(passport.capabilities, where="verify")
    except PassportError as exc:
        return PassportVerdict(False, str(exc), "capabilities_malformed")
    # -- signature ---------------------------------------------------
    try:
        signer_key = _hex_key(signer_public_key_hex, 32, where="verify")
    except PassportError:
        return PassportVerdict(
            False, "signer public key is malformed", "signer_key_malformed"
        )
    try:
        signature = bytes.fromhex(passport.signature)
    except (TypeError, ValueError):
        return PassportVerdict(
            False, "passport signature is not hex", "signature_malformed"
        )
    if len(signature) != 64 or not ed25519.verify(
        signer_key, canonical_json(passport.envelope()), signature
    ):
        return PassportVerdict(
            False,
            "passport signature invalid (forged or tampered)",
            "signature_invalid",
        )
    # -- expiry --------------------------------------------------------
    if passport.exp:
        if not time_iso:
            return PassportVerdict(
                False,
                "passport expires but no reference time was supplied; failing closed",
                "expiry_uncheckable",
            )
        if not time_iso < passport.exp:
            return PassportVerdict(
                False,
                f"passport expired at {passport.exp}",
                "passport_expired",
            )
    if passport.iat and time_iso and time_iso < passport.iat:
        return PassportVerdict(
            False,
            "passport is not yet valid (future-dated iat)",
            "passport_not_yet_valid",
        )
    # -- revocation (real) ----------------------------------------------
    if revocation is not None and revocation.is_revoked(passport.jti):
        return PassportVerdict(
            False,
            f"passport JTI {passport.jti} is revoked",
            "passport_revoked",
        )
    return PassportVerdict(
        True,
        "passport valid: format, signature, expiry and revocation all hold",
        depth=passport.delegation_depth,
    )


def check_tool_use(
    passport: CapabilityPassport,
    tool: str,
    *,
    signer_public_key_hex: str,
    time_iso: str = "",
    revocation: RevocationList | None = None,
) -> PassportVerdict:
    """Authorise one tool use against a passport (the step-5 analogue).

    The passport must verify, and the tool must be present with
    ``allowed=True``. A tool the passport does not carry is denied even
    when the holder's *identity* is valid — the passport, not the person,
    is the authority.
    """
    verdict = verify_passport(
        passport,
        signer_public_key_hex=signer_public_key_hex,
        time_iso=time_iso,
        revocation=revocation,
    )
    if not verdict.allowed:
        return verdict
    spec = passport.capabilities.get(tool)
    if not isinstance(spec, dict) or not spec.get("allowed", False):
        return PassportVerdict(
            False,
            f"tool {tool!r} is not granted by this passport",
            "tool_not_granted",
            depth=passport.delegation_depth,
        )
    return PassportVerdict(
        True,
        f"tool {tool!r} granted by passport {passport.jti}",
        depth=passport.delegation_depth,
    )


def verify_passport_chain(
    chain: Sequence[CapabilityPassport],
    *,
    root_signer_key_hex: str,
    time_iso: str = "",
    revocation: RevocationList | None = None,
    max_depth: int = DEFAULT_MAX_DEPTH,
) -> PassportVerdict:
    """Verify a delegation chain of passports, root first.

    Per hop, in order:

    1. the hop verifies as a single passport (format, signature, expiry,
       revocation) — signed by the *previous* hop's key (the root hop by
       the root authority key);
    2. ``parent_jti`` names the previous hop's JTI (chain continuity);
    3. ``delegation_depth`` increases by exactly one and never exceeds
       ``max_depth`` (malformed limits fail closed);
    4. the hop's capabilities satisfy :func:`capabilities_within` against
       the previous hop's (the intersection invariant re-checked at
       verify time — a tampered child that widened its own caps is
       caught even though the mint-time intersection was correct).

    Because every hop's JTI is revocation-checked, revoking any ancestor
    JTI invalidates the whole subtree below it.
    """
    if (
        not isinstance(max_depth, int)
        or isinstance(max_depth, bool)
        or max_depth < 1
    ):
        return PassportVerdict(
            False, "max_depth must be a positive integer", "max_depth_malformed"
        )
    hops = list(chain)
    if not hops:
        return PassportVerdict(False, "passport chain is empty", "empty_chain")
    previous: CapabilityPassport | None = None
    for index, hop in enumerate(hops):
        signer_hex = (
            root_signer_key_hex if index == 0 else previous.public_key_hex  # type: ignore[union-attr]
        )
        verdict = verify_passport(
            hop,
            signer_public_key_hex=signer_hex,
            time_iso=time_iso,
            revocation=revocation,
        )
        if not verdict.allowed:
            return PassportVerdict(
                verdict.allowed,
                f"hop {index}: {verdict.reason}",
                verdict.failed_rule,
                depth=index,
            )
        if index == 0:
            if hop.parent_jti:
                return PassportVerdict(
                    False,
                    "root passport must not name a parent JTI",
                    "root_has_parent",
                    depth=0,
                )
            if hop.delegation_depth != 0:
                return PassportVerdict(
                    False,
                    "root passport must sit at delegation_depth 0",
                    "root_depth_skew",
                    depth=0,
                )
        else:
            assert previous is not None
            if hop.parent_jti != previous.jti:
                return PassportVerdict(
                    False,
                    f"hop {index}: parent_jti does not continue the chain",
                    "chain_discontinuity",
                    depth=index,
                )
            if hop.delegation_depth != previous.delegation_depth + 1:
                return PassportVerdict(
                    False,
                    f"hop {index}: delegation_depth does not follow the chain",
                    "depth_skew",
                    depth=index,
                )
            ok, reason = capabilities_within(hop.capabilities, previous.capabilities)
            if not ok:
                return PassportVerdict(
                    False,
                    f"hop {index}: capability attenuation violated: {reason}",
                    "attenuation_violated",
                    depth=index,
                )
        if hop.delegation_depth > max_depth:
            return PassportVerdict(
                False,
                f"hop {index}: depth {hop.delegation_depth} exceeds max_depth={max_depth}",
                "depth_exceeded",
                depth=hop.delegation_depth,
            )
        previous = hop
    return PassportVerdict(
        True,
        f"passport chain valid: {len(hops)} passports, depth "
        f"{hops[-1].delegation_depth} within max_depth={max_depth}, "
        "capabilities attenuated at every hop",
        depth=hops[-1].delegation_depth,
    )


# ── Audit ───────────────────────────────────────────────────────────


def passport_audit_events(
    *,
    passport: CapabilityPassport | None = None,
    chain: Sequence[CapabilityPassport] = (),
    verdict: PassportVerdict | None = None,
    revoked_jti: str = "",
    note: str = "",
) -> list[dict[str, Any]]:
    """Audit events for passport issuance/delegation/verification/revocation.

    Each event pins the JTI (and the parent JTI + depth for delegations),
    so the ``audit.ndjson/1`` hash chain anchors which passport carried
    which capabilities at each hop. Feed these into
    ``audit_chain.chain_record`` / ``chain_records`` in order.
    """
    events: list[dict[str, Any]] = []
    if passport is not None:
        events.append(
            {
                "event": "passport.issued",
                "jti": passport.jti,
                "sub": passport.sub,
                "did": passport.did,
                "capabilities": {
                    k: sorted(v.get("constraints", {}).keys())
                    for k, v in passport.capabilities.items()
                },
                "iat": passport.iat,
                "exp": passport.exp,
                "trust_level": passport.trust_level,
                "issued_by": passport.issued_by,
                "passport_version": PASSPORT_VERSION,
                "note": note,
            }
        )
    for hop in chain:
        if not isinstance(hop, CapabilityPassport) or not hop.parent_jti:
            continue
        events.append(
            {
                "event": "passport.delegated",
                "jti": hop.jti,
                "parent_jti": hop.parent_jti,
                "sub": hop.sub,
                "depth": hop.delegation_depth,
                "capabilities": sorted(hop.capabilities.keys()),
                "purpose": hop.purpose,
                "signature": hop.signature,
                "note": note,
            }
        )
    if revoked_jti:
        events.append(
            {
                "event": "passport.revoked",
                "jti": revoked_jti,
                "passport_version": PASSPORT_VERSION,
                "note": note,
            }
        )
    if verdict is not None:
        events.append(
            {
                "event": (
                    "passport.verified" if verdict.allowed else "passport.denied"
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
    "DEFAULT_PASSPORT_TTL_SECONDS",
    "PASSPORT_VERSION",
    "TRUST_LEVELS",
    "CapabilityPassport",
    "PassportError",
    "PassportIssuer",
    "PassportVerdict",
    "RevocationEntry",
    "RevocationList",
    "capabilities_within",
    "check_tool_use",
    "delegate_passport",
    "intersect_capabilities",
    "passport_audit_events",
    "passport_for_identity",
    "verify_passport",
    "verify_passport_chain",
]
