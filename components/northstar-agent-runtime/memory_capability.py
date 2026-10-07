"""Memory write admission with capability tokens.

The alternative method to :mod:`memory_admission`'s consent regime. Where
consent asks *the user* to grant a memory write, capability tokens ask *an
issuer* -- a supervisor, a policy service, or the host -- to hand the writer
a signed token naming exactly which memory categories the holder may write.
No consent object, no consent dialogue: the writer presents a token, the
gate verifies the issuer's signature, the expiry, and the category set.

1. **Issuer-signed capabilities** -- ``issue_token`` mints a
   ``CapabilityToken`` covering a set of memory categories. The token body
   (schema pin, token id, sorted categories, expiry sequence) is signed
   with the issuer's Ed25519 key. A writer cannot widen its own rights:
   editing any field breaks the signature.
2. **Expiry on the caller's clock** -- ``expires_seq`` is an integer on
   the caller's logical clock (no wall-clock reads anywhere). A token
   with ``current_seq >= expires_seq`` is refused. Expiry is strict and
   sticky.
3. **Category-scoped** -- ``admit_write`` admits a write only when the
   category is inside the token's category set *and* the category is
   admissible at all. ``credential`` writes are refused even with a
   token in hand; ``health`` / ``political`` / ``sexual`` inference
   categories are refused even with a token in hand. A token cannot
   grant what the gate never admits -- capabilities narrow, never widen,
   the gate's fixed policy.
4. **No delegation chain here** -- tokens are single-hop by design. An
   issuer hands a token to a writer; the writer cannot re-issue, mint,
   or attenuate. Multi-hop authority is
   :mod:`delegation_credentials`' job, not this module's.

Admission runs at write time, fail-closed, in a fixed rule order; the
first failing rule names the denial reason. Every decision is recorded
in the decision log so a later audit can show *why* a write was refused.

Hard doctrine: memory is the future prompt. A capability that cannot be
verified (bad signature, unknown issuer key format, missing expiry) is
a capability denied. Silence -- a ``None`` token -- is not a capability.

When is this better than consent? Consent fits *user-owned* memory:
personal assistants writing preferences, where the user's grant is the
authority. Capabilities fit *delegated* memory: supervisors scoping a
worker agent's write rights per task, policy services issuing
time-boxed category grants to untrusted sub-agents, or host-owned
shared memory where no single user exists to consent. A capability
travels with the request; consent lives with the user. Use tokens when
the authority is an issuer, not a person.

Honest scope: corpus + gates, not a defense. The gate runs on
host-reported categories and token objects; a deployment that
miscategorizes a write (labels a health inference as a "fact") has
already lost. Revocation is expiry only -- there is no revocation
list; a compromised token stays valid until its sequence expires, so
issuers should keep ``expires_seq`` short.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import ed25519

#: Version of the capability-token construction described here.
#: Bump when the category vocabulary, the rule order, or the token
#: schema change.
MEMORY_CAPABILITY_VERSION = "memory-capability.v1"

#: Schema pin covered by the issuer's signature. Binds a token to this
#: exact contract; a token minted for another schema fails verification.
SCHEMA_PIN = "northstar.memory-capability.v1"

#: Categories the gate may admit under a valid, unexpired, in-scope token.
ADMITTABLE_CATEGORIES: tuple[str, ...] = (
    "preference",
    "fact",
    "conversation",
    "episodic",
)

#: The one category that is never admitted, token or not.
CATEGORY_CREDENTIAL = "credential"

#: Off-limits inference categories: never admitted, token or not.
PROHIBITED_INFERENCES: tuple[str, ...] = ("health", "political", "sexual")

#: Every category the gate knows how to name.
KNOWN_CATEGORIES: tuple[str, ...] = (
    ADMITTABLE_CATEGORIES + (CATEGORY_CREDENTIAL,) + PROHIBITED_INFERENCES
)

#: Fixed reason vocabulary for denials.
REASON_MALFORMED = "malformed"
REASON_MISSING_TOKEN = "missing-token"
REASON_INVALID_SIGNATURE = "invalid-signature"
REASON_EXPIRED = "expired"
REASON_CATEGORY_NOT_IN_TOKEN = "category-not-in-token"
REASON_PROHIBITED_INFERENCE = "prohibited-inference"
REASON_CREDENTIAL_NEVER = "credential-never-admitted"
REASON_UNKNOWN_CATEGORY = "unknown-category"
REASON_ADMITTED = "admitted"


def _canonical_json(obj: Any) -> bytes:
    """Canonical JSON bytes: sorted keys, compact separators, UTF-8."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _is_seq(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


@dataclass(frozen=True)
class CapabilityToken:
    """An issuer-signed memory-write capability.

    ``categories`` names the memory categories the holder may write.
    ``expires_seq`` is the strict expiry on the caller's logical clock:
    the token is valid while ``current_seq < expires_seq``.
    ``token_id`` is a unique mint id (``ctok-`` + hex). ``signature``
    is the issuer's Ed25519 signature over the canonical JSON of the
    body (schema pin, token id, sorted categories, expiry) -- it is
    excluded from its own signed bytes.
    """

    token_id: str
    categories: frozenset
    expires_seq: int
    signature: bytes = field(repr=False)

    def body(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "token_id": self.token_id,
            "categories": sorted(self.categories),
            "expires_seq": self.expires_seq,
        }

    def as_dict(self) -> Dict[str, Any]:
        d = self.body()
        d["signature"] = self.signature.hex()
        d["version"] = MEMORY_CAPABILITY_VERSION
        return d


def _validate_categories(categories: Any) -> frozenset:
    if not isinstance(categories, (set, frozenset, list, tuple)) or not categories:
        raise ValueError("categories must be a non-empty set/list/tuple")
    cats = frozenset(categories)
    for c in cats:
        if not isinstance(c, str) or not c:
            raise ValueError("each category must be a non-empty string")
        if c not in KNOWN_CATEGORIES:
            raise ValueError(f"unknown category: {c!r}")
        if c == CATEGORY_CREDENTIAL:
            raise ValueError("capabilities can never cover 'credential'")
        if c in PROHIBITED_INFERENCES:
            raise ValueError(f"capabilities can never cover prohibited inference: {c!r}")
    return cats


def _mint_token_id(token_id: Optional[str], secret: bytes) -> str:
    if token_id is not None:
        if not isinstance(token_id, str) or not token_id:
            raise ValueError("token_id must be a non-empty string")
        return token_id
    digest = hashlib.sha256(secret + b"memory-capability-token").hexdigest()[:16]
    return f"ctok-{digest}"


def issue_token(
    categories: Any,
    expires_seq: int,
    issuer_key: bytes,
    token_id: Optional[str] = None,
) -> CapabilityToken:
    """Mint a signed capability token.

    ``issuer_key`` is the issuer's 32-byte Ed25519 private seed.
    ``expires_seq`` is the strict expiry on the caller's logical clock.
    Raises :class:`ValueError` on malformed inputs -- an issuer that
    cannot describe a valid grant mints nothing.
    """
    if not isinstance(issuer_key, (bytes, bytearray)) or len(issuer_key) != 32:
        raise ValueError("issuer_key must be a 32-byte Ed25519 seed")
    if not _is_seq(expires_seq) or expires_seq == 0:
        raise ValueError("expires_seq must be a positive integer sequence number")
    cats = _validate_categories(categories)
    tid = _mint_token_id(token_id, bytes(issuer_key))
    token = CapabilityToken(
        token_id=tid,
        categories=cats,
        expires_seq=expires_seq,
        signature=b"",
    )
    sig = ed25519.sign(bytes(issuer_key), _canonical_json(token.body()))
    return CapabilityToken(
        token_id=tid, categories=cats, expires_seq=expires_seq, signature=bytes(sig)
    )


def verify_token(token: Any, issuer_pubkey: bytes) -> bool:
    """Verify a token's issuer signature and structural validity.

    Fail-closed: returns ``False`` -- never raises -- on a malformed
    token, a bad key, or a signature mismatch. Expiry is *not* checked
    here; callers check expiry against their own ``current_seq`` via
    :meth:`CapabilityAdmission.expired` or the admit rule order.
    """
    try:
        if not isinstance(token, CapabilityToken):
            return False
        if not isinstance(issuer_pubkey, (bytes, bytearray)) or len(issuer_pubkey) != 32:
            return False
        if not isinstance(token.token_id, str) or not token.token_id:
            return False
        if not isinstance(token.signature, (bytes, bytearray)) or len(token.signature) != 64:
            return False
        if not isinstance(token.categories, frozenset) or not token.categories:
            return False
        if not _is_seq(token.expires_seq) or token.expires_seq == 0:
            return False
        if not hmac.compare_digest(token.body()["schema"], SCHEMA_PIN):
            return False
        return bool(
            ed25519.verify(
                bytes(issuer_pubkey), _canonical_json(token.body()), bytes(token.signature)
            )
        )
    except Exception:
        return False


@dataclass(frozen=True)
class AdmissionDecision:
    """One recorded admit/deny verdict."""

    category: str
    admitted: bool
    reason: str
    current_seq: Optional[int]
    token_id: Optional[str] = None


class CapabilityAdmission:
    """Write-path admission gate driven by capability tokens.

    Constructed with the issuer's 32-byte Ed25519 public key. The gate
    admits a write only when the presented token verifies, is not
    expired against ``current_seq``, and covers the write's category --
    and the category is admissible at all (credential and prohibited
    inferences are refused even with a token in hand).
    """

    def __init__(self, issuer_pubkey: bytes):
        if not isinstance(issuer_pubkey, (bytes, bytearray)) or len(issuer_pubkey) != 32:
            raise ValueError("issuer_pubkey must be a 32-byte Ed25519 public key")
        self._issuer_pubkey = bytes(issuer_pubkey)
        self._decisions: List[AdmissionDecision] = []

    @staticmethod
    def expired(token: CapabilityToken, current_seq: int) -> bool:
        """True when the token is expired at ``current_seq`` (fail closed)."""
        if not isinstance(token, CapabilityToken):
            return True
        if not _is_seq(current_seq):
            return True
        return current_seq >= token.expires_seq

    def admit_write(
        self,
        category: Any,
        content: Any,
        token: Any,
        current_seq: Any,
    ) -> bool:
        """Admit (True) or deny (False) a memory write.

        Fixed rule order, first failure wins with the fixed reason
        vocabulary: malformed-category -> unknown-category ->
        credential-never-admitted -> prohibited-inference ->
        missing-token -> invalid-signature -> malformed-content ->
        expired -> category-not-in-token -> admitted.
        """
        if not isinstance(category, str) or not category:
            self._record("<malformed>", False, REASON_MALFORMED, None, None)
            return False
        if category not in KNOWN_CATEGORIES:
            self._record(category, False, REASON_UNKNOWN_CATEGORY, None, None)
            return False
        if category == CATEGORY_CREDENTIAL:
            self._record(category, False, REASON_CREDENTIAL_NEVER, None, None)
            return False
        if category in PROHIBITED_INFERENCES:
            self._record(category, False, REASON_PROHIBITED_INFERENCE, None, None)
            return False
        if token is None:
            self._record(category, False, REASON_MISSING_TOKEN, None, None)
            return False
        if not verify_token(token, self._issuer_pubkey):
            self._record(category, False, REASON_INVALID_SIGNATURE, None, None)
            return False
        if not isinstance(content, str) or not content:
            self._record(category, False, REASON_MALFORMED, None, token.token_id)
            return False
        if not _is_seq(current_seq):
            self._record(category, False, REASON_EXPIRED, None, token.token_id)
            return False
        if self.expired(token, current_seq):
            self._record(category, False, REASON_EXPIRED, current_seq, token.token_id)
            return False
        if category not in token.categories:
            self._record(
                category, False, REASON_CATEGORY_NOT_IN_TOKEN, current_seq, token.token_id
            )
            return False
        self._record(category, True, REASON_ADMITTED, current_seq, token.token_id)
        return True

    def _record(
        self,
        category: str,
        admitted: bool,
        reason: str,
        current_seq: Optional[int],
        token_id: Optional[str],
    ) -> None:
        self._decisions.append(
            AdmissionDecision(
                category=category if isinstance(category, str) else "<malformed>",
                admitted=admitted,
                reason=reason,
                current_seq=current_seq if _is_seq(current_seq) else None,
                token_id=token_id if isinstance(token_id, str) else None,
            )
        )

    def decisions(self) -> List[AdmissionDecision]:
        """All recorded verdicts, in order (read-only copy)."""
        return list(self._decisions)

    def denied(self) -> List[AdmissionDecision]:
        """Only the denials, in order."""
        return [d for d in self._decisions if not d.admitted]

    @staticmethod
    def version() -> str:
        return MEMORY_CAPABILITY_VERSION


def main() -> None:
    import os

    seed = hashlib.sha256(b"memory-capability self-check").digest()
    pub = ed25519.public_key(seed)
    token = issue_token({"preference", "fact"}, expires_seq=100, issuer_key=seed)
    gate = CapabilityAdmission(pub)
    assert gate.admit_write("preference", "likes tea", token, 10)
    assert not gate.admit_write("preference", "likes tea", token, 100)
    assert not gate.admit_write("credential", "password", token, 10)
    assert not gate.admit_write("health", "diagnosis", token, 10)
    assert not gate.admit_write("fact", "x", None, 10)
    print("memory-capability OK: token mint/verify/expire/deny branches")


if __name__ == "__main__":
    main()
