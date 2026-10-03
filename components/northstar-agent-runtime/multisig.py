"""m-of-n multisig approval for high-risk tool calls.

BIP-11 / Gnosis Safe semantics, adapted to the permission gate: a high-risk
call (anything that reaches the host-callback tier while a multisig policy is
configured) needs ``m`` valid signatures from ``n`` enrolled approvers before
the gate allows it. One compromised approver — or the host callback alone —
can no longer release the call.

The signed message pins the *exact* call: ``sha256`` over the canonical
``(call_id, arguments_digest)`` pair, using the same canonical-JSON digest
format as :func:`permissions.digest_arguments` (fifty-fifth batch). A
signature is therefore bound to one call id and one exact argument set; it
cannot authorize a different call, different arguments, or a replay. This is
the same structural isomorphism the cross-domain sweep noted: multisig *is*
per-call approval binding, with the approver set widened from one to m-of-n.

Signatures are Ed25519 (:mod:`ed25519`), verified against per-approver public
keys enrolled out of band. The engine keeps no signature state between calls:
every gated call re-checks the presented signatures, and a grant for one
``(call_id, arguments_digest)`` pair never replays onto another.

Fail-closed rules (all deny, none escalate):
- fewer than ``m`` *distinct* valid approvers → deny (so ``m-1`` blocks);
- a signature that does not verify for this exact call → deny, and the
  approver is named in the verdict (forgery is *detected*, not just blocked);
- duplicate signatures from one approver count once;
- unknown approver ids are rejected;
- a malformed signature (not hex, wrong length) is rejected.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from ed25519 import public_key as _ed25519_public_key
from ed25519 import sign as _ed25519_sign
from ed25519 import verify as _ed25519_verify

#: Domain separator for the signed message, so a multisig signature can
#: never be confused with a signature minted for another purpose.
MULTISIG_DOMAIN = b"northstar-multisig-approval/v1:"


@dataclass(frozen=True)
class MultisigPolicy:
    """Which approvers exist and how many must sign.

    ``approvers`` are opaque approver identities (human names, device ids,
    role labels — whatever the host enrolls). ``threshold`` is ``m`` of the
    ``n = len(approvers)``.
    """

    approvers: tuple[str, ...]
    threshold: int

    def __post_init__(self) -> None:
        approvers = tuple(str(a).strip() for a in self.approvers)
        if not approvers:
            raise ValueError("multisig policy needs at least one approver")
        if len(set(approvers)) != len(approvers):
            raise ValueError("multisig approver ids must be unique")
        if any(not a for a in approvers):
            raise ValueError("multisig approver ids must be non-empty")
        if not isinstance(self.threshold, int) or isinstance(self.threshold, bool):
            raise ValueError("multisig threshold must be an integer")
        if self.threshold < 1:
            raise ValueError("multisig threshold must be >= 1")
        if self.threshold > len(approvers):
            raise ValueError(
                f"multisig threshold {self.threshold} exceeds "
                f"{len(approvers)} enrolled approvers"
            )
        object.__setattr__(self, "approvers", approvers)

    @property
    def n(self) -> int:
        return len(self.approvers)

    @property
    def m(self) -> int:
        return self.threshold


@dataclass(frozen=True)
class MultisigSignature:
    """One approver's signature over the exact call."""

    approver_id: str = ""
    signature: str = ""  # hex-encoded Ed25519 signature

    def as_dict(self) -> dict[str, Any]:
        return {"approver_id": self.approver_id, "signature": self.signature}


def multisig_message(call_id: str, arguments_digest: str) -> bytes:
    """The exact bytes a multisig approver signs.

    Canonical JSON of the ``(call_id, arguments_digest)`` pair (sorted keys,
    compact separators — the same canonicalisation as
    :func:`permissions.digest_arguments`), sha256-hashed, then prefixed with
    the domain separator. Binding both the call id and the arguments digest
    is what makes a signature non-replayable across calls.
    """
    canonical = json.dumps(
        {"arguments_digest": arguments_digest, "call_id": call_id},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return MULTISIG_DOMAIN + hashlib.sha256(canonical).digest()


def derive_test_keypair(seed: str) -> tuple[bytes, bytes]:
    """Deterministic Ed25519 keypair for tests and the bench corpus.

    **Test only.** The secret is ``sha256`` of a fixed test-domain string plus
    the seed — anyone who reads this source can reconstruct it. Production
    deployments must enroll approver public keys generated out of band
    (:func:`ed25519`-backed, e.g. :func:`audit_chain.generate_keypair`).
    """
    secret = hashlib.sha256(b"northstar-multisig-test-key:" + seed.encode("utf-8")).digest()
    return secret, _ed25519_public_key(secret)


def sign_call(secret_key: bytes, call_id: str, arguments_digest: str) -> str:
    """Sign the exact call; returns the hex-encoded Ed25519 signature."""
    return _ed25519_sign(secret_key, multisig_message(call_id, arguments_digest)).hex()


@dataclass(frozen=True)
class MultisigVerdict:
    """The gate's multisig verdict for one call."""

    allowed: bool
    threshold: int
    enrolled: int
    valid_approvers: tuple[str, ...] = ()
    invalid: tuple[tuple[str, str], ...] = ()
    reason: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "threshold": self.threshold,
            "enrolled": self.enrolled,
            "valid_approvers": list(self.valid_approvers),
            "invalid": [
                {"approver_id": approver_id, "reason": reason}
                for approver_id, reason in self.invalid
            ],
            "reason": self.reason,
        }


class MultisigGate:
    """Verifies m-of-n signatures for one exact call. Keeps no state."""

    def __init__(
        self,
        policy: MultisigPolicy,
        approver_pubkeys: Mapping[str, bytes],
    ) -> None:
        self.policy = policy
        missing = [a for a in policy.approvers if a not in approver_pubkeys]
        if missing:
            raise ValueError(
                f"multisig gate is missing public keys for approver(s): "
                f"{', '.join(missing)}"
            )
        self._pubkeys: dict[str, bytes] = {
            approver: bytes(approver_pubkeys[approver]) for approver in policy.approvers
        }

    def check(
        self,
        call_id: str,
        arguments_digest: str,
        signatures: Sequence[MultisigSignature],
    ) -> MultisigVerdict:
        """Verify the presented signatures against the exact call."""
        message = multisig_message(call_id, arguments_digest)
        seen: set[str] = set()
        valid: list[str] = []
        invalid: list[tuple[str, str]] = []
        for presented in signatures or ():
            approver_id = str(presented.approver_id or "")
            if approver_id in seen:
                invalid.append((approver_id, "duplicate signature from one approver counts once"))
                continue
            seen.add(approver_id)
            pubkey = self._pubkeys.get(approver_id)
            if pubkey is None:
                invalid.append((approver_id, "unknown approver id"))
                continue
            try:
                sig_bytes = bytes.fromhex(str(presented.signature or ""))
            except ValueError:
                invalid.append((approver_id, "malformed signature (not hex)"))
                continue
            if len(sig_bytes) != 64:
                invalid.append((approver_id, "malformed signature (not 64 bytes)"))
                continue
            try:
                ok = _ed25519_verify(pubkey, message, sig_bytes)
            except Exception:  # noqa: BLE001 - a bad point must deny, not crash
                ok = False
            if ok:
                valid.append(approver_id)
            else:
                invalid.append(
                    (approver_id, "signature does not verify for this call")
                )
        valid_tuple = tuple(valid)
        allowed = len(valid_tuple) >= self.policy.threshold
        if allowed:
            reason = (
                f"multisig {self.policy.threshold}-of-{self.policy.n}: "
                f"{len(valid_tuple)} valid signature(s) from "
                f"{', '.join(valid_tuple)}"
            )
        else:
            reason = (
                f"multisig {self.policy.threshold}-of-{self.policy.n} not met: "
                f"{len(valid_tuple)} valid signature(s)"
                + (f" ({', '.join(v[0] for v in invalid)} rejected)" if invalid else "")
            )
        return MultisigVerdict(
            allowed=allowed,
            threshold=self.policy.threshold,
            enrolled=self.policy.n,
            valid_approvers=valid_tuple,
            invalid=tuple(invalid),
            reason=reason,
        )


__all__ = [
    "MULTISIG_DOMAIN",
    "MultisigGate",
    "MultisigPolicy",
    "MultisigSignature",
    "MultisigVerdict",
    "derive_test_keypair",
    "multisig_message",
    "sign_call",
]
