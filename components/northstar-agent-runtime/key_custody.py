"""Agent-held key custody: policy-sealed signing with a pre-sign rollback gate.

Absorption source: Moltbook asinhhc, "The key-custody layer we kept conceding
was missing is now live -- with its limits stated"
(https://www.moltbook.com/post/39049a95-73b8-460b-b1a3-aa2261b3d146, rank 6).
The source is a **first-party demo with unverified numbers** (its 14/14 demo
result is a design reference only, never a verified result here).

Two verbatim source lines frame this module:

* asinhhc: "This is a custody step, not a custody proof."
* agenthaven: "The hole in a sealed policy hash is rollback. An old vault with
  a looser policy still has a valid seal, so signing accepts it."

What this module IS:

* a **custody layer**: the agent holds its own ed25519 signing identity; the
  private key never leaves the custody object, and the outside world sees only
  the public key and the key id;
* a **policy seal**: the policy hash is sealed into a vault seal that carries a
  monotonically increasing vault version;
* a **pre-sign gate** (the Northstar extension, and the fix for the source's
  rollback hole): before every signature the gate re-reads the *anchored*
  policy hash and vault version from an append-only ledger and refuses on
  mismatch -- tamper, rollback, expiry, or cap exhaustion.

What this module IS NOT (honest scope, matching the source author's own
stated limits):

* the seal protects the policy **at rest** only;
* the caps constrain an **honest agent**, not a host takeover: a host that
  replaces the custody object can still forge envelopes;
* the anchor cadence here is **manual** -- nothing publishes the vault version
  off-host automatically;
* sealing proves **integrity and ordering**, never truth, and never signer
  independence beyond what the public key attests.

The signature primitive is NOT re-implemented here: this module signs with
the repository's vendored ``ed25519`` module -- the same primitive
``message_signing.py`` uses -- so there is exactly one ed25519 in the repo.

House style: frozen dataclasses, fail-closed, structured refusals (never a
bare exception that swallows the reason), ``sha256:`` digest pins, canonical
JSON for every hash, and a ``main()`` self-check.
"""

from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
import os
import sys
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Tuple

#: Module version pin.
KEY_CUSTODY_VERSION = "key-custody.v1"

#: Schema pin for the policy hash, the vault seal and the envelope.
SCHEMA_PIN = "northstar.key-custody.v1"

#: Tag for the canonical policy hash (domain separation).
_POLICY_HASH_TAG = b"northstar-key-custody:v1:policy"

#: Tag for the vault seal digest (domain separation).
_SEAL_TAG = b"northstar-key-custody:v1:seal"

#: Tag for the anchored-state digest (domain separation).
_ANCHOR_TAG = b"northstar-key-custody:v1:anchor"


def _load_sibling(name: str) -> Any:
    """Load a sibling module by path (component convention).

    Same pattern as ``forward_seal_ledger._load_grant_pin_ledger``: the
    component's modules are not installed as a package, so the sibling is
    loaded by path when it is not already importable.
    """
    module = sys.modules.get(name)
    if module is not None:
        return module
    try:  # pragma: no cover - depends on the caller's sys.path
        return __import__(name)
    except ImportError:
        pass
    path = Path(__file__).resolve().parent / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, str(path))
    if spec is None:
        raise ImportError(f"{name} not loadable")
    if spec.loader is None:
        raise ImportError(f"{name} not loadable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _ed25519() -> Any:
    """The repository's vendored ed25519 module (the one primitive).

    ``message_signing.py`` signs with exactly this module; this custody layer
    reuses it instead of introducing a second signing stack.
    """
    return _load_sibling("ed25519")


def _canonical(value: Any) -> bytes:
    """Canonical JSON bytes: sorted keys, compact separators, UTF-8."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _sha256_pin(data: bytes) -> str:
    """``sha256:`` pin of ``data``."""
    return "sha256:" + hashlib.sha256(data).hexdigest()


class RefusalReason(str, Enum):
    """Why a signature was refused (structured, never silent)."""

    #: The sealed policy hash does not match the anchored one (policy changed).
    POLICY_TAMPER = "POLICY_TAMPER"
    #: The vault version is older than the anchored version (rollback).
    ROLLBACK = "ROLLBACK"
    #: The policy is past its expiry.
    EXPIRED = "EXPIRED"
    #: The per-epoch signature cap is exhausted.
    CAP_EXCEEDED = "CAP_EXCEEDED"
    #: No policy is sealed (nothing to sign under).
    NOT_SEALED = "NOT_SEALED"
    #: The vault state was never anchored into the ledger.
    NOT_ANCHORED = "NOT_ANCHORED"
    #: The requested operation kind is not permitted by the policy.
    OP_NOT_ALLOWED = "OP_NOT_ALLOWED"
    #: The payload is not a mapping.
    BAD_PAYLOAD = "BAD_PAYLOAD"


class CustodyError(Exception):
    """Base class for custody errors."""


class CustodyRefusal(CustodyError):
    """A structured refusal: carries the reason, never swallowed.

    ``reason`` is a :class:`RefusalReason`; ``detail`` holds the compared
    values (the sealed hash, the anchored hash, the versions) so the refusal
    is investigable without re-running the gate.
    """

    def __init__(self, reason: RefusalReason, detail: Optional[Dict[str, Any]] = None):
        self.reason = reason
        self.detail: Dict[str, Any] = dict(detail) if detail else {}
        super().__init__(f"{reason.value}: {self.detail}")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "reason": self.reason.value,
            "detail": dict(self.detail),
            "schema": SCHEMA_PIN,
        }


@dataclass(frozen=True)
class CustodyPolicy:
    """The policy the signing identity is bound to.

    ``allowed_ops`` is the set of operation kinds the identity may sign;
    ``max_signatures_per_epoch`` caps the number of signatures inside one
    epoch; ``expires_at`` is the expiry (unix seconds); ``epoch_seconds`` is
    the width of an epoch.  The policy hash is canonical: the same policy
    always hashes to the same value, and changing any field changes it.
    """

    allowed_ops: Tuple[str, ...] = ()
    max_signatures_per_epoch: int = 1
    expires_at: float = 0.0
    epoch_seconds: int = 3600
    policy_id: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "allowed_ops", tuple(self.allowed_ops))
        if isinstance(self.max_signatures_per_epoch, bool):
            raise CustodyError("max_signatures_per_epoch must be an int")
        if not isinstance(self.max_signatures_per_epoch, int):
            raise CustodyError("max_signatures_per_epoch must be an int")
        if self.max_signatures_per_epoch < 0:
            raise CustodyError("max_signatures_per_epoch must be non-negative")
        if isinstance(self.expires_at, bool):
            raise CustodyError("expires_at must be a number")
        if not isinstance(self.expires_at, (int, float)):
            raise CustodyError("expires_at must be a number")
        object.__setattr__(self, "expires_at", float(self.expires_at))
        if isinstance(self.epoch_seconds, bool):
            raise CustodyError("epoch_seconds must be an int")
        if not isinstance(self.epoch_seconds, int):
            raise CustodyError("epoch_seconds must be an int")
        if self.epoch_seconds <= 0:
            raise CustodyError("epoch_seconds must be positive")

    def canonical_form(self) -> Dict[str, Any]:
        """The canonical body the policy hash is taken over."""
        return {
            "schema": SCHEMA_PIN,
            "allowed_ops": sorted(set(self.allowed_ops)),
            "max_signatures_per_epoch": self.max_signatures_per_epoch,
            "expires_at": self.expires_at,
            "epoch_seconds": self.epoch_seconds,
            "policy_id": self.policy_id,
        }

    @property
    def policy_hash(self) -> str:
        """Canonical ``sha256:`` hash of this policy."""
        return _sha256_pin(_POLICY_HASH_TAG + _canonical(self.canonical_form()))

    def epoch_of(self, now: float) -> int:
        """The epoch index ``now`` falls into."""
        return int(now // self.epoch_seconds)

    def is_expired(self, now: float) -> bool:
        """True once ``now`` is at or past the expiry."""
        return float(now) >= self.expires_at

    def allows(self, op: str) -> bool:
        """True when ``op`` is one of the permitted operation kinds."""
        return op in set(self.allowed_ops)


@dataclass(frozen=True)
class VaultSeal:
    """The seal that binds a policy hash to a vault version.

    The seal is *self-consistent*: ``verify_self()`` re-derives its digest.
    That is exactly the property the source's rollback hole abuses -- an old
    vault with a looser policy still has a valid seal.  The fix is the
    pre-sign gate, which compares this seal against the **anchored** state,
    not against itself.
    """

    vault_version: int
    policy_hash: str
    sealed_at: float
    key_id: str
    seal: str

    @classmethod
    def create(
        cls, *, vault_version: int, policy_hash: str, sealed_at: float, key_id: str
    ) -> "VaultSeal":
        """Build a seal over (version, policy hash, time, key id)."""
        body = {
            "schema": SCHEMA_PIN,
            "vault_version": int(vault_version),
            "policy_hash": policy_hash,
            "sealed_at": float(sealed_at),
            "key_id": key_id,
        }
        digest = _sha256_pin(_SEAL_TAG + _canonical(body))
        return cls(
            vault_version=int(vault_version),
            policy_hash=policy_hash,
            sealed_at=float(sealed_at),
            key_id=key_id,
            seal=digest,
        )

    def canonical_form(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "vault_version": self.vault_version,
            "policy_hash": self.policy_hash,
            "sealed_at": self.sealed_at,
            "key_id": self.key_id,
        }

    def verify_self(self) -> bool:
        """True when the seal digest re-derives (self-consistency only)."""
        expected = _sha256_pin(_SEAL_TAG + _canonical(self.canonical_form()))
        return expected == self.seal

    def to_dict(self) -> Dict[str, Any]:
        return dict(self.canonical_form(), seal=self.seal)


# --- anchored state ------------------------------------------------------

#: The intent string the anchor record carries in the ledger.
ANCHOR_INTENT = "key-custody-anchor"


def _anchor_digest(policy_hash: str, vault_version: int) -> str:
    """``sha256:`` digest binding a policy hash to a vault version."""
    return _sha256_pin(
        _ANCHOR_TAG + _canonical({"policy_hash": policy_hash, "vault_version": int(vault_version)})
    )


@dataclass(frozen=True)
class AnchoredState:
    """The vault state as published in the append-only ledger.

    This is the state the pre-sign gate reads back.  It lives *outside* the
    vault, which is what closes the source's rollback hole: a vault can be
    rolled back to an old (validly sealed) version, but the anchored version
    only ever moves forward.
    """

    vault_version: int
    policy_hash: str
    seq: int
    record_hash: str
    anchor_digest: str
    anchored_at: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "vault_version": self.vault_version,
            "policy_hash": self.policy_hash,
            "seq": self.seq,
            "record_hash": self.record_hash,
            "anchor_digest": self.anchor_digest,
            "anchored_at": self.anchored_at,
        }


def _parse_anchor_authorization(value: str) -> Optional[Tuple[int, str]]:
    """Parse ``vault_version=<v>;policy_hash=<h>`` into ``(version, hash)``."""
    if not isinstance(value, str) or ";" not in value:
        return None
    version: Optional[int] = None
    policy_hash = ""
    for part in value.split(";"):
        if part.startswith("vault_version="):
            try:
                version = int(part.split("=", 1)[1])
            except ValueError:
                return None
        elif part.startswith("policy_hash="):
            policy_hash = part.split("=", 1)[1]
    if version is None or not policy_hash:
        return None
    return version, policy_hash


def read_anchored(ledger: Any) -> Optional[AnchoredState]:
    """Read the newest anchored vault state back from the ledger.

    Returns ``None`` when the ledger holds no anchor record.  Only the
    ledger's public API is used (no code in the ledger is modified).
    """
    if ledger is None:
        return None
    total = len(ledger)
    for seq in range(total, 0, -1):
        try:
            record = ledger.record(seq)
        except Exception:  # pragma: no cover - defensive
            return None
        event = dict(record.event)
        if event.get("intent") != ANCHOR_INTENT:
            continue
        parsed = _parse_anchor_authorization(event.get("authorization", ""))
        if parsed is None:
            return None
        version, policy_hash = parsed
        return AnchoredState(
            vault_version=version,
            policy_hash=policy_hash,
            seq=seq,
            record_hash=record.record_hash,
            anchor_digest=_anchor_digest(policy_hash, version),
            anchored_at=0.0,
        )
    return None


def anchor_vault(ledger: Any, seal: VaultSeal, *, anchored_at: float = 0.0) -> AnchoredState:
    """Publish a sealed vault state into the append-only ledger.

    The version must strictly increase: the anchored version is the
    monotonic clock the pre-sign gate trusts, so a re-anchor with an older
    or equal version is refused.
    """
    if ledger is None or not callable(getattr(ledger, "append", None)):
        raise CustodyError("ledger must have append()")
    current = read_anchored(ledger)
    if current is not None and seal.vault_version <= current.vault_version:
        raise CustodyError(
            "vault version must increase: "
            f"{seal.vault_version} <= anchored {current.vault_version}"
        )
    authorization = f"vault_version={seal.vault_version};policy_hash={seal.policy_hash}"
    record = ledger.append(
        intent=ANCHOR_INTENT,
        action="anchor-vault",
        subject=seal.key_id,
        authorization=authorization,
        inputs_digest=_sha256_pin(seal.policy_hash.encode("utf-8")),
        logic_digest=_sha256_pin(_canonical({"schema": SCHEMA_PIN, "fields": ["vault_version", "policy_hash"]})),
        execution_digest=_sha256_pin(_canonical(seal.to_dict())),
        outcome="anchored",
    )
    return AnchoredState(
        vault_version=seal.vault_version,
        policy_hash=seal.policy_hash,
        seq=record.seq,
        record_hash=record.record_hash,
        anchor_digest=_anchor_digest(seal.policy_hash, seal.vault_version),
        anchored_at=float(anchored_at),
    )


def seal_is_valid(seal: VaultSeal) -> bool:
    """The *old* check: is the seal self-consistent?

    This is the check that lets a rollback through -- an old vault with a
    looser policy still has a valid seal.  It is kept as a named function so
    the difference between "seal valid" and "gate passes" is executable, not
    just documented.
    """
    return bool(seal.verify_self())


# --- the envelope --------------------------------------------------------


@dataclass(frozen=True)
class SignatureEnvelope:
    """The signed receipt envelope.

    A stranger who holds only the signer's public key and the anchored
    policy hash can verify this envelope and see *who* signed -- not merely
    that the bytes are intact.  That is the signer-independence property
    the source's audit-head conclusion 2 asked the public board to define.
    """

    schema: str
    key_id: str
    public_key: str
    signature: str
    policy_hash: str
    vault_version: int
    anchored_policy_hash: str
    anchored_vault_version: int
    anchor_seq: int
    payload_hash: str
    payload: Dict[str, Any]
    op: str
    seq: int
    timestamp: float

    def canonical_form(self) -> Dict[str, Any]:
        """The exact body the signature covers."""
        return {
            "schema": self.schema,
            "key_id": self.key_id,
            "public_key": self.public_key,
            "policy_hash": self.policy_hash,
            "vault_version": self.vault_version,
            "anchored_policy_hash": self.anchored_policy_hash,
            "anchored_vault_version": self.anchored_vault_version,
            "anchor_seq": self.anchor_seq,
            "payload_hash": self.payload_hash,
            "payload": self.payload,
            "op": self.op,
            "seq": self.seq,
            "timestamp": self.timestamp,
        }

    def signing_body(self) -> bytes:
        """Canonical bytes the signature is taken over."""
        return _canonical(self.canonical_form())

    def to_dict(self) -> Dict[str, Any]:
        return dict(self.canonical_form(), signature=self.signature)

    @classmethod
    def from_dict(cls, value: Dict[str, Any]) -> "SignatureEnvelope":
        """Rebuild an envelope from its dict form."""
        return cls(
            schema=str(value["schema"]),
            key_id=str(value["key_id"]),
            public_key=str(value["public_key"]),
            signature=str(value["signature"]),
            policy_hash=str(value["policy_hash"]),
            vault_version=int(value["vault_version"]),
            anchored_policy_hash=str(value["anchored_policy_hash"]),
            anchored_vault_version=int(value["anchored_vault_version"]),
            anchor_seq=int(value["anchor_seq"]),
            payload_hash=str(value["payload_hash"]),
            payload=dict(value["payload"]),
            op=str(value["op"]),
            seq=int(value["seq"]),
            timestamp=float(value["timestamp"]),
        )


def verify_envelope(
    envelope: SignatureEnvelope,
    public_key: bytes,
    *,
    anchored_policy_hash: Optional[str] = None,
) -> bool:
    """Verify an envelope with only the public key (and optionally the
    anchored policy hash).

    Checks: the signature over the canonical body, and -- when the anchored
    policy hash is supplied -- that the envelope claims exactly that policy
    hash.  Returns ``False`` on any defect; never raises.
    """
    try:
        ed = _ed25519()
        if not isinstance(public_key, (bytes, bytearray)) or len(public_key) != 32:
            return False
        signature = bytes.fromhex(envelope.signature)
        if len(signature) != 64:
            return False
        if not bool(ed.verify(bytes(public_key), envelope.signing_body(), signature)):
            return False
        if anchored_policy_hash is not None:
            if envelope.policy_hash != anchored_policy_hash:
                return False
            if envelope.anchored_policy_hash != anchored_policy_hash:
                return False
        expected_payload_hash = _sha256_pin(_canonical(envelope.payload))
        if envelope.payload_hash != expected_payload_hash:
            return False
        return True
    except (ValueError, TypeError, KeyError):
        return False


# --- the custody object --------------------------------------------------


class KeyCustody:
    """The agent-held signing identity, bound to a sealed policy.

    The private key is generated inside the object and never leaves it: the
    public API exposes the public key, the key id, the seal and the envelope
    -- never the seed.

    The signing path is always the same: :meth:`sign` runs the **pre-sign
    gate** first (:meth:`pre_sign_gate`); when the gate refuses, no
    signature is produced and the refusal is structured
    (:class:`CustodyRefusal`).
    """

    def __init__(
        self,
        *,
        agent_id: str,
        ledger: Any = None,
        seed: Optional[bytes] = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not isinstance(agent_id, str) or not agent_id:
            raise CustodyError("agent_id must be a non-empty string")
        self._agent_id = agent_id
        self._ledger = ledger
        self._clock = clock
        ed = _ed25519()
        if seed is None:
            seed = os.urandom(32)
        if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
            raise CustodyError("seed must be a 32-byte Ed25519 seed")
        self._seed = bytes(seed)
        self._public_key = ed.public_key(self._seed)
        self._key_id = "ed25519:" + hashlib.sha256(
            _canonical({"agent_id": agent_id, "public_key": self._public_key.hex()})
        ).hexdigest()[:32]
        self._seal: Optional[VaultSeal] = None
        self._policy: Optional[CustodyPolicy] = None
        self._epoch_counts: Dict[int, int] = {}
        self._seq = 0

    # -- introspection ---------------------------------------------------

    @property
    def agent_id(self) -> str:
        return self._agent_id

    @property
    def key_id(self) -> str:
        """The public identifier of the held signing key."""
        return self._key_id

    @property
    def public_key(self) -> bytes:
        """The public key (the only thing that leaves the custody object)."""
        return self._public_key

    @property
    def seal(self) -> Optional[VaultSeal]:
        """The current seal, or ``None`` when nothing is sealed."""
        return self._seal

    @property
    def policy(self) -> Optional[CustodyPolicy]:
        """The sealed policy, or ``None``."""
        return self._policy

    @property
    def ledger(self) -> Any:
        return self._ledger

    def signature_count(self, epoch: int) -> int:
        """How many signatures this custody object produced in ``epoch``."""
        return self._epoch_counts.get(epoch, 0)

    # -- sealing and anchoring ------------------------------------------

    def seal_policy(self, policy: CustodyPolicy, *, vault_version: int) -> VaultSeal:
        """Seal a policy into the vault at a given version.

        The version must strictly increase over the current seal: the vault
        version is the monotonic clock the gate trusts.
        """
        if not isinstance(policy, CustodyPolicy):
            raise CustodyError("policy must be a CustodyPolicy")
        if isinstance(vault_version, bool) or not isinstance(vault_version, int):
            raise CustodyError("vault_version must be an int")
        if vault_version < 1:
            raise CustodyError("vault_version must be >= 1")
        if self._seal is not None and vault_version <= self._seal.vault_version:
            raise CustodyError(
                "vault_version must increase: "
                f"{vault_version} <= sealed {self._seal.vault_version}"
            )
        seal = VaultSeal.create(
            vault_version=vault_version,
            policy_hash=policy.policy_hash,
            sealed_at=self._clock(),
            key_id=self._key_id,
        )
        self._seal = seal
        self._policy = policy
        return seal

    def anchor(self) -> AnchoredState:
        """Publish the current seal into the ledger (the off-vault copy)."""
        if self._seal is None:
            raise CustodyRefusal(RefusalReason.NOT_SEALED)
        return anchor_vault(self._ledger, self._seal, anchored_at=self._clock())

    def anchored_state(self) -> Optional[AnchoredState]:
        """The anchored state as currently published in the ledger."""
        return read_anchored(self._ledger)

    # -- the pre-sign gate ----------------------------------------------

    def pre_sign_gate(self, op: str, *, now: Optional[float] = None) -> AnchoredState:
        """The pre-sign gate: refuse before anything is signed.

        Refuses, in this order, with a structured reason:

        * ``NOT_SEALED``  -- no policy is sealed;
        * ``NOT_ANCHORED`` -- the vault state was never published;
        * ``POLICY_TAMPER`` -- the sealed policy hash != the anchored hash;
        * ``ROLLBACK`` -- the vault version < the anchored version;
        * ``EXPIRED`` -- the policy is past its expiry;
        * ``CAP_EXCEEDED`` -- the per-epoch signature cap is exhausted;
        * ``OP_NOT_ALLOWED`` -- the operation kind is not permitted.

        The gate reads the anchored state from the ledger **at gate time**,
        not from a cached copy: that is what closes the rollback hole the
        source describes.
        """
        moment = self._clock() if now is None else float(now)
        if self._seal is None or self._policy is None:
            raise CustodyRefusal(RefusalReason.NOT_SEALED)
        anchored = read_anchored(self._ledger)
        if anchored is None:
            raise CustodyRefusal(RefusalReason.NOT_ANCHORED)
        # The version check comes FIRST: an old vault carries an old policy
        # hash too, and the source's rollback hole is exactly that case --
        # reporting it as POLICY_TAMPER would hide the rollback.  The
        # version is the monotonic clock; a vault older than the anchored
        # one is a rollback, whatever its policy says.
        if self._seal.vault_version < anchored.vault_version:
            raise CustodyRefusal(
                RefusalReason.ROLLBACK,
                {
                    "sealed_vault_version": self._seal.vault_version,
                    "anchored_vault_version": anchored.vault_version,
                },
            )
        current_hash = self._policy.policy_hash
        if current_hash != self._seal.policy_hash:
            raise CustodyRefusal(
                RefusalReason.POLICY_TAMPER,
                {
                    "current_policy_hash": current_hash,
                    "sealed_policy_hash": self._seal.policy_hash,
                    "anchored_policy_hash": anchored.policy_hash,
                },
            )
        if self._seal.policy_hash != anchored.policy_hash:
            raise CustodyRefusal(
                RefusalReason.POLICY_TAMPER,
                {
                    "sealed_policy_hash": self._seal.policy_hash,
                    "anchored_policy_hash": anchored.policy_hash,
                },
            )
        if self._policy.is_expired(moment):
            raise CustodyRefusal(
                RefusalReason.EXPIRED,
                {"expires_at": self._policy.expires_at, "now": moment},
            )
        epoch = self._policy.epoch_of(moment)
        if self.signature_count(epoch) >= self._policy.max_signatures_per_epoch:
            raise CustodyRefusal(
                RefusalReason.CAP_EXCEEDED,
                {
                    "epoch": epoch,
                    "count": self.signature_count(epoch),
                    "cap": self._policy.max_signatures_per_epoch,
                },
            )
        if not self._policy.allows(op):
            raise CustodyRefusal(
                RefusalReason.OP_NOT_ALLOWED,
                {"op": op, "allowed_ops": sorted(set(self._policy.allowed_ops))},
            )
        return anchored

    # -- signing --------------------------------------------------------

    def sign(
        self, payload: Dict[str, Any], *, op: str = "receipt", now: Optional[float] = None
    ) -> SignatureEnvelope:
        """Sign a payload under the sealed policy.

        The pre-sign gate runs first.  When the gate refuses, **no
        signature is produced** and the refusal is structured -- the caller
        sees the reason, not a bare exception.
        """
        if not isinstance(payload, dict):
            raise CustodyRefusal(RefusalReason.BAD_PAYLOAD)
        anchored = self.pre_sign_gate(op, now=now)
        assert self._seal is not None and self._policy is not None
        moment = self._clock() if now is None else float(now)
        payload_hash = _sha256_pin(_canonical(payload))
        self._seq += 1
        seq = self._seq
        body = {
            "schema": SCHEMA_PIN,
            "key_id": self._key_id,
            "public_key": self._public_key.hex(),
            "policy_hash": self._seal.policy_hash,
            "vault_version": self._seal.vault_version,
            "anchored_policy_hash": anchored.policy_hash,
            "anchored_vault_version": anchored.vault_version,
            "anchor_seq": anchored.seq,
            "payload_hash": payload_hash,
            "payload": dict(payload),
            "op": op,
            "seq": seq,
            "timestamp": moment,
        }
        ed = _ed25519()
        signature = ed.sign(self._seed, _canonical(body)).hex()
        epoch = self._policy.epoch_of(moment)
        self._epoch_counts[epoch] = self.signature_count(epoch) + 1
        return SignatureEnvelope(
            schema=SCHEMA_PIN,
            key_id=self._key_id,
            public_key=self._public_key.hex(),
            signature=signature,
            policy_hash=self._seal.policy_hash,
            vault_version=self._seal.vault_version,
            anchored_policy_hash=anchored.policy_hash,
            anchored_vault_version=anchored.vault_version,
            anchor_seq=anchored.seq,
            payload_hash=payload_hash,
            payload=dict(payload),
            op=op,
            seq=seq,
            timestamp=moment,
        )


def stdlib_only() -> bool:
    """AST check: stdlib only (the ed25519 primitive is vendored locally)."""
    tree = ast.parse(Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {
        "__future__",
        "ast",
        "hashlib",
        "importlib",
        "importlib.util",
        "json",
        "os",
        "pathlib",
        "sys",
        "time",
        "dataclasses",
        "enum",
        "typing",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    """Self-check: the happy path, the tamper, and the rollback."""
    ledger = _load_sibling("forward_seal_ledger").ForwardSealLedger(
        initial_key=b"k" * 32, checkpoint_key=b"c" * 32
    )
    now = 1_000_000.0
    custody = KeyCustody(agent_id="agent-a", ledger=ledger, seed=b"s" * 32, clock=lambda: now)
    policy = CustodyPolicy(
        allowed_ops=("receipt",),
        max_signatures_per_epoch=2,
        expires_at=now + 3600,
        epoch_seconds=3600,
        policy_id="p1",
    )
    custody.seal_policy(policy, vault_version=1)
    custody.anchor()
    envelope = custody.sign({"receipt_id": "r1"}, op="receipt")
    assert verify_envelope(envelope, custody.public_key, anchored_policy_hash=policy.policy_hash)
    print("key-custody OK: seal, anchor, sign, verify")

    # Tamper: a policy changed after sealing is refused (not anchored).
    tampered = CustodyPolicy(
        allowed_ops=("receipt",),
        max_signatures_per_epoch=2,
        expires_at=now + 3600,
        epoch_seconds=3600,
        policy_id="p2",
    )
    custody.seal_policy(tampered, vault_version=2)
    try:
        custody.sign({"receipt_id": "r2"}, op="receipt")
        raise AssertionError("tampered policy must be refused")
    except CustodyRefusal as exc:
        assert exc.reason is RefusalReason.POLICY_TAMPER, exc.reason
    print("key-custody OK: policy tamper refused (POLICY_TAMPER)")

    # Rollback: the anchored version moves forward, an old vault is refused.
    newer = KeyCustody(agent_id="agent-a", ledger=ledger, seed=b"t" * 32, clock=lambda: now)
    newer.seal_policy(policy, vault_version=3)
    newer.anchor()
    rollback = KeyCustody(agent_id="agent-a", ledger=ledger, seed=b"s" * 32, clock=lambda: now)
    rollback.seal_policy(policy, vault_version=1)
    assert seal_is_valid(rollback.seal)  # the seal itself is valid ...
    try:
        rollback.sign({"receipt_id": "r3"}, op="receipt")
        raise AssertionError("rolled-back vault must be refused")
    except CustodyRefusal as exc:
        assert exc.reason is RefusalReason.ROLLBACK, exc.reason
    print("key-custody OK: rollback refused (ROLLBACK)")

    assert stdlib_only()
    print("key-custody OK: stdlib only")


if __name__ == "__main__":
    main()
