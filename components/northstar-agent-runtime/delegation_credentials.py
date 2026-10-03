"""Biscuit-style attenuating delegation credentials (minimal subset).

Semantic port of the attenuation pattern from Eclipse Biscuit
(https://doc.biscuitsec.org — read against the official "Introduction",
"Per-request attenuation" recipe and "Specifications" pages, 2026-10-03;
**not** wire-compatible with the biscuit protobuf token format):

* **authority block**: cryptographically signed facts stating what the token
  grants. Only the root key holder (the run's root authority — the host /
  supervisor role that also owns the audit signing key) can create one.
* **attenuation blocks**: any holder may *append* a block carrying only
  **checks** (restrictions). Checks are conjunctive and can only narrow the
  token's effective rights — never widen them. A block that carries facts
  outside the authority block is rejected, so amplification has no
  representation in the format.
* **signature chain**: each block carries ``next_pub`` and a signature by
  the *previous* key over ``canonical(block data) || next_pub``; the token
  also carries the private key of the last block's ``next_pub`` (the
  *proof*), which is what lets a holder attenuate **offline** without the
  root key. Removing, reordering or editing any block breaks the chain.
* **sealed token**: instead of the proof key, the token carries a signature
  of the last block by the last private key; a sealed token can be verified
  but never attenuated further.
* **offline verification**: the tool side needs only the root **public**
  key. It walks the signature chain, rejects fact-carrying non-authority
  blocks, then evaluates every check against the request facts. Unknown
  check predicates fail closed.

Honest scope: this is the authority-facts + check-attenuation + offline
Ed25519 verification subset. It is not Datalog (checks are a small fixed
predicate vocabulary), it does not parse real biscuit tokens, and it does
not claim conformance with the biscuit spec — only the attenuation
*mechanism* is borrowed, and the borrow is declared here and in the
CHANGELOG.

Every issuance / attenuation / sealing emits an audit event
(:func:`attenuation_audit_events`) whose body pins the credential id and
the block signature chain; appending those events to the
``audit.ndjson/1`` hash chain anchors the attenuation chain in the audit
trail, so a later verifier can prove *which* rights a delegation carried
at each hop.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Sequence

import ed25519
from audit_chain import canonical_json

#: Wire version of this credential format.
CREDENTIAL_VERSION = "northstar.delegation-credential/1"

#: Fact predicate vocabulary. Authority blocks may carry facts; attenuation
#: blocks may not (enforced by the verifier — this is the anti-amplification
#: gate).
FACT_RIGHT = "right"  # ("right", tool, operation)

#: Check predicate vocabulary. Unknown predicates fail closed at verify time.
CHECK_TOOL_IN = "tool_in"  # request tool must be in the named set
CHECK_OP_IN = "op_in"  # request operation must be in the named set
CHECK_DEPTH_AT_MOST = "depth_at_most"  # request depth <= bound
CHECK_EXPIRES_BEFORE = "expires_before"  # request time (ISO-8601) < bound

_KNOWN_CHECKS = frozenset(
    {CHECK_TOOL_IN, CHECK_OP_IN, CHECK_DEPTH_AT_MOST, CHECK_EXPIRES_BEFORE}
)


class CredentialError(Exception):
    """Raised when a credential cannot be built (caller bug), never on verify."""


def _hex(raw: bytes) -> str:
    return raw.hex()


def _raw(hexed: str, length: int) -> bytes | None:
    try:
        raw = bytes.fromhex(hexed)
    except (TypeError, ValueError):
        return None
    return raw if len(raw) == length else None


def _fresh_keypair() -> tuple[bytes, bytes]:
    """A fresh Ed25519 keypair for the next attenuation hop."""
    secret = os.urandom(32)
    return secret, ed25519.public_key(secret)


def _sign_block(secret: bytes, data: Mapping[str, Any], next_pub: bytes) -> bytes:
    return ed25519.sign(secret, canonical_json(data) + next_pub)


@dataclass(frozen=True)
class RequestFacts:
    """What the verifying (tool) side asserts about one request.

    No clock reads happen inside the verifier: ``time_iso`` is supplied by
    the caller (e.g. the tool execution context), keeping verification
    offline and deterministic — the same rule the audit chain follows.
    """

    agent: str
    tool: str
    operation: str
    depth: int = 0
    time_iso: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "agent": self.agent,
            "tool": self.tool,
            "operation": self.operation,
            "depth": self.depth,
            "time_iso": self.time_iso,
        }


@dataclass(frozen=True)
class CredentialVerdict:
    """Result of offline verification against the root public key."""

    allowed: bool
    reason: str = ""
    failed_check: str = ""
    chain_ok: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "failed_check": self.failed_check,
            "chain_ok": self.chain_ok,
        }


def _block_data(
    kind: str,
    *,
    facts: Sequence[Sequence[str]] | None = None,
    checks: Sequence[Mapping[str, Any]] | None = None,
    meta: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    data: dict[str, Any] = {"kind": kind}
    if facts is not None:
        data["facts"] = [list(f) for f in facts]
    if checks is not None:
        data["checks"] = [dict(c) for c in checks]
    if meta:
        data["meta"] = dict(meta)
    return data


class Issuer:
    """Root authority: the only party that can mint authority blocks.

    In Northstar terms this is the run's root authority (host / supervisor
    role) — the same trust root that signs the audit feed. The secret never
    leaves this object; verifiers and holders only ever see public keys.
    """

    def __init__(self, root_secret: bytes) -> None:
        if len(root_secret) != 32:
            raise CredentialError("root secret must be 32 bytes")
        self._root_secret = bytes(root_secret)
        self._root_pub = ed25519.public_key(root_secret)

    @property
    def root_public_key(self) -> bytes:
        return self._root_pub

    @classmethod
    def generate(cls) -> "Issuer":
        return cls(os.urandom(32))

    def issue(
        self,
        holder: str,
        rights: Iterable[tuple[str, str]],
        *,
        issued_by: str = "supervisor",
    ) -> dict[str, Any]:
        """Mint a credential: authority facts for ``holder``.

        ``rights`` are ``(tool, operation)`` pairs — the *maximum* the holder
        may ever exercise; every later hop can only narrow this set.
        """
        holder = holder.strip()
        if not holder:
            raise CredentialError("holder must be a non-empty agent id")
        right_list = sorted({(str(t), str(o)) for t, o in rights})
        if not right_list:
            raise CredentialError("issue with an empty rights set is meaningless")
        next_secret, next_pub = _fresh_keypair()
        data = _block_data(
            "authority",
            facts=[[FACT_RIGHT, tool, op] for tool, op in right_list],
            meta={
                "holder": holder,
                "issued_by": issued_by,
                "credential_version": CREDENTIAL_VERSION,
            },
        )
        block = {
            "data": data,
            "next_pub": _hex(next_pub),
            "sig": _hex(_sign_block(self._root_secret, data, next_pub)),
        }
        return {
            "version": CREDENTIAL_VERSION,
            "blocks": [block],
            # The proof key: lets the holder attenuate offline, exactly as in
            # biscuit ("the token also contains the private key corresponding
            # to the last public key, to sign a new block and attenuate").
            "proof": _hex(next_secret),
            "seal": None,
        }


def credential_id(token: Mapping[str, Any]) -> str:
    """Stable id of a credential: hex of the authority block signature."""
    try:
        return str(token["blocks"][0]["sig"])
    except (KeyError, IndexError, TypeError):
        return ""


def attenuate(
    token: Mapping[str, Any],
    checks: Sequence[Mapping[str, Any]],
    *,
    attenuated_by: str,
) -> dict[str, Any]:
    """Append an attenuation block carrying only checks (restrictions).

    Fails loudly (``CredentialError``) when the token is sealed or the
    caller tries to smuggle facts into an attenuation block — attenuation
    narrows, it never grants.
    """
    if token.get("seal"):
        raise CredentialError("sealed credentials cannot be attenuated")
    proof_hex = token.get("proof")
    proof = _raw(proof_hex, 32) if isinstance(proof_hex, str) else None
    if proof is None:
        raise CredentialError("token carries no proof key: cannot attenuate")
    check_list = [dict(c) for c in checks]
    if not check_list:
        raise CredentialError("attenuation must add at least one check")
    for check in check_list:
        predicate = check.get("predicate")
        if predicate not in _KNOWN_CHECKS:
            raise CredentialError(f"unknown check predicate {predicate!r}")
        if "fact" in check or "facts" in check:
            raise CredentialError("attenuation blocks may not carry facts")
    next_secret, next_pub = _fresh_keypair()
    data = _block_data(
        "attenuation",
        checks=check_list,
        meta={"attenuated_by": attenuated_by},
    )
    block = {
        "data": data,
        "next_pub": _hex(next_pub),
        "sig": _hex(_sign_block(proof, data, next_pub)),
    }
    return {
        "version": token.get("version", CREDENTIAL_VERSION),
        "blocks": [dict(b) for b in token["blocks"]] + [block],
        "proof": _hex(next_secret),
        "seal": None,
    }


def seal(token: Mapping[str, Any]) -> dict[str, Any]:
    """Seal a credential: verifiable, but no further attenuation possible.

    Mirrors biscuit's sealed token ("a signature of the last block by the
    private key"): the proof key is replaced by a seal signature, so nobody
    holding the sealed token can append blocks.
    """
    if token.get("seal"):
        raise CredentialError("already sealed")
    proof_hex = token.get("proof")
    proof = _raw(proof_hex, 32) if isinstance(proof_hex, str) else None
    if proof is None:
        raise CredentialError("token carries no proof key: cannot seal")
    try:
        last_sig = _raw(str(token["blocks"][-1]["sig"]), 64)
        last_pub = _raw(str(token["blocks"][-1]["next_pub"]), 32)
    except (KeyError, IndexError, TypeError):
        raise CredentialError("malformed token: cannot seal") from None
    if last_sig is None or last_pub is None:
        raise CredentialError("malformed token: cannot seal")
    return {
        "version": token.get("version", CREDENTIAL_VERSION),
        "blocks": [dict(b) for b in token["blocks"]],
        "proof": None,
        "seal": _hex(ed25519.sign(proof, last_sig)),
    }


def _verify_chain(
    token: Mapping[str, Any], root_pub: bytes
) -> tuple[bool, str, list[dict[str, Any]]]:
    """Walk the per-block signature chain. Returns (ok, reason, blocks)."""
    blocks = token.get("blocks")
    if not isinstance(blocks, list) or not blocks:
        return False, "token has no blocks", []
    current_pub = root_pub
    parsed: list[dict[str, Any]] = []
    for index, block in enumerate(blocks):
        if not isinstance(block, dict):
            return False, f"block {index} is not a mapping", []
        data = block.get("data")
        next_pub = _raw(block.get("next_pub", ""), 32)
        sig = _raw(block.get("sig", ""), 64)
        if not isinstance(data, dict) or next_pub is None or sig is None:
            return False, f"block {index} is malformed", []
        if not ed25519.verify(current_pub, canonical_json(data) + next_pub, sig):
            return (
                False,
                f"block {index} signature invalid "
                "(tampered, reordered or forged)",
                [],
            )
        parsed.append({"data": data, "next_pub": next_pub, "sig": sig})
        current_pub = next_pub
    return True, "", parsed


def _evaluate_checks(
    blocks: Sequence[Mapping[str, Any]], request: RequestFacts
) -> tuple[bool, str, str]:
    """Evaluate every check in every block against the request facts.

    Checks are conjunctive: one failure denies. Unknown predicates fail
    closed. Facts in non-authority blocks are rejected outright — there is
    no representation for "grant more" outside the authority block.
    """
    facts = request.as_dict()
    for index, block in enumerate(blocks):
        data = block["data"]
        kind = data.get("kind")
        if index == 0:
            if kind != "authority":
                return False, "first block is not the authority block", ""
        elif kind != "attenuation":
            return False, f"block {index} is not an attenuation block", ""
        if index > 0 and data.get("facts"):
            # The anti-amplification gate: only the authority block may grant.
            return (
                False,
                f"block {index} carries facts but is not the authority block: "
                "amplification attempt rejected",
                "",
            )
        for check in data.get("checks", []):
            predicate = check.get("predicate")
            if predicate not in _KNOWN_CHECKS:
                return False, f"unknown check predicate {predicate!r}: fail closed", str(predicate)
            ok = _check_holds(predicate, check, facts)
            if not ok:
                return False, f"check failed: {predicate}", str(predicate)
    return True, "", ""


def _check_holds(
    predicate: str, check: Mapping[str, Any], facts: Mapping[str, Any]
) -> bool:
    if predicate == CHECK_TOOL_IN:
        allowed = check.get("tools")
        return isinstance(allowed, list) and facts["tool"] in allowed
    if predicate == CHECK_OP_IN:
        allowed = check.get("operations")
        return isinstance(allowed, list) and facts["operation"] in allowed
    if predicate == CHECK_DEPTH_AT_MOST:
        bound = check.get("max_depth")
        return isinstance(bound, int) and facts["depth"] <= bound
    if predicate == CHECK_EXPIRES_BEFORE:
        bound = check.get("not_after")
        # ISO-8601 strings compare lexicographically when both are UTC "Z"
        # suffixed; the verifier never reads a clock.
        return (
            isinstance(bound, str)
            and isinstance(facts["time_iso"], str)
            and bool(facts["time_iso"])
            and facts["time_iso"] < bound
        )
    return False  # unreachable: caller filters unknown predicates


def verify(
    token: Mapping[str, Any],
    root_pub: bytes,
    request: RequestFacts,
) -> CredentialVerdict:
    """Offline verification with the root public key only.

    1. Walk the signature chain (tamper/reorder/forge → reject).
    2. If sealed, verify the seal (a sealed token's proof key is gone).
    3. Reject any facts outside the authority block (amplification gate).
    4. Authority: request agent must be the holder and (tool, operation)
       must be among the granted rights.
    5. Every check in every block must hold (conjunctive narrowing).
    """
    if len(root_pub) != 32:
        return CredentialVerdict(False, "root public key must be 32 bytes")
    chain_ok, reason, blocks = _verify_chain(token, root_pub)
    if not chain_ok:
        return CredentialVerdict(False, reason)
    seal_hex = token.get("seal")
    if seal_hex:
        seal = _raw(seal_hex, 64)
        if seal is None:
            return CredentialVerdict(False, "seal malformed: fail closed", chain_ok=True)
        last = blocks[-1]
        if not ed25519.verify(last["next_pub"], last["sig"], seal):
            return CredentialVerdict(False, "seal invalid: fail closed", chain_ok=True)
    authority = blocks[0]["data"]
    holder = (authority.get("meta") or {}).get("holder")
    if request.agent != holder:
        return CredentialVerdict(
            False,
            f"credential holder is {holder!r}, request is from {request.agent!r}",
            chain_ok=True,
        )
    granted = {
        (str(f[1]), str(f[2]))
        for f in authority.get("facts", [])
        if isinstance(f, list) and len(f) == 3 and f[0] == FACT_RIGHT
    }
    if (request.tool, request.operation) not in granted:
        return CredentialVerdict(
            False,
            f"({request.tool}, {request.operation}) not in granted rights",
            chain_ok=True,
        )
    ok, reason, failed = _evaluate_checks(blocks, request)
    if not ok:
        return CredentialVerdict(False, reason, failed_check=failed, chain_ok=True)
    return CredentialVerdict(True, "credential valid: holder, rights and all checks hold", chain_ok=True)


def attenuation_audit_events(
    token: Mapping[str, Any], *, chain_note: str = ""
) -> list[dict[str, Any]]:
    """Audit events for each block of the credential, for the hash chain.

    Each event pins ``credential_id`` and the block's signature, so the
    audit ``hash chain`` anchors the attenuation chain: a verifier can
    replay which rights each delegation hop carried. Feed these into
    ``audit_chain.chain_record`` / ``chain_records`` in order.
    """
    events: list[dict[str, Any]] = []
    cid = credential_id(token)
    blocks = token.get("blocks") or []
    for index, block in enumerate(blocks):
        if not isinstance(block, dict):
            continue
        data = block.get("data") or {}
        kind = data.get("kind", "?")
        meta = data.get("meta") or {}
        events.append(
            {
                "event": (
                    "delegation_credential.issued"
                    if index == 0
                    else "delegation_credential.attenuated"
                ),
                "credential_id": cid,
                "block_index": index,
                "block_kind": kind,
                "issued_by": meta.get("issued_by", ""),
                "holder": meta.get("holder", ""),
                "attenuated_by": meta.get("attenuated_by", ""),
                "checks_added": [c.get("predicate") for c in data.get("checks", [])],
                "block_sig": block.get("sig", ""),
                "chain_note": chain_note,
            }
        )
    if token.get("seal"):
        events.append(
            {
                "event": "delegation_credential.sealed",
                "credential_id": cid,
                "block_index": len(blocks) - 1,
                "seal": token.get("seal", ""),
                "chain_note": chain_note,
            }
        )
    return events


__all__ = [
    "CHECK_DEPTH_AT_MOST",
    "CHECK_EXPIRES_BEFORE",
    "CHECK_OP_IN",
    "CHECK_TOOL_IN",
    "CREDENTIAL_VERSION",
    "CredentialError",
    "CredentialVerdict",
    "Issuer",
    "RequestFacts",
    "attenuate",
    "attenuation_audit_events",
    "credential_id",
    "seal",
    "verify",
]
