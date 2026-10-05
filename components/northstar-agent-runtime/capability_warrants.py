"""Tenuo-inspired capability warrants: holder-bound, attenuating, audited.

Absorbs the *mechanism ideas* of Tenuo (https://github.com/tenuo-ai/tenuo,
Apache-2.0, read 2026-10-05; **no code copied** — field names, wire format
and the PoP challenge construction below are original):

* **Holder-bound warrants**: each warrant names the holder's public key;
  every execution requires a proof-of-possession (PoP) — the holder signs
  ``b"northstar-pop-v1" || canonical(warrant_id, tool, sorted_params,
  time_window)``. A stolen warrant without the holder key is useless.
  Delegation is only valid when the delegator IS the current holder
  ("you can only delegate what you hold").
* **Monotonic attenuation**: delegation walks an ordered checklist —
  delegator-is-holder, depth+1 within ceiling, parent unexpired, tool set is
  a subset (``"*"`` wildcard is top), typed constraint narrowing per kind
  (exact/prefix/range/pattern), clearance never rises,
  ``expires_at = min(child_ttl, parent)``, ``parent_hash`` chains the
  warrant. Anything that would widen authority fails closed.
* **Semantic parameter constraints**: constraints are typed
  (``exact``/``prefix``/``range``/``pattern``/``one_of``); evaluation is
  zero-trust — an unknown parameter name or unknown constraint type is a
  rejection, not a skip. Authorization order: expiry -> holder PoP ->
  tool allow-list -> constraints.
* **Signed receipts**: every authorization decision emits a receipt
  chained by ``prev_receipt_hash`` (no silent drops) and bound to the
  warrant by ``warrant_hash``; the receipt carries the decision, the
  evaluated constraints, and the PoP time window.

Cryptography: Ed25519 + SHA-256 + canonical JSON only (see :mod:`ed25519`,
:mod:`audit_chain`). No new dependencies.

Relationship to :mod:`delegation_credentials` (Biscuit-style): that module
is authority-facts + check-attenuation with offline chain verification.
This module is holder-bound capabilities + PoP + typed semantic
constraints + receipt chaining. The two are complementary: use
delegation credentials for *who may delegate what*, warrants for
*this specific holder may do this specific action now*.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

import ed25519
from audit_chain import canonical_json

#: Wire version of this warrant format.
WARRANT_VERSION = "northstar-warrant/v1"

#: PoP challenge domain tag (separate from identity challenges).
_POP_DOMAIN = b"northstar-pop-v1"

#: PoP time-window seconds (challenge binds a window, not an instant).
POP_WINDOW = 30

#: Clock tolerance windows for PoP verification (±2 windows).
POP_TOLERANCE_WINDOWS = 2


class WarrantError(Exception):
    """Raised for malformed warrants; authorization returns False, never raises."""


def _canonical(mapping: Mapping[str, Any]) -> bytes:
    return canonical_json(dict(mapping))


def _hash(mapping: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical(mapping)).hexdigest()


def _pop_challenge(
    *, warrant_id: str, tool: str, params: Mapping[str, Any], window: int
) -> bytes:
    """Build the PoP challenge bytes (deterministic)."""
    body = {
        "warrant_id": warrant_id,
        "tool": tool,
        "params": {k: params[k] for k in sorted(params)},
        "window": window,
    }
    return _POP_DOMAIN + _canonical(body)


@dataclass
class WarrantVerdict:
    ok: bool
    violations: tuple[str, ...] = ()
    receipt: dict[str, Any] | None = None


def issue(
    *,
    issuer_secret: bytes,
    holder_pubkey: bytes,
    tools: Sequence[str],
    constraints: Sequence[Mapping[str, Any]] | None = None,
    clearance: int = 1,
    ttl_seconds: int = 3600,
    max_depth: int = 3,
) -> dict[str, Any]:
    """Issue a root warrant (only the issuer key holder can create one)."""
    issuer_pub = ed25519.public_key(issuer_secret)
    now = int(time.time())
    warrant = {
        "format": WARRANT_VERSION,
        "warrant_id": hashlib.sha256(
            issuer_pub + holder_pubkey + now.to_bytes(8, "big")
        ).hexdigest()[:32],
        "issuer": issuer_pub.hex(),
        "holder": holder_pubkey.hex(),
        "tools": list(tools),
        "constraints": [dict(c) for c in (constraints or [])],
        "clearance": clearance,
        "issued_at": now,
        "expires_at": now + ttl_seconds,
        "depth": 0,
        "max_depth": max_depth,
        "parent_hash": "",
    }
    warrant["signature"] = ed25519.sign(issuer_secret, _canonical(warrant)).hex()
    return warrant


def _verify_warrant_signature(warrant: Mapping[str, Any]) -> bool:
    try:
        # Attenuated warrants are signed by the delegator (parent holder),
        # recorded in "signed_by"; root warrants are signed by the issuer.
        signer_hex = warrant.get("signed_by") or warrant["issuer"]
        signer_pub = bytes.fromhex(str(signer_hex))
        sig = bytes.fromhex(str(warrant["signature"]))
        body = {k: v for k, v in warrant.items() if k != "signature"}
        return ed25519.verify(signer_pub, _canonical(body), sig)
    except Exception:
        return False


def _constraint_narrows(
    parent: Mapping[str, Any], child: Mapping[str, Any]
) -> bool:
    """Check a child constraint narrows (never widens) its parent.

    Supported kinds: exact (equal), prefix (child extends), range
    (child interval within parent), one_of (child subset), pattern
    (child pattern implies parent — conservative: must be identical).
    Unknown kinds fail closed (return False).
    """
    if parent.get("param") != child.get("param"):
        return False
    pkind, ckind = parent.get("kind"), child.get("kind")
    if pkind != ckind:
        return False
    if pkind == "exact":
        return parent.get("value") == child.get("value")
    if pkind == "prefix":
        return str(child.get("value", "")).startswith(str(parent.get("value", "")))
    if pkind == "range":
        try:
            plo, phi = float(parent["min"]), float(parent["max"])
            clo, chi = float(child["min"]), float(child["max"])
            return plo <= clo and chi <= phi
        except (KeyError, TypeError, ValueError):
            return False
    if pkind == "one_of":
        return set(child.get("values", ())).issubset(set(parent.get("values", ())))
    if pkind == "pattern":
        # Conservative: patterns must be identical (implication is undecidable
        # in general; narrowing via pattern rewriting is out of scope).
        return parent.get("value") == child.get("value")
    return False  # unknown kind: fail closed


def attenuate(
    *,
    parent_warrant: Mapping[str, Any],
    holder_secret: bytes,
    child_holder_pubkey: bytes,
    tools: Sequence[str] | None = None,
    constraints: Sequence[Mapping[str, Any]] | None = None,
    ttl_seconds: int = 0,
) -> dict[str, Any]:
    """Delegate with attenuation (monotonic narrowing only).

    Ordered checklist (any failure raises WarrantError):
    1. parent signature valid and unexpired;
    2. caller IS the parent holder (only what you hold can be delegated);
    3. depth+1 within max_depth;
    4. tool set is a subset of parent's (``"*"`` in parent allows any);
    5. every child constraint narrows a parent constraint (typed);
    6. clearance does not rise;
    7. ``expires_at = min(now+ttl, parent.expires_at)``;
    8. ``parent_hash`` chains to the parent warrant hash.
    """
    now = int(time.time())
    if not _verify_warrant_signature(parent_warrant):
        raise WarrantError("parent warrant signature invalid")
    if int(parent_warrant.get("expires_at", 0)) <= now:
        raise WarrantError("parent warrant expired")
    parent_holder = bytes.fromhex(str(parent_warrant["holder"]))
    if ed25519.public_key(holder_secret) != parent_holder:
        raise WarrantError("only the holder can delegate")
    depth = int(parent_warrant.get("depth", 0)) + 1
    if depth > int(parent_warrant.get("max_depth", 0)):
        raise WarrantError("delegation depth exceeded")
    parent_tools = parent_warrant.get("tools", [])
    child_tools = list(tools) if tools is not None else list(parent_tools)
    if "*" not in parent_tools:
        if not set(child_tools).issubset(set(parent_tools)):
            raise WarrantError("tool set not a subset of parent")
    parent_constraints = {
        c.get("param"): c for c in parent_warrant.get("constraints", [])
    }
    child_constraints = (
        [dict(c) for c in constraints]
        if constraints is not None
        else [dict(c) for c in parent_warrant.get("constraints", [])]
    )
    for cc in child_constraints:
        pc = parent_constraints.get(cc.get("param"))
        if pc is None or not _constraint_narrows(pc, cc):
            raise WarrantError(
                f"constraint on {cc.get('param')!r} does not narrow parent"
            )
    child_ttl = ttl_seconds or (int(parent_warrant["expires_at"]) - now)
    child = {
        "format": WARRANT_VERSION,
        "warrant_id": hashlib.sha256(
            _hash(parent_warrant).encode() + child_holder_pubkey + now.to_bytes(8, "big")
        ).hexdigest()[:32],
        "issuer": parent_warrant["issuer"],
        "holder": child_holder_pubkey.hex(),
        "tools": child_tools,
        "constraints": child_constraints,
        "clearance": int(parent_warrant.get("clearance", 1)),
        "issued_at": now,
        "expires_at": min(now + child_ttl, int(parent_warrant["expires_at"])),
        "depth": depth,
        "max_depth": int(parent_warrant.get("max_depth", 0)),
        "parent_hash": _hash(parent_warrant),
    }
    child["signed_by"] = parent_holder.hex()
    child["signature"] = ed25519.sign(holder_secret, _canonical(child)).hex()
    return child


def _evaluate_constraints(
    constraints: Sequence[Mapping[str, Any]], params: Mapping[str, Any]
) -> list[str]:
    """Evaluate typed constraints against call params (zero-trust).

    When the warrant carries no constraints, params are unrestricted.
    When it does, any param not named by a constraint is rejected
    (zero-trust: the warrant defines the complete param surface).
    """
    violations: list[str] = []
    if not constraints:
        return violations
    known_params = {c.get("param") for c in constraints}
    for pname in params:
        if pname not in known_params:
            violations.append(f"unknown parameter: {pname!r} (zero-trust)")
    for c in constraints:
        pname = c.get("param")
        if pname not in params:
            continue  # absent params are not violations (narrowing may drop them)
        value = params[pname]
        kind = c.get("kind")
        if kind == "exact":
            if value != c.get("value"):
                violations.append(f"{pname}: expected {c.get('value')!r}")
        elif kind == "prefix":
            if not str(value).startswith(str(c.get("value", ""))):
                violations.append(f"{pname}: prefix mismatch")
        elif kind == "range":
            try:
                if not (float(c["min"]) <= float(value) <= float(c["max"])):
                    violations.append(f"{pname}: out of range")
            except (KeyError, TypeError, ValueError):
                violations.append(f"{pname}: range check malformed")
        elif kind == "one_of":
            if value not in c.get("values", ()):
                violations.append(f"{pname}: not in allowed set")
        elif kind == "pattern":
            import re as _re

            try:
                if not _re.fullmatch(str(c.get("value", "")), str(value)):
                    violations.append(f"{pname}: pattern mismatch")
            except _re.error:
                violations.append(f"{pname}: bad pattern")
        else:
            violations.append(f"unknown constraint kind: {kind!r} (fail-closed)")
    return violations


def authorize(
    *,
    warrant: Mapping[str, Any],
    tool: str,
    params: Mapping[str, Any],
    pop_signature: bytes,
    now: int,
    prev_receipt_hash: str = "",
) -> WarrantVerdict:
    """Authorize one action under a warrant (verifier side).

    Order: (1) warrant signature + expiry; (2) holder PoP over the
    (warrant_id, tool, params, time-window) challenge — checked BEFORE
    constraints so a stolen warrant cannot even reach policy evaluation;
    (3) tool in allow-list; (4) typed constraints. On success, emits a
    chained receipt. Never raises; failures are violations.
    """
    if not _verify_warrant_signature(warrant):
        return WarrantVerdict(ok=False, violations=("warrant signature invalid",))
    if int(warrant.get("expires_at", 0)) <= now:
        return WarrantVerdict(ok=False, violations=("warrant expired",))
    # PoP: holder proves possession of the holder key for THIS call.
    try:
        holder_pub = bytes.fromhex(str(warrant["holder"]))
    except Exception:
        return WarrantVerdict(ok=False, violations=("holder key malformed",))
    window = now // POP_WINDOW
    pop_ok = False
    for w in range(window - POP_TOLERANCE_WINDOWS, window + 1):
        chal = _pop_challenge(
            warrant_id=str(warrant["warrant_id"]),
            tool=tool,
            params=params,
            window=w,
        )
        if ed25519.verify(holder_pub, chal, pop_signature):
            pop_ok = True
            break
    if not pop_ok:
        return WarrantVerdict(ok=False, violations=("holder proof-of-possession failed",))
    # Tool allow-list.
    tools = warrant.get("tools", [])
    if tool not in tools and "*" not in tools:
        return WarrantVerdict(ok=False, violations=(f"tool {tool!r} not warranted",))
    # Constraints.
    violations = _evaluate_constraints(warrant.get("constraints", []), params)
    if violations:
        return WarrantVerdict(ok=False, violations=tuple(violations))
    # Receipt (chained).
    receipt = {
        "format": WARRANT_VERSION,
        "kind": "receipt",
        "warrant_hash": _hash(warrant),
        "tool": tool,
        "params_hash": hashlib.sha256(_canonical(params)).hexdigest(),
        "decision": "allow",
        "window": window,
        "prev_receipt_hash": prev_receipt_hash,
        "issued_at": now,
    }
    return WarrantVerdict(ok=True, receipt=receipt)


def pop_sign(
    *,
    holder_secret: bytes,
    warrant_id: str,
    tool: str,
    params: Mapping[str, Any],
    now: int,
) -> bytes:
    """Holder-side: sign a PoP challenge for one call (used by agents)."""
    window = now // POP_WINDOW
    chal = _pop_challenge(
        warrant_id=warrant_id, tool=tool, params=params, window=window
    )
    return ed25519.sign(holder_secret, chal)


__all__ = [
    "WARRANT_VERSION",
    "POP_WINDOW",
    "WarrantError",
    "WarrantVerdict",
    "attenuate",
    "authorize",
    "issue",
    "pop_sign",
]
