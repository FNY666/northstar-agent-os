"""Attribute-based encryption (ABE) interface: policy-bound decryption.

Research motivation: in ciphertext-policy ABE (CP-ABE, Bethencourt,
Sahai, Waters 2007) the encryptor names a *policy* over attributes
("clearance:top-secret AND team:alpha"), and a user can decrypt only if
their attribute set satisfies the policy. The access decision is
cryptographic: no separate ACL check runs at read time, so the rule
travels with the data instead of living in a policy engine the reader
must be trusted to consult.

This module is the *interface + policy bookkeeping* half: it pins the
policy language, the satisfaction semantics, and the encrypt/decrypt
call shape. Confidentiality itself is simulated -- a SHA-256 keystream
wrapped by the instance's master secret -- so the mechanics (policy
gating, key binding, ciphertext integrity) are exercisable without a
pairing library.

Public API:

- ``ABE`` -- the authority. ``setup()`` mints the master secret and
  returns frozen ``PublicParams``. ``keygen(attributes)`` issues a
  frozen ``SecretKey`` bound to an attribute set. ``encrypt(policy,
  data)`` returns a frozen ``Ciphertext`` carrying the policy pin and
  the wrapped blob. ``decrypt(key, ciphertext)`` unwraps iff the key's
  attributes satisfy the policy, else raises ``PolicyNotSatisfiedError``.
- ``parse_policy(text)`` -- parses the small policy language into a
  frozen ``Policy`` tree (atoms, AND, OR, k-of-n threshold).
- ``policy_satisfied(policy, attributes)`` -- pure satisfaction check.
- ``abe_audit_event(kind, seq, ...)`` -- shapes ``audit.ndjson/1``
  records for setup / key-issued / encrypted / decrypted / rejected.

Policy language (whitespace-insensitive)::

    policy  := or
    or      := and ("|" and)*
    and     := unary ("&" unary)*
    unary   := atom | "(" or ")" | kof
    kof     := INT "of" "(" or ("," or)* ")"
    atom    := [A-Za-z0-9_.:-]+          # e.g. clearance:top-secret

``&`` binds tighter than ``|``. ``2of(a,b,c)`` needs any two.
A bare atom is an atomic requirement.

Honest scope:

- Simulated cryptography: the wrap key is a SHA-256 keystream derived
  from the instance's master secret. Confidentiality therefore rests on
  the instance keeping its secret, not on pairing hardness -- a real
  CP-ABE scheme (Waters 2011 and successors) drops in without changing
  call sites, because the policy tree, key shape, and failure modes are
  already pinned here.
- The ABE instance is the trusted authority: anyone who holds the
  instance can unwrap any ciphertext it minted. Cross-instance use is
  refused fail-closed (unknown keys / ciphertexts raise).
- ``decrypt`` enforces policy satisfaction *before* unwrapping; a key
  whose attributes do not satisfy the policy never sees plaintext.
  Attribute truth is host-reported: the module cannot verify that a
  user really holds an attribute, only that the issued key claims it.
- Deterministic: no randomness, no wall-clock. Two instances in one
  process get distinct master secrets from a process-global counter,
  but two runs produce the same secrets -- do not use for real data.
- In-memory state machine: no disk I/O, no persistence, no network.
  The host owns durability of keys and ciphertexts.
"""

from __future__ import annotations

import hashlib
import hmac
import itertools
import re
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Sequence, Tuple, Union

#: Version pin for this module's record shape.
ABE_VERSION = "abe-interface.v1"

#: Schema pin carried by records and audit events.
SCHEMA_PIN = "northstar.abe-interface.v1"

#: Domain separation for master-secret derivation.
_SETUP_DOMAIN = b"northstar-abe-interface.v1/setup"

#: Domain separation for the wrap keystream.
_WRAP_DOMAIN = b"northstar-abe-interface.v1/wrap"

#: Guardrails.
MAX_ATTRIBUTES = 1024
MAX_POLICY_DEPTH = 64
MAX_DATA_BYTES = 1 << 26  # 64 MiB -- simulation, not a storage engine.

#: Audit event kinds.
_SETUP = "setup"
_KEY_ISSUED = "key-issued"
_ENCRYPTED = "encrypted"
_DECRYPTED = "decrypted"
_REJECTED = "rejected"

_KIND_VOCABULARY = (_SETUP, _KEY_ISSUED, _ENCRYPTED, _DECRYPTED, _REJECTED)

#: Process-global monotonic counter so sibling ABE instances in one
#: process derive distinct master secrets (deterministic, no randomness).
_instance_counter = itertools.count()


class ABEError(Exception):
    """Base class for ABE failures."""


class PolicyError(ABEError):
    """The policy is malformed or unsatisfiable as written."""


class PolicyNotSatisfiedError(ABEError):
    """The key's attribute set does not satisfy the ciphertext policy."""


class UnknownKeyError(ABEError):
    """The key was not issued by this ABE instance."""


class UnknownCiphertextError(ABEError):
    """The ciphertext was not minted by this ABE instance."""


class CiphertextIntegrityError(ABEError):
    """The ciphertext blob does not match its pinned digest."""


def _check_seq(seq: int, name: str = "seq") -> None:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise TypeError(f"{name} must be int, got {type(seq).__name__}")
    if seq < 0:
        raise ValueError(f"{name} must be non-negative, got {seq}")


def _check_attribute(name: Any) -> str:
    if isinstance(name, bool) or not isinstance(name, str):
        raise TypeError(
            f"attribute must be str, got {type(name).__name__}")
    if not name:
        raise ValueError("attribute must be non-empty")
    if not re.fullmatch(r"[A-Za-z0-9_.:\-]+", name):
        raise ValueError(f"attribute has illegal characters: {name!r}")
    return name


def _check_attributes(attributes: Any) -> FrozenSet[str]:
    if isinstance(attributes, (str, bytes)) or not isinstance(
            attributes, Sequence):
        raise TypeError(
            "attributes must be a sequence of str, got "
            f"{type(attributes).__name__}")
    checked = frozenset(_check_attribute(a) for a in attributes)
    if not checked:
        raise ValueError("attributes must be non-empty")
    if len(checked) > MAX_ATTRIBUTES:
        raise ValueError(
            f"too many attributes ({len(checked)} > {MAX_ATTRIBUTES})")
    return checked


# ---------------------------------------------------------------------------
# Policy tree
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Policy:
    """Frozen access-policy node.

    ``op`` is one of ``"atom"`` (``name`` set), ``"and"``, ``"or"``
    (``children`` set), or ``"threshold"`` (``k`` and ``children`` set).
    """
    op: str
    name: str = ""
    children: Tuple["Policy", ...] = ()
    k: int = 0

    def __post_init__(self) -> None:
        if self.op == "atom":
            if not self.name or self.children or self.k:
                raise PolicyError("atom node must carry only a name")
        elif self.op in ("and", "or"):
            if not self.children or len(self.children) < 2 or self.k:
                raise PolicyError(
                    f"{self.op} node needs >= 2 children, no threshold")
        elif self.op == "threshold":
            if not (1 <= self.k <= len(self.children)):
                raise PolicyError(
                    f"threshold k={self.k} out of range for "
                    f"{len(self.children)} children")
            if len(self.children) < 2:
                raise PolicyError("threshold needs >= 2 children")
        else:
            raise PolicyError(f"unknown policy op: {self.op!r}")

    def to_string(self) -> str:
        """Canonical policy text (children sorted, deduped)."""
        if self.op == "atom":
            return self.name
        inner = ", ".join(c.to_string() for c in self.children)
        if self.op == "and":
            return " & ".join(c.to_string() for c in self.children)
        if self.op == "or":
            return " | ".join(c.to_string() for c in self.children)
        return f"{self.k}of({inner})"

    def as_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {"op": self.op, "schema": SCHEMA_PIN}
        if self.op == "atom":
            d["name"] = self.name
        else:
            d["children"] = [c.as_dict() for c in self.children]
            if self.op == "threshold":
                d["k"] = self.k
        return d


def _canon_policy(node: Policy) -> Policy:
    """Normalize: sort/dedupe children, fold trivial thresholds."""
    if node.op == "atom":
        return node
    children = tuple(sorted(
        {_canon_policy(c) for c in node.children},
        key=lambda c: c.to_string()))
    # Dedupe identical children (set already did); drop singletons.
    if node.op == "threshold":
        if node.k == 1:
            return Policy(op="or", children=children)
        if node.k == len(children):
            return Policy(op="and", children=children)
        return Policy(op="threshold", children=children, k=node.k)
    if len(children) == 1:
        return children[0]
    return Policy(op=node.op, children=children)


_TOKEN_RE = re.compile(r"""
    (?P<ws>\s+)
  | (?P<num>\d+)
  | (?P<op>[&|(),])
  | (?P<atom>[A-Za-z0-9_.:\-]+)
""", re.VERBOSE)


def _tokenize(text: str) -> List[Tuple[str, str]]:
    if not isinstance(text, str):
        raise TypeError(
            f"policy must be str, got {type(text).__name__}")
    if not text.strip():
        raise PolicyError("policy must be non-empty")
    tokens: List[Tuple[str, str]] = []
    pos = 0
    while pos < len(text):
        m = _TOKEN_RE.match(text, pos)
        if not m:
            raise PolicyError(
                f"illegal character at offset {pos}: {text[pos:]!r}")
        pos = m.end()
        kind = m.lastgroup or ""
        val = m.group()
        if kind == "ws":
            continue
        tokens.append((kind, val))
    # Merge "of" keyword into following num? No -- handle in parser.
    return tokens


class _Parser:
    def __init__(self, tokens: List[Tuple[str, str]]) -> None:
        self.tokens = tokens
        self.pos = 0
        self.depth = 0

    def peek(self) -> Tuple[str, str] | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def next(self) -> Tuple[str, str]:
        tok = self.peek()
        if tok is None:
            raise PolicyError("unexpected end of policy")
        self.pos += 1
        return tok

    def parse(self) -> Policy:
        node = self.parse_or()
        if self.peek() is not None:
            raise PolicyError(
                f"trailing tokens: {self.tokens[self.pos:]}")
        return _canon_policy(node)

    def parse_or(self) -> Policy:
        parts = [self.parse_and()]
        while self.peek() == ("op", "|"):
            self.next()
            parts.append(self.parse_and())
        if len(parts) == 1:
            return parts[0]
        return Policy(op="or", children=tuple(parts))

    def parse_and(self) -> Policy:
        parts = [self.parse_unary()]
        while self.peek() == ("op", "&"):
            self.next()
            parts.append(self.parse_unary())
        if len(parts) == 1:
            return parts[0]
        return Policy(op="and", children=tuple(parts))

    def parse_unary(self) -> Policy:
        tok = self.peek()
        if tok is None:
            raise PolicyError("unexpected end of policy")
        kind, val = tok
        if (kind, val) == ("op", "("):
            self.depth += 1
            if self.depth > MAX_POLICY_DEPTH:
                raise PolicyError("policy nesting too deep")
            self.next()
            node = self.parse_or()
            closing = self.next()
            if closing != ("op", ")"):
                raise PolicyError(
                    f"expected ')', got {closing[1]!r}")
            self.depth -= 1
            return node
        if kind == "num":
            return self.parse_threshold()
        if kind == "atom" and val != "of":
            self.next()
            return Policy(op="atom", name=_check_attribute(val))
        raise PolicyError(f"unexpected token {val!r}")

    def parse_threshold(self) -> Policy:
        kind, val = self.next()
        k = int(val)
        if isinstance(k, bool) or k < 1:
            raise PolicyError(f"threshold k must be >= 1, got {val!r}")
        nxt = self.next()
        if nxt[1] != "of":
            raise PolicyError(
                f"expected 'of' after threshold count, got {nxt[1]!r}")
        if self.next() != ("op", "("):
            raise PolicyError("expected '(' after 'Nof'")
        parts = [self.parse_or()]
        while self.peek() == ("op", ","):
            self.next()
            parts.append(self.parse_or())
        if self.next() != ("op", ")"):
            raise PolicyError("expected ')' to close threshold list")
        if k > len(parts):
            raise PolicyError(
                f"threshold k={k} exceeds {len(parts)} children")
        return Policy(op="threshold", children=tuple(parts), k=k)


def parse_policy(text: str) -> Policy:
    """Parse policy text into a canonical frozen ``Policy`` tree."""
    return _Parser(_tokenize(text)).parse()


def policy_satisfied(policy: Policy, attributes: FrozenSet[str]) -> bool:
    """Pure satisfaction check: do the attributes satisfy the policy?"""
    if not isinstance(policy, Policy):
        raise TypeError(
            f"policy must be Policy, got {type(policy).__name__}")
    if not isinstance(attributes, frozenset):
        raise TypeError("attributes must be a frozenset of str")
    if policy.op == "atom":
        return policy.name in attributes
    if policy.op == "and":
        return all(policy_satisfied(c, attributes) for c in policy.children)
    if policy.op == "or":
        return any(policy_satisfied(c, attributes) for c in policy.children)
    # threshold
    hits = sum(1 for c in policy.children
               if policy_satisfied(c, attributes))
    return hits >= policy.k


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------

def _pin(*parts: bytes) -> str:
    return "sha256:" + hashlib.sha256(b"".join(parts)).hexdigest()


@dataclass(frozen=True)
class PublicParams:
    """Frozen public parameters minted by ``ABE.setup()``."""
    params_id: str
    version: str = ABE_VERSION

    def __post_init__(self) -> None:
        if not self.params_id.startswith("sha256:"):
            raise ABEError("params_id must be a sha256: pin")
        if self.version != ABE_VERSION:
            raise ABEError(f"version mismatch: {self.version!r}")

    def as_dict(self) -> Dict[str, Any]:
        return {"params_id": self.params_id,
                "version": self.version,
                "schema": SCHEMA_PIN}


@dataclass(frozen=True)
class SecretKey:
    """Frozen secret key bound to an attribute set."""
    key_id: str
    attributes: FrozenSet[str]
    params_id: str
    version: str = ABE_VERSION

    def __post_init__(self) -> None:
        if not self.key_id.startswith("sha256:"):
            raise ABEError("key_id must be a sha256: pin")
        if not self.params_id.startswith("sha256:"):
            raise ABEError("params_id must be a sha256: pin")
        if not self.attributes:
            raise ABEError("key must carry attributes")
        for a in self.attributes:
            _check_attribute(a)
        if self.version != ABE_VERSION:
            raise ABEError(f"version mismatch: {self.version!r}")

    def as_dict(self) -> Dict[str, Any]:
        return {"key_id": self.key_id,
                "attributes": sorted(self.attributes),
                "params_id": self.params_id,
                "version": self.version,
                "schema": SCHEMA_PIN}


@dataclass(frozen=True)
class Ciphertext:
    """Frozen ciphertext: policy pin + wrapped blob + data digest."""
    ct_id: str
    policy: Policy
    policy_digest: str
    blob: bytes
    data_digest: str
    params_id: str
    version: str = ABE_VERSION

    def __post_init__(self) -> None:
        for name in ("ct_id", "policy_digest", "data_digest", "params_id"):
            val = getattr(self, name)
            if not val.startswith("sha256:"):
                raise ABEError(f"{name} must be a sha256: pin")
        if not isinstance(self.policy, Policy):
            raise TypeError("policy must be Policy")
        if not isinstance(self.blob, bytes) or isinstance(self.blob, bool):
            raise TypeError("blob must be bytes")
        if self.version != ABE_VERSION:
            raise ABEError(f"version mismatch: {self.version!r}")

    def as_dict(self) -> Dict[str, Any]:
        return {"ct_id": self.ct_id,
                "policy": self.policy.to_string(),
                "policy_digest": self.policy_digest,
                "blob_hex": self.blob.hex(),
                "data_digest": self.data_digest,
                "params_id": self.params_id,
                "version": self.version,
                "schema": SCHEMA_PIN}


# ---------------------------------------------------------------------------
# The authority
# ---------------------------------------------------------------------------

class ABE:
    """Attribute-based encryption authority (simulated).

    ``setup()`` mints the master secret; ``keygen`` issues attribute
    keys; ``encrypt`` wraps data under a policy; ``decrypt`` unwraps
    only for satisfying keys. All state is in-memory.
    """

    def __init__(self) -> None:
        self._nonce = next(_instance_counter)
        self._master_secret: bytes | None = None
        self._params_id: str | None = None
        self._keys: Dict[str, SecretKey] = {}
        self._cts: Dict[str, Ciphertext] = {}
        self._nonces: Dict[str, bytes] = {}
        self._ct_counter = itertools.count(1)

    # -- setup ---------------------------------------------------------
    def setup(self) -> PublicParams:
        """Mint the master secret; return frozen public parameters."""
        if self._master_secret is not None:
            raise ABEError("setup() already called on this instance")
        nonce = self._nonce.to_bytes(8, "big")
        self._master_secret = hashlib.sha256(_SETUP_DOMAIN + nonce).digest()
        self._params_id = _pin(_SETUP_DOMAIN, nonce, self._master_secret)
        return PublicParams(params_id=self._params_id)

    def _require_setup(self) -> bytes:
        if self._master_secret is None or self._params_id is None:
            raise ABEError("call setup() before keygen/encrypt/decrypt")
        return self._master_secret

    # -- keygen --------------------------------------------------------
    def keygen(self, attributes: Sequence[str]) -> SecretKey:
        """Issue a secret key bound to an attribute set."""
        secret = self._require_setup()
        attrs = _check_attributes(attributes)
        assert self._params_id is not None
        key_id = _pin(secret, b"|key|",
                      "|".join(sorted(attrs)).encode("utf-8"))
        key = SecretKey(key_id=key_id, attributes=attrs,
                        params_id=self._params_id)
        self._keys[key_id] = key
        return key

    # -- encrypt -------------------------------------------------------
    def _keystream(self, ct_nonce: bytes, n: int) -> bytes:
        secret = self._require_setup()
        out = b""
        counter = 0
        while len(out) < n:
            out += hashlib.sha256(
                _WRAP_DOMAIN + secret + ct_nonce
                + counter.to_bytes(8, "big")).digest()
            counter += 1
        return out[:n]

    def encrypt(self, policy: Union[str, Policy], data: bytes) -> Ciphertext:
        """Wrap ``data`` under ``policy``; return a frozen ciphertext."""
        self._require_setup()
        if isinstance(policy, str):
            policy = parse_policy(policy)
        elif not isinstance(policy, Policy):
            raise TypeError(
                f"policy must be str or Policy, got "
                f"{type(policy).__name__}")
        policy = _canon_policy(policy)
        if not isinstance(data, bytes) or isinstance(data, bool):
            raise TypeError(
                f"data must be bytes, got {type(data).__name__}")
        if len(data) > MAX_DATA_BYTES:
            raise ValueError(
                f"data too large ({len(data)} > {MAX_DATA_BYTES})")
        assert self._params_id is not None
        ct_seq = next(self._ct_counter)
        ct_nonce = ct_seq.to_bytes(8, "big")
        ct_id = _pin(self._params_id.encode("utf-8"), b"|ct|", ct_nonce)
        blob = bytes(b ^ k for b, k in
                     zip(data, self._keystream(ct_nonce, len(data))))
        policy_text = policy.to_string().encode("utf-8")
        ct = Ciphertext(
            ct_id=ct_id,
            policy=policy,
            policy_digest=_pin(b"|policy|", policy_text),
            blob=blob,
            data_digest=_pin(b"|data|", data),
            params_id=self._params_id,
        )
        self._cts[ct_id] = ct
        self._nonces[ct_id] = ct_nonce
        return ct

    # -- decrypt -------------------------------------------------------
    def decrypt(self, key: SecretKey, ciphertext: Ciphertext) -> bytes:
        """Unwrap iff the key satisfies the policy and both are ours."""
        self._require_setup()
        if not isinstance(key, SecretKey):
            raise TypeError(
                f"key must be SecretKey, got {type(key).__name__}")
        if not isinstance(ciphertext, Ciphertext):
            raise TypeError(
                f"ciphertext must be Ciphertext, got "
                f"{type(ciphertext).__name__}")
        if key.key_id not in self._keys:
            raise UnknownKeyError("key was not issued by this instance")
        if key.params_id != self._params_id:
            raise UnknownKeyError("key belongs to a different setup")
        stored = self._cts.get(ciphertext.ct_id)
        if stored is None:
            raise UnknownCiphertextError(
                "ciphertext was not minted by this instance")
        if stored != ciphertext:
            # A forged or mutated record naming one of our ids.
            raise CiphertextIntegrityError(
                "ciphertext does not match the minted record")
        if not policy_satisfied(ciphertext.policy, key.attributes):
            raise PolicyNotSatisfiedError(
                f"attributes {sorted(key.attributes)} do not satisfy "
                f"{ciphertext.policy.to_string()!r}")
        data = self._unwrap(ciphertext)
        if _pin(b"|data|", data) != ciphertext.data_digest:
            raise CiphertextIntegrityError(
                "unwrapped data does not match pinned digest")
        if not hmac.compare_digest(
                ciphertext.policy_digest,
                _pin(b"|policy|",
                     ciphertext.policy.to_string().encode("utf-8"))):
            raise CiphertextIntegrityError("policy pin mismatch")
        return data

    def _unwrap(self, ciphertext: Ciphertext) -> bytes:
        nonce = self._nonces.get(ciphertext.ct_id)
        if nonce is None:
            raise UnknownCiphertextError("ct_id not reproducible")
        ks = self._keystream(nonce, len(ciphertext.blob))
        return bytes(b ^ k for b, k in zip(ciphertext.blob, ks))

    # -- views ---------------------------------------------------------
    def issued_keys(self) -> Tuple[str, ...]:
        """Key ids issued by this instance (audit view)."""
        return tuple(sorted(self._keys))

    def minted_ciphertexts(self) -> Tuple[str, ...]:
        """Ciphertext ids minted by this instance (audit view)."""
        return tuple(sorted(self._cts))


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------

def abe_audit_event(kind: str, seq: int,
                    key: SecretKey | None = None,
                    ciphertext: Ciphertext | None = None,
                    satisfied: bool | None = None
                    ) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for ABE decisions."""
    if kind not in _KIND_VOCABULARY:
        raise ValueError(f"unknown kind: {kind!r}")
    _check_seq(seq, "seq")
    event: Dict[str, Any] = {
        "schema": "audit.ndjson/1",
        "module": SCHEMA_PIN,
        "kind": kind,
        "audit_seq": seq,
    }
    if key is not None:
        if not isinstance(key, SecretKey):
            raise TypeError(
                f"key must be SecretKey, got {type(key).__name__}")
        event["key_id"] = key.key_id
        event["attributes"] = sorted(key.attributes)
    if ciphertext is not None:
        if not isinstance(ciphertext, Ciphertext):
            raise TypeError(
                f"ciphertext must be Ciphertext, got "
                f"{type(ciphertext).__name__}")
        event["ct_id"] = ciphertext.ct_id
        event["policy"] = ciphertext.policy.to_string()
    if satisfied is not None:
        if not isinstance(satisfied, bool):
            raise TypeError(
                f"satisfied must be bool, got {type(satisfied).__name__}")
        event["satisfied"] = satisfied
    return event


def main() -> None:
    abe = ABE()
    params = abe.setup()
    assert params.version == ABE_VERSION
    key = abe.keygen(["clearance:top-secret", "team:alpha"])
    ct = abe.encrypt("clearance:top-secret & team:alpha", b"launch codes")
    assert abe.decrypt(key, ct) == b"launch codes"
    weak = abe.keygen(["team:alpha"])
    try:
        abe.decrypt(weak, ct)
    except PolicyNotSatisfiedError:
        pass
    else:
        raise AssertionError("unsatisfied key decrypted")
    ev = abe_audit_event(_DECRYPTED, 1, key=key, ciphertext=ct,
                         satisfied=True)
    assert ev["schema"] == "audit.ndjson/1"
    print("abe-interface OK: setup, keygen, encrypt, policy-gated decrypt")


if __name__ == "__main__":
    main()
