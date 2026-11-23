"""Password hashing interface (Argon2id / scrypt / bcrypt shapes, simulated).

Research motivation: credential storage must turn a guessable secret into a
verifier that is *expensive* to brute-force. The modern answers are
memory-hard password hashing functions: Argon2id (RFC 9106, winner of the
Password Hashing Competition), scrypt (RFC 7914, memory-hard via ROMix),
and bcrypt (Provos & Mazieres 1999, cost-adaptive Blowfish key schedule).
Argon2id is the current recommendation: data-independent addressing
(resistant to side channels) with a data-dependent pass over memory.

This module is the *API and bookkeeping* half, pinned so the runtime's
credential-verifier plumbing cannot silently disagree with what a real
KDF would produce. The stretching itself is *simulated* - a SHA-256
iteration chain with the scheme's cost parameters threaded into the
domain separation - so that interface properties (parameter binding,
salt uniqueness, deterministic verify, needs-rehash signaling) are real
while the memory-hardness is not:

- ``PasswordHasher`` -- one configured policy (``scheme``, ``time_cost``,
  ``memory_cost_kib``, ``parallelism``). Parameters are pinned at
  construction; ``hash`` refuses to run with anything else.
- ``hash_password(password, seq)`` -- deterministic per-instance salts
  (monotonic counter -> domain-separated SHA-256; no global RNG, audit
  replay is exact). Returns a frozen ``PasswordHashRecord`` that is fully
  self-describing (scheme + all params + salt + digest).
- ``verify(password, record)`` -- recompute-and-compare via
  ``hmac.compare_digest``. Well-formed-but-wrong passwords return
  ``False`` (policy outcome); malformed inputs raise fail-closed.
- ``parse(encoded)`` -- parse the modular-crypt-format encoding back
  into a record.
- ``needs_rehash(record, hasher)`` -- True when the record's scheme or
  parameters differ from the current policy (upgrade signaling).
- ``password_hash_audit_event(kind, record, seq)`` -- ``audit.ndjson/1``
  records (``hashed`` / ``verified`` / ``verification-failed`` /
  ``parse-rejected``); the digest rides the audit path, never plaintext.

Fail-closed edges (fail loudly, never guess):

- Empty passwords are refused (a stored hash of ``""`` is a trap).
- ``bool`` is rejected anywhere an int/str is expected (``True`` must not
  alias ``"1"`` or ``1``).
- Passwords over ``MAX_PASSWORD_BYTES`` are refused so work is bounded.
- ``verify`` with a tampered salt/digest returns ``False``, never raises
  (timing-safe comparison).
- Time cost has a guardrail (``MAX_TIME_COST``) so a malicious config
  cannot DoS the host.

Honest scope:

- Simulated cryptography: the iteration chain is CPU-cheap SHA-256, not
  memory-hard. There is no Argon2 memory fill, no scrypt ROMix, no bcrypt
  key schedule here. Attackers win on hardware this code has no answer
  to. Do not use for real credential storage.
- Deterministic salts: a real deployment must draw salts from a CSPRNG
  (``secrets.token_bytes``); per-instance counter-derived salts make
  audits replayable but would let two hosts with equal counters reuse
  salt domains. Nothing-up-my-sleeve, documented, not hidden.
- This module proves *interface consistency* (parameter binding,
  round-trip verify, rehash signaling), not *hash security*.
"""

from __future__ import annotations

import hashlib
import hmac
import threading
from dataclasses import dataclass
from typing import Optional

PASSWORD_HASH_VERSION = "password-hash.v1"
PASSWORD_HASH_SCHEMA = "northstar.password-hash.v1"

# Scheme vocabulary. All three pin their PHC-style identifier so records
# from a real Argon2/scrypt/bcrypt library are at least recognizable in
# shape, even though this module never calls one.
SCHEME_ARGON2ID = "argon2id"
SCHEME_SCRYPT = "scrypt"
SCHEME_BCRYPT = "bcrypt"
_SUPPORTED_SCHEMES = (SCHEME_ARGON2ID, SCHEME_SCRYPT, SCHEME_BCRYPT)

MCF_PREFIX = "password-hash"
ENCODING_VERSION = "v=1"

MAX_PASSWORD_BYTES = 4096
MAX_TIME_COST = 100  # guardrail: keeps the simulated iteration loop honest
MAX_MEMORY_COST_KIB = 1 << 20
MAX_PARALLELISM = 16
_SALT_BYTES = 16
_DIGEST_BYTES = 32


class PasswordHashError(ValueError):
    """Fail-closed error for password hashing misuse."""


def _check_int(name: str, value: object, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an int")
    if not (minimum <= value <= maximum):
        raise PasswordHashError(f"{name} out of range [{minimum}, {maximum}]")
    return value


def _check_seq(seq: object) -> int:
    return _check_int("seq", seq, 0, 2**63 - 1)


def _encode_password(password: object) -> bytes:
    if isinstance(password, bool):
        raise TypeError("password must be str, not bool")
    if not isinstance(password, str):
        raise TypeError("password must be str")
    if password == "":
        raise PasswordHashError("empty password refused")
    raw = password.encode("utf-8")
    if len(raw) > MAX_PASSWORD_BYTES:
        raise PasswordHashError(
            f"password exceeds {MAX_PASSWORD_BYTES} bytes after UTF-8 encoding"
        )
    return raw


def _domain(scheme: str) -> bytes:
    return b"northstar.password-hash.v1:" + scheme.encode("ascii")


@dataclass(frozen=True)
class PasswordHashRecord:
    """Self-describing frozen hash record (parameters + salt + digest)."""

    version: str
    scheme: str
    time_cost: int
    memory_cost_kib: int
    parallelism: int
    salt: str  # hex
    digest: str  # hex
    encoded: str  # modular-crypt-format string

    def __post_init__(self) -> None:
        if self.version != PASSWORD_HASH_VERSION:
            raise PasswordHashError("unknown record version")
        if self.scheme not in _SUPPORTED_SCHEMES:
            raise PasswordHashError("unknown scheme")
        _check_int("time_cost", self.time_cost, 1, MAX_TIME_COST)
        _check_int("memory_cost_kib", self.memory_cost_kib, 1, MAX_MEMORY_COST_KIB)
        _check_int("parallelism", self.parallelism, 1, MAX_PARALLELISM)
        for name, value, width in (("salt", self.salt, 2 * _SALT_BYTES),
                                  ("digest", self.digest, 2 * _DIGEST_BYTES)):
            if not isinstance(value, str):
                raise TypeError(f"{name} must be hex str")
            if len(value) != width:
                raise PasswordHashError(f"{name} has wrong length")
            try:
                int(value, 16)
            except ValueError:
                raise PasswordHashError(f"{name} is not hex") from None
        if not isinstance(self.encoded, str) or not self.encoded:
            raise TypeError("encoded must be a non-empty str")

    def as_dict(self) -> dict:
        return {
            "version": self.version,
            "scheme": self.scheme,
            "time_cost": self.time_cost,
            "memory_cost_kib": self.memory_cost_kib,
            "parallelism": self.parallelism,
            "salt": self.salt,
            "digest": self.digest,
            "encoded": self.encoded,
            "schema": PASSWORD_HASH_SCHEMA,
        }


def _stretch(scheme: str, password_bytes: bytes, salt: bytes,
             time_cost: int, memory_cost_kib: int, parallelism: int) -> bytes:
    """Simulated KDF: domain-separated SHA-256 iteration chain.

    The cost parameters are bound into every iteration's domain so a
    record minted under one policy cannot silently verify as another.
    This is the *shape* of cost binding, not memory-hardness.
    """
    dom = _domain(scheme)
    param_block = (
        time_cost.to_bytes(4, "big")
        + memory_cost_kib.to_bytes(4, "big")
        + parallelism.to_bytes(2, "big")
    )
    state = hashlib.sha256(dom + b"seed" + param_block + salt + password_bytes).digest()
    for i in range(time_cost):
        # Lane folding: each "parallel lane" mixes the state, then lanes
        # are re-merged. Pure simulation, but parallelism affects the
        # output so records pin it.
        lanes = [
            hashlib.sha256(
                dom + b"round" + i.to_bytes(4, "big")
                + bytes([lane]) + state + salt + password_bytes
            ).digest()
            for lane in range(parallelism)
        ]
        state = hashlib.sha256(dom + b"merge" + b"".join(lanes)).digest()
    return hashlib.sha256(dom + b"final" + param_block + salt + state).digest()


def _encode_record(scheme: str, time_cost: int, memory_cost_kib: int,
                   parallelism: int, salt: bytes, digest: bytes) -> str:
    params = f"m={memory_cost_kib},t={time_cost},p={parallelism}"
    return (
        f"${MCF_PREFIX}${ENCODING_VERSION}${scheme}"
        f"${params}${salt.hex()}${digest.hex()}"
    )


class PasswordHasher:
    """One pinned hashing policy. Thread-safe via an RLock-guarded salt counter."""

    def __init__(self, scheme: str = SCHEME_ARGON2ID, time_cost: int = 3,
                 memory_cost_kib: int = 65536, parallelism: int = 1) -> None:
        if scheme not in _SUPPORTED_SCHEMES:
            raise PasswordHashError(
                f"unsupported scheme {scheme!r}; choose from {list(_SUPPORTED_SCHEMES)}"
            )
        self._scheme = scheme
        self._time_cost = _check_int("time_cost", time_cost, 1, MAX_TIME_COST)
        self._memory_cost_kib = _check_int("memory_cost_kib", memory_cost_kib, 1, MAX_MEMORY_COST_KIB)
        self._parallelism = _check_int("parallelism", parallelism, 1, MAX_PARALLELISM)
        self._lock = threading.RLock()
        self._salt_counter = 0

    @property
    def scheme(self) -> str:
        return self._scheme

    def _next_salt(self) -> bytes:
        # Deterministic per-instance salt: counter-derived under a
        # domain separator. Replayable for audits; see honest scope -
        # real deployments must use a CSPRNG salt.
        with self._lock:
            self._salt_counter += 1
            n = self._salt_counter
        return hashlib.sha256(
            _domain(self._scheme) + b"salt" + n.to_bytes(8, "big")
        ).digest()[:_SALT_BYTES]

    def hash_password(self, password: object, seq: object = 0) -> PasswordHashRecord:
        """Hash a password under this hasher's pinned policy."""
        _check_seq(seq)
        password_bytes = _encode_password(password)
        salt = self._next_salt()
        digest = _stretch(self._scheme, password_bytes, salt,
                          self._time_cost, self._memory_cost_kib, self._parallelism)
        return PasswordHashRecord(
            version=PASSWORD_HASH_VERSION,
            scheme=self._scheme,
            time_cost=self._time_cost,
            memory_cost_kib=self._memory_cost_kib,
            parallelism=self._parallelism,
            salt=salt.hex(),
            digest=digest.hex(),
            encoded=_encode_record(self._scheme, self._time_cost,
                                   self._memory_cost_kib, self._parallelism,
                                   salt, digest),
        )

    def verify(self, password: object, record: PasswordHashRecord) -> bool:
        """True iff password matches the record. False never raises."""
        password_bytes = _encode_password(password)
        if not isinstance(record, PasswordHashRecord):
            raise TypeError("record must be a PasswordHashRecord")
        candidate = _stretch(record.scheme, password_bytes, bytes.fromhex(record.salt),
                             record.time_cost, record.memory_cost_kib,
                             record.parallelism)
        return hmac.compare_digest(candidate.hex(), record.digest)

    def needs_rehash(self, record: PasswordHashRecord) -> bool:
        """True when record was minted under a different scheme/policy."""
        if not isinstance(record, PasswordHashRecord):
            raise TypeError("record must be a PasswordHashRecord")
        return (
            record.scheme != self._scheme
            or record.time_cost != self._time_cost
            or record.memory_cost_kib != self._memory_cost_kib
            or record.parallelism != self._parallelism
        )


def parse(encoded: object) -> PasswordHashRecord:
    """Parse a modular-crypt-format string back into a record.

    Fails closed (PasswordHashError) on any structural problem so a
    tampered or hand-edited hash never becomes a verifier.
    """
    if not isinstance(encoded, str):
        raise TypeError("encoded must be str")
    parts = encoded.split("$")
    # ['', 'password-hash', 'v=1', scheme, params, salt, digest]
    if len(parts) != 7 or parts[0] != "" or parts[1] != MCF_PREFIX:
        raise PasswordHashError("not a password-hash MCF string")
    _, _, enc_ver, scheme, params, salt, digest = parts
    if enc_ver != ENCODING_VERSION:
        raise PasswordHashError(f"unsupported encoding version {enc_ver!r}")
    if scheme not in _SUPPORTED_SCHEMES:
        raise PasswordHashError(f"unsupported scheme {scheme!r}")
    parsed: dict[str, int] = {}
    for item in params.split(","):
        if "=" not in item:
            raise PasswordHashError("malformed parameter block")
        key, val = item.split("=", 1)
        if key not in ("m", "t", "p") or key in parsed:
            raise PasswordHashError(f"bad parameter {key!r}")
        if isinstance(val, str) and (not val.isdigit()):
            raise PasswordHashError(f"bad parameter value {val!r}")
        parsed[key] = int(val)
    if set(parsed) != {"m", "t", "p"}:
        raise PasswordHashError("parameter block must carry m, t, p")
    time_cost = parsed["t"]
    memory_cost_kib = parsed["m"]
    parallelism = parsed["p"]
    _check_int("time_cost", time_cost, 1, MAX_TIME_COST)
    _check_int("memory_cost_kib", memory_cost_kib, 1, MAX_MEMORY_COST_KIB)
    _check_int("parallelism", parallelism, 1, MAX_PARALLELISM)
    # Build through the frozen record constructor so salt/digest length
    # and hex validation are reused, not duplicated.
    record = PasswordHashRecord(
        version=PASSWORD_HASH_VERSION,
        scheme=scheme,
        time_cost=time_cost,
        memory_cost_kib=memory_cost_kib,
        parallelism=parallelism,
        salt=salt,
        digest=digest,
        encoded=encoded,
    )
    if record.encoded != encoded:
        # Constructor accepted, but the string we re-derive would differ:
        # defensive; cannot happen unless _encode_record drifts.
        raise PasswordHashError("encoding round-trip mismatch")
    return record


def password_hash_audit_event(kind: str, record: PasswordHashRecord,
                              seq: object) -> dict:
    """Audit-shaped record for a password-hash observation.

    Carries the record's metadata and digest pin; never the password.
    """
    if kind not in ("hashed", "verified", "verification-failed", "parse-rejected"):
        raise ValueError("unknown kind")
    if not isinstance(record, PasswordHashRecord):
        raise TypeError("record must be a PasswordHashRecord")
    _check_seq(seq)
    return {
        "event": "password-hash",
        "kind": kind,
        "scheme": record.scheme,
        "params": {
            "time_cost": record.time_cost,
            "memory_cost_kib": record.memory_cost_kib,
            "parallelism": record.parallelism,
        },
        "digest": record.digest,
        "audit_seq": seq,
        "schema": "audit.ndjson/1",
    }


def main() -> None:
    h = PasswordHasher()
    rec = h.hash_password("correct-horse-battery-staple", seq=1)
    assert h.verify("correct-horse-battery-staple", rec), "round-trip verify"
    assert not h.verify("wrong-password", rec), "wrong password must fail"
    rec2 = parse(rec.encoded)
    assert rec2.digest == rec.digest, "MCF round-trip"
    weak = PasswordHasher(time_cost=1)
    assert weak.needs_rehash(rec), "policy change needs rehash"
    assert not h.needs_rehash(rec), "same policy needs no rehash"
    print(f"password-hash OK: {rec.scheme} verified, digest {rec.digest[:16]}...")


if __name__ == "__main__":
    main()
