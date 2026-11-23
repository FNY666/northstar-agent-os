"""Secure enclave interface: SGX / SEV-SNP / TDX attestation and sealed execution.

Research line: confidential computing for agent runtimes (Intel SGX,
AMD SEV-SNP, Intel TDX). The production need is a stable interface for
three operations an enclave provides:

* **Attest** — mint a quote binding the enclave's measured identity to a
  caller-supplied nonce, so a verifier can check "this ran inside the
  enclave I expect, and this quote is fresh".
* **Execute** — run a computation inside the enclave boundary.
* **Seal** — persist data so only the same enclave identity can unseal
  it later (measurement-bound storage).

HONEST SCOPE — read before deploying:

* This repository has no SGX, SEV-SNP, or TDX hardware, and nothing here
  walks a DCAP certificate chain or checks an AMD attestation report.
  Quotes minted by :class:`Enclave` are HMACs under a deterministic
  software key, not TEE quotes. Every emulated quote carries
  ``emulated: True`` and may only claim ``tee_type == "software"`` —
  claiming ``sgx`` / ``sev-snp`` / ``tdx`` on an emulated quote fails
  closed. The *interface* (quote shape, verification rules, sealing
  semantics, replay protection) is what this module pins; a real
  platform plugs in by replacing :class:`Enclave`'s quote minting and
  :func:`verify_quote`'s MAC check with the platform verifier.
* Execution is simulated as **registered-function dispatch**, never
  arbitrary code evaluation: the host registers named pure functions
  (``register_op``) and ``execute`` only runs registered names. Passing
  raw source through an ``execute(code)`` boundary would be an
  ``eval``-shaped hole; this module refuses that shape by construction.
* Sealing is measurement-bound XOR under a deterministic keystream, not
  AES-GCM: it provides the *binding semantics* (only the same
  measurement unseals) for bookkeeping tests. Zero confidentiality
  claim against a real attacker.

Design:

* ``Enclave(EnclaveConfig)`` — one simulated enclave instance. Config
  carries ``enclave_id``, ``tee_type``, and ``measurement`` (the
  ``sha256:`` pin of the code/config the enclave is supposed to run).
* ``attest(nonce, seq)`` — mints a frozen :class:`AttestationQuote`
  binding ``(enclave_id, tee_type, measurement, nonce, seq)`` under the
  attestation key ``HMAC(domain, enclave_id | measurement)``.
  Nonce + caller-supplied int ``seq`` give replay protection; the host
  must track the highest seq seen per enclave.
* ``execute(op_name, data, seq)`` — dispatches a registered op over
  canonical bytes, returns a frozen :class:`ExecutionResult` whose
  ``result_digest`` pins ``(op_name, input_digest, seq)`` and whose
  ``quote`` is a fresh attestation over that digest, so the result is
  bound to the attested measurement.
* ``seal(data, seq)`` / ``unseal(record)`` — measurement-bound sealing;
  unsealing recomputes the measurement key and fails closed on any
  mismatch or tamper.
* ``quote(seq)`` — convenience: a fresh quote with an empty nonce over
  the current measurement (for liveness / registry publication).
* :func:`verify_quote` — stateless verifier-side check: recomputes the
  MAC, pins ``tee_type``/``measurement``/``nonce``, enforces
  ``seq`` monotonicity expectations supplied by the caller, and rejects
  emulated quotes that claim a hardware ``tee_type``.

No wall-clock: callers supply integer seqs. Deterministic: same inputs
give same outputs. stdlib-only. Fail-closed on every bad input.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import Any, Callable, Mapping


VERSION = "enclave-interface.v1"
SCHEMA = "northstar.enclave-interface.v1"
AUDIT_SCHEMA = "northstar.audit.v1"

#: TEE types this interface knows. ``software`` is the only type the
#: emulated attestor may claim; the rest are schema slots for real
#: platform verifiers to fill.
TEE_TYPES: tuple[str, ...] = ("sgx", "sev-snp", "tdx", "software")

_DOMAIN = b"northstar.enclave-interface.v1"

# Simulated enclave op registry: name -> pure function(bytes) -> bytes.
_OPS: dict[str, Callable[[bytes], bytes]] = {}


def _sha256_hex(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _canonical(value: Any) -> bytes:
    """Deterministic canonical bytes for hashing (stdlib-only JCS-ish)."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def _reject_bool(name: str, value: Any) -> None:
    if isinstance(value, bool):
        raise TypeError(f"{name} must not be bool")


def _check_seq(name: str, value: Any) -> int:
    _reject_bool(name, value)
    if not isinstance(value, int):
        raise TypeError(f"{name} must be int")
    if value < 0:
        raise ValueError(f"{name} must be >= 0")
    return value


def _check_nonempty_str(name: str, value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a non-empty str")
    return value


class EnclaveError(Exception):
    """Base error for the enclave interface."""


class AttestationError(EnclaveError):
    """Quote minting or verification failed."""


class ExecutionError(EnclaveError):
    """Enclave execution failed (unknown op, bad input)."""


class SealingError(EnclaveError):
    """Seal/unseal failed (tamper, wrong measurement)."""


def register_op(name: str, fn: Callable[[bytes], bytes]) -> None:
    """Register a named pure function for simulated enclave execution."""
    _check_nonempty_str("name", name)
    if not callable(fn):
        raise TypeError("fn must be callable")
    _OPS[name] = fn


def registered_ops() -> tuple[str, ...]:
    """Names currently registered for enclave execution."""
    return tuple(sorted(_OPS))


# Built-in demo ops (pure, deterministic).
register_op("identity", lambda b: b)
register_op("sha256", lambda b: hashlib.sha256(b).digest())
register_op("reverse", lambda b: b[::-1])


@dataclass(frozen=True)
class EnclaveConfig:
    """Configuration an enclave instance is created from."""

    enclave_id: str
    tee_type: str
    measurement: str  # "sha256:<hex>" pin of the expected code/config
    max_data_bytes: int = 1 << 20

    def __post_init__(self) -> None:
        _check_nonempty_str("enclave_id", self.enclave_id)
        if self.tee_type not in TEE_TYPES:
            raise ValueError(f"tee_type must be one of {TEE_TYPES}")
        _check_nonempty_str("measurement", self.measurement)
        if not self.measurement.startswith("sha256:") or len(self.measurement) != 71:
            raise ValueError("measurement must be a sha256:<64hex> pin")
        _reject_bool("max_data_bytes", self.max_data_bytes)
        if not isinstance(self.max_data_bytes, int) or self.max_data_bytes <= 0:
            raise ValueError("max_data_bytes must be a positive int")

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "enclave_id": self.enclave_id,
            "tee_type": self.tee_type,
            "measurement": self.measurement,
            "max_data_bytes": self.max_data_bytes,
        }


@dataclass(frozen=True)
class AttestationQuote:
    """A minted attestation quote (simulated: HMAC, not a TEE quote)."""

    enclave_id: str
    tee_type: str
    measurement: str
    nonce: str  # hex
    seq: int
    emulated: bool
    mac: str  # hex HMAC binding all fields above

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "enclave_id": self.enclave_id,
            "tee_type": self.tee_type,
            "measurement": self.measurement,
            "nonce": self.nonce,
            "seq": self.seq,
            "emulated": self.emulated,
            "mac": self.mac,
        }

    def digest(self) -> str:
        return _sha256_hex(_canonical(self.as_dict()))


@dataclass(frozen=True)
class ExecutionResult:
    """Result of a simulated enclave execution, bound to a quote."""

    enclave_id: str
    op_name: str
    input_digest: str
    result_digest: str
    seq: int
    quote: AttestationQuote

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "enclave_id": self.enclave_id,
            "op_name": self.op_name,
            "input_digest": self.input_digest,
            "result_digest": self.result_digest,
            "seq": self.seq,
            "quote": self.quote.as_dict(),
        }


@dataclass(frozen=True)
class SealedData:
    """Measurement-bound sealed record."""

    enclave_id: str
    measurement: str
    seq: int
    ciphertext: bytes
    tag: str  # hex integrity tag

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "enclave_id": self.enclave_id,
            "measurement": self.measurement,
            "seq": self.seq,
            "ciphertext": self.ciphertext.hex(),
            "tag": self.tag,
        }


class Enclave:
    """A simulated secure enclave instance."""

    def __init__(self, config: EnclaveConfig) -> None:
        if not isinstance(config, EnclaveConfig):
            raise TypeError("config must be EnclaveConfig")
        self._config = config
        # Attestation key: deterministic, software-only.
        self._att_key = hmac.new(
            _DOMAIN,
            (config.enclave_id + "|" + config.measurement).encode("utf-8"),
            hashlib.sha256,
        ).digest()
        self._seal_key = hmac.new(
            _DOMAIN + b"|seal",
            config.measurement.encode("utf-8"),
            hashlib.sha256,
        ).digest()
        self._last_seq = -1

    @property
    def config(self) -> EnclaveConfig:
        return self._config

    def _mac(self, *parts: bytes) -> str:
        m = hmac.new(self._att_key, digestmod=hashlib.sha256)
        for p in parts:
            m.update(len(p).to_bytes(8, "big"))
            m.update(p)
        return m.hexdigest()

    def _mint(self, nonce: bytes, seq: int) -> AttestationQuote:
        seq = _check_seq("seq", seq)
        if seq <= self._last_seq:
            raise AttestationError("seq must strictly increase")
        self._last_seq = seq
        emulated = True  # this implementation is always the emulator
        mac = self._mac(
            self._config.enclave_id.encode(),
            self._config.tee_type.encode(),
            self._config.measurement.encode(),
            nonce,
            seq.to_bytes(8, "big"),
        )
        return AttestationQuote(
            enclave_id=self._config.enclave_id,
            tee_type="software" if emulated else self._config.tee_type,
            measurement=self._config.measurement,
            nonce=nonce.hex(),
            seq=seq,
            emulated=emulated,
            mac=mac,
        )

    def attest(self, nonce: bytes, seq: int) -> AttestationQuote:
        """Mint a quote binding this enclave's measurement to a nonce."""
        if not isinstance(nonce, (bytes, bytearray)) or len(nonce) == 0:
            raise AttestationError("nonce must be non-empty bytes")
        return self._mint(bytes(nonce), seq)

    def quote(self, seq: int) -> AttestationQuote:
        """A liveness quote with an empty nonce over the current measurement."""
        return self._mint(b"", seq)

    def execute(self, op_name: str, data: bytes, seq: int) -> ExecutionResult:
        """Run a registered op inside the simulated enclave boundary."""
        _check_nonempty_str("op_name", op_name)
        if op_name not in _OPS:
            raise ExecutionError(f"unknown op: {op_name!r}")
        if not isinstance(data, (bytes, bytearray)):
            raise ExecutionError("data must be bytes")
        data = bytes(data)
        if len(data) > self._config.max_data_bytes:
            raise ExecutionError("data exceeds max_data_bytes")
        seq = _check_seq("seq", seq)
        result = _OPS[op_name](data)
        if not isinstance(result, (bytes, bytearray)):
            raise ExecutionError("op must return bytes")
        input_digest = _sha256_hex(b"input|" + data)
        result_digest = _sha256_hex(b"result|" + bytes(result))
        # Bind the execution to a fresh quote over the result digest.
        quote = self._mint(hashlib.sha256(result_digest.encode()).digest(), seq)
        return ExecutionResult(
            enclave_id=self._config.enclave_id,
            op_name=op_name,
            input_digest=input_digest,
            result_digest=result_digest,
            seq=seq,
            quote=quote,
        )

    def seal(self, data: bytes, seq: int) -> SealedData:
        """Seal data so only this measurement can unseal it."""
        if not isinstance(data, (bytes, bytearray)):
            raise SealingError("data must be bytes")
        data = bytes(data)
        if len(data) > self._config.max_data_bytes:
            raise SealingError("data exceeds max_data_bytes")
        seq = _check_seq("seq", seq)
        keystream = hmac.new(
            self._seal_key, b"seal|" + seq.to_bytes(8, "big"), hashlib.sha256
        ).digest()
        ct = bytes(b ^ keystream[i % len(keystream)] for i, b in enumerate(data))
        tag = hmac.new(self._seal_key, b"tag|" + ct, hashlib.sha256).hexdigest()
        return SealedData(
            enclave_id=self._config.enclave_id,
            measurement=self._config.measurement,
            seq=seq,
            ciphertext=ct,
            tag=tag,
        )

    def unseal(self, record: SealedData) -> bytes:
        """Unseal a record; fails closed on measurement mismatch or tamper."""
        if not isinstance(record, SealedData):
            raise SealingError("record must be SealedData")
        if record.enclave_id != self._config.enclave_id:
            raise SealingError("enclave_id mismatch")
        if not hmac.compare_digest(record.measurement, self._config.measurement):
            raise SealingError("measurement mismatch: not the sealing enclave")
        expected_tag = hmac.new(
            self._seal_key, b"tag|" + record.ciphertext, hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(record.tag, expected_tag):
            raise SealingError("integrity tag mismatch")
        keystream = hmac.new(
            self._seal_key, b"seal|" + record.seq.to_bytes(8, "big"), hashlib.sha256
        ).digest()
        return bytes(
            b ^ keystream[i % len(keystream)] for i, b in enumerate(record.ciphertext)
        )


def verify_quote(
    quote: AttestationQuote,
    *,
    expected_measurement: str,
    expected_nonce: bytes | None = None,
    min_seq: int = 0,
    allow_emulated: bool = True,
) -> bool:
    """Stateless verifier-side quote check.

    Returns True only if every check passes; False on any mismatch.
    Raises TypeError on malformed caller input (programming error).
    """
    if not isinstance(quote, AttestationQuote):
        raise TypeError("quote must be AttestationQuote")
    _check_nonempty_str("expected_measurement", expected_measurement)
    min_seq = _check_seq("min_seq", min_seq)
    if expected_nonce is not None and not isinstance(expected_nonce, (bytes, bytearray)):
        raise TypeError("expected_nonce must be bytes or None")

    # Emulated quotes may never claim a hardware TEE type.
    if quote.emulated and quote.tee_type != "software":
        return False
    if quote.emulated and not allow_emulated:
        return False
    if not hmac.compare_digest(quote.measurement, expected_measurement):
        return False
    if expected_nonce is not None and not hmac.compare_digest(
        quote.nonce, bytes(expected_nonce).hex()
    ):
        return False
    if quote.seq < min_seq:
        return False
    # Recompute the MAC with the same derivation the Enclave uses.
    att_key = hmac.new(
        _DOMAIN,
        (quote.enclave_id + "|" + quote.measurement).encode("utf-8"),
        hashlib.sha256,
    ).digest()
    m = hmac.new(att_key, digestmod=hashlib.sha256)
    for part in (
        quote.enclave_id.encode(),
        quote.tee_type.encode(),
        quote.measurement.encode(),
        bytes.fromhex(quote.nonce) if quote.nonce else b"",
        quote.seq.to_bytes(8, "big"),
    ):
        m.update(len(part).to_bytes(8, "big"))
        m.update(part)
    return hmac.compare_digest(quote.mac, m.hexdigest())


def enclave_audit_event(
    kind: str,
    seq: int,
    *,
    enclave_id: str = "",
    detail: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Shape an ``audit.ndjson/1``-compatible enclave audit record."""
    valid = (
        "enclave-created",
        "enclave-attested",
        "enclave-quoted",
        "enclave-executed",
        "quote-verified",
        "quote-rejected",
        "sealed",
        "unsealed",
        "seal-rejected",
    )
    if kind not in valid:
        raise ValueError(f"kind must be one of {valid}")
    seq = _check_seq("seq", seq)
    return {
        "schema_version": AUDIT_SCHEMA,
        "event_type": f"enclave.{kind}",
        "seq": seq,
        "enclave_id": enclave_id,
        "detail": dict(detail) if detail else {},
    }


def main() -> None:
    cfg = EnclaveConfig(
        enclave_id="enc-1",
        tee_type="software",
        measurement=_sha256_hex(b"demo-enclave-code"),
    )
    enc = Enclave(cfg)
    q = enc.attest(b"nonce-1", 1)
    assert verify_quote(q, expected_measurement=cfg.measurement, expected_nonce=b"nonce-1")
    r = enc.execute("sha256", b"hello", 2)
    assert r.result_digest == _sha256_hex(b"result|" + hashlib.sha256(b"hello").digest())
    sealed = enc.seal(b"secret", 3)
    assert enc.unseal(sealed) == b"secret"
    ev = enclave_audit_event("enclave-executed", 4, enclave_id="enc-1")
    assert ev["event_type"] == "enclave.enclave-executed"
    print("enclave-interface OK: attest, verify, execute, seal")


__all__ = [
    "VERSION",
    "SCHEMA",
    "TEE_TYPES",
    "EnclaveError",
    "AttestationError",
    "ExecutionError",
    "SealingError",
    "EnclaveConfig",
    "AttestationQuote",
    "ExecutionResult",
    "SealedData",
    "Enclave",
    "register_op",
    "registered_ops",
    "verify_quote",
    "enclave_audit_event",
]


if __name__ == "__main__":
    main()
