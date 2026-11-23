"""Secure enclave lifecycle registry: multi-enclave provisioning with
attestation-gated unsealing.

Research line: confidential computing (Intel SGX, AMD SEV-SNP, Intel
TDX) as a trust primitive for agent runtimes: a verifier wants "only the
expected code, attested fresh, may read this secret". The sibling module
``enclave_interface`` owns the *single-instance* primitive layer
(``Enclave.attest`` / ``Enclave.execute`` / ``Enclave.seal`` /
``verify_quote``). This module owns the *registry/lifecycle* layer none
of the siblings own:

* **Provision** — register one enclave identity (id, TEE type,
  measurement pin) under management.
* **Attest** — mint a fresh quote for a provisioned enclave and book
  the verifier-side verdict *as data* (``attested`` True/False with a
  pinned reason), never raised.
* **Seal** — book a seal declaration binding a data digest to an
  enclave's measurement. The actual sealed bytes are produced by the
  sibling emulator; the ledger keeps digest pins only.
* **Unseal** — authorization-gated release: only when a
  ``attested=True`` decision newer than the seal is booked. Books the
  authorization; raw plaintext never enters a record.
* **Retire** — terminally retire an enclave identity.

HONEST SCOPE — read before deploying:

* Simulated. No SGX/SEV-SNP/TDX hardware here; quotes are HMACs minted
  by the sibling software emulator, sealing is its measurement-bound
  XOR keystream. This module proves nothing about real hardware.
* A booked ``attested=True`` means "the ledger's emulator verified the
  quote pins", never "a real TEE measured this code".
* Booked decisions are the host's declarations (GIGO): the ledger
  cannot observe whether a real enclave exists.
* Raw nonces, plaintext, sealed bytes, and key material never enter
  records and never cross the audit boundary (digest pins only).

No wall-clock: callers supply integer seqs strictly increasing per
registry instance; failed mutations consume their seq and book a
``secure-enclave.rejected`` row; rewinds raise bare without consuming.
Deterministic: same inputs give same pins. RLock-guarded. stdlib-only
besides the in-repo sibling ``enclave_interface``. Fail-closed on every
bad input.
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass
from typing import Any, Mapping

from enclave_interface import (
    Enclave,
    EnclaveConfig,
    SealedData,
    verify_quote,
)

#: Module version.
VERSION = "secure-enclave.v1"

#: Schema pin for records produced by this module.
SCHEMA = "northstar.secure-enclave.v1"

#: Audit schema.
AUDIT_SCHEMA = "northstar.audit.v1"

#: TEE types this registry accepts (mirrors the sibling interface).
TEE_TYPES = ("sgx", "sev-snp", "tdx", "software")


def _sha256_hex(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _canonical(value: Any) -> bytes:
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


def _check_id(name: str, value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise BadIdError(f"{name} must be a non-empty str")
    return value


def _check_digest(name: str, value: Any) -> str:
    if not isinstance(value, str) or not value.startswith("sha256:"):
        raise BadMeasurementError(f"{name} must be a sha256:<hex> pin")
    return value


class SecureEnclaveError(Exception):
    """Base error for the secure enclave registry."""


class BadIdError(SecureEnclaveError):
    """Malformed enclave / seal / attestation id."""


class DuplicateEnclaveError(SecureEnclaveError):
    """Provisioning an id that is already provisioned."""


class UnknownEnclaveError(SecureEnclaveError):
    """No provisioned enclave under that id."""


class RetiredEnclaveError(SecureEnclaveError):
    """The enclave id was retired; ids are never recycled."""


class BadTeeTypeError(SecureEnclaveError):
    """Unknown TEE type."""


class BadMeasurementError(SecureEnclaveError):
    """Malformed measurement pin."""


class BadNonceError(SecureEnclaveError):
    """Malformed nonce."""


class BadLabelError(SecureEnclaveError):
    """Malformed seal label."""


class BadDataError(SecureEnclaveError):
    """Malformed seal payload."""


class UnknownSealError(SecureEnclaveError):
    """No booked seal under that id."""


class SealDeniedError(SecureEnclaveError):
    """Unseal refused: no fresh attested=True decision booked."""


class VerificationError(SecureEnclaveError):
    """A record's digest pin does not recompute."""


class SeqOrderError(SecureEnclaveError):
    """Caller seq did not strictly increase."""


class AuditKindError(SecureEnclaveError):
    """Unknown audit event kind."""


def _digest_pin(*fields: Any) -> str:
    return _sha256_hex(_canonical({"schema": SCHEMA, "fields": list(fields)}))


@dataclass(frozen=True)
class ProvisionRecord:
    """One provisioned enclave identity."""

    enclave_id: str
    tee_type: str
    measurement: str
    seq: int
    digest: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "enclave_id": self.enclave_id,
            "tee_type": self.tee_type,
            "measurement": self.measurement,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> None:
        want = _digest_pin(self.enclave_id, self.tee_type, self.measurement, self.seq)
        if want != self.digest:
            raise VerificationError("provision digest mismatch")


@dataclass(frozen=True)
class AttestationDecision:
    """A booked attestation verdict (data, never raised)."""

    att_id: str
    enclave_id: str
    nonce_digest: str
    attested: bool
    reason: str  # "" | "measurement-mismatch"
    quote_digest: str
    seq: int
    digest: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "att_id": self.att_id,
            "enclave_id": self.enclave_id,
            "nonce_digest": self.nonce_digest,
            "attested": self.attested,
            "reason": self.reason,
            "quote_digest": self.quote_digest,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> None:
        want = _digest_pin(
            self.att_id, self.enclave_id, self.nonce_digest,
            self.attested, self.reason, self.quote_digest, self.seq,
        )
        if want != self.digest:
            raise VerificationError("attestation digest mismatch")


@dataclass(frozen=True)
class SealRecord:
    """A booked seal declaration (digest pins only)."""

    seal_id: str
    enclave_id: str
    label: str
    data_digest: str
    tag: str
    ciphertext_digest: str
    seq: int
    digest: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "seal_id": self.seal_id,
            "enclave_id": self.enclave_id,
            "label": self.label,
            "data_digest": self.data_digest,
            "tag": self.tag,
            "ciphertext_digest": self.ciphertext_digest,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> None:
        want = _digest_pin(
            self.seal_id, self.enclave_id, self.label,
            self.data_digest, self.tag, self.ciphertext_digest, self.seq,
        )
        if want != self.digest:
            raise VerificationError("seal digest mismatch")


@dataclass(frozen=True)
class UnsealRecord:
    """A booked unseal authorization (plaintext never stored)."""

    unseal_id: str
    enclave_id: str
    seal_id: str
    plaintext_digest: str
    seq: int
    digest: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "unseal_id": self.unseal_id,
            "enclave_id": self.enclave_id,
            "seal_id": self.seal_id,
            "plaintext_digest": self.plaintext_digest,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> None:
        want = _digest_pin(
            self.unseal_id, self.enclave_id, self.seal_id,
            self.plaintext_digest, self.seq,
        )
        if want != self.digest:
            raise VerificationError("unseal digest mismatch")


@dataclass(frozen=True)
class RetireRecord:
    """Terminal retirement of an enclave identity."""

    enclave_id: str
    reason: str
    seq: int
    digest: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "enclave_id": self.enclave_id,
            "reason": self.reason,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> None:
        want = _digest_pin(self.enclave_id, self.reason, self.seq)
        if want != self.digest:
            raise VerificationError("retire digest mismatch")


_AUDIT_KINDS = (
    "secure-enclave.provisioned",
    "secure-enclave.attested",
    "secure-enclave.sealed",
    "secure-enclave.unsealed",
    "secure-enclave.retired",
    "secure-enclave.rejected",
)

#: Raw material that must never cross the audit boundary (exact-key match).
_BANNED_AUDIT_KEYS = frozenset({
    "nonce", "data", "plaintext", "payload", "raw", "value", "text",
    "message", "content", "secret", "key", "quote", "ciphertext", "bytes",
})


def secure_enclave_audit_event(
    kind: str,
    seq: int,
    *,
    enclave_id: str = "",
    detail: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Shape an ``audit.ndjson/1``-compatible registry audit record."""
    if kind not in _AUDIT_KINDS:
        raise AuditKindError(f"kind must be one of {_AUDIT_KINDS}")
    _check_seq("seq", seq)
    detail = dict(detail) if detail else {}
    for k in detail:
        if k in _BANNED_AUDIT_KEYS:
            raise ValueError(f"audit detail key banned: {k!r}")
    return {
        "schema_version": AUDIT_SCHEMA,
        "event_type": kind,
        "seq": seq,
        "enclave_id": enclave_id,
        "detail": detail,
    }


class SecureEnclave:
    """Lifecycle registry for simulated secure enclaves."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq = -1
        self._next_att = 0
        self._next_seal = 0
        self._next_unseal = 0
        self._provisions: dict[str, ProvisionRecord] = {}
        self._retired: set[str] = set()
        self._enclaves: dict[str, Enclave] = {}
        self._inner_seq: dict[str, int] = {}
        self._attestations: dict[str, AttestationDecision] = {}
        self._att_by_enclave: dict[str, list[str]] = {}
        self._seals: dict[str, SealRecord] = {}
        self._sealed_bytes: dict[str, SealedData] = {}
        self._unseals: dict[str, UnsealRecord] = {}
        self._retirements: dict[str, RetireRecord] = {}
        self._audit: list[dict[str, Any]] = []

    # -- internal helpers -------------------------------------------------

    def _claim(self, seq: int) -> int:
        """Claim a caller seq; strictly increasing. Rewinds raise bare."""
        seq = _check_seq("seq", seq)
        if seq <= self._last_seq:
            raise SeqOrderError("seq must strictly increase")
        self._last_seq = seq
        return seq

    def _reject(self, seq: int, what: str) -> None:
        self._audit.append(
            secure_enclave_audit_event(
                "secure-enclave.rejected", seq, detail={"what": what}
            )
        )

    def _live(self, enclave_id: str) -> ProvisionRecord:
        enclave_id = _check_id("enclave_id", enclave_id)
        if enclave_id in self._retired:
            raise RetiredEnclaveError(f"enclave retired: {enclave_id!r}")
        try:
            return self._provisions[enclave_id]
        except KeyError:
            raise UnknownEnclaveError(f"unknown enclave: {enclave_id!r}")

    def _inner_next(self, enclave_id: str) -> int:
        self._inner_seq[enclave_id] += 1
        return self._inner_seq[enclave_id]

    # -- mutations --------------------------------------------------------

    def provision(self, enclave_id: str, tee_type: str, measurement: str, seq: int) -> ProvisionRecord:
        """Register one enclave identity under management."""
        with self._lock:
            seq = self._claim(seq)
            try:
                enclave_id = _check_id("enclave_id", enclave_id)
                if enclave_id in self._retired:
                    raise RetiredEnclaveError(f"enclave retired: {enclave_id!r}")
                if enclave_id in self._provisions:
                    raise DuplicateEnclaveError(f"duplicate enclave: {enclave_id!r}")
                if tee_type not in TEE_TYPES:
                    raise BadTeeTypeError(f"tee_type must be one of {TEE_TYPES}")
                measurement = _check_digest("measurement", measurement)
                enc = Enclave(EnclaveConfig(
                    enclave_id=enclave_id,
                    tee_type=tee_type,
                    measurement=measurement,
                ))
            except SecureEnclaveError as e:
                self._reject(seq, type(e).__name__)
                raise
            rec = ProvisionRecord(
                enclave_id=enclave_id,
                tee_type=tee_type,
                measurement=measurement,
                seq=seq,
                digest=_digest_pin(enclave_id, tee_type, measurement, seq),
            )
            self._provisions[enclave_id] = rec
            self._enclaves[enclave_id] = enc
            self._inner_seq[enclave_id] = 0
            self._att_by_enclave[enclave_id] = []
            self._audit.append(
                secure_enclave_audit_event(
                    "secure-enclave.provisioned", seq, enclave_id=enclave_id,
                    detail={"tee_type": tee_type, "measurement": measurement},
                )
            )
            return rec

    def attest(self, enclave_id: str, nonce: bytes, seq: int,
               expected_measurement: str = "") -> AttestationDecision:
        """Mint a fresh quote and book the verifier verdict as data."""
        with self._lock:
            seq = self._claim(seq)
            try:
                prov = self._live(enclave_id)
                if not isinstance(nonce, (bytes, bytearray)) or len(nonce) == 0:
                    raise BadNonceError("nonce must be non-empty bytes")
                nonce = bytes(nonce)
                if expected_measurement:
                    _check_digest("expected_measurement", expected_measurement)
                else:
                    expected_measurement = prov.measurement
                enc = self._enclaves[enclave_id]
                quote = enc.attest(nonce, self._inner_next(enclave_id))
                attested = bool(verify_quote(
                    quote,
                    expected_measurement=expected_measurement,
                    expected_nonce=nonce,
                ))
                reason = "" if attested else "measurement-mismatch"
            except SecureEnclaveError as e:
                self._reject(seq, type(e).__name__)
                raise
            self._next_att += 1
            att_id = f"att-{self._next_att}"
            nonce_digest = _sha256_hex(b"nonce|" + nonce)
            quote_digest = _sha256_hex(quote.digest().encode())
            rec = AttestationDecision(
                att_id=att_id,
                enclave_id=enclave_id,
                nonce_digest=nonce_digest,
                attested=attested,
                reason=reason,
                quote_digest=quote_digest,
                seq=seq,
                digest=_digest_pin(
                    att_id, enclave_id, nonce_digest,
                    attested, reason, quote_digest, seq,
                ),
            )
            self._attestations[att_id] = rec
            self._att_by_enclave[enclave_id].append(att_id)
            self._audit.append(
                secure_enclave_audit_event(
                    "secure-enclave.attested", seq, enclave_id=enclave_id,
                    detail={"att_id": att_id, "attested": attested, "reason": reason},
                )
            )
            return rec

    def seal(self, enclave_id: str, label: str, data: bytes, seq: int) -> SealRecord:
        """Book a seal declaration; sealed bytes stay out of the ledger."""
        with self._lock:
            seq = self._claim(seq)
            try:
                prov = self._live(enclave_id)
                if not isinstance(label, str) or not label:
                    raise BadLabelError("label must be a non-empty str")
                if not isinstance(data, (bytes, bytearray)) or len(data) == 0:
                    raise BadDataError("data must be non-empty bytes")
                data = bytes(data)
                enc = self._enclaves[enclave_id]
                sealed = enc.seal(data, self._inner_next(enclave_id))
            except SecureEnclaveError as e:
                self._reject(seq, type(e).__name__)
                raise
            self._next_seal += 1
            seal_id = f"seal-{self._next_seal}"
            data_digest = _sha256_hex(b"data|" + data)
            ct_digest = _sha256_hex(b"ciphertext|" + sealed.ciphertext)
            rec = SealRecord(
                seal_id=seal_id,
                enclave_id=enclave_id,
                label=label,
                data_digest=data_digest,
                tag=sealed.tag,
                ciphertext_digest=ct_digest,
                seq=seq,
                digest=_digest_pin(
                    seal_id, enclave_id, label, data_digest,
                    sealed.tag, ct_digest, seq,
                ),
            )
            self._seals[seal_id] = rec
            self._sealed_bytes[seal_id] = sealed
            self._audit.append(
                secure_enclave_audit_event(
                    "secure-enclave.sealed", seq, enclave_id=enclave_id,
                    detail={"seal_id": seal_id, "label": label,
                            "data_digest": data_digest},
                )
            )
            return rec

    def unseal(self, enclave_id: str, seal_id: str, seq: int) -> tuple[bytes, UnsealRecord]:
        """Release sealed bytes only with a fresh attested=True decision."""
        with self._lock:
            seq = self._claim(seq)
            try:
                prov = self._live(enclave_id)
                seal_id = _check_id("seal_id", seal_id)
                try:
                    rec = self._seals[seal_id]
                except KeyError:
                    raise UnknownSealError(f"unknown seal: {seal_id!r}")
                if rec.enclave_id != enclave_id:
                    raise UnknownSealError("seal belongs to another enclave")
                fresh = any(
                    self._attestations[a].attested and self._attestations[a].seq >= rec.seq
                    for a in self._att_by_enclave[enclave_id]
                )
                if not fresh:
                    raise SealDeniedError(
                        "no attested=True decision newer than the seal"
                    )
                plaintext = self._enclaves[enclave_id].unseal(self._sealed_bytes[seal_id])
            except SecureEnclaveError as e:
                self._reject(seq, type(e).__name__)
                raise
            self._next_unseal += 1
            unseal_id = f"unseal-{self._next_unseal}"
            pt_digest = _sha256_hex(b"plaintext|" + plaintext)
            record = UnsealRecord(
                unseal_id=unseal_id,
                enclave_id=enclave_id,
                seal_id=seal_id,
                plaintext_digest=pt_digest,
                seq=seq,
                digest=_digest_pin(unseal_id, enclave_id, seal_id, pt_digest, seq),
            )
            self._unseals[unseal_id] = record
            self._audit.append(
                secure_enclave_audit_event(
                    "secure-enclave.unsealed", seq, enclave_id=enclave_id,
                    detail={"unseal_id": unseal_id, "seal_id": seal_id},
                )
            )
            return plaintext, record

    def retire(self, enclave_id: str, seq: int, reason: str = "manual") -> RetireRecord:
        """Terminally retire an enclave identity (ids never recycled)."""
        with self._lock:
            seq = self._claim(seq)
            try:
                enclave_id = _check_id("enclave_id", enclave_id)
                if enclave_id in self._retired:
                    raise RetiredEnclaveError(f"enclave retired: {enclave_id!r}")
                if enclave_id not in self._provisions:
                    raise UnknownEnclaveError(f"unknown enclave: {enclave_id!r}")
                if not isinstance(reason, str) or not reason:
                    raise BadIdError("reason must be a non-empty str")
            except SecureEnclaveError as e:
                self._reject(seq, type(e).__name__)
                raise
            rec = RetireRecord(
                enclave_id=enclave_id,
                reason=reason,
                seq=seq,
                digest=_digest_pin(enclave_id, reason, seq),
            )
            self._retired.add(enclave_id)
            self._retirements[enclave_id] = rec
            self._audit.append(
                secure_enclave_audit_event(
                    "secure-enclave.retired", seq, enclave_id=enclave_id,
                    detail={"reason": reason},
                )
            )
            return rec

    # -- pure-read views (validate seq shape, consume nothing) ------------

    def _view_seq(self, seq: int) -> None:
        _check_seq("seq", seq)

    def provision_record(self, enclave_id: str, seq: int) -> ProvisionRecord:
        with self._lock:
            self._view_seq(seq)
            return self._provisions[_check_id("enclave_id", enclave_id)]

    def attestation_record(self, att_id: str, seq: int) -> AttestationDecision:
        with self._lock:
            self._view_seq(seq)
            return self._attestations[_check_id("att_id", att_id)]

    def attestations_for(self, enclave_id: str, seq: int) -> tuple[str, ...]:
        with self._lock:
            self._view_seq(seq)
            return tuple(self._att_by_enclave[_check_id("enclave_id", enclave_id)])

    def seal_record(self, seal_id: str, seq: int) -> SealRecord:
        with self._lock:
            self._view_seq(seq)
            return self._seals[_check_id("seal_id", seal_id)]

    def unseal_record(self, unseal_id: str, seq: int) -> UnsealRecord:
        with self._lock:
            self._view_seq(seq)
            return self._unseals[_check_id("unseal_id", unseal_id)]

    def enclave_ids(self, seq: int) -> tuple[str, ...]:
        with self._lock:
            self._view_seq(seq)
            return tuple(sorted(self._provisions))

    def stats(self, seq: int) -> dict[str, Any]:
        with self._lock:
            self._view_seq(seq)
            return {
                "schema": SCHEMA,
                "enclaves": len(self._provisions),
                "retired": len(self._retired),
                "attestations": len(self._attestations),
                "seals": len(self._seals),
                "unseals": len(self._unseals),
                "rejected": sum(
                    1 for e in self._audit
                    if e["event_type"] == "secure-enclave.rejected"
                ),
            }

    def audit_log(self, seq: int) -> tuple[dict[str, Any], ...]:
        with self._lock:
            self._view_seq(seq)
            return tuple(dict(e) for e in self._audit)


def main() -> None:
    reg = SecureEnclave()
    meas = "sha256:" + hashlib.sha256(b"demo-enclave-code").hexdigest()
    prov = reg.provision("enc-1", "software", meas, 1)
    prov.verify()
    seal = reg.seal("enc-1", "api-key", b"super-secret", 2)
    seal.verify()
    dec = reg.attest("enc-1", b"nonce-1", 3)
    dec.verify()
    assert dec.attested and dec.reason == ""
    plaintext, unseal = reg.unseal("enc-1", seal.seal_id, 4)
    assert plaintext == b"super-secret"
    unseal.verify()
    ret = reg.retire("enc-1", 5)
    ret.verify()
    assert reg.stats(6)["enclaves"] == 1
    print("secure-enclave OK: provision, attest, seal, unseal, retire")


__all__ = [
    "VERSION",
    "SCHEMA",
    "TEE_TYPES",
    "SecureEnclaveError",
    "BadIdError",
    "DuplicateEnclaveError",
    "UnknownEnclaveError",
    "RetiredEnclaveError",
    "BadTeeTypeError",
    "BadMeasurementError",
    "BadNonceError",
    "BadLabelError",
    "BadDataError",
    "UnknownSealError",
    "SealDeniedError",
    "VerificationError",
    "SeqOrderError",
    "AuditKindError",
    "ProvisionRecord",
    "AttestationDecision",
    "SealRecord",
    "UnsealRecord",
    "RetireRecord",
    "SecureEnclave",
    "secure_enclave_audit_event",
]


if __name__ == "__main__":
    main()
