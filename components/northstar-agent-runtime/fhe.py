"""FHE: fully-homomorphic-encryption decision ledger for agents.

Research note: fully homomorphic encryption (Gentry 2009; BFV/Brakerski-
Fan-Vercauteren, BGV/Brakerski-Gentry-Vaikuntanathan, CKKS/Cheon-Kim-Kim-
Song for approximate arithmetic, TFHE/CGGI for fast bootstrapped boolean
gates) lets a host *compute on ciphertexts* - additions and multiplications
(with noise budgets, relinearization, modulus switching, bootstrapping)
without ever holding the decryption key.

This module is the *decision ledger* for that practice, Simulated per spec.
It books:

* **keygen()** - one declared FHE key-set registration under a pinned
  scheme vocabulary (``bfv`` / ``bgv`` / ``ckks`` / ``tfhe``).
* **encrypt()** - one declared encryption: a host-supplied *plaintext
  digest* is bound to a named key, minting a ciphertext id. Raw plaintext
  never enters a record and never crosses the audit boundary - digest
  pins only.
* **compute()** - one declared homomorphic evaluation: a pinned op
  (``add`` / ``mul`` / ``rotate`` / ``bootstrap``) over declared input
  ciphertexts, minting an output ciphertext. This books the *declared*
  circuit, not the arithmetic; the "result" is ledger truth, never a
  proven homomorphic computation.
* **decrypt()** - a pure read view: the host-declared plaintext digest a
  ciphertext binds to. A declaration, never proof that the named key can
  decrypt the named ciphertext.

House style: frozen dataclasses, caller-supplied strictly-increasing int
seqs (claim-then-burn: failed mutations consume their seq and book an
``fhe.rejected`` row; rewinds raise bare without consuming), no
wall-clock, RLock guarding, fail-closed taxonomy, stdlib-only with the
standard ``canonical_json`` try/except fallback, ``sha256:`` digest pins,
and ``audit.ndjson/1`` events.

Honest scope: the module runs no FHE scheme, moves no noise budgets, and
cannot prove a computation is homomorphically correct. All values are
host-declared GIGO booked under digest pins; raw plaintext/key material
never crosses the module boundary.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

try:
    from canonical_json import jcs_dumps as _jcs_dumps, jcs_sha256_hex as _jcs_hash  # type: ignore
except Exception:  # pragma: no cover - fallback when canonical_json is absent

    def _jcs_dumps(obj: Any) -> bytes:  # type: ignore
        import json

        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def _jcs_hash(obj: Any) -> str:  # type: ignore
        return "sha256:" + hashlib.sha256(_jcs_dumps(obj)).hexdigest()


#: Module version pin.
FHE_VERSION = "fhe.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.fhe.v1"

#: Pinned FHE scheme vocabulary (declared, never executed).
SCHEMES = ("bfv", "bgv", "ckks", "tfhe")

#: Pinned homomorphic-op vocabulary.
OPS = ("add", "mul", "rotate", "bootstrap")

#: Audit kinds emitted by this module.
AUDIT_KINDS = (
    "key-registered",
    "encrypted",
    "computed",
    "rejected",
)

#: Keys that may never appear raw in an audit row.
_BANNED_AUDIT_KEYS = frozenset(
    {
        "plaintext",
        "plaintext_digest_raw",
        "key",
        "secret",
        "private",
        "sk",
        "key_material",
        "text",
        "content",
        "payload",
        "raw",
        "value",
        "data",
    }
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class FHEError(Exception):
    """Base error for FHE ledger misuse."""


class BadKeyError(FHEError):
    """Malformed key id or scheme."""


class DuplicateKeyError(FHEError):
    """Key id already registered."""


class UnknownKeyError(FHEError):
    """Key id not registered."""


class BadDigestError(FHEError):
    """Malformed sha256: digest pin."""


class DuplicateCiphertextError(FHEError):
    """Internal: a minted ciphertext id collided (never expected)."""


class UnknownCiphertextError(FHEError):
    """Ciphertext id not booked."""


class BadOpError(FHEError):
    """Unknown homomorphic op."""


class BadInputsError(FHEError):
    """Malformed input ciphertext list for compute()."""


class SeqOrderError(FHEError):
    """Seq is not a strictly increasing positive int."""


class AuditKindError(FHEError):
    """Unknown audit kind."""


# ---------------------------------------------------------------------------
# Records (all frozen)
# ---------------------------------------------------------------------------


def _require_digest(pin: str, field_name: str) -> str:
    if not isinstance(pin, str) or not pin.startswith("sha256:"):
        raise BadDigestError(f"{field_name} must be a 'sha256:' pin")
    hexpart = pin[7:]
    if len(hexpart) != 64 or any(c not in "0123456789abcdef" for c in hexpart):
        raise BadDigestError(f"{field_name} must be a 64-hex sha256 pin")
    return pin


@dataclass(frozen=True)
class KeyRecord:
    key_id: str
    scheme: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "key_id": self.key_id,
            "scheme": self.scheme,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {"schema": SCHEMA_PIN, "key_id": self.key_id, "scheme": self.scheme}
        )


@dataclass(frozen=True)
class CiphertextRecord:
    ciphertext_id: str
    key_id: str
    plaintext_digest: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "ciphertext_id": self.ciphertext_id,
            "key_id": self.key_id,
            "plaintext_digest": self.plaintext_digest,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "ciphertext_id": self.ciphertext_id,
                "key_id": self.key_id,
                "plaintext_digest": self.plaintext_digest,
            }
        )


@dataclass(frozen=True)
class ComputationRecord:
    computation_id: str
    op: str
    input_ids: Tuple[str, ...]
    output_id: str
    result_digest: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "computation_id": self.computation_id,
            "op": self.op,
            "input_ids": list(self.input_ids),
            "output_id": self.output_id,
            "result_digest": self.result_digest,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "computation_id": self.computation_id,
                "op": self.op,
                "input_ids": list(self.input_ids),
                "output_id": self.output_id,
                "result_digest": self.result_digest,
            }
        )


@dataclass(frozen=True)
class DecryptReport:
    ciphertext_id: str
    key_id: str
    plaintext_digest: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "ciphertext_id": self.ciphertext_id,
            "key_id": self.key_id,
            "plaintext_digest": self.plaintext_digest,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "ciphertext_id": self.ciphertext_id,
                "key_id": self.key_id,
                "plaintext_digest": self.plaintext_digest,
            }
        )


def _digest_pin(payload: Dict[str, Any]) -> str:
    raw = _jcs_hash(payload)
    hexpart = raw[7:] if raw.startswith("sha256:") else raw
    return "sha256:" + hexpart


# ---------------------------------------------------------------------------
# Audit event builder
# ---------------------------------------------------------------------------


def fhe_audit_event(kind: str, seq: int, **details: Any) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` event row for the FHE ledger."""
    if kind not in AUDIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise SeqOrderError("audit seq must be a non-negative int")
    for key in details:
        if key in _BANNED_AUDIT_KEYS:
            raise AuditKindError(f"banned raw key in audit detail: {key!r}")
    return {
        "schema": "audit.ndjson/1",
        "kind": kind,
        "seq": seq,
        "details": dict(details),
    }


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class FHE:
    """Fully-homomorphic-encryption decision ledger (Simulated).

    ``keygen()`` / ``encrypt()`` / ``compute()`` mutate the ledger and
    consume caller seqs; ``decrypt()`` and all views are pure reads.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._keys: Dict[str, KeyRecord] = {}
        self._ciphertexts: Dict[str, CiphertextRecord] = {}
        self._computations: Dict[str, ComputationRecord] = {}
        self._audit: List[Dict[str, Any]] = []
        self._seq = 0
        self._ct_counter = 0
        self._cmp_counter = 0

    # -- seq discipline ----------------------------------------------------

    def _check_seq(self, seq: int) -> int:
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise SeqOrderError("seq must be an int")
        if seq <= self._seq:
            raise SeqOrderError("seq must strictly increase")
        return seq

    def _claim(self, seq: int) -> int:
        self._check_seq(seq)
        self._seq = seq
        return seq

    def _burn(self, seq: int, kind: str, **details: Any) -> None:
        self._seq = seq
        try:
            row = fhe_audit_event("rejected", seq, rejected_kind=kind, **details)
        except (AuditKindError, SeqOrderError):
            row = {
                "schema": "audit.ndjson/1",
                "kind": "rejected",
                "seq": seq,
                "details": {"rejected_kind": kind},
            }
        self._audit.append(row)

    def _emit(self, audit_kind: str, seq: int, **details: Any) -> None:
        self._audit.append(fhe_audit_event(audit_kind, seq, **details))

    # -- keygen ------------------------------------------------------------

    def keygen(self, key_id: str, seq: int, scheme: str = "bfv") -> KeyRecord:
        """Declare one FHE key-set under a pinned scheme."""
        with self._lock:
            try:
                self._claim(seq)
            except FHEError:
                raise
            try:
                if not isinstance(key_id, str) or not key_id or len(key_id) > 128:
                    raise BadKeyError("key_id must be a non-empty str <= 128 chars")
                if scheme not in SCHEMES:
                    raise BadKeyError(f"scheme must be one of {SCHEMES}")
                if key_id in self._keys:
                    raise DuplicateKeyError(f"key already registered: {key_id!r}")
                digest = _digest_pin(
                    {"schema": SCHEMA_PIN, "key_id": key_id, "scheme": scheme}
                )
                record = KeyRecord(key_id=key_id, scheme=scheme, digest=digest)
                self._keys[key_id] = record
                self._emit("key-registered", seq, key_id=key_id, scheme=scheme)
                return record
            except FHEError:
                self._burn(seq, "keygen")
                raise

    # -- encrypt -----------------------------------------------------------

    def encrypt(
        self, key_id: str, plaintext_digest: str, seq: int
    ) -> CiphertextRecord:
        """Book a declared encryption: plaintext pin -> minted ciphertext."""
        with self._lock:
            try:
                self._claim(seq)
            except FHEError:
                raise
            try:
                if key_id not in self._keys:
                    raise UnknownKeyError(f"unknown key: {key_id!r}")
                _require_digest(plaintext_digest, "plaintext_digest")
                self._ct_counter += 1
                ct_id = f"ct-{self._ct_counter}"
                if ct_id in self._ciphertexts:
                    raise DuplicateCiphertextError(f"ciphertext id collision: {ct_id!r}")
                digest = _digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "ciphertext_id": ct_id,
                        "key_id": key_id,
                        "plaintext_digest": plaintext_digest,
                    }
                )
                record = CiphertextRecord(
                    ciphertext_id=ct_id,
                    key_id=key_id,
                    plaintext_digest=plaintext_digest,
                    digest=digest,
                )
                self._ciphertexts[ct_id] = record
                self._emit(
                    "encrypted", seq, ciphertext_id=ct_id, key_id=key_id
                )
                return record
            except FHEError:
                self._burn(seq, "encrypt")
                raise

    # -- compute -----------------------------------------------------------

    def compute(
        self,
        ciphertext_ids: Tuple[str, ...],
        op: str,
        seq: int,
        result_digest: str = "",
    ) -> ComputationRecord:
        """Book a declared homomorphic evaluation over input ciphertexts."""
        with self._lock:
            try:
                self._claim(seq)
            except FHEError:
                raise
            try:
                if op not in OPS:
                    raise BadOpError(f"op must be one of {OPS}")
                if (
                    not isinstance(ciphertext_ids, (tuple, list))
                    or not ciphertext_ids
                    or len(ciphertext_ids) > 64
                ):
                    raise BadInputsError(
                        "ciphertext_ids must be a non-empty tuple/list of <= 64 ids"
                    )
                seen = set()
                for ct_id in ciphertext_ids:
                    if not isinstance(ct_id, str) or not ct_id:
                        raise BadInputsError("ciphertext ids must be non-empty strs")
                    if ct_id in seen:
                        raise BadInputsError(f"duplicate input id: {ct_id!r}")
                    seen.add(ct_id)
                    if ct_id not in self._ciphertexts:
                        raise UnknownCiphertextError(f"unknown ciphertext: {ct_id!r}")
                key_ids = {
                    self._ciphertexts[ct_id].key_id for ct_id in ciphertext_ids
                }
                if len(key_ids) != 1:
                    raise BadInputsError("all inputs must share one key")
                pin = result_digest or _digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "inputs": sorted(ciphertext_ids),
                        "op": op,
                    }
                )
                _require_digest(pin, "result_digest")
                self._cmp_counter += 1
                cmp_id = f"cmp-{self._cmp_counter}"
                out_id = f"ct-{self._ct_counter + 1}"
                self._ct_counter += 1
                digest = _digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "computation_id": cmp_id,
                        "op": op,
                        "input_ids": list(ciphertext_ids),
                        "output_id": out_id,
                        "result_digest": pin,
                    }
                )
                record = ComputationRecord(
                    computation_id=cmp_id,
                    op=op,
                    input_ids=tuple(ciphertext_ids),
                    output_id=out_id,
                    result_digest=pin,
                    digest=digest,
                )
                self._computations[cmp_id] = record
                # The output is itself a booked ciphertext (unknown plaintext).
                out_record = CiphertextRecord(
                    ciphertext_id=out_id,
                    key_id=self._ciphertexts[ciphertext_ids[0]].key_id,
                    plaintext_digest=pin,
                    digest=_digest_pin(
                        {
                            "schema": SCHEMA_PIN,
                            "ciphertext_id": out_id,
                            "key_id": self._ciphertexts[ciphertext_ids[0]].key_id,
                            "plaintext_digest": pin,
                        }
                    ),
                )
                self._ciphertexts[out_id] = out_record
                self._emit(
                    "computed",
                    seq,
                    computation_id=cmp_id,
                    op=op,
                    n_inputs=len(ciphertext_ids),
                    output_id=out_id,
                )
                return record
            except FHEError:
                self._burn(seq, "compute")
                raise

    # -- decrypt (pure read) -----------------------------------------------

    def decrypt(self, ciphertext_id: str, key_id: str, seq: int) -> DecryptReport:
        """Pure read: the host-declared plaintext digest a ciphertext binds to."""
        with self._lock:
            if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
                raise SeqOrderError("seq must be a non-negative int")
            record = self._ciphertexts.get(ciphertext_id)
            if record is None:
                raise UnknownCiphertextError(f"unknown ciphertext: {ciphertext_id!r}")
            if record.key_id != key_id:
                raise UnknownKeyError(f"key mismatch for {ciphertext_id!r}")
            return DecryptReport(
                ciphertext_id=ciphertext_id,
                key_id=key_id,
                plaintext_digest=record.plaintext_digest,
                digest=_digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "ciphertext_id": ciphertext_id,
                        "key_id": key_id,
                        "plaintext_digest": record.plaintext_digest,
                    }
                ),
            )

    # -- pure-read views ---------------------------------------------------

    def key_record(self, key_id: str, seq: int) -> KeyRecord:
        with self._lock:
            if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
                raise SeqOrderError("seq must be a non-negative int")
            record = self._keys.get(key_id)
            if record is None:
                raise UnknownKeyError(f"unknown key: {key_id!r}")
            return record

    def ciphertext_record(self, ciphertext_id: str, seq: int) -> CiphertextRecord:
        with self._lock:
            if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
                raise SeqOrderError("seq must be a non-negative int")
            record = self._ciphertexts.get(ciphertext_id)
            if record is None:
                raise UnknownCiphertextError(f"unknown ciphertext: {ciphertext_id!r}")
            return record

    def computation_record(self, computation_id: str, seq: int) -> ComputationRecord:
        with self._lock:
            if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
                raise SeqOrderError("seq must be a non-negative int")
            record = self._computations.get(computation_id)
            if record is None:
                raise UnknownCiphertextError(f"unknown computation: {computation_id!r}")
            return record

    def key_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
                raise SeqOrderError("seq must be a non-negative int")
            return tuple(sorted(self._keys))

    def ciphertext_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
                raise SeqOrderError("seq must be a non-negative int")
            return tuple(sorted(self._ciphertexts))

    def computation_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
                raise SeqOrderError("seq must be a non-negative int")
            return tuple(sorted(self._computations))

    def stats(self, seq: int) -> Dict[str, Any]:
        with self._lock:
            if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
                raise SeqOrderError("seq must be a non-negative int")
            return {
                "schema": SCHEMA_PIN,
                "n_keys": len(self._keys),
                "n_ciphertexts": len(self._ciphertexts),
                "n_computations": len(self._computations),
                "n_audit_rows": len(self._audit),
            }

    def audit_log(self, seq: int) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
                raise SeqOrderError("seq must be a non-negative int")
            return tuple(dict(row) for row in self._audit)


def main() -> None:
    fhe = FHE()
    seq = 1
    pin = "sha256:" + "ab" * 32
    fhe.keygen("key-1", seq, scheme="bfv")
    seq += 1
    ct = fhe.encrypt("key-1", pin, seq)
    seq += 1
    cmp_ = fhe.compute((ct.ciphertext_id,), "bootstrap", seq)
    seq += 1
    report = fhe.decrypt(ct.ciphertext_id, "key-1", seq)
    assert report.verify()
    assert cmp_.verify()
    # refusal smoke: unknown key burns seq and books a rejected row
    try:
        fhe.encrypt("nope", pin, seq + 1)
    except UnknownKeyError:
        pass
    assert len(fhe.audit_log(0)) >= 4
    print("fhe OK: keygen, encrypt, compute, decrypt, pins, audit")


if __name__ == "__main__":
    main()
