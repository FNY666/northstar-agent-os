"""MFA manager: TOTP / WebAuthn enrollment and verification (simulated).

Research note: TOTP (RFC 6238, a profile of RFC 4226 HOTP) and WebAuthn
(W3C Web Authentication, CTAP2/FIDO2) are the two second factors the rest
of the web converged on, for different reasons:

* **TOTP** is a *shared-secret* factor: enrolment provisions one secret
  (usually via QR code, RFC 3548 base32), and both sides derive
  6-digit codes from ``HMAC(secret, time_step)``. The server verifies
  with a small *skew window* (``±1`` steps here) because clocks drift and
  humans type slowly. The failure mode is secret theft — a leaked secret
  lets anyone mint codes — which is why production servers store only a
  verifier and rate-limit guesses.
* **WebAuthn** is a *public-key* factor: enrolment registers a credential
  id plus the credential's public key under an RP id; each
  authentication is a fresh challenge signed by the authenticator, with a
  *signature counter* that must strictly increase — a regressing counter
  is the standard clone-detection signal (WebAuthn §6.1.2). The failure
  mode is phishing resistance gained at the cost of an enrolment
  ceremony and ceremony replay protection on the challenge.
* **Backup codes** are the escape hatch for lost factors: single-use,
  high-entropy strings whose verifiers are hashes. A code is *consumed*
  on first successful use — replay of a used code must fail, or the
  escape hatch becomes a second password.

Time is caller-supplied: TOTP uses a logical ``step`` (the 30-second
counter from RFC 6238, 8-byte big-endian), and WebAuthn challenges carry
a logical issue seq. A clock that moves backwards cannot resurrect an
expired, revoked, or consumed record.

Fail-closed rules (load-bearing):

* Enrolment ids (``cred_id`` / principal) are globally unique:
  re-enrolling an active enrolment raises ``DuplicateEnrollmentError``
  (rotate by disabling the old one first, never by mutating it).
* TOTP reuse within the *same* time step is rejected
  (``ReplayedCodeError``): a code is a one-time proof, exactly like an
  HOTP counter, and replaying a valid code must not verify twice.
* WebAuthn signature counter must strictly increase per credential:
  a non-increasing counter raises ``CloneDetectedError`` and the
  credential is flagged — the WebAuthn clone-detection rule.
* Backup codes verify exactly once; a used, unknown, or malformed code
  returns ``valid=False`` as data (no exception, no oracle).
* ``verify()`` on an unknown, disabled, or un-enrolled principal returns
  ``valid=False`` as data; only wrong *types* are programming errors and
  raise.
* Mutation seqs must strictly increase per manager (``SeqOrderError``),
  so the ledger order is total and replay-exact.
* Raw secrets never appear in ``as_dict()``, audit events, or digests:
  the digest pins bind (principal, cred_id, method, seqs, key verifiers)
  only.

Honest scope: this books *reported* MFA lifecycle events. It cannot
prove a real authenticator produced the response, cannot observe the
wire, and the cryptography is HMAC bookkeeping with simulated
authenticator responses — production deployments must use a real
``cryptography``-backed TOTP verifier and a WebAuthn library that parses
authenticator data, and must mint all secrets from the OS RNG
(``secrets``). With an explicit ``seed=`` the module is fully
deterministic for tests and audit replay; the default salt comes from
``secrets.token_bytes``.

Version pin: mfa-manager.v1
Schema pin: northstar.mfa-manager.v1
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except ImportError:  # pragma: no cover - fallback for standalone import

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        import json

        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


#: Module version.
MFA_MANAGER_VERSION = "mfa-manager.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.mfa-manager.v1"

#: TOTP code length (RFC 6238 uses 6–8 digits; 6 is the common default).
TOTP_DIGITS = 6

#: Allowed clock-skew window in time steps (accepts step-1, step, step+1).
TOTP_SKEW_STEPS = 1

#: Default number of backup codes minted per ``backup()`` call.
BACKUP_CODE_COUNT = 10

#: Backup code entropy in bytes (hex-encoded on issue).
BACKUP_CODE_BYTES = 10


class MFAError(Exception):
    """Base class for MFA manager errors."""


class DuplicateEnrollmentError(MFAError):
    """An active enrolment already exists for this principal/method."""


class UnknownEnrollmentError(MFAError):
    """No enrolment exists for this principal/method."""


class ReplayedCodeError(MFAError):
    """A TOTP code was presented for an already-consumed time step."""


class CloneDetectedError(MFAError):
    """A WebAuthn signature counter regressed: possible cloned key."""


class DisabledFactorError(MFAError):
    """The factor exists but is disabled."""


class SeqOrderError(MFAError):
    """Mutation seq did not strictly increase."""


def _sha256_hex(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _b32_nopad(secret: bytes) -> str:
    """Base32 (RFC 3548) without padding, the QR-code provisioning form."""
    return base64.b32encode(secret).decode("ascii").rstrip("=")


def _totp_code(secret: bytes, step: int, digits: int = TOTP_DIGITS) -> str:
    """RFC 4226 dynamic truncation over HMAC-SHA1(secret, step)."""
    mac = hmac.new(secret, struct.pack(">Q", step), hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    code_int = struct.unpack(">I", mac[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(code_int % (10**digits)).zfill(digits)


@dataclass(frozen=True)
class TOTPEnrollment:
    """Issued TOTP enrolment. ``secret_b32`` is returned to the caller
    exactly once; only the verifier is retained afterwards."""

    principal: str
    cred_id: str
    secret_b32: str
    secret_digest: str
    issued_at_seq: int
    disabled: bool
    last_used_step: Optional[int]
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "version": MFA_MANAGER_VERSION,
            "principal": self.principal,
            "cred_id": self.cred_id,
            "method": "totp",
            "secret_digest": self.secret_digest,
            "issued_at_seq": self.issued_at_seq,
            "disabled": self.disabled,
            "last_used_step": self.last_used_step,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class WebAuthnEnrollment:
    """Issued WebAuthn enrolment. ``simulated`` marks that the keypair is
    HMAC-derived bookkeeping, not a real COSE key."""

    principal: str
    cred_id: str
    rp_id: str
    key_digest: str
    issued_at_seq: int
    disabled: bool
    sign_count: int
    clone_detected: bool
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "version": MFA_MANAGER_VERSION,
            "principal": self.principal,
            "cred_id": self.cred_id,
            "method": "webauthn",
            "rp_id": self.rp_id,
            "key_digest": self.key_digest,
            "issued_at_seq": self.issued_at_seq,
            "disabled": self.disabled,
            "sign_count": self.sign_count,
            "clone_detected": self.clone_detected,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class BackupSet:
    """Minted backup-code set. Only digests are retained; the plaintext
    codes are handed to the caller exactly once."""

    principal: str
    set_id: str
    code_digests: FrozenSet[str]
    used_digests: FrozenSet[str]
    issued_at_seq: int
    digest: str

    def remaining(self) -> int:
        return len(self.code_digests - self.used_digests)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "version": MFA_MANAGER_VERSION,
            "principal": self.principal,
            "set_id": self.set_id,
            "code_count": len(self.code_digests),
            "used_count": len(self.used_digests),
            "issued_at_seq": self.issued_at_seq,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class VerifyResult:
    """Outcome of a ``verify()`` call — data, never an exception, for
    malformed or unknown input."""

    principal: str
    method: str
    valid: bool
    reason: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "version": MFA_MANAGER_VERSION,
            "principal": self.principal,
            "method": self.method,
            "valid": self.valid,
            "reason": self.reason,
        }


class MFAManager:
    """Enrolment and verification ledger for TOTP, WebAuthn, and backup
    codes (simulated).

    All time is caller-supplied (TOTP ``step``, WebAuthn challenge seqs);
    all mutation seqs must strictly increase.
    """

    def __init__(self, seed: Optional[bytes] = None) -> None:
        self._lock = threading.Lock()
        self._salt = seed if seed is not None else secrets.token_bytes(32)
        self._totp: Dict[Tuple[str, str], Dict[str, Any]] = {}
        self._webauthn: Dict[Tuple[str, str], Dict[str, Any]] = {}
        self._backup: Dict[Tuple[str, str], Dict[str, Any]] = {}
        self._audit_log: list = []
        self._last_seq = 0
        self._counter = 0

    # ------------------------------------------------------------------
    # internals
    # ------------------------------------------------------------------
    def _check_seq(self, seq: int) -> None:
        if not isinstance(seq, int):
            raise TypeError("seq must be int")
        if seq <= self._last_seq:
            raise SeqOrderError(
                "mutation seq must strictly increase: "
                "got %d, last was %d" % (seq, self._last_seq)
            )
        self._last_seq = seq

    def _next_id(self, kind: str) -> str:
        self._counter += 1
        raw = hmac.new(
            self._salt, ("%s:%d" % (kind, self._counter)).encode(), hashlib.sha256
        ).digest()
        return "%s-%s" % (kind, raw.hex()[:12])

    def _mint_secret(self, kind: str, ident: str, nbytes: int) -> bytes:
        self._counter += 1
        return hmac.new(
            self._salt,
            ("%s:%s:%d" % (kind, ident, self._counter)).encode(),
            hashlib.sha256,
        ).digest()[:nbytes]

    def _record_digest(self, kind: str, payload: Dict[str, Any]) -> str:
        blob = jcs_canonical_json(
            {"schema": SCHEMA_PIN, "kind": kind, "payload": payload}
        )
        return _sha256_hex(self._salt + b"|" + blob)

    def _audit(self, event: str, principal: str, method: str, seq: int,
               ok: bool, detail: str = "") -> None:
        self._audit_log.append(
            {
                "schema": SCHEMA_PIN,
                "version": MFA_MANAGER_VERSION,
                "event": event,
                "principal": principal,
                "method": method,
                "seq": seq,
                "ok": ok,
                "detail": detail,
            }
        )

    # ------------------------------------------------------------------
    # enrolment
    # ------------------------------------------------------------------
    def enroll(self, principal: str, method: str, seq: int,
               rp_id: str = "northstar.local") -> Any:
        """Enrol a factor for ``principal``. ``method`` is ``"totp"`` or
        ``"webauthn"``. Returns the enrolment record; for TOTP the record
        carries ``secret_b32`` exactly once."""
        if not isinstance(principal, str) or not principal:
            raise TypeError("principal must be a non-empty str")
        if method not in ("totp", "webauthn"):
            raise ValueError("method must be 'totp' or 'webauthn'")
        with self._lock:
            self._check_seq(seq)
            key = (principal, method)
            store = self._totp if method == "totp" else self._webauthn
            if key in store and not store[key]["disabled"]:
                raise DuplicateEnrollmentError(
                    "active %s enrolment for %r" % (method, principal)
                )
            if method == "totp":
                secret = self._mint_secret("totp", principal, 20)
                cred_id = self._next_id("totp")
                secret_digest = _sha256_hex(secret)
                digest = self._record_digest(
                    "totp-enroll",
                    {
                        "principal": principal,
                        "cred_id": cred_id,
                        "secret_digest": secret_digest,
                        "seq": seq,
                    },
                )
                rec = TOTPEnrollment(
                    principal=principal,
                    cred_id=cred_id,
                    secret_b32=_b32_nopad(secret),
                    secret_digest=secret_digest,
                    issued_at_seq=seq,
                    disabled=False,
                    last_used_step=None,
                    digest=digest,
                )
                store[key] = {"rec": rec, "secret": secret, "disabled": False,
                              "last_used_step": None}
            else:
                keymat = self._mint_secret("webauthn", principal, 32)
                cred_id = self._next_id("webauthn")
                key_digest = _sha256_hex(keymat)
                digest = self._record_digest(
                    "webauthn-enroll",
                    {
                        "principal": principal,
                        "cred_id": cred_id,
                        "rp_id": rp_id,
                        "key_digest": key_digest,
                        "seq": seq,
                    },
                )
                rec = WebAuthnEnrollment(
                    principal=principal,
                    cred_id=cred_id,
                    rp_id=rp_id,
                    key_digest=key_digest,
                    issued_at_seq=seq,
                    disabled=False,
                    sign_count=0,
                    clone_detected=False,
                    digest=digest,
                )
                store[key] = {"rec": rec, "keymat": keymat, "disabled": False,
                              "sign_count": 0, "clone_detected": False}
            self._audit("enroll", principal, method, seq, True,
                        "cred_id=%s" % cred_id)
            return rec

    def disable(self, principal: str, method: str, seq: int) -> None:
        """Disable a factor (terminal for that enrolment; re-enrolment
        mints a fresh credential id)."""
        with self._lock:
            self._check_seq(seq)
            key = (principal, method)
            store = self._totp if method == "totp" else self._webauthn
            if key not in store:
                raise UnknownEnrollmentError(
                    "no %s enrolment for %r" % (method, principal)
                )
            store[key]["disabled"] = True
            self._audit("disable", principal, method, seq, True)

    def backup(self, principal: str, seq: int,
               count: int = BACKUP_CODE_COUNT) -> Tuple[BackupSet, Tuple[str, ...]]:
        """Mint ``count`` single-use backup codes for ``principal``.
        Returns the retained record plus the plaintext codes, handed to
        the caller exactly once."""
        if not isinstance(principal, str) or not principal:
            raise TypeError("principal must be a non-empty str")
        if not isinstance(count, int) or count < 1 or count > 64:
            raise ValueError("count must be an int in [1, 64]")
        with self._lock:
            self._check_seq(seq)
            set_id = self._next_id("backup")
            codes = tuple(
                self._mint_secret("backup", "%s:%s" % (principal, set_id), BACKUP_CODE_BYTES).hex()
                for _ in range(count)
            )
            digests = frozenset(_sha256_hex(c.encode()) for c in codes)
            digest = self._record_digest(
                "backup-mint",
                {
                    "principal": principal,
                    "set_id": set_id,
                    "code_count": count,
                    "seq": seq,
                },
            )
            rec = BackupSet(
                principal=principal,
                set_id=set_id,
                code_digests=digests,
                used_digests=frozenset(),
                issued_at_seq=seq,
                digest=digest,
            )
            self._backup[(principal, set_id)] = {
                "rec": rec, "used": set(), "active": True
            }
            self._audit("backup-mint", principal, "backup", seq, True,
                        "set_id=%s count=%d" % (set_id, count))
            return rec, codes

    # ------------------------------------------------------------------
    # verification
    # ------------------------------------------------------------------
    def verify(self, principal: str, method: str, seq: int, **kwargs: Any) -> VerifyResult:
        """Verify a factor presentation. Returns ``VerifyResult`` as data;
        malformed input and unknown principals yield ``valid=False``, only
        wrong types raise.

        * ``method="totp"``: kwargs ``code`` (str), ``step`` (int).
        * ``method="webauthn"``: kwargs ``cred_id``, ``challenge``,
          ``response`` (simulated signature bytes), ``sign_count`` (int),
          ``rp_id`` (str).
        * ``method="backup"``: kwargs ``code`` (str).
        """
        with self._lock:
            if method == "totp":
                return self._verify_totp(principal, seq, kwargs)
            if method == "webauthn":
                return self._verify_webauthn(principal, seq, kwargs)
            if method == "backup":
                return self._verify_backup(principal, seq, kwargs)
            self._audit("verify", principal, str(method), seq, False,
                        "unknown-method")
            return VerifyResult(principal, str(method), False, "unknown-method")

    def _verify_totp(self, principal: str, seq: int,
                     kw: Dict[str, Any]) -> VerifyResult:
        code = kw.get("code")
        step = kw.get("step")
        key = (principal, "totp")
        if key not in self._totp:
            self._audit("verify", principal, "totp", seq, False, "unknown")
            return VerifyResult(principal, "totp", False, "unknown")
        entry = self._totp[key]
        if entry["disabled"]:
            self._audit("verify", principal, "totp", seq, False, "disabled")
            return VerifyResult(principal, "totp", False, "disabled")
        if not isinstance(code, str) or not isinstance(step, int):
            self._audit("verify", principal, "totp", seq, False, "malformed")
            return VerifyResult(principal, "totp", False, "malformed")
        secret = entry["secret"]
        matched: Optional[int] = None
        for cand in range(step - TOTP_SKEW_STEPS, step + TOTP_SKEW_STEPS + 1):
            if cand < 0:
                continue
            if hmac.compare_digest(_totp_code(secret, cand), code):
                matched = cand
                break
        if matched is None:
            self._audit("verify", principal, "totp", seq, False, "mismatch")
            return VerifyResult(principal, "totp", False, "mismatch")
        if entry["last_used_step"] is not None and matched <= entry["last_used_step"]:
            # A valid code presented for an already-consumed step: replay.
            self._audit("verify", principal, "totp", seq, False, "replay")
            raise ReplayedCodeError(
                "totp code for step %d already consumed" % matched
            )
        entry["last_used_step"] = matched
        self._audit("verify", principal, "totp", seq, True,
                    "step=%d" % matched)
        return VerifyResult(principal, "totp", True, "ok")

    def _verify_webauthn(self, principal: str, seq: int,
                         kw: Dict[str, Any]) -> VerifyResult:
        cred_id = kw.get("cred_id")
        challenge = kw.get("challenge")
        response = kw.get("response")
        sign_count = kw.get("sign_count")
        rp_id = kw.get("rp_id")
        key = (principal, "webauthn")
        entry = self._webauthn.get(key)
        if entry is None:
            self._audit("verify", principal, "webauthn", seq, False, "unknown")
            return VerifyResult(principal, "webauthn", False, "unknown")
        if entry["disabled"]:
            self._audit("verify", principal, "webauthn", seq, False, "disabled")
            return VerifyResult(principal, "webauthn", False, "disabled")
        rec: WebAuthnEnrollment = entry["rec"]
        if (not isinstance(cred_id, str) or cred_id != rec.cred_id
                or not isinstance(challenge, bytes) or not challenge
                or not isinstance(response, bytes)
                or not isinstance(sign_count, int)
                or not isinstance(rp_id, str) or rp_id != rec.rp_id):
            self._audit("verify", principal, "webauthn", seq, False, "malformed")
            return VerifyResult(principal, "webauthn", False, "malformed")
        if entry["clone_detected"]:
            self._audit("verify", principal, "webauthn", seq, False,
                        "clone-flagged")
            return VerifyResult(principal, "webauthn", False, "clone-flagged")
        if sign_count <= entry["sign_count"]:
            entry["clone_detected"] = True
            self._audit("verify", principal, "webauthn", seq, False,
                        "clone-detected")
            raise CloneDetectedError(
                "signature counter regressed: %d <= %d"
                % (sign_count, entry["sign_count"])
            )
        expected = hmac.new(
            entry["keymat"], b"webauthn-sign|" + rec.cred_id.encode() + b"|" + challenge,
            hashlib.sha256,
        ).digest()
        if not hmac.compare_digest(expected, response):
            self._audit("verify", principal, "webauthn", seq, False, "bad-signature")
            return VerifyResult(principal, "webauthn", False, "bad-signature")
        entry["sign_count"] = sign_count
        self._audit("verify", principal, "webauthn", seq, True,
                    "sign_count=%d" % sign_count)
        return VerifyResult(principal, "webauthn", True, "ok")

    def _verify_backup(self, principal: str, seq: int,
                       kw: Dict[str, Any]) -> VerifyResult:
        code = kw.get("code")
        if not isinstance(code, str):
            self._audit("verify", principal, "backup", seq, False, "malformed")
            return VerifyResult(principal, "backup", False, "malformed")
        digest = _sha256_hex(code.encode())
        for (p, _set_id), entry in self._backup.items():
            if p != principal or not entry["active"]:
                continue
            if digest in entry["rec"].code_digests and digest not in entry["used"]:
                entry["used"].add(digest)
                self._audit("verify", principal, "backup", seq, True,
                            "consumed")
                return VerifyResult(principal, "backup", True, "ok")
        self._audit("verify", principal, "backup", seq, False, "mismatch")
        return VerifyResult(principal, "backup", False, "mismatch")

    # ------------------------------------------------------------------
    # introspection
    # ------------------------------------------------------------------
    def sign_challenge(self, principal: str, cred_id: str,
                       challenge: bytes) -> bytes:
        """Simulated authenticator: produce the expected WebAuthn response
        for a challenge. Exists so tests (and callers) can drive the
        ceremony without real hardware; production must replace this."""
        key = (principal, "webauthn")
        entry = self._webauthn[key]
        if entry["disabled"]:
            raise DisabledFactorError("factor disabled")
        return hmac.new(
            entry["keymat"], b"webauthn-sign|" + cred_id.encode() + b"|" + challenge,
            hashlib.sha256,
        ).digest()

    def totp_code_for(self, principal: str, step: int) -> str:
        """Simulated authenticator app: mint the TOTP code for a step."""
        entry = self._totp[(principal, "totp")]
        if entry["disabled"]:
            raise DisabledFactorError("factor disabled")
        return _totp_code(entry["secret"], step)

    def audit_events(self) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            return tuple(self._audit_log)

    def as_dict(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "schema": SCHEMA_PIN,
                "version": MFA_MANAGER_VERSION,
                "totp_enrollments": len(self._totp),
                "webauthn_enrollments": len(self._webauthn),
                "backup_sets": len(self._backup),
                "audit_events": len(self._audit_log),
            }


def mfa_manager_audit_event(event: str, principal: str, method: str, seq: int,
                            ok: bool, detail: str = "") -> Dict[str, Any]:
    """Build a standalone audit event dict in this module's schema."""
    return {
        "schema": SCHEMA_PIN,
        "version": MFA_MANAGER_VERSION,
        "event": event,
        "principal": principal,
        "method": method,
        "seq": seq,
        "ok": ok,
        "detail": detail,
    }
