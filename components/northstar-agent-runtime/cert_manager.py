"""Certificate manager: cert-manager-style issuance, renewal, and revocation (simulated).

Research note: *cert-manager* is the Kubernetes controller that turns a
``Certificate`` resource into a live X.509 certificate. The controller
reconciles three questions on every pass:

* **Issue** — no Secret (or an unsatisfiable one) exists for the desired
  ``Certificate``, so the controller creates a ``CertificateRequest`` and
  asks the named ``Issuer`` (self-signed, CA, ACME/Let's Encrypt, Vault) to
  sign it. The returned key pair is stored in the referenced Secret.
* **Renew** — the certificate's ``renewalTime`` is
  ``notAfter - renewBefore``; once the clock reaches it, the controller
  requests a fresh certificate and atomically swaps the Secret, keeping the
  old one pinned as ``superseded``. Renewal is a *re-issue*, not a mutation.
* **Revoke** — cert-manager itself has no revocation primitive (revocation
  lives at the CA: CRL/OCSP publication). Deleting the Secret or the
  ``Certificate`` resource is the operational equivalent of "stop trusting
  this key". This module records revocation as an explicit ledger state so
  a revoked identity can never be renewed or treated as active again.

This module is the *control-plane bookkeeping* of that loop, not a PKI:
there are no key pairs, no CSRs, no ACME challenges, no ASN.1, and no wire
contact with any CA. ``issue()`` mints digest-pinned metadata records over
caller-supplied logical seqs (no wall-clock); ``renew()`` mints a new
record and pins the old one as superseded; ``revoke()`` pins a
non-reversible revocation. The ``issuer`` field is a *claim* — it names the
issuer the operator configured, and this module never verifies that any CA
actually signed anything.

Fail-closed rules (load-bearing):

* Two live certificates may not cover the same domain set: ``issue()``
  refuses with ``DuplicateCertificateError`` while an active, unexpired,
  unrevoked certificate pins identical domains. (In real cert-manager this
  is an operator config conflict between two ``Certificate`` resources.)
* A revoked certificate is terminal: ``renew()`` raises
  ``RevokedCertificateError`` and it never appears in ``active()`` again.
* A superseded certificate cannot be renewed: ``renew()`` raises
  ``SupersededCertificateError`` — renewal walks forward only.
* Expiry is computed from caller seqs: a certificate is active while
  ``at_seq < not_after_seq``. A clock that moves backwards cannot resurrect
  an expired or revoked record; the ledger is append-only.

Honest scope: this books *reported* certificate lifecycle events. It cannot
prove a CA signed anything, cannot observe the wire, and cannot verify that
a host actually stopped serving a revoked certificate. ``revoke()`` proves
"the ledger records this identity as revoked", never "the world distrusts
this key" — that part belongs to the CA's CRL/OCSP publication.

Version pin: cert-manager.v1
Schema pin: northstar.cert-manager.v1
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except ImportError:  # pragma: no cover - fallback for standalone import

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        import json

        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


#: Module version.
CERT_MANAGER_VERSION = "cert-manager.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.cert-manager.v1"

#: Issuers this manager will record (names are claims, never verified).
KNOWN_ISSUERS = (
    "selfsigned",
    "ca",
    "acme-staging",
    "acme-production",
    "vault",
)

#: Certificate lifecycle states.
STATUS_ACTIVE = "active"
STATUS_SUPERSEDED = "superseded"
STATUS_REVOKED = "revoked"


class CertManagerError(Exception):
    """Base error for the certificate manager (fail-closed programming error)."""


class UnknownCertificateError(CertManagerError):
    """No certificate with this id exists in the ledger."""


class DuplicateCertificateError(CertManagerError):
    """A live certificate already pins the same domain set."""


class RevokedCertificateError(CertManagerError):
    """Operation refused: the certificate is revoked (terminal state)."""


class AlreadyRevokedError(CertManagerError):
    """The certificate is already revoked; revocation is not repeated."""


class SupersededCertificateError(CertManagerError):
    """Operation refused: the certificate was superseded by a renewal."""


class IssuerError(CertManagerError):
    """Unknown or malformed issuer name."""


def _check_seq(value: Any, name: str = "seq") -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise CertManagerError(f"{name} must be an int, got {type(value).__name__}")
    if value < 0:
        raise CertManagerError(f"{name} must be non-negative, got {value}")
    return value


def _check_str(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise CertManagerError(f"{name} must be a non-empty str")
    return value


def _digest(payload: Any) -> str:
    return "sha256:" + hashlib.sha256(jcs_canonical_json(payload)).hexdigest()


def _check_domain_pattern(pattern: Any) -> str:
    """Full-leftmost-label wildcards only, same rule as tls_terminator."""
    pattern = _check_str(pattern, "domain")
    if "*" in pattern:
        if not pattern.startswith("*.") or pattern.count("*") != 1:
            raise CertManagerError(
                f"wildcard must be full leftmost label only, got {pattern!r}"
            )
        rest = pattern[2:]
        if not rest or "." not in rest or rest.startswith(".") or rest.endswith("."):
            raise CertManagerError(f"bad wildcard domain: {pattern!r}")
    elif pattern.startswith(".") or pattern.endswith(".") or ".." in pattern:
        raise CertManagerError(f"bad domain: {pattern!r}")
    return pattern.lower()


def _check_domains(domains: Any) -> Tuple[str, ...]:
    if not isinstance(domains, (tuple, list)) or not domains:
        raise CertManagerError("domains must be a non-empty tuple/list of str")
    checked = tuple(_check_domain_pattern(d) for d in domains)
    if len(set(checked)) != len(checked):
        raise CertManagerError("duplicate domains in request")
    return tuple(sorted(checked))


def _check_issuer(issuer: Any) -> str:
    issuer = _check_str(issuer, "issuer")
    if issuer not in KNOWN_ISSUERS:
        raise IssuerError(
            f"unknown issuer {issuer!r}; known: {', '.join(KNOWN_ISSUERS)}"
        )
    return issuer


@dataclass(frozen=True)
class IssuedCertificate:
    """Digest-pinned certificate metadata (simulated; no key material exists)."""

    version: str
    cert_id: str
    domains: Tuple[str, ...]
    issuer: str
    serial: str
    not_before_seq: int
    not_after_seq: int
    renew_before_seqs: int
    digest: str

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "version": self.version,
            "cert_id": self.cert_id,
            "domains": list(self.domains),
            "issuer": self.issuer,
            "serial": self.serial,
            "not_before_seq": self.not_before_seq,
            "not_after_seq": self.not_after_seq,
            "renew_before_seqs": self.renew_before_seqs,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class RenewalRecord:
    """One re-issue: old cert -> new cert, with due-ness pinned."""

    version: str
    cert_id: str
    new_cert_id: str
    renewal_seq: int
    was_due: bool
    digest: str

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "version": self.version,
            "cert_id": self.cert_id,
            "new_cert_id": self.new_cert_id,
            "renewal_seq": self.renewal_seq,
            "was_due": self.was_due,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class RevocationRecord:
    """Terminal revocation entry (non-reversible by design)."""

    version: str
    cert_id: str
    reason: str
    revocation_seq: int
    digest: str

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "version": self.version,
            "cert_id": self.cert_id,
            "reason": self.reason,
            "revocation_seq": self.revocation_seq,
            "digest": self.digest,
        }


class CertManager:
    """cert-manager control-plane bookkeeping over caller-supplied seqs."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._certs: Dict[str, IssuedCertificate] = {}
        self._status: Dict[str, str] = {}
        self._superseded_by: Dict[str, str] = {}
        self._revocations: Dict[str, RevocationRecord] = {}
        self._renewals: List[RenewalRecord] = []
        self._next_serial = 1

    # -- internal ----------------------------------------------------

    def _require(self, cert_id: str) -> IssuedCertificate:
        _check_str(cert_id, "cert_id")
        cert = self._certs.get(cert_id)
        if cert is None:
            raise UnknownCertificateError(f"unknown certificate: {cert_id!r}")
        return cert

    def _renewal_time(self, cert: IssuedCertificate) -> int:
        return cert.not_after_seq - cert.renew_before_seqs

    # -- lifecycle ---------------------------------------------------

    def issue(
        self,
        domains: Any,
        issuer: Any,
        seq: int,
        duration_seqs: int = 90,
        renew_before_seqs: int = 30,
    ) -> IssuedCertificate:
        """Mint a new certificate record (fail-closed on duplicate coverage)."""
        return self._issue(domains, issuer, seq, duration_seqs, renew_before_seqs)

    def _issue(
        self,
        domains: Any,
        issuer: Any,
        seq: int,
        duration_seqs: int,
        renew_before_seqs: int,
        exclude_id: Optional[str] = None,
    ) -> IssuedCertificate:
        domains = _check_domains(domains)
        issuer = _check_issuer(issuer)
        seq = _check_seq(seq)
        if isinstance(duration_seqs, bool) or not isinstance(duration_seqs, int):
            raise CertManagerError("duration_seqs must be an int")
        if isinstance(renew_before_seqs, bool) or not isinstance(renew_before_seqs, int):
            raise CertManagerError("renew_before_seqs must be an int")
        if duration_seqs <= 0:
            raise CertManagerError("duration_seqs must be positive")
        if renew_before_seqs <= 0:
            raise CertManagerError("renew_before_seqs must be positive")
        if renew_before_seqs >= duration_seqs:
            raise CertManagerError("renew_before_seqs must be < duration_seqs")

        with self._lock:
            for cid, existing in self._certs.items():
                if cid == exclude_id:
                    continue  # renewal re-issues its own domain set
                status = self._status[cid]
                if status == STATUS_REVOKED:
                    continue
                if status != STATUS_ACTIVE:
                    continue
                if existing.not_after_seq <= seq:
                    continue  # expired: does not block re-issue
                if set(existing.domains) == set(domains):
                    raise DuplicateCertificateError(
                        f"live certificate {cid!r} already pins {sorted(domains)}"
                    )
            cert_id = f"cert-{len(self._certs) + 1}"
            serial = f"serial-{self._next_serial}"
            self._next_serial += 1
            not_after = seq + duration_seqs
            body = {
                "cert_id": cert_id,
                "domains": sorted(domains),
                "issuer": issuer,
                "serial": serial,
                "not_before_seq": seq,
                "not_after_seq": not_after,
                "renew_before_seqs": renew_before_seqs,
            }
            cert = IssuedCertificate(
                version=CERT_MANAGER_VERSION,
                cert_id=cert_id,
                domains=tuple(sorted(domains)),
                issuer=issuer,
                serial=serial,
                not_before_seq=seq,
                not_after_seq=not_after,
                renew_before_seqs=renew_before_seqs,
                digest=_digest(body),
            )
            self._certs[cert_id] = cert
            self._status[cert_id] = STATUS_ACTIVE
            return cert

    def due_for_renewal(self, cert_id: str, at_seq: int) -> bool:
        """True once at_seq reaches not_after - renew_before (and cert is active)."""
        at_seq = _check_seq(at_seq, "at_seq")
        with self._lock:
            cert = self._require(cert_id)
            if self._status[cert_id] != STATUS_ACTIVE:
                return False
            return at_seq >= self._renewal_time(cert)

    def renew(self, cert_id: str, seq: int) -> RenewalRecord:
        """Re-issue: mint a new cert, pin the old one as superseded.

        Renewal is always a re-issue (never a mutation), mirroring
        cert-manager's CertificateRequest loop. ``was_due`` records whether
        the renewal time had been reached; early renewal (``cmctl renew``
        style) is allowed but pinned as not-due.
        """
        seq = _check_seq(seq)
        with self._lock:
            old = self._require(cert_id)
            status = self._status[cert_id]
            if status == STATUS_REVOKED:
                raise RevokedCertificateError(
                    f"cannot renew revoked certificate {cert_id!r}"
                )
            if status == STATUS_SUPERSEDED:
                raise SupersededCertificateError(
                    f"certificate {cert_id!r} already superseded by "
                    f"{self._superseded_by[cert_id]!r}"
                )
            was_due = seq >= self._renewal_time(old)
            new = self._issue(
                domains=old.domains,
                issuer=old.issuer,
                seq=seq,
                duration_seqs=old.not_after_seq - old.not_before_seq,
                renew_before_seqs=old.renew_before_seqs,
                exclude_id=cert_id,
            )
            self._status[cert_id] = STATUS_SUPERSEDED
            self._superseded_by[cert_id] = new.cert_id
            body = {
                "cert_id": cert_id,
                "new_cert_id": new.cert_id,
                "renewal_seq": seq,
                "was_due": was_due,
            }
            record = RenewalRecord(
                version=CERT_MANAGER_VERSION,
                cert_id=cert_id,
                new_cert_id=new.cert_id,
                renewal_seq=seq,
                was_due=was_due,
                digest=_digest(body),
            )
            self._renewals.append(record)
            return record

    def revoke(self, cert_id: str, seq: int, reason: str = "") -> RevocationRecord:
        """Terminal revocation. A revoked identity never becomes active again."""
        seq = _check_seq(seq)
        if not isinstance(reason, str):
            raise CertManagerError("reason must be a str")
        with self._lock:
            self._require(cert_id)
            if self._status[cert_id] == STATUS_REVOKED:
                raise AlreadyRevokedError(f"certificate {cert_id!r} already revoked")
            body = {
                "cert_id": cert_id,
                "reason": reason,
                "revocation_seq": seq,
            }
            record = RevocationRecord(
                version=CERT_MANAGER_VERSION,
                cert_id=cert_id,
                reason=reason,
                revocation_seq=seq,
                digest=_digest(body),
            )
            self._revocations[cert_id] = record
            self._status[cert_id] = STATUS_REVOKED
            return record

    # -- views -------------------------------------------------------

    def certificate(self, cert_id: str) -> IssuedCertificate:
        with self._lock:
            return self._require(cert_id)

    def certificates(self) -> Tuple[IssuedCertificate, ...]:
        with self._lock:
            return tuple(self._certs[c] for c in sorted(self._certs))

    def status(self, cert_id: str) -> str:
        with self._lock:
            self._require(cert_id)
            return self._status[cert_id]

    def superseded_by(self, cert_id: str) -> Optional[str]:
        with self._lock:
            self._require(cert_id)
            return self._superseded_by.get(cert_id)

    def revocation(self, cert_id: str) -> Optional[RevocationRecord]:
        with self._lock:
            self._require(cert_id)
            return self._revocations.get(cert_id)

    def renewals(self) -> Tuple[RenewalRecord, ...]:
        with self._lock:
            return tuple(self._renewals)

    def active(self, at_seq: int) -> Tuple[str, ...]:
        """Ids that are active, unrevoked, and unexpired at ``at_seq``."""
        at_seq = _check_seq(at_seq, "at_seq")
        with self._lock:
            return tuple(
                cid
                for cid in sorted(self._certs)
                if self._status[cid] == STATUS_ACTIVE
                and self._certs[cid].not_after_seq > at_seq
            )

    def due(self, at_seq: int) -> Tuple[str, ...]:
        """Active cert ids whose renewal time has been reached at ``at_seq``."""
        at_seq = _check_seq(at_seq, "at_seq")
        with self._lock:
            return tuple(
                cid
                for cid in sorted(self._certs)
                if self._status[cid] == STATUS_ACTIVE
                and at_seq >= self._renewal_time(self._certs[cid])
            )


def cert_manager_audit_event(kind: str, seq: int, detail: dict) -> dict:
    """Shape an ``audit.ndjson/1`` record for certificate-manager events."""
    seq = _check_seq(seq)
    allowed = {"issued", "renewed", "revoked", "rejected"}
    if kind not in allowed:
        raise CertManagerError(f"unknown audit kind: {kind!r}")
    if not isinstance(detail, dict):
        raise CertManagerError("detail must be a dict")
    # Never log key material: this module has none; only ids, pins, digests.
    return {
        "schema": SCHEMA_PIN,
        "version": CERT_MANAGER_VERSION,
        "audit_seq": seq,
        "event": "cert-manager",
        "kind": kind,
        "detail": detail,
    }


def main() -> None:
    """Self-check: issue, duplicate refusal, renewal, revoke, audit."""
    mgr = CertManager()
    cert = mgr.issue(("Example.COM",), "acme-production", seq=1)
    assert cert.digest.startswith("sha256:")
    assert cert.domains == ("example.com",)  # normalized
    assert cert.not_after_seq == 91
    assert mgr.status("cert-1") == STATUS_ACTIVE
    assert mgr.active(at_seq=50) == ("cert-1",)
    assert not mgr.due_for_renewal("cert-1", at_seq=50)
    assert mgr.due_for_renewal("cert-1", at_seq=61)  # 91 - 30

    # Live duplicate coverage is refused.
    try:
        mgr.issue(("example.com",), "ca", seq=2)
    except DuplicateCertificateError:
        pass
    else:
        raise AssertionError("expected DuplicateCertificateError")

    # Renewal is a re-issue; old cert is superseded.
    rec = mgr.renew("cert-1", seq=65)
    assert rec.was_due
    assert mgr.status("cert-1") == STATUS_SUPERSEDED
    assert mgr.superseded_by("cert-1") == "cert-2"
    assert mgr.status("cert-2") == STATUS_ACTIVE
    try:
        mgr.renew("cert-1", seq=66)
    except SupersededCertificateError:
        pass
    else:
        raise AssertionError("expected SupersededCertificateError")

    # Revocation is terminal.
    rev = mgr.revoke("cert-2", seq=70, reason="key-compromise")
    assert rev.digest.startswith("sha256:")
    assert mgr.status("cert-2") == STATUS_REVOKED
    assert mgr.active(at_seq=75) == ()
    try:
        mgr.renew("cert-2", seq=71)
    except RevokedCertificateError:
        pass
    else:
        raise AssertionError("expected RevokedCertificateError")
    try:
        mgr.revoke("cert-2", seq=72)
    except AlreadyRevokedError:
        pass
    else:
        raise AssertionError("expected AlreadyRevokedError")

    # Revoked certs no longer block re-issue of the same names.
    fresh = mgr.issue(("example.com",), "vault", seq=80)
    assert mgr.status(fresh.cert_id) == STATUS_ACTIVE

    event = cert_manager_audit_event(
        "revoked", 90, {"cert_id": "cert-2", "reason": "key-compromise"}
    )
    assert event["kind"] == "revoked"

    print("cert-manager OK: issue, duplicate refusal, renew, revoke, audit")


if __name__ == "__main__":
    main()
