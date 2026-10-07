"""TLS terminator: edge handshake negotiation + SNI certificate selection + ALPN (simulated).

Research note: *TLS termination* is the edge-proxy pattern where a front-end
(nginx ``ssl``, HAProxy ``ssl`` bind, Envoy ``transport_socket``) owns the
server side of the TLS handshake on behalf of backend services. Per RFC 8446
(TLS 1.3) and RFC 6066 (SNI), the terminator must decide three things from
the client's ClientHello before any plaintext reaches the application:

* **SNI certificate selection** — the server name indication picks which
  certificate to present. Exact names win over wildcards (``*.example.com``
  matches exactly one label deep); an unrecognized name is a hard refusal,
  not a default-certificate answer.
* **Version/cipher negotiation** — the server takes the highest mutually
  supported TLS version and then its own most-preferred cipher among the
  client's offers (server preference wins; the client's offer order is
  advisory). An empty overlap is a handshake failure, never a downgrade.
* **ALPN** (RFC 7301) — the server picks its most-preferred application
  protocol from the client's list (``h2`` over ``http/1.1``). No overlap
  means *no protocol selected*, which is a legal outcome — the connection
  may proceed without ALPN, not fail.

*Session resumption* (RFC 8446 §2.2 / RFC 5077-style tickets) skips
certificate presentation on a later connection: the client offers a session
ticket; the terminator authenticates it with a MAC over the ticket key
material and resumes the pinned parameters. A forged or expired ticket is
refused fail-closed — it never falls back to a silent full handshake with
the same audit trail.

Honest scope: this is the *negotiation bookkeeping* of a terminator, not a
TLS implementation. There is no ASN.1 parsing, no X.509 chain building, no
finite-field key exchange, no record-layer encryption — the "certificates"
are digest-pinned metadata records, the "key exchange" is a deterministic
HMAC derivation, and the "session keys" never protect anything. It proves
"the terminator negotiated these parameters for this SNI", never "the
peer is who the certificate claims" or "the channel is confidential".
``handshake()`` decides, it does not encrypt.

Version pin: tls-terminator.v1
Schema pin: northstar.tls-terminator.v1
"""

from __future__ import annotations

import hashlib
import hmac
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except ImportError:  # pragma: no cover - fallback for standalone import

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        import json

        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


#: Module version.
TLS_TERMINATOR_VERSION = "tls-terminator.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.tls-terminator.v1"

TLS_13 = "TLS1.3"
TLS_12 = "TLS1.2"

#: Server-supported versions, most preferred first.
SERVER_VERSIONS = (TLS_13, TLS_12)

#: Server-preferred cipher order per version (server preference wins).
SERVER_CIPHERS: Dict[str, Tuple[str, ...]] = {
    TLS_13: (
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
        "TLS_AES_128_GCM_SHA256",
    ),
    TLS_12: (
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    ),
}

#: Server-preferred ALPN protocols, most preferred first.
DEFAULT_ALPN_PROTOCOLS = ("h2", "http/1.1")

#: Ticket lifetime in caller-supplied seqs.
TICKET_LIFETIME_SEQS = 10_000

_KNOWN_CIPHERS = frozenset(c for ciphers in SERVER_CIPHERS.values() for c in ciphers)


class TLSTerminatorError(Exception):
    """Base error for the TLS terminator (fail-closed programming error)."""


class CertificateError(TLSTerminatorError):
    """Malformed certificate registration or invalid validity bounds."""


class UnknownServerNameError(TLSTerminatorError):
    """No certificate covers the presented SNI (no default-cert fallback)."""


class NoVersionOverlapError(TLSTerminatorError):
    """Client and server share no TLS version (refused, never downgraded)."""


class NoCipherOverlapError(TLSTerminatorError):
    """Client and server share no cipher suite for the negotiated version."""


class TicketError(TLSTerminatorError):
    """Session ticket failed authentication, lookup, or lifetime checks."""


class ExpiredCertificateError(TLSTerminatorError):
    """The selected certificate is not valid at the caller-supplied seq."""


def _check_seq(value: Any, name: str = "seq") -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TLSTerminatorError(f"{name} must be an int, got {type(value).__name__}")
    if value < 0:
        raise TLSTerminatorError(f"{name} must be non-negative, got {value}")
    return value


def _check_str(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise TLSTerminatorError(f"{name} must be a non-empty str")
    return value


def _digest(payload: Any) -> str:
    return "sha256:" + hashlib.sha256(jcs_canonical_json(payload)).hexdigest()


def _canonical(value: Any) -> Any:
    """Type-tagged canonical body so digests distinguish 1 vs "1" vs True."""
    if isinstance(value, bool):
        return {"t": "bool", "v": value}
    if isinstance(value, int):
        if value > 2**53 or value < -(2**53):
            raise TLSTerminatorError("int outside safe canonical range (>2^53)")
        return {"t": "int", "v": value}
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise TLSTerminatorError("NaN/inf not canonicalizable")
        return {"t": "float", "v": repr(value)}
    if isinstance(value, str):
        return {"t": "str", "v": value}
    if value is None:
        return {"t": "null"}
    if isinstance(value, (tuple, list)):
        return {"t": "list", "v": [_canonical(v) for v in value]}
    if isinstance(value, dict):
        return {"t": "map", "v": [[_canonical(k), _canonical(v)] for k, v in sorted(value.items())]}
    raise TLSTerminatorError(f"value of type {type(value).__name__} not canonicalizable")


def _sni_matches(pattern: str, server_name: str) -> bool:
    """Exact names match themselves; `*.example.com` matches one label deep."""
    if pattern == server_name:
        return True
    if pattern.startswith("*."):
        suffix = pattern[1:]  # ".example.com"
        if server_name.endswith(suffix):
            prefix = server_name[: -len(suffix)]
            return bool(prefix) and "." not in prefix
    return False


def _check_domain_pattern(pattern: Any) -> str:
    pattern = _check_str(pattern, "domain")
    if "*" in pattern:
        if not pattern.startswith("*.") or pattern.count("*") != 1:
            raise CertificateError(
                f"wildcard must be full leftmost label only, got {pattern!r}"
            )
        rest = pattern[2:]
        if not rest or "." not in rest or rest.startswith(".") or rest.endswith("."):
            raise CertificateError(f"bad wildcard domain: {pattern!r}")
    elif pattern.startswith(".") or pattern.endswith(".") or ".." in pattern:
        raise CertificateError(f"bad domain: {pattern!r}")
    return pattern.lower()


@dataclass(frozen=True)
class Certificate:
    """Digest-pinned certificate metadata (simulated; no ASN.1, no chain)."""

    version: str
    domains: Tuple[str, ...]
    serial: str
    not_before_seq: int
    not_after_seq: int
    digest: str

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "version": self.version,
            "domains": list(self.domains),
            "serial": self.serial,
            "not_before_seq": self.not_before_seq,
            "not_after_seq": self.not_after_seq,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class ClientHello:
    """Simulated client hello: offered versions, ciphers, ALPN, optional ticket."""

    versions: Tuple[str, ...]
    offered_ciphers: Tuple[str, ...]
    alpn_protocols: Tuple[str, ...]
    session_ticket: Optional[str] = None

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "versions": list(self.versions),
            "offered_ciphers": list(self.offered_ciphers),
            "alpn_protocols": list(self.alpn_protocols),
            "session_ticket": self.session_ticket,
        }


@dataclass(frozen=True)
class HandshakeResult:
    """Negotiated parameters for one terminated handshake."""

    version: str
    sni: str
    cert_digest: str
    tls_version: str
    cipher: str
    alpn_protocol: Optional[str]
    session_ticket: str
    resumed: bool
    seq: int
    handshake_digest: str

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "version": self.version,
            "sni": self.sni,
            "cert_digest": self.cert_digest,
            "tls_version": self.tls_version,
            "cipher": self.cipher,
            "alpn_protocol": self.alpn_protocol,
            "session_ticket": self.session_ticket,
            "resumed": self.resumed,
            "seq": self.seq,
            "handshake_digest": self.handshake_digest,
        }


@dataclass(frozen=True)
class _TicketRecord:
    ticket_id: str
    sni: str
    cert_digest: str
    tls_version: str
    cipher: str
    alpn_protocol: Optional[str]
    issued_seq: int
    mac: str


class TLSTerminator:
    """Simulated edge TLS terminator: SNI cert selection, negotiation, tickets.

    Owns a certificate registry (``add_cert``), negotiates full handshakes
    (``handshake``), picks ALPN protocols (``alpn``), and issues/authenticates
    session tickets (``resume``). Everything is caller-seq driven: no
    wall-clock anywhere, so certificate validity and ticket lifetimes are
    checked against caller-supplied logical seqs.
    """

    def __init__(
        self,
        ticket_secret: bytes,
        alpn_protocols: Tuple[str, ...] = DEFAULT_ALPN_PROTOCOLS,
    ) -> None:
        if not isinstance(ticket_secret, (bytes, bytearray)) or len(ticket_secret) < 16:
            raise TLSTerminatorError("ticket_secret must be bytes of at least 16 bytes")
        self._secret = bytes(ticket_secret)
        protos = tuple(_check_str(p, "alpn_protocol") for p in alpn_protocols)
        if len(set(protos)) != len(protos):
            raise TLSTerminatorError("duplicate ALPN protocols")
        self._alpn_protocols = protos
        self._certs: List[Certificate] = []
        self._tickets: Dict[str, _TicketRecord] = {}
        self._ticket_counter = 0
        self._lock = threading.RLock()

    # -- certificates ----------------------------------------------------

    def add_cert(
        self,
        domains: Tuple[str, ...],
        serial: str,
        not_before_seq: int,
        not_after_seq: int,
        seq: int,
    ) -> Certificate:
        """Register a certificate for one or more SNI domain patterns."""
        _check_seq(seq)
        serial = _check_str(serial, "serial")
        not_before_seq = _check_seq(not_before_seq, "not_before_seq")
        not_after_seq = _check_seq(not_after_seq, "not_after_seq")
        if not_after_seq <= not_before_seq:
            raise CertificateError("not_after_seq must exceed not_before_seq")
        if not isinstance(domains, (tuple, list)) or not domains:
            raise CertificateError("domains must be a non-empty tuple/list")
        norm = tuple(_check_domain_pattern(d) for d in domains)
        if len(set(norm)) != len(norm):
            raise CertificateError("duplicate domain patterns")
        digest = _digest(
            {
                "module": "tls-terminator",
                "kind": "certificate",
                "domains": list(norm),
                "serial": serial,
                "not_before_seq": not_before_seq,
                "not_after_seq": not_after_seq,
            }
        )
        cert = Certificate(
            version=TLS_TERMINATOR_VERSION,
            domains=norm,
            serial=serial,
            not_before_seq=not_before_seq,
            not_after_seq=not_after_seq,
            digest=digest,
        )
        with self._lock:
            self._certs.append(cert)
        return cert

    def cert_for(self, server_name: str, at_seq: int) -> Certificate:
        """Select the certificate for an SNI (exact beats wildcard)."""
        server_name = _check_str(server_name, "server_name").lower()
        at_seq = _check_seq(at_seq, "at_seq")
        with self._lock:
            certs = list(self._certs)
        exact: Optional[Certificate] = None
        wildcard: Optional[Certificate] = None
        for cert in certs:
            for pattern in cert.domains:
                if pattern == server_name:
                    exact = cert
                    break
                if pattern.startswith("*.") and _sni_matches(pattern, server_name):
                    wildcard = wildcard or cert
            if exact is not None:
                break
        chosen = exact or wildcard
        if chosen is None:
            raise UnknownServerNameError(f"no certificate for SNI {server_name!r}")
        if not (chosen.not_before_seq <= at_seq < chosen.not_after_seq):
            raise ExpiredCertificateError(
                f"certificate {chosen.serial} not valid at seq {at_seq}"
            )
        return chosen

    def certificates(self) -> Tuple[Certificate, ...]:
        """Registered certificates (digest pins, no private material)."""
        with self._lock:
            return tuple(self._certs)

    # -- ALPN ------------------------------------------------------------

    def alpn(self, client_protocols: Tuple[str, ...]) -> Optional[str]:
        """Pick the server's most-preferred protocol the client offers.

        No overlap is a legal outcome: returns ``None`` (proceed without
        ALPN) rather than failing the connection.
        """
        if not isinstance(client_protocols, (tuple, list)):
            raise TLSTerminatorError("client_protocols must be a tuple/list")
        offered = {_check_str(p, "client_protocol").lower() for p in client_protocols}
        for proto in self._alpn_protocols:
            if proto.lower() in offered:
                return proto
        return None

    # -- handshake -------------------------------------------------------

    def handshake(
        self, server_name: str, client_hello: ClientHello, seq: int
    ) -> HandshakeResult:
        """Negotiate a full handshake for ``server_name``.

        Selects the SNI certificate, intersects TLS versions (server takes
        the highest overlap), then picks the server's most-preferred cipher
        among the client's offers for that version. ALPN is negotiated via
        :meth:`alpn`. A fresh session ticket is issued for every result.
        """
        seq = _check_seq(seq)
        if not isinstance(client_hello, ClientHello):
            raise TLSTerminatorError("client_hello must be a ClientHello")
        cert = self.cert_for(server_name, seq)
        version = self._negotiate_version(client_hello)
        cipher = self._negotiate_cipher(version, client_hello)
        alpn_proto = self.alpn(client_hello.alpn_protocols)
        ticket = self._issue_ticket(
            sni=server_name.lower(),
            cert=cert,
            tls_version=version,
            cipher=cipher,
            alpn_protocol=alpn_proto,
            seq=seq,
        )
        digest = _digest(
            {
                "module": "tls-terminator",
                "kind": "handshake",
                "sni": server_name.lower(),
                "cert_digest": cert.digest,
                "tls_version": version,
                "cipher": cipher,
                "alpn_protocol": alpn_proto,
                "session_ticket": ticket,
                "resumed": False,
                "seq": seq,
            }
        )
        return HandshakeResult(
            version=TLS_TERMINATOR_VERSION,
            sni=server_name.lower(),
            cert_digest=cert.digest,
            tls_version=version,
            cipher=cipher,
            alpn_protocol=alpn_proto,
            session_ticket=ticket,
            resumed=False,
            seq=seq,
            handshake_digest=digest,
        )

    def resume(self, ticket_id: str, seq: int) -> HandshakeResult:
        """Resume a session from a ticket: authenticate the MAC, re-pin params.

        A forged, unknown, or expired ticket raises :class:`TicketError`
        fail-closed — never a silent downgrade to an anonymous session.
        """
        seq = _check_seq(seq)
        ticket_id = _check_str(ticket_id, "ticket_id")
        with self._lock:
            record = self._tickets.get(ticket_id)
        if record is None:
            raise TicketError("unknown session ticket")
        expected = hmac.new(
            self._secret, b"ticket:" + ticket_id.encode(), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(expected, record.mac):
            raise TicketError("session ticket failed authentication")
        if seq - record.issued_seq > TICKET_LIFETIME_SEQS:
            raise TicketError("session ticket expired")
        if seq < record.issued_seq:
            raise TicketError("ticket issued after presented seq (clock skew)")
        digest = _digest(
            {
                "module": "tls-terminator",
                "kind": "handshake",
                "sni": record.sni,
                "cert_digest": record.cert_digest,
                "tls_version": record.tls_version,
                "cipher": record.cipher,
                "alpn_protocol": record.alpn_protocol,
                "session_ticket": ticket_id,
                "resumed": True,
                "seq": seq,
            }
        )
        return HandshakeResult(
            version=TLS_TERMINATOR_VERSION,
            sni=record.sni,
            cert_digest=record.cert_digest,
            tls_version=record.tls_version,
            cipher=record.cipher,
            alpn_protocol=record.alpn_protocol,
            session_ticket=ticket_id,
            resumed=True,
            seq=seq,
            handshake_digest=digest,
        )

    # -- internals -------------------------------------------------------

    def _negotiate_version(self, hello: ClientHello) -> str:
        offered = {_check_str(v, "version") for v in hello.versions}
        for version in SERVER_VERSIONS:  # server preference: highest first
            if version in offered:
                return version
        raise NoVersionOverlapError(
            f"no TLS version overlap (client offered {sorted(offered)})"
        )

    def _negotiate_cipher(self, version: str, hello: ClientHello) -> str:
        offered = {_check_str(c, "cipher") for c in hello.offered_ciphers}
        for cipher in SERVER_CIPHERS[version]:  # server preference wins
            if cipher in offered:
                return cipher
        raise NoCipherOverlapError(
            f"no cipher overlap for {version} (client offered {len(offered)})"
        )

    def _issue_ticket(
        self,
        sni: str,
        cert: Certificate,
        tls_version: str,
        cipher: str,
        alpn_protocol: Optional[str],
        seq: int,
    ) -> str:
        with self._lock:
            self._ticket_counter += 1
            counter = self._ticket_counter
        body = f"{sni}|{counter}|{seq}"
        ticket_id = "tkt-" + hmac.new(
            self._secret, b"issue:" + body.encode(), hashlib.sha256
        ).hexdigest()[:32]
        mac = hmac.new(
            self._secret, b"ticket:" + ticket_id.encode(), hashlib.sha256
        ).hexdigest()
        with self._lock:
            self._tickets[ticket_id] = _TicketRecord(
                ticket_id=ticket_id,
                sni=sni,
                cert_digest=cert.digest,
                tls_version=tls_version,
                cipher=cipher,
                alpn_protocol=alpn_protocol,
                issued_seq=seq,
                mac=mac,
            )
        return ticket_id


def check_client_hello(
    versions: Tuple[str, ...],
    offered_ciphers: Tuple[str, ...],
    alpn_protocols: Tuple[str, ...] = (),
    session_ticket: Optional[str] = None,
) -> ClientHello:
    """Build a validated ClientHello (fail-closed on malformed offers)."""
    if not isinstance(versions, (tuple, list)) or not versions:
        raise TLSTerminatorError("versions must be a non-empty tuple/list")
    if not isinstance(offered_ciphers, (tuple, list)) or not offered_ciphers:
        raise TLSTerminatorError("offered_ciphers must be a non-empty tuple/list")
    for v in versions:
        _check_str(v, "version")
    for c in offered_ciphers:
        _check_str(c, "cipher")
    for p in alpn_protocols:
        _check_str(p, "alpn_protocol")
    if session_ticket is not None:
        _check_str(session_ticket, "session_ticket")
    return ClientHello(
        versions=tuple(versions),
        offered_ciphers=tuple(offered_ciphers),
        alpn_protocols=tuple(alpn_protocols),
        session_ticket=session_ticket,
    )


def tls_terminator_audit_event(kind: str, seq: int, detail: dict) -> dict:
    """Shape an ``audit.ndjson/1`` record for terminator events."""
    seq = _check_seq(seq)
    allowed = {
        "cert-added",
        "handshake",
        "handshake-refused",
        "ticket-issued",
        "resumed",
        "resume-refused",
        "rejected",
    }
    if kind not in allowed:
        raise TLSTerminatorError(f"unknown audit kind: {kind!r}")
    if not isinstance(detail, dict):
        raise TLSTerminatorError("detail must be a dict")
    # Never log raw secrets: only pins, ids, digests, and public parameters.
    return {
        "schema": SCHEMA_PIN,
        "version": TLS_TERMINATOR_VERSION,
        "audit_seq": seq,
        "event": "tls-terminator",
        "kind": kind,
        "detail": detail,
    }


def main() -> None:
    """Self-check: certs, SNI selection, negotiation, ALPN, tickets."""
    term = TLSTerminator(ticket_secret=b"0123456789abcdef")
    cert = term.add_cert(
        domains=("example.com", "*.example.com"),
        serial="00:11:22",
        not_before_seq=0,
        not_after_seq=10_000,
        seq=1,
    )
    assert cert.digest.startswith("sha256:")
    assert len(term.certificates()) == 1

    # SNI selection: exact beats wildcard.
    assert term.cert_for("example.com", 5) is cert
    assert term.cert_for("www.example.com", 5) is cert
    try:
        term.cert_for("deep.www.example.com", 5)  # wildcard is one label deep
    except UnknownServerNameError:
        pass
    else:
        raise AssertionError("expected UnknownServerNameError")
    try:
        term.cert_for("other.com", 5)
    except UnknownServerNameError:
        pass
    else:
        raise AssertionError("expected UnknownServerNameError")
    try:
        term.cert_for("example.com", 10_000)  # at boundary: expired
    except ExpiredCertificateError:
        pass
    else:
        raise AssertionError("expected ExpiredCertificateError")

    hello = check_client_hello(
        versions=("TLS1.2", "TLS1.3"),
        offered_ciphers=("TLS_AES_128_GCM_SHA256", "TLS_CHACHA20_POLY1305_SHA256"),
        alpn_protocols=("http/1.1", "h2"),
    )
    result = term.handshake("www.example.com", hello, seq=10)
    assert result.tls_version == "TLS1.3"  # highest overlap wins
    # server preference wins over client order: CHACHA before AES_128 in our list
    assert result.cipher == "TLS_CHACHA20_POLY1305_SHA256"
    assert result.alpn_protocol == "h2"  # server preference wins
    assert not result.resumed
    assert result.session_ticket.startswith("tkt-")

    # ALPN: no overlap is legal -> None, not an error.
    assert term.alpn(("spdy/3",)) is None

    # Version mismatch: refused, never downgraded.
    bad_version = check_client_hello(
        versions=("TLS1.1",), offered_ciphers=("TLS_AES_128_GCM_SHA256",)
    )
    try:
        term.handshake("example.com", bad_version, seq=11)
    except NoVersionOverlapError:
        pass
    else:
        raise AssertionError("expected NoVersionOverlapError")

    # Cipher mismatch for the negotiated version.
    bad_cipher = check_client_hello(
        versions=("TLS1.3",), offered_ciphers=("DES-CBC3-SHA",)
    )
    try:
        term.handshake("example.com", bad_cipher, seq=12)
    except NoCipherOverlapError:
        pass
    else:
        raise AssertionError("expected NoCipherOverlapError")

    # Session resumption round-trips the pinned parameters.
    resumed = term.resume(result.session_ticket, seq=20)
    assert resumed.resumed
    assert resumed.tls_version == result.tls_version
    assert resumed.cipher == result.cipher
    assert resumed.alpn_protocol == result.alpn_protocol
    assert resumed.cert_digest == result.cert_digest
    try:
        term.resume("tkt-forged", seq=21)
    except TicketError:
        pass
    else:
        raise AssertionError("expected TicketError")
    try:
        term.resume(result.session_ticket, seq=20 + TICKET_LIFETIME_SEQS + 1)
    except TicketError:
        pass
    else:
        raise AssertionError("expected TicketError (expired)")

    event = tls_terminator_audit_event(
        "handshake", 30, {"sni": "example.com", "cipher": result.cipher}
    )
    assert event["kind"] == "handshake"

    print("tls-terminator OK: certs, SNI, negotiation, ALPN, tickets")


if __name__ == "__main__":
    main()
