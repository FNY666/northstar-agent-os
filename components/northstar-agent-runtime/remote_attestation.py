"""Remote attestation interface (TPM-style, simulated).

Research motivation: *remote attestation* lets a verifier learn, over a
network, that a remote host runs the software it claims to run. The
classic construction is TPM-based: at boot each component's digest is
*measured* into Platform Configuration Registers (PCRs) via the
extend operation ``PCR_new = H(PCR_old || digest)``; to attest, the
TPM signs (quotes) the PCR values together with a verifier-supplied
nonce under an Attestation Key (AK); the verifier checks the
signature, the nonce freshness, and that the quoted PCRs match the
*golden* values for the expected software stack.

This module models the attestation *interface and state machine*,
deliberately simulated:

- **No TPM.** PCRs are an in-memory table; the extend math is real
  SHA-256 but nothing anchors it in hardware. The AK is a
  deterministic HMAC key derived from a pinned domain seed, not a
  certified key; there is no EK certificate chain.
- **Verifier knows the AK.** The simulated "signature" is an HMAC tag,
  so verification requires the verifier to share the AK. Real TPMs
  use asymmetric quotes verifiable under a public key plus a privacy
  CA / DAA scheme. The tag still binds every quoted field, so the
  *mechanics* under test (nonce freshness, PCR binding, golden-value
  comparison, tamper detection) are the same ones the host must get
  right when a real TPM drops in behind this interface.
- **Golden values are the host's policy.** A quote that verifies
  means "these PCRs were quoted by this attester with this nonce",
  never "this software is trustworthy". The verifier supplies the
  expected PCR map; anything else is a policy outcome (``False``).

Public API:

- ``Attester(label)`` -- the measured host; ``measure(component,
  digest)`` extends PCRs; ``quote(nonce, seq)`` mints a frozen
  ``Quote``; ``pcrs()`` snapshot view.
- ``Attester.endorse(endorsement_id, issuer_label, seq, ...)`` --
  books one issuer endorsement of this attester's attestation key
  (the privacy-CA / EK-certificate analogue); returns a frozen
  ``EndorsementRecord`` pinned by a deterministic digest; duplicate
  endorsement ids are refused fail-closed.
- ``RemoteAttestation`` -- spec-named facade over ``Attester``
  exposing the spec API ``quote()`` / ``verify()`` / ``endorse()``.
- ``verify(quote, expected_label, expected_nonce, expected_pcrs)`` -- verifier-side
  check; ``True`` / ``False`` (policy outcome, raises only on
  malformed caller input).
- ``expected_pcrs(attester)`` -- convenience: snapshot this
  attester's PCRs as golden values (for tests).
- ``remote_attestation_audit_event(kind, seq)`` -- ``audit.ndjson/1``
  records; kinds ``"measured"`` / ``"quoted"`` / ``"endorsed"`` /
  ``"verified"`` / ``"rejected"``.
- ``RemoteAttestationError``.

Measurement model:

- ``component`` names one of the pinned PCR indices:
  ``"bootloader"`` -> PCR 0, ``"firmware"`` -> PCR 1,
  ``"kernel"`` -> PCR 2, ``"runtime"`` -> PCR 3, ``"config"`` -> PCR 4.
  Unknown components are rejected fail-closed (an unmapped
  measurement must not land in a default bucket).
- ``digest`` is the component measurement, bytes (32 bytes expected
  but not required); str digests are rejected, never silently
  encoded.
- Extend: ``pcr[n] = SHA256(pcr[n] || digest)`` from the all-zeros
  genesis. Re-measuring a component extends again, so the PCR binds
  the full measurement *history*, not just the latest value.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field
from typing import Dict, Mapping, Tuple

__all__ = [
    "REMOTE_ATTESTATION_VERSION",
    "SCHEMA_PIN",
    "PCR_COMPONENTS",
    "RemoteAttestationError",
    "Quote",
    "EndorsementRecord",
    "Attester",
    "RemoteAttestation",
    "verify",
    "expected_pcrs",
    "remote_attestation_audit_event",
    "main",
]

REMOTE_ATTESTATION_VERSION = "remote-attestation.v1"
SCHEMA_PIN = "northstar.remote-attestation.v1"

# Component name -> PCR index. Closed vocabulary: an unknown component
# name is a caller error, never a default bucket.
PCR_COMPONENTS: Dict[str, int] = {
    "bootloader": 0,
    "firmware": 1,
    "kernel": 2,
    "runtime": 3,
    "config": 4,
}

_GENESIS_PCR = b"\x00" * 32
_DOMAIN = b"northstar.remote-attestation.v1"


class RemoteAttestationError(Exception):
    """Fail-closed attestation error."""


def _check_seq(seq: int) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise RemoteAttestationError("seq must be a non-negative int")
    return seq


def _check_component(component: str) -> str:
    if not isinstance(component, str) or component not in PCR_COMPONENTS:
        raise RemoteAttestationError(
            f"unknown component {component!r}; "
            f"expected one of {sorted(PCR_COMPONENTS)}"
        )
    return component


def _check_digest(digest: bytes) -> bytes:
    if not isinstance(digest, bytes) or len(digest) == 0:
        raise RemoteAttestationError("digest must be non-empty bytes")
    return digest


def _check_nonce(nonce: bytes) -> bytes:
    if not isinstance(nonce, bytes) or len(nonce) == 0:
        raise RemoteAttestationError("nonce must be non-empty bytes")
    return nonce


def _check_label(label: str) -> str:
    if not isinstance(label, str) or not label:
        raise RemoteAttestationError("label must be a non-empty str")
    return label


def _ak_key(label: str) -> bytes:
    """Deterministic attestation key for a label (simulated AK)."""
    return hashlib.sha256(_DOMAIN + b"/ak:" + label.encode("utf-8")).digest()


def _extend(pcr: bytes, digest: bytes) -> bytes:
    return hashlib.sha256(pcr + digest).digest()


def _quote_tag(
    label: str, pcr_map: Mapping[int, bytes], nonce: bytes, seq: int
) -> bytes:
    """Bind every quoted field into one tag (the simulated quote signature)."""
    h = hmac.new(_ak_key(label), _DOMAIN + b"/quote", hashlib.sha256)
    h.update(label.encode("utf-8"))
    for index in sorted(pcr_map):
        h.update(index.to_bytes(4, "big"))
        h.update(pcr_map[index])
    h.update(nonce)
    h.update(seq.to_bytes(8, "big"))
    return h.digest()


def _check_pin(pin: str) -> str:
    """An optional endorsement digest pin: '' or 'sha256:<64 hex>."""
    if not isinstance(pin, str):
        raise RemoteAttestationError(
            "endorsement_digest must be a 'sha256:<64hex>' pin or ''"
        )
    if pin and not (
        pin.startswith("sha256:")
        and len(pin) == 7 + 64
        and all(c in "0123456789abcdef" for c in pin[7:])
    ):
        raise RemoteAttestationError(
            "endorsement_digest must be a 'sha256:<64hex>' pin or ''"
        )
    return pin


def _endorsement_pin(
    endorsement_id: str,
    attester_label: str,
    issuer_label: str,
    endorsement_digest: str,
) -> bytes:
    """Deterministic pin binding one endorsement's declared fields."""
    h = hashlib.sha256(_DOMAIN + b"/endorsement")
    h.update(endorsement_id.encode("utf-8"))
    h.update(attester_label.encode("utf-8"))
    h.update(issuer_label.encode("utf-8"))
    h.update(endorsement_digest.encode("utf-8"))
    return h.digest()


@dataclass(frozen=True)
class Quote:
    """A signed PCR snapshot bound to a verifier nonce."""

    label: str
    pcrs: Tuple[Tuple[int, bytes], ...]
    nonce: bytes
    seq: int
    tag: bytes
    version: str = REMOTE_ATTESTATION_VERSION

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "version": self.version,
            "label": self.label,
            "pcrs": {str(i): p.hex() for i, p in self.pcrs},
            "nonce": self.nonce.hex(),
            "seq": self.seq,
            "tag": self.tag.hex(),
        }

    def pcr_map(self) -> Dict[int, bytes]:
        return dict(self.pcrs)


@dataclass(frozen=True)
class EndorsementRecord:
    """One issuer endorsement of an attester's attestation key.

    The privacy-CA / EK-certificate analogue: a third-party issuer
    declares that this attester's AK is trustworthy. The issuer's raw
    material never enters the record -- only the optional
    ``endorsement_digest`` pin. Integrity is self-contained:
    ``verify()`` recomputes the pin deterministically.
    """

    endorsement_id: str
    attester_label: str
    issuer_label: str
    endorsement_digest: str
    pin: bytes
    version: str = REMOTE_ATTESTATION_VERSION

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "version": self.version,
            "endorsement_id": self.endorsement_id,
            "attester_label": self.attester_label,
            "issuer_label": self.issuer_label,
            "endorsement_digest": self.endorsement_digest,
            "pin": self.pin.hex(),
        }

    def verify(self) -> bool:
        recomputed = _endorsement_pin(
            self.endorsement_id,
            self.attester_label,
            self.issuer_label,
            self.endorsement_digest,
        )
        return hmac.compare_digest(recomputed, self.pin)


class Attester:
    """The measured host: extends PCRs and mints quotes.

    One label per attester; labels are the attester identity the
    verifier keys its golden values on.
    """

    def __init__(self, label: str) -> None:
        self._label = _check_label(label)
        self._pcrs: Dict[int, bytes] = {
            i: _GENESIS_PCR for i in PCR_COMPONENTS.values()
        }
        self._quote_count = 0
        self._endorsements: Dict[str, EndorsementRecord] = {}

    @property
    def label(self) -> str:
        return self._label

    def measure(self, component: str, digest: bytes) -> bytes:
        """Extend the component's PCR; returns the new PCR value."""
        _check_component(component)
        _check_digest(digest)
        index = PCR_COMPONENTS[component]
        self._pcrs[index] = _extend(self._pcrs[index], digest)
        return self._pcrs[index]

    def pcrs(self) -> Dict[int, bytes]:
        """Snapshot of current PCR values (index -> value)."""
        return dict(self._pcrs)

    def quote(self, nonce: bytes, seq: int) -> Quote:
        """Mint a quote over the current PCRs bound to ``nonce``."""
        _check_nonce(nonce)
        _check_seq(seq)
        pcr_items = tuple(sorted(self._pcrs.items()))
        tag = _quote_tag(self._label, self._pcrs, nonce, seq)
        self._quote_count += 1
        return Quote(
            label=self._label,
            pcrs=pcr_items,
            nonce=nonce,
            seq=seq,
            tag=tag,
        )

    def quote_count(self) -> int:
        return self._quote_count

    def endorse(
        self,
        endorsement_id: str,
        issuer_label: str,
        seq: int,
        endorsement_digest: str = "",
    ) -> EndorsementRecord:
        """Book one issuer endorsement of this attester's AK.

        A declaration that ``issuer_label`` vouches for this attester's
        attestation key; the issuer's raw material never enters the
        ledger, only the optional ``endorsement_digest`` pin. Duplicate
        endorsement ids are refused fail-closed; ids are never
        recycled. Does not affect PCRs or quotes.
        """
        if not isinstance(endorsement_id, str) or not endorsement_id:
            raise RemoteAttestationError(
                "endorsement_id must be a non-empty str"
            )
        _check_label(issuer_label)
        _check_seq(seq)
        _check_pin(endorsement_digest)
        if endorsement_id in self._endorsements:
            raise RemoteAttestationError(
                f"duplicate endorsement {endorsement_id!r}"
            )
        record = EndorsementRecord(
            endorsement_id=endorsement_id,
            attester_label=self._label,
            issuer_label=issuer_label,
            endorsement_digest=endorsement_digest,
            pin=_endorsement_pin(
                endorsement_id, self._label, issuer_label, endorsement_digest
            ),
        )
        self._endorsements[endorsement_id] = record
        return record

    def endorsement_record(self, endorsement_id: str) -> EndorsementRecord:
        """Return one booked endorsement (raises on unknown id)."""
        try:
            return self._endorsements[endorsement_id]
        except (KeyError, TypeError):
            raise RemoteAttestationError(
                f"unknown endorsement {endorsement_id!r}"
            )

    def endorsement_ids(self) -> Tuple[str, ...]:
        """Sorted ids of every booked endorsement."""
        return tuple(sorted(self._endorsements))


def expected_pcrs(attester: Attester) -> Dict[int, bytes]:
    """Snapshot an attester's PCRs as golden values (test/fixture helper)."""
    if not isinstance(attester, Attester):
        raise RemoteAttestationError("expected an Attester")
    return attester.pcrs()


def verify(
    quote: Quote,
    expected_label: str,
    expected_nonce: bytes,
    expected_pcrs: Mapping[int, bytes],
) -> bool:
    """Verifier-side quote check.

    Returns True iff: the quote names the expected attester label; the
    tag re-binds (label, PCRs, nonce, seq); the nonce matches the
    verifier's challenge; every quoted PCR equals the golden value.
    Any mismatch is a policy outcome (False), never an exception.
    Malformed caller input raises.
    """
    if not isinstance(quote, Quote):
        raise RemoteAttestationError("quote must be a Quote")
    _check_label(expected_label)
    _check_nonce(expected_nonce)
    if not isinstance(expected_pcrs, Mapping):
        raise RemoteAttestationError("expected_pcrs must be a mapping")
    for k, v in expected_pcrs.items():
        if not isinstance(k, int) or not isinstance(v, bytes):
            raise RemoteAttestationError("expected_pcrs must map int -> bytes")

    if quote.label != expected_label:
        return False
    quoted = quote.pcr_map()
    recomputed = _quote_tag(quote.label, quoted, quote.nonce, quote.seq)
    if not hmac.compare_digest(recomputed, quote.tag):
        return False
    if not hmac.compare_digest(quote.nonce, expected_nonce):
        return False
    for index, golden in expected_pcrs.items():
        if quoted.get(index) != golden:
            return False
    return True


def remote_attestation_audit_event(kind: str, seq: int) -> dict:
    """Shape an attestation lifecycle event as an ``audit.ndjson/1`` record."""
    valid = ("measured", "quoted", "endorsed", "verified", "rejected")
    if kind not in valid:
        raise RemoteAttestationError(f"unknown audit kind {kind!r}")
    _check_seq(seq)
    return {
        "schema": "audit.ndjson/1",
        "kind": f"remote-attestation.{kind}",
        "module": SCHEMA_PIN,
        "version": REMOTE_ATTESTATION_VERSION,
        "seq": seq,
    }


class RemoteAttestation(Attester):
    """Spec-named facade over :class:`Attester`.

    Exposes the spec API ``quote()`` / ``verify()`` / ``endorse()``.
    ``quote()`` and ``endorse()`` are inherited unchanged; ``verify()``
    delegates to the module-level verifier-side check of the same name.
    """

    @staticmethod
    def verify(
        quote: Quote,
        expected_label: str,
        expected_nonce: bytes,
        expected_pcrs: Mapping[int, bytes],
    ) -> bool:
        return verify(quote, expected_label, expected_nonce, expected_pcrs)


def main() -> None:
    host = Attester("edge-node-1")
    host.measure("bootloader", b"B" * 32)
    host.measure("kernel", b"K" * 32)
    golden = expected_pcrs(host)
    q = host.quote(b"verifier-nonce-42", seq=7)
    assert verify(q, "edge-node-1", b"verifier-nonce-42", golden) is True
    # Stale nonce fails.
    assert verify(q, "edge-node-1", b"other-nonce", golden) is False
    # Tampered PCR fails.
    bad = dict(golden)
    bad[2] = b"\x00" * 32
    assert verify(q, "edge-node-1", b"verifier-nonce-42", bad) is False
    # A quote never verifies for the wrong attester identity, even with
    # identical software measurements.
    other = Attester("edge-node-2")
    other.measure("bootloader", b"B" * 32)
    other.measure("kernel", b"K" * 32)
    q2 = other.quote(b"verifier-nonce-42", seq=7)
    assert verify(q2, "edge-node-1", b"verifier-nonce-42", golden) is False
    assert verify(q2, "edge-node-2", b"verifier-nonce-42", expected_pcrs(other)) is True
    # Spec facade + endorsements.
    host3 = RemoteAttestation("edge-node-3")
    host3.measure("bootloader", b"B" * 32)
    rec = host3.endorse("end-1", "privacy-ca-1", seq=0)
    assert rec.verify() is True
    assert rec.as_dict()["attester_label"] == "edge-node-3"
    q3 = host3.quote(b"n3", seq=1)
    assert RemoteAttestation.verify(
        q3, "edge-node-3", b"n3", expected_pcrs(host3)
    ) is True
    ev = remote_attestation_audit_event("endorsed", seq=4)
    assert ev["kind"] == "remote-attestation.endorsed"
    print("remote-attestation OK: measure, quote, verify, nonce freshness, tamper detection")
