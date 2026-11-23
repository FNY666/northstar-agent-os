"""Confidential VM interface (AMD SEV-SNP / Intel TDX, simulated).

Research motivation: confidential VMs encrypt guest memory and (with
SEV-SNP's RMP / TDX's TDX Module) bind the launched measurement into a
hardware-rooted attestation report, so a verifier can check *what code*
is running before handing it secrets. The production flow is:
launch(image) -> the TEE measures the initial guest state -> attest()
returns a report signed by the hardware root of trust -> a verifier
checks the signature, the measurement (== expected image digest), and
the TCB version (firmware not vulnerable to a revoked CVE).

This module is the *mechanics half*, with the hardware replaced by a
simulated evidence MAC, so the plumbing the runtime depends on is
pinned:

- ``ConfidentialVM(provider)`` -- parameter holder; ``provider`` is
  ``"sev-snp"`` or ``"tdx"`` (fail-closed otherwise).
- ``launch(image: bytes, seq: int) -> VMInstance`` -- hashes the image
  into a ``sha256:`` measurement, derives a deterministic ``vm_id``,
  and records the launch under the provider's simulated TCB version.
- ``attest(seq) -> AttestationReport`` -- mints a report binding
  ``vm_id`` + measurement + TCB version + policy digest, sealed by a
  provider-specific simulated evidence MAC (``hmac.compare_digest``
  checked on the verify side).
- ``report(seq) -> VMReport`` -- current VM view (status, measurement,
  last attestation seq).
- ``verify_attestation(report, expected_image_digest, min_tcb,
  seq) -> bool`` -- stateless verifier-side check of everything
  computable without the TEE: MAC integrity, measurement == expected
  digest, TCB >= minimum, provider known. Returns ``False`` on any
  mismatch (policy outcome); raises only on malformed caller types.
- ``confidential_vm_audit_event(kind, seq, ...)`` -- ``audit.ndjson/1``
  shaped records (``launched`` / ``attested`` / ``verified`` /
  ``verification-failed`` / ``rejected``).

Honest scope:

- Simulated root of trust: the evidence MAC key is derived
  deterministically from a domain seed and *held in-process*, so this
  module cannot prove anything about real hardware. A real deployment
  swaps the MAC for the SEV-SNP VCEK chain (AMD KDS) or the TDX
  quote-verification library without changing call sites.
- Attestation proves *what was measured at launch*, not what is
  running now: a compromised guest after launch is not detected.
- The measurement binds the image *bytes* handed to ``launch`` - the
  host owns image fetch and integrity (supply-chain attacks on the
  image are out of scope here).
- No randomness, no wall-clock. Same provider/image/seq always gives
  the same ``vm_id`` and report on every machine (audit-replay safe).

No wall-clock anywhere. stdlib only (``hashlib``, ``hmac``,
``dataclasses``, ``typing``).
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Tuple

#: Version pin for the confidential-VM interface described here.
VM_VERSION = "confidential-vm.v1"

#: Schema pin stamped on structured outputs.
SCHEMA_PIN = "northstar.confidential-vm.v1"

#: Supported confidential-computing providers.
PROVIDERS: Tuple[str, ...] = ("sev-snp", "tdx")

#: Simulated TCB versions pinned per provider. A real deployment reads
#: these from the firmware/CPU; here they are fixed so deployments
#: cannot silently disagree on the simulated baseline.
TCB_VERSIONS = {"sev-snp": 2, "tdx": 1}

#: Minimum acceptable TCB version per provider for ``verify_attestation``
#: when the caller does not name one explicitly.
MIN_TCB = {"sev-snp": 2, "tdx": 1}

#: Domain seeds for the simulated evidence-MAC keys. Deterministic,
#: nothing-up-my-sleeve; these are NOT secrets in the real sense.
_MAC_DOMAIN = b"northstar-confidential-vm.v1/evidence-mac"
_VMID_DOMAIN = b"northstar-confidential-vm.v1/vm-id"


class ConfidentialVMError(ValueError):
    """Fail-closed confidential-VM error."""


def _reject_bool_int(name: str, value: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an int")


def _validate_seq(seq: int) -> int:
    _reject_bool_int("seq", seq)
    if seq < 0:
        raise ConfidentialVMError("seq must be a non-negative int")
    return seq


def _validate_provider(provider: str) -> str:
    if not isinstance(provider, str):
        raise TypeError("provider must be a str")
    if provider not in PROVIDERS:
        raise ConfidentialVMError(f"provider must be one of {PROVIDERS}")
    return provider


def _validate_image(image: bytes) -> bytes:
    if not isinstance(image, bytes):
        raise TypeError("image must be bytes (hash the explicit encoding first)")
    if len(image) == 0:
        raise ConfidentialVMError("image must be non-empty")
    return image


def _sha256_pin(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _evidence_key(provider: str) -> bytes:
    """Simulated hardware evidence key, per provider."""
    return hashlib.sha256(_MAC_DOMAIN + b"/" + provider.encode()).digest()


def _tcb_version(provider: str) -> int:
    return TCB_VERSIONS[provider]


@dataclass(frozen=True)
class VMInstance:
    """Frozen record of one launched confidential VM."""

    vm_id: str
    provider: str
    image_digest: str
    tcb_version: int
    launch_seq: int
    schema: str = SCHEMA_PIN

    def __post_init__(self) -> None:
        if not isinstance(self.vm_id, str) or not self.vm_id:
            raise ConfidentialVMError("vm_id must be a non-empty str")
        _validate_provider(self.provider)
        if (
            not isinstance(self.image_digest, str)
            or not self.image_digest.startswith("sha256:")
        ):
            raise ConfidentialVMError("image_digest must be a sha256: pin")
        _reject_bool_int("tcb_version", self.tcb_version)
        if self.tcb_version < 1:
            raise ConfidentialVMError("tcb_version must be >= 1")
        _validate_seq(self.launch_seq)
        if self.schema != SCHEMA_PIN:
            raise ConfidentialVMError("schema pin mismatch")

    def as_dict(self) -> dict:
        return {
            "vm_id": self.vm_id,
            "provider": self.provider,
            "image_digest": self.image_digest,
            "tcb_version": self.tcb_version,
            "launch_seq": self.launch_seq,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class AttestationReport:
    """Frozen simulated attestation report (quote)."""

    vm_id: str
    provider: str
    measurement: str
    tcb_version: int
    policy_digest: str
    evidence_mac: bytes
    attest_seq: int
    schema: str = SCHEMA_PIN

    def __post_init__(self) -> None:
        if not isinstance(self.vm_id, str) or not self.vm_id:
            raise ConfidentialVMError("vm_id must be a non-empty str")
        _validate_provider(self.provider)
        if (
            not isinstance(self.measurement, str)
            or not self.measurement.startswith("sha256:")
        ):
            raise ConfidentialVMError("measurement must be a sha256: pin")
        _reject_bool_int("tcb_version", self.tcb_version)
        if self.tcb_version < 1:
            raise ConfidentialVMError("tcb_version must be >= 1")
        if (
            not isinstance(self.policy_digest, str)
            or not self.policy_digest.startswith("sha256:")
        ):
            raise ConfidentialVMError("policy_digest must be a sha256: pin")
        if not isinstance(self.evidence_mac, bytes) or len(self.evidence_mac) == 0:
            raise ConfidentialVMError("evidence_mac must be non-empty bytes")
        _validate_seq(self.attest_seq)
        if self.schema != SCHEMA_PIN:
            raise ConfidentialVMError("schema pin mismatch")

    def as_dict(self) -> dict:
        return {
            "vm_id": self.vm_id,
            "provider": self.provider,
            "measurement": self.measurement,
            "tcb_version": self.tcb_version,
            "policy_digest": self.policy_digest,
            "evidence_mac": self.evidence_mac.hex(),
            "attest_seq": self.attest_seq,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class VMReport:
    """Frozen current-status view of a launched VM."""

    vm_id: str
    provider: str
    status: str
    measurement: str
    last_attest_seq: int
    schema: str = SCHEMA_PIN

    def __post_init__(self) -> None:
        if not isinstance(self.vm_id, str) or not self.vm_id:
            raise ConfidentialVMError("vm_id must be a non-empty str")
        _validate_provider(self.provider)
        if self.status not in ("launched", "attested"):
            raise ConfidentialVMError("status must be launched or attested")
        if (
            not isinstance(self.measurement, str)
            or not self.measurement.startswith("sha256:")
        ):
            raise ConfidentialVMError("measurement must be a sha256: pin")
        _validate_seq(self.last_attest_seq)
        if self.schema != SCHEMA_PIN:
            raise ConfidentialVMError("schema pin mismatch")

    def as_dict(self) -> dict:
        return {
            "vm_id": self.vm_id,
            "provider": self.provider,
            "status": self.status,
            "measurement": self.measurement,
            "last_attest_seq": self.last_attest_seq,
            "schema": self.schema,
        }


class ConfidentialVM:
    """Provider-scoped confidential-VM lifecycle (simulated TEE).

    One instance per provider. The provider choice is pinned at
    construction so launch/attest/verify cannot silently mix
    SEV-SNP and TDX evidence domains.
    """

    version: str = VM_VERSION

    def __init__(self, provider: str) -> None:
        _validate_provider(provider)
        object.__setattr__(self, "_provider", provider)
        object.__setattr__(self, "_mac_key", _evidence_key(provider))
        object.__setattr__(self, "_instance", None)
        object.__setattr__(self, "_last_attest_seq", None)

    @property
    def provider(self) -> str:
        return self._provider

    def launch(self, image: bytes, seq: int) -> VMInstance:
        """Measure the image and record a launch. One launch per instance."""
        _validate_image(image)
        _validate_seq(seq)
        if self._instance is not None:
            raise ConfidentialVMError("already launched (one launch per instance)")
        image_digest = _sha256_pin(image)
        vm_id = (
            "cvm-"
            + hashlib.sha256(
                _VMID_DOMAIN + b"/" + self._provider.encode()
                + b"/" + image_digest.encode() + b"/" + str(seq).encode()
            ).hexdigest()[:16]
        )
        instance = VMInstance(
            vm_id=vm_id,
            provider=self._provider,
            image_digest=image_digest,
            tcb_version=_tcb_version(self._provider),
            launch_seq=seq,
        )
        object.__setattr__(self, "_instance", instance)
        return instance

    def attest(self, seq: int) -> AttestationReport:
        """Mint an attestation report for the launched VM."""
        _validate_seq(seq)
        if self._instance is None:
            raise ConfidentialVMError("attest requires launch first")
        instance = self._instance
        # The default launch policy: run exactly the measured image with
        # debug disabled. The policy digest is part of the report so a
        # verifier can pin it too.
        policy_digest = _sha256_pin(
            b"debug=off;" + instance.image_digest.encode()
        )
        mac_body = b"|".join(
            (
                instance.vm_id.encode(),
                instance.image_digest.encode(),
                str(instance.tcb_version).encode(),
                policy_digest.encode(),
                str(seq).encode(),
            )
        )
        evidence_mac = hmac.new(self._mac_key, mac_body, hashlib.sha256).digest()
        object.__setattr__(self, "_last_attest_seq", seq)
        return AttestationReport(
            vm_id=instance.vm_id,
            provider=instance.provider,
            measurement=instance.image_digest,
            tcb_version=instance.tcb_version,
            policy_digest=policy_digest,
            evidence_mac=evidence_mac,
            attest_seq=seq,
        )

    def report(self, seq: int) -> VMReport:
        """Current status view of the launched VM."""
        _validate_seq(seq)
        if self._instance is None:
            raise ConfidentialVMError("report requires launch first")
        instance = self._instance
        last_attest = self._last_attest_seq
        return VMReport(
            vm_id=instance.vm_id,
            provider=instance.provider,
            status="attested" if last_attest is not None else "launched",
            measurement=instance.image_digest,
            last_attest_seq=last_attest if last_attest is not None else 0,
        )


def verify_attestation(
    report: AttestationReport,
    expected_image_digest: str,
    min_tcb: int | None = None,
) -> bool:
    """Verifier-side attestation check. False on any mismatch.

    Checks: provider known, evidence MAC intact (recomputed from the
    provider's simulated evidence key), measurement == the expected
    image digest, and TCB version >= the minimum. Returns ``False``
    (never raises) on any cryptographic/policy mismatch; raises only
    on malformed caller types.
    """
    if not isinstance(report, AttestationReport):
        raise TypeError("report must be an AttestationReport")
    if (
        not isinstance(expected_image_digest, str)
        or not expected_image_digest.startswith("sha256:")
    ):
        raise TypeError("expected_image_digest must be a sha256: pin")
    if min_tcb is None:
        min_tcb = MIN_TCB[report.provider]
    else:
        _reject_bool_int("min_tcb", min_tcb)

    mac_body = b"|".join(
        (
            report.vm_id.encode(),
            report.measurement.encode(),
            str(report.tcb_version).encode(),
            report.policy_digest.encode(),
            str(report.attest_seq).encode(),
        )
    )
    expected_mac = hmac.new(
        _evidence_key(report.provider), mac_body, hashlib.sha256
    ).digest()
    if not hmac.compare_digest(report.evidence_mac, expected_mac):
        return False
    if not hmac.compare_digest(report.measurement, expected_image_digest):
        return False
    if report.tcb_version < min_tcb:
        return False
    return True


def confidential_vm_audit_event(kind: str, seq: int, **fields: object) -> dict:
    """Audit-shaped record for a confidential-VM observation."""
    if kind not in (
        "launched",
        "attested",
        "verified",
        "verification-failed",
        "rejected",
    ):
        raise ValueError("unknown kind")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise ValueError("seq must be a non-negative int")
    record = {
        "event": "confidential-vm",
        "kind": kind,
        "audit_seq": seq,
        "schema": "audit.ndjson/1",
    }
    record.update(fields)
    return record


def main() -> None:
    for provider in PROVIDERS:
        cvm = ConfidentialVM(provider)
        inst = cvm.launch(b"guest-image-v1", 1)
        rep = cvm.attest(2)
        assert verify_attestation(rep, inst.image_digest), "roundtrip"
        view = cvm.report(3)
        assert view.status == "attested", "status"
        # Wrong expected digest must fail closed.
        bad = _sha256_pin(b"other-image")
        assert not verify_attestation(rep, bad), "wrong image rejected"
    print("confidential-vm OK: launch, attest, verify (sev-snp, tdx)")


if __name__ == "__main__":
    main()
