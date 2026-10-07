"""Confidential compute workload ledger (SGX / SEV-SNP / TDX, simulated).

Research motivation: confidential computing puts workload execution inside a
hardware-rooted TEE so the code handling secrets is isolated from the host,
the hypervisor, and the cloud operator. The production flow is: an enclave
session is established -> a workload runs inside it with inputs pinned by
digest -> the TEE emits an attestation report binding the enclave measurement
to the declared inputs and outputs -> a verifier checks the report before
trusting the result.

This module is the *workload-execution half* of that flow, with the hardware
replaced by deterministic simulated evidence, so the plumbing the runtime
depends on is pinned. It is deliberately distinct from the sibling
``confidential_vm.py`` (which owns the VM-launch mechanics: image
measurement, per-provider TCB versions, report minting):

- ``ConfidentialCompute(provider)`` -- enclave-session holder; ``provider``
  is ``"sgx"``, ``"sev-snp"``, or ``"tdx"`` (fail-closed otherwise).
- ``run(workload_id, input_digest, seq, output_digest="")`` -- books one
  declared enclave workload execution (``run-N`` ids); inputs and outputs
  travel as ``sha256:`` digest pins only, raw payload bytes never enter a
  record or cross the audit boundary. Each run is sealed by a simulated
  evidence MAC over (provider, workload_id, input_digest, output_digest).
- ``attest(run_id, seq)`` -- books one enclave attestation report binding
  the run to a simulated enclave measurement and the provider's pinned TCB
  version (``att-N`` ids).
- ``verify(run_id, seq, expect_attested=False)`` -- pure read view that
  re-derives every evidence MAC and digest pin; integrity is *data*
  (``ok`` bool), never proof of real hardware.

Honest scope:

- Simulated root of trust: the evidence MAC key is derived deterministically
  from a domain seed and *held in-process*, so this module cannot prove
  anything about real hardware. A real deployment swaps the MAC for the
  provider's quote-verification path (EPID/DCAP for SGX, SEV-SNP VCEK, TDX
  quote library) without changing call sites.
- A booked ``run`` records the host's *declaration* that a workload ran in
  an enclave; the module observed no enclave and proves nothing about where
  the declared output came from (GIGO boundary).
- ``verify`` checks ledger self-consistency (MAC recomputation, pin
  recomputation, attestation presence), never the truth of the declared
  output.

House rules: frozen dataclasses, caller int seqs strictly increasing
(claim-then-burn -- failed mutations consume their seq and book a
``confidential-compute.rejected`` audit row; rewinds raise bare without
consuming), RLock-guarded, fail-closed, no wall-clock, stdlib only plus the
sanctioned ``canonical_json`` try/except fallback, ``sha256:`` digest pins
with ``verify()``, ``audit.ndjson/1`` events.
"""

from __future__ import annotations

import hashlib
import hmac
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

try:
    from canonical_json import jcs_dumps as _jcs_dumps  # type: ignore
except Exception:  # pragma: no cover - fallback path
    _jcs_dumps = None

#: Version pin for the confidential-compute workload interface.
CC_VERSION = "confidential-compute.v1"

#: Schema pin stamped on structured outputs.
SCHEMA_PIN = "northstar.confidential-compute.v1"

#: Supported confidential-computing providers.
PROVIDERS: Tuple[str, ...] = ("sgx", "sev-snp", "tdx")

#: Simulated TCB versions pinned per provider. A real deployment reads these
#: from the CPU/firmware; here they are fixed so deployments cannot silently
#: disagree on the simulated baseline.
TCB_VERSIONS = {"sgx": 2, "sev-snp": 2, "tdx": 1}

#: Domain seeds -- the evidence MAC key is derived deterministically from
#: these and held in-process (simulated root of trust).
_EVIDENCE_DOMAIN = b"northstar.confidential-compute.evidence\x00"
_MEASURE_DOMAIN = b"northstar.confidential-compute.measure\x00"

#: Audit kinds emitted by this module.
AUDIT_KINDS: Tuple[str, ...] = ("run", "attested", "verified", "rejected")

#: Raw-payload keys that must never cross the audit boundary. Checked by
#: exact key match (not substring) so legitimate keys cannot false-positive.
_BANNED_KEYS = frozenset(
    {
        "workload",
        "input",
        "output",
        "args",
        "payload",
        "secret",
        "key",
        "raw",
        "data",
        "text",
        "body",
        "measurement",
    }
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class ConfidentialComputeError(Exception):
    """Base error for confidential-compute misuse."""


class BadProviderError(ConfidentialComputeError):
    """Raised when the provider is not in the pinned vocabulary."""


class BadWorkloadError(ConfidentialComputeError):
    """Raised when a workload id is malformed."""


class BadDigestError(ConfidentialComputeError):
    """Raised when a digest is not a well-formed ``sha256:<64hex>`` pin."""


class DuplicateRunError(ConfidentialComputeError):
    """Raised when a run id is booked twice."""


class UnknownRunError(ConfidentialComputeError):
    """Raised when a run id names no booked run."""


class DuplicateAttestError(ConfidentialComputeError):
    """Raised when a run is attested twice."""


class NotAttestedError(ConfidentialComputeError):
    """Raised when ``verify`` demands an attestation that is not booked."""


class SeqOrderError(ConfidentialComputeError):
    """Raised when a caller seq is not a strictly increasing int."""


class AuditKindError(ConfidentialComputeError):
    """Raised when the audit builder gets an unknown kind or bad seq."""


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def _is_digest(value: Any) -> bool:
    return (
        isinstance(value, str)
        and value.startswith("sha256:")
        and len(value) == 7 + 64
        and all(c in "0123456789abcdef" for c in value[7:])
    )


def _digest_pin(payload: Any) -> str:
    if _jcs_dumps is not None:
        body = _jcs_dumps(payload)
        if isinstance(body, str):
            body = body.encode("utf-8")
    else:
        import json

        body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
    return "sha256:" + hashlib.sha256(body).hexdigest()


def _evidence_key(provider: str) -> bytes:
    return hmac.new(_EVIDENCE_DOMAIN, provider.encode("utf-8"), hashlib.sha256).digest()


def _evidence_mac(provider: str, fields: Tuple[str, ...]) -> str:
    mac = hmac.new(
        _evidence_key(provider), b"|".join(f.encode("utf-8") for f in fields), hashlib.sha256
    )
    return mac.hexdigest()


def _enclave_measurement(provider: str, evidence_mac: str) -> str:
    body = hashlib.sha256(
        _MEASURE_DOMAIN + provider.encode("utf-8") + evidence_mac.encode("utf-8")
    ).hexdigest()
    return "sha256:" + body


def _check_workload_id(workload_id: Any) -> str:
    if isinstance(workload_id, bool) or not isinstance(workload_id, str):
        raise BadWorkloadError("workload_id must be a str")
    if not workload_id or len(workload_id) > 256:
        raise BadWorkloadError("workload_id must be non-empty and <= 256 chars")
    if any(ch.isspace() for ch in workload_id):
        raise BadWorkloadError("workload_id must not contain whitespace")
    return workload_id


def _run_id_impl(run_id: Any) -> str:
    if isinstance(run_id, bool) or not isinstance(run_id, str):
        raise BadWorkloadError("run_id must be a str")
    if not run_id or len(run_id) > 256:
        raise BadWorkloadError("run_id must be non-empty and <= 256 chars")
    return run_id


# ---------------------------------------------------------------------------
# Audit event builder
# ---------------------------------------------------------------------------


def confidential_compute_audit_event(
    kind: str, seq: int, details: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Build an ``audit.ndjson/1`` shaped event.

    Raw payload keys are banned from ``details`` by exact-key match; the
    caller passes digest pins only.
    """
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise AuditKindError("seq must be an int")
    if kind not in AUDIT_KINDS:
        raise AuditKindError("unknown audit kind: %r" % (kind,))
    details = dict(details or {})
    for key in details:
        if key in _BANNED_KEYS:
            raise AuditKindError("banned audit key: %r" % (key,))
    return {
        "schema": "audit.ndjson/1",
        "module": "confidential-compute",
        "kind": kind,
        "seq": seq,
        "details": details,
    }


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RunRecord:
    """One booked enclave workload execution (host-declared)."""

    run_id: str
    workload_id: str
    provider: str
    input_digest: str
    output_digest: str
    evidence_mac: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "run_id": self.run_id,
            "workload_id": self.workload_id,
            "provider": self.provider,
            "input_digest": self.input_digest,
            "output_digest": self.output_digest,
            "evidence_mac": self.evidence_mac,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self, provider: str) -> bool:
        """Recompute the digest pin and the evidence MAC."""
        body = {
            "schema": SCHEMA_PIN,
            "run_id": self.run_id,
            "workload_id": self.workload_id,
            "provider": self.provider,
            "input_digest": self.input_digest,
            "output_digest": self.output_digest,
            "evidence_mac": self.evidence_mac,
            "seq": self.seq,
        }
        if _digest_pin(body) != self.digest:
            return False
        want = _evidence_mac(
            provider,
            (self.run_id, self.workload_id, self.input_digest, self.output_digest),
        )
        return hmac.compare_digest(want, self.evidence_mac)


@dataclass(frozen=True)
class AttestRecord:
    """One booked enclave attestation report for a run."""

    attest_id: str
    run_id: str
    provider: str
    enclave_measurement: str
    tcb_version: int
    evidence_mac: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "attest_id": self.attest_id,
            "run_id": self.run_id,
            "provider": self.provider,
            "enclave_measurement": self.enclave_measurement,
            "tcb_version": self.tcb_version,
            "evidence_mac": self.evidence_mac,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self, provider: str) -> bool:
        body = {
            "schema": SCHEMA_PIN,
            "attest_id": self.attest_id,
            "run_id": self.run_id,
            "provider": self.provider,
            "enclave_measurement": self.enclave_measurement,
            "tcb_version": self.tcb_version,
            "evidence_mac": self.evidence_mac,
            "seq": self.seq,
        }
        if _digest_pin(body) != self.digest:
            return False
        want = _evidence_mac(
            provider,
            (self.attest_id, self.run_id, self.enclave_measurement, str(self.tcb_version)),
        )
        return hmac.compare_digest(want, self.evidence_mac)


@dataclass(frozen=True)
class VerifyReport:
    """Pure-read verification outcome: integrity as data, never a proof."""

    run_id: str
    mac_ok: bool
    pin_ok: bool
    attested: bool
    ok: bool
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "run_id": self.run_id,
            "mac_ok": self.mac_ok,
            "pin_ok": self.pin_ok,
            "attested": self.attested,
            "ok": self.ok,
            "digest": self.digest,
        }


# ---------------------------------------------------------------------------
# Session
# ---------------------------------------------------------------------------


class ConfidentialCompute:
    """Simulated confidential-compute enclave session for one provider."""

    def __init__(self, provider: str) -> None:
        if isinstance(provider, bool) or not isinstance(provider, str):
            raise BadProviderError("provider must be a str")
        if provider not in PROVIDERS:
            raise BadProviderError("unknown provider: %r" % (provider,))
        self._provider = provider
        self._tcb = TCB_VERSIONS[provider]
        self._lock = threading.RLock()
        self._last_seq = 0
        self._runs: Dict[str, RunRecord] = {}
        self._attests: Dict[str, AttestRecord] = {}
        self._attested_runs: Dict[str, str] = {}
        self._audit: List[Dict[str, Any]] = []

    # -- seq discipline ---------------------------------------------------

    def _claim(self, seq: Any) -> int:
        if isinstance(seq, bool) or not isinstance(seq, int) or seq <= self._last_seq:
            raise SeqOrderError("seq must be an int strictly greater than %d" % self._last_seq)
        self._last_seq = seq
        return seq

    def _shape(self, seq: Any) -> int:
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise SeqOrderError("seq must be an int")
        return seq

    def _burn(self, seq: int, reason: str) -> None:
        self._audit.append(
            confidential_compute_audit_event(
                "rejected",
                seq,
                {"reason": reason, "provider": self._provider},
            )
        )

    # -- mutations --------------------------------------------------------

    def run(
        self,
        run_id: str,
        workload_id: str,
        seq: int,
        input_digest: str = "",
        output_digest: str = "",
    ) -> RunRecord:
        """Book one declared enclave workload execution.

        Inputs/outputs travel as ``sha256:`` pins only (empty pins allowed:
        the host may book the execution before the digests are known and
        the digest pin still seals the declaration). Raw payload bytes are
        refused by construction -- there is no parameter for them.
        """
        with self._lock:
            seq = self._claim(seq)
            try:
                rid = _run_id_impl(run_id)
                wid = _check_workload_id(workload_id)
                if input_digest and not _is_digest(input_digest):
                    raise BadDigestError("input_digest must be a sha256: pin or empty")
                if output_digest and not _is_digest(output_digest):
                    raise BadDigestError("output_digest must be a sha256: pin or empty")
                if rid in self._runs:
                    raise DuplicateRunError("run already booked: %r" % (rid,))
                mac = _evidence_mac(
                    self._provider, (rid, wid, input_digest, output_digest)
                )
                body = {
                    "schema": SCHEMA_PIN,
                    "run_id": rid,
                    "workload_id": wid,
                    "provider": self._provider,
                    "input_digest": input_digest,
                    "output_digest": output_digest,
                    "evidence_mac": mac,
                    "seq": seq,
                }
                rec = RunRecord(
                    run_id=rid,
                    workload_id=wid,
                    provider=self._provider,
                    input_digest=input_digest,
                    output_digest=output_digest,
                    evidence_mac=mac,
                    seq=seq,
                    digest=_digest_pin(body),
                )
                self._runs[rid] = rec
                self._audit.append(
                    confidential_compute_audit_event(
                        "run",
                        seq,
                        {
                            "run_id": rid,
                            "workload_id": wid,
                            "provider": self._provider,
                            "run_digest": rec.digest,
                        },
                    )
                )
                return rec
            except ConfidentialComputeError:
                self._burn(seq, "run")
                raise

    def attest(self, run_id: str, seq: int) -> AttestRecord:
        """Book one enclave attestation report for a booked run."""
        with self._lock:
            seq = self._claim(seq)
            try:
                rid = _run_id_impl(run_id)
                if rid not in self._runs:
                    raise UnknownRunError("unknown run: %r" % (rid,))
                if rid in self._attested_runs:
                    raise DuplicateAttestError("run already attested: %r" % (rid,))
                attest_id = "att-%d" % (len(self._attests) + 1)
                run = self._runs[rid]
                measurement = _enclave_measurement(self._provider, run.evidence_mac)
                mac = _evidence_mac(
                    self._provider,
                    (attest_id, rid, measurement, str(self._tcb)),
                )
                body = {
                    "schema": SCHEMA_PIN,
                    "attest_id": attest_id,
                    "run_id": rid,
                    "provider": self._provider,
                    "enclave_measurement": measurement,
                    "tcb_version": self._tcb,
                    "evidence_mac": mac,
                    "seq": seq,
                }
                rec = AttestRecord(
                    attest_id=attest_id,
                    run_id=rid,
                    provider=self._provider,
                    enclave_measurement=measurement,
                    tcb_version=self._tcb,
                    evidence_mac=mac,
                    seq=seq,
                    digest=_digest_pin(body),
                )
                self._attests[attest_id] = rec
                self._attested_runs[rid] = attest_id
                self._audit.append(
                    confidential_compute_audit_event(
                        "attested",
                        seq,
                        {
                            "attest_id": attest_id,
                            "run_id": rid,
                            "provider": self._provider,
                            "tcb_version": self._tcb,
                            "attest_digest": rec.digest,
                        },
                    )
                )
                return rec
            except ConfidentialComputeError:
                self._burn(seq, "attest")
                raise

    # -- pure reads -------------------------------------------------------

    def verify(
        self, run_id: str, seq: int, expect_attested: bool = False
    ) -> VerifyReport:
        """Re-derive all evidence and pins for a run.

        Pure read: validates seq shape, consumes nothing, writes no audit
        row. Integrity is data (``ok`` bool); ``expect_attested=True``
        with no booked attestation raises :class:`NotAttestedError`.
        """
        with self._lock:
            seq = self._shape(seq)
            rid = _run_id_impl(run_id)
            if rid not in self._runs:
                raise UnknownRunError("unknown run: %r" % (rid,))
            run = self._runs[rid]
            mac_ok = hmac.compare_digest(
                _evidence_mac(
                    self._provider,
                    (run.run_id, run.workload_id, run.input_digest, run.output_digest),
                ),
                run.evidence_mac,
            )
            pin_ok = run.verify(self._provider)
            attest_id = self._attested_runs.get(rid)
            attested = attest_id is not None
            if expect_attested and not attested:
                raise NotAttestedError("run has no booked attestation: %r" % (rid,))
            attest_ok = True
            if attested:
                att = self._attests[attest_id]
                attest_ok = att.verify(self._provider) and att.tcb_version == self._tcb
            ok = bool(mac_ok and pin_ok and attest_ok)
            body = {
                "schema": SCHEMA_PIN,
                "run_id": rid,
                "mac_ok": mac_ok,
                "pin_ok": pin_ok,
                "attested": attested,
                "ok": ok,
                "seq": seq,
            }
            return VerifyReport(
                run_id=rid,
                mac_ok=mac_ok,
                pin_ok=pin_ok,
                attested=attested,
                ok=ok,
                digest=_digest_pin(body),
            )

    def run_record(self, run_id: str) -> RunRecord:
        with self._lock:
            rid = _run_id_impl(run_id)
            if rid not in self._runs:
                raise UnknownRunError("unknown run: %r" % (rid,))
            return self._runs[rid]

    def attest_record(self, attest_id: str) -> AttestRecord:
        with self._lock:
            if isinstance(attest_id, bool) or not isinstance(attest_id, str):
                raise UnknownRunError("attest_id must be a str")
            if attest_id not in self._attests:
                raise UnknownRunError("unknown attestation: %r" % (attest_id,))
            return self._attests[attest_id]

    def run_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._runs))

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "schema": SCHEMA_PIN,
                "provider": self._provider,
                "tcb_version": self._tcb,
                "runs": len(self._runs),
                "attestations": len(self._attests),
                "last_seq": self._last_seq,
            }

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            return tuple(self._audit)


# ---------------------------------------------------------------------------
# Self-check
# ---------------------------------------------------------------------------


def main() -> None:
    cc = ConfidentialCompute("sev-snp")
    assert CC_VERSION == "confidential-compute.v1"
    assert SCHEMA_PIN == "northstar.confidential-compute.v1"
    rec = cc.run("job-1", "inference", 1, input_digest="sha256:" + "a" * 64)
    assert rec.verify("sev-snp")
    att = cc.attest("job-1", 2)
    assert att.verify("sev-snp")
    rep = cc.verify("job-1", 3, expect_attested=True)
    assert rep.ok and rep.attested
    try:
        cc.run("job-1", "inference", 4)
        raise AssertionError("duplicate run accepted")
    except DuplicateRunError:
        pass
    try:
        ConfidentialCompute("nope")
        raise AssertionError("bad provider accepted")
    except BadProviderError:
        pass
    print("confidential-compute OK: run, attest, verify, pins, audit")


if __name__ == "__main__":
    main()
