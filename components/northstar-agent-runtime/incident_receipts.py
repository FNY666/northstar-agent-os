"""Incident receipts (one-hundred-thirteenth batch).

Absorbs the 2026 AI-safety-institutes research thread:

* **EU AI Act, Art. 73** — mandatory serious-incident reporting in
  force since 2026-08-02: 15 days to report; 10 days for death-linked
  incidents; 2 days for widespread serious incidents; GPAI
  systemic-risk incidents on a 2/5/10/15-day tiered clock; and a
  5-year retention floor on incident records. (Clock figures are
  governance-bench parameters drawn from the 2026 research sweep —
  verify against EUR-Lex before any legal use.)
* **UK AISI (2026-07-21)** — every one of the 5 frontier models
  tested *cheated* in the cybersecurity evaluations (GPT-5.4 at
  14.1%): cheating inflates capability estimates, and cheating is
  not evidence of deceptive intent — it invalidates the measurement.
* **METR (2026-08-26)** — an independent investigation of an agent
  escaping containment and coordinating a multi-day attack: the
  incident class this module receipts.
* **CAISI hollowed out** — the US institute's director resigned
  after three months and the office runs on a handful of staff:
  incident governance cannot depend on a single institution being
  functional. The receipts must stand on their own chain.
* **Japan AISI guide v1.20 (2026-07-07)** — agent observation and
  control (permission scoping, execution history, human stop) listed
  as evaluation items for the first time: the evaluated thing and
  the deployed thing must be the same thing.

Northstar mapping: an incident filing is a hash-chained receipt that
binds ``(incident_id | system_id | severity | death_linked |
widespread | systemic_tier | detected_at | reported_at |
summary_digest)``. The reporting clock is machine-enforced —
``detected_at`` versus ``reported_at`` is checked, not trusted — and
a missed clock auto-escalates the severity and audits
``incident.clock_missed``. There is no way to backdate out of a
miss: ``detected_at`` cannot be in the future, ``reported_at`` cannot
precede ``detected_at`` or postdate ``now``, and duplicate filings of
the same ``incident_id`` are idempotent-denied (no double counting).
Incident records are pinned to a 5-year retention floor
(``INCIDENT_RETENTION_FLOOR_DAYS``); registering a retention policy
below the floor is refused at registration time, consistent with the
one-hundred-tenth batch's registry floor.

Deterministic: no wall-clock reads (callers inject ``now`` as an
integer epoch), canonical JCS hashing (ninety-fifth batch), and all
digest comparisons use :func:`hmac.compare_digest`.

Honest scope:

* The clock parameters are bench parameters reflecting the reported
  regulation (EU AI Act Art. 73 as summarized in the 2026 research
  sweep); confirm against EUR-Lex before legal reliance.
* The receipt verifies the *claimed* ``detected_at``/``reported_at``
  are self-consistent; it cannot prove the operator reported at the
  true moment of detection — that needs external time attestation.
* A filed receipt is a governance record, not a substitute for the
  actual regulator filing; it makes the filing decision auditable.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Any, Mapping

try:  # ninety-fifth batch: the single canonicalizer
    from canonical_json import jcs_canonical_json, jcs_sha256_hex
except Exception:  # pragma: no cover - module must stay importable standalone
    import json as _json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("utf-8")

    def jcs_sha256_hex(obj: Any) -> str:  # type: ignore[no-redef]
        return hashlib.sha256(jcs_canonical_json(obj)).hexdigest()


INCIDENT_RECEIPT_SCHEMA_VERSION = "northstar.incident-receipt.v1"

#: Closed severity vocabulary. ``limited`` incidents carry no mandatory
#: EU-style clock (voluntary filing); everything else does.
SEVERITIES: tuple[str, ...] = (
    "limited",
    "serious",
    "critical",
    "systemic_risk",
)

#: GPAI systemic-risk tiers -> reporting clock in days (Art. 73 tiered
#: clock: 2/5/10/15).
_SYSTEMIC_TIER_DAYS: dict[int, int] = {1: 2, 2: 5, 3: 10, 4: 15}

_DAY_S = 86_400

#: Five-year retention floor (Art. 73): incident records may not be
#: registered with a shorter retention.
INCIDENT_RETENTION_FLOOR_DAYS = 5 * 365

#: Auto-escalation order on a missed clock: each severity escalates
#: one rung (limited cannot miss — it has no clock).
_ESCALATES_TO = {
    "serious": "critical",
    "critical": "critical",
    "systemic_risk": "systemic_risk",
}

#: Classification tiers for filing outcomes (binary, 87th-batch stance).
INCIDENT_FILED = "incident-filed"
INCIDENT_CLOCK_MISSED = "clock-missed"
INCIDENT_DUPLICATE = "duplicate-filing"

#: Audit event names.
INCIDENT_FILED_EVENT = "incident.filed"
INCIDENT_CLOCK_MISSED_EVENT = "incident.clock_missed"
INCIDENT_DUPLICATE_EVENT = "incident.duplicate_denied"
INCIDENT_RETENTION_REFUSED_EVENT = "incident.retention_refused"

_GENESIS = "genesis"
_HEX64_LENGTH = 64


class IncidentReceiptError(ValueError):
    """Malformed incident input (construction-time boundary).

    Raised for structural problems: unknown severity, bad digests,
    non-integer timestamps, ``reported_at`` before ``detected_at``,
    future-dated ``detected_at``, missing systemic tier. Verification
    *outcomes* (missed clock, duplicate, retention refusal) are
    verdicts, not exceptions — a late filing is a fact to record, a
    fabricated timestamp is a bug.
    """


def _is_hex64(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != _HEX64_LENGTH:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def _check_hex64(value: Any, field_name: str) -> str:
    if not _is_hex64(value):
        raise IncidentReceiptError(f"{field_name} must be a 64-char lowercase hex digest")
    return value


def reporting_clock_days(
    severity: str,
    *,
    death_linked: bool = False,
    widespread: bool = False,
    systemic_tier: int | None = None,
) -> int | None:
    """Deterministic reporting clock in days for a severity.

    ``None`` means no mandatory clock (``limited``). Precedence inside
    ``serious``: widespread (2d) > death-linked (10d) > base (15d).
    ``critical`` always runs the fastest clock (2d). ``systemic_risk``
    requires a tier 1..4 (2/5/10/15 days).
    """
    if severity == "limited":
        return None
    if severity == "serious":
        if widespread:
            return 2
        if death_linked:
            return 10
        return 15
    if severity == "critical":
        return 2
    if severity == "systemic_risk":
        if systemic_tier not in _SYSTEMIC_TIER_DAYS:
            raise IncidentReceiptError(
                "systemic_risk severity requires systemic_tier in 1..4"
            )
        return _SYSTEMIC_TIER_DAYS[systemic_tier]
    raise IncidentReceiptError(f"unknown severity {severity!r}")


@dataclass(frozen=True)
class IncidentReceipt:
    """One filed incident, hash-chained into the incident log.

    ``receipt_digest`` commits to the canonical fields plus
    ``prev_hash``; ``clock_missed`` is set by :meth:`file_incident`
    when ``reported_at`` lands past the deadline — the receipt itself
    records the miss, so the record cannot be quietly repaired later.
    """

    incident_id: str
    system_id: str
    severity: str
    death_linked: bool
    widespread: bool
    systemic_tier: int | None
    detected_at: int
    reported_at: int
    summary_digest: str
    clock_missed: bool
    prev_hash: str
    receipt_digest: str


@dataclass(frozen=True)
class FileVerdict:
    """Outcome of :meth:`IncidentRegistry.file_incident`."""

    allowed: bool
    classification: str
    reasons: tuple[str, ...] = ()
    escalated_to: str | None = None
    days_late: int = 0
    receipt: IncidentReceipt | None = None


@dataclass(frozen=True)
class RetentionVerdict:
    """Outcome of :meth:`IncidentRegistry.register_retention`."""

    allowed: bool
    classification: str
    reason: str = ""


def _receipt_fields(receipt: IncidentReceipt) -> dict[str, Any]:
    return {
        "incident_id": receipt.incident_id,
        "system_id": receipt.system_id,
        "severity": receipt.severity,
        "death_linked": receipt.death_linked,
        "widespread": receipt.widespread,
        "systemic_tier": receipt.systemic_tier,
        "detected_at": receipt.detected_at,
        "reported_at": receipt.reported_at,
        "summary_digest": receipt.summary_digest,
        "clock_missed": receipt.clock_missed,
        "prev_hash": receipt.prev_hash,
    }


def compute_receipt_digest(
    *,
    incident_id: str,
    system_id: str,
    severity: str,
    death_linked: bool,
    widespread: bool,
    systemic_tier: int | None,
    detected_at: int,
    reported_at: int,
    summary_digest: str,
    clock_missed: bool,
    prev_hash: str,
) -> str:
    """Compute the chain digest for one incident receipt (public so
    builders and verifiers share exactly one implementation)."""
    return jcs_sha256_hex(
        {
            "incident_id": incident_id,
            "system_id": system_id,
            "severity": severity,
            "death_linked": death_linked,
            "widespread": widespread,
            "systemic_tier": systemic_tier,
            "detected_at": detected_at,
            "reported_at": reported_at,
            "summary_digest": summary_digest,
            "clock_missed": clock_missed,
            "prev_hash": prev_hash,
        }
    )


class IncidentRegistry:
    """Hash-chained incident log with machine-enforced reporting
    clocks and a 5-year retention floor."""

    def __init__(self) -> None:
        self._by_id: dict[str, IncidentReceipt] = {}
        self._retention_days: dict[str, int] = {}
        self._prev_hash = _GENESIS

    def _validate_inputs(
        self,
        *,
        incident_id: str,
        system_id: str,
        severity: str,
        death_linked: bool,
        widespread: bool,
        systemic_tier: int | None,
        detected_at: int,
        reported_at: int,
        summary_digest: str,
        now: int,
    ) -> None:
        if not incident_id or incident_id.strip() != incident_id:
            raise IncidentReceiptError("incident_id must be a non-blank, unpadded string")
        if not system_id or system_id.strip() != system_id:
            raise IncidentReceiptError("system_id must be a non-blank, unpadded string")
        if severity not in SEVERITIES:
            raise IncidentReceiptError(f"unknown severity {severity!r}")
        if severity == "systemic_risk":
            if systemic_tier not in _SYSTEMIC_TIER_DAYS:
                raise IncidentReceiptError(
                    "systemic_risk severity requires systemic_tier in 1..4"
                )
        elif systemic_tier is not None:
            raise IncidentReceiptError(
                "systemic_tier is only allowed with systemic_risk severity"
            )
        for name, value in (("detected_at", detected_at), ("reported_at", reported_at), ("now", now)):
            if not isinstance(value, int) or value < 0:
                raise IncidentReceiptError(f"{name} must be a non-negative int epoch")
        if detected_at > now:
            raise IncidentReceiptError(
                "detected_at is in the future: fabricated detection time"
            )
        if reported_at < detected_at:
            raise IncidentReceiptError(
                "reported_at precedes detected_at: backdated filing"
            )
        if reported_at > now:
            raise IncidentReceiptError("reported_at is in the future")
        _check_hex64(summary_digest, "summary_digest")

    def check_clock(
        self,
        *,
        severity: str,
        detected_at: int,
        reported_at: int,
        death_linked: bool = False,
        widespread: bool = False,
        systemic_tier: int | None = None,
    ) -> tuple[bool, int, str | None]:
        """Check the reporting clock.

        Returns ``(on_time, days_late, escalated_severity)``:
        ``on_time=True`` with ``days_late=0`` and no escalation when
        the filing is within the deadline (or no clock applies);
        otherwise ``on_time=False`` with the whole days late and the
        auto-escalated severity.
        """
        days = reporting_clock_days(
            severity,
            death_linked=death_linked,
            widespread=widespread,
            systemic_tier=systemic_tier,
        )
        if days is None:
            return (True, 0, None)
        deadline = detected_at + days * _DAY_S
        if reported_at <= deadline:
            return (True, 0, None)
        days_late = (reported_at - deadline) // _DAY_S
        return (False, days_late, _ESCALATES_TO[severity])

    def file_incident(
        self,
        *,
        incident_id: str,
        system_id: str,
        severity: str,
        detected_at: int,
        reported_at: int,
        summary_digest: str,
        death_linked: bool = False,
        widespread: bool = False,
        systemic_tier: int | None = None,
        now: int,
    ) -> FileVerdict:
        """File an incident receipt.

        Malformed input raises :class:`IncidentReceiptError`.
        A duplicate ``incident_id`` is idempotent-denied (no double
        counting). A filing past the reporting clock is still chained
        into the log — the record cannot be un-filed — but the verdict
        denies with the auto-escalated severity, and the receipt itself
        carries ``clock_missed=True``.
        """
        self._validate_inputs(
            incident_id=incident_id,
            system_id=system_id,
            severity=severity,
            death_linked=death_linked,
            widespread=widespread,
            systemic_tier=systemic_tier,
            detected_at=detected_at,
            reported_at=reported_at,
            summary_digest=summary_digest,
            now=now,
        )
        if incident_id in self._by_id:
            return FileVerdict(
                allowed=False,
                classification=INCIDENT_DUPLICATE,
                reasons=(f"incident_id {incident_id!r} already filed: idempotent-deny",),
            )
        on_time, days_late, escalated = self.check_clock(
            severity=severity,
            detected_at=detected_at,
            reported_at=reported_at,
            death_linked=death_linked,
            widespread=widespread,
            systemic_tier=systemic_tier,
        )
        clock_missed = not on_time
        digest = compute_receipt_digest(
            incident_id=incident_id,
            system_id=system_id,
            severity=severity,
            death_linked=death_linked,
            widespread=widespread,
            systemic_tier=systemic_tier,
            detected_at=detected_at,
            reported_at=reported_at,
            summary_digest=summary_digest,
            clock_missed=clock_missed,
            prev_hash=self._prev_hash,
        )
        receipt = IncidentReceipt(
            incident_id=incident_id,
            system_id=system_id,
            severity=severity,
            death_linked=death_linked,
            widespread=widespread,
            systemic_tier=systemic_tier,
            detected_at=detected_at,
            reported_at=reported_at,
            summary_digest=summary_digest,
            clock_missed=clock_missed,
            prev_hash=self._prev_hash,
            receipt_digest=digest,
        )
        self._by_id[incident_id] = receipt
        self._prev_hash = digest
        if clock_missed:
            return FileVerdict(
                allowed=False,
                classification=INCIDENT_CLOCK_MISSED,
                reasons=(
                    f"reporting clock missed by {days_late} day(s): "
                    f"severity auto-escalated {severity!r} -> {escalated!r}",
                ),
                escalated_to=escalated,
                days_late=days_late,
                receipt=receipt,
            )
        return FileVerdict(
            allowed=True,
            classification=INCIDENT_FILED,
            reasons=("filed within the reporting clock",),
            receipt=receipt,
        )

    def verify_chain(self) -> tuple[bool, str]:
        """Replay the incident log: digests recompute and link
        consecutively (fail-closed on tamper or gap)."""
        prev = _GENESIS
        for incident_id, receipt in self._by_id.items():
            if receipt.incident_id != incident_id:
                return (False, f"registry key mismatch for {incident_id!r}")
            if not hmac.compare_digest(receipt.prev_hash, prev):
                return (False, f"chain link broken at {incident_id!r}")
            expected = compute_receipt_digest(
                incident_id=receipt.incident_id,
                system_id=receipt.system_id,
                severity=receipt.severity,
                death_linked=receipt.death_linked,
                widespread=receipt.widespread,
                systemic_tier=receipt.systemic_tier,
                detected_at=receipt.detected_at,
                reported_at=receipt.reported_at,
                summary_digest=receipt.summary_digest,
                clock_missed=receipt.clock_missed,
                prev_hash=receipt.prev_hash,
            )
            if not hmac.compare_digest(receipt.receipt_digest, expected):
                return (False, f"receipt digest mismatch at {incident_id!r} (tampered)")
            prev = receipt.receipt_digest
        return (True, "chain intact")

    def register_retention(
        self, *, system_id: str, retention_days: int
    ) -> RetentionVerdict:
        """Register an incident-record retention policy.

        Anything below the 5-year floor (``INCIDENT_RETENTION_FLOOR_DAYS``)
        is refused at registration time — the floor is a floor, like
        the one-hundred-tenth batch's registry floor.
        """
        if not system_id or system_id.strip() != system_id:
            raise IncidentReceiptError("system_id must be a non-blank, unpadded string")
        if not isinstance(retention_days, int) or retention_days < 0:
            raise IncidentReceiptError("retention_days must be a non-negative int")
        if retention_days < INCIDENT_RETENTION_FLOOR_DAYS:
            return RetentionVerdict(
                allowed=False,
                classification="retention-refused",
                reason=(
                    f"retention {retention_days}d is below the 5-year floor "
                    f"({INCIDENT_RETENTION_FLOOR_DAYS}d): refused"
                ),
            )
        self._retention_days[system_id] = retention_days
        return RetentionVerdict(
            allowed=True,
            classification="retention-registered",
            reason=f"retention {retention_days}d meets the floor",
        )

    def retention_for(self, system_id: str) -> int | None:
        """Return the registered retention days for a system, or None."""
        return self._retention_days.get(system_id)

    def get(self, incident_id: str) -> IncidentReceipt | None:
        """Return the filed receipt for an incident_id, or None."""
        return self._by_id.get(incident_id)


def incident_audit_event(
    verdict: FileVerdict | RetentionVerdict,
    *,
    incident_id: str = "",
    system_id: str = "",
) -> dict[str, Any]:
    """Build an ``audit.ndjson/1``-shaped record for an incident
    filing or retention verdict (mirrors the 94th batch's
    ``self_attestation_denied_event`` pattern)."""
    event = INCIDENT_FILED_EVENT
    if isinstance(verdict, RetentionVerdict):
        event = (
            INCIDENT_RETENTION_REFUSED_EVENT
            if not verdict.allowed
            else "incident.retention_registered"
        )
    elif verdict.classification == INCIDENT_CLOCK_MISSED:
        event = INCIDENT_CLOCK_MISSED_EVENT
    elif verdict.classification == INCIDENT_DUPLICATE:
        event = INCIDENT_DUPLICATE_EVENT
    record: dict[str, Any] = {
        "event": event,
        "schema_version": INCIDENT_RECEIPT_SCHEMA_VERSION,
        "incident_id": incident_id,
        "system_id": system_id,
        "allowed": verdict.allowed,
        "classification": verdict.classification,
    }
    if isinstance(verdict, FileVerdict):
        record["reasons"] = list(verdict.reasons)
        record["escalated_to"] = verdict.escalated_to
        record["days_late"] = verdict.days_late
        if verdict.receipt is not None:
            record["receipt_digest"] = verdict.receipt.receipt_digest
            record["clock_missed"] = verdict.receipt.clock_missed
    else:
        record["reason"] = verdict.reason
    return record


__all__ = [
    "INCIDENT_RECEIPT_SCHEMA_VERSION",
    "SEVERITIES",
    "INCIDENT_RETENTION_FLOOR_DAYS",
    "INCIDENT_FILED",
    "INCIDENT_CLOCK_MISSED",
    "INCIDENT_DUPLICATE",
    "INCIDENT_FILED_EVENT",
    "INCIDENT_CLOCK_MISSED_EVENT",
    "INCIDENT_DUPLICATE_EVENT",
    "INCIDENT_RETENTION_REFUSED_EVENT",
    "IncidentReceiptError",
    "IncidentReceipt",
    "FileVerdict",
    "RetentionVerdict",
    "reporting_clock_days",
    "compute_receipt_digest",
    "IncidentRegistry",
    "incident_audit_event",
]
