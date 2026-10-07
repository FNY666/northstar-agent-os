"""Data residency: regional storage pinning and cross-border transfer control (simulated).

Research note: the world's data-localization regimes (GDPR Chapter V on
transfers to third countries; China's PIPL Art. 38-40 on cross-border
provision of personal information; Russia's 152-FZ localization rule;
India's DPDP Act; sectoral rules in finance/healthcare) all converge on
one load-bearing shape: data *lives* somewhere, and moving it across a
jurisdictional boundary requires either (a) an allowed destination
(adequacy), or (b) an explicit transfer basis (SCCs/BCRs/derogations/
security assessments). The expensive failure modes are the same
everywhere:

1. **Unpinned data drifts.** Without a pinned region per subject/data
   class, nobody can answer "where is this person's data?" — and a
   transfer check cannot run at all. Here ``pin()`` is the only way to
   book a storage location, and each pin is a digest-pinned frozen
   record chained per subject.
2. **Silent cross-border moves.** A migration that crosses a
   jurisdictional boundary without a recorded basis is how Schrems-II
   findings happen. Here ``migrate()`` computes the (from, to)
   jurisdiction pair from the pinned region table and *refuses* unless
   the pair is allowed by the pinned policy — either unconditionally
   (same jurisdiction, non-personal data, adequacy-listed pair) or with
   an explicit, vocabulary-pinned ``transfer_basis``.
3. **Policy you cannot recompute is policy you cannot audit.** The
   default transfer policy is pinned data: ``policy_table()`` returns
   it, and its digest is pinned in the module, so drift between "the
   rules we shipped" and "the rules we enforced" is detectable by
   recomputation.
4. **One active location per (subject, data class).** Concurrent
   "current regions" would make deletion propagation and regulator
   answers ambiguous. ``pin()`` refuses a second active pin for the same
   (subject_id, data_class); moving is only via ``migrate()``, which
   appends an immutable ``MigrationRecord`` — the full history stays
   readable via ``migration_history()``.

This module is the *claims ledger* for that shape, against a simulated
region table. It books where data *may* live and whether a move was
allowed; it performs no network traffic, observes no storage wire, and
cannot prove a host's actual data placement.

House style: frozen dataclasses, caller-supplied strictly-increasing
int seqs (no wall-clock — callers inject integer epochs; no RNG),
RLock-guarded, fail-closed (unknown regions/jurisdictions/data
classes, duplicate pins, unauthorized transfers, non-increasing seqs
all raise a subclass of :class:`DataResidencyError`), stdlib-only,
type-tagged canonical digest encoding (bool != int; floats and
|n| >= 2**53 refused), ``sha256:`` digest pins, audit events shaped for
``audit.ndjson/1``, ``main()`` self-check.

Honest scope: this is a *simulated* residency ledger. It cannot prove
data physically resides in a region, cannot observe a host's real
storage placement, and its policy table is a curated, deliberately
simplified model — it is not a legal opinion about any jurisdiction's
law, does not know about sector-specific carve-outs, and does not
track consent, security-assessment approvals, or DPA filings. "Transfer
allowed" here means "allowed by this module's pinned policy with the
given basis", never "legal".
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
from dataclasses import dataclass, replace
from typing import Any, Dict, FrozenSet, List, Mapping, Optional, Tuple

VERSION = "data-residency.v1"
SCHEMA = "northstar.data-residency.v1"
AUDIT_SCHEMA = "audit.ndjson/1"

__all__ = [
    "VERSION",
    "SCHEMA",
    "AUDIT_SCHEMA",
    "JURISDICTIONS",
    "REGION_JURISDICTION",
    "DATA_CLASSES",
    "TRANSFER_BASES",
    "ADEQUACY_FROM_EU",
    "DataResidencyError",
    "SeqOrderError",
    "BadInputError",
    "UnknownJurisdictionError",
    "UnknownRegionError",
    "DuplicateRegionError",
    "UnknownDataClassError",
    "UnknownPinError",
    "DuplicatePinError",
    "TransferDeniedError",
    "InvalidBasisError",
    "DataResidency",
    "data_residency_audit_event",
]

# ---------------------------------------------------------------------------
# Pinned vocabularies and policy
# ---------------------------------------------------------------------------

# ISO-3166-ish jurisdiction codes. "other" is the catch-all for regions
# the host registers without a curated mapping.
JURISDICTIONS: FrozenSet[str] = frozenset({
    "eu", "uk", "us", "cn", "in", "br", "jp", "sg", "ae", "sa", "ru", "other",
})

# Curated region-code -> jurisdiction table (cloud-style region names).
# Hosts may register more regions via register_region(); unknown codes are
# refused until registered.
REGION_JURISDICTION: Mapping[str, str] = {
    # EU/EEA
    "eu-west-1": "eu", "eu-west-2": "eu", "eu-west-3": "eu",
    "eu-central-1": "eu", "eu-north-1": "eu", "eu-south-1": "eu",
    # UK
    "eu-west-2a": "uk",  # UK-local alias namespace
    # US
    "us-east-1": "us", "us-east-2": "us", "us-west-1": "us", "us-west-2": "us",
    "us-gov-west-1": "us",
    # China
    "cn-north-1": "cn", "cn-northwest-1": "cn",
    # India
    "ap-south-1": "in",
    # Brazil
    "sa-east-1": "br",
    # Japan / Singapore / UAE / Saudi Arabia
    "ap-northeast-1": "jp",
    "ap-southeast-1": "sg",
    "me-south-1": "ae",
    "me-central-1": "sa",
}

DATA_CLASSES: FrozenSet[str] = frozenset({
    "personal",      # identifiable personal data
    "sensitive",     # special-category / health / biometric-shaped
    "pseudonymized", # de-identified but re-identifiable in principle
    "non-personal",  # telemetry, aggregates, public data
})

TRANSFER_BASES: FrozenSet[str] = frozenset({
    "adequacy",             # adequacy decision (e.g. EU->UK, EU->Japan)
    "scc",                  # standard contractual clauses
    "bcr",                  # binding corporate rules
    "dpf",                  # EU-US Data Privacy Framework
    "derogation",           # explicit derogation / explicit consent
    "security-assessment",  # PIPL-style cross-border security assessment
    "contract",             # contractual necessity clause
})

# Jurisdictions with an EU adequacy decision (curated, simplified).
ADEQUACY_FROM_EU: FrozenSet[str] = frozenset({"uk", "jp", "sg"})

# Default transfer policy, pinned data. Keyed on (from_jurisdiction,
# to_jurisdiction, data_class). Value semantics:
#   {"allow": True,  "bases": frozenset()}        -- unconditionally allowed
#   {"allow": True,  "bases": {"scc", "bcr"}}     -- allowed with one of these
#   {"allow": False, "bases": frozenset()}        -- denied outright
# Any (from, to, class) not listed here is resolved by the
# _DEFAULT_RULE below (same-jurisdiction free; non-personal free;
# otherwise denied unless an explicit basis is recorded).
_DEFAULT_POLICY: Tuple[Tuple[str, str, str, bool, Tuple[str, ...]], ...] = (
    # China-origin personal data: localization-default posture.
    ("cn", "*", "personal", True, ("security-assessment",)),
    ("cn", "*", "sensitive", True, ("security-assessment",)),
    # EU-origin adequacy destinations.
    ("eu", "uk", "personal", True, ("adequacy",)),
    ("eu", "jp", "personal", True, ("adequacy",)),
    ("eu", "sg", "personal", True, ("adequacy",)),
    ("eu", "uk", "pseudonymized", True, ()),
    ("eu", "jp", "pseudonymized", True, ()),
    ("eu", "sg", "pseudonymized", True, ()),
    # EU-origin to the US: DPF or SCCs/BCRs; sensitive excludes derogation.
    ("eu", "us", "personal", True, ("dpf", "scc", "bcr", "derogation")),
    ("eu", "us", "pseudonymized", True, ()),
    ("eu", "us", "sensitive", True, ("dpf", "scc", "bcr")),
    # EU-origin elsewhere.
    ("eu", "*", "personal", True, ("scc", "bcr", "derogation")),
    ("eu", "*", "pseudonymized", True, ("adequacy",)),
    ("eu", "*", "sensitive", True, ("scc", "bcr")),
    # US-origin: SCC-style contractual basis for personal classes.
    ("us", "*", "personal", True, ("scc", "bcr", "derogation", "contract")),
    ("us", "*", "pseudonymized", True, ()),
    ("us", "*", "sensitive", True, ("scc", "bcr", "contract")),
    # Any-origin to "other": needs a recorded basis for personal classes.
    ("*", "other", "personal", True, ("scc", "bcr", "derogation")),
    ("*", "other", "pseudonymized", True, ("adequacy",)),
    ("*", "other", "sensitive", True, ("scc", "bcr")),
)

# Module-level digest pin over the default policy: detect policy drift by
# recomputation. (Computed after the digest helpers are defined.)

_KINDS: FrozenSet[str] = frozenset({
    "region-registered", "data-pinned", "migrated", "rejected",
})


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class DataResidencyError(Exception):
    """Base for all data-residency errors."""


class SeqOrderError(DataResidencyError):
    """Seq not a non-negative int, or not strictly increasing."""


class BadInputError(DataResidencyError):
    """Malformed input that fails closed before any ledger change."""


class UnknownJurisdictionError(DataResidencyError):
    """Jurisdiction code not in the pinned vocabulary."""


class UnknownRegionError(DataResidencyError):
    """Region code not registered."""


class DuplicateRegionError(DataResidencyError):
    """Region code already registered."""


class UnknownDataClassError(DataResidencyError):
    """Data class not in the pinned vocabulary."""


class UnknownPinError(DataResidencyError):
    """Pin id not known."""


class DuplicatePinError(DataResidencyError):
    """An active pin already exists for this (subject_id, data_class)."""


class TransferDeniedError(DataResidencyError):
    """The pinned policy forbids this (from, to, data_class) transfer."""


class InvalidBasisError(DataResidencyError):
    """Transfer basis not in the pinned vocabulary or not accepted."""


# ---------------------------------------------------------------------------
# Canonical digest helpers (batch-5 JCS discipline)
# ---------------------------------------------------------------------------

_MAX_SAFE_INT = 2 ** 53
_VALUE_DIGEST_PREFIX = "sha256:"
_REGION_CODE_RE = re.compile(r"^[a-z][a-z0-9-]{1,63}$")


def _check_seq(value: Any, field_name: str = "seq") -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise SeqOrderError(f"{field_name} must be an int, saw {type(value).__name__}")
    if value < 0:
        raise SeqOrderError(f"{field_name} must be non-negative, saw {value}")
    return value


def _check_str(value: Any, field_name: str, max_len: int = 256) -> str:
    if not isinstance(value, str) or not value:
        raise BadInputError(f"{field_name} must be a non-empty str, saw {type(value).__name__}")
    if len(value) > max_len:
        raise BadInputError(f"{field_name} longer than {max_len} chars refused")
    return value


def _check_region_code(value: Any) -> str:
    code = _check_str(value, "region_code", 64)
    if not _REGION_CODE_RE.match(code):
        raise BadInputError(f"region_code has bad shape: {code!r}")
    return code


def _check_jurisdiction(value: Any) -> str:
    if not isinstance(value, str) or value not in JURISDICTIONS:
        raise UnknownJurisdictionError(f"unknown jurisdiction: {value!r}")
    return value


def _check_data_class(value: Any) -> str:
    if not isinstance(value, str) or value not in DATA_CLASSES:
        raise UnknownDataClassError(f"unknown data class: {value!r}")
    return value


def _check_basis(value: Any) -> str:
    if not isinstance(value, str) or value not in TRANSFER_BASES:
        raise InvalidBasisError(f"unknown transfer basis: {value!r}")
    return value


def _tag(value: Any) -> Any:
    """Type-tagged canonical form: bool != int; floats refused."""
    if value is None:
        return ["n"]
    if isinstance(value, bool):
        return ["b", value]
    if isinstance(value, int):
        if abs(value) >= _MAX_SAFE_INT:
            raise BadInputError(f"int outside +/-2^53 refused: {value!r}")
        return ["i", value]
    if isinstance(value, float):
        raise BadInputError(f"floats refused at the residency boundary: {value!r}")
    if isinstance(value, str):
        if len(value) > 65536:
            raise BadInputError("str longer than 65536 chars refused")
        return ["s", value]
    if isinstance(value, (list, tuple)):
        if len(value) > 10000:
            raise BadInputError("list longer than 10000 items refused")
        return ["l", [_tag(item) for item in value]]
    if isinstance(value, dict):
        if len(value) > 10000:
            raise BadInputError("dict larger than 10000 entries refused")
        for k in value:
            if not isinstance(k, str):
                raise BadInputError("dict keys must be str")
        return ["d", [[k, _tag(value[k])] for k in sorted(value)]]
    if isinstance(value, (frozenset, set)):
        return ["l", [_tag(v) for v in sorted(value, key=repr)]]
    raise BadInputError(f"unencodable value type: {type(value).__name__}")


def _canonical(value: Any) -> bytes:
    return json.dumps(
        _tag(value), separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def _pin(*parts: bytes) -> str:
    digest = hashlib.sha256()
    for part in parts:
        digest.update(len(part).to_bytes(8, "big"))
        digest.update(part)
    return _VALUE_DIGEST_PREFIX + digest.hexdigest()


def _policy_digest() -> str:
    entries = [
        {"from": f, "to": t, "class": c, "allow": a, "bases": list(b)}
        for (f, t, c, a, b) in _DEFAULT_POLICY
    ]
    return _pin(b"data-residency-policy", _canonical(entries))


POLICY_DIGEST = _policy_digest()


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RegionRecord:
    """A registered storage region: code -> jurisdiction mapping."""

    region_code: str
    jurisdiction: str
    label: str
    registered_seq: int
    record_digest: str = ""

    def verify(self) -> bool:
        return _region_digest(self.region_code, self.jurisdiction,
                             self.label, self.registered_seq) == self.record_digest


@dataclass(frozen=True)
class PinRecord:
    """A data-subject residency pin: (subject, class) -> origin region."""

    pin_id: str
    subject_id: str
    data_class: str
    region_code: str
    pinned_seq: int
    prev_digest: str
    record_digest: str = ""

    def verify(self) -> bool:
        return _pin_digest(self.pin_id, self.subject_id, self.data_class,
                          self.region_code, self.pinned_seq,
                          self.prev_digest) == self.record_digest


@dataclass(frozen=True)
class MigrationRecord:
    """One immutable cross-region move of a pin."""

    mig_id: str
    pin_id: str
    from_region: str
    to_region: str
    data_class: str
    transfer_basis: Optional[str]
    migrated_seq: int
    record_digest: str = ""

    def verify(self) -> bool:
        return _migration_digest(
            self.mig_id, self.pin_id, self.from_region, self.to_region,
            self.data_class, self.transfer_basis, self.migrated_seq,
        ) == self.record_digest


def _region_digest(region_code: str, jurisdiction: str,
                   label: str, seq: int) -> str:
    return _pin(b"region", _canonical({
        "region_code": region_code,
        "jurisdiction": jurisdiction,
        "label": label,
        "seq": seq,
    }))


def _pin_digest(pin_id: str, subject_id: str, data_class: str,
                region_code: str, seq: int, prev_digest: str) -> str:
    return _pin(b"pin", _canonical({
        "pin_id": pin_id,
        "subject_id": subject_id,
        "data_class": data_class,
        "region_code": region_code,
        "seq": seq,
        "prev_digest": prev_digest,
    }))


def _migration_digest(mig_id: str, pin_id: str, from_region: str,
                      to_region: str, data_class: str,
                      transfer_basis: Optional[str], seq: int) -> str:
    return _pin(b"migration", _canonical({
        "mig_id": mig_id,
        "pin_id": pin_id,
        "from_region": from_region,
        "to_region": to_region,
        "data_class": data_class,
        "transfer_basis": transfer_basis,
        "seq": seq,
    }))


# ---------------------------------------------------------------------------
# Manager
# ---------------------------------------------------------------------------

class DataResidency:
    """Deterministic residency ledger: regions, pins, and migrations."""

    def __init__(self, seed: int = 0) -> None:
        _check_seq(seed, "seed")
        self._seed = seed
        self._lock = threading.RLock()
        self._last_seq = -1
        self._regions: Dict[str, RegionRecord] = {}
        self._pins: Dict[str, PinRecord] = {}
        self._migrations: Dict[str, MigrationRecord] = {}
        self._migrations_of: Dict[str, List[str]] = {}
        self._active_pin: Dict[Tuple[str, str], str] = {}
        self._pin_counter = 0
        self._mig_counter = 0
        self._audit_log: List[Mapping[str, Any]] = []
        for code, jur in sorted(REGION_JURISDICTION.items()):
            self._register_region_locked(code, jur, "", -1)

    # -- internal ----------------------------------------------------------

    def _consume_seq(self, seq: int) -> int:
        _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq must be strictly increasing: saw {seq} after {self._last_seq}"
            )
        self._last_seq = seq
        return seq

    def _audit(self, kind: str, seq: int, **detail: Any) -> None:
        self._audit_log.append(
            data_residency_audit_event(kind, seq, **detail)
        )

    def _reject_audit(self, op: str, seq: Any, exc: Exception) -> None:
        """Record a rejection audit entry without masking the original error."""
        audit_seq = seq if isinstance(seq, int) and not isinstance(seq, bool) and seq >= 0 else 0
        self._audit("rejected", audit_seq, op=op, reason=type(exc).__name__)

    def _register_region_locked(self, region_code: str, jurisdiction: str,
                                label: str, seq: int) -> RegionRecord:
        record = RegionRecord(
            region_code=region_code,
            jurisdiction=jurisdiction,
            label=label,
            registered_seq=seq,
            record_digest="",
        )
        record = replace(
            record,
            record_digest=_region_digest(region_code, jurisdiction, label, seq),
        )
        self._regions[region_code] = record
        return record

    def _jurisdiction_of(self, region_code: str) -> str:
        record = self._regions.get(region_code)
        if record is None:
            raise UnknownRegionError(f"unknown region: {region_code!r}")
        return record.jurisdiction

    # -- policy ------------------------------------------------------------

    def transfer_allowed(
        self,
        from_region: str,
        to_region: str,
        data_class: str,
        transfer_basis: Optional[str] = None,
    ) -> Tuple[bool, Optional[FrozenSet[str]]]:
        """Pure view: (allowed, accepted_bases) for a transfer.

        ``accepted_bases`` is None for unconditional decisions and the
        pinned accepted-basis set when a basis is required.
        """
        data_class = _check_data_class(data_class)
        if transfer_basis is not None:
            _check_basis(transfer_basis)
        from_jur = self._jurisdiction_of(_check_region_code(from_region))
        to_jur = self._jurisdiction_of(_check_region_code(to_region))
        return self._policy_lookup(from_jur, to_jur, data_class, transfer_basis)

    @staticmethod
    def _policy_lookup(
        from_jur: str,
        to_jur: str,
        data_class: str,
        transfer_basis: Optional[str],
    ) -> Tuple[bool, Optional[FrozenSet[str]]]:
        if from_jur == to_jur:
            return True, None
        if data_class == "non-personal":
            return True, None
        for (f, t, c, allow, bases) in _DEFAULT_POLICY:
            if (f in (from_jur, "*")) and (t in (to_jur, "*")) and c == data_class:
                if not allow:
                    return False, None
                if not bases:
                    return True, None
                accepted = frozenset(bases)
                if transfer_basis is not None and transfer_basis in accepted:
                    return True, accepted
                return False, accepted
        # Fallback rule: cross-jurisdiction movement of identified or
        # sensitive data without a listed rule is denied.
        return False, None

    def policy_table(self) -> List[Mapping[str, Any]]:
        """The pinned default policy as inspectable data."""
        return [
            {
                "from": f, "to": t, "class": c, "allow": a,
                "bases": sorted(b),
            }
            for (f, t, c, a, b) in _DEFAULT_POLICY
        ]

    # -- regions -----------------------------------------------------------

    def register_region(
        self,
        region_code: str,
        jurisdiction: str,
        seq: int,
        label: str = "",
    ) -> RegionRecord:
        """Register a new region code -> jurisdiction mapping."""
        with self._lock:
            try:
                self._consume_seq(seq)
                code = _check_region_code(region_code)
                jur = _check_jurisdiction(jurisdiction)
                if label is not None and not isinstance(label, str):
                    raise BadInputError("label must be a str")
                if code in self._regions:
                    raise DuplicateRegionError(f"region already registered: {code!r}")
                record = self._register_region_locked(code, jur, label or "", seq)
            except DataResidencyError as exc:
                self._reject_audit("register_region", seq, exc)
                raise
            self._audit("region-registered", seq, region_code=code,
                        jurisdiction=jur, digest=record.record_digest)
            return record

    def region(self, region_code: str) -> RegionRecord:
        """Pure read view of a registered region."""
        code = _check_region_code(region_code)
        record = self._regions.get(code)
        if record is None:
            raise UnknownRegionError(f"unknown region: {code!r}")
        return record

    def region_codes(self) -> List[str]:
        return sorted(self._regions)

    # -- pins --------------------------------------------------------------

    def pin(
        self,
        subject_id: str,
        region_code: str,
        seq: int,
        data_class: str = "personal",
    ) -> PinRecord:
        """Pin a (subject_id, data_class) to a region."""
        with self._lock:
            try:
                self._consume_seq(seq)
                subject = _check_str(subject_id, "subject_id", 128)
                code = _check_region_code(region_code)
                dclass = _check_data_class(data_class)
                if code not in self._regions:
                    raise UnknownRegionError(f"unknown region: {code!r}")
                if (subject, dclass) in self._active_pin:
                    raise DuplicatePinError(
                        f"active pin exists for ({subject!r}, {dclass!r}): "
                        "use migrate() to move it"
                    )
                self._pin_counter += 1
                pin_id = f"pin-{self._pin_counter}"
                # Per-subject digest chain: chain on the latest pin/migration digest.
                chain_head = self._chain_head_locked(subject)
                record = PinRecord(
                    pin_id=pin_id,
                    subject_id=subject,
                    data_class=dclass,
                    region_code=code,
                    pinned_seq=seq,
                    prev_digest=chain_head,
                    record_digest="",
                )
                record = replace(
                    record,
                    record_digest=_pin_digest(
                        pin_id, subject, dclass, code, seq, chain_head),
                )
            except DataResidencyError as exc:
                self._reject_audit("pin", seq, exc)
                raise
            self._pins[pin_id] = record
            self._migrations_of[pin_id] = []
            self._active_pin[(subject, dclass)] = pin_id
            self._audit("data-pinned", seq, pin_id=pin_id,
                        subject_id=subject, data_class=dclass,
                        region_code=code, digest=record.record_digest)
            return record

    def _chain_head_locked(self, subject: str) -> str:
        head = ""
        for record in self._pins.values():
            if record.subject_id == subject:
                head = record.record_digest
        for record in self._migrations.values():
            pin = self._pins.get(record.pin_id)
            if pin is not None and pin.subject_id == subject:
                head = record.record_digest
        return head

    def pin_record(self, pin_id: str) -> PinRecord:
        """Pure read view of a pin."""
        _check_str(pin_id, "pin_id", 64)
        record = self._pins.get(pin_id)
        if record is None:
            raise UnknownPinError(f"unknown pin: {pin_id!r}")
        return record

    def pins_of(self, subject_id: str) -> List[PinRecord]:
        """All pins (any data class) for a subject, in pin order."""
        subject = _check_str(subject_id, "subject_id", 128)
        return [r for r in sorted(self._pins.values(),
                                  key=lambda r: int(r.pin_id.split("-")[1]))
                if r.subject_id == subject]

    def residency(self, pin_id: str) -> str:
        """Current region code of a pin (latest migration wins)."""
        record = self.pin_record(pin_id)
        history = self._migrations_of.get(pin_id, [])
        if history:
            return self._migrations[history[-1]].to_region
        return record.region_code

    # -- migrations --------------------------------------------------------

    def migrate(
        self,
        pin_id: str,
        target_region_code: str,
        seq: int,
        transfer_basis: Optional[str] = None,
    ) -> MigrationRecord:
        """Move a pin's data to another region, enforcing the transfer policy."""
        with self._lock:
            try:
                self._consume_seq(seq)
                _check_str(pin_id, "pin_id", 64)
                record = self._pins.get(pin_id)
                if record is None:
                    raise UnknownPinError(f"unknown pin: {pin_id!r}")
                target = _check_region_code(target_region_code)
                if target not in self._regions:
                    raise UnknownRegionError(f"unknown region: {target!r}")
                if transfer_basis is not None:
                    _check_basis(transfer_basis)
                current = self.residency(pin_id)
                if target == current:
                    raise BadInputError("target region equals current region")
                from_jur = self._jurisdiction_of(current)
                to_jur = self._jurisdiction_of(target)
                allowed, accepted = self._policy_lookup(
                    from_jur, to_jur, record.data_class, transfer_basis)
                if not allowed:
                    if accepted is None:
                        raise TransferDeniedError(
                            f"transfer {from_jur}->{to_jur} ({record.data_class}) "
                            "denied outright by policy"
                        )
                    raise TransferDeniedError(
                        f"transfer {from_jur}->{to_jur} ({record.data_class}) "
                        f"requires one of {sorted(accepted)}"
                    )
                self._mig_counter += 1
                mig_id = f"mig-{self._mig_counter}"
                migration = MigrationRecord(
                    mig_id=mig_id,
                    pin_id=pin_id,
                    from_region=current,
                    to_region=target,
                    data_class=record.data_class,
                    transfer_basis=transfer_basis,
                    migrated_seq=seq,
                    record_digest="",
                )
                migration = replace(
                    migration,
                    record_digest=_migration_digest(
                        mig_id, pin_id, current, target, record.data_class,
                        transfer_basis, seq),
                )
            except DataResidencyError as exc:
                self._reject_audit("migrate", seq, exc)
                raise
            self._migrations[mig_id] = migration
            self._migrations_of[pin_id].append(mig_id)
            self._audit("migrated", seq, mig_id=mig_id, pin_id=pin_id,
                        from_region=current, to_region=target,
                        transfer_basis=transfer_basis,
                        digest=migration.record_digest)
            return migration

    def migration_history(self, pin_id: str) -> List[MigrationRecord]:
        """All migrations of a pin, in migration order."""
        _check_str(pin_id, "pin_id", 64)
        if pin_id not in self._pins:
            raise UnknownPinError(f"unknown pin: {pin_id!r}")
        return [self._migrations[mig_id] for mig_id in self._migrations_of[pin_id]]

    def audit(self, seq: int) -> Mapping[str, Any]:
        """Digest-pinned summary of the ledger (pure view)."""
        _check_seq(seq)
        state = {
            "regions": len(self._regions),
            "pins": len(self._pins),
            "migrations": len(self._migrations),
            "policy_digest": POLICY_DIGEST,
        }
        return {
            "schema": AUDIT_SCHEMA,
            "module": "data_residency",
            "module_version": VERSION,
            "seq": seq,
            "state": state,
            "state_digest": _pin(b"audit", _canonical(state)),
        }

    def audit_log(self) -> List[Mapping[str, Any]]:
        return list(self._audit_log)


# ---------------------------------------------------------------------------
# Audit event helper
# ---------------------------------------------------------------------------

def data_residency_audit_event(
    kind: str, seq: int, **detail: Any
) -> Mapping[str, Any]:
    """Shape an ``audit.ndjson/1`` record for the residency manager."""
    if kind not in _KINDS:
        raise DataResidencyError(f"unknown audit kind: {kind!r}")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise DataResidencyError(f"bad audit seq: {seq!r}")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": "data_residency",
        "module_version": VERSION,
        "seq": seq,
        "detail": dict(detail),
    }


def main() -> None:
    mgr = DataResidency()
    pin = mgr.pin("subject-1", "eu-west-1", 1, "personal")
    assert mgr.residency(pin.pin_id) == "eu-west-1"
    mig = mgr.migrate(pin.pin_id, "us-east-1", 2, "scc")
    assert mgr.residency(pin.pin_id) == "us-east-1"
    assert pin.verify() and mig.verify()
    assert mgr.region("eu-west-1").verify()
    assert mgr.audit(3)["state"]["migrations"] == 1
    print("data-residency OK: register, pin, migrate, policy, pins, audit")


if __name__ == "__main__":
    main()
