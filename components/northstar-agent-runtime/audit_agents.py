"""Audit & assurance discipline (one-hundred-forty-third batch).

Absorbs the 2026 AI-audit research thread:

* **EY (2026-04)** — agentic AI over 1.4 trillion journal-entry lines
  per year, 160,000 audit engagements, 130,000 assurance staff;
  end-to-end audit AI targeted by 2028. Full-population analysis is
  already operational.
* **KPMG Clara AI** — 95,000 auditors in 140+ countries; fee-evidence
  and unrecorded-liability agents; control-testing agents live in
  2026.
* **FloQast (2026-09)** — AI drafts plans, executes tests, one-click
  executive reports; COSO chair Lucia Wind joined as SVP.
* **Parker & Lawrence "AI in Risk & Compliance 2026"** (300
  institutions) — 72% run highly autonomous AI, of which **81% have
  no AI incident-management procedure**, 70.4% no pre-deployment
  review, 65.3% no AI inventory: "adoption outrunning preparation".
* **COSO 2026-02-23** "Achieving Effective Internal Control Over
  Generative AI" — 8 capability classes, audit-ready control mapping,
  6-step roadmap; audit trails must capture prompt / input / output /
  model version / human review — enough to reconstruct the AI's
  behavior rationale.
* **PCAOB AS 1105** (effective 2024-12-15) — information-system
  evidence standards extended to AI working papers.
* **OSFI E-23** (effective 2027-05-01) — model-risk management covers
  all federally regulated insurers plus AI/ML; 2026-07 circular: AI
  outputs are decision *inputs* only, humans are accountable.
* **US 2026-04 pivot** — OCC/FDIC revisions place generative/agentic
  AI outside model-risk scope (institutions self-govern): the
  receipts below cannot assume regulator coverage that may not
  exist.
* **Risk line** — evidence-chain drift, the "done is not provable"
  gap (OneTrust x Sapio 2026: governance evidence and audit trails
  are the weakest of 8 activities at 28%), rubber-stamp human
  oversight, and alert fatigue (≤5% conversion).

Northstar mapping: AI audit work is a hash-chained receipt that binds
``(work_id | prompt_digest | input_digest | output_digest |
model_version | human_reviewer_id | reviewed_at)``. Every gate is
fail-closed: AI work without a live reconstruction receipt is
NON_AUTHORITATIVE (COSO lesson); AI audit tools need 1–2 parallel-run
cycles against a human audit before go-live; AI outputs are evidence,
never conclusions — conclusion labels without a named-human signoff
are ``audit.unconcluded``; unregistered AI in the pipeline is denied
as shadow AI; AI deciding without a decision-rights charter is
``audit.no_charter``; rubber-stamp override rates trip
``audit.rubber_stamp``; highly autonomous AI without an
incident-management procedure is refused deployment; alerts converting
at ≤5% auto-degrade; and documentation must be current before new
functionality ships.

Deterministic: no wall-clock reads (callers inject ``now`` as an
integer epoch), canonical JCS hashing (ninety-fifth batch), and all
digest comparisons use :func:`hmac.compare_digest`.

Honest scope:

* The receipts verify the *claimed* bundle is self-consistent and
  authority-signed; they cannot prove the human reviewer actually
  reviewed — that needs independent evidence.
* The receipt is a governance record, not a substitute for the
  auditor's professional judgment; it makes the reliance decision
  auditable.
* Parallel-run cycle counts and alert-conversion thresholds are bench
  parameters drawn from the 2026 research sweep; confirm against the
  engagement's own audit standards before assurance reliance.
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

try:
    import ed25519
except Exception:  # pragma: no cover - vendored module is always present
    ed25519 = None  # type: ignore[assignment]


AUDIT_SCHEMA_VERSION = "northstar.audit.v1"

_GENESIS = "genesis"
_HEX64_LENGTH = 64
_HEX128_LENGTH = 128
_DAY_S = 86_400

CLASS_AUTHORITATIVE = "authoritative"
CLASS_NON_AUTHORITATIVE = "non_authoritative"

#: Minimum parallel-run cycles before an AI audit tool goes live
#: (1–2 cycles, per the 2026 research sweep).
PARALLEL_RUN_MIN_CYCLES = 1

#: Alert-conversion floor: audit alerts converting at or below this
#: rate auto-degrade (alert-fatigue lesson, ≤5% observed).
ALERT_CONVERSION_FLOOR = 0.05

#: Rubber-stamp line: override rates at or below this are audit
#: incidents, not supervision (automation-bias lesson).
OVERRIDE_RUBBER_STAMP_MAX = 0.02

#: Human-oversight capacity floor: reviewers per 1,000 AI decisions
#: per day. Below this, oversight is capacity-denied.
OVERSIGHT_CAPACITY_FLOOR_PER_1K = 1

#: Audit event names.
RECONSTRUCTION_ISSUED_EVENT = "audit.reconstruction_issued"
PARALLEL_RUN_RECORDED_EVENT = "audit.parallel_run_recorded"
INVENTORY_REGISTERED_EVENT = "audit.inventory_registered"
CHARTER_BOUND_EVENT = "audit.charter_bound"
PROCEDURE_BOUND_EVENT = "audit.procedure_bound"


class AuditError(ValueError):
    """A malformed audit receipt or a programming error.

    Raised for structural problems (bad digests, unknown checks,
    broken chains). Verification *failures* (missing reconstruction
    bundles, shadow AI, rubber-stamp oversight) return an
    :class:`AuditVerdict` with ``allowed=False`` instead — a failed
    gate is a verdict, a malformed receipt is a bug.
    """


# ---------------------------------------------------------------------------
# Field checks
# ---------------------------------------------------------------------------


def _is_hex(value: Any, length: int) -> bool:
    if not isinstance(value, str) or len(value) != length:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def _check_hex64(value: Any, field_name: str) -> str:
    if not _is_hex(value, _HEX64_LENGTH):
        raise AuditError(f"{field_name} must be a 64-char lowercase hex digest")
    return value


def _check_nonempty_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise AuditError(f"{field_name} must be a non-empty string")
    return value


def _check_ts(value: Any, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise AuditError(f"{field_name} must be a non-negative int epoch")
    return value


def _check_secret(value: Any, field_name: str) -> bytes:
    # The vendored ed25519 module takes a raw 32-byte seed (no keypair()).
    if not isinstance(value, bytes) or len(value) != 32:
        raise AuditError(f"{field_name} must be a 32-byte seed")
    return value


def _check_pubkey_hex(value: Any) -> str:
    if not _is_hex(value, _HEX64_LENGTH):
        raise AuditError("authority_pubkey_hex must be a 64-char lowercase hex digest")
    return value


def _check_sig_hex(value: Any, field_name: str) -> str:
    if not _is_hex(value, _HEX128_LENGTH):
        raise AuditError(f"{field_name} must be a 128-char lowercase hex signature")
    return value


def _check_bool(value: Any, field_name: str) -> bool:
    if not isinstance(value, bool):
        raise AuditError(f"{field_name} must be a bool")
    return value


def _check_nonneg_number(value: Any, field_name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
        raise AuditError(f"{field_name} must be a non-negative number")
    return float(value)


def _check_ratio(value: Any, field_name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise AuditError(f"{field_name} must be a number")
    if not 0.0 <= value <= 1.0:
        raise AuditError(f"{field_name} must be in [0, 1]")
    return float(value)


# ---------------------------------------------------------------------------
# Signing and chain verification
# ---------------------------------------------------------------------------


def _verify_signature(
    pubkey_hex: str, payload: Mapping[str, Any], signature_hex: str
) -> bool:
    try:
        return bool(
            ed25519.verify(
                bytes.fromhex(pubkey_hex),
                jcs_canonical_json(payload),
                bytes.fromhex(signature_hex),
            )
        )
    except Exception:
        return False


def _check_chain(log: list[Any], type_name: str) -> None:
    """Raise :class:`AuditError` if a receipt log is tampered/broken.

    Every entry must expose ``receipt_digest`` and ``prev_digest`` and
    a ``_payload()`` method; the entries must form one chain from
    ``"genesis"`` with recomputing digests and valid authority
    signatures.
    """
    expected_prev = _GENESIS
    for entry in log:
        if not hmac.compare_digest(entry.receipt_digest, jcs_sha256_hex(entry._payload())):
            raise AuditError(
                f"{type_name} receipt {entry.receipt_id!r} digest does not recompute"
            )
        if not hmac.compare_digest(entry.prev_digest, expected_prev):
            raise AuditError(
                f"{type_name} receipt {entry.receipt_id!r} chain break: "
                f"expected prev {expected_prev!r}"
            )
        # The authority signature covers the payload with a fixed
        # placeholder signature (the signature is stored alongside the
        # body it signs, not inside it); re-derive that signed body.
        signed_body = dict(entry._payload())
        signed_body["signature_hex"] = "00" * 64
        if not _verify_signature(
            entry.authority_pubkey_hex, signed_body, entry.signature_hex
        ):
            raise AuditError(
                f"{type_name} receipt {entry.receipt_id!r} authority signature invalid"
            )
        expected_prev = entry.receipt_digest


@dataclass(frozen=True)
class AuditVerdict:
    """Outcome of one audit-discipline gate check."""

    allowed: bool
    reason: str
    classification: str = CLASS_NON_AUTHORITATIVE
    receipt_digest: str = ""


def _deny(code: str, detail: str) -> AuditVerdict:
    return AuditVerdict(
        allowed=False,
        reason=f"{code}: {detail}",
        classification=CLASS_NON_AUTHORITATIVE,
    )


def _allow(detail: str, receipt_digest: str = "") -> AuditVerdict:
    return AuditVerdict(
        allowed=True,
        reason=detail,
        classification=CLASS_AUTHORITATIVE,
        receipt_digest=receipt_digest,
    )


# ---------------------------------------------------------------------------
# Authority registry (shared lookup for signed receipts)
# ---------------------------------------------------------------------------


@dataclass
class AuthorityRegistry:
    """Maps authority ids to Ed25519 public keys (hex)."""

    _pubkeys: dict[str, str] | None = None

    def __post_init__(self) -> None:
        self._pubkeys = {}

    def register(self, authority_id: str, pubkey_hex: str) -> None:
        _check_nonempty_str(authority_id, "authority_id")
        _check_pubkey_hex(pubkey_hex)
        self._pubkeys[authority_id] = pubkey_hex

    def pubkey(self, authority_id: str) -> str | None:
        return self._pubkeys.get(authority_id)


# ---------------------------------------------------------------------------
# 1. Reconstruction receipts (COSO 2026-02-23 lesson)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ReconstructionReceipt:
    """Binds the 5-piece COSO reconstruction bundle."""

    receipt_id: str
    work_id: str
    prompt_digest: str
    input_digest: str
    output_digest: str
    model_version: str
    human_reviewer_id: str
    reviewed_at: int
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": AUDIT_SCHEMA_VERSION,
            "type": "reconstruction",
            "receipt_id": self.receipt_id,
            "work_id": self.work_id,
            "prompt_digest": self.prompt_digest,
            "input_digest": self.input_digest,
            "output_digest": self.output_digest,
            "model_version": self.model_version,
            "human_reviewer_id": self.human_reviewer_id,
            "reviewed_at": self.reviewed_at,
            "authority_id": self.authority_id,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "signature_hex": "00" * 64,
            "prev_digest": self.prev_digest,
        }

    @property
    def receipt_digest(self) -> str:
        return jcs_sha256_hex(self._payload())


@dataclass
class ReconstructionRegistry:
    """Hash-chained log of reconstruction receipts per authority."""

    authorities: AuthorityRegistry
    log: list[ReconstructionReceipt] | None = None

    def __post_init__(self) -> None:
        self.log = []

    def issue(
        self,
        receipt_id: str,
        work_id: str,
        prompt_digest: str,
        input_digest: str,
        output_digest: str,
        model_version: str,
        human_reviewer_id: str,
        reviewed_at: int,
        authority_id: str,
        signature: bytes,
        issued_now: int,
    ) -> ReconstructionReceipt:
        _check_nonempty_str(receipt_id, "receipt_id")
        _check_nonempty_str(work_id, "work_id")
        _check_hex64(prompt_digest, "prompt_digest")
        _check_hex64(input_digest, "input_digest")
        _check_hex64(output_digest, "output_digest")
        _check_nonempty_str(model_version, "model_version")
        _check_nonempty_str(human_reviewer_id, "human_reviewer_id")
        _check_ts(reviewed_at, "reviewed_at")
        _check_ts(issued_now, "issued_now")
        pubkey = self.authorities.pubkey(authority_id)
        if pubkey is None:
            raise AuditError(f"unknown authority {authority_id!r}")
        prev = self.log[-1].receipt_digest if self.log else _GENESIS
        receipt = ReconstructionReceipt(
            receipt_id=receipt_id,
            work_id=work_id,
            prompt_digest=prompt_digest,
            input_digest=input_digest,
            output_digest=output_digest,
            model_version=model_version,
            human_reviewer_id=human_reviewer_id,
            reviewed_at=reviewed_at,
            authority_id=authority_id,
            authority_pubkey_hex=pubkey,
            signature_hex=signature.hex(),
            prev_digest=prev,
        )
        signed_body = dict(receipt._payload())
        signed_body["signature_hex"] = "00" * 64
        if not _verify_signature(pubkey, signed_body, receipt.signature_hex):
            raise AuditError("reconstruction receipt authority signature invalid")
        self.log.append(receipt)
        return receipt

    def find(self, work_id: str) -> ReconstructionReceipt | None:
        for entry in self.log:
            if entry.work_id == work_id:
                return entry
        return None

    def revoke(self, receipt_id: str) -> None:
        keep = [e for e in self.log if e.receipt_id != receipt_id]
        if len(keep) == len(self.log):
            raise AuditError(f"unknown receipt {receipt_id!r}")
        # Revocation breaks the stored chain position; callers must
        # re-verify with the remaining log.
        self.log[:] = keep


def reconstruction_receipt(
    registry: ReconstructionRegistry,
    work_id: str,
    now: int,
    max_review_age_s: int = 90 * _DAY_S,
) -> AuditVerdict:
    """AI work without a live reconstruction receipt is NON_AUTHORITATIVE.

    The receipt must exist, carry a named human reviewer, and the
    review must be fresh (default 90-day shelf life); expired or
    revoked receipts read as no receipt (COSO lesson: trails must be
    able to reconstruct behavior rationale).
    """
    _check_nonempty_str(work_id, "work_id")
    _check_ts(now, "now")
    try:
        _check_chain(registry.log, "reconstruction")
    except AuditError as exc:
        return _deny("audit:chain_broken", str(exc))
    entry = registry.find(work_id)
    if entry is None:
        return _deny(
            "audit:no_reconstruction",
            f"AI work {work_id!r} has no reconstruction bundle "
            "(prompt/input/output/model version/human review)",
        )
    if not entry.human_reviewer_id.strip():
        return _deny(
            "audit:no_reviewer",
            f"reconstruction receipt for {work_id!r} names no human reviewer",
        )
    if entry.reviewed_at > now:
        return _deny(
            "audit:future_review",
            f"reconstruction receipt for {work_id!r} is reviewed in the future",
        )
    if now - entry.reviewed_at > max_review_age_s:
        return _deny(
            "audit:stale_reconstruction",
            f"reconstruction receipt for {work_id!r} review is older than "
            f"{max_review_age_s}s",
        )
    return _allow(
        f"AI work {work_id!r} reconstructable: bundle {entry.receipt_id!r} "
        f"reviewed by {entry.human_reviewer_id!r}",
        entry.receipt_digest,
    )


# ---------------------------------------------------------------------------
# 2. Parallel-run gate (go-live discipline)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ParallelRunReceipt:
    """Records parallel-run cycles of an AI audit tool vs a human audit."""

    receipt_id: str
    tool_id: str
    cycles_run: int
    human_audit_digest: str
    agreement_rate: float
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    recorded_at: int
    prev_digest: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": AUDIT_SCHEMA_VERSION,
            "type": "parallel_run",
            "receipt_id": self.receipt_id,
            "tool_id": self.tool_id,
            "cycles_run": self.cycles_run,
            "human_audit_digest": self.human_audit_digest,
            "agreement_rate": self.agreement_rate,
            "authority_id": self.authority_id,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "signature_hex": "00" * 64,
            "recorded_at": self.recorded_at,
            "prev_digest": self.prev_digest,
        }

    @property
    def receipt_digest(self) -> str:
        return jcs_sha256_hex(self._payload())


@dataclass
class ParallelRunRegistry:
    """Hash-chained log of parallel-run receipts."""

    authorities: AuthorityRegistry
    log: list[ParallelRunReceipt] | None = None

    def __post_init__(self) -> None:
        self.log = []

    def issue(
        self,
        receipt_id: str,
        tool_id: str,
        cycles_run: int,
        human_audit_digest: str,
        agreement_rate: float,
        authority_id: str,
        signature: bytes,
        recorded_at: int,
    ) -> ParallelRunReceipt:
        _check_nonempty_str(receipt_id, "receipt_id")
        _check_nonempty_str(tool_id, "tool_id")
        if not isinstance(cycles_run, int) or isinstance(cycles_run, bool) or cycles_run < 0:
            raise AuditError("cycles_run must be a non-negative int")
        _check_hex64(human_audit_digest, "human_audit_digest")
        _check_ratio(agreement_rate, "agreement_rate")
        _check_ts(recorded_at, "recorded_at")
        pubkey = self.authorities.pubkey(authority_id)
        if pubkey is None:
            raise AuditError(f"unknown authority {authority_id!r}")
        prev = self.log[-1].receipt_digest if self.log else _GENESIS
        receipt = ParallelRunReceipt(
            receipt_id=receipt_id,
            tool_id=tool_id,
            cycles_run=cycles_run,
            human_audit_digest=human_audit_digest,
            agreement_rate=agreement_rate,
            authority_id=authority_id,
            authority_pubkey_hex=pubkey,
            signature_hex=signature.hex(),
            recorded_at=recorded_at,
            prev_digest=prev,
        )
        signed_body = dict(receipt._payload())
        signed_body["signature_hex"] = "00" * 64
        if not _verify_signature(pubkey, signed_body, receipt.signature_hex):
            raise AuditError("parallel-run receipt authority signature invalid")
        self.log.append(receipt)
        return receipt

    def latest(self, tool_id: str) -> ParallelRunReceipt | None:
        for entry in reversed(self.log):
            if entry.tool_id == tool_id:
                return entry
        return None


def parallel_run_gate(
    registry: ParallelRunRegistry,
    tool_id: str,
    now: int,
    min_cycles: int = PARALLEL_RUN_MIN_CYCLES,
) -> AuditVerdict:
    """AI audit tools need 1–2 parallel-run cycles before go-live.

    A tool with fewer recorded cycles than ``min_cycles`` is refused
    deployment (70.4% of highly autonomous AI had no pre-deployment
    review — this gate is the review).
    """
    _check_nonempty_str(tool_id, "tool_id")
    _check_ts(now, "now")
    try:
        _check_chain(registry.log, "parallel_run")
    except AuditError as exc:
        return _deny("audit:chain_broken", str(exc))
    entry = registry.latest(tool_id)
    if entry is None or entry.cycles_run < min_cycles:
        return _deny(
            "audit:no_parallel_run",
            f"AI audit tool {tool_id!r} has {entry.cycles_run if entry else 0} "
            f"recorded parallel-run cycles; {min_cycles} required before go-live",
        )
    if entry.recorded_at > now:
        return _deny(
            "audit:future_parallel_run",
            f"parallel-run receipt for {tool_id!r} is recorded in the future",
        )
    return _allow(
        f"AI audit tool {tool_id!r} ran {entry.cycles_run} parallel cycle(s) "
        f"against human audit (agreement {entry.agreement_rate:.2f})",
        entry.receipt_digest,
    )


# ---------------------------------------------------------------------------
# 3. Evidence, not conclusions (PCAOB AS 1105 / OSFI lesson)
# ---------------------------------------------------------------------------


#: Closed vocabulary for what an AI output may claim to be.
OUTPUT_ROLES: tuple[str, ...] = ("evidence", "draft", "lead")


def _check_output_role(value: Any) -> str:
    if value not in OUTPUT_ROLES:
        raise AuditError(
            f"output role must be one of {OUTPUT_ROLES}, saw {value!r}"
        )
    return value


def evidence_not_conclusion(
    output_id: str,
    output_role: str,
    human_signed: bool,
) -> AuditVerdict:
    """AI outputs are evidence, never conclusions.

    An output carrying a conclusion label (outside the closed
    ``OUTPUT_ROLES`` vocabulary) without a named-human signoff is
    ``audit.unconcluded``: AI outputs are decision inputs only
    (OSFI 2026-07), and PCAOB AS 1105 evidence standards apply to the
    working papers they land in.
    """
    _check_nonempty_str(output_id, "output_id")
    _check_bool(human_signed, "human_signed")
    if output_role in OUTPUT_ROLES:
        return _allow(
            f"AI output {output_id!r} stays in role {output_role!r} (evidence, not conclusion)"
        )
    if not human_signed:
        return _deny(
            "audit:unconcluded",
            f"AI output {output_id!r} claims conclusion role {output_role!r} "
            "without a named-human signoff",
        )
    return _allow(
        f"AI output {output_id!r} conclusion {output_role!r} is human-signed"
    )


# ---------------------------------------------------------------------------
# 4. Shadow-AI inventory (65.3% gap lesson)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class InventoryEntry:
    """Registers one AI component in the audit pipeline."""

    receipt_id: str
    component_id: str
    component_digest: str
    purpose: str
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    registered_at: int
    prev_digest: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": AUDIT_SCHEMA_VERSION,
            "type": "inventory",
            "receipt_id": self.receipt_id,
            "component_id": self.component_id,
            "component_digest": self.component_digest,
            "purpose": self.purpose,
            "authority_id": self.authority_id,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "signature_hex": "00" * 64,
            "registered_at": self.registered_at,
            "prev_digest": self.prev_digest,
        }

    @property
    def receipt_digest(self) -> str:
        return jcs_sha256_hex(self._payload())


@dataclass
class InventoryRegistry:
    """Hash-chained AI inventory for the audit pipeline."""

    authorities: AuthorityRegistry
    log: list[InventoryEntry] | None = None

    def __post_init__(self) -> None:
        self.log = []

    def issue(
        self,
        receipt_id: str,
        component_id: str,
        component_digest: str,
        purpose: str,
        authority_id: str,
        signature: bytes,
        registered_at: int,
    ) -> InventoryEntry:
        _check_nonempty_str(receipt_id, "receipt_id")
        _check_nonempty_str(component_id, "component_id")
        _check_hex64(component_digest, "component_digest")
        _check_nonempty_str(purpose, "purpose")
        _check_ts(registered_at, "registered_at")
        pubkey = self.authorities.pubkey(authority_id)
        if pubkey is None:
            raise AuditError(f"unknown authority {authority_id!r}")
        prev = self.log[-1].receipt_digest if self.log else _GENESIS
        entry = InventoryEntry(
            receipt_id=receipt_id,
            component_id=component_id,
            component_digest=component_digest,
            purpose=purpose,
            authority_id=authority_id,
            authority_pubkey_hex=pubkey,
            signature_hex=signature.hex(),
            registered_at=registered_at,
            prev_digest=prev,
        )
        signed_body = dict(entry._payload())
        signed_body["signature_hex"] = "00" * 64
        if not _verify_signature(pubkey, signed_body, entry.signature_hex):
            raise AuditError("inventory entry authority signature invalid")
        self.log.append(entry)
        return entry

    def find(self, component_id: str) -> InventoryEntry | None:
        for entry in self.log:
            if entry.component_id == component_id:
                return entry
        return None


def shadow_ai_inventory(
    registry: InventoryRegistry,
    component_id: str,
    component_digest: str,
    now: int,
) -> AuditVerdict:
    """Unregistered AI in the audit pipeline is denied until inventoried.

    The component digest must match the registered digest: swapping the
    model after registration without re-inventorying is shadow AI.
    """
    _check_nonempty_str(component_id, "component_id")
    _check_hex64(component_digest, "component_digest")
    _check_ts(now, "now")
    try:
        _check_chain(registry.log, "inventory")
    except AuditError as exc:
        return _deny("audit:chain_broken", str(exc))
    entry = registry.find(component_id)
    if entry is None:
        return _deny(
            "audit:shadow_ai",
            f"AI component {component_id!r} is not in the audit-pipeline inventory",
        )
    if not hmac.compare_digest(entry.component_digest, component_digest):
        return _deny(
            "audit:shadow_ai",
            f"AI component {component_id!r} digest does not match inventory "
            "(model swapped without re-inventory)",
        )
    return _allow(
        f"AI component {component_id!r} inventoried for purpose "
        f"{entry.purpose!r}",
        entry.receipt_digest,
    )


# ---------------------------------------------------------------------------
# 5. Decision-rights charter (decide decision rights before sampling)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CharterReceipt:
    """Binds who may decide what before the AI decides anything."""

    receipt_id: str
    charter_id: str
    decision_rights_digest: str
    ai_decision_scope: str
    human_decision_scope: str
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    bound_at: int
    expires_at: int
    prev_digest: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": AUDIT_SCHEMA_VERSION,
            "type": "charter",
            "receipt_id": self.receipt_id,
            "charter_id": self.charter_id,
            "decision_rights_digest": self.decision_rights_digest,
            "ai_decision_scope": self.ai_decision_scope,
            "human_decision_scope": self.human_decision_scope,
            "authority_id": self.authority_id,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "signature_hex": "00" * 64,
            "bound_at": self.bound_at,
            "expires_at": self.expires_at,
            "prev_digest": self.prev_digest,
        }

    @property
    def receipt_digest(self) -> str:
        return jcs_sha256_hex(self._payload())


@dataclass
class CharterRegistry:
    """Hash-chained log of decision-rights charters."""

    authorities: AuthorityRegistry
    log: list[CharterReceipt] | None = None

    def __post_init__(self) -> None:
        self.log = []

    def issue(
        self,
        receipt_id: str,
        charter_id: str,
        decision_rights_digest: str,
        ai_decision_scope: str,
        human_decision_scope: str,
        authority_id: str,
        signature: bytes,
        bound_at: int,
        expires_at: int,
    ) -> CharterReceipt:
        _check_nonempty_str(receipt_id, "receipt_id")
        _check_nonempty_str(charter_id, "charter_id")
        _check_hex64(decision_rights_digest, "decision_rights_digest")
        _check_nonempty_str(ai_decision_scope, "ai_decision_scope")
        _check_nonempty_str(human_decision_scope, "human_decision_scope")
        _check_ts(bound_at, "bound_at")
        _check_ts(expires_at, "expires_at")
        if expires_at <= bound_at:
            raise AuditError("expires_at must be after bound_at")
        pubkey = self.authorities.pubkey(authority_id)
        if pubkey is None:
            raise AuditError(f"unknown authority {authority_id!r}")
        prev = self.log[-1].receipt_digest if self.log else _GENESIS
        receipt = CharterReceipt(
            receipt_id=receipt_id,
            charter_id=charter_id,
            decision_rights_digest=decision_rights_digest,
            ai_decision_scope=ai_decision_scope,
            human_decision_scope=human_decision_scope,
            authority_id=authority_id,
            authority_pubkey_hex=pubkey,
            signature_hex=signature.hex(),
            bound_at=bound_at,
            expires_at=expires_at,
            prev_digest=prev,
        )
        signed_body = dict(receipt._payload())
        signed_body["signature_hex"] = "00" * 64
        if not _verify_signature(pubkey, signed_body, receipt.signature_hex):
            raise AuditError("charter receipt authority signature invalid")
        self.log.append(receipt)
        return receipt

    def live(self, charter_id: str, now: int) -> CharterReceipt | None:
        for entry in reversed(self.log):
            if entry.charter_id == charter_id and entry.bound_at <= now < entry.expires_at:
                return entry
        return None


def decision_rights_charter(
    registry: CharterRegistry,
    charter_id: str,
    ai_made_decision: bool,
    now: int,
) -> AuditVerdict:
    """AI deciding without a live decision-rights charter is refused.

    Sampling ratios and audit plans come *after* the charter: an AI
    that decides while no charter binds who may decide what is
    ``audit.no_charter``.
    """
    _check_nonempty_str(charter_id, "charter_id")
    _check_bool(ai_made_decision, "ai_made_decision")
    _check_ts(now, "now")
    try:
        _check_chain(registry.log, "charter")
    except AuditError as exc:
        return _deny("audit:chain_broken", str(exc))
    if not ai_made_decision:
        return _allow("AI made no decision; no charter required")
    entry = registry.live(charter_id, now)
    if entry is None:
        return _deny(
            "audit:no_charter",
            f"AI decided under charter {charter_id!r} but no live "
            "decision-rights charter binds (who-may-decide-what)",
        )
    return _allow(
        f"AI decision under live charter {charter_id!r} "
        f"(scope {entry.ai_decision_scope!r})",
        entry.receipt_digest,
    )


# ---------------------------------------------------------------------------
# 6. Oversight capacity & rubber-stamp probe
# ---------------------------------------------------------------------------


def oversight_capacity_ratio(
    reviewers: int,
    ai_decisions_per_day: int,
    override_rate: float,
) -> AuditVerdict:
    """Pins the human-oversight capacity ratio and trips rubber stamps.

    Two checks, either of which fails closed: (a) the reviewer count
    per 1,000 AI decisions/day must meet the floor — under-capacity
    oversight is capacity-denied; (b) an override rate at or below the
    rubber-stamp line means the humans are not supervising, they are
    rubber-stamping (automation-bias lesson).
    """
    if not isinstance(reviewers, int) or isinstance(reviewers, bool) or reviewers < 0:
        raise AuditError("reviewers must be a non-negative int")
    _check_nonneg_number(ai_decisions_per_day, "ai_decisions_per_day")
    _check_ratio(override_rate, "override_rate")
    if ai_decisions_per_day == 0:
        return _allow("no AI decisions; no oversight capacity required")
    per_1k = reviewers / (ai_decisions_per_day / 1000.0)
    if per_1k < OVERSIGHT_CAPACITY_FLOOR_PER_1K:
        return _deny(
            "audit:under_capacity",
            f"oversight capacity {per_1k:.2f} reviewers per 1k AI decisions/day "
            f"is below floor {OVERSIGHT_CAPACITY_FLOOR_PER_1K}",
        )
    if override_rate <= OVERRIDE_RUBBER_STAMP_MAX:
        return _deny(
            "audit:rubber_stamp",
            f"override rate {override_rate:.3f} is at or below the rubber-stamp "
            f"line {OVERRIDE_RUBBER_STAMP_MAX:.3f}: supervision is ceremonial",
        )
    return _allow(
        f"oversight capacity {per_1k:.2f} reviewers/1k decisions/day, "
        f"override rate {override_rate:.3f} shows live supervision"
    )


# ---------------------------------------------------------------------------
# 7. Incident-procedure gate (81% gap lesson)
# ---------------------------------------------------------------------------


#: Closed autonomy vocabulary.
AUTONOMY_LEVELS: tuple[str, ...] = ("assisted", "supervised", "highly_autonomous")


def _check_autonomy(value: Any) -> str:
    if value not in AUTONOMY_LEVELS:
        raise AuditError(
            f"autonomy level must be one of {AUTONOMY_LEVELS}, saw {value!r}"
        )
    return value


@dataclass(frozen=True)
class IncidentProcedureReceipt:
    """Binds an incident-management procedure to an AI deployment."""

    receipt_id: str
    deployment_id: str
    procedure_digest: str
    autonomy_level: str
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    bound_at: int
    prev_digest: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": AUDIT_SCHEMA_VERSION,
            "type": "incident_procedure",
            "receipt_id": self.receipt_id,
            "deployment_id": self.deployment_id,
            "procedure_digest": self.procedure_digest,
            "autonomy_level": self.autonomy_level,
            "authority_id": self.authority_id,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "signature_hex": "00" * 64,
            "bound_at": self.bound_at,
            "prev_digest": self.prev_digest,
        }

    @property
    def receipt_digest(self) -> str:
        return jcs_sha256_hex(self._payload())


@dataclass
class IncidentProcedureRegistry:
    """Hash-chained log of incident-procedure receipts."""

    authorities: AuthorityRegistry
    log: list[IncidentProcedureReceipt] | None = None

    def __post_init__(self) -> None:
        self.log = []

    def issue(
        self,
        receipt_id: str,
        deployment_id: str,
        procedure_digest: str,
        autonomy_level: str,
        authority_id: str,
        signature: bytes,
        bound_at: int,
    ) -> IncidentProcedureReceipt:
        _check_nonempty_str(receipt_id, "receipt_id")
        _check_nonempty_str(deployment_id, "deployment_id")
        _check_hex64(procedure_digest, "procedure_digest")
        _check_autonomy(autonomy_level)
        _check_ts(bound_at, "bound_at")
        pubkey = self.authorities.pubkey(authority_id)
        if pubkey is None:
            raise AuditError(f"unknown authority {authority_id!r}")
        prev = self.log[-1].receipt_digest if self.log else _GENESIS
        receipt = IncidentProcedureReceipt(
            receipt_id=receipt_id,
            deployment_id=deployment_id,
            procedure_digest=procedure_digest,
            autonomy_level=autonomy_level,
            authority_id=authority_id,
            authority_pubkey_hex=pubkey,
            signature_hex=signature.hex(),
            bound_at=bound_at,
            prev_digest=prev,
        )
        signed_body = dict(receipt._payload())
        signed_body["signature_hex"] = "00" * 64
        if not _verify_signature(pubkey, signed_body, receipt.signature_hex):
            raise AuditError("incident-procedure receipt authority signature invalid")
        self.log.append(receipt)
        return receipt

    def find(self, deployment_id: str) -> IncidentProcedureReceipt | None:
        for entry in reversed(self.log):
            if entry.deployment_id == deployment_id:
                return entry
        return None


def incident_procedure_gate(
    registry: IncidentProcedureRegistry,
    deployment_id: str,
    autonomy_level: str,
    now: int,
) -> AuditVerdict:
    """Highly autonomous AI without an incident-management procedure is refused.

    Assisted and supervised deployments may proceed with lighter
    handling; ``highly_autonomous`` without a bound procedure is
    ``audit.no_incident_procedure`` (81% of highly autonomous AI had
    none — this gate is the procedure).
    """
    _check_nonempty_str(deployment_id, "deployment_id")
    _check_autonomy(autonomy_level)
    _check_ts(now, "now")
    try:
        _check_chain(registry.log, "incident_procedure")
    except AuditError as exc:
        return _deny("audit:chain_broken", str(exc))
    if autonomy_level != "highly_autonomous":
        return _allow(
            f"deployment {deployment_id!r} is {autonomy_level}; incident "
            "procedure not mandatory at this autonomy level"
        )
    entry = registry.find(deployment_id)
    if entry is None:
        return _deny(
            "audit:no_incident_procedure",
            f"highly autonomous deployment {deployment_id!r} has no bound "
            "incident-management procedure",
        )
    if entry.bound_at > now:
        return _deny(
            "audit:future_procedure",
            f"incident-procedure receipt for {deployment_id!r} is bound in the future",
        )
    return _allow(
        f"highly autonomous deployment {deployment_id!r} binds procedure "
        f"{entry.receipt_id!r}",
        entry.receipt_digest,
    )


# ---------------------------------------------------------------------------
# 8. Alert-conversion probe (alert-fatigue lesson)
# ---------------------------------------------------------------------------


def alert_conversion_probe(
    channel_id: str,
    alerts_raised: int,
    alerts_converted: int,
) -> AuditVerdict:
    """Audit alerts converting at or below 5% auto-degrade.

    A channel whose alerts almost never convert is noise, not
    assurance: it degrades to NON_AUTHORITATIVE and routes to
    human-confirmed operation until the conversion rate recovers.
    """
    _check_nonempty_str(channel_id, "channel_id")
    for name, value in (("alerts_raised", alerts_raised),
                        ("alerts_converted", alerts_converted)):
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise AuditError(f"{name} must be a non-negative int")
    if alerts_converted > alerts_raised:
        raise AuditError("alerts_converted cannot exceed alerts_raised")
    if alerts_raised == 0:
        return _allow(f"alert channel {channel_id!r} raised nothing; no fatigue signal")
    rate = alerts_converted / alerts_raised
    if rate <= ALERT_CONVERSION_FLOOR:
        return _deny(
            "audit:alert_fatigue",
            f"alert channel {channel_id!r} converts at {rate:.3f} "
            f"(floor {ALERT_CONVERSION_FLOOR:.2f}): degraded to human-confirmed operation",
        )
    return _allow(
        f"alert channel {channel_id!r} converts at {rate:.3f}; assurance signal live"
    )


# ---------------------------------------------------------------------------
# 9. Continuous-ready gate (docs before features)
# ---------------------------------------------------------------------------


def continuous_ready_gate(
    functionality_version: str,
    documentation_version: str,
    docs_updated_for_version: str,
) -> AuditVerdict:
    """Documentation must be current before new functionality ships.

    ``docs_updated_for_version`` is the functionality version the docs
    were last updated for; shipping functionality ahead of the docs
    is ``audit.docs_stale`` — the "continuous ready" posture (always
    audit-ready) fails closed.
    """
    _check_nonempty_str(functionality_version, "functionality_version")
    _check_nonempty_str(documentation_version, "documentation_version")
    _check_nonempty_str(docs_updated_for_version, "docs_updated_for_version")
    if docs_updated_for_version != functionality_version:
        return _deny(
            "audit:docs_stale",
            f"functionality {functionality_version!r} ships ahead of docs "
            f"(docs current for {docs_updated_for_version!r})",
        )
    return _allow(
        f"docs {documentation_version!r} are current for functionality "
        f"{functionality_version!r}"
    )
