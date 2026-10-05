"""Pharma manufacturing defense gates (one-hundred-thirty-fifth batch).

Absorbs the 2026 AI-pharma-manufacturing research thread:

* **FDA's first AI warning letter (2026-04)** — AI drafted
  specs/SOPs/batch records were used without quality-unit substantive
  review, violating 21 CFR 211.22(c) + 211.100(a). The FDA position:
  AI may draft, it may never take judgment; the quality unit's
  judgment is non-delegable. This batch mechanizes the warning letter
  as a gate: an AI-drafted GMP document without a human
  quality-unit countersign is ``NON_AUTHORITATIVE``, and using it in
  production is ``pharma.undisclosed_judgment``.
* **EU GMP Annex 22 (draft)** — consultation ran 2025-07~10 (~1300
  comments), final text expected end-2026. Red lines (per regulatory
  consultancy readings of the draft, not the official text): critical
  GMP steps permit only static, deterministic models; dynamic and
  continuous-learning models are excluded; generative AI / LLMs are
  excluded from critical decisions; non-critical uses require a
  qualified person in the loop; audits must record model version +
  data input + decision output. (Verify against EudraLex before any
  legal use.)
* **FDA + EMA (2026-01)** — 10-point "Good AI Practice in drug
  development" guidance; FDA CSA guidance finalized 2026-02-03.
* **Deployed 2026** — Eli Lilly: AI + digital twins scaling GLP-1
  production (CIO: "human-in-the-loop / explainability /
  transparency" — industry-media paraphrase of an executive); AI-HPLC
  QC on commercial peptide lines (65-70% review-time cut, 4-6h early
  deviation prediction — **vendor PR**); Oncotelic PDAOAI AI-GMP
  platform at BIO 2026 (company PR).
* **Rentosertib** — first AI-designed candidate (target + molecule)
  reaching Phase III (IPF; 78 molecules / 1.5 years / $2.6M — company
  executive via media). As of 2026-07 no AI-discovered drug was truly
  marketed.

Northstar mapping: GMP documents carry quality-unit countersign
receipts; AI models carry deployment receipts with a closed
model-class vocabulary; audits carry 4-piece lineage receipts; AI
rewrites of electronic records pass the ALCOA+ attribute gate; model
uses bind their declared context-of-use; drift monitors bind a
tolerance and a revalidation trigger; marketing claims bind trial
evidence.

Fail-closed rules:

1. **Quality-unit countersign** — an AI-drafted GMP document
   (spec/SOP/batch record/protocol/change control) without a live,
   quality-unit countersign is ``NON_AUTHORITATIVE``
   (``pharma.unsigned_draft``). Using such a document in production
   is ``pharma.undisclosed_judgment`` — the 2026-04 warning letter
   mechanized.
2. **Static models only (critical)** — critical GMP steps permit only
   ``static_deterministic`` models. ``dynamic_adaptive`` and
   ``continuous_learning`` classes deny (``pharma.dynamic_model`` —
   the Annex 22 red line); ``generative_llm`` in a critical step
   denies (``pharma.generative_in_critical``).
3. **Generative exclusion** — generative AI/LLM outputs are excluded
   from critical decisions by default; in non-critical steps they
   require a qualified-person-in-the-loop receipt, else
   ``NON_AUTHORITATIVE`` (``pharma.unreviewed_generation``).
4. **Model lineage receipts** — audits bind ``(model_version,
   training_data_digest, input_digest, output_digest)``. A decision
   without the 4-piece bundle is ``pharma.missing_lineage``.
5. **ALCOA+ gate** — an AI rewrite of an electronic record must bind
   all 9 ALCOA+ attributes (attributable, legible, contemporaneous,
   original, accurate, complete, consistent, enduring, available);
   any missing attribute denies with ``pharma.alcoa_violation``.
6. **Context-of-use binding** — a model used outside its declared
   context-of-use auto-degrades to ``NON_AUTHORITATIVE``
   (``pharma.context_violation``); a missing declaration is
   ``pharma.undeclared_context``.
7. **Drift monitoring** — drift beyond tolerance denies with
   ``pharma.revalidation_required``; a model with no drift-monitor
   receipt is ``NON_AUTHORITATIVE``
   (``pharma.drift_unmonitored``).
8. **Marketing-claim evidence** — AI-pharma marketing claims
   (yield/time/cost numbers) must bind trial evidence; vendor claims
   without it are ``pharma.unverified_claim``.

Honest boundary: receipts are *declared evidence*. The gate checks
consistency — digests recompute, signatures verify, classes resolve,
attributes bind — not the pharmacology or the legal validity of the
Annex 22 reading. A forged-but-consistent receipt still needs an
off-chain adjudicator. What the gate guarantees: no AI-drafted GMP
document, no dynamic model, and no AI-rewritten record enters the
manufacturing pipeline without a checkable claim.

Deterministic: no wall-clock reads (callers inject integer epochs),
canonical JSON hashing (``canonical_json``), Ed25519 signatures via
the vendored ``ed25519`` module, and all digest comparisons use
:func:`hmac.compare_digest`.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from typing import Any, Callable, Mapping

import ed25519
from canonical_json import jcs_canonical_json, jcs_sha256_hex


PHARMA_SCHEMA_VERSION = "northstar.pharma.v1"

_GENESIS = "genesis"
_HEX64_LENGTH = 64

#: Policy classification tiers.
CLASS_AUTHORITATIVE = "authoritative"
CLASS_NON_AUTHORITATIVE = "non_authoritative"

#: Denial reason codes. All verdict reasons start with one of these.
DENY_UNDISCLOSED_JUDGMENT = "pharma.undisclosed_judgment"
DENY_UNSIGNED_DRAFT = "pharma.unsigned_draft"
DENY_DYNAMIC_MODEL = "pharma.dynamic_model"
DENY_GENERATIVE_IN_CRITICAL = "pharma.generative_in_critical"
DENY_UNREVIEWED_GENERATION = "pharma.unreviewed_generation"
DENY_MISSING_LINEAGE = "pharma.missing_lineage"
DENY_ALCOA_VIOLATION = "pharma.alcoa_violation"
DENY_CONTEXT_VIOLATION = "pharma.context_violation"
DENY_UNDECLARED_CONTEXT = "pharma.undeclared_context"
DENY_REVALIDATION_REQUIRED = "pharma.revalidation_required"
DENY_DRIFT_UNMONITORED = "pharma.drift_unmonitored"
DENY_UNVERIFIED_CLAIM = "pharma.unverified_claim"

#: Closed GMP document-class vocabulary.
DOC_CLASSES: tuple[str, ...] = (
    "specification",
    "sop",
    "batch_record",
    "protocol",
    "change_control",
)

#: Closed model-class vocabulary (Annex 22 red lines).
MODEL_CLASSES: tuple[str, ...] = (
    "static_deterministic",
    "dynamic_adaptive",
    "continuous_learning",
    "generative_llm",
)

#: Closed step-criticality vocabulary.
CRITICALITY: tuple[str, ...] = (
    "critical",
    "non_critical",
)

#: The 9 ALCOA+ attributes (attributable/legible/contemporaneous/
#: original/accurate + complete/consistent/enduring/available).
ALCOA_ATTRIBUTES: tuple[str, ...] = (
    "attributable",
    "legible",
    "contemporaneous",
    "original",
    "accurate",
    "complete",
    "consistent",
    "enduring",
    "available",
)

#: Quality-unit countersign freshness window (30 days).
_COUNTERSIGN_MAX_AGE_S = 30 * 86_400

#: Drift-monitor freshness window (7 days).
_DRIFT_MAX_AGE_S = 7 * 86_400


class PharmaError(ValueError):
    """A malformed pharma receipt or a programming error.

    Raised for structural problems (bad digests, unknown classes,
    non-binding fields). Verification *failures* (missing countersign,
    dynamic model, ALCOA breach) return a :class:`PharmaVerdict` with
    ``allowed=False`` instead — a failed gate is a verdict, a malformed
    receipt is a bug.
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


def _check_prev_digest(value: Any) -> str:
    if value == _GENESIS:
        return value
    return _check_hex64(value, "prev_digest")


def _check_hex64(value: Any, field_name: str) -> str:
    if not _is_hex(value, _HEX64_LENGTH):
        raise PharmaError(f"{field_name} must be a 64-char lowercase hex digest")
    return value


def _check_nonempty_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise PharmaError(f"{field_name} must be a non-empty string")
    return value


def _check_ts(value: Any, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise PharmaError(f"{field_name} must be a non-negative int epoch")
    return value


def _check_secret(value: Any, field_name: str) -> bytes:
    # The vendored ed25519 module takes a raw 32-byte seed (no keypair()).
    if not isinstance(value, bytes) or len(value) != 32:
        raise PharmaError(f"{field_name} must be a 32-byte seed")
    return value


def _check_doc_class(value: Any) -> str:
    if value not in DOC_CLASSES:
        raise PharmaError(f"doc_class must be one of {DOC_CLASSES}, saw {value!r}")
    return value


def _check_model_class(value: Any) -> str:
    if value not in MODEL_CLASSES:
        raise PharmaError(f"model_class must be one of {MODEL_CLASSES}, saw {value!r}")
    return value


def _check_criticality(value: Any) -> str:
    if value not in CRITICALITY:
        raise PharmaError(f"criticality must be one of {CRITICALITY}, saw {value!r}")
    return value


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


def _seal(receipt: Any, payload: Mapping[str, Any], secret: bytes) -> Any:
    """Sign ``payload`` with ``secret`` and stamp the receipt digest."""
    signature_hex = ed25519.sign(secret, jcs_canonical_json(payload)).hex()
    sealed = type(receipt)(**{**receipt.__dict__, "signature_hex": signature_hex})
    digest = jcs_sha256_hex(sealed._payload())
    return type(receipt)(**{**sealed.__dict__, "receipt_digest": digest})


def _check_chain(log: list[Any], type_name: str) -> None:
    """Raise :class:`PharmaError` if a receipt log is tampered/broken."""
    expected_prev = _GENESIS
    for entry in log:
        if not hmac.compare_digest(entry.receipt_digest, jcs_sha256_hex(entry._payload())):
            raise PharmaError(
                f"{type_name} receipt {entry.receipt_id!r} digest does not recompute"
            )
        if not hmac.compare_digest(entry.prev_digest, expected_prev):
            raise PharmaError(
                f"{type_name} receipt {entry.receipt_id!r} chain break: "
                f"expected prev {expected_prev!r}"
            )
        if not _verify_signature(
            entry.authority_pubkey_hex, entry._payload(), entry.signature_hex
        ):
            raise PharmaError(
                f"{type_name} receipt {entry.receipt_id!r} authority signature invalid"
            )
        expected_prev = entry.receipt_digest


@dataclass(frozen=True)
class PharmaVerdict:
    """Outcome of one pharma-manufacturing check."""

    allowed: bool
    reason: str
    classification: str = CLASS_NON_AUTHORITATIVE
    receipt_digest: str = ""


def _deny(code: str, detail: str) -> PharmaVerdict:
    return PharmaVerdict(
        allowed=False,
        reason=f"{code}: {detail}",
        classification=CLASS_NON_AUTHORITATIVE,
    )


def _allow(detail: str, receipt_digest: str = "") -> PharmaVerdict:
    return PharmaVerdict(
        allowed=True,
        reason=detail,
        classification=CLASS_AUTHORITATIVE,
        receipt_digest=receipt_digest,
    )


def _now_ok(signed_at: int, now: int, max_age: int) -> bool:
    return 0 <= signed_at <= now and (now - signed_at) <= max_age


# ---------------------------------------------------------------------------
# Quality-unit countersign (the 2026-04 FDA warning letter, mechanized)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class GmpDocumentLog:
    """Hash-chained log of GMP document quality-unit countersigns."""

    authority_pubkey_hex: str = ""


@dataclass(frozen=True)
class GmpDocumentReceipt:
    """An AI-drafted GMP document with its quality-unit countersign.

    ``drafted_by_ai`` marks AI authorship (AI may draft; it may never
    take judgment). ``countersignature_hex`` is the quality unit's
    Ed25519 signature over the document payload; ``counter_public_hex``
    is the quality unit's public key; ``counter_at`` is the signature
    epoch (freshness-bound to 30 days).
    """

    receipt_id: str = ""
    prev_digest: str = _GENESIS
    doc_class: str = ""
    doc_digest: str = ""
    drafted_by_ai: bool = False
    counter_public_hex: str = ""
    counter_at: int = 0
    countersignature_hex: str = ""
    authority_pubkey_hex: str = ""
    signature_hex: str = ""
    receipt_digest: str = ""

    def _payload(self) -> Mapping[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "prev_digest": self.prev_digest,
            "doc_class": self.doc_class,
            "doc_digest": self.doc_digest,
            "drafted_by_ai": self.drafted_by_ai,
            "counter_public_hex": self.counter_public_hex,
            "counter_at": self.counter_at,
            "countersignature_hex": self.countersignature_hex,
            "authority_pubkey_hex": self.authority_pubkey_hex,
        }


def gmp_document_receipt(
    *,
    receipt_id: str,
    prev_digest: str,
    doc_class: str,
    doc_digest: str,
    drafted_by_ai: bool,
    counter_public_hex: str,
    counter_at: int,
    counter_secret: bytes | None,
    authority_pubkey_hex: str,
    authority_secret: bytes,
) -> GmpDocumentReceipt:
    """Seal a GMP document countersign receipt.

    ``counter_secret`` is the quality unit's 32-byte seed; when
    ``drafted_by_ai`` is False the countersign may be omitted (pass
    ``None``) since a human-authored document needs no AI judgment
    to countersign.
    """
    _check_nonempty_str(receipt_id, "receipt_id")
    _check_prev_digest(prev_digest)
    _check_doc_class(doc_class)
    _check_hex64(doc_digest, "doc_digest")
    _check_hex64(counter_public_hex, "counter_public_hex")
    _check_ts(counter_at, "counter_at")
    _check_hex64(authority_pubkey_hex, "authority_pubkey_hex")
    _check_secret(authority_secret, "authority_secret")
    if not isinstance(drafted_by_ai, bool):
        raise PharmaError("drafted_by_ai must be a bool")
    countersignature_hex = ""
    if counter_secret is not None:
        _check_secret(counter_secret, "counter_secret")
        countersignature_hex = ed25519.sign(
            counter_secret,
            jcs_canonical_json(
                {
                    "doc_class": doc_class,
                    "doc_digest": doc_digest,
                    "counter_public_hex": counter_public_hex,
                    "counter_at": counter_at,
                }
            ),
        ).hex()
    return _seal(
        GmpDocumentReceipt(
            receipt_id=receipt_id,
            prev_digest=prev_digest,
            doc_class=doc_class,
            doc_digest=doc_digest,
            drafted_by_ai=drafted_by_ai,
            counter_public_hex=counter_public_hex,
            counter_at=counter_at,
            countersignature_hex=countersignature_hex,
            authority_pubkey_hex=authority_pubkey_hex,
            signature_hex="",
            receipt_digest="",
        ),
        {
            "receipt_id": receipt_id,
            "prev_digest": prev_digest,
            "doc_class": doc_class,
            "doc_digest": doc_digest,
            "drafted_by_ai": drafted_by_ai,
            "counter_public_hex": counter_public_hex,
            "counter_at": counter_at,
            "countersignature_hex": countersignature_hex,
            "authority_pubkey_hex": authority_pubkey_hex,
        },
        authority_secret,
    )


def quality_unit_countersign(
    receipt: GmpDocumentReceipt, countersignature_hex: str, *, now: int
) -> PharmaVerdict:
    """Check the quality-unit countersign on a GMP document.

    A human-authored document passes without a countersign. An
    AI-drafted document without a live, verifiable quality-unit
    countersign is ``NON_AUTHORITATIVE`` (``pharma.unsigned_draft``):
    AI may draft, it may never take judgment.
    """
    _check_ts(now, "now")
    if not receipt.drafted_by_ai:
        return _allow("human-authored GMP document needs no AI-judgment gate", receipt.receipt_digest)
    if not countersignature_hex:
        return _deny(DENY_UNSIGNED_DRAFT, "AI-drafted GMP document has no quality-unit countersign")
    payload = {
        "doc_class": receipt.doc_class,
        "doc_digest": receipt.doc_digest,
        "counter_public_hex": receipt.counter_public_hex,
        "counter_at": receipt.counter_at,
    }
    if not _verify_signature(receipt.counter_public_hex, payload, countersignature_hex):
        return _deny(DENY_UNSIGNED_DRAFT, "quality-unit countersignature does not verify")
    if not _now_ok(receipt.counter_at, now, _COUNTERSIGN_MAX_AGE_S):
        return _deny(DENY_UNSIGNED_DRAFT, "quality-unit countersign is stale or from the future")
    return _allow("AI-drafted GMP document carries a live quality-unit countersign", receipt.receipt_digest)


def use_in_production(
    receipt: GmpDocumentReceipt, countersignature_hex: str, *, now: int
) -> PharmaVerdict:
    """Gate the production use of a GMP document.

    Using an AI-drafted document without a countersign in production
    is ``pharma.undisclosed_judgment`` — the 2026-04 warning letter
    mechanized (21 CFR 211.22(c) + 211.100(a)).
    """
    verdict = quality_unit_countersign(receipt, countersignature_hex, now=now)
    if receipt.drafted_by_ai and not verdict.allowed:
        return _deny(DENY_UNDISCLOSED_JUDGMENT, f"AI judgment used in production without quality-unit review: {verdict.reason}")
    return verdict


# ---------------------------------------------------------------------------
# Static models only (Annex 22 red line) + generative exclusion
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ModelDeploymentReceipt:
    """An AI model's deployment claim for a GMP step.

    ``model_class`` is drawn from the closed vocabulary; ``locked``
    marks a locked (static) model build whose digest is pinned.
    ``criticality`` marks whether the GMP step is critical.
    """

    receipt_id: str = ""
    prev_digest: str = _GENESIS
    model_id: str = ""
    model_class: str = ""
    model_version: str = ""
    model_digest: str = ""
    locked: bool = False
    criticality: str = ""
    authority_pubkey_hex: str = ""
    signature_hex: str = ""
    receipt_digest: str = ""

    def _payload(self) -> Mapping[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "prev_digest": self.prev_digest,
            "model_id": self.model_id,
            "model_class": self.model_class,
            "model_version": self.model_version,
            "model_digest": self.model_digest,
            "locked": self.locked,
            "criticality": self.criticality,
            "authority_pubkey_hex": self.authority_pubkey_hex,
        }


def model_deployment_receipt(
    *,
    receipt_id: str,
    prev_digest: str,
    model_id: str,
    model_class: str,
    model_version: str,
    model_digest: str,
    locked: bool,
    criticality: str,
    authority_pubkey_hex: str,
    authority_secret: bytes,
) -> ModelDeploymentReceipt:
    _check_nonempty_str(receipt_id, "receipt_id")
    _check_prev_digest(prev_digest)
    _check_nonempty_str(model_id, "model_id")
    _check_model_class(model_class)
    _check_nonempty_str(model_version, "model_version")
    _check_hex64(model_digest, "model_digest")
    _check_criticality(criticality)
    _check_hex64(authority_pubkey_hex, "authority_pubkey_hex")
    _check_secret(authority_secret, "authority_secret")
    if not isinstance(locked, bool):
        raise PharmaError("locked must be a bool")
    return _seal(
        ModelDeploymentReceipt(
            receipt_id=receipt_id,
            prev_digest=prev_digest,
            model_id=model_id,
            model_class=model_class,
            model_version=model_version,
            model_digest=model_digest,
            locked=locked,
            criticality=criticality,
            authority_pubkey_hex=authority_pubkey_hex,
            signature_hex="",
            receipt_digest="",
        ),
        {
            "receipt_id": receipt_id,
            "prev_digest": prev_digest,
            "model_id": model_id,
            "model_class": model_class,
            "model_version": model_version,
            "model_digest": model_digest,
            "locked": locked,
            "criticality": criticality,
            "authority_pubkey_hex": authority_pubkey_hex,
        },
        authority_secret,
    )


def static_model_only(receipt: ModelDeploymentReceipt) -> PharmaVerdict:
    """Enforce the Annex 22 red line on a GMP step's AI model.

    Critical steps permit only ``static_deterministic`` models.
    ``dynamic_adaptive`` / ``continuous_learning`` deny with
    ``pharma.dynamic_model``; ``generative_llm`` in a critical step
    denies with ``pharma.generative_in_critical``. Non-critical steps
    admit any class but a generative model still needs the qualified-
    person gate (see :func:`generative_exclusion_gate`).
    """
    if receipt.criticality == "critical":
        if receipt.model_class in ("dynamic_adaptive", "continuous_learning"):
            return _deny(
                DENY_DYNAMIC_MODEL,
                f"critical GMP step permits only static models; saw {receipt.model_class}",
            )
        if receipt.model_class == "generative_llm":
            return _deny(
                DENY_GENERATIVE_IN_CRITICAL,
                "generative AI/LLM excluded from critical GMP decisions",
            )
        if receipt.model_class == "static_deterministic" and not receipt.locked:
            return _deny(
                DENY_DYNAMIC_MODEL,
                "static-class model must be a locked build for critical steps",
            )
    return _allow(
        f"model {receipt.model_id} ({receipt.model_class}) admitted for {receipt.criticality} step",
        receipt.receipt_digest,
    )


def generative_exclusion_gate(
    receipt: ModelDeploymentReceipt,
    qualified_person_in_loop: bool,
) -> PharmaVerdict:
    """Gate generative-AI/LLM outputs in GMP decisions.

    Generative outputs are excluded from critical decisions by
    default. In non-critical steps they require a qualified-person-
    in-the-loop receipt; otherwise ``NON_AUTHORITATIVE``
    (``pharma.unreviewed_generation``). Non-generative classes pass
    through.
    """
    if receipt.model_class != "generative_llm":
        return _allow("non-generative model class", receipt.receipt_digest)
    if receipt.criticality == "critical":
        return _deny(
            DENY_GENERATIVE_IN_CRITICAL,
            "generative AI/LLM excluded from critical GMP decisions",
        )
    if not qualified_person_in_loop:
        return _deny(
            DENY_UNREVIEWED_GENERATION,
            "generative output in non-critical step needs a qualified person in the loop",
        )
    return _allow(
        "generative output carries a qualified-person-in-the-loop receipt",
        receipt.receipt_digest,
    )


# ---------------------------------------------------------------------------
# Model lineage receipts (the 4-piece audit bundle)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ModelLineageReceipt:
    """An audit's 4-piece model lineage claim."""

    receipt_id: str = ""
    prev_digest: str = _GENESIS
    model_version: str = ""
    training_data_digest: str = ""
    input_digest: str = ""
    output_digest: str = ""
    authority_pubkey_hex: str = ""
    signature_hex: str = ""
    receipt_digest: str = ""

    def _payload(self) -> Mapping[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "prev_digest": self.prev_digest,
            "model_version": self.model_version,
            "training_data_digest": self.training_data_digest,
            "input_digest": self.input_digest,
            "output_digest": self.output_digest,
            "authority_pubkey_hex": self.authority_pubkey_hex,
        }


def model_lineage_receipt(
    *,
    receipt_id: str,
    prev_digest: str,
    model_version: str,
    training_data_digest: str,
    input_digest: str,
    output_digest: str,
    authority_pubkey_hex: str,
    authority_secret: bytes,
) -> ModelLineageReceipt:
    _check_nonempty_str(receipt_id, "receipt_id")
    _check_prev_digest(prev_digest)
    _check_nonempty_str(model_version, "model_version")
    _check_hex64(training_data_digest, "training_data_digest")
    _check_hex64(input_digest, "input_digest")
    _check_hex64(output_digest, "output_digest")
    _check_hex64(authority_pubkey_hex, "authority_pubkey_hex")
    _check_secret(authority_secret, "authority_secret")
    return _seal(
        ModelLineageReceipt(
            receipt_id=receipt_id,
            prev_digest=prev_digest,
            model_version=model_version,
            training_data_digest=training_data_digest,
            input_digest=input_digest,
            output_digest=output_digest,
            authority_pubkey_hex=authority_pubkey_hex,
            signature_hex="",
            receipt_digest="",
        ),
        {
            "receipt_id": receipt_id,
            "prev_digest": prev_digest,
            "model_version": model_version,
            "training_data_digest": training_data_digest,
            "input_digest": input_digest,
            "output_digest": output_digest,
            "authority_pubkey_hex": authority_pubkey_hex,
        },
        authority_secret,
    )


def check_model_lineage(
    lineage: ModelLineageReceipt | None, *, model_version: str
) -> PharmaVerdict:
    """Check the 4-piece audit bundle for a model's decision.

    Missing bundle or a version mismatch is
    ``pharma.missing_lineage``: audits must record model version +
    training data + data input + decision output.
    """
    if lineage is None:
        return _deny(DENY_MISSING_LINEAGE, "no model lineage receipt bound to this decision")
    if not hmac.compare_digest(lineage.model_version.encode(), model_version.encode()):
        return _deny(
            DENY_MISSING_LINEAGE,
            f"lineage pins {lineage.model_version!r}, model runs {model_version!r}",
        )
    if not _verify_signature(
        lineage.authority_pubkey_hex, lineage._payload(), lineage.signature_hex
    ):
        return _deny(DENY_MISSING_LINEAGE, "model lineage receipt signature invalid")
    return _allow("4-piece model lineage receipt binds this decision", lineage.receipt_digest)


# ---------------------------------------------------------------------------
# ALCOA+ gate for AI rewrites of electronic records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AlcoaProbeVerdict:
    """Attribute-level outcome of one ALCOA+ probe."""

    passed: bool
    missing_attributes: tuple[str, ...]
    reason: str


def alcoa_probe(
    bound_attributes: Mapping[str, bool] | None,
) -> AlcoaProbeVerdict:
    """Probe an AI rewrite of an electronic record against ALCOA+.

    ``bound_attributes`` maps each of the 9 ALCOA+ attributes to
    whether the rewrite binds evidence for it. Any missing attribute
    fails the probe (``pharma.alcoa_violation`` lists the missing
    ones); a ``None`` map is the same as all-missing.
    """
    attrs = bound_attributes or {}
    missing = tuple(a for a in ALCOA_ATTRIBUTES if not attrs.get(a, False))
    if missing:
        return AlcoaProbeVerdict(
            passed=False,
            missing_attributes=missing,
            reason=f"{DENY_ALCOA_VIOLATION}: AI rewrite missing ALCOA+ attributes: {', '.join(missing)}",
        )
    return AlcoaProbeVerdict(passed=True, missing_attributes=(), reason="all 9 ALCOA+ attributes bound")


# ---------------------------------------------------------------------------
# Context-of-use binding
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ContextOfUseReceipt:
    """A model's declared context-of-use claim."""

    receipt_id: str = ""
    prev_digest: str = _GENESIS
    model_id: str = ""
    context_digest: str = ""
    authority_pubkey_hex: str = ""
    signature_hex: str = ""
    receipt_digest: str = ""

    def _payload(self) -> Mapping[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "prev_digest": self.prev_digest,
            "model_id": self.model_id,
            "context_digest": self.context_digest,
            "authority_pubkey_hex": self.authority_pubkey_hex,
        }


def context_of_use_receipt(
    *,
    receipt_id: str,
    prev_digest: str,
    model_id: str,
    context_digest: str,
    authority_pubkey_hex: str,
    authority_secret: bytes,
) -> ContextOfUseReceipt:
    _check_nonempty_str(receipt_id, "receipt_id")
    _check_prev_digest(prev_digest)
    _check_nonempty_str(model_id, "model_id")
    _check_hex64(context_digest, "context_digest")
    _check_hex64(authority_pubkey_hex, "authority_pubkey_hex")
    _check_secret(authority_secret, "authority_secret")
    return _seal(
        ContextOfUseReceipt(
            receipt_id=receipt_id,
            prev_digest=prev_digest,
            model_id=model_id,
            context_digest=context_digest,
            authority_pubkey_hex=authority_pubkey_hex,
            signature_hex="",
            receipt_digest="",
        ),
        {
            "receipt_id": receipt_id,
            "prev_digest": prev_digest,
            "model_id": model_id,
            "context_digest": context_digest,
            "authority_pubkey_hex": authority_pubkey_hex,
        },
        authority_secret,
    )


def context_of_use_binding(
    receipt: ContextOfUseReceipt | None, *, actual_context_digest: str
) -> PharmaVerdict:
    """Check a model use against its declared context-of-use.

    No declaration is ``pharma.undeclared_context``; a mismatch
    auto-degrades to ``NON_AUTHORITATIVE``
    (``pharma.context_violation``).
    """
    _check_hex64(actual_context_digest, "actual_context_digest")
    if receipt is None:
        return _deny(DENY_UNDECLARED_CONTEXT, "model has no declared context-of-use")
    if not _verify_signature(
        receipt.authority_pubkey_hex, receipt._payload(), receipt.signature_hex
    ):
        return _deny(DENY_UNDECLARED_CONTEXT, "context-of-use receipt signature invalid")
    if not hmac.compare_digest(receipt.context_digest, actual_context_digest):
        return _deny(
            DENY_CONTEXT_VIOLATION,
            "model used outside its declared context-of-use; downgraded",
        )
    return _allow("model use matches its declared context-of-use", receipt.receipt_digest)


# ---------------------------------------------------------------------------
# Drift monitoring
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DriftMonitorReceipt:
    """A drift monitor's tolerance claim for a deployed model."""

    receipt_id: str = ""
    prev_digest: str = _GENESIS
    model_id: str = ""
    drift_metric: float = 0.0
    tolerance: float = 0.0
    checked_at: int = 0
    authority_pubkey_hex: str = ""
    signature_hex: str = ""
    receipt_digest: str = ""

    def _payload(self) -> Mapping[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "prev_digest": self.prev_digest,
            "model_id": self.model_id,
            "drift_metric": self.drift_metric,
            "tolerance": self.tolerance,
            "checked_at": self.checked_at,
            "authority_pubkey_hex": self.authority_pubkey_hex,
        }


def drift_monitor_receipt(
    *,
    receipt_id: str,
    prev_digest: str,
    model_id: str,
    drift_metric: float,
    tolerance: float,
    checked_at: int,
    authority_pubkey_hex: str,
    authority_secret: bytes,
) -> DriftMonitorReceipt:
    _check_nonempty_str(receipt_id, "receipt_id")
    _check_prev_digest(prev_digest)
    _check_nonempty_str(model_id, "model_id")
    if not isinstance(drift_metric, (int, float)) or isinstance(drift_metric, bool) or drift_metric < 0:
        raise PharmaError("drift_metric must be a non-negative number")
    if not isinstance(tolerance, (int, float)) or isinstance(tolerance, bool) or tolerance <= 0:
        raise PharmaError("tolerance must be a positive number")
    _check_ts(checked_at, "checked_at")
    _check_hex64(authority_pubkey_hex, "authority_pubkey_hex")
    _check_secret(authority_secret, "authority_secret")
    return _seal(
        DriftMonitorReceipt(
            receipt_id=receipt_id,
            prev_digest=prev_digest,
            model_id=model_id,
            drift_metric=float(drift_metric),
            tolerance=float(tolerance),
            checked_at=checked_at,
            authority_pubkey_hex=authority_pubkey_hex,
            signature_hex="",
            receipt_digest="",
        ),
        {
            "receipt_id": receipt_id,
            "prev_digest": prev_digest,
            "model_id": model_id,
            "drift_metric": float(drift_metric),
            "tolerance": float(tolerance),
            "checked_at": checked_at,
            "authority_pubkey_hex": authority_pubkey_hex,
        },
        authority_secret,
    )


def drift_monitor_gate(
    monitor: DriftMonitorReceipt | None, *, now: int
) -> PharmaVerdict:
    """Gate a deployed model on its drift monitor.

    Drift beyond tolerance denies with
    ``pharma.revalidation_required`` (the model must be revalidated
    before further GMP use). No monitor receipt is
    ``NON_AUTHORITATIVE`` (``pharma.drift_unmonitored``); a stale or
    unsigned monitor is treated as no monitor.
    """
    _check_ts(now, "now")
    if monitor is None:
        return _deny(DENY_DRIFT_UNMONITORED, "deployed model has no drift-monitor receipt")
    if not _verify_signature(
        monitor.authority_pubkey_hex, monitor._payload(), monitor.signature_hex
    ):
        return _deny(DENY_DRIFT_UNMONITORED, "drift-monitor receipt signature invalid")
    if not _now_ok(monitor.checked_at, now, _DRIFT_MAX_AGE_S):
        return _deny(DENY_DRIFT_UNMONITORED, "drift-monitor reading is stale")
    if monitor.drift_metric > monitor.tolerance:
        return _deny(
            DENY_REVALIDATION_REQUIRED,
            f"drift {monitor.drift_metric} exceeds tolerance {monitor.tolerance}: revalidation required",
        )
    return _allow("drift within tolerance", monitor.receipt_digest)


# ---------------------------------------------------------------------------
# Marketing-claim evidence
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PharmaClaimReceipt:
    """An AI-pharma marketing claim with bound trial evidence."""

    receipt_id: str = ""
    prev_digest: str = _GENESIS
    claim_digest: str = ""
    evidence_digest: str = ""
    authority_pubkey_hex: str = ""
    signature_hex: str = ""
    receipt_digest: str = ""

    def _payload(self) -> Mapping[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "prev_digest": self.prev_digest,
            "claim_digest": self.claim_digest,
            "evidence_digest": self.evidence_digest,
            "authority_pubkey_hex": self.authority_pubkey_hex,
        }


def pharma_claim_receipt(
    *,
    receipt_id: str,
    prev_digest: str,
    claim_digest: str,
    evidence_digest: str,
    authority_pubkey_hex: str,
    authority_secret: bytes,
) -> PharmaClaimReceipt:
    _check_nonempty_str(receipt_id, "receipt_id")
    _check_prev_digest(prev_digest)
    _check_hex64(claim_digest, "claim_digest")
    _check_hex64(evidence_digest, "evidence_digest")
    _check_hex64(authority_pubkey_hex, "authority_pubkey_hex")
    _check_secret(authority_secret, "authority_secret")
    return _seal(
        PharmaClaimReceipt(
            receipt_id=receipt_id,
            prev_digest=prev_digest,
            claim_digest=claim_digest,
            evidence_digest=evidence_digest,
            authority_pubkey_hex=authority_pubkey_hex,
            signature_hex="",
            receipt_digest="",
        ),
        {
            "receipt_id": receipt_id,
            "prev_digest": prev_digest,
            "claim_digest": claim_digest,
            "evidence_digest": evidence_digest,
            "authority_pubkey_hex": authority_pubkey_hex,
        },
        authority_secret,
    )


def pharma_claim_evidence(
    claim: PharmaClaimReceipt | None, *, claimed_numbers_digest: str
) -> PharmaVerdict:
    """Check an AI-pharma marketing claim against trial evidence.

    Vendor claims (yield/time/cost numbers) without bound trial
    evidence are ``pharma.unverified_claim``; a claim whose numbers
    do not match the bound evidence digest denies as well.
    """
    _check_hex64(claimed_numbers_digest, "claimed_numbers_digest")
    if claim is None:
        return _deny(DENY_UNVERIFIED_CLAIM, "marketing claim carries no bound trial evidence")
    if not _verify_signature(
        claim.authority_pubkey_hex, claim._payload(), claim.signature_hex
    ):
        return _deny(DENY_UNVERIFIED_CLAIM, "claim receipt signature invalid")
    if not hmac.compare_digest(claim.claim_digest, claimed_numbers_digest):
        return _deny(DENY_UNVERIFIED_CLAIM, "claimed numbers do not match the bound evidence")
    return _allow("marketing claim binds trial evidence", claim.receipt_digest)


# ---------------------------------------------------------------------------
# Chain log helpers (per-receipt-type hash chains)
# ---------------------------------------------------------------------------


class GmpDocumentChainLog:
    """Hash-chained log of GMP document countersign receipts."""

    def __init__(self, authority_pubkey_hex: str):
        _check_hex64(authority_pubkey_hex, "authority_pubkey_hex")
        self.authority_pubkey_hex = authority_pubkey_hex
        self._entries: list[GmpDocumentReceipt] = []

    def append(self, receipt: GmpDocumentReceipt) -> None:
        self._entries.append(receipt)
        _check_chain(self._entries, "gmp_document")

    def __len__(self) -> int:
        return len(self._entries)

    def head_digest(self) -> str:
        return self._entries[-1].receipt_digest if self._entries else _GENESIS


class ModelDeploymentChainLog:
    """Hash-chained log of model deployment receipts."""

    def __init__(self, authority_pubkey_hex: str):
        _check_hex64(authority_pubkey_hex, "authority_pubkey_hex")
        self.authority_pubkey_hex = authority_pubkey_hex
        self._entries: list[ModelDeploymentReceipt] = []

    def append(self, receipt: ModelDeploymentReceipt) -> None:
        self._entries.append(receipt)
        _check_chain(self._entries, "model_deployment")

    def __len__(self) -> int:
        return len(self._entries)

    def head_digest(self) -> str:
        return self._entries[-1].receipt_digest if self._entries else _GENESIS


class ModelLineageChainLog:
    """Hash-chained log of model lineage receipts."""

    def __init__(self, authority_pubkey_hex: str):
        _check_hex64(authority_pubkey_hex, "authority_pubkey_hex")
        self.authority_pubkey_hex = authority_pubkey_hex
        self._entries: list[ModelLineageReceipt] = []

    def append(self, receipt: ModelLineageReceipt) -> None:
        self._entries.append(receipt)
        _check_chain(self._entries, "model_lineage")

    def __len__(self) -> int:
        return len(self._entries)

    def head_digest(self) -> str:
        return self._entries[-1].receipt_digest if self._entries else _GENESIS


class DriftMonitorChainLog:
    """Hash-chained log of drift monitor receipts."""

    def __init__(self, authority_pubkey_hex: str):
        _check_hex64(authority_pubkey_hex, "authority_pubkey_hex")
        self.authority_pubkey_hex = authority_pubkey_hex
        self._entries: list[DriftMonitorReceipt] = []

    def append(self, receipt: DriftMonitorReceipt) -> None:
        self._entries.append(receipt)
        _check_chain(self._entries, "drift_monitor")

    def __len__(self) -> int:
        return len(self._entries)

    def head_digest(self) -> str:
        return self._entries[-1].receipt_digest if self._entries else _GENESIS


class PharmaClaimChainLog:
    """Hash-chained log of marketing-claim receipts."""

    def __init__(self, authority_pubkey_hex: str):
        _check_hex64(authority_pubkey_hex, "authority_pubkey_hex")
        self.authority_pubkey_hex = authority_pubkey_hex
        self._entries: list[PharmaClaimReceipt] = []

    def append(self, receipt: PharmaClaimReceipt) -> None:
        self._entries.append(receipt)
        _check_chain(self._entries, "pharma_claim")

    def __len__(self) -> int:
        return len(self._entries)

    def head_digest(self) -> str:
        return self._entries[-1].receipt_digest if self._entries else _GENESIS


# ---------------------------------------------------------------------------
# Convenience: full production gate over a GMP decision
# ---------------------------------------------------------------------------


def full_production_gate(
    *,
    doc_receipt: GmpDocumentReceipt,
    countersignature_hex: str,
    model_receipt: ModelDeploymentReceipt,
    lineage: ModelLineageReceipt | None,
    alcoa_attributes: Mapping[str, bool] | None,
    context_receipt: ContextOfUseReceipt | None,
    actual_context_digest: str,
    drift: DriftMonitorReceipt | None,
    claim: PharmaClaimReceipt | None,
    claimed_numbers_digest: str,
    generative_qualified_person: bool,
    now: int,
) -> Mapping[str, PharmaVerdict | AlcoaProbeVerdict]:
    """Run every pharma-manufacturing gate over one GMP decision.

    Returns per-gate verdicts; callers decide their own
    all-pass policy (fail-closed: any ``allowed=False`` denies).
    """
    return {
        "production_use": use_in_production(
            doc_receipt, countersignature_hex, now=now
        ),
        "static_model": static_model_only(model_receipt),
        "generative_exclusion": generative_exclusion_gate(
            model_receipt, generative_qualified_person
        ),
        "lineage": check_model_lineage(lineage, model_version=model_receipt.model_version),
        "alcoa": alcoa_probe(alcoa_attributes),
        "context": context_of_use_binding(
            context_receipt, actual_context_digest=actual_context_digest
        ),
        "drift": drift_monitor_gate(drift, now=now),
        "claim_evidence": pharma_claim_evidence(
            claim, claimed_numbers_digest=claimed_numbers_digest
        ),
    }
