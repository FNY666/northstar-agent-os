"""Model lineage receipts (one-hundredth batch).

Absorbs the 2026 AI-creative research thread — the copyright cases that
rewrote training-data governance:

* **Sony Music + UMG v. Suno, second wave (Sept 18, 2026)**: the
  "model laundering" / "fruit of the poisonous tree" theory — Suno v6
  was allegedly trained on the *outputs* of the earlier infringing
  model, so the infringement "doesn't wash clean" through retraining.
  61,000+ recordings at issue.
* **Bartz v. Anthropic ($1.5B, final approval July 20, 2026)**: the
  sharp split — *training itself* was fair use (the authors lost on
  that), but the $1.5B was for *pirated acquisition* of the books
  (~500k works at ~$3,000 each). The lesson: clean training cannot
  cure dirty acquisition; the poison is in how the data was obtained.
* **GEMA v. Suno (Munich, July 31, 2026)**: model memorization counts
  as reproduction under §16 UrhG; the TDM exception doesn't cover it.

Northstar mapping: training-data provenance and model lineage need the
same receipt discipline as tool calls and audit chains. A model version
is a ``LineageReceipt`` binding ``(model_digest |
training_corpus_manifest_digest | acquisition_method)`` to its parent
model, hash-chained into an append-only lineage log. Policy is
fail-closed on three laundering vectors:

1. **Lineage gap** — a claimed ``parent_model_digest`` that resolves to
   no known receipt. An unlinked parent is an unverifiable claim about
   where the weights came from.
2. **Consent-gated corpus without consent receipts** — the training
   pool must carry its consent receipts (the Splice / Landr Fair Trade
   AI pattern: per-source payment, opt-in pools, revenue share). A
   ``consent-gated`` manifest with no resolvable consent receipts is
   an unbacked claim.
3. **Tainted parent (no washing)** — taint propagates transitively and
   cannot be laundered away. A model is tainted if it was adjudicated
   tainted (``tainted=True`` — the court-found case), if its
   acquisition method is ``unknown`` (the Bartz lesson: pirated
   acquisition poisons the whole chain even when the training math is
   clean), or if any ancestor is tainted (the Sony/UMG laundering
   theory: retraining on a tainted model's outputs inherits the taint).

The acquisition vocabulary is closed: ``licensed``, ``public-domain``,
``consent-gated``, ``unknown``. ``unknown`` fail-closes — it is the
receipt-system encoding of "we cannot show how this data was
obtained," and unshowable acquisition is treated as pirated
acquisition.

Honest boundary: this module verifies *claimed* lineage consistency —
digests recompute, links resolve, taint propagates, consent receipts
exist. It cannot detect a *false parentage claim* (weights distilled
from tainted Y while the receipt names clean parent X); catching that
needs weight-level provenance analysis, which is outside this
module's scope. What it does guarantee: *if* the claimed parent is
tainted, the child is tainted — there is no washing step.

``classify_model()`` is the binary tier used by policy: a receipt that
fails verification classifies ``"unverifiable-lineage"``; a passing
one classifies ``"verified-lineage"``. Deliberately no partial tier
(the eighty-seventh batch's lesson).

Deterministic: no wall-clock reads (callers inject ``timestamp`` as an
integer), canonical JSON hashing, and all digest comparisons use
:func:`hmac.compare_digest`.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping


LINEAGE_RECEIPT_SCHEMA_VERSION = "northstar.model-lineage.v1"

#: Closed acquisition vocabulary. ``unknown`` is not a neutral default —
#: it fail-closes (Bartz: unshowable acquisition == pirated acquisition).
ACQUISITION_METHODS: tuple[str, ...] = (
    "licensed",
    "public-domain",
    "consent-gated",
    "unknown",
)

#: Classification tiers (binary, like the 87th batch's evidence tiers).
VERIFIED_LINEAGE = "verified-lineage"
UNVERIFIABLE_LINEAGE = "unverifiable-lineage"

_GENESIS = "genesis"
_HEX64_LENGTH = 64


class LineageReceiptError(ValueError):
    """A malformed lineage receipt or a programming error.

    Raised for structural problems (unknown acquisition method, bad
    digests, missing fields, non-hex digests). Verification *failures*
    (lineage gap, missing consent receipts, tainted ancestry) return a
    :class:`LineageVerdict` with ``allowed=False`` instead — a failed
    lineage is a verdict, a malformed receipt is a bug.
    """


# ---------------------------------------------------------------------------
# Canonical hashing
# ---------------------------------------------------------------------------


def _canonical_bytes(value: Any) -> bytes:
    """Canonical JSON bytes: sorted keys, compact separators, UTF-8.

    Delegates to the shared legacy canonicalizer (``audit_chain``); the
    domain exception is preserved.
    """
    from audit_chain import canonical_json

    try:
        return canonical_json(value)
    except (TypeError, ValueError) as error:
        raise LineageReceiptError("value is not canonical JSON") from error


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
        raise LineageReceiptError(
            f"{field_name} must be a 64-char lowercase hex digest"
        )
    return value


def _check_acquisition(value: Any) -> str:
    if value not in ACQUISITION_METHODS:
        raise LineageReceiptError(
            f"acquisition_method must be one of {ACQUISITION_METHODS}, saw {value!r}"
        )
    return value


# ---------------------------------------------------------------------------
# Receipt construction
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LineageReceipt:
    """One model version's lineage claim.

    ``parent_model_digest`` is the empty string for root models trained
    from scratch (no parent). ``tainted`` is the adjudication flag —
    set when a court, regulator, or internal review found the model (or
    its training data) infringing. ``consent_receipt_ids`` backs a
    ``consent-gated`` corpus; it must be empty for the other methods
    (a licensed corpus doesn't need per-source consent receipts, and a
    non-empty list on a non-consent-gated receipt is malformed —
    receipts must say exactly what they mean).
    """

    model_id: str
    model_digest: str
    parent_model_digest: str  # "" for root models
    corpus_manifest_digest: str
    acquisition_method: str
    consent_receipt_ids: tuple[str, ...] = ()
    tainted: bool = False
    timestamp: int = 0
    prev_digest: str = _GENESIS
    receipt_digest: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.model_id, str) or not self.model_id:
            raise LineageReceiptError("model_id must be a non-empty string")
        _check_hex64(self.model_digest, "model_digest")
        if self.parent_model_digest != "":
            _check_hex64(self.parent_model_digest, "parent_model_digest")
        _check_hex64(self.corpus_manifest_digest, "corpus_manifest_digest")
        _check_acquisition(self.acquisition_method)
        if not isinstance(self.consent_receipt_ids, tuple):
            raise LineageReceiptError("consent_receipt_ids must be a tuple")
        for rid in self.consent_receipt_ids:
            if not isinstance(rid, str) or not rid:
                raise LineageReceiptError("consent receipt ids must be non-empty strings")
        if self.acquisition_method != "consent-gated" and self.consent_receipt_ids:
            raise LineageReceiptError(
                "consent_receipt_ids must be empty unless acquisition_method "
                "is 'consent-gated'"
            )
        if not isinstance(self.tainted, bool):
            raise LineageReceiptError("tainted must be a bool")
        if not isinstance(self.timestamp, int) or self.timestamp < 0:
            raise LineageReceiptError("timestamp must be a non-negative int")
        if self.prev_digest != _GENESIS:
            _check_hex64(self.prev_digest, "prev_digest")
        if self.receipt_digest != "":
            _check_hex64(self.receipt_digest, "receipt_digest")


def compute_receipt_digest(receipt: LineageReceipt) -> str:
    """Recompute the receipt digest over all fields except itself."""
    payload = {
        "schema": LINEAGE_RECEIPT_SCHEMA_VERSION,
        "model_id": receipt.model_id,
        "model_digest": receipt.model_digest,
        "parent_model_digest": receipt.parent_model_digest,
        "corpus_manifest_digest": receipt.corpus_manifest_digest,
        "acquisition_method": receipt.acquisition_method,
        "consent_receipt_ids": list(receipt.consent_receipt_ids),
        "tainted": receipt.tainted,
        "timestamp": receipt.timestamp,
        "prev_digest": receipt.prev_digest,
    }
    return hashlib.sha256(_canonical_bytes(payload)).hexdigest()


def build_receipt(
    *,
    model_id: str,
    model_digest: str,
    parent_model_digest: str = "",
    corpus_manifest_digest: str,
    acquisition_method: str,
    consent_receipt_ids: tuple[str, ...] = (),
    tainted: bool = False,
    timestamp: int,
    prev_digest: str = _GENESIS,
) -> LineageReceipt:
    """Build a receipt and seal it with its digest."""
    bare = LineageReceipt(
        model_id=model_id,
        model_digest=model_digest,
        parent_model_digest=parent_model_digest,
        corpus_manifest_digest=corpus_manifest_digest,
        acquisition_method=acquisition_method,
        consent_receipt_ids=consent_receipt_ids,
        tainted=tainted,
        timestamp=timestamp,
        prev_digest=prev_digest,
    )
    digest = compute_receipt_digest(bare)
    return LineageReceipt(
        model_id=bare.model_id,
        model_digest=bare.model_digest,
        parent_model_digest=bare.parent_model_digest,
        corpus_manifest_digest=bare.corpus_manifest_digest,
        acquisition_method=bare.acquisition_method,
        consent_receipt_ids=bare.consent_receipt_ids,
        tainted=bare.tainted,
        timestamp=bare.timestamp,
        prev_digest=bare.prev_digest,
        receipt_digest=digest,
    )


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


@dataclass
class LineageVerdict:
    """Outcome of verifying one model version's lineage."""

    allowed: bool
    reason: str
    model_id: str = ""
    tainted: bool = False


def _index_by_digest(
    receipts: list[LineageReceipt],
) -> dict[str, LineageReceipt]:
    """Index receipts by model_digest. Duplicate digests are malformed."""
    index: dict[str, LineageReceipt] = {}
    for receipt in receipts:
        if receipt.model_digest in index:
            raise LineageReceiptError(
                f"duplicate model_digest for {receipt.model_id!r}: "
                "two receipts cannot claim the same weights"
            )
        index[receipt.model_digest] = receipt
    return index


def verify_lineage(
    receipts: list[LineageReceipt],
    *,
    consent_lookup: Callable[[str], Mapping[str, Any] | None] | None = None,
) -> dict[str, LineageVerdict]:
    """Verify a lineage log, fail-closed.

    Checks, in order:

    1. **Receipt integrity** — every ``receipt_digest`` recomputes.
    2. **Log chain** — ``prev_digest`` links form one chain starting at
       ``"genesis"`` (receipts must be passed in log order).
    3. **Lineage gap** — every non-root ``parent_model_digest`` must
       resolve to a receipt in this log. An unlinked parent denies.
    4. **Acquisition** — ``unknown`` denies outright (Bartz). Any other
       method must be internally consistent (enforced at construction).
    5. **Consent backing** — a ``consent-gated`` corpus must carry at
       least one consent receipt id, and every id must resolve through
       ``consent_lookup`` (a missing lookup denies — unresolvable
       consent is unbacked consent).
    6. **Taint propagation** — a receipt is tainted if ``tainted`` is
       set, if its acquisition is ``unknown``, or if its parent is
       tainted (transitive; the Sony/UMG no-washing rule). Tainted
       denies.

    Returns a per-``model_id`` verdict dict. Raises
    :class:`LineageReceiptError` only for structural problems (bad
    digests, duplicate weights, broken log chain) — those are bugs in
    the log, not verdicts about a model.
    """
    if not isinstance(receipts, list):
        raise LineageReceiptError("receipts must be a list")
    index = _index_by_digest(receipts)

    # 1+2. Integrity and log chain, in log order.
    expected_prev = _GENESIS
    for receipt in receipts:
        if not hmac.compare_digest(compute_receipt_digest(receipt), receipt.receipt_digest):
            raise LineageReceiptError(
                f"receipt digest mismatch for {receipt.model_id!r}: log tampered"
            )
        if not hmac.compare_digest(receipt.prev_digest, expected_prev):
            raise LineageReceiptError(
                f"log chain broken at {receipt.model_id!r}: "
                f"expected prev {expected_prev[:12]}..., saw {receipt.prev_digest[:12]}..."
            )
        expected_prev = receipt.receipt_digest

    verdicts: dict[str, LineageVerdict] = {}
    tainted_digests: set[str] = set()

    def _deny(model_id: str, reason: str, tainted: bool = False) -> LineageVerdict:
        return LineageVerdict(
            allowed=False, reason=reason, model_id=model_id, tainted=tainted
        )

    for receipt in receipts:
        model_id = receipt.model_id

        # 4. Unknown acquisition fail-closes (Bartz lesson).
        if receipt.acquisition_method == "unknown":
            tainted_digests.add(receipt.model_digest)
            verdicts[model_id] = _deny(
                model_id,
                "acquisition_method is 'unknown': unshowable acquisition is "
                "treated as pirated acquisition (Bartz v. Anthropic)",
                tainted=True,
            )
            continue

        # 3. Lineage gap: claimed parent must resolve.
        parent: LineageReceipt | None = None
        if receipt.parent_model_digest != "":
            parent = index.get(receipt.parent_model_digest)
            if parent is None:
                verdicts[model_id] = _deny(
                    model_id,
                    f"lineage gap: parent_model_digest "
                    f"{receipt.parent_model_digest[:12]}... resolves to no known "
                    "receipt — unverifiable parentage",
                )
                continue

        # 5. Consent-gated corpora must carry resolvable consent receipts.
        if receipt.acquisition_method == "consent-gated":
            if not receipt.consent_receipt_ids:
                verdicts[model_id] = _deny(
                    model_id,
                    "consent-gated corpus carries no consent receipts: "
                    "unbacked consent claim",
                )
                continue
            if consent_lookup is None:
                verdicts[model_id] = _deny(
                    model_id,
                    "consent-gated corpus but no consent_lookup provided: "
                    "consent cannot be resolved",
                )
                continue
            unresolvable = [
                rid for rid in receipt.consent_receipt_ids
                if consent_lookup(rid) is None
            ]
            if unresolvable:
                verdicts[model_id] = _deny(
                    model_id,
                    f"consent receipt(s) unresolvable: {unresolvable[0]!r} — "
                    "unresolvable consent is unbacked consent",
                )
                continue

        # 6. Taint: adjudicated, or inherited (no washing).
        if receipt.tainted:
            tainted_digests.add(receipt.model_digest)
            verdicts[model_id] = _deny(
                model_id,
                "model adjudicated tainted: infringement finding attaches "
                "to this model version",
                tainted=True,
            )
            continue
        if parent is not None and parent.model_digest in tainted_digests:
            tainted_digests.add(receipt.model_digest)
            verdicts[model_id] = _deny(
                model_id,
                f"taint inherited from parent {parent.model_id!r}: retraining "
                "on a tainted model's outputs does not wash the taint "
                "(model-laundering / fruit-of-the-poisonous-tree)",
                tainted=True,
            )
            continue

        verdicts[model_id] = LineageVerdict(
            allowed=True,
            reason="lineage verified: digests recompute, parent resolves, "
            "acquisition shown, consent backed, ancestry clean",
            model_id=model_id,
            tainted=False,
        )

    return verdicts


def classify_model(
    receipt: LineageReceipt,
    registry: list[LineageReceipt],
    *,
    consent_lookup: Callable[[str], Mapping[str, Any] | None] | None = None,
) -> str:
    """Binary policy tier for one model version.

    ``VERIFIED_LINEAGE`` iff the full log verifies and this model's
    verdict allows; otherwise ``UNVERIFIABLE_LINEAGE``. A ``None``
    receipt (model with no lineage claim at all) classifies
    ``UNVERIFIABLE_LINEAGE`` by construction — the 87th batch's
    ``NON_AUTHORITATIVE`` analogue. No partial tier.
    """
    if receipt is None:
        return UNVERIFIABLE_LINEAGE
    try:
        verdicts = verify_lineage(registry, consent_lookup=consent_lookup)
    except LineageReceiptError:
        return UNVERIFIABLE_LINEAGE
    verdict = verdicts.get(receipt.model_id)
    if verdict is None or not verdict.allowed:
        return UNVERIFIABLE_LINEAGE
    return VERIFIED_LINEAGE


__all__ = [
    "ACQUISITION_METHODS",
    "LINEAGE_RECEIPT_SCHEMA_VERSION",
    "UNVERIFIABLE_LINEAGE",
    "VERIFIED_LINEAGE",
    "LineageReceipt",
    "LineageReceiptError",
    "LineageVerdict",
    "build_receipt",
    "classify_model",
    "compute_receipt_digest",
    "verify_lineage",
]
