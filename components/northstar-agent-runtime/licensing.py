"""Licensed training receipts (one-hundred-twentieth batch).

Absorbs the 2026 AI-music/copyright research thread — the "litigate
then license" wave that rewrote training-data governance:

* **Suno v6 (Sept 9, 2026)**: the first industry-co-built models;
  deals with Warner (Nov 2025 settlement), BMG (Aug 12, 2026),
  Believe/TuneCore (Sept 8). Old models retired.
* **Udio**: UMG (Oct 2025, walled-garden opt-in platform), WMG,
  **Merlin** (Jan 2026 — opt-in framework for 30,000 indie labels),
  Kobalt.
* **Klay**: first AI company licensed by all three majors (Nov 2025).
* **NMPA precedent (June 10, 2026)**: 50/50 split between publishing
  and masters — compositions valued equally to recordings for the
  first time. Split *terms* are bound evidence here, not a fixed rule.
* **Sony + UMG second lawsuit v. Suno (Sept 18, 2026)**: 60,202
  recordings, up to $9B, and the "model laundering" /
  "fruit of the poisonous tree" theory — training v6 on the old
  model's outputs/distillations does not cut liability. (Allegation
  as of this writing; the mechanism below treats it as a *claim to
  be proven upstream* — the gate checks lineage consistency, not the
  legal conclusion.)
* **GEMA v. Suno (Munich, July 2026)** and **SOCAN (Canada, Sept
  2026)**: collection-society enforcement beyond the US majors.
* **JASRAC (June 11, 2026)**: the human-creative-contribution line —
  AI-only works are not managed, AI parts must be labeled "AI" in
  J-WID, and filers carry a guarantee obligation.
* **PLAVE (Korea)**: NOT AI — real performers in mocap suits;
  mislabeling forced a public apology. Disclosure tiers matter:
  "AI performer" is not one thing.

Northstar mapping: the one-hundredth batch (``model_lineage``) made
taint transitive for *models*. This batch does the same for *the
licensing layer around models*: training corpora must carry
per-licensor opt-in evidence; split terms must be pinned; lineage
derivation sources must resolve clean (the laundering gate);
works must declare their human-contribution line; synthetic
performers must declare an honest disclosure tier; likenesses need a
holder-signed grant; and production takes carry take-level receipts
(model version / prompt / assets / rights review).

Fail-closed rules:

1. **Licensed training** — a training corpus with no
   ``LicensedTrainingReceipt`` cannot authorize downstream training
   or deployment (``licensing.unlicensed_corpus``). Every licensor
   named on the receipt must resolve an opt-in proof through the
   caller-supplied lookup (the Merlin opt-in framework as template);
   one unresolvable licensor denies the whole corpus.
2. **Taint transitivity (no laundering)** — a model whose training
   lineage derives from another model's outputs/distillations must
   resolve each derivation source in a model-lineage log; an
   unresolvable source is a lineage gap, a tainted source taints the
   child (``licensing.laundered_model``). Retraining does not wash.
3. **Split terms** — shares are basis points summing to exactly
   10000; the terms digest is pinned into the training receipt, so
   terms cannot be silently renegotiated after training.
4. **Human contribution** — a work entering the rights-management
   pipeline must declare its contribution class. ``ai-only`` works
   classify ``licensing.ai_only`` and cannot enter the pipeline
   (JASRAC rule); ``ai-assisted`` works with unlabeled AI parts deny
   (``licensing.unlabeled_ai_parts``).
5. **Performer disclosure** — a synthetic performer receipt binds
   both the declared tier and the evidence tier; a mismatch is
   ``licensing.disclosure_tier_fraud`` (the PLAVE lesson: real
   performers in mocap suits are not AI).
6. **Likeness** — a synthetic likeness/voice with no live,
   holder-signed grant covering the use scope denies with
   ``licensing.likeness_theft``.
7. **Take-level receipts** — an AI-generated production take without
   a sealed receipt (model version, prompt digest, assets digest,
   rights-review digest) cannot ship (``licensing.no_rights_review``).

Honest boundary: receipts are *declared evidence*. The gate checks
lineage consistency — digests recompute, signatures verify, links
resolve, opt-ins exist, terms sum — not the legal validity of any
license. A forged-but-consistent receipt still needs an off-chain
adjudicator. What the gate guarantees: nothing trains, ships, or
enters the rights pipeline without a checkable licensing claim.

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


LICENSING_SCHEMA_VERSION = "northstar.licensing.v1"

_GENESIS = "genesis"
_HEX64_LENGTH = 64
_HEX128_LENGTH = 128

#: Policy classification tiers (mirrors the 87th batch's evidence tiers).
CLASS_AUTHORITATIVE = "authoritative"
CLASS_NON_AUTHORITATIVE = "non_authoritative"

#: Denial reason codes. All verdict reasons start with one of these.
DENY_UNLICENSED_CORPUS = "licensing.unlicensed_corpus"
DENY_LAUNDERED = "licensing.laundered_model"
DENY_LINEAGE_GAP = "licensing.lineage_gap"
DENY_BAD_SPLIT = "licensing.bad_split_terms"
DENY_AI_ONLY = "licensing.ai_only"
DENY_UNLABELED_AI_PARTS = "licensing.unlabeled_ai_parts"
DENY_TIER_FRAUD = "licensing.disclosure_tier_fraud"
DENY_LIKENESS_THEFT = "licensing.likeness_theft"
DENY_NO_RIGHTS_REVIEW = "licensing.no_rights_review"
DENY_UNKNOWN_TAKE = "licensing.unknown_take"
DENY_CHAIN_BROKEN = "licensing.chain_broken"

#: Closed contribution vocabulary (JASRAC line).
CONTRIBUTION_CLASSES: tuple[str, ...] = (
    "human-authored",
    "ai-assisted",
    "ai-only",
)

#: Closed performer disclosure tiers (PLAVE lesson: these are different
#: things and must not be collapsed).
PERFORMER_TIERS: tuple[str, ...] = (
    "mocap-assisted-real",
    "ai-co-created",
    "full-synthetic",
)


class LicensingError(ValueError):
    """A malformed licensing receipt or a programming error.

    Raised for structural problems (bad digests, unknown classes,
    non-summing splits, broken chains). Verification *failures*
    (missing opt-in, laundering, tier fraud) return a
    :class:`LicensingVerdict` with ``allowed=False`` instead — a failed
    license is a verdict, a malformed receipt is a bug.
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
        raise LicensingError(f"{field_name} must be a 64-char lowercase hex digest")
    return value


def _check_nonempty_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise LicensingError(f"{field_name} must be a non-empty string")
    return value


def _check_ts(value: Any, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise LicensingError(f"{field_name} must be a non-negative int epoch")
    return value


def _check_secret(value: Any, field_name: str) -> bytes:
    # The vendored ed25519 module takes a raw 32-byte seed (no keypair()).
    if not isinstance(value, bytes) or len(value) != 32:
        raise LicensingError(f"{field_name} must be a 32-byte seed")
    return value


def _check_contribution(value: Any) -> str:
    if value not in CONTRIBUTION_CLASSES:
        raise LicensingError(
            f"contribution_class must be one of {CONTRIBUTION_CLASSES}, saw {value!r}"
        )
    return value


def _check_tier(value: Any) -> str:
    if value not in PERFORMER_TIERS:
        raise LicensingError(
            f"tier must be one of {PERFORMER_TIERS}, saw {value!r}"
        )
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


def _check_chain(log: list[Any], type_name: str) -> None:
    """Raise :class:`LicensingError` if a receipt log is tampered/broken.

    Every entry must expose ``receipt_digest`` and ``prev_digest`` and
    a ``_payload()`` method; the entries must form one chain from
    ``"genesis"`` with recomputing digests and valid authority
    signatures.
    """
    expected_prev = _GENESIS
    for entry in log:
        if not hmac.compare_digest(entry.receipt_digest, jcs_sha256_hex(entry._payload())):
            raise LicensingError(
                f"{type_name} receipt {entry.receipt_id!r} digest does not recompute"
            )
        if not hmac.compare_digest(entry.prev_digest, expected_prev):
            raise LicensingError(
                f"{type_name} receipt {entry.receipt_id!r} chain break: "
                f"expected prev {expected_prev!r}"
            )
        if not _verify_signature(
            entry.authority_pubkey_hex, entry._payload(), entry.signature_hex
        ):
            raise LicensingError(
                f"{type_name} receipt {entry.receipt_id!r} authority signature invalid"
            )
        expected_prev = entry.receipt_digest


def _seal(receipt: Any, payload: Mapping[str, Any], secret: bytes) -> Any:
    """Sign ``payload`` with ``secret`` and stamp the receipt digest."""
    signature_hex = ed25519.sign(secret, jcs_canonical_json(payload)).hex()
    sealed = type(receipt)(**{**receipt.__dict__, "signature_hex": signature_hex})
    digest = jcs_sha256_hex(sealed._payload())
    return type(receipt)(**{**sealed.__dict__, "receipt_digest": digest})


@dataclass(frozen=True)
class LicensingVerdict:
    """Outcome of one licensing check."""

    allowed: bool
    reason: str
    classification: str = CLASS_NON_AUTHORITATIVE
    receipt_digest: str = ""


def _deny(code: str, detail: str) -> LicensingVerdict:
    return LicensingVerdict(
        allowed=False,
        reason=f"{code}: {detail}",
        classification=CLASS_NON_AUTHORITATIVE,
    )


def _allow(detail: str, receipt_digest: str = "") -> LicensingVerdict:
    return LicensingVerdict(
        allowed=True,
        reason=detail,
        classification=CLASS_AUTHORITATIVE,
        receipt_digest=receipt_digest,
    )


# ---------------------------------------------------------------------------
# Licensed training receipts
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LicensedTrainingReceipt:
    """A training corpus's licensing claim.

    ``licensor_ids`` names every licensor whose works are in the
    corpus (the Merlin opt-in framework as template: each licensor
    must carry opt-in proof). ``opt_in_proof_digest`` pins the pinned
    bundle of per-licensor proofs; ``split_terms_digest`` pins the
    revenue-split terms (see :func:`split_terms`), so terms cannot be
    renegotiated after training without a new receipt.
    """

    receipt_id: str
    model_id: str
    corpus_digest: str
    licensor_ids: tuple[str, ...]
    opt_in_proof_digest: str
    split_terms_digest: str
    issued_by: str
    authority_pubkey_hex: str
    signature_hex: str
    issued_at: int
    expires_at: int
    prev_digest: str = _GENESIS
    receipt_digest: str = ""
    schema_version: str = LICENSING_SCHEMA_VERSION

    def _payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "model_id": self.model_id,
            "corpus_digest": self.corpus_digest,
            "licensor_ids": list(self.licensor_ids),
            "opt_in_proof_digest": self.opt_in_proof_digest,
            "split_terms_digest": self.split_terms_digest,
            "issued_by": self.issued_by,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "schema_version": self.schema_version,
        }


def licensed_training_receipt(
    *,
    receipt_id: str,
    model_id: str,
    corpus_digest: str,
    licensor_ids: tuple[str, ...],
    opt_in_proof_digest: str,
    split_terms_digest: str,
    authority_secret: bytes,
    issued_by: str,
    issued_at: int,
    expires_at: int,
    prev_digest: str = _GENESIS,
) -> LicensedTrainingReceipt:
    """Issue an authority-signed licensed-training receipt.

    Fail-closed at issuance: an empty licensor list raises (a corpus
    with no named licensors is not a licensed corpus), and
    ``expires_at <= issued_at`` raises. The authority attests that
    opt-in evidence was reviewed — the *check* side re-verifies it.
    """
    _check_secret(authority_secret, "authority_secret")
    receipt_id = _check_nonempty_str(receipt_id, "receipt_id")
    model_id = _check_nonempty_str(model_id, "model_id")
    corpus_digest = _check_hex64(corpus_digest, "corpus_digest")
    if not isinstance(licensor_ids, (tuple, list)) or not licensor_ids:
        raise LicensingError("licensor_ids must be a non-empty tuple/list")
    licensor_ids = tuple(_check_nonempty_str(lid, "licensor_id") for lid in licensor_ids)
    if len(set(licensor_ids)) != len(licensor_ids):
        raise LicensingError("licensor_ids must be unique")
    opt_in_proof_digest = _check_hex64(opt_in_proof_digest, "opt_in_proof_digest")
    split_terms_digest = _check_hex64(split_terms_digest, "split_terms_digest")
    issued_by = _check_nonempty_str(issued_by, "issued_by")
    issued_at = _check_ts(issued_at, "issued_at")
    expires_at = _check_ts(expires_at, "expires_at")
    if expires_at <= issued_at:
        raise LicensingError("expires_at must be after issued_at")
    if not isinstance(prev_digest, str) or not prev_digest:
        raise LicensingError("prev_digest must be a non-empty string")

    authority_pubkey_hex = ed25519.public_key(authority_secret).hex()
    bare = LicensedTrainingReceipt(
        receipt_id=receipt_id,
        model_id=model_id,
        corpus_digest=corpus_digest,
        licensor_ids=licensor_ids,
        opt_in_proof_digest=opt_in_proof_digest,
        split_terms_digest=split_terms_digest,
        issued_by=issued_by,
        authority_pubkey_hex=authority_pubkey_hex,
        signature_hex="00" * _HEX128_LENGTH,  # placeholder; replaced by _seal
        issued_at=issued_at,
        expires_at=expires_at,
        prev_digest=prev_digest,
    )
    return _seal(bare, bare._payload(), authority_secret)


def check_training_receipt(
    log: list[LicensedTrainingReceipt],
    *,
    model_id: str,
    corpus_digest: str,
    opt_in_lookup: Callable[[str], str | None] | None = None,
    check_time: int,
) -> LicensingVerdict:
    """Fail-closed gate: may this model train on / ship with this corpus?

    Checks, in order: log integrity; the receipt names this
    ``model_id`` and this exact ``corpus_digest``; the receipt is live
    at ``check_time``; the pinned ``opt_in_proof_digest`` recomputes
    from the per-licensor proofs; and every named licensor resolves an
    opt-in proof through ``opt_in_lookup``. One unresolvable licensor
    denies the whole corpus — a corpus is only as licensed as its
    least-evidenced licensor.
    """
    model_id = _check_nonempty_str(model_id, "model_id")
    corpus_digest = _check_hex64(corpus_digest, "corpus_digest")
    check_time = _check_ts(check_time, "check_time")

    try:
        _check_chain(log, "licensed-training")
    except LicensingError as error:
        return _deny(DENY_CHAIN_BROKEN, f"training receipt log integrity failure: {error}")

    receipt = next((r for r in reversed(log) if r.model_id == model_id), None)
    if receipt is None:
        return _deny(
            DENY_UNLICENSED_CORPUS,
            f"no licensed-training receipt for model {model_id!r}: "
            "training without a licensing claim is unlicensed training",
        )
    if not hmac.compare_digest(receipt.corpus_digest, corpus_digest):
        return _deny(
            DENY_UNLICENSED_CORPUS,
            f"receipt binds corpus {receipt.corpus_digest[:12]}..., "
            f"invoked corpus is {corpus_digest[:12]}...: digest mismatch",
        )
    if not (receipt.issued_at <= check_time < receipt.expires_at):
        return _deny(
            DENY_UNLICENSED_CORPUS,
            f"receipt {receipt.receipt_id!r} is not live at check time",
        )
    if opt_in_lookup is None:
        return _deny(
            DENY_UNLICENSED_CORPUS,
            "no opt_in_lookup provided: licensor opt-in cannot be resolved",
        )
    proofs: dict[str, str] = {}
    for licensor_id in receipt.licensor_ids:
        proof = opt_in_lookup(licensor_id)
        if proof is None or not _is_hex(proof, _HEX64_LENGTH):
            return _deny(
                DENY_UNLICENSED_CORPUS,
                f"licensor {licensor_id!r} has no resolvable opt-in proof: "
                "missing opt-in denies the whole corpus",
            )
        proofs[licensor_id] = proof
    pinned = jcs_sha256_hex(
        sorted((licensor, proofs[licensor]) for licensor in receipt.licensor_ids)
    )
    if not hmac.compare_digest(pinned, receipt.opt_in_proof_digest):
        return _deny(
            DENY_UNLICENSED_CORPUS,
            "opt-in proof bundle does not recompute to the pinned digest: "
            "the licensing claim's evidence changed after issuance",
        )
    return _allow(
        f"corpus licensed: {len(receipt.licensor_ids)} licensor(s) with "
        "resolvable opt-in proofs, terms pinned",
        receipt_digest=receipt.receipt_digest,
    )


# ---------------------------------------------------------------------------
# Taint transitivity: the model-laundering gate
# ---------------------------------------------------------------------------


def verify_derivation_sources(
    *,
    derivation_sources: tuple[str, ...],
    lineage_lookup: Callable[[str], Mapping[str, Any] | None] | None = None,
) -> LicensingVerdict:
    """Fail-closed gate against model laundering.

    A model trained on another model's outputs/distillations declares
    its ``derivation_sources`` (parent model digests). Each source
    must resolve through ``lineage_lookup`` (a digest -> ``{"tainted":
    bool}`` mapping); an unresolvable source is a lineage gap, and a
    tainted source taints the child — retraining on a tainted model's
    outputs does not wash the taint (the Sony/UMG "fruit of the
    poisonous tree" theory as a deterministic mechanism).

    Honest boundary: this gate checks the *declared* derivation
    sources. A model that distills tainted Y while naming clean
    parent X defeats any receipt system; catching that needs
    weight-level provenance analysis.
    """
    if not isinstance(derivation_sources, (tuple, list)):
        raise LicensingError("derivation_sources must be a tuple/list")
    for source in derivation_sources:
        _check_hex64(source, "derivation source digest")
    if lineage_lookup is None:
        return _deny(
            DENY_LINEAGE_GAP,
            "no lineage_lookup provided: derivation sources cannot be resolved",
        )
    for source in derivation_sources:
        record = lineage_lookup(source)
        if record is None:
            return _deny(
                DENY_LINEAGE_GAP,
                f"derivation source {source[:12]}... resolves to no known "
                "lineage record: unverifiable parentage",
            )
        if record.get("tainted"):
            return _deny(
                DENY_LAUNDERED,
                f"derivation source {source[:12]}... is tainted: training on "
                "a tainted model's outputs inherits the taint — retraining "
                "does not wash it (model laundering)",
            )
    return _allow(
        f"all {len(derivation_sources)} derivation source(s) resolve clean",
    )


# ---------------------------------------------------------------------------
# Split terms (NMPA 50/50 as field template)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SplitTermsReceipt:
    """Pinned revenue-split terms for a licensed corpus.

    Shares are basis points (10000 == 100%). The NMPA June-2026 50/50
    publishing/masters precedent is a *field template* — the terms
    themselves are the bound evidence, not a fixed rule. Shares must
    sum to exactly 10000.
    """

    terms_id: str
    publishing_share_bps: int
    masters_share_bps: int
    effective_from: int
    issued_by: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str = _GENESIS
    receipt_digest: str = ""
    schema_version: str = LICENSING_SCHEMA_VERSION

    def _payload(self) -> dict[str, Any]:
        return {
            "terms_id": self.terms_id,
            "publishing_share_bps": self.publishing_share_bps,
            "masters_share_bps": self.masters_share_bps,
            "effective_from": self.effective_from,
            "issued_by": self.issued_by,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
            "schema_version": self.schema_version,
        }


def split_terms(
    *,
    terms_id: str,
    publishing_share_bps: int,
    masters_share_bps: int,
    effective_from: int,
    authority_secret: bytes,
    issued_by: str,
    prev_digest: str = _GENESIS,
) -> SplitTermsReceipt:
    """Issue authority-signed split terms. Non-summing shares raise."""
    _check_secret(authority_secret, "authority_secret")
    terms_id = _check_nonempty_str(terms_id, "terms_id")
    for name, value in (
        ("publishing_share_bps", publishing_share_bps),
        ("masters_share_bps", masters_share_bps),
    ):
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise LicensingError(f"{name} must be a non-negative int (basis points)")
    if publishing_share_bps + masters_share_bps != 10000:
        raise LicensingError(
            "split shares must sum to exactly 10000 bps "
            f"(saw {publishing_share_bps + masters_share_bps})"
        )
    effective_from = _check_ts(effective_from, "effective_from")
    issued_by = _check_nonempty_str(issued_by, "issued_by")
    if not isinstance(prev_digest, str) or not prev_digest:
        raise LicensingError("prev_digest must be a non-empty string")

    authority_pubkey_hex = ed25519.public_key(authority_secret).hex()
    bare = SplitTermsReceipt(
        terms_id=terms_id,
        publishing_share_bps=publishing_share_bps,
        masters_share_bps=masters_share_bps,
        effective_from=effective_from,
        issued_by=issued_by,
        authority_pubkey_hex=authority_pubkey_hex,
        signature_hex="00" * _HEX128_LENGTH,  # placeholder; replaced by _seal
        prev_digest=prev_digest,
    )
    return _seal(bare, bare._payload(), authority_secret)


def check_split_terms(
    log: list[SplitTermsReceipt],
    *,
    terms_id: str,
    terms_digest: str,
) -> LicensingVerdict:
    """Verify pinned split terms: the log's terms recompute to ``terms_digest``."""
    terms_id = _check_nonempty_str(terms_id, "terms_id")
    terms_digest = _check_hex64(terms_digest, "terms_digest")
    try:
        _check_chain(log, "split-terms")
    except LicensingError as error:
        return _deny(DENY_CHAIN_BROKEN, f"split-terms log integrity failure: {error}")
    receipt = next((r for r in reversed(log) if r.terms_id == terms_id), None)
    if receipt is None:
        return _deny(DENY_BAD_SPLIT, f"no split-terms receipt {terms_id!r}")
    if not hmac.compare_digest(receipt.receipt_digest, terms_digest):
        return _deny(
            DENY_BAD_SPLIT,
            f"split terms {terms_id!r} do not recompute to the pinned digest: "
            "terms changed after pinning",
        )
    return _allow(
        f"split terms pinned: publishing {receipt.publishing_share_bps} bps / "
        f"masters {receipt.masters_share_bps} bps",
        receipt_digest=receipt.receipt_digest,
    )


# ---------------------------------------------------------------------------
# Human creative contribution (JASRAC line)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class WorkContributionReceipt:
    """A work's declared human-creative-contribution line.

    ``contribution_class`` is one of ``human-authored``,
    ``ai-assisted``, ``ai-only``. For ``ai-assisted`` works,
    ``ai_parts_labeled`` must be true — AI parts must be labeled
    (the JASRAC J-WID rule). The filer carries a guarantee
    obligation: the declaration is signed by the filing authority.
    """

    receipt_id: str
    work_digest: str
    contribution_class: str
    ai_parts_labeled: bool
    declared_by: str
    authority_pubkey_hex: str
    signature_hex: str
    declared_at: int
    prev_digest: str = _GENESIS
    receipt_digest: str = ""
    schema_version: str = LICENSING_SCHEMA_VERSION

    def _payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "work_digest": self.work_digest,
            "contribution_class": self.contribution_class,
            "ai_parts_labeled": self.ai_parts_labeled,
            "declared_by": self.declared_by,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "declared_at": self.declared_at,
            "prev_digest": self.prev_digest,
            "schema_version": self.schema_version,
        }


def issue_work_contribution(
    *,
    receipt_id: str,
    work_digest: str,
    contribution_class: str,
    ai_parts_labeled: bool,
    authority_secret: bytes,
    declared_by: str,
    declared_at: int,
    prev_digest: str = _GENESIS,
) -> WorkContributionReceipt:
    """Issue a contribution declaration. Unknown classes raise."""
    _check_secret(authority_secret, "authority_secret")
    receipt_id = _check_nonempty_str(receipt_id, "receipt_id")
    work_digest = _check_hex64(work_digest, "work_digest")
    contribution_class = _check_contribution(contribution_class)
    if not isinstance(ai_parts_labeled, bool):
        raise LicensingError("ai_parts_labeled must be a bool")
    declared_by = _check_nonempty_str(declared_by, "declared_by")
    declared_at = _check_ts(declared_at, "declared_at")
    if not isinstance(prev_digest, str) or not prev_digest:
        raise LicensingError("prev_digest must be a non-empty string")

    authority_pubkey_hex = ed25519.public_key(authority_secret).hex()
    bare = WorkContributionReceipt(
        receipt_id=receipt_id,
        work_digest=work_digest,
        contribution_class=contribution_class,
        ai_parts_labeled=ai_parts_labeled,
        declared_by=declared_by,
        authority_pubkey_hex=authority_pubkey_hex,
        signature_hex="00" * _HEX128_LENGTH,  # placeholder; replaced by _seal
        declared_at=declared_at,
        prev_digest=prev_digest,
    )
    return _seal(bare, bare._payload(), authority_secret)


def human_contribution_gate(
    log: list[WorkContributionReceipt],
    *,
    work_digest: str,
) -> LicensingVerdict:
    """Fail-closed gate: may this work enter the rights-management pipeline?

    ``ai-only`` works classify ``licensing.ai_only`` and cannot enter
    (JASRAC: AI-only works are not managed). ``ai-assisted`` works
    with unlabeled AI parts deny. ``human-authored`` works allow. A
    work with no declaration at all denies — an undeclared
    contribution line is not a human-authored claim.
    """
    work_digest = _check_hex64(work_digest, "work_digest")
    try:
        _check_chain(log, "work-contribution")
    except LicensingError as error:
        return _deny(DENY_CHAIN_BROKEN, f"contribution log integrity failure: {error}")
    receipt = next((r for r in reversed(log) if r.work_digest == work_digest), None)
    if receipt is None:
        return _deny(
            DENY_AI_ONLY,
            f"no contribution declaration for work {work_digest[:12]}...: "
            "an undeclared contribution line cannot enter the rights pipeline",
        )
    if receipt.contribution_class == "ai-only":
        return LicensingVerdict(
            allowed=False,
            reason=f"{DENY_AI_ONLY}: work declared ai-only — AI-only works "
            "are not managed (JASRAC human-creative-contribution line)",
            classification=DENY_AI_ONLY,
        )
    if receipt.contribution_class == "ai-assisted" and not receipt.ai_parts_labeled:
        return _deny(
            DENY_UNLABELED_AI_PARTS,
            "ai-assisted work with unlabeled AI parts: AI parts must be "
            "labeled before rights management",
        )
    return _allow(
        f"contribution declared: {receipt.contribution_class}, "
        "rights pipeline entry permitted",
        receipt_digest=receipt.receipt_digest,
    )


# ---------------------------------------------------------------------------
# Synthetic performer disclosure tiers
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PerformerDisclosureReceipt:
    """A synthetic performer's disclosure tier declaration.

    ``declared_tier`` is what the platform claims; ``evidence_tier``
    is what the platform's own evidence supports. They must match —
    the PLAVE lesson: real performers in mocap suits
    (``mocap-assisted-real``) are not AI, and claiming a lower
    synthetic tier than the evidence shows is tier fraud.
    """

    receipt_id: str
    performer_id: str
    declared_tier: str
    evidence_tier: str
    issued_by: str
    authority_pubkey_hex: str
    signature_hex: str
    issued_at: int
    prev_digest: str = _GENESIS
    receipt_digest: str = ""
    schema_version: str = LICENSING_SCHEMA_VERSION

    def _payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "performer_id": self.performer_id,
            "declared_tier": self.declared_tier,
            "evidence_tier": self.evidence_tier,
            "issued_by": self.issued_by,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "issued_at": self.issued_at,
            "prev_digest": self.prev_digest,
            "schema_version": self.schema_version,
        }


def issue_performer_disclosure(
    *,
    receipt_id: str,
    performer_id: str,
    declared_tier: str,
    evidence_tier: str,
    authority_secret: bytes,
    issued_by: str,
    issued_at: int,
    prev_digest: str = _GENESIS,
) -> PerformerDisclosureReceipt:
    """Issue a performer disclosure receipt.

    The issuer records *both* the declared tier and the evidence tier.
    A mismatch is allowed at issuance (the receipt is honest about the
    mismatch) — it denies at *check* time, so the fraud is on the
    record rather than silently blocked at filing.
    """
    _check_secret(authority_secret, "authority_secret")
    receipt_id = _check_nonempty_str(receipt_id, "receipt_id")
    performer_id = _check_nonempty_str(performer_id, "performer_id")
    declared_tier = _check_tier(declared_tier)
    evidence_tier = _check_tier(evidence_tier)
    issued_by = _check_nonempty_str(issued_by, "issued_by")
    issued_at = _check_ts(issued_at, "issued_at")
    if not isinstance(prev_digest, str) or not prev_digest:
        raise LicensingError("prev_digest must be a non-empty string")

    authority_pubkey_hex = ed25519.public_key(authority_secret).hex()
    bare = PerformerDisclosureReceipt(
        receipt_id=receipt_id,
        performer_id=performer_id,
        declared_tier=declared_tier,
        evidence_tier=evidence_tier,
        issued_by=issued_by,
        authority_pubkey_hex=authority_pubkey_hex,
        signature_hex="00" * _HEX128_LENGTH,  # placeholder; replaced by _seal
        issued_at=issued_at,
        prev_digest=prev_digest,
    )
    return _seal(bare, bare._payload(), authority_secret)


def check_performer_tier(
    log: list[PerformerDisclosureReceipt],
    *,
    performer_id: str,
) -> LicensingVerdict:
    """Fail-closed gate: is this performer's disclosure tier honest?

    A declared tier that does not match the evidence tier denies with
    ``licensing.disclosure_tier_fraud``. No receipt at all denies —
    an undisclosed synthetic performer is an unverified performer.
    """
    performer_id = _check_nonempty_str(performer_id, "performer_id")
    try:
        _check_chain(log, "performer-disclosure")
    except LicensingError as error:
        return _deny(DENY_CHAIN_BROKEN, f"disclosure log integrity failure: {error}")
    receipt = next((r for r in reversed(log) if r.performer_id == performer_id), None)
    if receipt is None:
        return _deny(
            DENY_TIER_FRAUD,
            f"no disclosure receipt for performer {performer_id!r}: "
            "an undisclosed synthetic performer cannot be promoted",
        )
    if receipt.declared_tier != receipt.evidence_tier:
        return _deny(
            DENY_TIER_FRAUD,
            f"performer {performer_id!r} declares {receipt.declared_tier!r} "
            f"but the evidence supports {receipt.evidence_tier!r}: "
            "disclosure tier fraud",
        )
    return _allow(
        f"performer {performer_id!r} honestly disclosed as "
        f"{receipt.declared_tier!r}",
        receipt_digest=receipt.receipt_digest,
    )


# ---------------------------------------------------------------------------
# Likeness / voice rights
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LikenessGrantReceipt:
    """A likeness-holder-signed grant for synthetic likeness/voice use.

    Signed by the *holder's* key (not a platform authority): only the
    likeness holder can grant use of their likeness. ``scopes`` is the
    closed list of granted use scopes (e.g. ``"music-video"``,
    ``"advertising"``); a use outside the granted scopes denies.
    """

    grant_id: str
    likeness_digest: str
    holder_id: str
    scopes: tuple[str, ...]
    holder_pubkey_hex: str
    signature_hex: str
    granted_at: int
    expires_at: int
    prev_digest: str = _GENESIS
    receipt_digest: str = ""
    schema_version: str = LICENSING_SCHEMA_VERSION

    def _payload(self) -> dict[str, Any]:
        return {
            "grant_id": self.grant_id,
            "likeness_digest": self.likeness_digest,
            "holder_id": self.holder_id,
            "scopes": list(self.scopes),
            "holder_pubkey_hex": self.holder_pubkey_hex,
            "granted_at": self.granted_at,
            "expires_at": self.expires_at,
            "prev_digest": self.prev_digest,
            "schema_version": self.schema_version,
        }


def issue_likeness_grant(
    *,
    grant_id: str,
    likeness_digest: str,
    holder_id: str,
    scopes: tuple[str, ...],
    holder_secret: bytes,
    granted_at: int,
    expires_at: int,
    prev_digest: str = _GENESIS,
) -> LikenessGrantReceipt:
    """Issue a likeness grant, signed by the likeness holder's key."""
    _check_secret(holder_secret, "holder_secret")
    grant_id = _check_nonempty_str(grant_id, "grant_id")
    likeness_digest = _check_hex64(likeness_digest, "likeness_digest")
    holder_id = _check_nonempty_str(holder_id, "holder_id")
    if not isinstance(scopes, (tuple, list)) or not scopes:
        raise LicensingError("scopes must be a non-empty tuple/list")
    scopes = tuple(_check_nonempty_str(s, "scope") for s in scopes)
    granted_at = _check_ts(granted_at, "granted_at")
    expires_at = _check_ts(expires_at, "expires_at")
    if expires_at <= granted_at:
        raise LicensingError("expires_at must be after granted_at")
    if not isinstance(prev_digest, str) or not prev_digest:
        raise LicensingError("prev_digest must be a non-empty string")

    holder_pubkey_hex = ed25519.public_key(holder_secret).hex()
    bare = LikenessGrantReceipt(
        grant_id=grant_id,
        likeness_digest=likeness_digest,
        holder_id=holder_id,
        scopes=scopes,
        holder_pubkey_hex=holder_pubkey_hex,
        signature_hex="00" * _HEX128_LENGTH,  # placeholder; replaced by _seal
        granted_at=granted_at,
        expires_at=expires_at,
        prev_digest=prev_digest,
    )
    sealed = type(bare)(**{**bare.__dict__, "signature_hex": ed25519.sign(
        holder_secret, jcs_canonical_json(bare._payload())
    ).hex()})
    return type(bare)(
        **{**sealed.__dict__, "receipt_digest": jcs_sha256_hex(sealed._payload())}
    )


def _check_likeness_chain(log: list[LikenessGrantReceipt]) -> None:
    """Chain check for holder-signed grants (holder pubkey varies per grant)."""
    expected_prev = _GENESIS
    for entry in log:
        if not hmac.compare_digest(entry.receipt_digest, jcs_sha256_hex(entry._payload())):
            raise LicensingError(
                f"likeness grant {entry.grant_id!r} digest does not recompute"
            )
        if not hmac.compare_digest(entry.prev_digest, expected_prev):
            raise LicensingError(
                f"likeness grant {entry.grant_id!r} chain break: "
                f"expected prev {expected_prev!r}"
            )
        if not _verify_signature(
            entry.holder_pubkey_hex, entry._payload(), entry.signature_hex
        ):
            raise LicensingError(
                f"likeness grant {entry.grant_id!r} holder signature invalid"
            )
        expected_prev = entry.receipt_digest


def check_likeness_use(
    log: list[LikenessGrantReceipt],
    *,
    likeness_digest: str,
    use_scope: str,
    check_time: int,
) -> LicensingVerdict:
    """Fail-closed gate: may this synthetic likeness be used for this scope?

    Requires a live, holder-signed grant whose scopes cover
    ``use_scope``. No grant, an expired grant, or a scope outside the
    grant denies with ``licensing.likeness_theft``.
    """
    likeness_digest = _check_hex64(likeness_digest, "likeness_digest")
    use_scope = _check_nonempty_str(use_scope, "use_scope")
    check_time = _check_ts(check_time, "check_time")
    try:
        _check_likeness_chain(log)
    except LicensingError as error:
        return _deny(DENY_CHAIN_BROKEN, f"likeness log integrity failure: {error}")
    for grant in reversed(log):
        if not hmac.compare_digest(grant.likeness_digest, likeness_digest):
            continue
        if not (grant.granted_at <= check_time < grant.expires_at):
            continue
        if use_scope in grant.scopes:
            return _allow(
                f"likeness use {use_scope!r} covered by holder grant "
                f"{grant.grant_id!r} ({grant.holder_id})",
                receipt_digest=grant.receipt_digest,
            )
        return _deny(
            DENY_LIKENESS_THEFT,
            f"use scope {use_scope!r} is outside holder grant "
            f"{grant.grant_id!r} scopes {list(grant.scopes)!r}",
        )
    return _deny(
        DENY_LIKENESS_THEFT,
        f"no live holder-signed grant for likeness {likeness_digest[:12]}...: "
        "synthetic likeness without a holder grant is likeness theft",
    )


# ---------------------------------------------------------------------------
# Take-level receipts (production workflow)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TakeReceipt:
    """One AI-generated production take's rights receipt.

    Binds the model version, the prompt digest, the assets digest, and
    the rights-review digest for a single take (the CineMe / creator
    practice as the landing use case). A take ships only with a
    sealed receipt: no receipt, no rights review, no shipment.
    """

    take_id: str
    model_version: str
    prompt_digest: str
    assets_digest: str
    rights_review_digest: str
    issued_by: str
    authority_pubkey_hex: str
    signature_hex: str
    issued_at: int
    prev_digest: str = _GENESIS
    receipt_digest: str = ""
    schema_version: str = LICENSING_SCHEMA_VERSION

    def _payload(self) -> dict[str, Any]:
        return {
            "take_id": self.take_id,
            "model_version": self.model_version,
            "prompt_digest": self.prompt_digest,
            "assets_digest": self.assets_digest,
            "rights_review_digest": self.rights_review_digest,
            "issued_by": self.issued_by,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "issued_at": self.issued_at,
            "prev_digest": self.prev_digest,
            "schema_version": self.schema_version,
        }


def issue_take_receipt(
    *,
    take_id: str,
    model_version: str,
    prompt_digest: str,
    assets_digest: str,
    rights_review_digest: str,
    authority_secret: bytes,
    issued_by: str,
    issued_at: int,
    prev_digest: str = _GENESIS,
) -> TakeReceipt:
    """Issue a take-level receipt. An empty rights-review digest raises."""
    _check_secret(authority_secret, "authority_secret")
    take_id = _check_nonempty_str(take_id, "take_id")
    model_version = _check_nonempty_str(model_version, "model_version")
    prompt_digest = _check_hex64(prompt_digest, "prompt_digest")
    assets_digest = _check_hex64(assets_digest, "assets_digest")
    rights_review_digest = _check_hex64(rights_review_digest, "rights_review_digest")
    issued_by = _check_nonempty_str(issued_by, "issued_by")
    issued_at = _check_ts(issued_at, "issued_at")
    if not isinstance(prev_digest, str) or not prev_digest:
        raise LicensingError("prev_digest must be a non-empty string")

    authority_pubkey_hex = ed25519.public_key(authority_secret).hex()
    bare = TakeReceipt(
        take_id=take_id,
        model_version=model_version,
        prompt_digest=prompt_digest,
        assets_digest=assets_digest,
        rights_review_digest=rights_review_digest,
        issued_by=issued_by,
        authority_pubkey_hex=authority_pubkey_hex,
        signature_hex="00" * _HEX128_LENGTH,  # placeholder; replaced by _seal
        issued_at=issued_at,
        prev_digest=prev_digest,
    )
    return _seal(bare, bare._payload(), authority_secret)


def check_take(
    log: list[TakeReceipt],
    *,
    take_id: str,
) -> LicensingVerdict:
    """Fail-closed gate: may this AI-generated take ship?

    A take ships only with a sealed, chain-intact take receipt. An
    unknown take id denies — there is no "the take exists but the
    paperwork is pending" path.
    """
    take_id = _check_nonempty_str(take_id, "take_id")
    try:
        _check_chain(log, "take")
    except LicensingError as error:
        return _deny(DENY_CHAIN_BROKEN, f"take log integrity failure: {error}")
    receipt = next((r for r in reversed(log) if r.take_id == take_id), None)
    if receipt is None:
        return _deny(
            DENY_UNKNOWN_TAKE,
            f"no take receipt for {take_id!r}: a take without a sealed "
            "rights receipt cannot ship",
        )
    return _allow(
        f"take {take_id!r} sealed: model {receipt.model_version}, "
        "prompt/assets/rights-review digests bound",
        receipt_digest=receipt.receipt_digest,
    )


__all__ = [
    "CLASS_AUTHORITATIVE",
    "CLASS_NON_AUTHORITATIVE",
    "CONTRIBUTION_CLASSES",
    "DENY_AI_ONLY",
    "DENY_BAD_SPLIT",
    "DENY_CHAIN_BROKEN",
    "DENY_LAUNDERED",
    "DENY_LIKENESS_THEFT",
    "DENY_LINEAGE_GAP",
    "DENY_NO_RIGHTS_REVIEW",
    "DENY_TIER_FRAUD",
    "DENY_UNKNOWN_TAKE",
    "DENY_UNLABELED_AI_PARTS",
    "DENY_UNLICENSED_CORPUS",
    "LICENSING_SCHEMA_VERSION",
    "PERFORMER_TIERS",
    "LicensedTrainingReceipt",
    "LicensingError",
    "LicensingVerdict",
    "LikenessGrantReceipt",
    "PerformerDisclosureReceipt",
    "SplitTermsReceipt",
    "TakeReceipt",
    "WorkContributionReceipt",
    "check_likeness_use",
    "check_performer_tier",
    "check_split_terms",
    "check_take",
    "check_training_receipt",
    "human_contribution_gate",
    "issue_likeness_grant",
    "issue_performer_disclosure",
    "issue_take_receipt",
    "issue_work_contribution",
    "licensed_training_receipt",
    "split_terms",
    "verify_derivation_sources",
]
