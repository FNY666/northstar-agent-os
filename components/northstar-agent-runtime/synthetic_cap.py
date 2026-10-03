"""Synthetic-data ratio cap (one-hundred-twelfth batch).

Absorbs the 2026 synthetic-data research thread (mechanism ideas only,
honestly scoped):

* **Production synthetic data is privacy-driven, not a general training
  substitute.** Real 2026 deployments: tabular data for banks/insurance
  (MOSTLY AI, differential-privacy budgets), medical (MDClone, $104M),
  and physical-AI simulation (NVIDIA's Isaac GR00T Blueprint, Cosmos
  world models, Parallel Domain driving scenes). The governance
  question is not "is synthetic data allowed" but "how much synthetic
  is in the mix, and is it declared."
* **2026 collapse evidence: recursion is the poison.** RAG Collapse
  (arXiv:2608.22118) — weights fixed, only the retrieval corpus
  recursively polluted: 79.6% collapse across 1,528 simulations, with
  no retraining involved. "Scientific-judgment collapse" (Ho/Liu/Huang):
  synthetic review opinions compress score distributions and crush
  semantic diversity. The standing consensus: what collapses is
  *indiscriminate recursive reuse* — synthetic trained on synthetic —
  and keeping original data slows it. Hence the two hard rules here:
  (1) a synthetic-fraction cap, (2) a generation-2 recursion tripwire.
* **Regulatory treatment.** EU AI Act Art. 50 (machine-readable
  AI-output marking, effective 2026-08-02; systems already on the
  market get grace to 2026-12-02) and Art. 53 (training-data summary).
  Kneschke v. LAION (OLG Hamburg, Dec 2025): a TDM opt-out counts only
  when machine-readable (robots.txt / TDMRep); prose in terms of
  service does not count. EDPB 03/2026: GDPR applies to training data
  with no grandfathering of old corpora. These are encoded as
  deterministic checks, not legal advice — case-law references below
  are the *rationale* for the checks' shape, not counsel.

Northstar mapping:

* ``DataSliceManifest`` — per-slice (corpus shard) label: ``real`` or
  ``synthetic`` (+ ``generator_id`` for synthetic), a SHA-256
  ``slice_digest`` hash-pin, ``weight_units``, ``generation`` (0 for
  real, 1 for first-generation synthetic, >=2 means the slice was
  itself trained on synthetic slices), an authority Ed25519 signature
  (94th/104th-batch no-self-issuance discipline), and a hash chain.
  An undeclared slice (training uses a slice with no manifest) denies
  as ``data.undeclared_slice`` — the 100th batch's
  ``unverifiable-lineage`` analogue.
* ``check_synthetic_ratio()`` — deterministic cap per lineage:
  synthetic weight fraction above ``SYNTHETIC_RATIO_MAX`` denies as
  ``data.synthetic_cap_exceeded``. The threshold is a *bench-calibrated
  parameter*, documented as such — it is not a law of nature; the RAG
  Collapse evidence says recursion collapses, it does not hand down a
  universal safe percentage. "Accumulate never replace": a synthetic
  slice at ``generation >= 2`` denies as ``data.recursive_reuse``
  (the RAG-collapse tripwire), regardless of the ratio.
* ``check_tdm_optout()`` — a TDM opt-out is honored *only* when the
  source manifest carries the machine-readable flag
  (``tdm_optout_machine_readable``); ToS-prose opt-out alone
  (``tdm_optout_tos_prose``) does NOT count (Kneschke v. LAION
  rationale). A prose-only opt-out does not deny the source — it is
  simply not honored as an opt-out. The distinction is the whole
  point: silent over-honoring would let a prose clause silently veto
  lawful corpora; silent under-honoring would ignore real opt-outs.
* ``art50_gate()`` — EU deployments: outputs must carry
  machine-readable AI-generated marking. Missing marking:
  non-authoritative classification inside the 2026-12-02 grace window
  (time-gated exception for already-listed systems), hard deny after
  it (``data.art50_marking_missing``). No degraded "partially marked"
  tier (87th-batch binary semantics).
* ``training_summary_receipt()`` — Art. 53-aligned training-data
  summary receipt (top-source template by weight), verifiable
  alongside the 100th-batch lineage receipt via
  ``pin_to_lineage()``.
* ``pin_to_lineage()`` — binds the slice-manifest set digest into a
  ``model_lineage.LineageReceipt``'s ``corpus_manifest_digest``; a
  mismatch classifies the lineage ``unverifiable-lineage``.

Honest boundary: slice labels are *declared*, not forensically
verified — a liar can label synthetic output as real, and this module
cannot catch that; catching it needs corpus-level forensic analysis.
C2PA / SynthID signals are graded *evidence*, never a legal
presumption: no manifest does NOT mean fake (the C2PA hard boundary).
TDM and Art. 50 checks encode the *shape* of the rules as fail-closed
mechanics; they are not legal advice and do not cover every clause.

Deterministic: no wall-clock reads (callers inject integer epoch-day
timestamps), JCS canonical hashing (95th batch), Ed25519 via the
vendored ``ed25519`` module (97th-batch pattern), digest comparisons
via :func:`hmac.compare_digest`.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field
from typing import Any, Mapping

import ed25519
from canonical_json import jcs_canonical_json, jcs_sha256_hex

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SYNTHETIC_CAP_SCHEMA_VERSION = "northstar.synthetic-cap.v1"

#: Default synthetic-fraction cap. A *bench-calibrated parameter*, not a
#: law of nature: the 2026 collapse evidence (RAG Collapse, 79.6% across
#: 1,528 sims; scientific-judgment collapse) establishes that
#: indiscriminate *recursive* reuse collapses, not that any particular
#: percentage is universally safe. Deployments tune this from their own
#: bench; the cap exists to force the number to be declared and bounded.
SYNTHETIC_RATIO_MAX = 0.5

#: Art. 50 grace cutoff: 2026-12-02 (systems already on the market get
#: until then). Epoch days. After this date, unmarked EU outputs deny.
ART50_GRACE_CUTOFF_EPOCH_DAYS = 20789

#: Art. 50 in-force date: 2026-08-02 (epoch days), for documentation.
ART50_IN_FORCE_EPOCH_DAYS = 20667

#: Closed slice-origin vocabulary.
SLICE_ORIGIN_REAL = "real"
SLICE_ORIGIN_SYNTHETIC = "synthetic"
SLICE_ORIGINS: tuple[str, ...] = (SLICE_ORIGIN_REAL, SLICE_ORIGIN_SYNTHETIC)

#: Closed jurisdiction vocabulary for the Art. 50 gate.
JURISDICTION_EU = "eu"
JURISDICTION_NON_EU = "non-eu"
JURISDICTIONS: tuple[str, ...] = (JURISDICTION_EU, JURISDICTION_NON_EU)

#: Denial reason codes (the ``data.*`` namespace).
DENY_UNDECLARED_SLICE = "data.undeclared_slice"
DENY_RECURSIVE_REUSE = "data.recursive_reuse"
DENY_RATIO_EXCEEDED = "data.synthetic_cap_exceeded"
DENY_MALFORMED = "data.malformed"
DENY_MANIFEST_TAMPERED = "data.manifest_tampered"
DENY_MANIFEST_CHAIN_BROKEN = "data.manifest_chain_broken"
DENY_ART50_MARKING_MISSING = "data.art50_marking_missing"
DENY_LINEAGE_PIN_MISMATCH = "data.lineage_pin_mismatch"

NON_AUTHORITATIVE = "non_authoritative"
AUTHORITATIVE = "authoritative"

_GENESIS = "genesis"
_HEX64_LENGTH = 64


class SyntheticCapError(ValueError):
    """A malformed manifest or a programming error.

    Verification *failures* (cap exceeded, recursion tripwire, missing
    marking) return verdicts with ``allowed=False`` instead — a failed
    corpus is a verdict, a malformed manifest is a bug.
    """


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


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
        raise SyntheticCapError(
            f"{field_name} must be a 64-char lowercase hex digest"
        )
    return value


def _check_nonempty_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value:
        raise SyntheticCapError(f"{field_name} must be a non-empty string")
    return value


def _check_hex128(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or len(value) != 128:
        raise SyntheticCapError(f"{field_name} must be 128-char hex")
    try:
        int(value, 16)
    except ValueError:
        raise SyntheticCapError(f"{field_name} must be 128-char hex") from None
    return value


def _check_pubkey_hex(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or len(value) != 64:
        raise SyntheticCapError(f"{field_name} must be a 32-byte pubkey hex")
    try:
        int(value, 16)
    except ValueError:
        raise SyntheticCapError(f"{field_name} must be a 32-byte pubkey hex") from None
    return value


def _check_ts(value: Any, field_name: str) -> int:
    if not isinstance(value, int) or value < 0:
        raise SyntheticCapError(f"{field_name} must be a non-negative int")
    return value


def _check_origin(value: Any) -> str:
    if value not in SLICE_ORIGINS:
        raise SyntheticCapError(
            f"origin must be one of {SLICE_ORIGINS}, saw {value!r}"
        )
    return value


def _check_jurisdiction(value: Any) -> str:
    if value not in JURISDICTIONS:
        raise SyntheticCapError(
            f"jurisdiction must be one of {JURISDICTIONS}, saw {value!r}"
        )
    return value


# ---------------------------------------------------------------------------
# DataSliceManifest: per-slice (corpus shard) label, signed + chained
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DataSliceManifest:
    """One corpus slice's declared label.

    ``origin`` is ``"real"`` (captured/recorded data) or
    ``"synthetic"`` (generated). Synthetic slices MUST name
    ``generator_id`` (the generator model/tool that produced them) and
    declare ``generation``: 1 for first-generation synthetic (trained
    only on real data), >= 2 for slices trained on synthetic slices
    (the RAG-collapse tripwire). Real slices must have ``generation ==
    0`` and an empty ``generator_id`` — a "real" slice with a
    generation is malformed, not a clever middle tier.

    The manifest is authority-signed (Ed25519) and hash-chained, so a
    corpus label set is tamper-evident end to end.
    """

    slice_id: str
    origin: str
    slice_digest: str  # SHA-256 hex pin of the slice content
    weight_units: int  # tokens/records; >= 0
    generator_id: str  # "" for real slices
    generation: int  # 0 for real, >= 1 for synthetic
    issued_at: int
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str = _GENESIS
    manifest_digest: str = ""
    schema_version: str = SYNTHETIC_CAP_SCHEMA_VERSION

    def __post_init__(self) -> None:
        _check_nonempty_str(self.slice_id, "slice_id")
        _check_origin(self.origin)
        _check_hex64(self.slice_digest, "slice_digest")
        if not isinstance(self.weight_units, int) or self.weight_units < 0:
            raise SyntheticCapError("weight_units must be a non-negative int")
        if self.origin == SLICE_ORIGIN_REAL:
            if self.generator_id != "":
                raise SyntheticCapError(
                    "real slices must have an empty generator_id"
                )
            if self.generation != 0:
                raise SyntheticCapError("real slices must have generation == 0")
        else:
            _check_nonempty_str(self.generator_id, "generator_id")
            if not isinstance(self.generation, int) or self.generation < 1:
                raise SyntheticCapError(
                    "synthetic slices must have generation >= 1"
                )
        _check_ts(self.issued_at, "issued_at")
        _check_pubkey_hex(self.authority_pubkey_hex, "authority_pubkey_hex")
        _check_hex128(self.signature_hex, "signature_hex")
        if self.prev_digest != _GENESIS:
            _check_hex64(self.prev_digest, "prev_digest")
        if self.manifest_digest != "":
            _check_hex64(self.manifest_digest, "manifest_digest")


def _manifest_payload(manifest: DataSliceManifest) -> dict[str, Any]:
    """Canonical payload: everything except signature and digest."""
    return {
        "schema": manifest.schema_version,
        "slice_id": manifest.slice_id,
        "origin": manifest.origin,
        "slice_digest": manifest.slice_digest,
        "weight_units": manifest.weight_units,
        "generator_id": manifest.generator_id,
        "generation": manifest.generation,
        "issued_at": manifest.issued_at,
        "authority_pubkey_hex": manifest.authority_pubkey_hex,
        "prev_digest": manifest.prev_digest,
    }


def issue_slice_manifest(
    *,
    slice_id: str,
    origin: str,
    slice_digest: str,
    weight_units: int,
    generator_id: str = "",
    generation: int = 0,
    issued_at: int,
    authority_secret: bytes,
    prev_digest: str = _GENESIS,
) -> DataSliceManifest:
    """Issue an authority-signed slice manifest and seal it.

    The signature is over the canonical payload (signature excluded
    from its own payload); the manifest digest is the JCS SHA-256 of
    the payload. The vendored ed25519 module takes a raw 32-byte seed.
    """
    if not isinstance(authority_secret, bytes) or len(authority_secret) != 32:
        raise SyntheticCapError("authority_secret must be a 32-byte seed")
    pubkey_hex = ed25519.public_key(authority_secret).hex()
    bare = DataSliceManifest(
        slice_id=slice_id,
        origin=origin,
        slice_digest=slice_digest,
        weight_units=weight_units,
        generator_id=generator_id,
        generation=generation,
        issued_at=issued_at,
        authority_pubkey_hex=pubkey_hex,
        signature_hex="00" * 64,  # placeholder (64 bytes of zero); replaced below
        prev_digest=prev_digest,
    )
    payload = _manifest_payload(bare)
    signature_hex = ed25519.sign(
        authority_secret, jcs_canonical_json(payload)
    ).hex()
    return DataSliceManifest(
        slice_id=bare.slice_id,
        origin=bare.origin,
        slice_digest=bare.slice_digest,
        weight_units=bare.weight_units,
        generator_id=bare.generator_id,
        generation=bare.generation,
        issued_at=bare.issued_at,
        authority_pubkey_hex=bare.authority_pubkey_hex,
        signature_hex=signature_hex,
        prev_digest=bare.prev_digest,
        manifest_digest=jcs_sha256_hex(payload),
    )


def verify_manifest_set(manifests: list[DataSliceManifest]) -> str | None:
    """Verify a manifest set's integrity, in log order.

    Returns a denial reason (``data.manifest_tampered`` /
    ``data.manifest_chain_broken`` / ``data.malformed``) or ``None``
    when the set verifies. Chain linkage must start at ``"genesis"``.
    """
    expected_prev = _GENESIS
    for manifest in manifests:
        try:
            _check_nonempty_str(manifest.slice_id, "slice_id")
            _check_origin(manifest.origin)
            _check_hex64(manifest.slice_digest, "slice_digest")
            _check_pubkey_hex(manifest.authority_pubkey_hex, "authority_pubkey_hex")
            _check_hex128(manifest.signature_hex, "signature_hex")
        except SyntheticCapError:
            return DENY_MALFORMED
        if not hmac.compare_digest(
            jcs_sha256_hex(_manifest_payload(manifest)), manifest.manifest_digest
        ):
            return DENY_MANIFEST_TAMPERED
        try:
            sig_ok = ed25519.verify(
                bytes.fromhex(manifest.authority_pubkey_hex),
                jcs_canonical_json(_manifest_payload(manifest)),
                bytes.fromhex(manifest.signature_hex),
            )
        except Exception:
            sig_ok = False
        if not sig_ok:
            return DENY_MANIFEST_TAMPERED
        if not hmac.compare_digest(manifest.prev_digest, expected_prev):
            return DENY_MANIFEST_CHAIN_BROKEN
        expected_prev = manifest.manifest_digest
    return None


# ---------------------------------------------------------------------------
# Ratio cap + recursion tripwire
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RatioVerdict:
    """Outcome of the synthetic-ratio gate for one training corpus."""

    allowed: bool
    reason: str
    synthetic_weight_units: int = 0
    total_weight_units: int = 0
    synthetic_fraction: float = 0.0
    recursion_detected: bool = False


def check_synthetic_ratio(
    manifests: list[DataSliceManifest],
    used_slice_ids: list[str],
    *,
    ratio_max: float = SYNTHETIC_RATIO_MAX,
) -> RatioVerdict:
    """Gate a training run on declared slice labels. Fail-closed.

    Checks, in order:

    1. **Manifest integrity** — the set verifies (see
       :func:`verify_manifest_set`); tampering or chain breaks deny
       before any ratio is computed.
    2. **Declaration** — every ``used_slice_ids`` entry must resolve
       to a manifest. An undeclared slice denies as
       ``data.undeclared_slice`` (there is no "presumed real" tier —
       unshowable provenance is not real provenance).
    3. **Recursion tripwire** — any synthetic slice at ``generation >=
       2`` denies as ``data.recursive_reuse``, regardless of the
       ratio. This is the RAG-collapse tripwire: recursive reuse is
       where the 2026 evidence locates collapse, so it fails closed
       even when the headline ratio looks fine.
    4. **Ratio cap** — synthetic weight fraction above ``ratio_max``
       denies as ``data.synthetic_cap_exceeded``. The fraction is
       weight over total weight; an empty (zero-weight) corpus denies
       as malformed rather than dividing by zero.

    The ratio is computed over *declared* labels. A liar can label
    synthetic output as real; this module cannot catch that — it
    guarantees that *declared* mixes stay inside the cap, and that
    the declaration is tamper-evident.
    """
    integrity = verify_manifest_set(manifests)
    if integrity is not None:
        return RatioVerdict(
            allowed=False,
            reason=f"slice-manifest set failed integrity: {integrity}",
        )
    index = {m.slice_id: m for m in manifests}
    undeclared = [sid for sid in used_slice_ids if sid not in index]
    if undeclared:
        return RatioVerdict(
            allowed=False,
            reason=(
                f"{DENY_UNDECLARED_SLICE}: training slice {undeclared[0]!r} "
                "has no manifest — undeclared slices are unverifiable "
                "lineage, not presumed real"
            ),
        )
    used = [index[sid] for sid in used_slice_ids]
    total = sum(m.weight_units for m in used)
    if total <= 0:
        return RatioVerdict(
            allowed=False,
            reason=f"{DENY_MALFORMED}: corpus has zero total weight units",
        )
    synthetic = [m for m in used if m.origin == SLICE_ORIGIN_SYNTHETIC]
    recursive = [m for m in synthetic if m.generation >= 2]
    if recursive:
        return RatioVerdict(
            allowed=False,
            reason=(
                f"{DENY_RECURSIVE_REUSE}: slice {recursive[0].slice_id!r} "
                f"is generation {recursive[0].generation} synthetic — "
                "synthetic trained on synthetic is the recursion where "
                "the 2026 collapse evidence (RAG Collapse, "
                "scientific-judgment collapse) bites; 'accumulate never "
                "replace'"
            ),
            synthetic_weight_units=sum(m.weight_units for m in synthetic),
            total_weight_units=total,
            synthetic_fraction=sum(m.weight_units for m in synthetic) / total,
            recursion_detected=True,
        )
    synthetic_weight = sum(m.weight_units for m in synthetic)
    fraction = synthetic_weight / total
    if fraction > ratio_max:
        return RatioVerdict(
            allowed=False,
            reason=(
                f"{DENY_RATIO_EXCEEDED}: synthetic fraction {fraction:.4f} "
                f"exceeds cap {ratio_max} — declare a smaller synthetic "
                "mix or keep original data in the loop"
            ),
            synthetic_weight_units=synthetic_weight,
            total_weight_units=total,
            synthetic_fraction=fraction,
        )
    return RatioVerdict(
        allowed=True,
        reason=(
            f"synthetic fraction {fraction:.4f} within cap {ratio_max}; "
            "no recursive reuse; all slices declared"
        ),
        synthetic_weight_units=synthetic_weight,
        total_weight_units=total,
        synthetic_fraction=fraction,
    )


def manifest_set_digest(manifests: list[DataSliceManifest]) -> str:
    """JCS SHA-256 over the ordered manifest digests.

    This is the value a ``model_lineage.LineageReceipt`` pins via its
    ``corpus_manifest_digest`` — the slice labels are "signed into" the
    model lineage through this digest (see :func:`pin_to_lineage`).
    """
    return jcs_sha256_hex([m.manifest_digest for m in manifests])


def pin_to_lineage(receipt: Any, manifests: list[DataSliceManifest]) -> RatioVerdict:
    """Bind the slice-manifest set into a model-lineage receipt.

    ``receipt`` is a ``model_lineage.LineageReceipt`` (kept unimported
    to avoid a hard import cycle at module scope — duck-typed on
    ``corpus_manifest_digest``). A mismatch classifies the lineage
    ``unverifiable-lineage`` (the 100th batch's binary tier): the
    lineage claims a corpus the labels do not describe.
    """
    digest = manifest_set_digest(manifests)
    claimed = getattr(receipt, "corpus_manifest_digest", None)
    if not isinstance(claimed, str) or not hmac.compare_digest(claimed, digest):
        return RatioVerdict(
            allowed=False,
            reason=(
                f"{DENY_LINEAGE_PIN_MISMATCH}: lineage receipt's "
                "corpus_manifest_digest does not match the slice-manifest "
                "set digest — the labels describe a different corpus; "
                "classifies unverifiable-lineage"
            ),
        )
    return RatioVerdict(
        allowed=True,
        reason="slice-manifest set digest matches the lineage receipt's corpus pin",
    )


# ---------------------------------------------------------------------------
# TDM opt-out: machine-readable only (Kneschke v. LAION)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TDMPVerdict:
    """Outcome of the TDM opt-out check for one source."""

    honored: bool  # True iff the opt-out is honored (source excluded)
    reason: str
    source_id: str = ""


def check_tdm_optout(source: Mapping[str, Any]) -> TDMPVerdict:
    """Honor a TDM opt-out only when it is machine-readable.

    ``source`` carries ``tdm_optout_machine_readable`` (robots.txt /
    TDMRep flag seen in the source manifest) and
    ``tdm_optout_tos_prose`` (prose opt-out language in terms of
    service). Per Kneschke v. LAION (OLG Hamburg, December 2025), only
    the machine-readable signal counts — ToS prose does not. This is
    the *rationale* for the check's shape, not legal advice.

    A prose-only opt-out does NOT deny the source; it is simply not
    honored *as an opt-out*. The asymmetry is deliberate: silently
    over-honoring would let a prose clause silently veto lawful
    corpora; silently under-honoring would discard real opt-outs.
    Either silence is a governance failure, so the verdict says
    exactly which signal was seen.
    """
    source_id = str(source.get("source_id", ""))
    machine = bool(source.get("tdm_optout_machine_readable", False))
    prose = bool(source.get("tdm_optout_tos_prose", False))
    if machine:
        return TDMPVerdict(
            honored=True,
            reason=(
                "TDM opt-out honored: machine-readable signal present "
                "(robots.txt / TDMRep) — the only signal Kneschke v. LAION "
                "counts"
            ),
            source_id=source_id,
        )
    if prose:
        return TDMPVerdict(
            honored=False,
            reason=(
                "TDM opt-out NOT honored: only ToS prose found — prose "
                "does not count per Kneschke v. LAION (OLG Hamburg, Dec "
                "2025); source remains usable. Rationale, not legal advice."
            ),
            source_id=source_id,
        )
    return TDMPVerdict(
        honored=False,
        reason="no TDM opt-out signal of any kind present",
        source_id=source_id,
    )


# ---------------------------------------------------------------------------
# Art. 50 gate: machine-readable AI-output marking (EU deployments)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Art50Verdict:
    """Outcome of the Art. 50 marking gate for one deployment."""

    allowed: bool
    reason: str
    classification: str  # "authoritative" | "non_authoritative"


def art50_gate(
    *,
    jurisdiction: str,
    machine_readable_marking: bool,
    placed_on_market_epoch_days: int,
    now_epoch_days: int,
) -> Art50Verdict:
    """Gate EU deployments on machine-readable AI-output marking.

    Art. 50 (in force 2026-08-02): AI-generated outputs must carry
    machine-readable marking. Systems already on the market get grace
    until 2026-12-02 (``ART50_GRACE_CUTOFF_EPOCH_DAYS``).

    * non-EU deployments: the gate does not apply (allowed,
      authoritative — nothing to mark under this rule).
    * EU, marking present: allowed, authoritative.
    * EU, marking missing, ``placed_on_market_epoch_days`` before the
      cutoff: allowed but classified ``non_authoritative`` — the
      time-gated grace exception for already-listed systems. There is
      no "partially marked" tier.
    * EU, marking missing, placed on market at/after the cutoff:
      denied as ``data.art50_marking_missing`` — fail closed, no
      degraded mode.
    """
    _check_jurisdiction(jurisdiction)
    _check_ts(placed_on_market_epoch_days, "placed_on_market_epoch_days")
    _check_ts(now_epoch_days, "now_epoch_days")
    if jurisdiction == JURISDICTION_NON_EU:
        return Art50Verdict(
            allowed=True,
            reason="Art. 50 gate does not apply outside the EU",
            classification=AUTHORITATIVE,
        )
    if machine_readable_marking:
        return Art50Verdict(
            allowed=True,
            reason="machine-readable AI-output marking present",
            classification=AUTHORITATIVE,
        )
    if placed_on_market_epoch_days < ART50_GRACE_CUTOFF_EPOCH_DAYS:
        return Art50Verdict(
            allowed=True,
            reason=(
                "marking missing but system placed on market before the "
                "2026-12-02 grace cutoff: time-gated exception applies — "
                "outputs classify non_authoritative until marked"
            ),
            classification=NON_AUTHORITATIVE,
        )
    return Art50Verdict(
        allowed=False,
        reason=(
            f"{DENY_ART50_MARKING_MISSING}: EU deployment placed on "
            "market at/after the 2026-12-02 grace cutoff with no "
            "machine-readable AI-output marking — fail closed"
        ),
        classification=NON_AUTHORITATIVE,
    )


# ---------------------------------------------------------------------------
# Art. 53 training-data summary receipt
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TrainingSummaryReceipt:
    """Art. 53-aligned training-data summary, verifiable offline.

    ``top_sources`` is the top-source template (Art. 53's "sufficiently
    detailed summary"): source ids ordered by weight, with per-source
    origin. The receipt digest pins the summary so a later verifier
    can confirm the training summary describes the corpus the model
    actually trained on (checked via ``pin_to_lineage()`` alongside
    the 100th-batch lineage receipt).
    """

    model_id: str
    top_sources: tuple[tuple[str, str, int], ...]  # (source_id, origin, weight)
    synthetic_fraction: float
    slice_manifest_digest: str
    issued_at: int
    receipt_digest: str = ""
    schema_version: str = SYNTHETIC_CAP_SCHEMA_VERSION


def training_summary_receipt(
    *,
    model_id: str,
    manifests: list[DataSliceManifest],
    top_n: int = 10,
    issued_at: int,
) -> TrainingSummaryReceipt:
    """Build the Art. 53 training-data summary receipt.

    Sources are ranked by declared weight (ties broken by slice_id for
    determinism); the summary pins ``slice_manifest_digest`` so it is
    checkable against the same digest a lineage receipt carries.
    """
    _check_nonempty_str(model_id, "model_id")
    _check_ts(issued_at, "issued_at")
    if not isinstance(top_n, int) or top_n < 1:
        raise SyntheticCapError("top_n must be a positive int")
    ranked = sorted(
        manifests, key=lambda m: (-m.weight_units, m.slice_id)
    )[:top_n]
    top_sources = tuple(
        (m.slice_id, m.origin, m.weight_units) for m in ranked
    )
    total = sum(m.weight_units for m in manifests)
    synthetic = sum(
        m.weight_units
        for m in manifests
        if m.origin == SLICE_ORIGIN_SYNTHETIC
    )
    fraction = (synthetic / total) if total > 0 else 0.0
    bare = TrainingSummaryReceipt(
        model_id=model_id,
        top_sources=top_sources,
        synthetic_fraction=fraction,
        slice_manifest_digest=manifest_set_digest(manifests),
        issued_at=issued_at,
    )
    payload = {
        "schema": bare.schema_version,
        "model_id": bare.model_id,
        "top_sources": [list(t) for t in bare.top_sources],
        "synthetic_fraction": bare.synthetic_fraction,
        "slice_manifest_digest": bare.slice_manifest_digest,
        "issued_at": bare.issued_at,
    }
    return TrainingSummaryReceipt(
        model_id=bare.model_id,
        top_sources=bare.top_sources,
        synthetic_fraction=bare.synthetic_fraction,
        slice_manifest_digest=bare.slice_manifest_digest,
        issued_at=bare.issued_at,
        receipt_digest=jcs_sha256_hex(payload),
    )


def verify_training_summary(
    receipt: TrainingSummaryReceipt, manifests: list[DataSliceManifest]
) -> bool:
    """Recompute the summary receipt's digest and re-check its pins.

    Returns False on any mismatch (digest, manifest digest, top-source
    ranking, synthetic fraction) — verification failures are booleans
    here because the receipt is *evidence*, not a gate verdict.
    """
    try:
        ranked = sorted(
            manifests, key=lambda m: (-m.weight_units, m.slice_id)
        )[: len(receipt.top_sources)]
        expected_sources = tuple(
            (m.slice_id, m.origin, m.weight_units) for m in ranked
        )
        if expected_sources != receipt.top_sources:
            return False
        total = sum(m.weight_units for m in manifests)
        synthetic = sum(
            m.weight_units
            for m in manifests
            if m.origin == SLICE_ORIGIN_SYNTHETIC
        )
        fraction = (synthetic / total) if total > 0 else 0.0
        if abs(fraction - receipt.synthetic_fraction) > 1e-12:
            return False
        if not hmac.compare_digest(
            receipt.slice_manifest_digest, manifest_set_digest(manifests)
        ):
            return False
        payload = {
            "schema": receipt.schema_version,
            "model_id": receipt.model_id,
            "top_sources": [list(t) for t in receipt.top_sources],
            "synthetic_fraction": receipt.synthetic_fraction,
            "slice_manifest_digest": receipt.slice_manifest_digest,
            "issued_at": receipt.issued_at,
        }
        return hmac.compare_digest(
            jcs_sha256_hex(payload), receipt.receipt_digest
        )
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Audit event shapes (for audit_chain)
# ---------------------------------------------------------------------------


def synthetic_cap_audit_event(
    *, kind: str, detail: str, model_id: str = ""
) -> dict[str, Any]:
    """Build the audit payload for a synthetic-cap decision.

    ``kind`` is one of ``data.ratio_denied`` / ``data.recursion_denied`` /
    ``data.undeclared_slice_denied`` / ``data.art50_marking_missing`` /
    ``data.ratio_allowed``. The caller chains it via ``audit_chain``
    like any other runtime event.
    """
    if kind not in (
        "data.ratio_denied",
        "data.recursion_denied",
        "data.undeclared_slice_denied",
        "data.art50_marking_missing",
        "data.ratio_allowed",
    ):
        raise SyntheticCapError(f"unknown synthetic-cap audit kind {kind!r}")
    return {
        "event_type": kind,
        "producer": "runtime",
        "model_id": model_id,
        "detail": detail,
    }


__all__ = [
    "ART50_GRACE_CUTOFF_EPOCH_DAYS",
    "ART50_IN_FORCE_EPOCH_DAYS",
    "AUTHORITATIVE",
    "DENY_ART50_MARKING_MISSING",
    "DENY_LINEAGE_PIN_MISMATCH",
    "DENY_MALFORMED",
    "DENY_MANIFEST_CHAIN_BROKEN",
    "DENY_MANIFEST_TAMPERED",
    "DENY_RATIO_EXCEEDED",
    "DENY_RECURSIVE_REUSE",
    "DENY_UNDECLARED_SLICE",
    "JURISDICTION_EU",
    "JURISDICTION_NON_EU",
    "JURISDICTIONS",
    "NON_AUTHORITATIVE",
    "SLICE_ORIGIN_REAL",
    "SLICE_ORIGIN_SYNTHETIC",
    "SLICE_ORIGINS",
    "SYNTHETIC_CAP_SCHEMA_VERSION",
    "SYNTHETIC_RATIO_MAX",
    "Art50Verdict",
    "DataSliceManifest",
    "RatioVerdict",
    "SyntheticCapError",
    "TDMPVerdict",
    "TrainingSummaryReceipt",
    "art50_gate",
    "check_synthetic_ratio",
    "check_tdm_optout",
    "issue_slice_manifest",
    "manifest_set_digest",
    "pin_to_lineage",
    "synthetic_cap_audit_event",
    "training_summary_receipt",
    "verify_manifest_set",
    "verify_training_summary",
]
