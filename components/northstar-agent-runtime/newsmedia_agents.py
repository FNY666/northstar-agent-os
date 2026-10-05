"""News-media AI discipline (one-hundred-fifty-eighth batch).

Absorbs the 2026 AI-newsroom thread (mechanism ideas only, honestly
scoped):

* **AP July 2026 standards** — the most detailed newsroom AI policy on
  record: AI cannot replace reporting, sourcing, editorial judgment,
  or verification; generative AI still prohibited for creating /
  altering / enhancing news photography; disclosure required when
  generative AI plays a "material role". These become deterministic
  gates here, not guidance prose.
* **Brennan Center Aug 2026** — tested 6 chatbots on election
  misinformation ahead of the 2026 US midterms: ~half of responses
  had citation problems, 1/3 factual errors, all cited non-existent
  sources at some point. Citation integrity and verification depth
  are therefore pinned per claim tier, with hallucinated citations
  a whole-class refusal.
* **Korea AI-fake disasters** (Jan/Aug 2026) — Kamchatka "snow
  covering a 10-story building" and Nepal flood before/after photos
  broadcast as real by real newsrooms. External visual material
  binds source screening; unsourced visuals deny.
* **Pink slime** — NewsGuard Sept 2026: AI chatbots cited partisan
  fake-local-news sites in 48.2% of responses; 1,179 such outlets
  now outnumber the 937 US dailies. Funding-disclosure receipts
  bind partisan funding; undisclosed outlets deny.
* **Anthropic $1.5B settlement** (July 2026) — ~$3,000/work:
  legally-purchased training data = fair use, a 7M-pirated-book
  library = not. Training/source corpora bind license chains;
  pirated-chain content denies.
* **Originator Profile (Japan)** — Yomiuri/Asahi-adopted
  cryptographic publisher IDs: OP Inspector certifies *provenance*,
  explicitly not accuracy. That split is the honest boundary of
  this module too.
* **Trust paradox** (Toff research) — readers demand disclosure but
  trust stories LESS after disclosure. Disclosure formats are
  therefore A/B probed for comprehension, not just attached.
* **Labor** — Le Monde: 1,331 media jobs cut since Jan 2026; entry-
  level copy-editor roles absorbed first. Newsroom AI adoption
  binds junior-role replacement monitoring on a clock.
* **Election windows** — Korea bans AI video electioneering from
  90 days before election day; National Election Commission
  deepfake deletion requests hit ~10,000 (27x the 2024 general).
  Source-freeze windows bind covered claim tiers during elections.

Northstar mapping:

* ``SourceReceipt`` / ``check_attribution()`` — Originator-Profile-
  style issuer-identity binding per story. Anonymous AI stories deny
  as ``newsmedia.unattributed``.
* ``MaterialityReceipt`` / ``DisclosureReceipt`` /
  ``check_materiality_disclosure()`` — material AI use must be
  disclosed within a pinned window; past-deadline denies as
  ``newsmedia.undisclosed_material_use``; ungraded materiality
  denies as ``newsmedia.ungraded_materiality`` (the AP lesson).
* ``VerificationReceipt`` / ``check_verification_depth()`` —
  verification depth pinned per claim tier (low/medium/high/
  election); below-tier depth or unresolvable sources deny as
  ``newsmedia.citation_failure`` (the Brennan lesson).
* ``MediaScreenReceipt`` / ``check_media_screen()`` — external
  image/video binds a screening method and authenticity result;
  unscreened external visuals deny as ``newsmedia.unsourced_visual``
  (the Korea lesson).
* ``CitationRecord`` / ``citation_integrity_gate()`` — every cited
  source must resolve; fabricated citations deny whole-class as
  ``newsmedia.fabricated_citation`` (the Asahi-Iwate lesson: a real
  outlet's name lending a hallucination false credibility).
* ``FundingDisclosureReceipt`` / ``check_funding_disclosure()`` —
  pink-slime-style partisan-funding disclosure; undisclosed denies
  as ``newsmedia.funding_undisclosed``.
* ``BylineReceipt`` / ``check_byline()`` — bylines bind verified
  humans; fictional bylines deny as ``newsmedia.fictional_byline``
  (the Brown Brothers nonexistent-NASA-engineer lesson).
* ``LicenseReceipt`` / ``check_license_chain()`` — training/source
  corpora bind license chains; pirated chains deny as
  ``newsmedia.illegitimate_source`` (the Anthropic-settlement
  lesson).
* ``PipelineClockReceipt`` / ``check_pipeline_clock()`` —
  newsroom AI adoption binds junior-role replacement monitoring;
  above-tolerance replacement triggers ``newsmedia.pipeline_review``.
* ``DisclosureProbeReceipt`` /
  ``check_disclosure_effectiveness()`` — disclosure formats A/B
  probed; comprehension below floor denies as
  ``newsmedia.disclosure_ineffective`` (the trust-paradox lesson:
  disclosure must be measured, not just attached).
* ``ElectionFreezeReceipt`` / ``ElectionOverrideReceipt`` /
  ``check_election_freeze()`` — election-period source freezes;
  covered-tier claims without an override deny as
  ``newsmedia.freeze_violation``.
* ``check_photo_integrity()`` — AI news photography refused
  whole-class as ``newsmedia.photo_generation_refused`` (the AP
  lesson).

Honest boundary: these receipts bind *declared* newsroom
discipline — a sealed source receipt proves provenance, never
accuracy (the Originator Profile split). A hallucination-free
citation registry only covers citations it was shown; a
funding-disclosure receipt only names declared funders. They do
not end slop and they do not restore trust; they force the
discipline to be on the record, hash-chained, and
authority-signed so a missing one is a deny, not a shrug.

Deterministic: no wall-clock reads (callers inject integer epoch
timestamps), JCS canonical hashing (95th batch), Ed25519 via the
vendored ``ed25519`` module (97th-batch pattern), digest
comparisons via :func:`hmac.compare_digest`.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from typing import Any, Mapping

import ed25519
from canonical_json import jcs_canonical_json, jcs_sha256_hex


NEWSMEDIA_SCHEMA_VERSION = "northstar.newsmedia.v1"

_GENESIS = "genesis"
_HEX64_LENGTH = 64

CLASS_AUTHORITATIVE = "authoritative"
CLASS_NON_AUTHORITATIVE = "non_authoritative"

#: Denial reason codes. All verdict reasons start with one of these.
DENY_UNATTRIBUTED = "newsmedia.unattributed"
DENY_UNDISCLOSED_MATERIAL = "newsmedia.undisclosed_material_use"
DENY_UNGRADED_MATERIALITY = "newsmedia.ungraded_materiality"
DENY_CITATION_FAILURE = "newsmedia.citation_failure"
DENY_UNSOURCED_VISUAL = "newsmedia.unsourced_visual"
DENY_FABRICATED_CITATION = "newsmedia.fabricated_citation"
DENY_FUNDING_UNDISCLOSED = "newsmedia.funding_undisclosed"
DENY_FICTIONAL_BYLINE = "newsmedia.fictional_byline"
DENY_ILLEGITIMATE_SOURCE = "newsmedia.illegitimate_source"
DENY_PIPELINE_REVIEW = "newsmedia.pipeline_review"
DENY_DISCLOSURE_INEFFECTIVE = "newsmedia.disclosure_ineffective"
DENY_FREEZE_VIOLATION = "newsmedia.freeze_violation"
DENY_PHOTO_GENERATION = "newsmedia.photo_generation_refused"
DENY_CHAIN_BROKEN = "newsmedia.chain_broken"
DENY_MALFORMED = "newsmedia.malformed_receipt"

#: How much AI did. Closed vocabulary.
AI_HUMAN = "human"
AI_ASSISTED = "ai_assisted"
AI_GENERATED = "ai_generated"
AI_INVOLVEMENT: tuple[str, ...] = (AI_HUMAN, AI_ASSISTED, AI_GENERATED)

#: Materiality axis (the AP "material role" lesson).
MATERIAL = "material"
NON_MATERIAL = "non_material"
MATERIALITIES: tuple[str, ...] = (MATERIAL, NON_MATERIAL)

#: Claim tiers. Higher tiers demand deeper verification.
TIER_LOW = "low"
TIER_MEDIUM = "medium"
TIER_HIGH = "high"
TIER_ELECTION = "election"
CLAIM_TIERS: tuple[str, ...] = (TIER_LOW, TIER_MEDIUM, TIER_HIGH, TIER_ELECTION)

#: Minimum independent verifications per tier (bench-calibrated
#: numbers, not laws of nature).
TIER_MIN_DEPTH: dict[str, int] = {
    TIER_LOW: 1,
    TIER_MEDIUM: 2,
    TIER_HIGH: 3,
    TIER_ELECTION: 4,
}

#: External visual media kinds (closed vocabulary).
KIND_PHOTO = "photo"
KIND_VIDEO = "video"
KIND_AUDIO = "audio"
KIND_GRAPHIC = "graphic"
MEDIA_KINDS: tuple[str, ...] = (KIND_PHOTO, KIND_VIDEO, KIND_AUDIO, KIND_GRAPHIC)

#: Screening methods for external media (closed vocabulary).
SCREEN_METHODS: tuple[str, ...] = (
    "c2pa",
    "op_inspector",
    "human_forensic",
    "registry_pin",
)

#: License-chain sources (closed vocabulary).
LIC_LICENSED = "licensed"
LIC_FAIR_USE = "fair_use_asserted"
LIC_PUBLIC_DOMAIN = "public_domain"
LIC_OPT_OUT = "opt_out_honored"
LIC_PIRATED = "pirated"
LICENSE_SOURCES: tuple[str, ...] = (
    LIC_LICENSED,
    LIC_FAIR_USE,
    LIC_PUBLIC_DOMAIN,
    LIC_OPT_OUT,
    LIC_PIRATED,
)

#: Partisan alignments for funding disclosure (closed vocabulary).
ALIGNMENTS: tuple[str, ...] = ("left", "right", "center", "unknown")

#: Disclosure formats under A/B probing (closed vocabulary).
DISCLOSURE_FORMATS: tuple[str, ...] = (
    "inline_banner",
    "byline_tag",
    "footer_note",
    "machine_metadata",
)

#: Material AI use must be disclosed within this window of
#: publication. Bench-calibrated, not a law of nature.
MATERIALITY_DISCLOSURE_WINDOW_S = 86_400

#: Disclosure-format comprehension floor (basis points).
MIN_DISCLOSURE_COMPREHENSION_BPS = 3000

#: Junior-role replacement above this (basis points of baseline)
#: triggers a pipeline review.
MAX_JUNIOR_REPLACEMENT_BPS = 2000


class NewsmediaError(ValueError):
    """A malformed newsmedia receipt or a programming error.

    Raised for structural problems (bad digests, unknown codes,
    broken chains, vocabulary violations). Verification *failures*
    (unattributed stories, undisclosed material use, fabricated
    citations) return a :class:`NewsmediaVerdict` with
    ``allowed=False`` instead — a failed claim is a verdict, a
    malformed receipt is a bug.
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
        raise NewsmediaError(f"{field_name} must be a 64-char lowercase hex digest")
    return value


def _check_nonempty_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise NewsmediaError(f"{field_name} must be a non-empty string")
    return value


def _check_ts(value: Any, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise NewsmediaError(f"{field_name} must be a non-negative int epoch")
    return value


def _check_secret(value: Any, field_name: str) -> bytes:
    # The vendored ed25519 module takes a raw 32-byte seed.
    if not isinstance(value, bytes) or len(value) != 32:
        raise NewsmediaError(f"{field_name} must be a 32-byte seed")
    return value


def _check_bps(value: Any, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0 or value > 10000:
        raise NewsmediaError(f"{field_name} must be basis points 0..10000")
    return value


def _check_vocab(value: Any, vocab: tuple[str, ...], field_name: str) -> str:
    if value not in vocab:
        raise NewsmediaError(f"{field_name} must be one of {vocab}, got {value!r}")
    return value


def _check_str_tuple(value: Any, field_name: str, *, allow_empty: bool = False) -> tuple[str, ...]:
    if not isinstance(value, (tuple, list)):
        raise NewsmediaError(f"{field_name} must be a tuple/list of strings")
    items = tuple(value)
    if not allow_empty and not items:
        raise NewsmediaError(f"{field_name} must be non-empty")
    for item in items:
        if not isinstance(item, str) or not item.strip():
            raise NewsmediaError(f"{field_name} entries must be non-empty strings")
    if len(set(items)) != len(items):
        raise NewsmediaError(f"{field_name} must not contain duplicates")
    return items


def _check_bool(value: Any, field_name: str) -> bool:
    if not isinstance(value, bool):
        raise NewsmediaError(f"{field_name} must be a bool")
    return value


def _verify_signature(pubkey_hex: str, payload: Mapping[str, Any], signature_hex: str) -> bool:
    # The vendored ed25519.verify() returns a bool and never raises;
    # the return value is authoritative (the old try/except-returns-True
    # pattern silently accepted tampered signatures).
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
    """Raise :class:`NewsmediaError` if a receipt log is tampered/broken."""
    expected_prev = _GENESIS
    for entry in log:
        if not hmac.compare_digest(entry.receipt_digest, jcs_sha256_hex(entry._payload())):
            raise NewsmediaError(
                f"{type_name} receipt {entry.receipt_id!r} digest does not recompute"
            )
        if not hmac.compare_digest(entry.prev_digest, expected_prev):
            raise NewsmediaError(
                f"{type_name} receipt {entry.receipt_id!r} chain break: "
                f"expected prev {expected_prev!r}"
            )
        if not _verify_signature(
            entry.authority_pubkey_hex, entry._payload(), entry.signature_hex
        ):
            raise NewsmediaError(
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
class NewsmediaVerdict:
    """Outcome of one news-media-discipline check."""

    allowed: bool
    reason: str
    classification: str = CLASS_NON_AUTHORITATIVE
    receipt_digest: str = ""


def _deny(code: str, detail: str) -> NewsmediaVerdict:
    return NewsmediaVerdict(
        allowed=False,
        reason=f"{code}: {detail}",
        classification=CLASS_NON_AUTHORITATIVE,
    )


def _allow(detail: str, receipt_digest: str = "") -> NewsmediaVerdict:
    return NewsmediaVerdict(
        allowed=True,
        reason=detail,
        classification=CLASS_AUTHORITATIVE,
        receipt_digest=receipt_digest,
    )


def newsmedia_audit_event(verdict: NewsmediaVerdict, *, action: str) -> dict[str, Any]:
    """Build the audit event for a news-media-discipline verdict."""
    return {
        "action": _check_nonempty_str(action, "action"),
        "verdict_allowed": verdict.allowed,
        "reason": verdict.reason,
        "classification": verdict.classification,
        "receipt_digest": verdict.receipt_digest,
        "schema_version": NEWSMEDIA_SCHEMA_VERSION,
    }

# ---------------------------------------------------------------------------
# Source (issuer-identity) receipts — the Originator Profile split
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SourceReceipt:
    """An Originator-Profile-style issuer identity bound to a story.

    ``issuer_id`` is the cryptographic publisher identity;
    ``ai_involvement`` grades how much AI did;
    ``disclosure_receipt_digest`` pins the disclosure receipt when
    AI played a material role (empty string otherwise). Provenance
    is bound, never accuracy: the receipt says *who* published, not
    that the story is true.
    """

    receipt_id: str
    story_id: str
    issuer_id: str
    issuer_pubkey_hex: str
    ai_involvement: str
    disclosure_receipt_digest: str
    expires_at: int
    authority_pubkey_hex: str
    prev_digest: str
    signature_hex: str = ""
    receipt_digest: str = ""

    def _payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "story_id": self.story_id,
            "issuer_id": self.issuer_id,
            "issuer_pubkey_hex": self.issuer_pubkey_hex,
            "ai_involvement": self.ai_involvement,
            "disclosure_receipt_digest": self.disclosure_receipt_digest,
            "expires_at": self.expires_at,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
            "schema_version": NEWSMEDIA_SCHEMA_VERSION,
        }


def source_receipt(
    *,
    receipt_id: str,
    story_id: str,
    issuer_id: str,
    issuer_pubkey_hex: str,
    ai_involvement: str,
    disclosure_receipt_digest: str = "",
    expires_at: int,
    authority_pubkey_hex: str,
    authority_secret: bytes,
    prev_digest: str,
) -> SourceReceipt:
    """Seal an issuer-identity binding for a story."""
    if disclosure_receipt_digest:
        _check_hex64(disclosure_receipt_digest, "disclosure_receipt_digest")
    receipt = SourceReceipt(
        receipt_id=_check_nonempty_str(receipt_id, "receipt_id"),
        story_id=_check_nonempty_str(story_id, "story_id"),
        issuer_id=_check_nonempty_str(issuer_id, "issuer_id"),
        issuer_pubkey_hex=_check_hex64(issuer_pubkey_hex, "issuer_pubkey_hex"),
        ai_involvement=_check_vocab(ai_involvement, AI_INVOLVEMENT, "ai_involvement"),
        disclosure_receipt_digest=disclosure_receipt_digest,
        expires_at=_check_ts(expires_at, "expires_at"),
        authority_pubkey_hex=_check_hex64(authority_pubkey_hex, "authority_pubkey_hex"),
        prev_digest=_check_nonempty_str(prev_digest, "prev_digest"),
    )
    secret = _check_secret(authority_secret, "authority_secret")
    if not hmac.compare_digest(
        authority_pubkey_hex,
        ed25519.public_key(secret).hex(),
    ):
        raise NewsmediaError("authority_pubkey_hex does not match authority_secret (no self-issuance)")
    return _seal(receipt, receipt._payload(), secret)


class SourceLog:
    """Hash-chained log of source receipts."""

    def __init__(self) -> None:
        self._log: list[SourceReceipt] = []

    def append(self, receipt: SourceReceipt) -> SourceReceipt:
        expected_prev = self._log[-1].receipt_digest if self._log else _GENESIS
        if not hmac.compare_digest(receipt.prev_digest, expected_prev):
            raise NewsmediaError(
                f"receipt {receipt.receipt_id!r} does not chain to the log tip"
            )
        self._log.append(receipt)
        return receipt

    def latest_for_story(self, story_id: str) -> SourceReceipt | None:
        for receipt in reversed(self._log):
            if hmac.compare_digest(receipt.story_id, story_id):
                return receipt
        return None

    def verify(self) -> None:
        _check_chain(self._log, "source")


def check_attribution(
    *, story_id: str, log: SourceLog, checked_at: int
) -> NewsmediaVerdict:
    """A story must carry a live issuer-identity receipt."""
    _check_nonempty_str(story_id, "story_id")
    checked_at = _check_ts(checked_at, "checked_at")
    receipt = log.latest_for_story(story_id)
    if receipt is None:
        return _deny(DENY_UNATTRIBUTED, f"story {story_id!r} has no issuer-identity receipt")
    if checked_at >= receipt.expires_at:
        return _deny(
            DENY_UNATTRIBUTED,
            f"story {story_id!r} issuer identity expired at {receipt.expires_at}",
        )
    return _allow(
        f"story {story_id!r} attributed to {receipt.issuer_id} ({receipt.ai_involvement})",
        receipt.receipt_digest,
    )


# ---------------------------------------------------------------------------
# Materiality grades + disclosure receipts — the AP "material role" clock
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MaterialityReceipt:
    """A materiality grade for a story's AI use, with a disclosure deadline."""

    receipt_id: str
    story_id: str
    materiality: str
    published_at: int
    disclosure_deadline: int
    authority_pubkey_hex: str
    prev_digest: str
    signature_hex: str = ""
    receipt_digest: str = ""

    def _payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "story_id": self.story_id,
            "materiality": self.materiality,
            "published_at": self.published_at,
            "disclosure_deadline": self.disclosure_deadline,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
            "schema_version": NEWSMEDIA_SCHEMA_VERSION,
        }


@dataclass(frozen=True)
class DisclosureReceipt:
    """A disclosure made for a story's AI use."""

    receipt_id: str
    story_id: str
    disclosed_at: int
    disclosure_format: str
    placement_digest: str
    authority_pubkey_hex: str
    prev_digest: str
    signature_hex: str = ""
    receipt_digest: str = ""

    def _payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "story_id": self.story_id,
            "disclosed_at": self.disclosed_at,
            "disclosure_format": self.disclosure_format,
            "placement_digest": self.placement_digest,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
            "schema_version": NEWSMEDIA_SCHEMA_VERSION,
        }


def _issue_materiality_or_disclosure(cls: Any, **kwargs: Any) -> Any:
    secret = _check_secret(kwargs.pop("authority_secret"), "authority_secret")
    receipt = cls(**kwargs)
    if not hmac.compare_digest(
        receipt.authority_pubkey_hex,
        ed25519.public_key(secret).hex(),
    ):
        raise NewsmediaError("authority_pubkey_hex does not match authority_secret (no self-issuance)")
    return _seal(receipt, receipt._payload(), secret)


def materiality_receipt(
    *,
    receipt_id: str,
    story_id: str,
    materiality: str,
    published_at: int,
    authority_pubkey_hex: str,
    authority_secret: bytes,
    prev_digest: str,
) -> MaterialityReceipt:
    """Grade a story's AI use and pin its disclosure deadline."""
    published_at = _check_ts(published_at, "published_at")
    return _issue_materiality_or_disclosure(
        MaterialityReceipt,
        receipt_id=_check_nonempty_str(receipt_id, "receipt_id"),
        story_id=_check_nonempty_str(story_id, "story_id"),
        materiality=_check_vocab(materiality, MATERIALITIES, "materiality"),
        published_at=published_at,
        disclosure_deadline=published_at + MATERIALITY_DISCLOSURE_WINDOW_S,
        authority_pubkey_hex=_check_hex64(authority_pubkey_hex, "authority_pubkey_hex"),
        prev_digest=_check_nonempty_str(prev_digest, "prev_digest"),
        authority_secret=authority_secret,
    )


def disclosure_receipt(
    *,
    receipt_id: str,
    story_id: str,
    disclosed_at: int,
    disclosure_format: str,
    placement_digest: str,
    authority_pubkey_hex: str,
    authority_secret: bytes,
    prev_digest: str,
) -> DisclosureReceipt:
    """Seal a disclosure made for a story's AI use."""
    return _issue_materiality_or_disclosure(
        DisclosureReceipt,
        receipt_id=_check_nonempty_str(receipt_id, "receipt_id"),
        story_id=_check_nonempty_str(story_id, "story_id"),
        disclosed_at=_check_ts(disclosed_at, "disclosed_at"),
        disclosure_format=_check_vocab(disclosure_format, DISCLOSURE_FORMATS, "disclosure_format"),
        placement_digest=_check_hex64(placement_digest, "placement_digest"),
        authority_pubkey_hex=_check_hex64(authority_pubkey_hex, "authority_pubkey_hex"),
        prev_digest=_check_nonempty_str(prev_digest, "prev_digest"),
        authority_secret=authority_secret,
    )


class MaterialityLog:
    """Hash-chained log of materiality + disclosure receipts."""

    def __init__(self) -> None:
        self._log: list[Any] = []

    def append(self, receipt: Any) -> Any:
        expected_prev = self._log[-1].receipt_digest if self._log else _GENESIS
        if not hmac.compare_digest(receipt.prev_digest, expected_prev):
            raise NewsmediaError(
                f"receipt {receipt.receipt_id!r} does not chain to the log tip"
            )
        self._log.append(receipt)
        return receipt

    def latest_materiality(self, story_id: str) -> MaterialityReceipt | None:
        for receipt in reversed(self._log):
            if isinstance(receipt, MaterialityReceipt) and hmac.compare_digest(
                receipt.story_id, story_id
            ):
                return receipt
        return None

    def disclosure_for_story(self, story_id: str) -> DisclosureReceipt | None:
        for receipt in reversed(self._log):
            if isinstance(receipt, DisclosureReceipt) and hmac.compare_digest(
                receipt.story_id, story_id
            ):
                return receipt
        return None

    def verify(self) -> None:
        _check_chain(self._log, "materiality")


def materiality_disclosure_clock(
    *, story_id: str, log: MaterialityLog, checked_at: int
) -> NewsmediaVerdict:
    """Material AI use must be disclosed within its pinned window."""
    _check_nonempty_str(story_id, "story_id")
    checked_at = _check_ts(checked_at, "checked_at")
    grade = log.latest_materiality(story_id)
    if grade is None:
        return _deny(
            DENY_UNGRADED_MATERIALITY,
            f"story {story_id!r} has no AI-use materiality grade",
        )
    if grade.materiality == NON_MATERIAL:
        return _allow(
            f"story {story_id!r} graded non-material; no disclosure required",
            grade.receipt_digest,
        )
    disclosure = log.disclosure_for_story(story_id)
    if disclosure is None:
        return _deny(
            DENY_UNDISCLOSED_MATERIAL,
            f"story {story_id!r} material AI use has no disclosure on record",
        )
    if disclosure.disclosed_at > grade.disclosure_deadline:
        return _deny(
            DENY_UNDISCLOSED_MATERIAL,
            f"story {story_id!r} disclosed at {disclosure.disclosed_at}, "
            f"deadline was {grade.disclosure_deadline}",
        )
    return _allow(
        f"story {story_id!r} material AI use disclosed within window",
        disclosure.receipt_digest,
    )


# ---------------------------------------------------------------------------
# Verification depth + citation integrity — the Brennan/Asahi lessons
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class VerificationReceipt:
    """Verification depth bound to a claim, per tier."""

    receipt_id: str
    claim_id: str
    story_id: str
    claim_tier: str
    verification_depth: int
    source_digests: tuple[str, ...]
    verified_at: int
    authority_pubkey_hex: str
    prev_digest: str
    signature_hex: str = ""
    receipt_digest: str = ""

    def _payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "claim_id": self.claim_id,
            "story_id": self.story_id,
            "claim_tier": self.claim_tier,
            "verification_depth": self.verification_depth,
            "source_digests": list(self.source_digests),
            "verified_at": self.verified_at,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
            "schema_version": NEWSMEDIA_SCHEMA_VERSION,
        }


def verification_receipt(
    *,
    receipt_id: str,
    claim_id: str,
    story_id: str,
    claim_tier: str,
    verification_depth: int,
    source_digests: tuple[str, ...] | list[str],
    verified_at: int,
    authority_pubkey_hex: str,
    authority_secret: bytes,
    prev_digest: str,
) -> VerificationReceipt:
    """Seal a verification-depth record for a claim."""
    if not isinstance(verification_depth, int) or isinstance(verification_depth, bool) or verification_depth < 0:
        raise NewsmediaError("verification_depth must be a non-negative int")
    digests = _check_str_tuple(source_digests, "source_digests", allow_empty=True)
    for digest in digests:
        _check_hex64(digest, "source_digests entry")
    receipt = VerificationReceipt(
        receipt_id=_check_nonempty_str(receipt_id, "receipt_id"),
        claim_id=_check_nonempty_str(claim_id, "claim_id"),
        story_id=_check_nonempty_str(story_id, "story_id"),
        claim_tier=_check_vocab(claim_tier, CLAIM_TIERS, "claim_tier"),
        verification_depth=verification_depth,
        source_digests=digests,
        verified_at=_check_ts(verified_at, "verified_at"),
        authority_pubkey_hex=_check_hex64(authority_pubkey_hex, "authority_pubkey_hex"),
        prev_digest=_check_nonempty_str(prev_digest, "prev_digest"),
    )
    secret = _check_secret(authority_secret, "authority_secret")
    if not hmac.compare_digest(
        authority_pubkey_hex,
        ed25519.public_key(secret).hex(),
    ):
        raise NewsmediaError("authority_pubkey_hex does not match authority_secret (no self-issuance)")
    return _seal(receipt, receipt._payload(), secret)


class VerificationLog:
    """Hash-chained log of verification receipts."""

    def __init__(self) -> None:
        self._log: list[VerificationReceipt] = []

    def append(self, receipt: VerificationReceipt) -> VerificationReceipt:
        expected_prev = self._log[-1].receipt_digest if self._log else _GENESIS
        if not hmac.compare_digest(receipt.prev_digest, expected_prev):
            raise NewsmediaError(
                f"receipt {receipt.receipt_id!r} does not chain to the log tip"
            )
        self._log.append(receipt)
        return receipt

    def latest_for_claim(self, claim_id: str) -> VerificationReceipt | None:
        for receipt in reversed(self._log):
            if hmac.compare_digest(receipt.claim_id, claim_id):
                return receipt
        return None

    def verify(self) -> None:
        _check_chain(self._log, "verification")


@dataclass(frozen=True)
class CitationRecord:
    """One cited source and whether it resolved to real output.

    The Asahi-Iwate lesson: a real outlet's name (Iwate Nippo) lent
    a hallucination false credibility. Every cited source must
    resolve; a non-resolving citation is fabrication.
    """

    record_id: str
    claim_id: str
    cited_outlet_id: str
    cited_url_digest: str
    resolved: bool
    resolution_note: str

    def _payload(self) -> dict[str, Any]:
        return {
            "record_id": self.record_id,
            "claim_id": self.claim_id,
            "cited_outlet_id": self.cited_outlet_id,
            "cited_url_digest": self.cited_url_digest,
            "resolved": self.resolved,
            "resolution_note": self.resolution_note,
            "schema_version": NEWSMEDIA_SCHEMA_VERSION,
        }


class CitationRegistry:
    """Registry of cited sources keyed by digest."""

    def __init__(self) -> None:
        self._records: dict[str, CitationRecord] = {}

    def register(self, record: CitationRecord) -> CitationRecord:
        record_id = _check_nonempty_str(record.record_id, "record.record_id")
        _check_nonempty_str(record.claim_id, "record.claim_id")
        _check_nonempty_str(record.cited_outlet_id, "record.cited_outlet_id")
        _check_hex64(record.cited_url_digest, "record.cited_url_digest")
        _check_bool(record.resolved, "record.resolved")
        if record_id in self._records:
            raise NewsmediaError(f"citation record {record_id!r} already registered")
        self._records[record_id] = record
        return record

    def resolves(self, url_digest: str) -> bool:
        for record in self._records.values():
            if hmac.compare_digest(record.cited_url_digest, url_digest) and record.resolved:
                return True
        return False


def verification_depth_gate(
    *, claim_id: str, vlog: VerificationLog, citations: CitationRegistry
) -> NewsmediaVerdict:
    """Verification depth must meet the claim tier; sources must resolve."""
    _check_nonempty_str(claim_id, "claim_id")
    receipt = vlog.latest_for_claim(claim_id)
    if receipt is None:
        return _deny(DENY_CITATION_FAILURE, f"claim {claim_id!r} has no verification receipt")
    minimum = TIER_MIN_DEPTH[receipt.claim_tier]
    if receipt.verification_depth < minimum:
        return _deny(
            DENY_CITATION_FAILURE,
            f"claim {claim_id!r} tier {receipt.claim_tier} needs depth {minimum}, "
            f"has {receipt.verification_depth}",
        )
    for digest in receipt.source_digests:
        if not citations.resolves(digest):
            return _deny(
                DENY_CITATION_FAILURE,
                f"claim {claim_id!r} cites unresolvable source {digest[:16]}...",
            )
    return _allow(
        f"claim {claim_id!r} verified at depth {receipt.verification_depth} "
        f"(tier {receipt.claim_tier} minimum {minimum})",
        receipt.receipt_digest,
    )


def citation_integrity_gate(
    *, claim_id: str, citations: CitationRegistry
) -> NewsmediaVerdict:
    """Hallucinated citations are refused whole-class."""
    _check_nonempty_str(claim_id, "claim_id")
    records = [r for r in citations._records.values() if r.claim_id == claim_id]
    if not records:
        return _deny(DENY_FABRICATED_CITATION, f"claim {claim_id!r} has no citation records")
    for record in records:
        if not record.resolved:
            return _deny(
                DENY_FABRICATED_CITATION,
                f"claim {claim_id!r} cites {record.cited_outlet_id} "
                f"{record.cited_url_digest[:16]}... which did not resolve",
            )
    return _allow(f"claim {claim_id!r} all {len(records)} citations resolved")

# ---------------------------------------------------------------------------
# External visual-media screening — the Korea faked-disaster lesson
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MediaScreenReceipt:
    """A screening record for external visual material.

    External (non-newsroom-produced) image/video/audio binds a
    screening method and an authenticity result. ``ai_generated``
    marks synthetic content; news photography that is AI-generated
    is refused whole-class by :func:`check_photo_integrity`.
    """

    receipt_id: str
    media_id: str
    story_id: str
    media_kind: str
    external: bool
    ai_generated: bool
    screening_method: str
    authentic: bool
    screened_at: int
    authority_pubkey_hex: str
    prev_digest: str
    signature_hex: str = ""
    receipt_digest: str = ""

    def _payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "media_id": self.media_id,
            "story_id": self.story_id,
            "media_kind": self.media_kind,
            "external": self.external,
            "ai_generated": self.ai_generated,
            "screening_method": self.screening_method,
            "authentic": self.authentic,
            "screened_at": self.screened_at,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
            "schema_version": NEWSMEDIA_SCHEMA_VERSION,
        }


def media_screen_receipt(
    *,
    receipt_id: str,
    media_id: str,
    story_id: str,
    media_kind: str,
    external: bool,
    ai_generated: bool,
    screening_method: str,
    authentic: bool,
    screened_at: int,
    authority_pubkey_hex: str,
    authority_secret: bytes,
    prev_digest: str,
) -> MediaScreenReceipt:
    """Seal a screening record for external visual material."""
    receipt = MediaScreenReceipt(
        receipt_id=_check_nonempty_str(receipt_id, "receipt_id"),
        media_id=_check_nonempty_str(media_id, "media_id"),
        story_id=_check_nonempty_str(story_id, "story_id"),
        media_kind=_check_vocab(media_kind, MEDIA_KINDS, "media_kind"),
        external=_check_bool(external, "external"),
        ai_generated=_check_bool(ai_generated, "ai_generated"),
        screening_method=_check_vocab(screening_method, SCREEN_METHODS, "screening_method"),
        authentic=_check_bool(authentic, "authentic"),
        screened_at=_check_ts(screened_at, "screened_at"),
        authority_pubkey_hex=_check_hex64(authority_pubkey_hex, "authority_pubkey_hex"),
        prev_digest=_check_nonempty_str(prev_digest, "prev_digest"),
    )
    secret = _check_secret(authority_secret, "authority_secret")
    if not hmac.compare_digest(
        authority_pubkey_hex,
        ed25519.public_key(secret).hex(),
    ):
        raise NewsmediaError("authority_pubkey_hex does not match authority_secret (no self-issuance)")
    return _seal(receipt, receipt._payload(), secret)


class MediaScreenLog:
    """Hash-chained log of media-screening receipts."""

    def __init__(self) -> None:
        self._log: list[MediaScreenReceipt] = []

    def append(self, receipt: MediaScreenReceipt) -> MediaScreenReceipt:
        expected_prev = self._log[-1].receipt_digest if self._log else _GENESIS
        if not hmac.compare_digest(receipt.prev_digest, expected_prev):
            raise NewsmediaError(
                f"receipt {receipt.receipt_id!r} does not chain to the log tip"
            )
        self._log.append(receipt)
        return receipt

    def latest_for_media(self, media_id: str) -> MediaScreenReceipt | None:
        for receipt in reversed(self._log):
            if hmac.compare_digest(receipt.media_id, media_id):
                return receipt
        return None

    def verify(self) -> None:
        _check_chain(self._log, "media-screen")


def external_media_screen(
    *, media_id: str, external: bool, log: MediaScreenLog
) -> NewsmediaVerdict:
    """External visual material must bind a screening record."""
    _check_nonempty_str(media_id, "media_id")
    external = _check_bool(external, "external")
    if not external:
        return _allow(f"media {media_id!r} is newsroom-produced; no external screening needed")
    receipt = log.latest_for_media(media_id)
    if receipt is None:
        return _deny(
            DENY_UNSOURCED_VISUAL,
            f"external media {media_id!r} has no screening record",
        )
    if not receipt.authentic:
        return _deny(
            DENY_UNSOURCED_VISUAL,
            f"external media {media_id!r} failed authenticity screening "
            f"({receipt.screening_method})",
        )
    return _allow(
        f"external media {media_id!r} screened authentic via {receipt.screening_method}",
        receipt.receipt_digest,
    )


def check_photo_integrity(
    *, media_id: str, log: MediaScreenLog
) -> NewsmediaVerdict:
    """AI news photography is refused whole-class (the AP lesson)."""
    _check_nonempty_str(media_id, "media_id")
    receipt = log.latest_for_media(media_id)
    if receipt is None:
        return _allow(f"media {media_id!r} has no screening record; photo ban not triggered")
    if receipt.media_kind == KIND_PHOTO and receipt.ai_generated:
        return _deny(
            DENY_PHOTO_GENERATION,
            f"media {media_id!r} is AI-generated news photography: refused whole-class",
        )
    return _allow(f"media {media_id!r} is not AI-generated news photography", receipt.receipt_digest)


# ---------------------------------------------------------------------------
# Funding disclosure — the pink-slime lesson
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FundingDisclosureReceipt:
    """Partisan-funding disclosure bound to an outlet."""

    receipt_id: str
    outlet_id: str
    funders: tuple[str, ...]
    partisan_alignment: str
    disclosed_at: int
    authority_pubkey_hex: str
    prev_digest: str
    signature_hex: str = ""
    receipt_digest: str = ""

    def _payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "outlet_id": self.outlet_id,
            "funders": list(self.funders),
            "partisan_alignment": self.partisan_alignment,
            "disclosed_at": self.disclosed_at,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
            "schema_version": NEWSMEDIA_SCHEMA_VERSION,
        }


def funding_disclosure_receipt(
    *,
    receipt_id: str,
    outlet_id: str,
    funders: tuple[str, ...] | list[str],
    partisan_alignment: str,
    disclosed_at: int,
    authority_pubkey_hex: str,
    authority_secret: bytes,
    prev_digest: str,
) -> FundingDisclosureReceipt:
    """Seal a partisan-funding disclosure for an outlet."""
    receipt = FundingDisclosureReceipt(
        receipt_id=_check_nonempty_str(receipt_id, "receipt_id"),
        outlet_id=_check_nonempty_str(outlet_id, "outlet_id"),
        funders=_check_str_tuple(funders, "funders"),
        partisan_alignment=_check_vocab(partisan_alignment, ALIGNMENTS, "partisan_alignment"),
        disclosed_at=_check_ts(disclosed_at, "disclosed_at"),
        authority_pubkey_hex=_check_hex64(authority_pubkey_hex, "authority_pubkey_hex"),
        prev_digest=_check_nonempty_str(prev_digest, "prev_digest"),
    )
    secret = _check_secret(authority_secret, "authority_secret")
    if not hmac.compare_digest(
        authority_pubkey_hex,
        ed25519.public_key(secret).hex(),
    ):
        raise NewsmediaError("authority_pubkey_hex does not match authority_secret (no self-issuance)")
    return _seal(receipt, receipt._payload(), secret)


class FundingLog:
    """Hash-chained log of funding-disclosure receipts."""

    def __init__(self) -> None:
        self._log: list[FundingDisclosureReceipt] = []

    def append(self, receipt: FundingDisclosureReceipt) -> FundingDisclosureReceipt:
        expected_prev = self._log[-1].receipt_digest if self._log else _GENESIS
        if not hmac.compare_digest(receipt.prev_digest, expected_prev):
            raise NewsmediaError(
                f"receipt {receipt.receipt_id!r} does not chain to the log tip"
            )
        self._log.append(receipt)
        return receipt

    def latest_for_outlet(self, outlet_id: str) -> FundingDisclosureReceipt | None:
        for receipt in reversed(self._log):
            if hmac.compare_digest(receipt.outlet_id, outlet_id):
                return receipt
        return None

    def verify(self) -> None:
        _check_chain(self._log, "funding")


def political_funding_disclosure(
    *, outlet_id: str, log: FundingLog
) -> NewsmediaVerdict:
    """Outlets must carry a funding-disclosure receipt on record."""
    _check_nonempty_str(outlet_id, "outlet_id")
    receipt = log.latest_for_outlet(outlet_id)
    if receipt is None:
        return _deny(
            DENY_FUNDING_UNDISCLOSED,
            f"outlet {outlet_id!r} has no funding-disclosure receipt",
        )
    return _allow(
        f"outlet {outlet_id!r} funding disclosed "
        f"({len(receipt.funders)} funders, alignment {receipt.partisan_alignment})",
        receipt.receipt_digest,
    )


# ---------------------------------------------------------------------------
# Byline verification — the fictional-byline lesson
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BylineReceipt:
    """A byline bound to a verified human."""

    receipt_id: str
    story_id: str
    byline_name: str
    human_verified: bool
    identity_digest: str
    authority_pubkey_hex: str
    prev_digest: str
    signature_hex: str = ""
    receipt_digest: str = ""

    def _payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "story_id": self.story_id,
            "byline_name": self.byline_name,
            "human_verified": self.human_verified,
            "identity_digest": self.identity_digest,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
            "schema_version": NEWSMEDIA_SCHEMA_VERSION,
        }


def byline_receipt(
    *,
    receipt_id: str,
    story_id: str,
    byline_name: str,
    human_verified: bool,
    identity_digest: str,
    authority_pubkey_hex: str,
    authority_secret: bytes,
    prev_digest: str,
) -> BylineReceipt:
    """Bind a story byline to a verified human."""
    receipt = BylineReceipt(
        receipt_id=_check_nonempty_str(receipt_id, "receipt_id"),
        story_id=_check_nonempty_str(story_id, "story_id"),
        byline_name=_check_nonempty_str(byline_name, "byline_name"),
        human_verified=_check_bool(human_verified, "human_verified"),
        identity_digest=_check_hex64(identity_digest, "identity_digest"),
        authority_pubkey_hex=_check_hex64(authority_pubkey_hex, "authority_pubkey_hex"),
        prev_digest=_check_nonempty_str(prev_digest, "prev_digest"),
    )
    secret = _check_secret(authority_secret, "authority_secret")
    if not hmac.compare_digest(
        authority_pubkey_hex,
        ed25519.public_key(secret).hex(),
    ):
        raise NewsmediaError("authority_pubkey_hex does not match authority_secret (no self-issuance)")
    return _seal(receipt, receipt._payload(), secret)


class BylineLog:
    """Hash-chained log of byline receipts."""

    def __init__(self) -> None:
        self._log: list[BylineReceipt] = []

    def append(self, receipt: BylineReceipt) -> BylineReceipt:
        expected_prev = self._log[-1].receipt_digest if self._log else _GENESIS
        if not hmac.compare_digest(receipt.prev_digest, expected_prev):
            raise NewsmediaError(
                f"receipt {receipt.receipt_id!r} does not chain to the log tip"
            )
        self._log.append(receipt)
        return receipt

    def latest_for_story(self, story_id: str) -> BylineReceipt | None:
        for receipt in reversed(self._log):
            if hmac.compare_digest(receipt.story_id, story_id):
                return receipt
        return None

    def verify(self) -> None:
        _check_chain(self._log, "byline")


def byline_verification(
    *, story_id: str, log: BylineLog
) -> NewsmediaVerdict:
    """Bylines must bind to a verified human."""
    _check_nonempty_str(story_id, "story_id")
    receipt = log.latest_for_story(story_id)
    if receipt is None:
        return _deny(DENY_FICTIONAL_BYLINE, f"story {story_id!r} has no byline receipt")
    if not receipt.human_verified:
        return _deny(
            DENY_FICTIONAL_BYLINE,
            f"story {story_id!r} byline {receipt.byline_name!r} is not human-verified",
        )
    return _allow(
        f"story {story_id!r} byline {receipt.byline_name!r} human-verified",
        receipt.receipt_digest,
    )


# ---------------------------------------------------------------------------
# License chains — the Anthropic-settlement lesson
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LicenseReceipt:
    """A license chain bound to a training/source corpus.

    The settlement lesson: source of training data matters as much
    as use. A ``pirated`` chain denies whole-class.
    """

    receipt_id: str
    corpus_id: str
    license_source: str
    chain_digest: str
    checked_at: int
    authority_pubkey_hex: str
    prev_digest: str
    signature_hex: str = ""
    receipt_digest: str = ""

    def _payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "corpus_id": self.corpus_id,
            "license_source": self.license_source,
            "chain_digest": self.chain_digest,
            "checked_at": self.checked_at,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
            "schema_version": NEWSMEDIA_SCHEMA_VERSION,
        }


def license_chain_receipt(
    *,
    receipt_id: str,
    corpus_id: str,
    license_source: str,
    chain_digest: str,
    checked_at: int,
    authority_pubkey_hex: str,
    authority_secret: bytes,
    prev_digest: str,
) -> LicenseReceipt:
    """Seal a license chain for a training/source corpus."""
    receipt = LicenseReceipt(
        receipt_id=_check_nonempty_str(receipt_id, "receipt_id"),
        corpus_id=_check_nonempty_str(corpus_id, "corpus_id"),
        license_source=_check_vocab(license_source, LICENSE_SOURCES, "license_source"),
        chain_digest=_check_hex64(chain_digest, "chain_digest"),
        checked_at=_check_ts(checked_at, "checked_at"),
        authority_pubkey_hex=_check_hex64(authority_pubkey_hex, "authority_pubkey_hex"),
        prev_digest=_check_nonempty_str(prev_digest, "prev_digest"),
    )
    secret = _check_secret(authority_secret, "authority_secret")
    if not hmac.compare_digest(
        authority_pubkey_hex,
        ed25519.public_key(secret).hex(),
    ):
        raise NewsmediaError("authority_pubkey_hex does not match authority_secret (no self-issuance)")
    return _seal(receipt, receipt._payload(), secret)


class LicenseLog:
    """Hash-chained log of license receipts."""

    def __init__(self) -> None:
        self._log: list[LicenseReceipt] = []

    def append(self, receipt: LicenseReceipt) -> LicenseReceipt:
        expected_prev = self._log[-1].receipt_digest if self._log else _GENESIS
        if not hmac.compare_digest(receipt.prev_digest, expected_prev):
            raise NewsmediaError(
                f"receipt {receipt.receipt_id!r} does not chain to the log tip"
            )
        self._log.append(receipt)
        return receipt

    def latest_for_corpus(self, corpus_id: str) -> LicenseReceipt | None:
        for receipt in reversed(self._log):
            if hmac.compare_digest(receipt.corpus_id, corpus_id):
                return receipt
        return None

    def verify(self) -> None:
        _check_chain(self._log, "license")


def check_license_chain(
    *, corpus_id: str, log: LicenseLog
) -> NewsmediaVerdict:
    """Training/source corpora must bind a clean license chain."""
    _check_nonempty_str(corpus_id, "corpus_id")
    receipt = log.latest_for_corpus(corpus_id)
    if receipt is None:
        return _deny(
            DENY_ILLEGITIMATE_SOURCE,
            f"corpus {corpus_id!r} has no license-chain receipt",
        )
    if receipt.license_source == LIC_PIRATED:
        return _deny(
            DENY_ILLEGITIMATE_SOURCE,
            f"corpus {corpus_id!r} license chain is pirated: refused whole-class",
        )
    return _allow(
        f"corpus {corpus_id!r} license chain {receipt.license_source}",
        receipt.receipt_digest,
    )

# ---------------------------------------------------------------------------
# Junior-role pipeline clock — the Le Monde hollowing-out lesson
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PipelineClockReceipt:
    """Junior-role replacement monitoring bound to a newsroom."""

    receipt_id: str
    newsroom_id: str
    baseline_junior: int
    current_junior: int
    reviewed_at: int
    next_review_due: int
    authority_pubkey_hex: str
    prev_digest: str
    signature_hex: str = ""
    receipt_digest: str = ""

    def _payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "newsroom_id": self.newsroom_id,
            "baseline_junior": self.baseline_junior,
            "current_junior": self.current_junior,
            "reviewed_at": self.reviewed_at,
            "next_review_due": self.next_review_due,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
            "schema_version": NEWSMEDIA_SCHEMA_VERSION,
        }


def _check_nonneg_int(value: Any, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise NewsmediaError(f"{field_name} must be a non-negative int")
    return value


def pipeline_clock_receipt(
    *,
    receipt_id: str,
    newsroom_id: str,
    baseline_junior: int,
    current_junior: int,
    reviewed_at: int,
    next_review_due: int,
    authority_pubkey_hex: str,
    authority_secret: bytes,
    prev_digest: str,
) -> PipelineClockReceipt:
    """Seal a junior-role pipeline monitoring record."""
    baseline_junior = _check_nonneg_int(baseline_junior, "baseline_junior")
    current_junior = _check_nonneg_int(current_junior, "current_junior")
    if baseline_junior == 0:
        raise NewsmediaError("baseline_junior must be positive")
    reviewed_at = _check_ts(reviewed_at, "reviewed_at")
    next_review_due = _check_ts(next_review_due, "next_review_due")
    if next_review_due <= reviewed_at:
        raise NewsmediaError("next_review_due must be after reviewed_at")
    receipt = PipelineClockReceipt(
        receipt_id=_check_nonempty_str(receipt_id, "receipt_id"),
        newsroom_id=_check_nonempty_str(newsroom_id, "newsroom_id"),
        baseline_junior=baseline_junior,
        current_junior=current_junior,
        reviewed_at=reviewed_at,
        next_review_due=next_review_due,
        authority_pubkey_hex=_check_hex64(authority_pubkey_hex, "authority_pubkey_hex"),
        prev_digest=_check_nonempty_str(prev_digest, "prev_digest"),
    )
    secret = _check_secret(authority_secret, "authority_secret")
    if not hmac.compare_digest(
        authority_pubkey_hex,
        ed25519.public_key(secret).hex(),
    ):
        raise NewsmediaError("authority_pubkey_hex does not match authority_secret (no self-issuance)")
    return _seal(receipt, receipt._payload(), secret)


class PipelineLog:
    """Hash-chained log of pipeline-clock receipts."""

    def __init__(self) -> None:
        self._log: list[PipelineClockReceipt] = []

    def append(self, receipt: PipelineClockReceipt) -> PipelineClockReceipt:
        expected_prev = self._log[-1].receipt_digest if self._log else _GENESIS
        if not hmac.compare_digest(receipt.prev_digest, expected_prev):
            raise NewsmediaError(
                f"receipt {receipt.receipt_id!r} does not chain to the log tip"
            )
        self._log.append(receipt)
        return receipt

    def latest_for_newsroom(self, newsroom_id: str) -> PipelineClockReceipt | None:
        for receipt in reversed(self._log):
            if hmac.compare_digest(receipt.newsroom_id, newsroom_id):
                return receipt
        return None

    def verify(self) -> None:
        _check_chain(self._log, "pipeline")


def newsroom_job_pipeline_clock(
    *, newsroom_id: str, log: PipelineLog
) -> NewsmediaVerdict:
    """Junior-role replacement above tolerance triggers a review."""
    _check_nonempty_str(newsroom_id, "newsroom_id")
    receipt = log.latest_for_newsroom(newsroom_id)
    if receipt is None:
        return _deny(
            DENY_PIPELINE_REVIEW,
            f"newsroom {newsroom_id!r} has no pipeline-clock receipt",
        )
    reduction_bps = (receipt.baseline_junior - receipt.current_junior) * 10000 // receipt.baseline_junior
    if reduction_bps > MAX_JUNIOR_REPLACEMENT_BPS:
        return _deny(
            DENY_PIPELINE_REVIEW,
            f"newsroom {newsroom_id!r} junior roles down {reduction_bps} bps "
            f"(tolerance {MAX_JUNIOR_REPLACEMENT_BPS}): pipeline review required",
        )
    return _allow(
        f"newsroom {newsroom_id!r} junior-role reduction {reduction_bps} bps within tolerance",
        receipt.receipt_digest,
    )


# ---------------------------------------------------------------------------
# Disclosure-effectiveness probe — the trust-paradox lesson
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DisclosureProbeReceipt:
    """A comprehension probe for a disclosure format.

    The trust paradox: readers demand disclosure but trust less
    after it. Formats are A/B probed; comprehension below floor
    sends the format back for review.
    """

    receipt_id: str
    format_id: str
    comprehension_bps: int
    trust_delta_bps: int
    probed_at: int
    authority_pubkey_hex: str
    prev_digest: str
    signature_hex: str = ""
    receipt_digest: str = ""

    def _payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "format_id": self.format_id,
            "comprehension_bps": self.comprehension_bps,
            "trust_delta_bps": self.trust_delta_bps,
            "probed_at": self.probed_at,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
            "schema_version": NEWSMEDIA_SCHEMA_VERSION,
        }


def disclosure_probe_receipt(
    *,
    receipt_id: str,
    format_id: str,
    comprehension_bps: int,
    trust_delta_bps: int,
    probed_at: int,
    authority_pubkey_hex: str,
    authority_secret: bytes,
    prev_digest: str,
) -> DisclosureProbeReceipt:
    """Seal a disclosure-format comprehension probe."""
    if not isinstance(trust_delta_bps, int) or isinstance(trust_delta_bps, bool):
        raise NewsmediaError("trust_delta_bps must be an int (may be negative)")
    receipt = DisclosureProbeReceipt(
        receipt_id=_check_nonempty_str(receipt_id, "receipt_id"),
        format_id=_check_vocab(format_id, DISCLOSURE_FORMATS, "format_id"),
        comprehension_bps=_check_bps(comprehension_bps, "comprehension_bps"),
        trust_delta_bps=trust_delta_bps,
        probed_at=_check_ts(probed_at, "probed_at"),
        authority_pubkey_hex=_check_hex64(authority_pubkey_hex, "authority_pubkey_hex"),
        prev_digest=_check_nonempty_str(prev_digest, "prev_digest"),
    )
    secret = _check_secret(authority_secret, "authority_secret")
    if not hmac.compare_digest(
        authority_pubkey_hex,
        ed25519.public_key(secret).hex(),
    ):
        raise NewsmediaError("authority_pubkey_hex does not match authority_secret (no self-issuance)")
    return _seal(receipt, receipt._payload(), secret)


class ProbeLog:
    """Hash-chained log of disclosure-probe receipts."""

    def __init__(self) -> None:
        self._log: list[DisclosureProbeReceipt] = []

    def append(self, receipt: DisclosureProbeReceipt) -> DisclosureProbeReceipt:
        expected_prev = self._log[-1].receipt_digest if self._log else _GENESIS
        if not hmac.compare_digest(receipt.prev_digest, expected_prev):
            raise NewsmediaError(
                f"receipt {receipt.receipt_id!r} does not chain to the log tip"
            )
        self._log.append(receipt)
        return receipt

    def latest_for_format(self, format_id: str) -> DisclosureProbeReceipt | None:
        for receipt in reversed(self._log):
            if hmac.compare_digest(receipt.format_id, format_id):
                return receipt
        return None

    def verify(self) -> None:
        _check_chain(self._log, "probe")


def disclosure_effectiveness_probe(
    *, format_id: str, log: ProbeLog
) -> NewsmediaVerdict:
    """Disclosure formats must clear a comprehension floor."""
    _check_vocab(format_id, DISCLOSURE_FORMATS, "format_id")
    receipt = log.latest_for_format(format_id)
    if receipt is None:
        return _deny(
            DENY_DISCLOSURE_INEFFECTIVE,
            f"disclosure format {format_id!r} has no comprehension probe",
        )
    if receipt.comprehension_bps < MIN_DISCLOSURE_COMPREHENSION_BPS:
        return _deny(
            DENY_DISCLOSURE_INEFFECTIVE,
            f"disclosure format {format_id!r} comprehension "
            f"{receipt.comprehension_bps} bps below floor "
            f"{MIN_DISCLOSURE_COMPREHENSION_BPS}: format review required",
        )
    return _allow(
        f"disclosure format {format_id!r} comprehension "
        f"{receipt.comprehension_bps} bps clears floor",
        receipt.receipt_digest,
    )


# ---------------------------------------------------------------------------
# Election-period source freezes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ElectionFreezeReceipt:
    """A source-freeze window for an election."""

    receipt_id: str
    election_id: str
    freeze_start: int
    freeze_end: int
    covered_tiers: tuple[str, ...]
    authority_pubkey_hex: str
    prev_digest: str
    signature_hex: str = ""
    receipt_digest: str = ""

    def _payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "election_id": self.election_id,
            "freeze_start": self.freeze_start,
            "freeze_end": self.freeze_end,
            "covered_tiers": list(self.covered_tiers),
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
            "schema_version": NEWSMEDIA_SCHEMA_VERSION,
        }


@dataclass(frozen=True)
class ElectionOverrideReceipt:
    """An override permitting a covered-tier claim inside a freeze."""

    receipt_id: str
    election_id: str
    claim_id: str
    override_reason: str
    authority_pubkey_hex: str
    prev_digest: str
    signature_hex: str = ""
    receipt_digest: str = ""

    def _payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "election_id": self.election_id,
            "claim_id": self.claim_id,
            "override_reason": self.override_reason,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
            "schema_version": NEWSMEDIA_SCHEMA_VERSION,
        }


def _issue_freeze(cls: Any, **kwargs: Any) -> Any:
    secret = _check_secret(kwargs.pop("authority_secret"), "authority_secret")
    receipt = cls(**kwargs)
    if not hmac.compare_digest(
        receipt.authority_pubkey_hex,
        ed25519.public_key(secret).hex(),
    ):
        raise NewsmediaError("authority_pubkey_hex does not match authority_secret (no self-issuance)")
    return _seal(receipt, receipt._payload(), secret)


def election_source_freeze(
    *,
    receipt_id: str,
    election_id: str,
    freeze_start: int,
    freeze_end: int,
    covered_tiers: tuple[str, ...] | list[str],
    authority_pubkey_hex: str,
    authority_secret: bytes,
    prev_digest: str,
) -> ElectionFreezeReceipt:
    """Pin an election-period source-freeze window."""
    freeze_start = _check_ts(freeze_start, "freeze_start")
    freeze_end = _check_ts(freeze_end, "freeze_end")
    if freeze_end <= freeze_start:
        raise NewsmediaError("freeze_end must be after freeze_start")
    tiers = _check_str_tuple(covered_tiers, "covered_tiers")
    for tier in tiers:
        _check_vocab(tier, CLAIM_TIERS, "covered_tiers entry")
    return _issue_freeze(
        ElectionFreezeReceipt,
        receipt_id=_check_nonempty_str(receipt_id, "receipt_id"),
        election_id=_check_nonempty_str(election_id, "election_id"),
        freeze_start=freeze_start,
        freeze_end=freeze_end,
        covered_tiers=tiers,
        authority_pubkey_hex=_check_hex64(authority_pubkey_hex, "authority_pubkey_hex"),
        prev_digest=_check_nonempty_str(prev_digest, "prev_digest"),
        authority_secret=authority_secret,
    )


def election_override_receipt(
    *,
    receipt_id: str,
    election_id: str,
    claim_id: str,
    override_reason: str,
    authority_pubkey_hex: str,
    authority_secret: bytes,
    prev_digest: str,
) -> ElectionOverrideReceipt:
    """Seal an override for a covered-tier claim inside a freeze."""
    return _issue_freeze(
        ElectionOverrideReceipt,
        receipt_id=_check_nonempty_str(receipt_id, "receipt_id"),
        election_id=_check_nonempty_str(election_id, "election_id"),
        claim_id=_check_nonempty_str(claim_id, "claim_id"),
        override_reason=_check_nonempty_str(override_reason, "override_reason"),
        authority_pubkey_hex=_check_hex64(authority_pubkey_hex, "authority_pubkey_hex"),
        prev_digest=_check_nonempty_str(prev_digest, "prev_digest"),
        authority_secret=authority_secret,
    )


class FreezeLog:
    """Hash-chained log of election freeze/override receipts."""

    def __init__(self) -> None:
        self._log: list[Any] = []

    def append(self, receipt: Any) -> Any:
        expected_prev = self._log[-1].receipt_digest if self._log else _GENESIS
        if not hmac.compare_digest(receipt.prev_digest, expected_prev):
            raise NewsmediaError(
                f"receipt {receipt.receipt_id!r} does not chain to the log tip"
            )
        self._log.append(receipt)
        return receipt

    def freeze_covering(self, election_id: str, at_ts: int) -> ElectionFreezeReceipt | None:
        for receipt in reversed(self._log):
            if (
                isinstance(receipt, ElectionFreezeReceipt)
                and hmac.compare_digest(receipt.election_id, election_id)
                and receipt.freeze_start <= at_ts < receipt.freeze_end
            ):
                return receipt
        return None

    def override_for_claim(self, election_id: str, claim_id: str) -> ElectionOverrideReceipt | None:
        for receipt in reversed(self._log):
            if (
                isinstance(receipt, ElectionOverrideReceipt)
                and hmac.compare_digest(receipt.election_id, election_id)
                and hmac.compare_digest(receipt.claim_id, claim_id)
            ):
                return receipt
        return None

    def verify(self) -> None:
        _check_chain(self._log, "freeze")


def check_election_freeze(
    *, election_id: str, claim_id: str, claim_tier: str, claim_ts: int, log: FreezeLog
) -> NewsmediaVerdict:
    """Covered-tier claims inside a freeze need an override."""
    _check_nonempty_str(election_id, "election_id")
    _check_nonempty_str(claim_id, "claim_id")
    _check_vocab(claim_tier, CLAIM_TIERS, "claim_tier")
    claim_ts = _check_ts(claim_ts, "claim_ts")
    freeze = log.freeze_covering(election_id, claim_ts)
    if freeze is None:
        return _allow(f"no election freeze covers {claim_ts} for {election_id!r}")
    if claim_tier not in freeze.covered_tiers:
        return _allow(
            f"claim tier {claim_tier} not covered by {election_id!r} freeze",
            freeze.receipt_digest,
        )
    override = log.override_for_claim(election_id, claim_id)
    if override is None:
        return _deny(
            DENY_FREEZE_VIOLATION,
            f"claim {claim_id!r} tier {claim_tier} published inside "
            f"{election_id!r} freeze without override",
        )
    return _allow(
        f"claim {claim_id!r} override bound for {election_id!r} freeze",
        override.receipt_digest,
    )

# ---------------------------------------------------------------------------
# Bench runner: metrics.newsmedia_agents (12 scenarios, 4 allow / 8 deny)
# ---------------------------------------------------------------------------


def run_newsmedia_agents() -> dict[str, Any]:
    """News-media AI discipline (one-hundred-fifty-eighth batch).

    Absorbs the 2026 AI-newsroom thread: AP July 2026 standards (AI
    cannot replace reporting/sourcing/judgment/verification, full
    ban on AI news photography, material AI use must be disclosed);
    Brennan Center Aug 2026 (6 chatbots: ~half answers had citation
    problems, 1/3 factual errors, all cited nonexistent sources);
    Korea AI-fake disaster footage broadcast as real (Kamchatka
    blizzard, Nepal floods); pink-slime sites cited in 48.2% of
    chatbot answers, 1,179 outlets > 937 US dailies; Anthropic
    $1.5B settlement (~$3,000/work: legally purchased = fair use,
    7M pirated books ≠); Japan Originator Profile cryptographic
    publisher IDs (provenance, not accuracy); Toff trust paradox
    (readers demand disclosure, trust less after it); Le Monde
    1,331 media jobs cut since Jan 2026; Korea 90-day AI video
    electioneering ban.

    Fail-closed rules over 12 deterministic scenarios: stories bind
    issuer-identity receipts — anonymous AI stories are
    ``newsmedia.unattributed``; material AI use must be disclosed
    within its window — late is ``newsmedia.undisclosed_material_use``;
    claim verification must meet its tier depth — shallow is
    ``newsmedia.citation_failure``; external visuals bind screening
    — unscreened is ``newsmedia.unsourced_visual``; cited sources
    must resolve — fabrications are
    ``newsmedia.fabricated_citation``; outlets bind funding
    disclosure — pink-slime anonymity is
    ``newsmedia.funding_undisclosed``; bylines bind verified humans
    — fictional bylines are ``newsmedia.fictional_byline``; corpora
    bind license chains — pirated chains are
    ``newsmedia.illegitimate_source``. Ground truth is closed:
    4 allow / 8 deny.
    """
    SEC = b"nm-bench-auth-" + b"0" * 18  # 32 bytes
    assert len(SEC) == 32
    PUB = ed25519.public_key(SEC).hex()
    T0 = 1_800_000_000
    HEX64 = "ab" * 32
    HEX64_B = "cd" * 32
    HEX64_C = "ef" * 32
    HEX64_D = "12" * 32

    def tip(log: Any) -> str:
        return log._log[-1].receipt_digest if log._log else _GENESIS

    # --- source receipts: two attributed stories ---
    sources = SourceLog()
    sources.append(
        source_receipt(
            receipt_id="nm-src-1", story_id="story-ok", issuer_id="op-publisher-1",
            issuer_pubkey_hex=PUB, ai_involvement=AI_ASSISTED,
            expires_at=T0 + 86400, authority_pubkey_hex=PUB,
            authority_secret=SEC, prev_digest=tip(sources),
        )
    )
    sources.append(
        source_receipt(
            receipt_id="nm-src-2", story_id="story-human", issuer_id="op-publisher-1",
            issuer_pubkey_hex=PUB, ai_involvement=AI_HUMAN,
            expires_at=T0 + 86400, authority_pubkey_hex=PUB,
            authority_secret=SEC, prev_digest=tip(sources),
        )
    )

    # --- materiality: one disclosed-in-window, one disclosed-late ---
    material = MaterialityLog()
    material.append(
        materiality_receipt(
            receipt_id="nm-mat-1", story_id="story-disclosed", materiality=MATERIAL,
            published_at=T0, authority_pubkey_hex=PUB,
            authority_secret=SEC, prev_digest=tip(material),
        )
    )
    material.append(
        disclosure_receipt(
            receipt_id="nm-dis-1", story_id="story-disclosed", disclosed_at=T0 + 3600,
            disclosure_format="inline_banner", placement_digest=HEX64_B,
            authority_pubkey_hex=PUB, authority_secret=SEC, prev_digest=tip(material),
        )
    )
    material.append(
        materiality_receipt(
            receipt_id="nm-mat-2", story_id="story-late", materiality=MATERIAL,
            published_at=T0, authority_pubkey_hex=PUB,
            authority_secret=SEC, prev_digest=tip(material),
        )
    )
    material.append(
        disclosure_receipt(
            receipt_id="nm-dis-2", story_id="story-late", disclosed_at=T0 + 200_000,
            disclosure_format="inline_banner", placement_digest=HEX64_C,
            authority_pubkey_hex=PUB, authority_secret=SEC, prev_digest=tip(material),
        )
    )

    # --- verification: one deep enough, one shallow ---
    vlog = VerificationLog()
    vlog.append(
        verification_receipt(
            receipt_id="nm-ver-1", claim_id="claim-ok", story_id="story-ok",
            claim_tier=TIER_MEDIUM, verification_depth=2,
            source_digests=[HEX64_D], verified_at=T0,
            authority_pubkey_hex=PUB, authority_secret=SEC, prev_digest=tip(vlog),
        )
    )
    vlog.append(
        verification_receipt(
            receipt_id="nm-ver-2", claim_id="claim-shallow", story_id="story-ok",
            claim_tier=TIER_HIGH, verification_depth=1,
            source_digests=[HEX64_D], verified_at=T0,
            authority_pubkey_hex=PUB, authority_secret=SEC, prev_digest=tip(vlog),
        )
    )
    citations = CitationRegistry()
    citations.register(
        CitationRecord(
            record_id="nm-cit-1", claim_id="claim-ok",
            cited_outlet_id="wire-service", cited_url_digest=HEX64_D,
            resolved=True, resolution_note="resolves to live article",
        )
    )
    citations.register(
        CitationRecord(
            record_id="nm-cit-2", claim_id="claim-ghost",
            cited_outlet_id="iwate-nippo", cited_url_digest=HEX64_B,
            resolved=False, resolution_note="outlet denies ever publishing it",
        )
    )

    # --- media screening: one screened authentic video ---
    media = MediaScreenLog()
    media.append(
        media_screen_receipt(
            receipt_id="nm-med-1", media_id="video-ok", story_id="story-ok",
            media_kind=KIND_VIDEO, external=True, ai_generated=False,
            screening_method="human_forensic", authentic=True,
            screened_at=T0, authority_pubkey_hex=PUB,
            authority_secret=SEC, prev_digest=tip(media),
        )
    )

    # --- funding: one disclosed outlet ---
    funding = FundingLog()
    funding.append(
        funding_disclosure_receipt(
            receipt_id="nm-fun-1", outlet_id="outlet-ok",
            funders=["civic-trust-foundation"], partisan_alignment="center",
            disclosed_at=T0, authority_pubkey_hex=PUB,
            authority_secret=SEC, prev_digest=tip(funding),
        )
    )

    # --- bylines: one verified, one fictional ---
    bylines = BylineLog()
    bylines.append(
        byline_receipt(
            receipt_id="nm-by-1", story_id="story-ok", byline_name="Ada Reporter",
            human_verified=True, identity_digest=HEX64,
            authority_pubkey_hex=PUB, authority_secret=SEC, prev_digest=tip(bylines),
        )
    )
    bylines.append(
        byline_receipt(
            receipt_id="nm-by-2", story_id="story-fake-byline",
            byline_name="Dr. X NASA Engineer",
            human_verified=False, identity_digest=HEX64_B,
            authority_pubkey_hex=PUB, authority_secret=SEC, prev_digest=tip(bylines),
        )
    )

    # --- licenses: one licensed, one pirated ---
    licenses = LicenseLog()
    licenses.append(
        license_chain_receipt(
            receipt_id="nm-lic-1", corpus_id="corpus-ok",
            license_source=LIC_LICENSED, chain_digest=HEX64_C,
            checked_at=T0, authority_pubkey_hex=PUB,
            authority_secret=SEC, prev_digest=tip(licenses),
        )
    )
    licenses.append(
        license_chain_receipt(
            receipt_id="nm-lic-2", corpus_id="corpus-pirated",
            license_source=LIC_PIRATED, chain_digest=HEX64_D,
            checked_at=T0, authority_pubkey_hex=PUB,
            authority_secret=SEC, prev_digest=tip(licenses),
        )
    )

    scenarios_out: list[tuple[str, bool, str]] = []
    results: dict[str, dict[str, Any]] = {}

    def _record(sid: str, expect_allow: bool, needle: str, verdict: NewsmediaVerdict) -> None:
        scenarios_out.append((sid, expect_allow, needle))
        results[sid] = {"allowed": verdict.allowed, "reason": verdict.reason}

    # 1. attributed AI-assisted story -> allow
    _record(
        "allow_op_attributed", True, "",
        check_attribution(story_id="story-ok", log=sources, checked_at=T0 + 10),
    )
    # 2. human story with issuer receipt -> allow
    _record(
        "allow_human_story", True, "",
        check_attribution(story_id="story-human", log=sources, checked_at=T0 + 10),
    )
    # 3. material AI use disclosed within window -> allow
    _record(
        "allow_disclosed_material", True, "",
        materiality_disclosure_clock(story_id="story-disclosed", log=material, checked_at=T0 + 4000),
    )
    # 4. licensed corpus -> allow
    _record(
        "allow_licensed_corpus", True, "",
        check_license_chain(corpus_id="corpus-ok", log=licenses),
    )
    # 5. anonymous AI story -> deny
    _record(
        "deny_unattributed", False, "unattributed",
        check_attribution(story_id="story-ghost", log=sources, checked_at=T0 + 10),
    )
    # 6. material AI use disclosed late -> deny
    _record(
        "deny_undisclosed_material", False, "undisclosed_material_use",
        materiality_disclosure_clock(story_id="story-late", log=material, checked_at=T0 + 200_001),
    )
    # 7. high-tier claim with depth 1 -> deny
    _record(
        "deny_citation_failure", False, "citation_failure",
        verification_depth_gate(claim_id="claim-shallow", vlog=vlog, citations=citations),
    )
    # 8. external video with no screening -> deny
    _record(
        "deny_unsourced_visual", False, "unsourced_visual",
        external_media_screen(media_id="video-ghost", external=True, log=media),
    )
    # 9. fabricated citation -> deny
    _record(
        "deny_fabricated_citation", False, "fabricated_citation",
        citation_integrity_gate(claim_id="claim-ghost", citations=citations),
    )
    # 10. pink-slime outlet with no funding disclosure -> deny
    _record(
        "deny_funding_undisclosed", False, "funding_undisclosed",
        political_funding_disclosure(outlet_id="pink-slime-outlet", log=funding),
    )
    # 11. fictional byline -> deny
    _record(
        "deny_fictional_byline", False, "fictional_byline",
        byline_verification(story_id="story-fake-byline", log=bylines),
    )
    # 12. pirated corpus -> deny
    _record(
        "deny_illegitimate_source", False, "illegitimate_source",
        check_license_chain(corpus_id="corpus-pirated", log=licenses),
    )

    mismatches: list[str] = []
    allowed_ids: list[str] = []
    denial_reasons: dict[str, str] = {}
    for sid, expect_allow, needle in scenarios_out:
        r = results[sid]
        if r["allowed"]:
            allowed_ids.append(sid)
        else:
            denial_reasons[sid] = r["reason"]
        if r["allowed"] != expect_allow:
            mismatches.append(
                f"{sid}: expected allow={expect_allow}, saw allow={r['allowed']}"
            )
        elif not expect_allow and needle and needle not in r["reason"]:
            mismatches.append(f"{sid}: expected needle {needle!r} in {r['reason']!r}")
    return {
        "n_scenarios": len(scenarios_out),
        "n_allowed": len(allowed_ids),
        "n_denied": len(scenarios_out) - len(allowed_ids),
        "allowed_ids": allowed_ids,
        "denial_reasons": denial_reasons,
        "mismatches": mismatches,
    }
