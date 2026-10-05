"""Editorial countersign + publication gates (one-hundred-seventeenth batch).

Absorbs the 2026 AI-media thread, where labeling became law on three
continents while newsroom practice collapsed under speed:

* **EU AI Act Art. 50** (applicable 2026-08-02) + Transparency Code of
  Practice: machine-readable marking for AI-generated content,
  200-token watermark threshold, dual marking (visible +
  machine-readable), three EU label icons.
* **California SB 942** (aligned to the same 2026-08-02): machine-readable
  latent watermark for providers above 1M MAU + a free detection tool.
* **China** (synthetic-content labeling mandatory since 2025-09-01),
  **South Korea** AI Basic Act (2026-01-22), **India** (mandatory source
  labeling from 2026-02-20, 3-hour takedown window).
* **Anthropic**: Claude text now carries an invisible machine-readable
  watermark that survives copy-paste.
* **AP** (2026-07 guidance): AI output must be journalist-reviewed
  before publication; no AI edits to news photography.
* **Australia Medianet**: 54% of journalists already use AI, but 93%
  worry about quality and 22% lost work to AI in 2025.
* **Blackbook Media**: post-layoff AI replacements published with fake
  bylines and *leftover prompt text* in articles.
* **US midterms**: 164 AI political ads (~$80M spend), ~70% undisclosed;
  deepfaked candidate video rated "hyper-realistic".
* **Japan NTV + Logic & Design** (2026-07): joint R&D on news-image
  forgery detection, patent filed.

The governance takeaways, all fail-closed here:

1. **Editorial countersign.** AI-generated content publishes only with a
   signed countersign from a *registered human editor* who is not the
   publishing agent (the AP rule as a mechanism: the Blackbook fake-
   byline case is what happens when "reviewed" is self-asserted).
   Without a valid countersign, publication is refused and the content
   classifies ``NON_AUTHORITATIVE`` (87th-batch binary semantics).
2. **Disclosure binds the payload.** Public-interest AI content must
   carry a disclosure that is both visible and machine-readable, and the
   disclosure binds the *content digest* — the label follows the
   payload, not the page. Political/election content without a bound
   disclosure is hard-denied (``media.undisclosed_political``), not
   merely downgraded.
3. **Label resilience.** Content that *claims* to be AI-generated must
   carry verifiable machine-readable marking. Marking stripped or
   downgraded in transit (digest no longer matches the claimed marking)
   classifies ``unverified-origin`` — per the C2PA lesson from the
   112th batch, absence of a manifest never proves forgery, but a
   claimed origin without evidence is unverified.
4. **UGC probe.** User-generated content ingested for republication
   needs a capture attestation (device signature or provenance chain);
   without it the content is ``unverifiable-capture`` and is never
   auto-published.
5. **Election deepfake check.** Election-context content requires
   *both* source attestation *and* human review; either missing blocks
   publication pending review (``media.election_context_hold``).
6. **Slop velocity gate.** Publication velocity above
   ``SLOP_VELOCITY_MAX`` items per window from one agent source is the
   "digital slop" tell: the source is throttled and human review is
   required (``media.slop_velocity``).

Honest boundary: watermarks and labels are *declared* evidence — a
determined adversary can strip them, and this module verifies claimed
chains, not forensic ground truth. These gates are a tripwire for the
publishing pipeline, not a forgery guarantee. Machine-readable marking
formats are outside scope; this module checks presence, binding, and
chain consistency of the declared markings.

Deterministic: no wall-clock reads (callers inject integer epoch
timestamps), JCS canonical hashing (95th batch), Ed25519 via the
vendored ``ed25519`` module (97th-batch pattern), digest comparisons
via :func:`hmac.compare_digest`.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from typing import Any

import ed25519
from canonical_json import jcs_canonical_json, jcs_sha256_hex


EDITORIAL_SCHEMA_VERSION = "northstar.editorial.v1"

#: Classification tiers (binary, 87th-batch style).
AUTHORITATIVE = "authoritative"
NON_AUTHORITATIVE = "non_authoritative"
UNVERIFIED_ORIGIN = "unverified-origin"
UNVERIFIABLE_CAPTURE = "unverifiable-capture"
ELECTION_CONTEXT_HOLD = "election-context-hold"

#: Content kinds. "political" and "election" carry the hard disclosure
#: and review duties; "general" carries the softer AP-style duty.
CONTENT_KINDS: tuple[str, ...] = (
    "general",
    "political",
    "election",
)

#: Denial reasons (stable strings the bench pins).
DENY_NO_COUNTERSIGN = "media:no_editorial_countersign"
DENY_UNDISCLOSED_POLITICAL = "media:undisclosed_political"
DENY_DISCLOSURE_UNBOUND = "media:disclosure_unbound"
DENY_MARKING_STRIPPED = "media:marking_stripped"
DENY_UNVERIFIABLE_CAPTURE = "media:unverifiable_capture"
DENY_ELECTION_HOLD = "media:election_context_hold"
DENY_SLOP_VELOCITY = "media:slop_velocity"
DENY_EDITOR_IS_PUBLISHER = "media:editor_is_publisher"
DENY_STALE_REVIEW = "media:stale_review"

#: Maximum age (seconds) of a countersign at publish time. A review
#: from long ago does not authorize today's publication.
REVIEW_FRESHNESS_WINDOW_S = 2_592_000  # 30 days

#: "Digital slop" tell: publications per window from one agent source.
#: Above this, the source is throttled pending human review.
SLOP_VELOCITY_MAX = 20
SLOP_WINDOW_S = 3_600

EDITORIAL_DENIED_EVENT = "editorial.denied"
EDITORIAL_ALLOWED_EVENT = "editorial.allowed"

_GENESIS = "genesis"
_HEX64_LENGTH = 64
_HEX128_LENGTH = 128


class EditorialError(ValueError):
    """A malformed receipt/record or a programming error.

    Raised for structural problems (bad digests, bad signatures input,
    unknown content kind, non-hex fields). Publication *gate failures*
    (no countersign, undisclosed political content, stripped marking,
    unverifiable capture, election hold, slop velocity) return a
    :class:`PublicationVerdict` with ``allowed=False`` — a refused
    publication is a verdict, a malformed log is a bug.
    """


# ---------------------------------------------------------------------------
# Helpers
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
        raise EditorialError(
            f"{field_name} must be a 64-char lowercase hex digest"
        )
    return value


def _check_hex128(value: Any, field_name: str) -> str:
    if not _is_hex(value, _HEX128_LENGTH):
        raise EditorialError(
            f"{field_name} must be a 128-char hex value"
        )
    return value


def _check_kind(value: Any) -> str:
    if value not in CONTENT_KINDS:
        raise EditorialError(
            f"content_kind must be one of {CONTENT_KINDS}, saw {value!r}"
        )
    return value


def _check_ts(value: Any, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise EditorialError(f"{field_name} must be a non-negative int epoch")
    return value


def _check_secret(value: Any, field_name: str) -> bytes:
    if not isinstance(value, bytes) or len(value) != 32:
        raise EditorialError(f"{field_name} must be 32 bytes")
    return value


def _check_pubkey_hex(value: Any, field_name: str = "editor_pubkey_hex") -> str:
    # Ed25519 public keys are 32 bytes -> 64 hex chars.
    return _check_hex64(value, field_name)


# ---------------------------------------------------------------------------
# Editor registry — who counts as a human editor
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EditorRecord:
    """Registration of one human editor.

    ``editor_id`` is a stable human-readable handle; ``pubkey_hex`` is
    the editor's Ed25519 key. The Blackbook Media lesson is encoded in
    the gate, not here: registration alone does not authorize — the
    *gate* additionally requires the countersigner to differ from the
    publishing agent.
    """

    editor_id: str
    pubkey_hex: str
    registered_at: int
    revoked_at: int = 0  # 0 = active

    def __post_init__(self) -> None:
        if not isinstance(self.editor_id, str) or not self.editor_id:
            raise EditorialError("editor_id must be a non-empty string")
        _check_pubkey_hex(self.pubkey_hex)
        _check_ts(self.registered_at, "registered_at")
        if self.revoked_at:
            _check_ts(self.revoked_at, "revoked_at")
            if self.revoked_at < self.registered_at:
                raise EditorialError("revoked_at must not predate registered_at")


class EditorRegistry:
    """The set of editors whose countersigns can authorize publication."""

    def __init__(self) -> None:
        self._editors: dict[str, EditorRecord] = {}

    def register(self, record: EditorRecord) -> None:
        """Register (or re-register) an editor. Idempotent by id."""
        self._editors[record.editor_id] = record

    def revoke(self, editor_id: str, revoked_at: int) -> None:
        """Revoke an editor. Revocation is terminal in the registry."""
        record = self._editors.get(editor_id)
        if record is None:
            raise EditorialError(f"unknown editor {editor_id!r}")
        _check_ts(revoked_at, "revoked_at")
        self._editors[editor_id] = EditorRecord(
            editor_id=record.editor_id,
            pubkey_hex=record.pubkey_hex,
            registered_at=record.registered_at,
            revoked_at=revoked_at,
        )

    def active_pubkey(self, editor_id: str, at: int) -> str | None:
        """Return the editor's pubkey if registered and not revoked at ``at``."""
        record = self._editors.get(editor_id)
        if record is None:
            return None
        if record.registered_at > at:
            return None
        if record.revoked_at and record.revoked_at <= at:
            return None
        return record.pubkey_hex


# ---------------------------------------------------------------------------
# Editorial countersign — hash-chained receipts
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EditorialCountersign:
    """A registered human editor's signed review of one content item.

    Binds ``(content_digest, editor_id, reviewed_at, disclosure_digest)``
    to the editor's key. ``disclosure_digest`` binds the disclosure the
    editor reviewed — the editor cannot sign a review of content while a
    *different* disclosure ships with it. Sealed with ``receipt_digest``
    and chained via ``prev_digest``.
    """

    content_digest: str
    editor_id: str
    reviewed_at: int
    disclosure_digest: str
    editor_pubkey_hex: str
    signature_hex: str
    prev_digest: str = _GENESIS
    receipt_digest: str = ""

    def __post_init__(self) -> None:
        _check_hex64(self.content_digest, "content_digest")
        if not isinstance(self.editor_id, str) or not self.editor_id:
            raise EditorialError("editor_id must be a non-empty string")
        _check_ts(self.reviewed_at, "reviewed_at")
        _check_hex64(self.disclosure_digest, "disclosure_digest")
        _check_pubkey_hex(self.editor_pubkey_hex)
        _check_hex128(self.signature_hex, "signature_hex")
        if self.prev_digest != _GENESIS:
            _check_hex64(self.prev_digest, "prev_digest")
        if self.receipt_digest != "":
            _check_hex64(self.receipt_digest, "receipt_digest")


def _countersign_payload(countersign: EditorialCountersign) -> dict[str, Any]:
    return {
        "schema": EDITORIAL_SCHEMA_VERSION,
        "kind": "editorial-countersign",
        "content_digest": countersign.content_digest,
        "editor_id": countersign.editor_id,
        "reviewed_at": countersign.reviewed_at,
        "disclosure_digest": countersign.disclosure_digest,
        "editor_pubkey_hex": countersign.editor_pubkey_hex,
        "prev_digest": countersign.prev_digest,
    }


def compute_countersign_digest(countersign: EditorialCountersign) -> str:
    """Recompute a countersign's digest over all fields except itself."""
    return jcs_sha256_hex(_countersign_payload(countersign))


def countersign_content(
    *,
    content_digest: str,
    editor_id: str,
    editor_secret: bytes,
    reviewed_at: int,
    disclosure_digest: str,
    prev_digest: str = _GENESIS,
) -> EditorialCountersign:
    """Issue an editor-signed countersign for one content item and seal it."""
    _check_secret(editor_secret, "editor_secret")
    pubkey_hex = ed25519.public_key(editor_secret).hex()
    bare = EditorialCountersign(
        content_digest=_check_hex64(content_digest, "content_digest"),
        editor_id=editor_id,
        reviewed_at=_check_ts(reviewed_at, "reviewed_at"),
        disclosure_digest=_check_hex64(disclosure_digest, "disclosure_digest"),
        editor_pubkey_hex=pubkey_hex,
        signature_hex="00" * 64,  # placeholder; replaced below
        prev_digest=prev_digest,
    )
    payload = _countersign_payload(bare)
    signature_hex = ed25519.sign(editor_secret, jcs_canonical_json(payload)).hex()
    return EditorialCountersign(
        content_digest=bare.content_digest,
        editor_id=bare.editor_id,
        reviewed_at=bare.reviewed_at,
        disclosure_digest=bare.disclosure_digest,
        editor_pubkey_hex=bare.editor_pubkey_hex,
        signature_hex=signature_hex,
        prev_digest=bare.prev_digest,
        receipt_digest=jcs_sha256_hex(payload),
    )


def _verify_countersign_chain(log: list[EditorialCountersign]) -> None:
    """Verify digests and the single hash chain. Raises on any break."""
    expected = _GENESIS
    for entry in log:
        if not isinstance(entry, EditorialCountersign):
            raise EditorialError(
                "log entries must be EditorialCountersign, "
                f"saw {type(entry).__name__}"
            )
        digest = compute_countersign_digest(entry)
        if not hmac.compare_digest(digest, entry.receipt_digest):
            raise EditorialError(
                f"log tampered: digest mismatch on countersign by "
                f"{entry.editor_id!r}"
            )
        if not hmac.compare_digest(entry.prev_digest, expected):
            raise EditorialError(
                f"log chain broken at countersign by {entry.editor_id!r}: "
                f"expected prev {expected[:12]}..., "
                f"saw {entry.prev_digest[:12]}..."
            )
        expected = entry.receipt_digest


# ---------------------------------------------------------------------------
# Disclosure records — the label that follows the payload
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DisclosureRecord:
    """A disclosure bound to one content digest.

    The disclosure must be both *visible* (human-readable text ships
    with the content) and *machine-readable* (a verifiable marking
    payload). ``disclosure_digest`` is the JCS digest of the disclosure
    payload — the countersign binds this digest, so the label that was
    reviewed is the label that ships.
    """

    content_digest: str
    visible_text: str
    machine_readable_payload: str
    disclosed_at: int

    def __post_init__(self) -> None:
        _check_hex64(self.content_digest, "content_digest")
        if not isinstance(self.visible_text, str) or not self.visible_text.strip():
            raise EditorialError("visible_text must be a non-empty string")
        if not isinstance(self.machine_readable_payload, str) or not self.machine_readable_payload:
            raise EditorialError("machine_readable_payload must be a non-empty string")
        _check_ts(self.disclosed_at, "disclosed_at")

    @property
    def disclosure_digest(self) -> str:
        """JCS digest of the disclosure payload."""
        return jcs_sha256_hex(
            {
                "schema": EDITORIAL_SCHEMA_VERSION,
                "kind": "disclosure",
                "content_digest": self.content_digest,
                "visible_text": self.visible_text,
                "machine_readable_payload": self.machine_readable_payload,
            }
        )


# ---------------------------------------------------------------------------
# Capture attestations — for UGC republication
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CaptureAttestation:
    """Attestation that UGC was captured by a real device/pipeline.

    ``attestor_pubkey_hex`` is the device or provenance-pipeline key;
    ``capture_digest`` binds the captured bytes. The signature covers
    the canonical attestation payload.
    """

    capture_digest: str
    attestor_id: str
    captured_at: int
    attestor_pubkey_hex: str
    signature_hex: str

    def __post_init__(self) -> None:
        _check_hex64(self.capture_digest, "capture_digest")
        if not isinstance(self.attestor_id, str) or not self.attestor_id:
            raise EditorialError("attestor_id must be a non-empty string")
        _check_ts(self.captured_at, "captured_at")
        _check_pubkey_hex(self.attestor_pubkey_hex, "attestor_pubkey_hex")
        _check_hex128(self.signature_hex, "signature_hex")


def _attestation_payload(attestation: CaptureAttestation) -> dict[str, Any]:
    return {
        "schema": EDITORIAL_SCHEMA_VERSION,
        "kind": "capture-attestation",
        "capture_digest": attestation.capture_digest,
        "attestor_id": attestation.attestor_id,
        "captured_at": attestation.captured_at,
        "attestor_pubkey_hex": attestation.attestor_pubkey_hex,
    }


def attest_capture(
    *,
    capture_digest: str,
    attestor_id: str,
    attestor_secret: bytes,
    captured_at: int,
) -> CaptureAttestation:
    """Issue a device/pipeline-signed capture attestation."""
    _check_secret(attestor_secret, "attestor_secret")
    pubkey_hex = ed25519.public_key(attestor_secret).hex()
    bare = CaptureAttestation(
        capture_digest=_check_hex64(capture_digest, "capture_digest"),
        attestor_id=attestor_id,
        captured_at=_check_ts(captured_at, "captured_at"),
        attestor_pubkey_hex=pubkey_hex,
        signature_hex="00" * 64,  # placeholder; replaced below
    )
    payload = _attestation_payload(bare)
    signature_hex = ed25519.sign(attestor_secret, jcs_canonical_json(payload)).hex()
    return CaptureAttestation(
        capture_digest=bare.capture_digest,
        attestor_id=bare.attestor_id,
        captured_at=bare.captured_at,
        attestor_pubkey_hex=bare.attestor_pubkey_hex,
        signature_hex=signature_hex,
    )


def verify_capture_attestation(attestation: CaptureAttestation) -> bool:
    """Verify a capture attestation's signature. No exceptions."""
    try:
        return ed25519.verify(
            bytes.fromhex(attestation.attestor_pubkey_hex),
            jcs_canonical_json(_attestation_payload(attestation)),
            bytes.fromhex(attestation.signature_hex),
        )
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Publication verdicts and gates
# ---------------------------------------------------------------------------


@dataclass
class PublicationVerdict:
    """Outcome of checking one publication against the editorial gates."""

    allowed: bool
    reason: str
    classification: str = NON_AUTHORITATIVE
    receipt_digest: str = ""


def _check_countersign(
    *,
    countersign: EditorialCountersign | None,
    log: list[EditorialCountersign],
    registry: EditorRegistry,
    content_digest: str,
    disclosure: DisclosureRecord | None,
    publisher_agent_id: str,
    publish_time: int,
) -> PublicationVerdict | None:
    """Return a deny verdict, or None if the countersign gate passes."""
    if countersign is None:
        return PublicationVerdict(
            allowed=False,
            reason=f"{DENY_NO_COUNTERSIGN}: AI-generated content publishes "
            "only with a registered human editor's countersign",
            classification=NON_AUTHORITATIVE,
            receipt_digest="",
        )
    # Log integrity first: a tampered log denies everything.
    try:
        _verify_countersign_chain(log)
    except EditorialError as error:
        return PublicationVerdict(
            allowed=False,
            reason=f"countersign log integrity failure: {error}",
            classification=NON_AUTHORITATIVE,
            receipt_digest="",
        )
    known = next(
        (
            c
            for c in log
            if hmac.compare_digest(c.receipt_digest, countersign.receipt_digest)
        ),
        None,
    )
    if known is None:
        return PublicationVerdict(
            allowed=False,
            reason="countersign not present in the countersign log: unknown receipt",
            classification=NON_AUTHORITATIVE,
            receipt_digest=countersign.receipt_digest,
        )
    if not hmac.compare_digest(
        compute_countersign_digest(countersign), countersign.receipt_digest
    ):
        return PublicationVerdict(
            allowed=False,
            reason="countersign digest does not recompute: tampered receipt",
            classification=NON_AUTHORITATIVE,
            receipt_digest=countersign.receipt_digest,
        )
    # The countersigner must be a registered, active editor...
    pubkey = registry.active_pubkey(countersign.editor_id, publish_time)
    if pubkey is None or not hmac.compare_digest(pubkey, countersign.editor_pubkey_hex):
        return PublicationVerdict(
            allowed=False,
            reason=(
                f"countersigner {countersign.editor_id!r} is not a "
                "registered active editor at publish time"
            ),
            classification=NON_AUTHORITATIVE,
            receipt_digest=countersign.receipt_digest,
        )
    # ...and must not be the publishing agent itself (Blackbook lesson).
    if countersign.editor_id == publisher_agent_id:
        return PublicationVerdict(
            allowed=False,
            reason=f"{DENY_EDITOR_IS_PUBLISHER}: the countersigner must be "
            "a human editor distinct from the publishing agent",
            classification=NON_AUTHORITATIVE,
            receipt_digest=countersign.receipt_digest,
        )
    # Signature must verify against the editor's registered key.
    try:
        sig_ok = ed25519.verify(
            bytes.fromhex(countersign.editor_pubkey_hex),
            jcs_canonical_json(_countersign_payload(countersign)),
            bytes.fromhex(countersign.signature_hex),
        )
    except Exception:
        sig_ok = False
    if not sig_ok:
        return PublicationVerdict(
            allowed=False,
            reason="countersign signature invalid: not from the editor's key",
            classification=NON_AUTHORITATIVE,
            receipt_digest=countersign.receipt_digest,
        )
    # The countersign must be for THIS content...
    if not hmac.compare_digest(countersign.content_digest, content_digest):
        return PublicationVerdict(
            allowed=False,
            reason="countersign binds a different content digest: "
            "reviews do not transfer across content",
            classification=NON_AUTHORITATIVE,
            receipt_digest=countersign.receipt_digest,
        )
    # ...reviewed before publication, and still fresh.
    if countersign.reviewed_at > publish_time:
        return PublicationVerdict(
            allowed=False,
            reason="countersign postdates publication: review must precede publish",
            classification=NON_AUTHORITATIVE,
            receipt_digest=countersign.receipt_digest,
        )
    if publish_time - countersign.reviewed_at > REVIEW_FRESHNESS_WINDOW_S:
        return PublicationVerdict(
            allowed=False,
            reason=f"{DENY_STALE_REVIEW}: review is older than "
            f"{REVIEW_FRESHNESS_WINDOW_S}s at publish time",
            classification=NON_AUTHORITATIVE,
            receipt_digest=countersign.receipt_digest,
        )
    # ...and the disclosure that ships must be the one reviewed.
    if disclosure is None or not hmac.compare_digest(
        countersign.disclosure_digest, disclosure.disclosure_digest
    ):
        return PublicationVerdict(
            allowed=False,
            reason=f"{DENY_DISCLOSURE_UNBOUND}: the shipped disclosure is "
            "not the one the editor reviewed — the label must follow the "
            "reviewed payload",
            classification=NON_AUTHORITATIVE,
            receipt_digest=countersign.receipt_digest,
        )
    return None


def disclosure_gate(
    *,
    content_kind: str,
    disclosure: DisclosureRecord | None,
    content_digest: str,
) -> PublicationVerdict:
    """Gate publication on the disclosure duty.

    * ``political`` / ``election`` without a bound disclosure: hard deny
      (``media.undisclosed_political``). The 2026 US-midterms finding
      (~70% of AI political ads undisclosed) is the reason this is a
      deny, not a downgrade.
    * any kind with a disclosure whose digest does not bind the content:
      deny (``media.disclosure_unbound``).
    * ``general`` without disclosure: allowed but NON_AUTHORITATIVE.
    * disclosure present and bound: passes (authoritative pending the
      other gates).
    """
    _check_kind(content_kind)
    _check_hex64(content_digest, "content_digest")
    if disclosure is None:
        if content_kind in ("political", "election"):
            return PublicationVerdict(
                allowed=False,
                reason=f"{DENY_UNDISCLOSED_POLITICAL}: {content_kind} "
                "AI content without a bound disclosure is not published",
                classification=NON_AUTHORITATIVE,
            )
        return PublicationVerdict(
            allowed=True,
            reason="general AI content without disclosure: publishes as "
            "NON_AUTHORITATIVE",
            classification=NON_AUTHORITATIVE,
        )
    if not hmac.compare_digest(disclosure.content_digest, content_digest):
        return PublicationVerdict(
            allowed=False,
            reason=f"{DENY_DISCLOSURE_UNBOUND}: disclosure binds a "
            "different content digest — the label must follow the payload",
            classification=NON_AUTHORITATIVE,
        )
    return PublicationVerdict(
        allowed=True,
        reason="disclosure present, visible and machine-readable, bound to "
        "the content digest",
        classification=AUTHORITATIVE,
    )


def check_marking_resilience(
    *,
    claims_ai_generated: bool,
    marking_payload: str | None,
    expected_marking_digest: str | None,
) -> PublicationVerdict:
    """Verify machine-readable marking on content claiming AI origin.

    * Not claiming AI-generated: the gate does not apply.
    * Claiming AI-generated with verifiable marking (payload digest
      matches the expected digest): passes.
    * Claiming AI-generated with missing or mismatched marking: the
      marking was stripped or downgraded in transit —
      ``media.marking_stripped``, classification ``unverified-origin``.
      Per the 112th-batch C2PA lesson, an *absent* manifest never proves
      forgery — but a *claimed* origin without evidence is unverified,
      and publication is refused.
    """
    if not claims_ai_generated:
        return PublicationVerdict(
            allowed=True,
            reason="content does not claim AI generation: marking gate "
            "does not apply",
            classification=AUTHORITATIVE,
        )
    if marking_payload is None or expected_marking_digest is None:
        return PublicationVerdict(
            allowed=False,
            reason=f"{DENY_MARKING_STRIPPED}: content claims AI generation "
            "but carries no verifiable machine-readable marking",
            classification=UNVERIFIED_ORIGIN,
        )
    _check_hex64(expected_marking_digest, "expected_marking_digest")
    actual = jcs_sha256_hex({"marking_payload": marking_payload})
    if not hmac.compare_digest(actual, expected_marking_digest):
        return PublicationVerdict(
            allowed=False,
            reason=f"{DENY_MARKING_STRIPPED}: marking payload digest does "
            "not match the declared marking — stripped or downgraded in "
            "transit",
            classification=UNVERIFIED_ORIGIN,
        )
    return PublicationVerdict(
        allowed=True,
        reason="machine-readable marking present and digest-verified",
        classification=AUTHORITATIVE,
    )


def ugc_probe(
    *,
    capture_digest: str,
    attestation: CaptureAttestation | None,
) -> PublicationVerdict:
    """Probe UGC for republication.

    User-generated content ingested for republication needs a capture
    attestation (device signature or provenance chain). Without a valid
    attestation the content is ``unverifiable-capture`` and is never
    auto-published — the republication pipeline may surface it for
    manual review, but the automatic path refuses.
    """
    _check_hex64(capture_digest, "capture_digest")
    if attestation is None:
        return PublicationVerdict(
            allowed=False,
            reason=f"{DENY_UNVERIFIABLE_CAPTURE}: UGC without a capture "
            "attestation is never auto-published",
            classification=UNVERIFIABLE_CAPTURE,
        )
    if not hmac.compare_digest(attestation.capture_digest, capture_digest):
        return PublicationVerdict(
            allowed=False,
            reason=f"{DENY_UNVERIFIABLE_CAPTURE}: attestation binds a "
            "different capture",
            classification=UNVERIFIABLE_CAPTURE,
        )
    if not verify_capture_attestation(attestation):
        return PublicationVerdict(
            allowed=False,
            reason=f"{DENY_UNVERIFIABLE_CAPTURE}: capture attestation "
            "signature invalid",
            classification=UNVERIFIABLE_CAPTURE,
        )
    return PublicationVerdict(
        allowed=True,
        reason="capture attestation valid: device/provenance signature "
        "verifies",
        classification=AUTHORITATIVE,
    )


def election_deepfake_check(
    *,
    content_kind: str,
    source_attestation: CaptureAttestation | None,
    human_review: EditorialCountersign | None,
) -> PublicationVerdict:
    """Election-context hold: both attestation and human review required.

    Election content publishes only with *both* a source attestation
    and a human review. Either missing blocks publication pending
    review (``media.election_context_hold``) — the 2026 deepfake
    election incidents are why this is a hold, not a downgrade.
    Non-election content passes through.
    """
    _check_kind(content_kind)
    if content_kind != "election":
        return PublicationVerdict(
            allowed=True,
            reason="not election-context content: deepfake hold does not apply",
            classification=AUTHORITATIVE,
        )
    if source_attestation is None or not verify_capture_attestation(
        source_attestation
    ):
        return PublicationVerdict(
            allowed=False,
            reason=f"{DENY_ELECTION_HOLD}: election content without a valid "
            "source attestation is held pending review",
            classification=ELECTION_CONTEXT_HOLD,
        )
    if human_review is None:
        return PublicationVerdict(
            allowed=False,
            reason=f"{DENY_ELECTION_HOLD}: election content without human "
            "review is held pending review",
            classification=ELECTION_CONTEXT_HOLD,
        )
    return PublicationVerdict(
        allowed=True,
        reason="election content: source attested and human-reviewed",
        classification=AUTHORITATIVE,
    )


def slop_velocity_gate(
    *,
    source_id: str,
    publish_times: list[int],
    window_start: int,
    window_end: int,
) -> PublicationVerdict:
    """Throttle agent sources whose publication velocity screams "slop".

    Counts ``publish_times`` inside ``[window_start, window_end]`` for
    one agent source. Above ``SLOP_VELOCITY_MAX`` the source is throttled
    (``media.slop_velocity``) and human review is required before the
    next publication — speed is the tell for "digital slop".
    """
    if not isinstance(source_id, str) or not source_id:
        raise EditorialError("source_id must be a non-empty string")
    _check_ts(window_start, "window_start")
    _check_ts(window_end, "window_end")
    if window_end < window_start:
        raise EditorialError("window_end must not predate window_start")
    for ts in publish_times:
        _check_ts(ts, "publish_times entry")
    count = sum(1 for ts in publish_times if window_start <= ts <= window_end)
    if count > SLOP_VELOCITY_MAX:
        return PublicationVerdict(
            allowed=False,
            reason=f"{DENY_SLOP_VELOCITY}: source {source_id!r} published "
            f"{count} items in the window (max {SLOP_VELOCITY_MAX}): "
            "throttled pending human review",
            classification=NON_AUTHORITATIVE,
        )
    return PublicationVerdict(
        allowed=True,
        reason=f"source velocity {count}/{SLOP_VELOCITY_MAX} within bounds",
        classification=AUTHORITATIVE,
    )


def check_publication(
    *,
    content_digest: str,
    content_kind: str,
    publisher_agent_id: str,
    publish_time: int,
    countersign: EditorialCountersign | None,
    countersign_log: list[EditorialCountersign],
    registry: EditorRegistry,
    disclosure: DisclosureRecord | None,
    claims_ai_generated: bool = True,
    marking_payload: str | None = None,
    expected_marking_digest: str | None = None,
    ugc_capture: bool = False,
    capture_attestation: CaptureAttestation | None = None,
    election_source_attestation: CaptureAttestation | None = None,
) -> PublicationVerdict:
    """Run the full editorial gate stack on one publication. Fail-closed.

    Gate order is fixed and every gate must pass:

    1. Disclosure duty (hard deny for undisclosed political/election —
       runs first so the specific duty surfaces, not a knock-on).
    2. Countersign (registered human editor, distinct from the
       publisher, fresh, bound to this content and this disclosure).
    3. Marking resilience (claimed AI origin must carry verifiable
       machine-readable marking).
    4. UGC probe (only when ``ugc_capture``: republication needs a
       capture attestation).
    5. Election deepfake check (election kind: attestation + review).
    6. The countersign itself doubles as the election human review.

    Any failure refuses publication. The returned verdict carries the
    first failing gate's reason and classification.
    """
    _check_hex64(content_digest, "content_digest")
    _check_kind(content_kind)
    if not isinstance(publisher_agent_id, str) or not publisher_agent_id:
        raise EditorialError("publisher_agent_id must be a non-empty string")
    _check_ts(publish_time, "publish_time")

    gate = disclosure_gate(
        content_kind=content_kind,
        disclosure=disclosure,
        content_digest=content_digest,
    )
    if not gate.allowed:
        return gate

    gate = _check_countersign(
        countersign=countersign,
        log=countersign_log,
        registry=registry,
        content_digest=content_digest,
        disclosure=disclosure,
        publisher_agent_id=publisher_agent_id,
        publish_time=publish_time,
    )
    if gate is not None:
        return gate

    gate = check_marking_resilience(
        claims_ai_generated=claims_ai_generated,
        marking_payload=marking_payload,
        expected_marking_digest=expected_marking_digest,
    )
    if not gate.allowed:
        return gate

    if ugc_capture:
        gate = ugc_probe(
            capture_digest=content_digest,
            attestation=capture_attestation,
        )
        if not gate.allowed:
            return gate

    gate = election_deepfake_check(
        content_kind=content_kind,
        source_attestation=election_source_attestation,
        human_review=countersign,
    )
    if not gate.allowed:
        return gate

    assert countersign is not None  # gate 1 passed
    return PublicationVerdict(
        allowed=True,
        reason="editorial gates passed: countersigned, disclosed, marking "
        "verified, capture/election checks clear",
        classification=AUTHORITATIVE,
        receipt_digest=countersign.receipt_digest,
    )


def editorial_audit_event(verdict: PublicationVerdict, *, action: str) -> dict[str, Any]:
    """Shape a publication verdict as an audit-chain event dict."""
    return {
        "event": EDITORIAL_DENIED_EVENT if not verdict.allowed else EDITORIAL_ALLOWED_EVENT,
        "action": action,
        "allowed": verdict.allowed,
        "reason": verdict.reason,
        "classification": verdict.classification,
        "receipt_digest": verdict.receipt_digest,
    }
