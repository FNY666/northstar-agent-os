"""Legal practice discipline (one-hundred-forty-sixth batch).

Absorbs the 2026 AI-in-legal-practice thread — a year in which courts
and regulators on four continents drew the same line: AI assists,
humans decide, and the evidence must be checkable.

* **India Supreme Court "Court AI Use Rules (draft) 2026"** —
  retrieval/drafting/translation/transcription allowed; AI deciding
  judicial outcomes banned; outcome prediction banned; lawyers using
  AI must disclose.
* **China Supreme People's Court (2026-03)** — "steady R&D,
  auxiliary positioning, judicial responsibility can only rest with
  judges"; Shenzhen Intermediate Court judicial vertical LLM
  empowered 600,000+ cases (state-media claim, unaudited).
* **Korea MOJ "trial-support AI" (live 2026-02)** — 271,839 Q&A in
  7 months across 3,178 judges, but no published accuracy or
  hallucination performance standards; AI use in judgments left
  unmanaged. (The unmanaged-use gap is what
  :func:`performance_standard_pin` closes.)
* **Brazil** — Galileu draft-judgment assistant approved for all
  labor courts (final judgments exclusively human); CNJ 615/2025
  risk-proportionate governance; the first court-document
  prompt-injection sanction (Parauapebas: white-on-white hidden
  instructions, fine of 10% of case value ≈ R$84,250).
* **Germany (Grundlagenpapier 2026)** — AI is not a layoff tool and
  not a judgment substitute; social-court AI-pleading flood
  (NRW 1,400 → 3,600 emergency procedures).
* **Quebec** — four court guidelines: judgments exclusively human,
  plus a warning on "hidden instructions in documents".
* **Hallucination sanctions** — HEC Paris Charlotin database hit
  1,635 cases by 2026-06 (~40 countries); 2026-Q1 sanctions ≈
  $145,000. Withers v. Aberdeen (both sides filed fictitious
  precedents; 4 sanctioned, 2 barred 2 years); 6th Circuit $30,000;
  Oregon's per-item formula (15 fictitious citations → dismissal
  with prejudice + $15,500); Lexos Media v. Overstock ($12,000:
  "citation verification is non-delegable"); India Supreme Court
  2026-07-02 (unverified AI citations = professional misconduct).
* **Connecticut** — prompt-injection filing cost the filer
  e-filing rights. **Arizona** — appeals court vacated a 10-year
  sentence over an AI-generated "statement" video of a deceased
  victim.

Fail-closed rules:

1. **Citation verification** — every citation signed into a brief
   must bind a first-level-database existence verification
   (``legal.fictitious_citation`` on anything else). The gate checks
   receipt consistency, not case law: digests recompute, signatures
   verify, the citation id and database id match, and the receipt is
   live at signing time. An expired or mismatched verification is
   the same as no verification (Charlotin lesson).
2. **AI-use disclosure** — a lawyer's AI use on a matter binds a
   lawyer-signed disclosure receipt naming the tool and the
   (closed-vocabulary) use kinds. Undisclosed use denies with
   ``legal.undisclosed_ai_use`` (India draft lesson).
3. **Advisory-only** — ``outcome_prediction`` and
   ``judgment_rendering`` are refused whole-class
   (``legal.outcome_prediction`` / ``legal.ai_judgment``). The use
   vocabulary is closed: anything not in the advisory list is a
   programming error, not a maybe.
4. **Human-signoff clock** — a court AI whose human override rate
   falls to ≤ 2% over ≥ 100 observed cases triggers
   ``legal.rubber_stamp`` (Korea managed-use lesson: override
   trending to zero is the audit signal, not a success metric).
5. **Prompt-injection screen** — filings are screened for hidden
   characters (zero-width), hidden-styling markup (white-on-white,
   font-size:0, display:none) and closed-vocabulary instruction
   patterns. Any hit denies with ``legal.hidden_instructions``
   (Parauapebas/Connecticut lesson). The screen is a tripwire, not
   a proof of intent.
6. **AI-evidence authentication** — AI-generated audio/video
   evidence defaults to inadmissible without a live
   authentication chain binding source capture and provenance
   (``legal.unverified_evidence``; Arizona lesson). Non-AI media
   is outside this gate's scope.
7. **Self-represented litigant channel** — filing assistance
   without a declared verification-assistance channel is
   ``NON_AUTHORITATIVE`` (sanction-last-resort: the gate degrades
   confidence rather than punishing the filer first).
8. **Performance standards** — court/legal AI without a bound,
   published performance standard (accuracy + hallucination rate
   with an eval-protocol digest) is ``NON_AUTHORITATIVE`` (Korea
   lesson).
9. **Confidentiality** — confidential client data leaving the
   matter binds a lawyer-signed purpose receipt; without it the
   export denies with ``legal.no_confidentiality_receipt``.

Honest boundary: receipts bind *declared* legal discipline —
digests recompute, signatures verify, chains link, vocabularies are
closed. The gate cannot prove a citation is good law, a disclosure
was understood, or a human actually exercised judgment. What it
guarantees: nothing unverifiable enters a filing, no prediction
masquerades as advice, and no confidential data leaves without a
purpose.

Deterministic: no wall-clock reads (callers inject integer epoch
timestamps), JCS canonical hashing, Ed25519 via the vendored
``ed25519`` module, digest comparisons via :func:`hmac.compare_digest`.
"""

from __future__ import annotations
from _domain_base import DomainError

import hmac
import re
from dataclasses import dataclass
from typing import Any, Mapping

import ed25519
from canonical_json import jcs_canonical_json, jcs_sha256_hex


LEGAL_SCHEMA_VERSION = "northstar.legal_agents.v1"

_GENESIS = "genesis"
_HEX64_LENGTH = 64
_HEX128_LENGTH = 128

#: Classification tiers (87th-batch binary semantics).
CLASS_AUTHORITATIVE = "authoritative"
CLASS_NON_AUTHORITATIVE = "non_authoritative"

#: Denial reason codes. All verdict reasons start with one of these.
DENY_FICTITIOUS_CITATION = "legal.fictitious_citation"
DENY_UNDISCLOSED_AI_USE = "legal.undisclosed_ai_use"
DENY_AI_JUDGMENT = "legal.ai_judgment"
DENY_OUTCOME_PREDICTION = "legal.outcome_prediction"
DENY_HIDDEN_INSTRUCTIONS = "legal.hidden_instructions"
DENY_UNVERIFIED_EVIDENCE = "legal.unverified_evidence"
DENY_NO_CONFIDENTIALITY_RECEIPT = "legal.no_confidentiality_receipt"
DENY_RUBBER_STAMP = "legal.rubber_stamp"

#: Advisory AI uses (closed vocabulary). Retrieval/drafting/
#: translation/transcription/review are assistance; anything else —
#: including any deciding use — is not advisory.
ADVISORY_USE_KINDS: tuple[str, ...] = (
    "retrieval",
    "drafting",
    "translation",
    "transcription",
    "review",
)

#: Uses refused whole-class (India draft 2026: no deciding, no
#: predicting).
DECIDING_USE_KINDS: tuple[str, ...] = (
    "outcome_prediction",
    "judgment_rendering",
)

#: Closed media vocabulary for the evidence gate.
EVIDENCE_MEDIA_KINDS: tuple[str, ...] = (
    "audio",
    "video",
)

#: Zero-width / invisible unicode codepoints screened in filings.
_HIDDEN_CHARS = ("\u200b", "\u200c", "\u200d", "\ufeff")

#: Hidden-styling markup patterns (white-on-white et al.).
_HIDDEN_STYLE_PATTERNS: tuple[str, ...] = (
    "color:#fff",
    "color:#ffffff",
    "color:white",
    "color: white",
    "font-size:0",
    "font-size: 0",
    "display:none",
    "display: none",
    "visibility:hidden",
    "visibility: hidden",
)

#: Closed instruction-injection pattern vocabulary.
_INSTRUCTION_PATTERNS: tuple[str, ...] = (
    "ignore previous instructions",
    "ignore all prior instructions",
    "disregard prior instructions",
    "disregard all instructions",
    "you are now",
    "new instructions:",
    "system prompt override",
    "override your instructions",
)

#: Minimum observations before the signoff clock can fire (permits
#: a ramp-up period; avoids punishing small pilots).
SIGNOFF_MIN_OBSERVATIONS = 100
#: Override-rate floor: at or below this, the human is rubber-stamping.
SIGNOFF_MAX_OVERRIDE_RATE = 0.02


class LegalError(DomainError):
    """A malformed receipt/record or a programming error.

    Raised for structural problems (bad digests, unknown use kinds,
    broken chains). Verification *failures* (unverified citation,
    hidden instructions, whole-class refusals) return a
    :class:`LegalVerdict` with ``allowed=False`` instead.
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
        raise LegalError(f"{field_name} must be a 64-char lowercase hex digest")
    return value


def _check_nonempty_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise LegalError(f"{field_name} must be a non-empty string")
    return value


def _check_ts(value: Any, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise LegalError(f"{field_name} must be a non-negative int epoch")
    return value


def _check_secret(value: Any, field_name: str) -> bytes:
    # The vendored ed25519 module takes a raw 32-byte seed.
    if not isinstance(value, bytes) or len(value) != 32:
        raise LegalError(f"{field_name} must be a 32-byte seed")
    return value


def _check_pubkey_hex(value: Any, field_name: str) -> str:
    if not _is_hex(value, 64):
        raise LegalError(f"{field_name} must be a 64-char hex Ed25519 pubkey")
    return value


def _check_sig_hex(value: Any, field_name: str) -> str:
    if not _is_hex(value, _HEX128_LENGTH):
        raise LegalError(f"{field_name} must be a 128-char hex Ed25519 signature")
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
    """Raise :class:`LegalError` if a receipt log is tampered/broken.

    Every entry must expose ``receipt_digest`` and ``prev_digest``
    and a ``_payload()`` method; the entries must form one chain from
    ``"genesis"`` with recomputing digests and valid signatures.
    """
    expected_prev = _GENESIS
    for entry in log:
        if not hmac.compare_digest(entry.receipt_digest, jcs_sha256_hex(entry._payload())):
            raise LegalError(
                f"{type_name} receipt {entry.receipt_id!r} digest does not recompute"
            )
        if not hmac.compare_digest(entry.prev_digest, expected_prev):
            raise LegalError(
                f"{type_name} receipt {entry.receipt_id!r} chain break: "
                f"expected prev {expected_prev!r}"
            )
        if not _verify_signature(
            entry.authority_pubkey_hex, entry._payload(), entry.signature_hex
        ):
            raise LegalError(
                f"{type_name} receipt {entry.receipt_id!r} authority signature invalid"
            )
        expected_prev = entry.receipt_digest


@dataclass(frozen=True)
class LegalVerdict:
    """Outcome of one legal-discipline check."""

    allowed: bool
    reason: str
    classification: str = CLASS_NON_AUTHORITATIVE
    receipt_digest: str = ""


def _deny(code: str, detail: str) -> LegalVerdict:
    return LegalVerdict(
        allowed=False,
        reason=f"{code}: {detail}",
        classification=CLASS_NON_AUTHORITATIVE,
    )


def _allow(detail: str, receipt_digest: str = "") -> LegalVerdict:
    return LegalVerdict(
        allowed=True,
        reason=detail,
        classification=CLASS_AUTHORITATIVE,
        receipt_digest=receipt_digest,
    )


def _allow_non_authoritative(detail: str) -> LegalVerdict:
    return LegalVerdict(
        allowed=True,
        reason=detail,
        classification=CLASS_NON_AUTHORITATIVE,
    )


# ---------------------------------------------------------------------------
# Citation verification receipts
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CitationVerificationReceipt:
    """A first-level-database existence check for one citation.

    ``existence_digest`` is the JCS digest of the database lookup
    record (database id + citation id + normalized citation text).
    The gate recomputes nothing against the live database — it checks
    that the receipt is well-formed, live, and bound to *this*
    citation in *this* database. Citation verification is
    non-delegable: the receipt must exist before signing.
    """

    receipt_id: str
    citation_id: str
    database_id: str
    existence_digest: str
    verified_by: str
    authority_pubkey_hex: str
    signature_hex: str
    verified_at: int
    expires_at: int
    prev_digest: str = _GENESIS
    receipt_digest: str = ""
    schema_version: str = LEGAL_SCHEMA_VERSION

    def _payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "citation_id": self.citation_id,
            "database_id": self.database_id,
            "existence_digest": self.existence_digest,
            "verified_by": self.verified_by,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
            "verified_at": self.verified_at,
            "expires_at": self.expires_at,
            "schema_version": self.schema_version,
        }


def citation_verification_receipt(
    *,
    receipt_id: str,
    citation_id: str,
    database_id: str,
    existence_digest: str,
    verified_by: str,
    authority_secret: bytes,
    verified_at: int,
    expires_at: int,
    prev_digest: str = _GENESIS,
) -> CitationVerificationReceipt:
    """Issue an authority-signed citation existence verification.

    Fail-closed at issuance: ``expires_at <= verified_at`` raises.
    """
    _check_secret(authority_secret, "authority_secret")
    receipt_id = _check_nonempty_str(receipt_id, "receipt_id")
    citation_id = _check_nonempty_str(citation_id, "citation_id")
    database_id = _check_nonempty_str(database_id, "database_id")
    existence_digest = _check_hex64(existence_digest, "existence_digest")
    verified_by = _check_nonempty_str(verified_by, "verified_by")
    verified_at = _check_ts(verified_at, "verified_at")
    expires_at = _check_ts(expires_at, "expires_at")
    if expires_at <= verified_at:
        raise LegalError("expires_at must be after verified_at")
    if not isinstance(prev_digest, str) or not prev_digest:
        raise LegalError("prev_digest must be a non-empty string")

    authority_pubkey_hex = ed25519.public_key(authority_secret).hex()
    bare = CitationVerificationReceipt(
        receipt_id=receipt_id,
        citation_id=citation_id,
        database_id=database_id,
        existence_digest=existence_digest,
        verified_by=verified_by,
        authority_pubkey_hex=authority_pubkey_hex,
        signature_hex="00" * _HEX128_LENGTH,  # placeholder; replaced by _seal
        verified_at=verified_at,
        expires_at=expires_at,
        prev_digest=prev_digest,
    )
    return _seal(bare, bare._payload(), authority_secret)


def check_citation(
    *,
    citation_id: str,
    database_id: str,
    verification: CitationVerificationReceipt | None,
    check_time: int,
) -> LegalVerdict:
    """Gate a citation before it is signed into a brief.

    Fail-closed: no verification → ``legal.fictitious_citation``.
    A verification bound to a different citation or database, an
    expired verification, or a bad authority signature all deny
    with the same code (Charlotin lesson: citation verification is
    non-delegable, and an expired check is no check).
    """
    citation_id = _check_nonempty_str(citation_id, "citation_id")
    database_id = _check_nonempty_str(database_id, "database_id")
    check_time = _check_ts(check_time, "check_time")
    if verification is None:
        return _deny(
            DENY_FICTITIOUS_CITATION,
            f"citation {citation_id!r} has no database existence verification",
        )
    if verification.citation_id != citation_id:
        return _deny(
            DENY_FICTITIOUS_CITATION,
            "verification binds a different citation",
        )
    if verification.database_id != database_id:
        return _deny(
            DENY_FICTITIOUS_CITATION,
            "verification binds a different database",
        )
    if not (verification.verified_at <= check_time < verification.expires_at):
        return _deny(
            DENY_FICTITIOUS_CITATION,
            "verification is not live at signing time",
        )
    if not hmac.compare_digest(
        verification.receipt_digest, jcs_sha256_hex(verification._payload())
    ):
        return _deny(DENY_FICTITIOUS_CITATION, "verification digest does not recompute")
    if not _verify_signature(
        verification.authority_pubkey_hex,
        verification._payload(),
        verification.signature_hex,
    ):
        return _deny(DENY_FICTITIOUS_CITATION, "verification authority signature invalid")
    return _allow(
        f"citation {citation_id!r} verified in {database_id!r}",
        receipt_digest=verification.receipt_digest,
    )


# ---------------------------------------------------------------------------
# AI-use disclosure receipts
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AIDisclosureReceipt:
    """A lawyer's signed disclosure of AI use on a matter.

    ``use_kinds`` is a closed vocabulary (see
    :data:`ADVISORY_USE_KINDS`); deciding uses cannot be disclosed
    into permissibility — they are refused whole-class by
    :func:`advisory_only_pin`.
    """

    receipt_id: str
    matter_id: str
    lawyer_id: str
    ai_tool_id: str
    use_kinds: tuple[str, ...]
    lawyer_pubkey_hex: str
    signature_hex: str
    disclosed_at: int
    receipt_digest: str = ""
    schema_version: str = LEGAL_SCHEMA_VERSION

    def _payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "matter_id": self.matter_id,
            "lawyer_id": self.lawyer_id,
            "ai_tool_id": self.ai_tool_id,
            "use_kinds": list(self.use_kinds),
            "lawyer_pubkey_hex": self.lawyer_pubkey_hex,
            "disclosed_at": self.disclosed_at,
            "schema_version": self.schema_version,
        }


def ai_disclosure_receipt(
    *,
    receipt_id: str,
    matter_id: str,
    lawyer_id: str,
    ai_tool_id: str,
    use_kinds: tuple[str, ...],
    lawyer_secret: bytes,
    disclosed_at: int,
) -> AIDisclosureReceipt:
    """Issue a lawyer-signed AI-use disclosure.

    Fail-closed at issuance: empty ``use_kinds`` raises, and any
    deciding use kind raises (disclosure cannot launder a
    whole-class refusal).
    """
    _check_secret(lawyer_secret, "lawyer_secret")
    receipt_id = _check_nonempty_str(receipt_id, "receipt_id")
    matter_id = _check_nonempty_str(matter_id, "matter_id")
    lawyer_id = _check_nonempty_str(lawyer_id, "lawyer_id")
    ai_tool_id = _check_nonempty_str(ai_tool_id, "ai_tool_id")
    if not isinstance(use_kinds, (tuple, list)) or not use_kinds:
        raise LegalError("use_kinds must be a non-empty tuple/list")
    use_kinds = tuple(use_kinds)
    for kind in use_kinds:
        if kind not in ADVISORY_USE_KINDS:
            raise LegalError(
                f"use_kind must be one of {ADVISORY_USE_KINDS}, saw {kind!r}"
            )
    disclosed_at = _check_ts(disclosed_at, "disclosed_at")

    lawyer_pubkey_hex = ed25519.public_key(lawyer_secret).hex()
    bare = AIDisclosureReceipt(
        receipt_id=receipt_id,
        matter_id=matter_id,
        lawyer_id=lawyer_id,
        ai_tool_id=ai_tool_id,
        use_kinds=use_kinds,
        lawyer_pubkey_hex=lawyer_pubkey_hex,
        signature_hex="00" * _HEX128_LENGTH,  # placeholder; replaced by _seal
        disclosed_at=disclosed_at,
    )
    return _seal(bare, bare._payload(), lawyer_secret)


def check_ai_use_disclosure(
    *,
    matter_id: str,
    lawyer_id: str,
    ai_tool_id: str,
    use_kinds: tuple[str, ...],
    disclosure: AIDisclosureReceipt | None,
    check_time: int,
) -> LegalVerdict:
    """Gate a lawyer's AI use on a matter against their disclosure.

    Fail-closed: undisclosed AI use denies with
    ``legal.undisclosed_ai_use`` (India draft lesson). A disclosure
    for a different matter, lawyer, or tool, or one that does not
    cover every asserted use kind, also denies.
    """
    matter_id = _check_nonempty_str(matter_id, "matter_id")
    lawyer_id = _check_nonempty_str(lawyer_id, "lawyer_id")
    ai_tool_id = _check_nonempty_str(ai_tool_id, "ai_tool_id")
    if not isinstance(use_kinds, (tuple, list)) or not use_kinds:
        raise LegalError("use_kinds must be a non-empty tuple/list")
    use_kinds = tuple(use_kinds)
    check_time = _check_ts(check_time, "check_time")
    if disclosure is None:
        return _deny(
            DENY_UNDISCLOSED_AI_USE,
            f"lawyer {lawyer_id!r} has no AI-use disclosure on matter {matter_id!r}",
        )
    if (
        disclosure.matter_id != matter_id
        or disclosure.lawyer_id != lawyer_id
        or disclosure.ai_tool_id != ai_tool_id
    ):
        return _deny(DENY_UNDISCLOSED_AI_USE, "disclosure binds a different matter/lawyer/tool")
    if disclosure.disclosed_at > check_time:
        return _deny(DENY_UNDISCLOSED_AI_USE, "disclosure is dated after the use")
    uncovered = [k for k in use_kinds if k not in disclosure.use_kinds]
    if uncovered:
        return _deny(
            DENY_UNDISCLOSED_AI_USE,
            f"use kinds not covered by disclosure: {uncovered}",
        )
    if not hmac.compare_digest(
        disclosure.receipt_digest, jcs_sha256_hex(disclosure._payload())
    ):
        return _deny(DENY_UNDISCLOSED_AI_USE, "disclosure digest does not recompute")
    if not _verify_signature(
        disclosure.lawyer_pubkey_hex, disclosure._payload(), disclosure.signature_hex
    ):
        return _deny(DENY_UNDISCLOSED_AI_USE, "disclosure lawyer signature invalid")
    return _allow(
        f"AI use {sorted(use_kinds)} disclosed on matter {matter_id!r}",
        receipt_digest=disclosure.receipt_digest,
    )


# ---------------------------------------------------------------------------
# Advisory-only pin
# ---------------------------------------------------------------------------


def advisory_only_pin(*, use_kind: str) -> LegalVerdict:
    """Pin an AI use to the advisory vocabulary.

    ``outcome_prediction`` and ``judgment_rendering`` are refused
    whole-class (India draft 2026; Germany Grundlagenpapier 2026;
    Quebec guidelines). Any use kind outside the closed advisory
    vocabulary is a programming error (:class:`LegalError`), never
    a silent maybe.
    """
    if not isinstance(use_kind, str) or not use_kind:
        raise LegalError("use_kind must be a non-empty string")
    if use_kind == "outcome_prediction":
        return _deny(
            DENY_OUTCOME_PREDICTION,
            "outcome prediction is refused whole-class",
        )
    if use_kind == "judgment_rendering":
        return _deny(
            DENY_AI_JUDGMENT,
            "AI deciding judicial outcomes is refused whole-class",
        )
    if use_kind not in ADVISORY_USE_KINDS:
        raise LegalError(
            f"use_kind must be one of {ADVISORY_USE_KINDS + DECIDING_USE_KINDS}, "
            f"saw {use_kind!r}"
        )
    return _allow(f"advisory use {use_kind!r} is within the assistance vocabulary")


# ---------------------------------------------------------------------------
# Human-signoff clock
# ---------------------------------------------------------------------------


def human_signoff_clock(
    *,
    total_cases: int,
    human_overrides: int,
    min_observations: int = SIGNOFF_MIN_OBSERVATIONS,
    max_override_rate: float = SIGNOFF_MAX_OVERRIDE_RATE,
) -> LegalVerdict:
    """Audit-trigger for rubber-stamp human supervision.

    A court AI whose humans override ≤ 2% of ≥ 100 observed cases is
    not being supervised — the override rate trending to zero is the
    audit signal (Korea managed-use lesson). Below the observation
    floor the clock cannot fire; the deployment stays
    ``NON_AUTHORITATIVE`` until it earns a verdict.
    """
    if not isinstance(total_cases, int) or isinstance(total_cases, bool) or total_cases < 0:
        raise LegalError("total_cases must be a non-negative int")
    if (
        not isinstance(human_overrides, int)
        or isinstance(human_overrides, bool)
        or human_overrides < 0
    ):
        raise LegalError("human_overrides must be a non-negative int")
    if human_overrides > total_cases:
        raise LegalError("human_overrides cannot exceed total_cases")
    if total_cases < min_observations:
        return _allow_non_authoritative(
            f"only {total_cases} observations (< {min_observations}); "
            "signoff clock cannot fire yet"
        )
    rate = human_overrides / total_cases
    if rate <= max_override_rate:
        return _deny(
            DENY_RUBBER_STAMP,
            f"override rate {rate:.4f} over {total_cases} cases is at or below "
            f"{max_override_rate}: human supervision is rubber-stamping",
        )
    return _allow(
        f"override rate {rate:.4f} over {total_cases} cases shows live supervision"
    )


# ---------------------------------------------------------------------------
# Prompt-injection screen
# ---------------------------------------------------------------------------


def prompt_injection_screen(*, filing_text: str) -> LegalVerdict:
    """Screen a filing for hidden instructions.

    Tripwire, not a proof of intent: any zero-width character, any
    hidden-styling markup pattern, or any closed-vocabulary
    instruction pattern denies with ``legal.hidden_instructions``
    (Parauapebas/Connecticut lesson). The screen is deliberately
    conservative — a false positive is a re-file, a false negative
    is an injection.
    """
    if not isinstance(filing_text, str):
        raise LegalError("filing_text must be a string")
    for char in _HIDDEN_CHARS:
        if char in filing_text:
            return _deny(
                DENY_HIDDEN_INSTRUCTIONS,
                f"hidden unicode character U+{ord(char):04X} in filing",
            )
    lowered = filing_text.lower()
    for pattern in _HIDDEN_STYLE_PATTERNS:
        if pattern in lowered:
            return _deny(
                DENY_HIDDEN_INSTRUCTIONS,
                f"hidden-styling markup pattern {pattern!r} in filing",
            )
    for pattern in _INSTRUCTION_PATTERNS:
        if pattern in lowered:
            return _deny(
                DENY_HIDDEN_INSTRUCTIONS,
                f"instruction-injection pattern {pattern!r} in filing",
            )
    return _allow("filing text shows no hidden instructions")


# ---------------------------------------------------------------------------
# AI-evidence authentication
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EvidenceAuthenticationReceipt:
    """Authentication chain for AI-generated audio/video evidence.

    Binds the source capture digest and the provenance-chain digest
    under an authority signature. Without a live chain, AI-generated
    media defaults to inadmissible (Arizona lesson).
    """

    receipt_id: str
    evidence_id: str
    media_kind: str
    ai_generated: bool
    source_capture_digest: str
    provenance_chain_digest: str
    authenticated_by: str
    authority_pubkey_hex: str
    signature_hex: str
    authenticated_at: int
    expires_at: int
    prev_digest: str = _GENESIS
    receipt_digest: str = ""
    schema_version: str = LEGAL_SCHEMA_VERSION

    def _payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "evidence_id": self.evidence_id,
            "media_kind": self.media_kind,
            "ai_generated": self.ai_generated,
            "source_capture_digest": self.source_capture_digest,
            "provenance_chain_digest": self.provenance_chain_digest,
            "authenticated_by": self.authenticated_by,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
            "authenticated_at": self.authenticated_at,
            "expires_at": self.expires_at,
            "schema_version": self.schema_version,
        }


def evidence_authentication_receipt(
    *,
    receipt_id: str,
    evidence_id: str,
    media_kind: str,
    ai_generated: bool,
    source_capture_digest: str,
    provenance_chain_digest: str,
    authenticated_by: str,
    authority_secret: bytes,
    authenticated_at: int,
    expires_at: int,
    prev_digest: str = _GENESIS,
) -> EvidenceAuthenticationReceipt:
    """Issue an authority-signed evidence authentication.

    Fail-closed at issuance: ``expires_at <= authenticated_at``
    raises; non-AI media needs no receipt, so asserting
    ``ai_generated=False`` on a receipt is refused (a receipt that
    authenticates nothing is a forgery surface).
    """
    _check_secret(authority_secret, "authority_secret")
    receipt_id = _check_nonempty_str(receipt_id, "receipt_id")
    evidence_id = _check_nonempty_str(evidence_id, "evidence_id")
    if media_kind not in EVIDENCE_MEDIA_KINDS:
        raise LegalError(
            f"media_kind must be one of {EVIDENCE_MEDIA_KINDS}, saw {media_kind!r}"
        )
    if not isinstance(ai_generated, bool):
        raise LegalError("ai_generated must be a bool")
    if not ai_generated:
        raise LegalError("non-AI media needs no authentication receipt")
    source_capture_digest = _check_hex64(source_capture_digest, "source_capture_digest")
    provenance_chain_digest = _check_hex64(provenance_chain_digest, "provenance_chain_digest")
    authenticated_by = _check_nonempty_str(authenticated_by, "authenticated_by")
    authenticated_at = _check_ts(authenticated_at, "authenticated_at")
    expires_at = _check_ts(expires_at, "expires_at")
    if expires_at <= authenticated_at:
        raise LegalError("expires_at must be after authenticated_at")
    if not isinstance(prev_digest, str) or not prev_digest:
        raise LegalError("prev_digest must be a non-empty string")

    authority_pubkey_hex = ed25519.public_key(authority_secret).hex()
    bare = EvidenceAuthenticationReceipt(
        receipt_id=receipt_id,
        evidence_id=evidence_id,
        media_kind=media_kind,
        ai_generated=ai_generated,
        source_capture_digest=source_capture_digest,
        provenance_chain_digest=provenance_chain_digest,
        authenticated_by=authenticated_by,
        authority_pubkey_hex=authority_pubkey_hex,
        signature_hex="00" * _HEX128_LENGTH,  # placeholder; replaced by _seal
        authenticated_at=authenticated_at,
        expires_at=expires_at,
        prev_digest=prev_digest,
    )
    return _seal(bare, bare._payload(), authority_secret)


def ai_evidence_gate(
    *,
    evidence_id: str,
    media_kind: str,
    ai_generated: bool,
    authentication: EvidenceAuthenticationReceipt | None,
    check_time: int,
) -> LegalVerdict:
    """Gate AI-generated audio/video evidence.

    AI-generated media without a live, bound authentication chain
    denies with ``legal.unverified_evidence``. Non-AI media is
    outside this gate's scope and passes. An authentication receipt
    bound to different evidence, a different media kind, expired, or
    with a bad signature denies with the same code.
    """
    evidence_id = _check_nonempty_str(evidence_id, "evidence_id")
    if media_kind not in EVIDENCE_MEDIA_KINDS:
        raise LegalError(
            f"media_kind must be one of {EVIDENCE_MEDIA_KINDS}, saw {media_kind!r}"
        )
    if not isinstance(ai_generated, bool):
        raise LegalError("ai_generated must be a bool")
    check_time = _check_ts(check_time, "check_time")
    if not ai_generated:
        return _allow(f"evidence {evidence_id!r} is not AI-generated; gate not applicable")
    if authentication is None:
        return _deny(
            DENY_UNVERIFIED_EVIDENCE,
            f"AI-generated evidence {evidence_id!r} has no authentication chain",
        )
    if authentication.evidence_id != evidence_id:
        return _deny(DENY_UNVERIFIED_EVIDENCE, "authentication binds different evidence")
    if authentication.media_kind != media_kind:
        return _deny(DENY_UNVERIFIED_EVIDENCE, "authentication binds a different media kind")
    if not (authentication.authenticated_at <= check_time < authentication.expires_at):
        return _deny(DENY_UNVERIFIED_EVIDENCE, "authentication is not live at check time")
    if not hmac.compare_digest(
        authentication.receipt_digest, jcs_sha256_hex(authentication._payload())
    ):
        return _deny(DENY_UNVERIFIED_EVIDENCE, "authentication digest does not recompute")
    if not _verify_signature(
        authentication.authority_pubkey_hex,
        authentication._payload(),
        authentication.signature_hex,
    ):
        return _deny(DENY_UNVERIFIED_EVIDENCE, "authentication authority signature invalid")
    return _allow(
        f"AI-generated evidence {evidence_id!r} carries a live authentication chain",
        receipt_digest=authentication.receipt_digest,
    )


# ---------------------------------------------------------------------------
# Self-represented litigant verification channel
# ---------------------------------------------------------------------------


def lip_verification_aid(
    *,
    matter_id: str,
    channel_id: str | None,
    check_time: int,
) -> LegalVerdict:
    """Degrade, don't punish, the self-represented filer.

    Filing assistance with no declared verification-assistance
    channel is ``NON_AUTHORITATIVE`` (sanction-last-resort: a missing
    channel is a confidence problem, not a misconduct finding).
    A declared channel keeps the assistance authoritative.
    """
    matter_id = _check_nonempty_str(matter_id, "matter_id")
    check_time = _check_ts(check_time, "check_time")
    if channel_id is None or not str(channel_id).strip():
        return _allow_non_authoritative(
            f"matter {matter_id!r}: filing assistance has no verification-"
            "assistance channel; treat output as unverified"
        )
    return _allow(
        f"matter {matter_id!r}: verification-assistance channel {channel_id!r} declared"
    )


# ---------------------------------------------------------------------------
# Performance standards
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PerformanceStandardReceipt:
    """A published performance standard for a court/legal AI system.

    Binds accuracy and hallucination rate (basis points) plus the
    eval-protocol digest, so "we measured it" is a checkable claim
    (Korea lesson: 271,839 Q&A with no published standard is
    unmanaged use).
    """

    receipt_id: str
    system_id: str
    accuracy_bps: int
    hallucination_rate_bps: int
    eval_protocol_digest: str
    measured_at: int
    expires_at: int
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str = _GENESIS
    receipt_digest: str = ""
    schema_version: str = LEGAL_SCHEMA_VERSION

    def _payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "system_id": self.system_id,
            "accuracy_bps": self.accuracy_bps,
            "hallucination_rate_bps": self.hallucination_rate_bps,
            "eval_protocol_digest": self.eval_protocol_digest,
            "measured_at": self.measured_at,
            "expires_at": self.expires_at,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
            "schema_version": self.schema_version,
        }


def performance_standard_receipt(
    *,
    receipt_id: str,
    system_id: str,
    accuracy_bps: int,
    hallucination_rate_bps: int,
    eval_protocol_digest: str,
    authority_secret: bytes,
    measured_at: int,
    expires_at: int,
    prev_digest: str = _GENESIS,
) -> PerformanceStandardReceipt:
    """Issue an authority-signed performance standard.

    Fail-closed at issuance: rates must be basis points (0–10000)
    and ``expires_at <= measured_at`` raises.
    """
    _check_secret(authority_secret, "authority_secret")
    receipt_id = _check_nonempty_str(receipt_id, "receipt_id")
    system_id = _check_nonempty_str(system_id, "system_id")
    for name, value in (("accuracy_bps", accuracy_bps), ("hallucination_rate_bps", hallucination_rate_bps)):
        if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 10_000:
            raise LegalError(f"{name} must be an int in basis points (0-10000)")
    eval_protocol_digest = _check_hex64(eval_protocol_digest, "eval_protocol_digest")
    measured_at = _check_ts(measured_at, "measured_at")
    expires_at = _check_ts(expires_at, "expires_at")
    if expires_at <= measured_at:
        raise LegalError("expires_at must be after measured_at")
    if not isinstance(prev_digest, str) or not prev_digest:
        raise LegalError("prev_digest must be a non-empty string")

    authority_pubkey_hex = ed25519.public_key(authority_secret).hex()
    bare = PerformanceStandardReceipt(
        receipt_id=receipt_id,
        system_id=system_id,
        accuracy_bps=accuracy_bps,
        hallucination_rate_bps=hallucination_rate_bps,
        eval_protocol_digest=eval_protocol_digest,
        authority_pubkey_hex=authority_pubkey_hex,
        signature_hex="00" * _HEX128_LENGTH,  # placeholder; replaced by _seal
        measured_at=measured_at,
        expires_at=expires_at,
        prev_digest=prev_digest,
    )
    return _seal(bare, bare._payload(), authority_secret)


def performance_standard_pin(
    *,
    system_id: str,
    standard: PerformanceStandardReceipt | None,
    check_time: int,
) -> LegalVerdict:
    """Gate a court/legal AI system on a published performance standard.

    No bound, live standard → ``NON_AUTHORITATIVE`` (the system may
    run, but its outputs cannot be treated as authoritative). A
    standard for a different system, an expired standard, or a bad
    signature degrades with the same classification.
    """
    system_id = _check_nonempty_str(system_id, "system_id")
    check_time = _check_ts(check_time, "check_time")
    if standard is None:
        return _allow_non_authoritative(
            f"system {system_id!r} has no published performance standard"
        )
    if standard.system_id != system_id:
        return _allow_non_authoritative("standard binds a different system")
    if not (standard.measured_at <= check_time < standard.expires_at):
        return _allow_non_authoritative("standard is not live at check time")
    if not hmac.compare_digest(
        standard.receipt_digest, jcs_sha256_hex(standard._payload())
    ):
        return _allow_non_authoritative("standard digest does not recompute")
    if not _verify_signature(
        standard.authority_pubkey_hex, standard._payload(), standard.signature_hex
    ):
        return _allow_non_authoritative("standard authority signature invalid")
    return _allow(
        f"system {system_id!r} binds a live performance standard",
        receipt_digest=standard.receipt_digest,
    )


# ---------------------------------------------------------------------------
# Confidentiality purpose receipts
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ConfidentialityPurposeReceipt:
    """A lawyer-signed purpose binding for confidential client data.

    Confidential data leaving the matter must name its purpose and
    recipient; the receipt is lawyer-signed so the purpose is
    attributable (not a vendor's "trust us").
    """

    receipt_id: str
    matter_id: str
    data_scope: str
    purpose: str
    recipient: str
    lawyer_id: str
    lawyer_pubkey_hex: str
    signature_hex: str
    issued_at: int
    expires_at: int
    receipt_digest: str = ""
    schema_version: str = LEGAL_SCHEMA_VERSION

    def _payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "matter_id": self.matter_id,
            "data_scope": self.data_scope,
            "purpose": self.purpose,
            "recipient": self.recipient,
            "lawyer_id": self.lawyer_id,
            "lawyer_pubkey_hex": self.lawyer_pubkey_hex,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "schema_version": self.schema_version,
        }


def confidentiality_purpose_receipt(
    *,
    receipt_id: str,
    matter_id: str,
    data_scope: str,
    purpose: str,
    recipient: str,
    lawyer_id: str,
    lawyer_secret: bytes,
    issued_at: int,
    expires_at: int,
) -> ConfidentialityPurposeReceipt:
    """Issue a lawyer-signed confidentiality purpose receipt.

    Fail-closed at issuance: ``expires_at <= issued_at`` raises.
    """
    _check_secret(lawyer_secret, "lawyer_secret")
    receipt_id = _check_nonempty_str(receipt_id, "receipt_id")
    matter_id = _check_nonempty_str(matter_id, "matter_id")
    data_scope = _check_nonempty_str(data_scope, "data_scope")
    purpose = _check_nonempty_str(purpose, "purpose")
    recipient = _check_nonempty_str(recipient, "recipient")
    lawyer_id = _check_nonempty_str(lawyer_id, "lawyer_id")
    issued_at = _check_ts(issued_at, "issued_at")
    expires_at = _check_ts(expires_at, "expires_at")
    if expires_at <= issued_at:
        raise LegalError("expires_at must be after issued_at")

    lawyer_pubkey_hex = ed25519.public_key(lawyer_secret).hex()
    bare = ConfidentialityPurposeReceipt(
        receipt_id=receipt_id,
        matter_id=matter_id,
        data_scope=data_scope,
        purpose=purpose,
        recipient=recipient,
        lawyer_id=lawyer_id,
        lawyer_pubkey_hex=lawyer_pubkey_hex,
        signature_hex="00" * _HEX128_LENGTH,  # placeholder; replaced by _seal
        issued_at=issued_at,
        expires_at=expires_at,
    )
    return _seal(bare, bare._payload(), lawyer_secret)


def confidentiality_circuit_breaker(
    *,
    matter_id: str,
    data_scope: str,
    purpose: str,
    recipient: str,
    receipt: ConfidentialityPurposeReceipt | None,
    check_time: int,
) -> LegalVerdict:
    """Gate confidential client data leaving the matter.

    Fail-closed: no live, bound, lawyer-signed purpose receipt →
    ``legal.no_confidentiality_receipt``. A receipt for a different
    matter/scope/purpose/recipient, an expired receipt, or a bad
    lawyer signature denies with the same code.
    """
    matter_id = _check_nonempty_str(matter_id, "matter_id")
    data_scope = _check_nonempty_str(data_scope, "data_scope")
    purpose = _check_nonempty_str(purpose, "purpose")
    recipient = _check_nonempty_str(recipient, "recipient")
    check_time = _check_ts(check_time, "check_time")
    if receipt is None:
        return _deny(
            DENY_NO_CONFIDENTIALITY_RECEIPT,
            f"confidential data {data_scope!r} leaves matter {matter_id!r} "
            "with no purpose receipt",
        )
    if (
        receipt.matter_id != matter_id
        or receipt.data_scope != data_scope
        or receipt.purpose != purpose
        or receipt.recipient != recipient
    ):
        return _deny(
            DENY_NO_CONFIDENTIALITY_RECEIPT,
            "purpose receipt binds a different matter/scope/purpose/recipient",
        )
    if not (receipt.issued_at <= check_time < receipt.expires_at):
        return _deny(DENY_NO_CONFIDENTIALITY_RECEIPT, "purpose receipt is not live")
    if not hmac.compare_digest(
        receipt.receipt_digest, jcs_sha256_hex(receipt._payload())
    ):
        return _deny(DENY_NO_CONFIDENTIALITY_RECEIPT, "purpose receipt digest does not recompute")
    if not _verify_signature(
        receipt.lawyer_pubkey_hex, receipt._payload(), receipt.signature_hex
    ):
        return _deny(DENY_NO_CONFIDENTIALITY_RECEIPT, "purpose receipt lawyer signature invalid")
    return _allow(
        f"confidential data {data_scope!r} leaves matter {matter_id!r} "
        f"for {purpose!r} to {recipient!r}",
        receipt_digest=receipt.receipt_digest,
    )
