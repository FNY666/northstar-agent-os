"""Finance AI discipline (one-hundred-fifty-fifth batch).

Absorbs the 2026 AI-finance research thread
(``research_notes/beyond-ai-finance-20261004/report-20261004b.md``):

* **Disparate-impact reversal** — CFPB's 2026-07-21 final rule deleted
  disparate-impact liability under ECOA/Reg B: an AI credit model's
  racially skewed outcome is no longer per se unlawful; intent must be
  proven. OCC had quietly done the same a year earlier. Illinois
  answered with the Civil Rights Safeguard Act (enacted 2026-07-31,
  effective 2027-01-01), restoring disparate impact at state level;
  California, New York, New Jersey recognize the theory too. The
  Northstar answer is a *self-binding* proxy screen: models declare
  features, proxy features that reconstruct protected classes need
  either whole-class removal or a less-discriminatory-alternative
  proof — regardless of which theory the current federal rule keeps.
* **Account closure** — UK from 2026-04-28: 90 days' written notice
  plus a clear explanation, challengeable via the Financial
  Ombudsman (accounts opened on/after that date; older accounts:
  2 months, no reason required). Fraud suspicion allows shorter
  notice. UK s.333A Proceeds of Crime Act 2002 makes tipping off a
  criminal offence — the one lawful silence, which here is bound as
  an explicit "legally barred" receipt rather than opaque quiet.
* **Freeze proportionality** — India RBI draft (comments closed
  2026-10-02, effective 2027-04-01, following a 2026-08-04 Supreme
  Court order): debit hold capped at 60 days (not whole-account
  freezes), credits allowed, customer gets 20 days to rebut with
  ID/transaction proof, banks must review within 10 days.
* **Korea AI Basic Act (2026-01)** — loan review is "high-impact
  AI": transparency + safety obligations; even profiling results
  merely *referenced* by a banker may qualify. Shadow AI is
  ``finance.shadow_ai`` here.
* **Insurance pricing** — ASIC's 2026 review of five motor insurers:
  none explained the key premium factors or why premiums changed.
  Citizens Advice "ethnicity penalty": people of colour paid £250
  more on average for car insurance (2021 research).
* **Deterministic rules layer** (Cureus 2026-07): a seeded 14%
  proxy-pricing disparity cut to 0.14% by a rules layer that logged
  *every* evaluation, not just interceptions (+5ms latency, 20%
  intervention rate). "Evidence is a query, not a project."
* **German bank practice** — auto-accept / auto-decline plus a
  third lane: "an Kreditentscheider übergeben" (escalate to a human
  credit officer); simpler linear models preferred for
  interpretability.
* **ECOA / CDT** — Wells Fargo's "Enhanced Credit Score" reported
  to classify Black applicants as higher risk than similarly
  qualified white applicants; ECOA requires *specific,
  understandable* adverse-action reasons: "model output" is not
  compliant.
* **Debanking** — FCA: 343,000 UK closures in 2022, ~408,000 in
  2024; CFG 2024: 92% of UK charities had a banking issue; Muslim
  Charities Forum: 42% had services withdrawn. A low-credibility
  UK Finance cross-bank marker-sharing platform claim (zerohedge)
  is encoded as a guarded design: shared markers bind appeal
  receipts, or they are system-exclusionary by default.

Northstar mapping: closures bind written-notice receipts with the
jurisdiction's minimum notice period (90 days UK post-2026-04-28);
short-notice closures are ``finance.short_notice_closure`` unless a
tipping-off bar receipt is bound (UK s.333A lesson); freezes must
be proportional to the disputed amount (``finance.disproportionate_freeze``)
with a 60-day debit-hold clock, a 20-day customer rebuttal window,
and a 10-day bank review clock (RBI lesson); flags are leads —
automatic closure from a flag without human review is
``finance.no_human_review`` and without FP-rate disclosure is
``finance.fp_undisclosed``; proxy features reconstructing protected
classes need removal or a less-discriminatory-alternative proof
(``finance.proxy_feature``); adverse-action receipts must carry
specific understandable reasons — "model output" is
``finance.vague_reason``; the pricing rules layer logs every
evaluation and disparities over threshold are
``finance.proxy_pricing_disparity`` (Cureus lesson); shared crime
markers without appeal receipts are ``finance.systemic_exclusion``;
unregistered high-impact financial AI is ``finance.shadow_ai``;
auto-decisions without a human escalation lane are
``finance.no_human_lane`` (German third-lane lesson); premium quotes
without key-factor and year-over-year explanations are
``finance.premium_unexplained`` (ASIC lesson); lawful silence is
bound as an explicit receipt, never assumed.

Deterministic: no wall-clock reads (callers inject ``now`` as an
integer epoch), canonical JCS hashing (ninety-fifth batch), and all
digest comparisons use :func:`hmac.compare_digest`.

Honest scope:

* The receipts bind the *declared* financial discipline; they do
  not end credit exclusion. A signed notice receipt does not make
  the underlying closure fair.
* Proxy screens are feature-list declarations: a proxy re-encoded
  through unlisted interactions is not caught here — that needs
  statistical outcome audits plus outside review.
* Notice periods and clocks (90-day, 60-day, 20-day, 10-day) are
  bench parameters from the 2026 research sweep; confirm against
  the jurisdiction's own banking rules before reliance.
* Signature checks bind authority to receipt; they cannot prove
  the named human actually reviewed the file.
* The tipping-off bar receipt records a *claim* of legal
  prohibition; it cannot verify the underlying criminal statute
  applies.
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


FINANCE_SCHEMA_VERSION = "northstar.finance.v1"

_GENESIS = "genesis"
_HEX64_LENGTH = 64
_DAY_S = 86_400

CLASS_AUTHORITATIVE = "authoritative"
CLASS_NON_AUTHORITATIVE = "non_authoritative"

#: Minimum closure-notice period (days) for UK accounts opened on/after
#: 2026-04-28. Older accounts: 60 days, reason optional.
NOTICE_MIN_DAYS_NEW = 90
NOTICE_MIN_DAYS_OLD = 60

#: India RBI draft: debit hold capped at 60 days, not whole-account.
DEBIT_HOLD_MAX_S = 60 * _DAY_S

#: Customer rebuttal window and bank review deadline (RBI draft).
REBUTTAL_WINDOW_S = 20 * _DAY_S
BANK_REVIEW_MAX_S = 10 * _DAY_S

#: Receipt shelf lives.
NOTICE_MAX_AGE_S = 365 * _DAY_S
FREEZE_MAX_AGE_S = 365 * _DAY_S
ADVERSE_ACTION_MAX_AGE_S = 365 * _DAY_S
PROXY_AUDIT_MAX_AGE_S = 365 * _DAY_S
REGISTRY_CERT_MAX_AGE_S = 365 * _DAY_S

#: Features treated as protected-class proxies when declared in a
#: model without a less-discriminatory-alternative (LDA) proof.
#: (The dataexperts lesson: a model can reconstruct a protected
#: class from neutral features with no intent behind it.)
PROXY_FEATURES = frozenset({
    "postal_code",
    "zip_code",
    "application_grammar",
    "loyalty_card_data",
    "education_level",
    "occupation_code",
    "device_model",
    "browser_fingerprint",
})

#: Vague adverse-action reasons that fail ECOA's specific-and-
#: understandable test.
VAGUE_REASONS = frozenset({
    "model output",
    "algorithmic score",
    "risk score",
    "model decision",
    "ai score",
})

#: Pricing disparity line: seeded 14% -> 0.14% with a rules layer;
#: disparities above this need justification or removal.
PRICING_DISPARITY_MAX = 0.05

#: High-impact financial uses that must be registered (Korea lesson).
HIGH_IMPACT_USES = frozenset({
    "credit_scoring",
    "loan_underwriting",
    "insurance_pricing",
    "insurance_underwriting",
    "fraud_closure_decision",
    "account_freeze",
})

#: Decision lanes: the third lane must exist.
DECISION_LANES = frozenset({
    "auto_accept",
    "auto_decline",
    "escalate_to_officer",
})

#: Actions a fraud flag may trigger. Anything else — closure, freeze —
#: needs a human-review binding plus FP-rate disclosure.
FLAG_LEAD_ACTIONS = frozenset({
    "queue_review",
    "request_information",
    "restrict_amount",
})
FLAG_ACCOUNT_ACTIONS = frozenset({
    "close_account",
    "freeze_account",
    "debit_hold",
})


class FinanceError(ValueError):
    """A malformed finance-discipline receipt or a programming error.

    Raised for structural problems (bad digests, unknown registries,
    broken chains). Verification *failures* (short notice, proxy
    features, shadow AI, systemic exclusion) return a
    :class:`FinanceVerdict` with ``allowed=False`` instead — a failed
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
        raise FinanceError(f"{field_name} must be a 64-char lowercase hex digest")
    return value


def _check_nonempty_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise FinanceError(f"{field_name} must be a non-empty string")
    return value


def _check_ts(value: Any, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise FinanceError(f"{field_name} must be a non-negative int epoch")
    return value


def _check_pubkey_hex(value: Any) -> str:
    if not _is_hex(value, _HEX64_LENGTH):
        raise FinanceError("authority_pubkey_hex must be a 64-char lowercase hex digest")
    return value


def _check_ratio(value: Any, field_name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise FinanceError(f"{field_name} must be a number")
    if not 0.0 <= value <= 1.0:
        raise FinanceError(f"{field_name} must be within [0, 1]")
    return float(value)


def _check_positive_int(value: Any, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise FinanceError(f"{field_name} must be a positive int")
    return value


def _verify_signature(
    pubkey_hex: str, payload: Mapping[str, Any], signature_hex: str
) -> bool:
    # one-hundred-fifty-fifth batch: vendored ed25519.verify() returns a
    # bool and never raises; the return value must be honored (the old
    # try/except-around-verify pattern silently approved everything).
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
    expected_prev = _GENESIS
    for entry in log:
        if not hmac.compare_digest(entry.receipt_digest, jcs_sha256_hex(entry._payload())):
            raise FinanceError(
                f"{type_name} receipt {entry.receipt_id!r} digest does not recompute"
            )
        if not hmac.compare_digest(entry.prev_digest, expected_prev):
            raise FinanceError(
                f"{type_name} receipt {entry.receipt_id!r} chain break: "
                f"expected prev {expected_prev!r}"
            )
        signed_body = dict(entry._payload())
        signed_body["signature_hex"] = "00" * 64
        if not _verify_signature(
            entry.authority_pubkey_hex, signed_body, entry.signature_hex
        ):
            raise FinanceError(
                f"{type_name} receipt {entry.receipt_id!r} authority signature invalid"
            )
        expected_prev = entry.receipt_digest


@dataclass(frozen=True)
class FinanceVerdict:
    """Outcome of one finance-discipline gate check."""

    allowed: bool
    reason: str
    classification: str = CLASS_NON_AUTHORITATIVE
    receipt_digest: str = ""


def _deny(code: str, detail: str) -> FinanceVerdict:
    return FinanceVerdict(
        allowed=False,
        reason=f"{code}: {detail}",
        classification=CLASS_NON_AUTHORITATIVE,
    )


def _allow(detail: str, receipt_digest: str = "") -> FinanceVerdict:
    return FinanceVerdict(
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


def _new_log(registry: Any) -> str:
    return registry.log[-1].receipt_digest if registry.log else _GENESIS


# ---------------------------------------------------------------------------
# 1. Closure-notice receipts (UK 90-day lesson)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ClosureNoticeReceipt:
    """Binds an account closure to a written notice with a reason hash."""

    receipt_id: str
    account_id: str
    reason_hash: str  # sha256 of the written reason summary
    notice_period_days: int
    served_at: int
    account_opened_at: int
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str
    receipt_digest: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": FINANCE_SCHEMA_VERSION,
            "type": "closure_notice",
            "receipt_id": self.receipt_id,
            "account_id": self.account_id,
            "reason_hash": self.reason_hash,
            "notice_period_days": self.notice_period_days,
            "served_at": self.served_at,
            "account_opened_at": self.account_opened_at,
            "authority_id": self.authority_id,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
        }


@dataclass
class ClosureNoticeRegistry:
    """Hash-chained log of closure-notice receipts."""

    authorities: AuthorityRegistry
    log: list[ClosureNoticeReceipt]

    def __init__(self, authorities: AuthorityRegistry) -> None:
        self.authorities = authorities
        self.log = []

    def issue(
        self,
        receipt_id: str,
        account_id: str,
        reason_hash: str,
        notice_period_days: int,
        served_at: int,
        account_opened_at: int,
        authority_id: str,
        authority_secret: bytes,
    ) -> ClosureNoticeReceipt:
        _check_nonempty_str(receipt_id, "receipt_id")
        _check_nonempty_str(account_id, "account_id")
        _check_hex64(reason_hash, "reason_hash")
        _check_positive_int(notice_period_days, "notice_period_days")
        _check_ts(served_at, "served_at")
        _check_ts(account_opened_at, "account_opened_at")
        pubkey = self.authorities.pubkey(authority_id)
        if pubkey is None:
            raise FinanceError(f"unknown authority {authority_id!r}")
        prev = _new_log(self)
        payload = {
            "schema": FINANCE_SCHEMA_VERSION,
            "type": "closure_notice",
            "receipt_id": receipt_id,
            "account_id": account_id,
            "reason_hash": reason_hash,
            "notice_period_days": notice_period_days,
            "served_at": served_at,
            "account_opened_at": account_opened_at,
            "authority_id": authority_id,
            "authority_pubkey_hex": pubkey,
            "prev_digest": prev,
        }
        sig_body = dict(payload)
        sig_body["signature_hex"] = "00" * 64
        signature = ed25519.sign(authority_secret, jcs_canonical_json(sig_body))
        digest = jcs_sha256_hex(payload)
        receipt = ClosureNoticeReceipt(
            receipt_id=receipt_id,
            account_id=account_id,
            reason_hash=reason_hash,
            notice_period_days=notice_period_days,
            served_at=served_at,
            account_opened_at=account_opened_at,
            authority_id=authority_id,
            authority_pubkey_hex=pubkey,
            signature_hex=signature.hex(),
            prev_digest=prev,
            receipt_digest=digest,
        )
        self.log.append(receipt)
        _check_chain(self.log, "closure_notice")
        return receipt

    def get(self, receipt_id: str) -> ClosureNoticeReceipt | None:
        for r in self.log:
            if r.receipt_id == receipt_id:
                return r
        return None


@dataclass(frozen=True)
class TippingOffBarReceipt:
    """Explicit receipt that disclosure is legally barred (UK s.333A).

    Lawful silence must be *declared*, never assumed: without this
    receipt a short-notice closure reads as a process failure.
    """

    receipt_id: str
    account_id: str
    statute: str
    barred_at: int
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str
    receipt_digest: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": FINANCE_SCHEMA_VERSION,
            "type": "tipping_off_bar",
            "receipt_id": self.receipt_id,
            "account_id": self.account_id,
            "statute": self.statute,
            "barred_at": self.barred_at,
            "authority_id": self.authority_id,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
        }


@dataclass
class TippingOffBarRegistry:
    """Hash-chained log of tipping-off bar receipts."""

    authorities: AuthorityRegistry
    log: list[TippingOffBarReceipt]

    def __init__(self, authorities: AuthorityRegistry) -> None:
        self.authorities = authorities
        self.log = []

    def issue(
        self,
        receipt_id: str,
        account_id: str,
        statute: str,
        barred_at: int,
        authority_id: str,
        authority_secret: bytes,
    ) -> TippingOffBarReceipt:
        _check_nonempty_str(receipt_id, "receipt_id")
        _check_nonempty_str(account_id, "account_id")
        _check_nonempty_str(statute, "statute")
        _check_ts(barred_at, "barred_at")
        pubkey = self.authorities.pubkey(authority_id)
        if pubkey is None:
            raise FinanceError(f"unknown authority {authority_id!r}")
        prev = _new_log(self)
        payload = {
            "schema": FINANCE_SCHEMA_VERSION,
            "type": "tipping_off_bar",
            "receipt_id": receipt_id,
            "account_id": account_id,
            "statute": statute,
            "barred_at": barred_at,
            "authority_id": authority_id,
            "authority_pubkey_hex": pubkey,
            "prev_digest": prev,
        }
        sig_body = dict(payload)
        sig_body["signature_hex"] = "00" * 64
        signature = ed25519.sign(authority_secret, jcs_canonical_json(sig_body))
        receipt = TippingOffBarReceipt(
            receipt_id=receipt_id,
            account_id=account_id,
            statute=statute,
            barred_at=barred_at,
            authority_id=authority_id,
            authority_pubkey_hex=pubkey,
            signature_hex=signature.hex(),
            prev_digest=prev,
            receipt_digest=jcs_sha256_hex(payload),
        )
        self.log.append(receipt)
        _check_chain(self.log, "tipping_off_bar")
        return receipt

    def has_for(self, account_id: str) -> bool:
        return any(r.account_id == account_id for r in self.log)


def closure_notice_receipt(
    notices: ClosureNoticeRegistry,
    bars: TippingOffBarRegistry,
    receipt_id: str,
    closed_at: int,
    cutoff_epoch: int,
) -> FinanceVerdict:
    """A closure binds a written notice; short notice fails closed.

    Accounts opened on/after ``cutoff_epoch`` (the UK 2026-04-28 rule)
    need :data:`NOTICE_MIN_DAYS_NEW` days; older accounts need
    :data:`NOTICE_MIN_DAYS_OLD` days. A tipping-off bar receipt for the
    account is the *only* lawful bypass: shorter notice with a bound
    bar is ``finance.tipping_off_barred``, shorter notice without one
    is ``finance.short_notice_closure``.
    """
    _check_ts(closed_at, "closed_at")
    _check_ts(cutoff_epoch, "cutoff_epoch")
    notice = notices.get(receipt_id)
    if notice is None:
        return _deny(
            "finance:no_closure_notice",
            f"closure without a written-notice receipt {receipt_id!r}",
        )
    if notice.served_at > closed_at:
        return _deny(
            "finance:future_notice",
            f"notice {receipt_id!r} served after the closure date",
        )
    if closed_at - notice.served_at > NOTICE_MAX_AGE_S:
        return _deny(
            "finance:stale_notice",
            f"notice {receipt_id!r} is older than 365 days",
        )
    required = (
        NOTICE_MIN_DAYS_NEW
        if notice.account_opened_at >= cutoff_epoch
        else NOTICE_MIN_DAYS_OLD
    )
    if notice.notice_period_days >= required:
        return _allow(
            f"closure of {notice.account_id!r} had {notice.notice_period_days}-day notice",
            notice.receipt_digest,
        )
    if bars.has_for(notice.account_id):
        return _allow(
            f"short-notice closure of {notice.account_id!r} under a bound "
            "tipping-off bar (disclosure legally barred, explicitly receipted)",
            notice.receipt_digest,
        )
    return _deny(
        "finance:short_notice_closure",
        f"closure of {notice.account_id!r} had {notice.notice_period_days}-day "
        f"notice, required {required} days (UK 90-day rule)",
    )


# ---------------------------------------------------------------------------
# 2. Freeze proportionality (India RBI draft lesson)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FreezeReceipt:
    """Binds a freeze/debit-hold: disputed amount, hold clock, rebuttal."""

    receipt_id: str
    account_id: str
    disputed_amount_minor: int
    frozen_amount_minor: int
    account_balance_minor: int
    hold_started_at: int
    rebuttal_deadline: int
    review_completed_at: int  # 0 = not yet reviewed
    whole_account_frozen: bool
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str
    receipt_digest: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": FINANCE_SCHEMA_VERSION,
            "type": "freeze",
            "receipt_id": self.receipt_id,
            "account_id": self.account_id,
            "disputed_amount_minor": self.disputed_amount_minor,
            "frozen_amount_minor": self.frozen_amount_minor,
            "account_balance_minor": self.account_balance_minor,
            "hold_started_at": self.hold_started_at,
            "rebuttal_deadline": self.rebuttal_deadline,
            "review_completed_at": self.review_completed_at,
            "whole_account_frozen": self.whole_account_frozen,
            "authority_id": self.authority_id,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
        }


@dataclass
class FreezeRegistry:
    """Hash-chained log of freeze receipts."""

    authorities: AuthorityRegistry
    log: list[FreezeReceipt]

    def __init__(self, authorities: AuthorityRegistry) -> None:
        self.authorities = authorities
        self.log = []

    def issue(
        self,
        receipt_id: str,
        account_id: str,
        disputed_amount_minor: int,
        frozen_amount_minor: int,
        account_balance_minor: int,
        hold_started_at: int,
        rebuttal_deadline: int,
        review_completed_at: int,
        whole_account_frozen: bool,
        authority_id: str,
        authority_secret: bytes,
    ) -> FreezeReceipt:
        _check_nonempty_str(receipt_id, "receipt_id")
        _check_nonempty_str(account_id, "account_id")
        for name, value in (
            ("disputed_amount_minor", disputed_amount_minor),
            ("frozen_amount_minor", frozen_amount_minor),
            ("account_balance_minor", account_balance_minor),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise FinanceError(f"{name} must be a non-negative int")
        _check_ts(hold_started_at, "hold_started_at")
        _check_ts(rebuttal_deadline, "rebuttal_deadline")
        if review_completed_at != 0:
            _check_ts(review_completed_at, "review_completed_at")
        if not isinstance(whole_account_frozen, bool):
            raise FinanceError("whole_account_frozen must be a bool")
        pubkey = self.authorities.pubkey(authority_id)
        if pubkey is None:
            raise FinanceError(f"unknown authority {authority_id!r}")
        prev = _new_log(self)
        payload = {
            "schema": FINANCE_SCHEMA_VERSION,
            "type": "freeze",
            "receipt_id": receipt_id,
            "account_id": account_id,
            "disputed_amount_minor": disputed_amount_minor,
            "frozen_amount_minor": frozen_amount_minor,
            "account_balance_minor": account_balance_minor,
            "hold_started_at": hold_started_at,
            "rebuttal_deadline": rebuttal_deadline,
            "review_completed_at": review_completed_at,
            "whole_account_frozen": whole_account_frozen,
            "authority_id": authority_id,
            "authority_pubkey_hex": pubkey,
            "prev_digest": prev,
        }
        sig_body = dict(payload)
        sig_body["signature_hex"] = "00" * 64
        signature = ed25519.sign(authority_secret, jcs_canonical_json(sig_body))
        receipt = FreezeReceipt(
            receipt_id=receipt_id,
            account_id=account_id,
            disputed_amount_minor=disputed_amount_minor,
            frozen_amount_minor=frozen_amount_minor,
            account_balance_minor=account_balance_minor,
            hold_started_at=hold_started_at,
            rebuttal_deadline=rebuttal_deadline,
            review_completed_at=review_completed_at,
            whole_account_frozen=whole_account_frozen,
            authority_id=authority_id,
            authority_pubkey_hex=pubkey,
            signature_hex=signature.hex(),
            prev_digest=prev,
            receipt_digest=jcs_sha256_hex(payload),
        )
        self.log.append(receipt)
        _check_chain(self.log, "freeze")
        return receipt

    def get(self, receipt_id: str) -> FreezeReceipt | None:
        for r in self.log:
            if r.receipt_id == receipt_id:
                return r
        return None


def freeze_proportionality_gate(
    freezes: FreezeRegistry,
    receipt_id: str,
    checked_at: int,
) -> FinanceVerdict:
    """Freezes must be proportional: disputed amount only, on a clock.

    Whole-account freeze while the disputed amount is a fraction of the
    balance is ``finance.disproportionate_freeze`` (RBI draft lesson).
    A debit hold running longer than :data:`DEBIT_HOLD_MAX_S` is
    ``finance.hold_overdue``; a rebuttal window shorter than 20 days is
    ``finance.short_rebuttal``; a review completed more than 10 days
    after the hold started is ``finance.late_review``.
    """
    _check_ts(checked_at, "checked_at")
    freeze = freezes.get(receipt_id)
    if freeze is None:
        return _deny(
            "finance:no_freeze_receipt",
            f"freeze action without a freeze receipt {receipt_id!r}",
        )
    if checked_at - freeze.hold_started_at > FREEZE_MAX_AGE_S:
        return _deny(
            "finance:stale_freeze",
            f"freeze {receipt_id!r} is older than 365 days",
        )
    if (
        freeze.whole_account_frozen
        and freeze.disputed_amount_minor < freeze.account_balance_minor
    ):
        return _deny(
            "finance:disproportionate_freeze",
            f"freeze {receipt_id!r} locks the whole account of "
            f"{freeze.account_balance_minor} while only "
            f"{freeze.disputed_amount_minor} is disputed",
        )
    if freeze.rebuttal_deadline - freeze.hold_started_at < REBUTTAL_WINDOW_S:
        return _deny(
            "finance:short_rebuttal",
            f"freeze {receipt_id!r} gives less than 20 days to rebut",
        )
    if (
        freeze.review_completed_at != 0
        and freeze.review_completed_at - freeze.hold_started_at > BANK_REVIEW_MAX_S
    ):
        return _deny(
            "finance:late_review",
            f"freeze {receipt_id!r} review took longer than 10 days",
        )
    if checked_at - freeze.hold_started_at > DEBIT_HOLD_MAX_S:
        return _deny(
            "finance:hold_overdue",
            f"freeze {receipt_id!r} debit hold exceeds 60 days",
        )
    return _allow(
        f"freeze {receipt_id!r} is proportional and within its clocks",
        freeze.receipt_digest,
    )


# ---------------------------------------------------------------------------
# 3. Flag != guilt (Pakistan FBR lesson)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FraudFlag:
    """An AI-raised fraud flag: a lead, never a conviction."""

    flag_id: str
    account_id: str
    model_id: str
    false_positive_bps: int  # declared false-positive rate, basis points
    raised_at: int
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": FINANCE_SCHEMA_VERSION,
            "type": "fraud_flag",
            "flag_id": self.flag_id,
            "account_id": self.account_id,
            "model_id": self.model_id,
            "false_positive_bps": self.false_positive_bps,
            "raised_at": self.raised_at,
            "authority_id": self.authority_id,
            "authority_pubkey_hex": self.authority_pubkey_hex,
        }


@dataclass(frozen=True)
class HumanReviewReceipt:
    """A named human reviewed the flag before an account action."""

    review_id: str
    flag_id: str
    reviewer_id: str
    reviewed_at: int
    decision: str  # "uphold" | "dismiss"
    authority_pubkey_hex: str
    signature_hex: str


def flag_is_not_guilt_gate(
    flag: FraudFlag,
    action: str,
    review: HumanReviewReceipt | None,
    acted_at: int,
) -> FinanceVerdict:
    """Automatic account actions from a flag need human review + FP disclosure.

    Lead-grade actions (queue review, request information) pass.
    Account actions (close, freeze, debit hold) need a bound
    :class:`HumanReviewReceipt`; without one the verdict is
    ``finance.no_human_review``. A flag with no declared false-positive
    rate cannot drive an account action: ``finance.fp_undisclosed``
    (the "black-box + unknown FP" lesson). A bad flag signature reads
    as no flag.
    """
    _check_ts(acted_at, "acted_at")
    _check_nonempty_str(action, "action")
    if not isinstance(flag, FraudFlag):
        raise FinanceError("flag must be a FraudFlag")
    _check_nonempty_str(flag.flag_id, "flag.flag_id")
    _check_nonempty_str(flag.account_id, "flag.account_id")
    _check_nonempty_str(flag.model_id, "flag.model_id")
    _check_ts(flag.raised_at, "flag.raised_at")
    if flag.raised_at > acted_at:
        return _deny(
            "finance:future_flag",
            f"flag {flag.flag_id!r} raised in the future",
        )
    if not _verify_signature(flag.authority_pubkey_hex, flag._payload(), flag.signature_hex):
        return _deny(
            "finance:flag_sig_invalid",
            f"flag {flag.flag_id!r} authority signature invalid",
        )
    if action in FLAG_LEAD_ACTIONS:
        return _allow(f"flag {flag.flag_id!r} action {action!r} is lead-grade")
    if action not in FLAG_ACCOUNT_ACTIONS:
        return _deny(
            "finance:unknown_flag_action",
            f"action {action!r} is not a registered flag action",
        )
    if review is None or not isinstance(review, HumanReviewReceipt):
        return _deny(
            "finance:no_human_review",
            f"account action {action!r} from flag {flag.flag_id!r} without "
            "a bound human-review receipt",
        )
    if review.flag_id != flag.flag_id:
        return _deny(
            "finance:review_mismatch",
            f"review {review.review_id!r} does not bind flag {flag.flag_id!r}",
        )
    if review.decision != "uphold":
        return _deny(
            "finance:review_dismissed",
            f"review {review.review_id!r} dismissed flag {flag.flag_id!r}",
        )
    if flag.false_positive_bps == 0:
        return _deny(
            "finance:fp_undisclosed",
            f"flag {flag.flag_id!r} carries no declared false-positive rate",
        )
    return _allow(
        f"account action {action!r} from flag {flag.flag_id!r} has human "
        f"review {review.review_id!r} and a disclosed FP rate "
        f"({flag.false_positive_bps} bps)"
    )


# ---------------------------------------------------------------------------
# 4. Proxy screen (CFPB / Illinois disparate-impact split lesson)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ModelProxyAudit:
    """Binds a model version to its declared features + LDA proof."""

    audit_id: str
    model_id: str
    model_version: str
    declared_features: tuple[str, ...]
    proxy_features_removed: bool
    less_discriminatory_alternative: bool
    audited_at: int
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str
    receipt_digest: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": FINANCE_SCHEMA_VERSION,
            "type": "model_proxy_audit",
            "audit_id": self.audit_id,
            "model_id": self.model_id,
            "model_version": self.model_version,
            "declared_features": sorted(self.declared_features),
            "proxy_features_removed": self.proxy_features_removed,
            "less_discriminatory_alternative": self.less_discriminatory_alternative,
            "audited_at": self.audited_at,
            "authority_id": self.authority_id,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
        }


@dataclass
class ModelProxyAuditRegistry:
    """Hash-chained log of model proxy audits."""

    authorities: AuthorityRegistry
    log: list[ModelProxyAudit]

    def __init__(self, authorities: AuthorityRegistry) -> None:
        self.authorities = authorities
        self.log = []

    def issue(
        self,
        audit_id: str,
        model_id: str,
        model_version: str,
        declared_features: tuple[str, ...],
        proxy_features_removed: bool,
        less_discriminatory_alternative: bool,
        audited_at: int,
        authority_id: str,
        authority_secret: bytes,
    ) -> ModelProxyAudit:
        _check_nonempty_str(audit_id, "audit_id")
        _check_nonempty_str(model_id, "model_id")
        _check_nonempty_str(model_version, "model_version")
        if not declared_features or not all(
            isinstance(f, str) and f.strip() for f in declared_features
        ):
            raise FinanceError("declared_features must be a non-empty tuple of strings")
        if not isinstance(proxy_features_removed, bool):
            raise FinanceError("proxy_features_removed must be a bool")
        if not isinstance(less_discriminatory_alternative, bool):
            raise FinanceError("less_discriminatory_alternative must be a bool")
        _check_ts(audited_at, "audited_at")
        pubkey = self.authorities.pubkey(authority_id)
        if pubkey is None:
            raise FinanceError(f"unknown authority {authority_id!r}")
        prev = _new_log(self)
        payload = {
            "schema": FINANCE_SCHEMA_VERSION,
            "type": "model_proxy_audit",
            "audit_id": audit_id,
            "model_id": model_id,
            "model_version": model_version,
            "declared_features": sorted(declared_features),
            "proxy_features_removed": proxy_features_removed,
            "less_discriminatory_alternative": less_discriminatory_alternative,
            "audited_at": audited_at,
            "authority_id": authority_id,
            "authority_pubkey_hex": pubkey,
            "prev_digest": prev,
        }
        sig_body = dict(payload)
        sig_body["signature_hex"] = "00" * 64
        signature = ed25519.sign(authority_secret, jcs_canonical_json(sig_body))
        receipt = ModelProxyAudit(
            audit_id=audit_id,
            model_id=model_id,
            model_version=model_version,
            declared_features=tuple(declared_features),
            proxy_features_removed=proxy_features_removed,
            less_discriminatory_alternative=less_discriminatory_alternative,
            audited_at=audited_at,
            authority_id=authority_id,
            authority_pubkey_hex=pubkey,
            signature_hex=signature.hex(),
            prev_digest=prev,
            receipt_digest=jcs_sha256_hex(payload),
        )
        self.log.append(receipt)
        _check_chain(self.log, "model_proxy_audit")
        return receipt

    def latest_for(self, model_id: str, model_version: str) -> ModelProxyAudit | None:
        for r in reversed(self.log):
            if r.model_id == model_id and r.model_version == model_version:
                return r
        return None


def proxy_screen(
    audits: ModelProxyAuditRegistry,
    model_id: str,
    model_version: str,
    used_at: int,
) -> FinanceVerdict:
    """Models declaring proxy features need removal or an LDA proof.

    The declared features are checked against :data:`PROXY_FEATURES`
    (postcode, loyalty-card data, education, occupation, application
    grammar, device/browser fingerprints). If any are present, the
    latest audit must show them removed or prove a
    less-discriminatory alternative — otherwise
    ``finance.proxy_feature``. No audit is ``finance.no_proxy_audit``;
    a stale audit is ``finance.stale_proxy_audit``.
    """
    _check_nonempty_str(model_id, "model_id")
    _check_nonempty_str(model_version, "model_version")
    _check_ts(used_at, "used_at")
    audit = audits.latest_for(model_id, model_version)
    if audit is None:
        return _deny(
            "finance:no_proxy_audit",
            f"model {model_id!r} version {model_version!r} used without a "
            "proxy-feature audit",
        )
    if used_at - audit.audited_at > PROXY_AUDIT_MAX_AGE_S:
        return _deny(
            "finance:stale_proxy_audit",
            f"audit {audit.audit_id!r} for {model_id!r} is older than 365 days",
        )
    declared = {f.strip().lower() for f in audit.declared_features}
    present = sorted(declared & PROXY_FEATURES)
    if not present:
        return _allow(
            f"model {model_id!r} declares no proxy features",
            audit.receipt_digest,
        )
    if audit.proxy_features_removed:
        return _allow(
            f"model {model_id!r} declared {present} but removed them pre-use",
            audit.receipt_digest,
        )
    if audit.less_discriminatory_alternative:
        return _allow(
            f"model {model_id!r} binds a less-discriminatory-alternative "
            f"proof for {present}",
            audit.receipt_digest,
        )
    return _deny(
        "finance:proxy_feature",
        f"model {model_id!r} declares proxy features {present} with neither "
        "removal nor a less-discriminatory-alternative proof",
    )


# ---------------------------------------------------------------------------
# 5. Adverse-action receipts (ECOA lesson: "model output" is not a reason)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AdverseActionReceipt:
    """Binds an adverse decision to specific, understandable reasons."""

    receipt_id: str
    subject_id: str
    decision: str  # e.g. "decline", "rate_increase"
    reasons: tuple[str, ...]
    decided_at: int
    disputable: bool
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str
    receipt_digest: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": FINANCE_SCHEMA_VERSION,
            "type": "adverse_action",
            "receipt_id": self.receipt_id,
            "subject_id": self.subject_id,
            "decision": self.decision,
            "reasons": sorted(self.reasons),
            "decided_at": self.decided_at,
            "disputable": self.disputable,
            "authority_id": self.authority_id,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
        }


@dataclass
class AdverseActionRegistry:
    """Hash-chained log of adverse-action receipts."""

    authorities: AuthorityRegistry
    log: list[AdverseActionReceipt]

    def __init__(self, authorities: AuthorityRegistry) -> None:
        self.authorities = authorities
        self.log = []

    def issue(
        self,
        receipt_id: str,
        subject_id: str,
        decision: str,
        reasons: tuple[str, ...],
        decided_at: int,
        disputable: bool,
        authority_id: str,
        authority_secret: bytes,
    ) -> AdverseActionReceipt:
        _check_nonempty_str(receipt_id, "receipt_id")
        _check_nonempty_str(subject_id, "subject_id")
        _check_nonempty_str(decision, "decision")
        if not reasons or not all(isinstance(r, str) and r.strip() for r in reasons):
            raise FinanceError("reasons must be a non-empty tuple of strings")
        _check_ts(decided_at, "decided_at")
        if not isinstance(disputable, bool):
            raise FinanceError("disputable must be a bool")
        pubkey = self.authorities.pubkey(authority_id)
        if pubkey is None:
            raise FinanceError(f"unknown authority {authority_id!r}")
        prev = _new_log(self)
        payload = {
            "schema": FINANCE_SCHEMA_VERSION,
            "type": "adverse_action",
            "receipt_id": receipt_id,
            "subject_id": subject_id,
            "decision": decision,
            "reasons": sorted(reasons),
            "decided_at": decided_at,
            "disputable": disputable,
            "authority_id": authority_id,
            "authority_pubkey_hex": pubkey,
            "prev_digest": prev,
        }
        sig_body = dict(payload)
        sig_body["signature_hex"] = "00" * 64
        signature = ed25519.sign(authority_secret, jcs_canonical_json(sig_body))
        receipt = AdverseActionReceipt(
            receipt_id=receipt_id,
            subject_id=subject_id,
            decision=decision,
            reasons=tuple(reasons),
            decided_at=decided_at,
            disputable=disputable,
            authority_id=authority_id,
            authority_pubkey_hex=pubkey,
            signature_hex=signature.hex(),
            prev_digest=prev,
            receipt_digest=jcs_sha256_hex(payload),
        )
        self.log.append(receipt)
        _check_chain(self.log, "adverse_action")
        return receipt

    def get(self, receipt_id: str) -> AdverseActionReceipt | None:
        for r in self.log:
            if r.receipt_id == receipt_id:
                return r
        return None


def adverse_action_receipt(
    actions: AdverseActionRegistry,
    receipt_id: str,
    checked_at: int,
) -> FinanceVerdict:
    """Adverse decisions bind specific, understandable, disputable reasons.

    A missing receipt is ``finance.no_adverse_action``; any reason
    matching :data:`VAGUE_REASONS` ("model output", "algorithmic
    score", ...) is ``finance.vague_reason`` (ECOA lesson); a receipt
    that gives the subject no dispute path is
    ``finance.non_disputable``.
    """
    _check_ts(checked_at, "checked_at")
    action = actions.get(receipt_id)
    if action is None:
        return _deny(
            "finance:no_adverse_action",
            f"adverse decision without an adverse-action receipt {receipt_id!r}",
        )
    if checked_at - action.decided_at > ADVERSE_ACTION_MAX_AGE_S:
        return _deny(
            "finance:stale_adverse_action",
            f"adverse-action receipt {receipt_id!r} is older than 365 days",
        )
    vague = sorted({r.strip().lower() for r in action.reasons} & VAGUE_REASONS)
    if vague:
        return _deny(
            "finance:vague_reason",
            f"receipt {receipt_id!r} uses vague reasons {vague}: "
            '"model output" is not a compliant reason (ECOA)',
        )
    if not action.disputable:
        return _deny(
            "finance:non_disputable",
            f"receipt {receipt_id!r} gives the subject no dispute path",
        )
    return _allow(
        f"adverse action {receipt_id!r} binds {len(action.reasons)} specific "
        "disputable reasons",
        action.receipt_digest,
    )


# ---------------------------------------------------------------------------
# 6. Pricing-fairness rules layer (Cureus lesson: evidence is a query)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PricingEvaluation:
    """One logged pricing evaluation: log everything, not just intercepts."""

    evaluation_id: str
    model_id: str
    jurisdiction: str
    quoted_bps: int  # premium in basis points of the base rate
    proxy_signal_used: bool
    rule_intervened: bool
    evaluated_at: int
    prev_digest: str
    receipt_digest: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": FINANCE_SCHEMA_VERSION,
            "type": "pricing_evaluation",
            "evaluation_id": self.evaluation_id,
            "model_id": self.model_id,
            "jurisdiction": self.jurisdiction,
            "quoted_bps": self.quoted_bps,
            "proxy_signal_used": self.proxy_signal_used,
            "rule_intervened": self.rule_intervened,
            "evaluated_at": self.evaluated_at,
            "prev_digest": self.prev_digest,
        }


@dataclass
class PricingEvaluationLog:
    """Hash-chained log of *every* pricing evaluation."""

    log: list[PricingEvaluation]

    def __init__(self) -> None:
        self.log = []

    def record(
        self,
        evaluation_id: str,
        model_id: str,
        jurisdiction: str,
        quoted_bps: int,
        proxy_signal_used: bool,
        rule_intervened: bool,
        evaluated_at: int,
    ) -> PricingEvaluation:
        _check_nonempty_str(evaluation_id, "evaluation_id")
        _check_nonempty_str(model_id, "model_id")
        _check_nonempty_str(jurisdiction, "jurisdiction")
        _check_positive_int(quoted_bps, "quoted_bps")
        if not isinstance(proxy_signal_used, bool):
            raise FinanceError("proxy_signal_used must be a bool")
        if not isinstance(rule_intervened, bool):
            raise FinanceError("rule_intervened must be a bool")
        _check_ts(evaluated_at, "evaluated_at")
        prev = self.log[-1].receipt_digest if self.log else _GENESIS
        payload = {
            "schema": FINANCE_SCHEMA_VERSION,
            "type": "pricing_evaluation",
            "evaluation_id": evaluation_id,
            "model_id": model_id,
            "jurisdiction": jurisdiction,
            "quoted_bps": quoted_bps,
            "proxy_signal_used": proxy_signal_used,
            "rule_intervened": rule_intervened,
            "evaluated_at": evaluated_at,
            "prev_digest": prev,
        }
        digest = jcs_sha256_hex(payload)
        evaluation = PricingEvaluation(
            evaluation_id=evaluation_id,
            model_id=model_id,
            jurisdiction=jurisdiction,
            quoted_bps=quoted_bps,
            proxy_signal_used=proxy_signal_used,
            rule_intervened=rule_intervened,
            evaluated_at=evaluated_at,
            prev_digest=prev,
            receipt_digest=digest,
        )
        self.log.append(evaluation)
        return evaluation


def pricing_fairness_rules_layer(
    evaluations: PricingEvaluationLog,
    model_id: str,
    jurisdiction: str,
    proxy_quoted_bps: int,
    base_quoted_bps: int,
) -> FinanceVerdict:
    """The deterministic rules layer checks disparities on the full log.

    Given the jurisdiction's full evaluation log (everything, not just
    intercepts), the layer compares quotes that used proxy signals
    against those that did not. A mean disparity above
    :data:`PRICING_DISPARITY_MAX` is ``finance.proxy_pricing_disparity``
    (the Cureus 14%-to-0.14% lesson). An empty log is
    ``finance.no_pricing_log`` — the layer cannot audit what it never
    recorded.
    """
    _check_nonempty_str(model_id, "model_id")
    _check_nonempty_str(jurisdiction, "jurisdiction")
    _check_positive_int(proxy_quoted_bps, "proxy_quoted_bps")
    _check_positive_int(base_quoted_bps, "base_quoted_bps")
    rows = [
        e
        for e in evaluations.log
        if e.model_id == model_id and e.jurisdiction == jurisdiction
    ]
    if not rows:
        return _deny(
            "finance:no_pricing_log",
            f"no logged evaluations for {model_id!r} in {jurisdiction!r}; "
            "the rules layer needs the full log, not just intercepts",
        )
    proxy_rows = [e.quoted_bps for e in rows if e.proxy_signal_used]
    base_rows = [e.quoted_bps for e in rows if not e.proxy_signal_used]
    if not proxy_rows or not base_rows:
        return _allow(
            f"{len(rows)} evaluations logged; single-population log, "
            "no disparity to measure"
        )
    proxy_mean = sum(proxy_rows) / len(proxy_rows)
    base_mean = sum(base_rows) / len(base_rows)
    disparity = abs(proxy_mean - base_mean) / base_mean
    if disparity > PRICING_DISPARITY_MAX:
        return _deny(
            "finance:proxy_pricing_disparity",
            f"{model_id!r} in {jurisdiction!r}: proxy-signal quotes average "
            f"{disparity:.1%} vs base quotes, above the "
            f"{PRICING_DISPARITY_MAX:.0%} line ({len(rows)} evaluations logged)",
        )
    return _allow(
        f"{model_id!r} in {jurisdiction!r}: disparity {disparity:.2%} within "
        f"the {PRICING_DISPARITY_MAX:.0%} line ({len(rows)} evaluations logged)"
    )


# ---------------------------------------------------------------------------
# 7. Debanking-share guard (shared marker registries need appeal paths)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SharedMarkerAppealReceipt:
    """Binds a shared crime-marker hit to a customer appeal receipt."""

    appeal_id: str
    customer_id: str
    marker_source: str
    marker_evidence_hash: str
    appeal_channel: str
    filed_at: int
    resolved: bool
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str
    receipt_digest: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": FINANCE_SCHEMA_VERSION,
            "type": "shared_marker_appeal",
            "appeal_id": self.appeal_id,
            "customer_id": self.customer_id,
            "marker_source": self.marker_source,
            "marker_evidence_hash": self.marker_evidence_hash,
            "appeal_channel": self.appeal_channel,
            "filed_at": self.filed_at,
            "resolved": self.resolved,
            "authority_id": self.authority_id,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
        }


@dataclass
class SharedMarkerAppealRegistry:
    """Hash-chained log of shared-marker appeal receipts."""

    authorities: AuthorityRegistry
    log: list[SharedMarkerAppealReceipt]

    def __init__(self, authorities: AuthorityRegistry) -> None:
        self.authorities = authorities
        self.log = []

    def issue(
        self,
        appeal_id: str,
        customer_id: str,
        marker_source: str,
        marker_evidence_hash: str,
        appeal_channel: str,
        filed_at: int,
        resolved: bool,
        authority_id: str,
        authority_secret: bytes,
    ) -> SharedMarkerAppealReceipt:
        _check_nonempty_str(appeal_id, "appeal_id")
        _check_nonempty_str(customer_id, "customer_id")
        _check_nonempty_str(marker_source, "marker_source")
        _check_hex64(marker_evidence_hash, "marker_evidence_hash")
        _check_nonempty_str(appeal_channel, "appeal_channel")
        _check_ts(filed_at, "filed_at")
        if not isinstance(resolved, bool):
            raise FinanceError("resolved must be a bool")
        pubkey = self.authorities.pubkey(authority_id)
        if pubkey is None:
            raise FinanceError(f"unknown authority {authority_id!r}")
        prev = _new_log(self)
        payload = {
            "schema": FINANCE_SCHEMA_VERSION,
            "type": "shared_marker_appeal",
            "appeal_id": appeal_id,
            "customer_id": customer_id,
            "marker_source": marker_source,
            "marker_evidence_hash": marker_evidence_hash,
            "appeal_channel": appeal_channel,
            "filed_at": filed_at,
            "resolved": resolved,
            "authority_id": authority_id,
            "authority_pubkey_hex": pubkey,
            "prev_digest": prev,
        }
        sig_body = dict(payload)
        sig_body["signature_hex"] = "00" * 64
        signature = ed25519.sign(authority_secret, jcs_canonical_json(sig_body))
        receipt = SharedMarkerAppealReceipt(
            appeal_id=appeal_id,
            customer_id=customer_id,
            marker_source=marker_source,
            marker_evidence_hash=marker_evidence_hash,
            appeal_channel=appeal_channel,
            filed_at=filed_at,
            resolved=resolved,
            authority_id=authority_id,
            authority_pubkey_hex=pubkey,
            signature_hex=signature.hex(),
            prev_digest=prev,
            receipt_digest=jcs_sha256_hex(payload),
        )
        self.log.append(receipt)
        _check_chain(self.log, "shared_marker_appeal")
        return receipt

    def has_for(self, customer_id: str) -> bool:
        return any(r.customer_id == customer_id for r in self.log)


def debanking_share_guard(
    appeals: SharedMarkerAppealRegistry,
    customer_id: str,
    marker_source: str,
    account_refused: bool,
) -> FinanceVerdict:
    """Shared crime markers must bind an appeal receipt for the customer.

    When a shared marker leads to an account refusal and the customer
    has no appeal receipt, the marker network is exclusionary by
    design: ``finance.systemic_exclusion``. A bound appeal receipt
    (filed, with an appeal channel) makes the refusal contestable and
    passes.
    """
    _check_nonempty_str(customer_id, "customer_id")
    _check_nonempty_str(marker_source, "marker_source")
    if not isinstance(account_refused, bool):
        raise FinanceError("account_refused must be a bool")
    if not account_refused:
        return _allow(
            f"customer {customer_id!r}: no refusal on marker {marker_source!r}"
        )
    if not appeals.has_for(customer_id):
        return _deny(
            "finance:systemic_exclusion",
            f"customer {customer_id!r} refused on shared marker "
            f"{marker_source!r} with no appeal receipt: a shared marker "
            "with no appeal path locks the customer out of the system",
        )
    return _allow(
        f"customer {customer_id!r} refused on shared marker "
        f"{marker_source!r} but holds a bound appeal receipt"
    )


# ---------------------------------------------------------------------------
# 8. High-impact registry (Korea AI Basic Act lesson)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class HighImpactCert:
    """Binds a high-impact financial AI to registration + obligations."""

    cert_id: str
    model_id: str
    use: str
    transparency_obligations: tuple[str, ...]
    registered_at: int
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str
    receipt_digest: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": FINANCE_SCHEMA_VERSION,
            "type": "high_impact_cert",
            "cert_id": self.cert_id,
            "model_id": self.model_id,
            "use": self.use,
            "transparency_obligations": sorted(self.transparency_obligations),
            "registered_at": self.registered_at,
            "authority_id": self.authority_id,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
        }


@dataclass
class HighImpactRegistry:
    """Hash-chained log of high-impact financial-AI registrations."""

    authorities: AuthorityRegistry
    log: list[HighImpactCert]

    def __init__(self, authorities: AuthorityRegistry) -> None:
        self.authorities = authorities
        self.log = []

    def issue(
        self,
        cert_id: str,
        model_id: str,
        use: str,
        transparency_obligations: tuple[str, ...],
        registered_at: int,
        authority_id: str,
        authority_secret: bytes,
    ) -> HighImpactCert:
        _check_nonempty_str(cert_id, "cert_id")
        _check_nonempty_str(model_id, "model_id")
        _check_nonempty_str(use, "use")
        if use not in HIGH_IMPACT_USES:
            raise FinanceError(f"use {use!r} is not a registered high-impact use")
        if not transparency_obligations or not all(
            isinstance(o, str) and o.strip() for o in transparency_obligations
        ):
            raise FinanceError("transparency_obligations must be a non-empty tuple")
        _check_ts(registered_at, "registered_at")
        pubkey = self.authorities.pubkey(authority_id)
        if pubkey is None:
            raise FinanceError(f"unknown authority {authority_id!r}")
        prev = _new_log(self)
        payload = {
            "schema": FINANCE_SCHEMA_VERSION,
            "type": "high_impact_cert",
            "cert_id": cert_id,
            "model_id": model_id,
            "use": use,
            "transparency_obligations": sorted(transparency_obligations),
            "registered_at": registered_at,
            "authority_id": authority_id,
            "authority_pubkey_hex": pubkey,
            "prev_digest": prev,
        }
        sig_body = dict(payload)
        sig_body["signature_hex"] = "00" * 64
        signature = ed25519.sign(authority_secret, jcs_canonical_json(sig_body))
        receipt = HighImpactCert(
            cert_id=cert_id,
            model_id=model_id,
            use=use,
            transparency_obligations=tuple(transparency_obligations),
            registered_at=registered_at,
            authority_id=authority_id,
            authority_pubkey_hex=pubkey,
            signature_hex=signature.hex(),
            prev_digest=prev,
            receipt_digest=jcs_sha256_hex(payload),
        )
        self.log.append(receipt)
        _check_chain(self.log, "high_impact_cert")
        return receipt

    def has_for(self, model_id: str, use: str) -> HighImpactCert | None:
        for r in reversed(self.log):
            if r.model_id == model_id and r.use == use:
                return r
        return None


def high_impact_registry(
    registry: HighImpactRegistry,
    model_id: str,
    use: str,
    used_at: int,
) -> FinanceVerdict:
    """High-impact financial AI must be registered before use.

    An unregistered model in a high-impact use (credit scoring, loan
    underwriting, insurance pricing/underwriting, fraud closure,
    account freeze) is ``finance.shadow_ai`` (Korea lesson). A stale
    registration is ``finance.stale_registration``.
    """
    _check_nonempty_str(model_id, "model_id")
    _check_nonempty_str(use, "use")
    _check_ts(used_at, "used_at")
    if use not in HIGH_IMPACT_USES:
        raise FinanceError(f"use {use!r} is not a registered high-impact use")
    cert = registry.has_for(model_id, use)
    if cert is None:
        return _deny(
            "finance:shadow_ai",
            f"model {model_id!r} used for {use!r} without a high-impact "
            "registration",
        )
    if used_at - cert.registered_at > REGISTRY_CERT_MAX_AGE_S:
        return _deny(
            "finance:stale_registration",
            f"high-impact registration {cert.cert_id!r} for {model_id!r} is "
            "older than 365 days",
        )
    return _allow(
        f"model {model_id!r} is registered for {use!r} with "
        f"{len(cert.transparency_obligations)} transparency obligations",
        cert.receipt_digest,
    )


# ---------------------------------------------------------------------------
# 9. Human escalation lane (German "third lane" lesson)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DecisionRoutingReceipt:
    """Binds an auto decision to the lane it took."""

    receipt_id: str
    subject_id: str
    decision: str
    lane: str
    decided_at: int
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str
    receipt_digest: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": FINANCE_SCHEMA_VERSION,
            "type": "decision_routing",
            "receipt_id": self.receipt_id,
            "subject_id": self.subject_id,
            "decision": self.decision,
            "lane": self.lane,
            "decided_at": self.decided_at,
            "authority_id": self.authority_id,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
        }


@dataclass
class DecisionRoutingRegistry:
    """Hash-chained log of decision-routing receipts."""

    authorities: AuthorityRegistry
    log: list[DecisionRoutingReceipt]

    def __init__(self, authorities: AuthorityRegistry) -> None:
        self.authorities = authorities
        self.log = []

    def issue(
        self,
        receipt_id: str,
        subject_id: str,
        decision: str,
        lane: str,
        decided_at: int,
        authority_id: str,
        authority_secret: bytes,
    ) -> DecisionRoutingReceipt:
        _check_nonempty_str(receipt_id, "receipt_id")
        _check_nonempty_str(subject_id, "subject_id")
        _check_nonempty_str(decision, "decision")
        _check_nonempty_str(lane, "lane")
        if lane not in DECISION_LANES:
            raise FinanceError(f"lane {lane!r} is not a registered decision lane")
        _check_ts(decided_at, "decided_at")
        pubkey = self.authorities.pubkey(authority_id)
        if pubkey is None:
            raise FinanceError(f"unknown authority {authority_id!r}")
        prev = _new_log(self)
        payload = {
            "schema": FINANCE_SCHEMA_VERSION,
            "type": "decision_routing",
            "receipt_id": receipt_id,
            "subject_id": subject_id,
            "decision": decision,
            "lane": lane,
            "decided_at": decided_at,
            "authority_id": authority_id,
            "authority_pubkey_hex": pubkey,
            "prev_digest": prev,
        }
        sig_body = dict(payload)
        sig_body["signature_hex"] = "00" * 64
        signature = ed25519.sign(authority_secret, jcs_canonical_json(sig_body))
        receipt = DecisionRoutingReceipt(
            receipt_id=receipt_id,
            subject_id=subject_id,
            decision=decision,
            lane=lane,
            decided_at=decided_at,
            authority_id=authority_id,
            authority_pubkey_hex=pubkey,
            signature_hex=signature.hex(),
            prev_digest=prev,
            receipt_digest=jcs_sha256_hex(payload),
        )
        self.log.append(receipt)
        _check_chain(self.log, "decision_routing")
        return receipt

    def lanes_for(self, model_id: str) -> set[str]:  # noqa: ARG002 - registry of lanes
        return {r.lane for r in self.log}


@dataclass(frozen=True)
class LaneDeclaration:
    """Declares the lanes a deployment actually offers."""

    deployment_id: str
    lanes: tuple[str, ...]


def human_escalation_lane(
    declaration: LaneDeclaration,
    routing: DecisionRoutingRegistry,
    receipt_id: str,
) -> FinanceVerdict:
    """Auto-decisions need a declared human escalation lane.

    Auto-accept / auto-decline without a declared
    ``escalate_to_officer`` lane is ``finance.no_human_lane``
    (German bank lesson). A routing receipt that claims a lane the
    deployment never declared is ``finance.undeclared_lane``.
    """
    _check_nonempty_str(receipt_id, "receipt_id")
    if not isinstance(declaration, LaneDeclaration):
        raise FinanceError("declaration must be a LaneDeclaration")
    declared = set(declaration.lanes)
    receipt = next(
        (r for r in routing.log if r.receipt_id == receipt_id), None
    )
    if receipt is None:
        return _deny(
            "finance:no_routing_receipt",
            f"decision without a routing receipt {receipt_id!r}",
        )
    if receipt.lane not in declared:
        return _deny(
            "finance:undeclared_lane",
            f"routing {receipt_id!r} claims lane {receipt.lane!r} not in the "
            f"deployment's declared lanes {sorted(declared)}",
        )
    if "escalate_to_officer" not in declared:
        return _deny(
            "finance:no_human_lane",
            f"deployment {declaration.deployment_id!r} has no human "
            "escalation lane (auto-accept/auto-decline only)",
        )
    return _allow(
        f"routing {receipt_id!r} took lane {receipt.lane!r}; a human "
        "escalation lane is declared",
        receipt.receipt_digest,
    )


# ---------------------------------------------------------------------------
# 10. Premium-explanation receipts (ASIC lesson)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PremiumExplanationReceipt:
    """Binds a premium quote to its key factors + year-over-year change."""

    receipt_id: str
    quote_id: str
    premium_minor: int
    key_factors: tuple[str, ...]
    yoy_change_bps: int  # basis points vs the previous term; signed
    yoy_change_explained: bool
    quoted_at: int
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str
    receipt_digest: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": FINANCE_SCHEMA_VERSION,
            "type": "premium_explanation",
            "receipt_id": self.receipt_id,
            "quote_id": self.quote_id,
            "premium_minor": self.premium_minor,
            "key_factors": sorted(self.key_factors),
            "yoy_change_bps": self.yoy_change_bps,
            "yoy_change_explained": self.yoy_change_explained,
            "quoted_at": self.quoted_at,
            "authority_id": self.authority_id,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
        }


@dataclass
class PremiumExplanationRegistry:
    """Hash-chained log of premium-explanation receipts."""

    authorities: AuthorityRegistry
    log: list[PremiumExplanationReceipt]

    def __init__(self, authorities: AuthorityRegistry) -> None:
        self.authorities = authorities
        self.log = []

    def issue(
        self,
        receipt_id: str,
        quote_id: str,
        premium_minor: int,
        key_factors: tuple[str, ...],
        yoy_change_bps: int,
        yoy_change_explained: bool,
        quoted_at: int,
        authority_id: str,
        authority_secret: bytes,
    ) -> PremiumExplanationReceipt:
        _check_nonempty_str(receipt_id, "receipt_id")
        _check_nonempty_str(quote_id, "quote_id")
        _check_positive_int(premium_minor, "premium_minor")
        if not key_factors or not all(
            isinstance(f, str) and f.strip() for f in key_factors
        ):
            raise FinanceError("key_factors must be a non-empty tuple of strings")
        if not isinstance(yoy_change_bps, int) or isinstance(yoy_change_bps, bool):
            raise FinanceError("yoy_change_bps must be an int")
        if not isinstance(yoy_change_explained, bool):
            raise FinanceError("yoy_change_explained must be a bool")
        _check_ts(quoted_at, "quoted_at")
        pubkey = self.authorities.pubkey(authority_id)
        if pubkey is None:
            raise FinanceError(f"unknown authority {authority_id!r}")
        prev = _new_log(self)
        payload = {
            "schema": FINANCE_SCHEMA_VERSION,
            "type": "premium_explanation",
            "receipt_id": receipt_id,
            "quote_id": quote_id,
            "premium_minor": premium_minor,
            "key_factors": sorted(key_factors),
            "yoy_change_bps": yoy_change_bps,
            "yoy_change_explained": yoy_change_explained,
            "quoted_at": quoted_at,
            "authority_id": authority_id,
            "authority_pubkey_hex": pubkey,
            "prev_digest": prev,
        }
        sig_body = dict(payload)
        sig_body["signature_hex"] = "00" * 64
        signature = ed25519.sign(authority_secret, jcs_canonical_json(sig_body))
        receipt = PremiumExplanationReceipt(
            receipt_id=receipt_id,
            quote_id=quote_id,
            premium_minor=premium_minor,
            key_factors=tuple(key_factors),
            yoy_change_bps=yoy_change_bps,
            yoy_change_explained=yoy_change_explained,
            quoted_at=quoted_at,
            authority_id=authority_id,
            authority_pubkey_hex=pubkey,
            signature_hex=signature.hex(),
            prev_digest=prev,
            receipt_digest=jcs_sha256_hex(payload),
        )
        self.log.append(receipt)
        _check_chain(self.log, "premium_explanation")
        return receipt

    def get(self, receipt_id: str) -> PremiumExplanationReceipt | None:
        for r in self.log:
            if r.receipt_id == receipt_id:
                return r
        return None


def premium_explanation_receipt(
    premiums: PremiumExplanationRegistry,
    receipt_id: str,
    checked_at: int,
) -> FinanceVerdict:
    """Quotes bind key pricing factors and year-over-year changes.

    A missing receipt is ``finance.premium_unexplained`` (ASIC lesson:
    none of the five reviewed insurers explained key factors). A
    year-over-year change with no explanation is
    ``finance.unexplained_change``. Factors must be substantive, not
    a single vague token.
    """
    _check_ts(checked_at, "checked_at")
    quote = premiums.get(receipt_id)
    if quote is None:
        return _deny(
            "finance:premium_unexplained",
            f"quote without a premium-explanation receipt {receipt_id!r}",
        )
    if checked_at - quote.quoted_at > ADVERSE_ACTION_MAX_AGE_S:
        return _deny(
            "finance:stale_premium_explanation",
            f"premium-explanation receipt {receipt_id!r} is older than 365 days",
        )
    if quote.yoy_change_bps != 0 and not quote.yoy_change_explained:
        return _deny(
            "finance:unexplained_change",
            f"quote {receipt_id!r} changed {quote.yoy_change_bps} bps "
            "year-over-year with no explanation",
        )
    substantive = [f for f in quote.key_factors if len(f.strip()) >= 4]
    if len(substantive) < 2:
        return _deny(
            "finance:thin_factors",
            f"quote {receipt_id!r} lists no substantive pricing factors",
        )
    return _allow(
        f"quote {receipt_id!r} binds {len(substantive)} key factors and a "
        "year-over-year explanation",
        quote.receipt_digest,
    )


# ---------------------------------------------------------------------------
# 11. Tipping-off boundary (UK s.333A: lawful silence is receipted)
# ---------------------------------------------------------------------------


def tipping_off_boundary(
    bars: TippingOffBarRegistry,
    account_id: str,
    disclosed_reason: bool,
) -> FinanceVerdict:
    """Lawful silence is declared; unexplained silence fails.

    When the law bars disclosure, the system binds a
    :class:`TippingOffBarReceipt` — the customer learns the silence is
    a legal duty, not a black box. Disclosing nothing with no bar
    receipt is ``finance.silent_bar``; disclosing a reason while a bar
    receipt is bound is ``finance.bar_violated`` (disclosure may itself
    be the offence).
    """
    _check_nonempty_str(account_id, "account_id")
    if not isinstance(disclosed_reason, bool):
        raise FinanceError("disclosed_reason must be a bool")
    barred = bars.has_for(account_id)
    if barred and disclosed_reason:
        return _deny(
            "finance:bar_violated",
            f"account {account_id!r}: a reason was disclosed while a "
            "tipping-off bar receipt is bound (UK s.333A)",
        )
    if barred and not disclosed_reason:
        return _allow(
            f"account {account_id!r}: silence is legally barred and the bar "
            "is receipted — the customer sees the duty, not the box"
        )
    if not barred and not disclosed_reason:
        return _deny(
            "finance:silent_bar",
            f"account {account_id!r}: no reason disclosed and no tipping-off "
            "bar receipt bound — unexplained silence",
        )
    return _allow(
        f"account {account_id!r}: a reason was disclosed with no bar in force"
    )


__all__ = [
    "FINANCE_SCHEMA_VERSION",
    "HIGH_IMPACT_USES",
    "NOTICE_MIN_DAYS_NEW",
    "NOTICE_MIN_DAYS_OLD",
    "PROXY_FEATURES",
    "PRICING_DISPARITY_MAX",
    "VAGUE_REASONS",
    "AdverseActionReceipt",
    "AdverseActionRegistry",
    "AuthorityRegistry",
    "ClosureNoticeReceipt",
    "ClosureNoticeRegistry",
    "DecisionRoutingReceipt",
    "DecisionRoutingRegistry",
    "FinanceError",
    "FinanceVerdict",
    "FraudFlag",
    "FreezeReceipt",
    "FreezeRegistry",
    "HighImpactCert",
    "HighImpactRegistry",
    "HumanReviewReceipt",
    "LaneDeclaration",
    "ModelProxyAudit",
    "ModelProxyAuditRegistry",
    "PremiumExplanationReceipt",
    "PremiumExplanationRegistry",
    "PricingEvaluation",
    "PricingEvaluationLog",
    "SharedMarkerAppealReceipt",
    "SharedMarkerAppealRegistry",
    "TippingOffBarReceipt",
    "TippingOffBarRegistry",
    "adverse_action_receipt",
    "closure_notice_receipt",
    "debanking_share_guard",
    "flag_is_not_guilt_gate",
    "freeze_proportionality_gate",
    "high_impact_registry",
    "human_escalation_lane",
    "premium_explanation_receipt",
    "pricing_fairness_rules_layer",
    "proxy_screen",
    "tipping_off_boundary",
]
