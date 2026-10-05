"""Herd-correlation gate (one-hundred-eighth batch).

Absorbs the 2026 AI-finance research thread (mechanism ideas only,
honestly scoped):

* **The July 2026 AI selloff.** Quants surrendered a quarter of YTD
  gains (14.4% -> 10.8%) — not from model failure but from *synthetic
  correlation*: dozens of AIs made the same "right" trade on
  overlapping data (High-Flyer, DeepSeek's founder's shop, -15.7% in
  one week). The survivors had differentiated data, not smarter
  models. Neudata's read: AI adoption in trading is mainstream but the
  payoff is efficiency, not alpha — only 17% of adopters credit AI
  with better investment performance, and AI-for-strategy use actually
  *slipped* 31% -> 28%.
* **The regulatory gap.** SR 11-7 (model risk management) was
  rescinded in April 2026 and replaced by SR 26-2, which *explicitly
  excludes* generative and agentic AI from scope — so US banks running
  LLM trading controls have no governing framework for them. The EU
  AI Act treats credit scoring as Annex III high-risk (obligations
  delayed to 2027-12-02 via the Digital Omnibus) but fraud detection
  is carved out. A framework carve-out is not a risk carve-out:
  Northstar keeps its own evidence discipline regardless.

Northstar mapping: correlation is the risk, not just individual-model
error. Every autonomous trading strategy must *declare* its signal
sources (dataset/model digests, feature families, data windows,
training corpus manifest digest) in a hash-chained registry. A new
strategy whose declared signal overlap with any registered strategy
exceeds ``HERD_CORRELATION_MAX`` is denied — it would be the N+1st
copy of the same trade. And even uncorrelated strategies share a
correlated-exposure cap: the total notional across strategies that
share *any* signal source must stay under the cap, so a marginal
strategy that would concentrate the book denies.

Honest boundary: the gate checks *declared* sources. It cannot detect
a strategy that lies about its inputs (undeclared copying, or a
declared-clean strategy that actually trains on the herd's data);
catching that needs trade-level surveillance and weight/data
provenance, outside this module's scope. What it does guarantee: if
the *declared* overlap is herd-like, or the declared exposure would
concentrate the book, the strategy does not trade — there is no path
from a declared herd strategy to autonomous execution.

Deterministic: no wall-clock reads (callers inject ``declared_unix``
as an integer), canonical JCS hashing, and all digest comparisons
use :func:`hmac.compare_digest`.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field
from typing import Any, Mapping

from canonical_json import jcs_sha256_hex

HERD_GATE_SCHEMA_VERSION = "northstar.herd-gate.v1"

#: Maximum allowed Jaccard-style signal overlap with any single
#: registered strategy. Above this, the newcomer is judged a herd
#: clone and denied. Chosen so that a strategy sharing its corpus AND
#: most features with an incumbent trips, while a strategy sharing a
#: single common feature family does not.
HERD_CORRELATION_MAX = 0.7

#: Denial reason codes. All start with the ``herd:`` prefix so audit
#: consumers can filter the family.
DENY_NO_DECLARATION = "herd:no_declaration"
DENY_CORRELATED_STRATEGY = "herd:correlated_strategy"
DENY_EXPOSURE_CAPPED = "herd:exposure_capped"
DENY_DUPLICATE_STRATEGY_ID = "herd:duplicate_strategy_id"
DENY_UNAUTHORIZED_DEREGISTRATION = "herd:unauthorized_deregistration"
DENY_UNKNOWN_STRATEGY = "herd:unknown_strategy"
DENY_MALFORMED = "herd:malformed"
DENY_DIGEST_MISMATCH = "herd:digest_mismatch"

#: Audit event names (shaped for ``audit_chain.chain_record``).
HERD_STRATEGY_REGISTERED_EVENT = "herd.strategy_registered"
HERD_STRATEGY_DEREGISTERED_EVENT = "herd.strategy_deregistered"
HERD_STRATEGY_DENIED_EVENT = "herd.strategy_denied"
HERD_EXPOSURE_CAPPED_EVENT = "herd.exposure_capped"

#: Closed feature-family vocabulary. Strategies must pick from this
#: list; free-text feature names would let near-duplicates dodge the
#: overlap math by renaming the same signal.
FEATURE_FAMILIES: tuple[str, ...] = (
    "price-momentum",
    "order-book",
    "news-sentiment",
    "on-chain-flow",
    "macro-indicators",
    "options-flow",
    "fundamentals",
    "alternative-data",
)

_HEX64_LENGTH = 64


class HerdGateError(ValueError):
    """A malformed declaration, registry, or gate input — a programming
    error, not a verdict. Verification *failures* (herd correlation,
    exposure cap, bad authority) return a verdict with
    ``allowed=False`` instead; malformed inputs raise here, fail loud,
    never guess."""


def _is_hex64(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == _HEX64_LENGTH
        and all(c in "0123456789abcdef" for c in value)
    )


def _require_hex64(value: Any, what: str) -> str:
    if not _is_hex64(value):
        raise HerdGateError(f"{what} must be a 64-char lowercase hex digest")
    return value


def _require_nonempty(value: Any, what: str) -> str:
    if not isinstance(value, str) or not value:
        raise HerdGateError(f"{what} must be a non-empty string")
    return value


def _signal_tokens(
    signal_sources: frozenset[str],
    feature_families: frozenset[str],
    data_windows: frozenset[str],
    corpus_digest: str,
) -> frozenset[str]:
    """The overlap token set for one strategy.

    Corpus digest, feature families, and data windows all become
    tokens so that Jaccard overlap captures "same data, same signals,
    same lookback" in a single number.
    """
    tokens = {f"corpus:{corpus_digest}"}
    tokens.update(f"feature:{f}" for f in feature_families)
    tokens.update(f"window:{w}" for w in data_windows)
    tokens.update(f"source:{s}" for s in signal_sources)
    return frozenset(tokens)


def jaccard_overlap(a: frozenset[str], b: frozenset[str]) -> float:
    """Jaccard similarity of two token sets. Deterministic, pure."""
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


# ---------------------------------------------------------------------------
# SignalDeclaration: what a strategy says it trades on
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SignalDeclaration:
    """A strategy's declared signal sources, the receipt it is judged by.

    ``signal_sources`` are dataset/model digests (hex64);
    ``feature_families`` is drawn from the closed
    :data:`FEATURE_FAMILIES` vocabulary; ``data_windows`` are
    normalized lookback labels (e.g. ``"2026-01..2026-06"``);
    ``training_corpus_manifest_digest`` binds the training pool
    (model_lineage discipline); ``registered_by`` is the authority that
    filed the declaration; ``notional_cents`` is the strategy's maximum
    notional, used by the exposure cap.
    """

    strategy_id: str
    signal_sources: frozenset[str] = frozenset()
    feature_families: frozenset[str] = frozenset()
    data_windows: frozenset[str] = frozenset()
    training_corpus_manifest_digest: str = ""
    registered_by: str = ""
    declared_unix: int = 0
    notional_cents: int = 0

    def __post_init__(self) -> None:
        _require_nonempty(self.strategy_id, "strategy_id")
        _require_nonempty(self.registered_by, "registered_by")
        _require_hex64(self.training_corpus_manifest_digest, "training_corpus_manifest_digest")
        for s in self.signal_sources:
            _require_hex64(s, "signal source")
        for f in self.feature_families:
            if f not in FEATURE_FAMILIES:
                raise HerdGateError(f"feature family {f!r} not in closed vocabulary")
        for w in self.data_windows:
            _require_nonempty(w, "data window")
        if not isinstance(self.declared_unix, int) or self.declared_unix < 0:
            raise HerdGateError("declared_unix must be a non-negative int")
        if not isinstance(self.notional_cents, int) or self.notional_cents <= 0:
            raise HerdGateError("notional_cents must be a positive int")

    def signal_tokens(self) -> frozenset[str]:
        return _signal_tokens(
            self.signal_sources,
            self.feature_families,
            self.data_windows,
            self.training_corpus_manifest_digest,
        )

    def declaration_digest(self) -> str:
        return jcs_sha256_hex(
            {
                "schema": HERD_GATE_SCHEMA_VERSION,
                "strategy_id": self.strategy_id,
                "signal_sources": sorted(self.signal_sources),
                "feature_families": sorted(self.feature_families),
                "data_windows": sorted(self.data_windows),
                "training_corpus_manifest_digest": self.training_corpus_manifest_digest,
                "registered_by": self.registered_by,
                "declared_unix": self.declared_unix,
                "notional_cents": self.notional_cents,
            }
        )


def build_declaration(
    *,
    strategy_id: str,
    signal_sources: list[str] | None = None,
    feature_families: list[str] | None = None,
    data_windows: list[str] | None = None,
    training_corpus_manifest_digest: str,
    registered_by: str,
    declared_unix: int = 0,
    notional_cents: int,
) -> SignalDeclaration:
    """Construct a :class:`SignalDeclaration`, validating inputs."""
    return SignalDeclaration(
        strategy_id=strategy_id,
        signal_sources=frozenset(signal_sources or ()),
        feature_families=frozenset(feature_families or ()),
        data_windows=frozenset(data_windows or ()),
        training_corpus_manifest_digest=training_corpus_manifest_digest,
        registered_by=registered_by,
        declared_unix=declared_unix,
        notional_cents=notional_cents,
    )


# ---------------------------------------------------------------------------
# StrategyRegistry: hash-chained, authority-bound strategy log
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RegistryRecord:
    """One append-only registry entry binding a declaration digest."""

    strategy_id: str
    declaration_digest: str
    registered_by: str
    prev_hash: str
    recorded_unix: int

    def record_digest(self) -> str:
        return jcs_sha256_hex(
            {
                "schema": HERD_GATE_SCHEMA_VERSION,
                "strategy_id": self.strategy_id,
                "declaration_digest": self.declaration_digest,
                "registered_by": self.registered_by,
                "prev_hash": self.prev_hash,
                "recorded_unix": self.recorded_unix,
            }
        )


class StrategyRegistry:
    """The live strategy registry: hash-chained and authority-bound.

    Registration appends a record; deregistration requires the *same*
    authority that registered the strategy — no silent mid-session
    strategy swaps, no hostile takeovers of another desk's strategy.
    """

    def __init__(self) -> None:
        self._records: list[RegistryRecord] = []
        self._declarations: dict[str, SignalDeclaration] = {}

    def _head(self) -> str:
        return self._records[-1].record_digest() if self._records else ""

    def register(
        self,
        declaration: SignalDeclaration,
        *,
        recorded_unix: int = 0,
    ) -> RegistryRecord:
        if not isinstance(declaration, SignalDeclaration):
            raise HerdGateError("declaration must be a SignalDeclaration")
        if declaration.strategy_id in self._declarations:
            raise HerdGateError(
                f"strategy {declaration.strategy_id!r} already registered"
            )
        record = RegistryRecord(
            strategy_id=declaration.strategy_id,
            declaration_digest=declaration.declaration_digest(),
            registered_by=declaration.registered_by,
            prev_hash=self._head(),
            recorded_unix=recorded_unix,
        )
        self._records.append(record)
        self._declarations[declaration.strategy_id] = declaration
        return record

    def deregister(self, strategy_id: str, authority: str) -> bool:
        """Remove a strategy. Only the registering authority may do it."""
        _require_nonempty(strategy_id, "strategy_id")
        _require_nonempty(authority, "authority")
        declaration = self._declarations.get(strategy_id)
        if declaration is None:
            return False
        if not hmac.compare_digest(declaration.registered_by, authority):
            raise HerdGateError(
                f"authority {authority!r} did not register strategy {strategy_id!r}"
            )
        del self._declarations[strategy_id]
        # Removal is itself receipted: the chain stays append-only.
        record = RegistryRecord(
            strategy_id=f"~deregistered:{strategy_id}",
            declaration_digest=declaration.declaration_digest(),
            registered_by=authority,
            prev_hash=self._head(),
            recorded_unix=0,
        )
        self._records.append(record)
        return True

    def declaration(self, strategy_id: str) -> SignalDeclaration | None:
        return self._declarations.get(strategy_id)

    def live_strategies(self) -> list[SignalDeclaration]:
        return list(self._declarations.values())

    def verify_chain(self) -> bool:
        """Recompute every record digest and prev_hash linkage."""
        previous = ""
        for record in self._records:
            if not hmac.compare_digest(record.prev_hash, previous):
                return False
            digest = record.record_digest()
            if not _is_hex64(digest):
                return False
            previous = digest
        return True


# ---------------------------------------------------------------------------
# Herd-correlation check
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CorrelationVerdict:
    """Result of :func:`check_herd_correlation`."""

    allowed: bool
    max_overlap: float
    most_similar_id: str
    reason: str


def check_herd_correlation(
    new_declaration: SignalDeclaration,
    registered: list[SignalDeclaration],
) -> CorrelationVerdict:
    """Deny a strategy that is a herd clone of a registered one.

    Computes Jaccard overlap of the signal-token sets (corpus digest +
    feature families + data windows + signal sources) between the new
    declaration and every registered strategy. The worst overlap above
    :data:`HERD_CORRELATION_MAX` denies with
    ``herd:correlated_strategy``. Pure function, never raises on
    verdict outcomes.
    """
    if not isinstance(new_declaration, SignalDeclaration):
        raise HerdGateError("new_declaration must be a SignalDeclaration")
    new_tokens = new_declaration.signal_tokens()
    worst = 0.0
    worst_id = ""
    for existing in registered:
        if existing.strategy_id == new_declaration.strategy_id:
            continue
        overlap = jaccard_overlap(new_tokens, existing.signal_tokens())
        if overlap > worst:
            worst = overlap
            worst_id = existing.strategy_id
    if worst > HERD_CORRELATION_MAX:
        return CorrelationVerdict(
            allowed=False,
            max_overlap=worst,
            most_similar_id=worst_id,
            reason=DENY_CORRELATED_STRATEGY,
        )
    return CorrelationVerdict(
        allowed=True,
        max_overlap=worst,
        most_similar_id=worst_id,
        reason="herd_overlap_within_limit",
    )


def correlated_exposure_cents(
    new_declaration: SignalDeclaration,
    registered: list[SignalDeclaration],
) -> int:
    """Total notional of registered strategies sharing *any* signal
    token with the newcomer, plus the newcomer's own notional.

    Sharing even one token (one dataset, one feature family, one
    window) counts the whole strategy's notional as correlated — the
    July-2026 lesson is that partial overlap still moves together.
    """
    new_tokens = new_declaration.signal_tokens()
    total = new_declaration.notional_cents
    for existing in registered:
        if existing.strategy_id == new_declaration.strategy_id:
            continue
        if new_tokens & existing.signal_tokens():
            total += existing.notional_cents
    return total


# ---------------------------------------------------------------------------
# Trading gate
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TradeVerdict:
    """The verdict of :func:`authorize_trading`."""

    allowed: bool
    reason: str
    strategy_id: str
    audit_event: dict[str, Any]


def herd_audit_event(
    *,
    event: str,
    strategy_id: str,
    allowed: bool,
    reason: str,
    detail: Mapping[str, Any] | None = None,
    created_unix: int = 0,
) -> dict[str, Any]:
    """Audit event shaped to feed ``audit_chain.chain_record``."""
    body: dict[str, Any] = {
        "event": event,
        "strategy_id": strategy_id,
        "allowed": allowed,
        "reason": reason,
        "created_unix": created_unix,
    }
    if detail:
        body["detail"] = dict(detail)
    return body


def authorize_trading(
    *,
    strategy_id: str,
    registry: StrategyRegistry,
    exposure_cap_cents: int,
    created_unix: int = 0,
) -> TradeVerdict:
    """Gate an autonomous trading strategy's session, fail-closed.

    Gate order is fixed: (1) the strategy must be registered — an
    undeclared strategy cannot trade (``herd:no_declaration``); (2)
    its declared signal overlap with the registered herd must be
    within ``HERD_CORRELATION_MAX`` — a herd clone denies
    (``herd:correlated_strategy``); (3) the correlated exposure (the
    newcomer's notional plus every registered strategy sharing any
    signal token) must stay within ``exposure_cap_cents`` — a
    book-concentrating marginal strategy denies
    (``herd:exposure_capped``).

    Never raises on verification outcomes — denials are values. Raises
    :class:`HerdGateError` only on malformed *inputs*. Every call
    returns an audit event.
    """
    _require_nonempty(strategy_id, "strategy_id")
    if not isinstance(registry, StrategyRegistry):
        raise HerdGateError("registry must be a StrategyRegistry")
    if not isinstance(exposure_cap_cents, int) or exposure_cap_cents <= 0:
        raise HerdGateError("exposure_cap_cents must be a positive int")

    declaration = registry.declaration(strategy_id)
    if declaration is None:
        return TradeVerdict(
            allowed=False,
            reason=DENY_NO_DECLARATION,
            strategy_id=strategy_id,
            audit_event=herd_audit_event(
                event=HERD_STRATEGY_DENIED_EVENT,
                strategy_id=strategy_id,
                allowed=False,
                reason=DENY_NO_DECLARATION,
                created_unix=created_unix,
            ),
        )

    herd = [d for d in registry.live_strategies() if d.strategy_id != strategy_id]
    correlation = check_herd_correlation(declaration, herd)
    if not correlation.allowed:
        return TradeVerdict(
            allowed=False,
            reason=correlation.reason,
            strategy_id=strategy_id,
            audit_event=herd_audit_event(
                event=HERD_STRATEGY_DENIED_EVENT,
                strategy_id=strategy_id,
                allowed=False,
                reason=correlation.reason,
                detail={
                    "max_overlap": round(correlation.max_overlap, 4),
                    "most_similar_id": correlation.most_similar_id,
                    "limit": HERD_CORRELATION_MAX,
                },
                created_unix=created_unix,
            ),
        )

    exposure = correlated_exposure_cents(declaration, herd)
    if exposure > exposure_cap_cents:
        return TradeVerdict(
            allowed=False,
            reason=DENY_EXPOSURE_CAPPED,
            strategy_id=strategy_id,
            audit_event=herd_audit_event(
                event=HERD_EXPOSURE_CAPPED_EVENT,
                strategy_id=strategy_id,
                allowed=False,
                reason=DENY_EXPOSURE_CAPPED,
                detail={
                    "correlated_exposure_cents": exposure,
                    "exposure_cap_cents": exposure_cap_cents,
                },
                created_unix=created_unix,
            ),
        )

    return TradeVerdict(
        allowed=True,
        reason="herd_checks_passed",
        strategy_id=strategy_id,
        audit_event=herd_audit_event(
            event=HERD_STRATEGY_REGISTERED_EVENT,
            strategy_id=strategy_id,
            allowed=True,
            reason="herd_checks_passed",
            detail={
                "max_overlap": round(correlation.max_overlap, 4),
                "correlated_exposure_cents": exposure,
            },
            created_unix=created_unix,
        ),
    )


__all__ = [
    "HERD_GATE_SCHEMA_VERSION",
    "HERD_CORRELATION_MAX",
    "FEATURE_FAMILIES",
    "DENY_NO_DECLARATION",
    "DENY_CORRELATED_STRATEGY",
    "DENY_EXPOSURE_CAPPED",
    "DENY_DUPLICATE_STRATEGY_ID",
    "DENY_UNAUTHORIZED_DEREGISTRATION",
    "DENY_UNKNOWN_STRATEGY",
    "DENY_MALFORMED",
    "DENY_DIGEST_MISMATCH",
    "HERD_STRATEGY_REGISTERED_EVENT",
    "HERD_STRATEGY_DEREGISTERED_EVENT",
    "HERD_STRATEGY_DENIED_EVENT",
    "HERD_EXPOSURE_CAPPED_EVENT",
    "HerdGateError",
    "SignalDeclaration",
    "build_declaration",
    "RegistryRecord",
    "StrategyRegistry",
    "CorrelationVerdict",
    "check_herd_correlation",
    "correlated_exposure_cents",
    "jaccard_overlap",
    "TradeVerdict",
    "herd_audit_event",
    "authorize_trading",
]
