"""Transaction fraud detection interface (deterministic rules + additive scoring).

Research motivation: transaction fraud is the oldest adversarial corner of
agent-run economies -- stolen keys do not look like the owner for long.
Industry practice (Visa VAA, Mastercard Decision Intelligence, Stripe
Radar) converges on the same bookkeeping shape this module pins:

- *signals*: per-transaction facts (amount, velocity, device, geo, time)
  evaluated against per-account rolling history;
- *weighted rules*: each rule that fires contributes a calibrated weight;
  blacklists are a hard override, not a weight;
- *two thresholds*: ``review`` (human look) and ``block`` (auto-reject),
  so the gray zone is explicit instead of a single knife edge.

This module is the *bookkeeping* half of that shape, pinned so the
runtime's payment plumbing speaks one dialect:

- ``FraudDetector`` -- owns the ordered rule registry, per-account
  rolling history, and the two thresholds. ``add_rule()`` pins an
  immutable rule (one of the built-in kinds), ``score()`` evaluates a
  transaction and returns a frozen ``FraudScore`` (score, matched rules,
  recommended action), ``block()`` enforces the block threshold (raises
  ``BlockedTransactionError`` when the txn is block-worthy), and
  ``review()`` opens a ``ReviewRecord`` for the review band.
- ``fraud_detector_audit_event(kind, ...)`` -- ``audit.ndjson/1``
  records (``rule-added`` / ``scored`` / ``blocked`` / ``review-opened`` /
  ``review-needed-false`` / ``blacklist-added``); caller-supplied seqs only.

Fail-closed edges (fail loudly, never guess):

- Transaction ids and account ids are non-empty ``str`` and unique per
  submit where checked; ``amount`` is either a non-negative ``int`` in
  minor units (cents) or a ``str`` decimal ("12.34") parsed to cents --
  floats are refused outright (no binary float anywhere near money), as
  are ``NaN``/``inf`` and abs >= 2**63.
- ``ts`` is a caller-supplied unix epoch ``int`` (>= 0). The detector
  never calls the wall clock: history ordering is whatever the caller
  asserts.
- Unknown rule kinds, duplicate rule names, and weights outside (0, 1]
  are refused at add time, never at score time.
- A *missing* optional attribute (device_id, ip, merchant_id, geo) makes
  the rules that need it not fire (never an error, never a guess), except
  the required core (txn_id / account_id / amount / currency / ts).
- Score is ``min(1.0, sum(weights))``; a blacklist hit forces ``1.0``
  with action ``block`` regardless of thresholds. ``review_threshold <
  block_threshold`` is enforced at construction.

Honest scope:

- This module books *host-reported* signals. It cannot verify that the
  device_id or geo attached to a txn is true about the world; a lying
  host gets a lying score ledger. The digests bind the *reported*
  transactions to the decisions, not the truth.
- The rules are deterministic heuristics, not a trained model: there is
  no training, no online learning, no drift adaptation. The weights are
  calibrated defaults, not risk-engine output.
- History is in-memory per account, pruned to the configured window;
  pair with the durable audit writer if decisions must survive a
  restart. ``main()`` self-checks the shape.
"""

from __future__ import annotations

import hashlib
import math
import threading
from collections import deque
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_sha256_hex
except Exception:  # pragma: no cover - module must stay importable standalone
    import hashlib as _hashlib
    import json as _json

    def jcs_sha256_hex(obj: Any) -> str:  # type: ignore[no-redef]
        raw = _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True).encode("utf-8")
        return _hashlib.sha256(raw).hexdigest()

import canonical_json

FRAUD_DETECTOR_VERSION = "fraud-detector.v1"
FRAUD_DETECTOR_SCHEMA = "northstar.fraud-detector.v1"
AUDIT_SCHEMA = "audit.ndjson/1"

ACTION_ALLOW = "allow"
ACTION_REVIEW = "review"
ACTION_BLOCK = "block"

DEFAULT_BLOCK_THRESHOLD = 0.8
DEFAULT_REVIEW_THRESHOLD = 0.4

# Max speed (km/h) above which two consecutive geo-tagged txns are
# "impossible travel". 1000 km/h is just above airliner cruise speed.
IMPOSSIBLE_TRAVEL_KMH = 1000.0
# Rolling history is pruned beyond this (24h); velocity rules use a
# smaller caller-visible window.
HISTORY_WINDOW_S = 24 * 3600

REQUIRED_TXN_FIELDS = ("txn_id", "account_id", "amount", "currency", "ts")

# Built-in rule kinds. Each maps to a deterministic check over
# (txn, history_snapshot). Kept as a closed set so score-time behavior
# is fully pinned at add time.
RULE_KINDS = (
    "amount_outlier",
    "velocity",
    "new_device",
    "impossible_travel",
    "blacklisted",
    "odd_hour",
    "card_testing",
    "round_amount",
)


# ---------------------------------------------------------------------------
# errors
# ---------------------------------------------------------------------------


class FraudError(Exception):
    """Base error for the fraud detector."""


class UnknownRuleError(FraudError):
    """Raised for an unknown rule kind or an unknown rule name."""


class DuplicateRuleError(FraudError):
    """Raised when a rule name is registered twice."""


class InvalidTransactionError(FraudError):
    """Raised when a transaction fails shape validation."""


class BlockedTransactionError(FraudError):
    """Raised by ``block()`` when the txn is block-worthy.

    Carries the frozen ``BlockDecision`` in ``decision`` so callers can
    log / forward the exact score that caused the block.
    """

    def __init__(self, message: str, decision: "BlockDecision") -> None:
        super().__init__(message)
        self.decision = decision


# ---------------------------------------------------------------------------
# frozen records
# ---------------------------------------------------------------------------


def _digest(payload: Mapping[str, Any]) -> str:
    return "sha256:" + jcs_sha256_hex(payload)


@dataclass(frozen=True)
class RuleRecord:
    """An immutable registered rule."""

    name: str
    kind: str
    weight: float
    params: Tuple[Tuple[str, Any], ...]
    digest: str
    version: str = FRAUD_DETECTOR_VERSION
    schema: str = FRAUD_DETECTOR_SCHEMA


@dataclass(frozen=True)
class TriggeredRule:
    name: str
    kind: str
    weight: float
    evidence: str


@dataclass(frozen=True)
class FraudScore:
    """Frozen result of ``score()``."""

    txn_id: str
    account_id: str
    score: float
    action: str
    matched: Tuple[TriggeredRule, ...]
    blacklist_hit: bool
    digest: str
    version: str = FRAUD_DETECTOR_VERSION
    schema: str = FRAUD_DETECTOR_SCHEMA


@dataclass(frozen=True)
class BlockDecision:
    """Frozen result of ``block()``."""

    txn_id: str
    account_id: str
    allowed: bool
    score: FraudScore
    reason: str


@dataclass(frozen=True)
class ReviewRecord:
    """Frozen result of ``review()``."""

    case_id: str
    txn_id: str
    account_id: str
    needed: bool
    score: float
    reasons: Tuple[str, ...]


# ---------------------------------------------------------------------------
# audit events
# ---------------------------------------------------------------------------


def fraud_detector_audit_event(
    kind: str,
    *,
    seq: int,
    txn_id: Optional[str] = None,
    account_id: Optional[str] = None,
    score: Optional[float] = None,
    action: Optional[str] = None,
    detail: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for the fraud detector.

    ``seq`` is caller-supplied (the detector never mints its own).
    """
    if not isinstance(seq, int) or seq < 0:
        raise FraudError("seq must be a non-negative int")
    event: Dict[str, Any] = {
        "schema": AUDIT_SCHEMA,
        "component": "fraud-detector",
        "version": FRAUD_DETECTOR_VERSION,
        "kind": kind,
        "seq": seq,
    }
    if txn_id is not None:
        event["txn_id"] = txn_id
    if account_id is not None:
        event["account_id"] = account_id
    if score is not None:
        event["score"] = score
    if action is not None:
        event["action"] = action
    if detail is not None:
        event["detail"] = dict(detail)
    return event


# ---------------------------------------------------------------------------
# transaction normalization
# ---------------------------------------------------------------------------


def _to_cents(amount: Any) -> int:
    """Normalize ``amount`` to integer minor units.

    Accepts non-negative ``int`` (already minor units) or a ``str``
    decimal ("12.34" -> 1200). Floats are refused: no binary float is
    allowed near money. ``Decimal`` input is accepted for convenience.
    """
    if isinstance(amount, bool):
        raise InvalidTransactionError("amount must not be a bool")
    if isinstance(amount, int):
        cents = amount
    elif isinstance(amount, str):
        try:
            dec = Decimal(amount)
        except InvalidOperation:
            raise InvalidTransactionError(f"amount is not a decimal: {amount!r}")
        if dec.is_nan() or dec.is_infinite():
            raise InvalidTransactionError("amount must be finite")
        cents = int((dec * 100).to_integral_value())
        if Decimal(cents) != dec * 100:
            raise InvalidTransactionError(
                f"amount has sub-cent precision: {amount!r}"
            )
    elif isinstance(amount, Decimal):
        if amount.is_nan() or amount.is_infinite():
            raise InvalidTransactionError("amount must be finite")
        cents = int((amount * 100).to_integral_value())
    else:
        raise InvalidTransactionError(
            f"amount must be int minor units or str decimal, got {type(amount).__name__}"
        )
    if cents < 0:
        raise InvalidTransactionError("amount must be non-negative")
    if cents >= 2**63:
        raise InvalidTransactionError("amount out of range")
    return cents


@dataclass
class _Txn:
    txn_id: str
    account_id: str
    amount_cents: int
    currency: str
    ts: int
    merchant_id: Optional[str]
    device_id: Optional[str]
    ip: Optional[str]
    geo: Optional[Tuple[float, float]]  # (lat, lon)


def _normalize_txn(txn: Mapping[str, Any]) -> _Txn:
    if not isinstance(txn, Mapping):
        raise InvalidTransactionError("transaction must be a mapping")
    for f in REQUIRED_TXN_FIELDS:
        if f not in txn:
            raise InvalidTransactionError(f"transaction missing required field: {f}")
    txn_id = txn["txn_id"]
    account_id = txn["account_id"]
    if not isinstance(txn_id, str) or not txn_id:
        raise InvalidTransactionError("txn_id must be a non-empty str")
    if not isinstance(account_id, str) or not account_id:
        raise InvalidTransactionError("account_id must be a non-empty str")
    currency = txn["currency"]
    if not isinstance(currency, str) or len(currency) != 3 or not currency.isalpha():
        raise InvalidTransactionError("currency must be a 3-letter code")
    ts = txn["ts"]
    if isinstance(ts, bool) or not isinstance(ts, int) or ts < 0:
        raise InvalidTransactionError("ts must be a non-negative int unix epoch")

    def _opt_str(key: str) -> Optional[str]:
        v = txn.get(key)
        if v is None:
            return None
        if not isinstance(v, str) or not v:
            raise InvalidTransactionError(f"{key} must be a non-empty str or absent")
        return v

    geo = None
    raw_geo = txn.get("geo")
    if raw_geo is not None:
        if not isinstance(raw_geo, (list, tuple)) or len(raw_geo) != 2:
            raise InvalidTransactionError("geo must be a (lat, lon) pair or absent")
        lat, lon = raw_geo
        if isinstance(lat, bool) or isinstance(lon, bool):
            raise InvalidTransactionError("geo coordinates must be numbers")
        if not isinstance(lat, (int, float)) or not isinstance(lon, (int, float)):
            raise InvalidTransactionError("geo coordinates must be numbers")
        if math.isnan(lat) or math.isnan(lon) or math.isinf(lat) or math.isinf(lon):
            raise InvalidTransactionError("geo coordinates must be finite")
        if not (-90.0 <= lat <= 90.0) or not (-180.0 <= lon <= 180.0):
            raise InvalidTransactionError("geo coordinates out of range")
        geo = (float(lat), float(lon))

    return _Txn(
        txn_id=txn_id,
        account_id=account_id,
        amount_cents=_to_cents(txn["amount"]),
        currency=currency.upper(),
        ts=ts,
        merchant_id=_opt_str("merchant_id"),
        device_id=_opt_str("device_id"),
        ip=_opt_str("ip"),
        geo=geo,
    )


def _haversine_km(a: Tuple[float, float], b: Tuple[float, float]) -> float:
    lat1, lon1 = math.radians(a[0]), math.radians(a[1])
    lat2, lon2 = math.radians(b[0]), math.radians(b[1])
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    h = (
        math.sin(dlat / 2) ** 2
        + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2) ** 2
    )
    return 2 * 6371.0088 * math.asin(math.sqrt(h))


# ---------------------------------------------------------------------------
# rule evaluators
# ---------------------------------------------------------------------------
# Each evaluator takes (txn, history, params) and returns an evidence str
# when the rule fires, else None. ``history`` is the per-account deque of
# previously scored _Txn (oldest first), NOT including the current txn.


def _ev_amount_outlier(txn: _Txn, history: List[_Txn], params: Mapping[str, Any]) -> Optional[str]:
    multiple = float(params.get("multiple", 5.0))
    absolute_cents = int(params.get("absolute_cents", 10_000_00))  # $10k default
    if txn.amount_cents >= absolute_cents:
        return f"amount {txn.amount_cents}c >= absolute {absolute_cents}c"
    prior = [h.amount_cents for h in history]
    if len(prior) < 3:
        return None
    prior_sorted = sorted(prior)
    median = prior_sorted[len(prior_sorted) // 2]
    if median <= 0:
        return None
    if txn.amount_cents >= multiple * median:
        return (
            f"amount {txn.amount_cents}c >= {multiple}x rolling median {median}c"
        )
    return None


def _ev_velocity(txn: _Txn, history: List[_Txn], params: Mapping[str, Any]) -> Optional[str]:
    window_s = int(params.get("window_s", 300))
    limit = int(params.get("limit", 10))
    lo = txn.ts - window_s
    count = sum(1 for h in history if lo <= h.ts <= txn.ts) + 1  # include current
    if count >= limit:
        return f"{count} txns in {window_s}s >= limit {limit}"
    return None


def _ev_new_device(txn: _Txn, history: List[_Txn], params: Mapping[str, Any]) -> Optional[str]:
    if txn.device_id is None:
        return None
    seen = {h.device_id for h in history if h.device_id}
    if txn.device_id not in seen:
        return f"device {txn.device_id!r} not seen for account"
    return None


def _ev_impossible_travel(txn: _Txn, history: List[_Txn], params: Mapping[str, Any]) -> Optional[str]:
    if txn.geo is None:
        return None
    max_kmh = float(params.get("max_kmh", IMPOSSIBLE_TRAVEL_KMH))
    # Most recent prior txn with geo.
    prev = None
    for h in reversed(history):
        if h.geo is not None:
            prev = h
            break
    if prev is None:
        return None
    dt_s = txn.ts - prev.ts
    if dt_s <= 0:
        return None  # caller-supplied ordering; do not guess at <= 0 gaps
    dist_km = _haversine_km(prev.geo, txn.geo)
    speed_kmh = dist_km / (dt_s / 3600.0)
    if speed_kmh > max_kmh:
        return (
            f"geo moved {dist_km:.0f}km in {dt_s}s "
            f"({speed_kmh:.0f}km/h > {max_kmh:.0f}km/h)"
        )
    return None


def _ev_blacklisted(txn: _Txn, history: List[_Txn], params: Mapping[str, Any]) -> Optional[str]:
    blacklists = params.get("blacklists") or {}
    for field in ("merchant_id", "ip", "device_id"):
        banned = blacklists.get(field) or set()
        value = getattr(txn, field)
        if value is not None and value in banned:
            return f"{field} {value!r} is blacklisted"
    return None


def _ev_odd_hour(txn: _Txn, history: List[_Txn], params: Mapping[str, Any]) -> Optional[str]:
    # Caller-supplied ts is treated as account-local hour; the detector
    # does not know timezones, so this is a weak additive signal only.
    start = int(params.get("start_hour", 1))
    end = int(params.get("end_hour", 5))
    hour = (txn.ts // 3600) % 24
    if start <= hour < end:
        return f"txn hour {hour} in odd-hour window [{start}, {end})"
    return None


def _ev_card_testing(txn: _Txn, history: List[_Txn], params: Mapping[str, Any]) -> Optional[str]:
    small_cents = int(params.get("small_cents", 200))  # <$2
    window_s = int(params.get("window_s", 600))
    limit = int(params.get("limit", 5))
    if txn.amount_cents > small_cents:
        return None
    lo = txn.ts - window_s
    count = sum(
        1 for h in history if lo <= h.ts <= txn.ts and h.amount_cents <= small_cents
    ) + 1
    if count >= limit:
        return f"{count} sub-{small_cents}c txns in {window_s}s (card testing)"
    return None


def _ev_round_amount(txn: _Txn, history: List[_Txn], params: Mapping[str, Any]) -> Optional[str]:
    min_cents = int(params.get("min_cents", 100_00))  # >= $100
    if txn.amount_cents >= min_cents and txn.amount_cents % 100 == 0:
        return f"round amount {txn.amount_cents}c"
    return None


_EVALUATORS: Dict[str, Callable[[_Txn, List[_Txn], Mapping[str, Any]], Optional[str]]] = {
    "amount_outlier": _ev_amount_outlier,
    "velocity": _ev_velocity,
    "new_device": _ev_new_device,
    "impossible_travel": _ev_impossible_travel,
    "blacklisted": _ev_blacklisted,
    "odd_hour": _ev_odd_hour,
    "card_testing": _ev_card_testing,
    "round_amount": _ev_round_amount,
}


# ---------------------------------------------------------------------------
# detector
# ---------------------------------------------------------------------------


class FraudDetector:
    """Deterministic transaction-fraud rules engine with additive scoring."""

    def __init__(
        self,
        *,
        block_threshold: float = DEFAULT_BLOCK_THRESHOLD,
        review_threshold: float = DEFAULT_REVIEW_THRESHOLD,
        history_window_s: int = HISTORY_WINDOW_S,
    ) -> None:
        for name, value in (("block_threshold", block_threshold),
                            ("review_threshold", review_threshold)):
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise FraudError(f"{name} must be a number")
            if not (0.0 < value <= 1.0):
                raise FraudError(f"{name} must be in (0, 1]")
        if not review_threshold < block_threshold:
            raise FraudError("review_threshold must be < block_threshold")
        if isinstance(history_window_s, bool) or not isinstance(history_window_s, int) \
                or history_window_s <= 0:
            raise FraudError("history_window_s must be a positive int")
        self._block_threshold = float(block_threshold)
        self._review_threshold = float(review_threshold)
        self._history_window_s = history_window_s
        self._lock = threading.Lock()
        self._rules: Dict[str, RuleRecord] = {}
        self._blacklists: Dict[str, set] = {
            "merchant_id": set(),
            "ip": set(),
            "device_id": set(),
        }
        self._history: Dict[str, deque] = {}
        self._review_seq = 0

    # -- configuration ----------------------------------------------------

    @property
    def block_threshold(self) -> float:
        return self._block_threshold

    @property
    def review_threshold(self) -> float:
        return self._review_threshold

    def rule_names(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(self._rules)

    def add_rule(
        self,
        name: str,
        kind: str,
        weight: float,
        params: Optional[Mapping[str, Any]] = None,
    ) -> RuleRecord:
        """Pin an immutable rule. Unknown kinds, duplicate names, and
        weights outside (0, 1] are refused."""
        if not isinstance(name, str) or not name:
            raise FraudError("rule name must be a non-empty str")
        if kind not in RULE_KINDS:
            raise UnknownRuleError(f"unknown rule kind: {kind!r}")
        if isinstance(weight, bool) or not isinstance(weight, (int, float)):
            raise FraudError("weight must be a number")
        if not (0.0 < weight <= 1.0):
            raise FraudError("weight must be in (0, 1]")
        canon_params: Tuple[Tuple[str, Any], ...] = ()
        if params is not None:
            if not isinstance(params, Mapping):
                raise FraudError("params must be a mapping")
            for k, v in params.items():
                if not isinstance(k, str) or not k:
                    raise FraudError("param keys must be non-empty str")
                if isinstance(v, bool) or not isinstance(v, (int, float, str)):
                    raise FraudError(
                        f"param {k!r} must be int/float/str (bool excluded)"
                    )
                canon_params = canon_params + ((k, v),)
        with self._lock:
            if name in self._rules:
                raise DuplicateRuleError(f"duplicate rule name: {name!r}")
            rec = RuleRecord(
                name=name,
                kind=kind,
                weight=float(weight),
                params=canon_params,
                digest=_digest({
                    "component": "fraud-detector",
                    "kind": "rule",
                    "name": name,
                    "rule_kind": kind,
                    "weight": float(weight),
                    "params": dict(canon_params),
                    "version": FRAUD_DETECTOR_VERSION,
                }),
            )
            self._rules[name] = rec
            return rec

    def add_to_blacklist(self, field: str, value: str) -> None:
        """Add a merchant_id / ip / device_id to the blacklist.

        The ``blacklisted`` rule must be registered for this to take
        effect at score time; blacklists are consulted by params
        injection, never by global mutable state at evaluate time.
        """
        if field not in self._blacklists:
            raise FraudError(
                f"blacklist field must be one of {sorted(self._blacklists)}"
            )
        if not isinstance(value, str) or not value:
            raise FraudError("blacklist value must be a non-empty str")
        with self._lock:
            self._blacklists[field].add(value)

    # -- scoring ----------------------------------------------------------

    def _snapshot(self, account_id: str) -> List[_Txn]:
        with self._lock:
            return list(self._history.get(account_id, ()))

    def score(self, txn: Mapping[str, Any]) -> FraudScore:
        """Score a transaction: evaluate rules, sum weights, recommend an
        action. The txn is appended to the account's rolling history
        after evaluation (post-evaluation recording)."""
        norm = _normalize_txn(txn)
        history = self._snapshot(norm.account_id)
        matched: List[TriggeredRule] = []
        blacklist_hit = False
        with self._lock:
            rules = list(self._rules.values())
            blacklists = {k: set(v) for k, v in self._blacklists.items()}
        for rec in rules:
            params = dict(rec.params)
            if rec.kind == "blacklisted":
                params["blacklists"] = blacklists
            evidence = _EVALUATORS[rec.kind](norm, history, params)
            if evidence is not None:
                matched.append(TriggeredRule(
                    name=rec.name,
                    kind=rec.kind,
                    weight=rec.weight,
                    evidence=evidence,
                ))
                if rec.kind == "blacklisted":
                    blacklist_hit = True
        if blacklist_hit:
            total = 1.0
        else:
            total = min(1.0, sum(m.weight for m in matched))
        if total >= self._block_threshold:
            action = ACTION_BLOCK
        elif total >= self._review_threshold:
            action = ACTION_REVIEW
        else:
            action = ACTION_ALLOW
        digest = _digest({
            "component": "fraud-detector",
            "kind": "score",
            "txn_id": norm.txn_id,
            "account_id": norm.account_id,
            "score": total,
            "action": action,
            "matched": [m.name for m in matched],
            "version": FRAUD_DETECTOR_VERSION,
        })
        with self._lock:
            dq = self._history.setdefault(norm.account_id, deque())
            dq.append(norm)
            cutoff = norm.ts - self._history_window_s
            while dq and dq[0].ts < cutoff:
                dq.popleft()
        return FraudScore(
            txn_id=norm.txn_id,
            account_id=norm.account_id,
            score=total,
            action=action,
            matched=tuple(matched),
            blacklist_hit=blacklist_hit,
            digest=digest,
        )

    def block(self, txn: Mapping[str, Any]) -> BlockDecision:
        """Enforce the block threshold.

        Returns an allow ``BlockDecision`` when the score is below the
        block threshold; raises ``BlockedTransactionError`` (carrying the
        decision) when the txn is block-worthy.
        """
        result = self.score(txn)
        if result.action == ACTION_BLOCK:
            decision = BlockDecision(
                txn_id=result.txn_id,
                account_id=result.account_id,
                allowed=False,
                score=result,
                reason="; ".join(
                    f"{m.name}: {m.evidence}" for m in result.matched
                ) or "score exceeded block threshold",
            )
            raise BlockedTransactionError(
                f"txn {result.txn_id} blocked (score {result.score:.2f})",
                decision,
            )
        return BlockDecision(
            txn_id=result.txn_id,
            account_id=result.account_id,
            allowed=True,
            score=result,
            reason=f"score {result.score:.2f} below block threshold "
                   f"{self._block_threshold:.2f}",
        )

    def review(self, txn: Mapping[str, Any]) -> ReviewRecord:
        """Route a transaction to manual review.

        Returns a ``ReviewRecord`` with ``needed=True`` (and a stable
        case id) when the score lands in the review band; ``needed=False``
        otherwise. Block-worthy txns are *not* review cases -- they are
        already decided.
        """
        result = self.score(txn)
        with self._lock:
            self._review_seq += 1
            seq = self._review_seq
        if result.action != ACTION_REVIEW:
            return ReviewRecord(
                case_id="",
                txn_id=result.txn_id,
                account_id=result.account_id,
                needed=False,
                score=result.score,
                reasons=tuple(m.name for m in result.matched),
            )
        reasons = tuple(f"{m.name}: {m.evidence}" for m in result.matched)
        return ReviewRecord(
            case_id=f"fraud-review-{result.account_id}-{seq:06d}",
            txn_id=result.txn_id,
            account_id=result.account_id,
            needed=True,
            score=result.score,
            reasons=reasons,
        )


def default_detector() -> FraudDetector:
    """Build a detector with the standard rule pack registered."""
    d = FraudDetector()
    d.add_rule("amount-outlier", "amount_outlier", 0.45)
    d.add_rule("velocity-10-per-5m", "velocity", 0.35,
               {"window_s": 300, "limit": 10})
    d.add_rule("new-device", "new_device", 0.20)
    d.add_rule("impossible-travel", "impossible_travel", 0.55)
    d.add_rule("blacklist", "blacklisted", 1.0)
    d.add_rule("odd-hour", "odd_hour", 0.10)
    d.add_rule("card-testing", "card_testing", 0.50,
               {"small_cents": 200, "window_s": 600, "limit": 5})
    d.add_rule("round-amount", "round_amount", 0.10)
    return d


def main() -> None:
    """Self-check the module shape."""
    d = default_detector()
    ok = d.block({
        "txn_id": "t1", "account_id": "a1", "amount": 5000,
        "currency": "USD", "ts": 1_700_000_000, "device_id": "dev-1",
    })
    assert ok.allowed, "benign txn must be allowed"
    d.add_to_blacklist("merchant_id", "m-evil")
    try:
        d.block({
            "txn_id": "t2", "account_id": "a1", "amount": 5000,
            "currency": "USD", "ts": 1_700_000_100, "merchant_id": "m-evil",
        })
    except BlockedTransactionError as e:
        assert e.decision.score.blacklist_hit
        assert e.decision.score.score == 1.0
    else:
        raise AssertionError("blacklisted merchant must block")
    rev = d.review({
        "txn_id": "t3", "account_id": "a2", "amount": "149.99",
        "currency": "USD", "ts": 3 * 3600 + 1800,  # 03:30 -> odd hour
        "device_id": "dev-9",  # new device: 0.20 + 0.10 = 0.30 < 0.4
    })
    assert not rev.needed, "0.30 score must not need review"
    print("fraud-detector OK: score, block, review")


if __name__ == "__main__":
    main()
