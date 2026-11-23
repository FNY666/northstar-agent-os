"""Escrow service interface: hold/release/dispute bookkeeping.

Research note: an *escrow hold* is the neutral-third-party primitive behind
marketplaces, freelancing platforms, and agent-mediated commerce: the buyer
(payer) locks funds into escrow, the seller (payee) delivers, and the funds
release only when the release condition is met — or roll to a dispute
process when the parties disagree. The load-bearing invariants are:
(1) *amounts in minor units* — integer cents only, no IEEE floats anywhere
in the money path; (2) *no double-release* — cumulative releases (full,
partial, or dispute awards) can never exceed the held amount, so one hold
can never pay out twice; (3) *dispute freezes the hold* — once a hold is
disputed, no party can release it unilaterally; only a resolution with a
terminal outcome moves the funds; (4) *idempotent holds* — a retried hold
request with the same idempotency key returns the original hold instead of
locking the payer's funds twice; (5) *audit trail* — every transition is
pinned and auditable, because escrow disputes are resolved on records.

This module implements that shape as a deterministic, single-host ledger:

* **Holds** — :meth:`EscrowService.hold` records a frozen
  :class:`EscrowHold` (``esc-<n>`` id, minor-unit amount, ISO currency code,
  payer/payee ids, free-text release condition, ``sha256:`` digest pin).
  An optional caller-supplied ``idempotency_key`` makes the call
  idempotent: a repeat call with the same key returns the original hold.
* **Releases** — :meth:`EscrowService.release` records a frozen
  :class:`ReleaseRecord` (``rl-<n>`` id); full or partial; cumulative
  releases fail closed at the held amount (``ReleaseExceedsHoldError``);
  once fully released the hold is terminal.
* **Disputes** — :meth:`EscrowService.dispute` records a frozen
  :class:`DisputeRecord` (``ed-<n>`` id) and freezes the hold: further
  releases raise :class:`HoldDisputedError`. :meth:`EscrowService.resolve_dispute`
  terminates the dispute with one outcome: ``release`` (funds to payee),
  ``refund`` (funds back to payer), or ``split`` (caller-supplied
  payee/payer amounts that must sum exactly to the held amount).

House style: frozen dataclasses, caller-supplied int seqs (strictly
increasing per service, no wall-clock, no RNG for ids — ids are
monotonic ``esc-<n>``/``rl-<n>``/``ed-<n>`` counters), RLock-guarded,
fail-closed (non-int/negative/zero amounts, empty ids, unknown holds,
release overruns, releases on disputed or terminal holds, and
non-summing splits all raise a subclass of :class:`EscrowError`),
stdlib-only, type-tagged canonical digest encoding (bool != int; amounts
are ints in minor units so the batch-5 JCS float-loss caveat never
applies — floats are refused outright), audit events shaped for
``audit.ndjson/1``, ``main()`` self-check.

Honest scope: this is a *claims ledger*, not a custodian. It cannot move
money, verify that a payer has funds, contact a bank, or prove settlement.
``hold()`` pins what the host *reported*; a host that lies gets a
consistent ledger of lies (GIGO, same boundary as every other bookkeeping
module). For real custody pair with a PCI-scoped rail or licensed escrow
agent plus ``remote_attestation`` for the host.

Version pin: escrow-service.v1
"""

from __future__ import annotations

import hashlib
import json
import threading

__all__ = [
    "ESCROW_SERVICE_VERSION",
    "SCHEMA_PIN",
    "EscrowError",
    "HoldAmountError",
    "HoldIdentityError",
    "UnknownHoldError",
    "IdempotencyMismatchError",
    "ReleaseExceedsHoldError",
    "HoldNotActiveError",
    "HoldDisputedError",
    "DisputeStateError",
    "SplitSumError",
    "EscrowHold",
    "ReleaseRecord",
    "DisputeRecord",
    "DisputeResolution",
    "EscrowService",
    "escrow_service_audit_event",
    "main",
]

ESCROW_SERVICE_VERSION = "escrow-service.v1"
SCHEMA_PIN = "northstar.escrow-service.v1"

_HOLD = "held"
_RELEASED = "released"
_DISPUTED = "disputed"
_REFUNDED = "refunded"
_SPLIT = "split"

_VALID_OUTCOMES = ("release", "refund", "split")


def _canon(value: object) -> str:
    """Type-tagged canonical encoding for digest pins."""
    if value is None:
        return "n"
    if isinstance(value, bool):
        return "b:" + ("1" if value else "0")
    if isinstance(value, int):
        return "i:" + str(value)
    if isinstance(value, float):
        raise TypeError("floats refused in canonical encoding; use minor units")
    if isinstance(value, str):
        return "s:" + str(len(value)) + ":" + value
    if isinstance(value, (list, tuple)):
        return "l:" + str(len(value)) + ":" + "".join(_canon(v) for v in value)
    if isinstance(value, dict):
        items = sorted(value.items(), key=lambda kv: kv[0])
        return (
            "d:"
            + str(len(items))
            + ":"
            + "".join(_canon(k) + _canon(v) for k, v in items)
        )
    raise TypeError("unsupported type in canonical encoding: %r" % type(value))


def _pin(*parts: object) -> str:
    return "sha256:" + hashlib.sha256(
        "|".join(_canon(p) for p in parts).encode("utf-8")
    ).hexdigest()


def _require_minor_amount(amount: int, name: str = "amount") -> None:
    if isinstance(amount, bool) or not isinstance(amount, int):
        raise HoldAmountError("%s must be an int in minor units, got %r" % (name, amount))
    if amount <= 0:
        raise HoldAmountError("%s must be positive, got %r" % (name, amount))


def _require_party_id(value: str, name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise HoldIdentityError("%s must be a non-empty str" % name)


def _require_currency(currency: str) -> None:
    if (
        not isinstance(currency, str)
        or len(currency) != 3
        or not currency.isalpha()
        or currency != currency.upper()
    ):
        raise HoldIdentityError(
            "currency must be an ISO 4217 code (3 uppercase letters), got %r" % (currency,)
        )


class EscrowError(Exception):
    """Base class for all escrow-service failures (fail-closed)."""


class HoldAmountError(EscrowError):
    """Amount invalid: not an int in minor units, or not positive."""


class HoldIdentityError(EscrowError):
    """Party id empty / not a str, or currency not ISO 4217."""


class UnknownHoldError(EscrowError):
    """Referenced hold id does not exist."""


class IdempotencyMismatchError(EscrowError):
    """Same idempotency key replayed with different hold parameters."""


class ReleaseExceedsHoldError(EscrowError):
    """Cumulative releases (incl. awards) would exceed the held amount."""


class HoldNotActiveError(EscrowError):
    """Release attempted on a non-held hold (terminal or disputed)."""


class HoldDisputedError(EscrowError):
    """Release attempted on a hold with an open dispute (frozen)."""


class DisputeStateError(EscrowError):
    """Dispute opened twice, or resolved when none open, or bad outcome."""


class SplitSumError(EscrowError):
    """Split award amounts do not sum exactly to the held amount."""


from dataclasses import dataclass


@dataclass(frozen=True)
class EscrowHold:
    """Immutable record of funds locked into escrow."""

    hold_id: str
    payer_id: str
    payee_id: str
    amount: int  # minor units
    currency: str  # ISO 4217
    release_condition: str
    seq: int
    digest: str
    status: str = _HOLD


@dataclass(frozen=True)
class ReleaseRecord:
    """Immutable record of one (possibly partial) release to the payee."""

    release_id: str
    hold_id: str
    amount: int  # minor units released to payee
    cumulative_released: int  # minor units released so far incl. this
    seq: int
    digest: str


@dataclass(frozen=True)
class DisputeRecord:
    """Immutable record of an opened escrow dispute."""

    dispute_id: str
    hold_id: str
    raised_by: str
    reason: str
    seq: int
    digest: str
    status: str = "open"


@dataclass(frozen=True)
class DisputeResolution:
    """Immutable record of a dispute's terminal outcome."""

    dispute_id: str
    hold_id: str
    outcome: str  # release | refund | split
    to_payee: int  # minor units awarded to payee
    to_payer: int  # minor units returned to payer
    seq: int
    digest: str


class EscrowService:
    """Deterministic single-host escrow ledger: hold / release / dispute."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._holds: dict[str, EscrowHold] = {}
        self._holds_by_key: dict[str, EscrowHold] = {}
        self._releases: dict[str, list[ReleaseRecord]] = {}
        self._released_total: dict[str, int] = {}
        self._disputes: dict[str, DisputeRecord] = {}
        self._resolutions: dict[str, DisputeResolution] = {}
        self._n_hold = 0
        self._n_release = 0
        self._n_dispute = 0

    # -- internals --------------------------------------------------------

    def _next_seq(self, seq: int) -> None:
        if not isinstance(seq, int) or isinstance(seq, bool):
            raise EscrowError("seq must be an int, got %r" % (seq,))
        if seq <= self._seq:
            raise EscrowError(
                "seq must be strictly increasing (last %d, got %d)" % (self._seq, seq)
            )
        self._seq = seq

    def _get_hold(self, hold_id: str) -> EscrowHold:
        hold = self._holds.get(hold_id)
        if hold is None:
            raise UnknownHoldError("unknown hold %r" % (hold_id,))
        return hold

    # -- holds ------------------------------------------------------------

    def hold(
        self,
        payer_id: str,
        payee_id: str,
        amount: int,
        currency: str,
        seq: int,
        release_condition: str = "",
        idempotency_key: str | None = None,
    ) -> EscrowHold:
        """Lock funds into escrow. Idempotent on ``idempotency_key``."""
        _require_party_id(payer_id, "payer_id")
        _require_party_id(payee_id, "payee_id")
        _require_minor_amount(amount)
        _require_currency(currency)
        if release_condition is not None and not isinstance(release_condition, str):
            raise HoldIdentityError("release_condition must be a str")
        if idempotency_key is not None and (
            not isinstance(idempotency_key, str) or not idempotency_key.strip()
        ):
            raise HoldIdentityError("idempotency_key must be a non-empty str")
        with self._lock:
            if idempotency_key is not None and idempotency_key in self._holds_by_key:
                existing = self._holds_by_key[idempotency_key]
                if (
                    existing.payer_id != payer_id
                    or existing.payee_id != payee_id
                    or existing.amount != amount
                    or existing.currency != currency
                    or existing.release_condition != (release_condition or "")
                ):
                    raise IdempotencyMismatchError(
                        "idempotency_key %r replayed with different parameters"
                        % (idempotency_key,)
                    )
                return existing
            self._next_seq(seq)
            self._n_hold += 1
            hold_id = "esc-%d" % self._n_hold
            cond = release_condition or ""
            digest = _pin(
                "hold", hold_id, payer_id, payee_id, amount, currency, cond, seq
            )
            rec = EscrowHold(
                hold_id=hold_id,
                payer_id=payer_id,
                payee_id=payee_id,
                amount=amount,
                currency=currency,
                release_condition=cond,
                seq=seq,
                digest=digest,
            )
            self._holds[hold_id] = rec
            self._releases[hold_id] = []
            self._released_total[hold_id] = 0
            if idempotency_key is not None:
                self._holds_by_key[idempotency_key] = rec
            return rec

    def hold_status(self, hold_id: str) -> str:
        """Current lifecycle status of a hold."""
        return self._get_hold(hold_id).status

    def held_amount(self, hold_id: str) -> int:
        """Minor-unit amount locked for the hold."""
        return self._get_hold(hold_id).amount

    def remaining_releasable(self, hold_id: str) -> int:
        """Minor-unit amount still releasable (0 once terminal or disputed)."""
        hold = self._get_hold(hold_id)
        if hold.status != _HOLD:
            return 0
        return hold.amount - self._released_total[hold_id]

    # -- releases ----------------------------------------------------------

    def release(
        self,
        hold_id: str,
        seq: int,
        amount: int | None = None,
    ) -> ReleaseRecord:
        """Release funds to the payee; ``amount=None`` releases the remainder."""
        hold = self._get_hold(hold_id)
        if hold.status == _DISPUTED:
            raise HoldDisputedError(
                "hold %r is under open dispute; releases are frozen" % (hold_id,)
            )
        if hold.status != _HOLD:
            raise HoldNotActiveError(
                "hold %r is %r; releases are no longer allowed" % (hold_id, hold.status)
            )
        remaining = hold.amount - self._released_total[hold_id]
        if amount is None:
            amount = remaining
        _require_minor_amount(amount, "release amount")
        if amount > remaining:
            raise ReleaseExceedsHoldError(
                "release %d exceeds remaining %d on hold %r" % (amount, remaining, hold_id)
            )
        with self._lock:
            self._next_seq(seq)
            self._n_release += 1
            release_id = "rl-%d" % self._n_release
            cumulative = self._released_total[hold_id] + amount
            digest = _pin("release", release_id, hold_id, amount, cumulative, seq)
            rec = ReleaseRecord(
                release_id=release_id,
                hold_id=hold_id,
                amount=amount,
                cumulative_released=cumulative,
                seq=seq,
                digest=digest,
            )
            self._releases[hold_id].append(rec)
            self._released_total[hold_id] = cumulative
            if cumulative == hold.amount:
                self._holds[hold_id] = EscrowHold(
                    hold_id=hold.hold_id,
                    payer_id=hold.payer_id,
                    payee_id=hold.payee_id,
                    amount=hold.amount,
                    currency=hold.currency,
                    release_condition=hold.release_condition,
                    seq=hold.seq,
                    digest=hold.digest,
                    status=_RELEASED,
                )
            return rec

    def releases_for(self, hold_id: str) -> tuple[ReleaseRecord, ...]:
        """All release records against a hold, in order."""
        self._get_hold(hold_id)
        return tuple(self._releases[hold_id])

    # -- disputes ----------------------------------------------------------

    def dispute(
        self,
        hold_id: str,
        raised_by: str,
        reason: str,
        seq: int,
    ) -> DisputeRecord:
        """Open a dispute on an active hold; freezes further releases."""
        _require_party_id(raised_by, "raised_by")
        _require_party_id(reason, "reason")
        hold = self._get_hold(hold_id)
        if hold.status == _DISPUTED:
            raise DisputeStateError("hold %r already has an open dispute" % (hold_id,))
        if hold.status != _HOLD:
            raise DisputeStateError(
                "cannot dispute hold %r in status %r" % (hold_id, hold.status)
            )
        with self._lock:
            self._next_seq(seq)
            self._n_dispute += 1
            dispute_id = "ed-%d" % self._n_dispute
            digest = _pin("dispute", dispute_id, hold_id, raised_by, reason, seq)
            rec = DisputeRecord(
                dispute_id=dispute_id,
                hold_id=hold_id,
                raised_by=raised_by,
                reason=reason,
                seq=seq,
                digest=digest,
            )
            self._disputes[hold_id] = rec
            self._holds[hold_id] = EscrowHold(
                hold_id=hold.hold_id,
                payer_id=hold.payer_id,
                payee_id=hold.payee_id,
                amount=hold.amount,
                currency=hold.currency,
                release_condition=hold.release_condition,
                seq=hold.seq,
                digest=hold.digest,
                status=_DISPUTED,
            )
            return rec

    def resolve_dispute(
        self,
        hold_id: str,
        outcome: str,
        seq: int,
        split_payee: int = 0,
        split_payer: int = 0,
    ) -> DisputeResolution:
        """Terminate an open dispute.

        ``outcome`` is ``release`` (all funds to payee), ``refund`` (all
        funds back to payer), or ``split`` (``split_payee`` + ``split_payer``
        must sum exactly to the held amount, both positive ints in minor
        units).
        """
        if outcome not in _VALID_OUTCOMES:
            raise DisputeStateError(
                "outcome must be one of %r, got %r" % (_VALID_OUTCOMES, outcome)
            )
        hold = self._get_hold(hold_id)
        disp = self._disputes.get(hold_id)
        if disp is None or disp.status != "open" or hold.status != _DISPUTED:
            raise DisputeStateError("no open dispute on hold %r" % (hold_id,))
        if outcome == "release":
            to_payee, to_payer = hold.amount, 0
        elif outcome == "refund":
            to_payee, to_payer = 0, hold.amount
        else:
            _require_minor_amount(split_payee, "split_payee")
            _require_minor_amount(split_payer, "split_payer")
            if split_payee + split_payer != hold.amount:
                raise SplitSumError(
                    "split amounts %d + %d != held %d"
                    % (split_payee, split_payer, hold.amount)
                )
            to_payee, to_payer = split_payee, split_payer
        with self._lock:
            self._next_seq(seq)
            digest = _pin(
                "resolve", disp.dispute_id, hold_id, outcome, to_payee, to_payer, seq
            )
            res = DisputeResolution(
                dispute_id=disp.dispute_id,
                hold_id=hold_id,
                outcome=outcome,
                to_payee=to_payee,
                to_payer=to_payer,
                seq=seq,
                digest=digest,
            )
            terminal = (
                _RELEASED
                if outcome == "release"
                else _REFUNDED
                if outcome == "refund"
                else _SPLIT
            )
            self._resolutions[hold_id] = res
            self._disputes[hold_id] = DisputeRecord(
                dispute_id=disp.dispute_id,
                hold_id=disp.hold_id,
                raised_by=disp.raised_by,
                reason=disp.reason,
                seq=disp.seq,
                digest=disp.digest,
                status=outcome,
            )
            self._holds[hold_id] = EscrowHold(
                hold_id=hold.hold_id,
                payer_id=hold.payer_id,
                payee_id=hold.payee_id,
                amount=hold.amount,
                currency=hold.currency,
                release_condition=hold.release_condition,
                seq=hold.seq,
                digest=hold.digest,
                status=terminal,
            )
            return res

    def resolution_for(self, hold_id: str) -> DisputeResolution | None:
        """The resolution record for a hold, or None if none."""
        self._get_hold(hold_id)
        return self._resolutions.get(hold_id)


def escrow_service_audit_event(
    action: str, seq: int, record_id: str, amount: int | None = None
) -> dict:
    """Audit event shaped for ``audit.ndjson/1`` (no amount by default)."""
    event = {
        "schema": SCHEMA_PIN,
        "action": action,
        "record_id": record_id,
        "seq": seq,
        "module": ESCROW_SERVICE_VERSION,
    }
    if amount is not None:
        if isinstance(amount, bool) or not isinstance(amount, int) or amount < 0:
            raise HoldAmountError("audit amount must be a non-negative int")
        event["amount"] = amount
    return event


def main() -> None:
    svc = EscrowService()
    h = svc.hold("payer-1", "payee-1", 5000, "USD", 1, "delivery confirmed")
    assert h.hold_id == "esc-1" and h.status == "held"
    assert h.digest.startswith("sha256:")
    try:
        svc.hold("payer-1", "payee-1", 0, "USD", 2)
        raise AssertionError("zero amount hold must fail")
    except HoldAmountError:
        pass
    same = svc.hold("payer-1", "payee-1", 5000, "USD", 2, "delivery confirmed",
                    idempotency_key="key-1")
    assert same.hold_id == "esc-2", "idempotent key creates one hold"
    replay = svc.hold("payer-1", "payee-1", 5000, "USD", 3, "delivery confirmed",
                      idempotency_key="key-1")
    assert replay.hold_id == "esc-2", "idempotent replay must return original"
    try:
        svc.hold("payer-1", "payee-1", 6000, "USD", 4, idempotency_key="key-1")
        raise AssertionError("idempotency mismatch must fail")
    except IdempotencyMismatchError:
        pass
    r1 = svc.release("esc-1", 5, amount=2000)
    assert r1.cumulative_released == 2000 and svc.remaining_releasable("esc-1") == 3000
    try:
        svc.release("esc-1", 6, amount=4000)
        raise AssertionError("release overrun must fail")
    except ReleaseExceedsHoldError:
        pass
    d = svc.dispute("esc-1", "payer-1", "goods not delivered", 7)
    assert d.status == "open"
    try:
        svc.release("esc-1", 8)
        raise AssertionError("release during open dispute must fail")
    except HoldDisputedError:
        pass
    res = svc.resolve_dispute("esc-1", "split", 9, split_payee=2000, split_payer=3000)
    assert res.outcome == "split" and res.to_payee + res.to_payer == 5000
    assert svc.hold_status("esc-1") == "split"
    ev = escrow_service_audit_event("held", 10, record_id="esc-1")
    assert ev["schema"] == SCHEMA_PIN and "amount" not in ev
    print("escrow-service OK: hold, idempotency, partial release, dispute, split resolve")


if __name__ == "__main__":
    main()
