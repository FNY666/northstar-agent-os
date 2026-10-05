"""Twin-sync receipts: freshness-gated actuation for digital twins (ninety-sixth batch).

Absorbs the 2026 digital-twins-at-scale research thread (mechanism ideas
only, honestly scoped):

* **Synchronization drift is the critical governance issue.** GISEC 2026
  ran dedicated sessions on manipulated sensor inputs distorting the
  virtual representation of physical assets; practitioner taxonomies rank
  synchronization drift and the OT/IT bridge as CRITICAL — decisions made
  on stale twin state are the failure mode, not a degraded edge case.
  An SSRN systematic review (124 studies, peer-reviewed Nov 2025) lists
  data poisoning, model inversion, drift, and *unsafe actuation*, and
  concludes existing standards only partly address these risks.
* **Unsafe actuation** — a command that crosses twin→physical (BMW's
  Regensburg line: 400+ robots executing against the twin's plan;
  PepsiCo catching 90% of problems pre-deployment) must be gated on the
  twin state it was planned against. Planning on Tuesday's twin and
  actuating on Thursday is the twin analogue of a TOCTOU race.
* **Sensor-input poisoning** — the twin's authority comes from its
  sensors. If the sensor set behind an observation no longer matches the
  pinned manifest (a sensor swapped, spoofed, or silently dropped), the
  observation window is not authoritative — no matter how fresh it looks.

Northstar mapping:

* ``SyncReceipt`` — a hash-chained receipt binding
  ``(twin_id, state_digest, observed_at, source_sensor_set,
  staleness_budget)``. The chain (``prev_hash``) makes silent reordering
  or dropping of observations detectable, the same way ``audit_chain``
  does for audit events.
* ``check_freshness()`` — fail-closes when ``now - observed_at`` exceeds
  the staleness budget, when the receipt is from the future (clock lies),
  or when the receipt's sensor set differs from the pinned manifest
  without re-measurement (a changed sensor set means the twin was
  rebuilt from different inputs — the receipt no longer describes the
  twin it names).
* **Unsafe-actuation gate** — any command crossing twin→physical MUST
  present a Verifiable Action Card (eighty-fourth batch) whose bound
  arguments name the exact ``SyncReceipt`` authorizing it. The card binds
  ``(call_id, arguments_digest)``; the gate requires
  ``arguments["twin_receipt_id"]`` to name a fresh, sensor-clean,
  unconsumed receipt. Stale receipts deny with ``twin:stale_state``.
  Each receipt authorizes exactly one actuation: presenting the same
  receipt twice denies with ``twin:receipt_replay``.
* **Binary evidence tiers** (eighty-seventh batch semantics): a sensor
  manifest mismatch classifies the observation window
  ``NON_AUTHORITATIVE`` — permanently, with no "partially authoritative"
  rung to launder a poisoned window through. Actuation is high-stakes,
  and high-stakes decisions require AUTHORITATIVE evidence, so a
  poisoned window can never authorize actuation.

Everything here is offline and deterministic. No network; the only clock
is the ``now`` the caller injects (integer epoch seconds). All digest
comparisons use :func:`hmac.compare_digest`.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from action_card import ActionCard, verify_card_binding
from evidence_tiers import EvidenceTier

TWIN_RECEIPT_SCHEMA_VERSION = "northstar.twin-sync-receipt.v1"

#: Denial reason codes emitted by the actuation gate. All start with the
#: ``twin:`` prefix so audit consumers can filter the family.
DENY_NO_CARD = "twin:no_card"
DENY_CARD_BINDING_MISMATCH = "twin:card_binding_mismatch"
DENY_UNKNOWN_RECEIPT = "twin:unknown_receipt"
DENY_STALE_STATE = "twin:stale_state"
DENY_SENSOR_MISMATCH = "twin:sensor_mismatch"
DENY_RECEIPT_REPLAY = "twin:receipt_replay"
DENY_MALFORMED = "twin:malformed"


class TwinReceiptError(ValueError):
    """Malformed twin receipt or registry input. Fail loud, never guess."""


def _canonical(obj: Any) -> str:
    """Canonical JSON for digesting. Separators and sort_keys are pinned."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# SyncReceipt: hash-chained observation receipt
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SyncReceipt:
    """One twin observation, hash-chained to its predecessor.

    ``state_digest`` is the SHA-256 (hex) of the canonical twin state at
    ``observed_at``. ``source_sensor_set`` is the sorted tuple of sensor
    digests the observation was built from — the set the pinned manifest
    is checked against. ``staleness_budget`` is seconds: the observation
    is fresh while ``now - observed_at <= staleness_budget``.
    ``prev_hash`` chains to the previous receipt for the same twin (the
    empty string for the genesis receipt).
    """

    receipt_id: str
    twin_id: str
    state_digest: str
    observed_at: int
    source_sensor_set: tuple[str, ...]
    staleness_budget: int
    prev_hash: str = ""
    schema_version: str = TWIN_RECEIPT_SCHEMA_VERSION

    def receipt_hash(self) -> str:
        """The receipt's own hash — what the next receipt chains to."""
        payload = {
            "receipt_id": self.receipt_id,
            "twin_id": self.twin_id,
            "state_digest": self.state_digest,
            "observed_at": self.observed_at,
            "source_sensor_set": list(self.source_sensor_set),
            "staleness_budget": self.staleness_budget,
            "prev_hash": self.prev_hash,
            "schema_version": self.schema_version,
        }
        return _sha256_hex(_canonical(payload))

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": "twin-sync-receipt",
            "receipt_id": self.receipt_id,
            "twin_id": self.twin_id,
            "state_digest": self.state_digest,
            "observed_at": self.observed_at,
            "source_sensor_set": list(self.source_sensor_set),
            "staleness_budget": self.staleness_budget,
            "prev_hash": self.prev_hash,
            "receipt_hash": self.receipt_hash(),
            "schema_version": self.schema_version,
        }


def mint_receipt(
    *,
    receipt_id: str,
    twin_id: str,
    state_digest: str,
    observed_at: int,
    source_sensor_set: Sequence[str],
    staleness_budget: int,
    prev_hash: str = "",
) -> SyncReceipt:
    """Mint a receipt, validating every field. Garbage in -> loud error."""
    if not receipt_id or not isinstance(receipt_id, str):
        raise TwinReceiptError("receipt_id must be a non-empty string")
    if not twin_id or not isinstance(twin_id, str):
        raise TwinReceiptError("twin_id must be a non-empty string")
    if not isinstance(state_digest, str) or len(state_digest) != 64:
        raise TwinReceiptError("state_digest must be a 64-char hex SHA-256")
    try:
        int(state_digest, 16)
    except ValueError:
        raise TwinReceiptError("state_digest must be hex") from None
    if not isinstance(observed_at, int) or isinstance(observed_at, bool):
        raise TwinReceiptError("observed_at must be an integer epoch")
    if observed_at < 0:
        raise TwinReceiptError("observed_at must not be negative")
    sensors = tuple(sorted(str(s) for s in source_sensor_set))
    if not sensors:
        raise TwinReceiptError("source_sensor_set must be non-empty")
    if not isinstance(staleness_budget, int) or isinstance(staleness_budget, bool):
        raise TwinReceiptError("staleness_budget must be an integer number of seconds")
    if staleness_budget < 0:
        raise TwinReceiptError("staleness_budget must not be negative")
    if not isinstance(prev_hash, str):
        raise TwinReceiptError("prev_hash must be a string")
    return SyncReceipt(
        receipt_id=receipt_id,
        twin_id=twin_id,
        state_digest=state_digest,
        observed_at=observed_at,
        source_sensor_set=sensors,
        staleness_budget=staleness_budget,
        prev_hash=prev_hash,
    )


# ---------------------------------------------------------------------------
# Freshness: the staleness fail-closed rule
# ---------------------------------------------------------------------------


def check_freshness(receipt: SyncReceipt, *, now: int) -> tuple[bool, str]:
    """Freshness gate. Returns ``(True, "fresh")`` or ``(False, reason)``.

    Fail-closed on three conditions:

    1. ``now < observed_at`` — the receipt is from the future; the clock
       (or the receipt) is lying, and a lying clock invalidates every
       freshness claim.
    2. ``now - observed_at > staleness_budget`` — the observation is
       stale; decisions on it are the drift failure mode.
    3. Boundary is inclusive: exactly at ``observed_at + staleness_budget``
       is still fresh; one second past is stale. The boundary is sharp on
       purpose — "approximately fresh" is the footgun.
    """
    if not isinstance(now, int) or isinstance(now, bool):
        raise TwinReceiptError("now must be an integer epoch")
    if now < receipt.observed_at:
        return False, "receipt_from_future"
    age = now - receipt.observed_at
    if age > receipt.staleness_budget:
        return False, f"stale: age {age}s exceeds budget {receipt.staleness_budget}s"
    return True, "fresh"


# ---------------------------------------------------------------------------
# Sensor manifest: pinned inputs, poisoning -> NON_AUTHORITATIVE
# ---------------------------------------------------------------------------


class SensorManifestRegistry:
    """Pinned sensor manifests, one per twin.

    The twin's authority comes from its sensors. The registry pins the
    expected sensor set (as digests) at commissioning time; any later
    observation whose ``source_sensor_set`` differs is sensor-input
    poisoning until proven otherwise — the window classifies
    NON_AUTHORITATIVE and can never authorize actuation.
    """

    def __init__(self) -> None:
        self._manifests: dict[str, frozenset[str]] = {}

    def pin(self, twin_id: str, sensor_digests: Sequence[str]) -> None:
        """Pin (or re-pin) a twin's sensor manifest. Re-pinning is an
        audited, explicit operation — the caller records it; this registry
        only stores the current truth."""
        if not twin_id or not isinstance(twin_id, str):
            raise TwinReceiptError("twin_id must be a non-empty string")
        digests = frozenset(str(s) for s in sensor_digests)
        if not digests:
            raise TwinReceiptError("sensor manifest must be non-empty")
        self._manifests[twin_id] = digests

    def manifest_for(self, twin_id: str) -> frozenset[str] | None:
        return self._manifests.get(twin_id)

    def check_window(self, receipt: SyncReceipt) -> EvidenceTier:
        """Classify the observation window. Binary, no middle rung.

        AUTHORITATIVE requires the receipt's sensor set to exactly equal
        the pinned manifest. Any difference — added, removed, or swapped
        sensors — is sensor-input poisoning: NON_AUTHORITATIVE,
        permanently for that receipt. An unpinned twin has no trust anchor
        at all: also NON_AUTHORITATIVE (unknown is not authoritative).
        """
        manifest = self._manifests.get(receipt.twin_id)
        if manifest is None:
            return EvidenceTier.NON_AUTHORITATIVE
        if frozenset(receipt.source_sensor_set) != manifest:
            return EvidenceTier.NON_AUTHORITATIVE
        return EvidenceTier.AUTHORITATIVE


# ---------------------------------------------------------------------------
# Receipt registry: issuance, chain verification, consumption
# ---------------------------------------------------------------------------


class ReceiptRegistry:
    """Issuance + chain integrity + single-use consumption.

    A receipt authorizes exactly one actuation. After the actuation gate
    consumes it, presenting the same ``receipt_id`` again denies with
    ``twin:receipt_replay`` — a replayed receipt is the twin analogue of
    a replayed approval.
    """

    def __init__(self) -> None:
        self._receipts: dict[str, SyncReceipt] = {}
        self._consumed: set[str] = set()

    def issue(self, receipt: SyncReceipt) -> SyncReceipt:
        if receipt.receipt_id in self._receipts:
            raise TwinReceiptError(
                f"duplicate receipt_id {receipt.receipt_id!r}: receipts are unique"
            )
        self._receipts[receipt.receipt_id] = receipt
        return receipt

    def get(self, receipt_id: str) -> SyncReceipt | None:
        return self._receipts.get(receipt_id)

    def is_consumed(self, receipt_id: str) -> bool:
        return receipt_id in self._consumed

    def consume(self, receipt_id: str) -> None:
        if receipt_id not in self._receipts:
            raise TwinReceiptError(f"cannot consume unknown receipt {receipt_id!r}")
        self._consumed.add(receipt_id)

    def verify_chain(self, receipts: Sequence[SyncReceipt]) -> tuple[bool, str]:
        """Verify a hash chain: same twin, linked prev_hash, ordered time.

        A chain that reorders, drops, or splices receipts fails closed —
        silent observation loss is the drift failure mode with the audit
        trail to prove nothing happened.
        """
        ordered = list(receipts)
        if not ordered:
            return False, "empty chain"
        twin = ordered[0].twin_id
        prev_hash = ""
        prev_time = -1
        for r in ordered:
            if r.twin_id != twin:
                return False, f"chain mixes twins: {twin!r} vs {r.twin_id!r}"
            if not hmac.compare_digest(r.prev_hash, prev_hash):
                return False, f"broken link at {r.receipt_id!r}"
            if r.observed_at < prev_time:
                return False, f"time runs backwards at {r.receipt_id!r}"
            prev_hash = r.receipt_hash()
            prev_time = r.observed_at
        return True, f"chain ok: {len(ordered)} receipts"


# ---------------------------------------------------------------------------
# Unsafe-actuation gate: card + fresh receipt + clean sensors + single use
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ActuationVerdict:
    """The gate's answer. ``allowed`` is False for every failure mode."""

    allowed: bool
    reason: str
    receipt_id: str = ""
    window_tier: EvidenceTier = EvidenceTier.NON_AUTHORITATIVE


def gate_actuation(
    *,
    card: ActionCard | None,
    call_id: str,
    arguments: Mapping[str, Any],
    registry: ReceiptRegistry,
    manifests: SensorManifestRegistry,
    now: int,
) -> ActuationVerdict:
    """Decide whether a twin→physical command may execute. Fail closed.

    The checks run in order; the first failure wins and the rest are not
    consulted (no partial credit — a stale sensor-poisoned receipt with a
    valid card is still denied, just with the stale reason):

    1. A card must be present (``twin:no_card``).
    2. The card must bind this exact call (``twin:card_binding_mismatch``)
       — the eighty-fourth batch's execution-binding property.
    3. The call arguments must name a known receipt
       (``twin:unknown_receipt``).
    4. The receipt must be fresh (``twin:stale_state``).
    5. The receipt's sensor set must match the pinned manifest; a
       mismatch classifies the window NON_AUTHORITATIVE and denies
       (``twin:sensor_mismatch``) — actuation is high-stakes and
       high-stakes decisions require AUTHORITATIVE evidence.
    6. The receipt must not be consumed already
       (``twin:receipt_replay``).

    On allow, the receipt is consumed (single-use) and the verdict
    carries ``window_tier=AUTHORITATIVE``.
    """
    if not isinstance(now, int) or isinstance(now, bool):
        raise TwinReceiptError("now must be an integer epoch")

    if card is None:
        return ActuationVerdict(False, DENY_NO_CARD)

    if not verify_card_binding(card, call_id=call_id, arguments=arguments):
        return ActuationVerdict(False, DENY_CARD_BINDING_MISMATCH)

    receipt_id = arguments.get("twin_receipt_id")
    if not isinstance(receipt_id, str) or not receipt_id:
        return ActuationVerdict(False, DENY_MALFORMED)
    receipt = registry.get(receipt_id)
    if receipt is None:
        return ActuationVerdict(False, DENY_UNKNOWN_RECEIPT, receipt_id=receipt_id)

    fresh, _fresh_reason = check_freshness(receipt, now=now)
    if not fresh:
        return ActuationVerdict(False, DENY_STALE_STATE, receipt_id=receipt_id)

    tier = manifests.check_window(receipt)
    if tier is not EvidenceTier.AUTHORITATIVE:
        return ActuationVerdict(
            False, DENY_SENSOR_MISMATCH, receipt_id=receipt_id, window_tier=tier
        )

    if registry.is_consumed(receipt_id):
        return ActuationVerdict(False, DENY_RECEIPT_REPLAY, receipt_id=receipt_id)

    registry.consume(receipt_id)
    return ActuationVerdict(
        True, "allowed", receipt_id=receipt_id, window_tier=EvidenceTier.AUTHORITATIVE
    )


# ---------------------------------------------------------------------------
# Bench corpus: deterministic scenarios with closed ground truth
# ---------------------------------------------------------------------------


def _hex(seed: str) -> str:
    return _sha256_hex("twin:" + seed)


def run_twin_sync() -> dict[str, Any]:
    """Deterministic twin-sync scenarios: 12 scenarios, 3 allow / 9 deny.

    Ground truth (scenario id -> expected allow?):

    * allow_fresh_receipt_actuation — fresh receipt, clean sensors, bound
      card: the one happy path.
    * allow_boundary_fresh — age exactly == staleness_budget: still fresh.
    * allow_second_receipt_new_chain — the next chained receipt (prev_hash
      linked) authorizes its own actuation; consumption is per-receipt.
    * deny_stale_receipt — age one second past budget: ``twin:stale_state``.
    * deny_receipt_from_future — observed_at after now: clock lies, deny.
    * deny_sensor_added — observation from a sensor not in the manifest:
      ``twin:sensor_mismatch``, window NON_AUTHORITATIVE.
    * deny_sensor_removed — manifest sensor missing from the observation:
      same verdict — any difference is poisoning.
    * deny_unpinned_twin — no manifest pinned at all: unknown is not
      authoritative.
    * deny_actuation_without_card — no card: ``twin:no_card``.
    * deny_card_binding_mismatch — card bound to different arguments:
      ``twin:card_binding_mismatch``.
    * deny_receipt_replay — same receipt presented twice:
      ``twin:receipt_replay``.
    * deny_unknown_receipt — arguments name a receipt id never issued:
      ``twin:unknown_receipt``.

    No runtime, no network, no model. Deterministic: same verdicts every
    run. Times are pinned integers; ``now`` is fixed at 1_700_000_000.
    """
    from action_card import ActionCard, ActionProvenance, GateDecision

    NOW = 1_700_000_000
    TWIN = "twin/regensburg-line-7"
    SENSORS = (_hex("sensor/encoder-a"), _hex("sensor/torque-b"), _hex("sensor/lidar-c"))
    BUDGET = 300  # 5-minute staleness budget

    scenarios: list[tuple[str, bool, str]] = []

    def record(sid: str, allowed: bool, expect_allow: bool, reason: str) -> None:
        scenarios.append((sid, allowed, expect_allow, reason))

    def make_env(extra_manifests: bool = True):
        manifests = SensorManifestRegistry()
        if extra_manifests:
            manifests.pin(TWIN, SENSORS)
        registry = ReceiptRegistry()
        return manifests, registry

    def make_card(call_id: str, args: dict[str, Any]) -> ActionCard:
        from permissions import digest_arguments

        return ActionCard(
            card_id=_hex("card/" + call_id)[:32],
            tool="twin.actuate",
            call_id=call_id,
            arguments_digest=digest_arguments(args),
            risk_tier="tier3",
            provenance=ActionProvenance(
                agent="main",
                session_id="bench",
                turn_index=0,
                depth=0,
                delegation_chain=(),
            ),
            gate=GateDecision(
                would_auto_approve=False,
                auto_approved=False,
                policy_basis="bench-fixture",
                checks=(),
            ),
            created_unix=float(NOW),
        )

    def issue(
        registry: ReceiptRegistry,
        rid: str,
        observed_at: int,
        sensors: Sequence[str] = SENSORS,
        prev_hash: str = "",
    ) -> SyncReceipt:
        return registry.issue(
            mint_receipt(
                receipt_id=rid,
                twin_id=TWIN,
                state_digest=_hex("state/" + rid),
                observed_at=observed_at,
                source_sensor_set=sensors,
                staleness_budget=BUDGET,
                prev_hash=prev_hash,
            )
        )

    # -- A1. Happy path ---------------------------------------------------
    manifests, registry = make_env()
    r1 = issue(registry, "r1", NOW - 60)
    args = {"twin_receipt_id": "r1", "command": "torque.set", "value": 12.5}
    v = gate_actuation(
        card=make_card("call-1", args), call_id="call-1", arguments=args,
        registry=registry, manifests=manifests, now=NOW,
    )
    record("allow_fresh_receipt_actuation", v.allowed, True, v.reason)

    # -- A2. Boundary: age == budget is still fresh -----------------------
    manifests, registry = make_env()
    issue(registry, "r2", NOW - BUDGET)
    args = {"twin_receipt_id": "r2", "command": "torque.set", "value": 1.0}
    v = gate_actuation(
        card=make_card("call-2", args), call_id="call-2", arguments=args,
        registry=registry, manifests=manifests, now=NOW,
    )
    record("allow_boundary_fresh", v.allowed, True, v.reason)

    # -- A3. Chained next receipt authorizes its own actuation ------------
    manifests, registry = make_env()
    ra = issue(registry, "ra", NOW - 200)
    rb = issue(registry, "rb", NOW - 10, prev_hash=ra.receipt_hash())
    ok, _ = registry.verify_chain([ra, rb])
    args_a = {"twin_receipt_id": "ra", "command": "torque.set", "value": 2.0}
    va = gate_actuation(
        card=make_card("call-3a", args_a), call_id="call-3a", arguments=args_a,
        registry=registry, manifests=manifests, now=NOW,
    )
    args_b = {"twin_receipt_id": "rb", "command": "torque.set", "value": 3.0}
    vb = gate_actuation(
        card=make_card("call-3b", args_b), call_id="call-3b", arguments=args_b,
        registry=registry, manifests=manifests, now=NOW,
    )
    record(
        "allow_second_receipt_new_chain",
        ok and va.allowed and vb.allowed,
        True,
        f"chain={ok} a={va.reason} b={vb.reason}",
    )

    # -- D1. Stale: one second past the budget ----------------------------
    manifests, registry = make_env()
    issue(registry, "r3", NOW - BUDGET - 1)
    args = {"twin_receipt_id": "r3", "command": "torque.set", "value": 4.0}
    v = gate_actuation(
        card=make_card("call-4", args), call_id="call-4", arguments=args,
        registry=registry, manifests=manifests, now=NOW,
    )
    record(
        "deny_stale_receipt",
        v.allowed,
        False,
        v.reason if v.reason == DENY_STALE_STATE else f"WRONG-REASON:{v.reason}",
    )

    # -- D2. Receipt from the future --------------------------------------
    manifests, registry = make_env()
    issue(registry, "r4", NOW + 60)
    args = {"twin_receipt_id": "r4", "command": "torque.set", "value": 5.0}
    v = gate_actuation(
        card=make_card("call-5", args), call_id="call-5", arguments=args,
        registry=registry, manifests=manifests, now=NOW,
    )
    record("deny_receipt_from_future", v.allowed, False, v.reason)

    # -- D3. Sensor added (not in manifest) -------------------------------
    manifests, registry = make_env()
    poisoned = list(SENSORS) + [_hex("sensor/rogue-d")]
    issue(registry, "r5", NOW - 10, sensors=poisoned)
    args = {"twin_receipt_id": "r5", "command": "torque.set", "value": 6.0}
    v = gate_actuation(
        card=make_card("call-6", args), call_id="call-6", arguments=args,
        registry=registry, manifests=manifests, now=NOW,
    )
    record(
        "deny_sensor_added",
        v.allowed,
        False,
        v.reason if v.reason == DENY_SENSOR_MISMATCH
        and v.window_tier is EvidenceTier.NON_AUTHORITATIVE
        else f"WRONG:{v.reason}/{v.window_tier}",
    )

    # -- D4. Sensor removed (manifest sensor missing) ---------------------
    manifests, registry = make_env()
    issue(registry, "r6", NOW - 10, sensors=SENSORS[:2])
    args = {"twin_receipt_id": "r6", "command": "torque.set", "value": 7.0}
    v = gate_actuation(
        card=make_card("call-7", args), call_id="call-7", arguments=args,
        registry=registry, manifests=manifests, now=NOW,
    )
    record(
        "deny_sensor_removed",
        v.allowed,
        False,
        v.reason if v.reason == DENY_SENSOR_MISMATCH else f"WRONG-REASON:{v.reason}",
    )

    # -- D5. Unpinned twin -------------------------------------------------
    manifests, registry = make_env(extra_manifests=False)
    issue(registry, "r7", NOW - 10)
    args = {"twin_receipt_id": "r7", "command": "torque.set", "value": 8.0}
    v = gate_actuation(
        card=make_card("call-8", args), call_id="call-8", arguments=args,
        registry=registry, manifests=manifests, now=NOW,
    )
    record(
        "deny_unpinned_twin",
        v.allowed,
        False,
        v.reason if v.reason == DENY_SENSOR_MISMATCH else f"WRONG-REASON:{v.reason}",
    )

    # -- D6. No card -------------------------------------------------------
    manifests, registry = make_env()
    issue(registry, "r8", NOW - 10)
    args = {"twin_receipt_id": "r8", "command": "torque.set", "value": 9.0}
    v = gate_actuation(
        card=None, call_id="call-9", arguments=args,
        registry=registry, manifests=manifests, now=NOW,
    )
    record(
        "deny_actuation_without_card",
        v.allowed,
        False,
        v.reason if v.reason == DENY_NO_CARD else f"WRONG-REASON:{v.reason}",
    )

    # -- D7. Card bound to different arguments -----------------------------
    manifests, registry = make_env()
    issue(registry, "r9", NOW - 10)
    args = {"twin_receipt_id": "r9", "command": "torque.set", "value": 10.0}
    other_args = {"twin_receipt_id": "r9", "command": "torque.set", "value": 999.0}
    v = gate_actuation(
        card=make_card("call-10", other_args), call_id="call-10", arguments=args,
        registry=registry, manifests=manifests, now=NOW,
    )
    record(
        "deny_card_binding_mismatch",
        v.allowed,
        False,
        v.reason if v.reason == DENY_CARD_BINDING_MISMATCH else f"WRONG-REASON:{v.reason}",
    )

    # -- D8. Receipt replay ------------------------------------------------
    manifests, registry = make_env()
    issue(registry, "r10", NOW - 10)
    args1 = {"twin_receipt_id": "r10", "command": "torque.set", "value": 11.0}
    v1 = gate_actuation(
        card=make_card("call-11a", args1), call_id="call-11a", arguments=args1,
        registry=registry, manifests=manifests, now=NOW,
    )
    args2 = {"twin_receipt_id": "r10", "command": "torque.set", "value": 11.5}
    v2 = gate_actuation(
        card=make_card("call-11b", args2), call_id="call-11b", arguments=args2,
        registry=registry, manifests=manifests, now=NOW,
    )
    record(
        "deny_receipt_replay",
        v2.allowed,
        False,
        v2.reason
        if v1.allowed and v2.reason == DENY_RECEIPT_REPLAY
        else f"WRONG:first={v1.reason} second={v2.reason}",
    )

    # -- D9. Unknown receipt -----------------------------------------------
    manifests, registry = make_env()
    args = {"twin_receipt_id": "never-issued", "command": "torque.set", "value": 12.0}
    v = gate_actuation(
        card=make_card("call-12", args), call_id="call-12", arguments=args,
        registry=registry, manifests=manifests, now=NOW,
    )
    record(
        "deny_unknown_receipt",
        v.allowed,
        False,
        v.reason if v.reason == DENY_UNKNOWN_RECEIPT else f"WRONG-REASON:{v.reason}",
    )

    mismatches = [
        sid for (sid, allowed, expect_allow, _reason) in scenarios
        if allowed != expect_allow
    ]
    wrong_reasons = [
        f"{sid}:{reason}"
        for (sid, allowed, expect_allow, reason) in scenarios
        if allowed == expect_allow and reason.startswith("WRONG")
    ]
    allowed_ids = sorted(sid for (sid, allowed, _e, _r) in scenarios if allowed)
    return {
        "n_scenarios": len(scenarios),
        "n_allowed": len(allowed_ids),
        "n_denied": len(scenarios) - len(allowed_ids),
        "allowed_ids": allowed_ids,
        "mismatches": mismatches + wrong_reasons,
        "detail": {sid: reason for (sid, _a, _e, reason) in scenarios},
    }


__all__ = [
    "TWIN_RECEIPT_SCHEMA_VERSION",
    "DENY_NO_CARD",
    "DENY_CARD_BINDING_MISMATCH",
    "DENY_UNKNOWN_RECEIPT",
    "DENY_STALE_STATE",
    "DENY_SENSOR_MISMATCH",
    "DENY_RECEIPT_REPLAY",
    "DENY_MALFORMED",
    "TwinReceiptError",
    "SyncReceipt",
    "mint_receipt",
    "check_freshness",
    "SensorManifestRegistry",
    "ReceiptRegistry",
    "ActuationVerdict",
    "gate_actuation",
    "run_twin_sync",
]
