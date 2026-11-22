"""Gossip announcer: host-side wiring for the gossip dissemination plane.

This is the piece the gossip state machine was missing: a host-owned
announcer that turns local governance facts into rumors and puts them on
the wire. It owns three things from :mod:`gossip_protocol`:

* a ``GossipNode`` -- the seen-set (first-sight dedup) for rumors this
  host originates or receives;
* a ``GossipProtocol`` -- the SWIM membership ledger plus
  ``disseminate()`` target selection (dead members are never targeted);
* the loopback transport -- ``LocalGossipTransport``, an in-process
  registry of node id -> receiver. Delivery is synchronous and
  in-process: no sockets, no network, no public board.

What the announcer does:

* ``announce_head(ledger)`` -- when the sealed ledger's head has advanced
  since the last announcement, build an ``audit-head`` rumor carrying the
  head pin (``head_hash``, ``seq``, ``records_sealed``, ``genesis``) and
  disseminate it. Idempotent: a second call with the same head is a no-op.
  Cadence is the host's choice -- the loop announces at most once per turn
  boundary plus once at run close, so a run of many seals produces a
  handful of head rumors, not one per seal.
* ``tick()`` -- one anti-entropy round: re-disseminate the freshest head
  rumor known plus every alert rumor seen. A single spread can waste its
  fanout on nodes that already have the rumor (gossip draws are
  probabilistic), so convergence needs rounds, not one pass -- exactly
  like ``GossipNetwork.step``. Traffic is bounded: one head rumor (older
  heads are superseded) plus alerts, which are rare.
* ``announce_alert(kind, detail)`` -- immediate rumors for
  ``kill-switch`` and ``config-drift`` events. The loop has no trigger
  site for either yet, so this is the API a future trigger calls; it is
  tested, not wired to anything that fires today.
* ``receive(rumor)`` -- first-sight rumors are recorded and relayed
  (multi-hop: a rumor keeps spreading until every reachable peer has
  seen it); duplicates are dropped silently.

Seq discipline (one counter, no wall-clock): the announcer owns a
strictly increasing int counter. Joins consume seqs; every rumor is
built with a freshly allocated seq and ``disseminate()`` consumes that
same seq, so a dissemination report's digest pin equals the rumor's own
digest pin (asserted on originate). Relays allocate a fresh seq, so a
relay report pins the relay decision, not the original rumor.

Honest scope:

* This is dissemination, not delivery proof. Gossip is best-effort: a
  rumor may never reach a partitioned or dead peer, and ``converged()``
  is only meaningful relative to the configured member set. The sealed
  ledger stays the authority; a rumor is an announcement, not evidence.
* Received rumors are *untrusted content*: the loopback transport hands
  over the ``Rumor`` object itself, so a digest check here would be
  circular (the sender could recompute it). A network transport must
  add signed rumor payloads before trusting what arrives -- filtering
  Byzantine peers is the application layer's job, as
  :mod:`gossip_protocol` already states.
* Announcement is best-effort and never fails a run: the loop catches
  announcer errors at the hook and records them. A failed announcement
  loses a rumor, never a sealed record.
* The transport registry holds strong references to receivers. A host
  that creates many short-lived runtimes on one shared transport should
  call ``transport.unregister(node_id)`` when a runtime is retired.

House style: stdlib-only apart from the sibling :mod:`gossip_protocol`,
fail-closed (bad ids, duplicate peers, unknown alert kinds raise),
version/schema pins, ``main()`` self-check.
"""

from __future__ import annotations

import threading
from typing import Any, Callable, Mapping, Optional, Sequence

from gossip_protocol import (
    DEFAULT_FANOUT,
    DEFAULT_PROBABILITY,
    EVENT_RECEIVED,
    EVENT_SPREAD,
    GOSSIP_PROTOCOL_VERSION,
    GossipNode,
    GossipProtocol,
    Rumor,
    gossip_audit_event,
)

#: Module version pin.
GOSSIP_ANNOUNCER_VERSION = "gossip-announcer.v1"

#: Schema pin carried by audit events and state snapshots.
GOSSIP_ANNOUNCER_SCHEMA = "northstar.gossip-announcer.v1"

#: Alert kinds the announcer can originate. Anything else is refused.
ALERT_KINDS = ("kill-switch", "config-drift")

#: Rumor payload kind for audit-head announcements.
KIND_AUDIT_HEAD = "audit-head"


class GossipAnnouncerError(ValueError):
    """Configuration or usage error (fail-closed)."""


def _check_node_id(value: object, name: str) -> str:
    if not isinstance(value, str) or isinstance(value, bool):
        raise GossipAnnouncerError(f"{name} must be a str, got {type(value).__name__}")
    if not value:
        raise GossipAnnouncerError(f"{name} must be non-empty")
    return value


def _check_peers(value: object, node_id: str) -> tuple[str, ...]:
    if isinstance(value, str) or not isinstance(value, Sequence):
        raise GossipAnnouncerError("peers must be a sequence of str")
    peers = list(value)
    if not all(isinstance(p, str) and p for p in peers):
        raise GossipAnnouncerError("peers must be non-empty str")
    if len(set(peers)) != len(peers):
        raise GossipAnnouncerError("peers must not contain duplicates")
    if node_id in peers:
        raise GossipAnnouncerError("peers must not contain the node's own id")
    return tuple(peers)


class LocalGossipTransport:
    """In-process loopback transport: node id -> receiver registry.

    A receiver is any callable taking one :class:`Rumor`. Delivery is
    synchronous: ``deliver`` calls the receiver in the caller's thread,
    so a rumor relays multi-hop inside a single ``announce`` call. Each
    node relays a given rumor at most once (first-sight dedup), so
    recursion terminates; depth is bounded by the number of nodes.
    Unknown targets are data, not an error (``deliver`` returns False);
    a bad rumor type raises (fail-closed).
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._receivers: dict[str, Callable[[Rumor], Any]] = {}

    def register(self, node_id: str, receiver: Callable[[Rumor], Any]) -> None:
        """Register a receiver for ``node_id``. Duplicates are refused."""
        _check_node_id(node_id, "node_id")
        if not callable(receiver):
            raise GossipAnnouncerError("receiver must be callable")
        with self._lock:
            if node_id in self._receivers:
                raise GossipAnnouncerError(
                    f"transport already has a receiver for {node_id}"
                )
            self._receivers[node_id] = receiver

    def unregister(self, node_id: str) -> bool:
        """Drop a receiver. Returns True if one was registered."""
        _check_node_id(node_id, "node_id")
        with self._lock:
            return self._receivers.pop(node_id, None) is not None

    def deliver(self, target_id: str, rumor: Rumor) -> bool:
        """Deliver ``rumor`` to ``target_id``. False when unknown."""
        _check_node_id(target_id, "target_id")
        if not isinstance(rumor, Rumor):
            raise TypeError(
                f"rumor must be a Rumor, got {type(rumor).__name__}"
            )
        with self._lock:
            receiver = self._receivers.get(target_id)
        if receiver is None:
            return False
        receiver(rumor)
        return True

    def members(self) -> tuple[str, ...]:
        """Registered node ids, sorted."""
        with self._lock:
            return tuple(sorted(self._receivers))

    def __len__(self) -> int:
        with self._lock:
            return len(self._receivers)


class GossipAnnouncer:
    """Host-side gossip announcer: ledger head -> rumors -> peers.

    Owns a ``GossipNode`` (seen-set), a ``GossipProtocol`` (membership +
    target selection) and a transport. Constructing an announcer joins
    itself and its peers into the membership ledger and registers its
    ``receive`` with the transport, so it can both originate and relay.
    """

    def __init__(
        self,
        *,
        node_id: str,
        peers: Sequence[str] = (),
        fanout: int = DEFAULT_FANOUT,
        probability: float = DEFAULT_PROBABILITY,
        transport: Optional[LocalGossipTransport] = None,
    ) -> None:
        self.node_id = _check_node_id(node_id, "node_id")
        self._peers = _check_peers(peers, self.node_id)
        if isinstance(fanout, bool) or not isinstance(fanout, int):
            raise GossipAnnouncerError(
                f"fanout must be an int, got {type(fanout).__name__}"
            )
        if fanout < 1:
            raise GossipAnnouncerError("fanout must be >= 1")
        if isinstance(probability, bool) or not isinstance(probability, (int, float)):
            raise GossipAnnouncerError("probability must be a number")
        if not 0.0 <= float(probability) <= 1.0:
            raise GossipAnnouncerError("probability must be in [0, 1]")
        self.fanout = fanout
        self.probability = float(probability)
        if transport is None:
            transport = LocalGossipTransport()
        elif not callable(getattr(transport, "register", None)) or not callable(
            getattr(transport, "deliver", None)
        ):
            raise GossipAnnouncerError(
                "transport must provide register() and deliver()"
            )
        self.transport = transport
        self._lock = threading.RLock()
        self._node = GossipNode(
            self.node_id, self._peers, fanout=fanout, probability=self.probability
        )
        self._protocol = GossipProtocol()
        # One strictly increasing seq counter shared by joins and
        # disseminations; the protocol consumes exactly the seqs this
        # counter allocates, in order, so the two stay in sync.
        self._seq = 0
        self._last_head_seq = 0
        self._originated = 0
        self._received = 0
        self._relayed = 0
        self._audit: list[dict] = []
        #: Every rumor this host has seen (originated or received), by id.
        #: ``tick()`` re-spreads from this set, bounded to the freshest
        #: head rumor plus alerts.
        self._seen_rumors: dict[str, Rumor] = {}
        # Join self, then every peer, before registering to receive: a
        # rumor must never arrive before its originator is a member.
        self._protocol.join(self.node_id, self._next_seq())
        for peer in self._peers:
            self._protocol.join(peer, self._next_seq())
        self.transport.register(self.node_id, self.receive)

    # -- internals -----------------------------------------------------

    def _next_seq(self) -> int:
        """Allocate the next strictly increasing seq."""
        self._seq += 1
        return self._seq

    def _deliver(self, report_targets: Sequence[str], rumor: Rumor) -> tuple[str, ...]:
        """Deliver ``rumor`` to selected targets (never to self).

        Returns the targets actually attempted. Unknown targets are
        skipped (a peer may not be in-process); delivery failures
        propagate -- the caller decides whether announcement is
        best-effort.
        """
        targets = tuple(t for t in report_targets if t != self.node_id)
        for target in targets:
            self.transport.deliver(target, rumor)
        return targets

    def _originate(self, rumor: Rumor) -> Optional[Rumor]:
        """Disseminate a locally built rumor. None when already seen.

        The dissemination decision is booked first (so a later retry
        cannot double-book), then the rumor is marked seen, then
        delivered. A booked-but-undelivered report is harmless: the
        report is the decision record, delivery is separate.
        """
        with self._lock:
            report = self._protocol.disseminate(
                rumor.rumor_id,
                rumor.payload,
                rumor.seq,
                fanout=self.fanout,
                origin=rumor.origin,
            )
            # Originate pins one digest: the report's pin must equal the
            # rumor's own pin (same id, payload, origin, seq). A mismatch
            # means the module's assumptions broke -- fail, don't ship.
            if report.digest != rumor.digest():
                raise GossipAnnouncerError(
                    "dissemination digest does not match rumor digest"
                )
            if not self._node.receive(rumor):
                return None
            self._seen_rumors[rumor.rumor_id] = rumor
            targets = self._deliver(report.targets, rumor)
            self._audit.append(
                gossip_audit_event(
                    EVENT_SPREAD,
                    node_id=self.node_id,
                    rumor_id=rumor.rumor_id,
                    seq=rumor.seq,
                    detail={
                        "digest": rumor.digest(),
                        "targets": list(targets),
                    },
                )
            )
            self._originated += 1
            return rumor

    # -- originating -----------------------------------------------------

    def announce_head(self, ledger: Any) -> Optional[Rumor]:
        """Announce the sealed ledger's head if it advanced.

        Returns the originated rumor, or None when the head has not
        moved (empty ledger, or already announced). The rumor payload
        carries only pins (``head_hash``, ``seq``, ``records_sealed``,
        ``genesis``) -- never record contents.
        """
        if ledger is None or not callable(getattr(ledger, "record", None)):
            raise GossipAnnouncerError("ledger must provide record()")
        if not hasattr(ledger, "genesis"):
            raise GossipAnnouncerError("ledger must provide genesis")
        with self._lock:
            head_seq = len(ledger)
            if head_seq <= 0 or head_seq <= self._last_head_seq:
                return None
            head = ledger.record(head_seq)
            seq = self._next_seq()
            rumor = Rumor(
                rumor_id=f"{KIND_AUDIT_HEAD}:{head_seq}",
                payload={
                    "kind": KIND_AUDIT_HEAD,
                    "head_hash": head.record_hash,
                    "seq": head_seq,
                    "records_sealed": head_seq,
                    "genesis": ledger.genesis,
                },
                origin=self.node_id,
                seq=seq,
            )
            originated = self._originate(rumor)
            if originated is None:
                return None
            self._last_head_seq = head_seq
            return originated

    def announce_alert(
        self, kind: str, detail: Optional[Mapping] = None
    ) -> Optional[Rumor]:
        """Originate an immediate alert rumor (kill-switch / config-drift).

        Returns the rumor, or None when it was already seen (only
        possible if the seq counter was rewound, which it never is).
        Unknown kinds raise -- the caller must name a real event.
        """
        if kind not in ALERT_KINDS:
            raise GossipAnnouncerError(
                f"unknown alert kind: {kind!r} (expected one of {ALERT_KINDS})"
            )
        if detail is None:
            detail = {}
        if not isinstance(detail, Mapping):
            raise GossipAnnouncerError(
                f"detail must be a mapping, got {type(detail).__name__}"
            )
        with self._lock:
            seq = self._next_seq()
            rumor = Rumor(
                rumor_id=f"{kind}:{seq}",
                payload={"kind": kind, "detail": dict(detail)},
                origin=self.node_id,
                seq=seq,
            )
            return self._originate(rumor)

    # -- anti-entropy ------------------------------------------------------

    def tick(self) -> tuple[str, ...]:
        """One anti-entropy round: re-disseminate live rumors.

        Re-spreads the freshest head rumor known (older heads are
        superseded by it) plus every alert rumor seen. Each re-spread
        books a fresh seq, so the draw -- and therefore the target set --
        differs from the previous round; that is what makes convergence
        over rounds possible when a single spread wastes its fanout.
        Returns the targets attempted, in order. No-op when nothing live
        has been seen yet.
        """
        with self._lock:
            heads = [
                r
                for r in self._seen_rumors.values()
                if r.payload.get("kind") == KIND_AUDIT_HEAD
            ]
            alerts = [
                r
                for r in self._seen_rumors.values()
                if r.payload.get("kind") in ALERT_KINDS
            ]
            live: list[Rumor] = []
            if heads:
                live.append(max(heads, key=lambda r: r.payload["seq"]))
            live.extend(alerts)
            attempted: list[str] = []
            for rumor in live:
                report = self._protocol.disseminate(
                    rumor.rumor_id,
                    rumor.payload,
                    self._next_seq(),
                    fanout=self.fanout,
                    origin=rumor.origin,
                )
                targets = self._deliver(report.targets, rumor)
                self._audit.append(
                    gossip_audit_event(
                        EVENT_SPREAD,
                        node_id=self.node_id,
                        rumor_id=rumor.rumor_id,
                        seq=rumor.seq,
                        detail={
                            "digest": rumor.digest(),
                            "targets": list(targets),
                            "relayed": True,
                            "round": True,
                        },
                    )
                )
                attempted.extend(targets)
            return tuple(attempted)

    # -- receiving (relay) -------------------------------------------------

    def receive(self, rumor: Rumor) -> bool:
        """Accept a rumor from the transport; True on first sight.

        First-sight rumors are recorded and relayed to a deterministic
        subset of alive members (origin excluded, self excluded). The
        relay books a fresh seq, so its report pins the relay decision,
        not the original rumor. Duplicates return False, silently.
        """
        if not isinstance(rumor, Rumor):
            raise TypeError(
                f"rumor must be a Rumor, got {type(rumor).__name__}"
            )
        with self._lock:
            if not self._node.receive(rumor):
                return False
            self._received += 1
            self._seen_rumors[rumor.rumor_id] = rumor
            self._audit.append(
                gossip_audit_event(
                    EVENT_RECEIVED,
                    node_id=self.node_id,
                    rumor_id=rumor.rumor_id,
                    seq=rumor.seq,
                    detail={"digest": rumor.digest(), "origin": rumor.origin},
                )
            )
            report = self._protocol.disseminate(
                rumor.rumor_id,
                rumor.payload,
                self._next_seq(),
                fanout=self.fanout,
                origin=rumor.origin,
            )
            targets = self._deliver(report.targets, rumor)
            self._audit.append(
                gossip_audit_event(
                    EVENT_SPREAD,
                    node_id=self.node_id,
                    rumor_id=rumor.rumor_id,
                    seq=rumor.seq,
                    detail={
                        "digest": rumor.digest(),
                        "targets": list(targets),
                        "relayed": True,
                    },
                )
            )
            self._relayed += 1
            return True

    # -- membership (host-driven SWIM plane) -------------------------------

    def join_peer(self, peer_id: str) -> Any:
        """Admit a peer into the membership ledger (host-called)."""
        with self._lock:
            _check_node_id(peer_id, "peer_id")
            return self._protocol.join(peer_id, self._next_seq())

    def mark_suspect(self, peer_id: str) -> Any:
        """Mark a live peer suspect (missed probes; host-called)."""
        with self._lock:
            return self._protocol.suspect(peer_id, self._next_seq())

    def confirm_dead(self, peer_id: str) -> Any:
        """Confirm a suspect peer dead (terminal; host-called)."""
        with self._lock:
            return self._protocol.confirm(peer_id, self._next_seq())

    def mark_alive(self, peer_id: str) -> Any:
        """Refute a suspicion: suspect -> alive, incarnation bumps."""
        with self._lock:
            return self._protocol.alive(peer_id, self._next_seq())

    # -- views -----------------------------------------------------------

    @property
    def peers(self) -> tuple[str, ...]:
        """Peer node ids named at construction."""
        return self._peers

    @property
    def last_head_seq(self) -> int:
        """Ledger seq of the last announced head (0 = none yet)."""
        return self._last_head_seq

    def has_seen(self, rumor_id: str) -> bool:
        """True when this host has seen ``rumor_id`` (origin or relay)."""
        _check_node_id(rumor_id, "rumor_id")
        return self._node.has_seen(rumor_id)

    def seen_ids(self) -> tuple[str, ...]:
        """Rumor ids seen, in first-sight order."""
        return self._node.seen_ids()

    def reports(self) -> tuple[Any, ...]:
        """Dissemination decisions booked by the membership ledger."""
        return self._protocol.reports()

    def audit_log(self) -> tuple[dict, ...]:
        """Announcer audit events (received / spread), in order."""
        with self._lock:
            return tuple(self._audit)

    def membership_audit_log(self) -> tuple[dict, ...]:
        """Membership-plane audit events (join / suspect / confirm / ...)."""
        return self._protocol.audit_log()

    def alive_members(self) -> tuple[str, ...]:
        """Members currently alive, sorted."""
        return self._protocol.alive_members()

    def stats(self) -> dict:
        """Counters and current head position (pure view)."""
        with self._lock:
            return {
                "schema": GOSSIP_ANNOUNCER_SCHEMA,
                "version": GOSSIP_ANNOUNCER_VERSION,
                "node_id": self.node_id,
                "peers": list(self._peers),
                "fanout": self.fanout,
                "seen_rumors": len(self._node.seen_ids()),
                "originated": self._originated,
                "received": self._received,
                "relayed": self._relayed,
                "last_head_seq": self._last_head_seq,
                "alive_members": list(self._protocol.alive_members()),
                "disseminations": len(self._protocol.reports()),
            }

    def as_dict(self) -> dict:
        """State snapshot (pure view)."""
        with self._lock:
            return {
                "schema": GOSSIP_ANNOUNCER_SCHEMA,
                "version": GOSSIP_ANNOUNCER_VERSION,
                "node_id": self.node_id,
                "stats": self.stats(),
                "membership": self._protocol.as_dict(),
            }


def main() -> None:
    """Self-check: line topology proves multi-hop relay over loopback."""
    import os

    from forward_seal_ledger import ForwardSealLedger

    transport = LocalGossipTransport()
    # Line: A only knows B, B knows A and C, C only knows B. A fanout of 1
    # forces the rumor through B -- C cannot hear it from A directly.
    a = GossipAnnouncer(node_id="a", peers=("b",), fanout=1, transport=transport)
    b = GossipAnnouncer(node_id="b", peers=("a", "c"), fanout=1, transport=transport)
    c = GossipAnnouncer(node_id="c", peers=("b",), fanout=1, transport=transport)
    ledger = ForwardSealLedger(os.urandom(32), os.urandom(32))
    assert a.announce_head(ledger) is None  # empty ledger: nothing to say
    ledger.append(
        intent="permission-permission.allow",
        action="gate-decision",
        subject="agent-1",
        authorization="rule:mode:default",
        inputs_digest="sha256:" + "11" * 32,
        logic_digest="sha256:" + "22" * 32,
        execution_digest="sha256:" + "33" * 32,
        outcome="permission.allow",
    )
    rumor = a.announce_head(ledger)
    assert rumor is not None
    assert rumor.payload["kind"] == KIND_AUDIT_HEAD
    assert rumor.payload["head_hash"] == ledger.record(1).record_hash
    assert rumor.verify_digest(rumor.digest())
    assert a.announce_head(ledger) is None  # idempotent: head did not move
    # Convergence takes rounds, not one pass (fanout 1 can waste its slot
    # on a node that already has the rumor): tick every node until all
    # three have seen it, bounded like GossipNetwork's own demo.
    for _ in range(10):
        if b.has_seen(rumor.rumor_id) and c.has_seen(rumor.rumor_id):
            break
        a.tick()
        b.tick()
        c.tick()
    assert b.has_seen(rumor.rumor_id)
    assert c.has_seen(rumor.rumor_id)  # relayed through B, not from A
    assert a.last_head_seq == 1
    # Alerts: immediate, digest-pinned; they also converge over rounds.
    alert = a.announce_alert("kill-switch", {"reason": "operator-stop"})
    assert alert is not None and alert.payload["kind"] == "kill-switch"
    for _ in range(10):
        if b.has_seen(alert.rumor_id) and c.has_seen(alert.rumor_id):
            break
        a.tick()
        b.tick()
        c.tick()
    assert b.has_seen(alert.rumor_id)
    assert c.has_seen(alert.rumor_id)
    try:
        a.announce_alert("no-such-kind")
        raise AssertionError("unknown alert kind should raise")
    except GossipAnnouncerError:
        pass
    # Dead members are never targeted.
    a.mark_suspect("b")
    a.confirm_dead("b")
    ledger.append(
        intent="permission-permission.deny",
        action="gate-decision",
        subject="agent-1",
        authorization="rule:mode:default",
        inputs_digest="sha256:" + "44" * 32,
        logic_digest="sha256:" + "55" * 32,
        execution_digest="sha256:" + "66" * 32,
        outcome="permission.deny",
    )
    rumor2 = a.announce_head(ledger)
    assert rumor2 is not None
    assert a.last_head_seq == 2
    assert not b.has_seen(rumor2.rumor_id)
    print("gossip-announcer OK: line relay, head pins, dead exclusion, alerts")


if __name__ == "__main__":
    main()
