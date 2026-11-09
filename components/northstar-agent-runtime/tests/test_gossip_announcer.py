"""Tests for gossip_announcer: host-side gossip wiring for the audit head."""

import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import support  # noqa: F401
from support import RuntimeTestCase, text_turn, tool_turn

from forward_seal_ledger import ForwardSealLedger
from gossip_announcer import (
    ALERT_KINDS,
    GOSSIP_ANNOUNCER_VERSION,
    GossipAnnouncer,
    GossipAnnouncerError,
    LocalGossipTransport,
)
from gossip_protocol import Rumor
from loop import AgentRuntime, RuntimeConfig, RuntimeConfigurationError


def _ledger(n=0):
    ledger = ForwardSealLedger(os.urandom(32), os.urandom(32))
    for i in range(n):
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
    return ledger


def _line():
    """A-B-C line over one shared transport (fanout 1 everywhere)."""
    transport = LocalGossipTransport()
    a = GossipAnnouncer(node_id="a", peers=("b",), fanout=1, transport=transport)
    b = GossipAnnouncer(node_id="b", peers=("a", "c"), fanout=1, transport=transport)
    c = GossipAnnouncer(node_id="c", peers=("b",), fanout=1, transport=transport)
    return transport, a, b, c


class TestTransport(unittest.TestCase):
    def test_register_deliver_unregister(self):
        transport = LocalGossipTransport()
        seen = []
        transport.register("n1", seen.append)
        self.assertEqual(transport.members(), ("n1",))
        rumor = Rumor(rumor_id="r1", payload={"k": "v"}, origin="n1", seq=1)
        self.assertTrue(transport.deliver("n1", rumor))
        self.assertEqual(seen, [rumor])
        self.assertFalse(transport.deliver("ghost", rumor))
        self.assertTrue(transport.unregister("n1"))
        self.assertFalse(transport.unregister("n1"))
        self.assertEqual(len(transport), 0)

    def test_duplicate_registration_refused(self):
        transport = LocalGossipTransport()
        transport.register("n1", lambda r: None)
        with self.assertRaises(GossipAnnouncerError):
            transport.register("n1", lambda r: None)

    def test_bad_receiver_and_rumor_refused(self):
        transport = LocalGossipTransport()
        with self.assertRaises(GossipAnnouncerError):
            transport.register("n1", "not-callable")
        with self.assertRaises(GossipAnnouncerError):
            transport.register("", lambda r: None)
        with self.assertRaises(TypeError):
            transport.deliver("n1", {"not": "a rumor"})


class TestAnnouncerConstruction(unittest.TestCase):
    def test_defaults_off_members(self):
        transport = LocalGossipTransport()
        ann = GossipAnnouncer(node_id="solo", transport=transport)
        self.assertEqual(ann.node_id, "solo")
        self.assertEqual(ann.peers, ())
        self.assertEqual(ann.fanout, 3)
        self.assertEqual(ann.alive_members(), ("solo",))
        self.assertEqual(ann.last_head_seq, 0)

    def test_bad_node_id_peers_fanout(self):
        transport = LocalGossipTransport()
        with self.assertRaises(GossipAnnouncerError):
            GossipAnnouncer(node_id="", transport=transport)
        with self.assertRaises(GossipAnnouncerError):
            GossipAnnouncer(node_id="a", peers=("a",), transport=transport)
        with self.assertRaises(GossipAnnouncerError):
            GossipAnnouncer(node_id="a", peers=("b", "b"), transport=transport)
        with self.assertRaises(GossipAnnouncerError):
            GossipAnnouncer(node_id="a", peers=("b",), fanout=0, transport=transport)
        with self.assertRaises(GossipAnnouncerError):
            GossipAnnouncer(node_id="a", peers=("b",), transport="not-a-transport")

    def test_duplicate_node_id_on_shared_transport(self):
        transport = LocalGossipTransport()
        GossipAnnouncer(node_id="a", transport=transport)
        with self.assertRaises(GossipAnnouncerError):
            GossipAnnouncer(node_id="a", transport=transport)


class TestAnnounceHead(unittest.TestCase):
    def test_empty_ledger_announces_nothing(self):
        ann = GossipAnnouncer(node_id="solo")
        self.assertIsNone(ann.announce_head(_ledger(0)))
        self.assertEqual(ann.last_head_seq, 0)

    def test_head_rumor_pins_the_head(self):
        ledger = _ledger(2)
        ann = GossipAnnouncer(node_id="solo")
        rumor = ann.announce_head(ledger)
        self.assertIsNotNone(rumor)
        self.assertEqual(rumor.payload["kind"], "audit-head")
        self.assertEqual(rumor.payload["seq"], 2)
        self.assertEqual(rumor.payload["records_sealed"], 2)
        self.assertEqual(rumor.payload["head_hash"], ledger.record(2).record_hash)
        self.assertEqual(rumor.payload["genesis"], ledger.genesis)
        self.assertTrue(rumor.verify_digest(rumor.digest()))
        self.assertEqual(ann.last_head_seq, 2)

    def test_idempotent_until_head_moves(self):
        ledger = _ledger(1)
        ann = GossipAnnouncer(node_id="solo")
        first = ann.announce_head(ledger)
        self.assertIsNotNone(first)
        self.assertIsNone(ann.announce_head(ledger))
        _ledger_append(ledger)
        second = ann.announce_head(ledger)
        self.assertIsNotNone(second)
        self.assertNotEqual(second.rumor_id, first.rumor_id)
        self.assertEqual(second.payload["seq"], 2)

    def test_bad_ledger_refused(self):
        ann = GossipAnnouncer(node_id="solo")
        with self.assertRaises(GossipAnnouncerError):
            ann.announce_head(None)
        with self.assertRaises(GossipAnnouncerError):
            ann.announce_head(object())

    def test_digest_matches_dissemination_report(self):
        # Originate pins one digest: the report's pin equals the rumor's.
        _, a, b, _ = _line()
        ledger = _ledger(1)
        rumor = a.announce_head(ledger)
        self.assertIsNotNone(rumor)
        reports = a.reports()
        self.assertEqual(len(reports), 1)
        self.assertEqual(reports[0].digest, rumor.digest())
        self.assertEqual(reports[0].rumor_id, rumor.rumor_id)
        self.assertTrue(b.has_seen(rumor.rumor_id))


def _ledger_append(ledger):
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


class TestRelayAndTick(unittest.TestCase):
    def test_line_relay_forced_by_fanout(self):
        # A fanout 1 (only B reachable), B fanout 2 (covers B and C, self
        # filtered) -- C can only hear the rumor through B, deterministically.
        transport = LocalGossipTransport()
        a = GossipAnnouncer(node_id="a", peers=("b",), fanout=1, transport=transport)
        b = GossipAnnouncer(node_id="b", peers=("a", "c"), fanout=2, transport=transport)
        c = GossipAnnouncer(node_id="c", peers=("b",), fanout=1, transport=transport)
        rumor = a.announce_head(_ledger(1))
        self.assertIsNotNone(rumor)
        self.assertTrue(b.has_seen(rumor.rumor_id))
        self.assertTrue(c.has_seen(rumor.rumor_id))
        # The rumor object arrives unchanged: digest verifies at C.
        self.assertTrue(rumor.verify_digest(rumor.digest()))

    def test_tick_converges_over_rounds(self):
        _, a, b, c = _line()
        rumor = a.announce_head(_ledger(1))
        self.assertIsNotNone(rumor)
        for _ in range(10):
            if b.has_seen(rumor.rumor_id) and c.has_seen(rumor.rumor_id):
                break
            a.tick()
            b.tick()
            c.tick()
        self.assertTrue(b.has_seen(rumor.rumor_id))
        self.assertTrue(c.has_seen(rumor.rumor_id))

    def test_tick_only_respreads_freshest_head(self):
        _, a, b, c = _line()
        ledger = _ledger(1)
        first = a.announce_head(ledger)
        _ledger_append(ledger)
        second = a.announce_head(ledger)
        self.assertIsNotNone(first)
        self.assertIsNotNone(second)
        a.tick()
        round_ids = {
            event["rumor_id"]
            for event in a.audit_log()
            if event["detail"].get("round")
        }
        self.assertEqual(round_ids, {second.rumor_id})

    def test_duplicate_receive_dropped(self):
        _, a, b, _ = _line()
        rumor = a.announce_head(_ledger(1))
        self.assertIsNotNone(rumor)
        self.assertFalse(b.receive(rumor))
        with self.assertRaises(TypeError):
            b.receive({"not": "a rumor"})


class TestDeadMembers(unittest.TestCase):
    def test_dead_member_never_targeted(self):
        _, a, b, c = _line()
        a.mark_suspect("b")
        a.confirm_dead("b")
        self.assertEqual(a.alive_members(), ("a",))
        rumor = a.announce_head(_ledger(1))
        self.assertIsNotNone(rumor)
        self.assertFalse(b.has_seen(rumor.rumor_id))
        # The report still books the decision; it just has no live targets.
        self.assertEqual(a.reports()[-1].targets, ())

    def test_revive_brings_member_back(self):
        _, a, b, _ = _line()
        a.mark_suspect("b")
        rec = a.mark_alive("b")
        self.assertEqual(rec.incarnation, 1)
        self.assertEqual(a.alive_members(), ("a", "b"))
        rumor = a.announce_head(_ledger(1))
        self.assertTrue(b.has_seen(rumor.rumor_id))


class TestAlerts(unittest.TestCase):
    def test_alert_kinds_reach_live_peers(self):
        _, a, b, c = _line()
        for kind in ALERT_KINDS:
            rumor = a.announce_alert(kind, {"reason": "test"})
            self.assertIsNotNone(rumor)
            self.assertEqual(rumor.payload["kind"], kind)
            self.assertTrue(rumor.verify_digest(rumor.digest()))
            for _ in range(10):
                if b.has_seen(rumor.rumor_id) and c.has_seen(rumor.rumor_id):
                    break
                a.tick()
                b.tick()
                c.tick()
            self.assertTrue(b.has_seen(rumor.rumor_id))
            self.assertTrue(c.has_seen(rumor.rumor_id))

    def test_unknown_alert_kind_refused(self):
        ann = GossipAnnouncer(node_id="solo")
        with self.assertRaises(GossipAnnouncerError):
            ann.announce_alert("no-such-kind")
        with self.assertRaises(GossipAnnouncerError):
            ann.announce_alert("kill-switch", detail="not-a-mapping")


class TestLoopWiring(RuntimeTestCase):
    def _runtime_with_gossip(self, transport, **config_kwargs):
        from hooks import HookRegistry
        from loop import AgentRuntime, builtin_registry

        workspace = self.workspace({"a.txt": "hello\n"})
        config = RuntimeConfig(
            workspace=str(workspace),
            gossip_enabled=True,
            gossip_node_id="peer-a",
            gossip_peers=("peer-b",),
            **config_kwargs,
        )
        return AgentRuntime(
            provider=self.provider(
                [tool_turn("Read", {"path": "a.txt"}), text_turn("done")]
            ),
            config=config,
            hooks=HookRegistry(),
            agents=builtin_registry(),
            tracer=self.tracer,
            gossip_transport=transport,
        )

    def test_gossip_disabled_by_default(self):
        runtime = self.runtime([text_turn("done")])
        self.assertIsNone(runtime.gossip_announcer)
        self.assertIsNone(runtime.gossip_transport)
        self.assertIsNone(runtime.announce_alert("kill-switch"))

    def test_run_announces_head_to_peer(self):
        transport = LocalGossipTransport()
        peer = GossipAnnouncer(
            node_id="peer-b", peers=("peer-a",), transport=transport
        )
        runtime = self._runtime_with_gossip(transport)
        report = self.drive(runtime, "go")
        self.assertExactlyOneResult(report)
        self.assertGreater(len(runtime.sealed_ledger), 0)
        announcer = runtime.gossip_announcer
        self.assertIsNotNone(announcer)
        self.assertEqual(announcer.last_head_seq, len(runtime.sealed_ledger))
        self.assertIsNone(runtime._gossip_announce_error)
        head_ids = [
            rid for rid in announcer.seen_ids() if rid.startswith("audit-head:")
        ]
        self.assertTrue(head_ids)
        self.assertTrue(peer.has_seen(head_ids[-1]))

    def test_runtime_alert_api(self):
        transport = LocalGossipTransport()
        peer = GossipAnnouncer(
            node_id="peer-b", peers=("peer-a",), transport=transport
        )
        runtime = self._runtime_with_gossip(transport)
        rumor = runtime.announce_alert("kill-switch", {"reason": "test"})
        self.assertIsNotNone(rumor)
        self.assertEqual(rumor.payload["kind"], "kill-switch")
        self.assertTrue(peer.has_seen(rumor.rumor_id))
        with self.assertRaises(GossipAnnouncerError):
            runtime.announce_alert("no-such-kind")

    def test_announce_failure_never_fails_run(self):
        class RaisingTransport:
            def __init__(self):
                self.receivers = {}

            def register(self, node_id, receiver):
                self.receivers[node_id] = receiver

            def deliver(self, target_id, rumor):
                raise RuntimeError("transport is down")

        runtime = self._runtime_with_gossip(RaisingTransport())
        report = self.drive(runtime, "go")
        self.assertExactlyOneResult(report)
        self.assertIsNotNone(runtime._gossip_announce_error)
        self.assertIn("RuntimeError", runtime._gossip_announce_error)

    def test_bad_gossip_config_refused(self):
        with self.assertRaises(RuntimeConfigurationError):
            RuntimeConfig(gossip_enabled=True, gossip_fanout=0)
        with self.assertRaises(RuntimeConfigurationError):
            RuntimeConfig(gossip_enabled=True, gossip_peers=("a", "a"))
        workspace = self.workspace()
        with self.assertRaises(RuntimeConfigurationError):
            AgentRuntime(
                provider=self.provider([text_turn("done")]),
                config=RuntimeConfig(
                    workspace=str(workspace),
                    gossip_enabled=True,
                    gossip_node_id="peer-a",
                    gossip_peers=("peer-a",),
                ),
                gossip_transport=LocalGossipTransport(),
            )


if __name__ == "__main__":
    unittest.main()
