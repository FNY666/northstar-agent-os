"""Tests for the SWIM-style membership plane of gossip_protocol.

The rumor layer (GossipNode/GossipNetwork) is covered by
test_gossip_protocol.py; this file covers the additive SWIM extension:
GossipProtocol.join/suspect/confirm/alive/disseminate, the piggyback
update buffer, and the membership audit events.
"""

import ast
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from gossip_protocol import (
    DEFAULT_FANOUT,
    EVENT_ALIVE,
    EVENT_CONFIRMED,
    EVENT_DISSEMINATED,
    EVENT_JOINED,
    EVENT_MEMBERSHIP_REJECTED,
    EVENT_SUSPECTED,
    GOSSIP_PROTOCOL_SCHEMA,
    GOSSIP_PROTOCOL_VERSION,
    MEMBER_ALIVE,
    MEMBER_DEAD,
    MEMBER_SUSPECT,
    BadMemberStateError,
    DisseminationReport,
    DuplicateMemberError,
    GossipMembershipError,
    GossipProtocol,
    MemberRecord,
    SeqOrderError,
    UnknownMemberError,
    UpdateRecord,
    main,
    membership_audit_event,
)

_STDLIB_ALLOW = {
    "hashlib",
    "hmac",
    "threading",
    "dataclasses",
    "typing",
    "__future__",
}


def _proto(*ids):
    gp = GossipProtocol()
    for i, nid in enumerate(ids):
        gp.join(nid, i + 1)
    return gp


class TestPins(unittest.TestCase):
    def test_version_schema_and_state_pins(self):
        self.assertEqual(GOSSIP_PROTOCOL_VERSION, "gossip-protocol.v1")
        self.assertEqual(GOSSIP_PROTOCOL_SCHEMA, "northstar.gossip-protocol.v1")
        self.assertEqual((MEMBER_ALIVE, MEMBER_SUSPECT, MEMBER_DEAD),
                         ("alive", "suspect", "dead"))
        self.assertEqual(
            (EVENT_JOINED, EVENT_SUSPECTED, EVENT_CONFIRMED, EVENT_ALIVE,
             EVENT_DISSEMINATED, EVENT_MEMBERSHIP_REJECTED),
            ("gossip-joined", "gossip-suspected", "gossip-confirmed",
             "gossip-alive", "gossip-disseminated", "gossip-membership-rejected"),
        )

    def test_stdlib_only(self):
        src = Path(__file__).resolve().parent.parent / "gossip_protocol.py"
        tree = ast.parse(src.read_text())
        mods = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                mods.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom):
                mods.add((node.module or "").split(".")[0])
        self.assertLessEqual(mods, _STDLIB_ALLOW, f"non-stdlib imports: {mods - _STDLIB_ALLOW}")


class TestJoin(unittest.TestCase):
    def test_join_roundtrip(self):
        gp = GossipProtocol()
        rec = gp.join("n1", 1)
        self.assertIsInstance(rec, MemberRecord)
        self.assertEqual(rec.state, MEMBER_ALIVE)
        self.assertEqual(rec.incarnation, 0)
        self.assertTrue(rec.verify_digest(rec.digest()))
        self.assertFalse(rec.verify_digest("sha256:" + "0" * 64))
        self.assertEqual(gp.state_of("n1"), MEMBER_ALIVE)
        self.assertEqual(gp.member_ids(), ("n1",))
        self.assertEqual(gp.alive_members(), ("n1",))

    def test_join_duplicate_refused(self):
        gp = _proto("n1")
        with self.assertRaises(DuplicateMemberError):
            gp.join("n1", 2)
        kinds = [e["kind"] for e in gp.audit_log()]
        self.assertIn(EVENT_MEMBERSHIP_REJECTED, kinds)
        # failed mutation consumed its seq: the next mutation needs seq 3
        gp.join("n2", 3)
        self.assertEqual(gp.member_ids(), ("n1", "n2"))

    def test_join_bad_inputs(self):
        gp = GossipProtocol()
        with self.assertRaises((TypeError, ValueError)):
            gp.join("", 1)
        with self.assertRaises(TypeError):
            gp.join(123, 1)
        with self.assertRaises(TypeError):
            gp.join("n1", True)
        with self.assertRaises(ValueError):
            gp.join("n1", -1)
        with self.assertRaises(TypeError):
            gp.join("n1", 1.5)
        self.assertEqual(gp.member_ids(), ())

    def test_seq_rewind_refused(self):
        gp = _proto("n1")
        with self.assertRaises(SeqOrderError):
            gp.join("n2", 1)  # not strictly increasing
        self.assertNotIn("n2", gp.member_ids())


class TestSuspectLifecycle(unittest.TestCase):
    def test_suspect_alive_to_suspect(self):
        gp = _proto("n1")
        rec = gp.suspect("n1", 2)
        self.assertEqual(rec.state, MEMBER_SUSPECT)
        self.assertEqual(rec.incarnation, 0)  # suspicion pins current incarnation
        self.assertEqual(gp.suspects(), ("n1",))
        self.assertEqual(gp.alive_members(), ())

    def test_suspect_unknown_member(self):
        gp = GossipProtocol()
        with self.assertRaises(UnknownMemberError):
            gp.suspect("ghost", 1)

    def test_suspect_bad_state(self):
        gp = _proto("n1")
        gp.suspect("n1", 2)
        with self.assertRaises(BadMemberStateError):
            gp.suspect("n1", 3)  # already suspect
        self.assertIn(EVENT_MEMBERSHIP_REJECTED,
                      [e["kind"] for e in gp.audit_log()])

    def test_confirm_terminal(self):
        gp = _proto("n1")
        gp.suspect("n1", 2)
        rec = gp.confirm("n1", 3)
        self.assertEqual(rec.state, MEMBER_DEAD)
        self.assertEqual(gp.dead(), ("n1",))
        with self.assertRaises(BadMemberStateError):
            gp.confirm("n1", 4)  # dead is terminal
        with self.assertRaises(BadMemberStateError):
            gp.suspect("n1", 5)  # cannot suspect the dead
        with self.assertRaises(BadMemberStateError):
            gp.alive("n1", 6)  # cannot revive the dead

    def test_confirm_requires_suspect(self):
        gp = _proto("n1")
        with self.assertRaises(BadMemberStateError):
            gp.confirm("n1", 2)  # alive, not suspect

    def test_alive_refutes_suspicion(self):
        gp = _proto("n1")
        suspect_rec = gp.suspect("n1", 2)
        rec = gp.alive("n1", 3)
        self.assertEqual(rec.state, MEMBER_ALIVE)
        self.assertEqual(rec.incarnation, 1)  # refutation bumps incarnation
        self.assertNotEqual(rec.digest(), suspect_rec.digest())  # pin changes
        self.assertEqual(gp.alive_members(), ("n1",))
        self.assertEqual(gp.suspects(), ())

    def test_alive_requires_suspect(self):
        gp = _proto("n1")
        with self.assertRaises(BadMemberStateError):
            gp.alive("n1", 2)  # already alive
        with self.assertRaises(UnknownMemberError):
            gp.alive("ghost", 3)

    def test_error_taxonomy(self):
        for exc in (DuplicateMemberError, UnknownMemberError,
                    BadMemberStateError, SeqOrderError):
            self.assertTrue(issubclass(exc, GossipMembershipError))


class TestDisseminate(unittest.TestCase):
    def test_disseminate_deterministic_targets(self):
        gp = _proto("a", "b", "c", "d", "e")
        r1 = gp.disseminate("r1", {"k": "v"}, 6, fanout=2)
        r2 = GossipProtocol()
        for i, nid in enumerate("abcde"):
            r2.join(nid, i + 1)
        r2 = r2.disseminate("r1", {"k": "v"}, 6, fanout=2)
        self.assertIsInstance(r1, DisseminationReport)
        self.assertEqual(r1.targets, r2.targets)  # replayable
        self.assertEqual(r1.digest, r2.digest)  # digest pin deterministic
        self.assertTrue(r1.digest.startswith("sha256:"))
        self.assertEqual(len(set(r1.targets)), len(r1.targets))  # no dupes
        self.assertLessEqual(len(r1.targets), 2)
        d = r1.as_dict()
        self.assertEqual(d["rumor_id"], "r1")
        self.assertEqual(d["digest"], r1.digest)

    def test_disseminate_skips_dead_and_origin(self):
        gp = _proto("a", "b", "c")
        gp.suspect("c", 4)
        gp.confirm("c", 5)
        rep = gp.disseminate("r1", {"k": "v"}, 6, fanout=3, origin="a")
        self.assertNotIn("c", rep.targets)  # dead never targeted
        self.assertNotIn("a", rep.targets)  # origin excluded
        self.assertEqual(set(rep.targets), {"b"})

    def test_disseminate_empty_membership_is_data(self):
        gp = GossipProtocol()
        rep = gp.disseminate("r1", {"k": "v"}, 1)
        self.assertEqual(rep.targets, ())

    def test_disseminate_bad_inputs(self):
        gp = _proto("a")
        with self.assertRaises(TypeError):
            gp.disseminate("r1", "not-a-mapping", 2)
        with self.assertRaises(ValueError):
            gp.disseminate("r1", {"x": float("nan")}, 2)
        with self.assertRaises(TypeError):
            gp.disseminate("r1", {"k": "v"}, 2, fanout=True)
        with self.assertRaises(ValueError):
            gp.disseminate("r1", {"k": "v"}, 2, fanout=0)
        with self.assertRaises(TypeError):
            gp.disseminate("r1", {"k": "v"}, 2, origin=123)
        self.assertEqual(len(gp.reports()), 0)

    def test_disseminate_audit_bans_payload(self):
        gp = _proto("a", "b")
        gp.disseminate("r1", {"secret": "bytes"}, 3)
        ev = [e for e in gp.audit_log() if e["kind"] == EVENT_DISSEMINATED][0]
        self.assertEqual(ev["rumor_id"], "r1")
        self.assertNotIn("secret", str(ev["detail"]))
        self.assertIn("digest", ev["detail"])
        with self.assertRaises(ValueError):
            membership_audit_event(
                EVENT_DISSEMINATED, member_id="a", seq=9,
                detail={"payload": {"k": "v"}},
            )


class TestViews(unittest.TestCase):
    def test_member_views_sorted(self):
        gp = GossipProtocol()
        gp.join("zeta", 1)
        gp.join("alpha", 2)
        self.assertEqual(gp.member_ids(), ("alpha", "zeta"))
        self.assertEqual(gp.alive_members(), ("alpha", "zeta"))
        self.assertEqual(gp.suspects(), ())
        self.assertEqual(gp.dead(), ())

    def test_member_unknown_lookup(self):
        gp = GossipProtocol()
        with self.assertRaises(UnknownMemberError):
            gp.member("ghost")
        with self.assertRaises(UnknownMemberError):
            gp.state_of("ghost")

    def test_updates_piggyback_view(self):
        gp = GossipProtocol()
        for i in range(8):
            gp.join(f"n{i}", i + 1)
        buf = gp.updates(9)
        self.assertEqual(len(buf), 5)  # bounded by MAX_PIGGYBACK
        self.assertTrue(all(isinstance(u, UpdateRecord) for u in buf))
        self.assertEqual(buf[-1].member_id, "n7")
        self.assertEqual(buf[-1].kind, EVENT_JOINED)
        # pure view: seq not consumed, no audit row
        before = len(gp.audit_log())
        gp.updates(10, limit=2)
        self.assertEqual(len(gp.audit_log()), before)
        self.assertEqual(len(gp.updates(10, limit=2)), 2)
        with self.assertRaises(ValueError):
            gp.updates(10, limit=0)
        with self.assertRaises(TypeError):
            gp.updates(True)

    def test_as_dict(self):
        gp = _proto("a", "b")
        gp.suspect("b", 3)
        d = gp.as_dict()
        self.assertEqual(d["schema"], GOSSIP_PROTOCOL_SCHEMA)
        self.assertEqual(len(d["members"]), 2)
        self.assertEqual(d["pending_updates"], 3)
        self.assertEqual(d["disseminations"], 0)


class TestAudit(unittest.TestCase):
    def test_membership_audit_shapes(self):
        ev = membership_audit_event(EVENT_JOINED, member_id="n1", seq=1)
        self.assertEqual(ev["audit"], "audit.ndjson/1")
        self.assertEqual(ev["schema"], GOSSIP_PROTOCOL_SCHEMA)
        self.assertEqual(ev["kind"], EVENT_JOINED)
        self.assertEqual(ev["node_id"], "n1")
        self.assertEqual(ev["audit_seq"], 1)
        self.assertEqual(ev["detail"], {})

    def test_membership_audit_bad_kind(self):
        with self.assertRaises(ValueError):
            membership_audit_event("bogus", member_id="n1", seq=1)

    def test_membership_audit_bad_detail(self):
        with self.assertRaises(TypeError):
            membership_audit_event(EVENT_JOINED, member_id="n1", seq=1,
                                   detail="not-a-mapping")

    def test_join_emits_audit_row(self):
        gp = GossipProtocol()
        gp.join("n1", 1)
        kinds = [e["kind"] for e in gp.audit_log()]
        self.assertEqual(kinds, [EVENT_JOINED])

    def test_update_record_digest(self):
        gp = _proto("n1")
        upd = gp.updates(2)[0]
        self.assertTrue(upd.verify_digest(upd.digest()))
        d = upd.as_dict()
        self.assertEqual(d["kind"], EVENT_JOINED)
        self.assertEqual(d["incarnation"], 0)


class TestMain(unittest.TestCase):
    def test_main_subprocess(self):
        mod = Path(__file__).resolve().parent.parent / "gossip_protocol.py"
        proc = subprocess.run(
            [sys.executable, str(mod)],
            capture_output=True, text=True, timeout=60,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("gossip-protocol OK", proc.stdout)
        self.assertIn("gossip-membership OK", proc.stdout)


if __name__ == "__main__":
    unittest.main()
