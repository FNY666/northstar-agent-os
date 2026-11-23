"""Tests for team_manager (org teams: create / invite / roles)."""

import unittest

from team_manager import (
    TEAM_MANAGER_VERSION,
    SCHEMA_PIN,
    AlreadyMemberError,
    InvitationStateError,
    LastOwnerError,
    PermissionError,
    SeqOrderError,
    TeamError,
    TeamManager,
    UnknownInvitationError,
    UnknownMemberError,
    UnknownTeamError,
    team_manager_audit_event,
)


class TestVersionPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(TEAM_MANAGER_VERSION, "team-manager.v1")

    def test_schema_pin(self):
        self.assertEqual(SCHEMA_PIN, "northstar.team-manager.v1")


class TestCreate(unittest.TestCase):
    def test_create_owner_assigned(self):
        m = TeamManager()
        t = m.create("platform", "alice", 1, description="org team")
        self.assertEqual(t.team_id, "team-1")
        self.assertEqual(t.name, "platform")
        self.assertEqual(t.created_seq, 1)
        self.assertTrue(t.digest.startswith("sha256:"))
        self.assertEqual(m.member_role("team-1", "alice"), "owner")

class TestInvite(unittest.TestCase):
    def test_invite_defaults_member(self):
        m = TeamManager()
        m.create("platform", "alice", 1)
        inv = m.invite("team-1", "alice", "bob", 2)
        self.assertEqual(inv.invitation_id, "inv-1")
        self.assertEqual(inv.team_id, "team-1")
        self.assertEqual(inv.invitee_id, "bob")
        self.assertEqual(inv.role, "member")
        self.assertEqual(inv.state, "pending")
        self.assertTrue(inv.digest.startswith("sha256:"))

    def test_invite_requires_inviter_permission(self):
        m = TeamManager()
        m.create("platform", "alice", 1)
        inv = m.invite("team-1", "alice", "bob", 2)
        m.accept(inv.invitation_id, 3)
        with self.assertRaises(PermissionError):
            m.invite("team-1", "bob", "carol", 4)

    def test_invite_unknown_team(self):
        m = TeamManager()
        with self.assertRaises(UnknownTeamError):
            m.invite("team-99", "alice", "bob", 1)


class TestAccept(unittest.TestCase):
    def test_accept_admits_member(self):
        m = TeamManager()
        m.create("platform", "alice", 1)
        inv = m.invite("team-1", "alice", "bob", 2, role="viewer")
        accepted = m.accept(inv.invitation_id, 3)
        self.assertEqual(accepted.state, "accepted")
        self.assertEqual(m.member_role("team-1", "bob"), "viewer")

    def test_accept_twice_fails(self):
        m = TeamManager()
        m.create("platform", "alice", 1)
        inv = m.invite("team-1", "alice", "bob", 2)
        m.accept(inv.invitation_id, 3)
        with self.assertRaises(InvitationStateError):
            m.accept(inv.invitation_id, 4)


class TestRoles(unittest.TestCase):
    def test_roles_lists_assignments(self):
        m = TeamManager()
        m.create("platform", "alice", 1)
        inv = m.invite("team-1", "alice", "bob", 2)
        m.accept(inv.invitation_id, 3)
        got = [(a.member_id, a.role) for a in m.roles("team-1")]
        self.assertEqual(got, [("alice", "owner"), ("bob", "member")])

    def test_set_role_owner_only(self):
        m = TeamManager()
        m.create("platform", "alice", 1)
        inv = m.invite("team-1", "alice", "bob", 2)
        m.accept(inv.invitation_id, 3)
        m.set_role("team-1", "alice", "bob", "admin", 4)
        self.assertEqual(m.member_role("team-1", "bob"), "admin")
        inv2 = m.invite("team-1", "bob", "carol", 5)
        m.accept(inv2.invitation_id, 6)
        with self.assertRaises(PermissionError):
            m.set_role("team-1", "carol", "bob", "viewer", 7)

    def test_cannot_demote_last_owner(self):
        m = TeamManager()
        m.create("platform", "alice", 1)
        with self.assertRaises(LastOwnerError):
            m.set_role("team-1", "alice", "alice", "admin", 2)


class TestRemove(unittest.TestCase):
    def test_remove_member(self):
        m = TeamManager()
        m.create("platform", "alice", 1)
        inv = m.invite("team-1", "alice", "bob", 2)
        m.accept(inv.invitation_id, 3)
        removed = m.remove("team-1", "alice", "bob", 4)
        self.assertEqual(removed.member_id, "bob")
        self.assertEqual(removed.role, "member")
        self.assertIsNone(m.member_role("team-1", "bob"))

    def test_remove_last_owner_fails(self):
        m = TeamManager()
        m.create("platform", "alice", 1)
        with self.assertRaises(LastOwnerError):
            m.remove("team-1", "alice", "alice", 2)


class TestAuditAndSeq(unittest.TestCase):
    def test_audit_event_shape(self):
        evt = team_manager_audit_event("invited", 2, detail="inv-1")
        self.assertEqual(evt["kind"], "invited")
        self.assertEqual(evt["seq"], 2)
        self.assertEqual(evt["detail"], "inv-1")
        self.assertEqual(evt["module"], TEAM_MANAGER_VERSION)
        self.assertEqual(evt["schema"], SCHEMA_PIN)
        with self.assertRaises(TeamError):
            team_manager_audit_event("bogus-kind", 2)

    def test_seq_must_increase(self):
        m = TeamManager()
        m.create("platform", "alice", 5)
        with self.assertRaises(SeqOrderError):
            m.invite("team-1", "alice", "bob", 5)


if __name__ == "__main__":
    unittest.main()
