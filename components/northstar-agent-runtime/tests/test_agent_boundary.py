"""Tests for :mod:`agent_boundary` -- authorization as a boundary.

The invariants under test, in the order the module states them:

1. a denied call NEVER reaches the tool (proved with a callable that records
   having been called);
2. approval-required without an approver fails CLOSED;
3. a scope can only NARROW;
4. an expired or revoked boundary authorizes nothing;
5. an approval grant binds one call id and one digest, and a plain ``True``
   is not a grant;
6. the boundary is re-checked at DELEGATION time;
7. every decision leaves an auditable line with a reason code;
8. structurally invalid input is refused.

The tests assert BEHAVIOUR, not line coverage: the mutation probe plants
faults in ``agent_boundary.py`` and requires that the tests catch them, so a
test that only walks the code would let a broken boundary through.
"""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent_boundary import (  # noqa: E402
    REASON_APPROVAL_EXPIRED,
    REASON_APPROVAL_INVALID,
    REASON_APPROVAL_REQUIRED,
    REASON_DELEGATION_EXPIRED,
    REASON_DELEGATION_NOT_ALLOWED,
    REASON_EXPIRED,
    REASON_NOT_YET_ACTIVE,
    REASON_NO_BOUNDARY,
    REASON_REVOKED,
    REASON_SCOPE_MISMATCH,
    VERDICT_ALLOWED,
    VERDICT_DENIED,
    VERDICT_REQUIRE_HUMAN,
    ApprovalGrant,
    ApprovalRequiredError,
    AuthorizationBoundary,
    BoundaryCheck,
    BoundaryError,
    BoundaryRegistry,
    BoundaryScope,
    InvalidBoundaryError,
    ScopeWideningError,
)

SCOPE = BoundaryScope(
    resource_prefixes=("/workspace",),
    actions=("read",),
    allowed_tools=("Read",),
    denied_tools=("Bash",),
)


def make_check(**kwargs):
    """A check with one live boundary ``b1``."""
    check = BoundaryCheck()
    check.registry.issue(
        boundary_id="b1",
        scope=kwargs.get("scope", SCOPE),
        subject="user-1",
        grantee="agent-1",
        issued_at=kwargs.get("issued_at", 100),
        expires_at=kwargs.get("expires_at", 200),
        evidence_digest="sha256:deadbeef",
    )
    return check


class RecordingTool:
    """A callable that records every call, so a test can prove it was not called."""

    def __init__(self, result="ok"):
        self.calls = []
        self._result = result

    def __call__(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        return self._result

    @property
    def called(self):
        return bool(self.calls)


class DeniedCallNeverReachesTheToolTests(unittest.TestCase):
    """Invariant 1: a denied call never reaches the tool."""

    def test_a_scope_mismatch_never_calls_the_tool(self):
        check = make_check()
        tool = RecordingTool()
        with self.assertRaises(BoundaryError):
            check.execute(tool, call_id="c1", action="write", tool="Write",
                          resource="/workspace/a.txt", timestamp=150,
                          boundary_id="b1")
        self.assertEqual(tool.calls, [])

    def test_an_expired_boundary_never_calls_the_tool(self):
        check = make_check()
        tool = RecordingTool()
        with self.assertRaises(BoundaryError):
            check.execute(tool, call_id="c1", action="read", tool="Read",
                          resource="/workspace/a.txt", timestamp=999,
                          boundary_id="b1")
        self.assertEqual(tool.calls, [])

    def test_a_revoked_boundary_never_calls_the_tool(self):
        check = make_check()
        check.registry.revoke("b1", ts=120, reason="withdrawn")
        tool = RecordingTool()
        with self.assertRaises(BoundaryError):
            check.execute(tool, call_id="c1", action="read", tool="Read",
                          resource="/workspace/a.txt", timestamp=130,
                          boundary_id="b1")
        self.assertEqual(tool.calls, [])

    def test_an_unknown_boundary_never_calls_the_tool(self):
        check = make_check()
        tool = RecordingTool()
        with self.assertRaises(BoundaryError):
            check.execute(tool, call_id="c1", action="read", tool="Read",
                          resource="/workspace/a.txt", timestamp=150,
                          boundary_id="no-such-boundary")
        self.assertEqual(tool.calls, [])

    def test_a_denied_tool_in_the_deny_list_never_calls_the_tool(self):
        """The deny list wins over a matching action."""
        check = make_check()
        tool = RecordingTool()
        with self.assertRaises(BoundaryError):
            check.execute(tool, call_id="c1", action="read", tool="Bash",
                          resource="/workspace/a.txt", timestamp=150,
                          boundary_id="b1")
        self.assertEqual(tool.calls, [])

    def test_an_allowed_call_does_reach_the_tool(self):
        """The other half of invariant 1: the guarantee is not vacuous."""
        check = make_check()
        tool = RecordingTool(result="ran")
        out = check.execute(tool, call_id="c1", action="read", tool="Read",
                            resource="/workspace/a.txt", timestamp=150,
                            boundary_id="b1", argument="x")
        self.assertEqual(out, "ran")
        self.assertEqual(len(tool.calls), 1)
        self.assertEqual(tool.calls[0][1], {"argument": "x"})


class ApprovalFailsClosedTests(unittest.TestCase):
    """Invariant 2: approval-required without an approver fails closed."""

    def test_requires_human_without_a_grant_is_refused(self):
        check = make_check()
        record = check.authorize(call_id="c1", action="read", tool="Read",
                                 resource="/workspace/a.txt", timestamp=150,
                                 boundary_id="b1", requires_human=True)
        self.assertEqual(record.verdict, VERDICT_REQUIRE_HUMAN)
        self.assertEqual(record.reason, REASON_APPROVAL_REQUIRED)
        self.assertFalse(record.allowed)

    def test_requires_human_without_a_grant_never_calls_the_tool(self):
        check = make_check()
        tool = RecordingTool()
        with self.assertRaises(BoundaryError):
            check.execute(tool, call_id="c1", action="read", tool="Read",
                          resource="/workspace/a.txt", timestamp=150,
                          boundary_id="b1", requires_human=True)
        self.assertEqual(tool.calls, [])

    def test_authorize_or_raise_raises_when_no_approver_is_present(self):
        check = make_check()
        with self.assertRaises(ApprovalRequiredError) as ctx:
            check.authorize_or_raise(call_id="c1", action="read", tool="Read",
                                     resource="/workspace/a.txt", timestamp=150,
                                     boundary_id="b1", requires_human=True)
        self.assertEqual(ctx.exception.record.verdict, VERDICT_REQUIRE_HUMAN)

    def test_authorize_or_raise_raises_on_a_plain_denial(self):
        check = make_check()
        with self.assertRaises(BoundaryError):
            check.authorize_or_raise(call_id="c1", action="write", tool="Write",
                                     resource="/workspace/a.txt", timestamp=150,
                                     boundary_id="b1")

    def test_a_matching_grant_allows_the_call(self):
        check = make_check()
        digest = BoundaryCheck.call_digest(
            "c1", "read", "Read", "/workspace/a.txt")
        grant = ApprovalGrant(call_id="c1", digest=digest,
                              issued_at=100, expires_at=200)
        record = check.authorize(call_id="c1", action="read", tool="Read",
                                 resource="/workspace/a.txt", timestamp=150,
                                 boundary_id="b1", grant=grant)
        self.assertEqual(record.verdict, VERDICT_ALLOWED)

    def test_an_expired_grant_fails_closed(self):
        check = make_check()
        digest = BoundaryCheck.call_digest(
            "c1", "read", "Read", "/workspace/a.txt")
        grant = ApprovalGrant(call_id="c1", digest=digest,
                              issued_at=100, expires_at=120)
        record = check.authorize(call_id="c1", action="read", tool="Read",
                                 resource="/workspace/a.txt", timestamp=150,
                                 boundary_id="b1", grant=grant)
        self.assertEqual(record.verdict, VERDICT_DENIED)
        self.assertEqual(record.reason, REASON_APPROVAL_EXPIRED)


class ApprovalGrantBindingTests(unittest.TestCase):
    """Invariant 5: a grant binds one call id and one digest."""

    def test_a_grant_with_the_wrong_call_id_is_refused(self):
        check = make_check()
        digest = BoundaryCheck.call_digest(
            "c1", "read", "Read", "/workspace/a.txt")
        grant = ApprovalGrant(call_id="c-other", digest=digest,
                              issued_at=100, expires_at=200)
        record = check.authorize(call_id="c1", action="read", tool="Read",
                                 resource="/workspace/a.txt", timestamp=150,
                                 boundary_id="b1", grant=grant)
        self.assertEqual(record.verdict, VERDICT_DENIED)
        self.assertEqual(record.reason, REASON_APPROVAL_INVALID)

    def test_a_grant_with_the_wrong_digest_is_refused(self):
        check = make_check()
        grant = ApprovalGrant(call_id="c1", digest="sha256:not-the-digest",
                              issued_at=100, expires_at=200)
        record = check.authorize(call_id="c1", action="read", tool="Read",
                                 resource="/workspace/a.txt", timestamp=150,
                                 boundary_id="b1", grant=grant)
        self.assertEqual(record.verdict, VERDICT_DENIED)
        self.assertEqual(record.reason, REASON_APPROVAL_INVALID)

    def test_a_grant_does_not_transfer_to_another_action(self):
        """The digest covers the action, so a grant cannot be replayed."""
        check = make_check()
        digest = BoundaryCheck.call_digest(
            "c1", "read", "Read", "/workspace/a.txt")
        grant = ApprovalGrant(call_id="c1", digest=digest,
                              issued_at=100, expires_at=200)
        record = check.authorize(call_id="c1", action="write", tool="Read",
                                 resource="/workspace/a.txt", timestamp=150,
                                 boundary_id="b1", grant=grant)
        self.assertEqual(record.verdict, VERDICT_DENIED)

    def test_a_plain_true_is_not_a_grant(self):
        """A plain ``True`` carries no call id and no digest, so it is not one."""
        check = make_check()
        with self.assertRaises(InvalidBoundaryError):
            ApprovalGrant(call_id=True, digest=True,
                          issued_at=100, expires_at=200)

    def test_a_grant_whose_expiry_precedes_its_issue_is_refused(self):
        with self.assertRaises(InvalidBoundaryError):
            ApprovalGrant(call_id="c1", digest="sha256:x",
                          issued_at=200, expires_at=100)

    def test_the_call_digest_is_not_confused_by_the_tool_name(self):
        a = BoundaryCheck.call_digest("c1", "read", "Read", "/w")
        b = BoundaryCheck.call_digest("c1", "read", "Read", "/w")
        c = BoundaryCheck.call_digest("c1", "read", "Write", "/w")
        self.assertEqual(a, b)
        self.assertNotEqual(a, c)


class ScopeOnlyNarrowsTests(unittest.TestCase):
    """Invariant 3: a scope can only narrow."""

    def test_narrowing_to_a_subset_is_allowed(self):
        narrower = SCOPE.narrowed_to(actions=("read",))
        self.assertEqual(narrower.actions, ("read",))
        self.assertEqual(narrower.allowed_tools, SCOPE.allowed_tools)

    def test_narrowing_to_wider_actions_is_refused(self):
        with self.assertRaises(ScopeWideningError):
            SCOPE.narrowed_to(actions=("read", "write"))

    def test_narrowing_to_wider_tools_is_refused(self):
        with self.assertRaises(ScopeWideningError):
            SCOPE.narrowed_to(allowed_tools=("Read", "Write"))

    def test_narrowing_to_wider_resource_prefixes_is_refused(self):
        with self.assertRaises(ScopeWideningError):
            SCOPE.narrowed_to(resource_prefixes=("/",))

    def test_dropping_the_denied_tools_is_refused(self):
        """A narrowing may ADD a denial but never drop one."""
        with self.assertRaises(ScopeWideningError):
            SCOPE.narrowed_to(denied_tools=())

    def test_a_narrowed_scope_still_refuses_the_denied_tool(self):
        narrower = SCOPE.narrowed_to(actions=("read",))
        self.assertFalse(narrower.is_satisfied_by("read", tool="Bash"))

    def test_a_narrowed_boundary_keeps_the_parent_expiry_ceiling(self):
        check = make_check()
        with self.assertRaises(ScopeWideningError):
            check.registry.narrow("b1", "b2",
                                  scope=SCOPE.narrowed_to(actions=("read",)),
                                  issued_at=110, expires_at=999)

    def test_narrowing_the_boundary_refuses_a_wider_scope(self):
        check = make_check()
        with self.assertRaises(ScopeWideningError):
            check.registry.narrow("b1", "b2",
                                  scope=BoundaryScope(actions=("read", "write")),
                                  issued_at=110)

    def test_a_narrowed_boundary_does_not_mutate_the_parent(self):
        check = make_check()
        child = check.registry.narrow("b1", "b2",
                                      scope=SCOPE.narrowed_to(actions=("read",)),
                                      issued_at=110)
        parent = check.registry.get("b1")
        self.assertEqual(child.scope.actions, ("read",))
        self.assertEqual(parent.scope.actions, ("read",))
        self.assertIsNot(child, parent)
        self.assertEqual(child.parent_boundary_id, "b1")


class ExpiryAndRevocationTests(unittest.TestCase):
    """Invariant 4: an expired or revoked boundary authorizes nothing."""

    def test_a_boundary_is_valid_inside_its_window(self):
        check = make_check()
        record = check.authorize(call_id="c1", action="read", tool="Read",
                                 resource="/workspace/a.txt", timestamp=150,
                                 boundary_id="b1")
        self.assertEqual(record.verdict, VERDICT_ALLOWED)

    def test_a_boundary_is_not_valid_before_it_is_issued(self):
        check = make_check()
        record = check.authorize(call_id="c1", action="read", tool="Read",
                                 resource="/workspace/a.txt", timestamp=50,
                                 boundary_id="b1")
        self.assertEqual(record.verdict, VERDICT_DENIED)
        self.assertEqual(record.reason, REASON_NOT_YET_ACTIVE)

    def test_a_boundary_is_not_valid_after_its_expiry(self):
        check = make_check()
        record = check.authorize(call_id="c1", action="read", tool="Read",
                                 resource="/workspace/a.txt", timestamp=201,
                                 boundary_id="b1")
        self.assertEqual(record.verdict, VERDICT_DENIED)
        self.assertEqual(record.reason, REASON_EXPIRED)

    def test_a_revoked_boundary_is_denied_with_the_revoked_reason(self):
        check = make_check()
        check.registry.revoke("b1", ts=120, reason="operator withdrew")
        record = check.authorize(call_id="c1", action="read", tool="Read",
                                 resource="/workspace/a.txt", timestamp=130,
                                 boundary_id="b1")
        self.assertEqual(record.verdict, VERDICT_DENIED)
        self.assertEqual(record.reason, REASON_REVOKED)

    def test_revocation_does_not_mutate_the_original_boundary(self):
        check = make_check()
        before = check.registry.get("b1")
        check.registry.revoke("b1", ts=120, reason="withdrawn")
        self.assertIsNone(before.revoked_at)
        self.assertIsNotNone(check.registry.get("b1").revoked_at)

    def test_expire_stale_reports_the_lapsed_boundaries(self):
        check = make_check()
        self.assertEqual(check.registry.expire_stale(now=150), ())
        self.assertEqual(check.registry.expire_stale(now=201), ("b1",))

    def test_a_revoked_boundary_is_not_reported_as_expired(self):
        check = make_check()
        check.registry.revoke("b1", ts=120, reason="withdrawn")
        self.assertEqual(check.registry.expire_stale(now=201), ())


class DelegationRecheckTests(unittest.TestCase):
    """Invariant 6: the boundary is re-checked at delegation time."""

    def test_a_live_parent_allows_the_delegation(self):
        check = make_check()
        record = check.delegate("b1", "k1", "agent-2", issued_at=150)
        self.assertEqual(record.verdict, VERDICT_ALLOWED)

    def test_an_expired_parent_refuses_the_delegation(self):
        """The staleness is inherited: the check fires at delegation time."""
        check = make_check()
        record = check.delegate("b1", "k1", "agent-2", issued_at=250)
        self.assertEqual(record.verdict, VERDICT_DENIED)
        self.assertEqual(record.reason, REASON_DELEGATION_EXPIRED)

    def test_a_revoked_parent_refuses_the_delegation(self):
        check = make_check()
        check.registry.revoke("b1", ts=120, reason="withdrawn")
        record = check.delegate("b1", "k1", "agent-2", issued_at=130)
        self.assertEqual(record.verdict, VERDICT_DENIED)
        self.assertEqual(record.reason, REASON_REVOKED)

    def test_a_delegation_cannot_widen_the_scope(self):
        check = make_check()
        record = check.delegate(
            "b1", "k1", "agent-2",
            scope=BoundaryScope(actions=("read", "write")),
            issued_at=150)
        self.assertEqual(record.verdict, VERDICT_DENIED)
        self.assertEqual(record.reason, REASON_DELEGATION_NOT_ALLOWED)

    def test_a_refused_delegation_creates_no_child_boundary(self):
        check = make_check()
        check.delegate("b1", "k1", "agent-2", issued_at=250)
        self.assertIsNone(check.registry.get("k1"))

    def test_an_unknown_parent_refuses_the_delegation(self):
        check = make_check()
        record = check.delegate("no-such", "k1", "agent-2", issued_at=150)
        self.assertEqual(record.verdict, VERDICT_DENIED)
        self.assertEqual(record.reason, REASON_NO_BOUNDARY)

    def test_the_child_records_its_parent(self):
        check = make_check()
        check.delegate("b1", "k1", "agent-2", issued_at=150)
        child = check.registry.get("k1")
        self.assertIsNotNone(child)
        self.assertEqual(child.parent_boundary_id, "b1")
        self.assertEqual(child.grantee, "agent-2")


class AuditLineTests(unittest.TestCase):
    """Invariant 7: every decision leaves an auditable line."""

    def test_every_decision_produces_one_line(self):
        check = make_check()
        check.authorize(call_id="c1", action="read", tool="Read",
                        resource="/workspace/a.txt", timestamp=150,
                        boundary_id="b1")
        check.authorize(call_id="c2", action="write", tool="Write",
                        resource="/workspace/a.txt", timestamp=150,
                        boundary_id="b1")
        self.assertEqual(len(check.audit_lines()), 2)
        self.assertEqual(len(check.decisions), 2)

    def test_a_line_carries_the_verdict_the_reason_and_the_boundary(self):
        check = make_check()
        check.authorize(call_id="c1", action="write", tool="Write",
                        resource="/workspace/a.txt", timestamp=150,
                        boundary_id="b1")
        line = check.audit_lines()[0]
        self.assertIn('"verdict":"%s"' % VERDICT_DENIED, line)
        self.assertIn(REASON_SCOPE_MISMATCH, line)
        self.assertIn('"boundary_id":"b1"', line)
        self.assertIn('"call_id":"c1"', line)

    def test_a_line_for_a_denied_call_names_the_reason_code(self):
        check = make_check()
        check.authorize(call_id="c1", action="read", tool="Read",
                        resource="/workspace/a.txt", timestamp=999,
                        boundary_id="b1")
        self.assertIn(REASON_EXPIRED, check.audit_lines()[0])

    def test_the_record_round_trips_through_its_dict(self):
        check = make_check()
        record = check.authorize(call_id="c1", action="read", tool="Read",
                                 resource="/workspace/a.txt", timestamp=150,
                                 boundary_id="b1")
        self.assertEqual(record.as_dict()["verdict"], VERDICT_ALLOWED)
        self.assertTrue(record.allowed)
        self.assertFalse(record.denied)


class InvalidInputTests(unittest.TestCase):
    """Invariant 8: structurally invalid input is refused."""

    def test_an_empty_scope_is_refused(self):
        with self.assertRaises(InvalidBoundaryError):
            BoundaryScope()

    def test_a_scope_that_constrains_nothing_at_all_is_refused(self):
        """An entirely empty scope is not a scope."""
        with self.assertRaises(InvalidBoundaryError):
            BoundaryScope(resource_prefixes=(), actions=(), allowed_tools=())

    def test_a_prefix_only_scope_is_valid(self):
        """A scope may constrain the resource axis alone."""
        scope = BoundaryScope(resource_prefixes=("/workspace",))
        self.assertEqual(scope.resource_prefixes, ("/workspace",))
        self.assertTrue(scope.is_satisfied_by("read", resource="/workspace/a"))
        self.assertFalse(scope.is_satisfied_by("read", resource="/elsewhere/a"))

    def test_a_prefix_is_matched_hierarchically(self):
        """A sub-path of a covered prefix is covered."""
        scope = BoundaryScope(resource_prefixes=("/workspace",))
        self.assertTrue(scope.is_satisfied_by("read", resource="/workspace/sub/a"))
        self.assertFalse(scope.is_satisfied_by("read", resource="/workspaces/a"))

    def test_a_non_string_boundary_id_is_refused(self):
        with self.assertRaises(InvalidBoundaryError):
            AuthorizationBoundary(
                boundary_id=42, scope=SCOPE, subject="u", grantee="g",
                issued_at=0, expires_at=10, evidence_digest="sha256:x")

    def test_an_empty_subject_is_refused(self):
        with self.assertRaises(InvalidBoundaryError):
            AuthorizationBoundary(
                boundary_id="b", scope=SCOPE, subject="  ", grantee="g",
                issued_at=0, expires_at=10, evidence_digest="sha256:x")

    def test_an_empty_grantee_is_refused(self):
        with self.assertRaises(InvalidBoundaryError):
            AuthorizationBoundary(
                boundary_id="b", scope=SCOPE, subject="u", grantee="",
                issued_at=0, expires_at=10, evidence_digest="sha256:x")

    def test_a_non_string_action_is_refused(self):
        check = make_check()
        with self.assertRaises(InvalidBoundaryError):
            check.authorize(call_id="c1", action=None, tool="Read",
                            timestamp=150, boundary_id="b1")

    def test_a_non_string_call_id_is_refused(self):
        check = make_check()
        with self.assertRaises(InvalidBoundaryError):
            check.authorize(call_id=7, action="read", timestamp=150,
                            boundary_id="b1")

    def test_a_non_int_timestamp_is_refused(self):
        check = make_check()
        with self.assertRaises(InvalidBoundaryError):
            check.authorize(call_id="c1", action="read", timestamp="now",
                            boundary_id="b1")

    def test_a_boundary_id_cannot_be_issued_twice(self):
        check = make_check()
        with self.assertRaises(InvalidBoundaryError):
            check.registry.issue(
                boundary_id="b1", scope=SCOPE, subject="u", grantee="g",
                issued_at=0, expires_at=10)

    def test_an_unknown_parent_cannot_be_narrowed(self):
        check = make_check()
        with self.assertRaises(InvalidBoundaryError):
            check.registry.narrow("no-such", "b2", scope=SCOPE, issued_at=110)


class RegistryTests(unittest.TestCase):
    """The registry keeps the parent and the narrowed child side by side."""

    def test_a_narrowed_child_is_stored_beside_its_parent(self):
        check = make_check()
        check.registry.narrow("b1", "b2", scope=SCOPE.narrowed_to(actions=("read",)),
                              issued_at=110)
        self.assertIsNotNone(check.registry.get("b1"))
        self.assertIsNotNone(check.registry.get("b2"))
        self.assertEqual(len(check.registry), 2)

    def test_get_returns_none_for_an_unknown_id(self):
        check = make_check()
        self.assertIsNone(check.registry.get("nope"))

    def test_the_registry_issues_a_derived_digest_when_none_is_given(self):
        registry = BoundaryRegistry()
        boundary = registry.issue(
            boundary_id="b1", scope=SCOPE, subject="u", grantee="g",
            issued_at=0, expires_at=10)
        self.assertTrue(boundary.evidence_digest.startswith("sha256:"))

    def test_as_dict_reports_the_boundary_fields(self):
        check = make_check()
        data = check.registry.get("b1").as_dict()
        self.assertEqual(data["boundary_id"], "b1")
        self.assertEqual(data["subject"], "user-1")
        self.assertEqual(data["grantee"], "agent-1")
        self.assertEqual(data["scope"]["actions"], ["read"])


if __name__ == "__main__":
    unittest.main()
