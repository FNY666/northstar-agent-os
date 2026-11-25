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


class BoundaryEdgeTests(unittest.TestCase):
    """The edges of every window and every axis.

    These exist because the whole-file mutation census found survivors at
    exactly these places: the comparison operators on the window edges
    (``<=`` vs ``<``), the ``or`` in the integer type checks, the "dropping
    an axis widens the scope" branch, and the exact-match path in the
    resource-prefix matcher.
    """

    def test_a_boundary_is_valid_at_exactly_its_issue_time(self):
        check = make_check()
        record = check.authorize(call_id="c1", action="read", tool="Read",
                                 resource="/workspace/a.txt", timestamp=100,
                                 boundary_id="b1")
        self.assertEqual(record.verdict, VERDICT_ALLOWED)

    def test_a_boundary_is_valid_at_exactly_its_expiry(self):
        check = make_check()
        record = check.authorize(call_id="c1", action="read", tool="Read",
                                 resource="/workspace/a.txt", timestamp=200,
                                 boundary_id="b1")
        self.assertEqual(record.verdict, VERDICT_ALLOWED)

    def test_is_expired_at_is_false_at_exactly_the_expiry(self):
        check = make_check()
        boundary = check.registry.get("b1")
        self.assertFalse(boundary.is_expired_at(200))
        self.assertTrue(boundary.is_expired_at(201))

    def test_a_boundary_may_expire_at_the_moment_it_was_issued(self):
        """expires_at == issued_at is a legal, zero-length window.

        The boundary is constructed DIRECTLY, not through ``make_check``: the
        helper always passes a wider window, so a test built on it would
        never reach the ``expires_at < issued_at`` guard at all -- and a
        mutation of that guard (``<`` -> ``<=``) would survive.
        """
        boundary = AuthorizationBoundary(
            boundary_id="b0", scope=SCOPE, subject="user-1", grantee="agent-1",
            issued_at=100, expires_at=100, evidence_digest="sha256:zero")
        self.assertEqual(boundary.issued_at, boundary.expires_at)
        check = BoundaryCheck()
        check.registry.issue(
            boundary_id="b0", scope=SCOPE, subject="user-1", grantee="agent-1",
            issued_at=100, expires_at=100, evidence_digest="sha256:zero")
        record = check.authorize(call_id="c1", action="read", tool="Read",
                                 resource="/workspace/a.txt", timestamp=100,
                                 boundary_id="b0")
        self.assertEqual(record.verdict, VERDICT_ALLOWED)

    def test_a_narrowed_boundary_may_expire_at_the_moment_it_was_issued(self):
        check = make_check()
        child = check.registry.narrow("b1", "b2",
                                      scope=SCOPE.narrowed_to(actions=("read",)),
                                      issued_at=110, expires_at=110)
        self.assertEqual(child.expires_at, 110)

    def test_a_boolean_timestamp_is_refused(self):
        check = make_check()
        with self.assertRaises(InvalidBoundaryError):
            check.authorize(call_id="c1", action="read", timestamp=True,
                            boundary_id="b1")

    def test_a_boolean_timestamp_is_refused_by_is_valid_at(self):
        check = make_check()
        with self.assertRaises(InvalidBoundaryError):
            check.registry.get("b1").is_valid_at(True)

    def test_a_boolean_timestamp_is_refused_by_revoke(self):
        check = make_check()
        with self.assertRaises(InvalidBoundaryError):
            check.registry.revoke("b1", ts=True, reason="x")

    def test_a_boolean_now_is_refused_by_expire_stale(self):
        check = make_check()
        with self.assertRaises(InvalidBoundaryError):
            check.registry.expire_stale(now=True)

    def test_a_boolean_window_is_refused_on_a_grant(self):
        with self.assertRaises(InvalidBoundaryError):
            ApprovalGrant(call_id="c1", digest="sha256:x",
                          issued_at=True, expires_at=200)

    def test_a_boolean_window_is_refused_on_a_boundary(self):
        with self.assertRaises(InvalidBoundaryError):
            AuthorizationBoundary(
                boundary_id="b", scope=SCOPE, subject="u", grantee="g",
                issued_at=True, expires_at=200, evidence_digest="sha256:x")

    def test_a_boolean_revoked_at_is_refused(self):
        with self.assertRaises(InvalidBoundaryError):
            AuthorizationBoundary(
                boundary_id="b", scope=SCOPE, subject="u", grantee="g",
                issued_at=0, expires_at=10, evidence_digest="sha256:x",
                revoked_at=True)

    def test_a_resource_exactly_equal_to_the_prefix_is_covered(self):
        scope = BoundaryScope(resource_prefixes=("/workspace",))
        self.assertTrue(scope.is_satisfied_by("read", resource="/workspace"))

    def test_narrowing_to_the_identical_prefix_set_is_allowed(self):
        narrower = SCOPE.narrowed_to(resource_prefixes=("/workspace",))
        self.assertEqual(narrower.resource_prefixes, ("/workspace",))

    def test_dropping_the_action_axis_is_refused(self):
        """Dropping an axis RELEASES it -- that is a widening, not a narrowing."""
        with self.assertRaises(ScopeWideningError):
            SCOPE.narrowed_to(actions=())

    def test_dropping_the_tool_axis_is_refused(self):
        with self.assertRaises(ScopeWideningError):
            SCOPE.narrowed_to(allowed_tools=())

    def test_dropping_the_prefix_axis_is_refused(self):
        with self.assertRaises(ScopeWideningError):
            SCOPE.narrowed_to(resource_prefixes=())

    def test_an_unlisted_tool_is_refused_even_when_the_action_matches(self):
        """The action check must not mask the tool check."""
        check = make_check()
        record = check.authorize(call_id="c1", action="read", tool="Write",
                                 resource="/workspace/a.txt", timestamp=150,
                                 boundary_id="b1")
        self.assertEqual(record.verdict, VERDICT_DENIED)
        self.assertEqual(record.reason, REASON_SCOPE_MISMATCH)

    def test_a_tool_outside_the_scope_never_calls_the_tool(self):
        check = make_check()
        tool = RecordingTool()
        with self.assertRaises(BoundaryError):
            check.execute(tool, call_id="c1", action="read", tool="Write",
                          resource="/workspace/a.txt", timestamp=150,
                          boundary_id="b1")
        self.assertEqual(tool.calls, [])

    def test_a_delegation_at_the_parents_issue_time_is_allowed(self):
        check = make_check()
        record = check.delegate("b1", "k1", "agent-2", issued_at=100)
        self.assertEqual(record.verdict, VERDICT_ALLOWED)

    def test_a_delegation_before_the_parents_issue_time_is_refused(self):
        check = make_check()
        record = check.delegate("b1", "k1", "agent-2", issued_at=99)
        self.assertEqual(record.verdict, VERDICT_DENIED)
        self.assertEqual(record.reason, REASON_DELEGATION_EXPIRED)

    def test_a_scope_that_constrains_only_the_resource_axis_still_matches(self):
        scope = BoundaryScope(resource_prefixes=("/workspace",))
        check = make_check(scope=scope)
        record = check.authorize(call_id="c1", action="anything", tool="Anything",
                                 resource="/workspace/a", timestamp=150,
                                 boundary_id="b1")
        self.assertEqual(record.verdict, VERDICT_ALLOWED)


class ModuleSelfCheckTests(unittest.TestCase):
    """The module's own ``main()`` self-check is part of the contract.

    The mutation census found nineteen survivors inside ``main()``, because
    no test ran it.  It is the path the design doc quotes, so it is tested
    here rather than left to a human to run by hand.
    """

    def test_the_module_self_check_runs(self):
        import agent_boundary
        agent_boundary.main()

    def test_the_module_self_check_prints_its_verdict(self):
        import io
        import contextlib
        import agent_boundary
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            agent_boundary.main()
        self.assertIn("self-check OK", buffer.getvalue())


class MutantDistinguishingTests(unittest.TestCase):
    """Tests written to distinguish a specific mutant from the original.

    Each one here exists because the whole-file mutation census reported a
    SURVIVOR at that exact line: the mutant changed the code but no test
    could tell the difference.  A survivor is not proof that the code is
    wrong -- it is proof that nothing pins it down -- so each of these pins
    one down.
    """

    def test_the_tool_check_is_independent_of_the_action_check(self):
        """``and`` -> ``or`` at the tool-membership test.

        With ``or``, a scope that lists an allowed tool but not the action
        would still match.  This pins that the tool axis is checked
        independently of the action axis.
        """
        scope = BoundaryScope(actions=("read",), allowed_tools=("Read",))
        # The action is NOT in the scope, the tool IS.
        self.assertFalse(scope.is_satisfied_by("write", tool="Read"))

    def test_a_boundary_whose_expiry_precedes_its_issue_is_refused(self):
        """``<`` -> ``<=`` at the window check.

        A window whose expiry equals its issue is legal; a window whose
        expiry PRECEDES its issue is not.  The mutant made the legal case
        illegal, and no test covered it.
        """
        with self.assertRaises(InvalidBoundaryError):
            AuthorizationBoundary(
                boundary_id="b", scope=SCOPE, subject="u", grantee="g",
                issued_at=200, expires_at=100, evidence_digest="sha256:x")

    def test_a_revoked_boundary_is_not_valid_at_any_timestamp(self):
        """``return False`` -> ``return True`` at the revoked check.

        The revoked check must win over the window check, so a revoked
        boundary inside its own window is still invalid.
        """
        check = make_check()
        check.registry.revoke("b1", ts=120, reason="withdrawn")
        boundary = check.registry.get("b1")
        self.assertFalse(boundary.is_valid_at(150))

    def test_a_non_string_reason_is_refused_when_revoking(self):
        """``or`` -> ``and`` in the revoke timestamp check.

        ``isinstance(ts, bool) or not isinstance(ts, int)`` refuses both a
        bool and a non-int.  The mutant accepted a bool.
        """
        check = make_check()
        with self.assertRaises(InvalidBoundaryError):
            check.registry.revoke("b1", ts=True, reason="withdrawn")

    def test_a_non_string_reason_is_refused_when_revoking(self):
        check = make_check()
        with self.assertRaises(InvalidBoundaryError):
            check.registry.revoke("b1", ts=120, reason=None)

    def test_the_self_check_asserts_the_expired_reason_code(self):
        """The self-check's own assertions are pinned, not merely executed.

        Running ``main()`` is not enough: the census mutated its assertions
        (``and`` -> ``or``) and they still passed.  These tests assert the
        VALUES the self-check asserts, so a mutation of the self-check's own
        assertions is caught.
        """
        check = make_check()
        record = check.authorize(call_id="c4", action="read", tool="Read",
                                 resource="/workspace/a.txt", timestamp=500,
                                 boundary_id="b1")
        self.assertEqual(record.verdict, VERDICT_DENIED)
        self.assertEqual(record.reason, REASON_EXPIRED)

    def test_the_self_check_asserts_the_revoked_reason_code(self):
        check = make_check()
        check.registry.revoke("b1", ts=120, reason="operator withdrew")
        record = check.authorize(call_id="c5", action="read", tool="Read",
                                 resource="/workspace/a.txt", timestamp=130,
                                 boundary_id="b1")
        self.assertEqual(record.verdict, VERDICT_DENIED)
        self.assertEqual(record.reason, REASON_REVOKED)

    def test_the_self_check_asserts_the_invalid_grant_reason_code(self):
        check = make_check()
        grant = ApprovalGrant(call_id="c6", digest="sha256:wrong",
                              issued_at=100, expires_at=200)
        record = check.authorize(call_id="c6", action="read", tool="Read",
                                 resource="/workspace/a.txt", timestamp=150,
                                 boundary_id="b1", grant=grant)
        self.assertEqual(record.verdict, VERDICT_DENIED)
        self.assertEqual(record.reason, REASON_APPROVAL_INVALID)

    def test_the_self_check_asserts_the_delegation_expiry_reason_code(self):
        check = make_check()
        record = check.delegate("b1", "k1", "agent-2", issued_at=150)
        self.assertEqual(record.verdict, VERDICT_ALLOWED)
        record = check.delegate("b1", "k2", "agent-2", issued_at=250)
        self.assertEqual(record.verdict, VERDICT_DENIED)
        self.assertEqual(record.reason, REASON_DELEGATION_EXPIRED)

    def test_the_audit_lines_carry_a_verdict_field(self):
        """The self-check asserts this too; here it is asserted directly."""
        check = make_check()
        check.authorize(call_id="c1", action="read", tool="Read",
                        resource="/workspace/a.txt", timestamp=150,
                        boundary_id="b1")
        for line in check.audit_lines():
            self.assertIn('"verdict"', line)


class ApprovalGrantWindowTests(unittest.TestCase):
    """The grant's OWN window guard.

    ``ApprovalGrant`` and ``AuthorizationBoundary`` each carry an
    "expires_at must not precede issued_at" guard.  The census killed the
    mutation on the boundary's copy (line 443) but not on the GRANT's copy
    (line 384): the two are separate lines in separate classes, and only one
    of them had a test that reached it.
    """

    def test_a_grant_whose_expiry_equals_its_issue_is_allowed(self):
        """A zero-length grant window is legal."""
        grant = ApprovalGrant(call_id="c1", digest="sha256:x",
                              issued_at=100, expires_at=100)
        self.assertEqual(grant.issued_at, grant.expires_at)

    def test_a_grant_whose_expiry_precedes_its_issue_is_refused(self):
        with self.assertRaises(InvalidBoundaryError):
            ApprovalGrant(call_id="c1", digest="sha256:x",
                          issued_at=200, expires_at=100)

    def test_a_zero_length_grant_is_valid_at_exactly_its_issue(self):
        grant = ApprovalGrant(call_id="c1", digest="sha256:x",
                              issued_at=100, expires_at=100)
        self.assertTrue(grant.is_valid_at(100))
        self.assertFalse(grant.is_valid_at(101))

    def test_a_revoked_boundary_is_not_valid_even_inside_its_window(self):
        """The revoked check must precede the window check."""
        check = make_check()
        check.registry.revoke("b1", ts=120, reason="withdrawn")
        self.assertFalse(check.registry.get("b1").is_valid_at(150))


class ScopeAxisIndependenceTests(unittest.TestCase):
    """The scope's axes are checked INDEPENDENTLY of one another.

    A mutation that turns the resource-prefix conjunction into a
    disjunction (``and`` -> ``or``) would let a resource outside the scope
    match whenever the tool and the action match.  This pins that the
    resource axis is a conjunction, not a disjunction.
    """

    def test_a_resource_outside_the_prefixes_does_not_match(self):
        scope = BoundaryScope(
            resource_prefixes=("/workspace",),
            actions=("read",),
            allowed_tools=("Read",),
        )
        self.assertFalse(scope.is_satisfied_by(
            "read", tool="Read", resource="/elsewhere/a.txt"))

    def test_a_resource_outside_the_prefixes_is_refused_by_the_check(self):
        check = make_check()
        record = check.authorize(call_id="c1", action="read", tool="Read",
                                 resource="/elsewhere/a.txt", timestamp=150,
                                 boundary_id="b1")
        self.assertEqual(record.verdict, VERDICT_DENIED)
        self.assertEqual(record.reason, REASON_SCOPE_MISMATCH)

    def test_a_resource_outside_the_prefixes_never_calls_the_tool(self):
        check = make_check()
        tool = RecordingTool()
        with self.assertRaises(BoundaryError):
            check.execute(tool, call_id="c1", action="read", tool="Read",
                          resource="/elsewhere/a.txt", timestamp=150,
                          boundary_id="b1")
        self.assertEqual(tool.calls, [])


class RevocationTimestampTests(unittest.TestCase):
    """The revoke timestamp's type check refuses BOTH a bool and a non-int.

    ``isinstance(ts, bool) or not isinstance(ts, int)`` is a disjunction:
    a bool is refused because it is a bool, and a string is refused because
    it is not an int.  A mutation that turned it into a conjunction would
    accept a bool.
    """

    def test_a_bool_timestamp_is_refused_by_revoke(self):
        check = make_check()
        with self.assertRaises(InvalidBoundaryError):
            check.registry.revoke("b1", ts=True, reason="withdrawn")

    def test_a_string_timestamp_is_refused_by_revoke(self):
        check = make_check()
        with self.assertRaises(InvalidBoundaryError):
            check.registry.revoke("b1", ts="now", reason="withdrawn")

    def test_a_float_timestamp_is_refused_by_revoke(self):
        check = make_check()
        with self.assertRaises(InvalidBoundaryError):
            check.registry.revoke("b1", ts=1.5, reason="withdrawn")


class SelfCheckAssertionTests(unittest.TestCase):
    """The self-check's own assertions, pinned from the outside.

    The census mutated three of the self-check's ``and`` assertions into
    ``or`` and they all survived, because running ``main()`` only proves it
    does not raise -- a weakened assertion inside it does not raise.  These
    tests assert the same values from outside the self-check.
    """

    def test_the_expired_decision_carries_the_expired_reason(self):
        check = make_check()
        record = check.authorize(call_id="c4", action="read", tool="Read",
                                 resource="/workspace/a.txt", timestamp=500,
                                 boundary_id="b1")
        self.assertEqual(record.verdict, VERDICT_DENIED)
        self.assertEqual(record.reason, REASON_EXPIRED)
        self.assertTrue(record.denied)

    def test_the_revoked_decision_carries_the_revoked_reason(self):
        check = make_check()
        check.registry.revoke("b1", ts=120, reason="operator withdrew")
        record = check.authorize(call_id="c5", action="read", tool="Read",
                                 resource="/workspace/a.txt", timestamp=130,
                                 boundary_id="b1")
        self.assertEqual(record.verdict, VERDICT_DENIED)
        self.assertEqual(record.reason, REASON_REVOKED)

    def test_the_invalid_grant_decision_carries_the_invalid_reason(self):
        check = make_check()
        grant = ApprovalGrant(call_id="c6", digest="sha256:wrong",
                              issued_at=100, expires_at=200)
        record = check.authorize(call_id="c6", action="read", tool="Read",
                                 resource="/workspace/a.txt", timestamp=150,
                                 boundary_id="b1", grant=grant)
        self.assertEqual(record.verdict, VERDICT_DENIED)
        self.assertEqual(record.reason, REASON_APPROVAL_INVALID)

    def test_the_audit_line_of_a_denial_names_its_reason(self):
        check = make_check()
        check.authorize(call_id="c5", action="write", tool="Write",
                        resource="/workspace/a.txt", timestamp=130,
                        boundary_id="b1")
        self.assertIn(REASON_SCOPE_MISMATCH, check.audit_lines()[0])


class ScopeResourceAxisTests(unittest.TestCase):
    """The resource axis is a CONJUNCTION, not a disjunction.

    A scope that constrains resources requires the call to NAME one.  A
    mutation that turned the guard into a disjunction (``and`` -> ``or``)
    would let a call that names no resource satisfy a scope that constrains
    them, and no test caught it -- so it is pinned here.
    """

    def test_a_scope_that_constrains_resources_requires_the_call_to_name_one(self):
        scope = BoundaryScope(resource_prefixes=("/workspace",))
        self.assertFalse(scope.is_satisfied_by("read", resource=None))

    def test_a_scope_that_constrains_no_resources_does_not_require_one(self):
        scope = BoundaryScope(actions=("read",))
        self.assertTrue(scope.is_satisfied_by("read", resource=None))

    def test_a_call_naming_no_resource_is_refused_by_the_check(self):
        check = make_check()
        record = check.authorize(call_id="c1", action="read", tool="Read",
                                 resource=None, timestamp=150,
                                 boundary_id="b1")
        self.assertEqual(record.verdict, VERDICT_DENIED)
        self.assertEqual(record.reason, REASON_SCOPE_MISMATCH)

    def test_a_call_naming_no_resource_never_calls_the_tool(self):
        check = make_check()
        tool = RecordingTool()
        with self.assertRaises(BoundaryError):
            check.execute(tool, call_id="c1", action="read", tool="Read",
                          resource=None, timestamp=150, boundary_id="b1")
        self.assertEqual(tool.calls, [])


class RevokeTypeCheckTests(unittest.TestCase):
    """Revocation refuses a timestamp that is not an int.

    The type check used to live in ``revoke()`` as well as in the dataclass
    validation.  It was REDUNDANT: the dataclass refuses a bool and a
    non-int already, so the local copy changed nothing an observer could
    see, and a mutation of it survived.  It has been removed; these tests
    pin the behaviour that remains.
    """

    def test_a_string_timestamp_is_refused_when_revoking(self):
        check = make_check()
        with self.assertRaises(InvalidBoundaryError):
            check.registry.revoke("b1", ts="now", reason="withdrawn")

    def test_a_float_timestamp_is_refused_when_revoking(self):
        check = make_check()
        with self.assertRaises(InvalidBoundaryError):
            check.registry.revoke("b1", ts=1.5, reason="withdrawn")

    def test_a_bool_timestamp_is_refused_when_revoking(self):
        check = make_check()
        with self.assertRaises(InvalidBoundaryError):
            check.registry.revoke("b1", ts=True, reason="withdrawn")

    def test_a_non_string_reason_is_refused_when_revoking(self):
        check = make_check()
        with self.assertRaises(InvalidBoundaryError):
            check.registry.revoke("b1", ts=120, reason=None)


class SelfCheckStrengthTests(unittest.TestCase):
    """The self-check's assertions must be STRONG enough to be evidence.

    Running ``main()`` only proves it does not raise.  A weakened assertion
    inside it (``and`` -> ``or``) also does not raise, so the self-check
    would keep passing while asserting less.  These tests re-derive the
    self-check's claims from outside it, so a weakened assertion inside
    ``main()`` is caught even though ``main()`` still passes.
    """

    def _run_self_check(self):
        import agent_boundary
        agent_boundary.main()

    def test_the_self_check_would_not_pass_with_a_weakened_expiry_assertion(self):
        """The expiry claim, re-derived."""
        check = make_check()
        record = check.authorize(call_id="c4", action="read", tool="Read",
                                 resource="/workspace/a.txt", timestamp=500,
                                 boundary_id="b1")
        # Both halves, separately: a weakened "and" would let either pass.
        self.assertEqual(record.verdict, VERDICT_DENIED)
        self.assertEqual(record.reason, REASON_EXPIRED)

    def test_the_self_check_would_not_pass_with_a_weakened_revocation_assertion(self):
        check = make_check()
        check.registry.revoke("b1", ts=120, reason="operator withdrew")
        record = check.authorize(call_id="c5", action="read", tool="Read",
                                 resource="/workspace/a.txt", timestamp=130,
                                 boundary_id="b1")
        self.assertEqual(record.verdict, VERDICT_DENIED)
        self.assertEqual(record.reason, REASON_REVOKED)

    def test_the_self_check_would_not_pass_with_a_weakened_grant_assertion(self):
        check = make_check()
        grant = ApprovalGrant(call_id="c6", digest="sha256:wrong",
                              issued_at=100, expires_at=200)
        record = check.authorize(call_id="c6", action="read", tool="Read",
                                 resource="/workspace/a.txt", timestamp=150,
                                 boundary_id="b1", grant=grant)
        self.assertEqual(record.verdict, VERDICT_DENIED)
        self.assertEqual(record.reason, REASON_APPROVAL_INVALID)

    def test_the_self_check_still_runs(self):
        self._run_self_check()

    def test_the_module_runs_as_a_script(self):
        """``python3 agent_boundary.py`` must reach the self-check.

        A mutation of the ``__main__`` guard would stop the script from
        running its own check, and nothing else would notice -- so the
        script's entry point is exercised here by running it as a
        subprocess and checking its output.
        """
        import subprocess
        module_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "agent_boundary.py")
        completed = subprocess.run(
            [sys.executable, module_path],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            timeout=120)
        self.assertEqual(completed.returncode, 0, completed.stdout)
        self.assertIn("self-check OK", completed.stdout)
