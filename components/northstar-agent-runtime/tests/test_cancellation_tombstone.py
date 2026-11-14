"""Cancellation tombstones: a stop that survives compaction.

The failure these tests exist for is the one the Moltbook post names: a
summary that keeps the task and prunes the cancellation has manufactured
permission.  So the tests do not assert parts in isolation -- they drive
the whole path:

    declare -> compact -> attempt the revoked action -> blocked ->
    named lift -> allowed

and then the two survivals that matter:

    declare -> resume / fork -> still blocked
    declare -> handoff -> verify -> the grant still names the revoked action

The pieces are asserted too (each rule has its own test), but the path is
what makes the rules mean anything.
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

RUNTIME_ROOT = Path(__file__).resolve().parents[1]
INTEROP_ROOT = RUNTIME_ROOT.parent / "northstar-agent-interop"
HOST_ROOT = RUNTIME_ROOT.parent / "northstar-host"
CONTRACT_ROOT = RUNTIME_ROOT.parent / "northstar-run-contract"
for _path in (str(RUNTIME_ROOT), str(INTEROP_ROOT), str(HOST_ROOT), str(CONTRACT_ROOT)):
    if _path not in sys.path:
        sys.path.insert(0, _path)

import support  # noqa: F401
from support import RuntimeTestCase  # noqa: F401

from handoff import sign_attestation, verify_attestation  # noqa: E402
from interop_contract import AgentAttestation  # noqa: E402

import cancellation_tombstone as ct
import forward_seal_ledger as fsl
import sessions
from cancellation_tombstone import (
    CAPACITY,
    PERMISSION,
    Lift,
    Tombstone,
    TombstoneLiftError,
    TombstoneSet,
)
from forward_seal_ledger import ForwardSealError, ForwardSealLedger
from providers.base import (
    AssistantMessage,
    TextBlock,
    ToolResultBlock,
    ToolUseBlock,
    UserMessage,
)
from sessions import SessionStore

PRINCIPAL = "principal-1"
CHAT = "chat:principal"


def a_tombstone(**overrides) -> Tombstone:
    """The canonical stop: the principal said no to publishing one post."""
    values = {
        "grant_id": "grant-publish",
        "action": "publish",
        "subject": "post-42",
        "declarer": PRINCIPAL,
        "declarer_channel": CHAT,
        "declared_at": 100.0,
        "kind": PERMISSION,
    }
    values.update(overrides)
    return Tombstone(**values)


def a_named_lift(**overrides) -> Lift:
    """The canonical lift: the principal names the revoked action."""
    values = {
        "declarer": PRINCIPAL,
        "declarer_channel": CHAT,
        "grant_id": "grant-publish",
        "action": "publish",
        "subject": "post-42",
        "text": "I re-authorize publishing grant-publish/publish (post-42).",
        "lifted_at": 200.0,
    }
    values.update(overrides)
    return Lift(**values)


def a_ledger(registry=None) -> ForwardSealLedger:
    return ForwardSealLedger(b"k" * 32, b"c" * 32, tombstones=registry)


class TombstoneShapeTests(unittest.TestCase):
    """The tombstone's shape: identity, declarer, and the expiry split."""

    def test_a_tombstone_names_the_revoked_action_and_its_declarer(self):
        tombstone = a_tombstone()
        self.assertEqual(tombstone.identity, ("grant-publish", "publish", "post-42"))
        self.assertEqual(tombstone.declarer, PRINCIPAL)
        self.assertEqual(tombstone.declarer_channel, CHAT)

    def test_a_tombstone_round_trips_through_its_canonical_form(self):
        tombstone = a_tombstone()
        recovered = Tombstone.from_dict(json.loads(json.dumps(tombstone.to_dict())))
        self.assertEqual(recovered, tombstone)
        self.assertEqual(recovered.digest(), tombstone.digest())

    def test_a_tombstone_covers_its_own_identity_and_nothing_else(self):
        tombstone = a_tombstone()
        self.assertTrue(tombstone.covers("grant-publish", "publish", "post-42"))
        self.assertTrue(tombstone.covers("grant-publish", "publish", None))
        self.assertFalse(tombstone.covers("grant-publish", "publish", "post-99"))
        self.assertFalse(tombstone.covers("grant-other", "publish", "post-42"))
        self.assertFalse(tombstone.covers("grant-publish", "delete", "post-42"))

    def test_an_unscoped_tombstone_covers_every_subject_of_its_action(self):
        tombstone = a_tombstone(subject="")
        self.assertTrue(tombstone.covers("grant-publish", "publish", "post-42"))
        self.assertTrue(tombstone.covers("grant-publish", "publish", "post-99"))

    def test_a_tombstone_with_an_unknown_shape_is_refused(self):
        with self.assertRaises(ct.TombstoneError):
            Tombstone.from_dict({"grant_id": "g", "action": "publish", "surprise": 1})
        with self.assertRaises(ct.TombstoneError):
            Tombstone.from_dict("not a mapping")

    def test_the_cancelled_action_error_is_a_tombstone_error(self):
        self.assertTrue(issubclass(ct.CancelledActionError, ct.TombstoneError))
        self.assertTrue(issubclass(ct.TombstoneLiftError, ct.TombstoneError))

    def test_a_permission_stop_carries_no_expiry(self):
        with self.assertRaises(ct.TombstoneError):
            a_tombstone(kind=PERMISSION, expires_at=500.0)

    def test_a_capacity_denial_must_carry_the_bound_that_measures_it(self):
        with self.assertRaises(ct.TombstoneError):
            a_tombstone(kind=CAPACITY)
        bounded = a_tombstone(kind=CAPACITY, expires_at=500.0)
        self.assertEqual(bounded.expires_at, 500.0)


class LiftRuleTests(unittest.TestCase):
    """Only a new, named instruction from the declarer's channel lifts."""

    def test_a_generic_continuation_lifts_nothing(self):
        tombstone = a_tombstone()
        for text in ("continue the work", "resume", "go on", "Continue the work."):
            with self.subTest(text=text):
                lift = a_named_lift(text=text)
                with self.assertRaises(TombstoneLiftError):
                    ct.check_lift(tombstone, lift)

    def test_a_lift_that_names_the_wrong_action_lifts_nothing(self):
        tombstone = a_tombstone()
        with self.assertRaises(TombstoneLiftError):
            ct.check_lift(tombstone, a_named_lift(grant_id="grant-other"))
        with self.assertRaises(TombstoneLiftError):
            ct.check_lift(tombstone, a_named_lift(action="delete"))
        with self.assertRaises(TombstoneLiftError):
            ct.check_lift(tombstone, a_named_lift(subject="post-99"))

    def test_a_lift_from_another_channel_lifts_nothing(self):
        tombstone = a_tombstone()
        with self.assertRaises(TombstoneLiftError):
            ct.check_lift(tombstone, a_named_lift(declarer_channel="chat:somebody-else"))
        with self.assertRaises(TombstoneLiftError):
            ct.check_lift(tombstone, a_named_lift(declarer="somebody-else"))

    def test_a_lift_that_predates_the_tombstone_lifts_nothing(self):
        tombstone = a_tombstone(declared_at=100.0)
        with self.assertRaises(TombstoneLiftError):
            ct.check_lift(tombstone, a_named_lift(lifted_at=50.0))

    def test_the_named_lift_from_the_declarer_channel_lifts(self):
        tombstone = a_tombstone()
        ct.check_lift(tombstone, a_named_lift())


# ---------------------------------------------------------------------------
# The path: declare -> compact -> attempt -> blocked -> named lift -> allowed
# ---------------------------------------------------------------------------


def _assistant_with_call(call_id: str, name: str = "Publish") -> AssistantMessage:
    return AssistantMessage(
        content=(TextBlock(text="publishing it"), ToolUseBlock(id=call_id, name=name, input={"post": "post-42"}))
    )


def _user_with_result(call_id: str, text: str = "ok") -> UserMessage:
    return UserMessage(content=(ToolResultBlock(tool_use_id=call_id, content=text),))


def _publishing_transcript() -> list:
    """A transcript whose prose contains both the task and the stop."""
    return [
        UserMessage.text_block("Publish the post."),
        UserMessage.text_block("Stop. Don't publish."),
        _assistant_with_call("t1"),
        _user_with_result("t1"),
    ]


class DrivenPathTests(RuntimeTestCase):
    """One real path, driven end to end."""

    def test_declare_compact_attempt_blocked_named_lift_allowed(self):
        from compaction import compact

        # A session that was told to publish, and then told to stop.
        store = self.session_store()
        store.append("session_start", {"agent": "main", "data": {"workspace": str(self.workspace())}})
        store.append("user_prompt", {"agent": "main", "role": "user", "content": [{"type": "text", "text": "Publish the post."}]})
        store.append("user_prompt", {"agent": "main", "role": "user", "content": [{"type": "text", "text": "Stop. Don't publish."}]})

        # The stop becomes a tombstone: a record, not prose.
        tombstone = a_tombstone()
        store.record_cancellation(tombstone)

        # Compaction drops the words "Stop. Don't publish." -- that is the
        # point: the prose is prunable and the tombstone is not.
        transcript = _publishing_transcript()
        outcome = compact(transcript, force=True, keep_messages=1, summarizer=lambda _m: "User wants a post published.")
        self.assertTrue(outcome.performed, outcome.reason)
        self.assertNotIn("Don't publish", outcome.summary)
        # The compaction really did happen over the stop: the boundary
        # replaced the prefix that held it.
        self.assertEqual(outcome.transcript[0].subtype, "compact_boundary")

        # The attempt to publish: the ledger refuses the seal, and the
        # refusal lands no record.
        registry = store.tombstones()
        ledger = a_ledger(registry)
        before = len(ledger)
        with self.assertRaises(ForwardSealError):
            ledger.append_grant(grant_id="grant-publish", version="v1", counter=1, action="publish", subject="post-42")
        self.assertEqual(len(ledger), before, "a refused seal must leave no record")

        # The named lift: the principal names the revoked action.
        lift = a_named_lift()
        record = ledger.append_grant(
            grant_id="grant-publish", version="v1", counter=2, action="publish", subject="post-42", lift=lift
        )
        self.assertEqual(len(ledger), before + 1)
        self.assertIn("lift=", dict(record.event)["authorization"])

        # And now the action is allowed: the tombstone is gone.
        self.assertFalse(registry.is_blocked("grant-publish", "publish", "post-42"))
        again = ledger.append_grant(
            grant_id="grant-publish", version="v1", counter=3, action="publish", subject="post-42"
        )
        self.assertEqual(len(ledger), before + 2)

    def test_the_tombstone_survives_compaction_because_it_is_a_record(self):
        store = self.session_store()
        store.record_cancellation(a_tombstone())
        records, _dropped = store.read()
        kinds = [record["type"] for record in records]
        self.assertIn("cancellation", kinds)
        # The record is beside the transcript, not inside it.
        transcript, _unwind = store.resume_transcript()
        self.assertEqual([message for message in transcript], [])
        self.assertTrue(store.tombstones().is_blocked("grant-publish", "publish", "post-42"))

    def test_the_tombstone_survives_a_resume_and_a_fork(self):
        store = self.session_store()
        store.append("session_start", {"agent": "main", "data": {"workspace": str(self.workspace())}})
        store.append("user_prompt", {"agent": "main", "role": "user", "content": [{"type": "text", "text": "Stop. Don't publish."}]})
        store.record_cancellation(a_tombstone())

        # A resume of the same session.
        resumed, _unwind = store.resume_transcript()
        self.assertTrue(resumed is not None)
        live = store.tombstones()
        self.assertTrue(live.is_blocked("grant-publish", "publish", "post-42"))

        # A fork: a new session id, the same records.
        forked = SessionStore(store.directory, session_id="ns-forked-session")
        for record in records_of(store):
            forked.append(record["type"], {k: v for k, v in record.items() if k not in {"index", "ts", "hlc", "session_id", "chain", "genesis", "prev_hash", "chain_hash"}})
        forked_live = forked.tombstones()
        self.assertTrue(forked_live.is_blocked("grant-publish", "publish", "post-42"))


def records_of(store: SessionStore):
    records, _dropped = store.read()
    return records


class SessionRecordTests(RuntimeTestCase):
    """The tombstone's home: the session's append-only records."""

    def test_recording_a_tombstone_writes_a_cancellation_record(self):
        store = self.session_store()
        tombstone = a_tombstone()
        record = store.record_cancellation(tombstone)
        self.assertIsNotNone(record)
        self.assertEqual(record["type"], "cancellation")
        self.assertEqual(record["tombstone"]["grant_id"], "grant-publish")
        self.assertEqual(record["digest"], tombstone.digest())

    def test_the_live_tombstones_are_the_ones_still_standing(self):
        store = self.session_store()
        store.record_cancellation(a_tombstone())
        self.assertTrue(store.tombstones().is_blocked("grant-publish", "publish", "post-42"))
        store.record_cancellation_lift(a_tombstone(), a_named_lift())
        self.assertFalse(store.tombstones().is_blocked("grant-publish", "publish", "post-42"))

    def test_an_invalid_lift_leaves_the_tombstone_standing(self):
        store = self.session_store()
        store.record_cancellation(a_tombstone())
        # "continue the work" is not a lift: it is refused, and refused
        # means the tombstone stays.
        with self.assertRaises(TombstoneLiftError):
            store.record_cancellation_lift(a_tombstone(), a_named_lift(text="continue the work"))
        self.assertTrue(store.tombstones().is_blocked("grant-publish", "publish", "post-42"))

    def test_a_capacity_denial_expires_but_a_permission_stop_does_not(self):
        store = self.session_store()
        store.record_cancellation(a_tombstone(kind=CAPACITY, expires_at=500.0))
        live = store.tombstones()
        self.assertTrue(live.is_blocked("grant-publish", "publish", "post-42", now=499.0))
        self.assertFalse(live.is_blocked("grant-publish", "publish", "post-42", now=500.0))

        store2 = self.session_store()
        store2.record_cancellation(a_tombstone())
        live2 = store2.tombstones()
        # The executor's clock moves forward; the stop does not move with it.
        self.assertTrue(live2.is_blocked("grant-publish", "publish", "post-42", now=10_000.0))

    def test_a_capacity_denial_may_be_renewed_by_a_bounded_fresh_measurement(self):
        registry = TombstoneSet([a_tombstone(kind=CAPACITY, expires_at=500.0)])
        renewed = registry.renew(
            "grant-publish", "publish", measurement="budget headroom 12%", now=400.0, valid_until=900.0
        )
        self.assertEqual(renewed.expires_at, 900.0)
        self.assertTrue(registry.is_blocked("grant-publish", "publish", "post-42", now=800.0))
        self.assertFalse(registry.is_blocked("grant-publish", "publish", "post-42", now=900.0))

    def test_a_permission_stop_is_never_renewed_by_a_measurement(self):
        registry = TombstoneSet([a_tombstone()])
        with self.assertRaises(TombstoneLiftError):
            registry.renew(
                "grant-publish", "publish", measurement="budget headroom 12%", now=400.0, valid_until=900.0
            )
        self.assertTrue(registry.is_blocked("grant-publish", "publish", "post-42"))

    def test_a_renewal_must_be_bounded_in_the_future(self):
        registry = TombstoneSet([a_tombstone(kind=CAPACITY, expires_at=500.0)])
        with self.assertRaises(TombstoneLiftError):
            registry.renew(
                "grant-publish", "publish", measurement="budget headroom 12%", now=400.0, valid_until=400.0
            )
        with self.assertRaises(TombstoneLiftError):
            registry.renew(
                "grant-publish", "publish", measurement="   ", now=400.0, valid_until=900.0
            )
        self.assertTrue(registry.is_blocked("grant-publish", "publish", "post-42", now=400.0))

    def test_the_set_lists_tombstones_in_declaration_order(self):
        first = a_tombstone()
        second = a_tombstone(grant_id="grant-delete", action="delete", subject="post-42")
        registry = TombstoneSet([first, second])
        self.assertEqual([item.grant_id for item in registry.list()], ["grant-publish", "grant-delete"])
        self.assertEqual(len(registry), 2)
        self.assertEqual(TombstoneSet.from_list(registry.to_list()).list(), registry.list())


class SealedLedgerCasTests(unittest.TestCase):
    """The compare-and-swap: the check happens in the append's critical section."""

    def test_a_cancelled_action_is_refused_and_no_record_lands(self):
        registry = TombstoneSet([a_tombstone()])
        ledger = a_ledger(registry)
        with self.assertRaises(ForwardSealError):
            ledger.append_grant(grant_id="grant-publish", version="v1", counter=1, action="publish", subject="post-42")
        self.assertEqual(len(ledger), 0)
        self.assertEqual(len(registry), 1, "a refused seal must not consume the tombstone")

    def test_a_ledger_without_a_registry_behaves_exactly_as_before(self):
        ledger = a_ledger(None)
        record = ledger.append_grant(grant_id="grant-publish", version="v1", counter=1, action="publish")
        self.assertEqual(len(ledger), 1)
        self.assertEqual(dict(record.event)["authorization"], "grant:grant-publish;version=v1;counter=1")

    def test_the_named_lift_in_the_same_append_lands_the_seal_and_consumes_the_tombstone(self):
        registry = TombstoneSet([a_tombstone()])
        ledger = a_ledger(registry)
        record = ledger.append_grant(
            grant_id="grant-publish", version="v1", counter=1, action="publish", subject="post-42",
            lift=a_named_lift(),
        )
        self.assertEqual(len(ledger), 1)
        self.assertIn("lift=", dict(record.event)["authorization"])
        self.assertFalse(registry.is_blocked("grant-publish", "publish", "post-42"))

    def test_the_same_lift_is_consumed_once_and_the_second_attempt_is_refused(self):
        registry = TombstoneSet([a_tombstone()])
        ledger = a_ledger(registry)
        lift = a_named_lift()
        ledger.append_grant(
            grant_id="grant-publish", version="v1", counter=1, action="publish", subject="post-42", lift=lift
        )
        length = len(ledger)
        with self.assertRaises(ForwardSealError):
            ledger.append_grant(
                grant_id="grant-publish", version="v1", counter=2, action="publish", subject="post-42", lift=lift
            )
        self.assertEqual(len(ledger), length, "the second lift must land no record")

    def test_a_generic_continuation_offered_as_a_lift_is_refused_and_nothing_lands(self):
        registry = TombstoneSet([a_tombstone()])
        ledger = a_ledger(registry)
        with self.assertRaises(ForwardSealError):
            ledger.append_grant(
                grant_id="grant-publish", version="v1", counter=1, action="publish", subject="post-42",
                lift=a_named_lift(text="continue the work"),
            )
        self.assertEqual(len(ledger), 0)
        self.assertTrue(registry.is_blocked("grant-publish", "publish", "post-42"))

    def test_a_tombstone_for_another_action_does_not_block_this_one(self):
        registry = TombstoneSet([a_tombstone()])
        ledger = a_ledger(registry)
        record = ledger.append_grant(grant_id="grant-other", version="v1", counter=1, action="publish", subject="post-99")
        self.assertEqual(len(ledger), 1)
        self.assertNotIn("lift=", dict(record.event)["authorization"])

    def test_the_refused_seal_leaves_the_chain_verifiable(self):
        registry = TombstoneSet([a_tombstone()])
        ledger = a_ledger(registry)
        ledger.append_grant(grant_id="grant-other", version="v1", counter=1, action="publish", subject="post-99")
        with self.assertRaises(ForwardSealError):
            ledger.append_grant(grant_id="grant-publish", version="v1", counter=2, action="publish", subject="post-42")
        report = ledger.verify(b"k" * 32, b"c" * 32)
        self.assertEqual(record_count(report), 1)

    def test_a_capacity_denial_releases_the_seal_when_its_bound_passes(self):
        registry = TombstoneSet([a_tombstone(kind=CAPACITY, expires_at=500.0)])
        ledger = a_ledger(registry)
        with self.assertRaises(ForwardSealError):
            ledger.append_grant(
                grant_id="grant-publish", version="v1", counter=1, action="publish", subject="post-42", now=499.0
            )
        self.assertEqual(len(ledger), 0)
        ledger.append_grant(
            grant_id="grant-publish", version="v1", counter=2, action="publish", subject="post-42", now=500.0
        )
        self.assertEqual(len(ledger), 1)

    def test_a_permission_stop_holds_whatever_the_clock_says(self):
        registry = TombstoneSet([a_tombstone()])
        ledger = a_ledger(registry)
        with self.assertRaises(ForwardSealError):
            ledger.append_grant(
                grant_id="grant-publish", version="v1", counter=1, action="publish", subject="post-42", now=10_000_000.0
            )
        self.assertEqual(len(ledger), 0)


def record_count(report) -> int:
    """The number of records a verify report covers."""
    return int(report["records_verified"])


# ---------------------------------------------------------------------------
# The handoff: a tombstone rides every handoff
# ---------------------------------------------------------------------------


class HandoffCarryTests(unittest.TestCase):
    """A tombstone travels with the grant, through the signature."""

    def setUp(self) -> None:
        from authorization import HostPolicy, authorize_run, verify_authorization
        from binding import sign_binding, verify_binding
        from handoff import authorize_handoff, sign_attestation, verify_attestation, verify_handoff_grant
        from interop_contract import AgentAttestation, AgentProfile, AgentRegistry, HandoffRequest

        self._authorize_handoff = authorize_handoff
        self._verify_handoff_grant = verify_handoff_grant

        binding_secret = b"tombstone-binding-secret"
        authorization_secret = b"tombstone-authorization-secret"
        attestation_secret = b"tombstone-attestation-secret"
        self.attestation_secret = attestation_secret
        self.handoff_secret = b"tombstone-handoff-secret"

        run = {
            "schema_version": "northstar.run.v1",
            "run_id": "run-001",
            "actor_id": "actor-001",
            "workspace_id": "workspace-001",
            "task_kind": "implementation",
            "prompt": "Publish the post.",
            "timeout_ms": 10_000,
            "requested_capabilities": ["workspace:read", "workspace:write"],
            "parent_run_id": None,
        }
        binding = {
            "schema_version": run["schema_version"],
            "run_id": run["run_id"],
            "actor_id": run["actor_id"],
            "workspace_id": run["workspace_id"],
            "expires_at": 1_900,
        }
        verified = verify_binding(sign_binding(binding, binding_secret), binding_secret, now=1_000)
        self.root = verify_authorization(
            authorize_run(
                run,
                verified,
                HostPolicy.from_mapping("policy-1", {"actor-001": ["workspace:read", "workspace:write"]}),
                now=1_000,
                secret=authorization_secret,
                grant_ttl_seconds=500,
            ),
            authorization_secret,
            now=1_000,
        )
        self.source = verify_attestation(
            sign_attestation(
                AgentAttestation.from_dict(
                    {
                        "schema_version": "northstar.agent-attestation.v1",
                        "task_id": "task-001",
                        "thread_id": "thread-001",
                        "run_id": "run-001",
                        "actor_id": "actor-001",
                        "workspace_id": "workspace-001",
                        "policy_revision": "policy-1",
                        "agent_id": "claude-code",
                        "step_id": "implementation",
                        "trace_id": "trace-001",
                        "input_digest": "sha256:" + "1" * 64,
                        "capabilities": ["workspace:read", "workspace:write"],
                        "delegation_depth": 0,
                        "expires_at": 1_800,
                    }
                ),
                attestation_secret,
            ),
            attestation_secret,
            now=1_000,
        )
        self.registry = AgentRegistry()
        for agent_id in ("claude-code", "codex"):
            self.registry.register(
                AgentProfile.from_dict(
                    {
                        "schema_version": "northstar.agent-profile.v1",
                        "agent_id": agent_id,
                        "provider": "anthropic",
                        "version": "agent-v1",
                        "capabilities": ["workspace:read", "workspace:write"],
                    }
                )
            )
        self.request = HandoffRequest.from_dict(
            {
                "schema_version": "northstar.handoff-request.v1",
                "handoff_id": "handoff-001",
                "task_id": "task-001",
                "thread_id": "thread-001",
                "run_id": "run-001",
                "actor_id": "actor-001",
                "workspace_id": "workspace-001",
                "policy_revision": "policy-1",
                "source_agent_id": "claude-code",
                "target_agent_id": "codex",
                "step_id": "implementation",
                "trace_id": "trace-001",
                "input_digest": "sha256:" + "1" * 64,
                "requested_capabilities": ["workspace:read"],
                "expected_postconditions": ["tests_pass"],
                "delegation_depth": 1,
                "deadline_at": 1_700,
                "requested_at": 1_000,
                "idempotency_key": "handoff-attempt-1",
            }
        )

    def test_the_tombstone_rides_the_grant_and_comes_back_through_the_signature(self):
        tombstone = a_tombstone()
        token = self._authorize_handoff(
            self.request,
            parent_authorization=self.root,
            source_attestation=self.source,
            registry=self.registry,
            now=1_000,
            current_policy_revision="policy-1",
            secret=self.handoff_secret,
            tombstones=[tombstone.to_dict()],
        )
        verified = self._verify_handoff_grant(token, self.handoff_secret, now=1_001)
        self.assertTrue(verified.ok, verified.errors)
        self.assertEqual(len(verified.grant.tombstones), 1)
        carried = verified.grant.tombstones[0]
        self.assertEqual(carried["grant_id"], "grant-publish")
        self.assertEqual(carried["action"], "publish")
        self.assertEqual(carried["subject"], "post-42")
        self.assertEqual(carried["declarer"], PRINCIPAL)

    def test_a_handoff_without_tombstones_carries_none(self):
        token = self._authorize_handoff(
            self.request,
            parent_authorization=self.root,
            source_attestation=self.source,
            registry=self.registry,
            now=1_000,
            current_policy_revision="policy-1",
            secret=self.handoff_secret,
        )
        verified = self._verify_handoff_grant(token, self.handoff_secret, now=1_001)
        self.assertTrue(verified.ok, verified.errors)
        self.assertEqual(verified.grant.tombstones, ())

    def test_a_nested_handoff_inherits_the_parent_tombstones(self):
        tombstone = a_tombstone()
        first = self._authorize_handoff(
            self.request,
            parent_authorization=self.root,
            source_attestation=self.source,
            registry=self.registry,
            now=1_000,
            current_policy_revision="policy-1",
            secret=self.handoff_secret,
            tombstones=[tombstone.to_dict()],
        )
        first_validated = self._verify_handoff_grant(first, self.handoff_secret, now=1_001)
        self.assertTrue(first_validated.ok, first_validated.errors)

        nested_request = self.request.__class__.from_dict(
            {**self.request.to_dict(), "handoff_id": "handoff-002", "source_agent_id": "codex", "target_agent_id": "claude-code", "delegation_depth": 2, "idempotency_key": "handoff-attempt-2"}
        )
        nested_source = verify_attestation(
            sign_attestation(
                AgentAttestation.from_dict(
                    {
                        "schema_version": "northstar.agent-attestation.v1",
                        "task_id": "task-001",
                        "thread_id": "thread-001",
                        "run_id": "run-001",
                        "actor_id": "actor-001",
                        "workspace_id": "workspace-001",
                        "policy_revision": "policy-1",
                        "agent_id": "codex",
                        "step_id": "implementation",
                        "trace_id": "trace-001",
                        "input_digest": "sha256:" + "1" * 64,
                        "capabilities": ["workspace:read", "workspace:write"],
                        "delegation_depth": 1,
                        "expires_at": 1_800,
                    }
                ),
                self.attestation_secret,
            ),
            self.attestation_secret,
            now=1_001,
        )
        nested = self._authorize_handoff(
            nested_request,
            parent_handoff=first_validated,
            source_attestation=nested_source,
            registry=self.registry,
            now=1_002,
            current_policy_revision="policy-1",
            secret=self.handoff_secret,
        )
        nested_validated = self._verify_handoff_grant(nested, self.handoff_secret, now=1_003)
        self.assertTrue(nested_validated.ok, nested_validated.errors)
        self.assertEqual(len(nested_validated.grant.tombstones), 1)
        self.assertEqual(nested_validated.grant.tombstones[0]["grant_id"], "grant-publish")

    def test_a_carried_tombstone_must_name_the_action_it_revokes(self):
        with self.assertRaises(ValueError):
            self._authorize_handoff(
                self.request,
                parent_authorization=self.root,
                source_attestation=self.source,
                registry=self.registry,
                now=1_000,
                current_policy_revision="policy-1",
                secret=self.handoff_secret,
                tombstones=[{"declarer": PRINCIPAL, "declarer_channel": CHAT}],
            )
