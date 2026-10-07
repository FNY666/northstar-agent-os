"""Tests for a2a_gates: sabotage detection, turf-war detection, A2AGate."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from a2a_gates import (
    A2A_GATES_VERSION,
    ALLOW,
    DENY_SABOTAGE,
    DENY_TURF_WAR,
    A2AError,
    A2AGate,
    HandoffRecord,
    ResourceRegistry,
    a2a_gate_audit_events,
    default_registry,
    detect_sabotage,
    detect_turf_war,
    reset_default_registry,
)


def handoff(agent, action_type="", target="", claims=None, instruction=None):
    h = {"agent": agent, "action_type": action_type, "target": target}
    if claims is not None:
        h["claims"] = claims
    if instruction is not None:
        h["instruction"] = instruction
    return h


def entry(agent, action_type, target, claims=None, seq=0):
    e = {"agent": agent, "action_type": action_type, "target": target, "seq": seq}
    if claims is not None:
        e["claims"] = claims
    return e


class DetectSabotageTests(unittest.TestCase):
    def test_undo_pair_delete_after_create_is_sabotage(self):
        h = handoff("b", "delete", "artifact-1")
        hist = [entry("a", "create", "artifact-1")]
        self.assertTrue(detect_sabotage(h, hist))

    def test_undo_pair_either_direction(self):
        # create after delete also undoes the recorded work
        h = handoff("b", "create", "artifact-1")
        hist = [entry("a", "delete", "artifact-1")]
        self.assertTrue(detect_sabotage(h, hist))

    def test_undo_pair_different_target_is_fine(self):
        h = handoff("b", "delete", "artifact-2")
        hist = [entry("a", "create", "artifact-1")]
        self.assertFalse(detect_sabotage(h, hist))

    def test_same_agent_undo_is_revision_not_sabotage(self):
        h = handoff("a", "delete", "artifact-1")
        hist = [entry("a", "create", "artifact-1")]
        self.assertFalse(detect_sabotage(h, hist))

    def test_non_undo_pair_is_fine(self):
        h = handoff("b", "read", "artifact-1")
        hist = [entry("a", "create", "artifact-1")]
        self.assertFalse(detect_sabotage(h, hist))

    def test_contradictory_claims_is_sabotage(self):
        h = handoff("b", "notify", "t", claims={"approved": True})
        hist = [entry("a", "review", "t", claims={"approved": False})]
        self.assertTrue(detect_sabotage(h, hist))

    def test_agreeing_claims_is_fine(self):
        h = handoff("b", "notify", "t", claims={"approved": True})
        hist = [entry("a", "review", "t", claims={"approved": True})]
        self.assertFalse(detect_sabotage(h, hist))

    def test_disjoint_claim_keys_are_fine(self):
        h = handoff("b", "notify", "t", claims={"color": "red"})
        hist = [entry("a", "review", "t", claims={"size": "big"})]
        self.assertFalse(detect_sabotage(h, hist))

    def test_none_claim_never_contradicts(self):
        h = handoff("b", "notify", "t", claims={"flag": None})
        hist = [entry("a", "review", "t", claims={"flag": False})]
        self.assertFalse(detect_sabotage(h, hist))

    def test_empty_history_is_fine(self):
        h = handoff("b", "delete", "artifact-1")
        self.assertFalse(detect_sabotage(h, []))

    def test_malformed_handoff_fails_closed(self):
        self.assertTrue(detect_sabotage("not-a-mapping", []))
        self.assertTrue(detect_sabotage({}, []))
        self.assertTrue(detect_sabotage({"agent": "  "}, []))

    def test_malformed_history_entries_are_skipped(self):
        h = handoff("b", "read", "t")
        hist = ["garbage", {"no-agent": True}]
        self.assertFalse(detect_sabotage(h, hist))

    def test_case_insensitive_action_match(self):
        h = handoff("b", "DELETE", "artifact-1")
        hist = [entry("a", "Create", "artifact-1")]
        self.assertTrue(detect_sabotage(h, hist))


class ResourceRegistryTests(unittest.TestCase):
    def test_claim_and_holder(self):
        reg = ResourceRegistry()
        self.assertTrue(reg.claim("a", "gpu-0", 0))
        self.assertEqual(reg.holder("gpu-0"), "a")

    def test_claim_held_by_other_refused(self):
        reg = ResourceRegistry()
        reg.claim("a", "gpu-0", 0)
        self.assertFalse(reg.claim("b", "gpu-0", 1))
        self.assertEqual(reg.holder("gpu-0"), "a")

    def test_reclaim_by_holder_is_idempotent(self):
        reg = ResourceRegistry()
        reg.claim("a", "gpu-0", 0)
        self.assertTrue(reg.claim("a", "gpu-0", 1))

    def test_release(self):
        reg = ResourceRegistry()
        reg.claim("a", "gpu-0", 0)
        self.assertTrue(reg.release("a", "gpu-0"))
        self.assertIsNone(reg.holder("gpu-0"))

    def test_release_by_other_refused(self):
        reg = ResourceRegistry()
        reg.claim("a", "gpu-0", 0)
        self.assertFalse(reg.release("b", "gpu-0"))
        self.assertEqual(reg.holder("gpu-0"), "a")

    def test_release_free_resource_ok(self):
        reg = ResourceRegistry()
        self.assertTrue(reg.release("a", "gpu-0"))

    def test_held_by(self):
        reg = ResourceRegistry()
        reg.claim("a", "gpu-1", 0)
        reg.claim("a", "gpu-0", 1)
        reg.claim("b", "db", 2)
        self.assertEqual(reg.held_by("a"), ("gpu-0", "gpu-1"))
        self.assertEqual(reg.held_by("b"), ("db",))

    def test_bad_inputs_raise(self):
        reg = ResourceRegistry()
        with self.assertRaises(A2AError):
            reg.claim("", "gpu-0", 0)
        with self.assertRaises(A2AError):
            reg.claim("a", "  ", 0)
        with self.assertRaises(A2AError):
            reg.claim("a", "gpu-0", -1)
        with self.assertRaises(A2AError):
            reg.claim("a", "gpu-0", True)


class DetectTurfWarTests(unittest.TestCase):
    def setUp(self):
        self.reg = ResourceRegistry()

    def test_free_resource_no_war(self):
        self.assertFalse(detect_turf_war("b", ["gpu-0"], self.reg))

    def test_held_by_other_is_war(self):
        self.reg.claim("a", "gpu-0", 0)
        self.assertTrue(detect_turf_war("b", ["gpu-0"], self.reg))

    def test_own_resource_no_war(self):
        self.reg.claim("b", "gpu-0", 0)
        self.assertFalse(detect_turf_war("b", ["gpu-0"], self.reg))

    def test_one_conflict_among_many_is_war(self):
        self.reg.claim("a", "db", 0)
        self.assertTrue(detect_turf_war("b", ["gpu-0", "db"], self.reg))

    def test_empty_requests_no_war(self):
        self.assertFalse(detect_turf_war("b", [], self.reg))

    def test_malformed_inputs_fail_closed(self):
        self.assertTrue(detect_turf_war("", ["gpu-0"], self.reg))
        self.assertTrue(detect_turf_war("b", [""], self.reg))
        self.assertTrue(detect_turf_war("b", None, self.reg))
        self.assertTrue(detect_turf_war("b", ["gpu-0"], "not-a-registry"))

    def test_default_registry_used_when_none(self):
        reset_default_registry()
        default_registry().claim("a", "gpu-9", 0)
        try:
            self.assertTrue(detect_turf_war("b", ["gpu-9"]))
            self.assertFalse(detect_turf_war("a", ["gpu-9"]))
        finally:
            reset_default_registry()


class A2AGateTests(unittest.TestCase):
    def test_allow_happy_path(self):
        gate = A2AGate("g1")
        verdict = gate.check_handoff("a", "b", {"action_type": "create", "target": "t1"})
        self.assertEqual(verdict, ALLOW)

    def test_sabotage_denied(self):
        gate = A2AGate("g1")
        # a does the work first (recorded under a)
        self.assertEqual(
            gate.check_handoff("x", "a", {"action_type": "create", "target": "t1"}), ALLOW
        )
        # b's handoff would undo a's work: sabotage
        verdict = gate.check_handoff("a", "b", {"action_type": "delete", "target": "t1"})
        self.assertEqual(verdict, DENY_SABOTAGE)

    def test_own_revision_is_allowed(self):
        gate = A2AGate("g1")
        gate.check_handoff("x", "b", {"action_type": "create", "target": "t1"})
        # b revising its own prior work is not sabotage
        self.assertEqual(
            gate.check_handoff("a", "b", {"action_type": "delete", "target": "t1"}), ALLOW
        )

    def test_sabotage_beats_turf_war(self):
        gate = A2AGate("g1")
        gate.check_handoff("x", "a", {"action_type": "create", "target": "t1"})
        gate.check_handoff("x", "y", {"resources": ["gpu-0"]})
        # undo of a's work + contested resource: sabotage wins
        verdict = gate.check_handoff(
            "a", "b", {"action_type": "delete", "target": "t1", "resources": ["gpu-0"]}
        )
        self.assertEqual(verdict, DENY_SABOTAGE)

    def test_turf_war_denied(self):
        gate = A2AGate("g1")
        gate.check_handoff("a", "b", {"resources": ["gpu-0"]})
        verdict = gate.check_handoff("a", "c", {"resources": ["gpu-0"]})
        self.assertEqual(verdict, DENY_TURF_WAR)

    def test_denied_handoff_claims_nothing_and_records_nothing(self):
        gate = A2AGate("g1")
        gate.check_handoff("x", "a", {"action_type": "create", "target": "t1"})
        n_before = len(gate.history())
        verdict = gate.check_handoff("a", "b", {"action_type": "delete", "target": "t1", "resources": ["db"]})
        self.assertEqual(verdict, DENY_SABOTAGE)
        self.assertEqual(len(gate.history()), n_before)
        self.assertIsNone(gate.registry.holder("db"))

    def test_allowed_handoff_claims_resources(self):
        gate = A2AGate("g1")
        gate.check_handoff("a", "b", {"resources": ["gpu-0", "db"]})
        self.assertEqual(gate.registry.holder("gpu-0"), "b")
        self.assertEqual(gate.registry.holder("db"), "b")

    def test_malformed_payload_denied(self):
        gate = A2AGate("g1")
        self.assertEqual(gate.check_handoff("a", "b", "nope"), DENY_SABOTAGE)
        self.assertEqual(gate.check_handoff("", "b", {}), DENY_SABOTAGE)
        self.assertEqual(gate.check_handoff("a", "", {}), DENY_SABOTAGE)
        self.assertEqual(
            gate.check_handoff("a", "b", {"resources": [""]}), DENY_SABOTAGE
        )

    def test_contradictory_claims_denied(self):
        gate = A2AGate("g1")
        self.assertEqual(
            gate.check_handoff(
                "a", "b", {"action_type": "review", "target": "t", "claims": {"approved": True}}
            ),
            ALLOW,
        )
        # b's recorded claim contradicts: sabotage at the gate level
        self.assertEqual(
            gate.check_handoff(
                "a", "c", {"action_type": "notify", "target": "t", "claims": {"approved": False}}
            ),
            DENY_SABOTAGE,
        )

    def test_agreeing_claims_allowed(self):
        gate = A2AGate("g1")
        gate.check_handoff(
            "a", "b", {"action_type": "review", "target": "t", "claims": {"approved": True}}
        )
        self.assertEqual(
            gate.check_handoff(
                "a", "c", {"action_type": "notify", "target": "t", "claims": {"approved": True}}
            ),
            ALLOW,
        )

    def test_history_chain_verifies(self):
        gate = A2AGate("g1")
        gate.check_handoff("a", "b", {"action_type": "create", "target": "t1"})
        gate.check_handoff("b", "c", {"action_type": "create", "target": "t2"})
        self.assertTrue(gate.verify_chain())
        self.assertEqual(len(gate.history()), 2)
        self.assertEqual(gate.history()[0].seq, 0)
        self.assertEqual(gate.history()[1].seq, 1)

    def test_release(self):
        gate = A2AGate("g1")
        gate.check_handoff("a", "b", {"resources": ["gpu-0"]})
        result = gate.release("b", ["gpu-0"])
        self.assertEqual(result, {"gpu-0": True})
        # now another agent may take it
        self.assertEqual(gate.check_handoff("a", "c", {"resources": ["gpu-0"]}), ALLOW)

    def test_release_by_other_refused(self):
        gate = A2AGate("g1")
        gate.check_handoff("a", "b", {"resources": ["gpu-0"]})
        result = gate.release("c", ["gpu-0"])
        self.assertEqual(result, {"gpu-0": False})

    def test_version_pin(self):
        self.assertEqual(A2A_GATES_VERSION, "a2a-gates.v1")


class AuditEventsTests(unittest.TestCase):
    def test_audit_event_shape(self):
        gate = A2AGate("g9")
        gate.check_handoff("a", "b", {"action_type": "create", "target": "t1", "resources": ["gpu-0"]})
        record = gate.history()[0]
        events = a2a_gate_audit_events(record, note="n")
        self.assertEqual(len(events), 1)
        ev = events[0]
        self.assertEqual(ev["event"], "a2a_gates.handoff_allowed")
        self.assertEqual(ev["from_agent"], "a")
        self.assertEqual(ev["to_agent"], "b")
        self.assertEqual(ev["record_digest"], record.record_digest())
        self.assertEqual(ev["a2a_gates_version"], A2A_GATES_VERSION)

    def test_audit_rejects_non_record(self):
        with self.assertRaises(A2AError):
            a2a_gate_audit_events({"not": "a record"})

    def test_record_digest_stable(self):
        gate = A2AGate("g9")
        gate.check_handoff("a", "b", {"action_type": "create", "target": "t1"})
        r = gate.history()[0]
        self.assertEqual(r.record_digest(), r.record_digest())
        self.assertTrue(r.record_digest().startswith("sha256:"))


class MainTests(unittest.TestCase):
    def test_main_runs(self):
        import io
        from contextlib import redirect_stdout

        import a2a_gates

        buf = io.StringIO()
        with redirect_stdout(buf):
            a2a_gates.main()
        self.assertIn("a2a-gates OK", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
