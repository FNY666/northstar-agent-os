"""Tests for the memory-provenance axis: the write boundary and a computable
revocation.

Every public name in ``memory_provenance`` is named by at least one test
here, and each test drives a **behaviour** rather than a line: the mutant
probe plants a fault in the module and these tests must notice it.

The behaviours pinned here:

* a record cannot be constructed without an origin and a source session;
* the origin decides the disposition -- tool output is never auto-promoted;
* a promotion costs a named approver and a justification;
* a revocation reaches every downstream memory, transitively;
* the graph traversal terminates on a cycle;
* the hash chain names the first bad row;
* a merge inherits the worst origin and refuses a cross-tenant input whole.
"""
from __future__ import annotations

import unittest

import memory_provenance as mp


def _record(memory_id="m1", text="a fact", origin=mp.Origin.USER_DIRECT,
            session="s-1", turn=1, user="u-1", parents=(), created="2026-11-24T00:00:00Z"):
    """A well-formed record, so each test varies exactly one thing."""
    return mp.MemoryRecord(
        memory_id=memory_id,
        text=text,
        origin=origin,
        source_session_id=session,
        source_turn=turn,
        user_id=user,
        parent_ids=parents,
        created_at=created,
    )


class MemoryRecordTests(unittest.TestCase):
    """The record is the invariant: provenance is mandatory."""

    def test_a_record_carries_its_origin_and_its_source_session(self):
        record = _record(origin=mp.Origin.TOOL_OUTPUT, session="s-9f2c", turn=14)
        self.assertIs(record.origin, mp.Origin.TOOL_OUTPUT)
        self.assertEqual("s-9f2c", record.source_session_id)
        self.assertEqual(14, record.source_turn)
        self.assertEqual("u-1", record.user_id)

    def test_a_record_without_an_origin_cannot_be_constructed(self):
        with self.assertRaises(mp.MemoryProvenanceError):
            mp.MemoryRecord(
                memory_id="m1", text="a fact", origin=None,
                source_session_id="s-1", source_turn=1, user_id="u-1",
            )

    def test_an_unknown_origin_name_is_refused(self):
        with self.assertRaises(mp.MemoryProvenanceError):
            _record(origin="from_the_future")

    def test_an_empty_memory_id_is_refused(self):
        with self.assertRaises(mp.MemoryProvenanceError):
            _record(memory_id="   ")

    def test_an_empty_source_session_is_refused(self):
        with self.assertRaises(mp.MemoryProvenanceError):
            _record(session="")

    def test_an_empty_user_id_is_refused(self):
        with self.assertRaises(mp.MemoryProvenanceError):
            _record(user="")

    def test_a_negative_source_turn_is_refused(self):
        with self.assertRaises(mp.MemoryProvenanceError):
            _record(turn=-1)

    def test_a_boolean_source_turn_is_refused(self):
        # ``True`` is an int in Python; a turn number of ``True`` is a bug.
        with self.assertRaises(mp.MemoryProvenanceError):
            _record(turn=True)

    def test_empty_text_is_refused(self):
        with self.assertRaises(mp.MemoryProvenanceError):
            _record(text="   ")

    def test_parent_ids_must_be_a_sequence_of_ids(self):
        with self.assertRaises(mp.MemoryProvenanceError):
            _record(parents="m0")
        with self.assertRaises(mp.MemoryProvenanceError):
            _record(parents=["ok", ""])

    def test_the_digest_pins_the_text(self):
        record = _record(text="hello")
        self.assertTrue(record.digest.startswith("sha256:"))
        self.assertEqual(record.digest, _record(text="hello").digest)
        self.assertNotEqual(record.digest, _record(text="hello!").digest)

    def test_the_record_is_immutable(self):
        record = _record()
        with self.assertRaises(Exception):
            record.text = "tampered"  # type: ignore[misc]


class OriginGradingTests(unittest.TestCase):
    """The origin decides the disposition.  No classifier is in the way."""

    def test_a_tool_output_is_quarantined(self):
        gate = mp.WriteGate(mp.ProvenanceLedger())
        decision = gate.submit(_record(origin=mp.Origin.TOOL_OUTPUT))
        self.assertTrue(decision.accepted)
        self.assertIs(mp.Disposition.QUARANTINED, decision.disposition)

    def test_a_user_direct_record_is_promoted(self):
        gate = mp.WriteGate(mp.ProvenanceLedger())
        decision = gate.submit(_record(origin=mp.Origin.USER_DIRECT))
        self.assertIs(mp.Disposition.PROMOTED, decision.disposition)

    def test_an_agent_summary_is_quarantined_by_default(self):
        # Northstar's rule: an agent's own conclusion is drawn from text it
        # may have been fed, so it does not land without a human.
        gate = mp.WriteGate(mp.ProvenanceLedger())
        decision = gate.submit(_record(origin=mp.Origin.AGENT_SUMMARY))
        self.assertIs(mp.Disposition.QUARANTINED, decision.disposition)

    def test_an_imported_record_is_quarantined(self):
        gate = mp.WriteGate(mp.ProvenanceLedger())
        decision = gate.submit(_record(origin=mp.Origin.IMPORTED))
        self.assertIs(mp.Disposition.QUARANTINED, decision.disposition)

    def test_only_user_direct_is_auto_promotable(self):
        self.assertEqual(frozenset({mp.Origin.USER_DIRECT}), mp.AUTO_PROMOTABLE)
        for origin in mp.Origin:
            if origin is mp.Origin.USER_DIRECT:
                continue
            self.assertNotIn(origin, mp.AUTO_PROMOTABLE, origin)

    def test_a_quarantined_record_is_not_in_the_preload_set(self):
        gate = mp.WriteGate(mp.ProvenanceLedger())
        gate.submit(_record(memory_id="m1", origin=mp.Origin.USER_DIRECT))
        gate.submit(_record(memory_id="m2", origin=mp.Origin.TOOL_OUTPUT))
        preloaded = [r.memory_id for r in gate.promoted("u-1")]
        self.assertEqual(["m1"], preloaded)

    def test_the_preload_set_is_per_tenant(self):
        gate = mp.WriteGate(mp.ProvenanceLedger())
        gate.submit(_record(memory_id="m1", user="u-1"))
        gate.submit(_record(memory_id="m2", user="u-2"))
        self.assertEqual(["m1"], [r.memory_id for r in gate.promoted("u-1")])
        self.assertEqual(["m2"], [r.memory_id for r in gate.promoted("u-2")])

    def test_a_duplicate_memory_id_is_refused(self):
        gate = mp.WriteGate(mp.ProvenanceLedger())
        gate.submit(_record(memory_id="m1"))
        again = gate.submit(_record(memory_id="m1", text="a different fact"))
        self.assertFalse(again.accepted)
        self.assertEqual("duplicate_memory_id", again.reason)
        # The first write is untouched: a duplicate cannot launder a second
        # origin onto an existing id.
        self.assertEqual("a fact", gate.get("m1").text)


class PromotionGateTests(unittest.TestCase):
    """Quarantine has an exit, and the exit costs a named human."""

    def test_a_quarantined_record_is_promoted_with_an_approver(self):
        gate = mp.WriteGate(mp.ProvenanceLedger())
        gate.submit(_record(memory_id="m1", origin=mp.Origin.TOOL_OUTPUT))
        result = gate.promote("m1", approver="rakz@example.com",
                               justification="verified against dashboards")
        self.assertTrue(result.promoted)
        self.assertEqual("promoted", result.reason)
        self.assertIs(mp.Disposition.PROMOTED, gate.disposition_of("m1"))

    def test_a_promotion_without_an_approver_is_refused(self):
        gate = mp.WriteGate(mp.ProvenanceLedger())
        gate.submit(_record(memory_id="m1", origin=mp.Origin.TOOL_OUTPUT))
        result = gate.promote("m1", approver="", justification="because")
        self.assertFalse(result.promoted)
        self.assertEqual("approver_required", result.reason)
        self.assertIs(mp.Disposition.QUARANTINED, gate.disposition_of("m1"))

    def test_a_promotion_without_a_justification_is_refused(self):
        gate = mp.WriteGate(mp.ProvenanceLedger())
        gate.submit(_record(memory_id="m1", origin=mp.Origin.TOOL_OUTPUT))
        result = gate.promote("m1", approver="u-1", justification="   ")
        self.assertFalse(result.promoted)
        self.assertEqual("justification_required", result.reason)
        self.assertIs(mp.Disposition.QUARANTINED, gate.disposition_of("m1"))

    def test_a_promotion_of_an_unknown_memory_is_refused(self):
        gate = mp.WriteGate(mp.ProvenanceLedger())
        result = gate.promote("nope", approver="u-1", justification="why")
        self.assertFalse(result.promoted)
        self.assertEqual("unknown_memory", result.reason)

    def test_a_promotion_of_an_already_promoted_record_is_a_no_op(self):
        gate = mp.WriteGate(mp.ProvenanceLedger())
        gate.submit(_record(memory_id="m1", origin=mp.Origin.USER_DIRECT))
        result = gate.promote("m1", approver="u-1", justification="why")
        self.assertFalse(result.promoted)
        self.assertEqual("already_promoted", result.reason)

    def test_a_revoked_record_can_never_be_promoted(self):
        gate = mp.WriteGate(mp.ProvenanceLedger())
        gate.submit(_record(memory_id="m1", origin=mp.Origin.TOOL_OUTPUT,
                            session="s-bad"))
        mp.revoke_session(gate, "s-bad")
        result = gate.promote("m1", approver="u-1", justification="please")
        self.assertFalse(result.promoted)
        self.assertEqual("revoked_cannot_be_promoted", result.reason)
        self.assertIs(mp.Disposition.REVOKED, gate.disposition_of("m1"))

    def test_a_promotion_writes_the_approver_and_the_justification_to_the_ledger(self):
        ledger = mp.ProvenanceLedger()
        gate = mp.WriteGate(ledger)
        gate.submit(_record(memory_id="m1", origin=mp.Origin.TOOL_OUTPUT))
        gate.promote("m1", approver="u-1", justification="checked the source")
        rows = ledger.events("MEMORY_PROMOTED")
        self.assertEqual(1, len(rows))
        self.assertEqual("u-1", rows[0].payload["approver"])
        self.assertEqual("checked the source", rows[0].payload["justification"])

    def test_a_refused_promotion_leaves_a_trail(self):
        ledger = mp.ProvenanceLedger()
        gate = mp.WriteGate(ledger)
        gate.submit(_record(memory_id="m1", origin=mp.Origin.TOOL_OUTPUT))
        gate.promote("m1", approver="", justification="x")
        rows = ledger.events("PROMOTION_REFUSED")
        self.assertEqual(1, len(rows))
        self.assertEqual("approver_required", rows[0].payload["reason"])


class LedgerChainTests(unittest.TestCase):
    """The chain is what makes a revocation claim checkable."""

    def test_an_intact_chain_verifies(self):
        ledger = mp.ProvenanceLedger()
        ledger.append("MEMORY_WRITTEN", {"memory_id": "m1"})
        ledger.append("MEMORY_WRITTEN", {"memory_id": "m2"})
        self.assertEqual((True, None), ledger.verify())

    def test_an_empty_chain_verifies(self):
        self.assertEqual((True, None), mp.ProvenanceLedger().verify())

    def test_a_tampered_row_makes_the_chain_fail_and_names_the_first_bad_index(self):
        ledger = mp.ProvenanceLedger()
        ledger.append("MEMORY_WRITTEN", {"memory_id": "m1"})
        ledger.append("MEMORY_WRITTEN", {"memory_id": "m2"})
        ledger.append("MEMORY_WRITTEN", {"memory_id": "m3"})
        ledger._mutate_for_test(1, {"memory_id": "M2"})
        ok, first_bad = ledger.verify()
        self.assertFalse(ok)
        self.assertEqual(1, first_bad)

    def test_a_tampered_first_row_is_reported_at_index_zero(self):
        ledger = mp.ProvenanceLedger()
        ledger.append("MEMORY_WRITTEN", {"memory_id": "m1"})
        ledger._mutate_for_test(0, {"memory_id": "M1"})
        ok, first_bad = ledger.verify()
        self.assertFalse(ok)
        self.assertEqual(0, first_bad)

    def test_a_deleted_row_breaks_the_chain(self):
        ledger = mp.ProvenanceLedger()
        ledger.append("MEMORY_WRITTEN", {"memory_id": "m1"})
        ledger.append("MEMORY_WRITTEN", {"memory_id": "m2"})
        ledger.append("MEMORY_WRITTEN", {"memory_id": "m3"})
        # Drop the FIRST row.  The survivor's prev_hash still points at the
        # dropped row's hash, so the chain no longer starts at genesis.
        ledger._rows = ledger._rows[1:]
        ok, first_bad = ledger.verify()
        self.assertFalse(ok)
        self.assertEqual(0, first_bad)

    def test_an_inserted_row_breaks_the_chain(self):
        ledger = mp.ProvenanceLedger()
        ledger.append("MEMORY_WRITTEN", {"memory_id": "m1"})
        ledger.append("MEMORY_WRITTEN", {"memory_id": "m2"})
        # Splice a row in without re-chaining it.
        ledger._rows.insert(
            1,
            mp.LedgerRow(seq=1, event="MEMORY_WRITTEN", payload={"memory_id": "x"},
                         prev_hash=ledger.head, row_hash="sha256:" + "0" * 64),
        )
        ok, first_bad = ledger.verify()
        self.assertFalse(ok)
        self.assertEqual(1, first_bad)

    def test_the_row_hash_covers_the_payload(self):
        a = mp.compute_row_hash(0, "E", {"x": 1}, mp.GENESIS_HASH)
        b = mp.compute_row_hash(0, "E", {"x": 2}, mp.GENESIS_HASH)
        self.assertNotEqual(a, b)

    def test_the_row_hash_covers_the_prev_hash(self):
        a = mp.compute_row_hash(0, "E", {"x": 1}, mp.GENESIS_HASH)
        b = mp.compute_row_hash(0, "E", {"x": 1}, "sha256:" + "0" * 64)
        self.assertNotEqual(a, b)

    def test_the_head_is_the_genesis_pin_for_an_empty_chain(self):
        self.assertEqual(mp.GENESIS_HASH, mp.ProvenanceLedger().head)

    def test_the_head_advances_with_each_append(self):
        ledger = mp.ProvenanceLedger()
        before = ledger.head
        row = ledger.append("MEMORY_WRITTEN", {"memory_id": "m1"})
        self.assertNotEqual(before, ledger.head)
        self.assertEqual(row.row_hash, ledger.head)


class ProvenanceGraphTests(unittest.TestCase):
    """``parent_ids`` is free JSON, not a foreign key.  So the traversal must
    survive a cycle and a dangling id."""

    def test_the_ancestors_of_a_node_are_reachable_up_the_edges(self):
        graph = mp.ProvenanceGraph([
            _record(memory_id="a", parents=()),
            _record(memory_id="b", parents=("a",)),
            _record(memory_id="c", parents=("b",)),
        ])
        self.assertEqual({"a", "b", "c"}, graph.ancestors("c"))
        self.assertEqual({"a"}, graph.ancestors("a"))

    def test_the_descendants_of_a_node_are_reachable_down_the_edges(self):
        graph = mp.ProvenanceGraph([
            _record(memory_id="a", parents=()),
            _record(memory_id="b", parents=("a",)),
            _record(memory_id="c", parents=("b",)),
        ])
        self.assertEqual({"a", "b", "c"}, graph.descendants("a"))
        self.assertEqual({"c"}, graph.descendants("c"))

    def test_a_cycle_in_the_parent_edges_terminates(self):
        # a -> b -> a.  A naive recursion never returns.
        graph = mp.ProvenanceGraph([
            _record(memory_id="a", parents=("b",)),
            _record(memory_id="b", parents=("a",)),
        ])
        self.assertEqual({"a", "b"}, graph.ancestors("a"))
        self.assertEqual({"a", "b"}, graph.descendants("a"))

    def test_a_self_parent_terminates(self):
        graph = mp.ProvenanceGraph([_record(memory_id="a", parents=("a",))])
        self.assertEqual({"a"}, graph.ancestors("a"))
        self.assertEqual({"a"}, graph.descendants("a"))

    def test_a_longer_cycle_terminates(self):
        graph = mp.ProvenanceGraph([
            _record(memory_id="a", parents=("c",)),
            _record(memory_id="b", parents=("a",)),
            _record(memory_id="c", parents=("b",)),
        ])
        self.assertEqual({"a", "b", "c"}, graph.ancestors("a"))

    def test_a_dangling_parent_is_tolerated(self):
        graph = mp.ProvenanceGraph([_record(memory_id="a", parents=("ghost",))])
        self.assertEqual({"a", "ghost"}, graph.ancestors("a"))

    def test_an_unknown_node_has_only_itself(self):
        graph = mp.ProvenanceGraph([_record(memory_id="a")])
        self.assertEqual({"ghost"}, graph.ancestors("ghost"))

    def test_the_graph_knows_its_nodes(self):
        graph = mp.ProvenanceGraph([_record(memory_id="a", parents=("b",))])
        self.assertEqual({"a", "b"}, graph.nodes())


class RevocationClosureTests(unittest.TestCase):
    """Revoking a session is computable, and the closure is transitive."""

    def test_revoking_a_session_revokes_the_records_it_wrote(self):
        gate = mp.WriteGate(mp.ProvenanceLedger())
        gate.submit(_record(memory_id="m1", session="s-bad"))
        gate.submit(_record(memory_id="m2", session="s-good"))
        tainted = mp.revoke_session(gate, "s-bad")
        self.assertEqual({"m1"}, tainted)
        self.assertIs(mp.Disposition.REVOKED, gate.disposition_of("m1"))
        self.assertIs(mp.Disposition.PROMOTED, gate.disposition_of("m2"))

    def test_the_closure_reaches_a_promoted_child(self):
        # A tool fact, promoted by a human, is still downstream of the
        # session that produced it.
        gate = mp.WriteGate(mp.ProvenanceLedger())
        gate.submit(_record(memory_id="m1", origin=mp.Origin.TOOL_OUTPUT,
                            session="s-bad"))
        gate.promote("m1", approver="u-1", justification="checked")
        tainted = mp.revoke_session(gate, "s-bad")
        self.assertEqual({"m1"}, tainted)
        self.assertIs(mp.Disposition.REVOKED, gate.disposition_of("m1"))

    def test_the_closure_reaches_a_merged_child(self):
        # m2 was derived from m1 by a merge.  Revoking m1's session must
        # revoke m2, even though m2 carries a different source session.
        gate = mp.WriteGate(mp.ProvenanceLedger())
        gate.submit(_record(memory_id="m1", origin=mp.Origin.USER_DIRECT,
                            session="s-bad"))
        gate.submit(_record(memory_id="m2", origin=mp.Origin.USER_DIRECT,
                            session="s-other", parents=("m1",)))
        tainted = mp.revoke_session(gate, "s-bad")
        self.assertEqual({"m1", "m2"}, tainted)

    def test_the_closure_is_transitive_over_a_three_link_promotion_chain(self):
        # A -> B -> C, each derived from the last.  Revoking A's session
        # revokes B and C.
        gate = mp.WriteGate(mp.ProvenanceLedger())
        gate.submit(_record(memory_id="A", session="s-bad"))
        gate.submit(_record(memory_id="B", session="s-bad", parents=("A",)))
        gate.submit(_record(memory_id="C", session="s-bad", parents=("B",)))
        tainted = mp.revoke_session(gate, "s-bad")
        self.assertEqual({"A", "B", "C"}, tainted)
        for memory_id in ("A", "B", "C"):
            self.assertIs(mp.Disposition.REVOKED, gate.disposition_of(memory_id))

    def test_the_closure_reaches_a_grandchild_through_a_middle_session(self):
        # C descends from B, and B descends from A, but C carries its own
        # clean session id.  The closure must follow the EDGES.
        gate = mp.WriteGate(mp.ProvenanceLedger())
        gate.submit(_record(memory_id="A", session="s-bad"))
        gate.submit(_record(memory_id="B", session="s-mid", parents=("A",)))
        gate.submit(_record(memory_id="C", session="s-clean", parents=("B",)))
        tainted = mp.revoke_session(gate, "s-bad")
        self.assertEqual({"A", "B", "C"}, tainted)

    def test_revoking_an_unknown_session_revokes_nothing(self):
        gate = mp.WriteGate(mp.ProvenanceLedger())
        gate.submit(_record(memory_id="m1", session="s-1"))
        self.assertEqual(set(), mp.revoke_session(gate, "s-unknown"))
        self.assertIs(mp.Disposition.PROMOTED, gate.disposition_of("m1"))

    def test_a_revocation_is_an_appended_event_and_not_a_deletion(self):
        ledger = mp.ProvenanceLedger()
        gate = mp.WriteGate(ledger)
        gate.submit(_record(memory_id="m1", session="s-bad"))
        mp.revoke_session(gate, "s-bad")
        rows = ledger.events("SESSION_REVOKED")
        self.assertEqual(1, len(rows))
        self.assertEqual(["m1"], rows[0].payload["tainted_memory_ids"])
        # The record is still there -- a revocation is not a deletion.
        self.assertIsNotNone(gate.get("m1"))
        self.assertEqual(1, len(gate.records()))
        self.assertEqual((True, None), ledger.verify())

    def test_the_taint_closure_computes_without_changing_anything(self):
        gate = mp.WriteGate(mp.ProvenanceLedger())
        gate.submit(_record(memory_id="m1", session="s-bad"))
        tainted = mp.taint_closure(gate, {"s-bad"})
        self.assertEqual({"m1"}, tainted)
        self.assertIs(mp.Disposition.PROMOTED, gate.disposition_of("m1"))

    def test_a_cycle_in_the_parent_edges_does_not_hang_the_closure(self):
        gate = mp.WriteGate(mp.ProvenanceLedger())
        gate.submit(_record(memory_id="A", session="s-bad", parents=("B",)))
        gate.submit(_record(memory_id="B", session="s-bad", parents=("A",)))
        tainted = mp.revoke_session(gate, "s-bad")
        self.assertEqual({"A", "B"}, tainted)


class MergeGateTests(unittest.TestCase):
    """A merge is a second promotion path, so it is a gate."""

    def _two_promoted(self):
        gate = mp.WriteGate(mp.ProvenanceLedger())
        gate.submit(_record(memory_id="m1", origin=mp.Origin.USER_DIRECT,
                            session="s-1"))
        gate.submit(_record(memory_id="m2", origin=mp.Origin.USER_DIRECT,
                            session="s-2"))
        return gate

    def test_a_merge_of_two_promoted_records_keeps_the_user_direct_origin(self):
        gate = self._two_promoted()
        merger = mp.MergeGate(gate)
        decision = merger.merge(
            ["m1", "m2"], "GCP and Terraform", user_id="u-1",
            memory_id="m3", source_session_id="s-consolidate",
        )
        self.assertTrue(decision.accepted)
        self.assertIs(mp.Origin.USER_DIRECT, decision.record.origin)
        self.assertIs(mp.Disposition.PROMOTED, decision.disposition)

    def test_a_merge_inherits_the_worst_input_origin(self):
        # The worst origin by risk order is the one the merged record gets.
        gate = mp.WriteGate(mp.ProvenanceLedger())
        gate.submit(_record(memory_id="m1", origin=mp.Origin.USER_DIRECT))
        gate.submit(_record(memory_id="m2", origin=mp.Origin.AGENT_SUMMARY))
        gate.promote("m2", approver="u-1", justification="checked")
        merger = mp.MergeGate(gate)
        decision = merger.merge(
            ["m1", "m2"], "merged", user_id="u-1", memory_id="m3",
            source_session_id="s-consolidate",
        )
        self.assertIs(mp.Origin.AGENT_SUMMARY, decision.record.origin)

    def test_a_merge_of_a_tool_output_is_quarantined_even_when_promoted(self):
        gate = mp.WriteGate(mp.ProvenanceLedger())
        gate.submit(_record(memory_id="m1", origin=mp.Origin.USER_DIRECT))
        gate.submit(_record(memory_id="m2", origin=mp.Origin.TOOL_OUTPUT))
        gate.promote("m2", approver="u-1", justification="checked")
        merger = mp.MergeGate(gate)
        decision = merger.merge(
            ["m1", "m2"], "merged", user_id="u-1", memory_id="m3",
            source_session_id="s-consolidate",
        )
        self.assertIs(mp.Origin.TOOL_OUTPUT, decision.record.origin)
        self.assertIs(mp.Disposition.QUARANTINED, decision.disposition)

    def test_a_cross_tenant_merge_is_refused_whole(self):
        gate = mp.WriteGate(mp.ProvenanceLedger())
        gate.submit(_record(memory_id="m1", user="u-1"))
        gate.submit(_record(memory_id="m2", user="u-2"))
        merger = mp.MergeGate(gate)
        decision = merger.merge(
            ["m1", "m2"], "merged", user_id="u-1", memory_id="m3",
            source_session_id="s-consolidate",
        )
        self.assertFalse(decision.accepted)
        self.assertEqual("cross_tenant_merge", decision.reason)
        # Whole: the good input did not go through either.
        self.assertIsNone(gate.get("m3"))

    def test_a_merge_of_a_quarantined_input_is_refused(self):
        gate = mp.WriteGate(mp.ProvenanceLedger())
        gate.submit(_record(memory_id="m1", origin=mp.Origin.USER_DIRECT))
        gate.submit(_record(memory_id="m2", origin=mp.Origin.TOOL_OUTPUT))
        merger = mp.MergeGate(gate)
        decision = merger.merge(
            ["m1", "m2"], "merged", user_id="u-1", memory_id="m3",
            source_session_id="s-consolidate",
        )
        self.assertFalse(decision.accepted)
        self.assertEqual("input_not_promotable:m2", decision.reason)

    def test_a_merge_of_a_revoked_input_is_refused(self):
        gate = mp.WriteGate(mp.ProvenanceLedger())
        gate.submit(_record(memory_id="m1", origin=mp.Origin.USER_DIRECT,
                            session="s-bad"))
        mp.revoke_session(gate, "s-bad")
        merger = mp.MergeGate(gate)
        decision = merger.merge(
            ["m1"], "merged", user_id="u-1", memory_id="m3",
            source_session_id="s-consolidate",
        )
        self.assertFalse(decision.accepted)
        self.assertEqual("input_not_promotable:m1", decision.reason)

    def test_a_merge_of_an_unknown_input_is_refused(self):
        gate = self._two_promoted()
        merger = mp.MergeGate(gate)
        decision = merger.merge(
            ["m1", "ghost"], "merged", user_id="u-1", memory_id="m3",
            source_session_id="s-consolidate",
        )
        self.assertFalse(decision.accepted)
        self.assertEqual("unknown_input:ghost", decision.reason)

    def test_a_merge_with_no_inputs_is_refused(self):
        gate = self._two_promoted()
        decision = mp.MergeGate(gate).merge(
            [], "merged", user_id="u-1", memory_id="m3",
            source_session_id="s-consolidate",
        )
        self.assertFalse(decision.accepted)
        self.assertEqual("no_inputs", decision.reason)

    def test_the_merged_record_names_its_parents(self):
        gate = self._two_promoted()
        decision = mp.MergeGate(gate).merge(
            ["m1", "m2"], "merged", user_id="u-1", memory_id="m3",
            source_session_id="s-consolidate",
        )
        self.assertEqual(("m1", "m2"), decision.record.parent_ids)

    def test_a_refused_merge_leaves_a_trail(self):
        ledger = mp.ProvenanceLedger()
        gate = mp.WriteGate(ledger)
        gate.submit(_record(memory_id="m1", user="u-1"))
        gate.submit(_record(memory_id="m2", user="u-2"))
        mp.MergeGate(gate).merge(
            ["m1", "m2"], "merged", user_id="u-1", memory_id="m3",
            source_session_id="s-consolidate",
        )
        rows = ledger.events("MERGE_REFUSED")
        self.assertEqual(1, len(rows))
        self.assertEqual("cross_tenant_merge", rows[0].payload["reason"])

    def test_a_merge_records_a_consolidation_row(self):
        ledger = mp.ProvenanceLedger()
        gate = mp.WriteGate(ledger)
        gate.submit(_record(memory_id="m1"))
        mp.MergeGate(gate).merge(
            ["m1"], "merged", user_id="u-1", memory_id="m3",
            source_session_id="s-consolidate",
        )
        rows = ledger.events("MEMORY_CONSOLIDATED")
        self.assertEqual(1, len(rows))
        self.assertEqual(["m1"], rows[0].payload["input_memory_ids"])

    def test_the_merge_rescan_records_the_markers_it_found(self):
        gate = mp.WriteGate(mp.ProvenanceLedger())
        gate.submit(_record(memory_id="m1", origin=mp.Origin.USER_DIRECT))
        merger = mp.MergeGate(gate)
        decision = merger.merge(
            ["m1"], "user_direct also matters", user_id="u-1",
            memory_id="m3", source_session_id="s-consolidate",
        )
        self.assertIn("user_direct", decision.record.text)

    def test_a_merged_record_is_reachable_from_its_inputs(self):
        gate = self._two_promoted()
        merger = mp.MergeGate(gate)
        merger.merge(
            ["m1", "m2"], "merged", user_id="u-1", memory_id="m3",
            source_session_id="s-consolidate",
        )
        graph = mp.ProvenanceGraph(gate.records())
        self.assertIn("m3", graph.descendants("m1"))


class NoClockTests(unittest.TestCase):
    """No timestamp in this module comes from the machine."""

    def test_a_record_carries_the_timestamp_its_caller_gave_it(self):
        record = _record(created="2026-11-24T12:34:56Z")
        self.assertEqual("2026-11-24T12:34:56Z", record.created_at)
        self.assertEqual("2026-11-24T12:34:56Z", record.to_dict()["created_at"])

    def test_two_records_with_different_timestamps_keep_them(self):
        first = _record(memory_id="m1", created="2020-01-01T00:00:00Z")
        second = _record(memory_id="m2", created="2030-12-31T23:59:59Z")
        self.assertEqual("2020-01-01T00:00:00Z", first.created_at)
        self.assertEqual("2030-12-31T23:59:59Z", second.created_at)

    def test_a_non_string_timestamp_is_refused(self):
        with self.assertRaises(mp.MemoryProvenanceError):
            _record(created=1700000000)

    def test_the_ledger_row_carries_no_timestamp_of_its_own(self):
        ledger = mp.ProvenanceLedger()
        row = ledger.append("MEMORY_WRITTEN", {"memory_id": "m1"})
        self.assertNotIn("ts", row.to_dict())
        self.assertNotIn("timestamp", row.to_dict())

    def test_the_module_does_not_import_time(self):
        import ast
        import os
        path = os.path.join(os.path.dirname(mp.__file__), "memory_provenance.py")
        with open(path, "r", encoding="utf-8") as handle:
            tree = ast.parse(handle.read(), filename=path)
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported |= {alias.name.split(".")[0] for alias in node.names}
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
        self.assertNotIn("time", imported)
        self.assertNotIn("datetime", imported)

    def test_the_module_is_stdlib_only(self):
        self.assertTrue(mp.stdlib_only())


class RegistrationTests(unittest.TestCase):
    """A new module must be registered in both places, or it vanishes from
    the installed wheel."""

    def test_the_module_is_registered_in_the_runtime_registry(self):
        import runtime_registration as rr
        self.assertIn("memory_provenance", rr.registered_module_names())

    def test_the_module_is_declared_in_py_modules(self):
        import tomllib
        from pathlib import Path
        pyproject = Path(mp.__file__).resolve().parent / "pyproject.toml"
        data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
        self.assertIn("memory_provenance",
                      data["tool"]["setuptools"]["py-modules"])

    def test_the_registration_matches_the_disk(self):
        import runtime_registration as rr
        rr.assert_registration_matches_disk()

    def test_the_registry_and_py_modules_and_the_disk_agree(self):
        import runtime_registration as rr
        registered = set(rr.registered_module_names())
        import tomllib
        from pathlib import Path
        pyproject = Path(mp.__file__).resolve().parent / "pyproject.toml"
        data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
        declared = set(data["tool"]["setuptools"]["py-modules"])
        on_disk = {p.stem for p in Path(mp.__file__).resolve().parent.glob("*.py")
                   if not p.name.startswith("test_")}
        self.assertIn("memory_provenance", registered & declared & on_disk)


class FrontierRegistryTests(unittest.TestCase):
    """The survey's rank-1 source is now implemented."""

    def test_the_survey_row_is_marked_implemented(self):
        from frontier_registry import SEED_ENTRIES
        row = next(e for e in SEED_ENTRIES
                   if e.source_url == "https://arxiv.org/abs/2606.30306")
        self.assertEqual("implemented", row.status)
        self.assertEqual("memory-provenance-axis", row.linked_slice)

    def test_the_sentinel_mem_row_is_marked_implemented(self):
        from frontier_registry import SEED_ENTRIES
        row = next(e for e in SEED_ENTRIES
                   if e.source_url == "https://github.com/rajesamp/sentinel-mem")
        self.assertEqual("implemented", row.status)
        self.assertEqual("memory-provenance-axis", row.linked_slice)
