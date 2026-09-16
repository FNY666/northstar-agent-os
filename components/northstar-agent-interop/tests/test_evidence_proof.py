import unittest
from evidence_bundle import build_lineage_bundle, make_proof
from evidence_chain import EvidenceChain
from route_lineage import LineageGraph, RouteLineageEvent
from evidence_proof import ProofResult, verify_route_evidence_proof

class ProofTests(unittest.TestCase):
    def setup_data(self):
        event=RouteLineageEvent.from_dict({'schema_version':'northstar.route-lineage.v2','sequence':1,'prev_event_digest':'0'*64,'event_id':'e1','route_id':'r1','parent_event_id':None,'receipt_id':'receipt-1','status':'succeeded','target_agent_id':'codex','provider':'openai','capabilities':['workspace:read'],'deadline_at':90,'payload_digest':'sha256:'+'a'*64,'decision_fingerprint':'sha256:'+'b'*64,'retryable':False})
        lineage=LineageGraph(); lineage.append(event); bundle=build_lineage_bundle([event]); proof=make_proof(bundle,0); chain=EvidenceChain(); checkpoint=chain.append(bundle)
        identity={'route_id':'r1','selected_agent_id':'codex','selected_provider':'openai','deadline_at':90,'decision_fingerprint':'sha256:'+'b'*64,'payload_digest':'sha256:'+'a'*64}
        handoff={'route_id':'r1','target_agent_id':'codex','provider':'openai','deadline_at':90,'capabilities':['workspace:read'],'decision_fingerprint':'sha256:'+'b'*64,'payload_digest':'sha256:'+'a'*64}
        return identity,lineage,bundle,chain,event,proof,handoff
    def test_all_layers_verify(self):
        data=self.setup_data(); self.assertEqual(verify_route_evidence_proof(*data).verdict,'verified')
    def test_tampered_merkle_event_is_unknown(self):
        data=list(self.setup_data()); original=data[4]; changed=original.to_dict(); changed['status']='failed'; changed.pop('event_digest',None); data[4]=RouteLineageEvent.from_dict(changed); self.assertEqual(verify_route_evidence_proof(*data).verdict,'unknown')
    def test_failed_terminal_is_failed(self):
        data=list(self.setup_data()); graph=LineageGraph(); changed=data[4].to_dict(); changed['status']='failed'; changed.pop('event_digest',None); failed=RouteLineageEvent.from_dict(changed); graph.append(failed); data[1]=graph; self.assertEqual(verify_route_evidence_proof(*data).verdict,'unknown')
    def test_missing_handoff_is_unknown(self):
        data=list(self.setup_data()); data[-1]=None; self.assertEqual(verify_route_evidence_proof(*data).verdict,'unknown')

    def test_checkpoint_root_must_match_bundle_root(self):
        data=list(self.setup_data()); data[3]=EvidenceChain.from_records([])
        self.assertEqual(verify_route_evidence_proof(*data).verdict,'unknown')

    def test_verified_result_can_emit_bound_attestation(self):
        from evidence_proof import make_proof_attestation
        data=self.setup_data(); attestation=make_proof_attestation(*data)
        self.assertEqual(attestation.verdict,'verified')
        self.assertTrue(attestation.proof_digest.startswith('sha256:'))
        self.assertEqual(attestation.route_id,'r1')

    def test_failed_result_cannot_emit_verified_attestation(self):
        from evidence_proof import make_proof_attestation, ProofError
        data=list(self.setup_data()); data[-1]=None
        with self.assertRaises(ProofError): make_proof_attestation(*data)

    def test_cross_layer_gate_rejects_terminal_payload_mismatch(self):
        data = list(self.setup_data())
        event = data[4]
        changed = event.to_dict()
        changed["payload_digest"] = "sha256:" + "c" * 64
        changed.pop("event_digest", None)
        from route_lineage import LineageGraph
        graph = LineageGraph()
        graph.append(RouteLineageEvent.from_dict(changed))
        data[1] = graph
        from evidence_bundle import build_lineage_bundle, make_proof
        data[2] = build_lineage_bundle([graph.events["e1"]])
        data[3] = EvidenceChain()
        data[3].append(data[2])
        data[4] = graph.events["e1"]
        data[5] = make_proof(data[2], 0)
        self.assertEqual(verify_route_evidence_proof(*data).verdict, "unknown")

    def test_cross_layer_gate_rejects_lineage_route_mismatch(self):
        data = list(self.setup_data())
        event = data[4]
        changed = event.to_dict()
        changed["route_id"] = "other-route"
        changed.pop("event_digest", None)
        from route_lineage import LineageGraph
        graph = LineageGraph()
        graph.append(RouteLineageEvent.from_dict(changed))
        data[1] = graph
        from evidence_bundle import build_lineage_bundle, make_proof
        data[2] = build_lineage_bundle([graph.events["e1"]])
        data[3] = EvidenceChain()
        data[3].append(data[2])
        data[4] = graph.events["e1"]
        data[5] = make_proof(data[2], 0)
        self.assertEqual(verify_route_evidence_proof(*data).verdict, "unknown")

if __name__=='__main__': unittest.main()


class ProofLineageCoverageTests(ProofTests):
    def _graph_with_unaccounted_branch(self):
        from route_lineage import (
            INTEGRITY_SCHEMA, ZERO_DIGEST, LineageGraph, RouteLineageEvent,
        )
        def make(sequence, prev, event_id, status, parent):
            return RouteLineageEvent(
                schema_version=INTEGRITY_SCHEMA, event_id=event_id, route_id="r1",
                parent_event_id=parent, receipt_id="receipt-" + event_id,
                status=status, target_agent_id="codex", provider="openai",
                capabilities=("workspace:read",), deadline_at=90,
                payload_digest="sha256:" + "a" * 64,
                decision_fingerprint="sha256:" + "b" * 64, retryable=False,
                sequence=sequence, prev_event_digest=prev,
            )
        graph = LineageGraph()
        prev = ZERO_DIGEST
        for sequence, (event_id, status, parent) in enumerate(
            (("e1", "planned", None), ("e2", "dispatched", "e1"),
             ("e3", "dispatched", "e1"), ("e4", "succeeded", "e2")), start=1
        ):
            item = make(sequence, prev, event_id, status, parent)
            graph.append(item)
            prev = item.event_digest.removeprefix("sha256:")
        return graph

    def test_an_unaccounted_branch_is_not_verified_by_the_proof(self):
        from evidence_bundle import build_lineage_bundle, make_proof
        from evidence_chain import EvidenceChain
        data = list(self.setup_data())
        graph = self._graph_with_unaccounted_branch()
        terminal = graph.events["e4"]
        events = list(graph.read())
        data[1] = graph
        data[2] = build_lineage_bundle(events)
        chain = EvidenceChain(); chain.append(data[2]); data[3] = chain
        data[4] = terminal
        data[5] = make_proof(data[2], events.index(terminal))
        self.assertNotEqual(verify_route_evidence_proof(*data).verdict, "verified")
