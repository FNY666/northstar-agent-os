import tempfile
import unittest
from pathlib import Path
from evidence_bundle import EvidenceError, build_lineage_bundle, verify_lineage_bundle
from route_lineage import LineageGraph, RouteLineageEvent

class LineageBundleTests(unittest.TestCase):
    def events(self):
        return [RouteLineageEvent.from_dict({'schema_version':'northstar.route-lineage.v2','sequence':i+1,'prev_event_digest':'0'*64 if i==0 else '0'*64,'event_id':f'e{i}','route_id':'r1','parent_event_id':None,'receipt_id':f'receipt-{i}','status':'planned','target_agent_id':'codex','provider':'openai','capabilities':['workspace:read'],'deadline_at':90,'payload_digest':'sha256:'+'a'*64,'decision_fingerprint':'sha256:'+'b'*64,'retryable':False}) for i in range(2)]
    def test_bundle_binds_lineage_identity_and_terminal_digest(self):
        events=self.events(); bundle=build_lineage_bundle(events)
        verify_lineage_bundle(bundle,events)
        with self.assertRaises(EvidenceError): verify_lineage_bundle(bundle,[dict(events[0].to_dict(),route_id='r2'),events[1]])
    def test_sequence_or_terminal_status_change_fails(self):
        events=self.events(); bundle=build_lineage_bundle(events)
        with self.assertRaises(EvidenceError): verify_lineage_bundle(bundle,[events[0],RouteLineageEvent.from_dict({**events[1].to_dict(),'status':'failed'})])
    def test_bundle_serialization_round_trip(self):
        events=self.events(); bundle=build_lineage_bundle(events)
        self.assertEqual(type(bundle).from_dict(bundle.to_dict()),bundle)

if __name__=='__main__': unittest.main()
