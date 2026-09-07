import tempfile
import unittest
from pathlib import Path
from evidence_bundle import EvidenceError, EvidenceBundle, build_bundle, make_proof, verify_proof

class EvidenceBundleTests(unittest.TestCase):
    def events(self):
        return [{"schema_version":"northstar.route-lineage.v2","sequence":i+1,"event_id":f"e{i}","route_id":"r1","receipt_id":f"receipt-{i}","status":"succeeded","target_agent_id":"codex","provider":"openai","decision_fingerprint":"sha256:"+'b'*64,"payload_digest":"sha256:"+str(i).zfill(64)} for i in range(3)]
    def test_deterministic_root_and_order_sensitivity(self):
        first=build_bundle(self.events()); second=build_bundle(self.events())
        self.assertEqual(first.root_digest,second.root_digest)
        self.assertNotEqual(first.root_digest,build_bundle(list(reversed(self.events()))).root_digest)
    def test_empty_bundle_is_rejected(self):
        with self.assertRaises(EvidenceError): build_bundle([])
    def test_proof_round_trip_and_tamper_rejection(self):
        events=self.events(); bundle=build_bundle(events); proof=make_proof(bundle,1)
        verify_proof(bundle,events[1],proof)
        with self.assertRaises(EvidenceError): verify_proof(bundle,{**events[1],"status":"failed"},proof)
    def test_wrong_index_and_count_fail_closed(self):
        events=self.events(); bundle=build_bundle(events); proof=make_proof(bundle,1)
        with self.assertRaises(EvidenceError): verify_proof(bundle,events[0],proof)
        with self.assertRaises(EvidenceError): verify_proof(EvidenceBundle(bundle.root_digest,99,bundle.schema_version,bundle.leaf_digests),events[1],proof)
    def test_serialization_round_trip(self):
        bundle=build_bundle(self.events()); self.assertEqual(EvidenceBundle.from_dict(bundle.to_dict()),bundle)

if __name__=='__main__': unittest.main()
