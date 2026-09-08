import tempfile
import unittest
from pathlib import Path
from evidence_bundle import build_bundle
from evidence_chain import ChainError, EvidenceCheckpoint, EvidenceChain, verify_chain

class EvidenceChainTests(unittest.TestCase):
    def bundle(self,n):
        return build_bundle([{"schema_version":"route.v2","sequence":n,"event_id":f"e{n}","route_id":"r1","status":"succeeded","target_agent_id":"codex","provider":"openai","decision_fingerprint":"sha256:"+'b'*64,"payload_digest":"sha256:"+str(n).zfill(64)}])
    def test_first_and_continuous_checkpoints(self):
        chain=EvidenceChain(); a=chain.append(self.bundle(1)); b=chain.append(self.bundle(2)); self.assertEqual((a.batch_sequence,b.batch_sequence),(1,2)); verify_chain(chain)
    def test_reorder_gap_and_root_tamper_fail_closed(self):
        chain=EvidenceChain(); chain.append(self.bundle(1)); chain.append(self.bundle(2)); items=list(chain.read())
        with self.assertRaises(ChainError): verify_chain(EvidenceChain.from_records([items[1],items[0]]))
        tampered=EvidenceCheckpoint(items[1].schema_version,items[1].batch_sequence,"sha256:"+'f'*64,items[1].current_root,items[1].evidence_count,'sha256:'+'0'*64)
        tampered=EvidenceCheckpoint(tampered.schema_version,tampered.batch_sequence,tampered.previous_root,tampered.current_root,tampered.evidence_count,tampered.computed_digest)
        with self.assertRaises(ChainError): verify_chain(EvidenceChain.from_records([items[0],tampered]))
    def test_schema_and_unknown_fields_rejected(self):
        with self.assertRaises(ChainError): EvidenceCheckpoint.from_dict({"schema_version":"other"})
    def test_file_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'chain.jsonl'; chain=EvidenceChain(path); chain.append(self.bundle(1)); restored=EvidenceChain.from_path(path); self.assertEqual(list(restored.read()),list(chain.read()))

if __name__=='__main__': unittest.main()
