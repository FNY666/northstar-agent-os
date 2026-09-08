import tempfile
import unittest
from pathlib import Path
from evidence_bundle import build_bundle
from evidence_chain import ChainError, EvidenceChain, verify_chain

class EvidenceRecoveryTests(unittest.TestCase):
    def bundle(self,n):
        return build_bundle([{"schema_version":"route.v2","sequence":n,"event_id":f"e{n}","route_id":"r1","status":"succeeded","target_agent_id":"codex","provider":"openai","decision_fingerprint":"sha256:"+'b'*64,"payload_digest":"sha256:"+str(n).zfill(64)}])
    def test_restart_preserves_checkpoint_chain(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'chain.jsonl'; chain=EvidenceChain(path); chain.append(self.bundle(1)); chain.append(self.bundle(2))
            restored=EvidenceChain.from_path(path); verify_chain(restored); self.assertEqual([x.batch_sequence for x in restored.read()],[1,2])
    def test_truncated_tail_is_incomplete_not_valid_chain(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'chain.jsonl'; chain=EvidenceChain(path); chain.append(self.bundle(1)); path.write_bytes(path.read_bytes()+b'{"broken":')
            with self.assertRaises(ChainError): EvidenceChain.from_path(path)
    def test_checkpoint_append_after_restart_keeps_previous_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'chain.jsonl'; chain=EvidenceChain(path); first=chain.append(self.bundle(1)); restored=EvidenceChain.from_path(path); second=restored.append(self.bundle(2)); self.assertEqual(second.previous_root,first.current_root); verify_chain(restored)

    def test_fenced_append_rejects_stale_owner(self):
        from recovery_cursor import PersistentLeaseManager, RecoveryError
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); path=root/'chain.jsonl'; lease_path=root/'lease.json'; manager=PersistentLeaseManager(lease_path); old=manager.acquire('old',now=1,ttl=1); new=PersistentLeaseManager(lease_path).acquire('new',now=3,ttl=10)
            chain=EvidenceChain(path)
            with self.assertRaises((ChainError,RecoveryError)): chain.append_fenced(self.bundle(1),old,now=3,lease_path=lease_path)
            self.assertGreater(new.fencing_token,old.fencing_token)

if __name__=='__main__': unittest.main()
