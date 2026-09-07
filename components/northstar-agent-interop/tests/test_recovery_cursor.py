import tempfile
import unittest
from pathlib import Path
from recovery_cursor import RecoveryCursor, Lease, LeaseManager, RecoveryError

class RecoveryCursorTests(unittest.TestCase):
    def test_cursor_rejects_invalid_digest_and_sequence(self):
        with self.assertRaises(RecoveryError): RecoveryCursor.from_dict({'sequence':0,'event_digest':'bad','schema_version':'v2','journal_digest':'bad'})
    def test_lease_acquire_heartbeat_and_expiry(self):
        manager=LeaseManager()
        lease=manager.acquire('owner-a',now=100,ttl=10)
        self.assertEqual(lease.fencing_token,1)
        renewed=manager.heartbeat(lease,now=105,ttl=10)
        self.assertGreater(renewed.expires_at,lease.expires_at)
        with self.assertRaises(RecoveryError): manager.validate(renewed,now=116)
    def test_stale_owner_and_fencing_fail_closed(self):
        manager=LeaseManager(); first=manager.acquire('a',now=100,ttl=10); second=manager.acquire('b',now=111,ttl=10)
        self.assertGreater(second.fencing_token,first.fencing_token)
        with self.assertRaises(RecoveryError): manager.validate(first,now=112)


    def test_persisted_manager_increments_token_after_restart(self):
        from recovery_cursor import PersistentLeaseManager
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'lease.json'
            first=PersistentLeaseManager(path).acquire('a',now=1,ttl=1)
            second=PersistentLeaseManager(path).acquire('b',now=3,ttl=10)
            self.assertGreater(second.fencing_token,first.fencing_token)
            with self.assertRaises(RecoveryError): PersistentLeaseManager(path).validate(first,now=3)

    def test_concurrent_acquire_has_unique_monotonic_tokens(self):
        import multiprocessing
        from recovery_cursor import PersistentLeaseManager
        with tempfile.TemporaryDirectory() as tmp:
            path=str(Path(tmp)/'lease.json')
            def acquire(owner):
                manager=PersistentLeaseManager(path)
                try: manager.acquire(owner,now=100,ttl=1)
                except RecoveryError: pass
            workers=[multiprocessing.Process(target=acquire,args=(f'o{i}',)) for i in range(2)]
            for p in workers:p.start()
            for p in workers:p.join(5)
            self.assertTrue(all(p.exitcode==0 for p in workers))
            self.assertEqual(PersistentLeaseManager(path).read().fencing_token,1)

    def test_persistent_heartbeat_renews_without_changing_fence(self):
        from recovery_cursor import PersistentLeaseManager
        with tempfile.TemporaryDirectory() as tmp:
            manager=PersistentLeaseManager(Path(tmp)/'lease.json')
            lease=manager.acquire('owner',now=10,ttl=5)
            renewed=manager.heartbeat(lease,now=12,ttl=20)
            self.assertEqual(renewed.fencing_token,lease.fencing_token)
            self.assertEqual(renewed.expires_at,32)
            manager.validate(renewed,now=31)

if __name__=='__main__': unittest.main()
