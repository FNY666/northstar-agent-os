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

if __name__=='__main__': unittest.main()
