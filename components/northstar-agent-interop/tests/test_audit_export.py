import tempfile
import unittest
from pathlib import Path
from audit_export import AuditExportError, AuditManifest, export_ndjson, sanitize_event, verify_export

class AuditExportTests(unittest.TestCase):
    def test_allowed_projection_excludes_raw_fields(self):
        value={"schema_version":"northstar.route-lineage.v2","sequence":1,"event_digest":"sha256:"+'a'*64,"event_id":"e1","route_id":"r1","receipt_id":"receipt-1","status":"succeeded","target_agent_id":"codex","provider":"openai","failure_class":None,"policy_revision":"p1","prompt":"secret"}
        with self.assertRaises(AuditExportError): sanitize_event(value)
    def test_export_manifest_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/"audit.ndjson"; event={"schema_version":"northstar.route-lineage.v2","sequence":1,"event_digest":"sha256:"+'a'*64,"event_id":"e1","route_id":"r1","receipt_id":"receipt-1","status":"succeeded","target_agent_id":"codex","provider":"openai","failure_class":None,"policy_revision":"p1"}
            manifest=export_ndjson([event],path)
            verify_export(path,manifest)
            self.assertEqual(AuditManifest.from_dict(manifest.to_dict()),manifest)
    def test_tampered_export_fails_verification(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/"audit.ndjson"; manifest=export_ndjson([{"schema_version":"northstar.route-lineage.v2","sequence":1,"event_digest":"sha256:"+'a'*64,"event_id":"e1","route_id":"r1","receipt_id":"receipt-1","status":"failed","target_agent_id":"codex","provider":"openai","failure_class":"cooldown","policy_revision":"p1"}],path)
            path.write_text(path.read_text().replace('cooldown','unhealthy'),encoding='utf-8')
            with self.assertRaises(AuditExportError): verify_export(path,manifest)

    def test_lineage_event_projection_is_sanitized_and_verifiable(self):
        from route_lineage import RouteLineageEvent
        event=RouteLineageEvent.from_dict({'schema_version':'northstar.route-lineage.v2','sequence':1,'prev_event_digest':'0'*64,'event_id':'e1','route_id':'r1','parent_event_id':None,'receipt_id':'receipt-1','status':'succeeded','target_agent_id':'codex','provider':'openai','capabilities':['workspace:read'],'deadline_at':90,'payload_digest':'sha256:'+'a'*64,'decision_fingerprint':'sha256:'+'b'*64,'retryable':False})
        with tempfile.TemporaryDirectory() as tmp:
            manifest=export_ndjson([event.to_dict()],Path(tmp)/'audit.ndjson')
            verify_export(Path(tmp)/'audit.ndjson',manifest)

if __name__=='__main__': unittest.main()
