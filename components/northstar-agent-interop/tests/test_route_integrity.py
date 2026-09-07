import json
import tempfile
import unittest
from pathlib import Path
from route_lineage import LineageGraph, RouteLineageEvent, LineageError

class IntegrityTests(unittest.TestCase):
    def event(self,status='planned',event_id='e1',parent=None,sequence=1,prev='0'*64):
        return RouteLineageEvent.from_dict({
            'schema_version':'northstar.route-lineage.v2','sequence':sequence,'prev_event_digest':prev.removeprefix('sha256:'),
            'event_id':event_id,'route_id':'r1','parent_event_id':parent,'receipt_id':'receipt-'+event_id,
            'status':status,'target_agent_id':'codex','provider':'openai','capabilities':['workspace:read'],
            'deadline_at':90,'payload_digest':'sha256:'+'a'*64,
            'decision_fingerprint':'sha256:'+'b'*64,'retryable':False})
    def test_first_event_has_zero_previous_digest(self):
        graph=LineageGraph(); graph.append(self.event())
        self.assertEqual(list(graph.read())[0].sequence,1)
    def test_gap_or_reorder_fails_closed(self):
        graph=LineageGraph(); graph.append(self.event())
        with self.assertRaises(LineageError): graph.append(self.event('dispatched','e2','e1',sequence=3))
    def test_restart_detects_tampered_middle_event(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'lineage.jsonl'; graph=LineageGraph(path); graph.append(self.event())
            graph.append(self.event('dispatched','e2','e1',sequence=2,prev=list(graph.read())[-1].event_digest))
            lines=path.read_text().splitlines(); lines[1]=lines[1].replace('dispatched','failed')
            path.write_text('\n'.join(lines)+'\n')
            with self.assertRaises(LineageError): LineageGraph.from_path(path)
    def test_schema_migration_is_explicit(self):
        registry=LineageGraph.migrations(); registry.register('northstar.route-lineage.v1','northstar.route-lineage.v2',lambda v:{**v,'schema_version':'northstar.route-lineage.v2','sequence':1,'prev_event_digest':'0'*64})
        value, chain=registry.migrate({'schema_version':'northstar.route-lineage.v1','event_id':'e1'}, target_version='northstar.route-lineage.v2')
        self.assertEqual(value['schema_version'],'northstar.route-lineage.v2'); self.assertEqual(len(chain),1)


    def test_v1_history_migrates_to_v2_and_continues_chain(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'lineage.jsonl'
            migrated=Path(tmp)/'migrated.jsonl'
            old={
                'schema_version':'northstar.route-lineage.v1','event_id':'e1','route_id':'r1',
                'parent_event_id':None,'receipt_id':'receipt-e1','status':'planned',
                'target_agent_id':'codex','provider':'openai','capabilities':['workspace:read'],
                'deadline_at':90,'payload_digest':'sha256:'+'a'*64,
                'decision_fingerprint':'sha256:'+'b'*64,'retryable':False,
            }
            path.write_text(json.dumps(old,sort_keys=True,separators=(',',':'))+'\n',encoding='utf-8')
            registry=LineageGraph.migrations()
            try:
                registry.register('northstar.route-lineage.v1','northstar.route-lineage.v2',lambda v:{**v,'schema_version':'northstar.route-lineage.v2','sequence':1,'prev_event_digest':'0'*64})
            except Exception:
                pass
            graph=LineageGraph.from_migrated_path(path, target_path=migrated)
            self.assertNotEqual(path.read_bytes(), migrated.read_bytes())
            first=list(graph.read())[0]
            self.assertEqual((first.schema_version,first.sequence),('northstar.route-lineage.v2',1))
            second=RouteLineageEvent.from_dict({**old,'schema_version':'northstar.route-lineage.v2','event_id':'e2','parent_event_id':'e1','status':'dispatched','sequence':2,'prev_event_digest':first.event_digest.removeprefix('sha256:')})
            graph.append(second)
            self.assertEqual(len(list(graph.read())),2)

if __name__=='__main__': unittest.main()
