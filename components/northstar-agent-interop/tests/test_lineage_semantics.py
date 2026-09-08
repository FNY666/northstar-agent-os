import unittest
from route_lineage import LineageGraph, RouteLineageEvent, verify_lineage, active_attempts

class SemanticLineageTests(unittest.TestCase):
    def event(self,event_id,status='planned',parent=None,receipt=None,retryable=False,target='codex'):
        return RouteLineageEvent.from_dict({'schema_version':'northstar.route-lineage.v1','event_id':event_id,'route_id':'r1','parent_event_id':parent,'receipt_id':receipt or 'receipt-'+event_id,'status':status,'target_agent_id':target,'provider':'openai','capabilities':['workspace:read'],'deadline_at':90,'payload_digest':'sha256:'+'a'*64,'decision_fingerprint':'sha256:'+'b'*64,'retryable':retryable})
    def setUp(self): self.events=[]
    def test_retry_child_is_active_not_superseded_parent(self):
        graph=LineageGraph(); root=self.event('e1'); self.events.append(root); graph.append(root); dispatched=self.event('e2','dispatched','e1'); self.events.append(dispatched); graph.append(dispatched); failed=self.event('e3','failed','e2',retryable=True); self.events.append(failed); graph.append(failed); retry=self.event('e4','planned','e3'); self.events.append(retry); graph.append(retry); dispatched2=self.event('e5','dispatched','e4'); self.events.append(dispatched2); graph.append(dispatched2); done=self.event('e6','succeeded','e5'); graph.append(done)
        self.assertEqual(len(active_attempts(graph,'r1')),1)
        self.assertEqual(verify_lineage(graph,route_record={'selected_agent_id':'codex','selected_provider':'openai','deadline_at':90,'decision_fingerprint':'sha256:'+'b'*64,'payload_digest':'sha256:'+'a'*64},handoff={'target_agent_id':'codex','provider':'openai','deadline_at':90,'decision_fingerprint':'sha256:'+'b'*64,'payload_digest':'sha256:'+'a'*64,'capabilities':['workspace:read']}).verdict,'verified')
    def test_two_active_terminal_branches_are_unknown(self):
        graph=LineageGraph(); graph.append(self.event('e1')); graph.append(self.event('e2','dispatched','e1')); graph.append(self.event('e3','succeeded','e2')); graph.append(self.event('e4','dispatched','e1')); self.assertEqual(verify_lineage(graph,route_record={},handoff={}).verdict,'unknown')
    def test_replay_is_not_a_new_execution_success(self):
        graph=LineageGraph(); graph.append(self.event('e1')); graph.append(self.event('e2','dispatched','e1')); graph.append(self.event('e3','succeeded','e2')); graph.append(self.event('e4','replayed','e3')); self.assertEqual(verify_lineage(graph,route_record={},handoff={}).verdict,'unknown')

if __name__=='__main__': unittest.main()
