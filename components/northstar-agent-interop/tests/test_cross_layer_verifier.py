import unittest
from cross_layer_verifier import CrossLayerError, verify_cross_layer

class CrossLayerTests(unittest.TestCase):
    def base(self):
        identity={'route_id':'r1','target_agent_id':'codex','provider':'openai','deadline_at':80,'decision_fingerprint':'sha256:'+'b'*64,'payload_digest':'sha256:'+'a'*64}
        return identity
    def test_matching_layers_are_verified(self):
        identity=self.base(); result=verify_cross_layer(identity,identity,identity,identity); self.assertEqual(result.verdict,'verified')
    def test_identity_digest_or_deadline_mismatch_is_unknown(self):
        identity=self.base(); bad=dict(identity, target_agent_id='claude'); self.assertEqual(verify_cross_layer(identity,bad,identity,identity).verdict,'unknown')
        bad=dict(identity, payload_digest='sha256:'+'c'*64); self.assertEqual(verify_cross_layer(identity,identity,bad,identity).verdict,'unknown')
        bad=dict(identity, deadline_at=100); self.assertEqual(verify_cross_layer(identity,identity,identity,bad).verdict,'unknown')
    def test_missing_layer_is_unknown_not_success(self):
        identity=self.base(); self.assertEqual(verify_cross_layer(identity,None,identity,identity).verdict,'unknown')

if __name__=='__main__': unittest.main()
