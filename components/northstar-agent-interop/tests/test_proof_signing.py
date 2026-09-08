import unittest
from evidence_proof import ProofAttestation, make_proof_attestation
from proof_signing import ProofSignatureError, SignedProofAttestation, sign_attestation, verify_signed_attestation
from test_evidence_proof import ProofTests

class ProofSigningTests(unittest.TestCase):
    def setUp(self):
        self.data=ProofTests().setup_data()
        self.attestation=make_proof_attestation(*self.data)
        self.keys={'k1':b'first-key-for-proof-signing-32bytes','k2':b'rotated-key-for-proof-signing-32b'}
    def test_sign_and_verify_attestation_without_secret_in_payload(self):
        signed=sign_attestation(self.attestation,key_id='k1',secret=self.keys['k1'])
        verified=verify_signed_attestation(signed,key_resolver=lambda key_id:self.keys.get(key_id))
        self.assertEqual(verified,self.attestation)
        self.assertNotIn('first-key',repr(signed.to_dict()))
    def test_tamper_is_rejected(self):
        signed=sign_attestation(self.attestation,key_id='k1',secret=self.keys['k1'])
        tampered=SignedProofAttestation(signed.schema_version,signed.key_id,signed.signature,
                                        {**signed.attestation,'route_id':'other'})
        with self.assertRaises(ProofSignatureError): verify_signed_attestation(tampered,key_resolver=lambda _:self.keys['k1'])
    def test_unknown_key_and_rotation_policy_fail_closed(self):
        signed=sign_attestation(self.attestation,key_id='old',secret=b'old-proof-key-32-bytes-long-enough')
        with self.assertRaises(ProofSignatureError): verify_signed_attestation(signed,key_resolver=lambda _:None)
        rotated=sign_attestation(self.attestation,key_id='k2',secret=self.keys['k2'])
        with self.assertRaises(ProofSignatureError): verify_signed_attestation(rotated,key_resolver=lambda _:self.keys['k2'],expected_key_id='k1')
    def test_attestation_schema_is_strict(self):
        signed=sign_attestation(self.attestation,key_id='k1',secret=self.keys['k1'])
        with self.assertRaises(ProofSignatureError): SignedProofAttestation.from_dict({**signed.to_dict(),'extra':True})

    def test_inner_attestation_fields_are_strict(self):
        signed=sign_attestation(self.attestation,key_id='k1',secret=self.keys['k1'])
        with self.assertRaises(ProofSignatureError):
            SignedProofAttestation.from_dict({**signed.to_dict(),"attestation":{**signed.attestation,"extra":True}})
        with self.assertRaises(ProofSignatureError):
            SignedProofAttestation.from_dict({**signed.to_dict(),"attestation":{**signed.attestation,"proof_digest":"bad"}})

    def test_malformed_signature_and_resolver_failure_are_rejected(self):
        signed=sign_attestation(self.attestation,key_id='k1',secret=self.keys['k1'])
        with self.assertRaises(ProofSignatureError):
            verify_signed_attestation(SignedProofAttestation(signed.schema_version,signed.key_id,"not-base64",signed.attestation),key_resolver=lambda _:self.keys['k1'])
        def broken(_): raise RuntimeError("resolver failed")
        with self.assertRaises(ProofSignatureError): verify_signed_attestation(signed,key_resolver=broken)

if __name__=='__main__': unittest.main()
