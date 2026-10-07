"""Tests for confidential_vm.py (15 required)."""

import unittest

from confidential_vm import (
    MIN_TCB,
    PROVIDERS,
    SCHEMA_PIN,
    TCB_VERSIONS,
    VM_VERSION,
    AttestationReport,
    ConfidentialVM,
    ConfidentialVMError,
    VMInstance,
    VMReport,
    confidential_vm_audit_event,
    verify_attestation,
    main as cvm_main,
)


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(VM_VERSION, "confidential-vm.v1")
        self.assertEqual(ConfidentialVM.version, "confidential-vm.v1")

    def test_schema_pin(self):
        self.assertEqual(SCHEMA_PIN, "northstar.confidential-vm.v1")

    def test_providers(self):
        self.assertEqual(PROVIDERS, ("sev-snp", "tdx"))
        self.assertIn("sev-snp", TCB_VERSIONS)
        self.assertIn("tdx", TCB_VERSIONS)


class TestConstruction(unittest.TestCase):
    def test_provider_pinned(self):
        cvm = ConfidentialVM("sev-snp")
        self.assertEqual(cvm.provider, "sev-snp")

    def test_bad_provider_rejected(self):
        with self.assertRaises(ConfidentialVMError):
            ConfidentialVM("sgx")
        with self.assertRaises(ConfidentialVMError):
            ConfidentialVM("")

    def test_non_str_provider_rejected(self):
        with self.assertRaises(TypeError):
            ConfidentialVM(None)
        with self.assertRaises(TypeError):
            ConfidentialVM(123)


class TestLaunch(unittest.TestCase):
    def test_launch_happy_path(self):
        cvm = ConfidentialVM("tdx")
        inst = cvm.launch(b"guest-image-v1", 1)
        self.assertIsInstance(inst, VMInstance)
        self.assertTrue(inst.vm_id.startswith("cvm-"))
        self.assertEqual(inst.provider, "tdx")
        self.assertTrue(inst.image_digest.startswith("sha256:"))
        self.assertEqual(inst.tcb_version, TCB_VERSIONS["tdx"])
        self.assertEqual(inst.launch_seq, 1)
        self.assertEqual(inst.schema, SCHEMA_PIN)

    def test_launch_deterministic(self):
        a = ConfidentialVM("sev-snp").launch(b"img", 5)
        b = ConfidentialVM("sev-snp").launch(b"img", 5)
        self.assertEqual(a.vm_id, b.vm_id)
        self.assertEqual(a.image_digest, b.image_digest)

    def test_launch_differs_by_seq(self):
        a = ConfidentialVM("sev-snp").launch(b"img", 1)
        b = ConfidentialVM("sev-snp").launch(b"img", 2)
        self.assertNotEqual(a.vm_id, b.vm_id)

    def test_launch_differs_by_image(self):
        a = ConfidentialVM("sev-snp").launch(b"img-a", 1)
        b = ConfidentialVM("sev-snp").launch(b"img-b", 1)
        self.assertNotEqual(a.vm_id, b.vm_id)
        self.assertNotEqual(a.image_digest, b.image_digest)

    def test_launch_twice_rejected(self):
        cvm = ConfidentialVM("tdx")
        cvm.launch(b"img", 1)
        with self.assertRaises(ConfidentialVMError):
            cvm.launch(b"img", 2)

    def test_launch_validation(self):
        cvm = ConfidentialVM("tdx")
        with self.assertRaises(ConfidentialVMError):
            cvm.launch(b"", 1)
        with self.assertRaises(TypeError):
            cvm.launch("img", 1)
        with self.assertRaises(TypeError):
            cvm.launch(b"img", True)
        with self.assertRaises(ConfidentialVMError):
            cvm.launch(b"img", -1)


class TestAttest(unittest.TestCase):
    def test_attest_happy_path(self):
        cvm = ConfidentialVM("sev-snp")
        inst = cvm.launch(b"img", 1)
        rep = cvm.attest(2)
        self.assertIsInstance(rep, AttestationReport)
        self.assertEqual(rep.vm_id, inst.vm_id)
        self.assertEqual(rep.measurement, inst.image_digest)
        self.assertEqual(rep.tcb_version, TCB_VERSIONS["sev-snp"])
        self.assertTrue(rep.policy_digest.startswith("sha256:"))
        self.assertEqual(len(rep.evidence_mac), 32)
        self.assertEqual(rep.attest_seq, 2)

    def test_attest_before_launch_rejected(self):
        cvm = ConfidentialVM("sev-snp")
        with self.assertRaises(ConfidentialVMError):
            cvm.attest(1)

    def test_attest_bad_seq(self):
        cvm = ConfidentialVM("sev-snp")
        cvm.launch(b"img", 1)
        with self.assertRaises(ConfidentialVMError):
            cvm.attest(-1)
        with self.assertRaises(TypeError):
            cvm.attest(True)


class TestVerify(unittest.TestCase):
    def _launched(self, provider="tdx", image=b"img", seq=1):
        cvm = ConfidentialVM(provider)
        inst = cvm.launch(image, seq)
        rep = cvm.attest(seq + 1)
        return inst, rep

    def test_verify_roundtrip(self):
        inst, rep = self._launched()
        self.assertTrue(verify_attestation(rep, inst.image_digest))

    def test_verify_both_providers(self):
        for provider in PROVIDERS:
            inst, rep = self._launched(provider=provider)
            self.assertTrue(verify_attestation(rep, inst.image_digest))

    def test_verify_wrong_image(self):
        inst, rep = self._launched()
        self.assertFalse(verify_attestation(rep, "sha256:" + "00" * 32))

    def test_verify_tampered_mac(self):
        inst, rep = self._launched()
        bad = AttestationReport(
            vm_id=rep.vm_id,
            provider=rep.provider,
            measurement=rep.measurement,
            tcb_version=rep.tcb_version,
            policy_digest=rep.policy_digest,
            evidence_mac=b"\x00" * 32,
            attest_seq=rep.attest_seq,
        )
        self.assertFalse(verify_attestation(bad, inst.image_digest))

    def test_verify_tampered_measurement(self):
        inst, rep = self._launched()
        bad = AttestationReport(
            vm_id=rep.vm_id,
            provider=rep.provider,
            measurement="sha256:" + "ff" * 32,
            tcb_version=rep.tcb_version,
            policy_digest=rep.policy_digest,
            evidence_mac=rep.evidence_mac,
            attest_seq=rep.attest_seq,
        )
        # measurement no longer matches the MAC input nor the expectation
        self.assertFalse(verify_attestation(bad, inst.image_digest))

    def test_verify_tcb_too_low(self):
        inst, rep = self._launched(provider="sev-snp")
        self.assertTrue(
            verify_attestation(rep, inst.image_digest, min_tcb=MIN_TCB["sev-snp"])
        )
        self.assertFalse(
            verify_attestation(rep, inst.image_digest, min_tcb=MIN_TCB["sev-snp"] + 1)
        )

    def test_verify_type_errors(self):
        inst, rep = self._launched()
        with self.assertRaises(TypeError):
            verify_attestation("nope", inst.image_digest)
        with self.assertRaises(TypeError):
            verify_attestation(rep, b"bytes-digest")
        with self.assertRaises(TypeError):
            verify_attestation(rep, inst.image_digest, min_tcb=True)


class TestReport(unittest.TestCase):
    def test_report_launched_status(self):
        cvm = ConfidentialVM("tdx")
        inst = cvm.launch(b"img", 1)
        view = cvm.report(2)
        self.assertIsInstance(view, VMReport)
        self.assertEqual(view.status, "launched")
        self.assertEqual(view.measurement, inst.image_digest)
        self.assertEqual(view.last_attest_seq, 0)

    def test_report_attested_status(self):
        cvm = ConfidentialVM("tdx")
        cvm.launch(b"img", 1)
        cvm.attest(7)
        view = cvm.report(8)
        self.assertEqual(view.status, "attested")
        self.assertEqual(view.last_attest_seq, 7)

    def test_report_before_launch_rejected(self):
        cvm = ConfidentialVM("tdx")
        with self.assertRaises(ConfidentialVMError):
            cvm.report(1)


class TestRecords(unittest.TestCase):
    def test_frozen_records(self):
        cvm = ConfidentialVM("tdx")
        inst = cvm.launch(b"img", 1)
        rep = cvm.attest(2)
        view = cvm.report(3)
        for rec, attr in ((inst, "vm_id"), (rep, "vm_id"), (view, "vm_id")):
            with self.assertRaises(Exception):
                setattr(rec, attr, "changed")

    def test_as_dict_shapes(self):
        cvm = ConfidentialVM("sev-snp")
        inst = cvm.launch(b"img", 1)
        rep = cvm.attest(2)
        view = cvm.report(3)
        self.assertEqual(inst.as_dict()["provider"], "sev-snp")
        self.assertEqual(rep.as_dict()["attest_seq"], 2)
        self.assertEqual(view.as_dict()["status"], "attested")

    def test_record_schema_pin_enforced(self):
        with self.assertRaises(ConfidentialVMError):
            VMInstance(
                vm_id="cvm-x",
                provider="tdx",
                image_digest="sha256:" + "ab" * 32,
                tcb_version=1,
                launch_seq=0,
                schema="wrong",
            )


class TestAudit(unittest.TestCase):
    def test_audit_shapes(self):
        for kind in (
            "launched",
            "attested",
            "verified",
            "verification-failed",
            "rejected",
        ):
            rec = confidential_vm_audit_event(kind, 3, vm_id="cvm-x")
            self.assertEqual(rec["event"], "confidential-vm")
            self.assertEqual(rec["kind"], kind)
            self.assertEqual(rec["audit_seq"], 3)
            self.assertEqual(rec["schema"], "audit.ndjson/1")
            self.assertEqual(rec["vm_id"], "cvm-x")

    def test_audit_rejections(self):
        with self.assertRaises(ValueError):
            confidential_vm_audit_event("bogus", 1)
        with self.assertRaises(ValueError):
            confidential_vm_audit_event("launched", -1)
        with self.assertRaises(ValueError):
            confidential_vm_audit_event("launched", True)


class TestMain(unittest.TestCase):
    def test_main(self):
        cvm_main()


if __name__ == "__main__":
    unittest.main()
