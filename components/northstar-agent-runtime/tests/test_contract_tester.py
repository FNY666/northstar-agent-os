"""Tests for contract_tester.py (Pact-style consumer-driven contracts)."""

import ast
import unittest
from pathlib import Path

import contract_tester as ct


def _ix(description="get invoice", method="GET", path="/invoices/42",
        status=200, req_body=None, resp_body=None,
        req_headers=None, resp_headers=None):
    return {
        "description": description,
        "method": method,
        "path": path,
        "status": status,
        "request": {"headers": req_headers or {}, "body": req_body or {}},
        "response": {"headers": resp_headers or {}, "body": resp_body or {}},
    }


class TestPins(unittest.TestCase):
    def test_version_and_schema_pins(self):
        self.assertEqual(ct.CONTRACT_TESTER_VERSION, "contract-tester.v1")
        self.assertEqual(ct.CONTRACT_TESTER_SCHEMA,
                         "northstar.contract-tester.v1")
        self.assertEqual(ct.AUDIT_SCHEMA, "audit.ndjson/1")

    def test_stdlib_only_imports(self):
        src = Path(ct.__file__).read_text()
        tree = ast.parse(src)
        allowed = {"__future__", "threading", "dataclasses", "typing",
                   "hashlib", "canonical_json", "json"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.assertIn(a.name.split(".")[0], allowed)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn((node.module or "").split(".")[0], allowed)


class TestPact(unittest.TestCase):
    def test_pact_roundtrip_and_digest(self):
        t = ct.ContractTester()
        raw = [_ix()]
        rec = t.pact("web-ui", "billing", 1, raw, version="1.0.0")
        self.assertEqual(rec.pact_id, "pact-1")
        self.assertEqual(rec.interaction_count, 1)
        self.assertTrue(rec.pact_digest.startswith("sha256:"))
        self.assertTrue(rec.verify(raw))
        self.assertIn("pact-1", t.pact_ids())

    def test_duplicate_triple_refused(self):
        t = ct.ContractTester()
        t.pact("web-ui", "billing", 1, [_ix()], version="1.0.0")
        with self.assertRaises(ct.DuplicatePactError):
            t.pact("web-ui", "billing", 2, [_ix()], version="1.0.0")

    def test_bad_interactions_refused(self):
        t = ct.ContractTester()
        with self.assertRaises(ct.BadInteractionError):
            t.pact("web-ui", "billing", 1, [])
        with self.assertRaises(ct.BadInteractionError):
            t.pact("web-ui", "billing", 2, [_ix(method="BREW")])
        with self.assertRaises(ct.BadInteractionError):
            t.pact("web-ui", "billing", 3, [_ix(path="relative")])
        with self.assertRaises(ct.BadInteractionError):
            t.pact("web-ui", "billing", 4, [_ix(status=99)])
        with self.assertRaises(ct.BadInteractionError):
            t.pact("web-ui", "billing", 5,
                   [_ix(resp_body={"n": float("nan")})])

    def test_unknown_pact_lookup(self):
        t = ct.ContractTester()
        with self.assertRaises(ct.UnknownPactError):
            t.pact_record("pact-999")


class TestStubAndVerify(unittest.TestCase):
    def _matching(self, t=None):
        t = t or ct.ContractTester()
        t.stub("billing", "GET", "/invoices/42", 1, status=200,
               headers={"Content-Type": "application/json"},
               body={"id": 42, "total_cents": 1999})
        return t

    def test_verify_happy_path(self):
        t = self._matching()
        rec = t.pact("web-ui", "billing", 2, [
            _ix(resp_headers={"Content-Type": "application/json"},
                resp_body={"id": 42, "total_cents": 1999})],
            version="1.0.0")
        report = t.verify(rec.pact_id, 3)
        self.assertTrue(report.all_passed)
        self.assertEqual(report.passed, 1)
        self.assertEqual(report.failed, 0)
        self.assertEqual(report.results[0].reason, "match")

    def test_mismatch_is_data_not_exception(self):
        t = self._matching()
        rec = t.pact("web-ui", "billing", 2,
                     [_ix(resp_body={"id": 42, "total_cents": 1})],
                     version="1.0.0")
        report = t.verify(rec.pact_id, 3)
        self.assertFalse(report.all_passed)
        self.assertEqual(report.failed, 1)
        self.assertEqual(report.results[0].reason, ct.REASON_MISMATCH)

    def test_no_stub_is_data(self):
        t = ct.ContractTester()
        rec = t.pact("web-ui", "billing", 1, [_ix()], version="1.0.0")
        report = t.verify(rec.pact_id, 2)
        self.assertFalse(report.all_passed)
        self.assertEqual(report.results[0].reason, ct.REASON_NO_STUB)

    def test_verify_unknown_pact_raises(self):
        t = ct.ContractTester()
        with self.assertRaises(ct.UnknownPactError):
            t.verify("pact-999", 1)

    def test_header_subset_matching(self):
        t = ct.ContractTester()
        # Stub has extra headers: fine. Missing expected header: mismatch.
        t.stub("billing", "GET", "/invoices/42", 1, status=200,
               headers={"Content-Type": "application/json", "X-Trace": "1"},
               body={})
        ok = t.pact("a", "billing", 2,
                    [_ix(resp_headers={"Content-Type": "application/json"})],
                    version="1.0.0")
        self.assertTrue(t.verify(ok.pact_id, 3).all_passed)
        bad = t.pact("b", "billing", 4,
                     [_ix(resp_headers={"X-Missing": "no"})],
                     version="1.0.0")
        self.assertFalse(t.verify(bad.pact_id, 5).all_passed)

    def test_duplicate_stub_refused(self):
        t = self._matching()
        with self.assertRaises(ct.DuplicateStubError):
            t.stub("billing", "GET", "/invoices/42", 2, status=200)


class TestBroker(unittest.TestCase):
    def test_broker_matrix_and_can_i_deploy(self):
        t = ct.ContractTester()
        t.publish_provider("billing", "2.0.0", 1)
        t.stub("billing", "GET", "/invoices/42", 2, status=200, body={"ok": True})
        rec = t.pact("web-ui", "billing", 3, [_ix(resp_body={"ok": True})],
                     version="1.0.0")
        self.assertTrue(t.verify(rec.pact_id, 4).all_passed)
        matrix = t.broker(5)
        self.assertEqual(matrix.row_count, 1)
        self.assertTrue(matrix.all_verified)
        self.assertEqual(matrix.rows[0].status, ct.VERIFIED)
        self.assertEqual(matrix.rows[0].provider_version, "2.0.0")

    def test_broker_never_verified_and_failed(self):
        t = ct.ContractTester()
        t.publish_provider("billing", "3.0.0", 1)
        p1 = t.pact("a", "billing", 2, [_ix()], version="1.0.0")
        matrix = t.broker(3)
        self.assertEqual(matrix.rows[0].status, ct.NEVER_VERIFIED)
        self.assertFalse(matrix.all_verified)
        # history for unknown pact raises
        with self.assertRaises(ct.UnknownPactError):
            t.verification_history("pact-999")
        hist = t.verification_history(p1.pact_id)
        self.assertEqual(hist, {})


class TestAuditAndSeq(unittest.TestCase):
    def test_audit_shapes_and_ban(self):
        t = ct.ContractTester()
        t.pact("web-ui", "billing", 1, [_ix()], version="1.0.0")
        log = t.audit_log()
        self.assertEqual(len(log), 1)
        self.assertEqual(log[0]["kind"], ct.KIND_PACT_CREATED)
        self.assertEqual(log[0]["schema"], "audit.ndjson/1")
        ev = ct.contract_tester_audit_event(ct.KIND_VERIFIED, 7,
                                            {"pact_id": "pact-1"})
        self.assertEqual(ev["kind"], ct.KIND_VERIFIED)
        with self.assertRaises(ct.ContractTesterError):
            ct.contract_tester_audit_event(ct.KIND_VERIFIED, 8,
                                           {"body": {"x": 1}})
        with self.assertRaises(ct.BadAuditKindError):
            ct.contract_tester_audit_event("nope", 9)

    def test_seq_strictly_increasing(self):
        t = ct.ContractTester()
        t.pact("a", "billing", 5, [_ix()], version="1.0.0")
        with self.assertRaises(ct.SeqOrderError):
            t.pact("b", "billing", 5, [_ix()], version="2.0.0")
        with self.assertRaises(ct.SeqOrderError):
            t.pact("b", "billing", 3, [_ix()], version="2.0.0")


if __name__ == "__main__":
    unittest.main()
