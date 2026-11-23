"""Tests for edge_compute: 15 cases."""

import ast
import sys
import os
import threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import unittest

from edge_compute import (
    EdgeCompute,
    DeploymentRecord,
    UndeployRecord,
    InvocationRecord,
    LogPage,
    edge_compute_audit_event,
    EdgeComputeError,
    UnknownFunctionError,
    DuplicateFunctionError,
    BadDeployError,
    UnknownInvocationError,
    AlreadyDeliveredError,
    MaxAttemptsError,
    DeactivatedError,
    BadInvocationError,
    SeqOrderError,
    AuditKindError,
    EDGE_COMPUTE_VERSION,
    EDGE_COMPUTE_SCHEMA,
    MAX_ATTEMPTS,
    RUNTIMES,
    MEMORY_ALLOWANCES,
    REGIONS,
)

DIGEST = "sha256:" + "ab" * 32


def _mgr(executor=None, seed="test"):
    return EdgeCompute(seed=seed, executor=executor)


def _deploy(mgr, fid="fn-1", seq=1, **kw):
    kw.setdefault("name", "resize")
    kw.setdefault("runtime", "python")
    kw.setdefault("memory_mb", 128)
    kw.setdefault("entry_digest", DIGEST)
    return mgr.deploy(fid, seq, **kw)


class TestPins(unittest.TestCase):
    def test_version_pins(self):
        self.assertEqual(EDGE_COMPUTE_VERSION, "edge-compute.v1")
        self.assertEqual(EDGE_COMPUTE_SCHEMA, "northstar.edge-compute.v1")
        self.assertEqual(MAX_ATTEMPTS, 5)
        self.assertIn("python", RUNTIMES)
        self.assertIn(128, MEMORY_ALLOWANCES)
        self.assertIn("iad", REGIONS)

    def test_stdlib_only(self):
        path = os.path.join(os.path.dirname(__file__), "..", "edge_compute.py")
        tree = ast.parse(open(path).read())
        allowed = {
            "hashlib", "hmac", "re", "threading", "dataclasses", "typing",
            "__future__", "ast", "json", "canonical_json",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.assertIn(a.name.split(".")[0], allowed, a.name)


class TestDeploy(unittest.TestCase):
    def test_deploy_roundtrip(self):
        mgr = _mgr()
        fn = _deploy(mgr, regions=("iad", "sfo"))
        self.assertTrue(fn.verify())
        self.assertEqual(fn.state, "active")
        self.assertEqual(fn.regions, ("iad", "sfo"))
        self.assertEqual(mgr.function("fn-1"), fn)

    def test_deploy_bad_inputs(self):
        mgr = _mgr()
        for seq, kw in [
            (1, {"runtime": "cobol"}),
            (2, {"memory_mb": 1024}),
            (3, {"entry_digest": "nope"}),
            (4, {"regions": ("moon",)}),
            (5, {"name": ""}),
        ]:
            with self.assertRaises(BadDeployError, msg=kw):
                _deploy(mgr, fid=f"bad-{seq}", seq=seq, **kw)
        with self.assertRaises(DuplicateFunctionError):
            _deploy(mgr, seq=10)
            _deploy(mgr, seq=11)

    def test_seq_order(self):
        mgr = _mgr()
        _deploy(mgr, seq=5)
        with self.assertRaises(SeqOrderError):
            _deploy(mgr, fid="fn-2", seq=5)  # rewind
        with self.assertRaises(SeqOrderError):
            _deploy(mgr, fid="fn-3", seq=True)  # bool
        with self.assertRaises(SeqOrderError):
            _deploy(mgr, fid="fn-4", seq=-1)  # negative


class TestInvoke(unittest.TestCase):
    def test_invoke_happy(self):
        mgr = _mgr()
        _deploy(mgr, regions=("iad",))
        r = mgr.invoke("fn-1", 2, DIGEST)
        self.assertTrue(r.verify())
        self.assertEqual(r.status, "delivered")
        self.assertEqual(r.attempt, 1)
        self.assertEqual(r.region, "iad")
        self.assertTrue(r.output_digest.startswith("sha256:"))

    def test_invoke_failure_as_data(self):
        def always_raise(fn, digest, attempt, cold):
            raise RuntimeError("boom")

        mgr = _mgr(executor=always_raise)
        _deploy(mgr)
        r = mgr.invoke("fn-1", 2, DIGEST)
        self.assertEqual(r.status, "failed")
        self.assertEqual(r.output_digest, "")

    def test_retry_chain(self):
        def fail_first(fn, digest, attempt, cold):
            if attempt == 1:
                raise RuntimeError("cold")
            return DIGEST

        mgr = _mgr(executor=fail_first)
        _deploy(mgr)
        r1 = mgr.invoke("fn-1", 2, DIGEST)
        self.assertEqual(r1.status, "failed")
        r2 = mgr.retry_invocation(r1.invocation_id, 3)
        self.assertEqual(r2.status, "delivered")
        self.assertEqual(r2.attempt, 2)
        self.assertEqual(r2.prev_invocation_id, r1.invocation_id)
        with self.assertRaises(AlreadyDeliveredError):
            mgr.retry_invocation(r2.invocation_id, 4)

    def test_retry_exhausts_max_attempts(self):
        def always_raise(fn, digest, attempt, cold):
            raise RuntimeError("boom")

        mgr = _mgr(executor=always_raise)
        _deploy(mgr)
        r = mgr.invoke("fn-1", 2, DIGEST)
        seq = 3
        for _ in range(MAX_ATTEMPTS - 1):
            r = mgr.retry_invocation(r.invocation_id, seq)
            seq += 1
        self.assertEqual(r.attempt, MAX_ATTEMPTS)
        with self.assertRaises(MaxAttemptsError):
            mgr.retry_invocation(r.invocation_id, seq)

    def test_invoke_unknown_and_bad_digest(self):
        mgr = _mgr()
        with self.assertRaises(UnknownFunctionError):
            mgr.invoke("nope", 1, DIGEST)
        _deploy(mgr, seq=2)  # failed mutations consume their seq
        with self.assertRaises(BadInvocationError):
            mgr.invoke("fn-1", 3, "garbage")


class TestUndeploy(unittest.TestCase):
    def test_undeploy_terminal(self):
        mgr = _mgr()
        _deploy(mgr)
        u = mgr.undeploy("fn-1", 2, "superseded")
        self.assertTrue(u.verify())
        self.assertEqual(mgr.function("fn-1").state, "undeployed")
        with self.assertRaises(DeactivatedError):
            mgr.invoke("fn-1", 3, DIGEST)
        with self.assertRaises(DeactivatedError):
            mgr.undeploy("fn-1", 4)

    def test_undeploy_unknown(self):
        mgr = _mgr()
        with self.assertRaises(UnknownFunctionError):
            mgr.undeploy("nope", 1)


class TestLogs(unittest.TestCase):
    def test_logs_page(self):
        mgr = _mgr()
        _deploy(mgr)
        r1 = mgr.invoke("fn-1", 2, DIGEST)
        r2 = mgr.invoke("fn-1", 3, DIGEST, region="sfo", cold=True)
        page = mgr.logs("fn-1", 4)
        self.assertTrue(page.verify())
        self.assertEqual(len(page.entries), 2)
        self.assertEqual(page.entries[0].invocation_id, r1.invocation_id)
        self.assertEqual(page.entries[1].region, "sfo")
        # read-only: seq not consumed, logs() does not bump the ledger
        with self.assertRaises(SeqOrderError):
            mgr.invoke("fn-1", 3, DIGEST)  # seq 3 already used


class TestAudit(unittest.TestCase):
    def test_audit_shapes(self):
        mgr = _mgr()
        _deploy(mgr)
        mgr.invoke("fn-1", 2, DIGEST)
        kinds = [e["kind"] for e in mgr.audit_log()]
        self.assertIn("function-deployed", kinds)
        self.assertIn("invoked", kinds)
        for e in mgr.audit_log():
            self.assertEqual(e["schema"], "audit.ndjson/1")
            self.assertEqual(e["module"], "edge-compute.v1")
        # no payload bytes leak into the audit boundary
        self.assertNotIn("payload", str(mgr.audit_log()))

    def test_audit_bad_kind(self):
        with self.assertRaises(AuditKindError):
            edge_compute_audit_event("nope", 1)


if __name__ == "__main__":
    unittest.main()
