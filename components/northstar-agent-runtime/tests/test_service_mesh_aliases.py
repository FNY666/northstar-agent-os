"""Tests for service_mesh task API: inject()/mtls()/traffic() — 15 cases.

These cover the task-required API surface added on top of the
batch-18 service_mesh module (register/policy/route). The aliases are
thin: inject()->register, mtls()->policy (mode-only update),
traffic()->route.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from service_mesh import (
    MtlsMode,
    ServiceMesh,
    ServiceMeshError,
    UnknownServiceError,
    DuplicateEndpointError,
    main,
)


def fresh():
    return ServiceMesh()


class TestInject(unittest.TestCase):
    def test_inject_roundtrip(self):
        sm = fresh()
        rec = sm.inject("svc-a", ["10.0.0.1:8080"], 1)
        self.assertEqual(rec.service_id, "svc-a")
        self.assertEqual(rec.endpoints, ("10.0.0.1:8080",))
        self.assertTrue(rec.digest.startswith("sha256:"))
        self.assertEqual(sm.get("svc-a").digest, rec.digest)

    def test_inject_matches_register(self):
        sm = fresh()
        a = sm.inject("svc-a", ["h1:80", "h2:80"], 1)
        sm2 = fresh()
        b = sm2.register("svc-a", ["h1:80", "h2:80"], 1)
        self.assertEqual(a.digest, b.digest)

    def test_inject_bad_endpoint(self):
        sm = fresh()
        with self.assertRaises(ServiceMeshError):
            sm.inject("svc-a", ["not-an-endpoint"], 1)

    def test_inject_duplicate_endpoints(self):
        sm = fresh()
        with self.assertRaises(DuplicateEndpointError):
            sm.inject("svc-a", ["h1:80", "h1:80"], 1)

    def test_inject_empty_id(self):
        sm = fresh()
        with self.assertRaises(ServiceMeshError):
            sm.inject("  ", ["h1:80"], 1)


class TestMtls(unittest.TestCase):
    def test_mtls_default_strict(self):
        sm = fresh()
        sm.inject("svc-a", ["h1:80"], 1)
        pol = sm.mtls("svc-a", 2)
        self.assertIs(pol.mtls, MtlsMode.STRICT)

    def test_mtls_string_mode(self):
        sm = fresh()
        sm.inject("svc-a", ["h1:80"], 1)
        pol = sm.mtls("svc-a", 2, mode="permissive")
        self.assertIs(pol.mtls, MtlsMode.PERMISSIVE)

    def test_mtls_bad_mode(self):
        sm = fresh()
        sm.inject("svc-a", ["h1:80"], 1)
        with self.assertRaises(ServiceMeshError):
            sm.mtls("svc-a", 2, mode="bogus")

    def test_mtls_unknown_service(self):
        sm = fresh()
        with self.assertRaises(UnknownServiceError):
            sm.mtls("ghost", 1, mode="strict")

    def test_mtls_preserves_existing_policy(self):
        sm = fresh()
        sm.inject("svc-a", ["h1:80", "h2:80"], 1)
        sm.policy("svc-a", 2, mtls="disabled",
                  rules=[{"action": "deny", "sources": ["evil"]}],
                  timeout_ms=500, max_retries=3,
                  weights={"h1:80": 2, "h2:80": 1})
        pol = sm.mtls("svc-a", 3, mode="strict")
        self.assertIs(pol.mtls, MtlsMode.STRICT)
        # Everything else preserved; only the mode changed.
        self.assertEqual(pol.timeout_ms, 500)
        self.assertEqual(pol.max_retries, 3)
        self.assertFalse(pol.allows("evil"))
        self.assertTrue(pol.allows("web"))
        self.assertEqual(dict(pol.weights), {"h1:80": 2, "h2:80": 1})


class TestTraffic(unittest.TestCase):
    def test_traffic_allowed(self):
        sm = fresh()
        sm.inject("web", ["w:80"], 1)
        sm.inject("api", ["a:80"], 2)
        d = sm.traffic("web", "api", 3)
        self.assertTrue(d.allowed)
        self.assertEqual(d.endpoint, "a:80")

    def test_traffic_denied_is_data(self):
        sm = fresh()
        sm.inject("web", ["w:80"], 1)
        sm.inject("api", ["a:80"], 2)
        sm.policy("api", 3, rules=[{"action": "deny", "sources": ["web"]}])
        d = sm.traffic("web", "api", 4)
        self.assertFalse(d.allowed)
        self.assertIsNone(d.endpoint)
        self.assertEqual(d.cursor, -1)

    def test_traffic_unknown_dst(self):
        sm = fresh()
        sm.inject("web", ["w:80"], 1)
        with self.assertRaises(UnknownServiceError):
            sm.traffic("web", "ghost", 2)

    def test_traffic_round_robin(self):
        sm = fresh()
        sm.inject("web", ["w:80"], 1)
        sm.inject("api", ["a1:80", "a2:80"], 2)
        e1 = sm.traffic("web", "api", 3).endpoint
        e2 = sm.traffic("web", "api", 4).endpoint
        self.assertNotEqual(e1, e2)
        self.assertEqual({e1, e2}, {"a1:80", "a2:80"})

    def test_aliases_leave_existing_behavior_intact(self):
        # The batch-18 self-check still passes with the new methods present.
        main()


if __name__ == "__main__":
    unittest.main()
