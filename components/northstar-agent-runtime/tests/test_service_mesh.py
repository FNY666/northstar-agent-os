"""Tests for service_mesh: registry, policies, routing, audit."""

import unittest

from service_mesh import (
    SCHEMA_PIN,
    SERVICE_MESH_VERSION,
    AuthorizationError,
    AuthorizationRule,
    DuplicateEndpointError,
    MtlsMode,
    RouteDecision,
    ServiceMesh,
    ServiceMeshError,
    TrafficPolicy,
    UnknownServiceError,
    service_mesh_audit_event,
)


class VersionPinsTests(unittest.TestCase):
    def test_pins(self):
        self.assertEqual(SERVICE_MESH_VERSION, "service-mesh.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.service-mesh.v1")


class RegisterTests(unittest.TestCase):
    def test_register_roundtrip(self):
        mesh = ServiceMesh()
        rec = mesh.register("a", ["h:1", "h:2"], seq=0)
        self.assertEqual(rec.service_id, "a")
        self.assertEqual(rec.endpoints, ("h:1", "h:2"))
        self.assertTrue(rec.digest.startswith("sha256:"))
        self.assertEqual(mesh.get("a"), rec)

    def test_register_digest_deterministic(self):
        m1, m2 = ServiceMesh(), ServiceMesh()
        r1 = m1.register("a", ["h:1"], seq=3)
        r2 = m2.register("a", ["h:1"], seq=3)
        self.assertEqual(r1.digest, r2.digest)

    def test_register_update(self):
        mesh = ServiceMesh()
        old = mesh.register("a", ["h:1"], seq=1)
        new = mesh.register("a", ["h:1", "h:2"], seq=2)
        self.assertNotEqual(old.digest, new.digest)
        self.assertEqual(len(mesh.get("a").endpoints), 2)

    def test_register_rejects(self):
        mesh = ServiceMesh()
        with self.assertRaises(ServiceMeshError):
            mesh.register("", ["h:1"], seq=0)
        with self.assertRaises(ServiceMeshError):
            mesh.register("a", [], seq=0)
        with self.assertRaises(ServiceMeshError):
            mesh.register("a", ["no-port"], seq=0)
        with self.assertRaises(ServiceMeshError):
            mesh.register("a", ["h:99999"], seq=0)
        with self.assertRaises(ServiceMeshError):
            mesh.register("a", ["h:1"], seq=True)
        with self.assertRaises(DuplicateEndpointError):
            mesh.register("a", ["h:1", "h:1"], seq=0)

    def test_unknown_service(self):
        mesh = ServiceMesh()
        with self.assertRaises(UnknownServiceError):
            mesh.get("ghost")
        with self.assertRaises(UnknownServiceError):
            mesh.route("a", "ghost", 0)

    def test_deregister(self):
        mesh = ServiceMesh()
        mesh.register("a", ["h:1"], seq=0)
        self.assertTrue(mesh.deregister("a", 1))
        with self.assertRaises(UnknownServiceError):
            mesh.get("a")
        self.assertFalse(mesh.deregister("a", 2))
        self.assertEqual(mesh.services(), ())

    def test_record_frozen_and_as_dict(self):
        mesh = ServiceMesh()
        rec = mesh.register("a", ["h:1"], seq=0)
        d = rec.as_dict()
        self.assertEqual(d["service_id"], "a")
        self.assertEqual(d["schema"], SCHEMA_PIN)
        with self.assertRaises(Exception):
            rec.service_id = "x"  # frozen


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.mesh = ServiceMesh()
        self.mesh.register("dst", ["h:1", "h:2"], seq=0)

    def test_policy_roundtrip(self):
        pol = self.mesh.policy("dst", 1, mtls="strict", timeout_ms=100, max_retries=3)
        self.assertIs(pol.mtls, MtlsMode.STRICT)
        self.assertEqual(pol.timeout_ms, 100)
        self.assertEqual(pol.max_retries, 3)
        self.assertEqual(self.mesh.get_policy("dst"), pol)

    def test_policy_unknown_service(self):
        with self.assertRaises(UnknownServiceError):
            self.mesh.policy("ghost", 1)

    def test_policy_bad_mtls(self):
        with self.assertRaises(ServiceMeshError):
            self.mesh.policy("dst", 1, mtls="everything")

    def test_policy_bad_numbers(self):
        with self.assertRaises(ServiceMeshError):
            self.mesh.policy("dst", 1, timeout_ms=-1)
        with self.assertRaises(ServiceMeshError):
            self.mesh.policy("dst", 1, max_retries=True)

    def test_authorization_rules(self):
        rule = AuthorizationRule(action="deny", sources=("evil",))
        pol = self.mesh.policy("dst", 1, rules=(rule,))
        self.assertFalse(pol.allows("evil"))
        self.assertTrue(pol.allows("good"))
        # first matching rule wins
        pol2 = self.mesh.policy(
            "dst", 2,
            rules=[{"action": "allow", "sources": ["evil"]},
                   {"action": "deny", "sources": ["evil"]}],
        )
        self.assertTrue(pol2.allows("evil"))

    def test_bad_rules(self):
        with self.assertRaises(ServiceMeshError):
            self.mesh.policy("dst", 1, rules=[{"action": "maybe", "sources": ["x"]}])
        with self.assertRaises(ServiceMeshError):
            self.mesh.policy("dst", 1, rules=[{"action": "allow"}])

    def test_weights(self):
        pol = self.mesh.policy("dst", 1, weights={"h:1": 3, "h:2": 1})
        self.assertEqual(dict(pol.weights), {"h:1": 3, "h:2": 1})
        with self.assertRaises(ServiceMeshError):
            self.mesh.policy("dst", 2, weights={"h:9": 1})
        with self.assertRaises(ServiceMeshError):
            self.mesh.policy("dst", 3, weights={"h:1": 0})

    def test_policy_frozen_and_as_dict(self):
        pol = self.mesh.policy("dst", 1, mtls=MtlsMode.PERMISSIVE)
        d = pol.as_dict()
        self.assertEqual(d["mtls"], "permissive")
        with self.assertRaises(Exception):
            pol.timeout_ms = 5  # frozen


class RoutingTests(unittest.TestCase):
    def setUp(self):
        self.mesh = ServiceMesh()
        self.mesh.register("dst", ["h:1", "h:2"], seq=0)

    def test_route_round_robin(self):
        d1 = self.mesh.route("src", "dst", 1)
        d2 = self.mesh.route("src", "dst", 2)
        d3 = self.mesh.route("src", "dst", 3)
        self.assertTrue(d1.allowed and d2.allowed and d3.allowed)
        self.assertEqual((d1.endpoint, d2.endpoint, d3.endpoint), ("h:1", "h:2", "h:1"))
        self.assertEqual((d1.cursor, d2.cursor, d3.cursor), (0, 1, 2))

    def test_route_default_mtls(self):
        d = self.mesh.route("src", "dst", 1)
        self.assertEqual(d.mtls, "disabled")

    def test_route_denied_is_data(self):
        self.mesh.policy("dst", 1, rules=[{"action": "deny", "sources": ["src"]}])
        d = self.mesh.route("src", "dst", 2)
        self.assertFalse(d.allowed)
        self.assertIsNone(d.endpoint)
        self.assertEqual(d.cursor, -1)
        self.assertIsInstance(d, RouteDecision)

    def test_route_weighted(self):
        self.mesh.policy("dst", 1, weights={"h:1": 2, "h:2": 1})
        picks = [self.mesh.route("s", "dst", i).endpoint for i in range(2, 8)]
        self.assertEqual(picks, ["h:1", "h:1", "h:2"] * 2)

    def test_route_mtls_recorded(self):
        self.mesh.policy("dst", 1, mtls="strict")
        d = self.mesh.route("src", "dst", 2)
        self.assertEqual(d.mtls, "strict")

    def test_route_deterministic_digest(self):
        d = self.mesh.route("src", "dst", 9)
        self.assertTrue(d.digest.startswith("sha256:"))
        mesh2 = ServiceMesh()
        mesh2.register("dst", ["h:1", "h:2"], seq=0)
        d2 = mesh2.route("src", "dst", 9)
        self.assertEqual(d.digest, d2.digest)


class AuditTests(unittest.TestCase):
    def test_audit_shapes(self):
        mesh = ServiceMesh()
        rec = mesh.register("a", ["h:1"], seq=0)
        ev = service_mesh_audit_event("service-registered", 1, rec, detail="x")
        self.assertEqual(ev["event"], "service-mesh.service-registered")
        self.assertEqual(ev["audit_seq"], 1)
        self.assertEqual(ev["record"]["digest"], rec.digest)
        with self.assertRaises(ServiceMeshError):
            service_mesh_audit_event("nope", 1)
        with self.assertRaises(ServiceMeshError):
            service_mesh_audit_event("routed", True)

    def test_authorization_error_importable(self):
        self.assertTrue(issubclass(AuthorizationError, ServiceMeshError))


class MainTests(unittest.TestCase):
    def test_main(self):
        import service_mesh as sm

        sm.main()


if __name__ == "__main__":
    unittest.main()
