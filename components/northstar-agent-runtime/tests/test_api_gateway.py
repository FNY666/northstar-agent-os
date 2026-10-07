"""Targeted tests for api_gateway.py."""

from __future__ import annotations

import unittest

from api_gateway import (
    API_GATEWAY_VERSION,
    SCHEMA_PIN,
    APIGateway,
    APIGatewayError,
    DuplicatePluginError,
    DuplicateRouteError,
    RequestRejectedError,
    UnknownPluginError,
    UnknownRouteError,
    api_gateway_audit_event,
)


def _gw():
    return APIGateway()


class VersionPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(API_GATEWAY_VERSION, "api-gateway.v1")

    def test_schema_pin(self):
        self.assertEqual(SCHEMA_PIN, "northstar.api-gateway.v1")


class AddRoute(unittest.TestCase):
    def test_add_route_happy_path(self):
        gw = _gw()
        r = gw.add_route("r1", "/users", ("GET",), "svc-a", seq=1)
        self.assertEqual(r.route_id, "r1")
        self.assertEqual(r.pattern, "/users")
        self.assertEqual(r.methods, ("GET",))
        self.assertTrue(r.digest.startswith("sha256:"))

    def test_add_route_digest_deterministic(self):
        gw1, gw2 = _gw(), _gw()
        r1 = gw1.add_route("r1", "/users", ("GET",), "svc-a", seq=1)
        r2 = gw2.add_route("r1", "/users", ("GET",), "svc-a", seq=1)
        self.assertEqual(r1.digest, r2.digest)

    def test_add_route_duplicate_id(self):
        gw = _gw()
        gw.add_route("r1", "/users", ("GET",), "svc-a", seq=1)
        with self.assertRaises(DuplicateRouteError):
            gw.add_route("r1", "/other", ("GET",), "svc-b", seq=2)

    def test_add_route_duplicate_method_pattern(self):
        gw = _gw()
        gw.add_route("r1", "/users", ("GET",), "svc-a", seq=1)
        with self.assertRaises(DuplicateRouteError):
            gw.add_route("r2", "/users", ("GET",), "svc-b", seq=2)

    def test_add_route_same_pattern_different_method_ok(self):
        gw = _gw()
        gw.add_route("r1", "/users", ("GET",), "svc-a", seq=1)
        gw.add_route("r2", "/users", ("POST",), "svc-b", seq=2)
        self.assertEqual(len(gw.routes()), 2)

    def test_add_route_bad_pattern(self):
        gw = _gw()
        with self.assertRaises(ValueError):
            gw.add_route("r1", "users", ("GET",), "svc-a", seq=1)

    def test_add_route_lowercase_method(self):
        gw = _gw()
        with self.assertRaises(ValueError):
            gw.add_route("r1", "/users", ("get",), "svc-a", seq=1)

    def test_add_route_bad_seq(self):
        gw = _gw()
        with self.assertRaises(TypeError):
            gw.add_route("r1", "/users", ("GET",), "svc-a", seq=True)

    def test_unknown_route_lookup(self):
        gw = _gw()
        with self.assertRaises(UnknownRouteError):
            gw.route("nope")


class AddPlugin(unittest.TestCase):
    def test_add_plugin_happy_path(self):
        gw = _gw()
        p = gw.add_plugin("auth", lambda req: ("continue", None), priority=100, seq=1)
        self.assertEqual(p.name, "auth")
        self.assertEqual(p.priority, 100)

    def test_add_plugin_duplicate(self):
        gw = _gw()
        gw.add_plugin("auth", lambda req: ("continue", None), priority=100, seq=1)
        with self.assertRaises(DuplicatePluginError):
            gw.add_plugin("auth", lambda req: ("continue", None), priority=50, seq=2)

    def test_add_plugin_non_callable(self):
        gw = _gw()
        with self.assertRaises(TypeError):
            gw.add_plugin("auth", "not-a-fn", priority=100, seq=1)

    def test_remove_plugin(self):
        gw = _gw()
        gw.add_plugin("auth", lambda req: ("continue", None), priority=100, seq=1)
        gw.remove_plugin("auth")
        self.assertEqual(gw.plugins(), ())
        with self.assertRaises(UnknownPluginError):
            gw.remove_plugin("auth")

    def test_unknown_plugin_lookup(self):
        gw = _gw()
        with self.assertRaises(UnknownPluginError):
            gw.plugin("nope")


class Handle(unittest.TestCase):
    def _routed_gw(self):
        gw = _gw()
        gw.add_route("users", "/users/:id", ("GET",), "users-svc", seq=1)
        return gw

    def test_exact_match(self):
        gw = _gw()
        gw.add_route("health", "/healthz", ("GET",), "ops", seq=1)
        resp = gw.handle("GET", "/healthz", seq=2)
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.route_id, "health")

    def test_param_extraction(self):
        gw = self._routed_gw()
        resp = gw.handle("GET", "/users/42", seq=2)
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.route_id, "users")
        self.assertEqual(resp.route_params, (("id", "42"),))

    def test_no_match_404(self):
        gw = self._routed_gw()
        resp = gw.handle("GET", "/nope", seq=2)
        self.assertEqual(resp.status, 404)
        self.assertIsNone(resp.route_id)

    def test_method_mismatch_404(self):
        gw = self._routed_gw()
        resp = gw.handle("POST", "/users/42", seq=2)
        self.assertEqual(resp.status, 404)

    def test_segment_count_mismatch_404(self):
        gw = self._routed_gw()
        resp = gw.handle("GET", "/users/42/orders", seq=2)
        self.assertEqual(resp.status, 404)

    def test_plugin_short_circuit(self):
        gw = self._routed_gw()
        gw.add_plugin("blocker", lambda req: ("reject", 403), priority=10, seq=2)
        resp = gw.handle("GET", "/users/42", seq=3)
        self.assertEqual(resp.status, 403)
        self.assertEqual(resp.short_circuited_by, "blocker")
        self.assertIsNone(resp.route_id)
        self.assertEqual(resp.plugins_run, ("blocker",))

    def test_plugin_continue_reaches_route(self):
        gw = self._routed_gw()
        gw.add_plugin("tag", lambda req: ("continue", None), priority=10, seq=2)
        resp = gw.handle("GET", "/users/42", seq=3)
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.plugins_run, ("tag",))
        self.assertIsNone(resp.short_circuited_by)

    def test_plugin_priority_order(self):
        gw = self._routed_gw()
        seen = []
        gw.add_plugin("low", lambda req: seen.append("low") or ("continue", None),
                      priority=1, seq=2)
        gw.add_plugin("high", lambda req: seen.append("high") or ("continue", None),
                      priority=100, seq=3)
        gw.handle("GET", "/users/42", seq=4)
        self.assertEqual(seen, ["high", "low"])

    def test_plugin_header_mutation(self):
        gw = self._routed_gw()
        def mutator(req):
            return ("continue", req.headers + (("x-tag", "1"),))
        gw.add_plugin("mut", mutator, priority=10, seq=2)
        captured = []
        gw.add_plugin("cap", lambda req: captured.append(req.headers) or ("continue", None),
                      priority=5, seq=3)
        gw.handle("GET", "/users/42", seq=4)
        # Mutated headers propagate to later plugins; the pinned request
        # digest still binds the original inbound request.
        self.assertIn(("x-tag", "1"), captured[0])

    def test_plugin_raising_rejected(self):
        gw = self._routed_gw()
        def bad(req):
            raise RuntimeError("boom")
        gw.add_plugin("bad", bad, priority=10, seq=2)
        with self.assertRaises(RequestRejectedError):
            gw.handle("GET", "/users/42", seq=3)

    def test_plugin_unknown_verdict(self):
        gw = self._routed_gw()
        gw.add_plugin("weird", lambda req: ("bogus", None), priority=10, seq=2)
        with self.assertRaises(APIGatewayError):
            gw.handle("GET", "/users/42", seq=3)

    def test_handle_bad_path(self):
        gw = _gw()
        with self.assertRaises(ValueError):
            gw.handle("GET", "nope", seq=1)

    def test_handle_bad_seq(self):
        gw = _gw()
        with self.assertRaises(TypeError):
            gw.handle("GET", "/x", seq="1")

    def test_response_digest_deterministic(self):
        gw1, gw2 = self._routed_gw(), self._routed_gw()
        r1 = gw1.handle("GET", "/users/42", seq=2)
        r2 = gw2.handle("GET", "/users/42", seq=2)
        self.assertEqual(r1.response_digest, r2.response_digest)
        self.assertEqual(r1.request_digest, r2.request_digest)

    def test_first_registered_route_wins(self):
        gw = _gw()
        gw.add_route("a", "/items/:id", ("GET",), "svc-a", seq=1)
        gw.add_route("b", "/items/:name", ("GET",), "svc-b", seq=2)
        resp = gw.handle("GET", "/items/x", seq=3)
        self.assertEqual(resp.route_id, "a")

    def test_request_digest_binds_body(self):
        gw = self._routed_gw()
        r1 = gw.handle("POST", "/users/42", body="a", seq=2)
        r2 = gw.handle("POST", "/users/42", body="b", seq=2)
        self.assertNotEqual(r1.request_digest, r2.request_digest)


class Audit(unittest.TestCase):
    def test_audit_shapes(self):
        for kind in ("route-added", "plugin-added", "plugin-removed",
                     "request-handled", "request-rejected"):
            ev = api_gateway_audit_event(kind, 1, note="x")
            self.assertEqual(ev["schema"], "audit.ndjson/1")
            self.assertEqual(ev["module"], "api-gateway")
            self.assertEqual(ev["version"], API_GATEWAY_VERSION)
            self.assertIn("digest", ev)

    def test_audit_bad_kind(self):
        with self.assertRaises(ValueError):
            api_gateway_audit_event("bogus", 1)


class FrozenRecords(unittest.TestCase):
    def test_records_immutable(self):
        gw = _gw()
        r = gw.add_route("r1", "/users", ("GET",), "svc-a", seq=1)
        with self.assertRaises(Exception):
            r.target = "svc-b"  # type: ignore


if __name__ == "__main__":
    unittest.main()
