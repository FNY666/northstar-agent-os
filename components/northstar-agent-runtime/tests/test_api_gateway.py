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
    UnknownThrottleError,
    UnknownTransformError,
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


def _routed_gw():
    gw = _gw()
    gw.add_route("users", "/users/:id", ("GET", "POST"), "users-svc", seq=1)
    return gw


class SetTransform(unittest.TestCase):
    def test_set_transform_happy_path(self):
        gw = _routed_gw()
        rec = gw.set_transform(
            "users",
            seq=2,
            add_headers=(("x-gateway", "northstar"),),
            remove_headers=("x-internal",),
            add_query_params=(("gw", "1"),),
            remove_query_params=("debug",),
        )
        self.assertEqual(rec.route_id, "users")
        self.assertEqual(rec.add_headers, (("x-gateway", "northstar"),))
        self.assertEqual(rec.remove_headers, ("x-internal",))
        self.assertIsNone(rec.body_replace)
        # Digest deterministic across instances.
        gw2 = _routed_gw()
        rec2 = gw2.set_transform(
            "users",
            seq=2,
            add_headers=(("x-gateway", "northstar"),),
            remove_headers=("x-internal",),
            add_query_params=(("gw", "1"),),
            remove_query_params=("debug",),
        )
        self.assertEqual(rec.digest, rec2.digest)

    def test_set_transform_unknown_route(self):
        gw = _gw()
        with self.assertRaises(UnknownRouteError):
            gw.set_transform("nope", seq=1)

    def test_set_transform_replaces_previous(self):
        gw = _routed_gw()
        first = gw.set_transform("users", seq=2, add_headers=(("a", "1"),))
        second = gw.set_transform("users", seq=3, add_headers=(("b", "2"),))
        self.assertNotEqual(first.digest, second.digest)
        self.assertIs(gw.transform_record("users"), second)

    def test_set_transform_bad_inputs(self):
        gw = _routed_gw()
        with self.assertRaises(TypeError):
            gw.set_transform("users", seq=2, add_headers="x: 1")  # type: ignore
        with self.assertRaises(TypeError):
            gw.set_transform("users", seq=2, remove_headers=(1,))  # type: ignore
        with self.assertRaises(TypeError):
            gw.set_transform("users", seq=2, body_replace=42)  # type: ignore
        with self.assertRaises(TypeError):
            gw.set_transform("users", seq=True)
        with self.assertRaises(UnknownTransformError):
            gw.transform_record("nope")


class TransformApply(unittest.TestCase):
    def test_transform_applies_headers(self):
        gw = _routed_gw()
        gw.set_transform(
            "users",
            seq=2,
            add_headers=(("x-gateway", "northstar"),),
            remove_headers=("X-Internal",),
        )
        tr = gw.transform(
            "users",
            "GET",
            "/users/42",
            (("x-internal", "secret"), ("accept", "json")),
            seq=3,
        )
        self.assertEqual(tr.header("x-gateway"), "northstar")
        self.assertIsNone(tr.header("x-internal"))
        self.assertEqual(tr.header("accept"), "json")
        self.assertEqual(tr.route_id, "users")

    def test_transform_query_params(self):
        gw = _routed_gw()
        gw.set_transform(
            "users",
            seq=2,
            add_query_params=(("gw", "1"),),
            remove_query_params=("debug",),
        )
        tr = gw.transform("users", "GET", "/users/42?debug=1&lang=en", seq=3)
        self.assertEqual(tr.path, "/users/42?lang=en&gw=1")
        # No query string at all stays clean.
        tr2 = gw.transform("users", "GET", "/users/42", seq=4)
        self.assertEqual(tr2.path, "/users/42?gw=1")

    def test_transform_body_replace(self):
        gw = _routed_gw()
        gw.set_transform("users", seq=2, body_replace='{"redacted":true}')
        tr = gw.transform("users", "POST", "/users/7", (), "sensitive", seq=3)
        self.assertEqual(tr.body, '{"redacted":true}')
        # Without body_replace the body passes through.
        gw.set_transform("users", seq=4)
        tr2 = gw.transform("users", "POST", "/users/7", (), "sensitive", seq=5)
        self.assertEqual(tr2.body, "sensitive")

    def test_transform_digest_deterministic(self):
        def run():
            gw = _routed_gw()
            gw.set_transform("users", seq=2, add_headers=(("x", "y"),))
            return gw.transform(
                "users", "GET", "/users/1", (("a", "b"),), "body", seq=3
            ).digest

        self.assertEqual(run(), run())

    def test_transform_no_config(self):
        gw = _routed_gw()
        with self.assertRaises(UnknownTransformError):
            gw.transform("users", "GET", "/users/1", seq=2)

    def test_transform_unknown_route(self):
        gw = _gw()
        with self.assertRaises(UnknownRouteError):
            gw.transform("nope", "GET", "/x", seq=1)

    def test_transform_bad_inputs(self):
        gw = _routed_gw()
        gw.set_transform("users", seq=2)
        with self.assertRaises(ValueError):
            gw.transform("users", "get", "/users/1", seq=3)
        with self.assertRaises(ValueError):
            gw.transform("users", "GET", "users/1", seq=3)
        with self.assertRaises(TypeError):
            gw.transform("users", "GET", "/users/1", seq=True)


class SetThrottle(unittest.TestCase):
    def test_set_throttle_happy_path(self):
        gw = _routed_gw()
        rec = gw.set_throttle("users", limit=10, window=100, seq=2)
        self.assertEqual(rec.limit, 10)
        self.assertEqual(rec.window, 100)
        self.assertIs(gw.throttle_record("users"), rec)

    def test_set_throttle_bad_inputs(self):
        gw = _routed_gw()
        with self.assertRaises(UnknownRouteError):
            gw.set_throttle("nope", limit=1, window=1, seq=1)
        with self.assertRaises(ValueError):
            gw.set_throttle("users", limit=0, window=10, seq=1)
        with self.assertRaises(ValueError):
            gw.set_throttle("users", limit=-1, window=10, seq=1)
        with self.assertRaises(ValueError):
            gw.set_throttle("users", limit=1, window=0, seq=1)
        with self.assertRaises(TypeError):
            gw.set_throttle("users", limit=True, window=10, seq=1)
        with self.assertRaises(UnknownThrottleError):
            gw.throttle_record("nope")


class ThrottleCheck(unittest.TestCase):
    def test_throttle_allows_within_limit(self):
        gw = _routed_gw()
        gw.set_throttle("users", limit=3, window=100, seq=1)
        for s in (2, 3, 4):
            v = gw.throttle("users", seq=s)
            self.assertTrue(v.allowed)
            self.assertEqual(v.hits_in_window, s - 2)
            self.assertIsNone(v.retry_after_seq)

    def test_throttle_denies_over_limit_as_data(self):
        gw = _routed_gw()
        gw.set_throttle("users", limit=2, window=10, seq=1)
        gw.throttle("users", seq=2)
        gw.throttle("users", seq=3)
        denied = gw.throttle("users", seq=4)
        self.assertFalse(denied.allowed)  # denial is data, not an exception
        self.assertEqual(denied.hits_in_window, 2)
        self.assertEqual(denied.limit, 2)
        self.assertEqual(denied.retry_after_seq, 2 + 10)

    def test_throttle_window_expiry(self):
        gw = _routed_gw()
        gw.set_throttle("users", limit=1, window=5, seq=1)
        self.assertTrue(gw.throttle("users", seq=2).allowed)
        self.assertFalse(gw.throttle("users", seq=3).allowed)
        # Stop attempting: the seq=3 attempt ages out once seq >= 3 + 5.
        self.assertTrue(gw.throttle("users", seq=8).allowed)

    def test_throttle_no_config(self):
        gw = _routed_gw()
        with self.assertRaises(UnknownThrottleError):
            gw.throttle("users", seq=1)

    def test_throttle_unknown_route(self):
        gw = _gw()
        with self.assertRaises(UnknownRouteError):
            gw.throttle("nope", seq=1)

    def test_throttle_bad_seq(self):
        gw = _routed_gw()
        gw.set_throttle("users", limit=1, window=5, seq=1)
        with self.assertRaises(TypeError):
            gw.throttle("users", seq=False)


class NewAuditKinds(unittest.TestCase):
    def test_new_audit_shapes(self):
        for kind in (
            "transform-set",
            "request-transformed",
            "throttle-set",
            "throttle-checked",
        ):
            ev = api_gateway_audit_event(kind, 1, route_id="users")
            self.assertEqual(ev["schema"], "audit.ndjson/1")
            self.assertEqual(ev["module"], "api-gateway")
            self.assertTrue(ev["digest"].startswith("sha256:"))

    def test_bogus_kind_still_rejected(self):
        with self.assertRaises(ValueError):
            api_gateway_audit_event("bogus", 1)


class NewRecordsFrozen(unittest.TestCase):
    def test_new_records_immutable(self):
        gw = _routed_gw()
        t = gw.set_transform("users", seq=2)
        with self.assertRaises(Exception):
            t.seq = 99  # type: ignore
        th = gw.set_throttle("users", limit=1, window=5, seq=3)
        with self.assertRaises(Exception):
            th.limit = 99  # type: ignore
        v = gw.throttle("users", seq=4)
        with self.assertRaises(Exception):
            v.allowed = False  # type: ignore


if __name__ == "__main__":
    unittest.main()
