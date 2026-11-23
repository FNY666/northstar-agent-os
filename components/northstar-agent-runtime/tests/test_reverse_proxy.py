"""Tests for reverse_proxy (nginx-style routing decisions)."""

import ast
import unittest
from pathlib import Path

from reverse_proxy import (
    REVERSE_PROXY_VERSION,
    SCHEMA_PIN,
    BadHeaderRuleError,
    BadRequestError,
    BadRewriteError,
    DuplicateUpstreamError,
    NoUpstreamAvailable,
    ReverseProxy,
    ReverseProxyError,
    UnknownUpstreamError,
    reverse_proxy_audit_event,
)


def _proxy(names=("a", "b")):
    rp = ReverseProxy()
    for name in names:
        rp.add_upstream(name, f"{name}.internal", 8080)
    return rp


class VersionPinsTest(unittest.TestCase):
    def test_pins(self):
        self.assertEqual(REVERSE_PROXY_VERSION, "reverse-proxy.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.reverse-proxy.v1")

    def test_strategy_bad(self):
        with self.assertRaises(ReverseProxyError):
            ReverseProxy(strategy="bogus")


class UpstreamRegistrationTest(unittest.TestCase):
    def test_add_happy(self):
        rp = _proxy()
        self.assertEqual([u.name for u in rp.upstreams()], ["a", "b"])

    def test_duplicate(self):
        rp = _proxy()
        with self.assertRaises(DuplicateUpstreamError):
            rp.add_upstream("a", "a2.internal", 9090)

    def test_bad_values(self):
        rp = ReverseProxy()
        with self.assertRaises(ReverseProxyError):
            rp.add_upstream("", "h", 8080)
        with self.assertRaises(ReverseProxyError):
            rp.add_upstream("x", "", 8080)
        with self.assertRaises(ReverseProxyError):
            rp.add_upstream("x", "h", 0)
        with self.assertRaises(ReverseProxyError):
            rp.add_upstream("x", "h", 8080, weight=0)
        with self.assertRaises(ReverseProxyError):
            rp.add_upstream("x", "h", 8080, max_fails=True)

    def test_remove_and_unknown(self):
        rp = _proxy()
        rp.remove_upstream("a")
        self.assertEqual([u.name for u in rp.upstreams()], ["b"])
        with self.assertRaises(UnknownUpstreamError):
            rp.remove_upstream("a")
        with self.assertRaises(UnknownUpstreamError):
            rp.mark_down("a")


class RoundRobinTest(unittest.TestCase):
    def test_rotation(self):
        rp = _proxy()
        got = [rp.proxy(rp.make_request("GET", "/", {}, "1.2.3.4", i)).upstream_name
               for i in range(4)]
        self.assertEqual(got, ["a", "b", "a", "b"])

    def test_down_skipped(self):
        rp = _proxy()
        rp.mark_down("a")
        for i in range(3):
            d = rp.proxy(rp.make_request("GET", "/", {}, "1.2.3.4", i))
            self.assertEqual(d.upstream_name, "b")

    def test_all_down_refuses(self):
        rp = _proxy()
        rp.mark_down("a")
        rp.mark_down("b")
        with self.assertRaises(NoUpstreamAvailable):
            rp.proxy(rp.make_request("GET", "/", {}, "1.2.3.4", 0))


class WeightedTest(unittest.TestCase):
    def test_weighted_ratio(self):
        rp = ReverseProxy(strategy="weighted")
        rp.add_upstream("heavy", "h.internal", 80, weight=3)
        rp.add_upstream("light", "l.internal", 80, weight=1)
        got = [rp.proxy(rp.make_request("GET", "/", {}, "1.2.3.4", i)).upstream_name
               for i in range(4)]
        self.assertEqual(got.count("heavy"), 3)
        self.assertEqual(got.count("light"), 1)


class LeastConnTest(unittest.TestCase):
    def test_lowest_wins(self):
        rp = ReverseProxy(strategy="least_conn")
        rp.add_upstream("a", "a.internal", 80)
        rp.add_upstream("b", "b.internal", 80)
        rp.set_inflight("a", 5)
        rp.set_inflight("b", 1)
        d = rp.proxy(rp.make_request("GET", "/", {}, "9.9.9.9", 0))
        self.assertEqual(d.upstream_name, "b")
        with self.assertRaises(ReverseProxyError):
            rp.set_inflight("a", -1)


class IpHashTest(unittest.TestCase):
    def test_deterministic_and_stable(self):
        rp1 = ReverseProxy(strategy="ip_hash")
        rp2 = ReverseProxy(strategy="ip_hash")
        for rp in (rp1, rp2):
            rp.add_upstream("a", "a.internal", 80)
            rp.add_upstream("b", "b.internal", 80)
        req = rp1.make_request("GET", "/", {}, "203.0.113.7", 0)
        self.assertEqual(
            rp1.proxy(req).upstream_name, rp2.proxy(req).upstream_name
        )

    def test_same_ip_sticks(self):
        rp = ReverseProxy(strategy="ip_hash")
        rp.add_upstream("a", "a.internal", 80)
        rp.add_upstream("b", "b.internal", 80)
        first = rp.proxy(rp.make_request("GET", "/", {}, "10.0.0.1", 0)).upstream_name
        second = rp.proxy(rp.make_request("GET", "/", {}, "10.0.0.1", 1)).upstream_name
        self.assertEqual(first, second)


class RewriteTest(unittest.TestCase):
    def test_first_match_wins(self):
        rp = _proxy()
        rp.rewrite(r"^/api/(.*)$", r"/v2/\1")
        rp.rewrite(r"^/v2/(.*)$", r"/v3/\1")
        d = rp.proxy(rp.make_request("GET", "/api/users", {}, "1.1.1.1", 0))
        self.assertEqual(d.rewritten_path, "/v2/users")

    def test_no_match_passthrough(self):
        rp = _proxy()
        rp.rewrite(r"^/api/", "/v2/")
        d = rp.proxy(rp.make_request("GET", "/static/x", {}, "1.1.1.1", 0))
        self.assertEqual(d.rewritten_path, "/static/x")

    def test_bad_regex_rejected_at_registration(self):
        rp = ReverseProxy()
        with self.assertRaises(BadRewriteError):
            rp.rewrite("([a-z", "/x")

    def test_rules_view(self):
        rp = ReverseProxy()
        rp.rewrite("^/a", "/b")
        self.assertEqual(len(rp.rules()), 1)


class HeaderTest(unittest.TestCase):
    def test_hop_by_hop_stripped_host_xff(self):
        rp = _proxy()
        req = rp.make_request(
            "GET",
            "/",
            {"Connection": "keep-alive", "X-Custom": "yes"},
            "5.6.7.8",
            0,
        )
        d = rp.proxy(req)
        out = dict(d.outgoing_headers)
        self.assertNotIn("Connection", out)
        self.assertEqual(out["Host"], d.upstream_host)
        self.assertEqual(out["X-Forwarded-For"], "5.6.7.8")
        self.assertEqual(out["X-Custom"], "yes")

    def test_xff_appended(self):
        rp = _proxy()
        req = rp.make_request("GET", "/", {"X-Forwarded-For": "1.1.1.1"}, "2.2.2.2", 0)
        d = rp.proxy(req)
        self.assertEqual(dict(d.outgoing_headers)["X-Forwarded-For"], "1.1.1.1, 2.2.2.2")

    def test_header_rules_set_remove(self):
        rp = _proxy()
        rp.header_rule("set", "X-Tenant", "acme")
        rp.header_rule("remove", "X-Secret")
        req = rp.make_request("GET", "/", {"X-Secret": "shh"}, "3.3.3.3", 0)
        d = rp.proxy(req)
        out = dict(d.outgoing_headers)
        self.assertEqual(out["X-Tenant"], "acme")
        self.assertNotIn("X-Secret", out)

    def test_bad_header_rule(self):
        rp = ReverseProxy()
        with self.assertRaises(BadHeaderRuleError):
            rp.header_rule("mangle", "X-A")
        with self.assertRaises(BadHeaderRuleError):
            rp.header_rule("set", "")


class FailureHandlingTest(unittest.TestCase):
    def test_note_failure_auto_down(self):
        rp = _proxy()
        rp.note_failure("a")  # max_fails=1 by default
        d = rp.proxy(rp.make_request("GET", "/", {}, "1.1.1.1", 0))
        self.assertEqual(d.upstream_name, "b")
        report = rp.health()
        states = {name: (st, fails) for name, st, fails in report.states}
        self.assertEqual(states["a"][0], "down")
        self.assertEqual(states["a"][1], 1)

    def test_mark_up_resets(self):
        rp = _proxy()
        rp.note_failure("a")
        rp.mark_up("a")
        got = [rp.proxy(rp.make_request("GET", "/", {}, "1.1.1.1", i)).upstream_name
               for i in range(2)]
        self.assertIn("a", got)

    def test_unknown_failure(self):
        rp = ReverseProxy()
        with self.assertRaises(UnknownUpstreamError):
            rp.note_failure("ghost")


class RequestValidationTest(unittest.TestCase):
    def test_bad_request_type(self):
        rp = _proxy()
        with self.assertRaises(BadRequestError):
            rp.proxy("not-a-request")  # type: ignore[arg-type]

    def test_bad_seq(self):
        rp = _proxy()
        with self.assertRaises(ReverseProxyError):
            rp.proxy(rp.make_request("GET", "/", {}, "1.1.1.1", -1))

    def test_bad_headers_mapping(self):
        rp = _proxy()
        with self.assertRaises(BadRequestError):
            rp.make_request("GET", "/", [("a", "b")], "1.1.1.1", 0)  # type: ignore[arg-type]

    def test_empty_path(self):
        rp = ReverseProxy()
        rp.add_upstream("a", "a.internal", 80)
        with self.assertRaises(BadRequestError):
            rp.proxy(rp.make_request("GET", "", {}, "1.1.1.1", 0))


class DigestAndAuditTest(unittest.TestCase):
    def test_digest_pinned_and_deterministic(self):
        rp1, rp2 = _proxy(), _proxy()
        d1 = rp1.proxy(rp1.make_request("GET", "/x", {}, "1.1.1.1", 7))
        d2 = rp2.proxy(rp2.make_request("GET", "/x", {}, "1.1.1.1", 7))
        self.assertTrue(d1.digest.startswith("sha256:"))
        self.assertEqual(d1.digest, d2.digest)

    def test_audit_shapes(self):
        rec = reverse_proxy_audit_event("routed", 3, {"upstream": "a"})
        self.assertEqual(rec["event"], "reverse-proxy")
        self.assertEqual(rec["kind"], "routed")
        self.assertEqual(rec["audit_seq"], 3)
        self.assertEqual(rec["version"], "reverse-proxy.v1")
        self.assertEqual(rec["schema"], "northstar.reverse-proxy.v1")
        with self.assertRaises(ReverseProxyError):
            reverse_proxy_audit_event("bogus", 0)
        with self.assertRaises(ReverseProxyError):
            reverse_proxy_audit_event("routed", -1)
        with self.assertRaises(ReverseProxyError):
            reverse_proxy_audit_event("routed", 0, detail="nope")


class StdlibOnlyTest(unittest.TestCase):
    def test_stdlib_only(self):
        path = Path(__file__).resolve().parent.parent / "reverse_proxy.py"
        tree = ast.parse(path.read_text())
        allowed = {
            "hashlib", "re", "threading", "dataclasses", "enum", "typing",
            "__future__",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertIn(alias.name.split(".")[0], allowed, alias.name)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn((node.module or "").split(".")[0], allowed, node.module)


class MainTest(unittest.TestCase):
    def test_main(self):
        import reverse_proxy as mod

        mod.main()


if __name__ == "__main__":
    unittest.main()
