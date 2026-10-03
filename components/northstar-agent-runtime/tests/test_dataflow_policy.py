"""Unit tests for dataflow_policy.py and its permission-gate integration.

The mechanism under test is absorbed from archestra-ai/openappa (MIT):
trust_chain + source delta + sink requires, compiled from a strict,
deterministic TOML dialect.
"""

import unittest
from pathlib import Path

from dataflow_policy import (
    DataflowPolicy,
    DataflowPolicyError,
    SessionDataflow,
)
from permissions import PermissionEngine

BASE_TOML = """\
[policy]
version = 1
trust_chain = ["public", "internal", "confidential", "restricted"]

[[policy.source]]
tool = "Read"
match_args = { path = "/etc/*" }
delta = { trust = "confidential" }

[[policy.source]]
tool = "Read"
delta = { trust = "internal" }

[[policy.sink]]
tool = "http_post"
requires = { trust = "public" }

[[policy.sink]]
tool = "mcp/mail/send"
requires = { trust = "confidential", audience = { contains = ["$to"] } }
"""


def _policy(text: str = BASE_TOML) -> DataflowPolicy:
    return DataflowPolicy.from_toml(text, source="test")


class TestStrictParsing(unittest.TestCase):
    def test_unknown_top_level_field_refused(self):
        with self.assertRaises(DataflowPolicyError):
            _policy(BASE_TOML.replace('[policy]\nversion = 1', '[policy]\nversion = 1\nbogus = 1'))

    def test_unknown_source_field_refused(self):
        with self.assertRaises(DataflowPolicyError):
            _policy(BASE_TOML + '\n[[policy.source]]\ntool = "X"\nextra = 1\ndelta = { trust = "public" }\n')

    def test_wrong_version_refused(self):
        with self.assertRaises(DataflowPolicyError):
            _policy(BASE_TOML.replace("version = 1", "version = 2"))

    def test_unknown_rank_refused(self):
        with self.assertRaises(DataflowPolicyError):
            _policy(BASE_TOML.replace('trust = "confidential"', 'trust = "topsecret"'))

    def test_empty_chain_refused(self):
        with self.assertRaises(DataflowPolicyError):
            _policy('[policy]\nversion = 1\ntrust_chain = []\n')

    def test_duplicate_ranks_refused(self):
        with self.assertRaises(DataflowPolicyError):
            _policy('[policy]\nversion = 1\ntrust_chain = ["a", "a"]\n')

    def test_invalid_toml_refused(self):
        with self.assertRaises(DataflowPolicyError):
            _policy("this is [ not toml")

    def test_missing_tool_refused(self):
        with self.assertRaises(DataflowPolicyError):
            _policy('[policy]\nversion = 1\ntrust_chain = ["a"]\n[[policy.source]]\ndelta = { trust = "a" }\n')

    def test_deterministic_compile(self):
        self.assertEqual(_policy(), _policy())

    def test_default_policy_loads(self):
        policy = DataflowPolicy.default()
        self.assertEqual(policy.version, 1)
        self.assertEqual(policy.trust_chain[0], "public")
        self.assertTrue(policy.sources)
        self.assertTrue(policy.sinks)
        self.assertTrue(Path("policy/dataflow.toml").exists())

    def test_default_policy_matches_shipped_toml(self):
        from dataflow_policy import _DEFAULT_POLICY_PATH, _DEFAULT_POLICY_TOML

        self.assertEqual(
            _DEFAULT_POLICY_PATH.read_text(encoding="utf-8"),
            _DEFAULT_POLICY_TOML,
        )
        file_policy = DataflowPolicy.from_toml_file(_DEFAULT_POLICY_PATH)
        embedded_policy = DataflowPolicy.from_toml(_DEFAULT_POLICY_TOML, source="test")
        self.assertEqual(file_policy, embedded_policy)


class TestSourceMatching(unittest.TestCase):
    def test_glob_and_arg_match(self):
        policy = _policy()
        tracker = SessionDataflow(policy)
        rule = tracker.observe("Read", {"path": "/etc/passwd"})
        self.assertIsNotNone(rule)
        self.assertEqual(policy.rank_name(tracker.trust_index), "confidential")

    def test_first_match_wins(self):
        policy = _policy()
        tracker = SessionDataflow(policy)
        # "/etc/*" rule comes first in the file: confidential, not internal.
        tracker.observe("Read", {"path": "/etc/hosts"})
        self.assertEqual(policy.rank_name(tracker.trust_index), "confidential")

    def test_fallback_rule(self):
        policy = _policy()
        tracker = SessionDataflow(policy)
        tracker.observe("Read", {"path": "notes.txt"})
        self.assertEqual(policy.rank_name(tracker.trust_index), "internal")

    def test_missing_arg_skips_pinned_rule(self):
        policy = _policy()
        tracker = SessionDataflow(policy)
        # The /etc/* rule cannot match without `path`; the fallback rule
        # (internal) applies instead — first-match-wins in file order.
        rule = tracker.observe("Read", {})
        self.assertIsNotNone(rule)
        self.assertEqual(rule.delta_trust, policy.rank_index("internal"))

    def test_no_matching_rule(self):
        policy = _policy()
        tracker = SessionDataflow(policy)
        self.assertIsNone(tracker.observe("Write", {"path": "/etc/passwd"}))

    def test_trajectory_only_rises(self):
        policy = _policy()
        tracker = SessionDataflow(policy)
        tracker.observe("Read", {"path": "/etc/passwd"})  # confidential
        tracker.observe("Read", {"path": "notes.txt"})  # internal < confidential
        self.assertEqual(policy.rank_name(tracker.trust_index), "confidential")


class TestSinkCheck(unittest.TestCase):
    def test_hot_trajectory_escalates_cold_sink(self):
        policy = _policy()
        tracker = SessionDataflow(policy)
        tracker.observe("Read", {"path": "/etc/passwd"})
        verdict = tracker.check_sink("http_post", {"url": "http://x"})
        self.assertTrue(verdict.escalate)
        self.assertIn("confidential", verdict.reason)

    def test_cool_trajectory_passes(self):
        policy = _policy()
        tracker = SessionDataflow(policy)
        verdict = tracker.check_sink("http_post", {"url": "http://x"})
        self.assertFalse(verdict.escalate)

    def test_no_sink_rule_passes(self):
        policy = _policy()
        tracker = SessionDataflow(policy)
        tracker.observe("Read", {"path": "/etc/passwd"})
        self.assertFalse(tracker.check_sink("unknown_sink", {}).escalate)

    def test_audience_ok(self):
        policy = _policy()
        tracker = SessionDataflow(policy)
        tracker.observe("mcp/mail/send", {})  # no source rule; attach audience manually
        tracker.audience = frozenset({"hr@local"})
        verdict = tracker.check_sink("mcp/mail/send", {"to": "hr@local"})
        self.assertFalse(verdict.escalate)

    def test_audience_violation(self):
        policy = _policy()
        tracker = SessionDataflow(policy)
        tracker.audience = frozenset({"hr@local"})
        verdict = tracker.check_sink("mcp/mail/send", {"to": "outsider@x"})
        self.assertTrue(verdict.escalate)

    def test_missing_template_arg_fails_closed(self):
        policy = _policy()
        tracker = SessionDataflow(policy)
        tracker.audience = frozenset({"hr@local"})
        verdict = tracker.check_sink("mcp/mail/send", {})
        self.assertTrue(verdict.escalate)

    def test_empty_audience_vacuous(self):
        policy = _policy()
        tracker = SessionDataflow(policy)
        # Public data (no audience) may go anywhere the trust check allows.
        verdict = tracker.check_sink("mcp/mail/send", {"to": "anyone@x"})
        self.assertFalse(verdict.escalate)


def _engine(callback, **kwargs):
    kw = dict(
        mode="default",
        allowed_tools=("Read", "http_post"),
        can_use_tool=callback,
        tool_kinds={"Read": "read", "http_post": "network"},
    )
    kw.update(kwargs)
    return PermissionEngine(**kw)


class TestGateIntegration(unittest.TestCase):
    def test_escalation_consults_callback_and_approves(self):
        consulted = []
        engine = _engine(lambda t, a, c: consulted.append(t) or True)
        tracker = SessionDataflow(_policy())
        engine.evaluate("Read", kind="read", mutating=False,
                        payload={"path": "/etc/passwd"}, dataflow=tracker)
        decision = engine.evaluate("http_post", kind="network", mutating=True,
                                   payload={"url": "http://x"}, dataflow=tracker)
        self.assertTrue(decision.allowed)
        self.assertEqual(consulted, ["http_post"])
        self.assertEqual(decision.source, "host_callback")
        self.assertEqual(decision.rule, "dataflow:escalation:approved")

    def test_escalation_refusal_denies(self):
        engine = _engine(lambda t, a, c: False)
        tracker = SessionDataflow(_policy())
        engine.evaluate("Read", kind="read", mutating=False,
                        payload={"path": "/etc/passwd"}, dataflow=tracker)
        decision = engine.evaluate("http_post", kind="network", mutating=True,
                                   payload={"url": "http://x"}, dataflow=tracker)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.source, "host_callback")

    def test_escalation_without_callback_fails_closed(self):
        engine = _engine(None)
        tracker = SessionDataflow(_policy())
        engine.evaluate("Read", kind="read", mutating=False,
                        payload={"path": "/etc/passwd"}, dataflow=tracker)
        decision = engine.evaluate("http_post", kind="network", mutating=True,
                                   payload={"url": "http://x"}, dataflow=tracker)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.source, "mode")
        self.assertIn("dataflow", decision.rule)

    def test_no_dataflow_unchanged_behavior(self):
        engine = _engine(lambda t, a, c: True)
        decision = engine.evaluate("http_post", kind="network", mutating=True,
                                   payload={"url": "http://x"})
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.source, "allowed_tools")

    def test_denied_call_attaches_no_label(self):
        engine = _engine(lambda t, a, c: True, disallowed_tools=("Read",))
        tracker = SessionDataflow(_policy())
        decision = engine.evaluate("Read", kind="read", mutating=False,
                                   payload={"path": "/etc/passwd"}, dataflow=tracker)
        self.assertFalse(decision.allowed)
        self.assertEqual(tracker.trust_index, 0)

    def test_denied_sink_stays_denied(self):
        engine = _engine(lambda t, a, c: True, disallowed_tools=("http_post",))
        tracker = SessionDataflow(_policy())
        engine.evaluate("Read", kind="read", mutating=False,
                        payload={"path": "/etc/passwd"}, dataflow=tracker)
        decision = engine.evaluate("http_post", kind="network", mutating=True,
                                   payload={"url": "http://x"}, dataflow=tracker)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.source, "disallowed_tools")

    def test_bypass_skips_escalation(self):
        engine = _engine(lambda t, a, c: True, mode="bypassPermissions",
                         allowed_tools=("Read",))
        tracker = SessionDataflow(_policy())
        engine.evaluate("Read", kind="read", mutating=False,
                        payload={"path": "/etc/passwd"}, dataflow=tracker)
        decision = engine.evaluate("http_post", kind="network", mutating=True,
                                   payload={"url": "http://x"}, dataflow=tracker)
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.source, "mode")


if __name__ == "__main__":
    unittest.main()
