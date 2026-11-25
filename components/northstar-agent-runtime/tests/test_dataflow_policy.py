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
    def test_default_sensitive_patterns_precede_general_etc_rule(self):
        policy = DataflowPolicy.default()
        tracker = SessionDataflow(policy)
        tracker.observe("Read", {"path": "/etc/server.pem"})
        self.assertEqual(policy.rank_name(tracker.trust_index), "restricted")

        tracker = SessionDataflow(policy)
        tracker.observe("Read", {"path": "/etc/app-credentials.json"})
        self.assertEqual(policy.rank_name(tracker.trust_index), "restricted")

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
    def test_default_policy_marks_fetch_as_public_network_sink(self):
        tracker = SessionDataflow(DataflowPolicy.default())
        tracker.observe("Read", {"path": "server.pem"})

        verdict = tracker.check_sink("Fetch", {"host": "api.example.org"})

        self.assertTrue(verdict.escalate)
        self.assertIn("restricted", verdict.reason)
        self.assertIn("public", verdict.reason)

    def test_hot_trajectory_escalates_cold_sink(self):
        policy = _policy()
        tracker = SessionDataflow(policy)
        tracker.observe("Read", {"path": "/etc/passwd"})
        verdict = tracker.check_sink("http_post", {"url": "http://x"})
        self.assertTrue(verdict.escalate)
        self.assertIn("confidential", verdict.reason)

    def test_source_and_sink_on_same_call_use_projected_source_label(self):
        policy = _policy('''\
[policy]
version = 1
trust_chain = ["public", "confidential"]
[[policy.source]]
tool = "http_post"
delta = { trust = "confidential" }
[[policy.sink]]
tool = "http_post"
requires = { trust = "public" }
''')
        tracker = SessionDataflow(policy)
        verdict = tracker.check_sink("http_post", {"url": "https://example.invalid"})
        self.assertTrue(verdict.escalate)
        self.assertIn("confidential", verdict.reason)
        self.assertEqual(policy.rank_name(tracker.trust_index), "public")

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

    def test_injected_private_memory_seeds_audience_boundary(self):
        tracker = SessionDataflow.from_memory_audience(_policy(), ("hr@local",))
        source_read = tracker.check_sink("Read", {"path": "/etc/passwd"})
        allowed = tracker.check_sink("mcp/mail/send", {"to": "hr@local"})
        denied = tracker.check_sink("mcp/mail/send", {"to": "outsider@x"})
        self.assertFalse(source_read.escalate)
        self.assertFalse(allowed.escalate)
        self.assertTrue(denied.escalate)
        self.assertTrue(tracker.audience_labeled)
        self.assertEqual(tracker.events[0]["rule"], "memory_audience_manifest")

    def test_public_memory_does_not_add_audience_restriction(self):
        tracker = SessionDataflow.from_memory_audience(_policy(), ())
        self.assertFalse(tracker.audience_labeled)
        self.assertEqual(tracker.events, [])

    def test_private_memory_escalates_unbound_and_unknown_sinks(self):
        tracker = SessionDataflow.from_memory_audience(DataflowPolicy.default(), ("hr@local",))
        for tool_name in ("send_mail", "custom_upload"):
            with self.subTest(tool=tool_name):
                verdict = tracker.check_sink(tool_name, {"to": "hr@local"})
                self.assertTrue(verdict.escalate)
                self.assertIn("audience", verdict.reason)

    def test_unknown_resumed_audience_escalates_audience_restricted_sink(self):
        policy = _policy(BASE_TOML + '''\

[[policy.sink]]
tool = "internal_sink"
requires = { trust = "restricted" }
''')
        tracker = SessionDataflow(policy, trust_index=3, audience_unknown=True)
        for tool_name, arguments in (
            ("mcp/mail/send", {"to": "hr@local"}),
            ("internal_sink", {}),
            ("unknown_sink", {}),
        ):
            with self.subTest(tool=tool_name):
                verdict = tracker.check_sink(tool_name, arguments)
                self.assertTrue(verdict.escalate)
                self.assertIn("audience is unknown", verdict.reason)

    def test_combined_source_audiences_intersect(self):
        policy = _policy('''\
[policy]
version = 1
trust_chain = ["public", "confidential"]
[[policy.source]]
tool = "ReadA"
delta = { trust = "confidential", audience = ["hr", "legal"] }
[[policy.source]]
tool = "ReadB"
delta = { trust = "confidential", audience = ["legal", "finance"] }
[[policy.sink]]
tool = "send_mail"
requires = { audience = { contains = ["$to"] } }
''')
        tracker = SessionDataflow(policy)
        tracker.observe("ReadA", {})
        tracker.observe("ReadB", {})
        self.assertEqual(tracker.audience, frozenset({"legal"}))
        self.assertFalse(tracker.check_sink("send_mail", {"to": "legal"}).escalate)
        denied = tracker.check_sink("send_mail", {"to": "hr"})
        self.assertTrue(denied.escalate)

    def test_empty_intersection_remains_an_enforced_audience_label(self):
        policy = _policy('''\
[policy]
version = 1
trust_chain = ["public"]
[[policy.source]]
tool = "ReadA"
delta = { audience = ["hr"] }
[[policy.source]]
tool = "ReadB"
delta = { audience = ["finance"] }
[[policy.sink]]
tool = "send_mail"
requires = { audience = { contains = ["$to"] } }
''')
        tracker = SessionDataflow(policy)
        tracker.observe("ReadA", {})
        tracker.observe("ReadB", {})
        self.assertEqual(tracker.audience, frozenset())
        verdict = tracker.check_sink("send_mail", {"to": "hr"})
        self.assertTrue(verdict.escalate)
        self.assertIn("trajectory audience is []", verdict.reason)

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
    def test_default_policy_denies_fetch_after_sensitive_read_without_approval(self):
        engine = _engine(None, allowed_tools=("Read", "Fetch"),
                         tool_kinds={"Read": "read", "Fetch": "network"})
        tracker = SessionDataflow(DataflowPolicy.default())
        engine.evaluate("Read", kind="read", mutating=False,
                        payload={"path": "server.pem"}, dataflow=tracker)

        decision = engine.evaluate("Fetch", kind="network", mutating=True,
                                   payload={"host": "api.example.org"}, dataflow=tracker)

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.rule, "mode:default:dataflow_no_callback")
        self.assertTrue(decision.details["dataflow"]["sink_escalated"])

    def test_audit_sink_mutation_cannot_rewrite_returned_permission_evidence(self):
        def mutating_sink(record):
            record["details"]["dataflow"]["trust"] = "public"
            record["details"]["dataflow"]["source_rule"] = "forged"

        engine = _engine(None, audit_sink=mutating_sink)
        tracker = SessionDataflow(_policy())
        decision = engine.evaluate(
            "Read", kind="read", mutating=False,
            payload={"path": "/etc/passwd"}, dataflow=tracker,
        )

        self.assertTrue(decision.allowed)
        self.assertEqual(decision.details["dataflow"]["trust"], "confidential")
        self.assertEqual(decision.details["dataflow"]["source_rule"], "Read")

    def test_source_label_transition_is_in_content_free_audit_record(self):
        records = []
        engine = _engine(None, audit_sink=records.append)
        tracker = SessionDataflow(_policy())
        engine.evaluate(
            "Read", kind="read", mutating=False,
            payload={"path": "/etc/private-record.txt"}, dataflow=tracker,
        )
        self.assertEqual(len(records), 1)
        evidence = records[0]["details"]["dataflow"]
        self.assertEqual(evidence["source_rule"], "Read")
        self.assertEqual(evidence["trust"], "confidential")
        self.assertFalse(evidence["audience_labeled"])
        self.assertNotIn("private-record", str(records[0]))

    def test_denied_sink_escalation_is_present_in_audit_record(self):
        records = []
        engine = _engine(None, audit_sink=records.append)
        tracker = SessionDataflow(_policy())
        engine.evaluate("Read", kind="read", mutating=False,
                        payload={"path": "/etc/passwd"}, dataflow=tracker)
        decision = engine.evaluate(
            "http_post", kind="network", mutating=True,
            payload={"url": "https://example.invalid"}, dataflow=tracker,
        )
        self.assertFalse(decision.allowed)
        denial = records[-1]
        self.assertEqual(denial["event"], "permission.deny")
        evidence = denial["details"]["dataflow"]
        self.assertTrue(evidence["sink_escalated"])
        self.assertEqual(evidence["trust"], "confidential")

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

    def test_dataflow_escalation_callback_cannot_mutate_nested_payload(self):
        payload = {"request": {"url": "https://approved.invalid"}}

        def approve(_tool, callback_payload, _context):
            callback_payload["request"]["url"] = "https://unapproved.invalid"
            return True

        engine = _engine(approve)
        tracker = SessionDataflow(_policy())
        engine.evaluate("Read", kind="read", mutating=False,
                        payload={"path": "/etc/passwd"}, dataflow=tracker)
        decision = engine.evaluate(
            "http_post", kind="network", mutating=True,
            payload=payload, dataflow=tracker,
        )

        self.assertTrue(decision.allowed)
        self.assertEqual(payload, {"request": {"url": "https://approved.invalid"}})
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


class TestCamelIntegrityAndSubagentTaint(unittest.TestCase):
    """CaMeL-style untrusted-input integrity taint across tools, subagents, and resume."""

    def test_camel_default_taints_after_external_source_and_escalates_sinks(self):
        policy = DataflowPolicy.camel_default()
        self.assertTrue(policy.has_integrity_rules)
        tracker = SessionDataflow(policy)

        # Clean trajectory allows initial Fetch without integrity escalation.
        self.assertFalse(tracker.check_sink("Fetch", {"host": "example.com"}).escalate)

        # Observing Fetch taints the trajectory.
        tracker.observe("Fetch", {"host": "example.com"})
        self.assertTrue(tracker.untrusted_tainted)
        self.assertIn("tool:Fetch", tracker.untrusted_sources)

        for sink_name in ("Shell", "Edit", "Write", "Task", "Fetch", "mcp__slack__post"):
            verdict = tracker.check_sink(sink_name, {})
            self.assertTrue(verdict.escalate, f"{sink_name} should escalate after untrusted Fetch")
            self.assertIn("CaMeL integrity taint", verdict.reason)

    def test_camel_toml_strict_parsing_accepts_rules_and_rejects_unknown_fields(self):
        valid = DataflowPolicy.from_toml(
            """
            [policy]
            version = 1
            trust_chain = ["public", "restricted"]

            [[policy.untrusted_source]]
            tool = "mcp__*"
            label = "external_mcp"

            [[policy.untrusted_source]]
            tool = "*"
            match_trust = ["untrusted"]
            label = "runtime_untrusted"

            [[policy.privileged_sink]]
            tool = "Shell"
            description = "host command"
            """
        )
        self.assertTrue(valid.has_integrity_rules)
        tracker = SessionDataflow(valid)
        tracker.observe_provenance("CustomTool", source="tool:CustomTool", trust="untrusted")
        self.assertTrue(tracker.untrusted_tainted)
        self.assertTrue(tracker.check_sink("Shell", {"command": "id"}).escalate)

        with self.assertRaises(DataflowPolicyError):
            DataflowPolicy.from_toml(
                """
                [policy]
                version = 1
                trust_chain = ["public"]

                [[policy.untrusted_source]]
                tool = "Fetch"
                bogus = true
                """
            )

    def test_camel_strict_blocks_edit_after_workspace_read_and_consults_callback(self):
        import tempfile
        from pathlib import Path
        import sdk
        from providers.scripted import ScriptedTurn

        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            target = ws / "notes.txt"
            target.write_text("untrusted repo content\n", encoding="utf-8")

            turns = (
                ScriptedTurn.tool("Read", {"path": "notes.txt"}),
                ScriptedTurn.tool("Write", {"path": "out.txt", "content": "injected"}),
                ScriptedTurn.text("done"),
            )

            # 1) Without callback: even acceptEdits fails closed after untrusted Read.
            blocked = sdk.run(
                sdk.RunOptions(
                    prompt="read then write",
                    workspace=str(ws),
                    provider="scripted",
                    scripted_turns=turns,
                    permission_mode="acceptEdits",
                    dataflow_policy=DataflowPolicy.camel_strict(),
                    shell_backend="process",
                    shell_seccomp="off",
                    shell_capdrop="off",
                    workspace_agents=False,
                )
            )
            self.assertFalse((ws / "out.txt").exists())
            self.assertTrue(blocked.permission_denials)
            self.assertIn("CaMeL integrity taint", blocked.permission_denials[0]["reason"])

            # 2) With host callback: callback sees the CaMeL escalation reason and approves.
            seen_hints: list[str] = []

            def _approve(tool_name, tool_input, ctx):
                seen_hints.append(ctx.reason_hint)
                return {"allowed": True, "reason": "operator approved tainted write"}

            approved = sdk.run(
                sdk.RunOptions(
                    prompt="read then write",
                    workspace=str(ws),
                    provider="scripted",
                    scripted_turns=turns,
                    permission_mode="acceptEdits",
                    dataflow_policy=DataflowPolicy.camel_strict(),
                    can_use_tool=_approve,
                    shell_backend="process",
                    shell_seccomp="off",
                    shell_capdrop="off",
                    workspace_agents=False,
                )
            )
            self.assertEqual(approved.subtype, "success")
            self.assertEqual((ws / "out.txt").read_text(encoding="utf-8"), "injected")
            self.assertTrue(any("CaMeL integrity taint" in h for h in seen_hints))

    def test_camel_taint_propagates_across_subagents_both_directions(self):
        import tempfile
        from pathlib import Path
        from loop import AgentRuntime, RuntimeConfig
        from providers.scripted import ScriptedProvider, ScriptedTurn

        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "notes.txt").write_text("untrusted payload\n", encoding="utf-8")

            # Direction 1: Child reads untrusted file -> returns to parent -> parent Write blocked!
            parent_turns = [
                ScriptedTurn.tool("Task", {"agent": "explorer", "prompt": "read notes.txt"}),
                ScriptedTurn.tool("Write", {"path": "from_parent.txt", "content": "pwned"}),
                ScriptedTurn.text("parent finished"),
            ]
            child_turns = [
                ScriptedTurn.tool("Read", {"path": "notes.txt"}),
                ScriptedTurn.text("child read notes"),
            ]
            # ScriptedProvider shares one script or per-agent provider via providers dict.
            rt1 = AgentRuntime(
                provider=ScriptedProvider(parent_turns),
                providers={"scripted": ScriptedProvider(child_turns)},
                config=RuntimeConfig(
                    workspace=str(ws),
                    permission_mode="acceptEdits",
                    dataflow_policy=DataflowPolicy.camel_strict(),
                    shell_backend="process",
                    shell_seccomp="off",
                    shell_capdrop="off",
                ),
            )
            # Run via child_provider factory: explorer uses parent's provider unless overridden,
            # so supply a provider that serves parent + child turns sequentially.
            combined_turns = [
                ScriptedTurn.tool("Task", {"agent": "explorer", "prompt": "read notes.txt"}),
                # Child turns execute before parent's next turn:
                ScriptedTurn.tool("Read", {"path": "notes.txt"}),
                ScriptedTurn.text("child read notes"),
                # Back in parent:
                ScriptedTurn.tool("Write", {"path": "from_parent.txt", "content": "pwned"}),
                ScriptedTurn.text("parent finished"),
            ]
            rt_child_to_parent = AgentRuntime(
                provider=ScriptedProvider(combined_turns),
                config=RuntimeConfig(
                    workspace=str(ws),
                    permission_mode="acceptEdits",
                    dataflow_policy=DataflowPolicy.camel_strict(),
                    shell_backend="process",
                    shell_seccomp="off",
                    shell_capdrop="off",
                ),
            )
            events1 = list(rt_child_to_parent.run("delegate read then write"))
            self.assertTrue(rt_child_to_parent.dataflow.untrusted_tainted)
            self.assertTrue(
                any("subagent:explorer" in src for src in rt_child_to_parent.dataflow.untrusted_sources)
            )
            self.assertFalse((ws / "from_parent.txt").exists())
            result1 = [e for e in events1 if type(e).__name__ == "ResultMessage"][-1]
            self.assertTrue(
                any("CaMeL integrity taint" in d["reason"] for d in result1.permission_denials)
            )

            # Direction 2: Parent reads untrusted file -> delegates to general subagent
            # (approved for Task only) -> child's Write is STILL blocked by inherited taint!
            seen_calls: list[tuple[str, str]] = []

            def _approve_only_task(tool_name, tool_input, ctx):
                seen_calls.append((tool_name, ctx.agent))
                if tool_name == "Task":
                    return {"allowed": True, "reason": "allow delegation"}
                return {"allowed": False, "reason": "deny child write under taint"}

            parent_to_child_turns = [
                ScriptedTurn.tool("Read", {"path": "notes.txt"}),
                ScriptedTurn.tool("Task", {"agent": "general", "prompt": "write a file"}),
                # Child turns:
                ScriptedTurn.tool("Write", {"path": "from_child.txt", "content": "pwned"}),
                ScriptedTurn.text("child done"),
                # Parent finish:
                ScriptedTurn.text("parent done"),
            ]
            rt_parent_to_child = AgentRuntime(
                provider=ScriptedProvider(parent_to_child_turns),
                can_use_tool=_approve_only_task,
                config=RuntimeConfig(
                    workspace=str(ws),
                    permission_mode="acceptEdits",
                    dataflow_policy=DataflowPolicy.camel_strict(),
                    shell_backend="process",
                    shell_seccomp="off",
                    shell_capdrop="off",
                ),
            )
            list(rt_parent_to_child.run("read then delegate write"))
            self.assertFalse((ws / "from_child.txt").exists())
            self.assertIn(("Task", "main"), seen_calls)
            self.assertIn(("Write", "general"), seen_calls)

    def test_camel_resumed_session_marks_untrusted_taint_conservatively(self):
        import tempfile
        from pathlib import Path
        import sdk
        from providers.scripted import ScriptedTurn

        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            sess_dir = ws / ".sessions"
            r1 = sdk.run(
                sdk.RunOptions(
                    prompt="first turn",
                    workspace=str(ws),
                    provider="scripted",
                    scripted_turns=(ScriptedTurn.text("ok"),),
                    permission_mode="acceptEdits",
                    dataflow_policy=DataflowPolicy.camel_default(),
                    session_dir=str(sess_dir),
                    shell_backend="process",
                    shell_seccomp="off",
                    shell_capdrop="off",
                    workspace_agents=False,
                )
            )
            # Resumed turn under camel_default conservatively treats prior context as tainted.
            r2 = sdk.run(
                sdk.RunOptions(
                    prompt="second turn write",
                    workspace=str(ws),
                    provider="scripted",
                    scripted_turns=(
                        ScriptedTurn.tool("Write", {"path": "resumed.txt", "content": "x"}),
                        ScriptedTurn.text("done"),
                    ),
                    permission_mode="acceptEdits",
                    dataflow_policy=DataflowPolicy.camel_default(),
                    session_dir=str(sess_dir),
                    shell_backend="process",
                    shell_seccomp="off",
                    shell_capdrop="off",
                    workspace_agents=False,
                ),
                resume=r1.session_id,
            )
            self.assertFalse((ws / "resumed.txt").exists())
            self.assertTrue(r2.permission_denials)


if __name__ == "__main__":
    unittest.main()
