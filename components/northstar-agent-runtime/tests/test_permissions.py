"""The three permission layers, the four modes, and delegation gating by tool.
"""
from __future__ import annotations

import unittest

import support  # noqa: F401
from support import RuntimeTestCase, text_turn, tool_turn

from permissions import (
    PERMISSION_MODES,
    PT_DUPLICATE,
    PT_FACT_MISSING,
    PT_PRICE,
    PT_RATE,
    PT_SIZE,
    PermissionConfig,
    PermissionEngine,
    PermissionRequestContext,
    PreTradeRiskConfig,
    digest_arguments,
    normalise_names,
    subtract,
    validate_mode,
)
from tools import ToolRegistry, ToolSpec


def registry_with_extra() -> ToolRegistry:
    """Adds an exec-classified tool so acceptEdits has something to refuse."""
    from tools import ToolResult

    registry = ToolRegistry()
    registry.register(
        ToolSpec(
            name="Bash",
            description="run a command",
            input_schema={},
            handler=lambda payload, ctx: ToolResult.ok("ran"),
            kind="exec",
        )
    )
    return registry


class LayerOrderTests(unittest.TestCase):
    def make(self, **kwargs) -> PermissionEngine:
        return PermissionEngine(PermissionConfig(**kwargs))

    def test_disallowed_tools_beats_everything_including_bypass(self):
        for mode in PERMISSION_MODES:
            with self.subTest(mode=mode):
                engine = self.make(
                    mode=mode,
                    allowed_tools=("Write",),
                    disallowed_tools=("Write",),
                    can_use_tool=lambda name, payload, ctx: True,
                )
                decision = engine.evaluate("Write", kind="edit")
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.source, "disallowed_tools")

    def test_allowed_tools_auto_approves_before_the_mode_is_consulted(self):
        engine = self.make(mode="default", allowed_tools=("Write",))
        decision = engine.evaluate("Write", kind="edit")
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.source, "allowed_tools")

    def test_an_overlap_is_reported_but_never_raises_because_deny_wins(self):
        config = PermissionConfig(mode="default", allowed_tools=("Read", "Write"), disallowed_tools=("Write",))
        self.assertEqual(config.overlap, ("write",))  # canonical form
        engine = PermissionEngine(config)
        self.assertTrue(engine.evaluate("Read", kind="read").allowed)
        self.assertFalse(engine.evaluate("Write", kind="edit").allowed)

    def test_subtract_is_the_only_correct_way_to_combine_cli_lists(self):
        self.assertEqual(subtract(["Read", "Write"], ["Write"]), ("Read",))
        self.assertEqual(subtract([], ["Write"]), ())

    def test_names_are_normalised_and_bare_strings_refused(self):
        self.assertEqual(normalise_names([" Read ", "Read", "", "Grep"]), ("Read", "Grep"))
        with self.assertRaises(TypeError):
            normalise_names("Read")

    def test_unknown_mode_is_refused_at_construction(self):
        self.assertEqual(validate_mode("plan"), "plan")
        with self.assertRaises(ValueError):
            validate_mode("yolo")


class ModeTests(unittest.TestCase):
    def test_default_mode_allows_read_only_and_refuses_mutating_without_a_callback(self):
        engine = PermissionEngine(PermissionConfig(mode="default"))
        self.assertTrue(engine.evaluate("Read", kind="read").allowed)
        decision = engine.evaluate("Write", kind="edit")
        self.assertFalse(decision.allowed)
        self.assertIn("no host approval callback", decision.reason)

    def test_default_mode_asks_the_host_callback_for_mutating_tools(self):
        asked: list[tuple[str, dict]] = []

        def approve(name, payload, ctx):
            asked.append((name, payload))
            return True

        engine = PermissionEngine(PermissionConfig(mode="default", can_use_tool=approve))
        decision = engine.evaluate("Write", kind="edit", payload={"path": "a.txt"})
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.source, "host_callback")
        self.assertEqual(asked, [("Write", {"path": "a.txt"})])

    def test_a_callback_that_raises_fails_closed(self):
        def explode(name, payload, ctx):
            raise RuntimeError("approval service down")

        engine = PermissionEngine(PermissionConfig(mode="default", can_use_tool=explode))
        decision = engine.evaluate("Write", kind="edit")
        self.assertFalse(decision.allowed)
        self.assertIn("failing closed", decision.reason)

    def test_every_callback_verdict_shape_is_understood(self):
        cases = [
            (True, True),
            (False, False),
            ("allow", True),
            ("deny", False),
            ({"allowed": True}, True),
            ({"allow": False, "reason": "nope"}, False),
            ("nonsense", False),
            (None, False),
        ]
        for verdict, expected in cases:
            with self.subTest(verdict=str(verdict)):
                engine = PermissionEngine(PermissionConfig(mode="default", can_use_tool=lambda *args: verdict))
                self.assertEqual(engine.evaluate("Write", kind="edit").allowed, expected)

    def test_a_dict_reason_reaches_the_denial_text(self):
        engine = PermissionEngine(PermissionConfig(mode="default", can_use_tool=lambda *args: {"allowed": False, "reason": "outside business hours"}))
        self.assertIn("outside business hours", engine.evaluate("Write", kind="edit").reason)

    def test_plan_mode_is_a_hard_read_only_boundary(self):
        approve_everything = PermissionEngine(PermissionConfig(mode="plan", can_use_tool=lambda *args: True))
        decision = approve_everything.evaluate("Write", kind="edit")
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.rule, "mode:plan")
        self.assertTrue(approve_everything.evaluate("Grep", kind="read").allowed)

    def test_accept_edits_approves_edits_but_not_execution(self):
        engine = PermissionEngine(PermissionConfig(mode="acceptEdits"))
        self.assertTrue(engine.evaluate("Edit", kind="edit").allowed)
        self.assertTrue(engine.evaluate("Write", kind="edit").allowed)
        refused = engine.evaluate("Bash", kind="exec")
        self.assertFalse(refused.allowed)
        self.assertIn("no host approval callback", refused.reason)

    def test_bypass_permissions_still_respects_the_deny_list(self):
        engine = PermissionEngine(PermissionConfig(mode="bypassPermissions", disallowed_tools=("Bash",)))
        self.assertTrue(engine.evaluate("Bash", kind="exec").allowed is False)
        self.assertTrue(engine.evaluate("rm", kind="exec").allowed)

    def test_unknown_tools_are_refused_rather_than_defaulted_open(self):
        engine = PermissionEngine(PermissionConfig(mode="bypassPermissions"))
        decision = engine.evaluate("Mystery", kind="other", known=False)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.source, "unknown_tool")

    def test_a_delegation_tool_is_not_classified_as_mutating(self):
        engine = PermissionEngine(PermissionConfig(mode="default"))
        decision = engine.evaluate("Task", kind="task", mutating=False)
        self.assertTrue(decision.allowed, "denying Task by name would prevent subagents existing at all")


class DelegationGateTests(unittest.TestCase):
    def test_each_declared_tool_is_checked_on_its_own_merits(self):
        registry = registry_with_extra()
        engine = PermissionEngine(PermissionConfig(mode="default"))
        verdict = engine.check_delegation(
            "general",
            ("Read", "Grep", "Write"),
            kinds={**registry.kinds(), "Read": "read", "Grep": "read", "Write": "edit"},
        )
        self.assertFalse(verdict.ok)
        self.assertEqual([name for name, _reason in verdict.denied], ["Write"])
        self.assertEqual(verdict.allowed, ("Read", "Grep"))

    def test_the_failure_text_names_the_tool_not_the_task_wrapper(self):
        engine = PermissionEngine(PermissionConfig(mode="plan"))
        verdict = engine.check_delegation("general", ("Read", "Edit"), kinds={"Read": "read", "Edit": "edit"})
        self.assertIn("Edit", verdict.summary)
        self.assertNotIn("Task", verdict.summary)

    def test_host_extra_disallow_list_reaches_subagents(self):
        engine = PermissionEngine(PermissionConfig(mode="default"))
        verdict = engine.check_delegation("general", ("Read", "Grep"), kinds={"Read": "read", "Grep": "read"}, disallowed_extra=("Grep",))
        self.assertFalse(verdict.ok)
        self.assertEqual(verdict.denied[0][0], "Grep")

    def test_stable_identity_accepts_key_fingerprint(self):
        from permissions import PermissionConfig, PermissionEngine

        engine = PermissionEngine(PermissionConfig(mode="default"))
        fingerprint = "a" * 64
        verdict = engine.check_delegation(
            fingerprint,
            ("Read",),
            kinds={"Read": "read"},
            require_stable_identity=True,
        )
        self.assertTrue(verdict.ok)

    def test_stable_identity_accepts_did(self):
        from permissions import PermissionConfig, PermissionEngine

        engine = PermissionEngine(PermissionConfig(mode="default"))
        verdict = engine.check_delegation(
            "did:example:123456",
            ("Read",),
            kinds={"Read": "read"},
            require_stable_identity=True,
        )
        self.assertTrue(verdict.ok)

    def test_display_name_rejected_when_stable_required(self):
        from permissions import PermissionConfig, PermissionEngine

        engine = PermissionEngine(PermissionConfig(mode="default"))
        verdict = engine.check_delegation(
            "general",
            ("Read", "Grep"),
            kinds={"Read": "read", "Grep": "read"},
            require_stable_identity=True,
        )
        self.assertFalse(verdict.ok)
        self.assertEqual(len(verdict.denied), 2)
        self.assertIn("stable cryptographic identity", verdict.denied[0][1])

    def test_display_name_allowed_by_default(self):
        # Opt-in: without the flag, display names work as before.
        from permissions import PermissionConfig, PermissionEngine

        engine = PermissionEngine(PermissionConfig(mode="default"))
        verdict = engine.check_delegation(
            "general", ("Read",), kinds={"Read": "read"}
        )
        self.assertTrue(verdict.ok)


class OffensiveToolingTests(unittest.TestCase):
    def test_nmap_denied_by_default(self):
        from permissions import PermissionConfig, PermissionEngine

        engine = PermissionEngine(
            PermissionConfig(mode="default", can_use_tool=lambda n, p, c: True),
            tool_kinds={"nmap_scan": "exec"},
        )
        d = engine.evaluate("nmap_scan", kind="exec", payload={})
        self.assertFalse(d.allowed)
        self.assertEqual(d.rule, "offensive:deny_by_default")

    def test_metasploit_denied_by_default(self):
        from permissions import is_offensive_tool

        self.assertTrue(is_offensive_tool("metasploit"))
        self.assertTrue(is_offensive_tool("MSFConsole"))
        self.assertTrue(is_offensive_tool("sqlmap"))

    def test_benign_tools_unaffected(self):
        from permissions import is_offensive_tool

        self.assertFalse(is_offensive_tool("Read"))
        self.assertFalse(is_offensive_tool("Write"))
        self.assertFalse(is_offensive_tool("SendEmail"))

    def test_allowlist_re_enables(self):
        from permissions import PermissionConfig, PermissionEngine

        engine = PermissionEngine(
            PermissionConfig(
                mode="default",
                can_use_tool=lambda n, p, c: True,
                offensive_allowlist=("nmap_scan",),
            ),
            tool_kinds={"nmap_scan": "exec"},
        )
        d = engine.evaluate("nmap_scan", kind="exec", payload={})
        # Allowlisted: passes the offensive gate (other layers still apply).
        self.assertNotEqual(d.rule, "offensive:deny_by_default")


class DelegationTokenTests(unittest.TestCase):
    def test_mint_and_verify(self):
        from ed25519 import public_key as ed_pubkey
        from permissions import mint_delegation_token, verify_delegation_token

        seed = bytes(32)
        pubkey = ed_pubkey(seed)
        token = mint_delegation_token(
            delegator_id="did:example:alice",
            delegatee_id="did:example:bob",
            tools=("Read", "Grep"),
            delegator_seed=seed,
            issued_at=1000.0,
        )
        self.assertTrue(
            verify_delegation_token(token, pubkey, now=1100.0)
        )

    def test_expired_token_rejected(self):
        from ed25519 import public_key as ed_pubkey
        from permissions import mint_delegation_token, verify_delegation_token

        seed = bytes(32)
        pubkey = ed_pubkey(seed)
        token = mint_delegation_token(
            delegator_id="did:example:alice",
            delegatee_id="did:example:bob",
            tools=("Read",),
            delegator_seed=seed,
            ttl_seconds=300.0,
            issued_at=1000.0,
        )
        self.assertFalse(
            verify_delegation_token(token, pubkey, now=1400.0)
        )

    def test_wrong_key_rejected(self):
        from ed25519 import public_key as ed_pubkey
        from permissions import mint_delegation_token, verify_delegation_token

        seed = bytes(32)
        other_pubkey = ed_pubkey(bytes([1] * 32))
        token = mint_delegation_token(
            delegator_id="did:example:alice",
            delegatee_id="did:example:bob",
            tools=("Read",),
            delegator_seed=seed,
            issued_at=1000.0,
        )
        self.assertFalse(
            verify_delegation_token(token, other_pubkey, now=1100.0)
        )

    def test_audience_binding(self):
        # mandatum V9: token bound to audience X cannot be used by Y.
        from ed25519 import public_key as ed_pubkey
        from permissions import mint_delegation_token, verify_delegation_token

        seed = bytes(32)
        pubkey = ed_pubkey(seed)
        token = mint_delegation_token(
            delegator_id="did:example:alice",
            delegatee_id="did:example:bob",
            tools=("Read",),
            delegator_seed=seed,
            issued_at=1000.0,
            audience="did:example:bob",
        )
        self.assertTrue(
            verify_delegation_token(token, pubkey, now=1100.0, expected_audience="did:example:bob")
        )
        self.assertFalse(
            verify_delegation_token(token, pubkey, now=1100.0, expected_audience="did:example:mallory")
        )
        token2 = mint_delegation_token(
            delegator_id="did:example:alice",
            delegatee_id="did:example:bob",
            tools=("Read",),
            delegator_seed=seed,
            issued_at=1000.0,
        )
        self.assertTrue(verify_delegation_token(token2, pubkey, now=1100.0))
        self.assertFalse(
            verify_delegation_token(token2, pubkey, now=1100.0, expected_audience="did:example:bob")
        )

    def test_revocation_oracle(self):
        from ed25519 import public_key as ed_pubkey
        from permissions import mint_delegation_token, verify_delegation_token

        seed = bytes(32)
        pubkey = ed_pubkey(seed)
        token = mint_delegation_token(
            delegator_id="did:example:alice",
            delegatee_id="did:example:bob",
            tools=("Read",),
            delegator_seed=seed,
            issued_at=1000.0,
        )
        revoked = {token.token_hash()}
        oracle = lambda t: t.token_hash() in revoked
        self.assertFalse(verify_delegation_token(token, pubkey, now=1100.0, revocation_oracle=oracle))
        self.assertTrue(verify_delegation_token(token, pubkey, now=1100.0))
        def bad_oracle(t):
            raise RuntimeError("oracle down")
        self.assertFalse(verify_delegation_token(token, pubkey, now=1100.0, revocation_oracle=bad_oracle))

    def test_root_consistency(self):
        from ed25519 import public_key as ed_pubkey
        from permissions import mint_delegation_token, verify_delegation_token

        seed = bytes(32)
        pubkey = ed_pubkey(seed)
        token = mint_delegation_token(
            delegator_id="did:example:alice",
            delegatee_id="did:example:bob",
            tools=("Read",),
            delegator_seed=seed,
            issued_at=1000.0,
        )
        root_hash = token.token_hash()
        self.assertTrue(
            verify_delegation_token(token, pubkey, now=1100.0, expected_root_hash=root_hash)
        )
        self.assertFalse(
            verify_delegation_token(token, pubkey, now=1100.0, expected_root_hash="0" * 64)
        )

    def test_attenuation_enforced(self):
        from permissions import mint_delegation_token

        seed = bytes(32)
        parent = mint_delegation_token(
            delegator_id="did:example:alice",
            delegatee_id="did:example:bob",
            tools=("Read", "Grep"),
            delegator_seed=seed,
            issued_at=1000.0,
        )
        # Child with subset: OK.
        child = mint_delegation_token(
            delegator_id="did:example:bob",
            delegatee_id="did:example:carol",
            tools=("Read",),
            delegator_seed=seed,
            parent_token=parent,
            issued_at=1000.0,
        )
        self.assertEqual(child.parent_hash, parent.token_hash())
        # Child exceeding parent scope: rejected at mint time.
        with self.assertRaises(ValueError):
            mint_delegation_token(
                delegator_id="did:example:bob",
                delegatee_id="did:example:carol",
                tools=("Read", "Write"),
                delegator_seed=seed,
                parent_token=parent,
                issued_at=1000.0,
            )

    def test_parent_hash_binding(self):
        from ed25519 import public_key as ed_pubkey
        from permissions import mint_delegation_token, verify_delegation_token

        seed = bytes(32)
        pubkey = ed_pubkey(seed)
        parent = mint_delegation_token(
            delegator_id="did:example:alice",
            delegatee_id="did:example:bob",
            tools=("Read",),
            delegator_seed=seed,
            issued_at=1000.0,
        )
        child = mint_delegation_token(
            delegator_id="did:example:bob",
            delegatee_id="did:example:carol",
            tools=("Read",),
            delegator_seed=seed,
            parent_token=parent,
            issued_at=1000.0,
        )
        # Correct parent hash: verifies.
        self.assertTrue(
            verify_delegation_token(
                child, pubkey, now=1100.0,
                expected_parent_hash=parent.token_hash(),
            )
        )
        # Wrong parent hash: rejected.
        self.assertFalse(
            verify_delegation_token(
                child, pubkey, now=1100.0,
                expected_parent_hash="0" * 64,
            )
        )


class PerCallApprovalBindingTests(unittest.TestCase):
    """Per-call approval binding: no caching, no replay.

    Absorbed from byquexo/agent-approval-gate (``gate.ts``): the gate holds
    no state between calls, every gated call re-invokes the approver with
    the exact call (id + arguments), and a "yes" is scoped to exactly one
    tool call. These tests pin that rule on the runtime engine.
    """

    def make(self, **kwargs) -> PermissionEngine:
        return PermissionEngine(PermissionConfig(mode="default", **kwargs))

    def test_callback_sees_call_id_and_arguments_digest(self):
        seen: list[tuple[str, str, str]] = []

        def callback(name: str, payload: dict, ctx: PermissionRequestContext) -> bool:
            seen.append((name, ctx.call_id, ctx.arguments_digest))
            return True

        engine = self.make(can_use_tool=callback)
        payload = {"path": "a.txt", "content": "x"}
        decision = engine.evaluate(
            "Write",
            kind="edit",
            payload=payload,
            context=PermissionRequestContext(call_id="call-1"),
        )
        self.assertTrue(decision.allowed)
        self.assertEqual(len(seen), 1)
        name, call_id, digest = seen[0]
        self.assertEqual(name, "Write")
        self.assertEqual(call_id, "call-1")
        self.assertEqual(digest, digest_arguments(payload))
        self.assertTrue(digest.startswith("sha256:"))

    def test_digest_is_backfilled_when_caller_did_not_pin_it(self):
        seen: list[str] = []

        def callback(name: str, payload: dict, ctx: PermissionRequestContext) -> bool:
            seen.append(ctx.arguments_digest)
            return True

        engine = self.make(can_use_tool=callback)
        payload = {"path": "a.txt", "content": "x"}
        engine.evaluate("Write", kind="edit", payload=payload)
        self.assertEqual(seen, [digest_arguments(payload)])

    def test_approver_is_reinvoked_per_call_never_cached(self):
        calls: list[tuple[str, str]] = []

        def callback(name: str, payload: dict, ctx: PermissionRequestContext) -> bool:
            calls.append((name, ctx.arguments_digest))
            return len(calls) == 1  # approve only the very first call

        engine = self.make(can_use_tool=callback)
        first = engine.evaluate(
            "Write",
            kind="edit",
            payload={"path": "a.txt"},
            context=PermissionRequestContext(call_id="c1"),
        )
        second = engine.evaluate(
            "Write",
            kind="edit",
            payload={"path": "b.txt"},
            context=PermissionRequestContext(call_id="c2"),
        )
        self.assertTrue(first.allowed)
        # The first approval must not replay onto the second call: the
        # approver is asked again and now says no.
        self.assertFalse(second.allowed)
        self.assertEqual(second.source, "host_callback")
        self.assertEqual(len(calls), 2)
        self.assertNotEqual(calls[0][1], calls[1][1])

    def test_reused_approval_for_new_arguments_fails_closed(self):
        approved_digests = {digest_arguments({"path": "a.txt", "content": "1"})}

        def callback(name: str, payload: dict, ctx: PermissionRequestContext) -> bool:
            # A host grant scoped to one exact arguments digest.
            return ctx.arguments_digest in approved_digests

        engine = self.make(can_use_tool=callback)
        granted = engine.evaluate(
            "Write",
            kind="edit",
            payload={"path": "a.txt", "content": "1"},
            context=PermissionRequestContext(call_id="c1"),
        )
        # Same tool, different arguments: the old approval must not carry.
        replay = engine.evaluate(
            "Write",
            kind="edit",
            payload={"path": "a.txt", "content": "2"},
            context=PermissionRequestContext(call_id="c2"),
        )
        self.assertTrue(granted.allowed)
        self.assertFalse(replay.allowed)
        self.assertEqual(replay.source, "host_callback")


class EngineAtRuntimeTests(RuntimeTestCase):
    def test_mutating_tool_never_touches_disk_without_approval(self):
        workspace = self.workspace()
        provider = self.provider([tool_turn("Write", {"path": "note.txt", "content": "written"})])
        report = self.drive(self.runtime(provider=provider, workspace=workspace))
        self.assertFalse((workspace / "note.txt").exists())
        self.assertEqual(report.denials[0].source, "mode")
        refusal = report.transcript[2].tool_results[0]
        self.assertTrue(refusal.is_error)
        self.assertIn("permission gate", refusal.text())

    def test_host_approval_lets_the_write_through(self):
        workspace = self.workspace()
        provider = self.provider([tool_turn("Write", {"path": "note.txt", "content": "written"}), text_turn("done")])
        runtime = self.runtime(provider=provider, workspace=workspace, can_use_tool=lambda name, payload, ctx: True)
        report = self.drive(runtime, "write it")
        self.assertEqual((workspace / "note.txt").read_text(), "written")
        self.assertEqual([call.permission_source for call in report.tool_calls], ["host_callback"])
        self.assertEqual([call.name for call in report.tool_calls], ["Write"])
        self.assertEqual(report.denials, ())

    def test_plan_mode_at_runtime_refuses_writes_even_with_an_approving_callback(self):
        workspace = self.workspace()
        provider = self.provider([tool_turn("Write", {"path": "note.txt", "content": "x"})])
        report = self.drive(self.runtime(provider=provider, workspace=workspace, permission_mode="plan", can_use_tool=lambda *args: True))
        self.assertFalse((workspace / "note.txt").exists())
        self.assertEqual(report.denials[0].source, "mode")

    def test_read_only_tool_output_is_capped_and_flagged(self):
        workspace = self.workspace({"big.txt": "0123456789" * 40_000})
        provider = self.provider([tool_turn("Read", {"path": "big.txt"}), text_turn("done")])
        report = self.drive(self.runtime(provider=provider, workspace=workspace))
        text = provider.sent_tool_results()[0]["content"]
        self.assertIn("[first 262144 of 400000 bytes", text)
        self.assertLess(len(text), 280_000)

    def test_denial_is_recorded_once_per_call_with_its_source(self):
        provider = self.provider([tool_turn("Write", {"path": "a", "content": "1"}), tool_turn("Write", {"path": "b", "content": "2"}), text_turn("done")])
        report = self.drive(self.runtime(provider=provider, max_turns=5))
        self.assertEqual(len(report.denials), 2)
        self.assertEqual({denial.source for denial in report.denials}, {"mode"})
        self.assertEqual([denial.turn_index for denial in report.denials], [1, 2])

    def test_denial_tool_result_is_structured_with_tier_and_retryability(self):
        provider = self.provider([tool_turn("Write", {"path": "a", "content": "1"}), text_turn("done")])
        report = self.drive(self.runtime(provider=provider, can_use_tool=lambda *args: False))
        refusal = report.transcript[2].tool_results[0]
        self.assertTrue(refusal.is_error)
        content = refusal.content
        self.assertIsInstance(content, dict)
        self.assertEqual(content["status"], "denied")
        self.assertEqual(content["tool"], "Write")
        self.assertEqual(content["tier"], "host_callback")
        self.assertTrue(content["retryable"])
        self.assertIn("refused by the permission gate", content["message"])
        # The flattened text the model actually sees still carries the refusal.
        self.assertIn("refused by the permission gate", refusal.text())

    def test_policy_denial_tool_result_is_not_retryable(self):
        provider = self.provider([tool_turn("Write", {"path": "a", "content": "1"}), text_turn("done")])
        report = self.drive(
            self.runtime(
                provider=provider,
                disallowed_tools=("Write",),
                can_use_tool=lambda *args: True,
            )
        )
        refusal = report.transcript[2].tool_results[0]
        content = refusal.content
        self.assertIsInstance(content, dict)
        self.assertEqual(content["status"], "denied")
        self.assertEqual(content["tier"], "disallowed_tools")
        self.assertFalse(content["retryable"])

    def test_host_callback_receives_call_id_and_digest_at_runtime(self):
        seen: list[tuple[str, str]] = []

        def callback(name: str, payload: dict, ctx: PermissionRequestContext) -> bool:
            seen.append((ctx.call_id, ctx.arguments_digest))
            return True

        provider = self.provider([tool_turn("Write", {"path": "a", "content": "1"}), text_turn("done")])
        self.drive(self.runtime(provider=provider, workspace=self.workspace(), can_use_tool=callback))
        self.assertEqual(len(seen), 1)
        call_id, digest = seen[0]
        self.assertTrue(call_id)
        self.assertEqual(digest, digest_arguments({"path": "a", "content": "1"}))


class PreTradeRiskTests(unittest.TestCase):
    """SEC 15c3-5-style pre-trade semantics: four independent rejection
    conditions, missing-fact fail-closed, model-independent checks, and a
    synchronous deny audit trail."""

    def make_engine(self, **kw):
        now = [1_000.0]
        cfg = PreTradeRiskConfig(
            max_call_value=100.0,
            value_of=lambda tool, payload: payload.get("value"),
            reference_of=lambda tool, payload: payload.get("reference", 50.0),
            price_collar=0.10,
            max_payload_bytes=300,
            max_calls_per_window=2,
            window_seconds=10.0,
            dedupe_window_seconds=60.0,
        )
        audits: list[dict] = []
        engine = PermissionEngine(
            PermissionConfig(mode="default", can_use_tool=lambda n, p, c: True),
            tool_kinds={"Write": "edit"},
            pretrade=kw.pop("pretrade", cfg),
            audit_sink=kw.pop("audit_sink", audits.append),
            now=lambda: now[0],
            **kw,
        )
        return engine, audits, now

    def test_price_value_and_collar_deny_independently(self):
        engine, _, _ = self.make_engine()
        d = engine.evaluate("Write", kind="edit", payload={"value": 150, "reference": 150})
        self.assertFalse(d.allowed)
        self.assertEqual(d.source, "pretrade")
        self.assertTrue(d.rule.startswith(PT_PRICE))
        d = engine.evaluate("Write", kind="edit", payload={"value": 60, "reference": 50})
        self.assertFalse(d.allowed)
        self.assertIn("price_exceeded", d.rule)

    def test_missing_or_malformed_value_fails_closed(self):
        engine, _, _ = self.make_engine()
        for payload in ({"reference": 50}, {"value": float("nan")}, {"value": -1}):
            d = engine.evaluate("Write", kind="edit", payload=payload)
            self.assertFalse(d.allowed, payload)
            self.assertEqual(d.rule, PT_FACT_MISSING, payload)

    def test_unusable_reference_price_blocks_instead_of_skipping(self):
        engine, _, _ = self.make_engine()
        d = engine.evaluate("Write", kind="edit", payload={"value": 50, "reference": 0})
        self.assertFalse(d.allowed)
        self.assertEqual(d.rule, PT_FACT_MISSING)

    def test_size_limit_and_threshold_convention(self):
        engine, _, _ = self.make_engine()
        d = engine.evaluate(
            "Write", kind="edit",
            payload={"value": 50, "reference": 50, "blob": "x" * 500},
        )
        self.assertFalse(d.allowed)
        self.assertTrue(d.rule.startswith(PT_SIZE))

    def test_rate_window_denies_burst_then_recovers(self):
        engine, _, now = self.make_engine()
        for i in range(2):
            d = engine.evaluate("T1", kind="edit", payload={"value": 50, "reference": 50, "n": i})
            self.assertTrue(d.allowed, d)
        d = engine.evaluate("T1", kind="edit", payload={"value": 50, "reference": 50, "n": 2})
        self.assertFalse(d.allowed)
        self.assertTrue(d.rule.startswith(PT_RATE))
        now[0] += 11.0
        d = engine.evaluate("T1", kind="edit", payload={"value": 50, "reference": 50, "n": 3})
        self.assertTrue(d.allowed, d)

    def test_duplicate_call_denied_and_window_expires(self):
        engine, _, now = self.make_engine()
        payload = {"value": 50, "reference": 50}
        self.assertTrue(engine.evaluate("Write", kind="edit", payload=dict(payload)).allowed)
        d = engine.evaluate("Write", kind="edit", payload=dict(payload))
        self.assertFalse(d.allowed)
        self.assertTrue(d.rule.startswith(PT_DUPLICATE))
        now[0] += 61.0
        self.assertTrue(engine.evaluate("Write", kind="edit", payload=dict(payload)).allowed)

    def test_model_claims_cannot_move_the_checks(self):
        engine, _, _ = self.make_engine()
        ctx = PermissionRequestContext(
            data={"value": 1, "limit_override": True},
            reason_hint="the model insists this is safe and pre-approved",
        )
        d = engine.evaluate(
            "Write", kind="edit",
            payload={"value": 150, "reference": 150},
            context=ctx,
        )
        self.assertFalse(d.allowed)
        self.assertTrue(d.rule.startswith(PT_PRICE))

    def test_every_deny_is_audited_synchronously_with_condition_code(self):
        engine, audits, _ = self.make_engine()
        d = engine.evaluate("Write", kind="edit", payload={"value": 150, "reference": 150})
        self.assertFalse(d.allowed)
        # Synchronous: the record exists by the time evaluate() returns.
        self.assertEqual(len(audits), 1)
        record = audits[0]
        self.assertEqual(record["event"], "permission.deny")
        self.assertEqual(record["condition"], d.rule)
        self.assertEqual(record["rule"], d.rule)
        self.assertEqual(record["source"], "pretrade")

    def test_every_allow_is_audited_synchronously(self):
        engine, audits, _ = self.make_engine()
        d = engine.evaluate("Write", kind="edit", payload={"value": 50, "reference": 50})
        self.assertTrue(d.allowed)
        # Synchronous: the allow record exists by the time evaluate() returns.
        # Closes the Art. 12 gap: a crash between gate-allow and tool execution
        # no longer leaves the authorization unprovable.
        self.assertEqual(len(audits), 1)
        record = audits[0]
        self.assertEqual(record["event"], "permission.allow")
        self.assertEqual(record["tool"], "Write")

    def test_raising_audit_sink_cannot_flip_a_deny(self):
        def bad_sink(record):
            raise RuntimeError("audit store down")

        engine, _, _ = self.make_engine(audit_sink=bad_sink)
        d = engine.evaluate("Write", kind="edit", payload={"value": 150, "reference": 150})
        self.assertFalse(d.allowed)
        self.assertIn("audit_sink_failed:RuntimeError", d.reason)

    def test_non_serialisable_payload_denies_instead_of_raising(self):
        engine, _, _ = self.make_engine(pretrade=None)
        cyclic: dict = {}
        cyclic["self"] = cyclic
        d = engine.evaluate("Write", kind="edit", payload=cyclic)
        self.assertFalse(d.allowed)
        self.assertEqual(d.rule, PT_FACT_MISSING)

    def test_pretrade_disabled_by_default(self):
        engine = PermissionEngine(
            PermissionConfig(mode="default", can_use_tool=lambda n, p, c: True),
            tool_kinds={"Write": "edit"},
        )
        d = engine.evaluate("Write", kind="edit", payload={"value": 10**9})
        self.assertTrue(d.allowed)


class SignedApprovalTests(unittest.TestCase):
    def test_signed_receipt_verifies_approver(self):
        import time

        from ed25519 import public_key as ed_pubkey
        from egress_enforcer import build_approval_receipt
        from permissions import PermissionConfig, PermissionEngine

        seed = bytes(32)
        pubkey = ed_pubkey(seed)
        receipt = build_approval_receipt(
            card_id="c1",
            call_id="call-1",
            arguments_digest="sha256:abc",
            approver_id="alice",
            approver_seed=seed,
            decided_at=time.time(),
            body=b"{}",
        )

        def callback(name, payload, ctx):
            return {"allowed": True, "approval_receipt": receipt.as_dict()}

        engine = PermissionEngine(
            PermissionConfig(
                mode="default",
                can_use_tool=callback,
                approver_keys={"alice": pubkey},
            ),
            tool_kinds={"Write": "edit"},
        )
        d = engine.evaluate("Write", kind="edit", payload={})
        self.assertTrue(d.allowed)
        self.assertIn("alice", d.reason)

    def test_bad_signature_fails_closed(self):
        import time

        from ed25519 import public_key as ed_pubkey
        from egress_enforcer import build_approval_receipt
        from permissions import PermissionConfig, PermissionEngine

        seed = bytes(32)
        pubkey = ed_pubkey(seed)
        receipt = build_approval_receipt(
            card_id="c1",
            call_id="call-1",
            arguments_digest="sha256:abc",
            approver_id="alice",
            approver_seed=seed,
            decided_at=time.time(),
            body=b"{}",
        )
        # Tamper with the receipt after signing.
        tampered = receipt.as_dict()
        tampered["card_id"] = "evil-card"

        def callback(name, payload, ctx):
            return {"allowed": True, "approval_receipt": tampered}

        engine = PermissionEngine(
            PermissionConfig(
                mode="default",
                can_use_tool=callback,
                approver_keys={"alice": pubkey},
            ),
            tool_kinds={"Write": "edit"},
        )
        d = engine.evaluate("Write", kind="edit", payload={})
        self.assertFalse(d.allowed)
        self.assertEqual(d.rule, "host_callback:bad_signature")

    def test_unsigned_callback_still_works(self):
        # Opt-in: without approver_keys, plain bool verdicts work as before.
        from permissions import PermissionConfig, PermissionEngine

        engine = PermissionEngine(
            PermissionConfig(mode="default", can_use_tool=lambda n, p, c: True),
            tool_kinds={"Write": "edit"},
        )
        d = engine.evaluate("Write", kind="edit", payload={})
        self.assertTrue(d.allowed)

    def test_expired_receipt_rejected_with_injected_clock(self):
        # The injected wall clock determines freshness, not time.time().
        from ed25519 import public_key as ed_pubkey
        from egress_enforcer import build_approval_receipt
        from permissions import PermissionConfig, PermissionEngine

        seed = bytes(32)
        pubkey = ed_pubkey(seed)
        # Receipt decided at t=1000.
        receipt = build_approval_receipt(
            card_id="c1",
            call_id="call-1",
            arguments_digest="sha256:abc",
            approver_id="alice",
            approver_seed=seed,
            decided_at=1000.0,
            body=b"{}",
        )

        def callback(name, payload, ctx):
            return {"allowed": True, "approval_receipt": receipt.as_dict()}

        # Clock says t=1000+400 > 300s TTL -> expired.
        engine = PermissionEngine(
            PermissionConfig(
                mode="default",
                can_use_tool=callback,
                approver_keys={"alice": pubkey},
            ),
            tool_kinds={"Write": "edit"},
            wall_now=lambda: 1400.0,
        )
        d = engine.evaluate("Write", kind="edit", payload={})
        self.assertFalse(d.allowed)
        self.assertEqual(d.rule, "host_callback:bad_signature")

        # Clock says t=1000+100 within TTL -> allowed.
        engine2 = PermissionEngine(
            PermissionConfig(
                mode="default",
                can_use_tool=callback,
                approver_keys={"alice": pubkey},
            ),
            tool_kinds={"Write": "edit"},
            wall_now=lambda: 1100.0,
        )
        d2 = engine2.evaluate("Write", kind="edit", payload={})
        self.assertTrue(d2.allowed)


class ScopeLifetimeTests(unittest.TestCase):
    def test_open_scope_allows(self):
        from permissions import (
            PermissionConfig,
            PermissionEngine,
            PermissionRequestContext,
            ScopeManager,
        )

        mgr = ScopeManager()
        mgr.open_scope("phase-1", "data gathering")
        engine = PermissionEngine(
            PermissionConfig(mode="default", can_use_tool=lambda n, p, c: True),
            tool_kinds={"Write": "edit"},
            scope_manager=mgr,
        )
        ctx = PermissionRequestContext(scope_id="phase-1")
        d = engine.evaluate("Write", kind="edit", payload={}, context=ctx)
        self.assertTrue(d.allowed)

    def test_closed_scope_denies(self):
        from permissions import (
            PermissionConfig,
            PermissionEngine,
            PermissionRequestContext,
            ScopeManager,
        )

        mgr = ScopeManager()
        mgr.open_scope("phase-1", "data gathering")
        mgr.close_scope("phase-1")
        engine = PermissionEngine(
            PermissionConfig(mode="default", can_use_tool=lambda n, p, c: True),
            tool_kinds={"Write": "edit"},
            scope_manager=mgr,
        )
        ctx = PermissionRequestContext(scope_id="phase-1")
        d = engine.evaluate("Write", kind="edit", payload={}, context=ctx)
        self.assertFalse(d.allowed)
        self.assertEqual(d.rule, "scope:closed")
        self.assertIn("phase-1", d.reason)

    def test_unscoped_requests_unaffected(self):
        # Empty scope_id = no scoping, current behavior.
        from permissions import (
            PermissionConfig,
            PermissionEngine,
            PermissionRequestContext,
            ScopeManager,
        )

        mgr = ScopeManager()
        engine = PermissionEngine(
            PermissionConfig(mode="default", can_use_tool=lambda n, p, c: True),
            tool_kinds={"Write": "edit"},
            scope_manager=mgr,
        )
        d = engine.evaluate("Write", kind="edit", payload={})
        self.assertTrue(d.allowed)

    def test_no_manager_no_change(self):
        # Without a scope manager, scope_id is ignored.
        from permissions import (
            PermissionConfig,
            PermissionEngine,
            PermissionRequestContext,
        )

        engine = PermissionEngine(
            PermissionConfig(mode="default", can_use_tool=lambda n, p, c: True),
            tool_kinds={"Write": "edit"},
        )
        ctx = PermissionRequestContext(scope_id="phase-1")
        d = engine.evaluate("Write", kind="edit", payload={}, context=ctx)
        self.assertTrue(d.allowed)

    def test_reopen_closed_scope_fails(self):
        from permissions import ScopeManager

        mgr = ScopeManager()
        mgr.open_scope("s1")
        mgr.close_scope("s1")
        with self.assertRaises(ValueError):
            mgr.open_scope("s1")


class AuthorityCeilingTests(unittest.TestCase):
    def _engine(self, callback=None):
        from permissions import (
            PermissionConfig,
            PermissionEngine,
            ScopeManager,
        )

        mgr = ScopeManager()
        mgr.open_scope("phase-1", "test", capabilities=("Read", "Grep"))
        return PermissionEngine(
            PermissionConfig(
                mode="default",
                can_use_tool=callback or (lambda n, p, c: True),
            ),
            tool_kinds={"Read": "read", "Grep": "read", "Write": "edit"},
            scope_manager=mgr,
        ), mgr

    def test_within_ceiling_allowed(self):
        from permissions import PermissionRequestContext

        engine, _ = self._engine()
        ctx = PermissionRequestContext(scope_id="phase-1")
        d = engine.evaluate("Read", kind="read", payload={}, context=ctx)
        self.assertTrue(d.allowed)

    def test_outside_ceiling_needs_approval(self):
        from permissions import PermissionRequestContext

        # Host approves the ascent.
        engine, _ = self._engine(callback=lambda n, p, c: True)
        ctx = PermissionRequestContext(scope_id="phase-1")
        d = engine.evaluate("Write", kind="edit", payload={}, context=ctx)
        self.assertTrue(d.allowed)
        self.assertEqual(d.rule, "ceiling:ascent_approved")

    def test_outside_ceiling_denied_without_callback(self):
        from permissions import (
            PermissionConfig,
            PermissionEngine,
            PermissionRequestContext,
            ScopeManager,
        )

        mgr = ScopeManager()
        mgr.open_scope("phase-1", "test", capabilities=("Read",))
        engine = PermissionEngine(
            PermissionConfig(mode="default"),  # no callback
            tool_kinds={"Write": "edit"},
            scope_manager=mgr,
        )
        ctx = PermissionRequestContext(scope_id="phase-1")
        d = engine.evaluate("Write", kind="edit", payload={}, context=ctx)
        self.assertFalse(d.allowed)
        self.assertEqual(d.rule, "ceiling:needs_approval")

    def test_outside_ceiling_host_can_deny(self):
        from permissions import PermissionRequestContext

        engine, _ = self._engine(callback=lambda n, p, c: False)
        ctx = PermissionRequestContext(scope_id="phase-1")
        d = engine.evaluate("Write", kind="edit", payload={}, context=ctx)
        self.assertFalse(d.allowed)
        self.assertEqual(d.rule, "ceiling:ascent_denied")

    def test_no_ceiling_no_change(self):
        from permissions import (
            PermissionConfig,
            PermissionEngine,
            PermissionRequestContext,
            ScopeManager,
        )

        mgr = ScopeManager()
        mgr.open_scope("phase-1", "test")  # no capabilities = no ceiling
        engine = PermissionEngine(
            PermissionConfig(mode="default", can_use_tool=lambda n, p, c: True),
            tool_kinds={"Write": "edit"},
            scope_manager=mgr,
        )
        ctx = PermissionRequestContext(scope_id="phase-1")
        d = engine.evaluate("Write", kind="edit", payload={}, context=ctx)
        # No ceiling: normal gate behavior.
        self.assertTrue(d.allowed)

    def test_ceiling_cleared_on_close(self):
        from permissions import ScopeManager

        mgr = ScopeManager()
        mgr.open_scope("s1", capabilities=("Read",))
        self.assertEqual(mgr.ceiling("s1"), frozenset({"Read",}))
        mgr.close_scope("s1")
        self.assertIsNone(mgr.ceiling("s1"))


class ArgumentPolicyTests(unittest.TestCase):
    def _engine(self, policies):
        from permissions import PermissionConfig, PermissionEngine

        return PermissionEngine(
            PermissionConfig(
                mode="default",
                can_use_tool=lambda n, p, c: True,
                argument_policies=tuple(policies),
            ),
            tool_kinds={"Bash": "exec", "SendEmail": "write"},
        )

    def test_denylist_blocks(self):
        from permissions import ArgumentPolicy

        engine = self._engine([
            ArgumentPolicy(tool="Bash", argument="command", denylist=("rm -rf /", "mkfs")),
        ])
        d = engine.evaluate("Bash", kind="exec", payload={"command": "rm -rf / tmp"})
        self.assertFalse(d.allowed)
        self.assertEqual(d.rule, "argument:policy_violation")
        self.assertEqual(d.source, "argument")

    def test_denylist_case_insensitive(self):
        from permissions import ArgumentPolicy

        engine = self._engine([
            ArgumentPolicy(tool="Bash", argument="command", denylist=("rm -rf /",)),
        ])
        d = engine.evaluate("Bash", kind="exec", payload={"command": "RM -RF / data"})
        self.assertFalse(d.allowed)

    def test_clean_command_passes(self):
        from permissions import ArgumentPolicy

        engine = self._engine([
            ArgumentPolicy(tool="Bash", argument="command", denylist=("rm -rf /",)),
        ])
        d = engine.evaluate("Bash", kind="exec", payload={"command": "ls -la"})
        self.assertTrue(d.allowed)

    def test_allowlist_restricts(self):
        from permissions import ArgumentPolicy

        engine = self._engine([
            ArgumentPolicy(
                tool="SendEmail",
                argument="to",
                allowlist=("@company.com",),
                description="only internal recipients",
            ),
        ])
        d1 = engine.evaluate("SendEmail", kind="write", payload={"to": "alice@company.com"})
        self.assertTrue(d1.allowed)
        d2 = engine.evaluate("SendEmail", kind="write", payload={"to": "bob@external.com"})
        self.assertFalse(d2.allowed)
        self.assertEqual(d2.rule, "argument:policy_violation")

    def test_denylist_beats_allowlist(self):
        from permissions import ArgumentPolicy

        engine = self._engine([
            ArgumentPolicy(
                tool="SendEmail",
                argument="to",
                denylist=("blocked@company.com",),
                allowlist=("@company.com",),
            ),
        ])
        d = engine.evaluate("SendEmail", kind="write", payload={"to": "blocked@company.com"})
        self.assertFalse(d.allowed)

    def test_wrong_tool_ignored(self):
        from permissions import ArgumentPolicy

        engine = self._engine([
            ArgumentPolicy(tool="Bash", argument="command", denylist=("rm",)),
        ])
        d = engine.evaluate("SendEmail", kind="write", payload={"to": "rm@x.com"})
        self.assertTrue(d.allowed)

    def test_no_policies_no_change(self):
        engine = self._engine([])
        d = engine.evaluate("Bash", kind="exec", payload={"command": "rm -rf /"})
        self.assertTrue(d.allowed)


class CompositionClosureTests(unittest.TestCase):
    def _engine(self):
        from permissions import (
            CompositionRule,
            PermissionConfig,
            PermissionEngine,
        )

        return PermissionEngine(
            PermissionConfig(mode="default", can_use_tool=lambda n, p, c: True),
            tool_kinds={"ReadSecrets": "read", "SendEmail": "send"},
            composition_rules=[
                CompositionRule(
                    sequence=("read_sensitive", "external_send"),
                    description="exfiltration shape",
                )
            ],
            tool_categories={
                "ReadSecrets": "read_sensitive",
                "SendEmail": "external_send",
            },
        )

    def test_each_call_individually_allowed(self):
        engine = self._engine()
        d1 = engine.evaluate("ReadSecrets", kind="read", payload={})
        self.assertTrue(d1.allowed)
        # Fresh engine: send alone is fine.
        engine2 = self._engine()
        d2 = engine2.evaluate("SendEmail", kind="send", payload={})
        self.assertTrue(d2.allowed)

    def test_forbidden_sequence_denied(self):
        engine = self._engine()
        d1 = engine.evaluate("ReadSecrets", kind="read", payload={})
        self.assertTrue(d1.allowed)
        d2 = engine.evaluate("SendEmail", kind="send", payload={})
        self.assertFalse(d2.allowed)
        self.assertEqual(d2.rule, "composition:forbidden_sequence")
        self.assertIn("read_sensitive -> external_send", d2.reason)

    def test_unrelated_sequence_allowed(self):
        engine = self._engine()
        # Send without a preceding sensitive read: allowed.
        d = engine.evaluate("SendEmail", kind="send", payload={})
        self.assertTrue(d.allowed)
        # Read twice: no forbidden pair.
        d2 = engine.evaluate("ReadSecrets", kind="read", payload={})
        self.assertTrue(d2.allowed)

    def test_denied_call_does_not_extend_history(self):
        from permissions import (
            CompositionRule,
            PermissionConfig,
            PermissionEngine,
        )

        # ReadSecrets is denied via disallowed_tools: it must not enter
        # history, so a later SendEmail is still allowed.
        engine = PermissionEngine(
            PermissionConfig(
                mode="default",
                disallowed_tools=("ReadSecrets",),
                can_use_tool=lambda n, p, c: True,
            ),
            tool_kinds={"ReadSecrets": "read", "SendEmail": "read"},
            composition_rules=[
                CompositionRule(sequence=("read_sensitive", "external_send"))
            ],
            tool_categories={
                "ReadSecrets": "read_sensitive",
                "SendEmail": "external_send",
            },
        )
        d1 = engine.evaluate("ReadSecrets", kind="read", payload={})
        self.assertFalse(d1.allowed)
        d2 = engine.evaluate("SendEmail", kind="read", payload={})
        self.assertTrue(d2.allowed)

    def test_no_rules_no_change(self):
        from permissions import PermissionConfig, PermissionEngine

        engine = PermissionEngine(
            PermissionConfig(mode="default", can_use_tool=lambda n, p, c: True),
            tool_kinds={"ReadSecrets": "read", "SendEmail": "send"},
        )
        d1 = engine.evaluate("ReadSecrets", kind="read", payload={})
        d2 = engine.evaluate("SendEmail", kind="send", payload={})
        self.assertTrue(d1.allowed)
        self.assertTrue(d2.allowed)

    def test_rule_needs_two_categories(self):
        from permissions import CompositionRule

        with self.assertRaises(ValueError):
            CompositionRule(sequence=("only_one",))


class SharedContractTests(unittest.TestCase):
    """trace_violates_rules(): one spec, two roles (gate + bench)."""

    def test_clean_trace_no_violation(self):
        from permissions import CompositionRule, trace_violates_rules

        rule = CompositionRule(sequence=("read_sensitive", "external_send"))
        self.assertIsNone(
            trace_violates_rules(["read_sensitive"], [rule])
        )
        self.assertIsNone(
            trace_violates_rules(["external_send"], [rule])
        )
        self.assertIsNone(
            trace_violates_rules(["other", "read_sensitive", "other"], [rule])
        )

    def test_forbidden_sequence_detected(self):
        from permissions import CompositionRule, trace_violates_rules

        rule = CompositionRule(
            sequence=("read_sensitive", "external_send"),
            description="exfiltration",
        )
        violated = trace_violates_rules(
            ["other", "read_sensitive", "external_send"], [rule]
        )
        self.assertIsNotNone(violated)
        self.assertEqual(violated.description, "exfiltration")

    def test_longer_sequence(self):
        from permissions import CompositionRule, trace_violates_rules

        rule = CompositionRule(sequence=("a", "b", "c"))
        self.assertIsNone(trace_violates_rules(["a", "b"], [rule]))
        violated = trace_violates_rules(["x", "a", "b", "c"], [rule])
        self.assertIsNotNone(violated)

    def test_empty_inputs_safe(self):
        from permissions import CompositionRule, trace_violates_rules

        rule = CompositionRule(sequence=("a", "b"))
        self.assertIsNone(trace_violates_rules([], [rule]))
        self.assertIsNone(trace_violates_rules(["a", "b"], []))

    def test_bench_can_use_gate_rules(self):
        # The key property: the bench scores a trace with the EXACT same
        # rules the gate enforces. If the gate would deny, the bench
        # flags the trace.
        from permissions import (
            CompositionRule,
            PermissionConfig,
            PermissionEngine,
            trace_violates_rules,
        )

        rules = [
            CompositionRule(sequence=("read_sensitive", "external_send"))
        ]
        categories = {"ReadSecrets": "read_sensitive", "SendEmail": "external_send"}

        # Offline: bench checks the trace.
        trace = ["read_sensitive", "external_send"]
        self.assertIsNotNone(trace_violates_rules(trace, rules))

        # Online: gate denies the second call.
        engine = PermissionEngine(
            PermissionConfig(mode="default", can_use_tool=lambda n, p, c: True),
            tool_kinds={"ReadSecrets": "read", "SendEmail": "read"},
            composition_rules=rules,
            tool_categories=categories,
        )
        d1 = engine.evaluate("ReadSecrets", kind="read", payload={})
        self.assertTrue(d1.allowed)
        d2 = engine.evaluate("SendEmail", kind="read", payload={})
        self.assertFalse(d2.allowed)
        # Both agree: the trace is forbidden.


if __name__ == "__main__":
    unittest.main()
