"""Runtime ↔ interop handoff bridge: signed grants, capability narrowing, local-dev label."""
from __future__ import annotations

import unittest

import support  # noqa: F401

from interop_bridge import (
    BridgeReport,
    InteropBridgeError,
    cross_check,
    digest_input,
    mint_local_handoff,
    verify_local_grant,
)


SECRET = b"northstar-interop-bridge-test-secret"


class InteropBridgeAvailabilityTests(unittest.TestCase):
    def test_cross_check_sees_the_sibling_component(self):
        report = cross_check()
        self.assertIsInstance(report, BridgeReport)
        self.assertTrue(report.ok)
        self.assertIn(report.mode, {"unchecked", "unavailable"})
        # In this monorepo the interop component is always present.
        if report.mode == "unchecked":
            self.assertIn("grant_schema", report.detail or {})


class InteropBridgeMintTests(unittest.TestCase):
    def test_digest_is_stable(self):
        self.assertEqual(digest_input({"a": 1, "b": 2}), digest_input({"b": 2, "a": 1}))
        self.assertTrue(digest_input("hello").startswith("sha256:"))

    def test_mint_local_handoff_issues_a_verifiable_grant(self):
        try:
            minted = mint_local_handoff(
                secret=SECRET,
                source_agent_id="runtime-main",
                target_agent_id="codex-worker",
                target_capabilities=("workspace:read", "workspace:write"),
                requested_capabilities=("workspace:read",),
                input_payload={"prompt": "summarise the fixture"},
                run_id="run-bridge-1",
                actor_id="actor-bridge",
                workspace_id="ws-bridge",
                policy_revision="policy-bridge",
                now=1_700_000_000,
                grant_ttl_seconds=600,
            )
        except InteropBridgeError as error:
            self.fail(f"mint_local_handoff raised unexpectedly: {error}")

        self.assertIn("grant_token", minted)
        self.assertIn("attestation_token", minted)
        self.assertEqual(minted["report"]["mode"], "local-dev")
        self.assertTrue(minted["report"]["ok"])
        detail = minted["report"]["detail"]
        self.assertEqual(detail["source_agent_id"], "runtime-main")
        self.assertEqual(detail["target_agent_id"], "codex-worker")
        self.assertEqual(detail["capabilities"], ["workspace:read"])
        self.assertEqual(detail["delegation_depth"], 1)
        self.assertEqual(detail["policy_revision"], "policy-bridge")

        verified = verify_local_grant(minted["grant_token"], SECRET, now=1_700_000_000)
        self.assertTrue(verified.ok)
        self.assertEqual(verified.mode, "verified")
        self.assertEqual(verified.detail["target_agent_id"], "codex-worker")

    def test_requested_capability_cannot_exceed_source(self):
        with self.assertRaises(InteropBridgeError) as caught:
            mint_local_handoff(
                secret=SECRET,
                source_agent_id="runtime-main",
                target_agent_id="codex-worker",
                target_capabilities=("workspace:read", "workspace:write"),
                source_capabilities=("workspace:read",),
                requested_capabilities=("workspace:write",),
                input_payload="x",
                run_id="run-bridge-2",
                now=1_700_000_000,
            )
        self.assertIn("exceed source", str(caught.exception).lower())

    def test_requested_capability_cannot_exceed_target_profile(self):
        with self.assertRaises(InteropBridgeError) as caught:
            mint_local_handoff(
                secret=SECRET,
                source_agent_id="runtime-main",
                target_agent_id="codex-worker",
                # Source is wider than target: the bridge must still refuse when
                # the *target profile* cannot honour the request.
                source_capabilities=("workspace:read", "workspace:write"),
                target_capabilities=("workspace:read",),
                requested_capabilities=("workspace:write",),
                input_payload="x",
                run_id="run-bridge-3",
                now=1_700_000_000,
            )
        self.assertIn("exceed target", str(caught.exception).lower())

    def test_tampered_grant_fails_verification(self):
        minted = mint_local_handoff(
            secret=SECRET,
            source_agent_id="runtime-main",
            target_agent_id="codex-worker",
            target_capabilities=("workspace:read",),
            requested_capabilities=("workspace:read",),
            input_payload="x",
            run_id="run-bridge-4",
            now=1_700_000_000,
        )
        bad = minted["grant_token"][:-4] + "dead"
        verified = verify_local_grant(bad, SECRET, now=1_700_000_000)
        self.assertFalse(verified.ok)

    def test_empty_secret_is_refused(self):
        with self.assertRaises(InteropBridgeError):
            mint_local_handoff(
                secret=b"",
                source_agent_id="a",
                target_agent_id="b",
                target_capabilities=("workspace:read",),
                requested_capabilities=("workspace:read",),
                input_payload="x",
                run_id="run-bridge-5",
            )


if __name__ == "__main__":
    unittest.main()
