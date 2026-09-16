"""
Test that runtime automatically resumes when continuation admission is authorized.
"""
import unittest
import tempfile
from pathlib import Path
from continuation_admission import ContinuationPolicy
from autonomy_checkpoint_store import AutonomyCheckpointStore
from loop import AgentRuntime, RuntimeConfig
from sessions import SessionStore


class _MockProvider:
    """Provider that should not be called in authorization-only tests."""
    def chat_completion_create(self, **kwargs):
        raise RuntimeError("provider should not be called in authorization-only tests")


class AutoResumeTests(unittest.TestCase):
    def test_authorized_admission_returns_both_admission_and_report(self):
        """When admission is authorized, the method returns admission + report (may be empty)."""
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            sessions = SessionStore(root, session_id="auto-resume-test")
            runtime = AgentRuntime(
                provider=_MockProvider(),
                config=RuntimeConfig(session_id="auto-resume-test", workspace=str(root), max_budget_usd=1.0),
                sessions=sessions,
            )
            
            store = AutonomyCheckpointStore(root / "checkpoints.jsonl")
            result = runtime.persist_continuation_checkpoint(
                store, goal={"objective": "test"}, observed_at=1000
            )
            
            # Resume with authorizing policy
            policy = ContinuationPolicy(
                max_age_seconds=60,
                require_pinned_checkpoint=True,
                authorize_resume=True,
            )
            
            admission, report = runtime.resume_if_authorized_continuation(
                store,
                goal={"objective": "test"},
                policy=policy,
                prompt="continue",
                now=1010,
                expected_record_digest=result.record_digest,
                expected_head_digest=runtime.continuation_objective_history(store).head_digest,
            )
            
            # Verify admission was authorized
            self.assertTrue(admission.execution_authorized)
            
            # Verify report is returned (not None, even if empty)
            self.assertIsNotNone(report)
    
    def test_blocked_admission_does_not_resume(self):
        """When admission is blocked, runtime does not resume."""
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            sessions = SessionStore(root, session_id="blocked-test")
            runtime = AgentRuntime(
                provider=_MockProvider(),
                config=RuntimeConfig(session_id="blocked-test", workspace=str(root), max_budget_usd=1.0),
                sessions=sessions,
            )
            
            store = AutonomyCheckpointStore(root / "checkpoints.jsonl")
            runtime.persist_continuation_checkpoint(store, goal={"objective": "test"}, observed_at=1000)
            
            # Policy requires pin but we don't provide expected_record_digest → blocked
            policy = ContinuationPolicy(
                max_age_seconds=60,
                require_pinned_checkpoint=True,
                authorize_resume=True,
            )
            
            admission, report = runtime.resume_if_authorized_continuation(
                store,
                goal={"objective": "test"},
                policy=policy,
                prompt="continue",
                now=1010,
            )
            
            # Verify admission was blocked
            self.assertIn("blocked", admission.state)
            self.assertFalse(admission.execution_authorized)
            
            # Verify resume was NOT triggered (provider not called, no exception)
            self.assertIsNone(report)
    
    def test_non_authorizing_policy_does_not_resume(self):
        """When policy forbids authorization, runtime does not resume even if checks pass."""
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            sessions = SessionStore(root, session_id="non-auth-test")
            runtime = AgentRuntime(
                provider=_MockProvider(),
                config=RuntimeConfig(session_id="non-auth-test", workspace=str(root), max_budget_usd=1.0),
                sessions=sessions,
            )
            
            store = AutonomyCheckpointStore(root / "checkpoints.jsonl")
            result = runtime.persist_continuation_checkpoint(store, goal={"objective": "test"}, observed_at=1000)
            
            # All checks pass but authorize_resume=False
            policy = ContinuationPolicy(
                max_age_seconds=60,
                require_pinned_checkpoint=True,
                authorize_resume=False,  # Explicitly forbid
            )
            
            admission, report = runtime.resume_if_authorized_continuation(
                store,
                goal={"objective": "test"},
                policy=policy,
                prompt="continue",
                now=1010,
                expected_record_digest=result.record_digest,
                expected_head_digest=runtime.continuation_objective_history(store).head_digest,
            )
            
            # Verify admission state is admit but not authorized
            self.assertEqual(admission.state, "admit-continuation")
            self.assertFalse(admission.execution_authorized)
            
            # Verify resume was NOT triggered (provider not called, no exception)
            self.assertIsNone(report)


if __name__ == "__main__":
    unittest.main()
