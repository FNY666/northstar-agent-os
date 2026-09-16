"""
Test that authorized admissions enable continuation, and the authorization flag works correctly.
"""
import unittest
import tempfile
from pathlib import Path
from continuation_admission import ContinuationPolicy
from autonomy_checkpoint_store import AutonomyCheckpointStore
from loop import AgentRuntime, RuntimeConfig
from sessions import SessionStore


class _MinimalProvider:
    """Minimal provider for testing."""
    def chat_completion_create(self, **kwargs):
        raise RuntimeError("provider should not be called in authorization-only tests")


class AuthorizationFlagTests(unittest.TestCase):
    def test_authorization_flag_distinguishes_admit_states(self):
        """The execution_authorized flag correctly reflects policy and admission state."""
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            sessions = SessionStore(root, session_id="flag-test")
            runtime = AgentRuntime(
                provider=_MinimalProvider(),
                config=RuntimeConfig(session_id="flag-test", workspace=str(root), max_budget_usd=1.0),
                sessions=sessions,
            )
            store = AutonomyCheckpointStore(root / "checkpoints.jsonl")
            
            result = runtime.persist_continuation_checkpoint(
                store, goal={"objective": "test"}, observed_at=1000
            )
            
            # Case 1: authorize_resume=True, all checks pass → authorized
            policy_authorizing = ContinuationPolicy(
                max_age_seconds=60,
                require_pinned_checkpoint=True,
                require_objective_continuity=True,
                authorize_resume=True,
            )
            admission_authorized = runtime.admit_persisted_continuation_checkpoint(
                store,
                goal={"objective": "test"},
                now=1010,
                policy=policy_authorizing,
                expected_record_digest=result.record_digest,
                expected_head_digest=runtime.continuation_objective_history(store).head_digest,
            )
            self.assertEqual(admission_authorized.state, "admit-continuation")
            self.assertTrue(admission_authorized.execution_authorized, "should authorize when policy allows and checks pass")
            
            # Case 2: authorize_resume=False, same checks → not authorized
            policy_non_authorizing = ContinuationPolicy(
                max_age_seconds=60,
                require_pinned_checkpoint=True,
                require_objective_continuity=True,
                authorize_resume=False,  # Changed
            )
            admission_non_authorized = runtime.admit_persisted_continuation_checkpoint(
                store,
                goal={"objective": "test"},
                now=1010,
                policy=policy_non_authorizing,
                expected_record_digest=result.record_digest,
                expected_head_digest=runtime.continuation_objective_history(store).head_digest,
            )
            self.assertEqual(admission_non_authorized.state, "admit-continuation")
            self.assertFalse(admission_non_authorized.execution_authorized, "should not authorize when policy forbids")
            
            # Case 3: authorize_resume=True but checks fail → not authorized
            admission_blocked = runtime.admit_persisted_continuation_checkpoint(
                store,
                goal={"objective": "test"},
                now=1010,
                policy=policy_authorizing,
                # Missing expected_record_digest → unpinned → blocked
            )
            self.assertIn("blocked", admission_blocked.state)
            self.assertFalse(admission_blocked.execution_authorized, "blocked admissions never authorize")


if __name__ == "__main__":
    unittest.main()



if __name__ == "__main__":
    unittest.main()
