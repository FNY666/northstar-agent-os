"""
Test that a continuation policy can authorize resume when all checks pass.
"""
import unittest
import tempfile
from pathlib import Path
from continuation_admission import ContinuationPolicy, ContinuationAdmission
from autonomy_checkpoint_store import AutonomyCheckpointStore
from loop import AgentRuntime, RuntimeConfig
from sessions import SessionStore


class _MinimalProvider:
    """Minimal provider for admission testing; should never be called."""
    def chat_completion_create(self, **kwargs):
        raise RuntimeError("provider should not be called during admission-only tests")


class AuthorizedResumeTests(unittest.TestCase):
    def test_policy_with_authorize_resume_grants_execution_when_checks_pass(self):
        """When authorize_resume=True and all checks pass, admission must grant authorization."""
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            sessions = SessionStore(root, session_id="auth-test")
            runtime = AgentRuntime(
                provider=_MinimalProvider(),
                config=RuntimeConfig(session_id="auth-test", workspace=str(root), max_budget_usd=1.0),
                sessions=sessions,
            )
            store = AutonomyCheckpointStore(root / "checkpoints.jsonl")
            
            # Persist a checkpoint
            result = runtime.persist_continuation_checkpoint(
                store, goal={"objective": "test"}, observed_at=1000
            )
            
            # Admit with authorizing policy and all checks satisfied
            policy = ContinuationPolicy(
                max_age_seconds=60,
                require_pinned_checkpoint=True,
                require_objective_continuity=True,
                authorize_resume=True,
            )
            admission = runtime.admit_persisted_continuation_checkpoint(
                store,
                goal={"objective": "test"},
                now=1010,
                policy=policy,
                expected_record_digest=result.record_digest,
                expected_head_digest=runtime.continuation_objective_history(store).head_digest,
            )
            
            self.assertEqual(admission.state, "admit-continuation")
            self.assertTrue(admission.execution_authorized, "policy with authorize_resume=True must grant authorization when checks pass")
            
    def test_default_policy_remains_non_authorizing(self):
        """Existing tests must remain unaffected: default authorize_resume=False."""
        policy = ContinuationPolicy(max_age_seconds=60)
        self.assertFalse(hasattr(policy, 'authorize_resume') and policy.authorize_resume, 
                        "default policy must not authorize")
        
    def test_blocked_admission_never_authorizes_even_with_flag(self):
        """A blocked admission must not authorize regardless of the policy flag."""
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            sessions = SessionStore(root, session_id="block-test")
            runtime = AgentRuntime(
                provider=_MinimalProvider(),
                config=RuntimeConfig(session_id="block-test", workspace=str(root), max_budget_usd=1.0),
                sessions=sessions,
            )
            store = AutonomyCheckpointStore(root / "checkpoints.jsonl")
            
            result = runtime.persist_continuation_checkpoint(
                store, goal={"objective": "first"}, observed_at=1000
            )
            
            # Fresh but with authorize_resume=True; should not authorize because not pinned
            policy = ContinuationPolicy(
                max_age_seconds=60,
                require_pinned_checkpoint=True,
                authorize_resume=True,
            )
            admission = runtime.admit_persisted_continuation_checkpoint(
                store,
                goal={"objective": "first"},
                now=1010,
                policy=policy,
            )
            
            self.assertEqual(admission.state, "blocked-continuation-policy")
            self.assertFalse(admission.execution_authorized, "blocked admission must never authorize")


if __name__ == "__main__":
    unittest.main()
