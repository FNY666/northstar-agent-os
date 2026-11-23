"""Integration tests: BackendRouter + RouteLedger + ExperienceMiddleware.

Covers the two integration points and, most importantly, the invariant that
makes the feedback loop work: the fingerprint computed at point #1 (admission,
from a RouteRequest) must equal the one computed at point #2 (recording, from
a persisted RouteEvent). If they differ the loop silently does nothing.

These tests deliberately go through the real ledger rather than hand-seeding
Experience: an earlier revision hand-seeded and therefore passed while the
recording point was in fact a no-op.
"""
import sys
import tempfile
import unittest
from pathlib import Path

COMPONENT_ROOT = Path(__file__).resolve().parents[1]
HOST_ROOT = COMPONENT_ROOT.parent / "northstar-host"
sys.path.insert(0, str(COMPONENT_ROOT))
sys.path.insert(0, str(HOST_ROOT))
sys.path.insert(0, str(COMPONENT_ROOT.parent))
sys.path.insert(0, str(COMPONENT_ROOT.parent / "northstar-host"))
sys.path.insert(0, str(COMPONENT_ROOT.parent / "northstar-run-contract"))

from backend_router import BackendRouter, RouteRequest
from interop_contract import AgentProfile
from experience_middleware import ExperienceMiddleware, PolicyDeniedError
from experience_layering import ExperienceLayering, ExperienceRecord
from route_ledger import RouteLedger, RouteEvent, RouteReceipt


def make_request(
    *,
    step_id: str = "step-1",
    input_digest: str = "sha256:" + "a" * 64,
    run_id: str = "run-1",
    actor_id: str = "actor-1",
    capabilities: list = None,
) -> RouteRequest:
    return RouteRequest.from_dict({
        "schema_version": "northstar.route-request.v1",
        "task_id": "task-1",
        "thread_id": "thread-1",
        "run_id": run_id,
        "actor_id": actor_id,
        "workspace_id": "ws-1",
        "policy_revision": "policy-1",
        "step_id": step_id,
        "trace_id": "trace-1",
        "input_digest": input_digest,
        "requested_capabilities": capabilities or ["workspace:read"],
        "deadline_at": 10_000,
        "preferred_agent_ids": [],
        "excluded_agent_ids": [],
    })


def fingerprint_for(step_id: str = "step-1", actor_id: str = "actor-1") -> str:
    """The fingerprint the middleware derives for a given step/actor."""
    return f"{actor_id}:{step_id}"


def make_profile(agent_id: str = "codex", capabilities: tuple = ("workspace:read",)) -> AgentProfile:
    return AgentProfile.from_dict({
        "schema_version": "northstar.agent-profile.v1",
        "agent_id": agent_id,
        "provider": "test",
        "version": "v1",
        "capabilities": sorted(capabilities),
    })


class FakeAdapter:
    def __init__(self, agent_id: str):
        self.agent_id = agent_id


class ExperienceIntegrationTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.base = Path(self._tmp.name)
        self.experience = ExperienceLayering(base_dir=self.base / "exp")
        self.middleware = ExperienceMiddleware(self.experience)

    def tearDown(self):
        self._tmp.cleanup()

    def _router(self, middleware="default"):
        mw = self.middleware if middleware == "default" else middleware
        router = BackendRouter(experience_middleware=mw)
        router.register(make_profile(), FakeAdapter("codex"), priority=10)
        return router

    def _ledger(self, middleware="default", name: str = "route-ledger.jsonl"):
        mw = self.middleware if middleware == "default" else middleware
        return RouteLedger(self.base / name, experience_middleware=mw)

    def _seed(self, fingerprint: str, successes: int, losses: int):
        for i in range(successes):
            self.experience.settle(ExperienceRecord(
                fingerprint=fingerprint,
                outcome="success",
                reason=None,
                timestamp=1_000 + i,
                metadata={},
            ))
        for i in range(losses):
            self.experience.record_lost(
                fingerprint=fingerprint,
                reason="backend_timeout",
                timestamp=2_000 + i,
                run_id=f"lost-{i}",
            )

    def _receipt(self, decision, status: str, attempt: int = 1, key: str = "k", at: int = 2, **kw):
        base = dict(
            status=status,
            attempt=attempt,
            latency_ms=10,
            failure_class=None,
            error_code=None,
            retryable=False,
            idempotency_key=key,
            recorded_at=at,
        )
        base.update(kw)
        return RouteReceipt.from_decision(decision, **base)

    # -- point #1: admission -------------------------------------------

    def test_no_history_is_admitted(self):
        decision = self._router().select(make_request(step_id="s-none"), now=1)
        self.assertEqual(decision.target_agent_id, "codex")

    def test_good_history_is_admitted(self):
        self._seed(fingerprint_for("s-good"), successes=9, losses=1)
        decision = self._router().select(make_request(step_id="s-good"), now=1)
        self.assertEqual(decision.target_agent_id, "codex")

    def test_bad_history_is_blocked(self):
        self._seed(fingerprint_for("s-bad"), successes=2, losses=8)
        with self.assertRaises(PolicyDeniedError) as ctx:
            self._router().select(make_request(step_id="s-bad"), now=1)
        self.assertIn("success_rate", ctx.exception.reason)

    def test_history_does_not_leak_across_steps(self):
        """A bad step must not block an unrelated one."""
        self._seed(fingerprint_for("s-bad"), successes=0, losses=10)
        decision = self._router().select(make_request(step_id="s-other"), now=1)
        self.assertEqual(decision.target_agent_id, "codex")

    def test_without_middleware_history_is_ignored(self):
        self._seed(fingerprint_for("s-ign"), successes=0, losses=10)
        decision = self._router(middleware=None).select(make_request(step_id="s-ign"), now=1)
        self.assertEqual(decision.target_agent_id, "codex")

    # -- point #2: outcome recording ------------------------------------

    def test_failure_through_the_ledger_is_recorded(self):
        request = make_request(step_id="s-fail")
        ledger = self._ledger()
        decision = self._router().select(request, now=1)
        ledger.append_decision(decision, attempt=1, idempotency_key="k-dec", recorded_at=2)
        ledger.append_receipt(self._receipt(decision, "started", key="k-started"))
        ledger.append_receipt(self._receipt(
            decision, "failed", key="k-failed",
            failure_class="backend_timeout", error_code="timeout", retryable=True,
        ))
        stats = self.experience.query_statistics(fingerprint_for("s-fail"))
        self.assertEqual(stats["lost_count"], 1)

    def test_success_through_the_ledger_is_recorded(self):
        """Successes must be recorded too, or success_rate can never recover.

        An earlier revision recorded only failures here.
        """
        request = make_request(step_id="s-ok")
        ledger = self._ledger()
        decision = self._router().select(request, now=1)
        ledger.append_decision(decision, attempt=1, idempotency_key="k-dec", recorded_at=2)
        ledger.append_receipt(self._receipt(decision, "started", key="k-started"))
        ledger.append_receipt(self._receipt(decision, "succeeded", key="k-ok", at=3))
        stats = self.experience.query_statistics(fingerprint_for("s-ok"))
        self.assertEqual(stats["success_count"], 1)
        self.assertEqual(stats["lost_count"], 0)

    # -- THE invariant ---------------------------------------------------

    def test_fingerprint_agrees_across_both_integration_points(self):
        """Point #1 (RouteRequest) and #2 (RouteEvent) must agree exactly.

        This is the assertion that keeps the loop closed. It fails loudly if
        either side is switched to a field the other side cannot see -- for
        example input_digest, which RouteRequest has but the ledger does not
        persist onto RouteEvent.
        """
        request = make_request(step_id="s-inv", actor_id="actor-7")
        decision = self._router().select(request, now=1)
        event = RouteEvent.from_decision(
            decision, event_type="decision.selected", attempt=1,
            idempotency_key="k-dec", recorded_at=2,
        )

        from_point_1 = self.middleware.generate_fingerprint({
            "actor_id": request.actor_id,
            "step_id": request.step_id,
        })
        from_point_2 = self.middleware.generate_fingerprint({
            "actor_id": event.actor_id,
            "step_id": event.step_id,
        })
        self.assertEqual(from_point_1, from_point_2)
        self.assertEqual(from_point_1, "actor-7:s-inv")

    def test_ledger_blocking_is_visible_to_admission(self):
        """End-to-end: failures recorded via the ledger must block a later select.

        Each failure uses a distinct failure_class because the lost-event
        stream dedupes on (run_id, fingerprint, reason) -- repeating one
        reason would collapse to a single record and never cross min_samples.
        """
        request = make_request(step_id="s-e2e")
        ledger = self._ledger()
        decision = self._router().select(request, now=1)
        ledger.append_decision(decision, attempt=1, idempotency_key="k-dec", recorded_at=2)
        failures = [
            ("backend_timeout", "timeout"),
            ("backend_process_exit", "process_exit"),
            ("backend_malformed_output", "malformed_output"),
            ("backend_unavailable", "unavailable"),
            ("adapter_error", "adapter_error"),
            ("policy_denied", "policy_denied"),
            ("route_no_candidate", "no_candidate"),
        ]
        for i, (failure_class, error_code) in enumerate(failures):
            ledger.append_receipt(self._receipt(decision, "started", key=f"k-s-{i}", at=3))
            ledger.append_receipt(self._receipt(
                decision, "failed", key=f"k-f-{i}", at=4,
                failure_class=failure_class, error_code=error_code, retryable=True,
            ))
        stats = self.experience.query_statistics(fingerprint_for("s-e2e"))
        self.assertEqual(stats["lost_count"], len(failures))
        with self.assertRaises(PolicyDeniedError):
            self._router().select(make_request(step_id="s-e2e"), now=2)

    # -- recovery --------------------------------------------------------

    def test_recovery_is_reachable_once_successes_are_recorded(self):
        fp = fingerprint_for("s-rec")
        for i in range(8):
            self.middleware.record_lost(fp, "backend_timeout", {"run_id": f"l-{i}"})
        with self.assertRaises(PolicyDeniedError):
            self._router().select(make_request(step_id="s-rec"), now=1)
        for i in range(20):
            self.middleware.record_success(fp, {"run_id": f"s-{i}"})
        decision = self._router().select(make_request(step_id="s-rec"), now=2)
        self.assertEqual(decision.target_agent_id, "codex")

    def test_admission_block_is_not_self_clearing(self):
        """Pins a known limitation: a block cannot lift itself.

        Admitted runs are the only source of successes, and admission is
        exactly what the block withholds. Recovering needs an operator
        override, a probe allowance, or a coarser fingerprint.
        """
        self._seed(fingerprint_for("s-dead"), successes=2, losses=8)
        router = self._router()
        for attempt in range(3):
            with self.assertRaises(PolicyDeniedError):
                router.select(make_request(step_id="s-dead"), now=100 + attempt)
        stats = self.experience.query_statistics(fingerprint_for("s-dead"))
        self.assertEqual(stats["success_count"], 2)
        self.assertLess(stats["success_rate"], 0.7)

    # -- resilience ------------------------------------------------------

    def test_experience_error_does_not_block_execution(self):
        broken = ExperienceMiddleware(_BrokenExperience())
        decision = self._router(middleware=broken).select(make_request(step_id="s-brk"), now=1)
        self.assertEqual(decision.target_agent_id, "codex")

    def test_ledger_works_when_middleware_absent(self):
        request = make_request(step_id="s-none-mw")
        ledger = self._ledger(middleware=None, name="ledger-nomw.jsonl")
        decision = self._router(middleware=None).select(request, now=1)
        ledger.append_decision(decision, attempt=1, idempotency_key="k-dec", recorded_at=2)
        ledger.append_receipt(self._receipt(decision, "started", key="k-s"))
        ledger.append_receipt(self._receipt(decision, "succeeded", key="k-ok", at=3))
        self.assertEqual(self.experience.query_statistics(fingerprint_for("s-none-mw"))["total_runs"], 0)


class _BrokenExperience:
    """Experience stub that raises, to exercise the fail-open paths."""

    def query_statistics(self, fingerprint):
        raise RuntimeError("experience backend unavailable")

    def settle(self, record):
        raise RuntimeError("experience backend unavailable")

    def record_lost(self, *args, **kwargs):
        raise RuntimeError("experience backend unavailable")


class ProbeAllowanceTests(unittest.TestCase):
    """A block must be escapable -- otherwise it is permanent.

    Successes only come from admitted runs, and the block withholds
    admission, so without a probe allowance a fingerprint that once dipped
    below threshold can never recover.
    """

    def setUp(self):
        self.base = Path(tempfile.mkdtemp(prefix="probe-"))
        self.experience = ExperienceLayering(base_dir=self.base / "exp")
        self.fp = "actor-1:step-1"

    def _mw(self, **kwargs):
        kwargs.setdefault("probe_interval", 3)
        return ExperienceMiddleware(self.experience, **kwargs)

    def _block(self, mw, n=4):
        for i in range(n):
            mw.record_lost(self.fp, f"reason-{i}", {"timestamp": i, "run_id": "r1"})

    def test_every_nth_blocked_attempt_is_let_through(self):
        mw = self._mw()
        self._block(mw)
        seq = "".join(
            "P" if mw.check_admission(self.fp, {}).probe else "B"
            for _ in range(9)
        )
        self.assertEqual(seq, "BBPBBPBBP")

    def test_failed_probe_widens_the_window(self):
        mw = self._mw()
        self._block(mw)
        interval_before = mw.check_admission(self.fp, {}).metadata["probe_interval"]
        res = None
        while res is None or not res.probe:
            res = mw.check_admission(self.fp, {})
        # The probe we just handed out fails.
        mw.record_lost(self.fp, "backend_timeout", {"timestamp": 9, "run_id": "p1"})
        interval_after = mw.check_admission(self.fp, {}).metadata["probe_interval"]
        self.assertGreater(interval_after, interval_before)

    def test_ordinary_failure_does_not_widen_the_window(self):
        """Only probe failures justify backoff.

        An admitted run failing says nothing about whether the escape hatch
        works; treating it as backoff pressure would inflate the interval
        before the fingerprint is even blocked (this was a real bug: the
        window had already grown to 48 by the time blocking began).
        """
        mw = self._mw()
        for i in range(12):
            mw.record_lost(self.fp, f"reason-{i}", {"timestamp": i, "run_id": "r1"})
        res = mw.check_admission(self.fp, {})
        self.assertEqual(res.metadata["probe_interval"], 3)

    def test_probe_successes_lift_the_block(self):
        mw = self._mw()
        self._block(mw)
        for attempt in range(200):
            res = mw.check_admission(self.fp, {})
            if res.execution_authorized:
                mw.record_success(self.fp, {"timestamp": attempt, "run_id": f"p{attempt}"})
            if self.experience.query_statistics(self.fp)["success_rate"] >= 0.7:
                break
        self.assertEqual(mw.check_admission(self.fp, {}).decision, "admit")

    def test_probe_allowance_can_be_disabled(self):
        """probe_interval=1 admits every blocked attempt -> effectively off."""
        mw = self._mw(probe_interval=1)
        self._block(mw)
        self.assertTrue(mw.check_admission(self.fp, {}).execution_authorized)


class FailOpenObservabilityTests(unittest.TestCase):
    """Fail-open must stay visible, or a dead layer looks like an idle one."""

    def test_swallowed_errors_are_counted(self):
        middleware = ExperienceMiddleware(_BrokenExperience(), error_sink=lambda w, e: None)
        middleware.record_lost("fp", "backend_timeout", {"timestamp": 1, "run_id": "r"})
        middleware.record_success("fp", {"timestamp": 2, "run_id": "r"})
        middleware.check_admission("fp", {})
        self.assertEqual(middleware.error_counts.get("record_lost"), 1)
        self.assertEqual(middleware.error_counts.get("record_success"), 1)
        self.assertGreaterEqual(len(middleware.recent_errors()), 2)
        self.assertEqual(middleware.recent_errors(limit=1)[0][1], "RuntimeError")

    def test_healthy_middleware_reports_no_errors(self):
        base = Path(tempfile.mkdtemp(prefix="observe-"))
        middleware = ExperienceMiddleware(
            ExperienceLayering(base_dir=base / "exp"), error_sink=lambda w, e: None
        )
        middleware.record_lost("fp", "backend_timeout", {"timestamp": 1, "run_id": "r"})
        middleware.check_admission("fp", {})
        self.assertEqual(middleware.error_counts, {})
        self.assertEqual(middleware.recent_errors(), [])

    def test_broken_sink_does_not_raise(self):
        def exploding_sink(where, error):
            raise RuntimeError("sink is broken")

        middleware = ExperienceMiddleware(_BrokenExperience(), error_sink=exploding_sink)
        middleware.record_lost("fp", "backend_timeout", {"timestamp": 1, "run_id": "r"})
        self.assertEqual(middleware.error_counts.get("record_lost"), 1)


if __name__ == "__main__":
    unittest.main()
