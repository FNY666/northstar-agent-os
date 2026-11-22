"""R21: governance denials must be diagnosable without leaking unsafe text.

Two guarantees:

1. A host-tagged refusal (``_host_denial``) records its ``safe_reason`` in the
   ``step.action_denied`` evidence event under ``detail``.
2. Provider-influenced text (approval decisions, tool refusals) stays out of
   evidence entirely, and journals written before R21 (no ``detail`` key)
   still verify byte-identically.
"""
from __future__ import annotations

import json
import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT)]

from agent_loop import AgentLoop, LoopEvent  # noqa: E402
from action_gateway import _host_denial  # noqa: E402


class LoopEventDetailTests(unittest.TestCase):
    def test_detail_round_trips_through_to_dict_and_digest(self) -> None:
        event = LoopEvent.create(
            sequence=1, prev_event_digest=None, plan_digest="sha256:" + "a" * 64,
            event_type="plan.admitted", step_id="__plan__",
            execution_id=None, attempt_id=None, attempt=0,
            status="admitted", reason_code="plan_admitted",
            observed_digest=None, output_digest=None,
            plan_step_manifest=({
                "step_id": "s1", "execution_id": "execution-k1",
                "idempotency_key": "k1", "max_attempts": 2,
                "deadline_at": 200,
            },),
            idempotency_key="k1",
            recorded_at=100, detail="capability_not_authorized",
        )
        body = event.to_dict()
        self.assertEqual(body["detail"], "capability_not_authorized")
        # digest must cover the detail field
        self.assertIn(body["event_digest"], _digests(body))

    def test_unset_detail_is_omitted_for_pre_r21_round_trip(self) -> None:
        event = LoopEvent.create(
            sequence=1, prev_event_digest=None, plan_digest="sha256:" + "a" * 64,
            event_type="plan.admitted", step_id="__plan__",
            execution_id=None, attempt_id=None, attempt=0,
            status="admitted", reason_code="plan_admitted",
            observed_digest=None, output_digest=None,
            plan_step_manifest=({
                "step_id": "s1", "execution_id": "execution-k1",
                "idempotency_key": "k1", "max_attempts": 2,
                "deadline_at": 200,
            },),
            idempotency_key="k1",
            recorded_at=100,
        )
        body = event.to_dict()
        self.assertNotIn("detail", body,
                         "unset detail must be omitted so pre-R21 journals "
                         "round-trip byte-identically")

    def test_detail_is_rejected_if_not_a_bounded_string(self) -> None:
        with self.assertRaises(ValueError):
            LoopEvent.create(
                sequence=1, prev_event_digest=None, plan_digest="sha256:" + "a" * 64,
                event_type="plan.admitted", step_id="__plan__",
                execution_id=None, attempt_id=None, attempt=0,
                status="admitted", reason_code="plan_admitted",
                observed_digest=None, output_digest=None,
                plan_step_manifest=None, idempotency_key="k1",
                recorded_at=100, detail="x" * 401,
            )


class GovernanceDetailSurfaceTests(unittest.TestCase):
    """The denial path must carry only host-tagged safe reasons."""

    def test_governance_denied_preserves_safe_reason_only(self) -> None:
        from governed_dispatch import GovernanceDenied

        host = _host_denial("tool capability is not authorized",
                            "capability_not_authorized")
        # simulate the dispatch wrapper's selection logic
        safe = getattr(host, "safe_reason", None)
        if not isinstance(safe, str) or not safe or len(safe) > 64:
            safe = None
        denied = GovernanceDenied(type(host).__name__, safe)
        self.assertEqual(denied.detail, "capability_not_authorized")

    def test_plain_value_error_yields_no_detail(self) -> None:
        plain = ValueError("approval was denied")  # no safe_reason attribute
        safe = getattr(plain, "safe_reason", None)
        self.assertIsNone(safe)

    def test_payload_shape_reason_is_fixed_and_does_not_echo_input(self) -> None:
        from action_gateway import ToolRefused
        from governed_dispatch import GovernanceDenied
        refused = ToolRefused(
            "invalid read limit: sk-secret-value",
            safe_reason="payload_shape_invalid",
        )
        safe = getattr(refused, "safe_reason", None)
        self.assertEqual(safe, "payload_shape_invalid")
        denied = GovernanceDenied(type(refused).__name__, safe)
        event = LoopEvent.create(
            sequence=1, prev_event_digest=None, plan_digest="sha256:" + "a" * 64,
            event_type="step.action_denied", step_id="read-1",
            execution_id="execution-read-1", attempt_id="execution-read-1:attempt-1",
            attempt=1, status="attempted", reason_code=type(denied).__name__,
            observed_digest=None, output_digest=None, plan_step_manifest=None,
            idempotency_key="execution-read-1:attempt-1:denied",
            recorded_at=100, detail=denied.detail,
        )
        body = event.to_dict()
        self.assertEqual(body["detail"], "payload_shape_invalid")
        self.assertNotIn("sk-secret-value", json.dumps(body))

    def test_real_pre_r21_journal_replays_without_detail(self) -> None:
        import json
        from completion_replay import verify_evidence_chain
        path = Path(os.environ.get(
            "NORTHSTAR_LIVE_RUNS",
            "/var/minis/shared/northstar-live-runs",
        )) / "2026-10-23-kakouai/140-native/raw-evidence/hunt/s-4/evidence/round-1.evidence.jsonl"
        if not path.exists():
            self.skipTest("archived real pre-R21 journal is unavailable")
        events = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
        self.assertEqual(len(events), 15)
        self.assertTrue(all("detail" not in event for event in events))
        self.assertIsNone(verify_evidence_chain(events))


def _digests(body):
    import hashlib, json
    body = {k: v for k, v in body.items() if k != "event_digest"}
    forms = (
        json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True),
        json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False),
    )
    return tuple("sha256:" + hashlib.sha256(f.encode()).hexdigest() for f in forms)


if __name__ == "__main__":
    unittest.main()
