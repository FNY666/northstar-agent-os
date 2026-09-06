import sys
import unittest
from pathlib import Path

COMPONENT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(COMPONENT_ROOT))

from trace_metrics import MetricsSummary, TraceRecorder, TraceSpan  # noqa: E402


BASE = {
    "schema_version": "northstar.trace-span.v1",
    "span_id": "span-001",
    "parent_span_id": None,
    "trace_id": "trace-001",
    "task_id": "task-001",
    "thread_id": "thread-001",
    "run_id": "run-001",
    "step_id": "edit",
    "span_kind": "execute_tool",
    "name": "workspace.read_file",
    "started_at": 1_000,
    "ended_at": 1_005,
    "attempt": 1,
    "tool_name": "workspace.read_file",
    "scope_digest": "sha256:" + "1" * 64,
    "approval_state": "not_required",
    "status": "ok",
    "error_class": None,
    "verifier_verdict": None,
    "input_tokens": 12,
    "output_tokens": 8,
    "cost_micros": 42,
}


class TraceMetricsTests(unittest.TestCase):
    def test_trace_span_round_trips_and_computes_duration(self):
        span = TraceSpan.from_dict(BASE)
        self.assertEqual(span.to_dict(), BASE)
        self.assertEqual(span.duration_ms, 5_000)
        self.assertEqual(span.canonical_json(), TraceSpan.from_dict(dict(reversed(list(BASE.items())))).canonical_json())

    def test_trace_span_rejects_unknown_fields_and_sensitive_data(self):
        for field, value in (
            ("prompt", "do not persist"),
            ("secret", "do not persist"),
            ("authorization_token", "do not persist"),
            ("unknown", "reject"),
        ):
            invalid = dict(BASE)
            invalid[field] = value
            with self.subTest(field=field):
                with self.assertRaises(ValueError):
                    TraceSpan.from_dict(invalid)

    def test_trace_span_rejects_invalid_identity_timing_status_and_metrics(self):
        for field, value in (
            ("run_id", "run/002"),
            ("span_kind", "prompt"),
            ("started_at", -1),
            ("ended_at", 999),
            ("attempt", 0),
            ("approval_state", "maybe"),
            ("status", "succeeded"),
            ("input_tokens", -1),
            ("output_tokens", True),
            ("cost_micros", "42"),
        ):
            invalid = dict(BASE)
            invalid[field] = value
            with self.subTest(field=field, value=value):
                with self.assertRaises(ValueError):
                    TraceSpan.from_dict(invalid)

    def test_recorder_requires_parent_identity_and_returns_immutable_snapshot(self):
        recorder = TraceRecorder(
            task_id="task-001",
            thread_id="thread-001",
            run_id="run-001",
            trace_id="trace-001",
        )
        span = recorder.record(BASE)
        self.assertEqual(span, TraceSpan.from_dict(BASE))
        snapshot = recorder.spans()
        self.assertEqual(snapshot, (span,))
        with self.assertRaises(AttributeError):
            snapshot.append(span)

        invalid = dict(BASE)
        invalid["step_id"] = "other-step"
        with self.assertRaises(ValueError):
            recorder.record(invalid)

    def test_summary_aggregates_latency_cost_errors_and_verdicts_without_raw_content(self):
        recorder = TraceRecorder(
            task_id="task-001",
            thread_id="thread-001",
            run_id="run-001",
            trace_id="trace-001",
        )
        recorder.record(BASE)
        failed = dict(BASE)
        failed.update(
            {
                "span_id": "span-002",
                "step_id": "test",
                "span_kind": "guardrail",
                "name": "postcondition",
                "started_at": 2_000,
                "ended_at": 2_010,
                "tool_name": None,
                "status": "error",
                "error_class": "postcondition_failed",
                "verifier_verdict": "failed",
                "input_tokens": 2,
                "output_tokens": 3,
                "cost_micros": 7,
            }
        )
        recorder.record(failed)
        summary = MetricsSummary.from_spans(recorder.spans())
        self.assertEqual(summary.span_count, 2)
        self.assertEqual(summary.total_duration_ms, 15_000)
        self.assertEqual(summary.total_cost_micros, 49)
        self.assertEqual(summary.error_count, 1)
        self.assertEqual(summary.verifier_counts, {"failed": 1})
        self.assertNotIn("prompt", summary.to_dict())
        self.assertNotIn("secret", summary.to_dict())

    def test_recorder_rejects_cross_run_and_duplicate_span(self):
        recorder = TraceRecorder(
            task_id="task-001",
            thread_id="thread-001",
            run_id="run-001",
            trace_id="trace-001",
        )
        recorder.record(BASE)
        duplicate = dict(BASE)
        duplicate["started_at"] = 1_001
        with self.assertRaises(ValueError):
            recorder.record(duplicate)
        other = dict(BASE)
        other["span_id"] = "span-002"
        other["run_id"] = "run-002"
        with self.assertRaises(ValueError):
            recorder.record(other)


if __name__ == "__main__":
    unittest.main()
