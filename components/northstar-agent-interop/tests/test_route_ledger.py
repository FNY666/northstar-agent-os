import json
import multiprocessing
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

COMPONENT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(COMPONENT_ROOT))

from backend_router import RouteDecision  # noqa: E402
from route_ledger import (  # noqa: E402
    FAILURE_CLASSES,
    RouteDecisionRecord,
    RouteEvent,
    RouteLedger,
    RouteReceipt,
    RouteReplay,
)


DECISION = RouteDecision.from_dict(
    {
        "schema_version": "northstar.route-decision.v1",
        "route_id": "route-001",
        "task_id": "task-route-001",
        "thread_id": "thread-route-001",
        "run_id": "run-route-001",
        "actor_id": "actor-route-001",
        "workspace_id": "workspace-route-001",
        "policy_revision": "policy-route-1",
        "step_id": "implementation",
        "trace_id": "trace-route-001",
        "input_digest": "sha256:" + "1" * 64,
        "requested_capabilities": ["workspace:read"],
        "deadline_at": 1_900,
        "target_agent_id": "codex",
        "provider": "openai",
        "backend_version": "cli-v1",
        "priority": 10,
        "selected_at": 1_001,
    }
)


class RouteLedgerTestCase(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.path = Path(self.tempdir.name) / "route-events.jsonl"
        self.ledger = RouteLedger(self.path)

    def tearDown(self):
        self.tempdir.cleanup()

    def started(self, *, attempt=1, recorded_at=1_002, key="route-001-started-1"):
        return RouteReceipt.from_decision(
            DECISION,
            status="started",
            attempt=attempt,
            latency_ms=12,
            failure_class=None,
            error_code=None,
            retryable=False,
            idempotency_key=key,
            recorded_at=recorded_at,
        )

    def succeeded(self, *, attempt=1, recorded_at=1_010, key="route-001-succeeded-1"):
        return RouteReceipt.from_decision(
            DECISION,
            status="succeeded",
            attempt=attempt,
            latency_ms=42,
            failure_class=None,
            error_code=None,
            retryable=False,
            idempotency_key=key,
            recorded_at=recorded_at,
        )

    def failed(self, *, attempt=1, recorded_at=1_010, key="route-001-failed-1"):
        return RouteReceipt.from_decision(
            DECISION,
            status="failed",
            attempt=attempt,
            latency_ms=99,
            failure_class="backend_timeout",
            error_code="timeout",
            retryable=True,
            idempotency_key=key,
            recorded_at=recorded_at,
        )


class RouteRecordContractTests(RouteLedgerTestCase):
    def test_decision_record_round_trips_with_canonical_digest_and_no_secrets(self):
        record = RouteDecisionRecord.from_decision(
            DECISION,
            attempt=1,
            idempotency_key="route-001-selected-1",
            recorded_at=1_001,
        )
        self.assertEqual(record.decision, DECISION)
        self.assertTrue(record.decision_digest.startswith("sha256:"))
        self.assertEqual(
            RouteDecisionRecord.from_dict(record.to_dict()),
            record,
        )
        rendered = json.dumps(record.to_dict(), sort_keys=True)
        self.assertNotIn("prompt", rendered)
        self.assertNotIn("secret", rendered)
        self.assertNotIn("token", rendered)
        self.assertNotIn("raw_error", rendered)

    def test_decision_record_rejects_unknown_fields_bad_attempt_key_time_and_digest(self):
        record = RouteDecisionRecord.from_decision(
            DECISION,
            attempt=1,
            idempotency_key="route-001-selected-1",
            recorded_at=1_001,
        )
        cases = [
            {**record.to_dict(), "prompt": "must not persist"},
            {**record.to_dict(), "attempt": 0},
            {**record.to_dict(), "attempt": True},
            {**record.to_dict(), "idempotency_key": "key with space"},
            {**record.to_dict(), "recorded_at": True},
            {**record.to_dict(), "decision_digest": "sha256:" + "A" * 64},
        ]
        for invalid in cases:
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    RouteDecisionRecord.from_dict(invalid)

    def test_receipt_round_trips_and_exposes_only_bounded_observability(self):
        receipt = self.failed()
        self.assertEqual(RouteReceipt.from_dict(receipt.to_dict()), receipt)
        self.assertEqual(receipt.failure_class, "backend_timeout")
        self.assertEqual(receipt.error_code, "timeout")
        self.assertTrue(receipt.retryable)
        self.assertEqual(receipt.latency_ms, 99)
        rendered = json.dumps(receipt.to_dict(), sort_keys=True)
        self.assertNotIn("raw_error", rendered)
        self.assertNotIn("prompt", rendered)
        self.assertNotIn("secret", rendered)
        self.assertNotIn("traceback", rendered)

    def test_receipt_failure_fields_are_conjunctive_and_failure_class_is_finite(self):
        base = self.started().to_dict()
        for failure_class in set(FAILURE_CLASSES) | {"uncontrolled_model_text"}:
            invalid = dict(base)
            invalid["status"] = "failed"
            invalid["failure_class"] = failure_class
            invalid["error_code"] = "timeout"
            invalid["retryable"] = True
            if failure_class not in FAILURE_CLASSES:
                with self.assertRaises(ValueError):
                    RouteReceipt.from_dict(invalid)
        for invalid in (
            {**base, "status": "failed", "failure_class": None, "error_code": "timeout", "retryable": True},
            {**base, "status": "failed", "failure_class": "backend_timeout", "error_code": None, "retryable": True},
            {**base, "status": "succeeded", "failure_class": "backend_timeout", "error_code": "timeout", "retryable": True},
            {**base, "status": "failed", "failure_class": "backend_timeout", "error_code": "raw provider failure text", "retryable": True},
            {**base, "status": "started", "failure_class": None, "error_code": None, "retryable": True},
        ):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    RouteReceipt.from_dict(invalid)

    def test_receipt_rejects_structurally_invalid_fields(self):
        receipt = self.started()
        cases = (
            ("route_id", "route/other"),
            ("decision_digest", "not-a-digest"),
            ("attempt", 0),
            ("latency_ms", -1),
            ("recorded_at", 0),
        )
        for field, value in cases:
            invalid = receipt.to_dict()
            invalid[field] = value
            with self.subTest(field=field, value=value):
                with self.assertRaises(ValueError):
                    RouteReceipt.from_dict(invalid)

    def test_event_contract_round_trips_and_rejects_unknown_or_raw_payload(self):
        event = RouteEvent.from_decision(
            DECISION,
            event_type="decision.selected",
            attempt=1,
            idempotency_key="route-001-selected-1",
            recorded_at=1_001,
        )
        self.assertEqual(RouteEvent.from_dict(event.to_dict()), event)
        self.assertEqual(event.sequence, 1)
        for invalid in (
            {**event.to_dict(), "prompt": "no"},
            {**event.to_dict(), "raw_error": "no"},
            {**event.to_dict(), "event_type": "unknown.event"},
            {**event.to_dict(), "payload": {"secret": "no"}},
        ):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    RouteEvent.from_dict(invalid)

    def test_event_payload_digest_binds_the_typed_payload(self):
        event = RouteEvent.from_decision(
            DECISION,
            event_type="decision.selected",
            attempt=1,
            idempotency_key="route-001-selected-1",
            recorded_at=1_001,
        )
        invalid = event.to_dict()
        invalid["payload"]["decision"]["route_id"] = "route-other"
        with self.assertRaises(ValueError):
            RouteEvent.from_dict(invalid)

    def test_receipt_factory_rejects_invalid_terminal_combinations(self):
        with self.assertRaises(ValueError):
            RouteReceipt.from_decision(
                DECISION,
                status="succeeded",
                attempt=1,
                latency_ms=1,
                failure_class="backend_timeout",
                error_code="timeout",
                retryable=True,
                idempotency_key="route-001-succeeded-invalid",
                recorded_at=1_010,
            )
        with self.assertRaises(ValueError):
            RouteReceipt.from_decision(
                DECISION,
                status="failed",
                attempt=1,
                latency_ms=1,
                failure_class="backend_timeout",
                error_code="not-an-error-code",
                retryable=True,
                idempotency_key="route-001-failed-invalid",
                recorded_at=1_010,
            )

    def test_final_incomplete_jsonl_tail_is_ignored_and_repaired_on_next_append(self):
        self.ledger.append_decision(
            DECISION,
            attempt=1,
            idempotency_key="route-001-selected-1",
            recorded_at=1_001,
        )
        self.path.write_bytes(self.path.read_bytes() + b'{"schema_version":"northstar.route-event.v1"')
        self.assertEqual(len(self.ledger.read_history("run-route-001")), 1)
        started = self.ledger.append_receipt(self.started())
        self.assertEqual(started.sequence, 2)
        history = self.ledger.read_history("run-route-001")
        self.assertEqual(len(history), 2)
        self.assertTrue(self.path.read_bytes().endswith(b"\n"))


class RouteLedgerPersistenceTests(RouteLedgerTestCase):
    def test_decision_started_succeeded_persists_and_replays(self):
        decision_record = self.ledger.append_decision(
            DECISION,
            attempt=1,
            idempotency_key="route-001-selected-1",
            recorded_at=1_001,
        )
        self.assertEqual(decision_record.sequence, 1)
        started = self.ledger.append_receipt(self.started())
        succeeded = self.ledger.append_receipt(self.succeeded())
        self.assertEqual((started.sequence, succeeded.sequence), (2, 3))
        history = self.ledger.read_history("run-route-001")
        self.assertEqual([event.event_type for event in history], [
            "decision.selected",
            "route.started",
            "route.succeeded",
        ])
        replay = self.ledger.replay("run-route-001")
        self.assertIsInstance(replay, RouteReplay)
        self.assertEqual(replay.status, "succeeded")
        self.assertEqual(replay.current_attempt, 1)
        self.assertEqual(replay.target_agent_id, "codex")
        self.assertEqual(replay.receipt_count, 2)
        self.assertEqual(replay.total_latency_ms, 54)
        self.assertEqual(replay.failure_counts, {})

    def test_failed_attempt_can_retry_with_higher_attempt_and_replay_observes_both(self):
        self.ledger.append_decision(
            DECISION,
            attempt=1,
            idempotency_key="route-001-selected-1",
            recorded_at=1_001,
        )
        self.ledger.append_receipt(self.started())
        self.ledger.append_receipt(self.failed())
        retry = RouteReceipt.from_decision(
            DECISION,
            status="started",
            attempt=2,
            latency_ms=10,
            failure_class=None,
            error_code=None,
            retryable=False,
            idempotency_key="route-001-started-2",
            recorded_at=1_020,
        )
        success = RouteReceipt.from_decision(
            DECISION,
            status="succeeded",
            attempt=2,
            latency_ms=20,
            failure_class=None,
            error_code=None,
            retryable=False,
            idempotency_key="route-001-succeeded-2",
            recorded_at=1_030,
        )
        self.ledger.append_receipt(retry)
        self.ledger.append_receipt(success)
        replay = self.ledger.replay("run-route-001")
        self.assertEqual(replay.status, "succeeded")
        self.assertEqual(replay.current_attempt, 2)
        self.assertEqual(replay.failure_counts, {"backend_timeout": 1})
        self.assertEqual(replay.retry_count, 1)
        self.assertEqual(replay.receipt_count, 4)

    def test_same_event_replay_is_idempotent_but_same_key_conflict_is_rejected(self):
        record = self.ledger.append_decision(
            DECISION,
            attempt=1,
            idempotency_key="route-001-selected-1",
            recorded_at=1_001,
        )
        self.assertEqual(
            self.ledger.append_decision(
                DECISION,
                attempt=1,
                idempotency_key="route-001-selected-1",
                recorded_at=1_001,
            ),
            record,
        )
        changed = RouteDecision.from_dict({**DECISION.to_dict(), "priority": 99})
        with self.assertRaises(ValueError):
            self.ledger.append_decision(
                changed,
                attempt=1,
                idempotency_key="route-001-selected-1",
                recorded_at=1_001,
            )
        self.ledger.append_receipt(self.started())
        self.assertEqual(self.ledger.append_receipt(self.started()), self.ledger.read_history("run-route-001")[1])
        with self.assertRaises(ValueError):
            self.ledger.append_receipt(
                RouteReceipt.from_decision(
                    DECISION,
                    status="started",
                    attempt=1,
                    latency_ms=999,
                    failure_class=None,
                    error_code=None,
                    retryable=False,
                    idempotency_key="route-001-started-1",
                    recorded_at=1_003,
                )
            )

    def test_rejects_sequence_gap_cross_run_cross_route_and_wrong_decision_digest(self):
        record = self.ledger.append_decision(
            DECISION,
            attempt=1,
            idempotency_key="route-001-selected-1",
            recorded_at=1_001,
        )
        invalid_receipt = self.started().to_dict()
        invalid_receipt["decision_digest"] = "sha256:" + "9" * 64
        with self.assertRaises(ValueError):
            self.ledger.append_receipt(RouteReceipt.from_dict(invalid_receipt))
        self.path.write_text(
            json.dumps({**self.ledger.read_history("run-route-001")[0].to_dict(), "sequence": 3}) + "\n",
            encoding="utf-8",
        )
        with self.assertRaises(ValueError):
            self.ledger.read_history("run-route-001")
        self.path.unlink()
        self.ledger.append_decision(
            DECISION,
            attempt=1,
            idempotency_key="route-001-selected-1",
            recorded_at=1_001,
        )
        other = RouteDecision.from_dict({**DECISION.to_dict(), "route_id": "route-002", "run_id": "run-route-002"})
        with self.assertRaises(ValueError):
            self.ledger.append_decision(
                other,
                attempt=1,
                idempotency_key="route-002-selected-1",
                recorded_at=1_002,
            )

    def test_terminal_route_rejects_old_attempt_duplicate_terminal_and_illegal_transition(self):
        self.ledger.append_decision(
            DECISION,
            attempt=1,
            idempotency_key="route-001-selected-1",
            recorded_at=1_001,
        )
        self.ledger.append_receipt(self.started())
        self.ledger.append_receipt(self.succeeded())
        for invalid in (
            self.started(attempt=1, key="route-001-started-again-1", recorded_at=1_011),
            self.succeeded(attempt=1, key="route-001-succeeded-again-1", recorded_at=1_012),
            self.failed(attempt=1, key="route-001-failed-after-success-1", recorded_at=1_013),
        ):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    self.ledger.append_receipt(invalid)

    def test_cancelled_route_is_terminal_and_replay_is_deterministic(self):
        self.ledger.append_decision(
            DECISION,
            attempt=1,
            idempotency_key="route-001-selected-1",
            recorded_at=1_001,
        )
        self.ledger.append_receipt(
            RouteReceipt.from_decision(
                DECISION,
                status="started",
                attempt=1,
                latency_ms=2,
                failure_class=None,
                error_code=None,
                retryable=False,
                idempotency_key="route-001-started-1",
                recorded_at=1_002,
            )
        )
        self.ledger.append_receipt(
            RouteReceipt.from_decision(
                DECISION,
                status="cancelled",
                attempt=1,
                latency_ms=3,
                failure_class="cancelled_by_parent",
                error_code="cancelled",
                retryable=False,
                idempotency_key="route-001-cancelled-1",
                recorded_at=1_003,
            )
        )
        first = self.ledger.replay("run-route-001")
        second = self.ledger.replay("run-route-001")
        self.assertEqual(first, second)
        self.assertEqual(first.status, "cancelled")
        with self.assertRaises(ValueError):
            self.ledger.append_receipt(self.started(attempt=2, key="route-001-started-2", recorded_at=1_004))

    def test_history_corruption_unknown_fields_and_sensitive_payload_fail_closed(self):
        self.path.write_text(
            json.dumps({"schema_version": "northstar.route-event.v1", "prompt": "secret"}) + "\n",
            encoding="utf-8",
        )
        with self.assertRaises(ValueError):
            self.ledger.read_history("run-route-001")
        self.path.unlink()
        self.ledger.append_decision(
            DECISION,
            attempt=1,
            idempotency_key="route-001-selected-1",
            recorded_at=1_001,
        )
        self.path.write_text(
            self.path.read_text(encoding="utf-8").rstrip("\n")
            + "\n"
            + json.dumps({"schema_version": "northstar.route-event.v1", "raw_error": "secret"})
            + "\n",
            encoding="utf-8",
        )
        with self.assertRaises(ValueError):
            self.ledger.replay("run-route-001")
    def test_event_type_and_payload_receipt_status_must_agree(self):
        self.ledger.append_decision(
            DECISION,
            attempt=1,
            idempotency_key="route-001-selected-1",
            recorded_at=1_001,
        )
        self.ledger.append_receipt(self.started())
        event = self.ledger.read_history("run-route-001")[1].to_dict()
        event["event_type"] = "route.succeeded"
        self.path.write_text(
            self.path.read_text(encoding="utf-8").splitlines()[0]
            + "\n"
            + json.dumps(event)
            + "\n",
            encoding="utf-8",
        )
        with self.assertRaises(ValueError):
            self.ledger.replay("run-route-001")

    def test_append_honors_external_flock_before_mutating_history(self):
        import fcntl
        import subprocess
        import time

        self.ledger.append_decision(
            DECISION,
            attempt=1,
            idempotency_key="route-001-selected-1",
            recorded_at=1_001,
        )
        receipt = self.started().to_dict()
        payload_path = Path(self.tempdir.name) / "receipt.json"
        payload_path.write_text(json.dumps(receipt), encoding="utf-8")
        started_path = Path(self.tempdir.name) / "child-started"
        result_path = Path(self.tempdir.name) / "child-result"
        script = Path(self.tempdir.name) / "flock-child.py"
        script.write_text(
            "import json, sys\n"
            "from pathlib import Path\n"
            "Path(sys.argv[4]).write_text('started')\n"
            "sys.path.insert(0, sys.argv[3])\n"
            "from route_ledger import RouteLedger, RouteReceipt\n"
            "ledger = RouteLedger(sys.argv[1])\n"
            "ledger.append_receipt(RouteReceipt.from_dict(json.loads(Path(sys.argv[2]).read_text())))\n"
            "Path(sys.argv[5]).write_text('finished')\n",
            encoding="utf-8",
        )
        lock_path = self.path.with_name(self.path.name + ".lock")
        child = None
        try:
            with lock_path.open("a+b") as lock:
                fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
                child = subprocess.Popen(
                    [
                        sys.executable,
                        str(script),
                        str(self.path),
                        str(payload_path),
                        str(COMPONENT_ROOT),
                        str(started_path),
                        str(result_path),
                    ],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True,
                )
                deadline = time.monotonic() + 10
                while not started_path.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue(started_path.exists())
                time.sleep(0.25)
                self.assertFalse(result_path.exists())
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
            # See the note on the sibling concurrency test: memory pressure
            # makes child startup slow here, not deadlocked.
            child.wait(timeout=120)
            self.assertEqual(child.returncode, 0)
        finally:
            if child is not None and child.poll() is None:
                child.kill()
                child.wait()
        self.assertEqual(len(self.ledger.read_history("run-route-001")), 2)

    def test_stale_lock_file_is_reusable_and_normalized(self):
        lock_path = self.path.with_name(self.path.name + ".lock")
        lock_path.write_text("stale owner metadata", encoding="utf-8")
        self.ledger.append_decision(
            DECISION,
            attempt=1,
            idempotency_key="route-001-selected-1",
            recorded_at=1_001,
        )
        self.assertEqual(len(self.ledger.read_history("run-route-001")), 1)
        self.assertEqual(
            stat.S_IMODE(lock_path.stat().st_mode),
            0o600,
        )
        self.ledger.append_receipt(self.started())
        self.assertEqual(len(self.ledger.read_history("run-route-001")), 2)

    def test_concurrent_same_idempotency_key_is_written_once(self):
        import subprocess

        result_dir = Path(self.tempdir.name) / "results"
        result_dir.mkdir(mode=0o700)
        self.ledger.append_decision(
            DECISION,
            attempt=1,
            idempotency_key="route-001-selected-1",
            recorded_at=1_001,
        )
        receipt = self.started().to_dict()
        payload_path = Path(self.tempdir.name) / "receipt.json"
        payload_path.write_text(json.dumps(receipt), encoding="utf-8")
        script = Path(self.tempdir.name) / "append-child.py"
        script.write_text(
            "import json, sys\n"
            "from pathlib import Path\n"
            "sys.path.insert(0, sys.argv[3])\n"
            "from route_ledger import RouteLedger, RouteReceipt\n"
            "ledger = RouteLedger(sys.argv[1])\n"
            "try:\n"
            "    ledger.append_receipt(RouteReceipt.from_dict(json.loads(Path(sys.argv[2]).read_text())))\n"
            "    result = 'ok'\n"
            "except Exception as error:\n"
            "    result = type(error).__name__\n"
            "Path(sys.argv[4]).write_text(result)\n",
            encoding="utf-8",
        )
        processes = []
        streams = []
        for index in range(4):
            result_path = result_dir / f"child-{index}"
            error_path = result_dir / f"child-{index}.err"
            error_stream = error_path.open("w")
            streams.append(error_stream)
            process = subprocess.Popen(
                [sys.executable, str(script), str(self.path), str(payload_path), str(COMPONENT_ROOT), str(result_path)],
                stdout=subprocess.DEVNULL,
                stderr=error_stream,
                start_new_session=True,
            )
            processes.append((process, result_path, error_path))
        try:
            for process, result_path, error_path in processes:
                process.wait(timeout=120)
                self.assertEqual(process.returncode, 0, error_path.read_text())
                self.assertTrue(result_path.exists())
            results = [result_path.read_text() for _process, result_path, _error_path in processes]
            self.assertEqual(sum(result == "ok" for result in results), 4)
        finally:
            for process, _result_path, _error_path in processes:
                if process.poll() is None:
                    process.kill()
                    process.wait()
            for stream in streams:
                stream.close()
        self.assertEqual(len(self.ledger.read_history("run-route-001")), 2)


if __name__ == "__main__":
    unittest.main()
