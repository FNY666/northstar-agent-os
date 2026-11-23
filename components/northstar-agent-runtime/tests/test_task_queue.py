"""Targeted tests for task_queue."""

import ast
import threading
import unittest

from task_queue import (
    CLAIMED,
    CANCELLED,
    DEAD_LETTER,
    PENDING,
    SCHEMA_PIN,
    SUCCEEDED,
    TASK_QUEUE_VERSION,
    DequeuedTask,
    RetryDecision,
    TaskNotCompleteError,
    TaskOutcome,
    TaskPayloadError,
    TaskQueue,
    TaskQueueError,
    TaskRecord,
    TaskStateError,
    UnknownTaskError,
    ResultNotCanonicalError,
    task_queue_audit_event,
)


class TestPins(unittest.TestCase):
    def test_version_and_schema_pins(self):
        self.assertEqual(TASK_QUEUE_VERSION, "task-queue.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.task-queue.v1")


class TestEnqueue(unittest.TestCase):
    def test_enqueue_happy_path(self):
        q = TaskQueue()
        rec = q.enqueue("email.send", args=("a@b.c",), kwargs={"retry": True}, seq=0)
        self.assertIsInstance(rec, TaskRecord)
        self.assertEqual(rec.task_id, "task-1")
        self.assertEqual(rec.task_name, "email.send")
        self.assertEqual(rec.args, ("a@b.c",))
        self.assertEqual(rec.kwargs, (("retry", True),))
        self.assertEqual(rec.state, PENDING)
        self.assertEqual(rec.attempts, 0)
        self.assertTrue(rec.payload_digest.startswith("sha256:"))

    def test_task_ids_increment(self):
        q = TaskQueue()
        a = q.enqueue("t.a", seq=0)
        b = q.enqueue("t.b", seq=1)
        self.assertEqual(a.task_id, "task-1")
        self.assertEqual(b.task_id, "task-2")

    def test_digest_deterministic_and_distinct(self):
        q1 = TaskQueue()
        q2 = TaskQueue()
        r1 = q1.enqueue("t.x", args=(1,), seq=5)
        r2 = q2.enqueue("t.x", args=(1,), seq=5)
        self.assertEqual(r1.payload_digest, r2.payload_digest)
        r3 = q1.enqueue("t.x", args=(2,), seq=5)
        self.assertNotEqual(r1.payload_digest, r3.payload_digest)

    def test_empty_name_rejected(self):
        q = TaskQueue()
        with self.assertRaises(TaskPayloadError):
            q.enqueue("", seq=0)
        with self.assertRaises(TaskPayloadError):
            q.enqueue(None, seq=0)

    def test_bad_args_rejected(self):
        q = TaskQueue()
        with self.assertRaises(TaskPayloadError):
            q.enqueue("t", args="not-a-sequence", seq=0)
        with self.assertRaises(TaskPayloadError):
            q.enqueue("t", args=(object(),), seq=0)

    def test_bad_kwargs_rejected(self):
        q = TaskQueue()
        with self.assertRaises(TaskPayloadError):
            q.enqueue("t", kwargs={1: "x"}, seq=0)
        with self.assertRaises(TaskPayloadError):
            q.enqueue("t", kwargs="nope", seq=0)

    def test_bool_seq_rejected(self):
        q = TaskQueue()
        with self.assertRaises(TaskQueueError):
            q.enqueue("t", seq=True)

    def test_bool_priority_rejected(self):
        q = TaskQueue()
        with self.assertRaises(TaskPayloadError):
            q.enqueue("t", seq=0, priority=True)

    def test_negative_max_retries_rejected(self):
        q = TaskQueue()
        with self.assertRaises(TaskPayloadError):
            q.enqueue("t", seq=0, max_retries=-1)

    def test_kwargs_sorted(self):
        q = TaskQueue()
        rec = q.enqueue("t", kwargs={"z": 1, "a": 2}, seq=0)
        self.assertEqual(rec.kwargs, (("a", 2), ("z", 1)))


class TestDequeue(unittest.TestCase):
    def test_fifo_within_priority(self):
        q = TaskQueue()
        q.enqueue("a", seq=0)
        q.enqueue("b", seq=1)
        first = q.dequeue(seq=2)
        second = q.dequeue(seq=3)
        self.assertEqual(first.task_id, "task-1")
        self.assertEqual(second.task_id, "task-2")

    def test_priority_first(self):
        q = TaskQueue()
        q.enqueue("low", seq=0, priority=0)
        q.enqueue("high", seq=1, priority=10)
        got = q.dequeue(seq=2)
        self.assertEqual(got.task_id, "task-2")
        self.assertEqual(got.task_name, "high")

    def test_empty_queue_returns_none(self):
        q = TaskQueue()
        self.assertIsNone(q.dequeue(seq=0))

    def test_dequeue_claims_task(self):
        q = TaskQueue()
        q.enqueue("t", seq=0)
        got = q.dequeue(seq=1)
        self.assertIsInstance(got, DequeuedTask)
        self.assertEqual(got.attempt, 1)
        self.assertEqual(q.record("task-1").state, CLAIMED)
        self.assertEqual(q.pending_count(), 0)

    def test_dequeue_after_success_skips(self):
        q = TaskQueue()
        q.enqueue("a", seq=0)
        q.enqueue("b", seq=1)
        q.dequeue(seq=2)
        q.ack_success("task-1", "done", seq=3)
        got = q.dequeue(seq=4)
        self.assertEqual(got.task_id, "task-2")


class TestAckSuccess(unittest.TestCase):
    def test_ack_success_roundtrip(self):
        q = TaskQueue()
        q.enqueue("t", args=(1,), seq=0)
        q.dequeue(seq=1)
        outcome = q.ack_success("task-1", {"ok": True}, seq=2)
        self.assertIsInstance(outcome, TaskOutcome)
        self.assertTrue(outcome.succeeded)
        self.assertEqual(outcome.attempts, 1)
        self.assertIsNone(outcome.error_type)
        self.assertTrue(outcome.result_digest.startswith("sha256:"))
        self.assertEqual(q.record("task-1").state, SUCCEEDED)

    def test_result_returns_value(self):
        q = TaskQueue()
        q.enqueue("t", seq=0)
        q.dequeue(seq=1)
        q.ack_success("task-1", [1, 2, 3], seq=2)
        self.assertEqual(q.result("task-1"), [1, 2, 3])

    def test_result_before_success_raises(self):
        q = TaskQueue()
        q.enqueue("t", seq=0)
        q.dequeue(seq=1)
        with self.assertRaises(TaskNotCompleteError):
            q.result("task-1")

    def test_result_unknown_raises(self):
        q = TaskQueue()
        with self.assertRaises(UnknownTaskError):
            q.result("task-99")

    def test_non_canonical_result_refused(self):
        q = TaskQueue()
        q.enqueue("t", seq=0)
        q.dequeue(seq=1)
        with self.assertRaises(ResultNotCanonicalError):
            q.ack_success("task-1", object(), seq=2)
        # Task is still claimed; the ack can be retried.
        self.assertEqual(q.record("task-1").state, CLAIMED)

    def test_double_ack_raises(self):
        q = TaskQueue()
        q.enqueue("t", seq=0)
        q.dequeue(seq=1)
        q.ack_success("task-1", 1, seq=2)
        with self.assertRaises(TaskStateError):
            q.ack_success("task-1", 2, seq=3)

    def test_ack_unclaimed_raises(self):
        q = TaskQueue()
        q.enqueue("t", seq=0)
        with self.assertRaises(TaskStateError):
            q.ack_success("task-1", 1, seq=1)


class TestRetryAndDeadLetter(unittest.TestCase):
    def test_failure_requeues_with_retry_decision(self):
        q = TaskQueue(max_retries=2)
        q.enqueue("t", seq=0)
        q.dequeue(seq=1)
        retry = q.ack_failure("task-1", "ValueError", seq=2)
        self.assertIsInstance(retry, RetryDecision)
        self.assertTrue(retry.requeued)
        self.assertEqual(retry.attempt, 1)
        self.assertEqual(retry.retries_remaining, 2)
        self.assertEqual(q.record("task-1").state, PENDING)
        self.assertEqual(q.pending_count(), 1)

    def test_retry_attempt_increments(self):
        q = TaskQueue(max_retries=2)
        q.enqueue("t", seq=0)
        q.dequeue(seq=1)
        q.ack_failure("task-1", "ValueError", seq=2)
        got = q.dequeue(seq=3)
        self.assertEqual(got.attempt, 2)

    def test_exhaustion_dead_letters(self):
        q = TaskQueue(max_retries=1)
        q.enqueue("t", seq=0)
        q.dequeue(seq=1)
        q.ack_failure("task-1", "ValueError", seq=2)
        q.dequeue(seq=3)
        dead = q.ack_failure("task-1", "ValueError", seq=4)
        self.assertIsInstance(dead, TaskOutcome)
        self.assertFalse(dead.succeeded)
        self.assertEqual(dead.error_type, "ValueError")
        self.assertIsNone(dead.result_digest)
        self.assertEqual(q.record("task-1").state, DEAD_LETTER)
        self.assertEqual(q.pending_count(), 0)

    def test_zero_max_retries_dead_letters_immediately(self):
        q = TaskQueue(max_retries=0)
        q.enqueue("t", seq=0)
        q.dequeue(seq=1)
        dead = q.ack_failure("task-1", "Boom", seq=2)
        self.assertFalse(dead.succeeded)

    def test_empty_error_type_rejected(self):
        q = TaskQueue()
        q.enqueue("t", seq=0)
        q.dequeue(seq=1)
        with self.assertRaises(TaskQueueError):
            q.ack_failure("task-1", "", seq=2)

    def test_per_task_max_retries_override(self):
        q = TaskQueue(max_retries=5)
        q.enqueue("t", seq=0, max_retries=0)
        q.dequeue(seq=1)
        dead = q.ack_failure("task-1", "Boom", seq=2)
        self.assertFalse(dead.succeeded)


class TestCancel(unittest.TestCase):
    def test_cancel_pending(self):
        q = TaskQueue()
        rec = q.enqueue("t", seq=0)
        cancelled = q.cancel("task-1", seq=1)
        self.assertEqual(cancelled.state, CANCELLED)
        self.assertEqual(q.pending_count(), 0)

    def test_cancel_claimed_raises(self):
        q = TaskQueue()
        q.enqueue("t", seq=0)
        q.dequeue(seq=1)
        with self.assertRaises(TaskStateError):
            q.cancel("task-1", seq=2)

    def test_cancel_unknown_raises(self):
        q = TaskQueue()
        with self.assertRaises(UnknownTaskError):
            q.cancel("task-99", seq=0)


class TestViews(unittest.TestCase):
    def test_stats(self):
        q = TaskQueue(max_retries=0)
        q.enqueue("a", seq=0)
        q.enqueue("b", seq=1)
        q.dequeue(seq=2)
        q.ack_success("task-1", 1, seq=3)
        q.dequeue(seq=4)
        q.ack_failure("task-2", "E", seq=5)
        stats = q.stats()
        self.assertEqual(stats[SUCCEEDED], 1)
        self.assertEqual(stats[DEAD_LETTER], 1)
        self.assertEqual(stats[PENDING], 0)

    def test_record_frozen(self):
        q = TaskQueue()
        rec = q.enqueue("t", seq=0)
        with self.assertRaises(Exception):
            rec.state = "claimed"  # type: ignore[misc]


class TestAudit(unittest.TestCase):
    def test_all_kinds(self):
        for kind in ("task-enqueued", "task-dequeued", "task-succeeded",
                     "task-failed", "task-retried", "task-dead-lettered",
                     "task-cancelled", "rejected"):
            ev = task_queue_audit_event(kind, 7, task_id="task-1")
            self.assertEqual(ev["event"], kind)
            self.assertEqual(ev["audit_seq"], 7)
            self.assertEqual(ev["task_id"], "task-1")
            self.assertEqual(ev["module_version"], TASK_QUEUE_VERSION)

    def test_unknown_kind_rejected(self):
        with self.assertRaises(TaskQueueError):
            task_queue_audit_event("bogus", 0)

    def test_bad_seq_rejected(self):
        with self.assertRaises(TaskQueueError):
            task_queue_audit_event("task-enqueued", True)
        with self.assertRaises(TaskQueueError):
            task_queue_audit_event("task-enqueued", -1)


class TestAsDict(unittest.TestCase):
    def test_record_as_dict(self):
        q = TaskQueue()
        rec = q.enqueue("t", args=(1,), kwargs={"a": 2}, seq=3)
        d = rec.as_dict()
        self.assertEqual(d["schema"], SCHEMA_PIN)
        self.assertEqual(d["version"], TASK_QUEUE_VERSION)
        self.assertEqual(d["task_id"], "task-1")
        self.assertEqual(d["args"], [1])
        self.assertEqual(d["kwargs"], [["a", 2]])

    def test_dequeued_as_dict(self):
        q = TaskQueue()
        q.enqueue("t", seq=0)
        got = q.dequeue(seq=1)
        d = got.as_dict()
        self.assertEqual(d["attempt"], 1)
        self.assertEqual(d["dequeue_seq"], 1)


class TestConcurrency(unittest.TestCase):
    def test_concurrent_enqueue(self):
        q = TaskQueue()
        errors = []

        def worker(n):
            try:
                for i in range(10):
                    q.enqueue(f"t.{n}.{i}", seq=i)
            except Exception as exc:  # pragma: no cover
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(n,)) for n in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        self.assertEqual(q.pending_count(), 50)
        stats = q.stats()
        self.assertEqual(stats[PENDING], 50)


class TestStdlibOnly(unittest.TestCase):
    def test_stdlib_imports_only(self):
        import pathlib
        src = pathlib.Path(__file__).with_name("..").joinpath("task_queue.py").resolve()
        # tests run from the component dir; module sits next to the tests dir
        if not src.exists():
            src = pathlib.Path(__file__).parent.parent / "task_queue.py"
        tree = ast.parse(src.read_text())
        allowed = {
            "__future__", "hashlib", "math", "threading", "dataclasses",
            "typing", "json", "canonical_json",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertIn(alias.name.split(".")[0], allowed, alias.name)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn((node.module or "").split(".")[0], allowed, node.module)


class TestMain(unittest.TestCase):
    def test_main_self_check(self):
        import io
        from contextlib import redirect_stdout
        import task_queue

        buf = io.StringIO()
        with redirect_stdout(buf):
            task_queue.main()
        self.assertIn("task-queue OK", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
