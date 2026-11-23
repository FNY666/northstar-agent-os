"""Tests for graceful_shutdown: ordered cleanup on process termination."""

import signal
import sys
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from graceful_shutdown import (
    GRACEFUL_SHUTDOWN_SCHEMA,
    GRACEFUL_SHUTDOWN_VERSION,
    HookFailure,
    ShutdownError,
    ShutdownHook,
    ShutdownManager,
    ShutdownReport,
    shutdown_audit_event,
)


class TestVersionPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(GRACEFUL_SHUTDOWN_VERSION, "graceful-shutdown.v1")

    def test_schema_pin(self):
        self.assertEqual(GRACEFUL_SHUTDOWN_SCHEMA, "northstar.graceful-shutdown.v1")


class TestHookRecord(unittest.TestCase):
    def test_frozen(self):
        hook = ShutdownHook(name="a", registered_seq=0, func=lambda: None)
        with self.assertRaises(AttributeError):
            hook.name = "b"  # type: ignore[misc]

    def test_empty_name_rejected(self):
        with self.assertRaises(ValueError):
            ShutdownHook(name="", registered_seq=0, func=lambda: None)

    def test_non_callable_rejected(self):
        with self.assertRaises(TypeError):
            ShutdownHook(name="a", registered_seq=0, func="nope")  # type: ignore[arg-type]

    def test_bad_seq_rejected(self):
        with self.assertRaises(ValueError):
            ShutdownHook(name="a", registered_seq=-1, func=lambda: None)
        with self.assertRaises(ValueError):
            ShutdownHook(name="a", registered_seq=True, func=lambda: None)  # type: ignore[arg-type]


class TestRegistration(unittest.TestCase):
    def test_register_happy_path(self):
        manager = ShutdownManager()
        hook = manager.register_cleanup("flush", lambda: None, 0)
        self.assertEqual(hook.name, "flush")
        self.assertEqual(hook.registered_seq, 0)
        self.assertEqual(len(manager.hooks()), 1)

    def test_duplicate_name_rejected(self):
        manager = ShutdownManager()
        manager.register_cleanup("flush", lambda: None, 0)
        with self.assertRaises(ValueError):
            manager.register_cleanup("flush", lambda: None, 1)

    def test_register_non_callable_rejected(self):
        manager = ShutdownManager()
        with self.assertRaises(TypeError):
            manager.register_cleanup("x", 42, 0)  # type: ignore[arg-type]

    def test_unregister(self):
        manager = ShutdownManager()
        manager.register_cleanup("a", lambda: None, 0)
        hook = manager.unregister("a")
        self.assertEqual(hook.name, "a")
        self.assertEqual(manager.hooks(), ())

    def test_unregister_unknown_raises_keyerror(self):
        manager = ShutdownManager()
        with self.assertRaises(KeyError):
            manager.unregister("nope")

    def test_register_after_shutdown_rejected(self):
        manager = ShutdownManager()
        manager.shutdown(0)
        with self.assertRaises(ShutdownError):
            manager.register_cleanup("late", lambda: None, 1)


class TestShutdown(unittest.TestCase):
    def test_lifo_order(self):
        manager = ShutdownManager()
        order = []
        manager.register_cleanup("first", lambda: order.append("first"), 0)
        manager.register_cleanup("second", lambda: order.append("second"), 1)
        manager.register_cleanup("third", lambda: order.append("third"), 2)
        report = manager.shutdown(3)
        self.assertEqual(order, ["third", "second", "first"])
        self.assertEqual(report.completed, ("third", "second", "first"))
        self.assertEqual(report.failed, ())
        self.assertEqual(report.shutdown_seq, 3)

    def test_failure_recorded_and_continues(self):
        manager = ShutdownManager()
        order = []

        def boom():
            order.append("boom")
            raise RuntimeError("disk full")

        manager.register_cleanup("ok1", lambda: order.append("ok1"), 0)
        manager.register_cleanup("boom", boom, 1)
        manager.register_cleanup("ok2", lambda: order.append("ok2"), 2)
        report = manager.shutdown(3)
        # LIFO: ok2 runs, boom fails (recorded), ok1 still runs.
        self.assertEqual(order, ["ok2", "boom", "ok1"])
        self.assertEqual(report.completed, ("ok2", "ok1"))
        self.assertEqual(len(report.failed), 1)
        self.assertEqual(report.failed[0].name, "boom")
        self.assertIn("disk full", report.failed[0].error)

    def test_idempotent(self):
        manager = ShutdownManager()
        manager.register_cleanup("a", lambda: None, 0)
        first = manager.shutdown(1)
        self.assertFalse(first.already_shutdown)
        second = manager.shutdown(2)
        self.assertTrue(second.already_shutdown)
        self.assertEqual(second.completed, ())
        self.assertEqual(second.failed, ())

    def test_is_shut_down(self):
        manager = ShutdownManager()
        self.assertFalse(manager.is_shut_down())
        manager.shutdown(0)
        self.assertTrue(manager.is_shut_down())

    def test_report_frozen(self):
        manager = ShutdownManager()
        report = manager.shutdown(0)
        with self.assertRaises(AttributeError):
            report.completed = ()  # type: ignore[misc]


class TestSignalHandlers(unittest.TestCase):
    def test_install_on_worker_thread_rejected(self):
        manager = ShutdownManager()
        errors = []

        def try_install():
            try:
                manager.install_signal_handlers()
            except ValueError as exc:
                errors.append(exc)

        worker = threading.Thread(target=try_install)
        worker.start()
        worker.join()
        self.assertEqual(len(errors), 1)

    def test_install_and_uninstall_main_thread(self):
        manager = ShutdownManager()
        previous = manager.install_signal_handlers()
        self.assertIn(signal.SIGTERM, previous)
        self.assertIn(signal.SIGINT, previous)
        restored = manager.uninstall_signal_handlers()
        self.assertEqual(set(restored), set(previous))


class TestAuditEvent(unittest.TestCase):
    def test_audit_event_shape(self):
        manager = ShutdownManager()
        manager.register_cleanup("a", lambda: None, 0)
        report = manager.shutdown(1)
        event = shutdown_audit_event(report, 7)
        self.assertEqual(event["schema"], "audit.ndjson/1")
        self.assertEqual(event["module"], GRACEFUL_SHUTDOWN_VERSION)
        self.assertEqual(event["audit_seq"], 7)
        self.assertIn("completed", event["report"])

    def test_audit_event_bad_seq_rejected(self):
        manager = ShutdownManager()
        report = manager.shutdown(0)
        with self.assertRaises(ValueError):
            shutdown_audit_event(report, -1)

    def test_audit_event_wrong_type(self):
        with self.assertRaises(TypeError):
            shutdown_audit_event("nope", 0)  # type: ignore[arg-type]


class TestMain(unittest.TestCase):
    def test_main(self):
        from graceful_shutdown import main

        main()  # asserts internally


if __name__ == "__main__":
    unittest.main()
