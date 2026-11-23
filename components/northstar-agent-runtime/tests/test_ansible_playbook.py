"""Tests for the ansible_playbook module (unittest house style)."""

import unittest

from ansible_playbook import (
    ALWAYS_CHANGED_MODULES,
    IDEMPOTENT_MODULES,
    SCHEMA,
    VERSION,
    AnsiblePlaybook,
    CheckReport,
    DuplicatePlayError,
    PlayDefinition,
    PlayValidationError,
    RunReport,
    TaskFailedError,
    TaskSpec,
    UnknownPlayError,
    ansible_playbook_audit_event,
    main,
)


def _tasks():
    return (
        TaskSpec(name="write-conf", module="copy",
                 args=(("dest", "/etc/app.conf"),), notify=("restart",)),
        TaskSpec(name="ensure-svc", module="service",
                 args=(("name", "app"),)),
        TaskSpec(name="ping", module="command", args=(("cmd", "uptime"),)),
    )


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(VERSION, "ansible-playbook.v1")

    def test_schema_pin(self):
        self.assertEqual(SCHEMA, "northstar.ansible-playbook.v1")

    def test_module_categories(self):
        self.assertIn("copy", IDEMPOTENT_MODULES)
        self.assertIn("command", ALWAYS_CHANGED_MODULES)


class TestDefine(unittest.TestCase):
    def test_define_happy_path(self):
        pb = AnsiblePlaybook()
        play = pb.define("deploy", _tasks(), ["web1"], seq=1)
        self.assertIsInstance(play, PlayDefinition)
        self.assertEqual(play.play_id, "deploy")
        self.assertTrue(play.digest.startswith("sha256:"))

    def test_define_digest_deterministic(self):
        pb1, pb2 = AnsiblePlaybook(), AnsiblePlaybook()
        self.assertEqual(
            pb1.define("p", _tasks(), ["h"], seq=1).digest,
            pb2.define("p", _tasks(), ["h"], seq=1).digest,
        )

    def test_define_duplicate(self):
        pb = AnsiblePlaybook()
        pb.define("p", _tasks(), ["h"], seq=1)
        with self.assertRaises(DuplicatePlayError):
            pb.define("p", _tasks(), ["h"], seq=2)

    def test_define_empty_tasks(self):
        pb = AnsiblePlaybook()
        with self.assertRaises(PlayValidationError):
            pb.define("p", [], ["h"], seq=1)

    def test_define_empty_hosts(self):
        pb = AnsiblePlaybook()
        with self.assertRaises(PlayValidationError):
            pb.define("p", _tasks(), [], seq=1)

    def test_define_duplicate_task_names(self):
        pb = AnsiblePlaybook()
        dup = _tasks() + (TaskSpec(name="ping", module="shell",
                                   args=(("cmd", "x"),)),)
        with self.assertRaises(PlayValidationError):
            pb.define("p", dup, ["h"], seq=1)

    def test_define_duplicate_hosts(self):
        pb = AnsiblePlaybook()
        with self.assertRaises(PlayValidationError):
            pb.define("p", _tasks(), ["h", "h"], seq=1)

    def test_define_bad_seq(self):
        pb = AnsiblePlaybook()
        with self.assertRaises(PlayValidationError):
            pb.define("p", _tasks(), ["h"], seq=-1)
        with self.assertRaises(PlayValidationError):
            pb.define("p", _tasks(), ["h"], seq=True)

    def test_define_seq_must_increase(self):
        pb = AnsiblePlaybook()
        pb.define("p", _tasks(), ["h"], seq=5)
        with self.assertRaises(PlayValidationError):
            pb.define("q", _tasks(), ["h"], seq=5)

    def test_get_unknown(self):
        pb = AnsiblePlaybook()
        with self.assertRaises(UnknownPlayError):
            pb.get("nope")

    def test_views(self):
        pb = AnsiblePlaybook()
        pb.define("p", _tasks(), ["h1", "h2"], seq=1)
        self.assertEqual(pb.hosts("p"), ("h1", "h2"))
        self.assertEqual(len(pb.tasks("p")), 3)


class TestTaskSpec(unittest.TestCase):
    def test_task_pin_deterministic(self):
        t1 = TaskSpec(name="a", module="copy", args=(("dest", "/x"),))
        t2 = TaskSpec(name="b", module="copy", args=(("dest", "/x"),))
        self.assertEqual(t1.pin(), t2.pin())
        self.assertTrue(t1.pin().startswith("sha256:"))

    def test_task_validation(self):
        with self.assertRaises(PlayValidationError):
            TaskSpec(name="", module="copy")
        with self.assertRaises(PlayValidationError):
            TaskSpec(name="a", module="")
        with self.assertRaises(PlayValidationError):
            TaskSpec(name="a", module="copy",
                     args=(("k", float("nan")),))
        with self.assertRaises(PlayValidationError):
            TaskSpec(name="a", module="copy",
                     args=(("k", 1e60),))
        with self.assertRaises(PlayValidationError):
            TaskSpec(name="a", module="copy", notify="restart")
        with self.assertRaises(PlayValidationError):
            TaskSpec(name="a", module="copy", simulate_fail="yes")
        with self.assertRaises(PlayValidationError):
            TaskSpec(name="a", module="copy",
                     args=(("k", 1), ("k", 2)))

    def test_task_as_dict(self):
        t = TaskSpec(name="a", module="copy", args=(("dest", "/x"),))
        d = t.as_dict()
        self.assertEqual(d["name"], "a")
        self.assertIn("pin", d)


class TestCheck(unittest.TestCase):
    def test_check_reports_all_changes(self):
        pb = AnsiblePlaybook()
        pb.define("p", _tasks(), ["h1", "h2"], seq=1)
        report = pb.check("p", seq=2)
        self.assertIsInstance(report, CheckReport)
        self.assertEqual(report.would_change_count, 6)
        self.assertTrue(report.digest.startswith("sha256:"))

    def test_check_does_not_converge(self):
        pb = AnsiblePlaybook()
        pb.define("p", _tasks(), ["h"], seq=1)
        pb.check("p", seq=2)
        self.assertFalse(pb.is_converged("p", "h", "write-conf"))

    def test_check_notify_only_on_change(self):
        pb = AnsiblePlaybook()
        pb.define("p", _tasks(), ["h"], seq=1)
        pb.run("p", seq=2)  # converge idempotent tasks
        report = pb.check("p", seq=3)
        first = report.results[0]
        self.assertEqual(first.task_name, "write-conf")
        self.assertFalse(first.would_change)
        self.assertEqual(first.handlers_notified, ())

    def test_check_unknown_play(self):
        pb = AnsiblePlaybook()
        with self.assertRaises(UnknownPlayError):
            pb.check("nope", seq=1)


class TestRun(unittest.TestCase):
    def test_run_first_changes_all(self):
        pb = AnsiblePlaybook()
        pb.define("p", _tasks(), ["h1", "h2"], seq=1)
        report = pb.run("p", seq=2)
        self.assertIsInstance(report, RunReport)
        self.assertEqual(report.total_changed, 6)
        self.assertEqual(report.total_failed, 0)

    def test_run_idempotent_second(self):
        pb = AnsiblePlaybook()
        pb.define("p", _tasks(), ["h"], seq=1)
        pb.run("p", seq=2)
        report = pb.run("p", seq=3)
        # only the command task changes
        self.assertEqual(report.total_changed, 1)
        host = report.host_results[0]
        self.assertFalse(host.task_results[0].changed)
        self.assertTrue(host.task_results[2].changed)

    def test_run_always_changed_module(self):
        pb = AnsiblePlaybook()
        tasks = (TaskSpec(name="s", module="shell", args=(("cmd", "x"),)),)
        pb.define("p", tasks, ["h"], seq=1)
        self.assertEqual(pb.run("p", seq=2).total_changed, 1)
        self.assertEqual(pb.run("p", seq=3).total_changed, 1)

    def test_run_failure_stops_host(self):
        pb = AnsiblePlaybook()
        tasks = (
            TaskSpec(name="ok", module="copy", args=(("dest", "/x"),)),
            TaskSpec(name="boom", module="command", args=(("cmd", "y"),),
                     simulate_fail=True),
            TaskSpec(name="after", module="copy", args=(("dest", "/z"),)),
        )
        pb.define("p", tasks, ["h1", "h2"], seq=1)
        report = pb.run("p", seq=2)
        self.assertEqual(report.total_failed, 2)
        for host in report.host_results:
            self.assertTrue(host.failed)
            self.assertEqual(host.failed_task, "boom")
            self.assertEqual(len(host.task_results), 2)  # after not run

    def test_run_check_after_run(self):
        pb = AnsiblePlaybook()
        pb.define("p", _tasks(), ["h"], seq=1)
        pb.run("p", seq=2)
        report = pb.check("p", seq=3)
        # only the command task would change
        self.assertEqual(report.would_change_count, 1)

    def test_run_seq_must_increase(self):
        pb = AnsiblePlaybook()
        pb.define("p", _tasks(), ["h"], seq=1)
        pb.run("p", seq=2)
        with self.assertRaises(PlayValidationError):
            pb.run("p", seq=2)


class TestAudit(unittest.TestCase):
    def test_audit_shapes(self):
        for kind in ("defined", "checked", "ran", "rejected"):
            rec = ansible_playbook_audit_event(kind, seq=1, play_id="p")
            self.assertEqual(rec["format"], "audit.ndjson/1")
            self.assertEqual(rec["schema"], SCHEMA)
            self.assertEqual(rec["kind"], kind)
        with self.assertRaises(ValueError):
            ansible_playbook_audit_event("nope", seq=1)

    def test_audit_bad_seq(self):
        with self.assertRaises(PlayValidationError):
            ansible_playbook_audit_event("ran", seq=-1)


class TestStdlibAndMain(unittest.TestCase):
    def test_stdlib_only(self):
        import ast
        from pathlib import Path
        src = Path(__file__).resolve().parent.parent / "ansible_playbook.py"
        tree = ast.parse(src.read_text())
        allowed = {"__future__", "hashlib", "json", "math", "threading",
                   "dataclasses", "typing"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.assertIn(a.name.split(".")[0], allowed)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn(node.module.split(".")[0], allowed)

    def test_main(self):
        main()

    def test_frozen_records(self):
        pb = AnsiblePlaybook()
        pb.define("p", _tasks(), ["h"], seq=1)
        report = pb.run("p", seq=2)
        with self.assertRaises(Exception):
            report.total_changed = 0  # type: ignore


if __name__ == "__main__":
    unittest.main()
