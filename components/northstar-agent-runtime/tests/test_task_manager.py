"""Tests for task_manager (GTD task bookkeeping)."""

import unittest

from task_manager import (
    TASK_MANAGER_VERSION,
    SCHEMA_PIN,
    AlreadyCompletedError,
    BadProjectError,
    BadTaskError,
    DuplicateProjectError,
    NotCompletedError,
    SeqOrderError,
    TaskError,
    TaskManager,
    UnknownProjectError,
    UnknownTaskError,
    task_manager_audit_event,
    main,
)


class TestVersionPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(TASK_MANAGER_VERSION, "task-manager.v1")

    def test_schema_pin(self):
        self.assertEqual(SCHEMA_PIN, "northstar.task-manager.v1")


class TestAdd(unittest.TestCase):
    def test_add_defaults(self):
        m = TaskManager()
        t = m.add("write report", 1)
        self.assertEqual(t.task_id, "task-1")
        self.assertEqual(t.title, "write report")
        self.assertEqual(t.state, "open")
        self.assertEqual(t.priority, 4)
        self.assertEqual(t.labels, ())
        self.assertIsNone(t.project_id)
        self.assertIsNone(t.due_seq)
        self.assertTrue(t.digest.startswith("sha256:"))

    def test_add_full(self):
        m = TaskManager()
        p = m.create_project("work", 1)
        t = m.add(
            "ship v2",
            2,
            description="cut release",
            project_id=p.project_id,
            labels=("@desk", "@deep"),
            priority=1,
            due_seq=500,
        )
        self.assertEqual(t.project_id, p.project_id)
        self.assertEqual(t.labels, ("@deep", "@desk"))
        self.assertEqual(t.priority, 1)
        self.assertEqual(t.due_seq, 500)

    def test_add_bad_title(self):
        m = TaskManager()
        with self.assertRaises(BadTaskError):
            m.add("", 1)
        with self.assertRaises(BadTaskError):
            m.add("   ", 1)

    def test_add_bad_priority(self):
        m = TaskManager()
        with self.assertRaises(BadTaskError):
            m.add("x", 1, priority=0)
        with self.assertRaises(BadTaskError):
            m.add("x", 1, priority=5)
        with self.assertRaises(BadTaskError):
            m.add("x", 1, priority=True)

    def test_add_unknown_project(self):
        m = TaskManager()
        with self.assertRaises(UnknownProjectError):
            m.add("x", 1, project_id="proj-99")

    def test_seq_monotonic(self):
        m = TaskManager()
        m.add("a", 5)
        with self.assertRaises(SeqOrderError):
            m.add("b", 5)
        with self.assertRaises(SeqOrderError):
            m.add("b", 3)


class TestLifecycle(unittest.TestCase):
    def test_complete_and_reopen(self):
        m = TaskManager()
        t = m.add("call mom", 1)
        done = m.complete(t.task_id, 2)
        self.assertEqual(done.task_id, t.task_id)
        self.assertEqual(m.task(t.task_id).state, "completed")
        back = m.reopen(t.task_id, 3)
        self.assertEqual(back.state, "open")

    def test_double_complete_refused(self):
        m = TaskManager()
        t = m.add("x", 1)
        m.complete(t.task_id, 2)
        with self.assertRaises(AlreadyCompletedError):
            m.complete(t.task_id, 3)

    def test_reopen_open_refused(self):
        m = TaskManager()
        t = m.add("x", 1)
        with self.assertRaises(NotCompletedError):
            m.reopen(t.task_id, 2)

    def test_unknown_task(self):
        m = TaskManager()
        with self.assertRaises(UnknownTaskError):
            m.complete("task-99", 1)
        with self.assertRaises(UnknownTaskError):
            m.task("task-99")


class TestOrganize(unittest.TestCase):
    def test_prioritize(self):
        m = TaskManager()
        t = m.add("x", 1)
        updated = m.prioritize(t.task_id, 1, 2)
        self.assertEqual(updated.priority, 1)
        with self.assertRaises(BadTaskError):
            m.prioritize(t.task_id, 9, 3)

    def test_due_and_clear(self):
        m = TaskManager()
        t = m.add("x", 1)
        updated = m.set_due(t.task_id, 42, 2)
        self.assertEqual(updated.due_seq, 42)
        cleared = m.set_due(t.task_id, None, 3)
        self.assertIsNone(cleared.due_seq)
        with self.assertRaises(BadTaskError):
            m.set_due(t.task_id, -1, 4)

    def test_label_unlabel(self):
        m = TaskManager()
        t = m.add("x", 1)
        labeled = m.label(t.task_id, 2, "@home", "@calls")
        self.assertEqual(labeled.labels, ("@calls", "@home"))
        unlabeled = m.unlabel(t.task_id, 3, "@calls")
        self.assertEqual(unlabeled.labels, ("@home",))


class TestViews(unittest.TestCase):
    def test_next_actions_order(self):
        m = TaskManager()
        m.add("low", 1, priority=3)
        m.add("urgent", 2, priority=1)
        m.add("due-soon", 3, priority=2, due_seq=10)
        m.add("no-due", 4, priority=2)
        nxt = m.next_actions()
        self.assertEqual(
            [t.task_id for t in nxt.tasks], ["task-2", "task-3", "task-4", "task-1"]
        )

    def test_next_actions_skips_completed(self):
        m = TaskManager()
        t = m.add("x", 1)
        m.complete(t.task_id, 2)
        self.assertEqual(m.next_actions().total, 0)

    def test_tasks_filters(self):
        m = TaskManager()
        p = m.create_project("errands", 1)
        m.add("a", 2, project_id=p.project_id, labels=("@out",))
        m.add("b", 3, labels=("@out",))
        self.assertEqual(m.tasks(project_id=p.project_id).total, 1)
        self.assertEqual(m.tasks(label="@out").total, 2)

    def test_move_to_project_counts(self):
        m = TaskManager()
        p = m.create_project("p", 1)
        t = m.add("x", 2)
        self.assertEqual(m.project(p.project_id).task_count, 0)
        m.move_to_project(t.task_id, p.project_id, 3)
        self.assertEqual(m.project(p.project_id).task_count, 1)
        self.assertEqual(m.counts()["open"], 1)

    def test_duplicate_project_refused(self):
        m = TaskManager()
        m.create_project("same", 1)
        with self.assertRaises(DuplicateProjectError):
            m.create_project("same", 2)


class TestAudit(unittest.TestCase):
    def test_audit_shape(self):
        evt = task_manager_audit_event("added", 1, detail="task-1")
        self.assertEqual(evt["schema"], SCHEMA_PIN)
        self.assertEqual(evt["module"], TASK_MANAGER_VERSION)
        self.assertEqual(evt["detail"], "task-1")

    def test_audit_bad_kind(self):
        with self.assertRaises(TaskError):
            task_manager_audit_event("bogus", 1)

    def test_main(self):
        main()


if __name__ == "__main__":
    unittest.main()
