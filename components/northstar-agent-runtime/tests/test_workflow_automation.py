"""Tests for workflow_automation: Zapier-shaped trigger-to-action bookkeeping."""

import ast
import os
import sys
import threading
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from workflow_automation import (
    ACTION_KINDS,
    FILTER_OPS,
    TRIGGER_SOURCES,
    WORKFLOW_AUTOMATION_VERSION,
    SCHEMA_PIN,
    ActionRecord,
    AutomationRecord,
    BadActionError,
    BadAutomationError,
    BadEventError,
    BadFilterError,
    BadIdError,
    BadMappingError,
    BadTriggerError,
    DuplicateActionError,
    DuplicateAutomationError,
    DuplicateTriggerError,
    FilterRecord,
    RunReport,
    SeqOrderError,
    TriggerRecord,
    UnknownActionError,
    UnknownAutomationError,
    UnknownTriggerError,
    WorkflowAutomation,
    WorkflowAutomationError,
    workflow_automation_audit_event,
)


def make_mgr(**kw):
    return WorkflowAutomation(seed=b"workflow-automation-test", **kw)


def make_zap(mgr):
    mgr.trigger("t1", "form_submitted", 1, ("name", "email", "age"))
    mgr.action(
        "a1",
        "send_email",
        2,
        params=(("subject", "hi"),),
        mappings=(("to", "trigger.email"),),
    )
    mgr.action(
        "a2",
        "create_row",
        3,
        mappings=(("name", "trigger.name"),),
    )
    mgr.define_automation("z1", "t1", ("a1", "a2"), 4)
    return mgr


class TestPins(unittest.TestCase):
    def test_version_pins(self):
        self.assertEqual(WORKFLOW_AUTOMATION_VERSION, "workflow-automation.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.workflow-automation.v1")

    def test_vocabularies_pinned(self):
        self.assertIn("webhook", TRIGGER_SOURCES)
        self.assertIn("send_email", ACTION_KINDS)
        self.assertIn("eq", FILTER_OPS)
        self.assertGreaterEqual(len(TRIGGER_SOURCES), 8)
        self.assertGreaterEqual(len(ACTION_KINDS), 8)

    def test_stdlib_only(self):
        path = os.path.join(os.path.dirname(__file__), "..",
                            "workflow_automation.py")
        tree = ast.parse(open(path).read())
        allowed = {
            "hashlib", "secrets", "threading", "dataclasses", "typing",
            "__future__", "canonical_json", "json",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.assertIn(a.name.split(".")[0], allowed, a.name)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn((node.module or "").split(".")[0], allowed,
                              node.module)


class TestTrigger(unittest.TestCase):
    def test_trigger_roundtrip_and_verify(self):
        mgr = make_mgr()
        rec = mgr.trigger("t1", "webhook", 1, ("a", "b"))
        self.assertIsInstance(rec, TriggerRecord)
        self.assertTrue(rec.digest.startswith("sha256:"))
        self.assertTrue(rec.verify(mgr))
        self.assertEqual(mgr.get_trigger("t1"), rec)

    def test_trigger_duplicate_refused(self):
        mgr = make_mgr()
        mgr.trigger("t1", "webhook", 1)
        with self.assertRaises(DuplicateTriggerError):
            mgr.trigger("t1", "webhook", 2)

    def test_trigger_bad_source_refused(self):
        mgr = make_mgr()
        with self.assertRaises(BadTriggerError):
            mgr.trigger("t1", "carrier-pigeon", 1)

    def test_trigger_bad_id_refused(self):
        mgr = make_mgr()
        with self.assertRaises(BadIdError):
            mgr.trigger("", "webhook", 1)

    def test_trigger_duplicate_schema_field_refused(self):
        mgr = make_mgr()
        with self.assertRaises(BadTriggerError):
            mgr.trigger("t1", "webhook", 1, ("a", "a"))


class TestAction(unittest.TestCase):
    def test_action_roundtrip_and_verify(self):
        mgr = make_mgr()
        rec = mgr.action("a1", "notify", 1, params=(("msg", "hi"),),
                         mappings=(("who", "trigger.user"),))
        self.assertIsInstance(rec, ActionRecord)
        self.assertTrue(rec.verify(mgr))

    def test_action_duplicate_refused(self):
        mgr = make_mgr()
        mgr.action("a1", "notify", 1)
        with self.assertRaises(DuplicateActionError):
            mgr.action("a1", "notify", 2)

    def test_action_bad_kind_refused(self):
        mgr = make_mgr()
        with self.assertRaises(BadActionError):
            mgr.action("a1", "launch-missiles", 1)

    def test_action_bad_mapping_shape_refused(self):
        mgr = make_mgr()
        with self.assertRaises(BadMappingError):
            mgr.action("a1", "notify", 1, mappings=(("to", "nowhere.x"),))
        with self.assertRaises(BadMappingError):
            mgr.action("a1", "notify", 2, mappings=(("to", "action.x"),))

    def test_action_duplicate_mapping_target_refused(self):
        mgr = make_mgr()
        with self.assertRaises(BadMappingError):
            mgr.action("a1", "notify", 1,
                       mappings=(("to", "trigger.a"), ("to", "trigger.b")))


class TestAutomation(unittest.TestCase):
    def test_automation_roundtrip_and_verify(self):
        mgr = make_zap(make_mgr())
        rec = mgr.get_automation("z1")
        self.assertIsInstance(rec, AutomationRecord)
        self.assertEqual(rec.action_ids, ("a1", "a2"))
        self.assertTrue(rec.verify(mgr))

    def test_automation_unknown_trigger_refused(self):
        mgr = make_mgr()
        mgr.action("a1", "notify", 1)
        with self.assertRaises(UnknownTriggerError):
            mgr.define_automation("z1", "nope", ("a1",), 2)

    def test_automation_unknown_action_refused(self):
        mgr = make_mgr()
        mgr.trigger("t1", "webhook", 1)
        with self.assertRaises(UnknownActionError):
            mgr.define_automation("z1", "t1", ("nope",), 2)

    def test_automation_empty_action_list_refused(self):
        mgr = make_mgr()
        mgr.trigger("t1", "webhook", 1)
        with self.assertRaises(BadAutomationError):
            mgr.define_automation("z1", "t1", (), 2)


class TestFilter(unittest.TestCase):
    def test_filter_define_roundtrip(self):
        mgr = make_zap(make_mgr())
        rec = mgr.define_filter("z1", (("age", "gte", 18),), 5)
        self.assertIsInstance(rec, FilterRecord)
        self.assertTrue(rec.verify(mgr))

    def test_filter_bad_rule_refused(self):
        mgr = make_zap(make_mgr())
        with self.assertRaises(BadFilterError):
            mgr.define_filter("z1", (("age", "bogus-op", 1),), 5)
        with self.assertRaises(BadFilterError):
            mgr.define_filter("z1", (), 6)

    def test_filter_unknown_automation_refused(self):
        mgr = make_mgr()
        with self.assertRaises(UnknownAutomationError):
            mgr.define_filter("nope", (("a", "eq", 1),), 1)


class TestRun(unittest.TestCase):
    def test_run_happy_path(self):
        mgr = make_zap(make_mgr())
        rep = mgr.run("z1", {"name": "Ada", "email": "a@x.com", "age": 30}, 5)
        self.assertIsInstance(rep, RunReport)
        self.assertEqual(rep.status, "succeeded")
        self.assertTrue(rep.verify(mgr))
        self.assertEqual([r.action_id for r in rep.action_results],
                         ["a1", "a2"])
        self.assertTrue(all(r.ok for r in rep.action_results))

    def test_run_missing_field_refused(self):
        mgr = make_zap(make_mgr())
        with self.assertRaises(BadEventError):
            mgr.run("z1", {"name": "Ada", "email": "a@x.com"}, 5)

    def test_run_extra_field_refused(self):
        mgr = make_zap(make_mgr())
        with self.assertRaises(BadEventError):
            mgr.run("z1", {"name": "A", "email": "a@x.com", "age": 1,
                           "hack": True}, 5)

    def test_run_filtered_out_is_data(self):
        mgr = make_zap(make_mgr())
        mgr.define_filter("z1", (("age", "gte", 18),), 5)
        rep = mgr.run("z1", {"name": "Kid", "email": "k@x.com", "age": 5}, 6)
        self.assertEqual(rep.status, "filtered-out")
        self.assertEqual(rep.action_results, ())
        self.assertTrue(rep.verify(mgr))

    def test_run_filter_match_executes(self):
        mgr = make_zap(make_mgr())
        mgr.define_filter("z1", (("age", "gte", 18), ("email", "contains", "@")), 5)
        rep = mgr.run("z1", {"name": "A", "email": "a@x.com", "age": 20}, 6)
        self.assertEqual(rep.status, "succeeded")

    def test_run_action_failure_stop(self):
        def boom(action, inputs, seq):
            raise RuntimeError("integration down")
        mgr = make_zap(make_mgr(executor=boom))
        rep = mgr.run("z1", {"name": "A", "email": "a@x.com", "age": 1}, 5)
        self.assertEqual(rep.status, "failed")
        self.assertEqual(rep.failed_action, "a1")
        self.assertEqual(rep.error_type, "RuntimeError")
        # Chain stopped: only a1 attempted.
        self.assertEqual(len(rep.action_results), 1)
        self.assertTrue(rep.verify(mgr))

    def test_run_action_failure_continue(self):
        def flaky(action, inputs, seq):
            if action.action_id == "a1":
                raise RuntimeError("flaky")
            return {"ok": True}
        mgr = make_zap(make_mgr())
        # Rebuild with continue policy: a1 recreated with run_on_error=continue
        mgr2 = make_mgr(executor=flaky)
        mgr2.trigger("t1", "form_submitted", 1, ("name", "email", "age"))
        mgr2.action("a1", "send_email", 2, mappings=(("to", "trigger.email"),),
                    run_on_error="continue")
        mgr2.action("a2", "create_row", 3,
                    mappings=(("name", "trigger.name"),))
        mgr2.define_automation("z1", "t1", ("a1", "a2"), 4)
        rep = mgr2.run("z1", {"name": "A", "email": "a@x.com", "age": 1}, 5)
        self.assertEqual(rep.status, "succeeded")
        self.assertEqual(len(rep.action_results), 2)
        self.assertFalse(rep.action_results[0].ok)
        self.assertTrue(rep.action_results[1].ok)
        self.assertTrue(rep.verify(mgr2))

    def test_run_unresolvable_mapping_fails(self):
        mgr = make_mgr()
        mgr.trigger("t1", "webhook", 1, ("a",))
        # action.<missing> is a valid shape but the action id never ran.
        mgr.action("a1", "notify", 2, mappings=(("v", "action.zzz.x"),))
        mgr.define_automation("z1", "t1", ("a1",), 3)
        rep = mgr.run("z1", {"a": 1}, 4)
        self.assertEqual(rep.status, "failed")
        self.assertEqual(rep.error_type, "UnresolvableMapping")

    def test_run_unknown_automation_refused(self):
        mgr = make_mgr()
        with self.assertRaises(UnknownAutomationError):
            mgr.run("nope", {}, 1)

    def test_run_prior_action_output_mapping(self):
        seen = {}
        def echo(action, inputs, seq):
            seen[action.action_id] = dict(inputs)
            return {"row_id": "row-7"}
        mgr = make_mgr(executor=echo)
        mgr.trigger("t1", "form_submitted", 1, ("name",))
        mgr.action("a1", "create_row", 2,
                   mappings=(("name", "trigger.name"),))
        mgr.action("a2", "notify", 3,
                   mappings=(("row", "action.a1.row_id"),))
        mgr.define_automation("z1", "t1", ("a1", "a2"), 4)
        rep = mgr.run("z1", {"name": "Bo"}, 5)
        self.assertEqual(rep.status, "succeeded")
        self.assertEqual(seen["a2"]["row"], "row-7")

    def test_run_determinism_across_instances(self):
        def zap(seed):
            mgr = WorkflowAutomation(seed=seed)
            make_zap(mgr)
            return mgr.run("z1", {"name": "A", "email": "a@x.com",
                                 "age": 9}, 5)
        r1, r2 = zap(b"same"), zap(b"same")
        self.assertEqual(r1.digest, r2.digest)
        r3 = zap(b"other")
        self.assertNotEqual(r1.digest, r3.digest)


class TestSeq(unittest.TestCase):
    def test_seq_rewind_refused(self):
        mgr = make_mgr()
        mgr.trigger("t1", "webhook", 1)
        with self.assertRaises(SeqOrderError):
            mgr.trigger("t2", "webhook", 1)

    def test_seq_bool_refused(self):
        mgr = make_mgr()
        with self.assertRaises(SeqOrderError):
            mgr.trigger("t1", "webhook", True)

    def test_failed_mutation_consumes_seq(self):
        mgr = make_mgr()
        mgr.trigger("t1", "webhook", 1)
        with self.assertRaises(DuplicateTriggerError):
            mgr.trigger("t1", "webhook", 2)
        # seq 2 is burned; next valid seq is 3.
        with self.assertRaises(SeqOrderError):
            mgr.trigger("t2", "webhook", 2)
        rec = mgr.trigger("t2", "webhook", 3)
        self.assertEqual(rec.seq, 3)


class TestAudit(unittest.TestCase):
    def test_audit_shapes(self):
        mgr = make_zap(make_mgr())
        rep = mgr.run("z1", {"name": "A", "email": "a@x.com", "age": 1}, 5)
        kinds = [e["event"] for e in mgr.audit_log()]
        self.assertEqual(kinds, [
            "trigger-defined", "action-defined", "action-defined",
            "automation-defined", "run-started",
            "action-executed", "action-executed", "run-completed",
        ])

    def test_audit_no_payload_values_leak(self):
        mgr = make_zap(make_mgr())
        mgr.run("z1", {"name": "Ada Lovelace", "email": "ada@secret.io",
                       "age": 36}, 5)
        blob = str(mgr.audit_log())
        self.assertNotIn("Ada Lovelace", blob)
        self.assertNotIn("ada@secret.io", blob)

    def test_audit_helper_and_bad_kind(self):
        ev = workflow_automation_audit_event(
            "trigger-defined", {"trigger_id": "t1"})
        self.assertEqual(ev["schema"], "audit.ndjson/1")
        self.assertEqual(ev["module"], WORKFLOW_AUTOMATION_VERSION)
        with self.assertRaises(WorkflowAutomationError):
            workflow_automation_audit_event("nope", {})

    def test_main_selfcheck(self):
        import workflow_automation
        workflow_automation.main()  # asserts internally


class TestConcurrency(unittest.TestCase):
    def test_thread_safe_defines(self):
        mgr = make_mgr()
        errs = []
        def worker(i):
            try:
                mgr.trigger(f"t{i}", "webhook", i + 1)
            except Exception as e:  # noqa: BLE001
                errs.append(e)
        threads = [threading.Thread(target=worker, args=(i,))
                for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertFalse(errs, errs)
        self.assertEqual(len(mgr.trigger_ids()), 8)


if __name__ == "__main__":
    unittest.main()
