"""Targeted tests for the resource tagging interface."""

import ast
import subprocess
import sys
import unittest
from pathlib import Path

from resource_tagging import (
    AUDIT_SCHEMA,
    KIND_POLICY_DEFINED,
    KIND_POLICY_EVALUATED,
    KIND_REJECTED,
    KIND_RESOURCE_REGISTERED,
    KIND_TAGS_APPLIED,
    KIND_TAGS_REMOVED,
    RESOURCE_TAGGING_SCHEMA,
    RESOURCE_TAGGING_VERSION,
    BadPolicyError,
    BadResourceError,
    BadTagError,
    DuplicatePolicyError,
    DuplicateResourceError,
    PolicyEvaluation,
    PolicyRecord,
    ResourceRecord,
    ResourceTagging,
    ResourceTaggingError,
    SeqOrderError,
    TagApplication,
    UntagRecord,
    UnknownPolicyError,
    UnknownResourceError,
    main,
    resource_tagging_audit_event,
)

MODULE_PATH = Path(__file__).resolve().parent.parent / "resource_tagging.py"


class TestPins(unittest.TestCase):
    def test_version_and_schema_pins(self):
        self.assertEqual(RESOURCE_TAGGING_VERSION, "resource-tagging.v1")
        self.assertEqual(
            RESOURCE_TAGGING_SCHEMA, "northstar.resource-tagging.v1"
        )
        self.assertEqual(AUDIT_SCHEMA, "audit.ndjson/1")

    def test_stdlib_only(self):
        tree = ast.parse(MODULE_PATH.read_text())
        allowed = {
            "hashlib",
            "json",
            "re",
            "threading",
            "dataclasses",
            "typing",
            "__future__",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertIn(
                        alias.name.split(".")[0],
                        allowed,
                        f"non-stdlib import: {alias.name}",
                    )
            elif isinstance(node, ast.ImportFrom):
                self.assertIn(
                    (node.module or "").split(".")[0],
                    allowed,
                    f"non-stdlib import: {node.module}",
                )

    def test_main_self_check(self):
        proc = subprocess.run(
            [sys.executable, str(MODULE_PATH)],
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("resource-tagging OK", proc.stdout)


class TestRegister(unittest.TestCase):
    def test_register_roundtrip(self):
        mgr = ResourceTagging()
        rec = mgr.register("i-123", "ec2:instance", seq=1)
        self.assertIsInstance(rec, ResourceRecord)
        self.assertTrue(rec.verify())
        self.assertEqual(mgr.resource("i-123"), rec)
        self.assertEqual(mgr.resource_ids(), ("i-123",))
        self.assertEqual(mgr.tags("i-123"), {})

    def test_register_duplicate_and_bad_inputs(self):
        mgr = ResourceTagging()
        mgr.register("i-123", "ec2:instance", seq=1)
        with self.assertRaises(DuplicateResourceError):
            mgr.register("i-123", "ec2:instance", seq=2)
        for i, bad_id in enumerate(("", "   ", "a b", "x" * 513), start=3):
            with self.assertRaises(BadResourceError, msg=bad_id):
                mgr.register(bad_id, "ec2:instance", seq=i)
        for j, bad_type in enumerate(
            ("", "instance", "EC2:instance", "ec2 instance"), start=10
        ):
            with self.assertRaises(BadResourceError, msg=bad_type):
                mgr.register("i-124", bad_type, seq=j)


class TestTagUntag(unittest.TestCase):
    def test_tag_upsert_and_untag(self):
        mgr = ResourceTagging()
        mgr.register("i-123", "ec2:instance", seq=1)
        app = mgr.tag("i-123", {"env": "prod", "owner": "ops"}, seq=2)
        self.assertIsInstance(app, TagApplication)
        self.assertTrue(app.verify())
        self.assertEqual(app.tags, (("env", "prod"), ("owner", "ops")))
        # Upsert merges: latest wins, untouched keys survive.
        mgr.tag("i-123", {"env": "staging"}, seq=3)
        self.assertEqual(
            mgr.tags("i-123"), {"env": "staging", "owner": "ops"}
        )
        rec = mgr.untag("i-123", ("owner",), seq=4)
        self.assertIsInstance(rec, UntagRecord)
        self.assertTrue(rec.verify())
        self.assertEqual(mgr.tags("i-123"), {"env": "staging"})

    def test_tag_bad_inputs_and_unknown_resource(self):
        mgr = ResourceTagging()
        with self.assertRaises(UnknownResourceError):
            mgr.tag("ghost", {"env": "prod"}, seq=1)
        mgr.register("i-123", "ec2:instance", seq=2)
        with self.assertRaises(BadTagError):
            mgr.tag("i-123", {}, seq=3)
        with self.assertRaises(BadTagError):
            mgr.tag("i-123", "env=prod", seq=4)
        seq = 5
        for bad_key in ("", "aws:owner", "AWS:env", "k" * 129, "key!"):
            with self.assertRaises(BadTagError, msg=bad_key):
                mgr.tag("i-123", {bad_key: "v"}, seq=seq)
            seq += 1
        for bad_value in (123, "v" * 257, "va\x7flue"):
            with self.assertRaises(BadTagError, msg=str(bad_value)):
                mgr.tag("i-123", {"env": bad_value}, seq=seq)
            seq += 1

    def test_untag_refuses_unset_keys(self):
        mgr = ResourceTagging()
        mgr.register("i-123", "ec2:instance", seq=1)
        mgr.tag("i-123", {"env": "prod"}, seq=2)
        with self.assertRaises(BadTagError):
            mgr.untag("i-123", ("owner",), seq=3)
        # Failed mutation consumed its seq: next must be > 3.
        with self.assertRaises(SeqOrderError):
            mgr.untag("i-123", ("env",), seq=3)
        mgr.untag("i-123", ("env",), seq=4)
        self.assertEqual(mgr.tags("i-123"), {})


class TestSeqDiscipline(unittest.TestCase):
    def test_seq_rewind_and_bool_refused(self):
        mgr = ResourceTagging()
        mgr.register("i-123", "ec2:instance", seq=1)
        with self.assertRaises(SeqOrderError):
            mgr.register("i-124", "ec2:instance", seq=1)
        with self.assertRaises(ResourceTaggingError):
            mgr.register("i-124", "ec2:instance", seq=True)
        with self.assertRaises(ResourceTaggingError):
            mgr.tag("i-123", {"env": "prod"}, seq=-2)


class TestPolicy(unittest.TestCase):
    def test_policy_roundtrip_evaluate_compliant(self):
        mgr = ResourceTagging()
        mgr.register("i-123", "ec2:instance", seq=1)
        mgr.tag("i-123", {"env": "prod", "owner": "ops"}, seq=2)
        pol = mgr.policy(
            "baseline",
            ("env", "owner"),
            seq=3,
            allowed_values={"env": ("prod", "staging")},
        )
        self.assertIsInstance(pol, PolicyRecord)
        self.assertTrue(pol.verify())
        ev = mgr.evaluate("baseline", "i-123", seq=4)
        self.assertIsInstance(ev, PolicyEvaluation)
        self.assertTrue(ev.verify())
        self.assertTrue(ev.compliant)
        self.assertEqual(ev.violations, ())

    def test_evaluate_violations_are_data(self):
        mgr = ResourceTagging()
        mgr.register("i-123", "ec2:instance", seq=1)
        mgr.tag("i-123", {"env": "dev"}, seq=2)
        mgr.policy(
            "baseline",
            ("env", "owner"),
            seq=3,
            allowed_values={"env": ("prod", "staging")},
        )
        ev = mgr.evaluate("baseline", "i-123", seq=4)
        self.assertFalse(ev.compliant)
        self.assertEqual(
            ev.violations, (("env", "disallowed-value"), ("owner", "missing"))
        )
        # Evaluate is an audited read: seq not consumed.
        ev2 = mgr.evaluate("baseline", "i-123", seq=4)
        self.assertTrue(ev2.verify())

    def test_policy_bad_inputs_and_unknown(self):
        mgr = ResourceTagging()
        mgr.register("i-123", "ec2:instance", seq=1)
        seq = 2
        with self.assertRaises(BadPolicyError):
            mgr.policy("p", (), seq=seq)
        seq += 1
        with self.assertRaises(BadPolicyError):
            mgr.policy("p", ("env", "env"), seq=seq)
        seq += 1
        with self.assertRaises(BadTagError):
            mgr.policy("p", ("aws:env",), seq=seq)
        seq += 1
        with self.assertRaises(BadPolicyError):
            mgr.policy("p", ("env",), seq=seq, allowed_values={"env": []})
        seq += 1
        mgr.policy("p", ("env",), seq=seq)
        seq += 1
        with self.assertRaises(DuplicatePolicyError):
            mgr.policy("p", ("env",), seq=seq)
        seq += 1
        with self.assertRaises(UnknownPolicyError):
            mgr.evaluate("ghost", "i-123", seq=seq)
        seq += 1
        with self.assertRaises(UnknownResourceError):
            mgr.evaluate("p", "ghost", seq=seq)


class TestAudit(unittest.TestCase):
    def test_audit_shapes_and_value_leak_ban(self):
        mgr = ResourceTagging()
        mgr.register("i-123", "ec2:instance", seq=1)
        mgr.tag("i-123", {"env": "prod", "owner": "ops"}, seq=2)
        mgr.untag("i-123", ("owner",), seq=3)
        mgr.policy("baseline", ("env",), seq=4)
        mgr.evaluate("baseline", "i-123", seq=5)
        kinds = [e["kind"] for e in mgr.audit_log()]
        self.assertEqual(
            kinds,
            [
                KIND_RESOURCE_REGISTERED,
                KIND_TAGS_APPLIED,
                KIND_TAGS_REMOVED,
                KIND_POLICY_DEFINED,
                KIND_POLICY_EVALUATED,
            ],
        )
        for event in mgr.audit_log():
            self.assertEqual(event["schema"], AUDIT_SCHEMA)
            detail = event["detail"]
            self.assertNotIn("value", detail)
            self.assertNotIn("values", detail)
            self.assertNotIn("tags", detail)

    def test_audit_bad_kind_and_banned_keys(self):
        with self.assertRaises(ResourceTaggingError):
            resource_tagging_audit_event("bogus", 1)
        with self.assertRaises(ResourceTaggingError):
            resource_tagging_audit_event(
                KIND_TAGS_APPLIED, 1, tags={"env": "prod"}
            )

    def test_rejected_audited_on_duplicate(self):
        mgr = ResourceTagging()
        mgr.register("i-123", "ec2:instance", seq=1)
        with self.assertRaises(DuplicateResourceError):
            mgr.register("i-123", "ec2:instance", seq=2)
        self.assertEqual(
            [e["kind"] for e in mgr.audit_log()],
            [KIND_RESOURCE_REGISTERED, KIND_REJECTED],
        )


class TestViews(unittest.TestCase):
    def test_resource_and_policy_views(self):
        mgr = ResourceTagging()
        mgr.register("b-2", "s3:bucket", seq=1)
        mgr.register("i-1", "ec2:instance", seq=2)
        mgr.policy("p-b", ("env",), seq=3)
        mgr.policy("p-a", ("env",), seq=4)
        self.assertEqual(mgr.resource_ids(), ("b-2", "i-1"))
        self.assertEqual(mgr.policy_ids(), ("p-a", "p-b"))
        self.assertEqual(mgr.policy_record("p-a").policy_id, "p-a")
        with self.assertRaises(UnknownPolicyError):
            mgr.policy_record("ghost")
        with self.assertRaises(UnknownResourceError):
            mgr.resource("ghost")


if __name__ == "__main__":
    unittest.main()
