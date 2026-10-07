"""Targeted tests for rbac_engine.py."""

import ast
import threading
import unittest
from dataclasses import FrozenInstanceError
from pathlib import Path

from rbac_engine import (
    RBACEngine,
    AccessDecision,
    DuplicateAssignmentError,
    DuplicateGrantError,
    DuplicateInheritanceError,
    DuplicateRoleError,
    InheritanceCycleError,
    InheritanceInUseError,
    RoleInUseError,
    RBACError,
    RBAC_ENGINE_VERSION,
    SCHEMA_PIN,
    SelfInheritanceError,
    SeqOrderError,
    UnknownAssignmentError,
    UnknownGrantError,
    UnknownInheritanceError,
    UnknownRoleError,
    UnknownSubjectError,
    rbac_engine_audit_event,
)


class SeqHarness(unittest.TestCase):
    """Fresh engine with a monotonic seq counter per test."""

    def setUp(self):
        self.eng = RBACEngine()
        self.n = 0

    def seq(self):
        self.n += 1
        return self.n

    def fresh(self):
        e = RBACEngine()
        e.create_role("r", seq=1)
        return e


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(RBAC_ENGINE_VERSION, "rbac-engine.v1")

    def test_schema_pin(self):
        self.assertEqual(SCHEMA_PIN, "northstar.rbac-engine.v1")


class TestRoleLifecycle(SeqHarness):
    def test_create_happy_path(self):
        rec = self.eng.create_role("admin", seq=self.seq(), description="ops")
        self.assertEqual(rec.role_id, "admin")
        self.assertEqual(rec.description, "ops")
        self.assertTrue(rec.digest.startswith("sha256:"))
        self.assertEqual(self.eng.roles(), ("admin",))

    def test_create_roles_sorted(self):
        self.eng.create_role("zeta", seq=self.seq())
        self.eng.create_role("alpha", seq=self.seq())
        self.assertEqual(self.eng.roles(), ("alpha", "zeta"))

    def test_duplicate_role(self):
        self.eng.create_role("admin", seq=self.seq())
        with self.assertRaises(DuplicateRoleError):
            self.eng.create_role("admin", seq=self.seq())

    def test_bad_role_id(self):
        for bad in ("", 123, None, b"admin", True):
            with self.assertRaises((TypeError, ValueError)):
                self.eng.create_role(bad, seq=self.seq())

    def test_nul_role_id(self):
        with self.assertRaises(ValueError):
            self.eng.create_role("ad\x00min", seq=self.seq())

    def test_delete_unknown_role(self):
        with self.assertRaises(UnknownRoleError):
            self.eng.delete_role("ghost", seq=self.seq())

    def test_delete_unused_role(self):
        self.eng.create_role("temp", seq=self.seq())
        d = self.eng.delete_role("temp", seq=self.seq())
        self.assertEqual(d.role_id, "temp")
        self.assertNotIn("temp", self.eng.roles())
        with self.assertRaises(UnknownRoleError):
            self.eng.role("temp")

    def test_delete_role_in_use_by_assignment(self):
        self.eng.create_role("admin", seq=self.seq())
        self.eng.assign_role("alice", "admin", seq=self.seq())
        with self.assertRaises(RoleInUseError):
            self.eng.delete_role("admin", seq=self.seq())

    def test_delete_role_in_use_by_inheritance(self):
        self.eng.create_role("child", seq=self.seq())
        self.eng.create_role("parent", seq=self.seq())
        self.eng.add_inheritance("child", "parent", seq=self.seq())
        with self.assertRaises(InheritanceInUseError):
            self.eng.delete_role("parent", seq=self.seq())
        with self.assertRaises(InheritanceInUseError):
            self.eng.delete_role("child", seq=self.seq())

    def test_delete_after_unassign_and_uninherit(self):
        self.eng.create_role("child", seq=self.seq())
        self.eng.create_role("parent", seq=self.seq())
        self.eng.assign_role("alice", "child", seq=self.seq())
        self.eng.add_inheritance("child", "parent", seq=self.seq())
        self.eng.unassign_role("alice", "child", seq=self.seq())
        self.eng.remove_inheritance("child", "parent", seq=self.seq())
        self.eng.delete_role("child", seq=self.seq())
        self.eng.delete_role("parent", seq=self.seq())
        self.assertEqual(self.eng.roles(), ())


class TestGrants(SeqHarness):
    def test_grant_happy_path(self):
        e = self.fresh()
        g = e.grant_permission("r", "read:billing", seq=2)
        self.assertEqual(g.role_id, "r")
        self.assertEqual(g.permission, "read:billing")
        self.assertTrue(g.digest.startswith("sha256:"))
        self.assertEqual(e.direct_permissions("r"), ("read:billing",))

    def test_duplicate_grant(self):
        e = self.fresh()
        e.grant_permission("r", "read:billing", seq=2)
        with self.assertRaises(DuplicateGrantError):
            e.grant_permission("r", "read:billing", seq=3)

    def test_grant_unknown_role(self):
        with self.assertRaises(UnknownRoleError):
            self.eng.grant_permission("ghost", "read:x", seq=self.seq())

    def test_bad_permission(self):
        e = self.fresh()
        for bad in ("", 123, None, True):
            with self.assertRaises((TypeError, ValueError)):
                e.grant_permission("r", bad, seq=self.seq() + 1)

    def test_revoke_happy_path(self):
        e = self.fresh()
        e.grant_permission("r", "read:billing", seq=2)
        e.revoke_permission("r", "read:billing", seq=3)
        self.assertEqual(e.direct_permissions("r"), ())

    def test_revoke_unknown_grant(self):
        e = self.fresh()
        with self.assertRaises(UnknownGrantError):
            e.revoke_permission("r", "read:billing", seq=2)

    def test_regrant_after_revoke(self):
        e = self.fresh()
        e.grant_permission("r", "read:billing", seq=2)
        e.revoke_permission("r", "read:billing", seq=3)
        e.grant_permission("r", "read:billing", seq=4)
        self.assertEqual(e.direct_permissions("r"), ("read:billing",))


class TestAssignments(SeqHarness):
    def test_assign_happy_path(self):
        e = self.fresh()
        a = e.assign_role("alice", "r", seq=2)
        self.assertEqual(a.subject_id, "alice")
        self.assertTrue(a.digest.startswith("sha256:"))
        self.assertEqual(e.subject_roles("alice"), ("r",))

    def test_duplicate_assignment(self):
        e = self.fresh()
        e.assign_role("alice", "r", seq=2)
        with self.assertRaises(DuplicateAssignmentError):
            e.assign_role("alice", "r", seq=3)

    def test_assign_unknown_role(self):
        with self.assertRaises(UnknownRoleError):
            self.eng.assign_role("alice", "ghost", seq=self.seq())

    def test_unassign_happy_path(self):
        e = self.fresh()
        e.assign_role("alice", "r", seq=2)
        e.unassign_role("alice", "r", seq=3)
        self.assertEqual(e.subject_roles("alice"), ())
        with self.assertRaises(UnknownSubjectError):
            e.check("alice", "read:billing", seq=4)

    def test_unassign_unknown(self):
        e = self.fresh()
        with self.assertRaises(UnknownAssignmentError):
            e.unassign_role("alice", "r", seq=2)

    def test_multi_role_subject(self):
        e = self.fresh()
        e.create_role("s", seq=2)
        e.assign_role("alice", "r", seq=3)
        e.assign_role("alice", "s", seq=4)
        self.assertEqual(e.subject_roles("alice"), ("r", "s"))


class TestHierarchy(SeqHarness):
    def _two_roles(self):
        e = RBACEngine()
        e.create_role("senior", seq=1)
        e.create_role("junior", seq=2)
        return e

    def test_inherit_happy_path(self):
        e = self._two_roles()
        rec = e.add_inheritance("senior", "junior", seq=3)
        self.assertTrue(rec.digest.startswith("sha256:"))
        self.assertEqual(e.parents("senior"), ("junior",))
        self.assertEqual(e.children("junior"), ("senior",))

    def test_inherited_permissions(self):
        e = self._two_roles()
        e.grant_permission("junior", "read:billing", seq=3)
        e.add_inheritance("senior", "junior", seq=4)
        self.assertEqual(e.effective_permissions("senior"), ("read:billing",))
        self.assertEqual(e.effective_permissions("junior"), ("read:billing",))

    def test_transitive_inheritance(self):
        e = RBACEngine()
        e.create_role("c", seq=1)
        e.create_role("b", seq=2)
        e.create_role("a", seq=3)
        e.grant_permission("a", "root:all", seq=4)
        e.add_inheritance("b", "a", seq=5)
        e.add_inheritance("c", "b", seq=6)
        self.assertEqual(e.effective_permissions("c"), ("root:all",))

    def test_self_inheritance_refused(self):
        e = self._two_roles()
        with self.assertRaises(SelfInheritanceError):
            e.add_inheritance("senior", "senior", seq=3)

    def test_direct_cycle_refused(self):
        e = self._two_roles()
        e.add_inheritance("senior", "junior", seq=3)
        with self.assertRaises(InheritanceCycleError):
            e.add_inheritance("junior", "senior", seq=4)

    def test_long_cycle_refused(self):
        e = RBACEngine()
        for i, r in enumerate(("a", "b", "c")):
            e.create_role(r, seq=i + 1)
        e.add_inheritance("a", "b", seq=4)
        e.add_inheritance("b", "c", seq=5)
        with self.assertRaises(InheritanceCycleError):
            e.add_inheritance("c", "a", seq=6)

    def test_diamond_allowed(self):
        # diamond: d -> {b, c} -> a is a DAG, must be allowed
        e = RBACEngine()
        for i, r in enumerate(("a", "b", "c", "d")):
            e.create_role(r, seq=i + 1)
        e.grant_permission("a", "p", seq=5)
        e.add_inheritance("b", "a", seq=6)
        e.add_inheritance("c", "a", seq=7)
        e.add_inheritance("d", "b", seq=8)
        e.add_inheritance("d", "c", seq=9)
        self.assertEqual(e.effective_permissions("d"), ("p",))

    def test_duplicate_inheritance(self):
        e = self._two_roles()
        e.add_inheritance("senior", "junior", seq=3)
        with self.assertRaises(DuplicateInheritanceError):
            e.add_inheritance("senior", "junior", seq=4)

    def test_unknown_inheritance_removal(self):
        e = self._two_roles()
        with self.assertRaises(UnknownInheritanceError):
            e.remove_inheritance("senior", "junior", seq=3)

    def test_remove_inheritance_drops_permissions(self):
        e = self._two_roles()
        e.grant_permission("junior", "read:billing", seq=3)
        e.add_inheritance("senior", "junior", seq=4)
        e.remove_inheritance("senior", "junior", seq=5)
        self.assertEqual(e.effective_permissions("senior"), ())

    def test_inheritance_unknown_role(self):
        e = self._two_roles()
        with self.assertRaises(UnknownRoleError):
            e.add_inheritance("senior", "ghost", seq=3)
        with self.assertRaises(UnknownRoleError):
            e.add_inheritance("ghost", "junior", seq=4)


class TestCheck(SeqHarness):
    def test_check_direct_allowed(self):
        e = self.fresh()
        e.grant_permission("r", "read:billing", seq=2)
        e.assign_role("alice", "r", seq=3)
        dec = e.check("alice", "read:billing", seq=4)
        self.assertIsInstance(dec, AccessDecision)
        self.assertTrue(dec.allowed)
        self.assertEqual(dec.reason, "direct")
        self.assertEqual(dec.granting_roles, ("r",))
        self.assertFalse(dec.via_inheritance)
        self.assertTrue(dec.digest.startswith("sha256:"))

    def test_check_denied_is_data(self):
        e = self.fresh()
        e.assign_role("alice", "r", seq=2)
        dec = e.check("alice", "read:billing", seq=3)
        self.assertFalse(dec.allowed)
        self.assertEqual(dec.reason, "no-grant")
        self.assertEqual(dec.granting_roles, ())
        self.assertFalse(dec.via_inheritance)

    def test_check_unknown_subject_fails_closed(self):
        e = self.fresh()
        with self.assertRaises(UnknownSubjectError):
            e.check("mallory", "read:billing", seq=2)

    def test_check_via_inheritance(self):
        e = RBACEngine()
        e.create_role("senior", seq=1)
        e.create_role("junior", seq=2)
        e.grant_permission("junior", "read:billing", seq=3)
        e.add_inheritance("senior", "junior", seq=4)
        e.assign_role("bob", "senior", seq=5)
        dec = e.check("bob", "read:billing", seq=6)
        self.assertTrue(dec.allowed)
        self.assertEqual(dec.reason, "inherited")
        self.assertTrue(dec.via_inheritance)
        self.assertEqual(dec.granting_roles, ("senior",))

    def test_check_denied_after_revoke(self):
        e = self.fresh()
        e.grant_permission("r", "read:billing", seq=2)
        e.assign_role("alice", "r", seq=3)
        e.revoke_permission("r", "read:billing", seq=4)
        dec = e.check("alice", "read:billing", seq=5)
        self.assertFalse(dec.allowed)

    def test_check_decision_digest_deterministic(self):
        def build():
            e = RBACEngine()
            e.create_role("r", seq=1)
            e.grant_permission("r", "read:billing", seq=2)
            e.assign_role("alice", "r", seq=3)
            return e.check("alice", "read:billing", seq=99).digest

        self.assertEqual(build(), build())

    def test_check_bad_inputs(self):
        e = self.fresh()
        with self.assertRaises(TypeError):
            e.check(123, "read:billing", seq=2)
        with self.assertRaises(ValueError):
            e.check("alice", "", seq=2)
        with self.assertRaises(TypeError):
            e.check("alice", "read:billing", seq=True)

    def test_subject_effective_permissions(self):
        e = RBACEngine()
        e.create_role("senior", seq=1)
        e.create_role("junior", seq=2)
        e.grant_permission("junior", "read:billing", seq=3)
        e.grant_permission("senior", "write:billing", seq=4)
        e.add_inheritance("senior", "junior", seq=5)
        e.assign_role("bob", "senior", seq=6)
        self.assertEqual(
            e.subject_permissions("bob"), ("read:billing", "write:billing")
        )

    def test_subject_permissions_unknown_subject(self):
        e = self.fresh()
        with self.assertRaises(UnknownSubjectError):
            e.subject_permissions("mallory")


class TestSeqOrder(SeqHarness):
    def test_seq_rewind_rejected(self):
        e = self.fresh()  # consumed seq 1
        with self.assertRaises(SeqOrderError):
            e.create_role("s", seq=1)

    def test_seq_zero_allowed_then_must_increase(self):
        e = RBACEngine()
        e.create_role("r", seq=0)
        with self.assertRaises(SeqOrderError):
            e.create_role("s", seq=0)

    def test_bool_seq_rejected(self):
        e = self.fresh()
        with self.assertRaises(TypeError):
            e.grant_permission("r", "p", seq=True)

    def test_negative_seq_rejected(self):
        with self.assertRaises(ValueError):
            self.eng.create_role("r", seq=-1)


class TestAudit(unittest.TestCase):
    def test_audit_shapes(self):
        rec = rbac_engine_audit_event(
            "access-checked", 7, subject_id="alice", allowed=True
        )
        self.assertEqual(rec["schema"], "audit.ndjson/1")
        self.assertEqual(rec["kind"], "rbac-engine.access-checked")
        self.assertEqual(rec["module"], "rbac-engine.v1")
        self.assertEqual(rec["seq"], 7)
        self.assertTrue(rec["allowed"])

    def test_all_kinds(self):
        for kind in (
            "role-created",
            "role-deleted",
            "permission-granted",
            "permission-revoked",
            "role-assigned",
            "role-unassigned",
            "inheritance-added",
            "inheritance-removed",
            "access-checked",
            "rejected",
        ):
            rec = rbac_engine_audit_event(kind, 1)
            self.assertEqual(rec["kind"], f"rbac-engine.{kind}")

    def test_unknown_kind_rejected(self):
        with self.assertRaises(RBACError):
            rbac_engine_audit_event("nuked", 1)

    def test_bad_seq_rejected(self):
        with self.assertRaises(TypeError):
            rbac_engine_audit_event("role-created", True)


class TestHouseStyle(unittest.TestCase):
    def test_frozen_records(self):
        e = RBACEngine()
        rec = e.create_role("r", seq=1)
        with self.assertRaises(FrozenInstanceError):
            rec.role_id = "changed"  # type: ignore[misc]

    def test_as_dict_schema(self):
        e = RBACEngine()
        rec = e.create_role("r", seq=1)
        d = rec.as_dict()
        self.assertEqual(d["schema"], "northstar.rbac-engine.v1")
        self.assertEqual(d["version"], "rbac-engine.v1")

    def test_access_decision_as_dict(self):
        e = RBACEngine()
        e.create_role("r", seq=1)
        e.grant_permission("r", "p", seq=2)
        e.assign_role("alice", "r", seq=3)
        d = e.check("alice", "p", seq=4).as_dict()
        self.assertEqual(d["granting_roles"], ["r"])
        self.assertEqual(d["reason"], "direct")

    def test_stdlib_only(self):
        src = Path(__file__).resolve().parent.parent / "rbac_engine.py"
        tree = ast.parse(src.read_text())
        allowed = {"__future__", "hashlib", "threading", "dataclasses", "typing"}
        imports = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom):
                imports.add(node.module.split(".")[0])
        self.assertTrue(imports <= allowed, f"extra imports: {imports - allowed}")

    def test_thread_safety(self):
        e = RBACEngine()
        e.create_role("r", seq=1)
        seqs = iter(range(2, 2 + 5 * 10))
        lock = threading.Lock()
        errors = []

        def worker(i):
            try:
                for _ in range(10):
                    with lock:
                        s = next(seqs)
                    e.grant_permission("r", f"perm-{i}-{s}", seq=s)
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        self.assertEqual(len(e.direct_permissions("r")), 50)


class TestMain(unittest.TestCase):
    def test_main(self):
        import rbac_engine

        rbac_engine.main()


if __name__ == "__main__":
    unittest.main()
