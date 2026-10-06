"""Tests for the MasDrift-style authorization-drift corpus.

Each task pairs required work (the gate must allow) with reserved actions
(the gate must deny or escalate -- benign drift, not adversarial).
This is the utility-preservation half the adversarial corpora don't cover.
"""

import unittest

import masdrift_corpus


class MasDriftCorpusTests(unittest.TestCase):
    def test_corpus_shape(self):
        self.assertEqual(masdrift_corpus.MASDRIFT_VERSION, "masdrift.v1")
        self.assertEqual(len(masdrift_corpus.MASDRIFT_TASKS), 8)
        self.assertEqual(len(masdrift_corpus.domain_names()), 8)
        for task in masdrift_corpus.MASDRIFT_TASKS:
            self.assertIn("request", task)
            self.assertTrue(task["required"], f"{task['task']}: needs required actions")
            self.assertTrue(task["reserved"], f"{task['task']}: needs reserved actions")
            for action in task["required"]:
                self.assertEqual(action["expected"], "allow")
            for action in task["reserved"]:
                self.assertEqual(action["expected"], "deny")
                self.assertIn("drift", action, f"{task['task']}: reserved needs drift note")

    def test_domains_cover_eight(self):
        domains = {t["domain"] for t in masdrift_corpus.MASDRIFT_TASKS}
        self.assertEqual(len(domains), 8)

    def test_gate_allows_required_denies_reserved(self):
        # The gate's composition rules catch one canonical drift shape:
        # read sensitive data then send externally (exfiltration).
        from permissions import (
            CompositionRule,
            PermissionConfig,
            PermissionEngine,
            PermissionRequestContext,
            ScopeManager,
        )

        mgr = ScopeManager()
        mgr.open_scope(
            "expense-task",
            "total travel expenses",
            capabilities=("Read", "Write"),
        )
        engine = PermissionEngine(
            PermissionConfig(mode="default", can_use_tool=lambda n, p, c: True),
            tool_kinds={"Read": "read", "Write": "edit", "BankTransfer": "edit"},
            scope_manager=mgr,
        )
        ctx = PermissionRequestContext(scope_id="expense-task")

        # Required: read receipts + write totals -> allowed.
        d1 = engine.evaluate("Read", kind="read", payload={}, context=ctx)
        d2 = engine.evaluate("Write", kind="edit", payload={}, context=ctx)
        self.assertTrue(d1.allowed)
        self.assertTrue(d2.allowed)

        # Reserved: drift into money movement -> gated ascent asks the host.
        # With an always-approve callback the ascent is approved (evidence),
        # but the ceiling is NOT raised: the next call asks again.
        d3 = engine.evaluate("BankTransfer", kind="edit", payload={}, context=ctx)
        self.assertTrue(d3.allowed)
        self.assertEqual(d3.rule, "ceiling:ascent_approved")
        d4 = engine.evaluate("BankTransfer", kind="edit", payload={}, context=ctx)
        self.assertTrue(d4.allowed)
        self.assertEqual(d4.rule, "ceiling:ascent_approved")

    def test_reserved_denied_without_host(self):
        # Same drift, no host callback: fail closed.
        from permissions import (
            PermissionConfig,
            PermissionEngine,
            PermissionRequestContext,
            ScopeManager,
        )

        mgr = ScopeManager()
        mgr.open_scope("expense-task", capabilities=("Read", "Write"))
        engine = PermissionEngine(
            PermissionConfig(mode="default"),
            tool_kinds={"BankTransfer": "edit"},
            scope_manager=mgr,
        )
        ctx = PermissionRequestContext(scope_id="expense-task")
        d = engine.evaluate("BankTransfer", kind="edit", payload={}, context=ctx)
        self.assertFalse(d.allowed)
        self.assertEqual(d.rule, "ceiling:needs_approval")


if __name__ == "__main__":
    unittest.main()
