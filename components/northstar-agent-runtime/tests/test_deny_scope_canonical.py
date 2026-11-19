"""Tests for the deny scope's canonical key (slice: deny-scope-canonical).

The deny hot path is the runtime's **fail-closed precondition**: every
dispatch consults the sealed deny *before* the gate decides, so a revoked
scope never reaches the gate at all.  Its scope is ``<subject>/<tool>``.

The defect this file pins: the scope was compared **verbatim** on both the
write side (``DenyStore.revoke``) and the read side (``DenyStore.lookup``),
so a revocation was bypassed by a case variant of the action name -- and a
scope that is *missed* is not an unreadable counter, it is **no row**, which
the store reads as the cleanest possible allow:

    revoked 'main/Lookup', called 'Lookup'  -> blocked
    revoked 'main/lookup', called 'Lookup'  -> RAN      <- the hole
    revoked 'main/Lookup', called 'lookup'  -> RAN      <- the hole

The rule under test is the one the runtime already states twice, for the
same reason (``permissions.canonical_tool_name``, ``sessions.canonical_action``):
**an action name has one identity, whatever its spelling.**

The two halves of the compound scope get **different** treatment, and the
difference is measured, not assumed:

* the **last** half is an *action name* and is canonicalised;
* the **first** half is an *agent name* and is kept **verbatim** --
  ``AgentRegistry.get()`` is case-sensitive, so two agents differing only in
  case are two agents.

And the shape that must not move: the lookup stays **one** indexed read, a
``SEARCH`` on the primary key, never a ``SCAN``.
"""

from __future__ import annotations

import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import deny_hotpath
from deny_hotpath import (
    COUNTER_TABLE,
    DenyDispatcher,
    DenyStore,
    stdlib_only,
)
from support import RuntimeTestCase, text_turn, tool_turn
from tools import ToolRegistry, ToolResult, ToolSpec


def canonical_deny_scope(scope):
    """The module's canonical key, or a loud failure if it does not exist.

    The reference is resolved at call time rather than imported at module
    load, so that a module without the helper still runs -- and still
    fails -- on the BEHAVIOUR.  A missing name would otherwise hide every
    other failure behind one import error.
    """
    helper = getattr(deny_hotpath, "canonical_deny_scope", None)
    if helper is None:
        raise AssertionError(
            "deny_hotpath has no canonical_deny_scope: the deny scope's "
            "key is compared verbatim, so a case variant of the action "
            "reaches a different row than the revocation"
        )
    return helper(scope)


class DenyScopeKeyTests(unittest.TestCase):
    """The canonical key: the action half is folded, the subject half is not."""

    def test_the_action_half_is_canonicalised(self):
        # The rule the runtime already states for a tool name.
        self.assertEqual(canonical_deny_scope("main/Bash"), "main/bash")
        self.assertEqual(canonical_deny_scope("main/BASH"), "main/bash")
        self.assertEqual(canonical_deny_scope("main/  Bash  "), "main/bash")

    def test_the_subject_half_is_kept_verbatim(self):
        # Two agents differing only in case are two agents.
        self.assertEqual(canonical_deny_scope("Main/Bash"), "Main/bash")
        self.assertNotEqual(
            canonical_deny_scope("Main/Bash"),
            canonical_deny_scope("main/Bash"),
        )

    def test_a_scope_with_no_separator_is_kept_verbatim(self):
        # Not a compound scope: guessing at it would be worse than reading
        # it as written.
        self.assertEqual(canonical_deny_scope("scope-a"), "scope-a")
        self.assertEqual(canonical_deny_scope("SCOPE-A"), "SCOPE-A")

    def test_the_split_is_on_the_last_separator(self):
        self.assertEqual(canonical_deny_scope("a/b/c"), "a/b/c")
        self.assertEqual(canonical_deny_scope("a/b/Write"), "a/b/write")

    def test_a_non_string_scope_is_refused(self):
        with self.assertRaises(Exception):
            canonical_deny_scope(None)
        with self.assertRaises(Exception):
            canonical_deny_scope(123)

    def test_an_empty_scope_is_refused(self):
        with self.assertRaises(Exception):
            canonical_deny_scope("")
        with self.assertRaises(Exception):
            canonical_deny_scope("   ")

    def test_an_over_long_scope_is_refused(self):
        with self.assertRaises(Exception):
            canonical_deny_scope("x" * 300)

    def test_a_scope_that_casefolding_lengthens_is_refused(self):
        # Casefolding can LENGTHEN a string: "ß" folds to "ss".  So a
        # scope that was within the cap can become longer than it, and
        # the key space must stay bounded.
        scope = "main/" + ("ß" * 126)
        self.assertLessEqual(len(scope), 256)
        with self.assertRaises(Exception):
            canonical_deny_scope(scope)

    def test_a_scope_at_the_cap_is_still_accepted(self):
        scope = "main/" + ("a" * 251)
        self.assertEqual(len(scope), 256)
        self.assertEqual(canonical_deny_scope(scope), scope)


class DenyStoreCanonicalScopeTests(unittest.TestCase):
    """The store files under the canonical key and reads it back."""

    def _store(self) -> DenyStore:
        store = DenyStore()
        self.addCleanup(store.close)
        return store

    def test_a_revocation_blocks_a_case_variant_of_the_action(self):
        store = self._store()
        store.revoke("main/Bash", reason="operator revoked")
        self.assertTrue(store.lookup("main/bash").denied)
        self.assertTrue(store.lookup("main/BASH").denied)

    def test_a_revocation_blocks_the_runtime_s_own_canonical_spelling(self):
        # The host revoked using the spelling the runtime itself defines.
        store = self._store()
        store.revoke("main/lookup", reason="operator revoked")
        self.assertTrue(store.lookup("main/Lookup").denied)

    def test_the_subject_half_is_not_folded(self):
        store = self._store()
        store.revoke("main/Bash", reason="operator revoked")
        self.assertFalse(store.lookup("Main/Bash").denied)

    def test_the_exact_match_still_blocks(self):
        store = self._store()
        store.revoke("main/Bash", reason="operator revoked")
        self.assertTrue(store.lookup("main/Bash").denied)

    def test_an_unrevoked_scope_still_runs(self):
        store = self._store()
        self.assertFalse(store.lookup("main/Bash").denied)

    def test_the_store_keeps_one_row_for_two_spellings(self):
        store = self._store()
        store.revoke("main/Bash", reason="operator revoked")
        store.revoke("main/bash", reason="operator revoked")
        rows = store._conn.execute(
            f"SELECT scope FROM {COUNTER_TABLE}"
        ).fetchall()
        self.assertEqual(len(rows), 1, [tuple(r) for r in rows])

    def test_the_counter_is_monotonic_across_spellings(self):
        store = self._store()
        first = store.revoke("main/Bash", reason="operator revoked")
        second = store.revoke("main/bash", reason="operator revoked")
        self.assertEqual(second, first + 1)

    def test_the_key_row_holds_the_canonical_scope(self):
        store = self._store()
        store.revoke("main/Bash", reason="operator revoked")
        row = store._conn.execute(
            f"SELECT scope FROM {COUNTER_TABLE}"
        ).fetchone()
        self.assertEqual(row["scope"], "main/bash")

    def test_the_record_keeps_the_verbatim_scope(self):
        # The deny log is the audit trail: it shows what the caller wrote.
        store = self._store()
        store.write_refusal("main/Bash", seq=1)
        rows = store.refusals()
        self.assertEqual(rows[0]["scope"], "main/Bash")

    def test_the_counter_read_uses_the_canonical_key(self):
        store = self._store()
        store.revoke("main/Bash", reason="operator revoked")
        self.assertIsNotNone(store.counter("main/bash"))

    def test_the_lookup_is_still_one_statement(self):
        store = self._store()
        store.reset_statements()
        store.lookup("main/Bash")
        statements = store.statements
        self.assertEqual(len(statements), 1, statements)
        self.assertIn("WHERE scope = ", statements[0])
        self.assertIn(COUNTER_TABLE, statements[0])

    def test_the_lookup_is_still_a_seek_not_a_scan(self):
        store = self._store()
        store.revoke("main/Bash", reason="operator revoked")
        plan = store.explain_lookup("main/Bash")
        self.assertIn("SEARCH", plan.upper(), plan)
        self.assertNotIn("SCAN", plan.upper(), plan)

    def test_the_module_is_still_stdlib_only(self):
        self.assertTrue(stdlib_only())

    def test_the_stdlib_guard_rejects_a_foreign_import(self):
        # The guard must be EXERCISED, not merely called: a guard that
        # reads only its own clean file cannot be told apart from one
        # that always says "yes".
        self.assertFalse(stdlib_only("import requests\n"))

    def test_the_stdlib_guard_rejects_a_foreign_from_import(self):
        self.assertFalse(stdlib_only("from requests import get\n"))

    def test_the_stdlib_guard_rejects_a_relative_import(self):
        self.assertFalse(stdlib_only("from . import sibling\n"))

    def test_the_stdlib_guard_accepts_an_allowed_import(self):
        self.assertTrue(stdlib_only("import json\nfrom typing import Any\n"))

    def test_the_stdlib_guard_accepts_a_submodule_of_an_allowed_package(self):
        # "sqlite3" is allowed, and so is anything under it.
        self.assertTrue(stdlib_only("from sqlite3 import dbapi2\n"))

    def test_the_stdlib_guard_rejects_a_dotted_foreign_package(self):
        self.assertFalse(stdlib_only("from requests.sessions import get\n"))


class DenySelfCheckTests(unittest.TestCase):
    """The module's own self-check runs clean.

    The self-check is where the module's invariants are stated in the
    module itself -- the refusal row lands first, the lookup is one
    read, an unreadable counter denies.  A test that runs it is what
    keeps those assertions live rather than decorative.
    """

    def test_the_module_self_check_runs_clean(self):
        deny_hotpath.main()

    def test_the_module_runs_as_a_script(self):
        # The entry point must actually reach the self-check: a module
        # whose __main__ guard never fires would pass every test above
        # while its self-check never ran.
        import subprocess

        module = Path(deny_hotpath.__file__)
        result = subprocess.run(
            [sys.executable, str(module)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=120,
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("self-check ok", result.stdout)


class DenyCacheabilityTests(unittest.TestCase):
    """A deny lookup result is never cacheable.

    The whole point of the indexed read is that the lookup is cheap
    enough not to be cached; a cached deny would outlive its reason.
    """

    def _store(self) -> DenyStore:
        store = DenyStore()
        self.addCleanup(store.close)
        return store

    def test_a_lookup_result_is_not_cacheable(self):
        store = self._store()
        lookup = store.lookup("main/Bash")
        self.assertFalse(lookup.cacheable)
        self.assertEqual(lookup.cache_ttl_ms, 0)

    def test_a_denied_lookup_result_is_not_cacheable_either(self):
        store = self._store()
        store.revoke("main/Bash", reason="operator revoked")
        lookup = store.lookup("main/Bash")
        self.assertFalse(lookup.cacheable)
        self.assertEqual(lookup.cache_ttl_ms, 0)

    def test_a_fail_closed_lookup_result_is_not_cacheable(self):
        store = self._store()
        store._conn.execute(f"DROP TABLE {COUNTER_TABLE}")
        lookup = store.lookup("main/Bash")
        self.assertTrue(lookup.denied)
        self.assertFalse(lookup.cacheable)
        self.assertEqual(lookup.cache_ttl_ms, 0)


class DenyDecisionShapeTests(unittest.TestCase):
    """The decision carries what a caller needs to explain itself."""

    def _store(self) -> DenyStore:
        store = DenyStore()
        self.addCleanup(store.close)
        return store

    def test_a_refusal_row_is_readable_by_its_id(self):
        store = self._store()
        dispatcher = DenyDispatcher(store)
        store.revoke("main/Bash", reason="operator revoked")
        decision = dispatcher.check("main/Bash")
        row = store.refusal(decision.refusal_id)
        self.assertIsNotNone(row)
        self.assertEqual(row["outcome"], "denied")
        self.assertEqual(row["scope"], "main/Bash")

    def test_an_unknown_refusal_id_reads_back_as_none(self):
        store = self._store()
        self.assertIsNone(store.refusal("ref-does-not-exist"))

    def test_the_dispatcher_reports_the_fail_closed_source(self):
        store = self._store()
        dispatcher = DenyDispatcher(store)
        store._conn.execute(f"DROP TABLE {COUNTER_TABLE}")
        decision = dispatcher.check("main/Bash")
        self.assertTrue(decision.denied)
        self.assertEqual(decision.lookup.source, "fail-closed")


class DenyStoreMigrationTests(unittest.TestCase):
    """An existing store file keeps its revocations."""

    def test_a_store_written_with_the_old_spelling_still_denies(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "deny.sqlite3")
            # A store file written the way the runtime wrote it BEFORE the
            # canonical key existed: the row is filed under the host's own
            # spelling.
            legacy = sqlite3.connect(path)
            legacy.execute(
                f"CREATE TABLE {COUNTER_TABLE} ("
                "scope TEXT PRIMARY KEY, counter INTEGER NOT NULL DEFAULT 0, "
                "denied INTEGER NOT NULL DEFAULT 0, reason TEXT NOT NULL "
                "DEFAULT '', seq INTEGER NOT NULL DEFAULT 0)"
            )
            legacy.execute(
                f"INSERT INTO {COUNTER_TABLE} (scope, counter, denied, reason) "
                "VALUES ('main/Lookup', 3, 1, 'operator revoked')"
            )
            legacy.commit()
            legacy.close()

            store = DenyStore(path)
            self.addCleanup(store.close)
            self.assertTrue(
                store.lookup("main/lookup").denied,
                "a revocation written under the old spelling must survive",
            )
            self.assertTrue(store.lookup("main/Lookup").denied)

    def test_a_migration_keeps_the_denied_row(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "deny.sqlite3")
            legacy = sqlite3.connect(path)
            legacy.execute(
                f"CREATE TABLE {COUNTER_TABLE} ("
                "scope TEXT PRIMARY KEY, counter INTEGER NOT NULL DEFAULT 0, "
                "denied INTEGER NOT NULL DEFAULT 0, reason TEXT NOT NULL "
                "DEFAULT '', seq INTEGER NOT NULL DEFAULT 0)"
            )
            # Two rows that collide on the canonical key: one denied, one
            # cleared.  The denied one must win -- a migration must never
            # weaken a revocation.
            legacy.execute(
                f"INSERT INTO {COUNTER_TABLE} (scope, counter, denied, reason) "
                "VALUES ('main/Lookup', 3, 1, 'operator revoked')"
            )
            legacy.execute(
                f"INSERT INTO {COUNTER_TABLE} (scope, counter, denied, reason) "
                "VALUES ('main/lookup', 9, 0, '')"
            )
            legacy.commit()
            legacy.close()

            store = DenyStore(path)
            self.addCleanup(store.close)
            lookup = store.lookup("main/lookup")
            self.assertTrue(lookup.denied, "the denied row must win the collision")
            self.assertEqual(lookup.counter, 9, "the higher counter must win")

    def test_a_migration_does_not_move_the_counter_backwards(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "deny.sqlite3")
            legacy = sqlite3.connect(path)
            legacy.execute(
                f"CREATE TABLE {COUNTER_TABLE} ("
                "scope TEXT PRIMARY KEY, counter INTEGER NOT NULL DEFAULT 0, "
                "denied INTEGER NOT NULL DEFAULT 0, reason TEXT NOT NULL "
                "DEFAULT '', seq INTEGER NOT NULL DEFAULT 0)"
            )
            legacy.execute(
                f"INSERT INTO {COUNTER_TABLE} (scope, counter, denied, reason) "
                "VALUES ('main/lookup', 7, 1, 'operator revoked')"
            )
            legacy.commit()
            legacy.close()

            store = DenyStore(path)
            self.addCleanup(store.close)
            self.assertEqual(store.lookup("main/lookup").counter, 7)

    def _legacy_store(self, path: str, rows) -> None:
        """A store file written the way the runtime wrote it before the
        canonical key existed."""
        legacy = sqlite3.connect(path)
        legacy.execute(
            f"CREATE TABLE {COUNTER_TABLE} ("
            "scope TEXT PRIMARY KEY, counter INTEGER NOT NULL DEFAULT 0, "
            "denied INTEGER NOT NULL DEFAULT 0, reason TEXT NOT NULL "
            "DEFAULT '', seq INTEGER NOT NULL DEFAULT 0)"
        )
        for scope, counter, denied, reason in rows:
            legacy.execute(
                f"INSERT INTO {COUNTER_TABLE} (scope, counter, denied, reason) "
                "VALUES (?, ?, ?, ?)",
                (scope, counter, denied, reason),
            )
        legacy.commit()
        legacy.close()

    def test_a_migration_keeps_the_revocation_reason(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "deny.sqlite3")
            self._legacy_store(
                path,
                [("main/Lookup", 3, 1, "operator revoked")],
            )
            store = DenyStore(path)
            self.addCleanup(store.close)
            lookup = store.lookup("main/lookup")
            self.assertTrue(lookup.denied)
            self.assertEqual(lookup.reason, "operator revoked")

    def test_a_migration_keeps_a_cleared_scope_cleared(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "deny.sqlite3")
            self._legacy_store(
                path,
                [("main/Lookup", 3, 0, "")],
            )
            store = DenyStore(path)
            self.addCleanup(store.close)
            lookup = store.lookup("main/lookup")
            self.assertFalse(lookup.denied)
            self.assertEqual(lookup.counter, 3)

    def test_a_migration_leaves_a_canonical_row_alone(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "deny.sqlite3")
            self._legacy_store(
                path,
                [("main/lookup", 4, 1, "operator revoked")],
            )
            store = DenyStore(path)
            self.addCleanup(store.close)
            lookup = store.lookup("main/lookup")
            self.assertTrue(lookup.denied)
            self.assertEqual(lookup.counter, 4)

    def test_a_migration_does_not_touch_the_deny_log(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "deny.sqlite3")
            self._legacy_store(
                path,
                [("main/Lookup", 3, 1, "operator revoked")],
            )
            store = DenyStore(path)
            self.addCleanup(store.close)
            # The deny log is the record; the migration is about the key.
            self.assertEqual(store.refusal_count(), 0)

    def test_a_migration_leaves_the_events_sequence_empty(self):
        # The acceptance tests pin events[0] == "refusal"; a migration that
        # went through the store's own API would shift it.
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "deny.sqlite3")
            self._legacy_store(
                path,
                [("main/Lookup", 3, 1, "operator revoked")],
            )
            store = DenyStore(path)
            self.addCleanup(store.close)
            self.assertEqual(store.events, ())


class DenyDispatcherCanonicalScopeTests(unittest.TestCase):
    """The dispatcher's decision is about the action, not the spelling."""

    def _dispatcher(self) -> DenyDispatcher:
        store = DenyStore()
        self.addCleanup(store.close)
        return DenyDispatcher(store)

    def test_a_case_variant_of_the_action_is_denied(self):
        dispatcher = self._dispatcher()
        dispatcher.store.revoke("main/Bash", reason="operator revoked")
        decision = dispatcher.check("main/bash")
        self.assertTrue(decision.denied)
        self.assertEqual(decision.outcome, "denied")

    def test_an_unrevoked_case_variant_is_allowed(self):
        dispatcher = self._dispatcher()
        decision = dispatcher.check("main/bash")
        self.assertFalse(decision.denied)
        self.assertEqual(decision.outcome, "allowed")

    def test_the_refusal_row_still_comes_first(self):
        dispatcher = self._dispatcher()
        dispatcher.check("main/Bash")
        self.assertEqual(dispatcher.store.events[0], "refusal")
        self.assertEqual(dispatcher.store.events[1], "lookup")
        self.assertEqual(dispatcher.store.events[2], "finalize")


class DenyScopeEndToEndTests(RuntimeTestCase):
    """The bypass, measured on the runtime's own dispatch path."""

    def _registry(self, effects: list, name: str = "Lookup") -> ToolRegistry:
        registry = ToolRegistry()
        registry.register(
            ToolSpec(
                name=name,
                description="read-only lookup",
                input_schema={
                    "type": "object",
                    "properties": {"query": {"type": "string"}},
                    "additionalProperties": False,
                },
                handler=lambda payload, _ctx: effects.append(payload)
                or ToolResult.ok("looked up"),
                kind="read",
                is_mutating=False,
            )
        )
        return registry

    def _drive(self, revoked: str | None, tool_name: str = "Lookup"):
        effects: list = []
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "deny.sqlite3")
            if revoked is not None:
                store = DenyStore(path)
                store.revoke(revoked, reason="operator revoked")
                store.close()
            runtime = self.runtime(
                provider=self.provider([
                    tool_turn(tool_name, {"query": "x"}),
                    text_turn("done"),
                ]),
                tools=self._registry(effects, tool_name),
                can_use_tool=lambda *_args: True,
                allowed_tools=(tool_name,),
                deny_store_path=path,
            )
            report = self.drive(runtime)
            runtime.deny_store.close()
        denied = report.tool_calls[0].denied if report.tool_calls else None
        return bool(effects), denied

    def test_the_hosts_canonical_spelling_still_blocks_the_dispatch(self):
        ran, denied = self._drive("main/lookup")
        self.assertFalse(ran, "a revoked scope must not run the handler")
        self.assertTrue(denied)

    def test_the_exact_spelling_still_blocks_the_dispatch(self):
        ran, denied = self._drive("main/Lookup")
        self.assertFalse(ran, "a revoked scope must not run the handler")
        self.assertTrue(denied)

    def test_an_unrevoked_scope_still_runs_the_dispatch(self):
        ran, denied = self._drive(None)
        self.assertTrue(ran, "an unrevoked scope must run the handler")
        self.assertFalse(denied)


if __name__ == "__main__":
    unittest.main()
