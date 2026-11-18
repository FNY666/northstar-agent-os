"""Tests for the scope-qualifier gate's VERB identity.

B173 ``scope-verb-canonical``.  The runtime has a rule about spelling:

    "The gate must deny the *action*, not just the *spelling*."
    -- tests/test_naming_variants.py

The **permission engine** applies that rule (``permissions.canonical_tool_name``:
strip, casefold).  The **scope-qualifier gate** did not, and the gap is
measurable on the runtime's own dispatch path:

    grant verb "Lookup", fence DROPPED, tool "Lookup"  -> blocked (deny:scope)
    grant verb "lookup", fence DROPPED, tool "Lookup"  -> RAN  (allowed_tools)

The gate never looked: ``presented_for`` compared the verb verbatim, so the
grant that says ``"verb": "lookup"`` was not the grant that authorizes
``Lookup``, and the gate found no presented grant and skipped itself.

The same hole made a ``denied`` row evaporate:

    grant verb "lookup", row scope "grant-1/Lookup" kind "denied"  -> RAN

A row that explicitly refuses the scope was read as *absent*, because the
scope string differed by one letter of case.

The asymmetry that makes this a defect rather than a design choice: inside
the SAME module the fence's resources are already compared
case-insensitively (``_scope_atoms`` lowercases the resource,
``permitted_targets`` lowercases it, ``scope_tokens`` lowercases it), and
the qualifier's ``kind`` is lowercased at construction.  The fence is
case-insensitive and the verb was not.

What these tests pin:

* the verb has ONE identity -- whitespace stripped, casefolded -- and it
  has it from construction;
* the presented-grant lookup, the denial-row scope, and the row lookup all
  agree on that identity;
* a row is found under the host's literal spelling AND under the
  canonical one, so a host's sidecar spelling cannot hide a row;
* **fail-closed is preserved**: no row under either spelling is still
  ``outcome_unknown``, never a clean read;
* the fence comparison is untouched;
* the **grant id** is NOT canonicalised -- two grants whose ids differ
  only in case are two grants.
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from support import RuntimeTestCase, tool_turn, text_turn
from tools import ToolRegistry, ToolResult, ToolSpec
from scope_qualifier import (
    OUTCOME_MISMATCH,
    OUTCOME_UNKNOWN,
    ROW_CLEAR,
    ROW_DENIED,
    DenialRow,
    DenialRowStore,
    GrantRecord,
    ScopeQualifier,
    ScopeQualifierGate,
    SourceLine,
    SourceStore,
)

FOLDER_X = ScopeQualifier("only", "folder X")
ALL_FOLDERS = ScopeQualifier("only", "all folders")


def source_line(qualifiers=(FOLDER_X,), grant_id: str = "grant-1") -> SourceLine:
    return SourceLine(
        source_ref="src-1",
        grant_id=grant_id,
        qualifiers=tuple(qualifiers),
        revoked=False,
    )


def grant(verb: str = "write", grant_id: str = "grant-1",
          qualifiers=(FOLDER_X,)) -> GrantRecord:
    return GrantRecord(
        grant_id=grant_id,
        verb=verb,
        qualifiers=tuple(qualifiers),
        source_ref="src-1",
    )


def gate_for(rows, sources=(FOLDER_X,)) -> ScopeQualifierGate:
    return ScopeQualifierGate(
        SourceStore([source_line(qualifiers=sources)]),
        denial_rows=DenialRowStore(list(rows)),
        fallback_ttl_seconds=100,
    )


class CanonicalVerbTests(unittest.TestCase):
    """One verb identity: strip, casefold."""

    def _canonical(self, value):
        import scope_qualifier

        self.assertTrue(
            hasattr(scope_qualifier, "canonical_verb"),
            "scope_qualifier must expose canonical_verb(): the scope gate "
            "compares verbs and the runtime already has this rule "
            "(permissions.canonical_tool_name) for tool names",
        )
        return scope_qualifier.canonical_verb(value)

    def test_a_verb_is_stripped(self):
        self.assertEqual(self._canonical("  Lookup "), "lookup")

    def test_a_verb_is_casefolded(self):
        self.assertEqual(self._canonical("LOOKUP"), "lookup")

    def test_the_canonical_form_is_idempotent(self):
        once = self._canonical(" Lookup ")
        self.assertEqual(self._canonical(once), once)

    def test_an_empty_verb_is_refused(self):
        with self.assertRaises(Exception):
            self._canonical("   ")

    def test_a_non_string_verb_is_refused(self):
        with self.assertRaises(Exception):
            self._canonical(None)


class GrantVerbIdentityTests(unittest.TestCase):
    """The grant's verb is normalised at construction."""

    def test_the_verb_of_a_grant_is_canonical(self):
        self.assertEqual(grant(verb=" Lookup ").verb, "lookup")

    def test_two_grants_differing_only_in_case_are_one_verb(self):
        self.assertEqual(grant(verb="Lookup").verb, grant(verb="lookup").verb)

    def test_the_grant_id_is_not_canonicalised(self):
        """Two grants whose ids differ only in case are TWO grants."""
        self.assertNotEqual(
            grant(grant_id="grant-1").grant_id, grant(grant_id="GRANT-1").grant_id
        )


class PresentedGrantLookupTests(unittest.TestCase):
    """``presented_for`` compares the verb canonically."""

    def setUp(self):
        from scope_qualifier import ScopeGrantRegistry

        self.registry = ScopeGrantRegistry()
        self.registry.present(grant(verb="Lookup"))

    def test_the_exact_verb_finds_the_grant(self):
        self.assertEqual(len(self.registry.presented_for("Lookup")), 1)

    def test_a_lowercase_verb_finds_the_grant(self):
        self.assertEqual(len(self.registry.presented_for("lookup")), 1)

    def test_an_uppercase_verb_finds_the_grant(self):
        self.assertEqual(len(self.registry.presented_for("LOOKUP")), 1)

    def test_a_padded_verb_finds_the_grant(self):
        self.assertEqual(len(self.registry.presented_for("  Lookup  ")), 1)

    def test_a_different_verb_finds_nothing(self):
        self.assertEqual(len(self.registry.presented_for("write")), 0)


class DenialRowScopeTests(unittest.TestCase):
    """The row is found under the host's literal spelling AND the canonical one."""

    def test_the_literal_scope_is_found(self):
        gate = gate_for([DenialRow(scope="grant-1/Lookup", kind=ROW_DENIED)])
        check = gate.check(grant(verb="Lookup"), now=0)
        self.assertTrue(check.blocked)
        self.assertEqual(check.outcome, OUTCOME_MISMATCH)

    def test_the_canonical_scope_is_found(self):
        gate = gate_for([DenialRow(scope="grant-1/lookup", kind=ROW_DENIED)])
        check = gate.check(grant(verb="Lookup"), now=0)
        self.assertTrue(check.blocked)
        self.assertEqual(check.outcome, OUTCOME_MISMATCH)

    def test_a_row_in_the_hosts_spelling_is_found_for_a_case_variant_grant(self):
        """The host wrote ``grant-1/Lookup``; the grant's verb is ``Lookup``
        and the tool is called ``Lookup`` -- and a case variant must not
        make the row evaporate."""
        gate = gate_for([DenialRow(scope="grant-1/Lookup", kind=ROW_DENIED)])
        check = gate.check(grant(verb="Lookup"), now=0)
        self.assertTrue(check.blocked, "a denied row must not be missed")

    def test_a_canonical_row_is_found_for_a_literal_scope_grant(self):
        gate = gate_for([DenialRow(scope="grant-1/lookup", kind=ROW_DENIED)])
        check = gate.check(grant(verb="Lookup"), now=0)
        self.assertTrue(check.blocked, "a canonical row must not be missed")


class FailClosedPreservationTests(unittest.TestCase):
    """No row under either spelling is still ``outcome_unknown``."""

    def test_no_row_is_outcome_unknown_not_an_allow(self):
        gate = gate_for([])
        check = gate.check(grant(verb="Lookup"), now=0)
        self.assertTrue(check.blocked)
        self.assertEqual(check.outcome, OUTCOME_UNKNOWN)

    def test_a_row_for_a_different_scope_is_outcome_unknown(self):
        gate = gate_for([DenialRow(scope="grant-2/Lookup", kind=ROW_DENIED)])
        check = gate.check(grant(verb="Lookup"), now=0)
        self.assertTrue(check.blocked)
        self.assertEqual(check.outcome, OUTCOME_UNKNOWN)

    def test_a_clear_row_under_the_canonical_scope_allows(self):
        gate = gate_for([DenialRow(scope="grant-1/lookup", kind=ROW_CLEAR,
                                   signature="sig-1")])
        check = gate.check(grant(verb="Lookup"), now=0)
        self.assertFalse(check.blocked)

    def test_a_clear_row_under_the_literal_scope_allows(self):
        gate = gate_for([DenialRow(scope="grant-1/Lookup", kind=ROW_CLEAR,
                                   signature="sig-1")])
        check = gate.check(grant(verb="Lookup"), now=0)
        self.assertFalse(check.blocked)


class FenceUnchangedTests(unittest.TestCase):
    """The slice touches the verb, never the fence."""

    def test_a_dropped_fence_still_blocks(self):
        gate = gate_for([DenialRow(scope="grant-1/lookup", kind=ROW_CLEAR,
                                   signature="sig-1")])
        check = gate.check(grant(verb="Lookup", qualifiers=()), now=0)
        self.assertTrue(check.blocked)
        self.assertEqual(check.outcome, OUTCOME_MISMATCH)

    def test_a_widened_fence_still_blocks(self):
        gate = gate_for([DenialRow(scope="grant-1/lookup", kind=ROW_CLEAR,
                                   signature="sig-1")])
        check = gate.check(grant(verb="Lookup", qualifiers=(ALL_FOLDERS,)), now=0)
        self.assertTrue(check.blocked)

    def test_an_intact_fence_still_runs(self):
        gate = gate_for([DenialRow(scope="grant-1/lookup", kind=ROW_CLEAR,
                                   signature="sig-1")])
        check = gate.check(grant(verb="Lookup"), now=0)
        self.assertFalse(check.blocked)


# ---------------------------------------------------------------------------
# The end-to-end property: the gate on the runtime's own dispatch path
# ---------------------------------------------------------------------------

FOLDER_X_JSON = {"kind": "only", "resource": "folder X"}


def registry_payload(
    *,
    verb: str = "Lookup",
    row_scope: str | None = None,
    row_kind: str = ROW_CLEAR,
    presented_qualifiers=(FOLDER_X_JSON,),
) -> dict:
    """The JSON shape the runtime's scope-registry loader reads."""
    return {
        "sources": [
            {
                "source_ref": "src-1",
                "grant_id": "grant-1",
                "qualifiers": [FOLDER_X_JSON],
            }
        ],
        "presented": [
            {
                "grant_id": "grant-1",
                "verb": verb,
                "qualifiers": list(presented_qualifiers),
                "source_ref": "src-1",
            }
        ],
        "rows": [
            {
                "scope": row_scope if row_scope is not None else f"grant-1/{verb}",
                "kind": row_kind,
                "signature": "sig-1",
            }
        ],
    }


class ScopeVerbDispatchTests(RuntimeTestCase):
    """The property is end-to-end: the handler runs, or it does not."""

    def _registry(self, effects: list) -> ToolRegistry:
        registry = ToolRegistry()
        registry.register(
            ToolSpec(
                name="Lookup",
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

    def _write_registry(self, payload: dict) -> str:
        directory = self.temp_dir()
        path = str(Path(directory) / "scope-registry.json")
        Path(path).write_text(json.dumps(payload), encoding="utf-8")
        return path

    def _drive(self, path: str, effects: list):
        runtime = self.runtime(
            provider=self.provider(
                [tool_turn("Lookup", {"query": "x"}), text_turn("done")]
            ),
            tools=self._registry(effects),
            can_use_tool=lambda *_args: True,
            allowed_tools=("Lookup",),
            scope_registry_path=path,
        )
        report = self.drive(runtime)
        return report

    # -- the two measured bypasses --------------------------------------

    def test_a_dropped_fence_blocks_even_when_the_verb_differs_in_case(self):
        """The measured bypass: grant verb "lookup", tool "Lookup", fence
        dropped -> the handler RAN.  The gate must deny the action, not
        just the spelling."""
        effects: list = []
        path = self._write_registry(
            registry_payload(verb="lookup", presented_qualifiers=())
        )
        report = self._drive(path, effects)
        self.assertEqual(effects, [], "a dropped fence must not run")
        self.assertTrue(report.tool_calls[0].denied)

    def test_a_denied_row_blocks_even_when_the_row_spells_the_verb_differently(self):
        """The measured bypass: the row says "denied" for grant-1/Lookup,
        the grant's verb is "lookup" -> the handler RAN.  A row that
        refuses the scope must not evaporate."""
        effects: list = []
        path = self._write_registry(
            registry_payload(verb="lookup", row_scope="grant-1/Lookup",
                             row_kind=ROW_DENIED)
        )
        report = self._drive(path, effects)
        self.assertEqual(effects, [], "a denied row must not run")
        self.assertTrue(report.tool_calls[0].denied)

    def test_a_denied_row_blocks_when_the_row_uses_the_canonical_spelling(self):
        effects: list = []
        path = self._write_registry(
            registry_payload(verb="Lookup", row_scope="grant-1/lookup",
                             row_kind=ROW_DENIED)
        )
        report = self._drive(path, effects)
        self.assertEqual(effects, [], "a denied row must not run")
        self.assertTrue(report.tool_calls[0].denied)

    # -- the negative controls -------------------------------------------

    def test_an_intact_fence_still_runs(self):
        """The benign control: a gate that refuses everything is not a
        gate."""
        effects: list = []
        path = self._write_registry(registry_payload(verb="Lookup"))
        report = self._drive(path, effects)
        self.assertEqual(effects, [{"query": "x"}], "an intact fence must run")
        self.assertFalse(report.tool_calls[0].denied)

    def test_an_intact_fence_still_runs_when_the_verb_differs_in_case(self):
        effects: list = []
        path = self._write_registry(registry_payload(verb="lookup"))
        report = self._drive(path, effects)
        self.assertEqual(effects, [{"query": "x"}], "an intact fence must run")
        self.assertFalse(report.tool_calls[0].denied)

    def test_a_registry_without_a_denial_row_is_still_blocked(self):
        """Fail-closed is preserved: no row is ``outcome_unknown``, never
        a clean read."""
        effects: list = []
        payload = registry_payload(verb="lookup")
        payload["rows"] = []
        path = self._write_registry(payload)
        report = self._drive(path, effects)
        self.assertEqual(effects, [], "a missing denial row must not read as clear")
        self.assertTrue(report.tool_calls[0].denied)


if __name__ == "__main__":
    unittest.main()
