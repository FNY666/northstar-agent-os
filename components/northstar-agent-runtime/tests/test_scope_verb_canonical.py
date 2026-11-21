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
    KIND_CHECKED,
    OUTCOME_MISMATCH,
    OUTCOME_UNKNOWN,
    ROW_CLEAR,
    ROW_DENIED,
    DenialRow,
    DenialRowStore,
    GrantRecord,
    MalformedGrantError,
    ScopeCheck,
    ScopeFallback,
    ScopeGrantRegistry,
    ScopeQualifier,
    ScopeQualifierError,
    ScopeQualifierGate,
    ScopeSourceError,
    SourceLine,
    SourceStore,
    SurvivalMetrics,
    check_compaction_boundary,
    diff_qualifiers,
    measure_qualifier_survival,
    scope_audit_event,
    scope_relation,
    scope_tokens,
)

FOLDER_X = ScopeQualifier("only", "folder X")
FOLDER_Y = ScopeQualifier("only", "folder Y")
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


class CraftedInputTests(unittest.TestCase):
    """The defensive branches, woken with crafted inputs.

    A guard that only ever reads clean real input is unverifiable: the
    mutant probe reported these branches as SURVIVING, because no test
    ever reached them.  They are reachable -- measured one by one below --
    and simply untested.
    """

    def test_a_verb_longer_than_the_cap_is_refused(self):
        import scope_qualifier

        with self.assertRaises(scope_qualifier.MalformedGrantError):
            scope_qualifier.canonical_verb("v" * (scope_qualifier._MAX_ID_CHARS + 1))

    def test_a_verb_exactly_at_the_cap_is_accepted(self):
        import scope_qualifier

        value = "v" * scope_qualifier._MAX_ID_CHARS
        self.assertEqual(scope_qualifier.canonical_verb(value), value)

    def test_a_scope_with_no_verb_half_is_read_as_written(self):
        """A scope with no ``/`` is not a grant/verb scope; guessing at it
        would be worse than reading it as written."""
        import scope_qualifier

        self.assertEqual(scope_qualifier.canonical_scope_key("bare-scope"),
                         "bare-scope")

    def test_a_scope_with_an_uncanonicalisable_verb_half_is_read_as_written(self):
        import scope_qualifier

        self.assertEqual(scope_qualifier.canonical_scope_key("grant-1/"),
                         "grant-1/")

    def test_the_scope_key_canonicalises_only_the_verb_half(self):
        import scope_qualifier

        self.assertEqual(
            scope_qualifier.canonical_scope_key("Grant-1/Lookup"),
            "Grant-1/lookup",
            "the grant id half is an identifier and is kept verbatim",
        )

    def test_a_non_string_scope_is_refused(self):
        import scope_qualifier

        with self.assertRaises(scope_qualifier.MalformedGrantError):
            scope_qualifier.canonical_scope_key(None)

    def test_an_empty_scope_is_refused(self):
        import scope_qualifier

        with self.assertRaises(scope_qualifier.MalformedGrantError):
            scope_qualifier.canonical_scope_key("   ")

    def test_the_row_store_rejects_a_row_that_is_not_a_row(self):
        from scope_qualifier import DenialRowStore, MalformedGrantError

        with self.assertRaises(MalformedGrantError):
            DenialRowStore().put("not a row")

    def test_the_row_store_reads_a_broken_store_as_unreadable(self):
        from scope_qualifier import DenialRowStore, ScopeSourceError

        store = DenialRowStore()
        store.break_reads()
        with self.assertRaises(ScopeSourceError):
            store.fetch("grant-1/lookup")

    def test_the_row_store_refuses_an_empty_scope(self):
        from scope_qualifier import DenialRowStore, ScopeSourceError

        with self.assertRaises(ScopeSourceError):
            DenialRowStore().fetch("")

    def test_a_grant_with_a_non_int_counter_is_refused(self):
        with self.assertRaises(Exception):
            GrantRecord(grant_id="grant-1", verb="write", counter="3")

    def test_a_grant_with_a_bool_counter_is_refused(self):
        with self.assertRaises(Exception):
            GrantRecord(grant_id="grant-1", verb="write", counter=True)

    def test_a_grant_with_a_negative_counter_is_refused(self):
        with self.assertRaises(Exception):
            GrantRecord(grant_id="grant-1", verb="write", counter=-1)

    def test_a_row_with_an_empty_scope_is_refused(self):
        with self.assertRaises(Exception):
            DenialRow(scope="  ", kind=ROW_CLEAR, signature="sig-1")

    def test_a_row_that_does_not_deny_does_not_deny(self):
        self.assertFalse(DenialRow(scope="grant-1/lookup", kind=ROW_CLEAR,
                                   signature="sig-1").denies())
        self.assertTrue(DenialRow(scope="grant-1/lookup", kind=ROW_DENIED).denies())

    def test_the_registry_accepts_no_grants_at_all(self):
        from scope_qualifier import ScopeGrantRegistry

        registry = ScopeGrantRegistry()
        self.assertEqual(registry.presented(), ())
        self.assertEqual(registry.presented_for("write"), ())

    def test_the_row_store_accepts_no_rows_at_all(self):
        from scope_qualifier import DenialRowStore

        self.assertEqual(len(DenialRowStore()), 0)

    def test_the_presented_lookup_refuses_a_non_string_verb(self):
        from scope_qualifier import ScopeGrantRegistry

        registry = ScopeGrantRegistry()
        with self.assertRaises(Exception):
            registry.presented_for(None)


class GrantGuardTests(unittest.TestCase):
    """The guards on the grant record, woken with crafted inputs.

    These are the guards on the method the slice edited
    (``GrantRecord.__post_init__``).  The mutant probe reported several of
    them as SURVIVING: no test ever reached them.  Each one below is
    measured -- it names the guard it kills and what breaks without it.
    """

    def test_a_grant_with_a_blank_grant_id_is_refused(self):
        """Kills the ``grant_id`` half of the guard.

        Without it, a grant with no id could be built, and the denial-row
        scope it names would start with a bare ``/`` -- a scope that
        matches every verb.
        """
        with self.assertRaises(MalformedGrantError):
            GrantRecord(grant_id="   ", verb="write")

    def test_a_grant_with_an_over_long_grant_id_is_refused(self):
        """Kills the ``grant_id`` length guard."""
        with self.assertRaises(MalformedGrantError):
            GrantRecord(grant_id="g" * 257, verb="write")

    def test_a_grant_id_exactly_at_the_cap_is_accepted(self):
        """The boundary the length guard turns on.

        The guard is ``>`` the cap, so an id of exactly the cap's length is
        legal.  Without this boundary a stricter guard would go unnoticed.
        """
        import scope_qualifier

        cap = scope_qualifier._MAX_ID_CHARS
        record = GrantRecord(grant_id="g" * cap, verb="write")
        self.assertEqual(len(record.grant_id), cap)

    def test_a_grant_with_a_non_string_verb_is_refused(self):
        """Kills the verb half of the type guard.

        Without it, ``canonical_verb`` would be handed a non-string and
        the record would carry an unusable verb -- and the *lookup* side
        (``canonical_verb(grant.verb)``) would raise at read time, inside
        the gate, instead of at construction.
        """
        with self.assertRaises(MalformedGrantError):
            GrantRecord(grant_id="grant-1", verb=None)

    def test_a_grant_with_a_blank_verb_is_refused(self):
        """Kills the blank half of the verb guard.

        A blank verb canonicalises to the empty string, and an empty verb
        would name *every* action -- so it must never become a record.
        """
        with self.assertRaises(MalformedGrantError):
            GrantRecord(grant_id="grant-1", verb="   ")

    def test_a_grant_with_a_non_string_source_ref_is_refused(self):
        with self.assertRaises(MalformedGrantError):
            GrantRecord(grant_id="grant-1", verb="write", source_ref=17)

    def test_a_grant_with_a_bool_counter_is_refused(self):
        """Kills the ``counter`` type guard.

        ``True`` is an ``int`` in Python, so without the bool half a
        ``True`` counter would be accepted as the counter ``1``.
        """
        with self.assertRaises(MalformedGrantError):
            GrantRecord(grant_id="grant-1", verb="write", counter=True)

    def test_a_grant_with_a_non_int_counter_is_refused(self):
        with self.assertRaises(MalformedGrantError):
            GrantRecord(grant_id="grant-1", verb="write", counter="3")

    def test_a_grant_with_a_negative_counter_is_refused(self):
        """Kills the ``counter < 0`` guard.

        A negative counter is a version *before* the grant was issued;
        without the guard the gate would accept a pin that predates the
        grant it claims to pin.
        """
        with self.assertRaises(MalformedGrantError):
            GrantRecord(grant_id="grant-1", verb="write", counter=-1)

    def test_a_grant_with_a_zero_counter_is_accepted(self):
        """The boundary: ``0`` is a legal counter, and the guard is ``< 0``."""
        record = GrantRecord(grant_id="grant-1", verb="write", counter=0)
        self.assertEqual(record.counter, 0)

    def test_a_grant_with_no_counter_is_accepted(self):
        record = GrantRecord(grant_id="grant-1", verb="write")
        self.assertIsNone(record.counter)

    def test_a_grant_with_a_non_mapping_payload_is_refused(self):
        with self.assertRaises(MalformedGrantError):
            GrantRecord.from_dict("not a mapping")

    def test_a_grant_with_a_string_qualifier_list_is_refused(self):
        """Kills the ``qualifiers must be a list`` guard.

        A string is iterable, so without the guard ``"folder X"`` would
        be read as a list of *characters* as qualifiers.
        """
        with self.assertRaises(MalformedGrantError):
            GrantRecord.from_dict({
                "grant_id": "grant-1",
                "verb": "write",
                "qualifiers": "folder X",
            })

    def test_a_grant_with_a_mapping_qualifier_list_is_refused(self):
        """Kills the *other* half of the same guard.

        The guard has two halves -- "it is a string" and "it is not a
        list/tuple".  A mapping is neither, so only the second half
        refuses it.

        The *message* is asserted, not just the exception type: a mapping
        that slips past this guard raises a different
        ``MalformedGrantError`` downstream (while it is iterated), so the
        type alone would not distinguish "refused by the guard" from
        "refused later by accident".
        """
        with self.assertRaises(MalformedGrantError) as caught:
            GrantRecord.from_dict({
                "grant_id": "grant-1",
                "verb": "write",
                "qualifiers": {"kind": "only"},
            })
        self.assertIn("qualifiers must be a list", str(caught.exception))

    def test_a_grant_with_a_string_qualifier_list_is_refused_by_the_guard(self):
        """The same, for the string half of the guard."""
        with self.assertRaises(MalformedGrantError) as caught:
            GrantRecord.from_dict({
                "grant_id": "grant-1",
                "verb": "write",
                "qualifiers": "folder X",
            })
        self.assertIn("qualifiers must be a list", str(caught.exception))

    def test_a_grant_with_no_qualifiers_is_accepted(self):
        record = GrantRecord.from_dict({
            "grant_id": "grant-1",
            "verb": "Write",
        })
        self.assertEqual(record.verb, "write")
        self.assertEqual(record.qualifiers, ())


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


class ScopeQualifierCommonGuardTests(unittest.TestCase):
    """The guards both scope-qualifier slices share, woken with crafted
    inputs.

    ``scope-verb-canonical`` and ``diviner`` read the SAME module, so the
    same planted faults survive BOTH suites.  This class drives the arm
    of each guard that neither suite drove, and it is added to BOTH test
    files so that each slice's own census -- the one that measures *that*
    slice's tests -- sees the kill.

    Each test names the mutant it kills.  The technique is always the
    same: the guard has two arms and the suite drove one of them, so the
    test drives the other.

      or@274   ``not isinstance(self.kind, str) or
               not self.kind.strip()``        -- the EMPTINESS half
      or@276   the same for the resource
      gt@278   ``len(self.kind) > _MAX_SCOPE_CHARS``  -- the bound
      gt@280   ``len(self.resource) > _MAX_SCOPE_CHARS``
      or@303   ``str(value.get("note", "") or "")``    -- the DEFAULTING half
      gt@334   ``len(self.grant_id) > _MAX_ID_CHARS``  -- the bound
      or@336   ``not isinstance(self.verb, str) or
               not self.verb.strip()``         -- the TYPE half
      or@349   ``isinstance(self.counter, bool) or
               not isinstance(self.counter, int)``     -- the BOOL half
      lt@351   ``self.counter < 0``            -- the bound
      or@368   ``value.get("qualifiers") or ()``       -- the DEFAULTING half
      or@369   ``isinstance(quals, (str, bytes)) or
               not isinstance(quals, (list, tuple))``   -- the "not a list" half
      retF@455 ``_is_wildcard``'s ``return False``
      or@483   the source line's source_ref guard -- the EMPTINESS half
      or@485   the source line's grant_id guard  -- the EMPTINESS half
      or@516   ``value.get("qualifiers") or ()``       -- the DEFAULTING half
      or@517   the source line's qualifier-list guard -- the "not a list" half
      or@575   ``not isinstance(source_ref, str) or not source_ref``
               -- the EMPTINESS half
      eq@661   ``presented_targets == source_targets``
      eq@662   ``presented_atoms == source_atoms``
      or@746   the fallback's grant_id guard   -- the EMPTINESS half
      or@748   the fallback's scope_text guard -- the EMPTINESS half
      or@752   the fallback's int guard         -- the BOOL half
      or@759   the fallback clock's int guard   -- the BOOL half
      or@782   the fallback mapping's source_ref defaulting half
      or@783   the fallback mapping's reason defaulting half
      or@870   ``not isinstance(text, str) or not text``  -- the TYPE half
      and@888  ``isinstance(compacted_text, str) and
               REMOVAL_MARKER in compacted_text.lower()`` -- the TYPE half
      or@927   the gate's TTL int guard          -- the BOOL half
      or@983   the gate's clock int guard        -- the BOOL half
      or@1054  ``row.reason or 'denial row'``    -- the DEFAULTING half
      eq@1328  ``canonical_verb(grant.verb) == canonical``
      or@1396  the denial row's scope guard      -- the EMPTINESS half
      or@1483  ``not isinstance(scope, str) or not scope``
               -- the EMPTINESS half
      or@1550  the boundary check's sequence guard -- the "not a list" half
      eq@1618  ``if self.rounds == 0`` in ``grant_survival``
      eq@1625  the same in ``qualifier_survival``
      eq@1632  the same in ``widening_rate``
      eq@1639  ``if self.widened == 0`` in ``caught_rate``
      or@1682  the measure's sequence guard       -- the "not a list" half
      or@1684  the measure's rounds guard        -- the BOOL half
      lt@1684  the measure's ``rounds < 1`` bound
      eq@1696  ``drops = (index + round_index) % 3 == 0``
      and@1697 ``if drops and grant.qualifiers``
      and@1714 ``if check is not None and check.blocked``
      or@1744  the audit event's kind guard      -- the EMPTINESS half
      or@1746  the audit event's seq guard       -- the BOOL half
      lt@1746  the audit event's ``seq < 0`` bound
    """

    # -- the qualifier record's guards ----------------------------------

    def test_a_whitespace_only_kind_is_refused(self):
        """or@274: the EMPTINESS half of the kind guard.

        A kind that is a string but holds only whitespace names nothing,
        so it must be refused: the type half cannot see it.
        """
        with self.assertRaises(MalformedGrantError):
            ScopeQualifier(kind="   ", resource="the China segment")

    def test_a_whitespace_only_resource_is_refused(self):
        """or@276: the EMPTINESS half of the resource guard."""
        with self.assertRaises(MalformedGrantError):
            ScopeQualifier(kind="only", resource="\t\n ")

    def test_a_kind_at_the_character_limit_is_accepted(self):
        """gt@278: the bound on the kind is STRICT.

        A kind of exactly the cap's length is inside it.  Under the
        planted fault (``>`` -> ``>=``) it would be refused.
        """
        from scope_qualifier import _MAX_SCOPE_CHARS

        kind = "k" * _MAX_SCOPE_CHARS
        qualifier = ScopeQualifier(kind=kind, resource="segment")
        self.assertEqual(qualifier.kind, kind)

    def test_a_resource_at_the_character_limit_is_accepted(self):
        """gt@280: the bound on the resource is STRICT."""
        from scope_qualifier import _MAX_SCOPE_CHARS

        resource = "r" * _MAX_SCOPE_CHARS
        qualifier = ScopeQualifier(kind="only", resource=resource)
        self.assertEqual(qualifier.resource, resource)

    def test_a_null_note_becomes_the_empty_string(self):
        """or@303: the DEFAULTING half of the note guard.

        ``str(value.get("note", "") or "")`` -- the ``or ""`` is the half
        under test.  A note of None must become the empty string; with
        the connective flipped to ``and``, None would reach ``str()``
        and become the literal text "None", which is a note the grant
        never had.
        """
        qualifier = ScopeQualifier.from_dict(
            {"kind": "only", "resource": "segment", "note": None}
        )
        self.assertEqual(qualifier.note, "")
        self.assertNotEqual(qualifier.note, "None")

    def test_a_missing_note_becomes_the_empty_string(self):
        """or@303: the same, for an ABSENT note."""
        qualifier = ScopeQualifier.from_dict(
            {"kind": "only", "resource": "segment"}
        )
        self.assertEqual(qualifier.note, "")

    # -- the grant record's guards --------------------------------------

    def test_a_grant_id_at_the_character_limit_is_accepted(self):
        """gt@334: the bound on the grant id is STRICT."""
        from scope_qualifier import _MAX_ID_CHARS

        record = GrantRecord(grant_id="g" * _MAX_ID_CHARS, verb="write")
        self.assertEqual(len(record.grant_id), _MAX_ID_CHARS)

    def test_a_grant_with_a_non_string_verb_is_refused(self):
        """or@336: the TYPE half of the verb guard.

        Without it the guard is skipped and the record's own
        canonicalisation is handed a non-string, so the refusal
        arrives as an ``AttributeError`` (no ``strip``) rather than as
        the ``MalformedGrantError`` the record's contract promises.
        The *type* is asserted, not just "some exception".
        """
        with self.assertRaises(MalformedGrantError):
            GrantRecord(grant_id="grant-1", verb=None)

    def test_a_grant_with_a_bool_counter_is_refused(self):
        """or@349: the BOOL half of the counter guard.

        ``True`` IS an ``int`` in Python, so the "not an int" half never
        refuses a boolean -- only the explicit ``bool`` half does.
        """
        with self.assertRaises(MalformedGrantError):
            GrantRecord(grant_id="grant-1", verb="write", counter=True)

    def test_a_grant_with_a_zero_counter_is_accepted(self):
        """lt@351: the bound on the counter is STRICT.

        ``0`` is a legal counter, so the bound is ``counter < 0``.  Under
        the planted fault (``<`` -> ``<=``) a zero counter would be
        refused -- the first grant ever issued would be unbuildable.
        """
        record = GrantRecord(grant_id="grant-1", verb="write", counter=0)
        self.assertEqual(record.counter, 0)

    def test_a_grant_with_no_qualifiers_key_is_accepted(self):
        """or@368: the DEFAULTING half of the qualifier-list read.

        ``quals = value.get("qualifiers") or ()`` -- the ``or ()`` is the
        half under test.  A mapping with no ``qualifiers`` key must build
        a grant with an empty fence; with the connective flipped to
        ``and`` the None would fall through to the type guard and the
        grant would be refused for a field it never mentioned.
        """
        record = GrantRecord.from_dict({
            "grant_id": "grant-1",
            "verb": "write",
        })
        self.assertEqual(record.qualifiers, ())

    def test_a_grant_with_a_mapping_qualifier_list_is_refused(self):
        """or@369: the "not a list/tuple" half of the guard.

        The *message* is asserted, not just the exception type: with
        the connective flipped to ``and`` the mapping slips past the
        guard and is then iterated key by key, and the refusal arrives
        later from a different guard with a different message ("a
        qualifier must be a mapping").  The type alone would not
        distinguish "refused by this guard" from "refused later by
        accident".
        """
        with self.assertRaises(MalformedGrantError) as caught:
            GrantRecord.from_dict({
                "grant_id": "grant-1",
                "verb": "write",
                "qualifiers": {"kind": "only"},
            })
        self.assertIn("qualifiers must be a list", str(caught.exception))

    # -- the wildcard check ---------------------------------------------

    def test_an_empty_resource_is_not_the_unbounded_scope(self):
        """retF@455: the ``return False`` of the wildcard check.

        ``_is_wildcard`` answers "does this resource name everything?".
        An empty resource names nothing, so the answer is False.  Under
        the planted fault (``return False`` -> ``return True``) an empty
        resource would read as the unbounded scope -- the widest fence
        there is -- the opposite of the fail-closed rule.
        """
        from scope_qualifier import _is_wildcard

        self.assertFalse(_is_wildcard(""))
        self.assertFalse(_is_wildcard("   "))
        self.assertTrue(_is_wildcard("all folders"))
        self.assertFalse(_is_wildcard("folder X"))

    # -- the source line's guards ---------------------------------------

    def test_a_source_line_with_a_blank_source_ref_is_refused(self):
        """or@483: the EMPTINESS half of the source_ref guard."""
        with self.assertRaises(MalformedGrantError):
            SourceLine(source_ref="   ", grant_id="grant-1")

    def test_a_source_line_with_a_blank_grant_id_is_refused(self):
        """or@485: the EMPTINESS half of the source line's grant_id guard."""
        with self.assertRaises(MalformedGrantError):
            SourceLine(source_ref="src-1", grant_id="   ")

    def test_a_source_line_with_no_qualifiers_key_is_accepted(self):
        """or@516: the DEFAULTING half of the qualifier-list read.

        The same shape as the grant's or@368: a mapping that does not
        mention ``qualifiers`` must build a source line with an empty
        fence, not be refused for a field it never mentioned.
        """
        line = SourceLine.from_dict({
            "source_ref": "src-1",
            "grant_id": "grant-1",
        })
        self.assertEqual(line.qualifiers, ())

    def test_a_source_line_with_a_mapping_qualifier_list_is_refused(self):
        """or@517: the "not a list/tuple" half of the guard.

        The *message* is asserted, not just the exception type: with
        the connective flipped to ``and`` the mapping slips past the
        guard and is then iterated key by key, and the refusal arrives
        later from a different guard with a different message.
        """
        with self.assertRaises(MalformedGrantError) as caught:
            SourceLine.from_dict({
                "source_ref": "src-1",
                "grant_id": "grant-1",
                "qualifiers": {"kind": "only"},
            })
        self.assertIn("qualifiers must be a list", str(caught.exception))

    def test_the_source_store_refuses_an_empty_source_ref(self):
        """or@575: the EMPTINESS half of the fetch guard.

        An empty source_ref names no line, so it is a *read error*
        (``ScopeSourceError``) and not a clean miss.  Under the planted
        fault the empty ref would be looked up in the map and read as
        "no such line" -- a clean read from a malformed request.
        """
        store = SourceStore()
        with self.assertRaises(ScopeSourceError):
            store.fetch("")

    # -- the scope algebra ----------------------------------------------

    def test_the_same_fence_is_equal(self):
        """eq@661 and eq@662: the equality arm of the scope algebra.

        Two fences that permit the same targets under the same
        qualifiers are ``equal``.  Under eq@661 the equality test is
        inverted and an equal pair falls through to the incomparable
        answer; under eq@662 the atom test is inverted and the equal
        pair reads as ``narrower``.  Both would let a grant that stands
        as authorized be re-scoped instead.
        """
        self.assertEqual(scope_relation((FOLDER_X,), (FOLDER_X,)), "equal")

    def test_the_same_targets_under_a_different_qualifier_is_narrower(self):
        """eq@662: the second equality, on the ATOMS.

        The same permitted targets under a different qualifier are
        ``narrower`` -- the presented fence asks for no more, so it may
        run.  Under the inverted atom test this pair would read as
        ``equal``, which would let a presented fence that adds a
        restriction be reported as standing exactly as authorized.
        """
        self.assertEqual(
            scope_relation((ScopeQualifier("per", "folder X"),), (FOLDER_X,)),
            "narrower",
        )

    # -- the fallback's guards ------------------------------------------

    def test_a_fallback_with_an_empty_grant_id_is_refused(self):
        """or@746: the EMPTINESS half of the fallback's grant_id guard."""
        with self.assertRaises(MalformedGrantError):
            ScopeFallback(
                grant_id="", scope_text="folder X only", issued_at=0, expires_at=10
            )

    def test_a_fallback_with_an_empty_scope_text_is_refused(self):
        """or@748: the EMPTINESS half of the fallback's scope_text guard."""
        with self.assertRaises(MalformedGrantError):
            ScopeFallback(
                grant_id="grant-1", scope_text="", issued_at=0, expires_at=10
            )

    def test_a_fallback_with_a_boolean_issued_at_is_refused(self):
        """or@752: the BOOL half of the fallback's int guard.

        ``True`` IS an ``int`` in Python, so the "not an int" half never
        refuses a boolean -- only the explicit ``bool`` half does.  Under
        the planted fault a boolean clock would be accepted and used as
        the integer 1.
        """
        with self.assertRaises(MalformedGrantError):
            ScopeFallback(
                grant_id="grant-1", scope_text="folder X only",
                issued_at=True, expires_at=10,
            )

    def test_the_fallback_clock_refuses_a_boolean_now(self):
        """or@759: the BOOL half of the clock's int guard."""
        fallback = ScopeFallback(
            grant_id="grant-1", scope_text="folder X only",
            issued_at=0, expires_at=10,
        )
        with self.assertRaises(MalformedGrantError):
            fallback.is_expired(True)

    def test_a_fallback_mapping_defaults_its_source_ref(self):
        """or@782: the DEFAULTING half of the source_ref read.

        A source_ref that is explicitly None must become the empty
        string.  Under the planted fault (``or`` -> ``and``) the None
        would reach ``str()`` and become the literal text "None" -- a
        source ref the fallback never had.
        """
        fallback = ScopeFallback.from_dict({
            "grant_id": "grant-1",
            "scope_text": "folder X only",
            "issued_at": 0,
            "expires_at": 10,
            "source_ref": None,
        })
        self.assertEqual(fallback.source_ref, "")
        self.assertNotEqual(fallback.source_ref, "None")

    def test_a_fallback_mapping_defaults_its_reason(self):
        """or@783: the DEFAULTING half of the reason read."""
        fallback = ScopeFallback.from_dict({
            "grant_id": "grant-1",
            "scope_text": "folder X only",
            "issued_at": 0,
            "expires_at": 10,
            "reason": None,
        })
        self.assertEqual(fallback.reason, "")
        self.assertNotEqual(fallback.reason, "None")

    # -- the qualifier diff ---------------------------------------------

    def test_the_scope_tokens_of_a_non_string_are_empty(self):
        """or@870: the TYPE half of the scope-token guard.

        A non-string names no scope tokens, so the answer is the empty
        tuple.  Under the planted fault the guard is skipped and the
        token regex is handed a non-string, which raises a TypeError
        instead of returning "no tokens".
        """
        self.assertEqual(scope_tokens(5), ())
        self.assertEqual(scope_tokens(None), ())
        self.assertEqual(scope_tokens(""), ())

    def test_a_diff_against_a_non_string_compaction_is_not_an_error(self):
        """and@888: the TYPE half of the removal-note guard.

        The guard reads the compacted text's own spelling for the
        removal marker.  When the compacted text is not a string there
        is no spelling to read, so nothing is noted -- and the diff is
        still a diff.  Under the planted fault (``and`` -> ``or``) the
        second half runs on a non-string and raises AttributeError.
        """
        diff = diff_qualifiers("write to folder X only", None)
        self.assertEqual(diff.dropped, ("only",))
        self.assertEqual(diff.noted, ())
        self.assertEqual(diff.lost, ("only",))

    # -- the gate's guards ----------------------------------------------

    def test_the_gate_refuses_a_boolean_fallback_ttl(self):
        """or@927: the BOOL half of the TTL guard.

        ``True`` IS an ``int`` in Python, so without the explicit bool
        half a boolean TTL would be accepted as the TTL 1 -- a one
        second fallback, which expires before it can be used.
        """
        with self.assertRaises(ScopeQualifierError):
            ScopeQualifierGate(SourceStore(), fallback_ttl_seconds=True)

    def test_the_gate_refuses_a_boolean_now(self):
        """or@983: the BOOL half of the clock's int guard."""
        gate = ScopeQualifierGate(SourceStore())
        with self.assertRaises(ScopeQualifierError):
            gate.check(
                GrantRecord(
                    grant_id="grant-1", verb="write",
                    qualifiers=(FOLDER_X,), source_ref="src-1",
                ),
                now=True,
            )

    def test_a_denied_row_without_a_reason_still_names_the_denial(self):
        """or@1054: the DEFAULTING half of the denial reason.

        A denial row may carry no reason of its own; the gate still has
        to say that the scope is refused.  Under the planted fault
        (``or`` -> ``and``) the reason would be silently empty and the
        audit trail would not say what refused the scope.
        """
        store = SourceStore([
            SourceLine(
                source_ref="src-1", grant_id="grant-1", qualifiers=(FOLDER_X,)
            )
        ])
        rows = DenialRowStore([
            DenialRow(scope="grant-1/write", kind=ROW_DENIED)
        ])
        gate = ScopeQualifierGate(store, denial_rows=rows)
        check = gate.check(
            GrantRecord(
                grant_id="grant-1", verb="write",
                qualifiers=(FOLDER_X,), source_ref="src-1",
            ),
            now=0,
        )
        self.assertTrue(check.blocked)
        self.assertIn("denial row", check.reason)

    # -- the presented-grant lookup -------------------------------------

    def test_the_presented_lookup_finds_only_the_asked_verb(self):
        """eq@1328: the equality of the presented-grant lookup.

        The lookup answers "which presented grants authorize this
        verb?".  A grant that authorizes a DIFFERENT verb must not be
        in the answer.  Under the planted fault (``==`` -> ``!=``) the
        lookup would return exactly the grants that do NOT match.
        """
        from scope_qualifier import ScopeGrantRegistry

        registry = ScopeGrantRegistry()
        registry.present(GrantRecord(grant_id="grant-1", verb="write"))
        registry.present(GrantRecord(grant_id="grant-2", verb="read"))
        found = registry.presented_for("write")
        self.assertEqual([g.grant_id for g in found], ["grant-1"])
        self.assertEqual(registry.presented_for("read")[0].grant_id, "grant-2")

    # -- the denial row's guards ----------------------------------------

    def test_a_denial_row_with_a_blank_scope_is_refused(self):
        """or@1396: the EMPTINESS half of the row's scope guard.

        A scope that holds only whitespace names no scope, so the row
        must be refused: the type half cannot see it.
        """
        with self.assertRaises(MalformedGrantError):
            DenialRow(scope="   ", kind=ROW_CLEAR, signature="sig-1")

    def test_the_row_store_refuses_an_empty_scope(self):
        """or@1483: the EMPTINESS half of the row store's fetch guard.

        An empty scope names no row, so it is a *read error*
        (``ScopeSourceError``) and not a clean miss.  Under the planted
        fault the empty scope would be looked up in the map and read as
        "no such row" -- a clean read from a malformed request, and the
        gate would answer ``outcome_unknown`` for the wrong reason.
        """
        store = DenialRowStore()
        with self.assertRaises(ScopeSourceError):
            store.fetch("")

    # -- the compaction boundary ----------------------------------------

    def test_the_boundary_check_refuses_a_mapping_of_grants(self):
        """or@1550: the "not a list/tuple" half of the guard.

        The *message* is asserted, not just the exception type: with
        the connective flipped to ``and`` the mapping slips past the
        guard and is then iterated key by key, and the refusal arrives
        from a different guard with a different message.
        """
        with self.assertRaises(ScopeQualifierError) as caught:
            check_compaction_boundary({"grant-1": object()})
        self.assertIn("grants must be a sequence", str(caught.exception))

    # -- the survival measure -------------------------------------------

    def test_the_grant_survival_rate_is_the_share_that_survived(self):
        """eq@1618: the zero-round guard of ``grant_survival``.

        ``grant_survival`` reports 1.0 when NO round was measured (there
        is nothing to lose).  When a round WAS measured the rate is the
        share that survived.  Under the planted fault (``==`` -> ``!=``)
        the guard would fire on every measured round and report 1.0
        whatever happened -- exactly the "nothing was lost" reading the
        measure exists to disprove.
        """
        metrics = SurvivalMetrics(rounds=1, grants_in=2, grants_out=1)
        self.assertEqual(metrics.grant_survival, 0.5)

    def test_the_qualifier_survival_rate_is_the_share_that_survived(self):
        """eq@1625: the zero-round guard of ``qualifier_survival``."""
        metrics = SurvivalMetrics(rounds=1, qualifiers_in=2, qualifiers_out=1)
        self.assertEqual(metrics.qualifier_survival, 0.5)

    def test_the_widening_rate_is_the_share_that_widened(self):
        """eq@1632: the zero-round guard of ``widening_rate``."""
        metrics = SurvivalMetrics(rounds=1, grants_in=2, widened=1)
        self.assertEqual(metrics.widening_rate, 0.5)

    def test_the_caught_rate_is_the_share_of_the_widenings_caught(self):
        """eq@1639: the zero-widenings guard of ``caught_rate``.

        ``caught_rate`` reports 1.0 when nothing widened (there was
        nothing to catch).  When widenings happened, the rate is the
        share of them the gate caught.  Under the planted fault
        (``==`` -> ``!=``) the guard would fire whenever widenings
        existed and report 1.0 -- claiming every widening was caught
        when some were not.
        """
        metrics = SurvivalMetrics(rounds=1, widened=2, caught=1)
        self.assertEqual(metrics.caught_rate, 0.5)

    def test_the_measure_refuses_a_mapping_of_grants(self):
        """or@1682: the "not a list/tuple" half of the measure's guard.

        The *message* is asserted, not just the exception type: with
        the connective flipped to ``and`` the mapping slips past the
        guard and is then iterated key by key, and the refusal arrives
        from a different guard with a different message.
        """
        with self.assertRaises(ScopeQualifierError) as caught:
            measure_qualifier_survival({"grant-1": object()})
        self.assertIn("grants must be a sequence", str(caught.exception))

    def test_the_measure_refuses_a_boolean_round_count(self):
        """or@1684: the BOOL half of the round-count guard.

        ``True`` IS an ``int`` in Python, so without the explicit bool
        half a boolean round count would be accepted as one round.
        """
        with self.assertRaises(ScopeQualifierError):
            measure_qualifier_survival([], rounds=True)

    def test_the_measure_accepts_a_single_round(self):
        """lt@1684: the bound on the round count is STRICT.

        One round is a legal measurement, so the bound is ``rounds < 1``.
        Under the planted fault (``<`` -> ``<=``) a single round would
        be refused -- the measurement the survival tests exist to make
        could not be run at all.
        """
        metrics = measure_qualifier_survival([], rounds=1)
        self.assertEqual(metrics.rounds, 1)

    def test_the_measure_drops_the_fence_of_every_third_grant(self):
        """eq@1696 and and@1697: the deterministic rewrite.

        The simulation is deliberately deterministic: every third grant
        loses its fence.  With three grants, exactly ONE is rewritten
        and the other two keep their fences.  Under eq@1696
        (``==`` -> ``!=``) two grants would lose their fence; under
        and@1697 (``and`` -> ``or``) every grant would lose its fence,
        because a grant that still has qualifiers would be rewritten
        even when it was not the chosen one.
        """
        grants = [
            GrantRecord(
                grant_id=f"g{index}", verb="write",
                qualifiers=(FOLDER_X,), source_ref=f"s{index}",
            )
            for index in range(3)
        ]
        metrics = measure_qualifier_survival(grants, rounds=1)
        self.assertEqual(metrics.widened, 1, "exactly every third grant widens")
        self.assertEqual(metrics.qualifiers_out, 2, "the other two keep their fence")

    def test_the_measure_counts_only_the_widenings_the_gate_caught(self):
        """and@1714: the caught counter.

        A widening is caught when the gate BLOCKS the rewritten grant.
        The grants that were not rewritten were not blocked, so they
        are not widenings and must not be counted.  Under the planted
        fault (``and`` -> ``or``) every grant the gate answered at all
        would be counted as caught, and the catch rate would read 1.0
        no matter how many widenings went uncaught.
        """
        sources = [
            SourceLine(
                source_ref=f"s{index}", grant_id=f"g{index}",
                qualifiers=(FOLDER_X,),
            )
            for index in range(3)
        ]
        rows = [
            DenialRow(scope=f"g{index}/write", kind=ROW_CLEAR, signature="sig-1")
            for index in range(3)
        ]
        registry = ScopeGrantRegistry(sources=sources, rows=rows)
        grants = [
            GrantRecord(
                grant_id=f"g{index}", verb="write",
                qualifiers=(FOLDER_X,), source_ref=f"s{index}",
            )
            for index in range(3)
        ]
        metrics = measure_qualifier_survival(grants, gate=registry.gate, rounds=1)
        self.assertGreater(metrics.widened, 0)
        self.assertEqual(metrics.caught, metrics.widened, "every widening is caught")
        self.assertEqual(metrics.caught_rate, 1.0)

    # -- the audit event -----------------------------------------------

    def test_the_audit_event_refuses_an_empty_kind(self):
        """or@1744: the EMPTINESS half of the audit kind guard.

        An empty kind is not one of the module's audit kinds, so the
        event must be refused.  Under the planted fault the guard is
        skipped and an event with an unnamed kind is emitted -- a record
        no reader can route.
        """
        check = ScopeCheck(
            grant_id="grant-1", blocked=True, outcome=OUTCOME_MISMATCH
        )
        with self.assertRaises(ScopeQualifierError):
            scope_audit_event("", check)

    def test_the_audit_event_accepts_a_zero_sequence(self):
        """lt@1746: the bound on the audit sequence is STRICT.

        Sequence 0 is the first record of a stream, so it is legal: the
        bound is ``seq < 0``.  Under the planted fault (``<`` -> ``<=``)
        the first record of every stream would be refused.
        """
        check = ScopeCheck(
            grant_id="grant-1", blocked=True, outcome=OUTCOME_MISMATCH
        )
        event = scope_audit_event(KIND_CHECKED, check, seq=0)
        self.assertEqual(event["seq"], 0)

    def test_the_audit_event_refuses_a_boolean_sequence(self):
        """or@1746: the BOOL half of the audit sequence guard.

        ``True`` IS an ``int`` in Python, so without the explicit bool
        half a boolean sequence would be accepted as the sequence 1.
        """
        check = ScopeCheck(
            grant_id="grant-1", blocked=True, outcome=OUTCOME_MISMATCH
        )
        with self.assertRaises(ScopeQualifierError):
            scope_audit_event(KIND_CHECKED, check, seq=True)


class ScopeRelationEquivalenceTests(unittest.TestCase):
    """Two EQUIVALENT mutants in ``scope_relation``, proved rather than
    asserted.

    The scope algebra compares the two fences' *permitted target sets*::

        if presented_targets == source_targets:   # eq@661
            if presented_atoms == source_atoms:   # eq@662
                return SCOPE_EQUAL
            return SCOPE_NARROWER
        if presented_targets < source_targets:    # lt@667
            return SCOPE_NARROWER
        if presented_targets > source_targets:    # gt@669
            return SCOPE_WIDER
        return SCOPE_INCOMPARABLE

    The two comparisons at lt@667 and gt@669 are reached **only** when
    the equality test above them has already failed -- i.e. only when
    the two target sets are DIFFERENT.  For two different sets ``P < S``
    and ``P <= S`` agree (they differ only when ``P == S``), and so do
    ``P > S`` and ``P >= S``.  The planted faults are therefore
    EQUIVALENT mutants: no input can distinguish them.

    Equivalence is not asserted here, it is MEASURED.  The sweep below
    enumerates every subset of a four-element universe -- every pair of
    target sets there is, in that universe -- and compares the two
    spellings of each comparison directly.  The counts are pinned too,
    so a later edit that shrinks the sweep's coverage is visible.
    """

    #: The universe the sweep runs over.
    UNIVERSE = ("a", "b", "c", "d")

    def _all_target_sets(self):
        import itertools

        sets = []
        for size in range(len(self.UNIVERSE) + 1):
            for combo in itertools.combinations(self.UNIVERSE, size):
                sets.append(frozenset(combo))
        return sets

    def test_the_subset_comparison_is_equivalent_to_the_non_strict_one(self):
        """lt@667: the differential sweep that proves the equivalence.

        For every pair of DIFFERENT target sets, the strict subset test
        and the non-strict one must agree.  The count of disagreements
        is zero, so the planted fault cannot change the relation at any
        input.
        """
        sets = self._all_target_sets()
        disagreements = 0
        compared = 0
        for presented in sets:
            for source in sets:
                if presented == source:
                    continue
                compared += 1
                if (presented < source) != (presented <= source):
                    disagreements += 1
        self.assertEqual(disagreements, 0)
        self.assertEqual(compared, len(sets) * (len(sets) - 1))

    def test_the_superset_comparison_is_equivalent_to_the_non_strict_one(self):
        """gt@669: the differential sweep that proves the equivalence."""
        sets = self._all_target_sets()
        disagreements = 0
        compared = 0
        for presented in sets:
            for source in sets:
                if presented == source:
                    continue
                compared += 1
                if (presented > source) != (presented >= source):
                    disagreements += 1
        self.assertEqual(disagreements, 0)
        self.assertEqual(compared, len(sets) * (len(sets) - 1))

    def test_an_equal_target_set_is_decided_above_the_subset_comparison(self):
        """lt@667 and gt@669: the reason the sweep's precondition holds.

        The equality test at eq@661 comes FIRST, so an equal pair of
        target sets never reaches the subset or superset comparison at
        all.  That ordering is what makes the two planted faults
        equivalent, and it is pinned here so that reordering the
        algebra would be visible.
        """
        self.assertEqual(scope_relation((FOLDER_X,), (FOLDER_X,)), "equal")
        # The same permitted targets under a different qualifier: still
        # decided above the comparison.
        self.assertEqual(
            scope_relation((ScopeQualifier("per", "folder X"),), (FOLDER_X,)),
            "narrower",
        )

    def test_a_strict_subset_is_narrower_and_a_strict_superset_is_wider(self):
        """lt@667 and gt@669: the behaviour the two comparisons decide.

        A proper subset of the source's permitted targets is narrower;
        a proper superset is wider.  These are the two branches the
        equivalent mutants would have to change, and they do not.
        """
        self.assertEqual(
            scope_relation((FOLDER_X,), (FOLDER_X, FOLDER_Y)), "narrower"
        )
        self.assertEqual(
            scope_relation((FOLDER_X, FOLDER_Y), (FOLDER_X,)), "wider"
        )

if __name__ == "__main__":
    unittest.main()


class ScopeRelationEquivalenceHarnessControlTests(unittest.TestCase):
    """The ``lt@667`` / ``gt@669`` equivalence proof must be able to FAIL.

    ``ScopeRelationEquivalenceTests`` proves that the two planted faults
    in ``scope_relation`` change nothing: the strict and non-strict
    comparisons are reached only when the two target sets are already
    known to be DIFFERENT, and for two different sets the strict and
    non-strict spellings agree.

    A differential test that CANNOT fail proves nothing.  The sweep
    above SKIPS the equal pairs on purpose -- that skip is exactly the
    precondition the argument rests on, and it is also the place a
    difference would hide if the precondition ever stopped holding.

    This class gives the proof its **non-vacuity control**: the very
    same comparison, run over the pairs the sweep SKIPS, must find a
    difference.  A difference there is what licenses the "no difference
    over the different pairs" conclusion the sweep draws -- and it is
    also what shows the sweep is not skipping everything.

    A second control pins that the sweep is not vacuous in the other
    direction: it must actually COMPARE a substantial number of pairs,
    not zero.

    ``scope-verb-canonical`` and ``diviner`` read the SAME module, so
    the same planted faults survive BOTH suites.  This class is added to
    BOTH test files so that each slice's own census sees the control.
    """

    #: The universe the sweep runs over.
    UNIVERSE = ("a", "b", "c", "d")

    def _all_target_sets(self):
        import itertools

        sets = []
        for size in range(len(self.UNIVERSE) + 1):
            for combo in itertools.combinations(self.UNIVERSE, size):
                sets.append(frozenset(combo))
        return sets

    def test_the_same_comparison_finds_a_difference_on_the_skipped_pairs(self):
        """The SAME comparison, over the SKIPPED pairs, must disagree.

        The equal pairs are the ones the sweep skips.  If the strict and
        non-strict spellings agreed even there, the sweep would be
        skipping for no reason and its "no difference" result would say
        nothing.
        """
        sets = self._all_target_sets()
        differences = 0
        compared = 0
        for presented in sets:
            for source in sets:
                if presented != source:
                    continue
                compared += 1
                if (presented < source) != (presented <= source):
                    differences += 1
        self.assertGreater(compared, 0)
        self.assertGreater(
            differences,
            0,
            "the strict and non-strict comparisons agree even on the "
            "equal pairs, so the sweep's skip is not doing the work the "
            "equivalence argument claims",
        )

    def test_the_sweep_compares_a_substantial_number_of_pairs(self):
        """The sweep must actually COMPARE pairs, not zero of them."""
        sets = self._all_target_sets()
        compared = 0
        for presented in sets:
            for source in sets:
                if presented == source:
                    continue
                compared += 1
        self.assertEqual(compared, len(sets) * (len(sets) - 1))
        self.assertGreater(compared, 100)
