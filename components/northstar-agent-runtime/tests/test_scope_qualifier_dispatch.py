"""Tests for the scope-qualifier check on the real dispatch path.

B173 diviner: the check is not an isolated module.  It sits on the
dispatch path, in the same place the C54 deny hot-path lookup sits:
*before* the authorization gate decides.  These tests drive the runtime
loop end to end and assert on what actually happened -- the handler ran
or it did not.

The rules under test on the real path:

* a grant whose scope matches its source line lets the action run;
* a grant whose fence was dropped blocks the action -- the handler is
  never called;
* a widened fence blocks the action;
* a narrower grant runs under the narrower scope;
* the fallback's clock expiring blocks the action again;
* a registry that cannot be read refuses the run.
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from scope_qualifier import ROW_CLEAR, DenialRow
from support import RuntimeTestCase, tool_turn, text_turn
from loop import RuntimeConfigurationError
from tools import ToolRegistry, ToolResult, ToolSpec


FOLDER_X = {"kind": "only", "resource": "folder X"}
FOLDER_Y = {"kind": "only", "resource": "folder Y"}
ALL_FOLDERS = {"kind": "only", "resource": "all folders"}


def registry_payload(
    *,
    source_qualifiers=(FOLDER_X,),
    presented_qualifiers=(FOLDER_X,),
    verb: str = "Lookup",
    grant_id: str = "grant-1",
    include_row: bool = True,
    fallback_ttl_seconds: int = 900,
) -> dict:
    """The JSON shape the runtime's scope-registry loader reads."""
    payload = {
        "sources": [
            {
                "source_ref": "src-1",
                "grant_id": grant_id,
                "qualifiers": list(source_qualifiers),
            }
        ],
        "presented": [
            {
                "grant_id": grant_id,
                "verb": verb,
                "qualifiers": list(presented_qualifiers),
                "source_ref": "src-1",
            }
        ],
        "fallback_ttl_seconds": fallback_ttl_seconds,
    }
    if include_row:
        payload["rows"] = [
            {
                "scope": f"{grant_id}/{verb}",
                "kind": ROW_CLEAR,
                "signature": "sig-1",
            }
        ]
    return payload


class ScopeDispatchTests(RuntimeTestCase):
    """The check governs a real dispatch: the handler runs, or it does not."""

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
        return runtime, report

    # -- the two halves of the rule --------------------------------------

    def test_a_matching_scope_lets_the_action_run(self):
        """The qualifier is intact: the action proceeds."""
        effects: list = []
        path = self._write_registry(registry_payload())
        _runtime, report = self._drive(path, effects)
        self.assertEqual(effects, [{"query": "x"}], "the handler must have run")
        self.assertTrue(report.tool_calls)
        self.assertFalse(report.tool_calls[0].denied)

    def test_a_dropped_scope_blocks_the_action(self):
        """The qualifier was lost by a compaction: the action must not
        run.  This is the post's case -- a dropped "folder X only"
        converts a restriction into an apparent entitlement, and only a
        refusal closes that path."""
        effects: list = []
        path = self._write_registry(
            registry_payload(presented_qualifiers=())
        )
        _runtime, report = self._drive(path, effects)
        self.assertEqual(effects, [], "a grant with no fence must not run")
        self.assertTrue(report.tool_calls)
        self.assertTrue(report.tool_calls[0].denied)

    def test_a_widened_scope_blocks_the_action(self):
        """The grant grew from "folder X only" to everything: blocked."""
        effects: list = []
        path = self._write_registry(
            registry_payload(presented_qualifiers=(ALL_FOLDERS,))
        )
        _runtime, report = self._drive(path, effects)
        self.assertEqual(effects, [], "a widened grant must not run")
        self.assertTrue(report.tool_calls)
        self.assertTrue(report.tool_calls[0].denied)

    def test_a_narrower_scope_runs_under_the_narrower_scope(self):
        """The grant asks for less than it was given: the action runs, but
        under the narrower scope the two sides agree on."""
        effects: list = []
        path = self._write_registry(
            registry_payload(
                source_qualifiers=(FOLDER_X, FOLDER_Y),
                presented_qualifiers=(FOLDER_X,),
            )
        )
        _runtime, report = self._drive(path, effects)
        self.assertEqual(effects, [{"query": "x"}])
        self.assertFalse(report.tool_calls[0].denied)

    # -- the missing-as-a-state rules ------------------------------------

    def test_a_registry_without_a_denial_row_blocks_the_action(self):
        """Conclusion 96: the gate needs a row or a signed "no denial"
        proof.  An absent row is an unknown state, not permission."""
        effects: list = []
        path = self._write_registry(registry_payload(include_row=False))
        _runtime, report = self._drive(path, effects)
        self.assertEqual(effects, [], "a missing denial row must not read as clear")
        self.assertTrue(report.tool_calls[0].denied)

    def test_a_registry_naming_a_missing_source_blocks_the_action(self):
        """No source line to re-derive from: fail closed."""
        effects: list = []
        payload = registry_payload()
        payload["presented"][0]["source_ref"] = "src-does-not-exist"
        path = self._write_registry(payload)
        _runtime, report = self._drive(path, effects)
        self.assertEqual(effects, [])
        self.assertTrue(report.tool_calls[0].denied)

    def test_an_expired_fallback_blocks_the_action_again(self):
        """The narrowed grant must not become a permanent one: when the
        clock runs out, the action is blocked again."""
        effects: list = []
        path = self._write_registry(
            registry_payload(
                source_qualifiers=(FOLDER_X, FOLDER_Y),
                presented_qualifiers=(FOLDER_X,),
                fallback_ttl_seconds=100,
            )
        )
        clock = {"now": 1000}
        runtime = self.runtime(
            provider=self.provider(
                [tool_turn("Lookup", {"query": "x"}), text_turn("done")]
            ),
            tools=self._registry(effects),
            can_use_tool=lambda *_args: True,
            allowed_tools=("Lookup",),
            scope_registry_path=path,
            scope_clock=lambda: clock["now"],
        )
        report = self.drive(runtime)
        self.assertEqual(effects, [{"query": "x"}], "the narrowed scope runs first")
        self.assertFalse(report.tool_calls[0].denied)

        # The clock runs out: the same grant is refused now.
        clock["now"] = 1100
        effects.clear()
        runtime2 = self.runtime(
            provider=self.provider(
                [tool_turn("Lookup", {"query": "x"}), text_turn("done")]
            ),
            tools=self._registry(effects),
            can_use_tool=lambda *_args: True,
            allowed_tools=("Lookup",),
            scope_registry_path=path,
            scope_clock=lambda: clock["now"],
        )
        report2 = self.drive(runtime2)
        self.assertEqual(effects, [], "an expired fallback must block the action")
        self.assertTrue(report2.tool_calls[0].denied)

    # -- the registry itself ---------------------------------------------

    def test_the_scope_registry_is_off_by_default(self):
        runtime = self.runtime(provider=self.provider([text_turn("done")]))
        self.assertIsNone(runtime.scope_registry)

    def test_opting_in_wires_a_registry(self):
        path = self._write_registry(registry_payload())
        runtime = self.runtime(
            provider=self.provider([text_turn("done")]),
            scope_registry_path=path,
        )
        self.assertIsNotNone(runtime.scope_registry)

    def test_an_unreadable_registry_refuses_the_run(self):
        with self.assertRaises(RuntimeConfigurationError):
            self.runtime(
                provider=self.provider([text_turn("done")]),
                scope_registry_path=str(Path(self.temp_dir()) / "missing.json"),
            )

    def test_a_malformed_registry_refuses_the_run(self):
        directory = self.temp_dir()
        path = str(Path(directory) / "bad.json")
        Path(path).write_text("{not json", encoding="utf-8")
        with self.assertRaises(RuntimeConfigurationError):
            self.runtime(
                provider=self.provider([text_turn("done")]),
                scope_registry_path=path,
            )

    def test_a_non_string_registry_path_is_refused(self):
        with self.assertRaises(RuntimeConfigurationError):
            self.runtime(
                provider=self.provider([text_turn("done")]),
                scope_registry_path=123,
            )

    def test_an_unsigned_denial_row_refuses_the_run(self):
        """The registry loader must not accept an unsigned "no denial"
        row: it is a claim, not a proof."""
        payload = registry_payload()
        payload["rows"][0].pop("signature")
        path = self._write_registry(payload)
        with self.assertRaises(RuntimeConfigurationError):
            self.runtime(
                provider=self.provider([text_turn("done")]),
                scope_registry_path=path,
            )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
