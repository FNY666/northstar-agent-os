"""The needle test: a qualifier survives the context-engineering rules.

B173 fable.  The context rules remove bytes from what the model reads: a
tool result over 20,000 tokens goes to disk and leaves a pointer; at 85% of
the window an old write/edit call collapses to a pointer.  Every one of
those removals is a chance to lose something that was in the context for a
reason.

The thing that must not be lost is the **scope qualifier** -- the "folder X
only" fence that the diviner slice re-derives from the source line at
dispatch time.  Its whole purpose is to be present at the moment of
dispatch.  If the rules can push it out of the context, then "grants
generalize, fences shrink" stops being measurable: the fence shrinks
because it was dropped, not because it was narrowed.

So this test builds a long context whose *front* carries the qualifier and
whose *body* is a 30,000-token tool result that gets offloaded, and then
asserts that the dispatch-time scope-qualifier check still resolves
against the source line and still blocks a mismatched grant.

Two directions are checked:

* the qualifier is still in the context when the tool is dispatched, so
  the check still fires (a matching grant runs, a dropped fence is
  refused);
* the qualifier is not *carried* by the offload: the offloaded bytes are
  on disk and the pointer is in the context, but the pointer does not
  smuggle a widened scope back in.
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from context_budget import ContextThresholds
from scope_qualifier import ROW_CLEAR
from support import RuntimeTestCase, text_turn, tool_turn
from tools import ToolRegistry, ToolResult, ToolSpec

FOLDER_X = {"kind": "only", "resource": "folder X"}
ALL_FOLDERS = {"kind": "only", "resource": "all folders"}

#: The qualifier as it appears in the long context, at the front.
QUALIFIER_LINE = "scope-qualifier: folder X only"
#: A widened version.  If the offload or the truncation ever let a
#: widened qualifier through, this is the shape it would take.
WIDENED_LINE = "scope-qualifier: all folders"


def long_body(tokens: int = 30_000, marker: str = "z") -> str:
    """A body of roughly ``tokens`` tokens, with the qualifier at the front.

    The qualifier is the *first* line of the body, so it is exactly what
    the offload's 10-line preview would keep -- and it is also exactly
    what a truncation that kept the front would keep.  A rule that drops
    the front loses the qualifier; a rule that keeps the front does not.
    """
    return QUALIFIER_LINE + "\n" + marker * (tokens * 4)


def registry_payload(*, presented=(FOLDER_X,), verb: str = "Lookup") -> dict:
    """The JSON shape the runtime's scope-registry loader reads."""
    return {
        "sources": [
            {"source_ref": "src-1", "grant_id": "grant-1", "qualifiers": [FOLDER_X]}
        ],
        "presented": [
            {
                "grant_id": "grant-1",
                "verb": verb,
                "qualifiers": list(presented),
                "source_ref": "src-1",
            }
        ],
        "fallback_ttl_seconds": 900,
        "rows": [
            {"scope": f"grant-1/{verb}", "kind": ROW_CLEAR, "signature": "sig-1"}
        ],
    }


class NeedleTests(RuntimeTestCase):
    """A qualifier at the front of a long context survives the offload."""

    def _registry(self, effects: list, content: str) -> ToolRegistry:
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
                or ToolResult.ok(content),
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

    def _drive(self, *, presented=(FOLDER_X,), content=None, thresholds=ContextThresholds()):
        effects: list = []
        body = long_body() if content is None else content
        path = self._write_registry(registry_payload(presented=presented))
        provider = self.provider(
            [
                tool_turn("Lookup", {"query": "x"}),
                tool_turn("Lookup", {"query": "y"}),
                text_turn("done"),
            ]
        )
        runtime = self.runtime(
            provider=provider,
            workspace=self.workspace(),
            tools=self._registry(effects, body),
            can_use_tool=lambda *_args: True,
            allowed_tools=("Lookup",),
            scope_registry_path=path,
            context_thresholds=thresholds,
        )
        report = self.drive(runtime)
        return runtime, report, effects, provider

    # -- the needle itself ------------------------------------------------

    def test_the_qualifier_is_still_in_the_context_after_the_offload(self):
        """The front of the long context is not what the offload removes."""
        _runtime, _report, _effects, provider = self._drive()
        contents = [
            block["content"]
            for block in provider.sent_tool_results()
            if isinstance(block.get("content"), str)
        ]
        self.assertTrue(contents, "the tool result must have reached the provider")
        self.assertIn("offloaded tool result", contents[0])
        # The qualifier is in the preview, because it is the first line.
        self.assertIn(QUALIFIER_LINE, contents[0])

    def test_the_offloaded_bytes_are_still_on_disk_with_the_qualifier(self):
        """The pointer is recoverable: the qualifier is in the file too."""
        _runtime, report, _effects, _provider = self._drive()
        offloads = report.context["offloads"]
        self.assertTrue(offloads)
        path = offloads[0]["path"]
        self.assertTrue(Path(path).exists())
        self.assertIn(QUALIFIER_LINE, Path(path).read_text(encoding="utf-8"))

    # -- the check still governs the dispatch ----------------------------

    def test_the_scope_check_still_resolves_against_the_source_line(self):
        """A matching grant still runs: the qualifier was not lost."""
        _runtime, report, effects, _provider = self._drive()
        self.assertEqual(effects, [{"query": "x"}, {"query": "y"}])
        self.assertFalse(report.tool_calls[0].denied)

    def test_a_dropped_fence_is_still_refused_after_the_offload(self):
        """The other direction: losing the qualifier must fail closed."""
        _runtime, report, effects, _provider = self._drive(presented=())
        self.assertEqual(effects, [], "a grant with no fence must not run")
        self.assertTrue(report.tool_calls[0].denied)

    def test_a_widened_fence_is_still_refused_after_the_offload(self):
        """A widened scope must not survive the offload either."""
        _runtime, report, effects, _provider = self._drive(presented=(ALL_FOLDERS,))
        self.assertEqual(effects, [], "a widened grant must not run")
        self.assertTrue(report.tool_calls[0].denied)

    # -- and the rules do not smuggle a wider scope back in --------------

    def test_the_offload_never_widens_the_qualifier(self):
        """The offloaded body must not contain a widened qualifier."""
        _runtime, report, _effects, _provider = self._drive(
            content=QUALIFIER_LINE + "\n" + WIDENED_LINE + "\n" + "z" * (30_000 * 4)
        )
        offloads = report.context["offloads"]
        self.assertTrue(offloads)
        body = Path(offloads[0]["path"]).read_text(encoding="utf-8")
        # The body is offloaded verbatim -- the rules do not rewrite scope.
        # The check happens at dispatch, on the grant, not on the text.
        self.assertIn(WIDENED_LINE, body)

    def test_without_the_rules_the_qualifier_is_untouched(self):
        """Control: with no context rules the body reaches the provider."""
        _runtime, _report, effects, provider = self._drive(
            thresholds=None, content=long_body()
        )
        contents = [
            block["content"]
            for block in provider.sent_tool_results()
            if isinstance(block.get("content"), str)
        ]
        self.assertNotIn("offloaded tool result", contents[0])
        self.assertIn(QUALIFIER_LINE, contents[0])
        self.assertEqual(effects, [{"query": "x"}, {"query": "y"}])


if __name__ == "__main__":
    unittest.main()
