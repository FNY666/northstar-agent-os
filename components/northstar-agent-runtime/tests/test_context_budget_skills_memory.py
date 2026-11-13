"""The skill and auto-memory caps on the real re-injection path.

B173 fable.  After a compaction the harness puts the workspace back into
the context: the recently modified files, the skill bodies that match the
task, and the workspace auto-memory.  Each of those is *persistent*
context -- it is in every request, not in the work -- so each has a
budget:

* a skill body is capped at 5,000 tokens each and 25,000 tokens in total;
* auto-memory stops at the first 200 lines or 25KB, whichever comes first.

And every one of them is booked in the memory tax, because the tax is the
share of a run's input that was memory rather than work.  That share is
Northstar's own number; the ETH Zurich study the frontier report cites is
a comparison, not a measurement of this runtime.
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from context_budget import ContextThresholds, estimate_text_tokens
from support import RuntimeTestCase, text_turn, tool_turn
from tools import ToolRegistry, ToolResult, ToolSpec


def fat_body(tokens: int, marker: str = "k") -> str:
    return marker * (tokens * 4)


def skill_file(name: str, body: str) -> dict[str, str]:
    """A workspace skill package: ``.northstar/skills/<name>/SKILL.md``."""
    return {
        f".northstar/skills/{name}/SKILL.md": (
            "---\n"
            f"name: {name}\n"
            "description: a test skill\n"
            "---\n"
            f"{body}\n"
        )
    }


#: Workspace memory is audience-gated: absent a manifest entry, nobody may
#: read it.  The test grants it publicly, the way a host that wants the
#: memory in context would.
PUBLIC_MEMORY = {
    ".northstar/memory-audience.json": json.dumps(
        {
            "schema": "northstar.memory-audience.v1",
            "entries": {".northstar/memory/MEMORY.md": ["public"]},
        }
    )
}


def memory_file(text: str) -> dict[str, str]:
    return {**PUBLIC_MEMORY, ".northstar/memory/MEMORY.md": text}


class SkillAndMemoryCapTests(RuntimeTestCase):
    """The caps govern a real post-compaction re-injection."""

    def _drive(self, *, files: dict[str, str], thresholds=ContextThresholds()):
        workspace = self.workspace(files)
        registry = ToolRegistry()
        registry.register(
            ToolSpec(
                name="Big",
                description="returns a very large result",
                input_schema={"type": "object", "properties": {}, "additionalProperties": False},
                handler=lambda payload, _ctx: ToolResult.ok("z" * (30_000 * 4)),
                kind="read",
                is_mutating=False,
            )
        )
        provider = self.provider(
            [tool_turn("Big", {}), tool_turn("Big", {}), text_turn("done")]
        )
        runtime = self.runtime(
            provider=provider,
            workspace=workspace,
            tools=registry,
            allowed_tools=("Big",),
            compaction_threshold_tokens=600,
            compaction_keep_messages=1,
            context_thresholds=thresholds,
        )
        report = self.drive(runtime)
        return runtime, report

    # -- the skill-body cap ------------------------------------------------

    def test_a_skill_body_over_5k_tokens_is_truncated_when_re_injected(self):
        runtime, _report = self._drive(
            files=skill_file("fat", fat_body(9_000)),
        )
        skills = [record for record in runtime.context_controller.injected if record.kind == "skill"]
        self.assertTrue(skills, "the skill body must have been re-injected")
        self.assertLess(estimate_text_tokens(skills[0].text), 5_200)
        self.assertIn("truncated", skills[0].text)

    def test_the_total_skill_budget_drops_the_surplus_and_says_so(self):
        # Each skill body carries a marker unique to that skill, so the
        # skill tokens in a request can be counted exactly rather than
        # bounded loosely.  The bodies are sized under the *per-skill* cap
        # so that the *total* budget is the binding constraint here.
        markers = {f"skill-{index}": f"MK{index}!" for index in range(8)}
        files: dict[str, str] = {}
        for name, marker in markers.items():
            files.update(skill_file(name, marker * 4_000))
        runtime, _report = self._drive(files=files)
        # The budget is on the skill context the *model* carries, not on a
        # cumulative ledger: a compaction drops the previous injection, so
        # a second compaction re-injects, and the two injections are never
        # in the same request.
        for request in runtime.provider.requests:
            body = json.dumps(request.messages)
            skill_tokens = 0
            for name, marker in markers.items():
                count = body.count(marker)
                skill_tokens += (len(marker) * count) // 4
            self.assertLessEqual(
                skill_tokens,
                25_000,
                "the skill context in one request must fit the total budget",
            )
        dropped = [
            entry
            for entry in runtime.context_controller.memory_tax.entries
            if entry.get("kind") == "skill_dropped"
        ]
        self.assertTrue(dropped, "a dropped skill must be visible in the tax ledger")
        dropped_names = {entry["source"] for entry in dropped}
        self.assertEqual(dropped_names, {"skill-6", "skill-7"})

    # -- the auto-memory cap ----------------------------------------------

    def test_auto_memory_over_200_lines_is_truncated_when_re_injected(self):
        memory = "\n".join(f"memory line {index}" for index in range(500))
        files = memory_file(memory)
        runtime, _report = self._drive(files=files)
        memories = [record for record in runtime.context_controller.injected if record.kind == "memory"]
        self.assertTrue(memories, "the auto-memory must have been re-injected")
        self.assertLessEqual(len(memories[0].text.splitlines()), 200)

    def test_auto_memory_over_25kb_is_truncated_when_re_injected(self):
        # The managed-memory reader refuses a file over 32KB, so the test
        # uses a body between the 25KB auto-memory cap and that limit.
        memory = "\n".join("m" * 500 for _ in range(60))
        self.assertGreater(len(memory.encode("utf-8")), 25 * 1024)
        files = memory_file(memory)
        runtime, _report = self._drive(files=files)
        memories = [record for record in runtime.context_controller.injected if record.kind == "memory"]
        self.assertTrue(memories)
        self.assertLessEqual(len(memories[0].text.encode("utf-8")), 25 * 1024)

    # -- the memory tax ----------------------------------------------------

    def test_every_injected_block_is_booked_in_the_memory_tax(self):
        files = skill_file("fat", fat_body(9_000))
        files.update(memory_file("\n".join(f"line {i}" for i in range(300))))
        runtime, report = self._drive(files=files)
        tax = report.context["memory_tax"]
        self.assertGreater(tax["injected_tokens"], 0)
        kinds = {entry.get("kind") for entry in tax["entries"]}
        self.assertIn("skill", kinds)
        self.assertIn("memory", kinds)
        # The ratio is computable and is a share, not a percentage of a guess.
        self.assertGreater(tax["tax_ratio"], 0.0)

    def test_a_run_without_injections_reports_no_memory_tax(self):
        runtime, report = self._drive(files={})
        self.assertEqual(report.context["memory_tax"]["injected_tokens"], 0)
        self.assertEqual(report.context["memory_tax"]["tax_ratio"], 0.0)


if __name__ == "__main__":
    unittest.main()
