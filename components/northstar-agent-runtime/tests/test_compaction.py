import unittest

from compaction import (
    COMPACT_MARKER,
    assert_valid_conversation,
    compact_messages,
    estimate_tokens,
    find_safe_boundary,
    is_safe_boundary,
)
from helpers import make_runtime
from loop import SystemMessage


def assistant_tool_use(tid="tu_1"):
    return {"role": "assistant", "content": [{"type": "tool_use", "id": tid, "name": "Read", "input": {}}]}


def user_tool_result(tid="tu_1", error=False):
    return {"role": "user", "content": [{"type": "tool_result", "tool_use_id": tid, "content": "ok", "is_error": error}]}


def user_text(text="hello"):
    return {"role": "user", "content": text}


class SafeBoundaryTests(unittest.TestCase):
    def test_boundary_just_after_tool_use_is_unsafe(self):
        messages = [user_text(), assistant_tool_use()]
        self.assertFalse(is_safe_boundary(messages, 2), "cutting after a tool_use orphans it")
        self.assertTrue(is_safe_boundary(messages, 1))

    def test_boundary_after_tool_result_is_safe(self):
        messages = [user_text(), assistant_tool_use(), user_tool_result()]
        self.assertTrue(is_safe_boundary(messages, 3))
        self.assertFalse(is_safe_boundary(messages, 2))

    def test_zero_is_safe_full_depends_on_the_last_message(self):
        messages = [user_text(), assistant_tool_use()]
        self.assertTrue(is_safe_boundary(messages, 0))
        self.assertFalse(is_safe_boundary(messages, len(messages)), "full list ends with a pending tool_use")
        messages.append(user_tool_result())
        self.assertTrue(is_safe_boundary(messages, len(messages)))

    def test_find_safe_boundary_backs_up(self):
        messages = [user_text(), assistant_tool_use(), user_tool_result(), assistant_tool_use("tu_2")]
        # limit 4 cuts right after a pending tool_use; must back up to 3 (after the result)
        self.assertEqual(find_safe_boundary(messages, 4), 3)
        # limit 2 cuts between tool_use and its result; must back up to 1
        self.assertEqual(find_safe_boundary(messages, 2), 1)

    def test_assistant_text_message_does_not_block_a_boundary(self):
        messages = [user_text(), {"role": "assistant", "content": [{"type": "text", "text": "thinking..."}]}]
        self.assertTrue(is_safe_boundary(messages, 2))


class CompactMessagesTests(unittest.TestCase):
    def test_compaction_never_orphans_a_tool_use(self):
        # Invariant: whatever the cut, the rebuilt conversation must be API-valid.
        messages = [
            user_text("one"),
            assistant_tool_use("a"),
            user_tool_result("a"),
            assistant_tool_use("b"),
            user_tool_result("b"),
            assistant_tool_use("c"),
            user_tool_result("c"),
            assistant_tool_use("d"),
            user_tool_result("d"),
        ]
        for keep in range(1, len(messages)):
            rebuilt, dropped = compact_messages(messages, keep=keep)
            self.assertGreater(dropped, 0, f"keep={keep} should drop something")
            assert_valid_conversation(rebuilt)
            self.assertEqual(rebuilt[0]["role"], "user")
            self.assertIn(COMPACT_MARKER, rebuilt[0]["content"])

    def test_keeps_the_recent_messages(self):
        messages = [user_text(f"m{i}") for i in range(10)]
        rebuilt, dropped = compact_messages(messages, keep=3)
        self.assertEqual(dropped, 7)
        self.assertEqual(len(rebuilt), 4)  # summary + 3
        self.assertEqual(rebuilt[-1]["content"], "m9")

    def test_noop_when_nothing_safe_to_drop(self):
        messages = [user_text("only one")]
        rebuilt, dropped = compact_messages(messages, keep=1)
        self.assertEqual(dropped, 0)
        self.assertEqual(rebuilt, messages)

    def test_summary_names_the_tools_used(self):
        dropped = [user_text(), assistant_tool_use(), user_tool_result()]
        rebuilt, _ = compact_messages([*dropped, user_text("keep me")], keep=1)
        self.assertIn("Read", rebuilt[0]["content"])


class EstimateTests(unittest.TestCase):
    def test_estimate_grows_with_content(self):
        small = [user_text("hi")]
        big = [user_text("x" * 10000)]
        self.assertLess(estimate_tokens(small), estimate_tokens(big))


class RunCompactionTests(unittest.TestCase):
    def test_compaction_fires_at_a_safe_boundary_during_a_run(self):
        runtime, provider = make_runtime(
            [
                {"text": "t1", "tools": [{"name": "Read", "input": {"path": "missing1.txt"}}]},
                {"text": "t2", "tools": [{"name": "Read", "input": {"path": "missing2.txt"}}]},
                "done",
            ],
            compaction_threshold_tokens=10,
            compaction_keep_messages=2,
        )
        report = runtime.run("go")
        self.assertEqual(report.result.subtype, "success")

        boundaries = [e for e in report.events if isinstance(e, SystemMessage) and e.subtype == "compact_boundary"]
        self.assertGreaterEqual(len(boundaries), 1)
        self.assertGreater(boundaries[0].data["dropped_messages"], 0)

        # Every model request the loop sent must be API-valid (no orphan tool_use),
        # and later requests must contain the compaction marker.
        for call in provider.calls:
            assert_valid_conversation(list(call.messages))
        self.assertIn(COMPACT_MARKER, str(provider.calls[-1].messages))

    def test_no_compaction_below_threshold(self):
        runtime, provider = make_runtime(
            [
                {"text": "t1", "tools": [{"name": "Read", "input": {"path": "missing1.txt"}}]},
                "done",
            ],
            compaction_threshold_tokens=10_000_000,
        )
        report = runtime.run("go")
        boundaries = [e for e in report.events if isinstance(e, SystemMessage) and e.subtype == "compact_boundary"]
        self.assertEqual(boundaries, [])


if __name__ == "__main__":
    unittest.main()
