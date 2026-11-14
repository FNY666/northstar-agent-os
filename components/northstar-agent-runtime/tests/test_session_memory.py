"""Tests for session_memory (four-operation conversation-memory protocol).

The mechanism comes from the OpenAI Agents SDK sessions documentation
(https://openai.github.io/openai-agents-python/sessions/, read in full
on 2026-11-14). The rules taken from that source are marked ``[OpenAI]``
in the module docstring; the digest-pinned history and the fail-closed
exclusion are Northstar extensions, marked ``[Northstar]``.

Written as ``unittest.TestCase`` methods so the file is discovered by
``python3 -m unittest discover -s tests`` *and* by
``python3 -m unittest test_session_memory`` (the acceptance harness's
mutation probe runs the latter).
"""

import json
import subprocess
import sys
import unittest
from pathlib import Path

import session_memory
from session_memory import (
    CONTINUATION_OPTIONS,
    MemorySessionBackend,
    SessionBackend,
    SessionConfigError,
    SessionContentError,
    SessionEmptyError,
    SessionExclusionError,
    SessionIntegrityError,
    SessionItem,
    SessionSettings,
    SessionStore,
    begin_turn,
    end_turn,
    run_session,
)

MODULE_PATH = Path(__file__).resolve().parent.parent / "session_memory.py"


def _store(**kwargs):
    return SessionStore(**kwargs)


def _item(role, content):
    return SessionItem(role=role, content=content)


class FourOperationProtocolTests(unittest.TestCase):
    """The protocol is four operations: get_items, add_items, pop_item,
    clear_session."""

    def test_get_items_returns_items_in_insertion_order(self):
        """[OpenAI] get_items returns the stored items in insertion order."""
        store = _store()
        store.add_items([_item("user", "first"), _item("assistant", "second")])
        store.add_items([_item("user", "third")])
        items = store.get_items()
        self.assertEqual([item.content for item in items], ["first", "second", "third"])

    def test_add_items_appends_with_monotonic_seq(self):
        """[OpenAI] add_items appends a batch; [Northstar] each stored
        item carries a monotonically increasing seq."""
        store = _store()
        store.add_items([_item("user", "a"), _item("assistant", "b")])
        store.add_items([_item("user", "c")])
        seqs = [item.seq for item in store.get_items()]
        self.assertEqual(seqs, [0, 1, 2])
        self.assertEqual(seqs, sorted(seqs))
        self.assertEqual(len(set(seqs)), 3)

    def test_pop_item_returns_the_most_recent_item(self):
        """[OpenAI] pop_item removes and returns the last item."""
        store = _store()
        store.add_items([_item("user", "a"), _item("assistant", "b")])
        popped = store.pop_item()
        self.assertEqual(popped.role, "assistant")
        self.assertEqual(popped.content, "b")
        self.assertEqual([item.content for item in store.get_items()], ["a"])

    def test_pop_item_on_an_empty_session_refuses(self):
        """[Northstar] An empty pop refuses; it never answers None, which
        would be indistinguishable from a stored item whose content is
        None."""
        store = _store()
        with self.assertRaises(SessionEmptyError):
            store.pop_item()

    def test_pop_item_refuses_when_the_session_is_emptied_first(self):
        store = _store()
        store.add_items([_item("user", "a")])
        store.pop_item()
        with self.assertRaises(SessionEmptyError):
            store.pop_item()

    def test_clear_session_empties_the_session(self):
        """[OpenAI] clear_session removes every stored item."""
        store = _store()
        store.add_items([_item("user", "a"), _item("assistant", "b")])
        store.clear_session()
        self.assertEqual(store.get_items(), [])
        self.assertEqual(len(store), 0)

    def test_popped_seq_is_retired_and_never_reused(self):
        """[Northstar] A popped item's seq is retired for good, so a later
        item can never be mistaken for the popped one."""
        store = _store()
        store.add_items([_item("user", "a"), _item("assistant", "b")])
        popped = store.pop_item()
        store.add_items([_item("user", "c")])
        fresh = store.get_items()[-1]
        self.assertNotEqual(fresh.seq, popped.seq)
        self.assertGreater(fresh.seq, popped.seq)

    def test_add_items_rejects_an_unknown_role(self):
        store = _store()
        with self.assertRaises(SessionConfigError):
            store.add_items([_item("narrator", "not a role")])

    def test_add_items_accepts_role_content_pairs(self):
        store = _store()
        store.add_items([("user", "a"), ("assistant", "b")])
        self.assertEqual([item.content for item in store.get_items()], ["a", "b"])

    def test_add_items_refuses_unserializable_content(self):
        store = _store()
        with self.assertRaises(SessionContentError):
            store.add_items([_item("user", {"bad": object()})])

    def test_the_store_exposes_the_four_operations(self):
        store = _store()
        for name in ("get_items", "add_items", "pop_item", "clear_session"):
            self.assertTrue(callable(getattr(store, name)), name)


if __name__ == "__main__":
    unittest.main()


class RunnerContractTests(unittest.TestCase):
    """[OpenAI] Before each run the runner retrieves the session history
    and prepends it to the input; after the run it stores every item
    produced during that run."""

    def test_begin_turn_prepends_the_history_to_the_new_input(self):
        store = _store()
        store.add_items([_item("user", "旧问题"), _item("assistant", "旧答案")])
        model_input = begin_turn(store, ["新问题"])
        self.assertEqual(model_input, ["旧问题", "旧答案", "新问题"])

    def test_end_turn_stores_only_the_current_turns_new_items(self):
        """[OpenAI] The runner stores the new items of the current turn."""
        store = _store()
        store.add_items([_item("user", "旧问题")])
        end_turn(store, [_item("user", "新问题"), _item("assistant", "新答案")])
        self.assertEqual(
            [item.content for item in store.get_items()],
            ["旧问题", "新问题", "新答案"],
        )

    def test_history_items_are_never_stored_a_second_time(self):
        """[Northstar] The store books only what end_turn is handed; the
        seq distinguishes a stored item from a new one."""
        store = _store()
        store.add_items([_item("user", "第一轮")])
        before = store.get_items()
        begin_turn(store, ["第二轮"])
        end_turn(store, [_item("user", "第二轮")])
        after = store.get_items()
        self.assertEqual(len(after), 2)
        self.assertEqual(after[0].seq, before[0].seq)
        self.assertNotEqual(after[1].seq, before[0].seq)

    def test_the_runner_contract_drives_two_turns_end_to_end(self):
        """The real path (a): turn two's model input carries turn one's
        history; only turn two's new items are booked."""
        store = _store()
        turn1 = run_session(
            store,
            ["金门大桥在哪个城市？"],
            new_items=[
                _item("user", "金门大桥在哪个城市？"),
                _item("assistant", "旧金山。"),
            ],
        )
        self.assertEqual(turn1.model_input, ["金门大桥在哪个城市？"])
        turn2 = run_session(
            store,
            ["在哪个州？"],
            new_items=[
                _item("user", "在哪个州？"),
                _item("assistant", "加利福尼亚州。"),
            ],
        )
        self.assertEqual(
            turn2.model_input,
            ["金门大桥在哪个城市？", "旧金山。", "在哪个州？"],
        )
        self.assertEqual(len(store.get_items()), 4)
        self.assertEqual(
            [item.seq for item in store.get_items()],
            [0, 1, 2, 3],
        )

    def test_the_next_run_on_the_same_session_sees_the_full_history(self):
        """[OpenAI] The next run on the same session contains the full
        history."""
        store = _store()
        run_session(store, ["q1"], new_items=[_item("user", "q1"), _item("assistant", "a1")])
        run_session(store, ["q2"], new_items=[_item("user", "q2"), _item("assistant", "a2")])
        third = run_session(store, ["q3"], new_items=[_item("user", "q3")])
        self.assertEqual(
            third.model_input,
            ["q1", "a1", "q2", "a2", "q3"],
        )

    def test_run_session_retrieves_before_it_stores(self):
        """The order is fixed: the model input never contains the
        current turn's own output."""
        store = _store()
        result = run_session(
            store,
            ["问题"],
            new_items=[_item("user", "问题"), _item("assistant", "答案")],
        )
        self.assertEqual(result.model_input, ["问题"])
        self.assertEqual([item.content for item in result.stored], ["问题", "答案"])


class MergeCallbackTests(unittest.TestCase):
    """[OpenAI] session_input_callback(history, new_input) merges the
    retrieved history with the new input. The returned list controls the
    model input only; the SDK still persists only the current turn's
    items."""

    def test_the_callback_receives_the_history_and_the_new_input(self):
        store = _store()
        store.add_items([_item("user", "h1"), _item("assistant", "h2")])
        seen = {}

        def callback(history, new_input):
            seen["history"] = list(history)
            seen["new_input"] = list(new_input)
            return list(history) + list(new_input)

        begin_turn(store, ["n1"], merge_callback=callback)
        self.assertEqual(seen["history"], ["h1", "h2"])
        self.assertEqual(seen["new_input"], ["n1"])

    def test_the_callback_receives_copies(self):
        """[OpenAI] The callback receives copies, so it may modify them
        safely."""
        store = _store()
        store.add_items([_item("user", "h1")])

        def callback(history, new_input):
            history.clear()
            new_input.clear()
            return ["replaced"]

        model_input = begin_turn(store, ["n1"], merge_callback=callback)
        self.assertEqual(model_input, ["replaced"])
        # The store is untouched: the callback's mutations were on copies.
        self.assertEqual([item.content for item in store.get_items()], ["h1"])

    def test_the_callback_result_controls_the_model_input_only(self):
        """The real path (b): the callback truncates the history, but
        the storage keeps the full history."""
        store = _store()
        store.add_items([_item("user", f"旧历史 {index}") for index in range(15)])

        def keep_last_ten(history, new_input):
            return list(history)[-10:] + list(new_input)

        model_input = begin_turn(store, ["新问题"], merge_callback=keep_last_ten)
        self.assertEqual(len(model_input), 11)
        self.assertEqual(model_input[-1], "新问题")
        self.assertEqual(model_input[0], "旧历史 5")
        # The storage is unaffected by the truncation.
        self.assertEqual(len(store.get_items()), 15)

    def test_reordering_old_history_does_not_resave_it(self):
        """[Northstar] Reordering the old history never re-books it."""
        store = _store()
        store.add_items([_item("user", "a"), _item("assistant", "b"), _item("user", "c")])

        def reverse(history, new_input):
            return list(reversed(history)) + list(new_input)

        model_input = begin_turn(store, ["n"], merge_callback=reverse)
        self.assertEqual(model_input, ["c", "b", "a", "n"])
        end_turn(store, [_item("user", "n")])
        items = store.get_items()
        self.assertEqual(len(items), 4)
        self.assertEqual([item.content for item in items], ["a", "b", "c", "n"])
        self.assertEqual([item.seq for item in items], [0, 1, 2, 3])

    def test_filtering_old_history_does_not_resave_it(self):
        """[Northstar] Filtering the old history never re-books it."""
        store = _store()
        store.add_items([_item("user", "keep"), _item("assistant", "drop")])

        def drop_assistant(history, new_input):
            return [item for item in history if item != "drop"] + list(new_input)

        model_input = begin_turn(store, ["n"], merge_callback=drop_assistant)
        self.assertEqual(model_input, ["keep", "n"])
        end_turn(store, [_item("user", "n")])
        self.assertEqual(len(store.get_items()), 3)

    def test_the_callback_may_return_an_empty_list(self):
        store = _store()
        store.add_items([_item("user", "h1")])

        def callback(history, new_input):
            return []

        self.assertEqual(begin_turn(store, ["n"], merge_callback=callback), [])

    def test_a_callback_returning_none_refuses(self):
        store = _store()

        def callback(history, new_input):
            return None

        with self.assertRaises(SessionConfigError):
            begin_turn(store, ["n"], merge_callback=callback)


class LimitTests(unittest.TestCase):
    """[OpenAI] SessionSettings(limit=N) caps how much history is
    retrieved before each run; limit=None retrieves everything."""

    def _seeded(self, count=10):
        store = _store()
        store.add_items([_item("user", f"item {index}") for index in range(count)])
        return store

    def test_limit_none_retrieves_everything(self):
        store = self._seeded(10)
        self.assertEqual(len(store.get_items(limit=None)), 10)
        # 10 history items plus the one new input item.
        self.assertEqual(len(begin_turn(store, ["n"])), 11)

    def test_limit_n_retrieves_only_the_most_recent_n(self):
        store = self._seeded(10)
        items = store.get_items(limit=3)
        self.assertEqual([item.content for item in items], ["item 7", "item 8", "item 9"])

    def test_limit_n_applies_to_the_runner_retrieval(self):
        store = self._seeded(10)
        model_input = begin_turn(store, ["n"], settings=SessionSettings(limit=3))
        self.assertEqual(model_input, ["item 7", "item 8", "item 9", "n"])

    def test_limit_zero_retrieves_nothing(self):
        store = self._seeded(5)
        self.assertEqual(store.get_items(limit=0), [])

    def test_a_negative_limit_is_refused(self):
        with self.assertRaises(SessionConfigError):
            SessionSettings(limit=-1)

    def test_a_non_integer_limit_is_refused(self):
        for bad in ("10", 1.5, True, [1]):
            with self.assertRaises(SessionConfigError):
                SessionSettings(limit=bad)

    def test_an_invalid_limit_on_get_items_is_refused(self):
        store = self._seeded(3)
        with self.assertRaises(SessionConfigError):
            store.get_items(limit=-5)

    def test_the_session_default_limit_applies_to_the_runner(self):
        store = _store(settings=SessionSettings(limit=2))
        store.add_items([_item("user", f"item {index}") for index in range(10)])
        model_input = begin_turn(store, ["n"])
        self.assertEqual(model_input, ["item 8", "item 9", "n"])

    def test_a_per_run_override_replaces_the_session_default(self):
        """[OpenAI] RunConfig.session_settings overrides the session
        default per run."""
        store = _store(settings=SessionSettings(limit=2))
        store.add_items([_item("user", f"item {index}") for index in range(10)])
        model_input = begin_turn(store, ["n"], settings=SessionSettings(limit=5))
        self.assertEqual(model_input, ["item 5", "item 6", "item 7", "item 8", "item 9", "n"])

    def test_a_none_override_keeps_the_session_default(self):
        """A per-run override whose own limit is None does not override
        the session default."""
        store = _store(settings=SessionSettings(limit=2))
        store.add_items([_item("user", f"item {index}") for index in range(10)])
        model_input = begin_turn(store, ["n"], settings=SessionSettings(limit=None))
        self.assertEqual(model_input, ["item 8", "item 9", "n"])

    def test_the_limit_does_not_change_what_is_stored(self):
        store = self._seeded(10)
        begin_turn(store, ["n"], settings=SessionSettings(limit=3))
        self.assertEqual(len(store.get_items()), 10)


class ExclusionTests(unittest.TestCase):
    """[OpenAI] In the same run a session may not be combined with the
    run-level continuation options conversation_id, previous_response_id
    or auto_previous_response_id."""

    def _refuse(self, **kwargs):
        store = _store()
        with self.assertRaises(SessionExclusionError):
            begin_turn(store, ["n"], **kwargs)
        with self.assertRaises(SessionExclusionError):
            end_turn(store, [_item("user", "n")], **kwargs)

    def test_a_session_with_conversation_id_is_refused(self):
        self._refuse(conversation_id="conv-1")

    def test_a_session_with_previous_response_id_is_refused(self):
        self._refuse(previous_response_id="resp-1")

    def test_a_session_with_auto_previous_response_id_is_refused(self):
        self._refuse(auto_previous_response_id=True)

    def test_the_three_continuation_options_are_the_documented_three(self):
        self.assertEqual(
            CONTINUATION_OPTIONS,
            ("conversation_id", "previous_response_id", "auto_previous_response_id"),
        )

    def test_a_session_without_a_continuation_option_is_allowed(self):
        store = _store()
        self.assertEqual(begin_turn(store, ["n"]), ["n"])

    def test_run_session_refuses_a_continued_run(self):
        store = _store()
        with self.assertRaises(SessionExclusionError):
            run_session(store, ["n"], new_items=[_item("user", "n")], conversation_id="c")

    def test_the_refusal_names_the_offending_option(self):
        store = _store()
        with self.assertRaises(SessionExclusionError) as ctx:
            begin_turn(store, ["n"], previous_response_id="r")
        self.assertIn("previous_response_id", str(ctx.exception))

    def test_the_refused_run_stores_nothing(self):
        store = _store()
        with self.assertRaises(SessionExclusionError):
            end_turn(store, [_item("user", "n")], conversation_id="c")
        self.assertEqual(store.get_items(), [])


class PopCorrectionTests(unittest.TestCase):
    """[OpenAI] pop_item supports corrections: pop the assistant reply,
    then pop the user question, then ask the corrected question."""

    def test_two_consecutive_pops_undo_a_whole_turn(self):
        store = _store()
        store.add_items([_item("user", "问错的问题"), _item("assistant", "错答")])
        self.assertEqual(store.pop_item().role, "assistant")
        self.assertEqual(store.pop_item().role, "user")
        self.assertEqual(store.get_items(), [])

    def test_the_new_turn_after_a_correction_holds_only_the_corrected_items(self):
        """The real path (c): the popped items never come back."""
        store = _store()
        store.add_items([_item("user", "问错的问题"), _item("assistant", "错答")])
        store.pop_item()
        store.pop_item()
        result = run_session(
            store,
            ["修正后的问题"],
            new_items=[
                _item("user", "修正后的问题"),
                _item("assistant", "正答"),
            ],
        )
        self.assertEqual(result.model_input, ["修正后的问题"])
        self.assertEqual(
            [item.content for item in store.get_items()],
            ["修正后的问题", "正答"],
        )

    def test_the_popped_items_do_not_reappear_in_the_history(self):
        store = _store()
        store.add_items([_item("user", "错的"), _item("assistant", "错答")])
        store.pop_item()
        store.pop_item()
        store.add_items([_item("user", "对的")])
        contents = [item.content for item in store.get_items()]
        self.assertNotIn("错的", contents)
        self.assertNotIn("错答", contents)
        self.assertEqual(contents, ["对的"])

    def test_the_model_input_after_a_correction_has_no_old_item(self):
        store = _store()
        store.add_items([_item("user", "错的"), _item("assistant", "错答")])
        store.pop_item()
        store.pop_item()
        model_input = begin_turn(store, ["对的"])
        self.assertEqual(model_input, ["对的"])

    def test_a_popped_item_keeps_its_digest_verifiable(self):
        """The popped item is still a verifiable row: its pin matched
        before it was removed."""
        store = _store()
        store.add_items([_item("user", "a")])
        popped = store.pop_item()
        self.assertTrue(popped.digest.startswith("sha256:"))
        self.assertEqual(len(popped.digest), len("sha256:") + 64)


class DigestPinnedHistoryTests(unittest.TestCase):
    """[Northstar] Digest-pinned history. get_items refuses the whole
    call when a row fails to decode or its digest pin does not match; it
    never silently skips the row."""

    class TamperingBackend(MemorySessionBackend):
        """A backend that lets a test tamper with a stored row in place.

        ``rows`` is the live row list, so a mutation here is exactly the
        external edit the digest pin is meant to catch.
        """

        @property
        def rows(self):
            return self._rows

    def _store_with_one_row(self):
        backend = self.TamperingBackend()
        store = SessionStore(backend)
        store.add_items([_item("user", "原文")])
        return backend, store

    def test_a_stored_row_carries_a_sha256_digest_pin(self):
        store = _store()
        store.add_items([_item("user", "a")])
        item = store.get_items()[0]
        self.assertTrue(item.digest.startswith("sha256:"))
        self.assertEqual(len(item.digest), len("sha256:") + 64)

    def test_a_digest_mismatch_refuses_the_whole_get_items_call(self):
        backend, store = self._store_with_one_row()
        backend.rows[0]["content"] = "被改过的内容"
        with self.assertRaises(SessionIntegrityError):
            store.get_items()

    def test_a_digest_mismatch_refuses_even_when_other_rows_are_fine(self):
        """The refusal is not scoped to the bad row: the caller is never
        handed a silently shortened history."""
        backend = self.TamperingBackend()
        store = SessionStore(backend)
        store.add_items([_item("user", "a"), _item("assistant", "b"), _item("user", "c")])
        backend.rows[1]["content"] = "被改过的内容"
        with self.assertRaises(SessionIntegrityError):
            store.get_items()
        self.assertEqual(len(backend.rows), 3)

    def test_a_digest_mismatch_on_an_earlier_row_also_refuses(self):
        backend = self.TamperingBackend()
        store = SessionStore(backend)
        store.add_items([_item("user", "a"), _item("assistant", "b")])
        backend.rows[0]["content"] = "被改过的内容"
        with self.assertRaises(SessionIntegrityError):
            store.get_items()

    def test_a_row_that_does_not_decode_refuses_the_whole_call(self):
        """A row whose content cannot be rendered as canonical JSON
        refuses the call, rather than being skipped."""
        backend, store = self._store_with_one_row()
        backend.rows[0]["content"] = {"not": "decodable", "bad": object()}
        with self.assertRaises(SessionIntegrityError):
            store.get_items()

    def test_a_row_with_a_corrupted_content_pin_refuses_the_whole_call(self):
        """The row decodes but its pin does not match what it should."""
        backend, store = self._store_with_one_row()
        backend.rows[0]["content"] = {"not": "decodable"}
        backend.rows[0]["digest"] = "sha256:" + "0" * 64
        with self.assertRaises(SessionIntegrityError):
            store.get_items()

    def test_a_row_missing_its_digest_refuses_the_whole_call(self):
        backend, store = self._store_with_one_row()
        del backend.rows[0]["digest"]
        with self.assertRaises(SessionIntegrityError):
            store.get_items()

    def test_a_row_with_an_unknown_role_refuses_the_whole_call(self):
        backend, store = self._store_with_one_row()
        backend.rows[0]["role"] = "narrator"
        with self.assertRaises(SessionIntegrityError):
            store.get_items()

    def test_a_tampered_row_refuses_the_runner_retrieval_too(self):
        backend = self.TamperingBackend()
        store = SessionStore(backend)
        store.add_items([_item("user", "a")])
        backend.rows[0]["content"] = "被改过的内容"
        with self.assertRaises(SessionIntegrityError):
            begin_turn(store, ["n"])

    def test_an_untampered_store_reads_back_cleanly(self):
        store = _store()
        store.add_items([_item("user", "a"), _item("assistant", "b")])
        self.assertEqual(len(store.get_items()), 2)

    def test_a_reordered_row_refuses_the_whole_call(self):
        """An external reordering of the rows breaks the pins: the store
        does not detect reorderings silently, it refuses."""
        backend = self.TamperingBackend()
        store = SessionStore(backend)
        store.add_items([_item("user", "a"), _item("assistant", "b")])
        backend.rows.reverse()
        with self.assertRaises(SessionIntegrityError):
            store.get_items()

    def test_a_deleted_row_shortens_the_history_without_being_detected(self):
        """[OpenAI] The source's trust boundary: a backend does not detect
        external deletions. Northstar pins the rows it can see; it cannot
        detect a row that is gone. This is the documented limit of the
        Northstar extension, stated so it is not overclaimed."""
        backend = self.TamperingBackend()
        store = SessionStore(backend)
        store.add_items([_item("user", "a"), _item("assistant", "b")])
        backend.rows.pop(0)
        self.assertEqual([item.content for item in store.get_items()], ["b"])


class RealPathTests(unittest.TestCase):
    """The three real paths driven end to end."""

    def test_path_a_two_turn_conversation_carries_the_history_forward(self):
        """(a) Turn two's model input holds turn one's history plus the
        new question; end_turn books only turn two's new items."""
        store = _store()
        run_session(
            store,
            ["金门大桥在哪个城市？"],
            new_items=[
                _item("user", "金门大桥在哪个城市？"),
                _item("assistant", "旧金山。"),
            ],
        )
        turn2 = run_session(
            store,
            ["在哪个州？"],
            new_items=[
                _item("user", "在哪个州？"),
                _item("assistant", "加利福尼亚州。"),
            ],
        )
        self.assertEqual(
            turn2.model_input,
            ["金门大桥在哪个城市？", "旧金山。", "在哪个州？"],
        )
        stored = store.get_items()
        self.assertEqual(len(stored), 4)
        # The history was not stored a second time: four items, not six.
        self.assertEqual([item.seq for item in stored], [0, 1, 2, 3])

    def test_path_b_the_merge_callback_truncates_the_input_not_the_store(self):
        """(b) The callback keeps the last 10 history items plus the new
        input; the model input is truncated, the storage is not."""
        store = _store()
        store.add_items([_item("user", f"旧历史 {index}") for index in range(15)])

        def keep_last_ten(history, new_input):
            return list(history)[-10:] + list(new_input)

        model_input = begin_turn(store, ["新输入"], merge_callback=keep_last_ten)
        self.assertEqual(len(model_input), 11)
        self.assertEqual(model_input[0], "旧历史 5")
        self.assertEqual(model_input[-1], "新输入")
        end_turn(store, [_item("user", "新输入")])
        self.assertEqual(len(store.get_items()), 16)

    def test_path_c_the_correction_leaves_only_the_corrected_turn(self):
        """(c) After popping the assistant reply and the user question,
        the new turn holds only the corrected items."""
        store = _store()
        store.add_items([_item("user", "问错的问题"), _item("assistant", "错答")])
        store.pop_item()
        store.pop_item()
        result = run_session(
            store,
            ["修正后的问题"],
            new_items=[
                _item("user", "修正后的问题"),
                _item("assistant", "正答"),
            ],
        )
        self.assertEqual(result.model_input, ["修正后的问题"])
        self.assertEqual(
            [item.content for item in store.get_items()],
            ["修正后的问题", "正答"],
        )

    def test_the_module_self_check_runs(self):
        """The module's own self-check must pass."""
        proc = subprocess.run(
            [sys.executable, str(MODULE_PATH)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=60,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout)
        self.assertIn("session-memory OK", proc.stdout)

    def test_the_module_is_stdlib_only(self):
        """The module must import with no third-party dependency."""
        proc = subprocess.run(
            [sys.executable, "-c",
             "import sys; sys.path.insert(0, %r); import session_memory; print('ok')"
             % str(MODULE_PATH.parent)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=60,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout)
        self.assertIn("ok", proc.stdout)


class TrustBoundaryTests(unittest.TestCase):
    """[OpenAI] A session ID selects history but never authenticates or
    authorizes; the caller must authorize access itself."""

    def test_the_session_id_is_never_an_authorization(self):
        """Two stores with the same ID are two separate histories: the
        ID grants nothing."""
        one = _store(session_id="shared")
        two = _store(session_id="shared")
        one.add_items([_item("user", "私密")])
        self.assertEqual(two.get_items(), [])

    def test_the_module_performs_no_identity_check(self):
        """There is no caller identity parameter anywhere in the API:
        authorization is the caller's job, before the session is used."""
        import inspect

        for function in (begin_turn, end_turn, run_session):
            parameters = set(inspect.signature(function).parameters)
            for forbidden in ("user", "user_id", "principal", "identity", "token", "auth"):
                self.assertNotIn(forbidden, parameters, f"{function.__name__}/{forbidden}")

    def test_an_invalid_session_id_is_refused(self):
        for bad in ("", "has space", "a" * 200, "-leading-dash"):
            with self.assertRaises(SessionConfigError):
                SessionStore(session_id=bad)

    def test_a_valid_session_id_is_accepted(self):
        for good in ("session", "s-1", "a.b_c-d", "A1"):
            self.assertEqual(SessionStore(session_id=good).session_id, good)

    def test_the_session_id_is_exposed_on_the_store(self):
        self.assertEqual(_store(session_id="abc").session_id, "abc")


class BackendInterfaceTests(unittest.TestCase):
    """The backend is pluggable: the protocol semantics live in the
    store, the bytes live in the backend."""

    def test_a_custom_backend_is_used_by_the_store(self):
        class CountingBackend(MemorySessionBackend):
            def __init__(self):
                super().__init__()
                self.appends = 0

            def append(self, rows):
                self.appends += 1
                super().append(rows)

        backend = CountingBackend()
        store = SessionStore(backend)
        store.add_items([_item("user", "a")])
        self.assertEqual(backend.appends, 1)
        self.assertEqual(len(store.get_items()), 1)

    def test_the_backend_interface_declares_the_four_operations(self):
        for name in ("append", "read", "delete_last", "clear"):
            self.assertTrue(hasattr(SessionBackend, name), name)

    def test_the_content_survives_a_round_trip_through_the_store(self):
        """The stored content is the caller's content, unchanged."""
        payload = {"text": "hello", "nested": {"list": [1, 2, 3]}, "flag": True}
        store = _store()
        store.add_items([_item("user", payload)])
        self.assertEqual(store.get_items()[0].content, payload)

    def test_the_content_is_json_serializable(self):
        store = _store()
        store.add_items([_item("user", {"a": 1})])
        json.dumps(store.get_items()[0].content)


if __name__ == "__main__":
    unittest.main()


class ReopenedStoreTests(unittest.TestCase):
    """A store may be opened over a backend that already holds rows."""

    def test_a_reopened_store_does_not_reuse_a_stored_seq(self):
        backend = MemorySessionBackend()
        first = SessionStore(backend)
        first.add_items([_item("user", "a"), _item("assistant", "b")])
        reopened = SessionStore(backend)
        reopened.add_items([_item("user", "c")])
        seqs = [item.seq for item in reopened.get_items()]
        self.assertEqual(seqs, [0, 1, 2])
        self.assertEqual(len(set(seqs)), 3)

    def test_a_reopened_store_reads_the_existing_history(self):
        backend = MemorySessionBackend()
        SessionStore(backend).add_items([_item("user", "a")])
        reopened = SessionStore(backend)
        self.assertEqual([item.content for item in reopened.get_items()], ["a"])

    def test_a_reopened_store_keeps_the_history_verifiable(self):
        backend = MemorySessionBackend()
        SessionStore(backend).add_items([_item("user", "a")])
        reopened = SessionStore(backend)
        self.assertTrue(reopened.get_items()[0].digest.startswith("sha256:"))
