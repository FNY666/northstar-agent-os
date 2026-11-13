"""Tests for speaker_selector.py (group-chat speaker selection).

Covered acceptance rules (one named test per rule):

- round-robin order follows index modulo          -> test_round_robin_order_follows_index_modulo
- single participant is the sole speaker           -> test_round_robin_single_participant_is_sole_speaker
- state restore keeps the index aligned            -> test_round_robin_state_restore_keeps_index
- model reply with a legal name is selected        -> test_model_legal_name_is_selected_and_recorded
- selection follows the transcript, not a fixed order
                                                  -> test_model_selection_follows_transcript_not_order
- illegal reply falls back to the previous speaker -> test_model_illegal_name_falls_back_to_previous
- blank reply falls back                           -> test_model_blank_reply_falls_back
- ambiguous (multiple names) reply falls back      -> test_model_multiple_names_falls_back
- random fallback mode                             -> test_model_fallback_random_mode
- never hangs on an unusable reply                 -> test_model_never_hangs_on_unusable_reply
- no-repeat by default                             -> test_no_repeat_excludes_previous_by_default
- allow_repeated_speaker=True permits repeats      -> test_allow_repeated_speaker_permits_repeats
- custom selection function overrides the model    -> test_custom_selector_func_overrides_model
- custom function returning None defers to the model
                                                  -> test_custom_selector_func_none_defers_to_model
- max_rounds guard stops the chat                  -> test_max_rounds_guard_stops_the_chat
- selection record fields are complete             -> test_selection_record_fields_are_complete
- real path (a): round-robin trio                  -> test_real_path_round_robin_trio
- real path (b): model selector content-driven     -> test_real_path_model_selector_content_driven
- real path (c): no-repeat rule                    -> test_real_path_no_repeat_rule
- participant validation                           -> test_participant_validation_refuses_bad_rosters
- name-length boundary                             -> test_participant_name_length_boundary
"""

import random
import unittest

from speaker_selector import (
    FALLBACK_PREVIOUS,
    FALLBACK_RANDOM,
    RULE_CUSTOM,
    RULE_FALLBACK,
    RULE_MODEL,
    RULE_ROUND_ROBIN,
    SPEAKER_SELECTOR_SCHEMA,
    SPEAKER_SELECTOR_VERSION,
    BadFallbackError,
    BadParticipantError,
    DuplicateParticipantError,
    MaxRoundsError,
    ModelSelector,
    NoParticipantsError,
    Participant,
    RoundRobinSelector,
    SelectionRecord,
    SelectionRequest,
    SpeakerGroupChat,
    SpeakerSelectionError,
    parse_selection,
    transcript_digest,
)

PEOPLE = [
    Participant("Planner", "decomposes the task"),
    Participant("Coder", "writes the code"),
    Participant("Critic", "reviews the output"),
]


class RoundRobinTests(unittest.TestCase):
    """Path (a): deterministic rotation."""

    def test_round_robin_order_follows_index_modulo(self):
        selector = RoundRobinSelector(PEOPLE)
        picked = [selector.select_speaker().speaker for _ in range(6)]
        self.assertEqual(
            picked, ["Planner", "Coder", "Critic", "Planner", "Coder", "Critic"]
        )

    def test_round_robin_single_participant_is_sole_speaker(self):
        selector = RoundRobinSelector([Participant("Solo", "only one")])
        for _ in range(3):
            record = selector.select_speaker()
            self.assertEqual(record.speaker, "Solo")
            self.assertFalse(record.fallback)
            self.assertEqual(record.rule, RULE_ROUND_ROBIN)
        self.assertEqual(selector.next_speaker_index, 0)

    def test_round_robin_state_restore_keeps_index(self):
        selector = RoundRobinSelector(PEOPLE)
        selector.select_speaker()
        selector.select_speaker()
        self.assertEqual(selector.next_speaker_index, 2)
        state = selector.state()
        resumed = RoundRobinSelector(PEOPLE)
        resumed.restore(state)
        self.assertEqual(resumed.next_speaker_index, 2)
        self.assertEqual(resumed.select_speaker().speaker, "Critic")
        self.assertEqual(resumed.select_speaker().speaker, "Planner")

    def test_round_robin_state_restore_rejects_bad_index(self):
        selector = RoundRobinSelector(PEOPLE)
        bad = dict(selector.state())
        bad["next_speaker_index"] = 7
        with self.assertRaises(SpeakerSelectionError):
            selector.restore(bad)

    def test_round_robin_records_carry_rule_and_pin(self):
        selector = RoundRobinSelector(PEOPLE)
        record = selector.select_speaker(transcript=["hello"])
        self.assertEqual(record.rule, RULE_ROUND_ROBIN)
        self.assertFalse(record.fallback)
        self.assertTrue(record.verify())
        self.assertEqual(
            record.transcript_digest, transcript_digest(["hello"])
        )


class ModelSelectorTests(unittest.TestCase):
    """Path (b): model-based selection, output contract and fallback."""

    def test_model_legal_name_is_selected_and_recorded(self):
        selector = ModelSelector(PEOPLE, model=lambda request: " Coder ")
        record = selector.select_speaker(transcript=["plan the work"])
        self.assertEqual(record.speaker, "Coder")
        self.assertEqual(record.rule, RULE_MODEL)
        self.assertFalse(record.fallback)
        self.assertTrue(record.verify())
        self.assertEqual(record.round_index, 0)
        self.assertIn("Coder", record.reason)

    def test_model_selection_follows_transcript_not_order(self):
        def router(request):
            last = request.transcript[-1] if request.transcript else ""
            if "traceback" in last:
                return "Critic"
            return "Coder"

        selector = ModelSelector(PEOPLE, model=router)
        first = selector.select_speaker(transcript=["planner: on it"])
        self.assertEqual(first.speaker, "Coder")
        second = selector.select_speaker(transcript=["coder: traceback here"])
        self.assertEqual(second.speaker, "Critic")
        # not a fixed rotation: Planner is never picked by this router.
        third = selector.select_speaker(transcript=["critic: fine"])
        self.assertEqual(third.speaker, "Coder")

    def test_model_illegal_name_falls_back_to_previous(self):
        selector = ModelSelector(PEOPLE, model=lambda request: "Nobody")
        first = selector.select_speaker(transcript=["x"])
        # No previous speaker yet -> the fallback takes the first participant.
        self.assertTrue(first.fallback)
        self.assertEqual(first.speaker, "Planner")
        record = selector.select_speaker(transcript=["x", "y"])
        self.assertEqual(record.speaker, "Planner")
        self.assertEqual(record.rule, RULE_FALLBACK)
        self.assertTrue(record.fallback)
        self.assertTrue(record.verify())

    def test_model_blank_reply_falls_back(self):
        selector = ModelSelector(PEOPLE, model=lambda request: "   \n  ")
        first = selector.select_speaker(transcript=["x"])
        self.assertTrue(first.fallback)
        record = selector.select_speaker(transcript=["x"])
        self.assertEqual(record.speaker, "Planner")
        self.assertTrue(record.fallback)
        self.assertEqual(record.rule, RULE_FALLBACK)

    def test_model_multiple_names_falls_back(self):
        selector = ModelSelector(PEOPLE, model=lambda request: "Coder or Critic")
        first = selector.select_speaker(transcript=["x"])
        self.assertTrue(first.fallback)
        record = selector.select_speaker(transcript=["x"])
        self.assertEqual(record.speaker, "Planner")
        self.assertTrue(record.fallback)

    def test_model_fallback_random_mode(self):
        rng = random.Random(7)
        selector = ModelSelector(
            PEOPLE,
            model=lambda request: "???",
            fallback=FALLBACK_RANDOM,
            rng=rng,
        )
        picks = set()
        for _ in range(20):
            record = selector.select_speaker(transcript=["x"])
            self.assertTrue(record.fallback)
            self.assertIn(record.speaker, {"Planner", "Coder", "Critic"})
            picks.add(record.speaker)
        self.assertGreater(len(picks), 1)

    def test_model_never_hangs_on_unusable_reply(self):
        calls = []

        def bad_model(request):
            calls.append(request)
            return ""

        selector = ModelSelector(PEOPLE, model=bad_model, max_attempts=2)
        record = selector.select_speaker(transcript=["x"])
        self.assertTrue(record.fallback)
        self.assertIn(record.speaker, {"Planner", "Coder", "Critic"})
        # bounded: the retry loop stops after max_attempts calls.
        self.assertEqual(len(calls), 2)

    def test_model_exception_is_contained(self):
        def exploding(request):
            raise RuntimeError("provider down")

        selector = ModelSelector(PEOPLE, model=exploding, max_attempts=1)
        record = selector.select_speaker(transcript=["x"])
        self.assertTrue(record.fallback)
        self.assertIn(record.speaker, {"Planner", "Coder", "Critic"})

    def test_parse_selection_is_strict_about_ambiguity(self):
        names = ["Planner", "Coder", "Critic"]
        self.assertEqual(parse_selection("  Coder  ", names), "Coder")
        self.assertIsNone(parse_selection("", names))
        self.assertIsNone(parse_selection("Planner and Coder", names))
        self.assertIsNone(parse_selection("Unknown", names))


class NoRepeatTests(unittest.TestCase):
    """Path (c): the no-repeat rule."""

    def test_no_repeat_excludes_previous_by_default(self):
        selector = ModelSelector(
            PEOPLE, model=lambda request: "Critic", allow_repeated_speaker=False
        )
        first = selector.select_speaker(transcript=["x"])
        self.assertEqual(first.speaker, "Critic")
        # The previous speaker is out of the candidate set: the model may
        # still name it, but that name is not eligible, so it falls back.
        second = selector.select_speaker(transcript=["x"])
        self.assertTrue(second.fallback)
        self.assertNotEqual(second.speaker, "Critic")
        self.assertIn(
            second.speaker, {"Planner", "Coder"}
        )

    def test_no_repeat_only_when_one_agent_is_available(self):
        selector = ModelSelector(
            [Participant("Solo", "only one")],
            model=lambda request: "Solo",
        )
        record = selector.select_speaker(transcript=["x"])
        self.assertEqual(record.speaker, "Solo")
        self.assertFalse(record.fallback)
        self.assertEqual(record.rule, RULE_MODEL)

    def test_allow_repeated_speaker_permits_repeats(self):
        selector = ModelSelector(
            PEOPLE, model=lambda request: "Critic", allow_repeated_speaker=True
        )
        picks = [selector.select_speaker(transcript=["x"]).speaker for _ in range(3)]
        self.assertEqual(picks, ["Critic", "Critic", "Critic"])
        self.assertTrue(all(r.rule == RULE_MODEL for r in [selector.select_speaker(transcript=["x"])]))

    def test_no_repeat_candidates_exclude_previous(self):
        selector = ModelSelector(PEOPLE, model=lambda request: "Planner")
        self.assertEqual(
            selector.candidates("Planner"), ("Coder", "Critic")
        )
        selector2 = ModelSelector(
            PEOPLE, model=lambda request: "Planner", allow_repeated_speaker=True
        )
        self.assertEqual(
            selector2.candidates("Planner"), ("Planner", "Coder", "Critic")
        )


class CustomSelectorTests(unittest.TestCase):
    """A custom selection function overrides the model-based selection."""

    def test_custom_selector_func_overrides_model(self):
        def selector_func(request):
            if request.previous_speaker != "Planner":
                return "Planner"
            return None

        selector = ModelSelector(
            PEOPLE,
            model=lambda request: "Critic",
            selector_func=selector_func,
        )
        first = selector.select_speaker(transcript=["x"])
        self.assertEqual(first.speaker, "Planner")
        self.assertEqual(first.rule, RULE_CUSTOM)
        self.assertFalse(first.fallback)
        second = selector.select_speaker(transcript=["x"])
        self.assertEqual(second.speaker, "Critic")
        self.assertEqual(second.rule, RULE_MODEL)

    def test_custom_selector_func_none_defers_to_model(self):
        selector = ModelSelector(
            PEOPLE,
            model=lambda request: "Critic",
            selector_func=lambda request: None,
        )
        record = selector.select_speaker(transcript=["x"])
        self.assertEqual(record.speaker, "Critic")
        self.assertEqual(record.rule, RULE_MODEL)

    def test_custom_selector_func_returning_non_member_falls_back(self):
        selector = ModelSelector(
            PEOPLE,
            model=lambda request: "Critic",
            selector_func=lambda request: "Ghost",
        )
        record = selector.select_speaker(transcript=["x"])
        self.assertTrue(record.fallback)
        self.assertIn(record.speaker, {"Planner", "Coder", "Critic"})

    def test_custom_selector_func_raising_falls_back(self):
        def boom(request):
            raise ValueError("nope")

        selector = ModelSelector(
            PEOPLE, model=lambda request: "Critic", selector_func=boom
        )
        record = selector.select_speaker(transcript=["x"])
        self.assertTrue(record.fallback)
        self.assertIn(record.speaker, {"Planner", "Coder", "Critic"})


class GuardAndRecordTests(unittest.TestCase):
    """Termination guard and the selection record shape."""

    def test_max_rounds_guard_stops_the_chat(self):
        chat = SpeakerGroupChat(RoundRobinSelector(PEOPLE), max_rounds=3)
        records = chat.run(lambda name: f"{name} spoke")
        self.assertEqual(len(records), 3)
        self.assertEqual(chat.rounds_used, 3)
        with self.assertRaises(MaxRoundsError):
            chat.select_next()

    def test_max_rounds_guard_bounds_an_unbounded_loop(self):
        chat = SpeakerGroupChat(RoundRobinSelector(PEOPLE), max_rounds=8)
        records = chat.run(lambda name: "x")
        self.assertEqual(len(records), 8)
        self.assertEqual(
            [r.speaker for r in records],
            ["Planner", "Coder", "Critic", "Planner", "Coder", "Critic", "Planner", "Coder"],
        )

    def test_selection_record_fields_are_complete(self):
        selector = ModelSelector(PEOPLE, model=lambda request: "Coder")
        record = selector.select_speaker(transcript=["t"], round_index=7)
        as_dict = record.as_dict()
        for key in (
            "round_index",
            "speaker",
            "rule",
            "fallback",
            "transcript_digest",
            "reason",
            "digest",
            "schema",
        ):
            self.assertIn(key, as_dict)
        self.assertEqual(as_dict["round_index"], 7)
        self.assertEqual(as_dict["speaker"], "Coder")
        self.assertEqual(as_dict["rule"], RULE_MODEL)
        self.assertFalse(as_dict["fallback"])
        self.assertEqual(as_dict["schema"], SPEAKER_SELECTOR_SCHEMA)
        self.assertTrue(record.verify())

    def test_record_pin_detects_tampering(self):
        record = SelectionRecord(
            round_index=0,
            speaker="Planner",
            rule=RULE_MODEL,
            fallback=False,
        )
        self.assertTrue(record.verify())
        object.__setattr__(record, "speaker", "Coder")
        self.assertFalse(record.verify())


class ValidationTests(unittest.TestCase):
    """Fail-closed roster validation."""

    def test_participant_validation_refuses_bad_rosters(self):
        with self.assertRaises(NoParticipantsError):
            RoundRobinSelector([])
        with self.assertRaises(DuplicateParticipantError):
            RoundRobinSelector([Participant("A"), Participant("A")])
        with self.assertRaises(BadParticipantError):
            RoundRobinSelector([""])
        with self.assertRaises(BadParticipantError):
            RoundRobinSelector(["ok", 7])
        with self.assertRaises(BadFallbackError):
            ModelSelector(PEOPLE, fallback="coin-flip")

    def test_participant_name_length_boundary(self):
        long_name = "x" * 128
        RoundRobinSelector([long_name])  # exactly at the limit is fine
        with self.assertRaises(BadParticipantError):
            RoundRobinSelector(["y" * 129])

    def test_version_and_schema_pins(self):
        self.assertEqual(SPEAKER_SELECTOR_VERSION, "speaker-selector.v1")
        self.assertEqual(SPEAKER_SELECTOR_SCHEMA, "northstar.speaker-selector.v1")


class RealPathTests(unittest.TestCase):
    """The three canonical paths, driven end to end."""

    def test_real_path_round_robin_trio(self):
        chat = SpeakerGroupChat(RoundRobinSelector(PEOPLE), max_rounds=7)
        records = chat.run(lambda name: f"{name}: done")
        self.assertEqual(
            [r.speaker for r in records],
            ["Planner", "Coder", "Critic", "Planner", "Coder", "Critic", "Planner"],
        )
        for r in records:
            self.assertEqual(r.rule, RULE_ROUND_ROBIN)
            self.assertFalse(r.fallback)
            self.assertTrue(r.verify())
        self.assertEqual(len(chat.transcript), 7)

    def test_real_path_model_selector_content_driven(self):
        def router(request):
            last = request.transcript[-1] if request.transcript else ""
            if "traceback" in last:
                return "Critic"
            if "review" in last:
                return "Planner"
            return "Coder"

        chat = SpeakerGroupChat(ModelSelector(PEOPLE, model=router), max_rounds=4)
        records = chat.run(
            lambda name: {
                "Coder": "coder: traceback",
                "Critic": "critic: review needed",
                "Planner": "planner: ok",
            }[name]
        )
        self.assertEqual(
            [r.speaker for r in records],
            ["Coder", "Critic", "Planner", "Coder"],
        )
        for r in records:
            self.assertEqual(r.rule, RULE_MODEL)
            self.assertFalse(r.fallback)
            self.assertTrue(r.verify())

    def test_real_path_no_repeat_rule(self):
        selector = ModelSelector(
            PEOPLE, model=lambda request: "Critic", allow_repeated_speaker=False
        )
        picks = [selector.select_speaker(transcript=["x"]).speaker for _ in range(4)]
        # The invariant is "never twice in a row", not "never twice ever":
        # the router always names Critic, so the ineligible repeat falls
        # back to an eligible participant.
        for previous, current in zip(picks, picks[1:]):
            self.assertNotEqual(previous, current)
        self.assertNotEqual(picks[1], "Critic")

        repeated = ModelSelector(
            PEOPLE, model=lambda request: "Critic", allow_repeated_speaker=True
        )
        picks2 = [repeated.select_speaker(transcript=["x"]).speaker for _ in range(3)]
        self.assertEqual(picks2, ["Critic", "Critic", "Critic"])

    def test_real_path_fallback_never_hangs(self):
        chat = SpeakerGroupChat(
            ModelSelector(PEOPLE, model=lambda request: "  "), max_rounds=5
        )
        records = chat.run(lambda name: "x")
        self.assertEqual(len(records), 5)
        for r in records:
            self.assertTrue(r.fallback)
            self.assertEqual(r.rule, RULE_FALLBACK)
            self.assertIn(r.speaker, {"Planner", "Coder", "Critic"})

    def test_driver_state_round_trip_keeps_rotation(self):
        chat = SpeakerGroupChat(RoundRobinSelector(PEOPLE), max_rounds=6)
        chat.run(lambda name: "x", rounds=2)
        state = chat.state()
        resumed = SpeakerGroupChat(RoundRobinSelector(PEOPLE), max_rounds=6)
        resumed.restore(state)
        self.assertEqual(
            [r.speaker for r in resumed.run(lambda name: "x", rounds=2)],
            ["Critic", "Planner"],
        )

    def test_selection_request_exposes_roster_and_transcript(self):
        seen = {}

        def model(request):
            seen["request"] = request
            return "Coder"

        selector = ModelSelector(PEOPLE, model=model)
        selector.select_speaker(transcript=["hello", "world"])
        request = seen["request"]
        self.assertIsInstance(request, SelectionRequest)
        self.assertEqual(request.transcript, ("hello", "world"))
        self.assertEqual(
            [p.name for p in request.participants], ["Planner", "Coder", "Critic"]
        )
        self.assertEqual(request.candidates, ("Planner", "Coder", "Critic"))
        self.assertIsNone(request.previous_speaker)


if __name__ == "__main__":
    unittest.main()


class ModelStateTests(unittest.TestCase):
    """The previous speaker rides with the selector's state."""

    def test_model_state_restore_keeps_previous_speaker(self):
        selector = ModelSelector(PEOPLE, model=lambda request: "Coder")
        selector.select_speaker(transcript=["x"])
        self.assertEqual(selector.previous_speaker, "Coder")
        state = selector.state()
        resumed = ModelSelector(PEOPLE, model=lambda request: "Nobody")
        resumed.restore(state)
        self.assertEqual(resumed.previous_speaker, "Coder")
        record = resumed.select_speaker(transcript=["x"])
        self.assertTrue(record.fallback)
        self.assertEqual(record.speaker, "Coder")

    def test_model_state_restore_rejects_unknown_speaker(self):
        selector = ModelSelector(PEOPLE, model=lambda request: "Coder")
        bad = dict(selector.state())
        bad["previous_speaker"] = "Ghost"
        with self.assertRaises(SpeakerSelectionError):
            selector.restore(bad)
