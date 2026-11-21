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
        with self.assertRaises(BadParticipantError):
            Participant("z" * 129)

    def test_participant_description_length_boundary(self):
        Participant("Planner", "d" * 4096)  # exactly at the limit is fine
        with self.assertRaises(BadParticipantError):
            Participant("Planner", "d" * 4097)

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


class GuardArmsAndBoundariesTests(unittest.TestCase):
    """The arm of each guard and the boundary each bound is drawn at.

    Twelve planted faults survived this slice's suite:

      or@141   the ``bool`` half of the string guard
      or@187   the ``str``/``bytes`` half of the sequence guard
      gt@212   the duplicate-name test
      or@352   the ``bool`` half of the restore-index guard
      lt@356   the restore-index bound
      or@466   the ``bool`` half of the ``max_attempts`` guard
      or@474   the injected-``rng`` arm
      or@793   the ``bool`` half of the ``max_rounds`` guard
      lt@795   the ``max_rounds`` bound
      or@880   the ``bool`` half of the ``rounds`` guard
      lt@882   the ``rounds`` bound
      eq@932   the ``__main__`` guard

    Every one of them is driven below.  The recurring pattern is the one
    this module's guards share: a disjunction of a ``bool`` arm and a
    "not the right type" arm.  The existing suite fed the wrong-type
    side (a float, a string, a list); the ``bool`` arm -- the one that
    actually catches ``True`` -- was never driven, because
    ``isinstance(True, int)`` is True in Python and a boolean slips
    straight through the "not an int" arm.

    The other recurring pattern is the BOUND: several of these guards
    draw their bound at a value the existing suite never reached, so
    the killer is the boundary value itself.
    """

    # --- or@141: the `bool` half of the string guard ----------------------
    def test_a_non_string_participant_name_is_refused(self):
        """`or@141`: a non-string name is refused.

        The guard is ``isinstance(value, bool) or not isinstance(value,
        str)``.  Under the mutant (``or`` -> ``and``) the "not a string"
        arm is gone, so a non-string name is accepted and then crashes
        later with an ``AttributeError`` deep inside the guard's
        caller -- a crash instead of a refusal.  The killer asserts the
        refusal is a ``BadParticipantError``.
        """
        with self.assertRaises(BadParticipantError):
            Participant(7)
        with self.assertRaises(BadParticipantError):
            Participant(object())

    def test_a_boolean_participant_name_is_refused(self):
        """`or@141`: the ``bool`` arm specifically.

        A boolean is not a participant name, even though a boolean is an
        ``int`` and ``bool`` is a subclass of ``int``; the guard's
        explicit ``bool`` arm exists for exactly this.
        """
        with self.assertRaises(BadParticipantError):
            Participant(True)
        with self.assertRaises(BadParticipantError):
            Participant(False)

    def test_a_non_string_participant_description_is_refused(self):
        """`or@141`: the same guard on the description."""
        with self.assertRaises(BadParticipantError):
            Participant("Planner", 7)
        with self.assertRaises(BadParticipantError):
            Participant("Planner", True)

    # --- or@187: the `str`/`bytes` half of the sequence guard -------------
    def test_a_string_is_not_a_participant_sequence(self):
        """`or@187`: a bare string is not a roster.

        ``"abc"`` IS a ``Sequence`` -- every string is -- so the "not a
        Sequence" arm alone would accept it and then treat each CHARACTER
        as a participant.  Only the explicit ``str``/``bytes`` arm
        refuses it.  Under the mutant the roster is silently split into
        one participant per character.
        """
        with self.assertRaises(BadParticipantError):
            RoundRobinSelector("abc")
        with self.assertRaises(BadParticipantError):
            ModelSelector("abc")

    def test_bytes_are_not_a_participant_sequence(self):
        """`or@187`: the other half of the same arm."""
        with self.assertRaises(BadParticipantError):
            RoundRobinSelector(b"abc")

    def test_a_non_sequence_roster_is_refused(self):
        """`or@187`: the other arm, as the control."""
        with self.assertRaises(BadParticipantError):
            RoundRobinSelector(7)

    # --- gt@212: the duplicate-name test is a strict duplicate ----------
    def test_only_genuinely_duplicated_names_are_listed(self):
        """`gt@212`: the duplicate list names the duplicates, not everyone.

        The set comprehension is ``{n for n in names if names.count(n) >
        1}`` -- a name is listed only if it appears MORE THAN ONCE.  The
        mutant (``> 1`` -> ``>= 1``) lists EVERY name, so the error
        message for a single duplicated name among three participants
        would name all three instead of the one that is actually
        duplicated.  The killer asserts the message names the duplicate
        and not the unique names.
        """
        with self.assertRaises(DuplicateParticipantError) as caught:
            RoundRobinSelector(["A", "B", "A"])
        message = str(caught.exception)
        self.assertIn("'A'", message)
        self.assertNotIn("'B'", message)

    def test_a_roster_with_no_duplicates_is_accepted(self):
        """`gt@212`: the other side of the bound, as the control."""
        selector = RoundRobinSelector(["A", "B", "C"])
        self.assertEqual(selector.participant_names, ("A", "B", "C"))

    # --- or@352: the `bool` half of the restore-index guard --------------
    def test_a_boolean_restore_index_is_refused(self):
        """`or@352`: **a bool IS an int in Python**.

        The guard is ``isinstance(index, bool) or not isinstance(index,
        int)``.  Under the mutant a boolean index is accepted and used
        as the integer 1 (or 0), so a restored chat silently starts at
        the wrong place in the rotation instead of refusing the state.
        """
        selector = RoundRobinSelector(PEOPLE)
        for bad in (True, False):
            with self.subTest(bad=bad):
                with self.assertRaises(SpeakerSelectionError):
                    selector.restore({"next_speaker_index": bad})

    def test_a_float_restore_index_is_refused(self):
        """`or@352`: the other arm, as the control."""
        selector = RoundRobinSelector(PEOPLE)
        with self.assertRaises(SpeakerSelectionError):
            selector.restore({"next_speaker_index": 1.5})

    # --- lt@356: the restore-index bound INCLUDES zero ------------------
    def test_a_restore_index_of_zero_is_accepted(self):
        """`lt@356`: index zero is a legal position in the rotation.

        The bound is ``index < 0 or index >= len(names)`` -- zero is
        inside it, and it is the index every fresh selector starts at.
        Under the mutant (``< 0`` -> ``<= 0``) a state restored to the
        START of the rotation would be refused, so a chat could never
        be restored to its beginning.
        """
        selector = RoundRobinSelector(PEOPLE)
        state = dict(selector.state())
        state["next_speaker_index"] = 0
        selector.restore(state)
        self.assertEqual(selector.next_speaker_index, 0)
        self.assertEqual(selector.select_speaker().speaker, "Planner")

    def test_a_restore_index_past_the_end_is_still_refused(self):
        """`lt@356`: the other side of the bound, as the control."""
        selector = RoundRobinSelector(PEOPLE)
        state = dict(selector.state())
        state["next_speaker_index"] = len(PEOPLE)
        with self.assertRaises(SpeakerSelectionError):
            selector.restore(state)

    def test_a_negative_restore_index_is_still_refused(self):
        """`lt@356`: the other end of the bound."""
        selector = RoundRobinSelector(PEOPLE)
        state = dict(selector.state())
        state["next_speaker_index"] = -1
        with self.assertRaises(SpeakerSelectionError):
            selector.restore(state)

    # --- or@466: the `bool` half of the max_attempts guard --------------
    def test_a_boolean_max_attempts_is_refused(self):
        """`or@466`: **a bool IS an int in Python**.

        ``max_attempts`` is the bound on how many times the selector
        calls the model before it gives up and falls back.  Under the
        mutant a boolean is accepted and used as the integer 1 (or 0),
        so the retry budget silently becomes 1 -- or 0, which would end
        the selection with no attempt at all.
        """
        for bad in (True, False):
            with self.subTest(bad=bad):
                with self.assertRaises(SpeakerSelectionError):
                    ModelSelector(PEOPLE, model=lambda request: "Coder", max_attempts=bad)

    def test_a_float_max_attempts_is_refused(self):
        """`or@466`: the other arm, as the control."""
        with self.assertRaises(SpeakerSelectionError):
            ModelSelector(PEOPLE, model=lambda request: "Coder", max_attempts=1.5)

    def test_max_attempts_below_one_is_refused(self):
        """`or@466`: the bound below it."""
        with self.assertRaises(SpeakerSelectionError):
            ModelSelector(PEOPLE, model=lambda request: "Coder", max_attempts=0)

    # --- or@474: the injected rng is USED ------------------------------
    def test_the_injected_random_source_is_the_one_that_is_used(self):
        """`or@474`: the injected ``rng`` must actually drive the pick.

        The line is ``self._rng = rng or random.Random()``.  Under the
        mutant (``or`` -> ``and``) an injected ``rng`` is DISCARDED and
        a fresh ``random.Random()`` is used instead -- so the selector
        ignores the caller's seed and the fallback becomes
        irreproducible, which defeats the point of injecting one.

        The killer injects a stub whose ``choice`` records that it was
        called, and asserts it WAS.
        """
        class RecordingRandom:
            def __init__(self):
                self.calls = 0

            def choice(self, population):
                self.calls += 1
                return population[0]

        stub = RecordingRandom()
        selector = ModelSelector(
            PEOPLE,
            model=lambda request: "Nobody",
            fallback=FALLBACK_RANDOM,
            rng=stub,
        )
        record = selector.select_speaker(transcript=["x"])
        self.assertTrue(record.fallback)
        self.assertEqual(stub.calls, 1)

    def test_a_random_fallback_stays_inside_the_candidate_set(self):
        """`or@474`: the other side of the arm, as the control.

        With no injected ``rng`` the module makes its own, so the pick
        is still a participant -- the guard is about WHICH source is
        used, not about the pick being valid.
        """
        selector = ModelSelector(
            PEOPLE,
            model=lambda request: "Nobody",
            fallback=FALLBACK_RANDOM,
        )
        record = selector.select_speaker(transcript=["x"])
        self.assertTrue(record.fallback)
        self.assertIn(record.speaker, {"Planner", "Coder", "Critic"})

    # --- or@793: the `bool` half of the max_rounds guard ----------------
    def test_a_boolean_max_rounds_is_refused(self):
        """`or@793`: **a bool IS an int in Python**.

        ``max_rounds`` is the driver's termination guard -- the whole
        point of the class.  Under the mutant a boolean is accepted and
        used as the integer 1 (or 0), so the round budget silently
        changes.
        """
        for bad in (True, False):
            with self.subTest(bad=bad):
                with self.assertRaises(SpeakerSelectionError):
                    SpeakerGroupChat(RoundRobinSelector(PEOPLE), max_rounds=bad)

    def test_a_float_max_rounds_is_refused(self):
        """`or@793`: the other arm, as the control."""
        with self.assertRaises(SpeakerSelectionError):
            SpeakerGroupChat(RoundRobinSelector(PEOPLE), max_rounds=2.5)

    # --- lt@795: the max_rounds bound INCLUDES one ----------------------
    def test_exactly_one_round_is_accepted(self):
        """`lt@795`: one round is a legal budget.

        The bound is ``max_rounds < 1``, so exactly one is inside it.  A
        driver that is allowed one round is a driver that is allowed to
        run once and stop -- which is the smallest legal budget.  Under
        the mutant (``< 1`` -> ``<= 1``) that driver could not be
        built at all.
        """
        chat = SpeakerGroupChat(RoundRobinSelector(PEOPLE), max_rounds=1)
        self.assertEqual(chat.max_rounds, 1)
        records = chat.run(lambda name: f"{name} spoke")
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].speaker, "Planner")

    def test_zero_max_rounds_is_still_refused(self):
        """`lt@795`: the other side of the bound, as the control."""
        with self.assertRaises(SpeakerSelectionError):
            SpeakerGroupChat(RoundRobinSelector(PEOPLE), max_rounds=0)

    # --- or@880: the `bool` half of the per-call rounds guard ------------
    def test_a_boolean_rounds_argument_is_refused(self):
        """`or@880`: **a bool IS an int in Python**.

        The per-call ``rounds`` argument overrides ``max_rounds``.  Under
        the mutant a boolean is accepted and used as the integer 1 (or
        0), so the caller's round budget silently changes.
        """
        chat = SpeakerGroupChat(RoundRobinSelector(PEOPLE), max_rounds=4)
        for bad in (True, False):
            with self.subTest(bad=bad):
                with self.assertRaises(SpeakerSelectionError):
                    chat.run(lambda name: "x", rounds=bad)

    def test_a_float_rounds_argument_is_refused(self):
        """`or@880`: the other arm, as the control."""
        chat = SpeakerGroupChat(RoundRobinSelector(PEOPLE), max_rounds=4)
        with self.assertRaises(SpeakerSelectionError):
            chat.run(lambda name: "x", rounds=1.5)

    # --- lt@882: the rounds bound INCLUDES zero -------------------------
    def test_zero_rounds_produces_no_rounds(self):
        """`lt@882`: zero rounds is a legal request.

        The bound is ``budget < 0``, so zero is inside it: asking for no
        rounds produces an empty result, which is a legitimate way to
        ask the driver not to run at all.  Under the mutant
        (``< 0`` -> ``<= 0``) that request is refused outright.
        """
        chat = SpeakerGroupChat(RoundRobinSelector(PEOPLE), max_rounds=4)
        records = chat.run(lambda name: "x", rounds=0)
        self.assertEqual(records, ())
        self.assertEqual(chat.rounds_used, 0)

    def test_a_negative_rounds_argument_is_still_refused(self):
        """`lt@882`: the other end of the bound."""
        chat = SpeakerGroupChat(RoundRobinSelector(PEOPLE), max_rounds=4)
        with self.assertRaises(SpeakerSelectionError):
            chat.run(lambda name: "x", rounds=-1)


class MainGuardTests(unittest.TestCase):
    """`eq@932`: the ``__main__`` guard.

    The last line of the module is::

        if __name__ == "__main__":
            main()

    Under the planted fault (``==`` -> ``!=``) the guard is INVERTED:
    the self-check runs when the module is IMPORTED, and does NOT run
    when the module is executed as a script.

    An import-only suite cannot see this.  The import path calls
    ``main()`` either way, so the mutant prints the banner twice and
    still passes every assertion.

    The killer is the other direction: the module must be SILENT when
    it is imported.  The technique is ``runpy.run_path`` with
    ``run_name`` set to anything other than ``"__main__"`` -- that runs
    the module body exactly as an import would, without importing it,
    and captures whatever it prints.
    """

    def test_importing_the_module_prints_nothing(self):
        """`eq@932`: an import is silent.

        A module that prints on import corrupts the output of every
        tool that imports it.  Under the mutant the banner is printed
        on import.
        """
        import contextlib
        import io
        import runpy

        import speaker_selector

        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            runpy.run_path(
                speaker_selector.__file__, run_name="speaker_selector_import_probe"
            )
        self.assertEqual(
            stream.getvalue(),
            "",
            "the module must be silent when it is imported",
        )

    def test_running_the_module_as_a_script_prints_the_banner(self):
        """`eq@932`: the other side of the guard.

        Executed as a script, the module DOES run its self-check and
        DOES print the banner.  Under the mutant the banner never
        appears, because the inverted guard skips it.
        """
        import contextlib
        import io
        import runpy

        import speaker_selector

        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            runpy.run_path(speaker_selector.__file__, run_name="__main__")
        self.assertIn("speaker-selector OK", stream.getvalue())
