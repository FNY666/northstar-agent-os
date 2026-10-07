"""Tests for debate_protocol.py."""

from __future__ import annotations

import sys
from dataclasses import FrozenInstanceError
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import unittest

import debate_protocol as dp


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(dp.DEBATE_PROTOCOL_VERSION, "debate-protocol.v1")

    def test_schema_pin(self):
        self.assertEqual(dp.SCHEMA_PIN, "northstar.debate-protocol.v1")


class TestDebate(unittest.TestCase):
    def test_frozen(self):
        d = dp.Debate(debate_id="d1", topic="t", rounds=2, seq=0)
        with self.assertRaises(FrozenInstanceError):
            d.topic = "changed"

    def test_empty_topic_rejected(self):
        with self.assertRaises(ValueError):
            dp.Debate(debate_id="d1", topic="  ", rounds=2, seq=0)

    def test_zero_rounds_rejected(self):
        with self.assertRaises(ValueError):
            dp.Debate(debate_id="d1", topic="t", rounds=0, seq=0)

    def test_bool_rounds_rejected(self):
        with self.assertRaises(TypeError):
            dp.Debate(debate_id="d1", topic="t", rounds=True, seq=0)

    def test_bad_seq_rejected(self):
        with self.assertRaises(ValueError):
            dp.Debate(debate_id="d1", topic="t", rounds=2, seq=-1)


class TestArgument(unittest.TestCase):
    def test_frozen(self):
        a = dp.Argument(debater="a", round_no=1, text="hello world", seq=0)
        with self.assertRaises(FrozenInstanceError):
            a.text = "changed"

    def test_bad_debater_rejected(self):
        with self.assertRaises(ValueError):
            dp.Argument(debater="c", round_no=1, text="hello world", seq=0)

    def test_empty_text_rejected(self):
        with self.assertRaises(ValueError):
            dp.Argument(debater="a", round_no=1, text="   ", seq=0)


class TestScoring(unittest.TestCase):
    def test_rebuttal_bonus(self):
        judge = dp.Judge()
        opp = "the budget deficit grew because spending rose sharply"
        engaging = "the deficit did not grow because spending fell, so your deficit claim about spending is wrong"
        ignoring = "cats are nice animals and the weather is pleasant today"
        s_eng = judge.score_argument(engaging, opponent_prev_text=opp)
        s_ign = judge.score_argument(ignoring, opponent_prev_text=opp)
        self.assertGreater(s_eng, s_ign)

    def test_evidence_bonus(self):
        judge = dp.Judge()
        plain = "costs went down a lot according to the recent report published"
        specific = "costs fell 15 percent in 2024 according to the audit report filed"
        self.assertGreater(
            judge.score_argument(specific), judge.score_argument(plain)
        )

    def test_repetition_penalty(self):
        judge = dp.Judge()
        prev = "the policy reduces costs and improves outcomes for everyone involved"
        repeat = "the policy reduces costs and improves outcomes for everyone involved"
        fresh = "unrelated fresh points about implementation timelines and staffing needs here"
        s_rep = judge.score_argument(repeat, own_prev_text=prev)
        s_fresh = judge.score_argument(fresh, own_prev_text=prev)
        self.assertLess(s_rep, s_fresh)

    def test_score_non_negative(self):
        judge = dp.Judge()
        prev = "word " * 60
        self.assertGreaterEqual(judge.score_argument(prev, own_prev_text=prev), 0.0)

    def test_deterministic(self):
        judge = dp.Judge()
        text = "costs fell 12 percent in 2023 per the filed audit"
        self.assertEqual(judge.score_argument(text), judge.score_argument(text))

    def test_custom_weights(self):
        judge = dp.Judge(substance_weight=0.0, rebuttal_weight=0.0,
                         evidence_weight=0.0, repetition_penalty=0.0)
        self.assertEqual(judge.score_argument("any words here at all"), 0.0)

    def test_bad_weight_rejected(self):
        with self.assertRaises(ValueError):
            dp.Judge(substance_weight=-1.0)


class TestRunDebate(unittest.TestCase):
    def test_substantive_side_wins(self):
        result = dp.run_debate(
            "topic",
            ["costs fell 15 percent in 2024 according to the published audit report"],
            ["costs are down"],
        )
        self.assertEqual(result.winner, "a")
        self.assertEqual(result.rounds, 1)
        self.assertEqual(result.round_wins_a, 1)
        self.assertEqual(result.round_wins_b, 0)

    def test_identical_sides_tie(self):
        result = dp.run_debate("topic", ["same text here"], ["same text here"])
        self.assertEqual(result.winner, "tie")

    def test_round_verdict_order(self):
        result = dp.run_debate(
            "topic",
            ["first round argument with many substantive words here now",
             "second round rebuttal engaging the first round argument words here"],
            ["weak", "weaker still"],
        )
        self.assertEqual(result.rounds, 2)
        self.assertEqual([v.round_no for v in result.round_verdicts], [1, 2])

    def test_unequal_rounds_rejected(self):
        with self.assertRaises(ValueError):
            dp.run_debate("topic", ["one"], ["one", "two"])

    def test_empty_args_rejected(self):
        with self.assertRaises(ValueError):
            dp.run_debate("topic", [], ["one"])

    def test_non_sequence_args_rejected(self):
        with self.assertRaises(TypeError):
            dp.run_debate("topic", "not a list", ["one"])

    def test_bad_judge_rejected(self):
        with self.assertRaises(TypeError):
            dp.run_debate("topic", ["one"], ["one"], judge="not a judge")

    def test_result_frozen(self):
        result = dp.run_debate("topic", ["one two three"], ["four five six"])
        with self.assertRaises(FrozenInstanceError):
            result.winner = "b"

    def test_as_dict_shape(self):
        result = dp.run_debate("topic", ["one two three"], ["four five six"])
        d = result.as_dict()
        self.assertEqual(d["schema"], dp.SCHEMA_PIN)
        self.assertEqual(d["version"], dp.DEBATE_PROTOCOL_VERSION)
        self.assertIn(d["winner"], ("a", "b", "tie"))
        self.assertEqual(len(d["round_verdicts"]), 1)

    def test_audit_event(self):
        result = dp.run_debate("topic", ["one two three"], ["four five six"])
        event = dp.debate_audit_event(result, seq=7)
        self.assertEqual(event["audit_seq"], 7)
        self.assertEqual(event["winner"], result.winner)

    def test_multi_round_aggregation(self):
        # A wins round 1, B wins round 2 -> tie on round wins, totals break it.
        # (B's round-2 text is long, evidence-rich, and rebuts every content
        # word of A's round-1 argument, so it outscores A's short "weak"
        # even though "weak" fully rebuts B's own short round-1.)
        a_args = [
            "costs fell 15 percent in 2024 according to the published audit report today",
            "weak",
        ]
        b_args = [
            "weak",
            "The costs analysis shows revenue fell then rose: percent changes of 15 "
            "in 2024 and 22 in 2025 according to the published audit report filed "
            "today, and the deficit narrative contradicts the fell costs claim "
            "because spending data from 2024 proves revenue growth continued",
        ]
        result = dp.run_debate("topic", a_args, b_args)
        self.assertEqual(result.round_wins_a, 1)
        self.assertEqual(result.round_wins_b, 1)
        self.assertIn(result.winner, ("a", "b", "tie"))


class TestMain(unittest.TestCase):
    def test_main_runs(self):
        dp.main()


if __name__ == "__main__":
    unittest.main()
