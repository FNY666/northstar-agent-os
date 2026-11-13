"""Tests for CWL structured context eviction.

The suite is deliberately paranoid about the places where a structured
eviction policy usually lies:

* the **delimiter schema** is the agent's only channel for structure, so a
  malformed or impossible call must be *refused* with a message naming the
  broken rule -- never repaired, never ignored,
* the **graph invariants** (acyclicity, typed edges, prologue protection,
  active-episode protection) are the things that make eviction safe, so
  every one of them must fail closed,
* the **selection order** (oldest eligible ACT before any EXPL, oldest first
  inside a type) decides what the model still sees, and it must be
  deterministic,
* the **dependency constraint** is the non-obvious rule: an exploratory
  episode whose action still depends on it must not be evicted,
* the **graduated levels** must be applied least-destructive-first with a
  budget re-check after each one, and the budget met means *stop*,
* **user turns and the prologue** are never evictable, and when the budget
  cannot be met without touching them the policy must say so
  (UNMEETABLE) instead of quietly degrading.

Source: arXiv:2606.11213, "Beyond Compaction: Structured Context Eviction
for Long-Horizon Agents" (Semenov & Dorofeev, Kiz8, 2026-04-21).
"""

from __future__ import annotations

import unittest

import episode_eviction as ee
from episode_eviction import (
    ACT,
    EXPL,
    STATUS_CLOSED,
    STATUS_EVICTED,
    STATUS_OPEN,
    DelimiterError,
    EpisodeGraph,
    EpisodeGraphError,
    EvictionLevel,
    EvictionPolicy,
)


class DelimiterSchemaTests(unittest.TestCase):
    """The four canonical invocations are legal; every illegal combination
    is refused with a message that names the rule."""

    def _graph(self) -> EpisodeGraph:
        graph = EpisodeGraph()
        graph.add_prologue(tokens=40)
        return graph

    def test_four_canonical_invocations_are_legal(self):
        graph = self._graph()
        # 1. start exploration
        graph.handle_delimiter({"action": "start", "name": "expl-a", "type": EXPL})
        # 2. end exploration (description required)
        graph.handle_delimiter({"action": "end", "description": "found the config"})
        # 3. start action (dependencies required)
        graph.handle_delimiter(
            {"action": "start", "name": "act-a", "type": ACT, "dependencies": ["expl-a"]}
        )
        # 4. end action (no description)
        graph.handle_delimiter({"action": "end"})
        self.assertEqual(graph.require("expl-a").status, STATUS_CLOSED)
        self.assertEqual(graph.require("expl-a").description, "found the config")
        self.assertEqual(graph.require("act-a").status, STATUS_CLOSED)
        self.assertIsNone(graph.require("act-a").description)
        self.assertEqual(graph.require("act-a").dependencies, ["expl-a"])

    def test_start_without_name_is_rejected(self):
        graph = self._graph()
        with self.assertRaises(DelimiterError) as ctx:
            graph.handle_delimiter({"action": "start", "type": EXPL})
        self.assertIn(ee.RULE_START_NAME, str(ctx.exception))

    def test_start_without_type_is_rejected(self):
        graph = self._graph()
        with self.assertRaises(DelimiterError) as ctx:
            graph.handle_delimiter({"action": "start", "name": "expl-a"})
        self.assertIn(ee.RULE_START_TYPE, str(ctx.exception))

    def test_start_with_bad_type_is_rejected(self):
        graph = self._graph()
        with self.assertRaises(DelimiterError) as ctx:
            graph.handle_delimiter({"action": "start", "name": "x", "type": "scratch"})
        self.assertIn(ee.RULE_START_TYPE, str(ctx.exception))

    def test_act_start_without_dependencies_is_rejected(self):
        graph = self._graph()
        with self.assertRaises(DelimiterError) as ctx:
            graph.handle_delimiter({"action": "start", "name": "act-a", "type": ACT})
        self.assertIn(ee.RULE_ACT_DEPS, str(ctx.exception))

    def test_act_start_dependencies_must_reference_existing_expl(self):
        graph = self._graph()
        with self.assertRaises(DelimiterError) as ctx:
            graph.handle_delimiter(
                {"action": "start", "name": "act-a", "type": ACT, "dependencies": ["nope"]}
            )
        self.assertIn(ee.RULE_DEP_REF, str(ctx.exception))
        self.assertIn("does not exist", str(ctx.exception))

    def test_act_start_dependencies_must_reference_closed_expl(self):
        graph = self._graph()
        graph.handle_delimiter({"action": "start", "name": "expl-open", "type": EXPL})
        with self.assertRaises(DelimiterError) as ctx:
            graph.handle_delimiter(
                {
                    "action": "start",
                    "name": "act-a",
                    "type": ACT,
                    "dependencies": ["expl-open"],
                }
            )
        self.assertIn(ee.RULE_DEP_REF, str(ctx.exception))
        self.assertIn("not closed", str(ctx.exception))

    def test_act_start_cannot_depend_on_an_act(self):
        graph = self._graph()
        graph.handle_delimiter({"action": "start", "name": "expl-a", "type": EXPL})
        graph.handle_delimiter({"action": "end", "description": "d"})
        graph.handle_delimiter(
            {"action": "start", "name": "act-a", "type": ACT, "dependencies": ["expl-a"]}
        )
        graph.handle_delimiter({"action": "end"})
        with self.assertRaises(DelimiterError) as ctx:
            graph.handle_delimiter(
                {
                    "action": "start",
                    "name": "act-b",
                    "type": ACT,
                    "dependencies": ["act-a"],
                }
            )
        self.assertIn(ee.RULE_DEP_REF, str(ctx.exception))
        self.assertIn("not 'expl'", str(ctx.exception))

    def test_act_end_with_description_is_rejected(self):
        graph = self._graph()
        graph.handle_delimiter({"action": "start", "name": "expl-a", "type": EXPL})
        graph.handle_delimiter({"action": "end", "description": "read the file"})
        graph.handle_delimiter(
            {"action": "start", "name": "act-a", "type": ACT, "dependencies": ["expl-a"]}
        )
        with self.assertRaises(DelimiterError) as ctx:
            graph.handle_delimiter({"action": "end", "description": "wrote the file"})
        self.assertIn(ee.RULE_ACT_DESC, str(ctx.exception))

    def test_expl_end_without_description_is_rejected(self):
        graph = self._graph()
        graph.handle_delimiter({"action": "start", "name": "expl-a", "type": EXPL})
        with self.assertRaises(DelimiterError) as ctx:
            graph.handle_delimiter({"action": "end"})
        self.assertIn(ee.RULE_EXPL_DESC, str(ctx.exception))

    def test_expl_start_with_dependencies_is_rejected(self):
        graph = self._graph()
        with self.assertRaises(DelimiterError) as ctx:
            graph.handle_delimiter(
                {"action": "start", "name": "expl-a", "type": EXPL, "dependencies": ["x"]}
            )
        self.assertIn(ee.RULE_EXPL_NO_DEPS, str(ctx.exception))

    def test_unknown_action_is_rejected(self):
        graph = self._graph()
        with self.assertRaises(DelimiterError) as ctx:
            graph.handle_delimiter({"action": "pause", "name": "x"})
        self.assertIn(ee.RULE_ACTION, str(ctx.exception))

    def test_second_active_episode_is_rejected(self):
        graph = self._graph()
        graph.handle_delimiter({"action": "start", "name": "expl-a", "type": EXPL})
        with self.assertRaises(DelimiterError) as ctx:
            graph.handle_delimiter({"action": "start", "name": "expl-b", "type": EXPL})
        self.assertIn(ee.RULE_ACTIVE, str(ctx.exception))

    def test_end_without_active_episode_is_rejected(self):
        graph = self._graph()
        with self.assertRaises(DelimiterError) as ctx:
            graph.handle_delimiter({"action": "end", "description": "x"})
        self.assertIn(ee.RULE_NO_ACTIVE, str(ctx.exception))


class EpisodeGraphInvariantTests(unittest.TestCase):
    """Acyclicity, typed edges, prologue protection, active protection."""

    def test_dependency_on_open_episode_is_rejected(self):
        graph = EpisodeGraph()
        graph.add_episode("expl-a", EXPL, status=STATUS_OPEN)
        with self.assertRaises(EpisodeGraphError):
            graph.add_episode("act-a", ACT, dependencies=["expl-a"])

    def test_dependency_on_unknown_episode_is_rejected(self):
        graph = EpisodeGraph()
        with self.assertRaises(EpisodeGraphError):
            graph.add_episode("act-a", ACT, dependencies=["ghost"])

    def test_typed_edges_reject_act_to_act(self):
        graph = EpisodeGraph()
        graph.add_episode("act-a", ACT, status=STATUS_CLOSED)
        with self.assertRaises(EpisodeGraphError) as ctx:
            graph.add_episode("act-b", ACT, dependencies=["act-a"])
        self.assertIn(ee.RULE_DEP_REF, str(ctx.exception))

    def test_typed_edges_reject_expl_to_expl(self):
        graph = EpisodeGraph()
        graph.add_episode("expl-a", EXPL, status=STATUS_CLOSED)
        with self.assertRaises(EpisodeGraphError) as ctx:
            graph.add_episode("expl-b", EXPL, dependencies=["expl-a"])
        self.assertIn(ee.RULE_DEP_REF, str(ctx.exception))

    def test_add_dependency_enforces_typed_edges(self):
        graph = EpisodeGraph()
        graph.add_episode("act-a", ACT, status=STATUS_CLOSED)
        graph.add_episode("act-b", ACT, status=STATUS_CLOSED)
        with self.assertRaises(EpisodeGraphError):
            graph.add_dependency("act-a", "act-b")

    def test_add_dependency_enforces_closure(self):
        graph = EpisodeGraph()
        graph.add_episode("expl-a", EXPL, status=STATUS_OPEN)
        graph.add_episode("act-a", ACT, status=STATUS_CLOSED)
        with self.assertRaises(EpisodeGraphError):
            graph.add_dependency("expl-a", "act-a")

    def test_add_dependency_accepts_closed_expl_to_act(self):
        graph = EpisodeGraph()
        graph.add_episode("expl-a", EXPL, status=STATUS_CLOSED)
        graph.add_episode("act-a", ACT, status=STATUS_CLOSED)
        graph.add_dependency("expl-a", "act-a")
        self.assertEqual(graph.require("act-a").dependencies, ["expl-a"])
        self.assertEqual(graph.dependents("expl-a"), ["act-a"])

    def test_duplicate_episode_name_is_rejected(self):
        graph = EpisodeGraph()
        graph.add_episode("expl-a", EXPL)
        with self.assertRaises(EpisodeGraphError):
            graph.add_episode("expl-a", EXPL)

    def test_prologue_is_never_evictable(self):
        graph = EpisodeGraph()
        graph.add_prologue(tokens=500)
        graph.add_episode("expl-a", EXPL, status=STATUS_CLOSED, core_tokens=100)
        policy = EvictionPolicy(budget=1)
        receipt = policy.evict_to_budget(graph)
        self.assertTrue(graph.require("__prologue__").prologue)
        self.assertEqual(graph.require("__prologue__").status, STATUS_CLOSED)
        self.assertEqual(graph.require("__prologue__").token_count, 500)
        self.assertNotIn("__prologue__", receipt.episodes_touched)

    def test_active_episode_is_never_evictable(self):
        graph = EpisodeGraph()
        graph.add_episode("expl-open", EXPL, status=STATUS_OPEN, core_tokens=100)
        graph.add_episode("expl-closed", EXPL, status=STATUS_CLOSED, core_tokens=100)
        policy = EvictionPolicy(budget=150)
        receipt = policy.evict_to_budget(graph)
        self.assertEqual(graph.require("expl-open").status, "open")
        self.assertNotIn("expl-open", receipt.episodes_touched)

    def test_active_episode_blocks_eviction_of_its_dependents(self):
        # The act is closed but its dependency's episode is still active:
        # the act may be evicted, the expl never is (it is active).
        graph = EpisodeGraph()
        graph.add_episode("expl-a", EXPL, status=STATUS_OPEN, core_tokens=100)
        graph.add_episode("act-a", ACT, status=STATUS_CLOSED, core_tokens=100)
        graph.require("act-a").dependencies.append("expl-a")
        policy = EvictionPolicy(budget=1)
        receipt = policy.evict_to_budget(graph)
        self.assertEqual(graph.require("expl-a").status, "open")
        self.assertEqual(graph.require("act-a").status, STATUS_EVICTED)
        self.assertTrue(receipt.unmeetable)


class EvictionSelectionTests(unittest.TestCase):
    """Selection order: oldest eligible ACT before any EXPL, oldest first
    inside a type."""

    def _graph_with_two_acts_and_two_expls(self) -> EpisodeGraph:
        graph = EpisodeGraph()
        graph.add_prologue(tokens=10)
        graph.add_episode("expl-old", EXPL, status=STATUS_CLOSED, core_tokens=100)
        graph.add_episode("expl-new", EXPL, status=STATUS_CLOSED, core_tokens=100)
        graph.add_episode("act-old", ACT, status=STATUS_CLOSED, core_tokens=100)
        graph.add_episode("act-new", ACT, status=STATUS_CLOSED, core_tokens=100)
        return graph

    def test_oldest_act_is_evicted_before_any_expl(self):
        graph = self._graph_with_two_acts_and_two_expls()
        policy = EvictionPolicy(budget=300)
        target = policy.select_target(graph)
        self.assertIsNotNone(target)
        self.assertEqual(target.name, "act-old")
        self.assertEqual(target.type, ACT)

    def test_oldest_within_a_type_wins(self):
        graph = self._graph_with_two_acts_and_two_expls()
        policy = EvictionPolicy(budget=300)
        receipt = policy.evict_to_budget(graph)
        # 410 tokens, budget 300: the two oldest ACT episodes go first.
        self.assertEqual(receipt.episodes_touched[:2], ["act-old", "act-new"])

    def test_expl_is_evicted_only_when_no_act_is_eligible(self):
        graph = EpisodeGraph()
        graph.add_episode("expl-a", EXPL, status=STATUS_CLOSED, core_tokens=100)
        policy = EvictionPolicy(budget=50)
        target = policy.select_target(graph)
        self.assertIsNotNone(target)
        self.assertEqual(target.name, "expl-a")

    def test_no_candidate_returns_none(self):
        graph = EpisodeGraph()
        graph.add_prologue(tokens=100)
        policy = EvictionPolicy(budget=1)
        self.assertIsNone(policy.select_target(graph))


class DependencyConstraintTests(unittest.TestCase):
    """An EXPL with a live dependent is not eligible; it becomes eligible
    only after every dependent ACT is fully evicted."""

    def _graph(self) -> EpisodeGraph:
        graph = EpisodeGraph()
        graph.add_episode("expl-a", EXPL, status=STATUS_CLOSED, core_tokens=100)
        graph.add_episode("act-a", ACT, status=STATUS_CLOSED, core_tokens=100)
        graph.add_dependency("expl-a", "act-a")
        return graph

    def test_expl_with_live_dependent_is_not_a_candidate(self):
        graph = self._graph()
        policy = EvictionPolicy(budget=50)
        names = [ep.name for ep in policy.candidates(graph)]
        self.assertNotIn("expl-a", names)
        self.assertIn("act-a", names)

    def test_expl_becomes_eligible_after_dependent_is_fully_evicted(self):
        graph = self._graph()
        policy = EvictionPolicy(budget=50)
        receipt = policy.evict_to_budget(graph)
        self.assertEqual(graph.require("act-a").status, STATUS_EVICTED)
        # The expl is now eligible and is evicted in the same pass.
        self.assertIn("expl-a", receipt.episodes_touched)
        self.assertEqual(graph.require("expl-a").status, STATUS_EVICTED)
        self.assertTrue(receipt.budget_met)

    def test_expl_with_two_dependents_waits_for_both(self):
        graph = EpisodeGraph()
        graph.add_episode("expl-a", EXPL, status=STATUS_CLOSED, core_tokens=100)
        graph.add_episode("act-a", ACT, status=STATUS_CLOSED, core_tokens=100)
        graph.add_episode("act-b", ACT, status=STATUS_CLOSED, core_tokens=100)
        graph.add_dependency("expl-a", "act-a")
        graph.add_dependency("expl-a", "act-b")
        policy = EvictionPolicy(budget=150)
        policy.evict_to_budget(graph)
        # Only one ACT may go before the budget is met; the EXPL still has a
        # live dependent and must survive.
        self.assertEqual(graph.require("act-a").status, STATUS_EVICTED)
        self.assertEqual(graph.require("expl-a").status, STATUS_CLOSED)


class EvictionLevelTests(unittest.TestCase):
    """Levels are applied least destructive first, one per round, with a
    budget re-check after each."""

    def test_reasoning_strip_is_expl_only(self):
        graph = EpisodeGraph()
        graph.add_episode("act-a", ACT, status=STATUS_CLOSED, reasoning_tokens=50,
                           core_tokens=50)
        policy = EvictionPolicy(budget=50)
        receipt = policy.evict_to_budget(graph)
        # The ACT cannot lose its reasoning trace (expl-only rule); it must
        # be removed instead.
        self.assertNotIn(EvictionLevel.STRIP_REASONING, receipt.levels_applied)
        self.assertEqual(graph.require("act-a").status, STATUS_EVICTED)

    def test_expl_loses_reasoning_then_bulk_then_intermediate_then_core(self):
        graph = EpisodeGraph()
        graph.add_episode("expl-a", EXPL, status=STATUS_CLOSED, reasoning_tokens=10,
                           bulk_output_tokens=20, intermediate_tokens=30, core_tokens=40)
        policy = EvictionPolicy(budget=30)
        receipt = policy.evict_to_budget(graph)
        self.assertEqual(
            receipt.levels_applied,
            [
                EvictionLevel.STRIP_REASONING,
                EvictionLevel.STRIP_BULK_OUTPUT,
                EvictionLevel.STRIP_INTERMEDIATE,
                EvictionLevel.REMOVE_EPISODE,
            ],
        )
        self.assertEqual(graph.require("expl-a").status, STATUS_EVICTED)
        self.assertTrue(receipt.budget_met)

    def test_budget_is_rechecked_after_each_level_and_stops_when_met(self):
        graph = EpisodeGraph()
        graph.add_episode("expl-a", EXPL, status=STATUS_CLOSED, reasoning_tokens=10,
                           bulk_output_tokens=20, intermediate_tokens=30, core_tokens=40)
        policy = EvictionPolicy(budget=90)
        receipt = policy.evict_to_budget(graph)
        # 100 tokens -> strip reasoning (90) -> budget met -> stop.
        self.assertEqual(receipt.levels_applied, [EvictionLevel.STRIP_REASONING])
        self.assertEqual(graph.require("expl-a").status, STATUS_CLOSED)
        self.assertEqual(graph.require("expl-a").reasoning_tokens, 0)
        self.assertEqual(receipt.tokens_after, 90)
        self.assertTrue(receipt.budget_met)

    def test_levels_are_applied_in_the_papers_order(self):
        self.assertEqual(
            EvictionLevel.ORDER,
            (
                EvictionLevel.STRIP_REASONING,
                EvictionLevel.STRIP_BULK_OUTPUT,
                EvictionLevel.STRIP_INTERMEDIATE,
                EvictionLevel.REMOVE_EPISODE,
            ),
        )


class UserTurnAndUnmeetableTests(unittest.TestCase):
    """User turns and the prologue survive any pressure; an unmeetable
    budget is reported, not silently degraded."""

    def test_user_turns_are_never_evicted(self):
        graph = EpisodeGraph()
        graph.add_user_turn("please implement the feature")
        graph.add_episode("expl-a", EXPL, status=STATUS_CLOSED, core_tokens=500)
        before = graph.user_turn_tokens()
        policy = EvictionPolicy(budget=1)
        receipt = policy.evict_to_budget(graph)
        self.assertEqual(graph.user_turn_tokens(), before)
        self.assertEqual(len(graph.user_turns()), 1)
        self.assertTrue(receipt.unmeetable)
        self.assertIn("user", receipt.unmeetable_reason)

    def test_unmeetable_budget_is_reported_not_degraded(self):
        graph = EpisodeGraph()
        graph.add_prologue(tokens=1000)
        graph.add_user_turn("keep me")
        policy = EvictionPolicy(budget=10)
        receipt = policy.evict_to_budget(graph)
        self.assertFalse(receipt.budget_met)
        self.assertTrue(receipt.unmeetable)
        self.assertIsNotNone(receipt.unmeetable_reason)
        self.assertIn("prologue", receipt.unmeetable_reason)
        self.assertEqual(receipt.episodes_touched, [])
        self.assertEqual(graph.require("__prologue__").token_count, 1000)

    def test_token_count_includes_user_turns(self):
        graph = EpisodeGraph()
        graph.add_user_turn("a" * 40)
        graph.add_episode("expl-a", EXPL, status=STATUS_CLOSED, core_tokens=7)
        self.assertEqual(ee.count_tokens(graph), 10 + 7)
        self.assertEqual(graph.token_count(), ee.count_tokens(graph))


class RealPathTests(unittest.TestCase):
    """The three paths the slice must actually drive end to end."""

    def _mixed_session(self) -> EpisodeGraph:
        """A session over budget with mixed expl and act episodes.

        The trajectory: explore the repo, act on it, explore again, act
        again -- with the second act depending on the second expl.
        """

        graph = EpisodeGraph()
        graph.add_prologue(tokens=120)
        graph.add_user_turn("add a health endpoint")
        graph.handle_delimiter({"action": "start", "name": "expl-repo", "type": EXPL})
        graph.handle_delimiter({"action": "end", "description": "the server lives in app.py"})
        graph.handle_delimiter(
            {"action": "start", "name": "act-route", "type": ACT, "dependencies": ["expl-repo"]}
        )
        graph.handle_delimiter({"action": "end"})
        graph.handle_delimiter({"action": "start", "name": "expl-tests", "type": EXPL})
        graph.handle_delimiter({"action": "end", "description": "tests live in tests/test_app.py"})
        graph.handle_delimiter(
            {"action": "start", "name": "act-endpoint", "type": ACT, "dependencies": ["expl-tests"]}
        )
        graph.handle_delimiter({"action": "end"})
        graph.set_tokens("expl-repo", reasoning_tokens=40, bulk_output_tokens=60, core_tokens=20)
        graph.set_tokens("act-route", bulk_output_tokens=30, intermediate_tokens=50, core_tokens=20)
        graph.set_tokens("expl-tests", reasoning_tokens=40, bulk_output_tokens=60, core_tokens=20)
        graph.set_tokens("act-endpoint", bulk_output_tokens=30, intermediate_tokens=50, core_tokens=20)
        return graph

    def test_path_a_over_budget_session_evicts_act_before_expl(self):
        graph = self._mixed_session()
        before = ee.count_tokens(graph)
        self.assertGreater(before, 400)
        policy = EvictionPolicy(budget=300)
        receipt = policy.evict_to_budget(graph)
        self.assertTrue(receipt.budget_met)
        self.assertLessEqual(ee.count_tokens(graph), 300)
        touched = receipt.episodes_touched
        # The two ACT episodes are evicted before any EXPL episode.
        self.assertEqual(touched[0], "act-route")
        self.assertEqual(touched[1], "act-endpoint")
        self.assertTrue(graph.require("act-route").evicted)
        self.assertTrue(graph.require("act-endpoint").evicted)

    def test_path_a_expl_with_live_dependent_survives_the_act_eviction(self):
        graph = self._mixed_session()
        policy = EvictionPolicy(budget=300)
        policy.evict_to_budget(graph)
        # expl-tests is still depended on by act-endpoint? No: act-endpoint is
        # fully evicted now, so expl-tests becomes eligible -- but the budget
        # was already met, so it must still be there.
        self.assertEqual(graph.require("expl-tests").status, STATUS_CLOSED)
        self.assertGreater(graph.require("expl-tests").token_count, 0)

    def test_path_a_expl_is_blocked_while_its_dependent_is_live(self):
        graph = EpisodeGraph()
        graph.add_episode("expl-src", EXPL, status=STATUS_CLOSED, core_tokens=200)
        graph.add_episode("act-live", ACT, status=STATUS_CLOSED, bulk_output_tokens=100)
        graph.add_dependency("expl-src", "act-live")
        policy = EvictionPolicy(budget=150)
        receipt = policy.evict_to_budget(graph)
        # The ACT loses its bulk output (300 -> 200), which is still over
        # budget, so it is removed entirely.  Only then does the EXPL
        # become eligible -- the dependency constraint orders the two.
        self.assertEqual(receipt.episodes_touched, ["act-live", "expl-src"])
        self.assertTrue(graph.require("act-live").evicted)
        self.assertTrue(graph.require("expl-src").evicted)

    def test_path_b_dependency_violation_blocks_expl_until_act_is_gone(self):
        graph = EpisodeGraph()
        graph.add_episode("expl-src", EXPL, status=STATUS_CLOSED, core_tokens=200)
        graph.add_episode("act-edit", ACT, status=STATUS_CLOSED, core_tokens=200)
        graph.add_dependency("expl-src", "act-edit")
        policy = EvictionPolicy(budget=250)
        receipt = policy.evict_to_budget(graph)
        # act-edit is fully evicted first (its effect is durable in the
        # environment), which frees 200 tokens and meets the budget: the
        # EXPL is now eligible but the budget is already met, so it stays.
        self.assertTrue(receipt.budget_met)
        self.assertEqual(receipt.episodes_touched, ["act-edit"])
        self.assertTrue(graph.require("act-edit").evicted)
        self.assertEqual(graph.require("expl-src").status, STATUS_CLOSED)
        self.assertGreater(graph.require("expl-src").token_count, 0)

    def test_path_b_expl_is_evicted_only_after_its_dependent_is_gone(self):
        graph = EpisodeGraph()
        graph.add_episode("expl-src", EXPL, status=STATUS_CLOSED, core_tokens=200)
        graph.add_episode("act-edit", ACT, status=STATUS_CLOSED, core_tokens=200)
        graph.add_dependency("expl-src", "act-edit")
        policy = EvictionPolicy(budget=10)
        receipt = policy.evict_to_budget(graph)
        self.assertEqual(receipt.episodes_touched, ["act-edit", "expl-src"])
        self.assertTrue(graph.require("act-edit").evicted)
        self.assertTrue(graph.require("expl-src").evicted)

    def test_path_b_expl_is_protected_while_the_dependent_is_live(self):
        graph = EpisodeGraph()
        graph.add_episode("expl-src", EXPL, status=STATUS_CLOSED, core_tokens=200)
        graph.add_episode("act-edit", ACT, status=STATUS_CLOSED, core_tokens=200)
        graph.add_dependency("expl-src", "act-edit")
        policy = EvictionPolicy(budget=250)
        # Only strip the ACT's core is not possible: the ACT has no parts but
        # core, so it is removed.  Before that round the EXPL is not a
        # candidate.
        self.assertEqual(
            [ep.name for ep in policy.candidates(graph)],
            ["act-edit"],
        )

    def test_path_c_prologue_and_active_survive_extreme_pressure(self):
        graph = EpisodeGraph()
        graph.add_prologue(tokens=900)
        graph.add_user_turn("never lose this")
        graph.add_episode("expl-open", EXPL, status=STATUS_OPEN, core_tokens=300)
        graph.add_episode("expl-closed", EXPL, status=STATUS_CLOSED, core_tokens=100)
        policy = EvictionPolicy(budget=50)
        receipt = policy.evict_to_budget(graph)
        self.assertTrue(graph.require("__prologue__").prologue)
        self.assertEqual(graph.require("__prologue__").token_count, 900)
        self.assertEqual(graph.require("expl-open").status, STATUS_OPEN)
        self.assertEqual(graph.require("expl-open").token_count, 300)
        self.assertEqual(graph.require("expl-closed").status, STATUS_EVICTED)
        # The budget could not be met, and the policy said so.
        self.assertFalse(receipt.budget_met)
        self.assertTrue(receipt.unmeetable)
        self.assertIn("prologue", receipt.unmeetable_reason)
        self.assertIn("active", receipt.unmeetable_reason)
        self.assertIn("user", receipt.unmeetable_reason)

    def test_path_c_receipt_reports_what_was_touched(self):
        graph = self._mixed_session()
        policy = EvictionPolicy(budget=300)
        receipt = policy.evict_to_budget(graph)
        data = receipt.as_dict()
        self.assertEqual(data["budget"], 300)
        self.assertGreater(data["tokens_freed"], 0)
        self.assertTrue(data["budget_met"])
        self.assertFalse(data["unmeetable"])
        self.assertEqual(len(data["episodes_touched"]), len(set(data["episodes_touched"])))
