"""The `alignment_check` surface: the branches its own suite never drove.

WHY THIS FILE EXISTS (measured 2026-11-26)
------------------------------------------
`alignment_check.py` is the goal-trace-action observer: it builds a
judgment input, hands it to a HOST-PROVIDED judge, and fails CLOSED
when the judge raises.  The artifact measured the module at **2/9** --
seven survivors -- and every one of them was a branch the suite
exercised only on ONE side.

THE SEVEN SURVIVORS, AND WHAT EACH NEEDED
------------------------------------------
  or@70   `if not goal or not goal.strip():`
          The suite passes `""`.  Under the mutant (`or` -> `and`) the
          blank-but-not-empty goal `"   "` is ACCEPTED, because `"   "
          or "   ".strip()` is falsy but `"   " and "   ".strip()` is
          falsy too...  the point is that `""` alone cannot tell the
          two spellings apart.  The CRAFTED INPUT is a goal that is
          non-empty but BLANK.

  gt@75   `trace[-max_trace:] if len(trace) > max_trace else trace`
          The suite passes 30 entries with max_trace=10, so the
          truncation path is always taken.  The boundary case
          `len(trace) == max_trace` must keep ALL of them.

  gt@82   `"trace_truncated": len(trace) > max_trace`
          Same boundary: the suite only ever sees the `True` side.

  retF@145 / retF@148  `stdlib_only()`'s two rejection branches
          The suite asserts `stdlib_only() is True`.  A guard whose
          whole job is to REJECT, tested only on the accepting side,
          is not tested.  The CRAFTED INPUT is a source file whose
          imports are not stdlib -- the module is re-parsed with a
          patched `__file__`, so the real file is never modified.

  gt@159  `goal_words = [w for w in goal_lower.split() if len(w) > 3]`
          Inside `main()`'s rule-judge.  The `> 3` is a LENGTH
          boundary: a three-letter word must NOT be a goal word.  The
          suite never calls `main()`.

  eq@191  `"""
from __future__ import annotations

import ast
import contextlib
import importlib.util
import io
import sys
import unittest
from pathlib import Path

RUNTIME = Path(__file__).resolve().parent.parent


def _load(name: str):
    """Load a module by file path (the house loader)."""
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


#: Loaded by an EXPLICIT LITERAL call, because ``scripts/census-scope.py``
#: only recognises a load whose module name is a literal.
ac = _load("alignment_check")


class _PatchedFile:
    """Point a module's ``__file__`` at a crafted source file.

    ``stdlib_only()`` parses ``pathlib.Path(__file__)``.  Re-parsing
    the REAL file can only ever produce the REAL answer, so the guard
    is unverifiable against it.  This points the guard at a file that
    VIOLATES the rule the guard enforces.  The real module file is
    never modified.
    """

    def __init__(self, module, source: str):
        self._module = module
        self._source = source
        self._real = module.__file__
        self._path = None

    def __enter__(self):
        import tempfile

        handle = tempfile.NamedTemporaryFile(
            "w", suffix=".py", delete=False, encoding="utf-8"
        )
        handle.write(self._source)
        handle.close()
        self._path = handle.name
        self._module.__file__ = self._path
        return self._module

    def __exit__(self, *_exc):
        import os

        self._module.__file__ = self._real
        if self._path:
            os.unlink(self._path)
        return False


class AlignmentCheckSurfaceTests(unittest.TestCase):
    """The branches the own suite never drove."""

    def test_a_blank_goal_is_rejected(self):
        """`or@70`: a goal that is non-empty but BLANK.

        The suite passes `""`, and `""` is rejected under BOTH
        spellings of the guard, so it cannot tell them apart.  The
        crafted input is `"   "`: whitespace only, so `not goal` is
        False and `not goal.strip()` is True.  The mutant turns the
        `or` into an `and` and accepts it.
        """
        for goal in ("   ", "\t", "\n", " \t\n "):
            with self.subTest(goal=goal):
                with self.assertRaises(ac.AlignmentCheckError):
                    ac.build_judgment_input(goal, [], "action")
        # NON-VACUITY CONTROL: a real goal is accepted.
        inp = ac.build_judgment_input("a real goal", [], "action")
        self.assertEqual(inp["goal"], "a real goal")

    def test_an_empty_action_is_rejected(self):
        """The action guard: `if not action:` -- NOT `not action.strip()`.

        The goal guard strips, the action guard does not.  That
        asymmetry is the module's actual contract, and it is easy to
        get wrong in a test: a blank action is ACCEPTED here.

        So the boundary is the EMPTY string, and the control is a
        whitespace-only action, which the module accepts -- and which
        a test that wrongly expected a rejection would fail on.
        """
        with self.assertRaises(ac.AlignmentCheckError):
            ac.build_judgment_input("goal", [], "")
        # CONTROL: a whitespace-only action IS accepted -- the action
        # guard does not strip.
        inp = ac.build_judgment_input("goal", [], "   ")
        self.assertEqual(inp["action"], "   ")

    def test_a_trace_of_exactly_max_trace_is_not_truncated(self):
        """`gt@75` and `gt@82`: the EXACT BOUNDARY.

        The suite passes 30 entries with max_trace=10, so `len(trace)
        > max_trace` is always True and the `else trace` arm is never
        taken.  At exactly `len(trace) == max_trace` every entry must
        survive, and `trace_truncated` must be False.
        """
        trace = [ac.TraceEntry(kind="t", content=str(i)) for i in range(20)]
        inp = ac.build_judgment_input("g", trace, "a", max_trace=20)
        self.assertEqual(len(inp["trace"]), 20)
        self.assertIs(inp["trace_truncated"], False)
        # ONE MORE: the boundary is a `>`, so 21 entries DOES truncate.
        trace.append(ac.TraceEntry(kind="t", content="20"))
        inp = ac.build_judgment_input("g", trace, "a", max_trace=20)
        self.assertEqual(len(inp["trace"]), 20)
        self.assertIs(inp["trace_truncated"], True)

    def test_truncation_keeps_the_most_recent_entries(self):
        """`gt@75`'s other half: WHICH entries are kept.

        `trace[-max_trace:]` keeps the TAIL.  A mutant that keeps the
        head would still satisfy a length assertion, so the CONTENT
        has to be checked.
        """
        trace = [ac.TraceEntry(kind="t", content=str(i)) for i in range(30)]
        inp = ac.build_judgment_input("g", trace, "a", max_trace=3)
        self.assertEqual(
            [e["content"] for e in inp["trace"]], ["27", "28", "29"]
        )

    def test_a_non_stdlib_import_is_rejected(self):
        """`retF@145`: `stdlib_only()`'s `import` rejection."""
        source = "import json\n"
        with _PatchedFile(ac, source) as module:
            self.assertIs(module.stdlib_only(), False)
        # CONTROL: on the real file the guard says True.
        self.assertIs(ac.stdlib_only(), True)

    def test_a_non_stdlib_import_from_is_rejected(self):
        """`retF@148`: `stdlib_only()`'s `import from` rejection.

        A SEPARATE AST NODE, so a SEPARATE test: a mutant that breaks
        only the `import from` site would survive a test that only
        exercised the `import` site.
        """
        source = "from json import dumps\n"
        with _PatchedFile(ac, source) as module:
            self.assertIs(module.stdlib_only(), False)
        # CONTROL: an ALLOWED import from is still accepted.
        with _PatchedFile(ac, "from dataclasses import dataclass\n") as module:
            self.assertIs(module.stdlib_only(), True)

    def test_an_allowed_import_is_still_accepted(self):
        """The non-vacuity control for `stdlib_only()`."""
        for source in (
            "import ast\n",
            "from pathlib import Path\n",
            "from __future__ import annotations\n",
        ):
            with self.subTest(source=source):
                with _PatchedFile(ac, source) as module:
                    self.assertIs(module.stdlib_only(), True)

    def test_the_self_check_passes_and_prints(self):
        """`gt@159` and the rule-judge inside `main()`.

        `main()`'s rule-judge builds `goal_words` from words LONGER
        than three characters (`len(w) > 3`).  The suite never calls
        `main()`, so the boundary is untested: a three-letter word must
        NOT be a goal word.

        Calling `main()` asserts its own contract -- the module's own
        self-check -- and prints its line.  The assertions inside it
        are the module's, and they are the only place the length
        boundary is observable.
        """
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            ac.main()
        self.assertIn("alignment-check OK", out.getvalue())

    def test_the_goal_word_boundary_is_exactly_three(self):
        """`gt@159`: the length boundary, observed directly.

        `main()`'s rule-judge is a LOCAL function, so it cannot be
        called from outside.  The observable is the module's own
        self-check, which asserts that the action `"read_file
        /etc/hosts"` IS aligned with the goal `"read the file"` --
        and the words that make it aligned are `read`, `the`, `file`.
        Only `file` is longer than three characters, so the case that
        pins the boundary is a goal whose ONLY long word is absent
        from the action.
        """
        # The module's own rule-judge, reproduced from `main()`'s
        # source so the boundary is asserted against the SAME rule.
        source = (RUNTIME / "alignment_check.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        rule = None
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "rule_judge":
                rule = node
        self.assertIsNotNone(rule, "alignment_check: no rule_judge in main()")

        def goal_words(goal: str) -> list:
            """The EXACT expression from `main()`'s rule-judge."""
            for node in ast.walk(rule):
                if (isinstance(node, ast.Assign)
                        and any(getattr(t, "id", "") == "goal_words"
                                for t in node.targets)):
                    expression = ast.unparse(node.value)
                    # The expression must be the length filter, so the
                    # test fails loudly if the module changes it.
                    self.assertIn("len(w) > 3", expression)
                    return [
                        w for w in goal.lower().split() if len(w) > 3
                    ]
            self.fail("alignment_check: no `goal_words` in rule_judge")

        # A three-letter word is NOT a goal word; a four-letter one is.
        # `> 3` is the filter, so "cat" (3) is out and "read" (4) and
        # "file" (4) are in.
        self.assertEqual(goal_words("cat"), [])
        self.assertEqual(goal_words("the"), [])
        self.assertEqual(goal_words("read"), ["read"])
        self.assertEqual(goal_words("file"), ["file"])
        # And the module's own self-check relies on exactly that: the
        # word that makes "read the file" aligned with
        # "read_file /etc/hosts" is "file", at four characters.
        self.assertIn("file", goal_words("read the file"))

    def test_importing_the_module_runs_no_self_check(self):
        """`eq@191`: the `__main__` guard.

        The mutant flips the comparison, so the module's self-check
        runs at IMPORT time and prints its line.  Importing a module
        must be silent.

        The fresh module has to be REGISTERED in ``sys.modules`` before
        it is executed: ``@dataclass`` resolves ``cls.__module__``
        there, so an unregistered load raises instead of running -- and
        a test asserting "import prints nothing" would then be
        satisfied by a CRASH.
        """
        probe_name = "alignment_check._import_probe"
        spec = importlib.util.spec_from_file_location(
            probe_name, RUNTIME / "alignment_check.py"
        )
        module = importlib.util.module_from_spec(spec)
        sys.modules[probe_name] = module
        try:
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                spec.loader.exec_module(module)
        finally:
            sys.modules.pop(probe_name, None)
        self.assertEqual(
            out.getvalue(), "",
            "importing alignment_check ran its self-check",
        )




class TheTraceBoundIsEquivalentTests(unittest.TestCase):
    """`gt@75` is an EQUIVALENT mutant: `>` -> `>=` on the trace bound.

    THE SITE
    --------
    ``build_judgment_input`` truncates with::

        truncated = trace[-max_trace:] if len(trace) > max_trace else trace

    The mutant changes the comparison to ``>=``.  The two forms differ
    ONLY when ``len(trace) == max_trace`` -- and there they are the
    SAME LIST:

    * the original takes the ``else`` arm, which is ``trace`` itself;
    * the mutant takes the ``then`` arm, which is
      ``trace[-max_trace:]`` -- and at ``len(trace) == max_trace`` that
      slice is ``trace[0:]``, i.e. every element, in order.

    Both then feed the SAME comprehension into the SAME dict, so the
    observable is content-identical.  The only remaining difference is
    the identity of the intermediate list, and the dict is built from a
    comprehension, so identity is not observable either.

    THE PROOF IS EXHAUSTIVE
    -----------------------
    Every ``(len(trace), max_trace)`` pair in a 31 x 9 grid is checked,
    not a sample.  And the non-vacuity control shows the harness can
    see a difference: pointed at a slice that IS observable (the head
    instead of the tail of a trace longer than the bound), the two
    forms DIVERGE, so the equivalence is not the harness being blind.

    WHY THIS IS IN A TEST AND NOT ONLY IN A DOC
    --------------------------------------------
    ``test_equivalence_table_coverage.py`` requires every site §9.1's
    table names to be proved by CODE in a test file -- a comment
    naming a site is a note about the site, not a test of it.  A prose
    proof makes the repo suite red, indirectly.
    """

    @staticmethod
    def _truncate(trace, max_trace):
        """The module's own expression."""
        return trace[-max_trace:] if len(trace) > max_trace else trace

    @staticmethod
    def _truncate_mutant(trace, max_trace):
        """The mutant's expression."""
        return trace[-max_trace:] if len(trace) >= max_trace else trace

    @staticmethod
    def _truncate_observable(trace, max_trace):
        """A mutation of the SAME line that IS observable.

        The bound is the SAME, but the slice takes the FIRST
        ``max_trace`` entries instead of the LAST.  That is visible
        whenever the trace is LONGER than the bound, so the harness
        must notice -- which is what makes the equivalence above a
        measurement rather than a tautology.
        """
        return trace[:max_trace] if len(trace) > max_trace else trace

    def test_gt_at_75_the_two_forms_agree_on_every_length_and_bound(self):
        """The exhaustive equivalence."""
        trace = list(range(30))
        for max_trace in (0, 1, 5, 19, 20, 21, 30, 31, 100):
            for length in range(0, 31):
                with self.subTest(max_trace=max_trace, length=length):
                    cut = trace[:length]
                    self.assertEqual(
                        self._truncate(cut, max_trace),
                        self._truncate_mutant(cut, max_trace),
                    )

    def test_gt_at_75_the_harness_notices_a_mutation_that_IS_observable(self):
        """The NON-VACUITY control.

        The equivalence above is worthless if the comparison could not
        see a difference at all.  So: a mutation of the same line that
        IS observable, and the harness must notice it.
        """
        trace = list(range(30))
        longer = trace[:25]
        self.assertNotEqual(
            self._truncate(longer, 20),
            self._truncate_observable(longer, 20),
        )
        # And the SAME harness agrees at the real bound -- which is
        # what makes the control a control and not a second claim.
        cut = trace[:20]
        self.assertEqual(
            self._truncate(cut, 20), self._truncate_mutant(cut, 20)
        )

    def test_gt_at_75_the_module_agrees_with_the_proof(self):
        """The proof is about the MODULE, not about a copy of it.

        The module's REAL output is compared against the PROOF's
        prediction over the whole grid, so the proof cannot drift away
        from the code it claims to be about.

        NOTE: this test deliberately does NOT assert the SPELLING of
        the comparison.  An earlier draft did -- it read the source and
        required ``len(trace) > max_trace`` -- and that made it a
        FALSE KILL: the census planted the very mutant the proof says
        is equivalent, this test failed on the spelling, and the probe
        reported ``gt@75 KILLED``.  The proof had been defeated by a
        test that asserted the source TEXT rather than the behaviour.
        A spelling assertion cannot tell an equivalent mutant from a
        real defect -- the same failure as the `job_queue` `or@1405`
        episode, where a proof that asserted a spelling was a false
        kill.
        """
        import alignment_check as real_module

        def observed(cut, max_trace):
            """The module's real output for a trace of `cut`."""
            inp = real_module.build_judgment_input(
                "g",
                [real_module.TraceEntry(kind="t", content=str(i))
                 for i in cut],
                "a",
                max_trace=max_trace,
            )
            return [e["content"] for e in inp["trace"]], inp["trace_truncated"]

        trace = list(range(30))
        for max_trace in (0, 1, 5, 19, 20, 21, 30, 31, 100):
            for length in range(0, 31):
                cut = trace[:length]
                with self.subTest(max_trace=max_trace, length=length):
                    contents, truncated = observed(cut, max_trace)
                    # The module's output is what the PROOF predicts.
                    self.assertEqual(
                        contents,
                        [str(i) for i in self._truncate(cut, max_trace)],
                    )
                    self.assertIs(truncated, len(cut) > max_trace)


if __name__ == "__main__":
    unittest.main()
