"""Every shipped runtime module must carry a recorded documentation decision.

The API reference is built from an explicit manifest (``docbuild.MANIFEST``).
A module that ships -- that is, that is listed in the component's
``pyproject.toml`` ``py-modules`` array and is therefore installed by
``pip install .`` -- must appear in the manifest (published) or in the
exclusions (a recorded decision not to publish it).

The batch added 53 shipped runtime modules without either decision, so the
API reference silently shrank while the shipped surface grew.  These tests
pin the invariant that closes that hole:

* a shipped module is either published or explicitly excluded;
* a published module's page is up to date with its docstrings;
* the exclusions never name a module that does not exist;
* the manifest and the exclusions never overlap.

They are written against ``tests/docbuild.py`` -- the generator itself --
so they fail when the invariant is broken, not when a copy of it is.
"""
from __future__ import annotations

import ast
import contextlib
import io
import tempfile
import tomllib
import unittest
from pathlib import Path
from unittest import mock

import docbuild

ROOT = docbuild.ROOT
RUNTIME = "northstar-agent-runtime"


def _pyproject_modules(component: str) -> set[str]:
    """The modules the component's ``pyproject.toml`` installs.

    ``py-modules`` is what ``pip install .`` puts on the path, so it is the
    shipped surface -- the strongest available statement of "this is public".
    """
    path = ROOT / "components" / component / "pyproject.toml"
    with path.open("rb") as handle:
        data = tomllib.load(handle)
    return set(data["tool"]["setuptools"]["py-modules"])


def _manifest(component: str) -> set[str]:
    return set(docbuild.MANIFEST.get(component, ()))


def _exclusions(component: str) -> set[str]:
    return set(docbuild.MANIFEST_EXCLUSIONS.get(component, frozenset()))


class ShippedModuleDocumentationTests(unittest.TestCase):
    """The invariant: shipping a module forces a documentation decision."""

    def test_every_shipped_runtime_module_is_published_or_explicitly_excluded(self):
        shipped = _pyproject_modules(RUNTIME)
        decided = _manifest(RUNTIME) | _exclusions(RUNTIME)
        undecided = sorted(shipped - decided)
        self.assertEqual(
            undecided,
            [],
            "shipped runtime modules with no documentation decision -- add them to "
            "docbuild.MANIFEST (publish) or to docbuild.MANIFEST_EXCLUSIONS "
            f"(record why not): {undecided}",
        )

    def test_the_batch_modules_that_escaped_the_decision_are_all_accounted_for(self):
        # The 53 modules the batch shipped without a decision.  Named
        # explicitly so that the fix cannot be a wholesale widening of the
        # manifest that would hide a *different* module escaping later.
        escaped = {
            "actionable_digest", "agent_handoff", "annotation_pin", "approval_rules",
            "artifact_authority", "cancellation_tombstone", "capability_ceiling_probe",
            "checkpoint_durability", "checkpoint_store", "cost_per_delivery",
            "coverage_manifest", "deterministic_gate_score", "durable_resume",
            "effect_directive", "effort_scaling", "endpoint_identity", "episode_eviction",
            "event_condenser", "evidence_independence", "false_green_detector",
            "horizon_gate", "intent_bound_retry", "key_custody", "leased_task_claim",
            "ledger_concurrency", "merged_tree_review", "refusal_hold",
            "refusal_hold_wiring", "refusal_row", "resume_validation",
            "retry_clears_writes", "retry_config", "reversible_compaction",
            "revision_checked_tool_results", "runtime_registration", "scope_qualifier",
            "scope_verbatim_compaction", "scorer_disagreement", "session_memory",
            "shutdown_unwind", "signed_receipt", "silent_failure_detector",
            "speaker_selector", "stale_checkpoint_gate", "state_budget",
            "step_reliability_budget", "strands_checkpoint", "stuck_detector",
            "swe_failure_modes", "tool_failure", "tool_output_filter",
            "turn_truncation", "verifiability_tier",
        }
        decided = _manifest(RUNTIME) | _exclusions(RUNTIME)
        self.assertEqual(
            sorted(escaped - decided),
            [],
            "these shipped modules still carry no documentation decision",
        )

    def test_the_manifest_and_the_exclusions_never_overlap(self):
        # A module that is both published and excluded states two conflicting
        # decisions.  Whichever list it is in, the reader cannot tell which
        # one was meant.
        for component in docbuild.MANIFEST:
            with self.subTest(component=component):
                overlap = sorted(_manifest(component) & _exclusions(component))
                self.assertEqual(
                    overlap,
                    [],
                    f"{component}: published and excluded at once: {overlap}",
                )

    def test_the_exclusions_only_name_modules_that_exist_on_disk(self):
        # An exclusion that outlives its module is a lie about a decision.
        for component in docbuild.MANIFEST:
            if not (ROOT / "components" / component).is_dir():
                continue
            present = docbuild.public_modules(component)
            for name in sorted(_exclusions(component)):
                with self.subTest(component=component, name=name):
                    self.assertIn(
                        name,
                        present,
                        f"{component}: {name} excluded but not on disk",
                    )

    def test_a_published_module_is_present_on_disk(self):
        # The other direction: the manifest must not name a module that has
        # been renamed away, or the page documents a ghost.
        for component in docbuild.MANIFEST:
            root = ROOT / "components" / component
            if not root.is_dir():
                continue
            present = docbuild.public_modules(component)
            for name in sorted(_manifest(component)):
                with self.subTest(component=component, name=name):
                    self.assertIn(
                        name,
                        present,
                        f"{component}: {name} published but not on disk",
                    )


class ApiPageFreshnessTests(unittest.TestCase):
    """A published module's documentation must match its current docstrings."""

    def test_no_api_page_is_stale(self):
        stale = docbuild.stale_pages()
        self.assertEqual(
            stale,
            [],
            "docs/api pages are stale; run `python3 tests/docbuild.py build` and "
            f"commit the regeneration (stale: {', '.join(stale) or 'none'})",
        )

    def test_the_interop_page_documents_the_handoff_tombstones_parameter(self):
        # The stale interop page was `authorize_handoff`'s `tombstones`
        # parameter.  Named explicitly so a future signature change cannot
        # silently drop the parameter out of the published reference.
        page = (ROOT / "docs" / "api" / "northstar-agent-interop.md").read_text(
            encoding="utf-8"
        )
        self.assertIn("tombstones", page)

    def test_the_generation_is_reproducible(self):
        # The generator must be deterministic: two runs over the same tree
        # must produce byte-identical pages, or the committed page is a
        # coin flip and the freshness check is noise.
        for component in docbuild.MANIFEST:
            with self.subTest(component=component):
                self.assertEqual(
                    docbuild.render_page(component),
                    docbuild.render_page(component),
                )

    def test_every_published_module_appears_in_the_rendered_page(self):
        # The manifest is the input to the page; the page is the artefact a
        # reader reads.  A module that is in the manifest but has no heading
        # in the rendered page is published in principle and absent in
        # practice -- which is the failure the manifest alone cannot show.
        for component in docbuild.MANIFEST:
            page = docbuild.render_page(component)
            for module in docbuild.MANIFEST[component]:
                with self.subTest(component=component, module=module):
                    heading = f"### `{module.removesuffix('.__init__')}`"
                    self.assertIn(
                        heading,
                        page,
                        f"{component}: {module} is in the manifest but has no heading",
                    )


class ShippedModuleDocsGuardSecondHalfTests(unittest.TestCase):
    """The SECOND half of every guard in ``tests/docbuild.py``.

    These four slices SHARE one module -- ``tests/docbuild.py`` -- and the
    batch's planted-fault probe plants a fault in it and then runs EACH
    slice's OWN test file against it.  A killer test placed in one test
    file kills the mutant for that slice ONLY, so the same technique has to
    be applied in every one of the four files.

    The mutants that survived, per slice, measured with the batch's own
    probe (``b173-mutant.py --tries 64 --no-early-stop``, run against a
    copy of the tree with the unmutated module):

      exclusion-reasons           14 of 27 survived
      component-packaging-closure 20 of 27
      package-member-publication  13 of 27
      shipped-module-docs         12 of 27

    The union of the four survivor sets is the seventeen sites below.  Each
    one is a DOUBLE guard -- a type half joined to a second half by
    ``and``/``or``, or a bound compared against a constant -- and the
    existing suite drove only ONE half of each.  Under a planted fault the
    half that was never driven changes the answer, and the suite passes
    anyway.

      and@464   the ``@property`` decorator, Name form
      retT@465   its return
      retT@467   the ``@x.property`` decorator, Attribute form, its return
      eq@680     the exclusion-family lookup
      lt@755     the docstring-tag split
      retF@756   its "no tag" return
      or@808     the probe-corpus name test
      and@812    the guard-detector rule
      eq@1059    the runtime-module suffix
      and@1073   the wheel component sweep
      or@1151    the data-file scan
      eq@1157    the ``pyproject.toml`` exclusion
      or@1234    the staleness check
      or@1272    the external-link skip
      or@1298    the verify verdict
      or@1307    the argument check
      eq@1310    the build/verify dispatch

    Every test below fails when its own planted fault is applied alone.
    """

    # --- and@464 / retT@465: the Name-form property decorator ----------
    def test_a_name_decorator_that_is_not_a_property_is_not_a_property(self):
        """`and@464`: the second half of the Name-form guard.

        The guard is ``isinstance(decorator, ast.Name) AND decorator.id in
        {"property", "cached_property"}``.  The "is a known name" half
        never fires on ``@staticmethod`` -- only the type half does, and
        the type half is satisfied.  Under the mutant (``and`` -> ``or``)
        the guard would fire on ANY name decorator, and the reference
        page would drop the parentheses from a method that has arguments.
        """
        node = ast.parse("@staticmethod\ndef value(self):\n    pass\n").body[0]
        self.assertFalse(docbuild._is_property(node))

    def test_the_name_form_property_decorator_is_recognised(self):
        """`retT@465`: the return of the Name-form branch.

        A bare ``@property`` must still be recognised.  Under the mutant
        (``return True`` -> ``return False``) it would be reported as an
        ordinary method, so the page would show ``value()`` for a
        property.
        """
        node = ast.parse("@property\ndef value(self):\n    pass\n").body[0]
        self.assertTrue(docbuild._is_property(node))

    # --- retT@467: the Attribute-form property decorator ----------------
    def test_the_attribute_form_property_decorator_is_recognised(self):
        """`retT@467`: the return of the Attribute-form branch.

        ``@functools.cached_property`` is a property reached through an
        attribute, so it is this branch's own case.  Under the mutant
        (``return True`` -> ``return False``) it would lose its
        ``(property)`` marker on the reference page.
        """
        node = ast.parse(
            "@functools.cached_property\ndef value(self):\n    pass\n"
        ).body[0]
        self.assertTrue(docbuild._is_property(node))

    # --- eq@680: the exclusion-family lookup ----------------------------
    def test_a_family_lookup_returns_that_familys_members(self):
        """`eq@680`: the family that carries the requested name.

        ``family_members("ba")`` must return the ``ba`` family's members.
        Under the mutant (``==`` -> ``!=``) the lookup would accept the
        FIRST family whose name does NOT match, so a module would be
        classified under a family it does not belong to.
        """
        declared = docbuild.EXCLUSION_FAMILIES[1]
        self.assertEqual(
            docbuild.family_members(declared.name), declared.member_names()
        )
        self.assertNotEqual(
            docbuild.family_members(declared.name),
            docbuild.EXCLUSION_FAMILIES[0].member_names(),
        )

    # --- lt@755: the docstring split is strict --------------------------
    def test_a_single_docstring_marker_still_yields_the_tag(self):
        """`lt@755`: the bound, from the side that shows it is strict.

        The guard is ``if len(parts) < 2: return False``.  A source whose
        docstring marker has no closing marker splits into exactly TWO
        parts, and the second still carries the tag -- so the tag must be
        found.  With the bound weakened to ``<= 2`` the guard would
        return False and the tag would be missed.
        """
        source = '"""Module docstring carrying (D-OUT-123) and no closing marker'
        with mock.patch.object(docbuild, "_module_source", return_value=source):
            self.assertTrue(docbuild._has_design_tag(RUNTIME, "any"))

    # --- retF@756: the "no docstring at all" answer --------------------
    def test_a_source_with_no_docstring_marker_has_no_tag(self):
        """`retF@756`: the "there is no docstring" answer.

        A source with no ``\"\"\"`` marker at all splits into exactly ONE
        part, so there is nothing to scan and the answer must be False.
        Under the mutant (``return False`` -> ``return True``) every such
        module would be reported as carrying a design tag, and the
        guard-detector rule would claim modules that carry none.
        """
        with mock.patch.object(docbuild, "_module_source", return_value="x = 1\n"):
            self.assertFalse(docbuild._has_design_tag(RUNTIME, "any"))

    # --- or@808: the probe-corpus name test -----------------------------
    def test_the_probe_suffix_alone_makes_a_probe_corpus(self):
        """`or@808`: the ``_probe`` suffix -- the first half.

        The two halves are the two spellings -- ``_probe`` and
        ``_probes``.  Under the mutant (``or`` -> ``and``) a module ending
        in ``_probe`` would no longer be a probe corpus, so its exclusion
        would fall to a different reason kind.
        """
        kinds = docbuild.exclusion_reason_kinds(RUNTIME, "asi02_probe")
        self.assertIn("probe-corpus", kinds)

    # --- and@812: the guard-detector rule -------------------------------
    def test_an_untagged_module_is_not_a_guard_detector(self):
        """`and@812`: the half that has to be FALSE.

        ``egress_client`` carries no design tag, is in no family and is
        not a mock, so the tag rule must not claim it.  Under the mutant
        (``and`` -> ``or``) the second half -- ``"numbered-probe-family"
        not in kinds`` -- is true for every module, so EVERY module would
        be reported as a guard detector.
        """
        kinds = docbuild.exclusion_reason_kinds(RUNTIME, "egress_client")
        self.assertNotIn("guard-detector", kinds)

    # --- eq@1059: the runtime-module suffix ----------------------------
    def test_a_non_python_file_is_not_a_runtime_module(self):
        """`eq@1059`: the suffix half of the guard.

        The guard is ``path.is_file() AND path.suffix == ".py" AND ...``.
        A README is a file that is not Python, so it must not be counted
        as a runtime module.  Under the mutant (``==`` -> ``!=``) every
        non-Python file in a component directory would be counted, and
        the component's flat-module list would gain a name that is not a
        module at all.
        """
        readme = docbuild.ROOT / "components" / RUNTIME / "README.md"
        self.assertTrue(readme.is_file())
        self.assertFalse(docbuild.is_runtime_module(readme))

    # --- and@1073: the wheel component sweep ---------------------------
    def test_a_directory_without_a_pyproject_builds_no_wheel(self):
        """`and@1073`: the second half of the wheel sweep.

        A component directory with no ``pyproject.toml`` builds no wheel,
        so it must not be reported as shipping one.  Under the mutant
        (``and`` -> ``or``) the type half -- "it is a directory" -- would
        be enough, and every component directory would be reported.
        """
        wheels = docbuild.components_that_ship_a_wheel()
        self.assertIn(RUNTIME, wheels)
        self.assertNotIn("northstar-codex-sidecar", wheels)
        self.assertNotIn("northstar-egress-sidecar", wheels)

    # --- or@1151: the data-file scan -----------------------------------
    def test_only_data_suffixes_are_reported_as_data_files(self):
        """`or@1151`: the suffix half of the scan's skip rule.

        The rule is ``not path.is_file() OR path.suffix not in
        DATA_SUFFIXES`` -- skip anything that is not a data file.  A
        module's ``.py`` source is installed by ``py-modules`` and is not
        runtime data, so it must not be reported as one.  Under the mutant
        (``or`` -> ``and``) every file that EXISTS but is not a data file
        would be reported instead.
        """
        for name in docbuild.data_files_on_disk(RUNTIME):
            with self.subTest(name=name):
                self.assertTrue(name.endswith((".json", ".toml")), name)

    # --- eq@1157: the pyproject.toml exclusion -------------------------
    def test_the_pyproject_is_not_counted_as_a_data_file(self):
        """`eq@1157`: the packaging-configuration exclusion.

        A ``pyproject.toml`` is packaging configuration, not a file a
        module reads at runtime, so it must not be reported as a data
        file -- and the two files that ARE data files must still be
        reported.  Under the mutant (``==`` -> ``!=``) the exclusion
        would fire on every other file, and the two real data files
        would be reported INSTEAD.
        """
        found = docbuild.data_files_on_disk(RUNTIME)
        self.assertNotIn("pyproject.toml", found)
        self.assertIn("policy/dataflow.toml", found)
        self.assertIn("policy/deny_monotonicity_baseline.json", found)

    # --- or@1234: the staleness check ----------------------------------
    def test_a_stale_page_is_named_as_stale(self):
        """`or@1234`: the content half of the staleness rule.

        A committed page whose bytes differ from a fresh generation is
        stale and must be named.  Under the mutant (``or`` -> ``and``)
        the rule would only fire for a page that does not EXIST, so a
        page that is present but out of date would be reported as fresh
        -- which is exactly the drift the check exists to catch.
        """
        with tempfile.TemporaryDirectory() as tmp:
            api = Path(tmp)
            (api / "northstar-run-contract.md").write_text("stale", encoding="utf-8")
            with mock.patch.object(docbuild, "API_DIR", api), mock.patch.object(
                docbuild,
                "build_all",
                return_value={"northstar-run-contract": "fresh"},
            ):
                self.assertEqual(docbuild.stale_pages(), ["northstar-run-contract"])

    # --- or@1272: the external-link skip -------------------------------
    def test_an_external_link_is_not_a_broken_link(self):
        """`or@1272`: the first half of the skip rule.

        An ``http(s)`` or ``mailto:`` link points off-site, so it is not
        an internal link and must not be reported as broken.  Under the
        mutant (``or`` -> ``and``) the emptiness half would be the only
        one left, so every external link would be resolved against the
        local tree and reported as broken.
        """
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "doc.md").write_text(
                "[site](https://example.com/page)\n\n[mail](mailto:someone@example.com)\n",
                encoding="utf-8",
            )
            with mock.patch.object(docbuild, "ROOT", root):
                self.assertEqual(docbuild.broken_links(), [])

    # --- or@1298: the verify verdict -----------------------------------
    def test_stale_pages_alone_make_verify_fail(self):
        """`or@1298`: the two halves of the verdict.

        Stale pages and broken links are two independent failures, and
        EITHER one must fail the check.  Under the mutant (``or`` ->
        ``and``) a run with stale pages but no broken links would be
        reported as OK -- and the stale pages would go unnoticed.
        """
        with mock.patch.object(
            docbuild, "stale_pages", return_value=["northstar-run-contract"]
        ), mock.patch.object(docbuild, "broken_links", return_value=[]), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(docbuild.verify(), 1)

    # --- or@1307: the argument check -----------------------------------
    def test_running_with_no_argument_prints_the_usage(self):
        """`or@1307`: the emptiness half of the argument rule.

        With no argument at all there is no command, so the usage must
        be printed and the exit code must be 2.  Under the mutant
        (``or`` -> ``and``) the second half would be evaluated on an
        empty list and the guard would raise instead of refusing.
        """
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(docbuild.main([]), 2)

    def test_running_with_an_unknown_argument_prints_the_usage(self):
        """`or@1307`: the membership half of the argument rule.

        A command that is neither ``build`` nor ``verify`` must be
        refused with exit code 2.  Under the mutant (``or`` -> ``and``)
        an unknown command would fall through to the verify path.
        """
        with contextlib.redirect_stdout(io.StringIO()), mock.patch.object(
            docbuild, "verify", return_value=0
        ):
            self.assertEqual(docbuild.main(["nonsense"]), 2)

    # --- eq@1310: the build/verify dispatch ----------------------------
    def test_the_build_command_writes_the_pages(self):
        """`eq@1310`: the ``build`` half of the dispatch.

        ``build`` WRITES the pages.  Under the mutant (``==`` -> ``!=``)
        ``build`` would fall through to ``verify`` and write nothing, so
        the page would not exist afterwards.
        """
        with tempfile.TemporaryDirectory() as tmp:
            api = Path(tmp)
            with mock.patch.object(docbuild, "API_DIR", api), mock.patch.object(
                docbuild,
                "build_all",
                return_value={"northstar-run-contract": "fresh"},
            ), mock.patch.object(docbuild, "verify", return_value=0), mock.patch.object(
                docbuild, "ROOT", api
            ), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(docbuild.main(["build"]), 0)
            self.assertTrue((api / "northstar-run-contract.md").is_file())

    def test_the_verify_command_writes_nothing(self):
        """`eq@1310`: the ``verify`` half of the dispatch.

        ``verify`` CHECKS the pages and writes none of them.  Under the
        mutant (``==`` -> ``!=``) ``verify`` would regenerate the pages
        instead -- which would hide the very staleness it is meant to
        report.
        """
        with tempfile.TemporaryDirectory() as tmp:
            api = Path(tmp)
            with mock.patch.object(docbuild, "API_DIR", api), mock.patch.object(
                docbuild, "build_all", return_value={"northstar-run-contract": "fresh"}
            ), mock.patch.object(docbuild, "verify", return_value=0), \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(docbuild.main(["verify"]), 0)
            self.assertEqual(list(api.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
