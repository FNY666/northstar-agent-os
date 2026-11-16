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

import tomllib
import unittest
from pathlib import Path

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


if __name__ == "__main__":
    unittest.main()
