"""Unit tests for the in-toto-derived step-compliance rule engine."""
from __future__ import annotations

import hashlib
import unittest

import support  # noqa: F401 — sys.path bootstrap

from step_compliance import (
    Link,
    RuleError,
    StepLayout,
    parse_rule,
    verify_layout,
)


def digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


H_RAW = digest("raw content v1")
H_RAW_TAMPERED = digest("raw content EVIL")
H_REPORT = digest("report v1")
H_MANIFEST = digest("manifest v1")


def honest_links() -> tuple[Link, ...]:
    return (
        Link(name="fetch", materials={}, products={"raw.json": H_RAW}),
        Link(
            name="transform",
            materials={"raw.json": H_RAW},
            products={"report.txt": H_REPORT},
        ),
        Link(
            name="publish",
            materials={"report.txt": H_REPORT},
            products={"manifest.json": H_MANIFEST},
        ),
    )


def chain_layout() -> tuple[StepLayout, ...]:
    return (
        StepLayout(
            name="fetch",
            expected_materials=(),
            expected_products=("CREATE raw.json", "DISALLOW *"),
        ),
        StepLayout(
            name="transform",
            expected_materials=("MATCH raw.json WITH PRODUCTS FROM fetch",),
            expected_products=("CREATE report.txt", "DISALLOW *"),
        ),
        StepLayout(
            name="publish",
            expected_materials=("MATCH report.txt WITH PRODUCTS FROM transform",),
            expected_products=("CREATE manifest.json", "DISALLOW *"),
        ),
    )


class ParseRuleTest(unittest.TestCase):
    def test_all_seven_kinds(self):
        kinds = {
            "MATCH a WITH PRODUCTS FROM s": "MATCH",
            "CREATE a.txt": "CREATE",
            "DELETE a.txt": "DELETE",
            "MODIFY a.txt": "MODIFY",
            "ALLOW a.txt": "ALLOW",
            "DISALLOW *": "DISALLOW",
            "REQUIRE a.txt": "REQUIRE",
        }
        for text, kind in kinds.items():
            self.assertEqual(parse_rule(text).kind, kind, text)

    def test_match_prefixes(self):
        rule = parse_rule("MATCH data/x IN in/ WITH MATERIALS IN out/ FROM build")
        self.assertEqual(rule.src_prefix, "in/")
        self.assertEqual(rule.with_side, "MATERIALS")
        self.assertEqual(rule.dst_prefix, "out/")
        self.assertEqual(rule.from_step, "build")

    def test_garbage_rejected(self):
        for bad in ("", "FROBNICATE x", "MATCH", "CREATE", "MATCH x FROM"):
            with self.assertRaises(RuleError, msg=bad):
                parse_rule(bad)


class ChainTest(unittest.TestCase):
    def test_honest_chain_passes(self):
        verdict = verify_layout(chain_layout(), honest_links())
        self.assertTrue(verdict.ok, verdict.reasons)
        self.assertEqual(len(verdict.step_verdicts), 3)

    def test_tampered_material_hash_fails(self):
        links = list(honest_links())
        links[1] = Link(
            name="transform",
            materials={"raw.json": H_RAW_TAMPERED},  # swapped mid-chain
            products={"report.txt": H_REPORT},
        )
        verdict = verify_layout(chain_layout(), tuple(links))
        self.assertFalse(verdict.ok)
        self.assertTrue(
            any("MATCH" in reason and "tampered" in reason for reason in verdict.reasons),
            verdict.reasons,
        )

    def test_replaced_product_fails_downstream_match(self):
        links = list(honest_links())
        links[2] = Link(
            name="publish",
            materials={"report.txt": H_RAW},  # wrong artifact masquerading
            products={"manifest.json": H_MANIFEST},
        )
        verdict = verify_layout(chain_layout(), tuple(links))
        self.assertFalse(verdict.ok)
        self.assertTrue(any("MATCH" in r for r in verdict.reasons), verdict.reasons)

    def test_skipped_step_fails(self):
        links = (honest_links()[0], honest_links()[2])
        verdict = verify_layout(chain_layout(), links)
        self.assertFalse(verdict.ok)
        self.assertTrue(any("transform" in r for r in verdict.reasons), verdict.reasons)

    def test_reordered_steps_fail(self):
        links = (honest_links()[1], honest_links()[0], honest_links()[2])
        verdict = verify_layout(chain_layout(), links)
        self.assertFalse(verdict.ok)

    def test_undeclared_step_fails(self):
        links = honest_links() + (Link(name="exfiltrate", products={"loot": "x"}),)
        verdict = verify_layout(chain_layout(), links)
        self.assertFalse(verdict.ok)

    def test_unexpected_artifact_hits_disallow(self):
        links = list(honest_links())
        links[0] = Link(
            name="fetch",
            materials={},
            products={"raw.json": H_RAW, "debug.log": digest("oops")},
        )
        verdict = verify_layout(chain_layout(), tuple(links))
        self.assertFalse(verdict.ok)
        self.assertTrue(any("DISALLOW" in r for r in verdict.reasons), verdict.reasons)

    def test_require_missing_fails(self):
        layout = (
            StepLayout(
                name="only",
                expected_materials=(),
                expected_products=("REQUIRE manifest.json", "ALLOW manifest.json"),
            ),
        )
        verdict = verify_layout(layout, (Link(name="only", products={}),))
        self.assertFalse(verdict.ok)
        self.assertTrue(any("REQUIRE" in r for r in verdict.reasons), verdict.reasons)

    def test_require_present_but_unconsumed_still_fails(self):
        # REQUIRE does not consume: a lone REQUIRE leaves the artifact orphaned.
        layout = (
            StepLayout(
                name="only",
                expected_materials=(),
                expected_products=("REQUIRE manifest.json",),
            ),
        )
        verdict = verify_layout(
            layout, (Link(name="only", products={"manifest.json": H_MANIFEST}),)
        )
        self.assertFalse(verdict.ok)
        self.assertTrue(any("unconsumed" in r for r in verdict.reasons), verdict.reasons)

    def test_require_plus_allow_passes(self):
        layout = (
            StepLayout(
                name="only",
                expected_materials=(),
                expected_products=("REQUIRE manifest.json", "ALLOW manifest.json"),
            ),
        )
        verdict = verify_layout(
            layout, (Link(name="only", products={"manifest.json": H_MANIFEST}),)
        )
        self.assertTrue(verdict.ok, verdict.reasons)


class RuleSemanticsTest(unittest.TestCase):
    def _one(self, rules: tuple[str, ...], materials=None, products=None):
        layout = (
            StepLayout(name="s", expected_materials=(), expected_products=rules),
        )
        link = Link(
            name="s", materials=materials or {}, products=products or {}
        )
        return verify_layout(layout, (link,))

    def test_rule_order_is_significant(self):
        products = {"tmp/x": digest("x")}
        ok = self._one(("ALLOW tmp/*", "DISALLOW *"), products=products)
        self.assertTrue(ok.ok, ok.reasons)
        bad = self._one(("DISALLOW tmp/*", "ALLOW *"), products=products)
        self.assertFalse(bad.ok)

    def test_create_rejects_preexisting_material(self):
        verdict = self._one(
            ("CREATE a.txt",),
            materials={"a.txt": H_RAW},
            products={"a.txt": H_RAW},
        )
        self.assertFalse(verdict.ok)
        self.assertTrue(any("CREATE" in r for r in verdict.reasons))

    def test_delete(self):
        ok = self._one(("DELETE a.txt",), materials={"a.txt": H_RAW})
        # DELETE applies to the materials queue only in expected_materials;
        # here it sits in expected_products so 'a.txt' is unconsumed -> fail.
        self.assertFalse(ok.ok)

    def test_modify_consumes_both_queues(self):
        layout = (
            StepLayout(
                name="s",
                expected_materials=("MODIFY a.txt",),
                expected_products=(),
            ),
        )
        link = Link(
            name="s",
            materials={"a.txt": H_RAW},
            products={"a.txt": H_RAW_TAMPERED},
        )
        verdict = verify_layout(layout, (link,))
        self.assertTrue(verdict.ok, verdict.reasons)

    def test_modify_unchanged_hash_fails(self):
        layout = (
            StepLayout(
                name="s",
                expected_materials=("MODIFY a.txt",),
                expected_products=(),
            ),
        )
        link = Link(
            name="s", materials={"a.txt": H_RAW}, products={"a.txt": H_RAW}
        )
        verdict = verify_layout(layout, (link,))
        self.assertFalse(verdict.ok)

    def test_match_with_prefixes(self):
        layout = (
            StepLayout(
                name="build",
                expected_materials=(),
                expected_products=("CREATE out/bin", "DISALLOW *"),
            ),
            StepLayout(
                name="ship",
                expected_materials=(
                    "MATCH pkg/bin IN pkg/ WITH PRODUCTS IN out/ FROM build",
                ),
                expected_products=(),
            ),
        )
        links = (
            Link(name="build", products={"out/bin": H_RAW}),
            Link(name="ship", materials={"pkg/bin": H_RAW}),
        )
        verdict = verify_layout(layout, links)
        self.assertTrue(verdict.ok, verdict.reasons)

    def test_match_cannot_reference_later_or_self(self):
        layout = (
            StepLayout(
                name="s",
                expected_materials=("MATCH a WITH PRODUCTS FROM s",),
                expected_products=(),
            ),
        )
        link = Link(name="s", materials={"a": H_RAW}, products={"a": H_RAW})
        verdict = verify_layout(layout, (link,))
        self.assertFalse(verdict.ok)
        self.assertTrue(any("not an earlier step" in r for r in verdict.reasons))

    def test_fnmatch_wildcards(self):
        ok = self._one(("CREATE *.json",), products={"raw.json": H_RAW})
        self.assertTrue(ok.ok, ok.reasons)
        bad = self._one(("CREATE *.txt",), products={"raw.json": H_RAW})
        self.assertFalse(bad.ok)


if __name__ == "__main__":
    unittest.main()
