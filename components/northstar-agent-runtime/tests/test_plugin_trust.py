"""Plugin claim-evidence tiering: declarations need evidence, or the tier drops.

Every test below is one promise of the ERC-8004 validation-semantics port:

1. A trust-implying claim (publisher, compatibility.platforms, policy) with
   verifiable evidence counts toward the top tier.
2. The same claim without evidence *downgrades* the tier - it is never a refusal,
   because a declaration without proof is still a declaration.
3. *Malformed* evidence (bad digest, unknown kind/claim/key) is refused at parse:
   a broken binding is not weak evidence.
4. A forged publisher name gains no tier from the forgery itself.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

import support  # noqa: F401  (bootstraps sys.path)

import plugin_manifest as pm
import plugin_trust as pt

MANIFEST_HEAD = (
    'schema_version = "northstar.plugin.v1"\n'
    'name = "demo"\n'
    'version = "0.1.0"\n'
    'publisher = "arena"\n'
    'description = "A bundle that does very little."\n'
)

DIGEST = "sha256:" + "ab" * 32


def evidence_toml(*items: tuple[str, str]) -> str:
    lines = []
    for kind, claim in items:
        lines += [
            "[[evidence]]",
            f'kind = "{kind}"',
            f'claim = "{claim}"',
            'ref = "bench:northstar.governance.bench#x"',
            f'digest = "{DIGEST}"',
        ]
    return "\n".join(lines) + ("\n" if lines else "")


class BundleCase(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(support.tempfile.mkdtemp(prefix="nsar-trust-"))
        self.addCleanup(support.shutil.rmtree, self.root, True)

    def parse(self, manifest: str) -> pm.PluginManifest:
        root = self.root / "demo"
        root.mkdir(parents=True, exist_ok=True)
        (root / pm.MANIFEST_NAME).write_text(manifest, encoding="utf-8")
        return pm.parse_manifest(pm.load_bundle(root))

    def tier(self, manifest: pm.PluginManifest, *, pinned: bool, loadable: bool = True) -> tuple[str, tuple[str, ...]]:
        covered = frozenset(item.claim for item in manifest.evidence)
        return pt.trust_tier(loadable=loadable, pinned=pinned, covered_claims=covered)


class EvidenceParsingTests(BundleCase):
    def test_no_evidence_section_parses_to_empty(self):
        manifest = self.parse(MANIFEST_HEAD)
        self.assertEqual(manifest.evidence, ())

    def test_well_formed_evidence_parses(self):
        manifest = self.parse(MANIFEST_HEAD + evidence_toml(("attestation", "publisher"), ("bench", "policy")))
        self.assertEqual(len(manifest.evidence), 2)
        self.assertEqual(manifest.evidence[0].kind, "attestation")
        self.assertEqual(manifest.evidence[0].claim, "publisher")
        self.assertEqual(manifest.evidence[0].digest, DIGEST)

    def test_unknown_kind_is_refused(self):
        with self.assertRaises(pm.PluginError) as caught:
            self.parse(MANIFEST_HEAD + evidence_toml(("vibes", "publisher")))
        self.assertIn("kind", str(caught.exception))

    def test_unknown_claim_is_refused(self):
        with self.assertRaises(pm.PluginError) as caught:
            self.parse(MANIFEST_HEAD + evidence_toml(("bench", "description")))
        self.assertIn("claim", str(caught.exception))

    def test_malformed_digest_is_refused(self):
        text = evidence_toml(("bench", "policy")).replace(DIGEST, "sha256:xyz")
        with self.assertRaises(pm.PluginError) as caught:
            self.parse(MANIFEST_HEAD + text)
        self.assertIn("digest", str(caught.exception))

    def test_unknown_evidence_key_is_refused(self):
        text = evidence_toml(("bench", "policy")) + 'witness = "mallory"\n'
        with self.assertRaises(pm.PluginError) as caught:
            self.parse(MANIFEST_HEAD + text)
        self.assertIn("witness", str(caught.exception))

    def test_empty_ref_is_refused(self):
        text = evidence_toml(("bench", "policy")).replace(
            'ref = "bench:northstar.governance.bench#x"', 'ref = ""'
        )
        with self.assertRaises(pm.PluginError) as caught:
            self.parse(MANIFEST_HEAD + text)
        self.assertIn("ref", str(caught.exception))

    def test_evidence_must_be_a_list(self):
        with self.assertRaises(pm.PluginError):
            self.parse(MANIFEST_HEAD + '[evidence]\nkind = "bench"\n')


class TieringTests(BundleCase):
    def test_full_evidence_pinned_is_evidenced(self):
        manifest = self.parse(
            MANIFEST_HEAD
            + evidence_toml(
                ("attestation", "publisher"),
                ("bench", "compatibility.platforms"),
                ("review", "policy"),
            )
        )
        tier, gaps = self.tier(manifest, pinned=True)
        self.assertEqual(tier, pt.TIER_EVIDENCED)
        self.assertEqual(gaps, ())

    def test_missing_evidence_downgrades_pinned_to_reviewed(self):
        manifest = self.parse(MANIFEST_HEAD)
        tier, gaps = self.tier(manifest, pinned=True)
        self.assertEqual(tier, pt.TIER_REVIEWED)
        self.assertEqual(set(gaps), set(pt.COVERABLE_CLAIMS))

    def test_forged_publisher_gains_no_tier(self):
        manifest = self.parse(MANIFEST_HEAD.replace('publisher = "arena"', 'publisher = "northstar-official"'))
        tier, gaps = self.tier(manifest, pinned=True)
        self.assertEqual(tier, pt.TIER_REVIEWED)
        self.assertIn("publisher", gaps)

    def test_unpinned_is_declared_even_with_evidence(self):
        manifest = self.parse(
            MANIFEST_HEAD
            + evidence_toml(
                ("attestation", "publisher"),
                ("bench", "compatibility.platforms"),
                ("review", "policy"),
            )
        )
        tier, _gaps = self.tier(manifest, pinned=False)
        self.assertEqual(tier, pt.TIER_DECLARED)

    def test_not_loadable_is_refused(self):
        manifest = self.parse(MANIFEST_HEAD)
        tier, gaps = self.tier(manifest, pinned=True, loadable=False)
        self.assertEqual(tier, pt.TIER_REFUSED)
        self.assertTrue(gaps)

    def test_partial_evidence_still_caps_at_reviewed(self):
        manifest = self.parse(MANIFEST_HEAD + evidence_toml(("seal", "publisher")))
        tier, gaps = self.tier(manifest, pinned=True)
        self.assertEqual(tier, pt.TIER_REVIEWED)
        self.assertEqual(set(gaps), {"compatibility.platforms", "policy"})

    def test_tier_ordering(self):
        self.assertEqual(
            pt.TIERS,
            (pt.TIER_REFUSED, pt.TIER_DECLARED, pt.TIER_REVIEWED, pt.TIER_EVIDENCED),
        )


if __name__ == "__main__":
    unittest.main()
