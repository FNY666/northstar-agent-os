"""Tests for the dual-graph lineage: two graphs and the anchors between them.

These tests pin the *behaviour* of ``exploration_graph``, not its text.
The properties that matter:

* the **dedup key is computed by the program**.  An agent may not hand the
  graph a key; every asset node's key is derived from the raw fields the
  agent supplied, and the same raw fields always yield the same key while
  a different spelling of the same asset does not;
* the **exploration graph** holds goal/intent/fact/finding/hint nodes and
  spawns/derived_from/yields/proves edges, and it refuses an edge whose
  endpoints do not exist or whose relation does not fit the endpoint kinds;
* the **asset graph** holds root_domain/subdomain/ip/service/app/endpoint
  nodes, and it computes the parent/child relations itself;
* the **anchors** tie an exploration node to an asset, and they refuse an
  anchor whose node or asset does not exist;
* **lineage**: a finding traces back through its fact chain to the
  intentions and the goal that produced it, and the chain is complete and
  cycle-safe;
* **coverage**: the assets in scope that were actually tested are
  computable, and an asset anchored only by a non-fact node does not
  count as tested;
* the module is **pure and deterministic**: no clock, no network, no
  randomness, and the same inputs always yield the same keys and the
  same answers.

The design is Northstar's own.  The two-graph *idea* (an exploration
chain and a shared asset truth, joined by anchors) was learned from
WSARTEX, which is AGPL-3.0-or-later; Northstar is MIT, so no WSARTEX
code, identifiers or text are reused here.  See
``docs/design/dual-graph-lineage.md``.
"""

from __future__ import annotations

import unittest

import exploration_graph
from exploration_graph import (
    AssetGraph,
    AssetKind,
    ExplorationGraph,
    ExplorationGraphError,
    NodeKind,
    Relation,
)


def _asset(**overrides):
    """A raw asset observation -- what an agent would submit."""
    base = dict(kind=AssetKind.ROOT_DOMAIN, value="Example.COM")
    base.update(overrides)
    return base


class DedupKeyTests(unittest.TestCase):
    """The key is the program's, not the agent's."""

    def test_the_agent_cannot_supply_a_dedup_key(self):
        graph = AssetGraph()
        # ``key`` is not an accepted field: an agent that tries to pin its
        # own key is refused rather than obeyed.
        with self.assertRaises(ExplorationGraphError):
            graph.upsert_asset(_asset(key="agent-chosen-key"))

    def test_the_key_is_computed_from_the_raw_fields(self):
        graph = AssetGraph()
        node = graph.upsert_asset(_asset())
        self.assertTrue(node.key)
        self.assertNotEqual("agent-chosen-key", node.key)

    def test_the_same_raw_fields_yield_the_same_key(self):
        graph = AssetGraph()
        first = graph.upsert_asset(_asset(value="example.com"))
        second = graph.upsert_asset(_asset(value="example.com"))
        self.assertEqual(first.key, second.key)

    def test_a_different_spelling_yields_the_same_key(self):
        graph = AssetGraph()
        first = graph.upsert_asset(_asset(value="example.com"))
        second = graph.upsert_asset(_asset(value="  EXAMPLE.com.  "))
        self.assertEqual(first.key, second.key)

    def test_two_different_assets_yield_two_different_keys(self):
        graph = AssetGraph()
        first = graph.upsert_asset(_asset(value="example.com"))
        second = graph.upsert_asset(_asset(value="other.com"))
        self.assertNotEqual(first.key, second.key)

    def test_the_key_is_injective_across_asset_kinds(self):
        # The same string can be a root domain and an app name; the key
        # must not collide across kinds.
        graph = AssetGraph()
        root = graph.upsert_asset(_asset(kind=AssetKind.ROOT_DOMAIN, value="example.com"))
        app = graph.upsert_asset(_asset(kind=AssetKind.APP, value="example.com"))
        self.assertNotEqual(root.key, app.key)

    def test_a_rejected_asset_yields_no_node(self):
        graph = AssetGraph()
        with self.assertRaises(ExplorationGraphError):
            graph.upsert_asset(_asset(value="   "))
        self.assertEqual(0, len(graph.nodes()))

    def test_an_unknown_kind_is_refused(self):
        graph = AssetGraph()
        with self.assertRaises(ExplorationGraphError):
            graph.upsert_asset(_asset(kind="not-a-kind"))

    def test_the_graph_is_deterministic_across_instances(self):
        first = AssetGraph().upsert_asset(_asset(value="example.com"))
        second = AssetGraph().upsert_asset(_asset(value="example.com"))
        self.assertEqual(first.key, second.key)

    def test_the_key_carries_the_module_s_own_domain_separator(self):
        # The key is a digest over a domain-separated body, so it cannot
        # collide with a digest the runtime computes over other content.
        import hashlib

        graph = AssetGraph()
        node = graph.upsert_asset(_asset(value="example.com"))
        bare = hashlib.sha256(b"root_domain\x1fexample.com").hexdigest()
        self.assertNotIn(bare, node.key)

    def test_the_key_is_a_digest_of_the_normalised_body(self):
        # The key must be *derived*, not opaque: the same body must give
        # the same digest.  This pins that the value that reaches the
        # digest is the normalised one.
        import hashlib

        graph = AssetGraph()
        node = graph.upsert_asset(_asset(value="EXAMPLE.com"))
        body = b"root_domain\x1fexample.com"
        expected = hashlib.sha256(
            b"northstar.exploration-graph.asset.v1\x1f" + body
        ).hexdigest()
        self.assertTrue(node.key.endswith(expected))


class AssetNormalisationTests(unittest.TestCase):
    """The program normalises; the agent does not."""

    def test_a_domain_is_lowercased_and_stripped_of_a_trailing_dot(self):
        graph = AssetGraph()
        node = graph.upsert_asset(_asset(value="WWW.Example.COM."))
        self.assertEqual("www.example.com", node.value)

    def test_an_ip_is_normalised_to_its_canonical_form(self):
        graph = AssetGraph()
        node = graph.upsert_asset(_asset(kind=AssetKind.IP, value="192.168.001.001"))
        self.assertEqual("192.168.1.1", node.value)

    def test_an_ipv6_is_normalised_to_its_canonical_form(self):
        graph = AssetGraph()
        node = graph.upsert_asset(_asset(kind=AssetKind.IP, value="2001:0DB8::0001"))
        self.assertEqual("2001:db8::1", node.value)

    def test_a_malformed_ip_is_refused(self):
        graph = AssetGraph()
        with self.assertRaises(ExplorationGraphError):
            graph.upsert_asset(_asset(kind=AssetKind.IP, value="999.1.1.1"))

    def test_an_endpoint_key_covers_its_method(self):
        graph = AssetGraph()
        get = graph.upsert_asset(_asset(kind=AssetKind.ENDPOINT, value="https://a.example/x", method="get"))
        post = graph.upsert_asset(_asset(kind=AssetKind.ENDPOINT, value="https://a.example/x", method="POST"))
        self.assertNotEqual(get.key, post.key)

    def test_an_endpoint_method_is_normalised_to_upper_case(self):
        graph = AssetGraph()
        lower = graph.upsert_asset(_asset(kind=AssetKind.ENDPOINT, value="https://a.example/x", method="get"))
        upper = graph.upsert_asset(_asset(kind=AssetKind.ENDPOINT, value="https://a.example/x", method="GET"))
        self.assertEqual(lower.key, upper.key)

    def test_an_endpoint_without_a_method_matches_one_with_an_empty_method(self):
        # A missing method and an absent one are the same endpoint.
        graph = AssetGraph()
        without = graph.upsert_asset(_asset(kind=AssetKind.ENDPOINT, value="https://a.example/x"))
        with_empty = graph.upsert_asset(
            _asset(kind=AssetKind.ENDPOINT, value="https://a.example/x", method="  "))
        self.assertEqual(without.key, with_empty.key)

    def test_a_service_key_covers_its_port(self):
        graph = AssetGraph()
        eighty = graph.upsert_asset(_asset(kind=AssetKind.SERVICE, value="a.example", port=80))
        eighteighty = graph.upsert_asset(_asset(kind=AssetKind.SERVICE, value="a.example", port=8080))
        self.assertNotEqual(eighty.key, eighteighty.key)


class AssetGraphStructureTests(unittest.TestCase):
    """The asset graph computes its own parent/child relations."""

    def test_a_subdomain_is_linked_under_its_root_domain(self):
        graph = AssetGraph()
        root = graph.upsert_asset(_asset(kind=AssetKind.ROOT_DOMAIN, value="example.com"))
        sub = graph.upsert_asset(_asset(kind=AssetKind.SUBDOMAIN, value="api.example.com"))
        self.assertIn(sub.key, [child.key for child in graph.children(root.key)])
        self.assertIn(root.key, [parent.key for parent in graph.parents(sub.key)])

    def test_a_root_domain_is_not_linked_under_itself(self):
        graph = AssetGraph()
        root = graph.upsert_asset(_asset(kind=AssetKind.ROOT_DOMAIN, value="example.com"))
        self.assertEqual((), graph.children(root.key))

    def test_a_root_domain_has_no_parent_at_all(self):
        graph = AssetGraph()
        root = graph.upsert_asset(_asset(kind=AssetKind.ROOT_DOMAIN, value="example.com"))
        self.assertEqual((), graph.parents(root.key))
        self.assertIsNone(root.parent_key)

    def test_an_ip_has_no_parent(self):
        graph = AssetGraph()
        node = graph.upsert_asset(_asset(kind=AssetKind.IP, value="192.168.1.1"))
        self.assertEqual((), graph.parents(node.key))
        self.assertIsNone(node.parent_key)

    def test_an_app_has_no_parent(self):
        graph = AssetGraph()
        node = graph.upsert_asset(_asset(kind=AssetKind.APP, value="acme"))
        self.assertEqual((), graph.parents(node.key))
        self.assertIsNone(node.parent_key)

    def test_a_root_domain_is_never_a_child_of_anything(self):
        graph = AssetGraph()
        root = graph.upsert_asset(_asset(kind=AssetKind.ROOT_DOMAIN, value="example.com"))
        for parent in graph.parents(root.key):
            self.fail(f"a root domain was placed under {parent.key}")

    def test_the_same_asset_submitted_twice_is_one_node(self):
        graph = AssetGraph()
        graph.upsert_asset(_asset(value="example.com"))
        graph.upsert_asset(_asset(value="EXAMPLE.com"))
        self.assertEqual(1, len(graph.nodes()))

    def test_an_asset_node_carries_its_kind(self):
        graph = AssetGraph()
        node = graph.upsert_asset(_asset(kind=AssetKind.APP, value="acme"))
        self.assertIs(AssetKind.APP, node.kind)


class ExplorationGraphTests(unittest.TestCase):
    """The exploration graph holds the chain and refuses bad edges."""

    def test_a_node_carries_its_kind(self):
        graph = ExplorationGraph(AssetGraph())
        node = graph.add_node(NodeKind.GOAL, "find the admin panel")
        self.assertIs(NodeKind.GOAL, node.kind)

    def test_an_unknown_node_kind_is_refused(self):
        graph = ExplorationGraph(AssetGraph())
        with self.assertRaises(ExplorationGraphError):
            graph.add_node("not-a-kind", "text")

    def test_an_empty_node_text_is_refused(self):
        graph = ExplorationGraph(AssetGraph())
        with self.assertRaises(ExplorationGraphError):
            graph.add_node(NodeKind.GOAL, "   ")

    def test_an_edge_links_two_existing_nodes(self):
        graph = ExplorationGraph(AssetGraph())
        goal = graph.add_node(NodeKind.GOAL, "g")
        intent = graph.add_node(NodeKind.INTENT, "i")
        graph.link(goal.key, Relation.SPAWNS, intent.key)
        self.assertIn(intent.key, [n.key for n in graph.children(goal.key)])

    def test_an_edge_to_a_missing_node_is_refused(self):
        graph = ExplorationGraph(AssetGraph())
        goal = graph.add_node(NodeKind.GOAL, "g")
        with self.assertRaises(ExplorationGraphError):
            graph.link(goal.key, Relation.SPAWNS, "no-such-node")

    def test_an_unknown_relation_is_refused(self):
        graph = ExplorationGraph(AssetGraph())
        goal = graph.add_node(NodeKind.GOAL, "g")
        with self.assertRaises(ExplorationGraphError):
            graph.link(goal.key, "not-a-relation", goal.key)

    def test_a_self_edge_is_refused(self):
        graph = ExplorationGraph(AssetGraph())
        goal = graph.add_node(NodeKind.GOAL, "g")
        with self.assertRaises(ExplorationGraphError):
            graph.link(goal.key, Relation.SPAWNS, goal.key)

    def test_a_relation_whose_endpoints_do_not_fit_is_refused(self):
        # ``yields`` runs from an intention to what it produced; it cannot
        # run from a goal to a goal.
        graph = ExplorationGraph(AssetGraph())
        goal = graph.add_node(NodeKind.GOAL, "g")
        other = graph.add_node(NodeKind.GOAL, "g2")
        with self.assertRaises(ExplorationGraphError):
            graph.link(goal.key, Relation.YIELDS, other.key)

    def test_a_proves_edge_runs_from_an_intent_to_a_finding(self):
        graph = ExplorationGraph(AssetGraph())
        intent = graph.add_node(NodeKind.INTENT, "i")
        finding = graph.add_node(NodeKind.FINDING, "f")
        graph.link(intent.key, Relation.PROVES, finding.key)
        self.assertIn(finding.key, [n.key for n in graph.children(intent.key)])

    def test_a_proves_edge_to_a_fact_is_refused(self):
        graph = ExplorationGraph(AssetGraph())
        intent = graph.add_node(NodeKind.INTENT, "i")
        fact = graph.add_node(NodeKind.FACT, "f")
        with self.assertRaises(ExplorationGraphError):
            graph.link(intent.key, Relation.PROVES, fact.key)

    def test_a_derived_from_edge_runs_to_an_intent(self):
        # ``derived_from`` runs from the thing that was derived to the
        # thing it was derived from, so the fact is the parent and the
        # intent is downstream of it.
        graph = ExplorationGraph(AssetGraph())
        fact = graph.add_node(NodeKind.FACT, "f")
        intent = graph.add_node(NodeKind.INTENT, "i")
        graph.link(fact.key, Relation.DERIVED_FROM, intent.key)
        self.assertIn(intent.key, [n.key for n in graph.children(fact.key)])
        self.assertIn(fact.key, [n.key for n in graph.parents(intent.key)])

    def test_the_graph_reports_whether_a_node_exists(self):
        graph = ExplorationGraph(AssetGraph())
        node = graph.add_node(NodeKind.GOAL, "g")
        self.assertTrue(graph.has_node(node.key))
        self.assertFalse(graph.has_node("nope"))

    def test_the_graph_reports_whether_an_edge_exists(self):
        graph = ExplorationGraph(AssetGraph())
        goal = graph.add_node(NodeKind.GOAL, "g")
        intent = graph.add_node(NodeKind.INTENT, "i")
        graph.link(goal.key, Relation.SPAWNS, intent.key)
        self.assertTrue(graph.has_edge(goal.key, Relation.SPAWNS, intent.key))
        self.assertFalse(graph.has_edge(goal.key, Relation.YIELDS, intent.key))

    # -- the relation vocabulary is enforced -------------------------------
    #
    # These pin the *source* half of the endpoint check.  Without them the
    # graph would accept ``yields`` from a goal, which claims a production
    # that never happened.

    def test_a_spawns_edge_from_an_intent_is_refused(self):
        graph = ExplorationGraph(AssetGraph())
        intent = graph.add_node(NodeKind.INTENT, "i")
        other = graph.add_node(NodeKind.INTENT, "i2")
        with self.assertRaises(ExplorationGraphError):
            graph.link(intent.key, Relation.SPAWNS, other.key)

    def test_a_spawns_edge_to_a_fact_is_refused(self):
        graph = ExplorationGraph(AssetGraph())
        goal = graph.add_node(NodeKind.GOAL, "g")
        fact = graph.add_node(NodeKind.FACT, "f")
        with self.assertRaises(ExplorationGraphError):
            graph.link(goal.key, Relation.SPAWNS, fact.key)

    def test_a_yields_edge_from_a_goal_is_refused(self):
        graph = ExplorationGraph(AssetGraph())
        goal = graph.add_node(NodeKind.GOAL, "g")
        fact = graph.add_node(NodeKind.FACT, "f")
        with self.assertRaises(ExplorationGraphError):
            graph.link(goal.key, Relation.YIELDS, fact.key)

    def test_a_yields_edge_to_a_goal_is_refused(self):
        graph = ExplorationGraph(AssetGraph())
        intent = graph.add_node(NodeKind.INTENT, "i")
        goal = graph.add_node(NodeKind.GOAL, "g")
        with self.assertRaises(ExplorationGraphError):
            graph.link(intent.key, Relation.YIELDS, goal.key)

    def test_a_proves_edge_from_a_fact_is_refused(self):
        graph = ExplorationGraph(AssetGraph())
        fact = graph.add_node(NodeKind.FACT, "f")
        finding = graph.add_node(NodeKind.FINDING, "fi")
        with self.assertRaises(ExplorationGraphError):
            graph.link(fact.key, Relation.PROVES, finding.key)

    def test_a_proves_edge_to_an_intent_is_refused(self):
        graph = ExplorationGraph(AssetGraph())
        intent = graph.add_node(NodeKind.INTENT, "i")
        other = graph.add_node(NodeKind.INTENT, "i2")
        with self.assertRaises(ExplorationGraphError):
            graph.link(intent.key, Relation.PROVES, other.key)

    def test_a_refused_edge_leaves_the_graph_unchanged(self):
        # A refused edge must not be half-recorded: the node must still
        # have no such parent.
        graph = ExplorationGraph(AssetGraph())
        goal = graph.add_node(NodeKind.GOAL, "g")
        fact = graph.add_node(NodeKind.FACT, "f")
        with self.assertRaises(ExplorationGraphError):
            graph.link(goal.key, Relation.YIELDS, fact.key)
        self.assertEqual((), graph.parents(fact.key))
        self.assertEqual((), graph.children(goal.key))
        self.assertFalse(graph.has_edge(goal.key, Relation.YIELDS, fact.key))

    def test_a_self_edge_is_refused_even_when_the_kinds_would_fit(self):
        # A node cannot be linked to itself.  The pair chosen here fits
        # the relation's endpoint kinds, so the refusal must come from
        # the self-edge check and not from the endpoint check.
        graph = ExplorationGraph(AssetGraph())
        intent = graph.add_node(NodeKind.INTENT, "i")
        with self.assertRaises(ExplorationGraphError):
            graph.link(intent.key, Relation.DERIVED_FROM, intent.key)

    def test_a_self_edge_leaves_the_graph_unchanged(self):
        graph = ExplorationGraph(AssetGraph())
        intent = graph.add_node(NodeKind.INTENT, "i")
        with self.assertRaises(ExplorationGraphError):
            graph.link(intent.key, Relation.DERIVED_FROM, intent.key)
        self.assertEqual((), graph.children(intent.key))
        self.assertEqual((), graph.parents(intent.key))


class AnchorTests(unittest.TestCase):
    """The anchors are what make the two graphs one object."""

    def _pair(self):
        """An asset graph holding one asset, and an exploration graph on it."""
        assets = AssetGraph()
        assets.upsert_asset(_asset(value="example.com"))
        return assets, ExplorationGraph(assets)

    def test_an_anchor_links_an_exploration_node_to_an_asset(self):
        assets, graph = self._pair()
        fact = graph.add_node(NodeKind.FACT, "f")
        graph.anchor(fact.key, assets.lookup_key(AssetKind.ROOT_DOMAIN, "example.com"))
        self.assertEqual(1, len(graph.anchors_for(fact.key)))

    def test_an_anchor_to_a_missing_asset_is_refused(self):
        _, graph = self._pair()
        fact = graph.add_node(NodeKind.FACT, "f")
        with self.assertRaises(ExplorationGraphError):
            graph.anchor(fact.key, "no-such-asset")

    def test_an_anchor_to_a_missing_node_is_refused(self):
        assets, graph = self._pair()
        with self.assertRaises(ExplorationGraphError):
            graph.anchor("no-such-node", assets.lookup_key(AssetKind.ROOT_DOMAIN, "example.com"))

    def test_the_same_anchor_twice_is_one_anchor(self):
        assets, graph = self._pair()
        fact = graph.add_node(NodeKind.FACT, "f")
        key = assets.lookup_key(AssetKind.ROOT_DOMAIN, "example.com")
        graph.anchor(fact.key, key)
        graph.anchor(fact.key, key)
        self.assertEqual(1, len(graph.anchors_for(fact.key)))


class LineageTests(unittest.TestCase):
    """A finding traces back to the facts and the goal that produced it."""

    def _chain(self):
        """goal -> intent -> fact -> intent -> fact -> finding."""
        graph = ExplorationGraph(AssetGraph())
        goal = graph.add_node(NodeKind.GOAL, "find the admin panel")
        first = graph.add_node(NodeKind.INTENT, "enumerate hosts")
        fact_one = graph.add_node(NodeKind.FACT, "api.example.com resolves")
        second = graph.add_node(NodeKind.INTENT, "probe the admin route")
        fact_two = graph.add_node(NodeKind.FACT, "admin route returns 200")
        finding = graph.add_node(NodeKind.FINDING, "admin panel is unauthenticated")
        graph.link(goal.key, Relation.SPAWNS, first.key)
        graph.link(first.key, Relation.YIELDS, fact_one.key)
        graph.link(fact_one.key, Relation.DERIVED_FROM, second.key)
        graph.link(second.key, Relation.YIELDS, fact_two.key)
        graph.link(second.key, Relation.PROVES, finding.key)
        return graph, goal, first, fact_one, second, fact_two, finding

    def test_a_finding_traces_back_to_its_fact_chain(self):
        graph, _, _, _, _, _, finding = self._chain()
        chain = graph.lineage(finding.key)
        texts = [node.text for node in chain.facts]
        self.assertIn("api.example.com resolves", texts)
        self.assertIn("admin route returns 200", texts)

    def test_the_chain_reaches_the_goal(self):
        graph, goal, _, _, _, _, finding = self._chain()
        chain = graph.lineage(finding.key)
        self.assertIn(goal.key, [node.key for node in chain.goals])

    def test_the_chain_names_the_intentions_that_produced_the_facts(self):
        graph, _, first, _, second, _, finding = self._chain()
        chain = graph.lineage(finding.key)
        self.assertIn(first.key, [node.key for node in chain.intents])
        self.assertIn(second.key, [node.key for node in chain.intents])

    def test_an_unrelated_finding_is_not_in_the_chain(self):
        graph = ExplorationGraph(AssetGraph())
        goal = graph.add_node(NodeKind.GOAL, "g")
        intent = graph.add_node(NodeKind.INTENT, "i")
        fact = graph.add_node(NodeKind.FACT, "f")
        other = graph.add_node(NodeKind.FINDING, "unrelated")
        graph.link(goal.key, Relation.SPAWNS, intent.key)
        graph.link(intent.key, Relation.YIELDS, fact.key)
        chain = graph.lineage(other.key)
        self.assertEqual((), chain.facts)

    def test_the_lineage_of_a_missing_node_is_refused(self):
        graph = ExplorationGraph(AssetGraph())
        with self.assertRaises(ExplorationGraphError):
            graph.lineage("no-such-node")

    def test_the_lineage_of_a_node_that_is_not_a_finding_is_refused(self):
        graph = ExplorationGraph(AssetGraph())
        fact = graph.add_node(NodeKind.FACT, "f")
        with self.assertRaises(ExplorationGraphError):
            graph.lineage(fact.key)

    def test_a_cyclic_graph_terminates(self):
        # A cycle must not hang the lineage walk.
        graph = ExplorationGraph(AssetGraph())
        one = graph.add_node(NodeKind.INTENT, "one")
        two = graph.add_node(NodeKind.INTENT, "two")
        graph.link(one.key, Relation.DERIVED_FROM, two.key)
        graph.link(two.key, Relation.DERIVED_FROM, one.key)
        finding = graph.add_node(NodeKind.FINDING, "f")
        graph.link(one.key, Relation.PROVES, finding.key)
        chain = graph.lineage(finding.key)
        self.assertIsNotNone(chain)

    def test_a_cyclic_graph_terminates_quickly(self):
        # The walk must *terminate*, not merely terminate eventually: a
        # cycle that made the walk loop forever would hang the run.
        graph = ExplorationGraph(AssetGraph())
        one = graph.add_node(NodeKind.INTENT, "one")
        two = graph.add_node(NodeKind.INTENT, "two")
        three = graph.add_node(NodeKind.INTENT, "three")
        graph.link(one.key, Relation.DERIVED_FROM, two.key)
        graph.link(two.key, Relation.DERIVED_FROM, three.key)
        graph.link(three.key, Relation.DERIVED_FROM, one.key)
        finding = graph.add_node(NodeKind.FINDING, "f")
        graph.link(one.key, Relation.PROVES, finding.key)
        chain = graph.lineage(finding.key)
        # Every intent in the cycle is reachable exactly once.
        self.assertEqual(3, len(chain.intents))
        self.assertEqual(3, len({node.key for node in chain.intents}))

    def test_the_lineage_is_deterministic(self):
        graph, _, _, _, _, _, finding = self._chain()
        first = [node.key for node in graph.lineage(finding.key).facts]
        second = [node.key for node in graph.lineage(finding.key).facts]
        self.assertEqual(first, second)


class CoverageTests(unittest.TestCase):
    """Which in-scope assets were actually tested."""

    def _scoped(self):
        """Three in-scope assets; one is anchored by a fact, two are not."""
        assets = AssetGraph()
        assets.upsert_asset(_asset(kind=AssetKind.ROOT_DOMAIN, value="example.com"))
        assets.upsert_asset(_asset(kind=AssetKind.SUBDOMAIN, value="api.example.com"))
        assets.upsert_asset(_asset(kind=AssetKind.SUBDOMAIN, value="shop.example.com"))

        graph = ExplorationGraph(assets)
        intent = graph.add_node(NodeKind.INTENT, "enumerate hosts")
        fact = graph.add_node(NodeKind.FACT, "api.example.com resolves")
        graph.link(intent.key, Relation.YIELDS, fact.key)
        graph.anchor(fact.key, assets.lookup_key(AssetKind.SUBDOMAIN, "api.example.com"))

        scope = [
            assets.lookup_key(AssetKind.ROOT_DOMAIN, "example.com"),
            assets.lookup_key(AssetKind.SUBDOMAIN, "api.example.com"),
            assets.lookup_key(AssetKind.SUBDOMAIN, "shop.example.com"),
        ]
        return graph, assets, scope

    def test_a_tested_asset_is_reported_as_tested(self):
        graph, assets, scope = self._scoped()
        report = graph.coverage(scope)
        tested = report.tested_keys()
        self.assertIn(assets.lookup_key(AssetKind.SUBDOMAIN, "api.example.com"), tested)

    def test_an_untested_asset_is_reported_as_untested(self):
        graph, assets, scope = self._scoped()
        report = graph.coverage(scope)
        untested = report.untested_keys()
        self.assertIn(assets.lookup_key(AssetKind.SUBDOMAIN, "shop.example.com"), untested)

    def test_a_tested_asset_outside_the_scope_is_not_counted(self):
        # The scope is the denominator.  An asset that was tested but is
        # not in scope must not be reported as tested, or the figure
        # would exceed 100%.
        graph, assets, scope = self._scoped()
        outside = assets.upsert_asset(_asset(kind=AssetKind.SUBDOMAIN, value="other.example.com"))
        fact = graph.add_node(NodeKind.FACT, "other host resolves")
        graph.anchor(fact.key, outside.key)
        report = graph.coverage(scope)
        self.assertNotIn(outside.key, report.tested_keys())
        self.assertEqual(3, report.denominator)
        self.assertEqual(1, report.tested_count)

    def test_the_coverage_figure_never_exceeds_one(self):
        graph, assets, scope = self._scoped()
        report = graph.coverage(scope)
        self.assertLessEqual(report.pct, 1.0)

    def test_a_repeated_scope_member_does_not_inflate_the_denominator(self):
        # The scope is a set of assets.  A member listed twice is one
        # asset, and counting it twice would let the denominator grow
        # under the caller's hand while the tested count stayed put.
        graph, assets, scope = self._scoped()
        key = assets.lookup_key(AssetKind.SUBDOMAIN, "api.example.com")
        report = graph.coverage(scope + [key])
        self.assertEqual(3, report.denominator)
        self.assertEqual(1, report.tested_count)

    def test_a_repeated_scope_member_is_listed_once(self):
        graph, assets, scope = self._scoped()
        key = assets.lookup_key(AssetKind.SUBDOMAIN, "api.example.com")
        report = graph.coverage(scope + [key])
        self.assertEqual(1, report.tested_keys().count(key))
        self.assertEqual(2, len(report.untested_keys()))

    def test_the_denominator_is_the_whole_scope(self):
        graph, assets, scope = self._scoped()
        report = graph.coverage(scope)
        self.assertEqual(3, report.denominator)
        self.assertEqual(1, report.tested_count)

    def test_an_empty_scope_has_no_percentage(self):
        graph, _, _ = self._scoped()
        report = graph.coverage([])
        self.assertEqual(0, report.denominator)
        self.assertIsNone(report.pct)

    def test_an_asset_anchored_only_by_a_non_fact_node_is_not_tested(self):
        # Only a *fact* is evidence that the asset was actually exercised.
        assets = AssetGraph()
        assets.upsert_asset(_asset(kind=AssetKind.SUBDOMAIN, value="api.example.com"))
        graph = ExplorationGraph(assets)
        intent = graph.add_node(NodeKind.INTENT, "i")
        graph.anchor(intent.key, assets.lookup_key(AssetKind.SUBDOMAIN, "api.example.com"))
        report = graph.coverage([assets.lookup_key(AssetKind.SUBDOMAIN, "api.example.com")])
        self.assertEqual(0, report.tested_count)

    def test_a_finding_anchored_to_an_asset_does_not_by_itself_count_as_tested(self):
        assets = AssetGraph()
        assets.upsert_asset(_asset(kind=AssetKind.SUBDOMAIN, value="api.example.com"))
        graph = ExplorationGraph(assets)
        finding = graph.add_node(NodeKind.FINDING, "f")
        graph.anchor(finding.key, assets.lookup_key(AssetKind.SUBDOMAIN, "api.example.com"))
        report = graph.coverage([assets.lookup_key(AssetKind.SUBDOMAIN, "api.example.com")])
        self.assertEqual(0, report.tested_count)

    def test_a_scope_key_that_is_not_an_asset_is_refused(self):
        graph, _, _ = self._scoped()
        with self.assertRaises(ExplorationGraphError):
            graph.coverage(["not-an-asset-key"])

    def test_the_coverage_report_groups_by_asset_kind(self):
        graph, assets, scope = self._scoped()
        report = graph.coverage(scope)
        # One root domain in scope, untested; two subdomains in scope, one
        # of them tested.
        self.assertEqual(1, report.by_kind(AssetKind.ROOT_DOMAIN).total)
        self.assertEqual(0, report.by_kind(AssetKind.ROOT_DOMAIN).tested_count)
        self.assertEqual(2, report.by_kind(AssetKind.SUBDOMAIN).total)
        self.assertEqual(1, report.by_kind(AssetKind.SUBDOMAIN).tested_count)


class AssetCoverageLookupTests(unittest.TestCase):
    """From an asset, back to what was done to it."""

    def test_an_asset_knows_the_exploration_nodes_anchored_to_it(self):
        assets = AssetGraph()
        assets.upsert_asset(_asset(kind=AssetKind.SUBDOMAIN, value="api.example.com"))
        graph = ExplorationGraph(assets)
        fact = graph.add_node(NodeKind.FACT, "f")
        graph.anchor(fact.key, assets.lookup_key(AssetKind.SUBDOMAIN, "api.example.com"))
        self.assertEqual((fact.key,), graph.nodes_for_asset(
            assets.lookup_key(AssetKind.SUBDOMAIN, "api.example.com")))

    def test_an_asset_with_no_anchors_has_no_nodes(self):
        assets = AssetGraph()
        assets.upsert_asset(_asset(kind=AssetKind.SUBDOMAIN, value="api.example.com"))
        graph = ExplorationGraph(assets)
        self.assertEqual((), graph.nodes_for_asset(
            assets.lookup_key(AssetKind.SUBDOMAIN, "api.example.com")))


class PurityTests(unittest.TestCase):
    """The module is a pure library."""

    def test_the_module_imports_nothing_outside_the_standard_library(self):
        self.assertTrue(exploration_graph.stdlib_only())

    def test_the_module_uses_no_clock(self):
        # A module that reads the clock cannot be replayed; the lineage
        # must be the same on every run.
        self.assertFalse(exploration_graph.uses_clock())


if __name__ == "__main__":  # pragma: no cover - convenience entry
    unittest.main()
