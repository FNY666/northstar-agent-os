"""Dual-graph lineage: an exploration chain and a shared asset truth, joined
by anchors.

What was missing
----------------
Northstar can say *what* it concluded and it can say *how much* it did,
but it could not say **which conclusion came from which facts, and which
assets those facts were collected against**.  Two artefacts existed that
each answered half the question and neither answered the whole:

* the exploration side -- goals, intents, facts, findings and hints -- was
  a flat set of records.  A finding named its subject but not the chain
  that produced it, so "is this conclusion supported?" was a question
  about prose rather than about structure.
* the asset side -- hosts, services, endpoints -- had no identity that the
  *program* owned.  A caller named an asset, so two spellings of one host
  were two assets, and "did we test this?" had no denominator.

The two halves could not be joined, so the question that actually matters
for a red-team run -- **"which of the in-scope assets did we actually
exercise, and what did we conclude about them?"** -- had no answer at all.

The design
----------
Two graphs and the anchors between them:

* the **exploration graph** is a chain of *how we thought*: ``goal``
  (an objective) spawns ``intent`` (a direction), an intent ``yields`` a
  ``fact`` or a ``finding``, a fact is ``derived_from`` the intent it came
  from, and an intent ``proves`` a finding.  Every edge points *downstream*
  (parent to child), so a finding's lineage is the set of nodes reachable
  by walking its parents upward.
* the **asset graph** is the *what we touched* truth: ``root_domain``,
  ``subdomain``, ``ip``, ``service``, ``app`` and ``endpoint`` nodes, with
  the parent/child relations between them computed by the program from the
  raw observations, never asserted by the caller.
* the **anchors** join them: an anchor says "this exploration node is
  about this asset".  From the exploration side an anchor says *what we
  did to which asset*; from the asset side it says *how this asset was
  tested*.

The one rule that makes the asset graph worth anything
-------------------------------------------------------
**The dedup key is computed by the program.**  A caller submits a raw
observation -- a kind and a value, plus whatever fields that kind carries
-- and the program derives the key.  A caller that tries to supply its own
key is refused outright rather than obeyed.  This is not a stylistic
preference: a caller-chosen key is a claim about identity, and an agent
that is allowed to make identity claims will make them inconsistently
(``API.example.com`` and ``api.example.com`` become two assets, and the
coverage denominator quietly doubles).  The program owns identity because
identity is a property of the *observation*, not of the observer.

The coverage denominator
------------------------
Coverage is computed against the *fact* nodes only.  An intent that names
an asset is a plan; a finding that names an asset is a conclusion; only a
fact is evidence that the asset was actually exercised.  So the answer to
"did we test it?" is derived from the graph rather than from a counter
somebody maintains.

Source and licence basis
------------------------
The two-graph *idea* -- an exploration chain and a shared asset truth,
joined by anchors, with program-computed asset identity -- was learned
from **WSARTEX** (``https://github.com/willsurpass/WSARTEX``), which
documents that architecture in its ``README.detailed.md`` and implements
it in ``agent/`` and ``db/``.

WSARTEX is licensed **AGPL-3.0-or-later**.  Northstar is licensed
**MIT**, and MIT is not compatible with AGPL-3.0 for the reuse of
licence-covered code.  **No WSARTEX code, identifiers, table definitions,
schema or text are reused in this module.**  Everything here -- the node
kinds, the relation vocabulary, the key derivation, the coverage rule and
the lineage walk -- is Northstar's own implementation of the *idea*, written
from the design description rather than from the source.  See
``docs/design/dual-graph-lineage.md`` for the recorded licence basis.

Northstar extensions (explicitly **not** from the source)
----------------------------------------------------------
* The **key derivation** is Northstar's: the source computes a key from
  the raw columns of its own schema, while Northstar derives a
  kind-specific canonical key from a normalised observation and refuses a
  caller-supplied one.
* The **relation vocabulary** is Northstar's, and the graph *enforces*
  which kinds a relation may join (``yields`` runs from an intention to
  what it produced; ``proves`` runs from an intention to a finding).  The
  source's database only records the edge.
* The **coverage rule** -- that only a fact counts as evidence of testing
  -- is Northstar's, and it is why an intent anchored to an asset does not
  inflate the coverage figure.
* The **lineage walk** is Northstar's, and it is cycle-safe.

Scope: this module is a pure library.  It performs no I/O, no clock read
and no randomness, so the same observations always yield the same keys and
the same answers -- which is what lets the lineage be replayed and compared
against the run that produced it.
"""

from __future__ import annotations

import hashlib
import ipaddress
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Mapping, Optional, Sequence, Set, Tuple

__all__ = [
    "AssetGraph",
    "AssetKind",
    "AssetNode",
    "CoverageReport",
    "ExplorationGraph",
    "ExplorationGraphError",
    "KindCoverage",
    "Lineage",
    "Node",
    "NodeKind",
    "Relation",
    "stdlib_only",
    "uses_clock",
]


#: Version pin for this module's record shape.
EXPLORATION_GRAPH_VERSION = "northstar.exploration-graph.v1"

#: The domain separator for every key this module computes.  A key is a
#: digest over the canonical body of a normalised observation, and the
#: domain separator keeps those digests from being comparable with any
#: other digest the runtime computes over unrelated content.
_KEY_DOMAIN = "northstar.exploration-graph.asset.v1"

#: The prefix every asset key carries, so a key is recognisable as one.
_KEY_PREFIX = "asset:"


class ExplorationGraphError(ValueError):
    """Raised when an observation, a node, an edge or an anchor is not well formed."""


class NodeKind(str, Enum):
    """The kinds of node the exploration graph holds.

    ``GOAL`` is an objective.  ``INTENT`` is a direction taken toward it.
    ``FACT`` is an observation recorded while following an intent.
    ``FINDING`` is a conclusion about the target.  ``HINT`` is a piece of
    guidance offered to the run.
    """

    GOAL = "goal"
    INTENT = "intent"
    FACT = "fact"
    FINDING = "finding"
    HINT = "hint"


class AssetKind(str, Enum):
    """The kinds of node the asset graph holds."""

    ROOT_DOMAIN = "root_domain"
    SUBDOMAIN = "subdomain"
    IP = "ip"
    SERVICE = "service"
    APP = "app"
    ENDPOINT = "endpoint"


class Relation(str, Enum):
    """The edges the exploration graph holds.

    Every relation points **downstream**: the source is the parent and
    the destination is the child.  ``SPAWNS`` runs from a goal to an
    intent; ``YIELDS`` from an intent to what it produced; ``DERIVED_FROM``
    from a fact to the intent it came from; ``PROVES`` from an intent to
    a finding.

    The directions are what make the lineage walk well defined: a
    finding's lineage is the set of nodes reachable by walking parents
    upward, and every relation is oriented so that "up" means "came
    from".
    """

    SPAWNS = "spawns"
    DERIVED_FROM = "derived_from"
    YIELDS = "yields"
    PROVES = "proves"


#: Which node kinds a relation may join, as ``(source kinds, destination
#: kinds)``.  A relation that does not fit its endpoints is refused: the
#: relation vocabulary is a claim about causality, and a ``yields`` edge
#: from a goal to a goal claims a production that never happened.
_RELATION_ENDPOINTS: Dict[Relation, Tuple[frozenset, frozenset]] = {
    Relation.SPAWNS: (frozenset({NodeKind.GOAL}), frozenset({NodeKind.INTENT})),
    Relation.YIELDS: (
        frozenset({NodeKind.INTENT}),
        frozenset({NodeKind.FACT, NodeKind.FINDING, NodeKind.HINT}),
    ),
    Relation.DERIVED_FROM: (
        frozenset({NodeKind.FACT, NodeKind.FINDING, NodeKind.HINT, NodeKind.INTENT}),
        frozenset({NodeKind.INTENT}),
    ),
    Relation.PROVES: (frozenset({NodeKind.INTENT}), frozenset({NodeKind.FINDING})),
}


def _require_text(value: Any, name: str) -> str:
    """Return a non-empty, stripped string, or refuse."""
    if not isinstance(value, str):
        raise ExplorationGraphError(f"{name} must be a string")
    text = value.strip()
    if not text:
        raise ExplorationGraphError(f"{name} must not be empty")
    return text


def _require_node_kind(value: Any) -> NodeKind:
    """Coerce a node kind, refusing an unknown one."""
    if isinstance(value, NodeKind):
        return value
    if isinstance(value, str):
        try:
            return NodeKind(value)
        except ValueError:
            raise ExplorationGraphError(f"unknown node kind: {value!r}") from None
    raise ExplorationGraphError(f"unknown node kind: {value!r}")


def _require_asset_kind(value: Any) -> AssetKind:
    """Coerce an asset kind, refusing an unknown one."""
    if isinstance(value, AssetKind):
        return value
    if isinstance(value, str):
        try:
            return AssetKind(value)
        except ValueError:
            raise ExplorationGraphError(f"unknown asset kind: {value!r}") from None
    raise ExplorationGraphError(f"unknown asset kind: {value!r}")


def _require_relation(value: Any) -> Relation:
    """Coerce a relation, refusing an unknown one."""
    if isinstance(value, Relation):
        return value
    if isinstance(value, str):
        try:
            return Relation(value)
        except ValueError:
            raise ExplorationGraphError(f"unknown relation: {value!r}") from None
    raise ExplorationGraphError(f"unknown relation: {value!r}")


def _normalise_domain(value: str) -> str:
    """Lowercase a domain and drop its trailing dot.

    A trailing dot is the same name written absolutely, and a name is
    case-insensitive, so both spellings are one asset.
    """
    text = value.strip().lower()
    while text.endswith("."):
        text = text[:-1]
    if not text:
        raise ExplorationGraphError("domain must not be empty")
    return text


def _normalise_ip(value: str) -> str:
    """Return an address in its canonical form, or refuse a malformed one.

    A dotted quad is normalised by decimal octet, so ``192.168.001.001``
    and ``192.168.1.1`` are one address.  The octets are read as decimal
    rather than octal, which is what every address in the wild means by
    them; an octet outside ``0..255`` is refused rather than guessed at.
    """
    text = value.strip()
    try:
        return ipaddress.ip_address(text).compressed
    except ValueError:
        pass
    parts = text.split(".")
    if len(parts) == 4 and all(part.isdigit() for part in parts):
        octets = [int(part) for part in parts]
        if all(0 <= octet <= 255 for octet in octets):
            return ".".join(str(octet) for octet in octets)
    raise ExplorationGraphError(f"malformed ip address: {value!r}")


def _normalise_port(value: Any) -> Optional[int]:
    """Coerce a port number, refusing an out-of-range one."""
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise ExplorationGraphError(f"port must be an integer: {value!r}")
    if not 1 <= value <= 65535:
        raise ExplorationGraphError(f"port out of range: {value!r}")
    return value


def _normalise_endpoint(value: str) -> str:
    """Normalise an endpoint URL to a canonical, comparable form.

    The scheme and the host are lowercased, the default port is dropped,
    and a bare-root trailing slash is removed, so the same endpoint
    written two ways is one endpoint.
    """
    text = value.strip()
    if not text:
        raise ExplorationGraphError("endpoint must not be empty")
    lowered = text.lower()
    scheme = ""
    rest = lowered
    if "://" in rest:
        scheme, rest = rest.split("://", 1)
        scheme = scheme + "://"
    host = rest
    tail = ""
    for mark in ("/", "?", "#"):
        index = rest.find(mark)
        if index != -1:
            host = rest[:index]
            tail = rest[index:]
            break
    if host.endswith(":80") and scheme == "http://":
        host = host[:-3]
    elif host.endswith(":443") and scheme == "https://":
        host = host[:-4]
    if tail == "/" and not scheme:
        tail = ""
    return f"{scheme}{host}{tail}"


def _host_of(value: str) -> str:
    """The host part of a service or endpoint value."""
    host = value.strip().lower()
    for scheme in ("https://", "http://"):
        if host.startswith(scheme):
            host = host[len(scheme):]
            break
    for mark in ("/", "?", "#"):
        index = host.find(mark)
        if index != -1:
            host = host[:index]
            break
    if host.startswith("["):  # an IPv6 literal
        end = host.find("]")
        if end != -1:
            host = host[1:end]
    elif ":" in host:
        host = host.rsplit(":", 1)[0]
    return host


@dataclass(frozen=True)
class AssetNode:
    """One node of the asset graph.

    ``key`` is the program's identity for the asset.  ``parent_key`` is
    the program's own conclusion about where the asset sits, not the
    caller's.
    """

    key: str
    kind: AssetKind
    value: str
    parent_key: Optional[str] = None
    detail: Tuple[Tuple[str, str], ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        """Return the node as a plain dict."""
        return {
            "key": self.key,
            "kind": self.kind.value,
            "value": self.value,
            "parent_key": self.parent_key,
            "detail": dict(self.detail),
        }


@dataclass(frozen=True)
class Node:
    """One node of the exploration graph."""

    key: str
    kind: NodeKind
    text: str

    def to_dict(self) -> Dict[str, Any]:
        """Return the node as a plain dict."""
        return {"key": self.key, "kind": self.kind.value, "text": self.text}


@dataclass(frozen=True)
class Lineage:
    """The chain that produced a finding.

    ``facts`` are the observations the conclusion rests on, ``intents`` the
    directions that produced them, and ``goals`` the objectives those
    directions served.
    """

    finding: str
    facts: Tuple[Node, ...] = ()
    intents: Tuple[Node, ...] = ()
    goals: Tuple[Node, ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        """Return the lineage as a plain dict."""
        return {
            "finding": self.finding,
            "facts": [node.to_dict() for node in self.facts],
            "intents": [node.to_dict() for node in self.intents],
            "goals": [node.to_dict() for node in self.goals],
        }


@dataclass(frozen=True)
class KindCoverage:
    """The coverage of one asset kind."""

    kind: AssetKind
    total: int
    tested_count: int

    def to_dict(self) -> Dict[str, Any]:
        """Return the row as a plain dict."""
        return {
            "kind": self.kind.value,
            "total": self.total,
            "tested": self.tested_count,
        }


@dataclass(frozen=True)
class CoverageReport:
    """The coverage of a scope: which in-scope assets were tested.

    ``denominator`` is the size of the scope the caller asked about.
    ``tested`` are the scope members that a *fact* is anchored to.
    """

    denominator: int
    tested: Tuple[str, ...] = ()
    untested: Tuple[str, ...] = ()
    by_kind_rows: Tuple[KindCoverage, ...] = ()

    @property
    def tested_count(self) -> int:
        """How many in-scope assets were tested."""
        return len(self.tested)

    def tested_keys(self) -> Tuple[str, ...]:
        """The keys of the in-scope assets that were tested."""
        return self.tested

    def untested_keys(self) -> Tuple[str, ...]:
        """The keys of the in-scope assets that were not tested."""
        return self.untested

    @property
    def pct(self) -> Optional[float]:
        """The fraction of the scope that was tested, or ``None`` if empty.

        An empty scope has no percentage: "everything was tested" would be
        a claim about nothing.
        """
        if not self.denominator:
            return None
        return len(self.tested) / self.denominator

    def by_kind(self, kind: AssetKind) -> KindCoverage:
        """The coverage row for one asset kind."""
        for row in self.by_kind_rows:
            if row.kind is kind:
                return row
        return KindCoverage(kind, 0, 0)

    def to_dict(self) -> Dict[str, Any]:
        """Return the report as a plain dict."""
        return {
            "denominator": self.denominator,
            "tested": list(self.tested),
            "untested": list(self.untested),
            "tested_count": self.tested_count,
            "pct": self.pct,
            "by_kind": [row.to_dict() for row in self.by_kind_rows],
        }


def _compute_key(kind: AssetKind, value: str, detail: Mapping[str, str]) -> str:
    """Compute the dedup key of a normalised observation.

    The key is a digest over the canonical body of the observation: its
    kind, its normalised value and the kind-specific detail that makes it
    distinct from its siblings (a port for a service, a method for an
    endpoint).  The body is built in a fixed field order, so the same
    observation always yields the same key.
    """
    parts = [kind.value, value]
    for name in sorted(detail):
        parts.append(f"{name}={detail[name]}")
    body = "\x1f".join(parts).encode("utf-8")
    return _KEY_PREFIX + hashlib.sha256(
        _KEY_DOMAIN.encode("utf-8") + b"\x1f" + body
    ).hexdigest()


class AssetGraph:
    """The shared truth about what was touched.

    The graph owns asset identity: a caller submits a raw observation and
    the graph derives the key, the normalised value and the parent/child
    relations.  Two observations of the same asset collapse onto one node,
    however they were spelled.
    """

    def __init__(self) -> None:
        self._nodes: Dict[str, AssetNode] = {}

    # -- observation -------------------------------------------------------

    def _normalise(self, raw: Mapping[str, Any]) -> Tuple[AssetKind, str, Dict[str, str]]:
        """Turn a raw observation into a kind, a normalised value and detail."""
        if not isinstance(raw, Mapping):
            raise ExplorationGraphError("an asset observation must be a mapping")
        if "key" in raw:
            # The key is the program's to compute.  A caller that supplies
            # one is making an identity claim the program will not accept.
            raise ExplorationGraphError(
                "the dedup key is computed by the program; remove 'key' from the observation"
            )
        kind = _require_asset_kind(raw.get("kind"))
        if "value" not in raw:
            raise ExplorationGraphError("an asset observation needs a 'value'")
        value = raw.get("value")
        if not isinstance(value, str):
            raise ExplorationGraphError("asset value must be a string")
        detail: Dict[str, str] = {}

        if kind in (AssetKind.ROOT_DOMAIN, AssetKind.SUBDOMAIN):
            normalised = _normalise_domain(value)
        elif kind is AssetKind.IP:
            normalised = _normalise_ip(value)
        elif kind is AssetKind.APP:
            normalised = _require_text(value, "app name")
        elif kind is AssetKind.SERVICE:
            normalised = _require_text(value, "service value")
            port = _normalise_port(raw.get("port"))
            if port is not None:
                detail["port"] = str(port)
        elif kind is AssetKind.ENDPOINT:
            normalised = _normalise_endpoint(value)
            method = raw.get("method")
            if method is not None:
                if not isinstance(method, str):
                    raise ExplorationGraphError("endpoint method must be a string")
                method_text = method.strip().upper()
                if method_text:
                    detail["method"] = method_text
        else:  # pragma: no cover - _require_asset_kind refuses the rest
            raise ExplorationGraphError(f"unknown asset kind: {kind!r}")

        return kind, normalised, detail

    def upsert_asset(self, raw: Mapping[str, Any]) -> AssetNode:
        """Record a raw observation and return the node it belongs to.

        The same observation twice is one node; a different spelling of
        the same observation is also one node.
        """
        kind, value, detail = self._normalise(raw)
        key = _compute_key(kind, value, detail)
        existing = self._nodes.get(key)
        if existing is not None:
            return existing

        node = AssetNode(
            key=key,
            kind=kind,
            value=value,
            parent_key=self._derive_parent(kind, value),
            detail=tuple(sorted(detail.items())),
        )
        self._nodes[key] = node
        return node

    def _derive_parent(self, kind: AssetKind, value: str) -> Optional[str]:
        """Work out where an asset sits, from the observation itself.

        The relation is *computed*, so it is the program's claim and not
        the caller's: a subdomain sits under the registrable domain it
        ends with, a service or endpoint sits under the host it names,
        and a root domain sits under nothing.
        """
        if kind is AssetKind.ROOT_DOMAIN:
            return None
        if kind is AssetKind.SUBDOMAIN:
            # ``api.example.com`` sits under ``example.com``.  The
            # registrable domain is the last two labels, which is the
            # right answer for the common two-label public suffix and is
            # never *worse* than guessing: an over-deep split produces a
            # parent that exists, where a public-suffix table that is
            # absent would produce none at all.
            labels = value.split(".")
            if len(labels) < 3:
                return None
            root = ".".join(labels[-2:])
            return _compute_key(AssetKind.ROOT_DOMAIN, root, {})
        if kind in (AssetKind.SERVICE, AssetKind.ENDPOINT):
            host = _host_of(value)
            if not host:
                return None
            try:
                ipaddress.ip_address(host)
            except ValueError:
                return _compute_key(AssetKind.SUBDOMAIN, _normalise_domain(host), {})
            return _compute_key(AssetKind.IP, host, {})
        return None

    # -- lookup ------------------------------------------------------------

    def lookup_key(self, kind: AssetKind, value: str, **detail: Any) -> str:
        """The key the program would compute for an observation.

        This is the key a caller needs in order to *name* an asset it
        already knows about -- for a scope, or for an anchor -- without
        having to record it first.
        """
        probe: Dict[str, Any] = {"kind": _require_asset_kind(kind), "value": value}
        probe.update(detail)
        normalised_kind, normalised_value, normalised_detail = self._normalise(probe)
        return _compute_key(normalised_kind, normalised_value, normalised_detail)

    def get(self, key: str) -> Optional[AssetNode]:
        """The node with this key, or ``None``."""
        return self._nodes.get(key)

    def nodes(self) -> Tuple[AssetNode, ...]:
        """Every node, in insertion order."""
        return tuple(self._nodes.values())

    def children(self, key: str) -> Tuple[AssetNode, ...]:
        """The nodes directly under this one.

        A child is a node whose computed parent is this one, so the
        relation does not depend on the order the assets were recorded
        in.
        """
        return tuple(
            node for node in self._nodes.values() if node.parent_key == key
        )

    def parents(self, key: str) -> Tuple[AssetNode, ...]:
        """The nodes directly above this one."""
        node = self._nodes.get(key)
        if node is None or node.parent_key is None:
            return ()
        parent = self._nodes.get(node.parent_key)
        return () if parent is None else (parent,)

    def __len__(self) -> int:
        return len(self._nodes)


class ExplorationGraph:
    """The chain of how a run thought, joined to the assets it touched.

    The graph owns three things: the nodes, the edges between them, and
    the anchors to the asset graph.  It owns none of the asset identity --
    that belongs to the :class:`AssetGraph`, and an anchor names an asset
    by the key that graph computed.
    """

    def __init__(self, assets: AssetGraph) -> None:
        if not isinstance(assets, AssetGraph):
            raise ExplorationGraphError("an exploration graph needs an asset graph")
        self._assets = assets
        self._nodes: Dict[str, Node] = {}
        self._children: Dict[str, List[str]] = {}
        self._parents: Dict[str, List[str]] = {}
        self._edges: Set[Tuple[str, Relation, str]] = set()
        self._anchors: Dict[str, Set[str]] = {}
        self._asset_anchors: Dict[str, Set[str]] = {}
        self._counter = 0

    # -- nodes -------------------------------------------------------------

    def add_node(self, kind: NodeKind, text: str) -> Node:
        """Add a node to the chain and return it."""
        kind = _require_node_kind(kind)
        text = _require_text(text, "node text")
        self._counter += 1
        key = f"node:{self._counter}:{kind.value}"
        node = Node(key=key, kind=kind, text=text)
        self._nodes[key] = node
        return node

    def has_node(self, key: str) -> bool:
        """Whether the graph holds a node with this key."""
        return key in self._nodes

    def node(self, key: str) -> Optional[Node]:
        """The node with this key, or ``None``."""
        return self._nodes.get(key)

    def nodes(self) -> Tuple[Node, ...]:
        """Every node, in insertion order."""
        return tuple(self._nodes.values())

    # -- edges -------------------------------------------------------------

    def link(self, src: str, relation: Relation, dst: str) -> None:
        """Join two nodes with a relation.

        The relation is checked against the kinds of its endpoints: the
        relation vocabulary is a claim about causality, so an edge that
        does not fit what it joins is refused rather than recorded.
        """
        relation = _require_relation(relation)
        source = self._nodes.get(src)
        target = self._nodes.get(dst)
        if source is None:
            raise ExplorationGraphError(f"unknown source node: {src!r}")
        if target is None:
            raise ExplorationGraphError(f"unknown target node: {dst!r}")
        if src == dst:
            raise ExplorationGraphError("a node cannot be linked to itself")
        allowed_sources, allowed_targets = _RELATION_ENDPOINTS[relation]
        if source.kind not in allowed_sources:
            raise ExplorationGraphError(
                f"relation {relation.value} cannot run from a {source.kind.value}"
            )
        if target.kind not in allowed_targets:
            raise ExplorationGraphError(
                f"relation {relation.value} cannot run to a {target.kind.value}"
            )
        edge = (src, relation, dst)
        if edge in self._edges:
            return
        self._edges.add(edge)
        self._children.setdefault(src, []).append(dst)
        self._parents.setdefault(dst, []).append(src)

    def has_edge(self, src: str, relation: Relation, dst: str) -> bool:
        """Whether the graph holds this edge."""
        try:
            relation = _require_relation(relation)
        except ExplorationGraphError:
            return False
        return (src, relation, dst) in self._edges

    def children(self, key: str) -> Tuple[Node, ...]:
        """The nodes directly downstream of this one."""
        return tuple(self._nodes[child] for child in self._children.get(key, ()))

    def parents(self, key: str) -> Tuple[Node, ...]:
        """The nodes directly upstream of this one."""
        return tuple(self._nodes[parent] for parent in self._parents.get(key, ()))

    # -- anchors -----------------------------------------------------------

    def anchor(self, node_key: str, asset_key: str) -> None:
        """Say that this exploration node is about this asset.

        The asset is named by the key the asset graph computed.  An anchor
        to an asset the graph does not hold is refused, because an anchor
        that points at nothing is a silent no-op that reads as coverage.
        """
        if node_key not in self._nodes:
            raise ExplorationGraphError(f"unknown node: {node_key!r}")
        asset_key = _require_text(asset_key, "asset key")
        if self._assets.get(asset_key) is None:
            raise ExplorationGraphError(f"unknown asset: {asset_key!r}")
        self._anchors.setdefault(node_key, set()).add(asset_key)
        self._asset_anchors.setdefault(asset_key, set()).add(node_key)

    def anchors_for(self, node_key: str) -> Tuple[str, ...]:
        """The asset keys this node is anchored to."""
        return tuple(sorted(self._anchors.get(node_key, ())))

    def nodes_for_asset(self, asset_key: str) -> Tuple[str, ...]:
        """The exploration node keys anchored to this asset."""
        return tuple(sorted(self._asset_anchors.get(asset_key, ())))

    # -- lineage -----------------------------------------------------------

    def _walk_up(self, start: str) -> Set[str]:
        """Every node reachable by walking the parent edges upward.

        The walk marks a node when it is *pushed*, so no node is ever
        expanded twice and a cyclic graph terminates.  The step budget is
        the belt to that pair of braces: it is one longer than the number
        of nodes, so a walk that somehow exceeded it is refused with a
        clear error rather than spinning.
        """
        seen: Set[str] = set()
        stack: List[str] = []
        for parent in self._parents.get(start, ()):
            if parent not in seen:
                seen.add(parent)
                stack.append(parent)
        budget = len(self._nodes) + 1
        while stack:
            if budget <= 0:
                raise ExplorationGraphError("the lineage walk exceeded its bound")
            budget -= 1
            current = stack.pop()
            for parent in self._parents.get(current, ()):
                if parent not in seen:
                    seen.add(parent)
                    stack.append(parent)
        return seen

    def lineage(self, finding_key: str) -> Lineage:
        """The chain that produced a finding.

        The lineage is everything that stands behind the finding: the
        nodes reachable upward from it, plus the facts that those nodes
        produced.

        The upward walk alone is not enough, and the reason is worth
        stating.  A fact and the finding drawn from it are **siblings**:
        both were produced by the same intent.  So a finding that an
        intent *proves* has that intent as a parent, but the facts the
        intent yielded are the intent's other children, not its
        ancestors -- and they are exactly the evidence the finding rests
        on.  A lineage that stopped at the ancestors would report a
        finding with no facts behind it even though the graph holds the
        facts that produced it.
        """
        finding = self._nodes.get(finding_key)
        if finding is None:
            raise ExplorationGraphError(f"unknown node: {finding_key!r}")
        if finding.kind is not NodeKind.FINDING:
            raise ExplorationGraphError(
                f"lineage is asked for a finding, not a {finding.kind.value}"
            )
        upstream = self._walk_up(finding_key)

        # The facts that stand behind the finding: the ones its upstream
        # chain produced, plus the finding's own siblings.
        supporting: Set[str] = set(upstream)
        for key in upstream:
            for child in self._children.get(key, ()):
                child_node = self._nodes.get(child)
                if child_node is not None and child_node.kind is NodeKind.FACT:
                    supporting.add(child)
        for child in self._children.get(finding_key, ()):
            child_node = self._nodes.get(child)
            if child_node is not None and child_node.kind is NodeKind.FACT:
                supporting.add(child)

        def of_kind(kind: NodeKind) -> Tuple[Node, ...]:
            return tuple(
                node for node in self._nodes.values()
                if node.key in supporting and node.kind is kind
            )

        return Lineage(
            finding=finding_key,
            facts=of_kind(NodeKind.FACT),
            intents=of_kind(NodeKind.INTENT),
            goals=of_kind(NodeKind.GOAL),
        )

    # -- coverage ----------------------------------------------------------

    def _tested_asset_keys(self) -> Set[str]:
        """The assets that a *fact* is anchored to.

        Only a fact is evidence that an asset was exercised.  An intent
        is a plan and a finding is a conclusion; neither is evidence that
        the asset was actually touched.
        """
        tested: Set[str] = set()
        for key, node in self._nodes.items():
            if node.kind is not NodeKind.FACT:
                continue
            tested.update(self._anchors.get(key, ()))
        return tested

    def coverage(self, scope: Sequence[str]) -> CoverageReport:
        """Which of the in-scope assets were tested.

        The scope is the denominator the caller asserts; every member
        must be a key of a known asset.  The report says which of them a
        fact is anchored to, and which were never exercised.

        The scope is a **set** of assets: a member listed twice is one
        member.  Otherwise the denominator could be grown under the
        caller's hand -- by repeating an untested entry -- while the
        tested count stayed put, and the coverage figure would fall
        without a single asset going untested.
        """
        if isinstance(scope, (str, bytes)):
            raise ExplorationGraphError("the scope must be a sequence of asset keys")
        members: List[str] = []
        seen: Set[str] = set()
        for entry in scope:
            key = _require_text(entry, "scope member")
            if self._assets.get(key) is None:
                raise ExplorationGraphError(f"unknown asset in scope: {key!r}")
            if key in seen:
                continue
            seen.add(key)
            members.append(key)

        tested_assets = self._tested_asset_keys()
        tested = tuple(key for key in members if key in tested_assets)
        untested = tuple(key for key in members if key not in tested_assets)

        counts: Dict[AssetKind, List[int]] = {}
        for key in members:
            node = self._assets.get(key)
            if node is None:  # pragma: no cover - checked above
                continue
            row = counts.setdefault(node.kind, [0, 0])
            row[0] += 1
            if key in tested_assets:
                row[1] += 1
        rows = tuple(
            KindCoverage(kind=kind, total=values[0], tested_count=values[1])
            for kind, values in sorted(counts.items(), key=lambda item: item[0].value)
        )
        return CoverageReport(
            denominator=len(members),
            tested=tested,
            untested=untested,
            by_kind_rows=rows,
        )

    def __len__(self) -> int:
        return len(self._nodes)


def stdlib_only() -> bool:
    """Whether this module imports nothing outside the standard library."""
    import ast
    import os

    allowed = {
        "hashlib", "ipaddress", "dataclasses", "enum", "typing",
        "ast", "os", "__future__",
    }
    here = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(here, "exploration_graph.py")
    with open(path, "r", encoding="utf-8") as handle:
        tree = ast.parse(handle.read(), filename=path)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                if root not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.level:  # a relative import is outside the boundary
                return False
            root = (node.module or "").split(".")[0]
            if root not in allowed:
                return False
    return True


def uses_clock() -> bool:
    """Whether this module reads a clock.

    It does not: every key is a pure function of the observation, so two
    runs over the same observations produce the same graph.
    """
    import ast
    import os

    here = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(here, "exploration_graph.py")
    with open(path, "r", encoding="utf-8") as handle:
        tree = ast.parse(handle.read(), filename=path)
    clock_modules = {"time", "datetime"}
    clock_names = {"monotonic", "perf_counter", "time", "now", "today"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] in clock_modules:
                    return True
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                continue
            if (node.module or "").split(".")[0] in clock_modules:
                return True
        elif isinstance(node, ast.Attribute):
            if node.attr in clock_names and isinstance(node.value, ast.Name):
                if node.value.id in clock_modules:
                    return True
    return False
