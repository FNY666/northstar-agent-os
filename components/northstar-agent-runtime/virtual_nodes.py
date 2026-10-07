"""Virtual nodes: Dynamo/Cassandra-style vnode ownership bookkeeping.

Research note: virtual nodes (DeCandia et al., "Dynamo", 2007; Cassandra's
``num_tokens``) divide the key space into a fixed number of vnode slots —
here ``0 .. num_vnodes-1`` — and assign whole vnodes to physical nodes.
Membership changes then move vnodes, not arbitrary hash ranges: adding a
node or losing one reassigns a bounded, deterministic set of slots, and
heterogeneous nodes can hold proportionally more vnodes by construction.

This module is the *slot ledger*, deliberately distinct from
``consistent_hash``:

* ``consistent_hash`` places per-node random ring points and routes a key
  to the first clockwise point.
* ``virtual_nodes`` books *which physical node owns each numbered vnode
  slot*, and plans deterministic *moves* when membership changes.
  ``owner_of_key`` is a convenience that hashes a key to a slot and then
  to the slot's owner; the canonical unit of the module is the vnode,
  not the key.

Deterministic placement rule: vnode ``v`` hashes to slot ``v`` itself —
the slot *is* the position on the ring (``owner(v)`` is a table lookup,
``owner_of_key(key)`` is ``owner(sha256(key) mod num_vnodes)``). No
randomness, no wall-clock; replays are exact and two hosts with the same
ledger agree.

Fail-closed: assigning to an empty node id, moving more vnodes than exist,
asking the owner of an out-of-range or unassigned vnode, and rebalancing
an empty fleet all raise rather than guess.

Honest scope: this module books *declared* ownership — it cannot verify a
node is alive, can hold the load, or has actually received the data. A
rebalance plan is a proposal the host must execute; "``owner(7)`` is
``db-3``" means the ledger says so, never that db-3 is reachable or
already holds slot 7.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

#: Module version.
VIRTUAL_NODES_VERSION = "virtual-nodes.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.virtual-nodes.v1"

#: Hash domain separator so key-to-slot hashes cannot collide with others.
_HASH_DOMAIN = b"northstar.virtual-nodes.v1\x00"

#: Audit kinds.
ACTION_ASSIGNED = "assigned"
ACTION_REBALANCED = "rebalanced"
ACTION_DRAINED = "drained"
_AUDIT_ACTIONS = (ACTION_ASSIGNED, ACTION_REBALANCED, ACTION_DRAINED)


class VirtualNodesError(Exception):
    """Base error for virtual-node ledger misuse."""


class UnknownNodeError(VirtualNodesError):
    """Raised when naming a node that owns nothing on the ledger."""


class UnknownVNodeError(VirtualNodesError):
    """Raised when naming a vnode slot outside the ledger range."""


class UnassignedVNodeError(VirtualNodesError):
    """Raised when asking the owner of a vnode nobody owns yet."""


class NoNodesError(VirtualNodesError):
    """Raised when rebalancing a ledger with no nodes."""


def _check_node_id(node_id: object) -> str:
    if not isinstance(node_id, str):
        raise TypeError("node_id must be a str")
    if not node_id:
        raise ValueError("node_id must be non-empty")
    if len(node_id) > 256:
        raise ValueError("node_id must be <= 256 chars")
    return node_id


def _check_vnode(vnode: object, num_vnodes: int) -> int:
    if isinstance(vnode, bool) or not isinstance(vnode, int):
        raise TypeError("vnode must be an int")
    if not 0 <= vnode < num_vnodes:
        raise UnknownVNodeError(
            f"vnode {vnode!r} out of range [0, {num_vnodes})"
        )
    return vnode


def _slot_for_key(key: str, num_vnodes: int) -> int:
    digest = hashlib.sha256(_HASH_DOMAIN + key.encode("utf-8")).digest()
    return int.from_bytes(digest, "big") % num_vnodes


@dataclass(frozen=True)
class AssignmentRecord:
    """Immutable record of one ``assign`` call."""

    schema: str
    node_id: str
    requested: Optional[int]
    assigned: Tuple[int, ...]
    ledger_digest: str

    def as_dict(self) -> dict:
        return {
            "schema": self.schema,
            "node_id": self.node_id,
            "requested": self.requested,
            "assigned": list(self.assigned),
            "ledger_digest": self.ledger_digest,
        }


@dataclass(frozen=True)
class MoveRecord:
    """One vnode ownership change: ``vnode`` moves from ``src`` to ``dst``."""

    vnode: int
    src: Optional[str]  # None when the vnode was unassigned
    dst: str

    def as_dict(self) -> dict:
        return {"vnode": self.vnode, "src": self.src, "dst": self.dst}


@dataclass(frozen=True)
class RebalancePlan:
    """Immutable plan produced by ``rebalance`` or ``drain``."""

    schema: str
    moves: Tuple[MoveRecord, ...]
    owners_digest: str  # digest of the ownership table after the moves

    def as_dict(self) -> dict:
        return {
            "schema": self.schema,
            "moves": [m.as_dict() for m in self.moves],
            "owners_digest": self.owners_digest,
        }


class VirtualNodes:
    """Fixed-slot vnode ownership ledger.

    ``num_vnodes`` is fixed at construction: the slot set is the
    coordination contract between hosts, and changing it silently would
    re-place every key. Create a new ledger if the slot count must
    change.
    """

    def __init__(self, num_vnodes: int = 256) -> None:
        if isinstance(num_vnodes, bool) or not isinstance(num_vnodes, int):
            raise TypeError("num_vnodes must be an int")
        if num_vnodes < 1:
            raise ValueError("num_vnodes must be >= 1")
        if num_vnodes > 1 << 20:
            raise ValueError("num_vnodes must be <= 1048576")
        self._num_vnodes = num_vnodes
        # vnode -> node_id. Absent vnode = unassigned.
        self._owners: Dict[int, str] = {}

    @property
    def num_vnodes(self) -> int:
        return self._num_vnodes

    # -- queries ------------------------------------------------------

    def owner(self, vnode: int) -> str:
        """Return the node that owns ``vnode``.

        Raises :class:`UnknownVNodeError` for an out-of-range slot and
        :class:`UnassignedVNodeError` for a slot nobody owns yet — a key
        must never be "owned" by a default node nobody booked.
        """
        _check_vnode(vnode, self._num_vnodes)
        try:
            return self._owners[vnode]
        except KeyError:
            raise UnassignedVNodeError(f"vnode {vnode} has no owner")

    def owner_of_key(self, key: str) -> str:
        """Hash ``key`` to a slot and return that slot's owner.

        ``key`` must be a non-empty str; the owner of the *slot* is the
        verdict, so this inherits the fail-closed rules of :meth:`owner`.
        """
        if not isinstance(key, str):
            raise TypeError("key must be a str")
        if not key:
            raise ValueError("key must be non-empty")
        return self.owner(_slot_for_key(key, self._num_vnodes))

    def vnodes_for(self, node_id: str) -> Tuple[int, ...]:
        """Sorted vnode slots owned by ``node_id`` (empty tuple if none)."""
        _check_node_id(node_id)
        return tuple(sorted(v for v, n in self._owners.items() if n == node_id))

    def nodes(self) -> Tuple[str, ...]:
        """Node ids that own at least one vnode, in first-assigned order."""
        seen: List[str] = []
        for vnode in sorted(self._owners):
            node = self._owners[vnode]
            if node not in seen:
                seen.append(node)
        return tuple(seen)

    def unassigned(self) -> Tuple[int, ...]:
        """Sorted vnode slots with no owner yet."""
        owned = set(self._owners)
        return tuple(v for v in range(self._num_vnodes) if v not in owned)

    # -- mutation -----------------------------------------------------

    def assign(self, node_id: str, count: Optional[int] = None) -> AssignmentRecord:
        """Assign unowned vnodes to ``node_id``.

        The lowest-numbered unassigned slots go first, so two hosts
        replaying the same calls build the same ledger. ``count=None``
        takes all unassigned slots. Returns a frozen
        :class:`AssignmentRecord` — assignment is booked in the same call,
        the record is the receipt, not the plan.
        """
        _check_node_id(node_id)
        if count is not None:
            if isinstance(count, bool) or not isinstance(count, int):
                raise TypeError("count must be an int or None")
            if count < 0:
                raise ValueError("count must be >= 0")
        free = self.unassigned()
        take = free if count is None else free[:count]
        for vnode in take:
            self._owners[vnode] = node_id
        return AssignmentRecord(
            schema=SCHEMA_PIN,
            node_id=node_id,
            requested=count,
            assigned=tuple(take),
            ledger_digest=self._ledger_digest(),
        )

    def rebalance(self) -> RebalancePlan:
        """Even out vnode ownership across current owners; return the plan.

        Computes each node's fair share (``num_vnodes // n`` with the
        remainder going to the earliest-assigned nodes) and moves vnodes
        deterministically: the most over-full node sheds its *highest*
        slots first, the most under-full node receives the lowest freed
        slot first. The moves are applied to the ledger in the same call.
        Raises :class:`NoNodesError` when no node owns anything — there
        is no fair share of nothing.
        """
        nodes = self.nodes()
        if not nodes:
            raise NoNodesError("cannot rebalance: no node owns any vnode")
        return self._plan_even(nodes)

    def drain(self, node_id: str) -> RebalancePlan:
        """Move all of ``node_id``'s vnodes to the remaining owners.

        The decommission path: ``node_id`` ends owning nothing and its
        slots spread evenly (by count, then lowest slot first) over the
        survivors. Raises :class:`UnknownNodeError` for a node that owns
        nothing, and :class:`VirtualNodesError` when it is the last node —
        draining the only owner would strand every key.
        """
        _check_node_id(node_id)
        owned = self.vnodes_for(node_id)
        if not owned:
            raise UnknownNodeError(f"node owns no vnodes: {node_id!r}")
        survivors = [n for n in self.nodes() if n != node_id]
        if not survivors:
            raise VirtualNodesError(
                f"cannot drain the last owning node: {node_id!r}"
            )
        moves: List[MoveRecord] = []
        # Round-robin the drained slots over survivors for even spread.
        for i, vnode in enumerate(owned):
            dst = survivors[i % len(survivors)]
            self._owners[vnode] = dst
            moves.append(MoveRecord(vnode=vnode, src=node_id, dst=dst))
        return RebalancePlan(
            schema=SCHEMA_PIN,
            moves=tuple(moves),
            owners_digest=self._ledger_digest(),
        )

    # -- internals ----------------------------------------------------

    def _plan_even(self, nodes: Tuple[str, ...]) -> RebalancePlan:
        base, extra = divmod(self._num_vnodes, len(nodes))
        # Earliest-assigned nodes absorb the remainder first: stable rule.
        targets = {
            node: base + (1 if i < extra else 0) for i, node in enumerate(nodes)
        }
        current = {node: len(self.vnodes_for(node)) for node in nodes}
        moves: List[MoveRecord] = []
        # Sources: over-full nodes, highest slots first, most over-full first.
        # Sinks: under-full nodes, most under-full first.
        while True:
            over = sorted(
                (n for n in nodes if current[n] > targets[n]),
                key=lambda n: (current[n] - targets[n], n),
                reverse=True,
            )
            under = sorted(
                (n for n in nodes if current[n] < targets[n]),
                key=lambda n: (targets[n] - current[n], n),
                reverse=True,
            )
            if not over or not under:
                break
            src, dst = over[0], under[0]
            # Highest slot of the source moves: keeps low slots stable.
            vnode = max(self.vnodes_for(src))
            self._owners[vnode] = dst
            current[src] -= 1
            current[dst] += 1
            moves.append(MoveRecord(vnode=vnode, src=src, dst=dst))
        return RebalancePlan(
            schema=SCHEMA_PIN,
            moves=tuple(moves),
            owners_digest=self._ledger_digest(),
        )

    def _ledger_digest(self) -> str:
        """Domain-separated digest of the full ownership table."""
        h = hashlib.sha256(_HASH_DOMAIN + b"ledger\x00")
        for vnode in range(self._num_vnodes):
            owner = self._owners.get(vnode, "")
            h.update(f"{vnode}:{owner}\x00".encode("utf-8"))
        return "sha256:" + h.hexdigest()

    def stats(self) -> dict:
        """Summary view: slot count, per-node counts, unassigned count."""
        return {
            "schema": SCHEMA_PIN,
            "num_vnodes": self._num_vnodes,
            "assigned": len(self._owners),
            "unassigned": self._num_vnodes - len(self._owners),
            "node_counts": [
                {"node_id": node, "vnodes": len(self.vnodes_for(node))}
                for node in self.nodes()
            ],
            "ledger_digest": self._ledger_digest(),
        }

    def __len__(self) -> int:
        return len(self.nodes())


def virtual_nodes_audit_event(
    action: str, vn: VirtualNodes, node_id: Optional[str], seq: int
) -> dict:
    """Shape an ``audit.ndjson/1``-style record for a ledger change."""
    if action not in _AUDIT_ACTIONS:
        raise ValueError(f"unknown action: {action!r}")
    if node_id is not None:
        _check_node_id(node_id)
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise ValueError("seq must be a non-negative int")
    if not isinstance(vn, VirtualNodes):
        raise TypeError("vn must be a VirtualNodes")
    stats = vn.stats()
    return {
        "schema": SCHEMA_PIN,
        "event": "virtual-nodes." + action,
        "node_id": node_id,
        "num_vnodes": stats["num_vnodes"],
        "assigned": stats["assigned"],
        "unassigned": stats["unassigned"],
        "ledger_digest": stats["ledger_digest"],
        "audit_seq": seq,
    }


def main() -> None:
    vn = VirtualNodes(num_vnodes=16)
    rec = vn.assign("db-1", 6)
    assert len(rec.assigned) == 6, rec
    vn.assign("db-2", 6)
    vn.assign("db-3")  # takes the remaining 4
    assert vn.unassigned() == (), vn.unassigned()
    # Every slot has exactly one owner.
    assert {vn.owner(v) for v in range(16)} == {"db-1", "db-2", "db-3"}
    plan = vn.rebalance()
    counts = {n: len(vn.vnodes_for(n)) for n in vn.nodes()}
    assert sorted(counts.values()) == [5, 5, 6], counts
    # Draining a node keeps every slot owned, by the survivors only.
    plan2 = vn.drain("db-3")
    assert all(m.src == "db-3" for m in plan2.moves), plan2
    assert "db-3" not in vn.nodes()
    assert all(vn.owner(v) in {"db-1", "db-2"} for v in range(16))
    # Key routing follows the ledger.
    assert vn.owner_of_key("orders/42") == vn.owner(
        _slot_for_key("orders/42", 16)
    )
    print(
        "virtual-nodes OK: assign, rebalance to [5,5,6], "
        f"drain moved {len(plan2.moves)} slots, key routing matches ledger"
    )


if __name__ == "__main__":
    main()
