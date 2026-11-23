"""Anti-entropy via Merkle-tree sync (Dynamo/Riak shaped).

Two replicas that each hold a set of ``(key, value)`` pairs converge by
comparing Merkle roots over their keyspaces, then drilling down to the
divergent leaves and exchanging only those keys. This module books the
*decisions* of that process — what to compare, what differs, what to
exchange — on a single host with no network, no timers, and no wall-clock.

* **Inventory** — ``put`` pins a ``(key, value)`` pair; ``remove`` books
  a tombstone (delete must converge, not just vanish locally).
* **Digest** — ``digest`` builds a binary Merkle tree (reusing the
  sibling ``merkle_tree`` module) over the keyspace sorted by key digest;
  the root pins the whole inventory with one ``sha256:`` pin. An empty
  inventory has a fixed ``EMPTY_ROOT`` constant — there is nothing to
  anchor, so the constant is the honest answer.
* **Compare** — ``compare`` takes the peer's root *and* the peer's
  key→(digest, update_seq) inventory (host-reported, GIGO). Roots alone
  can only say "same or different"; finding *which* keys differ needs the
  inventories, which is exactly what real anti-entropy exchanges after a
  root mismatch. The verdict is data: ``to_push`` (keys the peer lacks),
  ``to_pull`` (keys this replica lacks), and ``conflicts`` (same key,
  different live values on both sides). Delete-wins: a tombstone on one
  side propagates to the other; for live/live conflicts the module
  refuses to pick a winner — per-replica ledger seqs are not a shared
  clock, so the host resolves with its own policy.
* **Repair** — ``repair`` applies a host-supplied pull set
  ``{key: value_bytes}`` plus a host-supplied tombstone list; entries
  whose digest already matches are no-ops (booked as ``skipped_stale``),
  the rest are applied and tombstones win over live entries in the same
  batch. Returns a frozen ``RepairRecord`` with counts and key lists. It
  books the *decision*, not the wire: "these keys were merged" is ledger
  truth, never "the peer received them".

House style: frozen dataclasses, caller int seqs strictly increasing,
no wall-clock, RLock-guarded, fail-closed, stdlib-only plus the
registered sibling ``merkle_tree`` (itself stdlib-only), ``sha256:``
digest pins, ``audit.ndjson/1`` events, raw values banned from the
audit boundary, version/schema pins, ``main()`` self-check.

Honest scope: books declared inventories and host-reported peer data —
cannot prove the peer's inventory is honest, cannot observe the wire.
Tombstones are converged, never garbage-collected here (GC policy is a
caller decision). A stale or lying peer inventory yields a wrong diff;
the module reports what the inputs imply, nothing more.

Version pin: anti-entropy.v1
Schema pin: northstar.anti-entropy.v1
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass, field

from merkle_tree import MerkleTree

ANTI_ENTROPY_VERSION = "anti-entropy.v1"
SCHEMA_PIN = "northstar.anti-entropy.v1"
AUDIT_FORMAT = "audit.ndjson/1"

# Fixed root for an empty inventory: there is nothing to anchor, so the
# constant says exactly that — it is not a hash of "nothing".
EMPTY_ROOT = "sha256:" + hashlib.sha256(b"northstar.anti-entropy.v1:empty").hexdigest()

# Well-known digest marking a tombstone. Deletes converge because every
# replica books the same digest for "deleted"; compare() detects it on
# either side and lets the delete win (delete-wins, Cassandra style).
TOMBSTONE_DIGEST = "sha256:" + hashlib.sha256(
    b"northstar.anti-entropy.v1:tombstone"
).hexdigest()

_MAX_KEY_LEN = 1024
_MAX_VALUE_LEN = 1 << 20  # 1 MiB per value


# ---------------------------------------------------------------------------
# Fail-closed taxonomy
# ---------------------------------------------------------------------------

class AntiEntropyError(Exception):
    """Base class for all anti-entropy errors."""


class BadKeyError(AntiEntropyError):
    pass


class BadValueError(AntiEntropyError):
    pass


class BadInventoryError(AntiEntropyError):
    pass


class BadDigestError(AntiEntropyError):
    pass


class SeqOrderError(AntiEntropyError):
    pass


class AuditKindError(AntiEntropyError):
    pass


_AUDIT_KINDS = frozenset(
    {
        "anti-entropy.put",
        "anti-entropy.removed",
        "anti-entropy.digest",
        "anti-entropy.compared",
        "anti-entropy.repaired",
        "anti-entropy.rejected",
    }
)


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

def _check_seq(seq) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError(f"seq must be an int, got {type(seq).__name__}")
    if seq < 0:
        raise SeqOrderError("seq must be non-negative")
    return seq


def _check_key(key: str) -> str:
    if isinstance(key, bool) or not isinstance(key, str):
        raise BadKeyError(f"key must be a str, got {type(key).__name__}")
    if not key:
        raise BadKeyError("key must be non-empty")
    if len(key) > _MAX_KEY_LEN:
        raise BadKeyError(f"key longer than {_MAX_KEY_LEN} chars")
    return key


def _check_value(value: bytes) -> bytes:
    if not isinstance(value, (bytes, bytearray)):
        raise BadValueError(f"value must be bytes, got {type(value).__name__}")
    value = bytes(value)
    if len(value) > _MAX_VALUE_LEN:
        raise BadValueError(f"value larger than {_MAX_VALUE_LEN} bytes")
    return value


def _digest_of(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _check_pin(pin: str, what: str) -> str:
    if isinstance(pin, bool) or not isinstance(pin, str):
        raise BadDigestError(f"{what} must be a sha256: pin")
    if not pin.startswith("sha256:") or len(pin) != 7 + 64:
        raise BadDigestError(f"{what} must be a sha256: pin")
    hexpart = pin[7:]
    if any(c not in "0123456789abcdef" for c in hexpart):
        raise BadDigestError(f"{what} must be lowercase hex")
    return pin


def _check_inventory(inventory, what: str) -> dict:
    """Validate a peer inventory: {key: (sha256: pin, update_seq)}."""
    if not isinstance(inventory, dict):
        raise BadInventoryError(f"{what} must be a dict")
    out = {}
    for k, v in inventory.items():
        key = _check_key(k)
        if not isinstance(v, (tuple, list)) or len(v) != 2:
            raise BadInventoryError(f"{what}[{key!r}] must be (digest, update_seq)")
        pin, useq = v
        if isinstance(useq, bool) or not isinstance(useq, int) or useq < 0:
            raise BadInventoryError(f"{what}[{key!r}] update_seq must be a non-negative int")
        out[key] = (_check_pin(pin, f"{what}[{key!r}]"), useq)
    return out


def _check_pull(pull, what: str) -> dict:
    if not isinstance(pull, dict):
        raise BadInventoryError(f"{what} must be a dict")
    out = {}
    for k, v in pull.items():
        out[_check_key(k)] = _check_value(v)
    return out


def _canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PutRecord:
    key: str
    value_digest: str
    update_seq: int
    seq: int
    schema: str = SCHEMA_PIN


@dataclass(frozen=True)
class RemoveRecord:
    key: str
    update_seq: int
    seq: int
    schema: str = SCHEMA_PIN


@dataclass(frozen=True)
class DigestRecord:
    root: str
    key_count: int
    leaf_count: int
    seq: int
    schema: str = SCHEMA_PIN


@dataclass(frozen=True)
class CompareReport:
    roots_equal: bool
    local_root: str
    peer_root: str
    to_push: tuple
    to_pull: tuple
    conflicts: tuple
    seq: int
    schema: str = SCHEMA_PIN


@dataclass(frozen=True)
class RepairRecord:
    applied: int
    skipped_stale: int
    tombstoned: int
    applied_keys: tuple
    seq: int
    schema: str = SCHEMA_PIN


@dataclass(frozen=True)
class AntiEntropyStats:
    replica_id: str
    live_keys: int
    tombstones: int
    puts: int
    removes: int
    repairs: int
    last_seq: int


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------

def anti_entropy_audit_event(kind: str, seq: int, **fields) -> dict:
    """Build an ``audit.ndjson/1`` event for anti-entropy decisions."""
    if kind not in _AUDIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    event = {
        "format": AUDIT_FORMAT,
        "kind": kind,
        "seq": seq,
        "schema": SCHEMA_PIN,
    }
    event.update(fields)
    return event


# ---------------------------------------------------------------------------
# The ledger
# ---------------------------------------------------------------------------

class AntiEntropy:
    """Single-host anti-entropy bookkeeping for one replica's inventory.

    All mutations take a caller-supplied strictly increasing int ``seq``;
    failed mutations consume their seq and book ``anti-entropy.rejected``
    (the batch-21 discipline). Pure reads validate the seq shape but
    consume nothing and write no audit row.
    """

    def __init__(self, replica_id: str) -> None:
        if isinstance(replica_id, bool) or not isinstance(replica_id, str) or not replica_id:
            raise BadKeyError("replica_id must be a non-empty str")
        self._replica_id = replica_id
        self._lock = threading.RLock()
        self._last_seq = -1
        # key -> (value_digest, update_seq); tombstoned keys live here too
        self._entries: dict[str, tuple[str, int]] = {}
        self._tombstones: set[str] = set()
        self._puts = 0
        self._removes = 0
        self._repairs = 0
        self._audit: list[dict] = []

    # -- internals --------------------------------------------------------

    def _claim(self, seq: int) -> int:
        seq = _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq must be strictly increasing: got {seq}, last {self._last_seq}"
            )
        self._last_seq = seq
        return seq

    def _reject(self, seq: int, reason: str) -> None:
        # Failed mutations consume their seq, then book the rejection.
        try:
            self._claim(seq)
        except SeqOrderError:
            return
        self._audit.append(
            anti_entropy_audit_event("anti-entropy.rejected", seq, reason=reason)
        )

    def _leaf_for(self, key: str) -> bytes:
        # NOTE: update_seq is deliberately excluded — two replicas holding
        # the same values must anchor the same root even though their
        # per-replica ledger seqs differ. The leaf pins key + digest +
        # tombstone state, nothing more.
        digest, _ = self._entries[key]
        tombstone = key in self._tombstones
        return _canonical(
            {
                "key": key,
                "value_digest": digest,
                "tombstone": tombstone,
            }
        )

    # -- mutations ----------------------------------------------------------

    def put(self, key: str, value: bytes, seq: int) -> PutRecord:
        """Pin ``(key, value)`` into the local inventory."""
        with self._lock:
            try:
                key = _check_key(key)
                value = _check_value(value)
                seq = self._claim(seq)
            except AntiEntropyError as exc:
                self._reject(seq if isinstance(seq, int) else -1, str(exc))
                raise
            digest = _digest_of(value)
            self._entries[key] = (digest, seq)
            self._tombstones.discard(key)
            self._puts += 1
            rec = PutRecord(
                key=key, value_digest=digest, update_seq=seq, seq=seq
            )
            self._audit.append(
                anti_entropy_audit_event(
                    "anti-entropy.put", seq, key=key, value_digest=digest
                )
            )
            return rec

    def remove(self, key: str, seq: int) -> RemoveRecord:
        """Book a tombstone for ``key`` so deletes converge across replicas."""
        with self._lock:
            try:
                key = _check_key(key)
                seq = self._claim(seq)
            except AntiEntropyError as exc:
                self._reject(seq if isinstance(seq, int) else -1, str(exc))
                raise
            tombstone_digest = TOMBSTONE_DIGEST
            self._entries[key] = (tombstone_digest, seq)
            self._tombstones.add(key)
            self._removes += 1
            rec = RemoveRecord(key=key, update_seq=seq, seq=seq)
            self._audit.append(
                anti_entropy_audit_event("anti-entropy.removed", seq, key=key)
            )
            return rec

    # -- digest / compare / repair ------------------------------------------

    def digest(self, seq: int) -> DigestRecord:
        """Merkle root over the keyspace sorted by key digest."""
        with self._lock:
            try:
                seq = self._claim(seq)
            except AntiEntropyError:
                self._reject(seq if isinstance(seq, int) else -1, "bad seq")
                raise
            keys = sorted(self._entries, key=lambda k: hashlib.sha256(k.encode()).hexdigest())
            if not keys:
                rec = DigestRecord(
                    root=EMPTY_ROOT, key_count=0, leaf_count=0, seq=seq
                )
            else:
                tree = MerkleTree.build([self._leaf_for(k) for k in keys])
                rec = DigestRecord(
                    root=tree.root(),
                    key_count=len(keys),
                    leaf_count=len(keys),
                    seq=seq,
                )
            self._audit.append(
                anti_entropy_audit_event(
                    "anti-entropy.digest",
                    seq,
                    root=rec.root,
                    key_count=rec.key_count,
                )
            )
            return rec

    def compare(self, peer_root: str, peer_inventory: dict, seq: int) -> CompareReport:
        """Diff the local inventory against a host-reported peer inventory.

        ``peer_inventory`` maps key -> ``(sha256: digest, update_seq)`` as
        the peer reports it (GIGO). Roots alone only say "same or
        different"; the inventories say *which* keys differ.

        Direction rules, deterministic and documented:

        * key only on one side -> ``to_push`` / ``to_pull``;
        * both sides tombstoned (same well-known digest) -> nothing;
        * local tombstone, peer live -> ``to_push`` (delete-wins);
        * peer tombstone, local live -> ``to_pull`` (delete-wins);
        * both live with differing digests -> ``conflicts``. Per-replica
          ledger seqs are not a shared clock, so this module refuses to
          pick a winner; the host resolves with its own policy.
        """
        with self._lock:
            try:
                peer_root = _check_pin(peer_root, "peer_root")
                peer_inventory = _check_inventory(peer_inventory, "peer_inventory")
                seq = self._claim(seq)
            except AntiEntropyError as exc:
                self._reject(seq if isinstance(seq, int) else -1, str(exc))
                raise
            local_root = self._current_root()
            to_push: list[str] = []
            to_pull: list[str] = []
            conflicts: list[str] = []
            local_keys = set(self._entries)
            peer_keys = set(peer_inventory)
            for key in local_keys - peer_keys:
                to_push.append(key)
            for key in peer_keys - local_keys:
                to_pull.append(key)
            for key in local_keys & peer_keys:
                local_digest, _ = self._entries[key]
                peer_digest, _ = peer_inventory[key]
                if local_digest == peer_digest:
                    continue
                local_tomb = local_digest == TOMBSTONE_DIGEST
                peer_tomb = peer_digest == TOMBSTONE_DIGEST
                if local_tomb and not peer_tomb:
                    to_push.append(key)
                elif peer_tomb and not local_tomb:
                    to_pull.append(key)
                else:
                    conflicts.append(key)
            rec = CompareReport(
                roots_equal=(local_root == peer_root),
                local_root=local_root,
                peer_root=peer_root,
                to_push=tuple(sorted(to_push)),
                to_pull=tuple(sorted(to_pull)),
                conflicts=tuple(sorted(conflicts)),
                seq=seq,
            )
            self._audit.append(
                anti_entropy_audit_event(
                    "anti-entropy.compared",
                    seq,
                    roots_equal=rec.roots_equal,
                    push_count=len(rec.to_push),
                    pull_count=len(rec.to_pull),
                    conflict_count=len(rec.conflicts),
                )
            )
            return rec

    def repair(self, pull_entries: dict, pull_tombstones, seq: int) -> RepairRecord:
        """Apply a host-supplied pull set and tombstone list.

        ``pull_entries`` maps key -> full value bytes (the host fetched
        them after a ``compare``); ``pull_tombstones`` is an iterable of
        keys the peer reports as deleted. Entries whose digest already
        matches the local entry are no-ops booked as ``skipped_stale``;
        everything else is applied with the repair's seq as its new
        update marker. A tombstone always wins over a live entry in the
        same batch, so deletes converge.
        """
        with self._lock:
            try:
                pull_entries = _check_pull(pull_entries, "pull_entries")
                if not isinstance(pull_tombstones, (list, tuple, set, frozenset)):
                    raise BadInventoryError("pull_tombstones must be a list/tuple/set")
                tombstone_keys = [_check_key(k) for k in pull_tombstones]
                seq = self._claim(seq)
            except AntiEntropyError as exc:
                self._reject(seq if isinstance(seq, int) else -1, str(exc))
                raise
            applied: list[str] = []
            skipped = 0
            tombstoned = 0
            tombstone_digest = TOMBSTONE_DIGEST
            for key, value in pull_entries.items():
                digest = _digest_of(value)
                local = self._entries.get(key)
                if local is not None and local[0] == digest:
                    # Peer and local agree already; nothing to merge.
                    skipped += 1
                    continue
                self._entries[key] = (digest, seq)
                self._tombstones.discard(key)
                applied.append(key)
            for key in tombstone_keys:
                local = self._entries.get(key)
                if key in self._tombstones:
                    skipped += 1
                    continue
                self._entries[key] = (tombstone_digest, seq)
                self._tombstones.add(key)
                tombstoned += 1
            self._repairs += 1
            rec = RepairRecord(
                applied=len(applied),
                skipped_stale=skipped,
                tombstoned=tombstoned,
                applied_keys=tuple(sorted(applied)),
                seq=seq,
            )
            self._audit.append(
                anti_entropy_audit_event(
                    "anti-entropy.repaired",
                    seq,
                    applied=rec.applied,
                    skipped_stale=rec.skipped_stale,
                    tombstoned=rec.tombstoned,
                )
            )
            return rec

    # -- pure read views ------------------------------------------------------

    def _current_root(self) -> str:
        keys = sorted(self._entries, key=lambda k: hashlib.sha256(k.encode()).hexdigest())
        if not keys:
            return EMPTY_ROOT
        tree = MerkleTree.build([self._leaf_for(k) for k in keys])
        return tree.root()

    def inventory(self, seq: int) -> dict:
        """Host-side key -> (digest, update_seq) view (pure; seq validated, never consumed)."""
        with self._lock:
            _check_seq(seq)
            return {k: (d, u) for k, (d, u) in self._entries.items()}

    def tombstones(self, seq: int) -> tuple:
        """Sorted tombstoned keys (pure; seq validated, never consumed)."""
        with self._lock:
            _check_seq(seq)
            return tuple(sorted(self._tombstones))

    def stats(self, seq: int) -> AntiEntropyStats:
        """Pure read view over replica bookkeeping."""
        with self._lock:
            _check_seq(seq)
            return AntiEntropyStats(
                replica_id=self._replica_id,
                live_keys=len(self._entries) - len(self._tombstones),
                tombstones=len(self._tombstones),
                puts=self._puts,
                removes=self._removes,
                repairs=self._repairs,
                last_seq=self._last_seq,
            )

    def audit_log(self) -> tuple:
        """The booked audit events, in order."""
        with self._lock:
            return tuple(self._audit)


def main() -> None:
    a = AntiEntropy("replica-a")
    b = AntiEntropy("replica-b")
    seq = 0

    def next_seq() -> int:
        nonlocal seq
        seq += 1
        return seq

    # A holds two keys; B holds one overlapping, one unique, one stale.
    a.put("k1", b"v1", next_seq())
    a.put("k2", b"v2", next_seq())
    b.put("k1", b"v1-stale", next_seq())
    b.put("k3", b"v3", next_seq())
    da = a.digest(next_seq())
    db = b.digest(next_seq())
    assert da.root != db.root

    # Compare: A pushes k2 (B lacks it) and pulls k3 (A lacks it);
    # k1 is a live/live conflict the module refuses to resolve.
    rep = a.compare(db.root, b.inventory(next_seq()), next_seq())
    assert not rep.roots_equal
    assert rep.to_push == ("k2",), rep.to_push
    assert rep.to_pull == ("k3",), rep.to_pull
    assert rep.conflicts == ("k1",), rep.conflicts

    # Symmetric exchange: host resolves the k1 conflict in A's favor.
    brec = b.repair({"k1": b"v1", "k2": b"v2"}, (), next_seq())
    assert brec.applied == 2 and brec.skipped_stale == 0
    arec = a.repair({"k3": b"v3"}, (), next_seq())
    assert arec.applied == 1
    assert a.digest(next_seq()).root == b.digest(next_seq()).root

    # Delete converges: B removes k1, A pulls the tombstone.
    b.remove("k1", next_seq())
    db2 = b.digest(next_seq())
    rep2 = a.compare(db2.root, b.inventory(next_seq()), next_seq())
    assert "k1" in rep2.to_pull
    rec2 = a.repair({}, ("k1",), next_seq())
    assert rec2.tombstoned == 1
    assert "k1" in a.tombstones(next_seq())

    print(
        "anti-entropy OK: digest, compare, repair, tombstones, audit, "
        f"{len(a.audit_log())} audit rows"
    )


if __name__ == "__main__":
    main()
