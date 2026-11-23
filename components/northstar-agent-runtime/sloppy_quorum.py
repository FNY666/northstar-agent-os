"""Sloppy quorum — Dynamo-style quorum read/write bookkeeping (batch 39).

Research note (Dynamo, DeCandia et al. 2007, "Dynamo: Amazon's Highly
Available Key-value Store"): every write is routed to a *preference list*
of the first ``N`` healthy nodes responsible for the key; the write succeeds
when at least ``W`` of them acknowledge. When fewer than ``N`` healthy
preference-list nodes are reachable, the coordinator falls back to
*sloppy* quorum — any other healthy node accepts the write and holds it as
a *hinted handoff* until the intended recipient recovers. Reads go to the
first ``R`` reachable nodes holding the key and reconcile divergent
versions; read-repair propagates the newest version back to stale holders.

This module is the deterministic single-host *ledger* for that contract:

* **Cluster membership** — ``node()`` registers storage nodes; ``fail()``
  / ``recover()`` book host-reported node state (GIGO on the host — a
  "healthy" row means the host said so, never wire truth).
* **Preference lists** — the first ``N`` nodes (by sorted node id, rotated
  by a key hash) are the preferred holders for a key. Deterministic across
  instances, no wall-clock.
* **w / write** — ``w()`` pins the write quorum size; ``write()`` books a
  versioned write to the first ``W`` healthy preference-list nodes, using
  sloppy fallback to other healthy nodes (booked as *hints*) when the
  preference list is short. Values are pinned by digest only — raw value
  bytes never enter a record or the audit boundary.
* **read** — ``read()`` books a version-reconciliation report over the
  first ``R`` reachable holders: the newest version wins, divergence is
  reported as data, and read-repair targets are listed for the host to
  execute (the ledger books the *decision*, never the repair itself).
* **hinted handoff** — ``deliver_hint()`` clears booked hints when the
  intended holder recovers.

House rules: frozen dataclasses, caller-supplied strictly-increasing int
seqs (failed mutations consume their seq), RLock guarding, fail-closed
taxonomy, stdlib-only (+ standard ``canonical_json`` try/except fallback),
type-tagged ``sha256:`` digest pins, ``audit.ndjson/1`` events.

Honest boundary: this books *declared* topology and *declared* writes —
it runs no network, stores no real bytes, and cannot prove a replica
actually persisted anything. A "written" record means "the host booked
W placements", never "W replicas hold the bytes". Versions are monotone
ledger counters, not vector clocks; cross-datacenter conflict resolution
is out of scope.
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional, Tuple

try:  # stdlib-first; canonical_json is the sibling JCS helper
    import canonical_json as _cj  # type: ignore
except Exception:  # pragma: no cover - fallback keeps stdlib-only promise
    _cj = None  # type: ignore

#: Module version pin for this module's record shape.
SLOPPY_QUORUM_VERSION = "sloppy-quorum.v1"

#: Schema pin carried by records and audit events.
SLOPPY_QUORUM_SCHEMA = "northstar.sloppy-quorum.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Digest prefix for all pins minted by this module.
_DIGEST_PREFIX = "sha256:"

#: Audit event kinds.
KIND_NODE_REGISTERED = "sloppy-quorum.node-registered"
KIND_NODE_FAILED = "sloppy-quorum.node-failed"
KIND_NODE_RECOVERED = "sloppy-quorum.node-recovered"
KIND_W_SET = "sloppy-quorum.w-set"
KIND_WRITTEN = "sloppy-quorum.written"
KIND_READ = "sloppy-quorum.read"
KIND_HINT_DELIVERED = "sloppy-quorum.hint-delivered"
KIND_REJECTED = "sloppy-quorum.rejected"
_KINDS = (
    KIND_NODE_REGISTERED,
    KIND_NODE_FAILED,
    KIND_NODE_RECOVERED,
    KIND_W_SET,
    KIND_WRITTEN,
    KIND_READ,
    KIND_HINT_DELIVERED,
    KIND_REJECTED,
)

#: Max magnitude kept exact by canonical JSON (|n| < 2**53).
_MAX_SAFE = 2 ** 53 - 1

_GENESIS = "genesis"


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class SloppyQuorumError(Exception):
    """Base error for the sloppy quorum ledger."""


class BadNodeError(SloppyQuorumError):
    """Malformed node id or membership input."""


class DuplicateNodeError(SloppyQuorumError):
    """Node id already registered."""


class UnknownNodeError(SloppyQuorumError):
    """No node with this id is registered."""


class BadKeyError(SloppyQuorumError):
    """Malformed key."""


class BadValueError(SloppyQuorumError):
    """Malformed value digest."""


class BadQuorumError(SloppyQuorumError):
    """Malformed quorum configuration."""


class UnknownKeyError(SloppyQuorumError):
    """No version of this key has ever been written."""


class InsufficientReplicasError(SloppyQuorumError):
    """Fewer than W healthy nodes are available for a write."""


class SeqOrderError(SloppyQuorumError):
    """Caller seq did not strictly increase."""


class AuditKindError(SloppyQuorumError):
    """Unknown audit event kind."""


# ---------------------------------------------------------------------------
# Canonical bytes + digest helpers
# ---------------------------------------------------------------------------


def _canonical(obj: Any) -> bytes:
    """Canonical bytes for an object (JCS when available)."""
    if _cj is not None:
        return _cj.jcs_canonical_json(obj)
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )


def _pin(payload: Any) -> str:
    """Type-tagged sha256 digest pin for a canonical payload."""
    return _DIGEST_PREFIX + hashlib.sha256(_canonical(payload)).hexdigest()


def _check_id(value: Any, what: str, error: type = BadNodeError) -> str:
    """Validate a non-empty string id, raising the module's error class."""
    if not isinstance(value, str) or isinstance(value, bool) or not value.strip():
        raise error(f"bad {what}")
    if len(value) > 256:
        raise error(f"bad {what}")
    return value


def _check_digest(value: Any) -> str:
    if not isinstance(value, str) or isinstance(value, bool):
        raise BadValueError("value_digest must be a sha256: pin")
    if not value.startswith(_DIGEST_PREFIX):
        raise BadValueError("value_digest must be a sha256: pin")
    body = value[len(_DIGEST_PREFIX):]
    if len(body) != 64 or any(c not in "0123456789abcdef" for c in body):
        raise BadValueError("value_digest must be sha256: + 64 lowercase hex")
    return value


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class NodeRecord:
    """Booked registration/state change of a storage node."""

    node_id: str
    status: str  # "healthy" | "failed"
    seq: int
    digest: str

    def verify(self) -> bool:
        """Recompute the digest pin and compare (constant-time)."""
        import hmac

        expect = _pin(("node", self.node_id, self.status, self.seq))
        return hmac.compare_digest(expect, self.digest)


@dataclass(frozen=True)
class ConfigRecord:
    """Booked write-quorum configuration (``w()``)."""

    quorum: int
    seq: int
    digest: str

    def verify(self) -> bool:
        """Recompute the digest pin and compare (constant-time)."""
        import hmac

        expect = _pin(("w-config", self.quorum, self.seq))
        return hmac.compare_digest(expect, self.digest)


@dataclass(frozen=True)
class Placement:
    """One booked replica placement for a write (holder, hinted?)."""

    node_id: str
    hinted: bool  # True = sloppy fallback, booked as a hint for the owner


@dataclass(frozen=True)
class WriteRecord:
    """Booked versioned write: digest pinned, placements listed."""

    key: str
    value_digest: str
    version: int
    placements: Tuple[Placement, ...]
    seq: int
    digest: str

    def verify(self) -> bool:
        """Recompute the digest pin and compare (constant-time)."""
        import hmac

        payload = (
            "write",
            self.key,
            self.value_digest,
            self.version,
            tuple((p.node_id, p.hinted) for p in self.placements),
            self.seq,
        )
        return hmac.compare_digest(_pin(payload), self.digest)


@dataclass(frozen=True)
class ReadReport:
    """Booked version-reconciliation read report."""

    key: str
    found: bool
    value_digest: str
    version: int
    sources: Tuple[str, ...]
    divergent: int
    quorum_met: bool
    seq: int
    digest: str

    def verify(self) -> bool:
        """Recompute the digest pin and compare (constant-time)."""
        import hmac

        payload = (
            "read",
            self.key,
            self.found,
            self.value_digest,
            self.version,
            self.sources,
            self.divergent,
            self.quorum_met,
            self.seq,
        )
        return hmac.compare_digest(_pin(payload), self.digest)


@dataclass(frozen=True)
class HintRecord:
    """Booked hinted-handoff entry: holder node keeps this for owner."""

    owner_id: str
    holder_id: str
    key: str
    version: int
    seq: int
    digest: str

    def verify(self) -> bool:
        """Recompute the digest pin and compare (constant-time)."""
        import hmac

        payload = ("hint", self.owner_id, self.holder_id, self.key, self.version, self.seq)
        return hmac.compare_digest(_pin(payload), self.digest)


@dataclass(frozen=True)
class HintDeliveryRecord:
    """Booked completion of a hinted handoff."""

    owner_id: str
    holder_id: str
    key: str
    seq: int
    digest: str

    def verify(self) -> bool:
        """Recompute the digest pin and compare (constant-time)."""
        import hmac

        payload = ("hint-delivered", self.owner_id, self.holder_id, self.key, self.seq)
        return hmac.compare_digest(_pin(payload), self.digest)


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------


def sloppy_quorum_audit_event(kind: str, seq: int, **fields: Any) -> Mapping[str, Any]:
    """Build an ``audit.ndjson/1`` event for this module.

    Raw value bytes are banned from the audit boundary: only digest pins,
    ids, counts, and quorum config cross it.
    """
    if kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    if not isinstance(seq, int) or isinstance(seq, bool) or seq <= 0:
        raise SeqOrderError("audit seq must be a positive int")
    banned = {"value", "value_bytes", "payload", "body", "data"}
    for key in fields:
        if key in banned:
            raise AuditKindError(f"key {key!r} is banned from the audit boundary")
    event: Dict[str, Any] = {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "seq": seq,
        "module": SLOPPY_QUORUM_VERSION,
    }
    event.update(fields)
    return event


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class SloppyQuorum:
    """Deterministic Dynamo-style quorum read/write ledger.

    ``N`` = preference-list size, ``W`` = write quorum, ``R`` = read quorum.
    Caller-supplied seqs must strictly increase; failed mutations consume
    their seq (batch discipline).
    """

    def __init__(self, n: int = 3, w: int = 2, r: int = 2) -> None:
        for name, value in (("n", n), ("w", w), ("r", r)):
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise BadQuorumError(f"{name} must be a positive int")
        if w > n or r > n:
            raise BadQuorumError("w and r must not exceed n")
        self._n = n
        self._w = w
        self._r = r
        self._lock = threading.RLock()
        self._seq = 0
        self._nodes: Dict[str, str] = {}  # node_id -> "healthy" | "failed"
        self._keys: Dict[str, Dict[str, Any]] = {}  # key -> per-version state
        self._hints: Dict[Tuple[str, str, str], HintRecord] = {}  # (owner, holder, key)
        self._audit: Tuple[Mapping[str, Any], ...] = ()

    # -- internal ---------------------------------------------------------

    def _claim(self, seq: int) -> None:
        if not isinstance(seq, int) or isinstance(seq, bool):
            raise SeqOrderError("seq must be an int")
        if seq <= self._seq:
            raise SeqOrderError("seq must strictly increase")
        self._seq = seq

    def _emit(self, kind: str, seq: int, **fields: Any) -> None:
        self._audit = self._audit + (sloppy_quorum_audit_event(kind, seq, **fields),)

    def _guarded(self, seq: int, fn: Any, *args: Any, **kwargs: Any) -> Any:
        self._claim(seq)
        try:
            return fn(*args, **kwargs)
        except SloppyQuorumError as exc:
            self._emit(KIND_REJECTED, seq, error=type(exc).__name__)
            raise

    def _healthy(self) -> Tuple[str, ...]:
        return tuple(sorted(n for n, s in self._nodes.items() if s == "healthy"))

    def preference_list(self, key: str) -> Tuple[str, ...]:
        """Deterministic preference list: first N nodes rotated by key hash."""
        nodes = sorted(self._nodes)
        if not nodes:
            return ()
        start = int(hashlib.sha256(key.encode("utf-8")).hexdigest(), 16) % len(nodes)
        rotated = nodes[start:] + nodes[:start]
        return tuple(rotated[: self._n])

    # -- membership --------------------------------------------------------

    def node(self, node_id: str, seq: int) -> NodeRecord:
        """Register a storage node (starts healthy)."""
        def _do() -> NodeRecord:
            nid = _check_id(node_id, "node_id")
            if nid in self._nodes:
                raise DuplicateNodeError(f"node already registered: {nid}")
            self._nodes[nid] = "healthy"
            rec = NodeRecord(
                node_id=nid, status="healthy", seq=seq,
                digest=_pin(("node", nid, "healthy", seq)),
            )
            self._emit(KIND_NODE_REGISTERED, seq, node_id=nid)
            return rec

        with self._lock:
            return self._guarded(seq, _do)

    def fail(self, node_id: str, seq: int) -> NodeRecord:
        """Book a host-reported node failure."""
        def _do() -> NodeRecord:
            nid = _check_id(node_id, "node_id")
            if nid not in self._nodes:
                raise UnknownNodeError(f"unknown node: {nid}")
            self._nodes[nid] = "failed"
            rec = NodeRecord(
                node_id=nid, status="failed", seq=seq,
                digest=_pin(("node", nid, "failed", seq)),
            )
            self._emit(KIND_NODE_FAILED, seq, node_id=nid)
            return rec

        with self._lock:
            return self._guarded(seq, _do)

    def recover(self, node_id: str, seq: int) -> NodeRecord:
        """Book a host-reported node recovery."""
        def _do() -> NodeRecord:
            nid = _check_id(node_id, "node_id")
            if nid not in self._nodes:
                raise UnknownNodeError(f"unknown node: {nid}")
            self._nodes[nid] = "healthy"
            rec = NodeRecord(
                node_id=nid, status="healthy", seq=seq,
                digest=_pin(("node", nid, "healthy", seq)),
            )
            self._emit(KIND_NODE_RECOVERED, seq, node_id=nid)
            return rec

        with self._lock:
            return self._guarded(seq, _do)

    # -- configuration -----------------------------------------------------

    def w(self, quorum: int, seq: int) -> ConfigRecord:
        """Pin the write quorum size W (1 <= W <= N)."""
        def _do() -> ConfigRecord:
            if not isinstance(quorum, int) or isinstance(quorum, bool):
                raise BadQuorumError("w must be an int")
            if not 1 <= quorum <= self._n:
                raise BadQuorumError("w must satisfy 1 <= w <= n")
            self._w = quorum
            rec = ConfigRecord(
                quorum=quorum, seq=seq, digest=_pin(("w-config", quorum, seq))
            )
            self._emit(KIND_W_SET, seq, w=quorum)
            return rec

        with self._lock:
            return self._guarded(seq, _do)

    # -- writes ------------------------------------------------------------

    def write(self, key: str, value_digest: str, seq: int) -> WriteRecord:
        """Book a versioned write.

        Writes to the first W healthy preference-list nodes; when the
        preference list is short on healthy nodes, sloppy fallback uses
        other healthy nodes and books each as a hinted handoff for the
        intended owner. Raises :class:`InsufficientReplicasError` (fail-closed,
        seq consumed) when fewer than W healthy nodes exist cluster-wide.
        """
        def _do() -> WriteRecord:
            k = _check_id(key, "key", BadKeyError)
            vd = _check_digest(value_digest)
            pref = self.preference_list(k)
            if not pref:
                raise InsufficientReplicasError("no nodes registered")
            healthy = set(self._healthy())
            pref_healthy = [n for n in pref if n in healthy]
            targets: Tuple[str, ...] = tuple(pref_healthy[: self._w])
            hinted: Tuple[bool, ...] = tuple(False for _ in targets)
            if len(targets) < self._w:
                # Sloppy fallback: other healthy nodes, booked as hints.
                owners = [n for n in pref if n not in healthy]
                extras = [n for n in self._healthy() if n not in pref and n not in targets]
                need = self._w - len(targets)
                sloppy = extras[:need]
                for i, holder in enumerate(sloppy):
                    owner = owners[i % len(owners)] if owners else pref[0]
                    hint = HintRecord(
                        owner_id=owner, holder_id=holder, key=k,
                        version=self._keys.get(k, {}).get("version", 0) + 1,
                        seq=seq,
                        digest=_pin(("hint", owner, holder, k,
                                    self._keys.get(k, {}).get("version", 0) + 1, seq)),
                    )
                    self._hints[(owner, holder, k)] = hint
                targets = targets + tuple(sloppy)
                hinted = hinted + tuple(True for _ in sloppy)
            if len(targets) < self._w:
                raise InsufficientReplicasError(
                    f"only {len(targets)} healthy nodes, need w={self._w}"
                )
            state = self._keys.setdefault(
                k, {"version": 0, "holders": {}, "digest": None}
            )
            state["version"] = state["version"] + 1
            version = state["version"]
            holders: Dict[str, int] = state["holders"]
            for i, node in enumerate(targets):
                # Direct holders store the version; sloppy holders' versions
                # ride with the hint until delivered.
                if not hinted[i]:
                    holders[node] = version
            state["digest"] = vd
            placements = tuple(
                Placement(node_id=node, hinted=flag)
                for node, flag in zip(targets, hinted)
            )
            rec = WriteRecord(
                key=k, value_digest=vd, version=version, placements=placements,
                seq=seq,
                digest=_pin((
                    "write", k, vd, version,
                    tuple((p.node_id, p.hinted) for p in placements), seq,
                )),
            )
            self._emit(
                KIND_WRITTEN, seq, key=k, version=version,
                targets=[p.node_id for p in placements],
                hinted=sum(1 for p in placements if p.hinted),
                value_digest=vd,
            )
            return rec

        with self._lock:
            return self._guarded(seq, _do)

    # -- reads -------------------------------------------------------------

    def read(self, key: str, seq: int) -> ReadReport:
        """Book a version-reconciliation read over the first R holders.

        Unknown keys are *data* (``found=False``), never raised. Divergence
        is reported as data; the newest version wins.
        """
        def _do() -> ReadReport:
            k = _check_id(key, "key", BadKeyError)
            state = self._keys.get(k)
            if state is None:
                rep = ReadReport(
                    key=k, found=False, value_digest=_DIGEST_PREFIX + "0" * 64,
                    version=0, sources=(), divergent=0, quorum_met=False,
                    seq=seq,
                    digest=_pin(("read", k, False, _DIGEST_PREFIX + "0" * 64,
                                 0, (), 0, False, seq)),
                )
                self._emit(KIND_READ, seq, key=k, found=False)
                return rep
            holders: Dict[str, int] = state["holders"]
            alive_holders = sorted(n for n in holders if self._nodes.get(n) == "healthy")
            # Hinted copies count as reachable holders for reconciliation.
            hint_holders = sorted(
                holder for (owner, holder, hk) in self._hints if hk == k
            )
            reachable = sorted(set(alive_holders) | set(hint_holders))
            sources = tuple(reachable[: self._r])
            versions = []
            for n in sources:
                if n in holders:
                    versions.append(holders[n])
                else:
                    # Reachable only via a hinted handoff: the hint carries
                    # the newest written version.
                    versions.append(state["version"])
            newest = max(versions) if versions else 0
            divergent = sum(1 for v in versions if v != newest)
            quorum_met = len(sources) >= self._r
            rep = ReadReport(
                key=k, found=True, value_digest=state["digest"],
                version=newest, sources=sources, divergent=divergent,
                quorum_met=quorum_met, seq=seq,
                digest=_pin(("read", k, True, state["digest"], newest,
                             sources, divergent, quorum_met, seq)),
            )
            self._emit(
                KIND_READ, seq, key=k, found=True, version=newest,
                sources=list(sources), divergent=divergent,
                quorum_met=quorum_met,
            )
            return rep

        with self._lock:
            return self._guarded(seq, _do)

    # -- hinted handoff ----------------------------------------------------

    def deliver_hint(self, owner_id: str, holder_id: str, key: str, seq: int) -> HintDeliveryRecord:
        """Book completion of a hinted handoff to the recovered owner."""
        def _do() -> HintDeliveryRecord:
            owner = _check_id(owner_id, "owner_id")
            holder = _check_id(holder_id, "holder_id")
            k = _check_id(key, "key", BadKeyError)
            hint = self._hints.pop((owner, holder, k), None)
            if hint is None:
                raise UnknownKeyError("no such hint booked")
            state = self._keys.get(k)
            if state is not None:
                state["holders"][owner] = hint.version  # read-repair target set
            rec = HintDeliveryRecord(
                owner_id=owner, holder_id=holder, key=k, seq=seq,
                digest=_pin(("hint-delivered", owner, holder, k, seq)),
            )
            self._emit(KIND_HINT_DELIVERED, seq, owner_id=owner,
                       holder_id=holder, key=k)
            return rec

        with self._lock:
            return self._guarded(seq, _do)

    # -- views (pure reads: seq validated, never consumed) -----------------

    def _view_seq(self, seq: int) -> None:
        if not isinstance(seq, int) or isinstance(seq, bool) or seq <= 0:
            raise SeqOrderError("view seq must be a positive int")

    def node_ids(self, seq: int) -> Tuple[str, ...]:
        """Sorted registered node ids (pure read)."""
        self._view_seq(seq)
        with self._lock:
            return tuple(sorted(self._nodes))

    def node_status(self, node_id: str, seq: int) -> str:
        """Host-reported status of a node (pure read)."""
        self._view_seq(seq)
        with self._lock:
            nid = _check_id(node_id, "node_id")
            if nid not in self._nodes:
                raise UnknownNodeError(f"unknown node: {nid}")
            return self._nodes[nid]

    def quorum_config(self, seq: int) -> Mapping[str, int]:
        """Current (n, w, r) configuration (pure read)."""
        self._view_seq(seq)
        with self._lock:
            return {"n": self._n, "w": self._w, "r": self._r}

    def hints_for(self, owner_id: str, seq: int) -> Tuple[HintRecord, ...]:
        """Pending hints booked for an owner (pure read)."""
        self._view_seq(seq)
        with self._lock:
            owner = _check_id(owner_id, "owner_id")
            return tuple(
                h for (o, _h, _k), h in sorted(self._hints.items()) if o == owner
            )

    def stats(self, seq: int) -> Mapping[str, int]:
        """Ledger counters (pure read)."""
        self._view_seq(seq)
        with self._lock:
            return {
                "nodes": len(self._nodes),
                "healthy": len(self._healthy()),
                "keys": len(self._keys),
                "hints": len(self._hints),
                "audit_rows": len(self._audit),
                "last_seq": self._seq,
            }

    def audit_log(self) -> Tuple[Mapping[str, Any], ...]:
        """Booked audit events (pure read)."""
        with self._lock:
            return self._audit

    def as_dict(self) -> Mapping[str, Any]:
        """JSON-safe snapshot of the ledger (pure read)."""
        with self._lock:
            return {
                "version": SLOPPY_QUORUM_VERSION,
                "schema": SLOPPY_QUORUM_SCHEMA,
                "n": self._n,
                "w": self._w,
                "r": self._r,
                "nodes": dict(self._nodes),
                "keys": {k: v["version"] for k, v in self._keys.items()},
                "hints": len(self._hints),
                "last_seq": self._seq,
            }


# ---------------------------------------------------------------------------
# Self-check
# ---------------------------------------------------------------------------


def main() -> None:
    """Deterministic self-check: quorum write/read with a sloppy fallback."""
    digest = _DIGEST_PREFIX + hashlib.sha256(b"value-1").hexdigest()
    sq = SloppyQuorum(n=3, w=2, r=2)
    sq.node("n1", seq=1)
    sq.node("n2", seq=2)
    sq.node("n3", seq=3)
    sq.node("n4", seq=4)
    rec = sq.write("k", digest, seq=5)
    assert rec.verify() and rec.version == 1
    assert len(rec.placements) == 2
    rep = sq.read("k", seq=6)
    assert rep.verify() and rep.found and rep.value_digest == digest
    assert rep.quorum_met and rep.divergent == 0
    # Fail two preference-list nodes; the next write cannot reach W=2 from
    # the preference list alone, so it must go sloppy.
    pref = sq.preference_list("k2")
    sq.fail(pref[0], seq=7)
    sq.fail(pref[1], seq=8)
    rec2 = sq.write("k2", digest, seq=9)
    assert rec2.verify()
    assert any(p.hinted for p in rec2.placements)
    sq.recover(pref[0], seq=10)
    hint = next(h for h in sq.audit_log() if h["kind"] == KIND_WRITTEN and h["key"] == "k2")
    assert hint["hinted"] >= 1
    cfg = sq.w(3, seq=11)
    assert cfg.verify() and cfg.quorum == 3
    print("sloppy-quorum OK: node, w, write, read, sloppy-hint, audit")


if __name__ == "__main__":
    main()
