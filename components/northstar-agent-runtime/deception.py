"""Deception: honeypot deception-operations ledger, Simulated.

Research note: honeypots (fake services, honey-tokens, decoy documents,
darknet sensors, honey accounts) are the classic defender-side use of
deception: controlled, instrumented assets that no legitimate user should
touch, so any interaction is evidence of hostile reconnaissance. A
reported "engagement" is never proof of attacker intent - the host
declares interactions and the ledger books them as data.

This module is the *deception-operations* ledger, deliberately distinct
from its sibling:

- ``deception_detector.py`` - analyzes a (claim, evidence) pair for
  deceptive reasoning (false-claim / evidence-concealment /
  source-fabrication). It reasons about text; it deploys nothing.

This module owns the honeypot lifecycle instead:

* **deploy()** - declare one honeypot asset deployed (pinned kind
  vocabulary, digest-pinned configuration; raw configs never enter
  records).
* **lure()** - book one declared attacker interaction against a decoy
  (pinned interaction vocabulary; actors travel as digest pins only).
* **analyze()** - pure read view: interaction tallies per kind and an
  engagement verdict as data.
* **retire()** - terminal; decoy ids are never recycled (a burned decoy
  stays burned in the ledger).

House style: frozen dataclasses, caller-supplied strictly-increasing int
seqs (claim-then-burn: failed mutations consume their seq and book a
``deception.rejected`` row; rewinds raise bare without consuming), no
wall-clock, RLock guarding, fail-closed taxonomy, stdlib-only with the
standard ``canonical_json`` try/except fallback, ``sha256:`` digest pins,
and ``audit.ndjson/1`` events.

Honest scope: this module runs no services, lures nobody, and inspects no
packets. All interactions are host-declared GIGO booked under digest pins;
a booked ``engaged`` means "the host declared interactions", never "an
attacker was caught". Raw configurations, actor identifiers, and payload
material never cross the module boundary.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

try:
    from canonical_json import jcs_dumps as _jcs_dumps, jcs_sha256_hex as _jcs_hash  # type: ignore
except Exception:  # pragma: no cover - fallback when canonical_json is absent

    def _jcs_dumps(obj: Any) -> bytes:  # type: ignore
        import json

        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def _jcs_hash(obj: Any) -> str:  # type: ignore
        return "sha256:" + hashlib.sha256(_jcs_dumps(obj)).hexdigest()


#: Module version pin.
DECEPTION_VERSION = "deception.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.deception.v1"

#: Pinned honeypot-asset vocabulary (declared, never actually run).
KINDS = (
    "fake-service",
    "honey-token",
    "decoy-document",
    "darknet",
    "honey-account",
    "decoy-api",
)

#: Pinned interaction vocabulary for booked engagements.
INTERACTION_KINDS = (
    "probe",
    "brute-force",
    "scan",
    "payload",
    "lateral",
    "exfiltrate-attempt",
)

#: Pinned retirement-reason vocabulary.
RETIRE_REASONS = ("manual", "burned", "completed", "superseded")

#: Audit kinds emitted by this module.
AUDIT_KINDS = (
    "deployed",
    "interaction-recorded",
    "retired",
    "rejected",
)

#: Keys that may never appear raw in an audit row.
_BANNED_AUDIT_KEYS = frozenset(
    {
        "config",
        "configuration",
        "actor",
        "actor_id",
        "actor_ip",
        "payload",
        "payload_bytes",
        "content",
        "document",
        "token",
        "secret",
        "credentials",
        "password",
        "raw",
        "text",
        "data",
        "value",
        "packets",
        "key",
        "private_key",
    }
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class DeceptionError(Exception):
    """Base error for deception-ledger misuse."""


class BadDecoyError(DeceptionError):
    """Malformed decoy id."""


class DuplicateDecoyError(DeceptionError):
    """Decoy id already deployed."""


class RetiredDecoyError(DeceptionError):
    """Decoy id retired; never recycled."""


class UnknownDecoyError(DeceptionError):
    """Decoy id not deployed."""


class BadKindError(DeceptionError):
    """Unknown decoy or interaction kind."""


class BadDigestError(DeceptionError):
    """Malformed sha256: digest pin."""


class BadReasonError(DeceptionError):
    """Unknown retirement reason."""


class UnknownInteractionError(DeceptionError):
    """Interaction id not booked."""


class SeqOrderError(DeceptionError):
    """Seq is not a strictly increasing positive int."""


class AuditKindError(DeceptionError):
    """Unknown audit kind, or banned raw key in audit details."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _require_id(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise BadDecoyError(f"{field_name} must be a non-empty str <= 128 chars")
    return value


def _require_digest(pin: str, field_name: str) -> str:
    if not isinstance(pin, str) or not pin.startswith("sha256:"):
        raise BadDigestError(f"{field_name} must be a 'sha256:' pin")
    hexpart = pin[7:]
    if len(hexpart) != 64 or any(c not in "0123456789abcdef" for c in hexpart):
        raise BadDigestError(f"{field_name} must be a 64-hex sha256 pin")
    return pin


def _digest_pin(payload: Dict[str, Any]) -> str:
    raw = _jcs_hash(payload)
    hexpart = raw[7:] if raw.startswith("sha256:") else raw
    return "sha256:" + hexpart


# ---------------------------------------------------------------------------
# Records (all frozen)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DeploymentRecord:
    decoy_id: str
    kind: str
    config_digest: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "decoy_id": self.decoy_id,
            "kind": self.kind,
            "config_digest": self.config_digest,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "decoy_id": self.decoy_id,
                "kind": self.kind,
                "config_digest": self.config_digest,
            }
        )


@dataclass(frozen=True)
class InteractionRecord:
    interaction_id: str
    decoy_id: str
    actor_digest: str
    interaction_kind: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "interaction_id": self.interaction_id,
            "decoy_id": self.decoy_id,
            "actor_digest": self.actor_digest,
            "interaction_kind": self.interaction_kind,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "interaction_id": self.interaction_id,
                "decoy_id": self.decoy_id,
                "actor_digest": self.actor_digest,
                "interaction_kind": self.interaction_kind,
            }
        )


@dataclass(frozen=True)
class RetireRecord:
    decoy_id: str
    reason: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "decoy_id": self.decoy_id,
            "reason": self.reason,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "decoy_id": self.decoy_id,
                "reason": self.reason,
            }
        )


@dataclass(frozen=True)
class AnalysisReport:
    decoy_id: str
    n_interactions: int
    interaction_tally: Tuple[Tuple[str, str], ...]
    n_actors: int
    engaged: bool
    integrity_ok: bool
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "decoy_id": self.decoy_id,
            "n_interactions": self.n_interactions,
            "interaction_tally": [
                {"interaction_kind": k, "count": c}
                for k, c in self.interaction_tally
            ],
            "n_actors": self.n_actors,
            "engaged": self.engaged,
            "integrity_ok": self.integrity_ok,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "decoy_id": self.decoy_id,
                "n_interactions": self.n_interactions,
                "interaction_tally": [
                    {"interaction_kind": k, "count": c}
                    for k, c in self.interaction_tally
                ],
                "n_actors": self.n_actors,
                "engaged": self.engaged,
                "integrity_ok": self.integrity_ok,
            }
        )


# ---------------------------------------------------------------------------
# Audit event builder
# ---------------------------------------------------------------------------


def deception_audit_event(
    audit_kind: str, seq: int, **details: Any
) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` event row for the deception ledger."""
    if audit_kind not in AUDIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {audit_kind!r}")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise SeqOrderError("audit seq must be a non-negative int")
    for key in details:
        if key in _BANNED_AUDIT_KEYS:
            raise AuditKindError(f"banned raw key in audit detail: {key!r}")
    return {
        "schema": "audit.ndjson/1",
        "kind": audit_kind,
        "seq": seq,
        "details": dict(details),
    }


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class Deception:
    """Honeypot deception-operations ledger (Simulated).

    ``deploy()`` / ``lure()`` / ``retire()`` mutate the ledger and consume
    caller seqs; ``analyze()`` and all views are pure reads.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._deployments: Dict[str, DeploymentRecord] = {}
        self._interactions: Dict[str, InteractionRecord] = {}
        self._decoy_interactions: Dict[str, List[str]] = {}
        self._retirements: Dict[str, RetireRecord] = {}
        self._retired: set = set()
        self._audit: List[Dict[str, Any]] = []
        self._seq = 0
        self._int_counter = 0

    # -- seq discipline ----------------------------------------------------

    def _check_seq(self, seq: int) -> int:
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise SeqOrderError("seq must be an int")
        if seq <= self._seq:
            raise SeqOrderError("seq must strictly increase")
        return seq

    def _claim(self, seq: int) -> int:
        self._check_seq(seq)
        self._seq = seq
        return seq

    def _burn(self, seq: int, kind: str, **details: Any) -> None:
        self._seq = seq
        try:
            row = deception_audit_event("rejected", seq,
                                        rejected_kind=kind, **details)
        except (AuditKindError, SeqOrderError):
            row = {
                "schema": "audit.ndjson/1",
                "kind": "rejected",
                "seq": seq,
                "details": {"rejected_kind": kind},
            }
        self._audit.append(row)

    def _emit(self, audit_kind: str, seq: int, **details: Any) -> None:
        self._audit.append(deception_audit_event(audit_kind, seq, **details))

    def _live_decoy(self, decoy_id: str) -> None:
        """Fail-closed: id must be deployed and not retired."""
        if decoy_id in self._retired:
            raise RetiredDecoyError(
                f"decoy id retired, never recycled: {decoy_id!r}")
        if decoy_id not in self._deployments:
            raise UnknownDecoyError(f"unknown decoy: {decoy_id!r}")

    # -- deploy --------------------------------------------------------------

    def deploy(
        self, decoy_id: str, kind: str, seq: int, config_digest: str = ""
    ) -> DeploymentRecord:
        """Declare one honeypot asset deployed.

        ``kind`` is pinned; configuration travels as a ``sha256:`` digest
        pin only - raw configs never enter records.
        """
        with self._lock:
            try:
                self._claim(seq)
            except DeceptionError:
                raise
            try:
                _require_id(decoy_id, "decoy_id")
                if kind not in KINDS:
                    raise BadKindError(f"kind must be one of {KINDS}")
                if config_digest:
                    _require_digest(config_digest, "config_digest")
                else:
                    config_digest = "sha256:" + "00" * 32
                if decoy_id in self._retired:
                    raise RetiredDecoyError(
                        f"decoy id retired, never recycled: {decoy_id!r}")
                if decoy_id in self._deployments:
                    raise DuplicateDecoyError(
                        f"decoy already deployed: {decoy_id!r}")
                digest = _digest_pin(
                    {"schema": SCHEMA_PIN, "decoy_id": decoy_id,
                     "kind": kind, "config_digest": config_digest}
                )
                record = DeploymentRecord(
                    decoy_id=decoy_id, kind=kind,
                    config_digest=config_digest, digest=digest,
                )
                self._deployments[decoy_id] = record
                self._decoy_interactions[decoy_id] = []
                self._emit("deployed", seq, decoy_id=decoy_id, kind=kind)
                return record
            except DeceptionError:
                self._burn(seq, "deploy")
                raise

    # -- lure ----------------------------------------------------------------

    def lure(
        self,
        decoy_id: str,
        actor_digest: str,
        seq: int,
        interaction_kind: str = "probe",
    ) -> InteractionRecord:
        """Book one declared attacker interaction against a decoy.

        The actor travels as a ``sha256:`` digest pin only - raw actor
        identifiers never enter records. The interaction is booked as data,
        never proof of attacker intent.
        """
        with self._lock:
            try:
                self._claim(seq)
            except DeceptionError:
                raise
            try:
                self._live_decoy(decoy_id)
                _require_digest(actor_digest, "actor_digest")
                if interaction_kind not in INTERACTION_KINDS:
                    raise BadKindError(
                        f"interaction_kind must be one of {INTERACTION_KINDS}")
                self._int_counter += 1
                interaction_id = f"int-{self._int_counter}"
                digest = _digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "interaction_id": interaction_id,
                        "decoy_id": decoy_id,
                        "actor_digest": actor_digest,
                        "interaction_kind": interaction_kind,
                    }
                )
                record = InteractionRecord(
                    interaction_id=interaction_id,
                    decoy_id=decoy_id,
                    actor_digest=actor_digest,
                    interaction_kind=interaction_kind,
                    digest=digest,
                )
                self._interactions[interaction_id] = record
                self._decoy_interactions[decoy_id].append(interaction_id)
                self._emit(
                    "interaction-recorded", seq,
                    interaction_id=interaction_id, decoy_id=decoy_id,
                    interaction_kind=interaction_kind,
                )
                return record
            except DeceptionError:
                self._burn(seq, "lure")
                raise

    # -- analyze (pure read) -------------------------------------------------

    def analyze(self, decoy_id: str, seq: int) -> AnalysisReport:
        """Pure read: interaction tallies and engagement verdict as data."""
        with self._lock:
            if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
                raise SeqOrderError("analyze seq must be a non-negative int")
            record = self._deployments.get(decoy_id)
            if record is None:
                raise UnknownDecoyError(f"unknown decoy: {decoy_id!r}")
            integrity_ok = record.verify()
            ids = self._decoy_interactions.get(decoy_id, [])
            interactions = [self._interactions[i] for i in ids]
            for interaction in interactions:
                if not interaction.verify():
                    integrity_ok = False
            tally: Dict[str, int] = {}
            actors: set = set()
            for interaction in interactions:
                tally[interaction.interaction_kind] = (
                    tally.get(interaction.interaction_kind, 0) + 1)
                actors.add(interaction.actor_digest)
            tally_tuple = tuple(sorted(
                (k, str(tally[k])) for k in tally))
            engaged = len(interactions) > 0
            digest = _digest_pin(
                {
                    "schema": SCHEMA_PIN,
                    "decoy_id": decoy_id,
                    "n_interactions": len(interactions),
                    "interaction_tally": [
                        {"interaction_kind": k, "count": c}
                        for k, c in tally_tuple
                    ],
                    "n_actors": len(actors),
                    "engaged": engaged,
                    "integrity_ok": integrity_ok,
                }
            )
            return AnalysisReport(
                decoy_id=decoy_id,
                n_interactions=len(interactions),
                interaction_tally=tally_tuple,
                n_actors=len(actors),
                engaged=engaged,
                integrity_ok=integrity_ok,
                digest=digest,
            )

    # -- retire --------------------------------------------------------------

    def retire(self, decoy_id: str, seq: int, reason: str = "manual"
               ) -> RetireRecord:
        """Terminal: retire a decoy. The id is never recycled."""
        with self._lock:
            try:
                self._claim(seq)
            except DeceptionError:
                raise
            try:
                self._live_decoy(decoy_id)
                if reason not in RETIRE_REASONS:
                    raise BadReasonError(
                        f"reason must be one of {RETIRE_REASONS}")
                digest = _digest_pin(
                    {"schema": SCHEMA_PIN, "decoy_id": decoy_id,
                     "reason": reason}
                )
                record = RetireRecord(
                    decoy_id=decoy_id, reason=reason, digest=digest)
                self._retirements[decoy_id] = record
                self._retired.add(decoy_id)
                self._emit("retired", seq, decoy_id=decoy_id, reason=reason)
                return record
            except DeceptionError:
                self._burn(seq, "retire")
                raise

    # -- pure-read views -------------------------------------------------------

    def _view_seq_ok(self, seq: int) -> None:
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
            raise SeqOrderError("view seq must be a non-negative int")

    def deployment_record(self, decoy_id: str, seq: int) -> DeploymentRecord:
        with self._lock:
            self._view_seq_ok(seq)
            record = self._deployments.get(decoy_id)
            if record is None:
                raise UnknownDecoyError(f"unknown decoy: {decoy_id!r}")
            return record

    def interaction_record(self, interaction_id: str, seq: int
                           ) -> InteractionRecord:
        with self._lock:
            self._view_seq_ok(seq)
            record = self._interactions.get(interaction_id)
            if record is None:
                raise UnknownInteractionError(
                    f"unknown interaction: {interaction_id!r}")
            return record

    def decoy_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._view_seq_ok(seq)
            return tuple(sorted(self._deployments))

    def interaction_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._view_seq_ok(seq)
            return tuple(sorted(self._interactions))

    def interactions_for(self, decoy_id: str, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._view_seq_ok(seq)
            if decoy_id not in self._deployments:
                raise UnknownDecoyError(f"unknown decoy: {decoy_id!r}")
            return tuple(self._decoy_interactions.get(decoy_id, ()))

    def retired_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._view_seq_ok(seq)
            return tuple(sorted(self._retired))

    def stats(self, seq: int) -> Dict[str, int]:
        with self._lock:
            self._view_seq_ok(seq)
            return {
                "decoys": len(self._deployments),
                "interactions": len(self._interactions),
                "retired": len(self._retired),
                "audit_rows": len(self._audit),
            }

    def audit_log(self, seq: int) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            self._view_seq_ok(seq)
            return tuple(self._audit)


def main() -> None:
    d = Deception()
    dep = d.deploy("decoy-1", "fake-service", 1)
    assert dep.verify()
    i1 = d.lure("decoy-1", "sha256:" + "ab" * 32, 2, interaction_kind="scan")
    i2 = d.lure("decoy-1", "sha256:" + "cd" * 32, 3,
                interaction_kind="brute-force")
    assert i1.verify() and i2.verify()
    report = d.analyze("decoy-1", 0)
    assert report.verify()
    assert report.engaged and report.n_interactions == 2
    assert report.n_actors == 2
    r = d.retire("decoy-1", 4, reason="burned")
    assert r.verify()
    print("deception OK: deploy, lure, analyze, retire, pins, audit")


if __name__ == "__main__":
    main()
