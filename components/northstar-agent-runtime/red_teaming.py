"""Red teaming (attack/probe/report) interface, simulated.

Research motivation: adversarial testing is the defensive twin of
capability work -- Anthropic's red-team programs, OpenAI's
preparedness evaluations, and the academic jailbreak literature (GCG,
prompt-injection suites, tool-call smuggling) all reduce to the same
operational shape: declare an attack scenario, probe a *simulated*
target with it, and book the verdict as data. Real red teaming runs
against live models with safety oversight; this module never touches
a live model.

This module is the *campaign ledger* half of that shape:

- ``RedTeaming.attack(attack_id, category, seq)`` -- declare one
  attack scenario. Returns a frozen ``AttackRecord`` with a
  ``sha256:`` digest pin. Attack definitions live off-ledger; the
  module pins a digest of the scenario, never its content.
- ``RedTeaming.probe(attack_id, probe_id, seq)`` -- book one probe
  attempt against a declared attack scenario. Returns a frozen
  ``ProbeRecord`` with a minted ``probe-N`` id and a host-reported
  outcome over the pinned verdict vocabulary.
- ``RedTeaming.report(attack_id, seq)`` -- aggregate one attack's
  probes into a frozen ``ReportRecord``: success counts, verdict
  distribution, and a verdict *as data* (``resilient`` / ``mixed`` /
  ``vulnerable``), never raised.
- ``red_teaming_audit_event(kind, ...)`` -- ``audit.ndjson/1``
  records (``attack-declared`` / ``probed`` / ``reported`` /
  ``rejected``); caller-supplied seqs only. Raw attack content and
  probe transcripts never cross the audit boundary -- audit rows
  carry ids, counts, digests, and verdicts only.

Fail-closed edges (fail loudly, never guess):

- ``attack_id`` / ``probe_id`` must be non-empty str, <= 256 chars,
  no whitespace.
- ``category`` must come from the pinned attack-category vocabulary.
- ``probe`` on an unknown attack raises ``UnknownAttackError``.
- ``outcome`` must come from the pinned probe-verdict vocabulary;
  ``success_rate`` evidence is host-reported data, never proof.
- Seqs are ints (not bool), >= 0, strictly increasing per instance.
  Failed mutations consume their seq and book a ``rejected`` audit
  row; seq rewinds raise bare ``SeqOrderError`` without consuming.

Honest scope:

- This module books *declared* attack scenarios and *host-reported*
  probe outcomes. A booked ``breached`` outcome means the host
  reported a breach -- the module ran no attack, touched no target,
  and proves nothing about any real system's robustness.
- The attack-category and verdict vocabularies are pinned so that
  campaigns are comparable and auditable; they are not claims about
  the real-world exploit landscape.
- A ``vulnerable`` verdict is a ledger summary of booked outcomes,
  never a finding of fact about a production system.
- No persistence: the ledger is in-memory. Pair with the durable
  audit writer if campaign state must survive a restart.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json, jcs_sha256_hex
except Exception:  # pragma: no cover - module must stay importable standalone
    import json as _json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("utf-8")

    def jcs_sha256_hex(obj: Any) -> str:  # type: ignore[no-redef]
        return hashlib.sha256(jcs_canonical_json(obj)).hexdigest()


#: Version pin for this module's record shape.
RED_TEAMING_VERSION = "red-teaming.v1"

#: Schema pin carried by records and audit events.
RED_TEAMING_SCHEMA = "northstar.red-teaming.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Audit event kinds.
KIND_ATTACK_DECLARED = "attack-declared"
KIND_PROBED = "probed"
KIND_REPORTED = "reported"
KIND_REJECTED = "rejected"
_KINDS = (KIND_ATTACK_DECLARED, KIND_PROBED, KIND_REPORTED, KIND_REJECTED)

#: Detail keys banned from the audit boundary (raw content never crosses it).
_BANNED_DETAIL_KEYS = frozenset(
    {"attack", "scenario", "transcript", "payload", "raw", "evidence",
     "prompt", "response"})

#: Max id length.
_MAX_ID_LEN = 256

#: Pinned attack-category vocabulary. Categories are bookkeeping labels,
#: not claims about the real-world exploit landscape.
CATEGORY_PROMPT_INJECTION = "prompt-injection"
CATEGORY_JAILBREAK = "jailbreak"
CATEGORY_TOOL_ABUSE = "tool-abuse"
CATEGORY_DATA_EXFILTRATION = "data-exfiltration"
CATEGORY_PRIVILEGE_ESCALATION = "privilege-escalation"
CATEGORY_MULTI_TURN = "multi-turn"
CATEGORIES = (
    CATEGORY_PROMPT_INJECTION,
    CATEGORY_JAILBREAK,
    CATEGORY_TOOL_ABUSE,
    CATEGORY_DATA_EXFILTRATION,
    CATEGORY_PRIVILEGE_ESCALATION,
    CATEGORY_MULTI_TURN,
)

#: Pinned probe-verdict vocabulary. Verdicts are host-reported data.
VERDICT_BLOCKED = "blocked"
VERDICT_REFUSED = "refused"
VERDICT_BREACHED = "breached"
VERDICT_INCONCLUSIVE = "inconclusive"
VERDICTS = (
    VERDICT_BLOCKED,
    VERDICT_REFUSED,
    VERDICT_BREACHED,
    VERDICT_INCONCLUSIVE,
)


class RedTeamingError(Exception):
    """Base error for the red teaming ledger (programming errors)."""


class BadIdError(RedTeamingError):
    """Raised when an attack/probe id is malformed."""


class DuplicateAttackError(RedTeamingError):
    """Raised when an attack id is declared twice."""


class UnknownAttackError(RedTeamingError):
    """Raised when an attack id names no declared attack."""


class BadCategoryError(RedTeamingError):
    """Raised when an attack category is not in the pinned vocabulary."""


class BadVerdictError(RedTeamingError):
    """Raised when a probe verdict is not in the pinned vocabulary."""


class DuplicateProbeError(RedTeamingError):
    """Raised when a probe id is booked twice."""


class NoProbesError(RedTeamingError):
    """Raised when report() is called on an attack with zero probes."""


class SeqOrderError(RedTeamingError):
    """Raised when a seq is malformed or not strictly increasing."""


class AuditKindError(RedTeamingError):
    """Raised when an audit event kind is unknown or leaks banned keys."""


def _check_seq(value: object, name: str = "seq") -> int:
    """Validate a caller-supplied ordering seq: int, not bool, >= 0."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise SeqOrderError(f"{name} must be int, got {type(value).__name__}")
    if value < 0:
        raise SeqOrderError(f"{name} must be >= 0, got {value}")
    return value


def _check_id(value: object, label: str) -> str:
    """Validate an id: non-empty str, no whitespace, <= 256 chars."""
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadIdError(f"{label} must be str, got {type(value).__name__}")
    if not value:
        raise BadIdError(f"{label} must not be empty")
    if len(value) > _MAX_ID_LEN:
        raise BadIdError(f"{label} too long (>{_MAX_ID_LEN} chars)")
    if any(ch.isspace() for ch in value):
        raise BadIdError(f"{label} must not contain whitespace")
    return value


def _pin(*parts: object) -> str:
    """Digest pin over a domain-separated canonical tuple."""
    return "sha256:" + jcs_sha256_hex({
        "domain": RED_TEAMING_SCHEMA,
        "parts": list(parts),
    })


def red_teaming_audit_event(kind: str, detail: Dict[str, object],
                            seq: object) -> Dict[str, object]:
    """Build one ``audit.ndjson/1`` audit row for the red teaming ledger."""
    if kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    banned = _BANNED_DETAIL_KEYS.intersection(detail.keys())
    if banned:
        raise AuditKindError(
            f"detail keys banned from audit boundary: {sorted(banned)}")
    return {
        "schema": AUDIT_SCHEMA,
        "module": RED_TEAMING_VERSION,
        "kind": kind,
        "seq": seq,
        "detail": dict(detail),
    }


@dataclass(frozen=True)
class AttackRecord:
    """Frozen record of one declared attack scenario."""
    attack_id: str
    category: str
    seq: int
    digest: str

    def verify(self, attack_id: str, category: str) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin("attack", attack_id, category, self.seq)


@dataclass(frozen=True)
class ProbeRecord:
    """Frozen record of one booked probe attempt (host-reported outcome)."""
    probe_id: str
    attack_id: str
    verdict: str
    seq: int
    digest: str

    def verify(self, attack_id: str, verdict: str) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin(
            "probe", self.probe_id, attack_id, verdict, self.seq)


@dataclass(frozen=True)
class ReportRecord:
    """Frozen per-attack aggregate report: verdicts as data, never raised."""
    attack_id: str
    probe_count: int
    breached_count: int
    blocked_count: int
    refused_count: int
    inconclusive_count: int
    verdict: str
    seq: int
    digest: str

    def verify(self, attack_id: str, counts: Tuple[int, int, int, int]) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        breached, blocked, refused, inconclusive = counts
        return self.digest == _pin(
            "report", attack_id, breached, blocked, refused, inconclusive,
            self.seq)


class RedTeaming:
    """Red teaming campaign ledger (simulated attacks, booked outcomes)."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq: int = -1
        self._attacks: Dict[str, AttackRecord] = {}
        self._probes: Dict[str, ProbeRecord] = {}
        self._probe_order: Tuple[str, ...] = ()
        self._audit: Tuple[Dict[str, object], ...] = ()
        self._probe_seq: int = 0

    def _claim(self, seq: int) -> None:
        """Claim a seq (strictly increasing); raise bare on rewind."""
        _check_seq(seq)
        with self._lock:
            if seq <= self._last_seq:
                raise SeqOrderError(
                    f"seq must be > {self._last_seq}, got {seq}")
            self._last_seq = seq

    def _burn(self, seq: int, attack_id: str = "") -> None:
        """Book a rejected row after a failed mutation consumed its seq."""
        detail: Dict[str, object] = {}
        if attack_id:
            detail["attack_id"] = attack_id
        event = red_teaming_audit_event(KIND_REJECTED, detail, seq)
        with self._lock:
            self._audit = self._audit + (event,)

    def _emit(self, audit_kind: str, detail: Dict[str, object],
              seq: int) -> None:
        """Append an audit event (caller has already claimed the seq)."""
        event = red_teaming_audit_event(audit_kind, detail, seq)
        with self._lock:
            self._audit = self._audit + (event,)

    def attack(self, attack_id: str, category: str, seq: int) -> AttackRecord:
        """Declare one attack scenario (pins the scenario digest, never
        its content). Returns the frozen ``AttackRecord``."""
        self._claim(seq)
        try:
            attack_id = _check_id(attack_id, "attack_id")
            if isinstance(category, bool) or not isinstance(category, str):
                raise BadCategoryError(
                    f"category must be str, got {type(category).__name__}")
            if category not in CATEGORIES:
                raise BadCategoryError(
                    f"category must be one of {sorted(CATEGORIES)}, "
                    f"got {category!r}")
            with self._lock:
                if attack_id in self._attacks:
                    raise DuplicateAttackError(
                        f"attack already declared: {attack_id!r}")
                record = AttackRecord(
                    attack_id=attack_id,
                    category=category,
                    seq=seq,
                    digest=_pin("attack", attack_id, category, seq),
                )
                self._attacks[attack_id] = record
        except RedTeamingError:
            self._burn(seq, attack_id if isinstance(attack_id, str) else "")
            raise
        self._emit(KIND_ATTACK_DECLARED,
                   {"attack_id": attack_id, "category": category}, seq)
        return record

    def probe(self, attack_id: str, probe_id: str, seq: int,
              verdict: str = VERDICT_INCONCLUSIVE) -> ProbeRecord:
        """Book one probe attempt against a declared attack scenario.
        The outcome is host-reported data; this books the decision, not
        proof of execution. Returns the frozen ``ProbeRecord``."""
        self._claim(seq)
        minted_id: Optional[str] = None
        try:
            attack_id = _check_id(attack_id, "attack_id")
            probe_id = _check_id(probe_id, "probe_id")
            if isinstance(verdict, bool) or not isinstance(verdict, str):
                raise BadVerdictError(
                    f"verdict must be str, got {type(verdict).__name__}")
            if verdict not in VERDICTS:
                raise BadVerdictError(
                    f"verdict must be one of {sorted(VERDICTS)}, "
                    f"got {verdict!r}")
            with self._lock:
                if attack_id not in self._attacks:
                    raise UnknownAttackError(
                        f"unknown attack: {attack_id!r}")
                if probe_id in self._probes:
                    raise DuplicateProbeError(
                        f"probe already booked: {probe_id!r}")
                self._probe_seq += 1
                minted_id = f"probe-{self._probe_seq}"
                record = ProbeRecord(
                    probe_id=probe_id,
                    attack_id=attack_id,
                    verdict=verdict,
                    seq=seq,
                    digest=_pin("probe", probe_id, attack_id, verdict, seq),
                )
                self._probes[probe_id] = record
                self._probe_order = self._probe_order + (probe_id,)
        except RedTeamingError:
            self._burn(seq, attack_id if isinstance(attack_id, str) else "")
            raise
        self._emit(KIND_PROBED,
                   {"probe_id": probe_id, "attack_id": attack_id,
                    "verdict": verdict, "ledger_id": minted_id}, seq)
        return record

    def report(self, attack_id: str, seq: int) -> ReportRecord:
        """Aggregate one attack's probes into a report. The verdict is
        *data* (``resilient`` / ``mixed`` / ``vulnerable``), never raised.
        Returns the frozen ``ReportRecord``."""
        self._claim(seq)
        try:
            attack_id = _check_id(attack_id, "attack_id")
            with self._lock:
                if attack_id not in self._attacks:
                    raise UnknownAttackError(
                        f"unknown attack: {attack_id!r}")
                probes = [self._probes[pid] for pid in self._probe_order
                          if self._probes[pid].attack_id == attack_id]
            if not probes:
                raise NoProbesError(
                    f"no probes booked for attack {attack_id!r}")
            breached = sum(1 for p in probes if p.verdict == VERDICT_BREACHED)
            blocked = sum(1 for p in probes if p.verdict == VERDICT_BLOCKED)
            refused = sum(1 for p in probes if p.verdict == VERDICT_REFUSED)
            inconclusive = sum(
                1 for p in probes if p.verdict == VERDICT_INCONCLUSIVE)
            if breached > 0:
                verdict = "vulnerable"
            elif blocked + refused == len(probes):
                verdict = "resilient"
            else:
                verdict = "mixed"
            with self._lock:
                record = ReportRecord(
                    attack_id=attack_id,
                    probe_count=len(probes),
                    breached_count=breached,
                    blocked_count=blocked,
                    refused_count=refused,
                    inconclusive_count=inconclusive,
                    verdict=verdict,
                    seq=seq,
                    digest=_pin("report", attack_id, breached, blocked,
                                refused, inconclusive, seq),
                )
        except RedTeamingError:
            self._burn(seq, attack_id if isinstance(attack_id, str) else "")
            raise
        self._emit(KIND_REPORTED,
                   {"attack_id": attack_id, "verdict": verdict,
                    "probe_count": len(probes),
                    "breached_count": breached}, seq)
        return record

    def audit_log(self) -> Tuple[Dict[str, object], ...]:
        """Pure read view of the audit events (no seq, no audit row)."""
        with self._lock:
            return self._audit

    def stats(self) -> Dict[str, int]:
        """Pure read view of ledger counters (no seq, no audit row)."""
        with self._lock:
            return {
                "attacks": len(self._attacks),
                "probes": len(self._probes),
                "audit_rows": len(self._audit),
            }


def main() -> None:
    """Self-check: declare, probe, report, verify pins, audit."""
    rt = RedTeaming()
    rec = rt.attack("inj-1", CATEGORY_PROMPT_INJECTION, 1)
    assert rec.verify("inj-1", CATEGORY_PROMPT_INJECTION)
    p1 = rt.probe("inj-1", "p-1", 2, VERDICT_BLOCKED)
    assert p1.verify("inj-1", VERDICT_BLOCKED)
    p2 = rt.probe("inj-1", "p-2", 3, VERDICT_BREACHED)
    assert p2.verify("inj-1", VERDICT_BREACHED)
    rpt = rt.report("inj-1", 4)
    assert rpt.verdict == "vulnerable"
    assert rpt.verify("inj-1", (1, 1, 0, 0))
    assert rt.stats()["probes"] == 2
    # Refusal spot-checks consume their seqs.
    rt.attack("inj-empty", CATEGORY_MULTI_TURN, 5)
    seq = 6
    for thunk in (
        lambda s: rt.attack("inj-1", CATEGORY_JAILBREAK, s),
        lambda s: rt.attack("bad attack!", CATEGORY_JAILBREAK, s),
        lambda s: rt.attack("inj-2", "unknown-cat", s),
        lambda s: rt.probe("nope", "p-3", s, VERDICT_BLOCKED),
        lambda s: rt.probe("inj-1", "p-1", s, VERDICT_BLOCKED),
        lambda s: rt.probe("inj-1", "p-4", s, "unknown-verdict"),
        lambda s: rt.report("inj-empty", s),   # NoProbesError path
        lambda s: rt.report("unknown-attack", s),
    ):
        try:
            thunk(seq)
        except RedTeamingError:
            seq += 1
        else:
            raise AssertionError("expected refusal")
    print("red-teaming OK: attack, probe, report, pins, audit")


if __name__ == "__main__":
    main()
