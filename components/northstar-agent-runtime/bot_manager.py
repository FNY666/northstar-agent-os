"""Good/bad bot management: allowlist, challenge, and block bookkeeping.

A ``BotManager`` books host-reported bot-classification decisions as a
deterministic single-host state machine, in the shape of Cloudflare Bot
Management / Akamai bot rules:

- ``register_bot(bot_id, category, seq)`` pins a bot category from the
  pinned vocabulary ``("good", "unknown", "suspicious", "bad")``.
- ``allow(bot_id, seq)`` returns a frozen ``Verdict``. ``allowed=True``
  only for ``good`` bots; other categories return ``allowed=False`` as
  data (never raised). A blocked bot raises ``BlockedBotError``
  fail-closed. Pure read view: the seq is validated, not consumed.
- ``challenge(bot_id, seq)`` issues a frozen ``ChallengeRecord``
  (managed challenge / JS challenge / interactive challenge; the *kind*
  is pinned, the challenge itself is simulated). Blocked bots and
  unknown bots are refused fail-closed.
- ``solve_challenge(challenge_id, seq, passed)`` books the host's
  challenge outcome as data; a passed challenge lifts a ``suspicious``
  bot to ``unknown`` (the host decides whether to allowlist it).
  Passing a challenge on a ``bad`` bot does not un-flag it.
- ``block(bot_id, seq, reason)`` / ``unblock(bot_id, seq, reason)``
  manage terminal blocks.

House style: frozen dataclasses, caller-supplied strictly increasing
int seqs (no wall-clock), RLock-guarded, fail-closed taxonomy,
stdlib-only plus the standard ``canonical_json`` try/except fallback,
``sha256:`` digest pins, ``audit.ndjson/1`` events, version pin
``bot-manager.v1``, schema pin ``northstar.bot-manager.v1``, ``main()``
self-check.

Honest scope: this module books *host-reported* classifications and
challenge outcomes. It cannot detect a bot it was never told about,
cannot solve a challenge, and cannot observe the wire. A "good" verdict
means "the host classified this bot as good and we have it pinned",
never "this traffic is human".
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except ImportError:  # pragma: no cover - fallback for standalone import
    import json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


#: Version pin for this module's record shape.
BOT_MANAGER_VERSION = "bot-manager.v1"

#: Schema pin carried by records and audit events.
BOT_MANAGER_SCHEMA = "northstar.bot-manager.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Pinned bot categories. Drift is detectable because categories are
#: pinned inside every record digest.
CATEGORY_GOOD = "good"
CATEGORY_UNKNOWN = "unknown"
CATEGORY_SUSPICIOUS = "suspicious"
CATEGORY_BAD = "bad"
CATEGORIES = (CATEGORY_GOOD, CATEGORY_UNKNOWN, CATEGORY_SUSPICIOUS, CATEGORY_BAD)

#: Pinned challenge kinds (the challenge itself is simulated).
CHALLENGE_MANAGED = "managed"
CHALLENGE_JAVASCRIPT = "javascript"
CHALLENGE_INTERACTIVE = "interactive"
CHALLENGE_KINDS = (CHALLENGE_MANAGED, CHALLENGE_JAVASCRIPT, CHALLENGE_INTERACTIVE)

#: Challenge validity window in logical-seq units.
CHALLENGE_WINDOW_SEQ = 100


# ---------------------------------------------------------------------------
# Errors (fail-closed taxonomy)
# ---------------------------------------------------------------------------


class BotManagerError(ValueError):
    """Base for all bot-manager structural problems and refused transitions."""


class BadBotError(BotManagerError):
    """Bot registration is malformed (bad id or category)."""


class DuplicateBotError(BotManagerError):
    """A bot id is already registered."""


class UnknownBotError(BotManagerError):
    """No bot is registered under the requested id."""


class BlockedBotError(BotManagerError):
    """The bot is blocked; the requested action is refused fail-closed."""


class AlreadyBlockedError(BotManagerError):
    """The bot is already blocked."""


class UnknownBlockError(BotManagerError):
    """No active block exists for the bot."""


class UnknownChallengeError(BotManagerError):
    """No challenge exists under the requested id."""


class ChallengeStateError(BotManagerError):
    """The challenge is already resolved or expired."""


class SeqOrderError(BotManagerError):
    """Caller seq did not strictly increase."""


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _check_seq(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise SeqOrderError(f"{name} must be a non-negative int")
    return value


def _check_nonempty_str(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise BotManagerError(f"{name} must be a non-empty string")
    return value.strip()


def _pin(*parts: Any) -> str:
    digest = hashlib.sha256(
        jcs_canonical_json([BOT_MANAGER_VERSION, *parts])
    ).hexdigest()
    return f"sha256:{digest}"


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BotRecord:
    """One pinned bot classification (frozen)."""

    bot_id: str
    category: str
    seq: int
    digest: str
    schema: str = BOT_MANAGER_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin("bot", self.bot_id, self.category, self.seq)


@dataclass(frozen=True)
class Verdict:
    """One allow-gate verdict (frozen). ``allowed=False`` is data."""

    bot_id: str
    category: str
    allowed: bool
    reason: str
    seq: int
    digest: str
    schema: str = BOT_MANAGER_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "verdict", self.bot_id, self.category, self.allowed,
            self.reason, self.seq,
        )


@dataclass(frozen=True)
class ChallengeRecord:
    """One issued challenge (frozen). Simulated: no puzzle is generated."""

    challenge_id: str
    bot_id: str
    kind: str
    issued_seq: int
    expires_seq: int
    resolved: bool
    passed: bool
    digest: str
    schema: str = BOT_MANAGER_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "challenge", self.challenge_id, self.bot_id, self.kind,
            self.issued_seq, self.expires_seq, self.resolved, self.passed,
        )


@dataclass(frozen=True)
class ChallengeResult:
    """One booked challenge outcome (frozen). The outcome is host data."""

    challenge_id: str
    bot_id: str
    passed: bool
    expired: bool
    category_after: str
    seq: int
    digest: str
    schema: str = BOT_MANAGER_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "solve", self.challenge_id, self.bot_id, self.passed,
            self.expired, self.category_after, self.seq,
        )


@dataclass(frozen=True)
class BlockRecord:
    """One terminal bot block (frozen)."""

    bot_id: str
    reason: str
    seq: int
    digest: str
    schema: str = BOT_MANAGER_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin("block", self.bot_id, self.reason, self.seq)


@dataclass(frozen=True)
class UnblockRecord:
    """One block release (frozen)."""

    bot_id: str
    reason: str
    seq: int
    digest: str
    schema: str = BOT_MANAGER_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin("unblock", self.bot_id, self.reason, self.seq)


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------

KIND_BOT_REGISTERED = "bot-manager.bot-registered"
KIND_ALLOWED = "bot-manager.allowed"
KIND_DENIED = "bot-manager.denied"
KIND_CHALLENGED = "bot-manager.challenged"
KIND_CHALLENGE_SOLVED = "bot-manager.challenge-solved"
KIND_BLOCKED = "bot-manager.blocked"
KIND_UNBLOCKED = "bot-manager.unblocked"
KIND_REJECTED = "bot-manager.rejected"
_KINDS = (
    KIND_BOT_REGISTERED, KIND_ALLOWED, KIND_DENIED, KIND_CHALLENGED,
    KIND_CHALLENGE_SOLVED, KIND_BLOCKED, KIND_UNBLOCKED, KIND_REJECTED,
)


def bot_manager_audit_event(kind: str, seq: int, **detail: Any) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` event for the bot ledger."""
    if kind not in _KINDS:
        raise BotManagerError(f"unknown audit kind: {kind!r}")
    _check_seq(seq, "seq")
    return {
        "schema_version": AUDIT_SCHEMA,
        "component": "northstar-agent-runtime",
        "module": BOT_MANAGER_VERSION,
        "event": kind,
        "seq": seq,
        "level": "info",
        "payload": dict(detail),
    }


# ---------------------------------------------------------------------------
# The manager
# ---------------------------------------------------------------------------


class BotManager:
    """Deterministic good/bad bot bookkeeping."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._bots: Dict[str, BotRecord] = {}
        self._blocks: Dict[str, BlockRecord] = {}
        self._challenges: Dict[str, ChallengeRecord] = {}
        self._seq: int = 0
        self._challenge_seq: int = 0
        self._audit: List[Dict[str, Any]] = []

    # -- internal ------------------------------------------------------

    def _next_seq(self, seq: int) -> int:
        _check_seq(seq, "seq")
        if seq <= self._seq:
            raise SeqOrderError("seq must strictly increase")
        self._seq = seq
        return seq

    def _reject(self, seq: int, reason: str) -> BotManagerError:
        # Failed mutations consume their seq (batch-21 ledger discipline).
        try:
            self._next_seq(seq)
        except SeqOrderError as exc:
            raise exc
        self._audit.append(bot_manager_audit_event(KIND_REJECTED, seq, reason=reason))
        return BotManagerError(reason)

    def _get_bot(self, bot_id: str) -> BotRecord:
        bot = self._bots.get(bot_id)
        if bot is None:
            raise UnknownBotError(f"unknown bot: {bot_id!r}")
        return bot

    def _ensure_unblocked(self, bot_id: str) -> None:
        if bot_id in self._blocks:
            raise BlockedBotError(f"bot is blocked: {bot_id!r}")

    # -- mutations -----------------------------------------------------

    def register_bot(self, bot_id: str, category: str, seq: int) -> BotRecord:
        """Pin a bot category. Duplicate ids refused fail-closed."""
        with self._lock:
            bot_id = _check_nonempty_str(bot_id, "bot_id")
            if bot_id in self._bots:
                raise self._reject(seq, f"duplicate bot: {bot_id!r}") from DuplicateBotError(
                    f"duplicate bot: {bot_id!r}"
                )
            if category not in CATEGORIES:
                raise self._reject(seq, f"unknown category: {category!r}") from BadBotError(
                    f"unknown category: {category!r}"
                )
            self._next_seq(seq)
            record = BotRecord(
                bot_id=bot_id,
                category=category,
                seq=seq,
                digest=_pin("bot", bot_id, category, seq),
            )
            self._bots[bot_id] = record
            self._audit.append(
                bot_manager_audit_event(
                    KIND_BOT_REGISTERED, seq, bot_id=bot_id, category=category,
                    digest=record.digest,
                )
            )
            return record

    def challenge(
        self, bot_id: str, seq: int, kind: str = CHALLENGE_MANAGED
    ) -> ChallengeRecord:
        """Issue a simulated challenge to a registered, unblocked bot."""
        with self._lock:
            bot = self._get_bot(bot_id)
            self._ensure_unblocked(bot_id)
            if kind not in CHALLENGE_KINDS:
                raise self._reject(seq, f"unknown challenge kind: {kind!r}") from BotManagerError(
                    f"unknown challenge kind: {kind!r}"
                )
            self._next_seq(seq)
            self._challenge_seq += 1
            challenge_id = f"ch-{self._challenge_seq}"
            record = ChallengeRecord(
                challenge_id=challenge_id,
                bot_id=bot_id,
                kind=kind,
                issued_seq=seq,
                expires_seq=seq + CHALLENGE_WINDOW_SEQ,
                resolved=False,
                passed=False,
                digest="",
                schema=BOT_MANAGER_SCHEMA,
            )
            record = ChallengeRecord(
                challenge_id=record.challenge_id,
                bot_id=record.bot_id,
                kind=record.kind,
                issued_seq=record.issued_seq,
                expires_seq=record.expires_seq,
                resolved=False,
                passed=False,
                digest=_pin(
                    "challenge", challenge_id, bot_id, kind, seq,
                    seq + CHALLENGE_WINDOW_SEQ, False, False,
                ),
            )
            self._challenges[challenge_id] = record
            self._audit.append(
                bot_manager_audit_event(
                    KIND_CHALLENGED, seq, challenge_id=challenge_id,
                    bot_id=bot_id, challenge_kind=kind, category=bot.category,
                    digest=record.digest,
                )
            )
            return record

    def solve_challenge(self, challenge_id: str, seq: int, passed: bool) -> ChallengeResult:
        """Book the host-reported challenge outcome as data.

        A passed challenge lifts a ``suspicious`` bot to ``unknown``. It
        never promotes a ``bad`` bot, and expired challenges resolve as
        expired regardless of the reported outcome.
        """
        with self._lock:
            challenge = self._challenges.get(challenge_id)
            if challenge is None:
                raise self._reject(seq, f"unknown challenge: {challenge_id!r}") from UnknownChallengeError(
                    f"unknown challenge: {challenge_id!r}"
                )
            if not isinstance(passed, bool):
                raise self._reject(seq, "passed must be bool") from BotManagerError(
                    "passed must be bool"
                )
            self._next_seq(seq)
            if challenge.resolved:
                raise ChallengeStateError(f"challenge already resolved: {challenge_id!r}")
            expired = seq > challenge.expires_seq
            bot = self._get_bot(challenge.bot_id)
            category_after = bot.category
            if not expired and passed and bot.category == CATEGORY_SUSPICIOUS:
                category_after = CATEGORY_UNKNOWN
            resolved = ChallengeRecord(
                challenge_id=challenge.challenge_id,
                bot_id=challenge.bot_id,
                kind=challenge.kind,
                issued_seq=challenge.issued_seq,
                expires_seq=challenge.expires_seq,
                resolved=True,
                passed=bool(passed and not expired),
                digest=_pin(
                    "challenge", challenge.challenge_id, challenge.bot_id,
                    challenge.kind, challenge.issued_seq, challenge.expires_seq,
                    True, bool(passed and not expired),
                ),
            )
            self._challenges[challenge_id] = resolved
            if category_after != bot.category:
                new_bot = BotRecord(
                    bot_id=bot.bot_id,
                    category=category_after,
                    seq=seq,
                    digest=_pin("bot", bot.bot_id, category_after, seq),
                )
                self._bots[bot.bot_id] = new_bot
            result = ChallengeResult(
                challenge_id=challenge_id,
                bot_id=challenge.bot_id,
                passed=bool(passed and not expired),
                expired=expired,
                category_after=category_after,
                seq=seq,
                digest=_pin(
                    "solve", challenge_id, challenge.bot_id,
                    bool(passed and not expired), expired, category_after, seq,
                ),
            )
            self._audit.append(
                bot_manager_audit_event(
                    KIND_CHALLENGE_SOLVED, seq, challenge_id=challenge_id,
                    bot_id=challenge.bot_id, passed=result.passed,
                    expired=expired, category_after=category_after,
                    digest=result.digest,
                )
            )
            return result

    def block(self, bot_id: str, seq: int, reason: str) -> BlockRecord:
        """Terminally block a registered bot."""
        with self._lock:
            bot = self._get_bot(bot_id)
            reason = _check_nonempty_str(reason, "reason")
            if bot_id in self._blocks:
                raise self._reject(seq, f"already blocked: {bot_id!r}") from AlreadyBlockedError(
                    f"already blocked: {bot_id!r}"
                )
            self._next_seq(seq)
            record = BlockRecord(
                bot_id=bot_id,
                reason=reason,
                seq=seq,
                digest=_pin("block", bot_id, reason, seq),
            )
            self._blocks[bot_id] = record
            self._audit.append(
                bot_manager_audit_event(
                    KIND_BLOCKED, seq, bot_id=bot_id, category=bot.category,
                    reason=reason, digest=record.digest,
                )
            )
            return record

    def unblock(self, bot_id: str, seq: int, reason: str) -> UnblockRecord:
        """Release a terminal bot block."""
        with self._lock:
            self._get_bot(bot_id)
            reason = _check_nonempty_str(reason, "reason")
            if bot_id not in self._blocks:
                raise self._reject(seq, f"no active block: {bot_id!r}") from UnknownBlockError(
                    f"no active block: {bot_id!r}"
                )
            self._next_seq(seq)
            del self._blocks[bot_id]
            record = UnblockRecord(
                bot_id=bot_id,
                reason=reason,
                seq=seq,
                digest=_pin("unblock", bot_id, reason, seq),
            )
            self._audit.append(
                bot_manager_audit_event(
                    KIND_UNBLOCKED, seq, bot_id=bot_id, reason=reason,
                    digest=record.digest,
                )
            )
            return record

    # -- read views (seq validated, not consumed) -----------------------

    def allow(self, bot_id: str, seq: int) -> Verdict:
        """Gate verdict. ``allowed=False`` is data; blocked bots raise.

        Pure read view: the seq shape is validated but the seq is not
        consumed and nothing is audited.
        """
        with self._lock:
            _check_seq(seq, "seq")
            bot = self._get_bot(bot_id)
            self._ensure_unblocked(bot_id)
            if bot.category == CATEGORY_GOOD:
                allowed, reason = True, "allowlisted-good"
            elif bot.category == CATEGORY_UNKNOWN:
                allowed, reason = False, "not-allowlisted"
            elif bot.category == CATEGORY_SUSPICIOUS:
                allowed, reason = False, "suspicious"
            else:
                allowed, reason = False, "known-bad"
            return Verdict(
                bot_id=bot_id,
                category=bot.category,
                allowed=allowed,
                reason=reason,
                seq=seq,
                digest=_pin("verdict", bot_id, bot.category, allowed, reason, seq),
            )

    # -- pure views ----------------------------------------------------

    def bot(self, bot_id: str) -> BotRecord:
        """Return the pinned record for a bot."""
        with self._lock:
            return self._get_bot(bot_id)

    def bot_ids(self) -> Tuple[str, ...]:
        """Sorted registered bot ids."""
        with self._lock:
            return tuple(sorted(self._bots))

    def is_blocked(self, bot_id: str) -> bool:
        """Whether the bot currently has an active block."""
        with self._lock:
            return bot_id in self._blocks

    def challenge_record(self, challenge_id: str) -> ChallengeRecord:
        """Return a pinned challenge record."""
        with self._lock:
            challenge = self._challenges.get(challenge_id)
            if challenge is None:
                raise UnknownChallengeError(f"unknown challenge: {challenge_id!r}")
            return challenge

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        """The append-only audit trail (frozen snapshots)."""
        with self._lock:
            return tuple(dict(event) for event in self._audit)


def main() -> None:
    manager = BotManager()
    good = manager.register_bot("googlebot", CATEGORY_GOOD, 1)
    assert good.verify()
    verdict = manager.allow("googlebot", 2)
    assert verdict.allowed and verdict.verify()
    suspect = manager.register_bot("scraper-7", CATEGORY_SUSPICIOUS, 3)
    assert suspect.verify()
    denied = manager.allow("scraper-7", 4)
    assert not denied.allowed and denied.reason == "suspicious" and denied.verify()
    challenge = manager.challenge("scraper-7", 5, CHALLENGE_JAVASCRIPT)
    assert challenge.verify() and not challenge.resolved
    result = manager.solve_challenge(challenge.challenge_id, 6, True)
    assert result.passed and result.category_after == CATEGORY_UNKNOWN and result.verify()
    bad = manager.register_bot("stuffing-net", CATEGORY_BAD, 7)
    assert bad.verify()
    block = manager.block("stuffing-net", 8, "credential stuffing")
    assert block.verify() and manager.is_blocked("stuffing-net")
    try:
        manager.allow("stuffing-net", 9)
    except BlockedBotError:
        pass
    else:
        raise AssertionError("blocked bot must raise")
    unblock = manager.unblock("stuffing-net", 10, "ops review")
    assert unblock.verify() and not manager.is_blocked("stuffing-net")
    event = bot_manager_audit_event(KIND_ALLOWED, 11, bot_id="googlebot")
    assert event["schema_version"] == AUDIT_SCHEMA
    print("bot-manager OK: register, allow, challenge, solve, block, unblock, audit")
    return None


if __name__ == "__main__":
    main()
