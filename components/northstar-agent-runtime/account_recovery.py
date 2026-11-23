"""Account recovery: code-issued recovery flows (simulated).

Research note: account recovery is the standard "lost credentials" escape
hatch across consumer and enterprise identity systems, and every provider
converges on the same lifecycle, codified in NIST SP 800-63B section 6
(authenticator recovery) and in the recovery docs of Google, Apple, GitHub,
and Stripe:

* **Initiate** — the account holder (or someone claiming to be them)
  requests recovery against a *contact* (email address or phone number)
  the account previously verified. The service mints a short-lived,
  single-use verification *code* and "sends" it to that contact. The
  ledger stores a verifier (an HMAC of the code), never the code.
* **Verify** — the requester presents the code. Each miss consumes one
  attempt; too many misses locks the request (GitHub's rate-limited
  "enter the code" step, Apple's cool-down). A code presented after
  expiry is dead even if it is correct.
* **Complete** — once verified, the request is *consumed* and the service
  issues a single-use *recovery token* that authorizes exactly one
  credential reset. The token is shown to the caller once; the ledger
  keeps only a digest of it.

Codes and tokens are short bearer secrets, so the same fail-closed rules
as password-reset tokens apply:

* A pending request is exclusive per ``account_id``: a second
  ``initiate()`` while one is pending raises ``DuplicateRequestError``
  (prevents code-spraying the same contact).
* Codes are 6 decimal digits, minted from the manager's RNG, and compared
  with ``hmac.compare_digest``; malformed input is ``valid=False`` as
  data, wrong types raise.
* ``max_attempts`` wrong codes lock the request terminally
  (``RequestLockedError``) — lockout is recorded, never silent.
* Expiry is in caller-supplied logical seqs (no wall-clock): a code is
  live while ``at_seq < expires_at_seq``. ``initiate()`` requires
  ``ttl_seqs > 0``.
* Mutation seqs must strictly increase per manager (``SeqOrderError``).
* ``complete()`` requires the ``"verified"`` state and consumes the
  request: a second ``complete()`` raises ``AlreadyConsumedError``, and
  the recovery token verifies at most once (``TokenReplayError`` on
  reuse).
* Raw codes/tokens never appear in ``as_dict()``, audit events, or
  digests: the digest pins bind (request_id, account_id, channel, seqs)
  only.

Honest scope: this books *reported* recovery events. It cannot prove a
code reached the right human, cannot observe the delivery channel, and
the codes are HMAC-derived bookkeeping, not a CSPRNG boundary —
production deployments must mint from the OS RNG (``secrets``) and
deliver through a real out-of-band channel. With an explicit ``seed=``
the module is fully deterministic for tests and audit replay; the
default salt comes from ``secrets.token_bytes``.

Version pin: account-recovery.v1
Schema pin: northstar.account-recovery.v1
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except ImportError:  # pragma: no cover - fallback for standalone import

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        import json

        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


ACCOUNT_RECOVERY_VERSION = "account-recovery.v1"
SCHEMA_PIN = "northstar.account-recovery.v1"

CODE_DIGITS = 6
DEFAULT_TTL_SEQS = 50
DEFAULT_MAX_ATTEMPTS = 5
TOKEN_BYTES = 24


class AccountRecoveryError(Exception):
    """Base class for account recovery errors."""


class DuplicateRequestError(AccountRecoveryError):
    """A pending recovery request already exists for this account."""


class UnknownRequestError(AccountRecoveryError):
    """No such recovery request id."""


class RequestLockedError(AccountRecoveryError):
    """The request is locked after too many wrong codes."""


class RequestExpiredError(AccountRecoveryError):
    """The verification code has expired."""


class NotVerifiedError(AccountRecoveryError):
    """complete() requires the verified state."""


class AlreadyConsumedError(AccountRecoveryError):
    """The request was already completed/consumed."""


class TokenReplayError(AccountRecoveryError):
    """The recovery token was already redeemed."""


class UnknownTokenError(AccountRecoveryError):
    """No such recovery token."""


class SeqOrderError(AccountRecoveryError):
    """Mutation seqs must strictly increase per manager."""


def _check_seq_kind(value: int, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError(f"{name} must be an int, got {type(value).__name__}")
    return value


@dataclass
class RecoveryRequest:
    request_id: str
    account_id: str
    contact: str
    channel: str
    code_verifier: bytes
    issued_at_seq: int
    expires_at_seq: int
    max_attempts: int
    attempts_used: int = 0
    state: str = "pending"  # pending | verified | locked | expired | consumed
    token_digest: Optional[bytes] = None

    def as_dict(self) -> Dict[str, Any]:
        return {
            "request_id": self.request_id,
            "account_id": self.account_id,
            "contact": self.contact,
            "channel": self.channel,
            "issued_at_seq": self.issued_at_seq,
            "expires_at_seq": self.expires_at_seq,
            "max_attempts": self.max_attempts,
            "attempts_used": self.attempts_used,
            "state": self.state,
            "has_token": self.token_digest is not None,
        }


class AccountRecovery:
    """Simulated account-recovery flow manager.

    ``initiate()`` mints a one-time numeric code bound to ``account_id``;
    ``verify()`` checks the presented code; ``complete()`` consumes a
    verified request and issues a single-use recovery token. All time is
    logical (caller-supplied seqs).
    """

    def __init__(self, seed: Optional[bytes] = None) -> None:
        self._rng = (
            secrets.SystemRandom() if seed is None else _SeededRng(seed)
        )
        self._salt = secrets.token_bytes(16) if seed is None else hashlib.sha256(
            b"account-recovery-salt:" + seed
        ).digest()[:16]
        self._lock = threading.Lock()
        self._requests: Dict[str, RecoveryRequest] = {}
        self._tokens: Dict[bytes, str] = {}  # token_digest -> account_id
        self._used_tokens: set = set()
        self._counter = 0
        self._last_seq = -1
        self._audit_log: List[Dict[str, Any]] = []

    # -- internals -----------------------------------------------------

    def _bump_seq(self, seq: int, name: str = "seq") -> int:
        seq = _check_seq_kind(seq, name)
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"{name}={seq} must be > last seq {self._last_seq}"
            )
        self._last_seq = seq
        return seq

    def _mint_code(self) -> str:
        return f"{self._rng.randrange(0, 10 ** CODE_DIGITS):0{CODE_DIGITS}d}"

    def _code_verifier(self, request_id: str, code: str) -> bytes:
        return hmac.new(
            self._salt, (request_id + ":" + code).encode(), hashlib.sha256
        ).digest()

    def _mint_token(self) -> str:
        raw = bytes(self._rng.randrange(256) for _ in range(TOKEN_BYTES))
        return "nrt_" + raw.hex()

    def _token_digest(self, token: str) -> bytes:
        return hashlib.sha256((token + ":").encode() + self._salt).digest()

    def _audit(self, event: str, payload: Dict[str, Any]) -> None:
        self._audit_log.append(
            {
                "event": event,
                "schema": SCHEMA_PIN,
                "payload": payload,
            }
        )

    def _get(self, request_id: str) -> RecoveryRequest:
        try:
            return self._requests[request_id]
        except KeyError:
            raise UnknownRequestError(f"unknown request {request_id!r}")

    # -- public API ----------------------------------------------------

    def initiate(
        self,
        account_id: str,
        contact: str,
        channel: str = "email",
        *,
        ttl_seqs: int = DEFAULT_TTL_SEQS,
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
        at_seq: int = 0,
    ) -> Dict[str, Any]:
        """Start a recovery request; returns the request record plus the code.

        The code is returned here (simulating delivery to the contact) and
        never stored in the ledger — only an HMAC verifier is kept.
        """
        if not isinstance(account_id, str) or not account_id:
            raise TypeError("account_id must be a non-empty str")
        if not isinstance(contact, str) or not contact:
            raise TypeError("contact must be a non-empty str")
        if channel not in ("email", "sms", "voice"):
            raise ValueError(f"unsupported channel {channel!r}")
        ttl_seqs = _check_seq_kind(ttl_seqs, "ttl_seqs")
        if ttl_seqs <= 0:
            raise ValueError("ttl_seqs must be > 0")
        max_attempts = _check_seq_kind(max_attempts, "max_attempts")
        if max_attempts <= 0:
            raise ValueError("max_attempts must be > 0")

        with self._lock:
            self._bump_seq(at_seq)
            for req in self._requests.values():
                if req.account_id == account_id and req.state in (
                    "pending",
                    "verified",
                ):
                    raise DuplicateRequestError(
                        f"account {account_id!r} already has an open request"
                    )
            self._counter += 1
            request_id = f"rcv-{self._counter:06d}"
            code = self._mint_code()
            req = RecoveryRequest(
                request_id=request_id,
                account_id=account_id,
                contact=contact,
                channel=channel,
                code_verifier=self._code_verifier(request_id, code),
                issued_at_seq=at_seq,
                expires_at_seq=at_seq + ttl_seqs,
                max_attempts=max_attempts,
            )
            self._requests[request_id] = req
            self._audit(
                "recovery.initiated",
                {
                    "request_id": request_id,
                    "account_id": account_id,
                    "channel": channel,
                    "expires_at_seq": req.expires_at_seq,
                    "max_attempts": max_attempts,
                },
            )
            return {"request": req.as_dict(), "code": code}

    def verify(
        self, request_id: str, code: Any, *, at_seq: int = 0
    ) -> Dict[str, Any]:
        """Check a presented code. Returns a result dict; locks on exhaustion."""
        with self._lock:
            self._bump_seq(at_seq)
            req = self._get(request_id)
            if req.state == "consumed":
                raise AlreadyConsumedError(f"request {request_id!r} consumed")
            if req.state == "locked":
                raise RequestLockedError(f"request {request_id!r} locked")
            if req.state == "verified":
                return {"request_id": request_id, "valid": True, "state": "verified"}
            if at_seq >= req.expires_at_seq:
                req.state = "expired"
                self._audit(
                    "recovery.expired",
                    {"request_id": request_id, "account_id": req.account_id},
                )
                return {
                    "request_id": request_id,
                    "valid": False,
                    "state": "expired",
                    "reason": "expired",
                }
            if not isinstance(code, str):
                raise TypeError(
                    f"code must be a str, got {type(code).__name__}"
                )
            expected = req.code_verifier
            presented = self._code_verifier(request_id, code)
            ok = hmac.compare_digest(presented, expected)
            if ok:
                req.state = "verified"
                self._audit(
                    "recovery.verified",
                    {"request_id": request_id, "account_id": req.account_id},
                )
                return {
                    "request_id": request_id,
                    "valid": True,
                    "state": "verified",
                }
            req.attempts_used += 1
            remaining = req.max_attempts - req.attempts_used
            if remaining <= 0:
                req.state = "locked"
                self._audit(
                    "recovery.locked",
                    {
                        "request_id": request_id,
                        "account_id": req.account_id,
                        "attempts_used": req.attempts_used,
                    },
                )
                return {
                    "request_id": request_id,
                    "valid": False,
                    "state": "locked",
                    "reason": "too_many_attempts",
                }
            return {
                "request_id": request_id,
                "valid": False,
                "state": "pending",
                "reason": "wrong_code",
                "attempts_remaining": remaining,
            }

    def complete(self, request_id: str, *, at_seq: int = 0) -> Dict[str, Any]:
        """Consume a verified request and issue a single-use recovery token."""
        with self._lock:
            self._bump_seq(at_seq)
            req = self._get(request_id)
            if req.state == "consumed":
                raise AlreadyConsumedError(f"request {request_id!r} consumed")
            if req.state != "verified":
                raise NotVerifiedError(
                    f"request {request_id!r} is {req.state!r}, not verified"
                )
            token = self._mint_token()
            digest = self._token_digest(token)
            req.token_digest = digest
            req.state = "consumed"
            self._tokens[digest] = req.account_id
            self._audit(
                "recovery.completed",
                {"request_id": request_id, "account_id": req.account_id},
            )
            return {"request_id": request_id, "recovery_token": token}

    def redeem_token(self, token: str) -> str:
        """Redeem a recovery token exactly once; returns the account_id."""
        if not isinstance(token, str):
            raise TypeError(f"token must be a str, got {type(token).__name__}")
        with self._lock:
            digest = self._token_digest(token)
            if digest in self._used_tokens:
                raise TokenReplayError("recovery token already redeemed")
            try:
                account_id = self._tokens[digest]
            except KeyError:
                raise UnknownTokenError("unknown recovery token")
            self._used_tokens.add(digest)
            self._audit(
                "recovery.token_redeemed", {"account_id": account_id}
            )
            return account_id

    # -- inspection ----------------------------------------------------

    def get(self, request_id: str) -> Dict[str, Any]:
        """Return the request record (no secrets)."""
        with self._lock:
            return self._get(request_id).as_dict()

    def audit_log(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [dict(e) for e in self._audit_log]

    def request_digest(self, request_id: str) -> str:
        """Pin binding the non-secret request fields."""
        with self._lock:
            req = self._get(request_id)
            payload = {
                "request_id": req.request_id,
                "account_id": req.account_id,
                "channel": req.channel,
                "issued_at_seq": req.issued_at_seq,
                "expires_at_seq": req.expires_at_seq,
            }
        return "sha256:" + hashlib.sha256(
            jcs_canonical_json(payload)
        ).hexdigest()


class _SeededRng:
    """Deterministic RNG for tests: HMAC-DRBG style over a seed."""

    def __init__(self, seed: bytes) -> None:
        self._key = hashlib.sha256(b"account-recovery-drbg:" + seed).digest()
        self._ctr = 0

    def _next_block(self) -> bytes:
        self._ctr += 1
        return hmac.new(
            self._key, self._ctr.to_bytes(8, "big"), hashlib.sha256
        ).digest()

    def randrange(self, start: int, stop: Optional[int] = None) -> int:
        # matches random.Random.randrange(start, stop); one-arg form
        # randrange(n) is accepted as randrange(0, n).
        if stop is None:
            start, stop = 0, start
        assert stop > start
        n = stop - start
        # rejection sampling to avoid modulo bias
        bits = n.bit_length()
        nbytes = (bits + 7) // 8
        limit = (256 ** nbytes) // n * n
        while True:
            block = self._next_block()
            val = int.from_bytes(block[:nbytes], "big")
            if val < limit:
                return start + (val % n)


def account_recovery_audit_event(
    event: str, payload: Dict[str, Any]
) -> Dict[str, Any]:
    """Build an audit event envelope for account recovery."""
    return {
        "event": event,
        "schema": SCHEMA_PIN,
        "module_version": ACCOUNT_RECOVERY_VERSION,
        "payload": payload,
    }
