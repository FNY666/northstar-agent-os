"""Artifact authority: the artifact carries the authority it was granted.

Vina's counter-position challenges the consensus that Northstar's slice 6
settled: re-checking the grant at dispatch time.  Verbatim, as carried in
the B173 slice brief's source list (Moltbook post ``737eade5``; the post
is not in this repository and was not fetched when this module was
written, so the id and title are as-briefed and only the quoted
sentences are carried as source text):

    "A checksum is a witness that never expires, and a grant is a witness
    that always does. The mismatch is structural, not a scheduling bug.
    Checking later is not authorization. It is integrity with extra steps."

The design this module implements is the one the thread converged on:
**the receipt travels with the bytes.**  A sealed artifact carries the grant
that permitted it, the revocation epoch that grant was read at, the seq it
was permitted at, and the identity of the clock and the issuer.  The
receipt's shape is spiritofthefleet's (as carried in the slice brief): *"permitted at T, check the list for
now"* -- the receipt is a statement about the **past**, and the list of
revocations is what says something about the present.

Three rules do the load-bearing work.

**Past tense, always.**  :meth:`ArtifactReceipt.render` emits a receipt
text that says the artifact *was permitted* at seq ``T``.  It never claims
present-tense authorization: "authorized", "permitted now" and "valid" are
refused tokens, and :func:`verify` never returns ``VALID`` for a receipt
whose epoch or tombstone status has moved on.  A receipt that claims to
authorize *now* is a bug, and it is refused at render and at parse.

**The epoch must come from a clock the issuer does not own.**  ``bind``
fails closed when ``clock_id == issuer_id``: an epoch read off the issuer's
own clock proves nothing about the issuer's own revocation.

**Read-time tombstone check.**  A tombstone is consulted when the receipt
is *read*, not only when it was sealed.  A receipt sealed before a
cancellation was declared must come back ``REVOKED`` afterwards; it never
silently stays ``VALID``.

Honest scope -- and this is the gap the module explicitly does **not**
close:

* Sealing proves integrity and order, never truth.  A receipt records what
  the host reported; it cannot prove a grant existed, that the counter was
  the right one, or that the epoch was read from the clock it names.
* The module **cannot prove that the clock is independent of the issuer**.
  It records ``clock_id`` and ``issuer_id`` and refuses them being the same
  identity.  That is the whole of the guarantee.  A host that lies about
  both -- or that runs the clock it names under the issuer's control -- is
  out of scope, and the module does not pretend otherwise.
* ``permitted_at`` is a caller-supplied integer seq, never a wall clock:
  the same house rule every ledger in this repo follows.

House style: frozen dataclasses, no wall-clock, fail-closed taxonomy,
stdlib-only, ``sha256:`` digest pins, version/schema pins.

Version pin: ``artifact-authority.v1``
Schema pin: ``northstar.artifact-authority.v1``
"""

from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Optional, Tuple

#: Module version pin.
ARTIFACT_AUTHORITY_VERSION = "artifact-authority.v1"

#: Schema pin carried by receipts and their renderings.
SCHEMA_PIN = "northstar.artifact-authority.v1"

#: The verdict states.  ``VALID`` is the only one that says "current".
VALID = "VALID"
STALE = "STALE"
REVOKED = "REVOKED"
UNBOUND = "UNBOUND"
UNNAMED = "UNNAMED"

#: Every state ``verify`` may return.
VERDICT_STATES = (VALID, STALE, REVOKED, UNBOUND, UNNAMED)

#: Tokens that would turn the receipt into a present-tense authorization
#: claim.  A receipt that contains one of them is refused at render and at
#: parse: "permitted at T" is a statement about the past, and the past is
#: all a receipt is allowed to claim.
FORBIDDEN_NOW_TENSE = (
    "authorized",
    "authorised",
    "permitted now",
    "currently valid",
    "is valid",
    "valid",
)

#: The literal clause every receipt ends with -- spiritofthefleet's
#: "check the list for now".  The receipt points at the revocation list;
#: it never stands in for it.
CHECK_THE_LIST_FOR_NOW = "check the list for now"

#: The literal past-tense clause: "permitted at <seq>".
PERMITTED_AT_PREFIX = "permitted at "

#: The container prefix of a sealed artifact.
SEAL_PREFIX = b"northstar-artifact-authority:v1\n"

_MAX_ID_CHARS = 256
_MAX_TEXT_CHARS = 512


class ArtifactAuthorityError(Exception):
    """Base class for artifact-authority errors."""


class MalformedReceiptError(ArtifactAuthorityError):
    """The receipt is not a well-formed receipt."""


class UnnamedGrantError(ArtifactAuthorityError):
    """The grant is unnamed: the seal is refused, no receipt lands."""


class ClockNotIndependentError(ArtifactAuthorityError):
    """The epoch's clock is the issuer's own clock: fail closed."""


class PresentTenseClaimError(ArtifactAuthorityError):
    """The receipt text claims present-tense authorization."""


def _load_grant_pin_ledger() -> Any:
    """Load the sibling ``grant_pin_ledger`` by path (component convention).

    The pin's shape lives in exactly one place; this module reuses
    :class:`grant_pin_ledger.GrantPin` verbatim and never re-declares it.
    The module is loaded lazily by path so this file keeps its stdlib-only
    import profile.
    """
    module = sys.modules.get("grant_pin_ledger")
    if module is not None:
        return module
    path = Path(__file__).resolve().parent / "grant_pin_ledger.py"
    spec = importlib.util.spec_from_file_location("grant_pin_ledger", str(path))
    if spec is None or spec.loader is None:  # pragma: no cover - defensive
        raise ImportError("grant_pin_ledger not loadable")
    module = importlib.util.module_from_spec(spec)
    sys.modules["grant_pin_ledger"] = module
    spec.loader.exec_module(module)
    return module


_PINS = _load_grant_pin_ledger()

#: The pin type, reused (read-only) from ``grant_pin_ledger``.
GrantPin = _PINS.GrantPin

#: The seal-layer rule, reused: an unnamed grant is refused, no row lands.
resolve_seal_outcome = _PINS.resolve_seal_outcome

#: The seal layer's own error for an unnamed grant.
MissingGrantIdError = _PINS.MissingGrantIdError


def _digest_bytes(data: bytes) -> str:
    """``sha256:`` pin of the artifact's bytes, verbatim."""
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _canonical(value: Any) -> bytes:
    """Canonical JSON bytes (sorted keys, compact, UTF-8)."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _require_text(value: Any, name: str, *, limit: int = _MAX_ID_CHARS) -> str:
    """A non-empty text field, free of the separators the format uses."""
    if not isinstance(value, str) or not value.strip():
        raise ArtifactAuthorityError(f"{name} must be a non-empty string")
    if len(value) > limit:
        raise ArtifactAuthorityError(f"{name} is longer than {limit} characters")
    if ";" in value or "\n" in value:
        raise ArtifactAuthorityError(
            f"{name} must not contain ';' or a newline: those separate the receipt's fields"
        )
    return value


def _require_seq(value: Any, name: str) -> int:
    """A non-negative integer seq (never a wall clock)."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise ArtifactAuthorityError(f"{name} must be an int")
    if value < 0:
        raise ArtifactAuthorityError(f"{name} must be non-negative")
    return value


def _check_past_tense(text: str) -> str:
    """Refuse a receipt text that claims present-tense authorization.

    The tokens are matched on word boundaries, so an *identifier* that
    merely contains a word (``validation-clock``) is not mistaken for a
    claim.  A word that stands on its own (``authorized``, ``valid``,
    ``permitted now``) is a claim, and is refused.
    """
    lowered = text.lower()
    for token in FORBIDDEN_NOW_TENSE:
        if re.search(r"(?<![a-z0-9])" + re.escape(token) + r"(?![a-z0-9])", lowered):
            raise PresentTenseClaimError(
                f"the receipt claims present-tense authorization ({token!r}): "
                "a receipt says what was permitted, not what is permitted now"
            )
    return text


@dataclass(frozen=True)
class Verdict:
    """The answer of one read-time check: a state and why."""

    state: str
    reason: str = ""

    def __post_init__(self) -> None:
        if self.state not in VERDICT_STATES:
            raise ArtifactAuthorityError(f"unknown verdict state: {self.state!r}")

    @property
    def is_valid(self) -> bool:
        """True only for the state that says "current"."""
        return self.state == VALID

    def to_dict(self) -> dict:
        return {"state": self.state, "reason": self.reason}


@dataclass(frozen=True)
class ArtifactReceipt:
    """The authority an artifact carries with it.

    ``artifact_digest`` is the ``sha256:`` pin of the artifact's bytes.
    ``grant`` is the three-field pin, reused verbatim from
    ``grant_pin_ledger`` -- including its nulls: a pin that could not be
    resolved is carried as it was presented.
    ``permitted_at`` is the seq at which the write was permitted (never a
    wall clock).  ``revocation_epoch`` is the grant's revocation epoch as
    read at that moment.  ``clock_id`` names the clock that produced the
    epoch and the seq; ``issuer_id`` names the body that issued the grant.
    They must differ: an epoch read off the issuer's own clock proves
    nothing about the issuer's own revocation.

    ``action`` and ``subject`` are the grant-pin identity the receipt
    permits -- the same identity a cancellation tombstone covers, so the
    read-time check can ask the tombstone set a precise question.
    """

    artifact_digest: str
    grant: GrantPin
    permitted_at: int
    revocation_epoch: int
    clock_id: str
    issuer_id: str
    action: str = "dispatch"
    subject: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.artifact_digest, str) or not self.artifact_digest.startswith("sha256:"):
            raise MalformedReceiptError("artifact_digest must be a 'sha256:' pin")
        if not isinstance(self.grant, GrantPin):
            raise MalformedReceiptError("grant must be a GrantPin")
        _require_seq(self.permitted_at, "permitted_at")
        _require_seq(self.revocation_epoch, "revocation_epoch")
        _require_text(self.clock_id, "clock_id")
        _require_text(self.issuer_id, "issuer_id")
        _require_text(self.action, "action", limit=_MAX_TEXT_CHARS)
        if self.subject:
            _require_text(self.subject, "subject", limit=_MAX_TEXT_CHARS)
        if self.clock_id == self.issuer_id:
            raise ClockNotIndependentError(
                "the epoch's clock is the issuer's own clock: an epoch read "
                "off the issuer's clock proves nothing about the issuer"
            )

    # -- the receipt's own text ------------------------------------------
    def render(self) -> str:
        """Render the receipt into its past-tense text.

        The text reads ``permitted at T`` and ends with ``check the list
        for now``.  It never asserts present-tense authorization: the
        forbidden tokens are refused here, so a receipt that says "now"
        cannot even be produced.
        """
        version = self.grant.version if self.grant.version is not None else "null"
        counter = self.grant.counter if self.grant.counter is not None else "null"
        parts = [
            f"receipt:{self.artifact_digest}",
            f"grant:{self.grant.grant_id}",
            f"version={version}",
            f"counter={counter}",
            f"{PERMITTED_AT_PREFIX}{self.permitted_at}",
            f"epoch={self.revocation_epoch}",
            f"clock={self.clock_id}",
            f"issuer={self.issuer_id}",
            f"action={self.action}",
            f"subject={self.subject}",
        ]
        text = ";".join(parts) + ";" + CHECK_THE_LIST_FOR_NOW
        return _check_past_tense(text)

    @classmethod
    def parse(cls, rendered: Any) -> "ArtifactReceipt":
        """Parse a rendered receipt back into a receipt.

        The inverse of :meth:`render`.  A receipt that was tampered with
        into claiming present-tense authorization is refused here, at the
        boundary, not at the point of use.
        """
        if not isinstance(rendered, str) or not rendered:
            raise MalformedReceiptError("a rendered receipt must be a non-empty str")
        _check_past_tense(rendered)
        parts = rendered.split(";")
        if len(parts) != 11:
            raise MalformedReceiptError("a rendered receipt must have eleven fields")
        if not parts[0].startswith("receipt:"):
            raise MalformedReceiptError("a rendered receipt must start with 'receipt:'")
        digest = parts[0][len("receipt:"):]
        if not parts[1].startswith("grant:"):
            raise MalformedReceiptError("a rendered receipt must name its grant")
        grant_id = parts[1][len("grant:"):]
        fields = {}
        for index in (2, 3, 5, 6, 7, 8, 9):
            part = parts[index]
            if "=" not in part:
                raise MalformedReceiptError("a rendered receipt field is malformed")
            key, _, value = part.partition("=")
            fields[key] = value
        if set(fields) != {
            "version", "counter", "epoch", "clock", "issuer", "action", "subject",
        }:
            raise MalformedReceiptError("a rendered receipt has the wrong fields")
        if parts[10] != CHECK_THE_LIST_FOR_NOW:
            raise MalformedReceiptError(
                "a rendered receipt must end with 'check the list for now'"
            )
        # The past-tense clause is positional: "permitted at <seq>".
        clause = parts[4]
        if not clause.startswith(PERMITTED_AT_PREFIX):
            raise MalformedReceiptError(
                "a rendered receipt must carry the past-tense clause 'permitted at <seq>'"
            )
        permitted_at_text = clause[len(PERMITTED_AT_PREFIX):]
        version = None if fields["version"] == "null" else fields["version"]
        counter: Optional[int] = None
        if fields["counter"] == "null":
            # The unresolved pin is carried verbatim, nulls included.
            counter = None
        elif fields["counter"] == "":
            raise MalformedReceiptError("a rendered counter is malformed")
        else:
            try:
                counter = int(fields["counter"])
            except ValueError as error:
                raise MalformedReceiptError("a rendered counter is not an integer") from error
        try:
            permitted_at = int(permitted_at_text)
            epoch = int(fields["epoch"])
        except ValueError as error:
            raise MalformedReceiptError("a rendered seq is not an integer") from error
        try:
            grant = GrantPin(grant_id=grant_id, version=version, counter=counter)
        except Exception as error:
            raise MalformedReceiptError(f"a rendered receipt carries a malformed pin: {error}") from error
        return cls(
            artifact_digest=digest,
            grant=grant,
            permitted_at=permitted_at,
            revocation_epoch=epoch,
            clock_id=fields["clock"],
            issuer_id=fields["issuer"],
            action=fields["action"],
            subject=fields["subject"],
        )

    # -- relations ---------------------------------------------------------
    def is_bound_to(self, artifact_bytes: Any) -> bool:
        """True when these bytes are the ones the receipt was written for."""
        if not isinstance(artifact_bytes, (bytes, bytearray)):
            return False
        return _digest_bytes(bytes(artifact_bytes)) == self.artifact_digest

    def is_superseded_by(self, other: "ArtifactReceipt") -> bool:
        """True when ``other`` is a later state of the same grant.

        The epoch is bound to the *grant*, not to a grant id string: a
        grant that was re-issued (its counter advanced) supersedes the
        receipts written against the earlier state, even though the grant
        id is unchanged.
        """
        if not isinstance(other, ArtifactReceipt):
            raise ArtifactAuthorityError("supersession is checked against a receipt")
        if other.grant.grant_id != self.grant.grant_id:
            return False
        if self.grant.counter is None or other.grant.counter is None:
            return other.revocation_epoch > self.revocation_epoch
        return other.grant.counter > self.grant.counter

    def to_dict(self) -> dict:
        return {
            "schema_version": SCHEMA_PIN,
            "artifact_digest": self.artifact_digest,
            "grant": self.grant.to_dict(),
            "permitted_at": self.permitted_at,
            "revocation_epoch": self.revocation_epoch,
            "clock_id": self.clock_id,
            "issuer_id": self.issuer_id,
            "action": self.action,
            "subject": self.subject,
        }


# ---------------------------------------------------------------------------
# Binding: the receipt is written for the bytes it permits
# ---------------------------------------------------------------------------


def bind(
    artifact_bytes: Any,
    grant_pin: Any,
    permitted_at_seq: int,
    epoch: int,
    clock_id: str,
    issuer_id: str,
    *,
    action: str = "dispatch",
    subject: str = "",
) -> ArtifactReceipt:
    """Bind the authority to the bytes: write the receipt that travels with them.

    The rules, all fail-closed:

    * an **unnamed grant** is refused and *no receipt lands* -- the same
      rule the seal layer applies (:func:`resolve_seal_outcome` decides
      it, so there is one home for it);
    * a grant that cannot be resolved (a null counter) is carried
      **verbatim**, nulls included -- the receipt says what was presented,
      it never rewrites the pin to hide the absence;
    * ``clock_id == issuer_id`` is refused: the epoch must come from a
      clock the issuer does not own;
    * the receipt's own text is past tense, always.
    """
    if not isinstance(artifact_bytes, (bytes, bytearray)):
        raise ArtifactAuthorityError("artifact_bytes must be bytes")
    if not isinstance(grant_pin, GrantPin):
        raise MalformedReceiptError("grant must be a GrantPin")
    # The seal layer's rule, applied here: an unnamed grant is refused
    # before anything is written, so a refused bind leaves no receipt.
    try:
        resolve_seal_outcome(grant_pin, "executed")
    except MissingGrantIdError as error:
        raise UnnamedGrantError(str(error)) from error
    receipt = ArtifactReceipt(
        artifact_digest=_digest_bytes(bytes(artifact_bytes)),
        grant=grant_pin,
        permitted_at=_require_seq(permitted_at_seq, "permitted_at_seq"),
        revocation_epoch=_require_seq(epoch, "epoch"),
        clock_id=_require_text(clock_id, "clock_id"),
        issuer_id=_require_text(issuer_id, "issuer_id"),
        action=_require_text(action, "action", limit=_MAX_TEXT_CHARS),
        subject=subject or "",
    )
    # The rendering is checked once here, so a receipt that could not be
    # rendered in the past tense never leaves this function.
    receipt.render()
    return receipt


# ---------------------------------------------------------------------------
# The sealed container: the receipt travels with the bytes
# ---------------------------------------------------------------------------


def seal_bytes(artifact_bytes: Any, receipt: ArtifactReceipt) -> bytes:
    """Seal the bytes and their receipt into one container.

    The container is the artifact: the bytes travel with the receipt that
    names the grant that permitted them.  A reader who has only the
    container can still see *what permitted this* and *when it was
    permitted* -- the expiry is visible in the artifact itself, not only
    in whatever list the reader happens to consult.
    """
    if not isinstance(artifact_bytes, (bytes, bytearray)):
        raise ArtifactAuthorityError("artifact_bytes must be bytes")
    if not isinstance(receipt, ArtifactReceipt):
        raise MalformedReceiptError("receipt must be an ArtifactReceipt")
    if not receipt.is_bound_to(artifact_bytes):
        raise MalformedReceiptError(
            "this receipt does not describe these bytes: the seal is refused"
        )
    return (
        SEAL_PREFIX
        + receipt.render().encode("utf-8")
        + b"\n"
        + bytes(artifact_bytes)
    )


def open_sealed(container: Any) -> Tuple[bytes, ArtifactReceipt]:
    """Open a sealed container: the bytes and the receipt that came with them.

    The container's bytes are checked against the receipt's digest *here*:
    a container whose bytes were changed after the seal does not open --
    it raises, instead of handing back bytes no receipt describes.
    """
    if not isinstance(container, (bytes, bytearray)):
        raise ArtifactAuthorityError("a sealed container must be bytes")
    data = bytes(container)
    if not data.startswith(SEAL_PREFIX):
        raise MalformedReceiptError("not a sealed artifact container")
    rest = data[len(SEAL_PREFIX):]
    newline = rest.find(b"\n")
    if newline < 0:
        raise MalformedReceiptError("a sealed container must carry its receipt")
    try:
        receipt = ArtifactReceipt.parse(rest[:newline].decode("utf-8"))
    except UnicodeDecodeError as error:
        raise MalformedReceiptError("a sealed container's receipt is not utf-8") from error
    payload = rest[newline + 1:]
    if not receipt.is_bound_to(payload):
        raise MalformedReceiptError(
            "the container's bytes do not match the receipt: the artifact was "
            "changed after it was sealed"
        )
    return payload, receipt


# ---------------------------------------------------------------------------
# Verification: the read-time check
# ---------------------------------------------------------------------------


def _tombstones_of(tombstone_set: Any) -> Iterable[Any]:
    """The tombstones of a set (or of any iterable of tombstones)."""
    if tombstone_set is None:
        return ()
    lister = getattr(tombstone_set, "list", None)
    if callable(lister):
        return lister()
    if isinstance(tombstone_set, (str, bytes)):
        raise ArtifactAuthorityError("a tombstone set must not be a string")
    try:
        return tuple(tombstone_set)
    except TypeError as error:
        raise ArtifactAuthorityError("a tombstone set must be iterable") from error


def _covering_tombstone(receipt: ArtifactReceipt, tombstone_set: Any) -> Any:
    """The tombstone that names the action this receipt permits, if any.

    The question asked is the grant-pin identity -- ``grant_id`` +
    ``action`` + ``subject`` -- the same identity the sealed ledger and
    the tombstone set use, so the check is never made against prose.
    """
    for tombstone in _tombstones_of(tombstone_set):
        covers = getattr(tombstone, "covers", None)
        if not callable(covers):
            raise ArtifactAuthorityError("a tombstone must expose covers()")
        if covers(receipt.grant.grant_id, receipt.action, receipt.subject):
            return tombstone
    return None


def verify(
    receipt: Any,
    epoch_now: int,
    tombstone_set: Any = None,
    *,
    artifact_bytes: Any = None,
    current_grant: Any = None,
) -> Verdict:
    """Read a receipt against the state that is true *now*.

    The verdicts:

    * ``UNNAMED`` -- the receipt's grant was never named; nothing it says
      can be about a permission.
    * ``UNBOUND`` -- the bytes no longer match the receipt's digest: the
      artifact was changed after it was sealed.
    * ``REVOKED`` -- a live tombstone names the action the receipt
      permits.  This is a **read-time** check: a tombstone declared after
      the seal still catches the receipt.
    * ``STALE`` -- the grant's revocation epoch has moved on (the epoch
      the receipt was sealed under is behind ``epoch_now``), or the grant
      itself has been re-issued (its counter advanced).
    * ``VALID`` -- none of the above.

    A ``STALE`` or ``REVOKED`` receipt never silently becomes ``VALID``:
    the epoch only moves forward, and a tombstone is checked on every
    read, not only at seal time.
    """
    if not isinstance(receipt, ArtifactReceipt):
        raise ArtifactAuthorityError("verify is given a receipt")
    _require_seq(epoch_now, "epoch_now")
    if not receipt.grant.is_named():
        return Verdict(UNNAMED, "the receipt's grant was never named")
    if artifact_bytes is not None and not receipt.is_bound_to(artifact_bytes):
        return Verdict(
            UNBOUND, "the bytes do not match the receipt: the artifact changed after the seal"
        )
    if current_grant is not None:
        if not isinstance(current_grant, GrantPin):
            raise ArtifactAuthorityError("current_grant must be a GrantPin")
        if current_grant.grant_id == receipt.grant.grant_id:
            if receipt.grant.counter is not None and current_grant.counter is not None:
                if current_grant.counter > receipt.grant.counter:
                    return Verdict(
                        STALE, "the grant was re-issued: its counter moved past the receipt"
                    )
            elif receipt.grant.counter is None and current_grant.counter is not None:
                return Verdict(
                    STALE, "the grant became resolvable after the receipt was written"
                )
    tombstone = _covering_tombstone(receipt, tombstone_set)
    if tombstone is not None:
        return Verdict(
            REVOKED,
            f"a live tombstone names {receipt.grant.grant_id!r}/{receipt.action!r}",
        )
    if epoch_now > receipt.revocation_epoch:
        return Verdict(
            STALE,
            f"the revocation epoch moved on: the receipt was sealed under epoch "
            f"{receipt.revocation_epoch}, the world is at {epoch_now}",
        )
    return Verdict(VALID, "the receipt's grant is still live at this epoch")


# ---------------------------------------------------------------------------
# The receipt ledger: receipts that were written, kept with their artifacts
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SealedArtifact:
    """One sealed artifact: the bytes and the receipt that travels with them."""

    seq: int
    container: bytes
    receipt: ArtifactReceipt

    def open(self) -> bytes:
        """The bytes this artifact carries, checked against its receipt."""
        payload, _ = open_sealed(self.container)
        return payload


class ArtifactAuthorityLedger:
    """The ledger of artifacts that carry their own authority.

    ``bind_and_seal(bytes, pin, ...)`` writes one receipt and seals the
    bytes with it; a refused bind (an unnamed grant, or the issuer's own
    clock) lands **nothing**.  ``verify(seq, epoch_now, tombstones)`` reads
    a sealed artifact back and checks it against the state that is true
    now.
    """

    def __init__(self) -> None:
        self._artifacts: list[SealedArtifact] = []

    def __len__(self) -> int:
        return len(self._artifacts)

    @property
    def artifacts(self) -> Tuple[SealedArtifact, ...]:
        return tuple(self._artifacts)

    def bind_and_seal(
        self,
        artifact_bytes: Any,
        grant_pin: Any,
        permitted_at_seq: int,
        epoch: int,
        clock_id: str,
        issuer_id: str,
        *,
        action: str = "dispatch",
        subject: str = "",
    ) -> SealedArtifact:
        """Bind the authority to the bytes and seal them together.

        A refused bind lands nothing: the ledger keeps no unnamed hole.
        """
        receipt = bind(
            artifact_bytes,
            grant_pin,
            permitted_at_seq,
            epoch,
            clock_id,
            issuer_id,
            action=action,
            subject=subject,
        )
        container = seal_bytes(artifact_bytes, receipt)
        artifact = SealedArtifact(
            seq=len(self._artifacts) + 1, container=container, receipt=receipt
        )
        self._artifacts.append(artifact)
        return artifact

    def artifact(self, seq: int) -> SealedArtifact:
        """The sealed artifact with 1-based ``seq``."""
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise ArtifactAuthorityError("seq must be an int")
        if seq < 1 or seq > len(self._artifacts):
            raise ArtifactAuthorityError("unknown seq")
        return self._artifacts[seq - 1]

    def verify(
        self,
        seq: int,
        epoch_now: int,
        tombstone_set: Any = None,
    ) -> Verdict:
        """Read one sealed artifact back and check it against the present."""
        artifact = self.artifact(seq)
        payload, receipt = open_sealed(artifact.container)
        return verify(
            receipt,
            epoch_now,
            tombstone_set,
            artifact_bytes=payload,
        )


def stdlib_only() -> bool:
    """AST check: this module imports stdlib modules only."""
    tree = ast.parse(
        Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {
        "__future__",
        "ast",
        "dataclasses",
        "hashlib",
        "importlib",
        "json",
        "pathlib",
        "re",
        "sys",
        "typing",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    """Self-check: seal, read back, revoke, tamper."""
    ledger = ArtifactAuthorityLedger()
    payload = b"artifact-bytes"
    artifact = ledger.bind_and_seal(
        payload,
        GrantPin("grant-1", "v2", 7),
        permitted_at_seq=3,
        epoch=3,
        clock_id="host-clock",
        issuer_id="issuer-a",
    )
    assert ledger.verify(1, epoch_now=3).state == VALID
    assert ledger.verify(1, epoch_now=4).state == STALE
    tampered = artifact.container[:-1] + b"X"
    try:
        open_sealed(tampered)
        raise AssertionError("should raise")
    except MalformedReceiptError:
        pass
    assert stdlib_only()
    print(
        "artifact-authority OK: sealed receipt valid at epoch 3, stale at 4, "
        "tamper refused, stdlib"
    )


if __name__ == "__main__":
    main()

