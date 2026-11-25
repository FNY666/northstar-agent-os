"""Authorization is a BOUNDARY, not a prompt: a scope that only narrows, an
expiry, and a delegation-time re-check.

Two sources, quoted verbatim in ``docs/design/agent-authorization-boundary.md``:

* agent-guard (https://github.com/agent-rails/agent-guard): "Policy is
  evaluated before the tool runs; denied calls never reach the tool;
  approval-required calls fail closed without an approver; and the decision is
  written to an audit sink." ... "Authority is evaluated outside the prompt.
  The model can request an action, but prompt text is not itself an
  authorization rule." ... "An approver must return an ApprovalGrant with the
  same call ID and digest; plain True values and stale grants fail closed."
* Steward (https://github.com/Mohil-Ahuja/Steward): "Steward is a policy
  decision point and enforcement point for that boundary."

What this module ADDS to those sources (a Northstar extension, not a source
claim): the scope carries an expiry, the scope can only ever be NARROWED, and
the boundary is re-checked at DELEGATION time, not only at call time.  The
third one is prompted by a community counter-example recorded in the survey
(a sub-agent that inherits a parent's token inherits its staleness too), and
the survey's own verdict says so explicitly: "Northstar's boundary object
carries a *scope* that can only be narrowed, and re-checks the boundary at
delegation time. agent-guard does not claim either."

The invariants this module exists to make true:

1. **Authorization is decided before the tool runs.**  :meth:`BoundaryCheck.
   authorize` decides; :meth:`BoundaryCheck.execute` acts.  They are two
   steps, so a denied call provably never reaches the tool.
2. **A denied call never touches the tool.**  ``execute`` refuses to call
   ``fn`` for a ``denied`` verdict, and the refusal is observable because the
   callable is never invoked.
3. **Approval-required without an approver fails CLOSED.**  A verdict of
   ``require_human`` with no matching :class:`ApprovalGrant` is a denial,
   not an advisory and not a pass.
4. **The scope can only shrink.**  ``narrow_to`` refuses any request that
   would widen the resource prefixes, the action set, or the tool set.
5. **An expired or revoked boundary authorizes nothing.**  Expiry is
   evaluated against a caller-supplied timestamp; this module never reads a
   clock.
6. **Every decision leaves an auditable line.**  Each authorization produces
   a :class:`DecisionRecord` carrying the verdict, the boundary it matched
   (or did not), and a reason code.

House style: frozen dataclasses, no wall-clock (the caller supplies the
timestamp), fail-closed taxonomy, stdlib-only, ``sha256:`` digest pins,
``main()`` self-check.

Version pin: ``agent-boundary.v1``
Schema pin: ``northstar.agent-boundary.v1``
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
from typing import Any, Callable, Iterable, Mapping, Optional, Sequence

__all__ = [
    "VERDICT_ALLOWED",
    "VERDICT_DENIED",
    "VERDICT_REQUIRE_HUMAN",
    "REASON_NO_BOUNDARY",
    "REASON_SCOPE_MISMATCH",
    "REASON_EXPIRED",
    "REASON_REVOKED",
    "REASON_APPROVAL_REQUIRED",
    "REASON_APPROVAL_INVALID",
    "REASON_APPROVAL_EXPIRED",
    "REASON_DELEGATION_EXPIRED",
    "REASON_DELEGATION_NOT_ALLOWED",
    "REASON_INVALID_INPUT",
    "REASON_NOT_YET_ACTIVE",
    "BoundaryError",
    "ScopeWideningError",
    "InvalidBoundaryError",
    "ApprovalRequiredError",
    "BoundaryScope",
    "AuthorizationBoundary",
    "ApprovalGrant",
    "BoundaryRegistry",
    "DecisionRecord",
    "BoundaryCheck",
]

# --- verdicts ---------------------------------------------------------------

VERDICT_ALLOWED = "allowed"
VERDICT_DENIED = "denied"
VERDICT_REQUIRE_HUMAN = "require_human"

# --- reason codes -----------------------------------------------------------
#
# Every decision line names ONE of these.  They are strings, not an enum, so
# that an audit sink can store them without importing this module.

REASON_NO_BOUNDARY = "no_boundary"
REASON_SCOPE_MISMATCH = "scope_mismatch"
REASON_EXPIRED = "expired"
REASON_REVOKED = "revoked"
REASON_APPROVAL_REQUIRED = "approval_required"
REASON_APPROVAL_INVALID = "approval_invalid"
REASON_APPROVAL_EXPIRED = "approval_expired"
REASON_DELEGATION_EXPIRED = "delegation_expired"
REASON_DELEGATION_NOT_ALLOWED = "delegation_not_allowed"
REASON_INVALID_INPUT = "invalid_input"
REASON_NOT_YET_ACTIVE = "not_yet_active"


class BoundaryError(Exception):
    """Base class for every refusal this module raises."""


class ScopeWideningError(BoundaryError):
    """Raised when a narrowing request would WIDEN the scope.

    Raised, never silently ignored: a caller that asked to widen a scope and
    got a wider scope would be authorizing something nobody granted.
    """


class InvalidBoundaryError(BoundaryError):
    """Raised on structurally invalid input (empty scope, non-string id)."""


class ApprovalRequiredError(BoundaryError):
    """Raised when a call needs human approval and the grant is absent.

    This is the fail-closed path: "approval-required calls fail closed
    without an approver".  The exception is the closure; it is never an
    advisory.
    """

    def __init__(self, message: str, record: "DecisionRecord") -> None:
        super().__init__(message)
        self.record = record


# --- helpers ----------------------------------------------------------------


def _require_text(value: Any, field: str) -> str:
    """Return ``value`` if it is a non-empty string, else raise.

    Every public constructor runs its inputs through this.  A boundary with an
    empty id is representable only long enough to be REFUSED -- exactly the
    rule ``grant_pin_ledger`` states for its grant id: "an audit row that says
    nothing about what it authorized is worse than no row at all, because it
    looks like evidence."
    """
    if not isinstance(value, str):
        raise InvalidBoundaryError(f"{field} must be a string, got {type(value).__name__}")
    if not value.strip():
        raise InvalidBoundaryError(f"{field} must not be empty")
    return value


def _require_text_tuple(values: Any, field: str) -> tuple:
    """Return a sorted, de-duplicated tuple of non-empty strings."""
    if values is None:
        raise InvalidBoundaryError(f"{field} must not be None")
    if isinstance(values, str):
        raise InvalidBoundaryError(f"{field} must be a sequence of strings, not a string")
    try:
        items = list(values)
    except TypeError:
        raise InvalidBoundaryError(f"{field} must be an iterable of strings")
    out = set()
    for item in items:
        if not isinstance(item, str):
            raise InvalidBoundaryError(
                f"{field} entries must be strings, got {type(item).__name__}")
        if not item.strip():
            raise InvalidBoundaryError(f"{field} entries must not be empty")
        out.add(item)
    return tuple(sorted(out))


def _covers(prefix: str, resource: str) -> bool:
    """True when ``prefix`` covers ``resource`` on a PATH BOUNDARY.

    A bare ``startswith`` would let "/workspace" cover "/workspaces/a" --
    a sibling directory, not a sub-path.  The prefix must match the whole
    path or a whole leading SEGMENT of it, so the boundary is a separator.
    """
    if prefix == resource:
        return True
    if not prefix.endswith("/"):
        prefix = prefix + "/"
    return resource.startswith(prefix)


def _digest(*parts: str) -> str:
    """Return a ``sha256:`` digest over the NUL-joined parts.

    A digest over the WHOLE identity, never over a prefix: a truncated
    identifier is not injective, so two different grants could share a pin.
    """
    h = hashlib.sha256()
    for part in parts:
        h.update(part.encode("utf-8"))
        h.update(b"\x00")
    return "sha256:" + h.hexdigest()


@dataclasses.dataclass(frozen=True)
class BoundaryScope:
    """An immutable description of WHAT a boundary authorizes.

    Three independent axes, each a set of names:

    * ``resource_prefixes`` -- the filesystem/resource prefixes the grant
      covers;
    * ``actions`` -- the verbs the grant covers;
    * ``allowed_tools`` -- the tool names the grant covers;
    * ``denied_tools`` -- tool names that are NEVER covered, whatever the
      other axes say.

    ``denied_tools`` wins over everything.  That asymmetry is what makes
    narrowing monotone: a narrowed scope can only ever remove capabilities,
    never add one, so a deny can never be lost by a narrowing.
    """

    resource_prefixes: tuple = ()
    actions: tuple = ()
    allowed_tools: tuple = ()
    denied_tools: tuple = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "resource_prefixes",
                           _require_text_tuple(self.resource_prefixes, "resource_prefixes"))
        object.__setattr__(self, "actions",
                           _require_text_tuple(self.actions, "actions"))
        object.__setattr__(self, "allowed_tools",
                           _require_text_tuple(self.allowed_tools, "allowed_tools"))
        object.__setattr__(self, "denied_tools",
                           _require_text_tuple(self.denied_tools, "denied_tools"))
        if not (self.resource_prefixes or self.actions or self.allowed_tools):
            raise InvalidBoundaryError(
                "scope must name at least one resource prefix, action or tool")

    # -- narrowing ---------------------------------------------------------

    def _is_subset(self, other: "BoundaryScope") -> bool:
        """True when ``self`` is NO BROADER than ``other``.

        So ``self._is_subset(other)`` means "self fits inside other".

        The rule is stated in BEHAVIOUR terms, not in set terms, because the
        two differ and the behavioural one is the one that matters.  An axis
        with an EMPTY set does not constrain that axis: a scope with no
        ``allowed_tools`` places no restriction on which tool may run.

        So for the three "capability" axes (resource prefixes, actions,
        allowed tools) the cases are:

        * self empty, other non-empty -> self is BROADER (it constrains
          nothing where other constrains something) -> NOT a subset;
        * self non-empty, other empty -> self is narrower -> a subset;
        * both non-empty -> the usual set containment.

        For ``denied_tools`` the direction is the other way: MORE denials is
        narrower, so self must CONTAIN other -- a narrowing may add a
        denial but never drop one.

        The set-only version of this rule (plain ``<=`` on every axis) has a
        hole that matters: it treats "drop the action axis" as a narrowing,
        when dropping the axis actually RELEASES every action.  This
        behavioural rule closes that hole.
        """
        # Resource prefixes are HIERARCHICAL, not set members: "/workspace/sub"
        # is narrower than "/workspace", so the test is that every prefix in
        # self is covered by some prefix in other, not that it is a member.
        mine = set(self.resource_prefixes)
        theirs = set(other.resource_prefixes)
        if mine:
            if theirs and not any(
                p.startswith(q) for p in mine for q in theirs
            ):
                return False
        elif theirs:
            return False
        for axis in ("actions", "allowed_tools"):
            mine = set(getattr(self, axis))
            theirs = set(getattr(other, axis))
            if not mine:
                if theirs:
                    return False
                continue
            if not theirs:
                continue
            if not mine <= theirs:
                return False
        return set(self.denied_tools) >= set(other.denied_tools)

    def narrowed_to(
        self,
        resource_prefixes: Optional[Iterable[str]] = None,
        actions: Optional[Iterable[str]] = None,
        allowed_tools: Optional[Iterable[str]] = None,
        denied_tools: Optional[Iterable[str]] = None,
    ) -> "BoundaryScope":
        """Return a NEW scope that is no broader than ``self``.

        Any axis left as ``None`` is carried over unchanged.  A request that
        would widen an axis raises :class:`ScopeWideningError` -- it does not
        return a wider scope, and it does not return the old scope either,
        because a caller that asked to widen and got "the old one" would have
        no signal that the request was refused.
        """
        candidate = BoundaryScope(
            resource_prefixes=self.resource_prefixes if resource_prefixes is None
            else resource_prefixes,
            actions=self.actions if actions is None else actions,
            allowed_tools=self.allowed_tools if allowed_tools is None else allowed_tools,
            denied_tools=self.denied_tools if denied_tools is None else denied_tools,
        )
        if not candidate._is_subset(self):
            raise ScopeWideningError(
                "narrowing refused: the requested scope is broader than the "
                "current one")
        return candidate

    # -- matching ----------------------------------------------------------

    def is_satisfied_by(
        self,
        action: str,
        tool: Optional[str] = None,
        resource: Optional[str] = None,
    ) -> bool:
        """True when ``action``/``tool``/``resource`` fall inside this scope.

        An axis that the scope does not constrain does not veto.  A scope
        with no ``allowed_tools`` constrains no tool; a scope with no
        ``actions`` constrains no action.  This is what makes "the scope can
        only shrink" expressible: dropping an axis from ``allowed_tools``
        would widen the scope, and :meth:`narrowed_to` refuses that.
        """
        if self.denied_tools and tool in self.denied_tools:
            return False
        if self.actions and action not in self.actions:
            return False
        if self.allowed_tools and tool is not None and tool not in self.allowed_tools:
            return False
        prefixes = self.resource_prefixes
        if prefixes:
            # The scope constrains resources, so the call must name one and it
            # must fall under a covered prefix.
            if resource is None:
                return False
            if not any(_covers(p, resource) for p in prefixes):
                return False
        return True

    def as_dict(self) -> dict:
        return {
            "resource_prefixes": list(self.resource_prefixes),
            "actions": list(self.actions),
            "allowed_tools": list(self.allowed_tools),
            "denied_tools": list(self.denied_tools),
        }


@dataclasses.dataclass(frozen=True)
class ApprovalGrant:
    """A human approval, bound to exactly one call.

    "An approver must return an ApprovalGrant with the same call ID and
    digest; plain True values and stale grants fail closed."  So a grant
    carries ``call_id`` and ``digest``, and both are compared.  A plain
    ``True`` is not a grant at all -- it has no call id and no digest, so it
    cannot be one.
    """

    call_id: str
    digest: str
    issued_at: int
    expires_at: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "call_id", _require_text(self.call_id, "call_id"))
        object.__setattr__(self, "digest", _require_text(self.digest, "digest"))
        for field in ("issued_at", "expires_at"):
            value = getattr(self, field)
            if isinstance(value, bool) or not isinstance(value, int):
                raise InvalidBoundaryError(f"{field} must be an int")
        if self.expires_at < self.issued_at:
            raise InvalidBoundaryError("expires_at must not precede issued_at")

    def is_valid_at(self, ts: int) -> bool:
        """True when this grant is unexpired at ``ts``."""
        return self.issued_at <= ts <= self.expires_at

    def matches(self, call_id: str, digest: str) -> bool:
        """True when this grant binds exactly this call."""
        return self.call_id == call_id and self.digest == digest

    def as_dict(self) -> dict:
        return {
            "call_id": self.call_id,
            "digest": self.digest,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
        }


@dataclasses.dataclass(frozen=True)
class AuthorizationBoundary:
    """One authorization: WHO may do WHAT, until WHEN, on WHICH evidence.

    The object is frozen.  Narrowing produces a NEW boundary
    (:meth:`narrow_to`); revocation produces a NEW boundary
    (:meth:`revoke`).  Neither mutates the original, so a decision that
    matched the original can always be explained by the original.

    States: ``valid``, ``expired``, ``revoked``, ``narrowed``.  The state is
    not a stored field -- it is DERIVED from ``revoked_at`` and the
    caller's timestamp -- because a stored state would need a clock to
    advance it, and this module never reads a clock.
    """

    boundary_id: str
    scope: BoundaryScope
    subject: str
    grantee: str
    issued_at: int
    expires_at: int
    evidence_digest: str
    revoked_at: Optional[int] = None
    revoke_reason: Optional[str] = None
    parent_boundary_id: Optional[str] = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "boundary_id",
                           _require_text(self.boundary_id, "boundary_id"))
        object.__setattr__(self, "subject", _require_text(self.subject, "subject"))
        object.__setattr__(self, "grantee", _require_text(self.grantee, "grantee"))
        object.__setattr__(self, "evidence_digest",
                           _require_text(self.evidence_digest, "evidence_digest"))
        if not isinstance(self.scope, BoundaryScope):
            raise InvalidBoundaryError("scope must be a BoundaryScope")
        for field in ("issued_at", "expires_at"):
            value = getattr(self, field)
            if isinstance(value, bool) or not isinstance(value, int):
                raise InvalidBoundaryError(f"{field} must be an int")
        if self.expires_at < self.issued_at:
            raise InvalidBoundaryError("expires_at must not precede issued_at")
        if self.revoked_at is not None:
            if isinstance(self.revoked_at, bool) or not isinstance(self.revoked_at, int):
                raise InvalidBoundaryError("revoked_at must be an int or None")

    # -- state -------------------------------------------------------------

    @property
    def state(self) -> str:
        """The CURRENT state, derived from the caller's timestamp."""
        if self.revoked_at is not None:
            return "revoked"
        return "valid"

    def is_valid_at(self, ts: int) -> bool:
        """True when this boundary authorizes something at ``ts``.

        A revoked boundary is never valid.  An expired one is not valid at
        any ``ts`` after ``expires_at``.
        """
        if self.revoked_at is not None:
            return False
        if isinstance(ts, bool) or not isinstance(ts, int):
            raise InvalidBoundaryError("ts must be an int")
        return self.issued_at <= ts <= self.expires_at

    def is_expired_at(self, ts: int) -> bool:
        """True when this boundary's expiry has passed at ``ts``."""
        return ts > self.expires_at

    # -- transitions -------------------------------------------------------

    def narrow_to(
        self,
        boundary_id: str,
        scope: BoundaryScope,
        issued_at: int,
        expires_at: Optional[int] = None,
        grantee: Optional[str] = None,
    ) -> "AuthorizationBoundary":
        """Return a NEW boundary with a no-broader scope.

        The new boundary inherits ``subject`` and ``evidence_digest`` from
        this one, records ``parent_boundary_id``, and keeps the parent's
        expiry ceiling: a narrowing can shorten a life but never extend it.
        A request to widen raises :class:`ScopeWideningError`.
        """
        if not isinstance(scope, BoundaryScope):
            raise InvalidBoundaryError("scope must be a BoundaryScope")
        if not scope._is_subset(self.scope):
            raise ScopeWideningError(
                "narrowing refused: the requested scope is broader than the "
                "parent boundary's")
        if expires_at is None:
            expires_at = self.expires_at
        if expires_at > self.expires_at:
            raise ScopeWideningError(
                "narrowing refused: the requested expiry is later than the "
                "parent boundary's")
        if expires_at < issued_at:
            raise InvalidBoundaryError("expires_at must not precede issued_at")
        return AuthorizationBoundary(
            boundary_id=_require_text(boundary_id, "boundary_id"),
            scope=scope,
            subject=self.subject,
            grantee=self.grantee if grantee is None else _require_text(grantee, "grantee"),
            issued_at=issued_at,
            expires_at=expires_at,
            evidence_digest=self.evidence_digest,
            parent_boundary_id=self.boundary_id,
        )

    def revoke(self, ts: int, reason: str) -> "AuthorizationBoundary":
        """Return a NEW boundary that is revoked at ``ts``.

        Revocation never mutates the original, so a decision that was ALLOWED
        under the original can still be explained by it.
        """
        # The timestamp's type is checked by ``AuthorizationBoundary``'s own
        # validation, which refuses a bool as well as a non-int (a bool IS
        # an int in Python).  Checking it here as well would be dead code:
        # a mutant of a redundant guard changes nothing an observer can see.
        reason = _require_text(reason, "reason")
        return dataclasses.replace(self, revoked_at=ts, revoke_reason=reason)

    def as_dict(self) -> dict:
        return {
            "boundary_id": self.boundary_id,
            "scope": self.scope.as_dict(),
            "subject": self.subject,
            "grantee": self.grantee,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "evidence_digest": self.evidence_digest,
            "revoked_at": self.revoked_at,
            "revoke_reason": self.revoke_reason,
            "parent_boundary_id": self.parent_boundary_id,
        }


@dataclasses.dataclass(frozen=True)
class DecisionRecord:
    """The auditable line left by every authorization decision.

    "the decision is written to an audit sink" -- this is what is written.
    It carries the verdict, the boundary that matched (or the reason none
    did), the reason code, and the call identity, so a reader can tell a
    denial from a non-match from an expiry without consulting anything else.
    """

    call_id: str
    action: str
    tool: Optional[str]
    verdict: str
    reason: str
    boundary_id: Optional[str]
    grantee: Optional[str]
    timestamp: int
    digest: str

    @property
    def allowed(self) -> bool:
        return self.verdict == VERDICT_ALLOWED

    @property
    def denied(self) -> bool:
        return self.verdict == VERDICT_DENIED

    def as_line(self) -> str:
        """Return the one-line audit rendering of this decision."""
        return json.dumps(
            {
                "call_id": self.call_id,
                "action": self.action,
                "tool": self.tool,
                "verdict": self.verdict,
                "reason": self.reason,
                "boundary_id": self.boundary_id,
                "grantee": self.grantee,
                "timestamp": self.timestamp,
                "digest": self.digest,
            },
            sort_keys=True,
            separators=(",", ":"),
        )

    def as_dict(self) -> dict:
        return json.loads(self.as_line())


class BoundaryRegistry:
    """A store of boundaries, keyed by ``boundary_id``.

    The registry is where a NARROWED boundary and its parent both live: the
    narrowing does not replace the parent, it adds a sibling that records
    ``parent_boundary_id``.  Both remain retrievable, so "who narrowed what,
    and when" stays answerable.
    """

    def __init__(self) -> None:
        self._by_id: dict = {}

    def issue(
        self,
        boundary_id: str,
        scope: BoundaryScope,
        subject: str,
        grantee: str,
        issued_at: int,
        expires_at: int,
        evidence_digest: Optional[str] = None,
        parent_boundary_id: Optional[str] = None,
    ) -> AuthorizationBoundary:
        """Create and store a new boundary.

        ``evidence_digest`` may be omitted; the registry then derives one
        from the boundary's own identity fields, so the field is never
        empty.
        """
        boundary_id = _require_text(boundary_id, "boundary_id")
        if boundary_id in self._by_id:
            raise InvalidBoundaryError(f"boundary_id already issued: {boundary_id}")
        if evidence_digest is None:
            evidence_digest = _digest(boundary_id, subject, grantee, str(issued_at))
        boundary = AuthorizationBoundary(
            boundary_id=boundary_id,
            scope=scope,
            subject=subject,
            grantee=grantee,
            issued_at=issued_at,
            expires_at=expires_at,
            evidence_digest=evidence_digest,
            parent_boundary_id=parent_boundary_id,
        )
        self._by_id[boundary_id] = boundary
        return boundary

    def get(self, boundary_id: str) -> Optional[AuthorizationBoundary]:
        """Return the boundary with this id, or ``None``."""
        if not isinstance(boundary_id, str):
            raise InvalidBoundaryError("boundary_id must be a string")
        return self._by_id.get(boundary_id)

    def narrow(
        self,
        parent_boundary_id: str,
        boundary_id: str,
        scope: BoundaryScope,
        issued_at: int,
        expires_at: Optional[int] = None,
        grantee: Optional[str] = None,
    ) -> AuthorizationBoundary:
        """Narrow a stored boundary and store the RESULT as a new boundary."""
        parent = self.get(parent_boundary_id)
        if parent is None:
            raise InvalidBoundaryError(f"no such boundary: {parent_boundary_id}")
        child = parent.narrow_to(
            boundary_id=boundary_id,
            scope=scope,
            issued_at=issued_at,
            expires_at=expires_at,
            grantee=grantee,
        )
        if boundary_id in self._by_id:
            raise InvalidBoundaryError(f"boundary_id already issued: {boundary_id}")
        self._by_id[boundary_id] = child
        return child

    def revoke(self, boundary_id: str, ts: int, reason: str) -> AuthorizationBoundary:
        """Revoke a stored boundary; the revoked copy REPLACES the entry."""
        current = self.get(boundary_id)
        if current is None:
            raise InvalidBoundaryError(f"no such boundary: {boundary_id}")
        revoked = current.revoke(ts=ts, reason=reason)
        self._by_id[boundary_id] = revoked
        return revoked

    def expire_stale(self, now: int) -> tuple:
        """Return the ids of the boundaries that are expired at ``now``.

        Expiry is not a mutation: an expired boundary is already invalid, so
        this REPORTS which ones have lapsed rather than rewriting them.  The
        reason code for an expired boundary is the same either way.
        """
        if isinstance(now, bool) or not isinstance(now, int):
            raise InvalidBoundaryError("now must be an int")
        return tuple(
            sorted(
                bid for bid, b in self._by_id.items()
                if b.revoked_at is None and b.is_expired_at(now)
            )
        )

    def all(self) -> tuple:
        """Return every stored boundary, sorted by id."""
        return tuple(self._by_id[k] for k in sorted(self._by_id))

    def __len__(self) -> int:
        return len(self._by_id)


class BoundaryCheck:
    """The pre-execution decision point.

    The two steps are SEPARATE ON PURPOSE:

    * :meth:`authorize` decides and returns a :class:`DecisionRecord`;
    * :meth:`execute` acts, and it acts ONLY on an ``allowed`` verdict.

    That separation is what makes "denied calls never reach the tool"
    checkable rather than merely asserted: :meth:`execute` does not call the
    callable for a denied verdict, and the test suite proves it with a
    callable that would record having been called.

    The check never reads a clock.  Every method that needs "now" takes a
    ``timestamp`` argument.
    """

    def __init__(self, registry: Optional[BoundaryRegistry] = None) -> None:
        self._registry = registry if registry is not None else BoundaryRegistry()
        self._decisions: list = []

    @property
    def registry(self) -> BoundaryRegistry:
        return self._registry

    @property
    def decisions(self) -> tuple:
        """Every decision this check has produced, in order."""
        return tuple(self._decisions)

    def audit_lines(self) -> tuple:
        """Every decision as an audit line, in order."""
        return tuple(d.as_line() for d in self._decisions)

    # -- helpers -----------------------------------------------------------

    @staticmethod
    def call_digest(call_id: str, action: str, tool: Optional[str],
                    resource: Optional[str]) -> str:
        """The digest an approval grant must bind to.

        It covers the call identity AND the action, so a grant for one tool
        call cannot be replayed onto a different action.
        """
        return _digest(
            _require_text(call_id, "call_id"),
            _require_text(action, "action"),
            tool or "",
            resource or "",
        )

    def _record(
        self,
        call_id: str,
        action: str,
        tool: Optional[str],
        verdict: str,
        reason: str,
        boundary: Optional[AuthorizationBoundary],
        timestamp: int,
        digest: str,
    ) -> DecisionRecord:
        record = DecisionRecord(
            call_id=call_id,
            action=action,
            tool=tool,
            verdict=verdict,
            reason=reason,
            boundary_id=boundary.boundary_id if boundary is not None else None,
            grantee=boundary.grantee if boundary is not None else None,
            timestamp=timestamp,
            digest=digest,
        )
        self._decisions.append(record)
        return record

    # -- the decision ------------------------------------------------------

    def authorize(
        self,
        call_id: str,
        action: str,
        tool: Optional[str] = None,
        resource: Optional[str] = None,
        timestamp: int = 0,
        boundary_id: Optional[str] = None,
        grant: Optional[ApprovalGrant] = None,
        requires_human: bool = False,
    ) -> DecisionRecord:
        """Decide whether a call is authorized, and record the decision.

        The order of the checks is the order of the failure taxonomy, and it
        is deliberately fail-closed at every step:

        1. no boundary at all -> ``denied`` / ``no_boundary``;
        2. the boundary is revoked -> ``denied`` / ``revoked``;
        3. the boundary has expired -> ``denied`` / ``expired``;
        4. the call falls outside the scope -> ``denied`` / ``scope_mismatch``;
        5. the call needs a human approval and there is none -> ``denied`` /
           ``approval_required`` (this is the fail-closed limb: the verdict
           is ``denied``, not ``require_human``, because the check cannot
           proceed);
        6. the grant is present but binds a different call or a different
           digest -> ``denied`` / ``approval_invalid``;
        7. the grant has expired -> ``denied`` / ``approval_expired``;
        8. otherwise -> ``allowed``.

        The ``require_human`` verdict is a REFUSAL, not an advisory: it is
        distinct from ``denied`` only so a caller can tell "a human must
        approve this" from "this is refused outright".  Neither is
        executable -- :meth:`execute` calls the tool only for ``allowed``.
        """
        call_id = _require_text(call_id, "call_id")
        action = _require_text(action, "action")
        if isinstance(timestamp, bool) or not isinstance(timestamp, int):
            raise InvalidBoundaryError("timestamp must be an int")
        digest = self.call_digest(call_id, action, tool, resource)

        boundary: Optional[AuthorizationBoundary] = None
        if boundary_id is not None:
            boundary = self._registry.get(boundary_id)
            if boundary is None:
                return self._record(call_id, action, tool, VERDICT_DENIED,
                                    REASON_NO_BOUNDARY, None, timestamp, digest)

        if boundary is None:
            return self._record(call_id, action, tool, VERDICT_DENIED,
                                REASON_NO_BOUNDARY, None, timestamp, digest)

        if boundary.revoked_at is not None:
            return self._record(call_id, action, tool, VERDICT_DENIED,
                                REASON_REVOKED, boundary, timestamp, digest)

        if boundary.is_expired_at(timestamp):
            return self._record(call_id, action, tool, VERDICT_DENIED,
                                REASON_EXPIRED, boundary, timestamp, digest)

        if timestamp < boundary.issued_at:
            return self._record(call_id, action, tool, VERDICT_DENIED,
                                REASON_NOT_YET_ACTIVE, boundary, timestamp, digest)

        if not boundary.scope.is_satisfied_by(action, tool=tool, resource=resource):
            return self._record(call_id, action, tool, VERDICT_DENIED,
                                REASON_SCOPE_MISMATCH, boundary, timestamp, digest)

        if requires_human or grant is not None:
            if grant is None:
                # A call that needs a human approval and has none is
                # REFUSED.  The verdict is ``require_human`` rather than
                # ``denied`` so a caller can tell "a human must approve this"
                # from "this is refused outright" -- but it is NOT an
                # advisory: :meth:`execute` refuses to call the tool for
                # anything that is not ``allowed``, and
                # :meth:`authorize_or_raise` raises.
                return self._record(call_id, action, tool, VERDICT_REQUIRE_HUMAN,
                                    REASON_APPROVAL_REQUIRED, boundary,
                                    timestamp, digest)
            if not grant.matches(call_id, digest):
                return self._record(call_id, action, tool, VERDICT_DENIED,
                                    REASON_APPROVAL_INVALID, boundary,
                                    timestamp, digest)
            if not grant.is_valid_at(timestamp):
                return self._record(call_id, action, tool, VERDICT_DENIED,
                                    REASON_APPROVAL_EXPIRED, boundary,
                                    timestamp, digest)

        return self._record(call_id, action, tool, VERDICT_ALLOWED,
                            "authorized", boundary, timestamp, digest)

    def authorize_or_raise(
        self,
        call_id: str,
        action: str,
        tool: Optional[str] = None,
        resource: Optional[str] = None,
        timestamp: int = 0,
        boundary_id: Optional[str] = None,
        grant: Optional[ApprovalGrant] = None,
        requires_human: bool = False,
    ) -> DecisionRecord:
        """Authorize, and raise :class:`ApprovalRequiredError` when a human
        approval is needed and absent.

        The raise is the fail-closed limb made unmissable: a caller that
        forgets to inspect the verdict cannot accidentally proceed, because
        this method does not return until the call is allowed.
        """
        record = self.authorize(
            call_id=call_id,
            action=action,
            tool=tool,
            resource=resource,
            timestamp=timestamp,
            boundary_id=boundary_id,
            grant=grant,
            requires_human=requires_human,
        )
        if record.verdict == VERDICT_REQUIRE_HUMAN:
            raise ApprovalRequiredError(
                f"call {record.call_id} requires human approval "
                f"({record.reason})", record)
        if record.verdict != VERDICT_ALLOWED:
            raise BoundaryError(
                f"call {record.call_id} denied: {record.reason}")
        return record

    def execute(
        self,
        fn: Callable,
        call_id: str,
        action: str,
        tool: Optional[str] = None,
        resource: Optional[str] = None,
        timestamp: int = 0,
        boundary_id: Optional[str] = None,
        grant: Optional[ApprovalGrant] = None,
        requires_human: bool = False,
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        """Authorize, then call ``fn`` ONLY if the verdict is ``allowed``.

        This is the structural guarantee.  ``fn`` is not called for a denied
        or require-human verdict -- not "called and rolled back", not
        "called and the result discarded": not called.  A test proves it
        with a callable that records having been called.
        """
        record = self.authorize(
            call_id=call_id,
            action=action,
            tool=tool,
            resource=resource,
            timestamp=timestamp,
            boundary_id=boundary_id,
            grant=grant,
            requires_human=requires_human,
        )
        if record.verdict != VERDICT_ALLOWED:
            raise BoundaryError(
                f"call {record.call_id} refused: {record.reason} "
                f"(verdict {record.verdict}); the tool was not reached")
        return fn(*args, **kwargs)

    # -- delegation --------------------------------------------------------

    def delegate(
        self,
        parent_boundary_id: str,
        child_boundary_id: str,
        grantee: str,
        scope: Optional[BoundaryScope] = None,
        issued_at: int = 0,
        expires_at: Optional[int] = None,
    ) -> DecisionRecord:
        """Re-check the parent boundary AT DELEGATION TIME and delegate.

        The community counter-example recorded in the survey: "Their 'still
        the thing you authorized' test needs the re-check to fire at
        delegation time, not at call time.  A sub-agent that inherits a
        parent's token inherits its staleness too."

        So the check happens HERE, at the moment the authority changes
        hands, and it is a hard refusal: if the parent has expired or been
        revoked, the delegation does not happen and the decision line says
        so.  The child boundary is created only when the parent is still
        live.
        """
        parent = self._registry.get(parent_boundary_id)
        digest = self.call_digest(child_boundary_id, "delegate", None, None)
        if parent is None:
            return self._record(child_boundary_id, "delegate", None,
                                VERDICT_DENIED, REASON_NO_BOUNDARY, None,
                                issued_at, digest)
        if parent.revoked_at is not None:
            return self._record(child_boundary_id, "delegate", None,
                                VERDICT_DENIED, REASON_REVOKED, parent,
                                issued_at, digest)
        if parent.is_expired_at(issued_at):
            return self._record(child_boundary_id, "delegate", None,
                                VERDICT_DENIED, REASON_DELEGATION_EXPIRED,
                                parent, issued_at, digest)
        if issued_at < parent.issued_at:
            return self._record(child_boundary_id, "delegate", None,
                                VERDICT_DENIED, REASON_DELEGATION_EXPIRED,
                                parent, issued_at, digest)
        child_scope = parent.scope if scope is None else scope
        if not child_scope._is_subset(parent.scope):
            return self._record(child_boundary_id, "delegate", None,
                                VERDICT_DENIED, REASON_DELEGATION_NOT_ALLOWED,
                                parent, issued_at, digest)
        child = self._registry.narrow(
            parent_boundary_id=parent_boundary_id,
            boundary_id=child_boundary_id,
            scope=child_scope,
            issued_at=issued_at,
            expires_at=expires_at,
            grantee=grantee,
        )
        return self._record(child_boundary_id, "delegate", None,
                            VERDICT_ALLOWED, "delegated", child, issued_at, digest)


def main() -> None:
    """Self-check: denied calls never reach the tool, scope only narrows,
    expiry and revocation bind, a grant binds one call, delegation re-checks
    at delegation time, and every decision leaves a line."""
    scope = BoundaryScope(
        resource_prefixes=("/workspace",),
        actions=("read",),
        allowed_tools=("Read",),
        denied_tools=("Bash",),
    )
    check = BoundaryCheck()
    check.registry.issue(
        boundary_id="b1",
        scope=scope,
        subject="user-1",
        grantee="agent-1",
        issued_at=100,
        expires_at=200,
        evidence_digest="sha256:deadbeef",
    )

    # Allowed: the call runs.
    calls = []

    def fake_tool(value):
        calls.append(value)
        return value * 2

    out = check.execute(
        fake_tool, call_id="c1", action="read", tool="Read",
        resource="/workspace/a.txt", timestamp=150, boundary_id="b1", value=21)
    assert out == 42
    assert calls == [21], "the tool must run when the call is allowed"

    # Denied: the tool is NOT reached.
    calls.clear()
    try:
        check.execute(
            fake_tool, call_id="c2", action="write", tool="Write",
            resource="/workspace/a.txt", timestamp=150, boundary_id="b1", value=1)
        raise AssertionError("should have refused")
    except BoundaryError:
        pass
    assert calls == [], "a denied call must never reach the tool"

    # Denied by the explicit deny list, even though the action matches.
    calls.clear()
    try:
        check.execute(
            fake_tool, call_id="c3", action="read", tool="Bash",
            resource="/workspace/a.txt", timestamp=150, boundary_id="b1", value=1)
        raise AssertionError("should have refused")
    except BoundaryError:
        pass
    assert calls == [], "a denied tool must never reach the tool"

    # Expired.
    rec = check.authorize(call_id="c4", action="read", tool="Read",
                          resource="/workspace/a.txt", timestamp=500,
                          boundary_id="b1")
    assert rec.verdict == VERDICT_DENIED
    assert rec.reason == REASON_EXPIRED

    # Revoked.
    check.registry.revoke("b1", ts=120, reason="operator withdrew")
    rec = check.authorize(call_id="c5", action="read", tool="Read",
                          resource="/workspace/a.txt", timestamp=130,
                          boundary_id="b1")
    assert rec.verdict == VERDICT_DENIED
    assert rec.reason == REASON_REVOKED

    # Scope only narrows.
    try:
        scope.narrowed_to(actions=("read", "write"))
        raise AssertionError("should have refused the widening")
    except ScopeWideningError:
        pass
    narrower = scope.narrowed_to(actions=("read",))
    assert narrower.actions == ("read",)

    # Approval: plain True is not a grant, and a mismatched digest fails.
    check2 = BoundaryCheck()
    check2.registry.issue(
        boundary_id="b2", scope=scope, subject="user-1", grantee="agent-1",
        issued_at=0, expires_at=1000, evidence_digest="sha256:cafe")
    digest = BoundaryCheck.call_digest("c6", "read", "Read", "/workspace/a.txt")
    rec = check2.authorize(call_id="c6", action="read", tool="Read",
                           resource="/workspace/a.txt", timestamp=10,
                           boundary_id="b2", requires_human=True)
    assert rec.verdict == VERDICT_REQUIRE_HUMAN
    assert rec.reason == REASON_APPROVAL_REQUIRED
    bad = ApprovalGrant(call_id="c6", digest="sha256:wrong",
                         issued_at=0, expires_at=100)
    rec = check2.authorize(call_id="c6", action="read", tool="Read",
                           resource="/workspace/a.txt", timestamp=10,
                           boundary_id="b2", grant=bad)
    assert rec.verdict == VERDICT_DENIED
    assert rec.reason == REASON_APPROVAL_INVALID
    good = ApprovalGrant(call_id="c6", digest=digest, issued_at=0, expires_at=100)
    rec = check2.authorize(call_id="c6", action="read", tool="Read",
                           resource="/workspace/a.txt", timestamp=10,
                           boundary_id="b2", grant=good)
    assert rec.verdict == VERDICT_ALLOWED

    # Delegation re-checks at delegation time.
    check3 = BoundaryCheck()
    check3.registry.issue(
        boundary_id="p1", scope=scope, subject="user-1", grantee="agent-1",
        issued_at=0, expires_at=100, evidence_digest="sha256:feed")
    rec = check3.delegate("p1", "k1", "agent-2", issued_at=50)
    assert rec.verdict == VERDICT_ALLOWED
    rec = check3.delegate("p1", "k2", "agent-2", issued_at=150)
    assert rec.verdict == VERDICT_DENIED
    assert rec.reason == REASON_DELEGATION_EXPIRED

    # Every decision left an auditable line.
    assert len(check.audit_lines()) == 5
    assert all("\"verdict\"" in line for line in check.audit_lines())

    print("agent_boundary self-check OK")


if __name__ == "__main__":
    main()
