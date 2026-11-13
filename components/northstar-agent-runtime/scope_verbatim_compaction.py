"""Carry the scope block verbatim through compaction, fail closed on drop.

Source (the excerpt carried by the slice brief is the source -- verbatim as
briefed; the post is not in this repository and was not crawled):

    "I suspect the interesting variable is not compaction itself but the shape
    of what happens right after one: a resummarization that loses
    instructions, a tool call whose arguments depend on state that was just
    summarized away, a context window that gets rebuilt with a different
    ordering."

and the author's own response to it:

    "Now I check the log first. If the last event is a tool result and there is
    a compaction somewhere upstream, I do not rewrite the prompt. I re-dispatch
    the same prompt. The prompt was probably fine. What got lost was the thread
    that was carrying it, and a rewritten prompt is a worse version of the same
    instruction."

and the round-3 conclusion this slice implements ("compression drops scope ==
permission laundering"): when compaction loses the scope, the agent has
quietly widened its own authority -- an operation refused before the
compaction is not refused after it, because the constraint that refused it
was summarized away.

Northstar gap this closes (read from the code, not assumed):

* ``compaction.py`` replaces a summarised prefix with **one summary string**
  (``extractive_summary``, clipped at 4000 chars with a truncation marker).
  The host's compaction ``instructions`` are *concatenated into* that string
  (``- host compaction instruction: ...``), and the whole string then goes
  through ``defensive_agent.sanitize_for_model``, which may replace it
  wholesale with ``[blocked by defensive agent]``.  The retained tail is the
  only part that survives byte-identical.
* **Nothing in the repository validates scope after a compaction.**  The
  transcript carries no scope block, so there is nothing to compare: the
  scope simply stops existing when the prefix is summarized.
* ``scope_qualifier.py`` is adjacent but different.  It re-derives a *grant's*
  scope from a **structured source line** at dispatch (a sidecar the
  summarizer never touches) and blocks on mismatch.  That protects a
  permission's *fence*; it does not carry the scope *through* the
  compaction, and it does not detect that the transcript lost the scope in
  the first place.

Design invariants this module enforces:

* **the scope is a byte-preserved region, not a summary** -- it is rendered
  into a delimited block and carried as its own record; no summarizer ever
  sees, rewrites, reorders, or drops it,
* **the check is character equality, never "close enough"** -- a block that
  is missing, reworded, reordered, or truncated is *not* preserved, and the
  product of such a compaction is not usable as a scope-carrying
  compaction,
* **fail closed** -- the failure is a ``False``/a raised error, never a
  warning, and never a "reconstructed" scope,
* **an empty scope is explicit** -- "no scope" and "a scope with nothing in
  it" are different facts, and only one of them may be silent.

Field mapping -- where each :class:`Scope` field comes from in this
repository (read, not assumed):

``instructions``
    The verbatim instruction strings a run is bound by:
    ``loop.RuntimeConfig.system_prompt`` (the system prompt), the
    ``== Project instructions ({name}) ==`` block ``policy_file.py``
    appends to it, and any host-declared compaction instruction.  These are
    the strings the source calls "instructions" -- the thing a
    resummarization loses.
``grants``
    The grant / permission identifiers the scope authorizes.  Two shapes
    exist in this repository and both are carried verbatim: the tool names
    in a scope's authority ceiling (``permissions.ScopeManager.open_scope``
    ``capabilities=...``, ``permissions.PermissionConfig.allowed_tools`` /
    ``disallowed_tools``) and the pinned grant identity
    (``grant_pin_ledger.GrantPin.render()`` -> ``grant:<id>;version=..;counter=..``).
``goal``
    The host-owned goal statement: ``code_task.CodeTask.goal`` (a
    programming run's task) or the run's task/prompt text.
``scope_id``
    The scope's identity: ``permissions.ScopeManager.open_scope(scope_id)``
    -- the id a closed scope can never be reopened under.

Honest scope: this module guarantees that the scope block crosses a
compaction **verbatim**.  It does **not** guarantee the quality of the
summarized body, and it does **not** detect a summary that dropped a
critical fact from the *body* (only from the scope block).  It also does
not re-derive the scope from a stored source: that is the reversible
compaction slice's job.  A block that survives this module is exactly the
block that was handed in -- nothing more is claimed.
"""

from __future__ import annotations

import ast
import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Sequence, Tuple

#: Module version pin.
VERSION = "scope-verbatim-compaction.v1"

#: Schema pin for the records this module produces.
SCHEMA = "northstar.scope-verbatim-compaction.v1"

#: The delimiters of the verbatim scope block.  Fixed strings: the block is
#: compared byte for byte, so the markers may not drift.
BLOCK_BEGIN = "<<NORTHSTAR-SCOPE-BEGIN v1>>"
BLOCK_END = "<<NORTHSTAR-SCOPE-END v1>>"

#: The marker line that declares an entirely empty scope.  An empty scope is
#: rendered, never omitted: "no scope at all" and "a scope with nothing in
#: it" are different facts.
EMPTY_SCOPE_MARKER = "scope: empty"


class ScopeError(Exception):
    """Base class for this module's refusals."""


class MalformedScopeError(ScopeError):
    """A scope or a scope block could not be read."""


class ScopeNotPreservedError(ScopeError):
    """A compaction product does not carry its scope verbatim."""


# ---------------------------------------------------------------------------
# The scope
# ---------------------------------------------------------------------------


def _as_text_tuple(value: Any, field: str) -> Tuple[str, ...]:
    """Coerce a field to a tuple of verbatim strings.

    A bare string is refused rather than silently wrapped: ``"one line"`` is
    a plausible mistake for ``("one line",)`` and the ambiguity would show
    up as a scope that lost an item.
    """
    if value is None:
        return ()
    if isinstance(value, str):
        raise MalformedScopeError(f"{field} must be a sequence of strings, not a bare string")
    if isinstance(value, Mapping):
        raise MalformedScopeError(f"{field} must be a sequence of strings, not a mapping")
    items: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise MalformedScopeError(f"{field} entries must be strings")
        items.append(item)
    return tuple(items)


@dataclass(frozen=True)
class Scope:
    """The scope that must cross a compaction unchanged.

    Every field is carried verbatim: the order of ``instructions`` and
    ``grants`` is part of the scope (reordering is a rewrite), and no entry
    is ever trimmed, folded, or dropped.  Empty fields are representable --
    an empty scope renders an explicit empty block, because "the scope was
    empty" and "the scope was dropped" are different answers.
    """

    instructions: Tuple[str, ...] = ()
    grants: Tuple[str, ...] = ()
    goal: str = ""
    scope_id: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "instructions", _as_text_tuple(self.instructions, "instructions"))
        object.__setattr__(self, "grants", _as_text_tuple(self.grants, "grants"))
        if not isinstance(self.goal, str):
            raise MalformedScopeError("goal must be a string")
        if not isinstance(self.scope_id, str):
            raise MalformedScopeError("scope_id must be a string")

    @classmethod
    def coerce(cls, value: Any) -> "Scope":
        """Build a scope from a scope or from a mapping over its fields.

        A mapping's key order is irrelevant: the scope is canonicalized
        before it is hashed or rendered.
        """
        if isinstance(value, Scope):
            return value
        if isinstance(value, Mapping):
            unknown = sorted(set(value) - {"instructions", "grants", "goal", "scope_id"})
            if unknown:
                raise MalformedScopeError("scope carries unknown fields: " + ", ".join(unknown))
            return cls(
                instructions=value.get("instructions", ()),
                grants=value.get("grants", ()),
                goal=value.get("goal", ""),
                scope_id=value.get("scope_id", ""),
            )
        raise MalformedScopeError("scope must be a Scope or a mapping over its fields")

    def is_empty(self) -> bool:
        """True when nothing at all was declared."""
        return not self.instructions and not self.grants and not self.goal and not self.scope_id

    def grant_set(self) -> frozenset:
        """The grants as a set -- the permission-laundering comparison."""
        return frozenset(self.grants)

    def canonical(self) -> dict:
        """The canonical form of this scope.

        Field order is fixed here, so two scopes built from mappings with
        different key orders canonicalize identically.  *Item* order is
        preserved: reordering instructions is a rewrite of the scope.
        """
        return {
            "goal": self.goal,
            "grants": list(self.grants),
            "instructions": list(self.instructions),
            "scope_id": self.scope_id,
        }

    def as_dict(self) -> dict:
        return self.canonical()


def scope_hash(scope: Any) -> str:
    """``sha256:`` pin of the scope's canonical form.

    The hash is over the canonical mapping, never over the surface form of
    the object, so the field order a caller happened to use cannot change
    the pin.
    """
    canonical = Scope.coerce(scope).canonical()
    payload = json.dumps(
        canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


# ---------------------------------------------------------------------------
# The verbatim block
# ---------------------------------------------------------------------------


def _scalar_line(key: str, value: str) -> str:
    """One ``key[len]: value`` line.

    The length prefix is what makes the block *reversible*: an instruction
    may contain newlines, colons, or the markers themselves, and without a
    length the reader could not tell where the value ends.  With it, the
    value's bytes appear in the block unchanged and the block parses back to
    the same scope.
    """
    return f"{key}[{len(value)}]: {value}"


def _list_header(key: str, count: int) -> str:
    return f"{key}[{count}]:"


def verbatim_scope_block(scope: Any) -> str:
    """Render the scope as a byte-preserved block.

    The rendering never rewrites, summarizes, reorders, or drops an item:
    the instruction and grant strings appear in the block exactly as they
    were handed in, in the order they were handed in.  An empty scope
    renders the explicit empty marker -- never an empty block, and never
    nothing at all.
    """
    resolved = Scope.coerce(scope)
    if resolved.is_empty():
        return f"{BLOCK_BEGIN}\n{EMPTY_SCOPE_MARKER}\n{BLOCK_END}\n"
    lines = [
        BLOCK_BEGIN,
        _scalar_line("scope_id", resolved.scope_id),
        _scalar_line("goal", resolved.goal),
        _list_header("instructions", len(resolved.instructions)),
    ]
    for instruction in resolved.instructions:
        lines.append(_scalar_line("item", instruction))
    lines.append(_list_header("grants", len(resolved.grants)))
    for grant in resolved.grants:
        lines.append(_scalar_line("item", grant))
    lines.append(BLOCK_END)
    return "\n".join(lines) + "\n"


def _read_header(cursor: str) -> tuple[str, int, int]:
    """Read one header at the start of ``cursor``.

    Returns ``(key, length, value_offset)`` where ``value_offset`` is the
    index in ``cursor`` at which the value's bytes start.  A scalar header
    is ``key[len]: value`` (the value may itself contain newlines, so the
    length is what delimits it); a list header is ``key[count]:`` alone.
    """
    end = cursor.find("\n")
    line = cursor if end < 0 else cursor[:end]
    if line.endswith(":"):
        head = line[:-1]
        value_offset = len(line) + 1 if end >= 0 else len(line)
    elif ": " in line:
        head, _, _ = line.partition(": ")
        value_offset = len(head) + 2
    else:
        raise MalformedScopeError(f"scope block header is malformed: {line!r}")
    if "[" not in head or not head.endswith("]"):
        raise MalformedScopeError(f"scope block header is malformed: {line!r}")
    key = head[: head.index("[")]
    if key not in ("scope_id", "goal", "instructions", "grants", "item"):
        raise MalformedScopeError(f"scope block header is not a known field: {key!r}")
    try:
        length = int(head[head.index("[") + 1 : -1])
    except ValueError as error:
        raise MalformedScopeError(f"scope block header has a bad length: {line!r}") from error
    if length < 0:
        raise MalformedScopeError(f"scope block header has a bad length: {line!r}")
    return key, length, value_offset


def parse_scope_block(block: Any) -> Scope:
    """Parse a rendered scope block back into a :class:`Scope`.

    The inverse of :func:`verbatim_scope_block`: parsing the block and
    rendering it again yields the same bytes.  That round-trip is what
    makes "the scope crossed the compaction unchanged" a checkable claim
    rather than an assertion.
    """
    if not isinstance(block, str) or not block:
        raise MalformedScopeError("scope block must be a non-empty str")
    if not block.startswith(BLOCK_BEGIN + "\n") or not block.endswith(BLOCK_END + "\n"):
        raise MalformedScopeError("scope block is missing its begin or end marker")
    body = block[len(BLOCK_BEGIN) + 1 : -len(BLOCK_END + "\n")]
    if body.rstrip("\n") == EMPTY_SCOPE_MARKER:
        return Scope()
    scope_id = ""
    goal = ""
    instructions: list[str] = []
    grants: list[str] = []
    cursor = body
    seen_scalars: set[str] = set()
    while cursor:
        key, length, offset = _read_header(cursor)
        if key in ("scope_id", "goal"):
            if key in seen_scalars:
                raise MalformedScopeError(f"scope block repeats the {key} field")
            seen_scalars.add(key)
            value = cursor[offset : offset + length]
            if len(value) != length:
                raise MalformedScopeError("scope block scalar value is truncated")
            if key == "scope_id":
                scope_id = value
            else:
                goal = value
            cursor = cursor[offset + length :]
            if cursor.startswith("\n"):
                cursor = cursor[1:]
            continue
        if key in ("instructions", "grants"):
            target = instructions if key == "instructions" else grants
            cursor = cursor[offset:]
            for _ in range(length):
                ikey, ilen, ioffset = _read_header(cursor)
                if ikey != "item":
                    raise MalformedScopeError("scope block list entry is not an item")
                value = cursor[ioffset : ioffset + ilen]
                if len(value) != ilen:
                    raise MalformedScopeError("scope block item value is truncated")
                target.append(value)
                cursor = cursor[ioffset + ilen :]
                if cursor.startswith("\n"):
                    cursor = cursor[1:]
            continue
        raise MalformedScopeError(f"scope block header is not a known field: {key!r}")
    return Scope(instructions=tuple(instructions), grants=tuple(grants), goal=goal, scope_id=scope_id)


def extract_scope_block(text: Any) -> str | None:
    """Find the scope block inside a carried text.

    Returns the block *including* its markers, or ``None`` when there is
    no block at all.  A missing block is the fail-closed case: it is
    reported as missing, never reconstructed.
    """
    if not isinstance(text, str) or not text:
        return None
    begin = text.find(BLOCK_BEGIN)
    if begin < 0:
        return None
    end = text.find(BLOCK_END, begin)
    if end < 0:
        return None
    return text[begin : end + len(BLOCK_END)]


def block_hash(block: str) -> str:
    """``sha256:`` pin of the block's exact bytes."""
    return "sha256:" + hashlib.sha256(block.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# The manifest
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ScopeManifest:
    """What the compaction carried, and how.

    The manifest is the record that says *which parts are verbatim and
    which are summarized*.  It names the scope's canonical hash and the
    block's own byte hash separately: the first pins the scope's meaning,
    the second pins the bytes that crossed the boundary.  A manifest whose
    two hashes do not agree with the block it accompanies is not a
    manifest of that block.
    """

    #: The scope's canonical hash (``scope_hash``).
    scope_hash: str = ""
    #: The byte hash of the carried block (``block_hash``).
    block_hash: str = ""
    #: The carried block, verbatim.
    scope_block: str = ""
    #: The fields that crossed verbatim.
    verbatim_fields: Tuple[str, ...] = ()
    #: The fields that went through the summarizer.
    summarized_fields: Tuple[str, ...] = ()
    #: The byte length of the carried block.
    scope_block_bytes: int = 0
    #: The scope's grant set at the boundary (permission laundering check).
    grants: Tuple[str, ...] = ()
    #: The scope's id at the boundary.
    scope_id: str = ""

    def as_dict(self) -> dict:
        return {
            "scope_hash": self.scope_hash,
            "block_hash": self.block_hash,
            "scope_block": self.scope_block,
            "verbatim_fields": list(self.verbatim_fields),
            "summarized_fields": list(self.summarized_fields),
            "scope_block_bytes": self.scope_block_bytes,
            "grants": list(self.grants),
            "scope_id": self.scope_id,
        }

    def block_is_intact(self) -> bool:
        """True when the manifest's own hashes agree with its own block.

        A manifest that was edited next to its block (or a block that was
        edited next to its manifest) fails here -- the hashes are the
        cross-check, not the comparison.
        """
        if not self.scope_block:
            return False
        if block_hash(self.scope_block) != self.block_hash:
            return False
        return scope_hash(parse_scope_block(self.scope_block)) == self.scope_hash


# ---------------------------------------------------------------------------
# The compaction
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CompactedSession:
    """One compaction that carries a scope.

    ``scope_block`` is the verbatim region, ``summary`` is the summarized
    body, and ``manifest`` records which is which.  The scope block is
    stored *next to* the summary, not inside it, so no summarizer can
    reach it.
    """

    #: The scope block, verbatim, exactly as rendered.
    scope_block: str = ""
    #: The summarized body of the transcript.
    summary: str = ""
    #: The transcript as it stood after the compaction.
    transcript: Tuple[Any, ...] = ()
    #: What was carried, and how.
    manifest: ScopeManifest = field(default_factory=ScopeManifest)
    #: The scope the compaction was made under.
    scope: Scope = field(default_factory=Scope)

    def scope_text(self) -> str:
        """The scope block as it would be carried in the prompt."""
        return self.scope_block

    def carried_text(self) -> str:
        """The scope block and the summary, in that order.

        The scope comes **first** and on its own: a summary that mentions
        the scope must not be able to be read as the scope.
        """
        return f"{self.scope_block}\n{self.summary}" if self.summary else self.scope_block

    def as_dict(self) -> dict:
        return {
            "scope_block": self.scope_block,
            "summary": self.summary,
            "manifest": self.manifest.as_dict(),
        }


#: The fields that are always carried verbatim, and the fields that are
#: always summarized.  Pinned here so the manifest cannot drift from the
#: behaviour.
VERBATIM_FIELDS: Tuple[str, ...] = ("instructions", "grants", "goal", "scope_id")
SUMMARIZED_FIELDS: Tuple[str, ...] = ("transcript_body",)


def compact_with_scope(
    transcript: Sequence[Any],
    scope: Any,
    summarize: Callable[[Sequence[Any]], str],
) -> CompactedSession:
    """Compact ``transcript`` while carrying ``scope`` verbatim.

    ``summarize`` is the caller's summary function: this module does not
    implement a summarizer and never calls one on the scope.  The scope
    block is rendered *before* the summarizer runs and is not part of the
    input the summarizer receives, so a summarizer cannot drop it.

    The scope block is carried as its own record beside the summary; the
    manifest records the boundary between the two.
    """
    resolved = Scope.coerce(scope)
    block = verbatim_scope_block(resolved)
    materialised = tuple(transcript)
    summary = str(summarize(materialised) or "")
    manifest = ScopeManifest(
        scope_hash=scope_hash(resolved),
        block_hash=block_hash(block),
        scope_block=block,
        verbatim_fields=VERBATIM_FIELDS,
        summarized_fields=SUMMARIZED_FIELDS,
        scope_block_bytes=len(block.encode("utf-8")),
        grants=resolved.grants,
        scope_id=resolved.scope_id,
    )
    return CompactedSession(
        scope_block=block,
        summary=summary,
        transcript=materialised,
        manifest=manifest,
        scope=resolved,
    )


def scope_preserved(compacted: Any, original_scope: Any) -> bool:
    """True only when the scope crossed the compaction **verbatim**.

    The check is character equality of the block *and* equality of the
    canonical hash.  A missing block, a reworded block, a reordered block,
    a truncated block, and a block that was summarized away are all
    ``False``: this function never accepts "close enough" and never
    reconstructs a scope from the summary.

    A product that is not a :class:`CompactedSession` (or a plain mapping
    carrying a ``scope_block``) is not preserved either -- an unreadable
    product is not a preserved one.
    """
    if isinstance(compacted, CompactedSession):
        block = compacted.scope_block
        manifest = compacted.manifest
    elif isinstance(compacted, Mapping):
        block = compacted.get("scope_block")
        manifest = compacted.get("manifest")
    else:
        return False
    if not isinstance(block, str) or not block:
        return False
    resolved = Scope.coerce(original_scope)
    expected = verbatim_scope_block(resolved)
    # Byte equality first: the strongest and cheapest statement.
    if block != expected:
        return False
    # Hash equality second: the canonical statement, and the check that
    # catches a block rebuilt to the same bytes but from a different scope.
    if scope_hash(resolved) != scope_hash(parse_scope_block(block)):
        return False
    # The manifest must agree with the block it describes, when there is one.
    if isinstance(manifest, ScopeManifest) and not manifest.block_is_intact():
        return False
    if isinstance(manifest, Mapping):
        if manifest.get("block_hash") != block_hash(block):
            return False
        if manifest.get("scope_hash") != scope_hash(resolved):
            return False
    return True


def require_scope_preserved(compacted: Any, original_scope: Any) -> Scope:
    """Return the scope when it was preserved; raise when it was not.

    The fail-closed form: a caller that uses a compaction product without
    checking it gets an error, not a warning.
    """
    if not scope_preserved(compacted, original_scope):
        raise ScopeNotPreservedError(
            "the compaction product does not carry its scope verbatim; "
            "it must not be used as a scope-carrying compaction"
        )
    return Scope.coerce(original_scope)


# ---------------------------------------------------------------------------
# House style: stdlib-only self-check
# ---------------------------------------------------------------------------


def stdlib_only() -> bool:
    """AST check: this module imports stdlib modules only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {
        "__future__",
        "ast",
        "dataclasses",
        "hashlib",
        "json",
        "pathlib",
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
    """Self-check: the scope crosses verbatim, and every way of losing it
    is caught."""
    scope = Scope(
        instructions=("do not touch main", "no network"),
        grants=("grant:read;version=v1;counter=3", "Bash"),
        goal="ship the fix",
        scope_id="phase-1",
    )
    block = verbatim_scope_block(scope)
    assert parse_scope_block(block) == scope, "the block must parse back to the scope"
    compacted = compact_with_scope(("a", "b"), scope, lambda transcript: "summary of 2 messages")
    assert scope_preserved(compacted, scope), "the scope must survive a compaction"
    assert scope_hash(scope) == scope_hash(Scope.coerce(scope.as_dict()))
    assert not scope_preserved(compacted, Scope(instructions=("do not touch main",)))
    assert not scope_preserved(
        CompactedSession(scope_block=block.replace("ship the fix", "ship the fixes"), summary="s"),
        scope,
    ), "a reworded scope must fail closed"
    assert not scope_preserved(CompactedSession(scope_block="", summary="s"), scope)
    assert not scope_preserved(CompactedSession(scope_block=block.replace("Bash", "bash"), summary="s"), scope)
    assert verbatim_scope_block(Scope()) != "", "an empty scope renders an explicit block"
    assert stdlib_only()
    print(
        "scope-verbatim-compaction OK: scope crosses verbatim, a reworded scope "
        "fails closed, stdlib"
    )


if __name__ == "__main__":  # pragma: no cover - self-check entry point
    main()
