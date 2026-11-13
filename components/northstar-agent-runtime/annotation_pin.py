"""Annotation-hint pinning for MCP tools (silent-widening defense), Simulated.

MCP tool annotations (``readOnlyHint``, ``destructiveHint``) are *self-
descriptions*: testimony, not grants.  The dangerous failure is not a lying
description -- it is a hint flipping silently between sessions so the client
stops asking for confirmation.  Nobody reads a diff of metadata.

This module is the *second* pinning layer, complementary to ``tool_pinning``:

* ``tool_pinning`` pins the tool **definition** (name, description, inputSchema,
  version) -- tool-identity continuity.  It defends against the rug pull: the
  definition is swapped behind a stable identity.
* ``annotation_pin`` pins the **claimed effect** (the annotation hint set plus
  the schema hash) -- it defends against the silent widening: the tool keeps
  its name and its definition, but its *claim* flips from read-only to
  destructive between sessions.

Direction matters.  A flip that *narrows* the claim (destructive -> read-only)
is safe and is accepted silently; a flip that *widens* it (read-only ->
destructive) must re-arm the human-in-the-loop confirmation until a human
re-pins it.  The pin is on the **artifact** (the schema hash), never on the
version string: servers repoint behaviour behind a stable version number, so
a version bump alone is not a change of effect, while a schema change behind
an unchanged version is.

Trust lives in an operator-written per-server setting, never in a server's own
claim.  A server is either ``trusted`` (its annotations are treated as claims
worthy of pinning) or ``untrusted`` (its annotations are ignored entirely and
the tool is treated as write-capable).  The default is untrusted.

Fail-closed rules, all of them:

* a missing, non-dict, or malformed annotation set is treated as
  write-capable (destructive) -- never as read-only;
* a pin whose ``hint_digest`` is missing or empty is refused by
  ``AnnotationPin.from_dict`` -- a pin that was never proven is not a pin;
* a tool that was never pinned is ``UNPINNED`` and requires confirmation.

What this IS: a gate interface for annotation-hint continuity.

What this IS NOT:
* Not a replacement for ``tool_pinning`` -- the two pin different things.
* Not a live-provider client -- it consumes what a host already fetched.
* The gate itself is not modified here; the host calls
  ``requires_confirmation()`` before letting a call through.
"""

from __future__ import annotations

import ast
import hashlib
import json
from dataclasses import dataclass
from typing import Any, Dict, Iterable, Mapping, Optional, Tuple

#: Module version.
ANNOTATION_PIN_VERSION = "annotation-pinning.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.annotation-pinning.v1"

#: Verification outcomes.
OK = "OK"
SAFE_FLIP = "SAFE_FLIP"
DANGEROUS_FLIP = "DANGEROUS_FLIP"
DRIFT = "DRIFT"
UNPINNED = "UNPINNED"

#: Capability ranks.  Lower is safer.  A widening raises the rank.
RANK_READ_ONLY = 0
RANK_NEUTRAL = 1
RANK_WRITE = 2

#: Hint spellings that mean the same thing, normalised to one canonical name.
_ALIASES: Dict[str, str] = {
    "read_only": "read_only",
    "readOnly": "read_only",
    "readOnlyHint": "read_only",
    "readonly": "read_only",
    "destructive": "destructive",
    "destructiveHint": "destructive",
}

#: The two hints the capability judgement is made from.
REQUIRED_HINTS = ("read_only", "destructive")


class AnnotationPinError(Exception):
    """Fail-closed: an unusable pin or an unusable hint set raises."""


def _canonical(obj: Any) -> str:
    """Canonical JSON: sorted keys, compact separators, UTF-8.

    Same shape as ``tool_pinning.hash_definition`` so the two layers digest
    the same way.  Never raises: an object that cannot be serialised is
    rendered through ``repr`` so the digest stays deterministic instead of
    blowing up mid-verification.
    """
    try:
        return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=repr)
    except (TypeError, ValueError):
        return json.dumps({"__unserialisable__": repr(obj)}, sort_keys=True, separators=(",", ":"))


def _sha256(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def hash_schema(schema: Optional[Mapping[str, Any]]) -> str:
    """Hash a tool's input schema -- the artifact, not the version string."""
    return _sha256(_canonical(schema if schema is not None else {}))


def normalize_annotations(annotations: Any) -> Optional[Dict[str, Any]]:
    """Normalise an annotation set, or return ``None`` if it is unusable.

    ``None`` means "malformed": not a dict, a required hint missing, or a
    required hint that is not a boolean.  Malformed is fail-closed: the caller
    treats it as write-capable.
    """
    if not isinstance(annotations, dict):
        return None
    out: Dict[str, Any] = {}
    for key, value in annotations.items():
        out[_ALIASES.get(key, key)] = value
    for hint in REQUIRED_HINTS:
        if hint not in out:
            return None
        if not isinstance(out[hint], bool):
            return None
    return out


def capability_rank(annotations: Any) -> int:
    """Rank the *claimed* effect.  Higher means more dangerous.

    Malformed or missing annotations rank as write-capable, always.
    """
    normalized = normalize_annotations(annotations)
    if normalized is None:
        return RANK_WRITE
    read_only = normalized["read_only"]
    destructive = normalized["destructive"]
    if read_only and destructive:
        # Contradictory claim ("read-only and destructive"): fail closed.
        return RANK_WRITE
    if read_only:
        return RANK_READ_ONLY
    if destructive:
        return RANK_WRITE
    return RANK_NEUTRAL


def effective_read_only(annotations: Any) -> bool:
    """True only when the annotation set *proves* a read-only tool."""
    normalized = normalize_annotations(annotations)
    if normalized is None:
        return False
    return bool(normalized["read_only"]) and not normalized["destructive"]


@dataclass(frozen=True)
class AnnotationPin:
    """A pinned annotation hint set for one tool of one server."""

    server: str
    tool: str
    hint_digest: str
    pinned_at: str = ""
    pinned_by: str = ""

    def to_dict(self) -> Dict[str, str]:
        """Serialise the pin."""
        return {
            "server": self.server,
            "tool": self.tool,
            "hint_digest": self.hint_digest,
            "pinned_at": self.pinned_at,
            "pinned_by": self.pinned_by,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "AnnotationPin":
        """Rebuild a pin.  Fails closed.

        A pin without a usable ``hint_digest`` is refused: a pin that was
        never proven is not a pin, and accepting one would let a drifted or
        forged record pass as continuity.
        """
        if not isinstance(data, Mapping):
            raise AnnotationPinError("pin record must be a mapping")
        server = data.get("server")
        tool = data.get("tool")
        digest = data.get("hint_digest")
        if not isinstance(server, str) or not server:
            raise AnnotationPinError("pin record needs a non-empty server")
        if not isinstance(tool, str) or not tool:
            raise AnnotationPinError("pin record needs a non-empty tool")
        if not isinstance(digest, str) or not digest.strip():
            raise AnnotationPinError("pin record needs a non-empty hint_digest")
        pinned_at = data.get("pinned_at") or ""
        pinned_by = data.get("pinned_by") or ""
        if not isinstance(pinned_at, str):
            raise AnnotationPinError("pinned_at must be a string")
        if not isinstance(pinned_by, str):
            raise AnnotationPinError("pinned_by must be a string")
        return cls(
            server=server,
            tool=tool,
            hint_digest=digest,
            pinned_at=pinned_at,
            pinned_by=pinned_by,
        )


class TrustTable:
    """Operator-written per-server trust.

    The table is written by the operator, never read from the server.  A
    server that is not listed is **untrusted**: its annotations are ignored
    entirely and the tool is treated as write-capable.

    Default: untrusted.  (MCP spec, 2026-07-28, as quoted by outsideloop:
    "clients MUST consider tool annotations to be untrusted unless they come
    from trusted servers.")
    """

    def __init__(self, trusted_servers: Optional[Iterable[str]] = None) -> None:
        self._trusted: set[str] = set(trusted_servers or ())

    def trust(self, server: str) -> None:
        """Mark a server trusted (operator action)."""
        if not server:
            raise AnnotationPinError("server required")
        self._trusted.add(server)

    def distrust(self, server: str) -> None:
        """Remove a server from the trusted set."""
        self._trusted.discard(server)

    def is_trusted(self, server: str) -> bool:
        """True only for an explicitly trusted server."""
        return server in self._trusted

    def trusted_servers(self) -> Tuple[str, ...]:
        """The trusted servers, sorted."""
        return tuple(sorted(self._trusted))

    def to_dict(self) -> Dict[str, Any]:
        """Serialise the table."""
        return {"trusted_servers": list(self.trusted_servers())}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "TrustTable":
        """Rebuild the table.  Unknown or malformed entries are ignored."""
        if not isinstance(data, Mapping):
            raise AnnotationPinError("trust table must be a mapping")
        raw = data.get("trusted_servers") or ()
        if not isinstance(raw, (list, tuple, set)):
            raise AnnotationPinError("trusted_servers must be a list")
        return cls(s for s in raw if isinstance(s, str) and s)


@dataclass(frozen=True)
class _PinnedMaterial:
    """The pinned hint vector, kept live next to the digest.

    The portable pin record carries only the digest; the direction of a flip
    (safe narrowing vs dangerous widening) needs the *pinned* claim, not just
    the current one.  The registry therefore keeps the material in memory.
    When a pin is restored from an exported record alone, the material is
    unknown and verification degrades to ``DRIFT`` -- fail closed.
    """

    annotations: Optional[Dict[str, Any]]
    schema_hash: str
    rank: int


def hint_digest(annotations: Any, schema: Optional[Mapping[str, Any]]) -> str:
    """The digest of one tool's claimed effect: hints + schema hash.

    The version string is not part of it -- servers repoint behaviour behind a
    stable version, so the pin is on the artifact, not on the label.
    """
    payload = {
        "hints": _hint_vector(annotations),
        "schema_hash": hash_schema(schema),
    }
    return _sha256(_canonical(payload))


def _hint_vector(annotations: Any) -> Dict[str, Any]:
    """Canonical form of an annotation set, or a malformed marker."""
    normalized = normalize_annotations(annotations)
    if normalized is None:
        return {"valid": False, "annotations": None, "raw": _canonical(annotations)}
    return {"valid": True, "annotations": normalized}


class AnnotationRegistry:
    """Registry of annotation-hint pins, with a per-server trust table.

    The gate calls :meth:`requires_confirmation` before letting a call
    through; this module never touches the gate itself.
    """

    def __init__(self, trust: Optional[TrustTable] = None) -> None:
        self._pins: Dict[Tuple[str, str], AnnotationPin] = {}
        self._material: Dict[Tuple[str, str], _PinnedMaterial] = {}
        self._trust = trust if trust is not None else TrustTable()

    # -- trust -----------------------------------------------------------
    @property
    def trust(self) -> TrustTable:
        """The operator-written trust table."""
        return self._trust

    def is_trusted(self, server: str) -> bool:
        """True only for an explicitly trusted server."""
        return self._trust.is_trusted(server)

    # -- pinning ---------------------------------------------------------
    def pin(
        self,
        server: str,
        tool: str,
        annotations: Any,
        schema: Optional[Mapping[str, Any]],
        pinned_by: str,
        pinned_at: str = "",
    ) -> AnnotationPin:
        """Pin a tool's claimed effect (first discovery, or a human re-pin).

        A human re-pin is what releases a tool after a dangerous-direction
        flip: the operator re-approves the *new* claim, and the pin moves.
        """
        if not server:
            raise AnnotationPinError("server required")
        if not tool:
            raise AnnotationPinError("tool required")
        if not pinned_by:
            raise AnnotationPinError("pinned_by required")
        digest = hint_digest(annotations, schema)
        pin = AnnotationPin(
            server=server,
            tool=tool,
            hint_digest=digest,
            pinned_at=pinned_at,
            pinned_by=pinned_by,
        )
        key = (server, tool)
        self._pins[key] = pin
        self._material[key] = _PinnedMaterial(
            annotations=normalize_annotations(annotations),
            schema_hash=hash_schema(schema),
            rank=capability_rank(annotations),
        )
        return pin

    def is_pinned(self, server: str, tool: str) -> bool:
        """True when this tool has a pin."""
        return (server, tool) in self._pins

    def get_pin(self, server: str, tool: str) -> Optional[AnnotationPin]:
        """The pin for a tool, or ``None``."""
        return self._pins.get((server, tool))

    def pins(self) -> Tuple[AnnotationPin, ...]:
        """Every pin, sorted by (server, tool)."""
        return tuple(self._pins[key] for key in sorted(self._pins))

    def export_pins(self) -> Dict[str, Dict[str, str]]:
        """Export the pins as plain records (portable, digest-only)."""
        return {f"{s}/{t}": pin.to_dict() for (s, t), pin in sorted(self._pins.items())}

    def restore_pins(self, records: Mapping[str, Any]) -> int:
        """Restore exported pins.

        The exported record carries only the digest, so the pinned *claim*
        behind it is unknown: a restored pin verifies only against the digest
        it carries and otherwise degrades to ``DRIFT``.  Fails closed.
        """
        if not isinstance(records, Mapping):
            raise AnnotationPinError("pin records must be a mapping")
        count = 0
        for raw in records.values():
            if not isinstance(raw, Mapping):
                continue
            try:
                pin = AnnotationPin.from_dict(raw)
            except AnnotationPinError:
                continue
            key = (pin.server, pin.tool)
            self._pins[key] = pin
            self._material.pop(key, None)
            count += 1
        return count

    # -- verification ----------------------------------------------------
    def verify(
        self,
        server: str,
        tool: str,
        annotations: Any,
        schema: Optional[Mapping[str, Any]],
    ) -> str:
        """Classify a tool's claimed effect against its pin.

        Returns one of ``OK``, ``SAFE_FLIP``, ``DANGEROUS_FLIP``, ``DRIFT`` or
        ``UNPINNED``.

        The order of the questions matters:

        1. An untrusted server's annotations are ignored -- the tool is
           write-capable whatever it claims, so there is no hint continuity
           to judge and the tool is treated as never-pinned.
        2. A malformed or missing annotation set is fail-closed
           write-capable; against a pin that claimed read-only, that is a
           dangerous-direction flip; against any other pin it is drift.
        3. A schema change is drift, whatever the hints say -- the artifact
           moved.  (A version change is invisible here on purpose: the pin
           is on the schema, not on the version string.)
        4. Unchanged hints and schema are ``OK``.
        5. A narrowed claim (destructive -> read-only) is ``SAFE_FLIP``: the
           safe direction, accepted silently, and the pin is updated.
        6. A widened claim (read-only -> destructive) is ``DANGEROUS_FLIP``:
           the pin is *not* updated, and the gate must re-arm confirmation
           until a human re-pins.
        """
        key = (server, tool)
        if not self._trust.is_trusted(server):
            return UNPINNED
        if key not in self._pins:
            return UNPINNED
        material = self._material.get(key)
        if material is None:
            # Restored from an exported record: the pinned claim is unknown.
            # Fail closed -- the digest may still match, but a flip could
            # not be classified, so it is drift.
            return DRIFT

        current_normalized = normalize_annotations(annotations)
        current_schema_hash = hash_schema(schema)

        if material.schema_hash != current_schema_hash:
            return DRIFT

        if current_normalized is None:
            # Malformed / missing hints: fail closed to write-capable.
            if material.rank == RANK_READ_ONLY:
                return DANGEROUS_FLIP
            return DRIFT

        if material.annotations is None:
            # The pin itself was taken over a malformed hint set.
            return DRIFT

        if material.annotations == current_normalized:
            return OK

        current_rank = capability_rank(current_normalized)
        if current_rank < material.rank:
            return SAFE_FLIP
        if current_rank > material.rank:
            return DANGEROUS_FLIP
        # Same rank, different hints: neither narrower nor wider, but the
        # claimed effect changed (a new hint appeared, one was renamed).
        return DRIFT

    def accept_safe_flip(
        self,
        server: str,
        tool: str,
        annotations: Any,
        schema: Optional[Mapping[str, Any]],
        pinned_by: str = "system",
        pinned_at: str = "",
    ) -> Optional[AnnotationPin]:
        """Move the pin forward over a *safe* flip.

        Only a narrowing may be accepted silently.  A dangerous flip is
        refused here -- it needs a human, which calls ``pin()`` explicitly.
        """
        outcome = self.verify(server, tool, annotations, schema)
        if outcome != SAFE_FLIP:
            return None
        return self.pin(server, tool, annotations, schema, pinned_by, pinned_at)

    # -- gate interface --------------------------------------------------
    def requires_confirmation(
        self,
        server: str,
        tool: str,
        annotations: Any,
        schema: Optional[Mapping[str, Any]],
    ) -> bool:
        """True when the human-in-the-loop step must be re-armed.

        The gate calls this before letting a call through.  Confirmation is
        required for ``DANGEROUS_FLIP``, ``DRIFT`` and ``UNPINNED`` -- and for
        a missing or malformed annotation set, which is fail-closed
        write-capable and therefore never silently allowed.
        """
        if not self._trust.is_trusted(server):
            return True
        if normalize_annotations(annotations) is None:
            return True
        outcome = self.verify(server, tool, annotations, schema)
        return outcome in (DANGEROUS_FLIP, DRIFT, UNPINNED)

    def rearm_reason(
        self,
        server: str,
        tool: str,
        annotations: Any,
        schema: Optional[Mapping[str, Any]],
    ) -> str:
        """Why confirmation is required (empty string when it is not)."""
        if not self._trust.is_trusted(server):
            return (
                f"server '{server}' is not in the operator's trust table; its "
                "annotations are ignored and the tool is treated as write-capable"
            )
        if normalize_annotations(annotations) is None:
            return (
                f"tool '{tool}' on server '{server}' has a missing or malformed "
                "annotation set; treated as write-capable"
            )
        outcome = self.verify(server, tool, annotations, schema)
        if outcome == DANGEROUS_FLIP:
            return (
                f"tool '{tool}' on server '{server}' widened its claimed effect "
                "(read-only -> destructive); the pin was not updated and a human "
                "must re-approve"
            )
        if outcome == DRIFT:
            return (
                f"tool '{tool}' on server '{server}' drifted from its pin "
                "(the artifact behind the hint set changed)"
            )
        if outcome == UNPINNED:
            return (
                f"tool '{tool}' on server '{server}' has no annotation pin; "
                "pin it before trusting its claimed effect"
            )
        return ""


def stdlib_only() -> bool:
    """AST check: stdlib only."""
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
    """Self-check: pin, verify, safe flip, dangerous flip, drift."""
    registry = AnnotationRegistry()
    registry.trust.trust("fs")
    schema = {"type": "object", "properties": {"path": {"type": "string"}}}

    # (a) discovery pins the hint set; the next session verifies OK.
    registry.pin("fs", "read", {"read_only": True, "destructive": False}, schema, "operator")
    assert registry.verify("fs", "read", {"read_only": True, "destructive": False}, schema) == OK
    assert registry.requires_confirmation("fs", "read", {"read_only": True, "destructive": False}, schema) is False

    # (b) safe flip: destructive -> read-only, silently accepted.
    registry.pin("fs", "write", {"read_only": False, "destructive": True}, schema, "operator")
    assert registry.verify("fs", "write", {"read_only": True, "destructive": False}, schema) == SAFE_FLIP
    registry.accept_safe_flip("fs", "write", {"read_only": True, "destructive": False}, schema)
    assert registry.verify("fs", "write", {"read_only": True, "destructive": False}, schema) == OK

    # (c) dangerous flip: read-only -> destructive, pin not updated.
    assert registry.verify("fs", "read", {"read_only": False, "destructive": True}, schema) == DANGEROUS_FLIP
    assert registry.requires_confirmation("fs", "read", {"read_only": False, "destructive": True}, schema) is True
    assert registry.get_pin("fs", "read").hint_digest == hint_digest(
        {"read_only": True, "destructive": False}, schema
    )

    # (d) missing annotation: fail closed to write-capable.
    assert registry.verify("fs", "read", None, schema) == DANGEROUS_FLIP
    assert registry.requires_confirmation("fs", "read", None, schema) is True

    # (e) version is not part of the pin; a schema change behind a stable
    # version is drift.
    assert registry.verify("fs", "read", {"read_only": True, "destructive": False}, schema) == OK
    assert registry.verify("fs", "read", {"read_only": True, "destructive": False},
                           {"type": "object", "properties": {"path": {"type": "integer"}}}) == DRIFT

    # An untrusted server's annotations are ignored entirely.
    other = AnnotationRegistry()
    other.pin("rogue", "x", {"read_only": True, "destructive": False}, schema, "operator")
    assert other.verify("rogue", "x", {"read_only": True, "destructive": False}, schema) == UNPINNED
    assert other.requires_confirmation("rogue", "x", {"read_only": True, "destructive": False}, schema) is True

    assert stdlib_only()
    print(
        "annotation-pinning OK: pin, verify, safe flip, dangerous flip, "
        "drift, fail-closed"
    )


if __name__ == "__main__":
    main()
