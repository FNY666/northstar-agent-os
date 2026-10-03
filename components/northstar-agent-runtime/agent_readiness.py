"""Agent-readiness probes for public-facing agent UI (one-hundred-first batch).

Absorbs the 2026 AI-accessibility research thread: "Agent Readiness" —
screen readers and AI agents read the *same* accessibility tree, so
BFSG/EAA compliance is the foundation of legible agent UI. The EU
Accessibility Act is enforced (fines up to uncapped in Sweden); AI-generated
UI routinely fails EN 301 549, and automated checkers find only ~1/3 of
problems. The governance absorption: a public-facing action card whose
accessibility tree is illegible is *unverifiable presentation* — the
decision may be fine, but the human (or assistive agent) cannot check it.

This module renders an 84th-batch ``ActionCard`` into a simplified,
deterministic accessibility tree (role / name / states / input paths) and
runs four fail-closed probes:

* named actions — every actionable element has a non-blank accessible name
  (no unnamed buttons). Finding: ``readiness:unnamed_action``.
* irreversible marked — every action the caller declares irreversible (from
  ground truth, e.g. the card's risk tier — the tree itself is untrusted
  for this) is marked as such in the tree, either on the node or via a
  ``destructive-warning`` ancestor. Finding: ``readiness:hidden_irreversible``.
* reachable paths — every actionable element is reachable via at least one
  *accessible* input path (``keyboard`` or ``at``); pointer-only (or
  unreachable) actions fail. Finding: ``readiness:inaccessible_path``.
* round-trip stability — serialize -> parse -> serialize is byte-identical;
  content the canonical form cannot represent is a finding, never silently
  dropped. Finding: ``readiness:unstable_tree``.

A card with any finding classifies ``NON_AUTHORITATIVE`` *for
presentation* (87th-batch binary semantics: no partial tier — the
presentation is either trustworthy or it is not). The underlying *decision*
is untouched by this module; presentation trust and decision trust are
separate axes.

Design rules: stdlib only, deterministic (no wall-clock, no randomness),
fail-closed (malformed input -> findings, never exceptions out of the probe
entry points), probes return findings as values.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Collection, Sequence

from evidence_tiers import EvidenceTier

# ---------------------------------------------------------------------------
# Vocabulary (closed sets — anything outside them is unrepresentable)
# ---------------------------------------------------------------------------

#: Roles that can carry an accessible name and be acted upon.
ACTIONABLE_ROLES: tuple[str, ...] = (
    "button",
    "link",
    "checkbox",
    "menuitem",
    "switch",
    "textbox",
)

#: Structural / informational roles. Never actionable; names optional.
STRUCTURAL_ROLES: tuple[str, ...] = (
    "dialog",
    "heading",
    "text",
    "list",
    "listitem",
    "region",
    "generic",
)

KNOWN_ROLES: frozenset[str] = frozenset(ACTIONABLE_ROLES + STRUCTURAL_ROLES)

#: Input modalities. Only keyboard/at are *accessible* paths; pointer-only
#: reachability is a finding.
KNOWN_MODALITIES: frozenset[str] = frozenset({"keyboard", "at", "pointer"})
ACCESSIBLE_MODALITIES: frozenset[str] = frozenset({"keyboard", "at"})

#: States the tree model understands.
KNOWN_STATES: frozenset[str] = frozenset(
    {
        "focusable",
        "disabled",
        "irreversible",
        "destructive-warning",
        "expanded",
        "checked",
    }
)

#: Finding codes emitted by the probes.
UNNAMED_ACTION = "readiness:unnamed_action"
HIDDEN_IRREVERSIBLE = "readiness:hidden_irreversible"
INACCESSIBLE_PATH = "readiness:inaccessible_path"
UNSTABLE_TREE = "readiness:unstable_tree"


# ---------------------------------------------------------------------------
# Tree model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class A11yNode:
    """One node in the simplified accessibility tree.

    ``paths`` is the set of input modalities that can reach this node;
    ``states`` a subset of ``KNOWN_STATES``. Construction does *not*
    validate — probes and the parser are where validation lives, so
    hand-built trees with unrepresentable content can be tested for
    round-trip stability.
    """

    role: str
    name: str = ""
    states: tuple[str, ...] = ()
    paths: tuple[str, ...] = ()
    children: tuple["A11yNode", ...] = ()

    def __post_init__(self) -> None:
        # Canonical order at construction: states/paths are sets with a
        # canonical serialization, so sort them once here.
        object.__setattr__(self, "states", tuple(sorted(self.states)))
        object.__setattr__(self, "paths", tuple(sorted(self.paths)))

    def is_actionable(self) -> bool:
        return self.role in ACTIONABLE_ROLES

    def walk(self) -> "list[tuple[tuple[int, ...], A11yNode]]":
        """Depth-first (path, node) pairs; path is the child-index tuple."""
        out: list[tuple[tuple[int, ...], A11yNode]] = []

        def _rec(node: "A11yNode", path: tuple[int, ...]) -> None:
            out.append((path, node))
            for i, child in enumerate(node.children):
                _rec(child, path + (i,))

        _rec(self, ())
        return out


@dataclass(frozen=True)
class ReadinessFinding:
    """One probe finding. ``node_path`` is the child-index path from the
    root, ``/``-joined (``""`` for the root itself)."""

    code: str
    node_path: str
    detail: str

    def as_dict(self) -> dict[str, Any]:
        return {"code": self.code, "node_path": self.node_path, "detail": self.detail}


def _path_str(path: tuple[int, ...]) -> str:
    return "/".join(str(i) for i in path)


# ---------------------------------------------------------------------------
# Canonical serialization / parsing
# ---------------------------------------------------------------------------


def _escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace("\n", "\\n").replace("|", "\\p")


def _split_fields(line: str) -> list[str]:
    """Split on unescaped ``|``; escaped pipes (``\\p``) stay inside fields."""
    parts: list[str] = []
    cur: list[str] = []
    i = 0
    while i < len(line):
        ch = line[i]
        if ch == "\\" and i + 1 < len(line):
            cur.append(ch)
            cur.append(line[i + 1])
            i += 2
        elif ch == "|":
            parts.append("".join(cur))
            cur = []
            i += 1
        else:
            cur.append(ch)
            i += 1
    parts.append("".join(cur))
    return parts


def _unescape(text: str) -> str:
    out: list[str] = []
    i = 0
    while i < len(text):
        ch = text[i]
        if ch == "\\" and i + 1 < len(text):
            nxt = text[i + 1]
            if nxt == "n":
                out.append("\n")
            elif nxt == "p":
                out.append("|")
            elif nxt == "\\":
                out.append("\\")
            else:
                raise TreeParseError(f"bad escape in {text!r}")
            i += 2
        else:
            out.append(ch)
            i += 1
    return "".join(out)


class TreeParseError(ValueError):
    """Raised by ``parse_tree`` on structurally malformed canonical text."""


def serialize_tree(root: A11yNode) -> str:
    """Deterministic canonical text form of a tree.

    One node per line, depth-indented; fields in fixed order
    ``role|name|states|paths`` with states/paths comma-joined sorted.
    Children are emitted in document order (order is content — the
    serializer never re-sorts).
    """
    lines: list[str] = []

    def _rec(node: A11yNode, depth: int) -> None:
        states = ",".join(sorted(node.states))
        paths = ",".join(sorted(node.paths))
        lines.append(
            "  " * depth + f"{_escape(node.role)}|{_escape(node.name)}|{states}|{paths}"
        )
        for child in node.children:
            _rec(child, depth + 1)

    _rec(root, 0)
    return "\n".join(lines) + "\n"


def parse_tree(text: str) -> A11yNode:
    """Parse canonical text back into a tree.

    Fail-closed normalization: unknown roles collapse to ``"generic"``;
    unknown modalities and states are *dropped* (they are unrepresentable —
    the round-trip probe reports this as ``readiness:unstable_tree`` rather
    than silently keeping them). Structurally malformed input raises
    ``TreeParseError``.
    """
    if not text.endswith("\n") or not text.strip():
        raise TreeParseError("canonical tree text must be non-empty and newline-terminated")

    rows: list[tuple[int, A11yNode]] = []
    for lineno, raw in enumerate(text.split("\n")[:-1], start=1):
        depth = 0
        while raw.startswith("  ", depth * 2):
            depth += 1
        fields = _split_fields(raw[depth * 2 :])
        if len(fields) != 4:
            raise TreeParseError(f"line {lineno}: expected 4 fields, saw {len(fields)}")
        role, name, states_s, paths_s = (_unescape(f) for f in fields)
        if role not in KNOWN_ROLES:
            role = "generic"
        states = (
            tuple(s for s in sorted(states_s.split(",")) if s in KNOWN_STATES)
            if states_s
            else ()
        )
        paths = (
            tuple(p for p in sorted(paths_s.split(",")) if p in KNOWN_MODALITIES)
            if paths_s
            else ()
        )
        rows.append((depth, A11yNode(role=role, name=name, states=states, paths=paths)))

    def _build(idx: int, depth: int) -> tuple[A11yNode, int]:
        node_depth, node = rows[idx]
        if node_depth != depth:
            raise TreeParseError(f"row {idx}: bad indentation depth {node_depth}")
        children: list[A11yNode] = []
        idx += 1
        while idx < len(rows) and rows[idx][0] == depth + 1:
            child, idx = _build(idx, depth + 1)
            children.append(child)
        if idx < len(rows) and rows[idx][0] > depth + 1:
            raise TreeParseError(f"row {idx}: depth jump without parent")
        return (
            A11yNode(
                role=node.role,
                name=node.name,
                states=node.states,
                paths=node.paths,
                children=tuple(children),
            ),
            idx,
        )

    if not rows or rows[0][0] != 0:
        raise TreeParseError("no root node")
    built, next_idx = _build(0, 0)
    if next_idx != len(rows):
        raise TreeParseError("trailing nodes after root subtree")
    return built


# ---------------------------------------------------------------------------
# Probes (each returns findings as values; never raises on tree input)
# ---------------------------------------------------------------------------


def probe_named_actions(root: A11yNode) -> list[ReadinessFinding]:
    """Every actionable element must have a non-blank accessible name."""
    findings: list[ReadinessFinding] = []
    for path, node in root.walk():
        if node.is_actionable() and not node.name.strip():
            findings.append(
                ReadinessFinding(
                    code=UNNAMED_ACTION,
                    node_path=_path_str(path),
                    detail=f"actionable <{node.role}> has no accessible name",
                )
            )
    return findings


def _has_warning_ancestor(root: A11yNode, path: tuple[int, ...]) -> bool:
    """True if the node itself or any ancestor carries destructive-warning."""
    if "destructive-warning" in root.states:
        return True
    cur = root
    for i in path:
        if i >= len(cur.children):
            return False
        cur = cur.children[i]
        if "destructive-warning" in cur.states:
            return True
    return False


def probe_irreversible_marked(
    root: A11yNode, irreversible_names: Collection[str] = ()
) -> list[ReadinessFinding]:
    """Every action declared irreversible (ground truth from the caller —
    e.g. the card's risk tier, never the tree itself) must be marked in
    the tree: ``irreversible`` on the node, or a ``destructive-warning``
    on the node or an ancestor.

    Disabled actions are skipped: they cannot be taken, so marking is moot.
    """
    targets = set(irreversible_names)
    if not targets:
        return []
    findings: list[ReadinessFinding] = []
    for path, node in root.walk():
        if not node.is_actionable() or "disabled" in node.states:
            continue
        if node.name not in targets:
            continue
        if "irreversible" in node.states or _has_warning_ancestor(root, path):
            continue
        findings.append(
            ReadinessFinding(
                code=HIDDEN_IRREVERSIBLE,
                node_path=_path_str(path),
                detail=(
                    f"actionable <{node.role} name={node.name!r}> is declared "
                    "irreversible but carries no irreversible mark and has no "
                    "destructive-warning ancestor"
                ),
            )
        )
    return findings


def probe_reachable_paths(root: A11yNode) -> list[ReadinessFinding]:
    """Every actionable element must be reachable via keyboard or AT.

    Pointer-only (or unreachable) actions fail: a keyboard/AT user — or an
    AT-driven agent — can neither take nor refuse the action.
    """
    findings: list[ReadinessFinding] = []
    for path, node in root.walk():
        if not node.is_actionable():
            continue
        if not (set(node.paths) & ACCESSIBLE_MODALITIES):
            findings.append(
                ReadinessFinding(
                    code=INACCESSIBLE_PATH,
                    node_path=_path_str(path),
                    detail=(
                        f"actionable <{node.role} name={node.name!r}> reachable "
                        f"only via {sorted(node.paths) or 'nothing'}; "
                        "keyboard/AT path required"
                    ),
                )
            )
    return findings


def probe_roundtrip(root: A11yNode) -> list[ReadinessFinding]:
    """serialize -> parse -> serialize must be byte-identical.

    Content the canonical form cannot represent (unknown roles,
    modalities, states) is normalized away by the parser — the tree is
    then *unstable*, reported as a finding, never silently kept.
    """
    try:
        once = serialize_tree(root)
        twice = serialize_tree(parse_tree(once))
    except (TreeParseError, ValueError, AssertionError) as exc:
        return [
            ReadinessFinding(
                code=UNSTABLE_TREE,
                node_path="",
                detail=f"tree does not survive canonical round-trip: {exc}",
            )
        ]
    if once != twice:
        return [
            ReadinessFinding(
                code=UNSTABLE_TREE,
                node_path="",
                detail=(
                    "tree changed across serialize->parse->serialize; it "
                    "contains content the canonical form cannot represent"
                ),
            )
        ]
    return []


def probe_tree(
    root: A11yNode, irreversible_names: Collection[str] = ()
) -> list[ReadinessFinding]:
    """Run all four probes; findings in deterministic probe order."""
    findings: list[ReadinessFinding] = []
    findings.extend(probe_named_actions(root))
    findings.extend(probe_irreversible_marked(root, irreversible_names))
    findings.extend(probe_reachable_paths(root))
    findings.extend(probe_roundtrip(root))
    return findings


# ---------------------------------------------------------------------------
# Presentation classification (87th-batch binary semantics, presentation axis)
# ---------------------------------------------------------------------------


def classify_presentation(findings: Sequence[ReadinessFinding]) -> EvidenceTier:
    """Binary presentation trust: any finding -> NON_AUTHORITATIVE.

    Mirrors the 87th batch's binary evidence tiers with no partial grade:
    the *presentation* is either trustworthy or it is not. The underlying
    *decision* is a separate axis and is untouched by this module.
    """
    if findings:
        return EvidenceTier.NON_AUTHORITATIVE
    return EvidenceTier.AUTHORITATIVE


# ---------------------------------------------------------------------------
# Rendering an ActionCard into an accessibility tree
# ---------------------------------------------------------------------------

#: Risk tiers whose approval is irreversible unless the gate says otherwise.
IRREVERSIBLE_RISK_TIERS: frozenset[str] = frozenset({"tier3", "tier4", "critical"})

APPROVE_NAME = "Approve"
DENY_NAME = "Deny"


def render_card_tree(card: Any) -> A11yNode:
    """Render an 84th-batch ``ActionCard`` into an accessibility tree.

    Deterministic and total: every field of the card that a human approver
    needs becomes a named node. Tier-3+ (irreversible) cards mark the
    approve button ``irreversible`` and the dialog ``destructive-warning``.
    Both approve and deny are keyboard+AT reachable — a deny action that
    only a pointer can reach is a refusal the user cannot express.
    """
    tool = getattr(card, "tool", "") or ""
    call_id = getattr(card, "call_id", "") or ""
    arguments_digest = getattr(card, "arguments_digest", "") or ""
    risk_tier = getattr(card, "risk_tier", "") or ""
    gate = getattr(card, "gate", None)
    checks = list(getattr(gate, "checks", []) or [])
    agent_hint = getattr(card, "agent_hint", "") or ""

    irreversible = risk_tier in IRREVERSIBLE_RISK_TIERS

    check_items = tuple(
        A11yNode(
            role="listitem",
            name=(
                f"{'pass' if getattr(c, 'passed', False) else 'FAIL'} "
                f"{getattr(c, 'id', 'check')}"
                + (f" - {getattr(c, 'detail', '')}" if getattr(c, "detail", "") else "")
            ),
            paths=("keyboard", "at"),
        )
        for c in checks
    )

    children: list[A11yNode] = [
        A11yNode(role="heading", name=f"Approval requested: {tool}", paths=("keyboard", "at")),
        A11yNode(role="text", name=f"call {call_id}", paths=("keyboard", "at")),
        A11yNode(role="text", name=f"arguments {arguments_digest}", paths=("keyboard", "at")),
        A11yNode(role="text", name=f"risk tier {risk_tier}", paths=("keyboard", "at")),
    ]
    if agent_hint:
        # The agent's words are content, never the action description:
        # quarantined under an explicit UNTRUSTED label (84th-batch rule).
        children.append(
            A11yNode(
                role="text",
                name=f"the agent claims: {agent_hint} (UNTRUSTED)",
                paths=("keyboard", "at"),
            )
        )
    children.append(
        A11yNode(
            role="list", name="gate checks", children=check_items, paths=("keyboard", "at")
        )
    )
    children.append(
        A11yNode(
            role="button",
            name=APPROVE_NAME,
            states=("irreversible",) if irreversible else (),
            paths=("keyboard", "at", "pointer"),
        )
    )
    children.append(
        A11yNode(
            role="button",
            name=DENY_NAME,
            paths=("keyboard", "at", "pointer"),
        )
    )
    return A11yNode(
        role="dialog",
        name=f"Action card for {tool}",
        states=("destructive-warning",) if irreversible else (),
        paths=("keyboard", "at"),
        children=tuple(children),
    )


def irreversible_actions_for_card(card: Any) -> frozenset[str]:
    """Ground-truth irreversible action names for a card (from risk tier)."""
    risk_tier = getattr(card, "risk_tier", "") or ""
    if risk_tier in IRREVERSIBLE_RISK_TIERS:
        return frozenset({APPROVE_NAME})
    return frozenset()


def assess_card_presentation(card: Any) -> dict[str, Any]:
    """Render + probe + classify a card's presentation.

    Returns ``{"tree": ..., "findings": [...], "tier": ...}`` as plain
    data. Never raises on card input.
    """
    try:
        tree = render_card_tree(card)
        findings = probe_tree(tree, irreversible_actions_for_card(card))
        tier = classify_presentation(findings)
        return {
            "tree": serialize_tree(tree),
            "findings": [f.as_dict() for f in findings],
            "tier": tier.value,
        }
    except Exception as exc:  # defensive: an unrenderable card is unpresentable
        finding = ReadinessFinding(
            code=UNSTABLE_TREE, node_path="", detail=f"card failed to render: {exc}"
        )
        return {
            "tree": None,
            "findings": [finding.as_dict()],
            "tier": EvidenceTier.NON_AUTHORITATIVE.value,
        }


# ---------------------------------------------------------------------------
# Audit event helper
# ---------------------------------------------------------------------------


def readiness_audit_event(
    card_id: str,
    findings: Sequence[ReadinessFinding],
    tier: EvidenceTier,
) -> dict[str, Any]:
    """Build an ``audit.ndjson/1``-shaped event for a presentation assessment."""
    return {
        "event": "readiness.presentation_assessed",
        "card_id": card_id,
        "finding_codes": sorted({f.code for f in findings}),
        "n_findings": len(findings),
        "presentation_tier": tier.value,
    }
