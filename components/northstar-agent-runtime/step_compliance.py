"""in-toto-derived step compliance for multi-step bench tasks (offline).

Absorbs the artifact-rule mechanism of in-toto spec v1.0.0 (``in-toto/specification``,
``in-toto-spec.md`` §4.3.2/§4.3.3, verified against the specification text):
a Layout declares the expected steps of a multi-step task and, per step, the
expected materials/products as *artifact rules*; each executed step is recorded
as a Link (materials/products with hashes); verification evaluates the seven
artifact rules in order, where the first matching rule *consumes* the artifact::

    MATCH <pattern> [IN <source-path-prefix>] WITH (MATERIALS|PRODUCTS)
        [IN <destination-path-prefix>] FROM <step>
    CREATE <pattern>
    DELETE <pattern>
    MODIFY <pattern>
    ALLOW <pattern>
    DISALLOW <pattern>
    REQUIRE <file>

The MATCH rule is the heart of the mechanism for an agent bench: it requires a
step's material to have the same hash as a previous step's material or product
(after optional path-prefix stripping), so a tampered or swapped artifact
mid-chain fails verification. Rule order is semantically significant
(ALLOW-then-DISALLOW and DISALLOW-first give different verdicts); artifacts
nobody's rule consumes also fail.

Honestly scoped: this is the **rule engine only**. in-toto's Layout signature
verification, functionary public keys/thresholds, expiration, and inspections
(§4) are NOT implemented — a deterministic offline bench has no signers, and
nothing here claims who authorized what. What the bench asserts is narrower:
"the steps ran in the laid-out order and artifacts flowed between them
untampered". Signatures remain the job of the audit chain (Rekor-anchored),
not of this module.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from typing import Mapping

__all__ = [
    "ArtifactMap",
    "Link",
    "StepLayout",
    "StepVerdict",
    "LayoutVerdict",
    "Rule",
    "RuleError",
    "parse_rule",
    "verify_step",
    "verify_layout",
]

#: path -> sha256 hex digest
ArtifactMap = dict[str, str]

_MATCH_RE = re.compile(
    r"^MATCH\s+(?P<pattern>\S+)"
    r"(?:\s+IN\s+(?P<src>\S+))?"
    r"\s+WITH\s+(?P<side>MATERIALS|PRODUCTS)"
    r"(?:\s+IN\s+(?P<dst>\S+))?"
    r"\s+FROM\s+(?P<step>\S+)$"
)


class RuleError(ValueError):
    """A rule string is not one of the seven in-toto artifact rules."""


@dataclass(frozen=True)
class Rule:
    """One parsed in-toto artifact rule."""

    kind: str  # CREATE|DELETE|MODIFY|MATCH|ALLOW|DISALLOW|REQUIRE
    pattern: str
    src_prefix: str = ""
    with_side: str = ""  # MATERIALS|PRODUCTS (MATCH only)
    dst_prefix: str = ""
    from_step: str = ""  # MATCH only


@dataclass(frozen=True)
class Link:
    """Recorded execution of one layout step: materials and products w/ hashes."""

    name: str
    materials: ArtifactMap = field(default_factory=dict)
    products: ArtifactMap = field(default_factory=dict)


@dataclass(frozen=True)
class StepLayout:
    """Expected rules for one step of the layout."""

    name: str
    expected_materials: tuple[str, ...] = ()
    expected_products: tuple[str, ...] = ()


@dataclass(frozen=True)
class StepVerdict:
    ok: bool
    reasons: tuple[str, ...] = ()


@dataclass(frozen=True)
class LayoutVerdict:
    ok: bool
    step_verdicts: dict[str, StepVerdict]
    reasons: tuple[str, ...] = ()


def parse_rule(text: str) -> Rule:
    """Parse one in-toto artifact rule string; raises RuleError on unknown forms."""
    text = text.strip()
    match = _MATCH_RE.match(text)
    if match:
        return Rule(
            kind="MATCH",
            pattern=match.group("pattern"),
            src_prefix=match.group("src") or "",
            with_side=match.group("side"),
            dst_prefix=match.group("dst") or "",
            from_step=match.group("step"),
        )
    for kind in ("CREATE", "DELETE", "MODIFY", "ALLOW", "DISALLOW", "REQUIRE"):
        prefix = kind + " "
        if text.startswith(prefix) and len(text) > len(prefix):
            return Rule(kind=kind, pattern=text[len(prefix):].strip())
    raise RuleError(f"not an in-toto artifact rule: {text!r}")


def _check_match(
    rule: Rule,
    path: str,
    digest: str,
    link: Link,
    links_by_step: Mapping[str, Link],
    step_order: Mapping[str, int],
) -> str | None:
    """MATCH: artifact must equal (path + hash) an upstream step's artifact."""
    if rule.from_step not in links_by_step:
        return f"MATCH: step '{rule.from_step}' has no recorded link"
    if step_order.get(rule.from_step, 0) >= step_order.get(link.name, 0):
        return (
            f"MATCH: step '{rule.from_step}' is not an earlier step "
            f"than '{link.name}'"
        )
    relative = path
    if rule.src_prefix:
        if not path.startswith(rule.src_prefix):
            # Prefix does not cover this artifact: the rule does not match it,
            # it stays in the queue for a later rule (per in-toto §4.3.3).
            return "SKIP"
        relative = path[len(rule.src_prefix):]
    upstream = links_by_step[rule.from_step]
    pool = upstream.materials if rule.with_side == "MATERIALS" else upstream.products
    for up_path, up_digest in pool.items():
        up_relative = up_path
        if rule.dst_prefix:
            if not up_path.startswith(rule.dst_prefix):
                continue
            up_relative = up_path[len(rule.dst_prefix):]
        if up_relative == relative:
            if up_digest != digest:
                return (
                    f"MATCH: '{path}' hash differs from step "
                    f"'{rule.from_step}' {rule.with_side.lower()} (tampered in transit)"
                )
            return None
    return (
        f"MATCH: '{path}' not found among step '{rule.from_step}' "
        f"{rule.with_side.lower()}"
    )


def _apply_rules(
    rules: tuple[Rule, ...],
    materials: ArtifactMap,
    products: ArtifactMap,
    which: str,
    link: Link,
    links_by_step: Mapping[str, Link],
    step_order: Mapping[str, int],
) -> str | None:
    """Evaluate rules in order against one queue; failure reason or None."""
    remaining = dict(materials if which == "materials" else products)
    for rule in rules:
        if rule.kind == "REQUIRE":
            # Presence check against the whole link; consumes nothing.
            if rule.pattern not in link.materials and rule.pattern not in link.products:
                return f"REQUIRE {rule.pattern}: missing from link '{link.name}'"
            continue
        for path in [p for p in remaining if fnmatch.fnmatchcase(p, rule.pattern)]:
            if rule.kind == "DISALLOW":
                return (
                    f"DISALLOW {rule.pattern}: artifact '{path}' reached a "
                    f"disallow rule in link '{link.name}'"
                )
            if rule.kind == "CREATE":
                if path in link.materials:
                    return f"CREATE {rule.pattern}: '{path}' already in materials"
            elif rule.kind == "DELETE":
                if path in link.products:
                    return f"DELETE {rule.pattern}: '{path}' still in products"
            elif rule.kind == "MODIFY":
                if path not in link.materials:
                    return f"MODIFY {rule.pattern}: '{path}' missing from materials"
                if path not in link.products:
                    return f"MODIFY {rule.pattern}: '{path}' missing from products"
                if link.materials[path] == link.products[path]:
                    return f"MODIFY {rule.pattern}: '{path}' hash unchanged"
            elif rule.kind == "MATCH":
                problem = _check_match(
                    rule, path, remaining[path], link, links_by_step, step_order
                )
                if problem == "SKIP":
                    continue
                if problem:
                    return problem
            # First matching rule consumes the artifact (ALLOW consumes too).
            if rule.kind == "MODIFY":
                # MODIFY consumes from both queues.
                materials.pop(path, None)
                products.pop(path, None)
                remaining.pop(path, None)
            else:
                remaining.pop(path, None)
    if remaining:
        return (
            f"unconsumed artifacts in link '{link.name}' "
            f"({which}): {', '.join(sorted(remaining))}"
        )
    return None


def verify_step(
    layout_step: StepLayout,
    link: Link,
    links_by_step: Mapping[str, Link],
    step_order: Mapping[str, int],
) -> StepVerdict:
    """Verify one step's materials/products against its layout rules."""
    problems: list[str] = []
    materials = dict(link.materials)
    products = dict(link.products)
    rules = tuple(parse_rule(text) for text in layout_step.expected_materials)
    problem = _apply_rules(
        rules, materials, products, "materials", link, links_by_step, step_order
    )
    if problem:
        problems.append(problem)
    rules = tuple(parse_rule(text) for text in layout_step.expected_products)
    problem = _apply_rules(
        rules, materials, products, "products", link, links_by_step, step_order
    )
    if problem:
        problems.append(problem)
    return StepVerdict(ok=not problems, reasons=tuple(problems))


def verify_layout(
    steps: tuple[StepLayout, ...] | list[StepLayout],
    links: tuple[Link, ...] | list[Link],
) -> LayoutVerdict:
    """Verify a full trajectory against the layout.

    Step-name sequence must equal the layout order exactly: a skipped step, a
    reordered step, or an extra step not declared in the layout all fail.
    """
    step_names = [s.name for s in steps]
    link_names = [link.name for link in links]
    problems: list[str] = []
    if link_names != step_names:
        problems.append(
            f"step sequence {link_names} != layout {step_names} "
            "(skipped, reordered, or undeclared step)"
        )
        return LayoutVerdict(ok=False, step_verdicts={}, reasons=tuple(problems))
    links_by_step = {link.name: link for link in links}
    step_order = {name: index for index, name in enumerate(step_names)}
    verdicts: dict[str, StepVerdict] = {}
    for layout_step in steps:
        verdict = verify_step(
            layout_step, links_by_step[layout_step.name], links_by_step, step_order
        )
        verdicts[layout_step.name] = verdict
        if not verdict.ok:
            problems.extend(f"{layout_step.name}: {reason}" for reason in verdict.reasons)
    return LayoutVerdict(
        ok=not problems, step_verdicts=verdicts, reasons=tuple(problems)
    )
