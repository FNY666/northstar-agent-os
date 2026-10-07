"""Template engine interface (Mustache / Jinja rendering discipline, simulated).

Research motivation: prompts, receipts, notification bodies and audit
narratives all need *string assembly* -- but raw f-strings are an
injection sink (HTML/JS/command contexts) and untyped concatenation
loses the audit trail of *what* was substituted *where*. Mustache
(logic-less templates, ``{{var}}`` / ``{{{var}}}`` / ``{{#section}}`` /
``{{> partial}}``) and Jinja2 converged on the same bookkeeping shape:

- *named templates*: registered once, pinned by digest, rendered many
  times;
- *escaped interpolation*: ``{{var}}`` escapes for HTML by default;
  ``{{{var}}}`` / ``{{& var}}`` bypass explicitly (the bypass is
  visible in the template, never silent);
- *sections*: ``{{#list}}...{{/list}}`` iterates, ``{{^x}}`` renders on
  falsy -- the only "logic" allowed;
- *partials*: ``{{> name}}`` includes a registered sub-template, so a
  receipt body and a notification digest share one footer without
  copy-paste.

This module is the *bookkeeping* half of that shape:

- ``TemplateEngine`` -- owns the template registry.
  ``register()`` pins a template (syntax-checked at registration,
  ``sha256:`` digest), ``partial()`` registers a partial invocable via
  ``{{> name}}``, ``render()`` interpolates a caller-supplied context
  and returns a frozen ``RenderedTemplate`` pinning the template
  digest, the canonicalized context and the seq.
- ``escape()`` -- the module-level (and ``TemplateEngine.escape``)
  HTML escaper used for ``{{var}}``; ``quote=True``.
- ``template_engine_audit_event(kind, ...)`` -- ``audit.ndjson/1``
  records (``template-registered`` / ``partial-registered`` /
  ``rendered`` / ``rejected``); caller-supplied seqs only.

Fail-closed edges (fail loudly, never guess):

- Template names are non-empty ``str`` and unique;
  ``DuplicateTemplateError`` on re-registration. ``register()`` parses
  eagerly: unclosed ``{{`` / unbalanced ``{{/x}}`` / stray closing
  tags raise ``TemplateSyntaxError`` -- a broken template never enters
  the registry.
- ``render()`` on an unknown name raises ``UnknownTemplateError``;
  ``{{> name}}`` on an unregistered partial raises
  ``UnknownPartialError``. Partials that include each other past
  ``MAX_PARTIAL_DEPTH`` (32) raise ``RecursionDepthError`` -- a
  self-referential partial is a hang, refused as data.
- A *missing* variable renders as the empty string (Mustache spec
  semantics -- documented, not silent: the digest still binds the
  canonicalized context that was actually supplied). Interpolating a
  mapping or list raises ``BadValueError`` -- use a ``{{#section}}``.
- Context values must be canonicalizable: ``None`` / bool / int /
  ``str`` / finite float / list / str-keyed mapping. ``NaN`` / ``inf``,
  integral floats, and ints with ``abs >= 2**53`` are refused with
  ``BadContextError`` (the batch-5 JCS float-loss caveat). Bool is not
  int: ``True`` interpolates as ``"true"``, never ``"1"``.
- Mutation seqs are caller-supplied strictly-increasing ints
  (no wall-clock); rewinds raise ``SeqOrderError``.
- ``{{var}}`` output is HTML-escaped; ``{{{var}}}`` and ``{{& var}}``
  are the *only* unescaped paths, and both are greppable in the
  template source. ``escape()`` is deterministic: ``html.escape(...,
  quote=True)``.

Honest scope:

- This is a *rendering* ledger, not a sandbox: ``{{#section}}`` gives
  iteration, but there are no filters, no attribute calls, no
  evaluation -- there is deliberately nothing to sandbox. A host that
  registers ``{{{cmd}}}`` and renders attacker input gets exactly the
  injection it asked for; the unescaped tag is the visible audit
  marker.
- The digest pins the *reported* context, not the truth of it; a lying
  host renders a lying receipt. In-memory only: pair with the durable
  audit writer if template history must survive a restart.
  ``main()`` self-checks the shape.
"""

from __future__ import annotations

import html
import math
import re
import threading
from dataclasses import dataclass
from typing import Any, Mapping, Optional, Sequence, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json, jcs_sha256_hex
except Exception:  # pragma: no cover - module must stay importable standalone
    import hashlib as _hashlib
    import json as _json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("utf-8")

    def jcs_sha256_hex(obj: Any) -> str:  # type: ignore[no-redef]
        return _hashlib.sha256(jcs_canonical_json(obj)).hexdigest()


#: Version pin for this module's record shape.
TEMPLATE_ENGINE_VERSION = "template-engine.v1"

#: Schema pin carried by records and audit events.
TEMPLATE_ENGINE_SCHEMA = "northstar.template-engine.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Maximum nesting of ``{{> partial}}`` includes before refusal.
MAX_PARTIAL_DEPTH = 32

#: Audit kinds.
_KINDS = ("template-registered", "partial-registered", "rendered", "rejected")


# -- errors ------------------------------------------------------------


class TemplateError(Exception):
    """Base class for all template-engine errors."""


class TemplateSyntaxError(TemplateError):
    """Template source fails to parse (raised at registration)."""


class DuplicateTemplateError(TemplateError):
    """A template name is already registered."""


class UnknownTemplateError(TemplateError):
    """``render()`` named an unregistered template."""


class UnknownPartialError(TemplateError):
    """``{{> name}}`` named an unregistered partial."""


class RecursionDepthError(TemplateError):
    """Partial inclusion exceeded ``MAX_PARTIAL_DEPTH``."""


class BadContextError(TemplateError):
    """A context value is not canonicalizable (NaN/inf, >2**53, ...)."""


class BadValueError(TemplateError):
    """A value cannot be interpolated (mapping/list in ``{{var}}``)."""


class SeqOrderError(TemplateError):
    """A mutation seq was not strictly increasing."""


# -- records -----------------------------------------------------------


@dataclass(frozen=True)
class TemplateRecord:
    """A pinned, parse-checked template."""

    name: str
    source: str
    digest: str  # "sha256:<hex>" over the source
    is_partial: bool
    seq: int

    def as_dict(self) -> Mapping[str, Any]:
        return {
            "name": self.name, "source": self.source,
            "digest": self.digest, "is_partial": self.is_partial,
            "seq": self.seq,
        }


@dataclass(frozen=True)
class RenderedTemplate:
    """The pinned result of one ``render()`` call."""

    name: str
    text: str
    template_digest: str
    context_digest: str  # "sha256:<hex>" over the canonicalized context
    seq: int
    digest: str  # "sha256:<hex>" over name + template digest + context digest + seq

    def as_dict(self) -> Mapping[str, Any]:
        return {
            "name": self.name, "text": self.text,
            "template_digest": self.template_digest,
            "context_digest": self.context_digest,
            "seq": self.seq, "digest": self.digest,
        }


# -- small validators --------------------------------------------------


def _check_seq(seq: Any, what: str = "seq") -> int:
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise TemplateError(f"{what} must be an int >= 0 (not bool)")
    return seq


def _check_name(name: Any, what: str = "name") -> str:
    if not isinstance(name, str) or not name:
        raise TemplateError(f"{what} must be a non-empty str")
    return name


def _check_source(source: Any) -> str:
    if not isinstance(source, str):
        raise TemplateError("template source must be str")
    return source


def _pin(parts: Sequence[Any]) -> str:
    return "sha256:" + jcs_sha256_hex(list(parts))


# -- context canonicalization ------------------------------------------

_MISSING = object()


def _canon(value: Any) -> Any:
    """Type-tagged canonical form of a context value (JCS-digestable).

    Refuses NaN/inf, integral floats, and ints with abs >= 2**53 --
    the batch-5 JCS float-loss caveat. Bool is not int.
    """
    if value is None:
        return ["n"]
    if isinstance(value, bool):
        return ["b", value]
    if isinstance(value, int):
        if abs(value) >= 2 ** 53:
            raise BadContextError(f"int abs >= 2**53 refused: {value!r}")
        return ["i", value]
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise BadContextError(f"NaN/inf refused: {value!r}")
        if value.is_integer() or abs(value) >= 2 ** 53:
            raise BadContextError(f"float refused (integral or >= 2**53): {value!r}")
        return ["f", repr(value)]
    if isinstance(value, str):
        return ["s", value]
    if isinstance(value, Mapping):
        pairs = []
        for key in sorted(value.keys(), key=str):
            if not isinstance(key, str):
                raise BadContextError(f"context keys must be str, got {key!r}")
            pairs.append([key, _canon(value[key])])
        return ["m", pairs]
    if isinstance(value, (list, tuple)):
        return ["l", [_canon(v) for v in value]]
    raise BadContextError(f"context value of type {type(value).__name__} refused")


def _stringify(value: Any) -> str:
    """Render one interpolated value to text (fail-closed)."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return str(value)
    if isinstance(value, str):
        return value
    raise BadValueError(
        f"cannot interpolate {type(value).__name__} in {{{{var}}}}; "
        "use a {{#section}}"
    )


# -- parser ------------------------------------------------------------

# Matches {{...}}, {{{...}}}. Group 1: inner of triple-stache; group 2: inner of double.
_TAG_RE = re.compile(r"\{\{\{(.*?)\}\}\}|\{\{(.*?)\}\}", re.DOTALL)


class _Text:
    __slots__ = ("text",)

    def __init__(self, text: str) -> None:
        self.text = text

    def render(self, ctx: "_Ctx", engine: "TemplateEngine", depth: int) -> str:
        return self.text


class _Var:
    __slots__ = ("path", "escaped")

    def __init__(self, path: str, escaped: bool) -> None:
        self.path = path
        self.escaped = escaped

    def render(self, ctx: "_Ctx", engine: "TemplateEngine", depth: int) -> str:
        value = ctx.resolve(self.path)
        if value is _MISSING:
            return ""
        text = _stringify(value)
        return escape(text) if self.escaped else text


class _Section:
    __slots__ = ("path", "inverted", "children")

    def __init__(self, path: str, inverted: bool, children: list) -> None:
        self.path = path
        self.inverted = inverted
        self.children = children

    def render(self, ctx: "_Ctx", engine: "TemplateEngine", depth: int) -> str:
        value = ctx.resolve(self.path)
        truthy = _truthy(value)
        if self.inverted:
            truthy = not truthy
        if not truthy:
            return ""
        if isinstance(value, (list, tuple)) and not self.inverted:
            out = []
            for item in value:
                out.append(_render_children(self.children, ctx.child(item), engine, depth))
            return "".join(out)
        return _render_children(self.children, ctx, engine, depth)


class _Partial:
    __slots__ = ("name",)

    def __init__(self, name: str) -> None:
        self.name = name

    def render(self, ctx: "_Ctx", engine: "TemplateEngine", depth: int) -> str:
        return engine._render_partial(self.name, ctx, depth + 1)


def _truthy(value: Any) -> bool:
    if value is _MISSING or value is None or value is False:
        return False
    if isinstance(value, (int, float)) and value == 0:
        return False
    if isinstance(value, str) and value == "":
        return False
    if isinstance(value, (list, tuple, Mapping)) and len(value) == 0:
        return False
    return True


def _render_children(children: list, ctx: "_Ctx", engine: "TemplateEngine", depth: int) -> str:
    return "".join(node.render(ctx, engine, depth) for node in children)


class _Ctx:
    """Rendering context: a stack of scopes plus the dot value."""

    __slots__ = ("scopes", "dot")

    def __init__(self, scopes: Tuple[Any, ...], dot: Any) -> None:
        self.scopes = scopes
        self.dot = dot

    def child(self, item: Any) -> "_Ctx":
        if isinstance(item, Mapping):
            return _Ctx(self.scopes + (item,), item)
        return _Ctx(self.scopes, item)

    def resolve(self, path: str) -> Any:
        if path == ".":
            return self.dot
        segments = path.split(".")
        for scope in reversed(self.scopes):
            if isinstance(scope, Mapping) and segments[0] in scope:
                value: Any = scope[segments[0]]
                for seg in segments[1:]:
                    if isinstance(value, Mapping) and seg in value:
                        value = value[seg]
                    else:
                        return _MISSING
                return value
        return _MISSING


def _parse(source: str) -> list:
    """Parse a template source into nodes (raises TemplateSyntaxError)."""
    root: list = []
    stack: list = []  # (kind, path, inverted, children)
    pos = 0
    for match in _TAG_RE.finditer(source):
        start, end = match.span()
        if start > pos:
            _append(stack, root, _Text(source[pos:start]))
        triple, double = match.group(1), match.group(2)
        pos = end
        if triple is not None:
            path = triple.strip()
            _check_var_path(path)
            _append(stack, root, _Var(path, escaped=False))
            continue
        inner = double.strip()
        if not inner:
            raise TemplateSyntaxError("empty tag {{}}")
        sigil = inner[0]
        if sigil == "!":
            continue  # comment
        if sigil == ">":
            name = inner[1:].strip()
            _check_name(name, "partial name")
            _append(stack, root, _Partial(name))
        elif sigil == "&":
            path = inner[1:].strip()
            _check_var_path(path)
            _append(stack, root, _Var(path, escaped=False))
        elif sigil == "#":
            path = inner[1:].strip()
            _check_var_path(path)
            stack.append(("#", path, False, []))
        elif sigil == "^":
            path = inner[1:].strip()
            _check_var_path(path)
            stack.append(("^", path, True, []))
        elif sigil == "/":
            path = inner[1:].strip()
            if not stack:
                raise TemplateSyntaxError(f"stray closing tag {{/{path}}}")
            kind, open_path, inverted, children = stack.pop()
            if open_path != path:
                raise TemplateSyntaxError(
                    f"mismatched section: open {{{{#{open_path}}}}} "
                    f"closed by {{{{/{path}}}}}"
                )
            _append(stack, root, _Section(path, inverted, children))
        else:
            _check_var_path(inner)
            _append(stack, root, _Var(inner, escaped=True))
    if pos < len(source):
        _append(stack, root, _Text(source[pos:]))
    if stack:
        kind, open_path, _, _ = stack[-1]
        raise TemplateSyntaxError(f"unclosed section {{{{#{open_path}}}}}")
    return root


def _append(stack: list, root: list, node: Any) -> None:
    if stack:
        stack[-1][3].append(node)
    else:
        root.append(node)


_VAR_PATH_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$")


def _check_var_path(path: str) -> None:
    if path != "." and not _VAR_PATH_RE.match(path):
        raise TemplateSyntaxError(f"bad variable path: {path!r}")


# -- escape ------------------------------------------------------------


def escape(value: Any) -> str:
    """HTML-escape a value for ``{{var}}`` interpolation (``quote=True``)."""
    if value is None:
        return ""
    return html.escape(str(value), quote=True)


# -- engine ------------------------------------------------------------


class TemplateEngine:
    """Named-template registry with Mustache-discipline rendering."""

    escape = staticmethod(escape)

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._templates: dict = {}
        self._last_seq = -1

    # -- registration --------------------------------------------------

    def register(self, name: str, source: str, seq: int) -> TemplateRecord:
        """Register (and syntax-check) a template. Duplicate names refused."""
        return self._register(name, source, seq, is_partial=False)

    def partial(self, name: str, source: str, seq: int) -> TemplateRecord:
        """Register a partial invocable via ``{{> name}}``."""
        return self._register(name, source, seq, is_partial=True)

    def _register(self, name: str, source: str, seq: int, is_partial: bool) -> TemplateRecord:
        _check_name(name)
        _check_source(source)
        with self._lock:
            seq = self._claim_seq(seq)
            if name in self._templates:
                raise DuplicateTemplateError(f"template already registered: {name!r}")
            nodes = _parse(source)  # syntax checked *before* pinning
            digest = _pin(["template", name, source])
            record = TemplateRecord(
                name=name, source=source, digest=digest,
                is_partial=is_partial, seq=seq,
            )
            self._templates[name] = (record, nodes)
            return record

    # -- rendering -----------------------------------------------------

    def render(self, name: str, context: Mapping[str, Any], seq: int) -> RenderedTemplate:
        """Render a registered template against a caller-supplied context."""
        _check_name(name)
        if not isinstance(context, Mapping):
            raise BadContextError("render context must be a mapping")
        with self._lock:
            entry = self._templates.get(name)
            if entry is None:
                raise UnknownTemplateError(f"unknown template: {name!r}")
            record, nodes = entry
            seq = self._claim_seq(seq)
            canon = _canon(dict(context))  # refuses NaN/inf/>2**53 here
            context_digest = _pin(["context", canon])
            ctx = _Ctx((dict(context),), dict(context))
            text = _render_children(nodes, ctx, self, depth=0)
            digest = _pin(["rendered", name, record.digest, context_digest, seq])
            return RenderedTemplate(
                name=name, text=text, template_digest=record.digest,
                context_digest=context_digest, seq=seq, digest=digest,
            )

    def _render_partial(self, name: str, ctx: _Ctx, depth: int) -> str:
        if depth > MAX_PARTIAL_DEPTH:
            raise RecursionDepthError(
                f"partial include depth exceeded ({MAX_PARTIAL_DEPTH}): {name!r}"
            )
        entry = self._templates.get(name)
        if entry is None:
            raise UnknownPartialError(f"unknown partial: {name!r}")
        _, nodes = entry
        return _render_children(nodes, ctx, self, depth)

    # -- views ----------------------------------------------------------

    def template(self, name: str) -> TemplateRecord:
        with self._lock:
            entry = self._templates.get(_check_name(name))
            if entry is None:
                raise UnknownTemplateError(f"unknown template: {name!r}")
            return entry[0]

    def names(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._templates))

    def template_count(self) -> int:
        with self._lock:
            return len(self._templates)

    # -- internals ------------------------------------------------------

    def _claim_seq(self, seq: Any) -> int:
        seq = _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq must be strictly increasing; got {seq} after {self._last_seq}"
            )
        self._last_seq = seq
        return seq


def template_engine_audit_event(kind: str, seq: int, **detail: Any) -> Mapping[str, Any]:
    """Shape an ``audit.ndjson/1`` record for the template engine."""
    if kind not in _KINDS:
        raise TemplateError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": "template_engine",
        "module_version": TEMPLATE_ENGINE_VERSION,
        "seq": seq,
        "detail": dict(detail),
    }


def main() -> None:
    engine = TemplateEngine()
    engine.register("hello", "Hello, {{name}}!", seq=1)
    engine.partial("footer", "-- {{org}}", seq=2)
    engine.register("page", "<h1>{{title}}</h1>{{> footer}}", seq=3)
    r1 = engine.render("hello", {"name": "<b>Ada</b>"}, seq=4)
    assert r1.text == "Hello, &lt;b&gt;Ada&lt;/b&gt;!", r1.text
    r2 = engine.render("page", {"title": "Hi", "org": "ACME"}, seq=5)
    assert r2.text == "<h1>Hi</h1>-- ACME", r2.text
    engine.register("list", "{{#items}}{{.}};{{/items}}{{^items}}empty{{/items}}", seq=6)
    r3 = engine.render("list", {"items": ["a", "b"]}, seq=7)
    assert r3.text == "a;b;", r3.text
    r4 = engine.render("list", {"items": []}, seq=8)
    assert r4.text == "empty", r4.text
    engine.register("objs", "{{#users}}{{name}},{{/users}}", seq=9)
    r5 = engine.render("objs", {"users": [{"name": "x"}, {"name": "y"}]}, seq=10)
    assert r5.text == "x,y,", r5.text
    print("template-engine OK: register, escape, partials, sections, inverted")


if __name__ == "__main__":
    main()
