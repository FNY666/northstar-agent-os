"""Markdown rendering interface (CommonMark-shaped subset, deterministic).

Research motivation: agent runtimes constantly shuttle human-readable
content -- plans, receipts, audit narratives, tool results -- and that
content needs one pinned dialect between "authored markdown" and "safe
HTML for display". Full CommonMark is a 200+ rule grammar with
reference implementations; this module pins the *bookkeeping* half of
that shape that the runtime actually needs:

- ``MarkdownRenderer.render()`` -- block + inline parsing of a pinned
  CommonMark subset (ATX headings, paragraphs, fenced code, bullet /
  ordered lists, blockquotes, horizontal rules; inline ``**strong**``,
  ``*em*``, `` `code` ``, links, images, autolinks) into deterministic
  HTML plus a ``sha256:`` digest over the canonical block AST.
- ``MarkdownRenderer.toc()`` -- heading entries (level, text, deduped
  anchor slug) for navigation / audit cross-references.
- ``MarkdownRenderer.sanitize()`` -- allowlist HTML sanitizer (script /
  style / iframe content dropped, event-handler attributes dropped,
  ``javascript:`` URLs dropped) so rendered output is safe to embed.

Fail-closed edges (fail loudly, never guess):

- ``source`` / ``html`` must be ``str``; anything else is refused.
- Caller-supplied ``seq`` is a non-negative ``int`` (``bool`` refused)
  and must strictly increase per renderer instance -- the same ledger
  discipline as the sibling batch modules. A rewind raises
  ``SeqOrderError`` and consumes nothing.
- Link and image URLs with dangerous schemes (``javascript:``,
  ``vbscript:``, ``data:``, ``file:``) are never emitted: links degrade
  to their inner text, ``sanitize()`` drops the attribute.
- Unclosed fenced code blocks close at end of input (CommonMark); a
  ``#`` run longer than 6 is a paragraph, not a heading.
- The sanitizer keeps an explicit allowlist of tags/attributes. Any
  tag outside it is stripped (``script``/``style``/``iframe``/
  ``object``/``embed``/``noscript`` lose their *content* too); anything
  else keeps its inner text.

Honest scope:

- This is a pinned *subset*, not a CommonMark reference implementation:
  no Setext headings, no indented code blocks, no nested list blocks,
  no tables, no footnotes, no reference-style links, no raw-HTML
  passthrough in ``render()`` (raw HTML in source is escaped as text).
- ``sanitize()`` is a syntactic allowlist, not a security proof: it
  cannot see through CSS-based exfiltration or a lying host. Pair with
  a real HTML sanitizer at the trust boundary if the HTML leaves the
  runtime.
- Digests bind the *reported* source to the output, never the truth of
  any claim inside the markdown. ``main()`` self-checks the shape.
"""

from __future__ import annotations

import hashlib
import html
import re
import threading
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Any, Dict, List, Mapping, Optional, Tuple, Union

try:  # the single canonicalizer
    from canonical_json import jcs_sha256_hex
except Exception:  # pragma: no cover - module must stay importable standalone
    import json as _json

    def jcs_sha256_hex(obj: Any) -> str:  # type: ignore[no-redef]
        raw = _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()


MARKDOWN_RENDERER_VERSION = "markdown-renderer.v1"
MARKDOWN_RENDERER_SCHEMA = "northstar.markdown-renderer.v1"
AUDIT_SCHEMA = "audit.ndjson/1"


# ---------------------------------------------------------------------------
# errors
# ---------------------------------------------------------------------------


class MarkdownError(Exception):
    """Base error for the markdown renderer."""


class InvalidInputError(MarkdownError):
    """Raised when source/html fails shape validation."""


class SeqOrderError(MarkdownError):
    """Raised when a caller seq is not a strictly increasing int."""


# ---------------------------------------------------------------------------
# frozen records: inline spans
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Text:
    text: str


@dataclass(frozen=True)
class Strong:
    inlines: Tuple["Inline", ...]


@dataclass(frozen=True)
class Em:
    inlines: Tuple["Inline", ...]


@dataclass(frozen=True)
class CodeSpan:
    code: str


@dataclass(frozen=True)
class Link:
    text: Tuple["Inline", ...]
    url: str
    title: str


@dataclass(frozen=True)
class Image:
    alt: str
    src: str
    title: str


Inline = Union[Text, Strong, Em, CodeSpan, Link, Image]


# ---------------------------------------------------------------------------
# frozen records: blocks
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Heading:
    level: int
    inlines: Tuple[Inline, ...]
    anchor: str


@dataclass(frozen=True)
class Paragraph:
    inlines: Tuple[Inline, ...]


@dataclass(frozen=True)
class CodeBlock:
    language: str
    code: str


@dataclass(frozen=True)
class ListBlock:
    ordered: bool
    items: Tuple[Tuple[Inline, ...], ...]


@dataclass(frozen=True)
class Blockquote:
    blocks: Tuple["Block", ...]


@dataclass(frozen=True)
class Rule:
    """A horizontal rule."""


Block = Union[Heading, Paragraph, CodeBlock, ListBlock, Blockquote, Rule]


@dataclass(frozen=True)
class TocEntry:
    level: int
    text: str
    anchor: str


@dataclass(frozen=True)
class RenderedDocument:
    """Frozen result of ``render()``."""

    html: str
    toc: Tuple[TocEntry, ...]
    block_count: int
    digest: str
    seq: int
    version: str = MARKDOWN_RENDERER_VERSION
    schema: str = MARKDOWN_RENDERER_SCHEMA


@dataclass(frozen=True)
class TocDocument:
    """Frozen result of ``toc()``."""

    entries: Tuple[TocEntry, ...]
    digest: str
    seq: int
    version: str = MARKDOWN_RENDERER_VERSION
    schema: str = MARKDOWN_RENDERER_SCHEMA


@dataclass(frozen=True)
class SanitizedOutput:
    """Frozen result of ``sanitize()``."""

    html: str
    stripped_tags: Tuple[str, ...]
    digest: str
    seq: int
    version: str = MARKDOWN_RENDERER_VERSION
    schema: str = MARKDOWN_RENDERER_SCHEMA


# ---------------------------------------------------------------------------
# helpers: digests, urls, slugs
# ---------------------------------------------------------------------------


def _digest(payload: Mapping[str, Any]) -> str:
    return "sha256:" + jcs_sha256_hex(payload)


_UNSAFE_SCHEMES = ("javascript:", "vbscript:", "data:", "file:")


def _safe_url(url: str) -> bool:
    """True when ``url`` may appear in href/src output."""
    u = url.strip()
    if not u:
        return False
    low = u.lower()
    for scheme in _UNSAFE_SCHEMES:
        if low.startswith(scheme):
            return False
    return True


def _slugify(text: str) -> str:
    s = text.lower()
    s = re.sub(r"[^a-z0-9 _-]", "", s)
    s = re.sub(r"[\s_]+", "-", s.strip())
    s = re.sub(r"-+", "-", s)
    return s or "section"


def _plain_text(spans: Tuple[Inline, ...]) -> str:
    parts: List[str] = []
    for s in spans:
        if isinstance(s, Text):
            parts.append(s.text)
        elif isinstance(s, (Strong, Em)):
            parts.append(_plain_text(s.inlines))
        elif isinstance(s, CodeSpan):
            parts.append(s.code)
        elif isinstance(s, Link):
            parts.append(_plain_text(s.text))
        elif isinstance(s, Image):
            parts.append(s.alt)
    return "".join(parts)


# ---------------------------------------------------------------------------
# inline parsing
# ---------------------------------------------------------------------------

_ESCAPABLE = set("!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~")
_AUTOLINK_RE = re.compile(r"<((?:https?|mailto):[^<>\s]*)>")


def _parse_link(text: str, i: int):
    """Parse ``[inner](url "title")`` starting at the ``[`` (index ``i``).

    Returns ``(inner, url, title, end)`` or ``None``.
    """
    close = text.find("]", i + 1)
    if close == -1:
        return None
    inner = text[i + 1:close]
    if close + 1 >= len(text) or text[close + 1] != "(":
        return None
    j = close + 2
    n = len(text)
    while j < n and text[j] in " \t\n":
        j += 1
    if j < n and text[j] == "<":
        k = text.find(">", j + 1)
        if k == -1:
            return None
        url = text[j + 1:k]
        j = k + 1
    else:
        k = j
        depth = 0
        while k < n and text[k] not in " \t\n":
            if text[k] == "(":
                depth += 1
            elif text[k] == ")":
                if depth == 0:
                    break
                depth -= 1
            k += 1
        url = text[j:k]
        j = k
    while j < n and text[j] in " \t\n":
        j += 1
    title = ""
    if j < n and text[j] in "\"'":
        q = text[j]
        k = text.find(q, j + 1)
        if k == -1:
            return None
        title = text[j + 1:k]
        j = k + 1
        while j < n and text[j] in " \t\n":
            j += 1
    if j >= n or text[j] != ")":
        return None
    return (inner, url, title, j + 1)


def _parse_inline(text: str) -> Tuple[Inline, ...]:
    spans: List[Inline] = []
    buf: List[str] = []

    def flush() -> None:
        if buf:
            spans.append(Text("".join(buf)))
            buf.clear()

    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch == "\\" and i + 1 < n:
            nxt = text[i + 1]
            if nxt == "\n":
                buf.append("\n")
            elif nxt in _ESCAPABLE:
                buf.append(nxt)
            else:
                buf.append(ch)
                buf.append(nxt)
            i += 2
            continue
        if ch == "`":
            j = i
            while j < n and text[j] == "`":
                j += 1
            run = j - i
            k = text.find("`" * run, j)
            if k == -1:
                buf.append(text[i:j])
                i = j
                continue
            code = text[j:k].replace("\n", " ")
            if len(code) > 1 and code[0] == " " and code[-1] == " ":
                code = code[1:-1]
            flush()
            spans.append(CodeSpan(code))
            i = k + run
            continue
        if ch == "!" and i + 1 < n and text[i + 1] == "[":
            r = _parse_link(text, i + 1)
            if r is not None:
                inner, url, title, end = r
                flush()
                alt = _plain_text(_parse_inline(inner))
                spans.append(Image(alt=alt, src=url, title=title))
                i = end
                continue
            buf.append(ch)
            i += 1
            continue
        if ch == "[":
            r = _parse_link(text, i)
            if r is not None:
                inner, url, title, end = r
                flush()
                inner_spans = _parse_inline(inner)
                if _safe_url(url):
                    spans.append(Link(text=inner_spans, url=url, title=title))
                else:
                    # Unsafe scheme: degrade to inner text, never emit.
                    spans.extend(inner_spans)
                i = end
                continue
            buf.append(ch)
            i += 1
            continue
        if ch in "*_":
            if ch == "_" and i > 0 and text[i - 1].isalnum():
                buf.append(ch)
                i += 1
                continue
            if text.startswith(ch * 2, i):
                end = text.find(ch * 2, i + 2)
                if end != -1 and end > i + 2:
                    flush()
                    spans.append(Strong(_parse_inline(text[i + 2:end])))
                    i = end + 2
                    continue
            end = text.find(ch, i + 1)
            if end != -1 and end > i + 1:
                flush()
                spans.append(Em(_parse_inline(text[i + 1:end])))
                i = end + 1
                continue
            buf.append(ch)
            i += 1
            continue
        if ch == "<":
            m = _AUTOLINK_RE.match(text, i)
            if m:
                url = m.group(1)
                flush()
                if _safe_url(url):
                    spans.append(Link(text=(Text(url),), url=url, title=""))
                else:
                    buf.append(url)
                i = m.end()
                continue
            buf.append(ch)
            i += 1
            continue
        buf.append(ch)
        i += 1
    flush()
    return tuple(spans)


# ---------------------------------------------------------------------------
# block parsing
# ---------------------------------------------------------------------------

_FENCE_RE = re.compile(r"^ {0,3}(`{3,})[ \t]*([^\n`]*)$")
_ATX_RE = re.compile(r"^(#{1,6})(?:[ \t]+(.*))?$")
_HR_RE = re.compile(r"^ {0,3}(?:(?:-[ \t]*){3,}|(?:\*[ \t]*){3,}|(?:_[ \t]*){3,})$")
_ULIST_RE = re.compile(r"^ {0,3}[-*+][ \t]+(.*)$")
_OLIST_RE = re.compile(r"^ {0,3}\d{1,9}[.)][ \t]+(.*)$")


def _is_fence_close(line: str, run: int) -> bool:
    return re.match(r"^ {0,3}`{%d,}[ \t]*$" % run, line) is not None


def _block_start(line: str) -> bool:
    if line.strip() == "":
        return True
    if _FENCE_RE.match(line) or _ATX_RE.match(line) or _HR_RE.match(line):
        return True
    if line.lstrip().startswith(">"):
        return True
    if _ULIST_RE.match(line) or _OLIST_RE.match(line):
        return True
    return False


def _parse_blocks(lines: List[str]) -> List[Block]:
    blocks: List[Block] = []
    i, n = 0, len(lines)
    while i < n:
        line = lines[i]
        if line.strip() == "":
            i += 1
            continue
        m = _FENCE_RE.match(line)
        if m:
            run = len(m.group(1))
            lang = (m.group(2) or "").strip()
            code_lines: List[str] = []
            i += 1
            while i < n and not _is_fence_close(lines[i], run):
                code_lines.append(lines[i])
                i += 1
            if i < n:
                i += 1  # consume the closing fence
            blocks.append(CodeBlock(language=lang, code="\n".join(code_lines)))
            continue
        m = _ATX_RE.match(line)
        if m:
            level = len(m.group(1))
            content = (m.group(2) or "").strip()
            content = re.sub(r"[ \t]+#+[ \t]*$", "", content)
            blocks.append(Heading(level=level,
                                  inlines=_parse_inline(content),
                                  anchor=""))
            i += 1
            continue
        if _HR_RE.match(line):
            blocks.append(Rule())
            i += 1
            continue
        if line.lstrip().startswith(">"):
            qlines: List[str] = []
            while i < n and lines[i].lstrip().startswith(">"):
                inner = lines[i].lstrip()[1:]
                if inner.startswith(" "):
                    inner = inner[1:]
                qlines.append(inner)
                i += 1
            blocks.append(Blockquote(blocks=tuple(_parse_blocks(qlines))))
            continue
        m = _ULIST_RE.match(line)
        if m:
            items: List[Tuple[Inline, ...]] = []
            while i < n:
                m2 = _ULIST_RE.match(lines[i])
                if not m2:
                    break
                items.append(_parse_inline(m2.group(1).strip()))
                i += 1
            blocks.append(ListBlock(ordered=False, items=tuple(items)))
            continue
        m = _OLIST_RE.match(line)
        if m:
            items = []
            while i < n:
                m2 = _OLIST_RE.match(lines[i])
                if not m2:
                    break
                items.append(_parse_inline(m2.group(1).strip()))
                i += 1
            blocks.append(ListBlock(ordered=True, items=tuple(items)))
            continue
        plines: List[str] = []
        while i < n and not _block_start(lines[i]):
            plines.append(lines[i].strip())
            i += 1
        blocks.append(Paragraph(inlines=_parse_inline("\n".join(plines))))
    return blocks


def _assign_anchors(blocks: List[Block]) -> List[Block]:
    """Fill heading anchors with deduped slugs (document order)."""
    seen: Dict[str, int] = {}

    def slug_for(text: str) -> str:
        base = _slugify(text)
        count = seen.get(base, 0)
        seen[base] = count + 1
        return base if count == 0 else "%s-%d" % (base, count)

    def fix(block: Block) -> Block:
        if isinstance(block, Heading):
            return Heading(level=block.level, inlines=block.inlines,
                           anchor=slug_for(_plain_text(block.inlines)))
        if isinstance(block, Blockquote):
            return Blockquote(blocks=tuple(fix(b) for b in block.blocks))
        return block

    return [fix(b) for b in blocks]


def _collect_headings(blocks: List[Block]) -> List[TocEntry]:
    entries: List[TocEntry] = []
    for b in blocks:
        if isinstance(b, Heading):
            entries.append(TocEntry(level=b.level,
                                    text=_plain_text(b.inlines),
                                    anchor=b.anchor))
        elif isinstance(b, Blockquote):
            entries.extend(_collect_headings(list(b.blocks)))
    return entries


# ---------------------------------------------------------------------------
# canonical AST for digests
# ---------------------------------------------------------------------------


def _inline_to_dict(span: Inline) -> Any:
    if isinstance(span, Text):
        return {"t": "text", "text": span.text}
    if isinstance(span, Strong):
        return {"t": "strong",
                "inlines": [_inline_to_dict(s) for s in span.inlines]}
    if isinstance(span, Em):
        return {"t": "em",
                "inlines": [_inline_to_dict(s) for s in span.inlines]}
    if isinstance(span, CodeSpan):
        return {"t": "code", "code": span.code}
    if isinstance(span, Link):
        return {"t": "link", "url": span.url, "title": span.title,
                "text": [_inline_to_dict(s) for s in span.text]}
    if isinstance(span, Image):
        return {"t": "image", "alt": span.alt, "src": span.src,
                "title": span.title}
    raise MarkdownError("unknown inline span: %r" % type(span))


def _block_to_dict(block: Block) -> Any:
    if isinstance(block, Heading):
        return {"t": "heading", "level": block.level,
                "anchor": block.anchor,
                "inlines": [_inline_to_dict(s) for s in block.inlines]}
    if isinstance(block, Paragraph):
        return {"t": "paragraph",
                "inlines": [_inline_to_dict(s) for s in block.inlines]}
    if isinstance(block, CodeBlock):
        return {"t": "code", "language": block.language, "code": block.code}
    if isinstance(block, ListBlock):
        return {"t": "list", "ordered": block.ordered,
                "items": [[_inline_to_dict(s) for s in item]
                          for item in block.items]}
    if isinstance(block, Blockquote):
        return {"t": "quote",
                "blocks": [_block_to_dict(b) for b in block.blocks]}
    if isinstance(block, Rule):
        return {"t": "rule"}
    raise MarkdownError("unknown block: %r" % type(block))


# ---------------------------------------------------------------------------
# HTML rendering
# ---------------------------------------------------------------------------


def _render_inline(spans: Tuple[Inline, ...]) -> str:
    out: List[str] = []
    for s in spans:
        if isinstance(s, Text):
            out.append(html.escape(s.text, quote=False))
        elif isinstance(s, Strong):
            out.append("<strong>%s</strong>" % _render_inline(s.inlines))
        elif isinstance(s, Em):
            out.append("<em>%s</em>" % _render_inline(s.inlines))
        elif isinstance(s, CodeSpan):
            out.append("<code>%s</code>" % html.escape(s.code, quote=False))
        elif isinstance(s, Link):
            attrs = ' href="%s"' % html.escape(s.url, quote=True)
            if s.title:
                attrs += ' title="%s"' % html.escape(s.title, quote=True)
            out.append("<a%s>%s</a>" % (attrs, _render_inline(s.text)))
        elif isinstance(s, Image):
            attrs = (' src="%s" alt="%s"'
                     % (html.escape(s.src, quote=True),
                        html.escape(s.alt, quote=True)))
            if s.title:
                attrs += ' title="%s"' % html.escape(s.title, quote=True)
            out.append("<img%s />" % attrs)
    return "".join(out)


def _render_block(block: Block) -> str:
    if isinstance(block, Heading):
        return ('<h%d id="%s">%s</h%d>'
                % (block.level, html.escape(block.anchor, quote=True),
                   _render_inline(block.inlines), block.level))
    if isinstance(block, Paragraph):
        return "<p>%s</p>" % _render_inline(block.inlines)
    if isinstance(block, CodeBlock):
        body = html.escape(block.code, quote=False)
        if block.language:
            return ('<pre><code class="language-%s">%s</code></pre>'
                    % (html.escape(block.language, quote=True), body))
        return "<pre><code>%s</code></pre>" % body
    if isinstance(block, ListBlock):
        tag = "ol" if block.ordered else "ul"
        items = "".join("<li>%s</li>" % _render_inline(item)
                        for item in block.items)
        return "<%s>%s</%s>" % (tag, items, tag)
    if isinstance(block, Blockquote):
        inner = "\n".join(_render_block(b) for b in block.blocks)
        return "<blockquote>\n%s\n</blockquote>" % inner
    if isinstance(block, Rule):
        return "<hr />"
    raise MarkdownError("unknown block: %r" % type(block))


# ---------------------------------------------------------------------------
# sanitizer
# ---------------------------------------------------------------------------

_ALLOWED_TAGS = frozenset({
    "p", "h1", "h2", "h3", "h4", "h5", "h6",
    "ul", "ol", "li", "blockquote", "pre", "code",
    "strong", "em", "a", "img", "hr", "br",
})
_ALLOWED_ATTRS: Dict[str, frozenset] = {
    "a": frozenset({"href", "title"}),
    "img": frozenset({"src", "alt", "title"}),
}
_DROP_CONTENT_TAGS = frozenset({
    "script", "style", "iframe", "object", "embed", "noscript",
})
_VOID_TAGS = frozenset({"hr", "br", "img"})


class _Sanitizer(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=False)
        self._out: List[str] = []
        self._open: List[str] = []
        self._drop_depth = 0
        self._stripped: List[str] = []

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        tag = tag.lower()
        if self._drop_depth:
            if tag in _DROP_CONTENT_TAGS:
                self._drop_depth += 1
            return
        if tag in _DROP_CONTENT_TAGS:
            self._drop_depth = 1
            self._stripped.append(tag)
            return
        if tag not in _ALLOWED_TAGS:
            self._stripped.append(tag)
            return
        kept: List[Tuple[str, str]] = []
        for name, value in attrs:
            name = name.lower()
            if name not in _ALLOWED_ATTRS.get(tag, frozenset()):
                continue
            val = value or ""
            if name in ("href", "src") and not _safe_url(val):
                continue
            kept.append((name, val))
        attr_str = "".join(' %s="%s"' % (n, html.escape(v, quote=True))
                           for n, v in kept)
        if tag in _VOID_TAGS:
            self._out.append("<%s%s />" % (tag, attr_str))
        else:
            self._out.append("<%s%s>" % (tag, attr_str))
            self._open.append(tag)

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if self._drop_depth:
            if tag in _DROP_CONTENT_TAGS:
                self._drop_depth -= 1
            return
        if self._open and self._open[-1] == tag:
            self._open.pop()
            self._out.append("</%s>" % tag)
        # stray end tags are dropped silently

    def handle_startendtag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)

    def handle_data(self, data: str) -> None:
        if not self._drop_depth:
            self._out.append(data)

    def handle_comment(self, data: str) -> None:
        pass

    def handle_decl(self, decl: str) -> None:
        pass

    def handle_pi(self, data: str) -> None:
        pass

    def result(self) -> Tuple[str, Tuple[str, ...]]:
        return "".join(self._out), tuple(sorted(set(self._stripped)))


# ---------------------------------------------------------------------------
# audit events
# ---------------------------------------------------------------------------

_AUDIT_KINDS = frozenset({"rendered", "toc-built", "sanitized", "rejected"})


def markdown_renderer_audit_event(
    kind: str,
    *,
    seq: int,
    detail: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for the markdown renderer.

    ``seq`` is caller-supplied (the renderer never mints its own).
    """
    if kind not in _AUDIT_KINDS:
        raise MarkdownError("unknown audit kind: %r" % kind)
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise MarkdownError("seq must be a non-negative int")
    event: Dict[str, Any] = {
        "schema": AUDIT_SCHEMA,
        "component": "markdown-renderer",
        "version": MARKDOWN_RENDERER_VERSION,
        "kind": kind,
        "seq": seq,
    }
    if detail is not None:
        event["detail"] = dict(detail)
    return event


# ---------------------------------------------------------------------------
# renderer
# ---------------------------------------------------------------------------


class MarkdownRenderer:
    """Deterministic markdown -> HTML renderer with toc and sanitizer."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq = -1

    def _claim_seq(self, seq: int) -> int:
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise SeqOrderError("seq must be an int")
        if seq < 0:
            raise SeqOrderError("seq must be non-negative")
        if seq <= self._last_seq:
            raise SeqOrderError(
                "seq must strictly increase (got %d after %d)"
                % (seq, self._last_seq))
        self._last_seq = seq
        return seq

    @staticmethod
    def _require_source(source: Any) -> str:
        if not isinstance(source, str):
            raise InvalidInputError("source must be str")
        return source

    def _parse(self, source: str) -> Tuple[List[Block], List[TocEntry]]:
        blocks = _assign_anchors(_parse_blocks(source.split("\n")))
        return blocks, _collect_headings(blocks)

    def render(self, source: str, seq: int) -> RenderedDocument:
        """Render markdown ``source`` to deterministic HTML."""
        source = self._require_source(source)
        with self._lock:
            self._claim_seq(seq)
            blocks, toc = self._parse(source)
            html_out = "\n".join(_render_block(b) for b in blocks)
            digest = _digest({
                "blocks": [_block_to_dict(b) for b in blocks],
                "toc": [{"level": e.level, "text": e.text, "anchor": e.anchor}
                        for e in toc],
            })
            return RenderedDocument(
                html=html_out,
                toc=tuple(toc),
                block_count=len(blocks),
                digest=digest,
                seq=seq,
            )

    def toc(self, source: str, seq: int) -> TocDocument:
        """Build the heading table of contents for ``source``."""
        source = self._require_source(source)
        with self._lock:
            self._claim_seq(seq)
            _, toc = self._parse(source)
            digest = _digest({
                "toc": [{"level": e.level, "text": e.text, "anchor": e.anchor}
                        for e in toc],
            })
            return TocDocument(entries=tuple(toc), digest=digest, seq=seq)

    def sanitize(self, html_text: str, seq: int) -> SanitizedOutput:
        """Allowlist-sanitize ``html_text``; dangerous markup is dropped."""
        if not isinstance(html_text, str):
            raise InvalidInputError("html_text must be str")
        with self._lock:
            self._claim_seq(seq)
            parser = _Sanitizer()
            parser.feed(html_text)
            parser.close()
            clean, stripped = parser.result()
            digest = _digest({"html": clean, "stripped": list(stripped)})
            return SanitizedOutput(html=clean, stripped_tags=stripped,
                                   digest=digest, seq=seq)


def main() -> None:
    """Self-check the module shape."""
    r = MarkdownRenderer()
    doc = r.render("# Hello\n\n**bold** and `code`.\n", seq=1)
    assert '<h1 id="hello">Hello</h1>' in doc.html, doc.html
    assert "<strong>bold</strong>" in doc.html
    assert "<code>code</code>" in doc.html
    assert doc.digest.startswith("sha256:")
    toc = r.toc("# Hello\n\n## World\n", seq=2)
    assert [e.anchor for e in toc.entries] == ["hello", "world"]
    out = r.sanitize(
        '<p>ok</p><script>alert(1)</script>'
        '<a href="javascript:x" onclick="y()">z</a>', seq=3)
    assert "<script>" not in out.html
    assert "javascript:" not in out.html
    assert "onclick" not in out.html
    assert out.html == '<p>ok</p><a>z</a>', out.html
    print("markdown-renderer OK: render, toc, sanitize")


if __name__ == "__main__":
    main()
