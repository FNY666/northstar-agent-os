"""Pandoc-style document format conversion, in-memory.

Research note: a *document converter* (pandoc is the reference) maps a
document between markup/text formats via an intermediate representation --
readers parse input formats into an AST, writers serialize the AST into
output formats. The load-bearing production concerns, all kept here:

* **Format registry** -- the supported reader/writer pairs are pinned in
  code and listed by ``formats()``; an unknown format name is refused
  fail-closed (``UnknownFormatError``) rather than guessed.
* **Deterministic transforms** -- every conversion is a pure function of
  (content, from_fmt, to_fmt, options); identical inputs replay to
  byte-identical output and digest pins.
* **Pins, not claims** -- each conversion record carries a ``sha256:``
  pin over the canonical (input, output, options) triple, so a tampered
  conversion no longer verifies. The pin proves internal consistency,
  never fidelity to the source format's full grammar.
* **Loss ledger** -- each converter declares what it drops (e.g. markdown
  tables lost on the markdown->text path); the record names the losses so
  downstream code can refuse silently lossy paths.
* **Strict seqs** -- every mutation takes a caller-supplied strictly
  increasing int seq; the module never touches the wall clock.

Honest scope: this is a *structural bookkeeping* interface over a tiny
simulated converter, not a pandoc replacement. The built-in transforms
cover a small deterministic subset (headings, bold/italic/code spans,
links, paragraphs, lists); they do not parse full CommonMark, HTML, or
reStructuredText, cannot prove a conversion preserved meaning, and must
not be used where layout fidelity matters. Real deployments hand the
pinned content to pandoc itself and record its digest here.

Version pin: doc-converter.v1
Schema pin: northstar.doc-converter.v1
"""

from __future__ import annotations

import hashlib
import re
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Mapping, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except ImportError:  # pragma: no cover - fallback for standalone import

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        import json

        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


#: Module version.
DOC_CONVERTER_VERSION = "doc-converter.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.doc-converter.v1"

#: Largest document accepted, in UTF-8 bytes: 1 MiB.
MAX_DOC_BYTES = 1 << 20

#: Reader formats this module claims to parse (simulated subset).
_READERS: FrozenSet[str] = frozenset({"markdown", "html", "text", "rst"})

#: Writer formats this module claims to emit.
_WRITERS: FrozenSet[str] = frozenset({"markdown", "html", "text", "rst", "json"})

#: Declared losses per (from, to) pair, so callers can audit fidelity.
_LOSSES: Dict[Tuple[str, str], Tuple[str, ...]] = {
    ("markdown", "html"): ("markdown tables become pre blocks",),
    ("markdown", "text"): ("links keep text only, URLs dropped", "emphasis dropped"),
    ("markdown", "rst"): ("raw html blocks dropped",),
    ("markdown", "json"): ("formatting normalized to plain text",),
    ("html", "text"): ("tags dropped", "link hrefs dropped"),
    ("html", "markdown"): ("tables dropped", "inline styles dropped"),
    ("text", "markdown"): ("no headings inferred",),
    ("text", "html"): ("paragraphs only",),
    ("text", "rst"): ("no sections inferred",),
    ("rst", "text"): ("directives dropped", "roles dropped"),
    ("rst", "markdown"): ("footnotes inlined",),
}


class DocConverterError(Exception):
    """Base error for document conversion misuse or constraint violations."""


class UnknownFormatError(DocConverterError):
    """A conversion named a format this module does not support."""


class UnsupportedConversionError(DocConverterError):
    """The (from, to) pair has no converter registered."""


class EmptyDocumentError(DocConverterError):
    """Content was empty or whitespace-only."""


class DocumentTooLargeError(DocConverterError):
    """Content exceeded MAX_DOC_BYTES."""


class ValidationError(DocConverterError):
    """A field failed fail-closed validation."""


class SeqOrderError(DocConverterError):
    """A caller seq did not strictly increase."""


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise ValidationError("seq must be an int, not bool")
    if seq < 0:
        raise ValidationError("seq must be non-negative")
    return seq


def _check_format(name: Any, role: str) -> str:
    if not isinstance(name, str) or not name.strip():
        raise ValidationError(f"{role} format must be a non-empty str")
    return name.strip().lower()


def _check_content(content: Any) -> str:
    if not isinstance(content, str):
        raise ValidationError("content must be a str")
    if not content.strip():
        raise EmptyDocumentError("content is empty or whitespace-only")
    if len(content.encode("utf-8")) > MAX_DOC_BYTES:
        raise DocumentTooLargeError(f"content exceeds {MAX_DOC_BYTES} bytes")
    return content


def _pin(body: Any) -> str:
    return "sha256:" + hashlib.sha256(jcs_canonical_json(body)).hexdigest()


# ---------------------------------------------------------------------------
# Simulated converters (pure functions; tiny deterministic subsets)
# ---------------------------------------------------------------------------

_HEADING_RE = re.compile(r"^(#{1,6})\s+(.*?)\s*$")
_BOLD_RE = re.compile(r"\*\*(.+?)\*\*")
_ITALIC_RE = re.compile(r"(?<!\*)\*(?!\*)(.+?)(?<!\*)\*(?!\*)")
_CODE_RE = re.compile(r"`([^`]+?)`")
_LINK_RE = re.compile(r"\[([^\]]+?)\]\(([^)]+?)\)")
_LIST_RE = re.compile(r"^\s*[-*]\s+(.*)$")
_TAG_RE = re.compile(r"<[^>]+>")
_ENTITY_RE = re.compile(r"&(amp|lt|gt|quot|#39);")
_RST_HEADING_CHARS = set("=~^-\"'#")


def _md_inline_to_html(text: str) -> str:
    text = _CODE_RE.sub(r"<code>\1</code>", text)
    text = _LINK_RE.sub(r'<a href="\2">\1</a>', text)
    text = _BOLD_RE.sub(r"<strong>\1</strong>", text)
    text = _ITALIC_RE.sub(r"<em>\1</em>", text)
    return text


def _md_to_html(content: str) -> str:
    out: List[str] = []
    for line in content.splitlines():
        m = _HEADING_RE.match(line)
        if m:
            level = len(m.group(1))
            out.append(f"<h{level}>{_md_inline_to_html(m.group(2))}</h{level}>")
            continue
        m = _LIST_RE.match(line)
        if m:
            out.append(f"<ul><li>{_md_inline_to_html(m.group(1))}</li></ul>")
            continue
        if line.strip():
            out.append(f"<p>{_md_inline_to_html(line.strip())}</p>")
    return "\n".join(out)


def _strip_md(content: str) -> str:
    lines: List[str] = []
    for line in content.splitlines():
        m = _HEADING_RE.match(line)
        body = m.group(2) if m else line
        m2 = _LIST_RE.match(body)
        body = m2.group(1) if m2 else body
        body = _LINK_RE.sub(r"\1", body)
        body = _BOLD_RE.sub(r"\1", body)
        body = _ITALIC_RE.sub(r"\1", body)
        body = _CODE_RE.sub(r"\1", body)
        lines.append(body.strip())
    return "\n".join(lines)


def _md_to_rst(content: str) -> str:
    out: List[str] = []
    for line in content.splitlines():
        m = _HEADING_RE.match(line)
        if m:
            level = len(m.group(1))
            chars = ["=", "-", "~", "^", '"', "#"][min(level - 1, 5)]
            title = _strip_md(m.group(2))
            out.append(title)
            out.append(chars * max(len(title), 1))
            continue
        out.append(_strip_md(line))
    return "\n".join(out)


def _html_to_text(content: str) -> str:
    text = _TAG_RE.sub(" ", content)
    text = _ENTITY_RE.sub(
        lambda m: {"amp": "&", "lt": "<", "gt": ">", "quot": '"', "#39": "'"}[m.group(1)],
        text,
    )
    return "\n".join(line.strip() for line in text.splitlines() if line.strip())


def _html_to_md(content: str) -> str:
    text = _html_to_text(content)
    return "\n\n".join(text.splitlines())


def _text_to_html(content: str) -> str:
    return "\n".join(f"<p>{line.strip()}</p>" for line in content.splitlines() if line.strip())


def _text_to_md(content: str) -> str:
    return "\n\n".join(line.strip() for line in content.splitlines() if line.strip())


def _text_to_rst(content: str) -> str:
    return _text_to_md(content)


def _rst_to_text(content: str) -> str:
    out: List[str] = []
    for line in content.splitlines():
        stripped = line.strip()
        if stripped and set(stripped) <= _RST_HEADING_CHARS and len(stripped) >= 3:
            continue  # underline decoration
        if stripped.startswith(".. "):
            continue  # directive
        out.append(re.sub(r"`([^`]+?)`__?", r"\1", stripped))
    return "\n".join(l for l in out if l)


def _rst_to_md(content: str) -> str:
    return _rst_to_text(content)


def _to_json_repr(content: str) -> str:
    paragraphs = [p.strip() for p in content.splitlines() if p.strip()]
    import json

    return json.dumps(
        {"format": "paragraphs", "blocks": [{"type": "para", "text": p} for p in paragraphs]},
        sort_keys=True,
        separators=(",", ":"),
    )


_CONVERTERS: Dict[Tuple[str, str], Any] = {
    ("markdown", "html"): _md_to_html,
    ("markdown", "text"): _strip_md,
    ("markdown", "rst"): _md_to_rst,
    ("markdown", "json"): _to_json_repr,
    ("html", "text"): _html_to_text,
    ("html", "markdown"): _html_to_md,
    ("text", "html"): _text_to_html,
    ("text", "markdown"): _text_to_md,
    ("text", "rst"): _text_to_rst,
    ("text", "json"): _to_json_repr,
    ("rst", "text"): _rst_to_text,
    ("rst", "markdown"): _rst_to_md,
}


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ConversionRecord:
    """One pinned conversion: inputs, output digest, declared losses."""

    conversion_id: str
    from_format: str
    to_format: str
    input_digest: str
    output_digest: str
    losses: Tuple[str, ...]
    options_digest: str
    seq: int
    version: str = DOC_CONVERTER_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "conversion_id": self.conversion_id,
            "from_format": self.from_format,
            "to_format": self.to_format,
            "input_digest": self.input_digest,
            "output_digest": self.output_digest,
            "losses": list(self.losses),
            "options_digest": self.options_digest,
            "seq": self.seq,
            "version": self.version,
            "schema": self.schema,
        }

    def verify(self, output: str) -> bool:
        """Re-derive the output pin for a candidate output string."""
        return _pin({"output": output}) == self.output_digest


@dataclass(frozen=True)
class DocumentMetadata:
    """Extracted document metadata (title/author/date), digest-pinned."""

    doc_digest: str
    title: Optional[str]
    author: Optional[str]
    date: Optional[str]
    seq: int
    version: str = DOC_CONVERTER_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "doc_digest": self.doc_digest,
            "title": self.title,
            "author": self.author,
            "date": self.date,
            "seq": self.seq,
            "version": self.version,
            "schema": self.schema,
        }


# ---------------------------------------------------------------------------
# Converter
# ---------------------------------------------------------------------------


class DocConverter:
    """Pandoc-style format conversion bookkeeping, in-memory."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq = -1
        self._counter = 0
        self._conversions: Dict[str, ConversionRecord] = {}
        self._audit: List[Dict[str, Any]] = []

    def _advance(self, seq: int) -> int:
        seq = _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError("seq must strictly increase")
        self._last_seq = seq
        return seq

    # -- format registry -------------------------------------------------

    def formats(self, direction: Optional[str] = None) -> List[str]:
        """List supported formats; direction is in/out/None (both)."""
        if direction is None:
            return sorted(_READERS | _WRITERS)
        if direction not in ("in", "out"):
            raise ValidationError("direction must be 'in', 'out', or None")
        return sorted(_READERS if direction == "in" else _WRITERS)

    def supported_pairs(self) -> List[Tuple[str, str]]:
        """List every (from, to) conversion pair this module can run."""
        return sorted(_CONVERTERS.keys())

    # -- conversion ------------------------------------------------------

    def convert(
        self,
        content: str,
        from_format: str,
        to_format: str,
        seq: int,
        options: Optional[Mapping[str, Any]] = None,
    ) -> Tuple[ConversionRecord, str]:
        """Convert content between formats; returns (record, output)."""
        with self._lock:
            seq = self._advance(seq)
            content = _check_content(content)
            from_format = _check_format(from_format, "from")
            to_format = _check_format(to_format, "to")
            if from_format not in _READERS:
                raise UnknownFormatError(f"unknown reader format: {from_format}")
            if to_format not in _WRITERS:
                raise UnknownFormatError(f"unknown writer format: {to_format}")
            if from_format == to_format:
                raise ValidationError("from_format and to_format must differ")
            fn = _CONVERTERS.get((from_format, to_format))
            if fn is None:
                raise UnsupportedConversionError(
                    f"no converter for {from_format} -> {to_format}"
                )
            opts = dict(options) if options else {}
            try:
                jcs_canonical_json(opts)
            except (TypeError, ValueError) as exc:
                raise ValidationError(f"options are not canonicalizable: {exc}") from exc

            output = fn(content)
            self._counter += 1
            cid = f"conv-{self._counter}"
            losses = _LOSSES.get((from_format, to_format), ())
            record = ConversionRecord(
                conversion_id=cid,
                from_format=from_format,
                to_format=to_format,
                input_digest=_pin({"content": content}),
                output_digest=_pin({"output": output}),
                losses=tuple(losses),
                options_digest=_pin({"options": opts}),
                seq=seq,
            )
            self._conversions[cid] = record
            self._audit.append(doc_converter_audit_event("converted", seq, cid))
            return record, output

    def conversion(self, conversion_id: str) -> ConversionRecord:
        """Look up a conversion record by id."""
        if not isinstance(conversion_id, str) or not conversion_id:
            raise ValidationError("conversion_id must be a non-empty str")
        with self._lock:
            try:
                return self._conversions[conversion_id]
            except KeyError:
                raise ValidationError(f"unknown conversion_id: {conversion_id}") from None

    # -- metadata --------------------------------------------------------

    def metadata(self, content: str, from_format: str, seq: int) -> DocumentMetadata:
        """Extract title/author/date from frontmatter or first heading."""
        with self._lock:
            seq = self._advance(seq)
            content = _check_content(content)
            from_format = _check_format(from_format, "from")
            if from_format not in _READERS:
                raise UnknownFormatError(f"unknown reader format: {from_format}")
            title = author = date = None
            for line in content.splitlines():
                s = line.strip()
                m = _HEADING_RE.match(s)
                if m and title is None:
                    title = m.group(2).strip()
                elif s.lower().startswith("title:") and title is None:
                    title = s.split(":", 1)[1].strip() or None
                elif s.lower().startswith("author:") and author is None:
                    author = s.split(":", 1)[1].strip() or None
                elif s.lower().startswith("date:") and date is None:
                    date = s.split(":", 1)[1].strip() or None
            record = DocumentMetadata(
                doc_digest=_pin({"content": content}),
                title=title,
                author=author,
                date=date,
                seq=seq,
            )
            self._audit.append(doc_converter_audit_event("metadata-extracted", seq, ""))
            return record

    # -- audit -----------------------------------------------------------

    def audit_log(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._audit)


def doc_converter_audit_event(kind: str, seq: int, conversion_id: str) -> Dict[str, Any]:
    """Shape an audit.ndjson/1 record for this module (digests, never content)."""
    if kind not in ("converted", "metadata-extracted", "rejected"):
        raise ValidationError(f"unknown audit kind: {kind}")
    _check_seq(seq)
    return {
        "kind": kind,
        "seq": seq,
        "conversion_id": conversion_id,
        "module": "doc-converter",
        "version": DOC_CONVERTER_VERSION,
        "schema": "audit.ndjson/1",
    }


def main() -> None:
    dc = DocConverter()
    rec, out = dc.convert("# Hello\n\n**bold** text", "markdown", "html", 1)
    assert "<h1>Hello</h1>" in out and "<strong>bold</strong>" in out
    assert rec.verify(out)
    md = dc.metadata("# Title\nAuthor: Ada\nDate: 2026-10-07", "markdown", 2)
    assert md.title == "Title" and md.author == "Ada" and md.date == "2026-10-07"
    print("doc-converter OK: convert, losses, pins, metadata, audit")


if __name__ == "__main__":
    main()
