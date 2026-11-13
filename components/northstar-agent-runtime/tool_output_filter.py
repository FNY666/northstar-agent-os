"""Filter tool outputs *in code* before they are allowed into a context.

The gap this module closes: today a tool result is handed to the model as it
came off the tool.  Northstar already has the pieces to judge a body --
``credential_detector`` knows what a credential looks like, ``injection_detector``
knows what an instruction forgery looks like -- but nothing stands *between* a
tool and the model's context and asks the three questions that decide whether
the bytes should go in:

1. **Is it too big to read linearly?**  A body over the cap becomes a
   recoverable pointer: a path plus the first N lines.
2. **Does it carry a secret?**  A credential is replaced by a fixed,
   greppable placeholder before the body is read.
3. **Does it try to give the model orders?**  A body that matches an
   instruction-forgery pattern is quarantined, not passed and not quietly
   rewritten into something that looks clean.

The order is fixed and it is not an accident:

* **size cap first** -- redacting a megabyte nobody will read is wasted work;
* **redaction before injection scan** -- the scanner must never read a secret,
  because a scanner that sees a secret is a scanner that can report one.

The source of the shape is the frontier report "Harness debt" (AI Heroes,
frontier #15, rank 1), which reports that filtering tool outputs in code --
rather than streaming raw results through context -- moved BrowseComp from
45.3% to 61.6% for Opus 4.6, and that the fix is to *delete* capability
scaffolding while *keeping* the consequence boundaries: confirmation gates,
staleness checks, structured logging, permission boundaries.  This module is
one of those boundaries: it is a gate with a receipt, not scaffolding.

The size numbers are the ones the same frontier line reports for Deep Agents
(frontier #4): a tool response above 20,000 tokens is written to disk and
replaced by a path plus the first 10 lines.  This module keeps the *rule*
(write it down, keep the head) but measures it in **UTF-8 bytes**, because
bytes are reproducible and a token estimate is not.  The default byte cap is
the source's 20,000 tokens converted with this repository's own constant
(``context_budget.BYTES_PER_TOKEN == 4``): 80,000 bytes.

House style shared with ``credential_detector`` and ``injection_detector``:

* every layer produces a **receipt** -- what it did, why, and where the full
  body is -- and the receipts are JSON-serialisable and greppable;
* a layer that is switched off says so *in its receipt*; there is no silent
  degradation;
* deterministic: no wall clock, no network, no model calls;
* fail-closed: non-string input raises ``TypeError`` rather than returning
  "nothing to filter".

Honest scope: this module governs **what enters the model's context**.  It
does not claim at-rest hygiene for the files it writes -- the verbatim copy of
an oversized body is the tool's own output as produced, so a host that needs
secrets redacted on disk must apply :func:`redact_credentials` to the stored
copy itself.  And a clean scan is evidence of "no known pattern matched",
never proof of "no injection".
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Sequence

import credential_detector
from credential_detector import CredentialType
from injection_detector import scan_injection

#: Version of the rule set.  Bump when patterns or defaults change so a host
#: can pin which rule set produced a filter result.
TOOL_OUTPUT_FILTER_VERSION = "tool-output-filter.v1"

#: Default size cap, in **UTF-8 bytes**.  80,000 bytes is the frontier
#: report's 20,000-token rule converted with this repository's own constant
#: (``context_budget.BYTES_PER_TOKEN == 4``).  The unit is bytes on purpose:
#: it is measurable and reproducible, a token estimate is neither.
DEFAULT_MAX_BYTES = 80_000

#: How many lines of the head of an oversized body stay in the context.  The
#: number is the frontier report's Deep Agents rule ("the first 10 lines").
DEFAULT_PREVIEW_LINES = 10

#: A line count is not a bound: one 120,000-character line is one line.  The
#: preview is therefore also bounded in bytes, and the bound is applied at
#: *line* granularity so the preview stays a verbatim prefix of the original.
DEFAULT_PREVIEW_MAX_BYTES = 4_000

#: The placeholder a redacted value is replaced with.  Fixed format, fixed
#: vocabulary, greppable: ``[[REDACTED:<credential type>]]``.
REDACTION_PLACEHOLDER = "[[REDACTED:{kind}]]"

#: Layer names, in the order the layers run.  The order is the contract.
LAYER_SIZE_CAP = "size_cap"
LAYER_REDACTION = "redaction"
LAYER_INJECTION_SCAN = "injection_scan"
LAYER_ORDER = (LAYER_SIZE_CAP, LAYER_REDACTION, LAYER_INJECTION_SCAN)

#: The injection rules this filter enforces.  The vocabulary comes from
#: ``injection_detector``; the *selection* is narrower, on purpose:
#:
#: * ``code-fence`` and ``bare-markdown-header`` are excluded -- almost any
#:   tool output that contains a fenced block or a markdown heading would
#:   otherwise be quarantined, and a quarantine that fires on ordinary output
#:   is a quarantine people learn to switch off;
#: * ``base64-blob`` is excluded -- machine output carries base64 payloads
#:   (certificates, images, attachments) and flagging them proves nothing.
#:
#: What remains is forgery: instructions aimed at the model, and the markers
#: that impersonate a role the tool has no right to claim.
INJECTION_RULE_ALLOWLIST = frozenset({
    # direct
    "ignore-previous-instructions",
    "disregard-instructions",
    "forget-instructions",
    "you-are-now",
    "system-role-forge",
    "override-instructions",
    "new-instructions",
    # jailbreak
    "do-anything-now",
    "dan-persona",
    "developer-mode",
    "jailbreak-word",
    "bypass-restrictions",
    "unrestricted",
    # indirect (role impersonation only)
    "markdown-header-forge",
})


class ToolOutputFilterError(RuntimeError):
    """The filter could not take the body.  Never raised for a filter decision."""


@dataclass(frozen=True)
class FilterConfig:
    """Every number and switch the filter enforces, in one place.

    Defaults are the measured harness values.  A host lowers or raises them
    here; no rule in this module hard-codes a number of its own.
    """

    #: Size cap in UTF-8 bytes.  A body over the cap is truncated.
    max_bytes: int = DEFAULT_MAX_BYTES
    #: How many lines of the head stay in the context when a body is capped.
    preview_lines: int = DEFAULT_PREVIEW_LINES
    #: Hard byte bound on the preview, applied at line granularity.
    preview_max_bytes: int = DEFAULT_PREVIEW_MAX_BYTES
    #: Layer 1.  Off by default only if a host says so.
    enable_size_cap: bool = True
    #: Layer 2.
    enable_redaction: bool = True
    #: Layer 3.
    enable_injection_scan: bool = True
    #: Where full bodies and quarantined bodies are written.  ``None`` means
    #: "make a private temporary directory the first time one is needed".
    store_dir: str | None = None

    def __post_init__(self) -> None:
        for name in ("max_bytes", "preview_lines", "preview_max_bytes"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int):
                raise ValueError(f"{name} must be an int")
            if value <= 0:
                raise ValueError(f"{name} must be positive")
        for name in ("enable_size_cap", "enable_redaction", "enable_injection_scan"):
            if not isinstance(getattr(self, name), bool):
                raise ValueError(f"{name} must be a bool")
        if self.store_dir is not None and not isinstance(self.store_dir, str):
            raise ValueError("store_dir must be a string or None")


@dataclass(frozen=True)
class FilterReceipt:
    """One layer's receipt: what it did, why, and where the body is.

    The receipt is the *only* thing a layer is allowed to leave behind.  It is
    JSON-serialisable as-is and greppable: ``"action"`` and ``"reason"`` are
    fixed vocabularies, the details mapping holds only JSON scalars.
    """

    layer: str
    enabled: bool
    action: str
    reason: str
    input_bytes: int
    output_bytes: int
    path: str = ""
    details: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "layer": self.layer,
            "enabled": self.enabled,
            "action": self.action,
            "reason": self.reason,
            "input_bytes": self.input_bytes,
            "output_bytes": self.output_bytes,
            "path": self.path,
            "details": dict(self.details),
        }

    def to_json(self) -> str:
        """The receipt as one JSON line."""
        return json.dumps(self.as_dict(), sort_keys=True, ensure_ascii=False)


@dataclass(frozen=True)
class FilteredOutput:
    """What a caller may put into a context, and the evidence for it.

    ``output`` is the only field that belongs in a model's context.  The
    receipts are the audit trail: one per layer, in the order the layers ran.
    """

    output: str
    receipts: tuple[FilterReceipt, ...]
    full_output_path: str = ""
    truncated: bool = False
    redacted: bool = False
    redaction_count: int = 0
    quarantined: bool = False
    injection_rules: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "output": self.output,
            "receipts": [receipt.as_dict() for receipt in self.receipts],
            "full_output_path": self.full_output_path,
            "truncated": self.truncated,
            "redacted": self.redacted,
            "redaction_count": self.redaction_count,
            "quarantined": self.quarantined,
            "injection_rules": list(self.injection_rules),
        }

    def receipt_for(self, layer: str) -> FilterReceipt:
        """The receipt of one named layer."""
        for receipt in self.receipts:
            if receipt.layer == layer:
                return receipt
        raise KeyError(layer)

    def to_json(self) -> str:
        """The whole result as one JSON document."""
        return json.dumps(self.as_dict(), sort_keys=True, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Layer 2: redaction
# ---------------------------------------------------------------------------


def _redaction_patterns() -> list[tuple[CredentialType, "re.Pattern[str]"]]:
    """The credential shapes this module redacts.

    The shapes are the ones ``credential_detector`` already knows -- this
    module *reuses* them rather than inventing a second vocabulary, so a
    secret that the detector would flag is a secret this module redacts.

    The difference from the detector is that the detector reports a *masked*
    value (first two and last two characters) and keeps the span, while a
    redactor has to remove the value from the body entirely.  So the
    patterns are re-derived here from the detector's own table, keeping the
    detector's order (most specific first) and the detector's rule that a
    span is claimed by the tightest pattern that matches it.

    The one pattern that is deliberately *not* reused is the JWT-shaped
    branch of the token pattern: a JWT is ``header.payload.signature``, and
    redacting only the ``Bearer`` prefix of it would leave the secret in the
    body.  Redaction replaces the whole matched span instead.
    """
    patterns: list[tuple[CredentialType, "re.Pattern[str]"]] = []
    for cred_type, pattern in credential_detector._PATTERNS:  # noqa: SLF001
        patterns.append((cred_type, pattern))
    return patterns


def _value_offset(matched: str) -> int:
    """Where the *value* starts inside a matched credential span.

    A credential in an assignment -- ``password: hunter2``, ``api_key="sk-..."``
    -- is matched whole, but only the *value* may be replaced: the field
    name is structure, and the rule is that redaction replaces values and
    leaves the shape of the body alone.

    So the label and its separator are kept, and the replacement starts
    after the separator and after any opening quote.
    """
    match = re.search(r"[:=]\s*[\"']?", matched)
    if match is None:
        return 0
    return match.end()


def _value_end(matched: str, start_offset: int) -> int:
    """Where the *value* ends inside a matched credential span.

    The closing quote of an assignment belongs to the field, not to the
    secret, so it is kept.
    """
    end = start_offset
    while end > 0 and matched[end - 1] in "\"'":
        end -= 1
    return end


def _redaction_spans(text: str) -> list[tuple[int, int, int, int, CredentialType]]:
    """Every credential span in ``text``, tightest pattern first.

    Mirrors ``credential_detector.scan_for_credentials``'s claiming rule: a
    span already claimed by a tighter pattern is not claimed again.  The
    multiline pattern (a PEM block) is searched over the whole text, the
    single-line patterns per line -- exactly as the detector does it.

    Each entry is ``(start, end, value_start, value_end, credential_type)``:
    ``start``/``end`` bound the whole match, ``value_start``/``value_end``
    bound the part that may be replaced.
    """
    spans: list[tuple[int, int, int, int, CredentialType]] = []
    claimed: list[tuple[int, int]] = []

    def _is_claimed(start: int, end: int) -> bool:
        return any(not (end <= c_start or start >= c_end) for c_start, c_end in claimed)

    patterns = _redaction_patterns()
    # 1. The multiline pattern first: a PEM block spans lines, so it is
    #    searched over the whole text, and the whole block is one span.
    multiline_type, multiline_pattern = patterns[0]
    for match in multiline_pattern.finditer(text):
        start, end = match.start(), match.end()
        if _is_claimed(start, end):
            continue
        spans.append((start, end, start, end, multiline_type))
        claimed.append((start, end))

    # 2. The single-line patterns, per line.
    lines = text.split("\n")
    for cred_type, pattern in patterns[1:]:
        offset = 0
        for line in lines:
            for match in pattern.finditer(line):
                start = offset + match.start()
                end = offset + match.end()
                if _is_claimed(start, end):
                    continue
                matched = match.group(0)
                value_start = start + _value_offset(matched)
                value_end = start + _value_end(matched, len(matched))
                spans.append((start, end, value_start, value_end, cred_type))
                claimed.append((start, end))
            # The next line starts one past this line's newline.
            offset += len(line) + 1
    spans.sort(key=lambda item: (item[0], item[1]))
    return spans


def redact_credentials(text: str) -> tuple[str, list[dict[str, Any]]]:
    """Replace every credential value in ``text`` with a fixed placeholder.

    Returns the redacted text and one record per replacement.  A record
    names the credential *type* and the line number; it never carries the
    value, not even masked -- a receipt that leaks the first and last two
    characters of a secret is a partial disclosure.

    The structure of the text is preserved:

    * the replacement is in-place, so the line count and the field names
      around the value do not move;
    * only the *value* is replaced -- the label of an assignment survives,
      and so does its closing quote;
    * a multi-line match (a PEM block) is replaced by the placeholder plus
      the newlines it spanned, so the line numbering of everything after it
      is unchanged.
    """
    if not isinstance(text, str):
        raise TypeError("text must be a string")
    spans = _redaction_spans(text)
    if not spans:
        return text, []
    pieces: list[str] = []
    records: list[dict[str, Any]] = []
    cursor = 0
    for start, end, value_start, value_end, cred_type in spans:
        pieces.append(text[cursor:value_start])
        placeholder = REDACTION_PLACEHOLDER.format(kind=cred_type.value)
        pieces.append(placeholder)
        # Keep the line count: a span that spanned newlines leaves its
        # newlines behind so the lines after it keep their numbers.
        pieces.append("\n" * text.count("\n", value_start, value_end))
        # Keep whatever trailed the value inside the match -- the closing
        # quote of an assignment belongs to the field, not to the secret.
        pieces.append(text[value_end:end])
        records.append({
            "credential_type": cred_type.value,
            "line_number": text.count("\n", 0, value_start) + 1,
            "placeholder": placeholder,
        })
        cursor = end
    pieces.append(text[cursor:])
    return "".join(pieces), records


def _scan_injection_rules(text: str) -> tuple[str, ...]:
    """The names of the injection rules ``text`` matches, in order.

    Only the rules in :data:`INJECTION_RULE_ALLOWLIST` count; the rest of
    the detector's vocabulary is too noisy for a gate that must quarantine
    ordinary tool output.
    """
    names: list[str] = []
    for finding in scan_injection(text):
        if finding.pattern in INJECTION_RULE_ALLOWLIST and finding.pattern not in names:
            names.append(finding.pattern)
    return tuple(names)


# ---------------------------------------------------------------------------
# The body store
# ---------------------------------------------------------------------------


class BodyStore:
    """Where a body that does not fit in a context goes.

    The store's whole promise is "the bytes are still there, at this path".
    A filter that hands a model a pointer has handed it a recovery route, not
    a truncation -- so the store writes the body verbatim and the receipt
    names the path.
    """

    def __init__(self, root: str | os.PathLike[str] | None = None) -> None:
        self._root = Path(root).expanduser() if root else None
        self._counter = 0

    def _directory(self) -> Path:
        if self._root is not None:
            directory = self._root
        else:
            directory = Path(tempfile.mkdtemp(prefix="northstar-tool-output-"))
            self._root = directory
        try:
            directory.mkdir(parents=True, exist_ok=True)
        except OSError as error:
            raise ToolOutputFilterError(f"body store could not be created: {error}") from error
        return directory

    def write(self, text: str, *, name: str) -> str:
        """Write ``text`` verbatim; return the path it was written to."""
        if not isinstance(text, str):
            raise TypeError("text must be a string")
        directory = self._directory()
        self._counter += 1
        safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in name)
        safe = safe.strip("._") or "tool-output"
        target = directory / f"{safe}-{self._counter:06d}.txt"
        try:
            target.write_text(text, encoding="utf-8")
        except OSError as error:
            raise ToolOutputFilterError(f"body store write failed: {error}") from error
        return str(target)


def _byte_len(text: str) -> int:
    """The size of ``text`` in UTF-8 bytes -- the unit the cap is measured in."""
    return len(text.encode("utf-8"))


def _preview_lines(text: str, *, lines: int, max_bytes: int) -> tuple[str, int]:
    """The head of ``text``: its first ``lines`` lines, byte-bounded.

    The preview is a **verbatim prefix** of the original: the lines are taken
    whole, in order, and nothing is added to them.  The byte bound is
    applied at line granularity -- if adding the next line would exceed
    ``max_bytes``, the preview stops before it.  The result is therefore
    always ``text``'s own first N lines, character for character.
    """
    source_lines = text.split("\n")
    kept: list[str] = []
    used = 0
    for line in source_lines[:lines]:
        cost = len(line.encode("utf-8")) + (1 if kept else 0)
        if kept and used + cost > max_bytes:
            break
        kept.append(line)
        used += cost
    return "\n".join(kept), len(kept)


def _truncation_notice(path: str, *, total_bytes: int, shown_lines: int) -> str:
    """The header a truncated preview carries.

    It says three things and nothing else: the body was truncated, the full
    body is at ``path``, and the full body was ``total_bytes`` bytes.  A
    truncation that does not say these is a silent truncation.
    """
    return (
        f"[tool output truncated: {total_bytes} bytes total; "
        f"full output at {path}; "
        f"showing the first {shown_lines} line(s)]"
    )


# ---------------------------------------------------------------------------
# The filter
# ---------------------------------------------------------------------------


class ToolOutputFilter:
    """The gate a tool output passes before it is allowed into a context.

    Usage::

        filt = ToolOutputFilter(FilterConfig(max_bytes=2000))
        result = filt.filter(big_tool_output)
        context_text = result.output          # the only field for a model
        audit = result.to_json()              # the receipts

    The three layers run in a fixed order -- size cap, redaction, injection
    scan -- and each produces exactly one receipt.  A layer that is switched
    off still produces a receipt, and that receipt says ``enabled: false``
    with the reason ``disabled_by_configuration``: there is no silent
    degradation, because a filter that silently stops filtering is worse
    than no filter at all.
    """

    def __init__(self, config: FilterConfig | None = None) -> None:
        if config is None:
            config = FilterConfig()
        if not isinstance(config, FilterConfig):
            raise TypeError("config must be a FilterConfig")
        self.config = config
        self._store = BodyStore(config.store_dir)

    # -- the three layers ------------------------------------------------

    def _apply_size_cap(
        self, text: str, name: str
    ) -> tuple[str, FilterReceipt, str]:
        """Layer 1.  Returns (text for the next layer, receipt, body path)."""
        size = _byte_len(text)
        if not self.config.enable_size_cap:
            receipt = FilterReceipt(
                layer=LAYER_SIZE_CAP,
                enabled=False,
                action="skipped",
                reason="disabled_by_configuration",
                input_bytes=size,
                output_bytes=size,
                details={"max_bytes": self.config.max_bytes},
            )
            return text, receipt, ""
        if size <= self.config.max_bytes:
            receipt = FilterReceipt(
                layer=LAYER_SIZE_CAP,
                enabled=True,
                action="passed",
                reason="within_max_bytes",
                input_bytes=size,
                output_bytes=size,
                details={"max_bytes": self.config.max_bytes},
            )
            return text, receipt, ""
        path = self._store.write(text, name=name)
        preview, shown = _preview_lines(
            text,
            lines=self.config.preview_lines,
            max_bytes=self.config.preview_max_bytes,
        )
        notice = _truncation_notice(path, total_bytes=size, shown_lines=shown)
        filtered = f"{notice}\n{preview}"
        receipt = FilterReceipt(
            layer=LAYER_SIZE_CAP,
            enabled=True,
            action="truncated",
            reason="exceeds_max_bytes",
            input_bytes=size,
            output_bytes=_byte_len(filtered),
            path=path,
            details={
                "max_bytes": self.config.max_bytes,
                "total_bytes": size,
                "preview_lines": shown,
                "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
            },
        )
        return filtered, receipt, path

    def _apply_redaction(self, text: str) -> tuple[str, FilterReceipt, list[dict[str, Any]]]:
        """Layer 2.  Returns (text for the next layer, receipt, records)."""
        size = _byte_len(text)
        if not self.config.enable_redaction:
            receipt = FilterReceipt(
                layer=LAYER_REDACTION,
                enabled=False,
                action="skipped",
                reason="disabled_by_configuration",
                input_bytes=size,
                output_bytes=size,
            )
            return text, receipt, []
        redacted, records = redact_credentials(text)
        if not records:
            receipt = FilterReceipt(
                layer=LAYER_REDACTION,
                enabled=True,
                action="passed",
                reason="no_credentials_found",
                input_bytes=size,
                output_bytes=size,
                details={"redaction_count": 0, "credential_types": []},
            )
            return redacted, receipt, []
        types = sorted({record["credential_type"] for record in records})
        receipt = FilterReceipt(
            layer=LAYER_REDACTION,
            enabled=True,
            action="redacted",
            reason="credentials_found",
            input_bytes=size,
            output_bytes=_byte_len(redacted),
            details={
                "redaction_count": len(records),
                "credential_types": types,
                "lines": sorted({record["line_number"] for record in records}),
            },
        )
        return redacted, receipt, records

    def _apply_injection_scan(
        self, text: str, name: str
    ) -> tuple[str, FilterReceipt, str, tuple[str, ...]]:
        """Layer 3.  Returns (text for the context, receipt, path, rules)."""
        size = _byte_len(text)
        if not self.config.enable_injection_scan:
            receipt = FilterReceipt(
                layer=LAYER_INJECTION_SCAN,
                enabled=False,
                action="skipped",
                reason="disabled_by_configuration",
                input_bytes=size,
                output_bytes=size,
            )
            return text, receipt, "", ()
        rules = _scan_injection_rules(text)
        if not rules:
            receipt = FilterReceipt(
                layer=LAYER_INJECTION_SCAN,
                enabled=True,
                action="passed",
                reason="no_injection_pattern_matched",
                input_bytes=size,
                output_bytes=size,
                details={"matched_rules": []},
            )
            return text, receipt, "", ()
        path = self._store.write(text, name=name)
        notice = (
            f"[tool output quarantined: matched injection rule(s) "
            f"{', '.join(rules)}; "
            f"full output at {path}; "
            f"the body was NOT passed into the context]"
        )
        receipt = FilterReceipt(
            layer=LAYER_INJECTION_SCAN,
            enabled=True,
            action="quarantined",
            reason="injection_pattern_matched",
            input_bytes=size,
            output_bytes=_byte_len(notice),
            path=path,
            details={"matched_rules": list(rules)},
        )
        return notice, receipt, path, rules

    # -- the gate --------------------------------------------------------

    def filter(self, output: str, *, name: str = "tool-output") -> FilteredOutput:
        """Run the three layers over ``output`` and return the result.

        The order is fixed: **size cap, then redaction, then injection
        scan**.  Each layer sees the previous layer's output, and each
        produces one receipt.
        """
        if not isinstance(output, str):
            raise TypeError("output must be a string")
        if not isinstance(name, str) or not name:
            raise ValueError("name must be a non-empty string")

        capped, size_receipt, body_path = self._apply_size_cap(output, name)
        redacted, redaction_receipt, records = self._apply_redaction(capped)
        final, scan_receipt, quarantine_path, rules = self._apply_injection_scan(
            redacted, name
        )

        receipts = (size_receipt, redaction_receipt, scan_receipt)
        return FilteredOutput(
            output=final,
            receipts=receipts,
            full_output_path=body_path or quarantine_path,
            truncated=size_receipt.action == "truncated",
            redacted=bool(records),
            redaction_count=len(records),
            quarantined=scan_receipt.action == "quarantined",
            injection_rules=rules,
        )
