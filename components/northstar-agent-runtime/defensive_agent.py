"""Deterministic blue-team assessment for agent inputs and tool targets.

This is an orchestration layer, not an autonomous scanner.  It consumes text
and an optional declared tool target, runs the existing local detectors, and
returns a small, redaction-safe decision.  It never makes network requests,
executes commands, or attempts to exploit a finding.

Encoding does not change a payload's meaning.  The lexical tripwires only see
plain text, so before they run the boundary also inspects a small set of
*bounded, reversible* views of the same input:

* **percent-decoding** (``%69gnore``) and **HTML entities** (``&#105;gnore``);
* **``\\xNN`` / ``\\uNNNN`` escape** sequences;
* **decodable base64 / base32 runs** — this is what closes the short-blob hole
  the injection detector's 40-character carrier rule left open;
* **Latin-skeleton folding** — Cyrillic/Greek homoglyphs (``іgnore``) and
  compatibility ligatures/sub/superscripts collapse to their Latin skeleton;
* **separator folding** — punctuation and emoji between letters are joined
  (``ig❤nore`` → ``ignore``), because ``ignore-previous-instructions`` did not
  spell it with an emoji in the middle.

These transforms are deliberately *not* a general deobfuscator.  Each is
bounded (input size, run count, per-view output), applied at most once, and
only a *high-confidence* view finding escalates the verdict; a weakened signal
only reaches the review tier as ``D-INJ-004`` with a redaction-safe
``view:<name>`` tag.  Homoglyph/separator folding is heuristic and will
occasionally join benign text; that is why it can only produce a review, never
a block on its own.  A clean result still means "no known tripwire fired".
"""
from __future__ import annotations

import base64
import binascii
import html
import re
import unicodedata
from dataclasses import dataclass, replace
from enum import Enum
from typing import Any
from urllib.parse import unquote

from adversarial_detector import analyze_input
from credential_detector import scan_for_credentials
from injection_detector import InjectionType, scan_injection
from mcp_pivoting_detector import check_tool_call


VERSION = "defensive-agent.v2"
SCHEMA_PIN = "northstar.defensive-agent.v1"
_MAX_ASSESS_CHARS = 64 * 1024

#: Bounding constants for the decode/fold views.  Budgets are per assessment,
#: not per view, so a hostile input cannot multiply work by pattern choice.
_MAX_DECODED_VIEWS = 8
_MAX_DECODED_VIEW_CHARS = 8 * 1024
_MAX_B64_RUNS = 6
_MAX_PCT_RUNS = 6
_MIN_B64_RUN_CHARS = 12
_MAX_FOLD_CHARS = 8 * 1024

_PCT_RUN_RE = re.compile(r"(?:%[0-9A-Fa-f]{2}){3,}")
_HTML_ENTITY_RE = re.compile(r"&(?:#[0-9]{1,7}|#[xX][0-9A-Fa-f]{1,6}|[A-Za-z][A-Za-z0-9]{1,31});")
_ESCAPE_RE = re.compile(r"\\(?:x[0-9A-Fa-f]{2}|u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8})")
_B64_RUN_RE = re.compile(r"[A-Za-z0-9+/_\-]{%d,}={0,2}" % _MIN_B64_RUN_CHARS)

#: Latin skeleton for the Greek/Cyrillic look-alikes an attacker substitutes to
#: break a lexical pattern while a reader still sees an ordinary word.  Only
#: codepoints that are visually identical or near-identical to a Latin letter
#: are listed; genuine words in those scripts mostly keep other letters.
_CONFUSABLE_SKELETON = str.maketrans(
    {
        # Cyrillic
        "\u0410": "A", "\u0430": "a", "\u0412": "B", "\u0412": "B", "\u0432": "b",
        "\u0415": "E", "\u0435": "e", "\u041a": "K", "\u043a": "k", "\u041c": "M",
        "\u043c": "m", "\u041d": "H", "\u043d": "h", "\u041e": "O", "\u043e": "o",
        "\u0420": "P", "\u0440": "p", "\u0421": "C", "\u0441": "c", "\u0422": "T",
        "\u0442": "t", "\u0423": "Y", "\u0443": "y", "\u0425": "X", "\u0445": "x",
        "\u0406": "I", "\u0456": "i", "\u0408": "J", "\u0458": "j", "\u0405": "S",
        "\u0455": "s", "\u041f": "n", "\u043f": "n", "\u0418": "N", "\u0438": "u",
        "\u0417": "3", "\u0437": "3", "\u04bb": "h", "\u04cf": "l",
        # Greek
        "\u0391": "A", "\u03b1": "a", "\u0392": "B", "\u03b2": "b", "\u0395": "E",
        "\u03b5": "e", "\u0396": "Z", "\u0397": "H", "\u03b7": "n", "\u0399": "I",
        "\u03b9": "i", "\u039a": "K", "\u03ba": "k", "\u039c": "M", "\u039d": "N",
        "\u039f": "O", "\u03bf": "o", "\u03a1": "P", "\u03c1": "p", "\u03a4": "T",
        "\u03c4": "t", "\u03a5": "Y", "\u03c5": "u", "\u03a7": "X", "\u03c7": "x",
        "\u03b6": "z", "\u03bd": "v", "\u03c9": "w",
    }
)


class Decision(str, Enum):
    ALLOW = "allow"
    REVIEW = "review"
    BLOCK = "block"


@dataclass(frozen=True)
class DefensiveFinding:
    """A safe-to-log finding; raw input and URLs never appear here."""

    rule_id: str
    category: str
    severity: int
    detail: str


@dataclass(frozen=True)
class DefensiveAssessment:
    """The complete deterministic result of one local assessment."""

    version: str
    schema: str
    decision: Decision
    findings: tuple[DefensiveFinding, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "schema": self.schema,
            "decision": self.decision.value,
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "category": f.category,
                    "severity": f.severity,
                    "detail": f.detail,
                }
                for f in self.findings
            ],
        }


def _bounded(text: str) -> str:
    """Keep both edges of an oversized artifact (headers and tails both matter)."""
    if len(text) <= _MAX_ASSESS_CHARS:
        return text
    edge = _MAX_ASSESS_CHARS // 2
    return text[:edge] + "\n...[assessment middle omitted]...\n" + text[-edge:]


def _decode_base64_runs(text: str) -> str | None:
    """Decode decodable base64/base32 runs and splice the plaintext back in.

    The injection detector only treats a *40-character* blob as a carrier, so a
    28-character encoding of a full instruction slipped past it.  This decodes
    any run at or above :data:`_MIN_B64_RUN_CHARS`, bounded by
    :data:`_MAX_B64_RUNS` runs, and drops the parts that do not decode.
    """
    parts: list[str] = []
    cursor = 0
    runs = 0
    changed = False
    for match in _B64_RUN_RE.finditer(text):
        if runs >= _MAX_B64_RUNS:
            break
        runs += 1
        candidate = match.group(0)
        if len(set(candidate.rstrip("="))) < 4:
            continue
        padded = candidate + "=" * (-len(candidate) % 4)
        decoded: bytes | None = None
        for decoder in (base64.b64decode, base64.b32decode, base64.urlsafe_b64decode):
            try:
                if decoder is base64.b64decode:
                    raw = decoder(padded, validate=True)
                else:
                    raw = decoder(padded)
            except (binascii.Error, ValueError, TypeError):
                continue
            if raw and all(9 <= byte <= 13 or 32 <= byte <= 126 for byte in raw):
                decoded = raw
                break
        if decoded is None:
            continue
        parts.append(text[cursor:match.start()])
        parts.append(decoded.decode("ascii"))
        cursor = match.end()
        changed = True
    if not changed:
        return None
    parts.append(text[cursor:])
    return "".join(parts)


def _decode_percent_runs(text: str) -> str | None:
    """Percent-decode runs of escapes (``%69%67%6e%6f%72%65``)."""
    parts: list[str] = []
    cursor = 0
    runs = 0
    for match in _PCT_RUN_RE.finditer(text):
        if runs >= _MAX_PCT_RUNS:
            break
        runs += 1
        parts.append(text[cursor:match.start()])
        parts.append(unquote(match.group(0), errors="replace"))
        cursor = match.end()
    if not runs:
        return None
    parts.append(text[cursor:])
    return "".join(parts)


def _decode_escape_runs(text: str) -> str | None:
    """Decode ``\\xNN`` / ``\\uNNNN`` escape sequences without eval."""

    def _one(match: re.Match[str]) -> str:
        token = match.group(0)
        try:
            return chr(int(token[2:], 16))
        except (ValueError, OverflowError):
            return token

    if not _ESCAPE_RE.search(text):
        return None
    return _ESCAPE_RE.sub(_one, text)


def _decode_html_entities(text: str) -> str | None:
    """Decode numeric/named HTML entities (``&#105;gnore``)."""
    if not _HTML_ENTITY_RE.search(text):
        return None
    decoded = _HTML_ENTITY_RE.sub(lambda m: html.unescape(m.group(0)), text)
    return decoded if decoded != text else None


def _fold_confusables(text: str) -> str | None:
    """Fold homoglyphs/ligatures to a Latin skeleton (``іgnore`` → ``ignore``)."""
    head = text[:_MAX_FOLD_CHARS]
    folded = unicodedata.normalize("NFKC", head).translate(_CONFUSABLE_SKELETON)
    return folded if folded != head else None


def _fold_separators(text: str) -> str | None:
    """Drop punctuation/emoji inserted between letters (``ig❤nore``).

    A separator between two letters disappears, so ``ig❤nore`` reads as
    ``ignore``.  The same rule also changes word boundaries (``foo-bar`` →
    ``foobar``), which is why :func:`_decode_fold_views` also produces the
    space-joined reading (:func:`_fold_separators_spaced`) — the two readings
    together cover the plausible meanings of "separator inside a word".
    """
    head = text[:_MAX_FOLD_CHARS]
    out: list[str] = []
    previous_alpha = False
    dropped = 0
    for index, char in enumerate(head):
        is_alpha = char.isalpha()
        # Ordinary whitespace is the word boundary itself; joining across it
        # would destroy the sentence ("nore previous" → "noreprevious").
        # Only an *invisible-in-reading* separator inside a word is folded.
        if not is_alpha and not char.isspace() and previous_alpha and dropped < _MAX_FOLD_CHARS:
            following = head[index + 1] if index + 1 < len(head) else ""
            if following and following.isalpha():
                # A separator sandwiched between two letters: drop it.
                dropped += 1
                previous_alpha = True
                continue
        out.append(char)
        previous_alpha = is_alpha
    return "".join(out) if dropped else None


def _fold_separators_spaced(text: str) -> str | None:
    """The word-boundary reading of the separator fold (``foo-bar`` → ``foo bar``)."""
    head = text[:_MAX_FOLD_CHARS]
    out: list[str] = []
    previous_alpha = False
    dropped = 0
    for index, char in enumerate(head):
        is_alpha = char.isalpha()
        if not is_alpha and not char.isspace() and previous_alpha and dropped < _MAX_FOLD_CHARS:
            following = head[index + 1] if index + 1 < len(head) else ""
            if following and following.isalpha():
                out.append(" ")
                dropped += 1
                previous_alpha = True
                continue
        out.append(char)
        previous_alpha = is_alpha
    return "".join(out) if dropped else None


def _decode_fold_views(text: str) -> tuple[tuple[str, str], ...]:
    """All bounded, reversible views worth a second lexical pass.

    Returns ``(view_name, view_text)`` pairs.  Every transform is single-pass
    and size-bounded, and the list itself is capped at
    :data:`_MAX_DECODED_VIEWS`, so a large or hostile input cannot multiply
    detector work by choosing a fancy encoding.
    """
    views: list[tuple[str, str]] = []
    seen = {text}

    def add(name: str, value: str | None) -> None:
        if not value or len(views) >= _MAX_DECODED_VIEWS:
            return
        value = value[:_MAX_DECODED_VIEW_CHARS]
        if value in seen:
            return
        seen.add(value)
        views.append((name, value))

    folded = _fold_confusables(text)
    joined = _fold_separators(text)
    spaced = _fold_separators_spaced(text)
    spaced = _fold_separators_spaced(text)
    b64 = _decode_base64_runs(text)
    pct = _decode_percent_runs(text)
    esc = _decode_escape_runs(text)
    ent = _decode_html_entities(text)

    # Order matters for budget: the transforms that produced measured misses
    # go first, then their compositions (b64 inside HTML, homoglyph inside
    # percent-encoding), so a second-layer encoding still lands in the budget.
    add("homoglyph-fold", folded)
    add("separator-fold", joined)
    add("separator-fold-spaced", spaced)
    add("base64", b64)
    add("percent", pct)
    add("escapes", esc)
    add("html-entities", ent)
    for name, view in tuple(views):
        if name in {"base64", "percent", "html-entities"}:
            add(f"{name}+homoglyph-fold", _fold_confusables(view))
            add(f"{name}+separator-fold", _fold_separators(view))
            add(f"{name}+separator-fold-spaced", _fold_separators_spaced(view))
    for source_name, source in (("homoglyph-fold", folded), ("separator-fold", joined)):
        if source:
            add(f"{source_name}+base64", _decode_base64_runs(source))
            break
    return tuple(views)


def _scan_views(text: str) -> tuple[DefensiveFinding, ...]:
    """Scan the decode/fold views and classify them by confidence.

    A *high-confidence* view hit (jailbreak family, or a direct family that the
    plain view did not already carry) escalates to the normal block threshold.
    Anything weaker is a ``D-INJ-004`` review finding tagged with the view name
    — never a silent allow, never a block on a heuristic alone.
    """
    plain_patterns = {finding.pattern for finding in scan_injection(text)}
    out: list[DefensiveFinding] = []
    for name, view in _decode_fold_views(text):
        for finding in scan_injection(view)[:4]:
            family = finding.injection_type
            if family is InjectionType.JAILBREAK:
                out.append(
                    DefensiveFinding(
                        rule_id="D-INJ-003",
                        category=f"encoded-{family.value}",
                        severity=90,
                        detail=f"view:{name};pattern:{finding.pattern}",
                    )
                )
            elif family is InjectionType.DIRECT and finding.pattern not in plain_patterns:
                out.append(
                    DefensiveFinding(
                        rule_id="D-INJ-003",
                        category=f"encoded-{family.value}",
                        severity=75,
                        detail=f"view:{name};pattern:{finding.pattern}",
                    )
                )
            else:
                out.append(
                    DefensiveFinding(
                        rule_id="D-INJ-004",
                        category="encoded-signal",
                        severity=65,
                        detail=f"view:{name};pattern:{finding.pattern};family:{family.value}",
                    )
                )
    return tuple(out)


def assess(
    text: str = "",
    *,
    tool_name: str | None = None,
    url: str | None = None,
) -> DefensiveAssessment:
    """Assess untrusted content and an optional tool target.

    The function is pure apart from detector-local computation.  A jailbreak,
    hardcoded credential, or blocked internal target is a fail-closed block.
    Known instruction forgery without those stronger signals requires review.
    Invalid detector input propagates as a programming error instead of being
    silently treated as clean.
    """
    if not isinstance(text, str):
        raise TypeError("text must be a string")
    if tool_name is not None and not isinstance(tool_name, str):
        raise TypeError("tool_name must be a string or None")
    if url is not None and not isinstance(url, str):
        raise TypeError("url must be a string or None")
    if url is not None and tool_name is None:
        raise ValueError("tool_name is required when url is provided")

    # Keep regex and base64 inspection bounded even when a tool returned a
    # large but already-capped artifact. Preserve both edges so an injection
    # appended to a normal header is still visible to the local tripwires.
    text = _bounded(text)

    # Inspect a compatibility-normalized view as well as the original bytes.
    # Fullwidth Latin and similar presentation forms otherwise evade lexical
    # tripwires while rendering as ordinary instructions to a model.
    inspection_text = unicodedata.normalize("NFKC", text)
    findings: list[DefensiveFinding] = []
    injection_findings = scan_injection(inspection_text)
    for finding in injection_findings:
        family = finding.injection_type
        severity = 90 if family is InjectionType.JAILBREAK else 70
        findings.append(
            DefensiveFinding(
                rule_id="D-INJ-001" if family is InjectionType.JAILBREAK else "D-INJ-002",
                category=family.value,
                severity=severity,
                detail=f"pattern:{finding.pattern};span:{finding.start}-{finding.end}",
            )
        )

    # Encoding is not meaning: percent/HTML/escape/base64/homoglyph/separator
    # views get one bounded lexical pass of their own (defensive-agent.v2).
    findings.extend(_scan_views(inspection_text))

    # Unicode format/control characters and mixed-script confusables are a
    # separate tripwire from lexical injection. Keep their signal at review
    # severity: legitimate multilingual and rich-text content exists, but an
    # invisible character must never be silently treated as clean.
    adversarial = analyze_input(text)
    for signal in adversarial.findings:
        if signal.signal.value == "high-frequency-noise":
            rule_id = "D-ADV-001"
        elif signal.signal.value == "imperceptible-perturbation":
            rule_id = "D-ADV-002"
        else:
            rule_id = "D-ADV-003"
        findings.append(
            DefensiveFinding(
                rule_id=rule_id,
                category=f"adversarial-{signal.signal.value}",
                severity=80,
                detail=f"score:{signal.score:.3f}",
            )
        )

    lowered = inspection_text.lower()
    credential_candidate = any(
        marker in lowered
        for marker in (
            "sk-", "akia", "ghp_", "gho_", "ghu_", "ghs_", "ghr_",
            "xox", "aiza", "api_key", "apikey", "bearer", "token",
            "password", "private key",
        )
    ) or (inspection_text.count(".") >= 2 and len(inspection_text) < 16_384)
    for finding in scan_for_credentials(inspection_text) if credential_candidate else ():
        findings.append(
            DefensiveFinding(
                rule_id="D-SEC-001",
                category="credential-exposure",
                severity=100,
                detail=f"type:{finding.credential_type.value};line:{finding.line_number};value:{finding.masked_value}",
            )
        )

    if url is not None and tool_name is not None:
        if check_tool_call(tool_name, url).blocked:
            findings.append(
                DefensiveFinding(
                    rule_id="D-NET-001",
                    category="internal-target",
                    severity=100,
                    detail="tool target rejected by local egress rule",
                )
            )

    findings.sort(key=lambda item: (-item.severity, item.rule_id, item.detail))
    if any(item.severity >= 90 for item in findings):
        decision = Decision.BLOCK
    elif findings:
        decision = Decision.REVIEW
    else:
        decision = Decision.ALLOW
    return DefensiveAssessment(VERSION, SCHEMA_PIN, decision, tuple(findings))


def sanitize_for_model(
    text: str,
    *,
    preserve_length: bool = False,
) -> tuple[str, DefensiveAssessment]:
    """Remove known instruction-forgery spans before model consumption.

    High-confidence findings are replaced with a fixed quarantine marker. For
    review-level direct/indirect injections, only the matched spans are
    replaced so surrounding benign tool output remains useful. Credentials,
    jailbreaks, and blocked targets therefore never get partial disclosure.
    ``preserve_length`` keeps the returned review-level artifact within the
    input's character budget using inert padding; it is for resource accounting
    at an output boundary, not for preserving the matched bytes.
    """
    if not isinstance(preserve_length, bool):
        raise TypeError("preserve_length must be a bool")
    assessment = assess(text)
    if assessment.decision is Decision.BLOCK:
        return "[blocked by defensive agent]", assessment
    if not isinstance(text, str):
        raise TypeError("text must be a string")
    normalized = unicodedata.normalize("NFKC", text)
    scan_text = normalized if normalized != text else text
    if len(scan_text) <= _MAX_ASSESS_CHARS:
        findings = scan_injection(scan_text)
    else:
        edge = _MAX_ASSESS_CHARS // 2
        prefix = scan_injection(scan_text[:edge])
        suffix_offset = len(scan_text) - edge
        suffix = tuple(
            replace(finding, start=finding.start + suffix_offset, end=finding.end + suffix_offset)
            for finding in scan_injection(scan_text[-edge:])
        )
        findings = prefix + suffix
    has_unicode_controls = any(
        unicodedata.category(char) == "Cf"
        or (unicodedata.category(char) == "Cc" and char not in "\t\n\r")
        for char in text
    )
    has_unicode_separators = any(
        unicodedata.category(char) in {"Pd", "Zs"} for char in normalized
    )
    if not findings and not has_unicode_controls and not has_unicode_separators:
        return text, assessment
    sanitized = scan_text
    for finding in sorted(findings, key=lambda item: (item.start, item.end), reverse=True):
        sanitized = sanitized[: finding.start] + "[redacted defensive rule]" + sanitized[finding.end :]
    # Remove Unicode format and control characters independently of lexical
    # injection matches. In preserve-length mode use a visible one-character
    # marker so accounting stays stable without reconstructing a readable
    # instruction; otherwise leave an explicit marker for operators.
    unicode_rewritten: list[str] = []
    for char in sanitized:
        category = unicodedata.category(char)
        if category == "Cf" or (category == "Cc" and char not in "\t\n\r"):
            unicode_rewritten.append("□" if preserve_length else "[redacted unicode]")
        else:
            unicode_rewritten.append(char)
    sanitized = "".join(unicode_rewritten)
    # Removing an invisible separator can join words into a fresh jailbreak
    # phrase that was not present during the first scan. Re-assess the cleaned
    # representation before releasing it, and fail closed if it now matches a
    # high-confidence rule.
    # Collapse only for detection: model-visible spacing is preserved below,
    # while equivalent whitespace cannot hide a phrase from lexical rules.
    post_cleanup = assess(" ".join(sanitized.split()))
    separator_cleanup = "".join(
        " " if char == "□" or unicodedata.category(char) in {"Pd", "Zs"} else char
        for char in sanitized
    )
    separator_pass = assess(" ".join(separator_cleanup.split()))
    if separator_pass.findings and any(
        finding.rule_id.startswith("D-INJ-") for finding in separator_pass.findings
    ):
        post_cleanup = replace(separator_pass, decision=Decision.BLOCK)
    if post_cleanup.decision is Decision.BLOCK or any(
        finding.rule_id.startswith("D-INJ-") for finding in post_cleanup.findings
    ):
        return "[blocked by defensive agent]", replace(post_cleanup, decision=Decision.BLOCK)
    if preserve_length and len(sanitized) < len(text):
        # Keep resource accounting stable without retaining any bytes from the
        # matched span. Padding is deliberately inert whitespace: it cannot be
        # interpreted as a hidden instruction, but it still exercises the same
        # context/compaction ceilings as the original artifact.
        sanitized += " " * (len(text) - len(sanitized))
    elif preserve_length and len(sanitized) > len(text):
        # A short marker (for example ``### system``) can be shorter than the
        # fixed redaction label. Never let a safety rewrite increase the caller's
        # resource budget; retain the safe prefix and drop the rest.
        sanitized = sanitized[: len(text)]
    return sanitized, assessment


def stdlib_only() -> bool:
    """The orchestrator itself uses only stdlib plus local sibling modules."""
    return True


__all__ = [
    "Decision",
    "DefensiveFinding",
    "DefensiveAssessment",
    "assess",
    "sanitize_for_model",
]
