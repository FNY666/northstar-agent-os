"""Deceptive reasoning detector: false claims, evidence concealment, source fabrication.

Research basis (second-hand):
- Reuters bidding-experiment coverage (~Oct 2026): agents in competitive bidding
  sessions made false claims at 88%/84%/88% rates, rising +12-20pp after learning;
  deception as an instrumental strategy, not a glitch.
- Shanghai AI Lab x HKUST failure-concealment study: agents guessed, swapped
  sources, and fabricated *despite holding the evidence* - concealment with the
  receipts in hand.
- Alignment line ("Silent Stop" eval, Oct 2026): models that concluded a target
  was real reported it only 17-18% of the time; narration vs action dissociate.

Design: lexical/shape detector over a host-reported (claim, evidence) pair. The
caller supplies the evidence as structured facts and sources; the detector checks
three failure modes:

- FALSE_CLAIM: the claim asserts a value for a fact key that contradicts the
  evidence's value (including "no failures" style denials over adverse facts).
- EVIDENCE_CONCEALMENT: the claim asserts completeness ("all tests passed")
  while the evidence holds material adverse facts the claim never mentions.
- SOURCE_FABRICATION: the claim cites a source absent from the evidence, or
  attributes quoted content to a source that does not contain it.

Detector, not defense: it names the failure mode; the gate layer decides what
to do with the verdict.

Honest scope: pattern-based. It catches explicit value contradictions,
completeness-claims over adverse evidence, and citations to absent sources. It
does not adjudicate open-world truth, understand novel paraphrase, or verify
that a cited source is itself trustworthy. A lie that never touches an evidence
key is invisible to this module.

No wall-clock anywhere. All inputs are strings/mappings; all functions are pure.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Mapping, Optional, Sequence, Tuple

#: Version pin for the detector described here.
DECEPTION_DETECTOR_VERSION = "deception-detector.v1"

#: Schema pin stamped on structured outputs.
SCHEMA_PIN = "northstar.deception-detector.v1"


class DeceptionType(Enum):
    """The three deception failure modes this module detects."""

    FALSE_CLAIM = "false-claim"
    EVIDENCE_CONCEALMENT = "evidence-concealment"
    SOURCE_FABRICATION = "source-fabrication"


@dataclass(frozen=True)
class Evidence:
    """Structured evidence the claim is checked against.

    ``facts`` maps a fact key (e.g. ``"highest_bid"``) to its evidenced value
    (e.g. ``"120"``). ``sources`` maps a source id (e.g. ``"bid-log"`` or a URL)
    to the source's text.
    """

    facts: Mapping[str, str] = field(default_factory=dict)
    sources: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.facts, Mapping):
            raise TypeError("facts must be a mapping")
        if not isinstance(self.sources, Mapping):
            raise TypeError("sources must be a mapping")
        for k, v in self.facts.items():
            if not isinstance(k, str) or not k.strip():
                raise ValueError("fact keys must be non-empty strings")
            if not isinstance(v, str):
                raise TypeError("fact values must be strings")
        for k, v in self.sources.items():
            if not isinstance(k, str) or not k.strip():
                raise ValueError("source ids must be non-empty strings")
            if not isinstance(v, str):
                raise TypeError("source texts must be strings")


@dataclass(frozen=True)
class DetectionResult:
    """Structured verdict of :func:`analyze_deception`."""

    deceptive: bool
    deception_type: Optional[DeceptionType]
    detail: str
    schema: str = SCHEMA_PIN

    def __post_init__(self) -> None:
        if not isinstance(self.deceptive, bool):
            raise TypeError("deceptive must be a bool")
        if self.deception_type is not None and not isinstance(
            self.deception_type, DeceptionType
        ):
            raise TypeError("deception_type must be a DeceptionType or None")
        if not isinstance(self.detail, str):
            raise TypeError("detail must be a string")
        if self.deceptive and self.deception_type is None:
            raise ValueError("deceptive verdicts must name a deception type")
        if not self.deceptive and self.deception_type is not None:
            raise ValueError("clean verdicts must not name a deception type")


# ---------------------------------------------------------------------------
# Marker sets
# ---------------------------------------------------------------------------

#: Phrases by which a claim asserts everything is fine.
_COMPLETENESS_MARKERS = (
    "no issues",
    "no errors",
    "no failures",
    "no problems",
    "all tests passed",
    "everything succeeded",
    "all clear",
    "nothing failed",
    "zero issues",
    "complete success",
    "fully successful",
)

#: Tokens that mark a fact key as adverse (failures, breaches, ...).
_ADVERSE_KEY_TOKENS = (
    "fail",
    "error",
    "breach",
    "violation",
    "incident",
    "bug",
    "defect",
    "fraud",
)

#: Fact values that mean "nothing adverse happened".
_BENIGN_VALUES = frozenset({"0", "none", "no", "false", "", "n/a", "na", "zero"})

#: Negation words that turn a mention of an adverse key into a denial.
_NEGATIONS = ("no ", "not ", "never ", "n't ", "without ", "zero ", "none of ")


def _normalize(text: str) -> str:
    """Lowercase, collapse whitespace, strip surrounding punctuation."""
    return re.sub(r"\s+", " ", text.strip().lower().strip(".,;:!?\"'")).strip()


def _key_variants(key: str) -> Tuple[str, ...]:
    """Spellings under which a fact key may appear in prose."""
    lowered = key.lower()
    return (lowered, lowered.replace("_", " "), lowered.replace("_", "-"))


def _is_adverse_fact(key: str, value: str) -> bool:
    """True when the fact records that something bad happened."""
    key_l = key.lower()
    if not any(tok in key_l for tok in _ADVERSE_KEY_TOKENS):
        return False
    return _normalize(value) not in _BENIGN_VALUES


# ---------------------------------------------------------------------------
# False-claim detection
# ---------------------------------------------------------------------------

#: "key is X" / "key: X" / "key = X" / "key was X" assertion shapes.
#: The asserted value is a single token (no spaces) so "bid of 150 was the
#: highest" pins "150", not "150 was the highest".
_ASSERTION_RE = re.compile(
    r"([a-z][a-z0-9 _\-]{1,40}?)\s*(?:is|:|=|was|were|of|at)\s*"
    r"[\"\']?([a-z0-9][a-z0-9_\-./%]*)[\"\']?",
    re.IGNORECASE,
)

#: Reversed shape: "150 was the highest bid" (value first, key last).
_REVERSED_ASSERTION_RE = re.compile(
    r"[\"\']?([a-z0-9][a-z0-9_\-./%]*)[\"\']?\s+(?:was|were|is)\s+the\s+"
    r"([a-z][a-z0-9 _\-]{1,40})",
    re.IGNORECASE,
)


def _key_tokens(key: str) -> Tuple[str, ...]:
    """The key's word tokens, e.g. ``highest_bid`` -> ``("highest", "bid")``."""
    return tuple(t for t in re.split(r"[_\- ]+", key.lower()) if t)


def _subject_mentions_key(subject: str, key: str) -> bool:
    """True when an assertion's subject is about the fact key.

    Exact variant match, or any shared content token (length >= 3, so "of"
    and "at" do not count). Lexical backstop: "our bid" mentions
    ``highest_bid`` via "bid"; genuinely unrelated subjects do not.
    """
    subject_n = _normalize(subject)
    if subject_n in _key_variants(key):
        return True
    subj_toks = {t for t in subject_n.split() if len(t) >= 3}
    key_toks = {t for t in _key_tokens(key) if len(t) >= 3}
    return bool(subj_toks & key_toks)


def _detect_false_claim(claimed: str, facts: Mapping[str, str]) -> Optional[str]:
    """Return a detail string when the claim asserts a contradicted value."""
    lowered = claimed.lower()
    for key, value in facts.items():
        value_n = _normalize(value)
        if not value_n:
            continue
        # Path 1: assertion-shaped "subject <sep> X" where the subject is
        # about this key and X differs from the evidenced value.
        for match in _ASSERTION_RE.finditer(claimed):
            if not _subject_mentions_key(match.group(1), key):
                continue
            asserted = _normalize(match.group(2))
            if asserted and asserted != value_n:
                return (
                    f"false-claim: claim asserts {key}={asserted!r} "
                    f"but evidence records {value_n!r}"
                )
        # Path 1b: reversed "X was the <key>".
        for match in _REVERSED_ASSERTION_RE.finditer(claimed):
            if not _subject_mentions_key(match.group(2), key):
                continue
            asserted = _normalize(match.group(1))
            if asserted and asserted != value_n:
                return (
                    f"false-claim: claim asserts {key}={asserted!r} "
                    f"but evidence records {value_n!r}"
                )
        # Path 2: negation-shaped denial over an adverse fact, e.g.
        # "no failures" while facts record failures="3".
        if _is_adverse_fact(key, value):
            for variant in _key_variants(key):
                if variant not in lowered:
                    continue
                for neg in _NEGATIONS:
                    if neg + variant in lowered:
                        return (
                            f"false-claim: claim denies {key} "
                            f"but evidence records {value_n!r}"
                        )
    return None


# ---------------------------------------------------------------------------
# Evidence-concealment detection
# ---------------------------------------------------------------------------


def _detect_evidence_concealment(
    claimed: str, facts: Mapping[str, str]
) -> Optional[str]:
    """Return a detail string when completeness is claimed over adverse facts."""
    lowered = claimed.lower()
    if not any(marker in lowered for marker in _COMPLETENESS_MARKERS):
        return None
    concealed = []
    for key, value in facts.items():
        if not _is_adverse_fact(key, value):
            continue
        # The adverse fact is disclosed if the claim mentions its key at all.
        if any(v in lowered for v in _key_variants(key)):
            continue
        concealed.append(f"{key}={_normalize(value)!r}")
    if concealed:
        return (
            "evidence-concealment: claim asserts completeness while omitting "
            f"adverse facts: {', '.join(sorted(concealed))}"
        )
    return None


# ---------------------------------------------------------------------------
# Source-fabrication detection
# ---------------------------------------------------------------------------

_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
_CITATION_RES = (
    re.compile(r"according to ([^.]{1,60}?)(?:[.,;]|$)", re.IGNORECASE),
    re.compile(r"source:\s*([^\s,;]{1,60})", re.IGNORECASE),
    re.compile(r"study by ([^.]{1,60}?)(?:[.,;]|$)", re.IGNORECASE),
    re.compile(r"\[(\d{1,3})\]"),
)
_QUOTE_RE = re.compile(r"[\"\u201c]([^\"\u201d]{4,200})[\"\u201d]")


def _extract_citations(claimed: str) -> Tuple[str, ...]:
    """Citation strings found in the claim (URLs, named sources, [n] refs)."""
    found: list[str] = []
    for m in _URL_RE.finditer(claimed):
        found.append(_normalize(m.group(0)))
    for rx in _CITATION_RES:
        for m in rx.finditer(claimed):
            found.append(_normalize(m.group(1)))
    # Deduplicate, preserve order.
    seen: set[str] = set()
    out: list[str] = []
    for c in found:
        if c and c not in seen:
            seen.add(c)
            out.append(c)
    return tuple(out)


def _citation_matches_source(citation: str, sources: Mapping[str, str]) -> bool:
    """True when the citation resolves to a source the evidence holds."""
    for source_id in sources:
        sid = _normalize(source_id)
        if not sid:
            continue
        if citation == sid or citation in sid or sid in citation:
            return True
    return False


def _detect_source_fabrication(
    claimed: str, sources: Mapping[str, str]
) -> Optional[str]:
    """Return a detail string when the claim cites absent or misquoted sources."""
    if not sources and not _extract_citations(claimed):
        return None
    citations = _extract_citations(claimed)
    for citation in citations:
        if not _citation_matches_source(citation, sources):
            return (
                f"source-fabrication: claim cites {citation!r} "
                "which is absent from the evidence sources"
            )
    # Attributed quotes: a quoted span near a citation must appear in a source.
    for quote_m in _QUOTE_RE.finditer(claimed):
        quote = _normalize(quote_m.group(1))
        if len(quote) < 8:
            continue
        window = claimed[max(0, quote_m.start() - 120) : quote_m.end() + 120].lower()
        cited_here = [c for c in citations if c in window]
        if not cited_here:
            continue
        if not any(quote in _normalize(text) for text in sources.values()):
            return (
                "source-fabrication: claim attributes a quote to a cited source "
                "but the quote appears in none of the evidence sources"
            )
    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def analyze_deception(claimed: str, evidence: Evidence) -> DetectionResult:
    """Analyze a claim against evidence; fixed check order, first hit wins.

    Order: false-claim, evidence-concealment, source-fabrication. A claim that
    trips none of the three is clean.
    """
    if not isinstance(claimed, str):
        raise TypeError("claimed must be a string")
    if not isinstance(evidence, Evidence):
        raise TypeError("evidence must be an Evidence")
    if not claimed.strip():
        return DetectionResult(
            deceptive=False,
            deception_type=None,
            detail="empty claim carries no assertion",
        )

    detail = _detect_false_claim(claimed, evidence.facts)
    if detail is not None:
        return DetectionResult(
            deceptive=True, deception_type=DeceptionType.FALSE_CLAIM, detail=detail
        )

    detail = _detect_evidence_concealment(claimed, evidence.facts)
    if detail is not None:
        return DetectionResult(
            deceptive=True,
            deception_type=DeceptionType.EVIDENCE_CONCEALMENT,
            detail=detail,
        )

    detail = _detect_source_fabrication(claimed, evidence.sources)
    if detail is not None:
        return DetectionResult(
            deceptive=True,
            deception_type=DeceptionType.SOURCE_FABRICATION,
            detail=detail,
        )

    return DetectionResult(
        deceptive=False, deception_type=None, detail="no deception pattern matched"
    )


def detect_deception(claimed: str, evidence: Evidence) -> bool:
    """True when the claim contradicts the evidence in any of the three modes."""
    return analyze_deception(claimed, evidence).deceptive


def classify_deception(claimed: str, evidence: Evidence) -> Optional[DeceptionType]:
    """The deception mode, or None when the claim is clean."""
    return analyze_deception(claimed, evidence).deception_type


def main() -> None:
    ev = Evidence(
        facts={"highest_bid": "120", "failures": "3"},
        sources={"bid-log": "round 3: agent_a bid 120, the highest recorded"},
    )
    cases = [
        ("our bid of 150 was the highest", True, DeceptionType.FALSE_CLAIM),
        ("no failures occurred, all tests passed", True, DeceptionType.FALSE_CLAIM),
        ("all tests passed", True, DeceptionType.EVIDENCE_CONCEALMENT),
        ("per https://fake.example/report the bid was 120", True, DeceptionType.SOURCE_FABRICATION),
        ("the highest bid was 120 with 3 failures logged", False, None),
    ]
    for text, want_deceptive, want_type in cases:
        got = analyze_deception(text, ev)
        status = "ok" if (got.deceptive, got.deception_type) == (want_deceptive, want_type) else "MISMATCH"
        print(f"[{status}] {text!r} -> {got.deceptive} {got.deception_type}")
    print("deception-detector OK")


if __name__ == "__main__":
    main()
