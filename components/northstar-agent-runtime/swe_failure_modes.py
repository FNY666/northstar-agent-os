"""Failure-mode classifier for failed patches, with a per-mode check route.

Northstar today treats a failed patch as one undifferentiated thing: the
tests are red, so the loop says "run the tests again".  That single route
is wrong for at least four different reasons, and the Real-SWE failure
taxonomy (frontier #16) is the evidence.  Different models miss in
different ways, and a missed requirement is *not* caught by an
integration suite, and an integration break is *not* caught by re-reading
the instruction against the diff.  One review checklist cannot cover both.

This module is the missing half:

- :func:`classify` sorts a failed patch into one of four modes (or
  ``UNKNOWN``, when it fits none -- it is never forced into a bucket);
- :func:`route` sends each mode to the check that can actually catch it,
  as a fixed structure (check name + inputs + pass criterion), not free
  text;
- :func:`cost_per_delivery` books cost per *verified delivery*, not per
  run, and apportions it across failure modes.

Source (Real-SWE, industry write-up by Specific Labs, via
constructionaibrief, 2026-09-14 -- a **secondary** write-up, not the
benchmark paper; the underlying task count is not stated there).  Values
below are quoted from that write-up:

- Resolution, pass@1 averaged over eight runs per task: "Claude Code
  (Fable 5.1)" 38.8%, "Codex CLI (GPT-6 Astra)" 33.8%, "Gemini 3.8 Flash"
  31.2%.
- Cost: Fable 5.1 $6.96 per rollout, "~$17.94" per resolved task; Gemini
  3.8 Flash $2.50 per rollout, "~$8.01" per resolved task.  Codex CLI's
  cost cells are empty in the source.
- Task shape: "The median task touches 11 files and the median
  instruction runs about 1,742 characters"; scores are "pass@1, averaged
  over eight runs per task".
- Failure taxonomy: "Grok 4.6's failures were dominated by missed
  requirements -- 67.2% of its misses"; "Gemini 3.8 Flash's failures were
  mostly integration errors (49.1%)"; "GPT-5.6 Sol's failures leaned
  toward unverified assumptions about how the existing system worked
  (43.3%)"; "Fable 5.1 and GPT-6 Astra spread their failures more evenly
  across categories, with no single failure type above 37%."

The write-up's own implication is the rule this module implements: "a
requirements-miss model is caught by comparing the diff to the original
ask, while an integration-error model requires running the tool against
real data -- one checklist cannot cover both."

Northstar extensions (marked as such, not presented as the source's):

- The four-mode vocabulary, the deterministic rule set, the check routes
  and the cost-per-delivery accounting are Northstar's.  The source
  supplies the failure categories and the cost shape; it does not
  specify thresholds or check routing.
- ``WRONG_LAYER`` (fixed the symptom, wrong layer) is a Northstar
  addition: the source's taxonomy is about what the patch *did*, and
  does not name this mode.
- The module performs no model inference and no test execution: it
  classifies a failure record the caller supplies, and routes it.

Everything here is pure and deterministic.  No wall-clock, no I/O.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Mapping, Optional, Sequence, Tuple

#: Version pin for this module's record shapes.
SWE_FAILURE_MODES_VERSION = "swe-failure-modes.v1"

#: Schema pin stamped on structured outputs.
SCHEMA_PIN = "northstar.swe-failure-modes.v1"


class FailureMode(Enum):
    """The four failure modes, plus the explicit ``UNKNOWN`` bucket.

    ``UNKNOWN`` is a real answer, not a failure to answer: a failure that
    fits none of the four rules is reported as ``UNKNOWN`` rather than
    forced into the nearest category.
    """

    REQUIREMENT_MISS = "requirement-miss"
    INTEGRATION_BREAK = "integration-break"
    UNVERIFIED_ASSUMPTION = "unverified-assumption"
    WRONG_LAYER = "wrong-layer"
    UNKNOWN = "unknown"


#: The four routable modes, in the order the classifier checks them.
CLASSIFIABLE_MODES: Tuple[FailureMode, ...] = (
    FailureMode.REQUIREMENT_MISS,
    FailureMode.INTEGRATION_BREAK,
    FailureMode.UNVERIFIED_ASSUMPTION,
    FailureMode.WRONG_LAYER,
)

#: Rule names, pinned.  A classification always names the rule that fired.
RULE_REQUIREMENT_UNMET = "requirement-unmet"
RULE_INTEGRATION_OFF_TARGET = "integration-off-target"
RULE_ASSUMPTION_UNVERIFIED = "assumption-unverified"
RULE_SYMPTOM_ONLY = "symptom-only"

#: The rule that fires when nothing matched.
RULE_NONE = "no-rule-matched"


class SweFailureModesError(ValueError):
    """Raised when a record would carry a value outside the closed set."""


# ---------------------------------------------------------------------------
# records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TestOutcome:
    """One test's outcome, as the caller reports it.

    ``passed_before_patch`` is the *only* way to tell an integration break
    from a plain failure: a test that was already red before the patch
    says nothing about what the patch broke.
    """

    name: str
    passed: bool
    file: str = ""
    line: int = 0
    #: True when this test passed before the patch was applied.
    passed_before_patch: Optional[bool] = None
    #: The module/file the test exercises, when known.  Used to compare a
    #: failing test against the files the patch touched.
    target_file: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name.strip():
            raise SweFailureModesError("test name must be a non-empty string")
        if not isinstance(self.passed, bool):
            raise SweFailureModesError("passed must be a bool")
        if not isinstance(self.line, int) or isinstance(self.line, bool):
            raise SweFailureModesError("line must be an int")
        if self.line < 0:
            raise SweFailureModesError("line must not be negative")
        if self.passed_before_patch is not None and not isinstance(
            self.passed_before_patch, bool
        ):
            raise SweFailureModesError("passed_before_patch must be a bool or None")


@dataclass(frozen=True)
class PatchChange:
    """One file the patch touched, and what it did there."""

    file: str
    #: Lines of the patch (the hunk body), used to see which names the
    #: patch references.
    added_lines: Tuple[str, ...] = ()
    #: The symbols (function / class / attribute names) the patch touches.
    symbols: Tuple[str, ...] = ()
    #: True when the patch *modified* this file rather than adding it.
    modified: bool = True

    def __post_init__(self) -> None:
        if not isinstance(self.file, str) or not self.file.strip():
            raise SweFailureModesError("patch file must be a non-empty string")
        if not isinstance(self.symbols, tuple):
            object.__setattr__(self, "symbols", tuple(self.symbols))
        if not isinstance(self.added_lines, tuple):
            object.__setattr__(self, "added_lines", tuple(self.added_lines))

    def touched_symbols(self) -> Tuple[str, ...]:
        """Every symbol name the patch refers to in this file."""
        return tuple(self.symbols)


@dataclass(frozen=True)
class FailureRecord:
    """A failed patch, described from both sides.

    The two sides are what make classification possible at all:

    * ``instruction`` -- what the task asked for;
    * ``changes`` -- what the patch actually did.

    A record with only one side cannot be classified into any of the four
    modes; the classifier says ``UNKNOWN`` for such a record rather than
    guessing.

    ``repo_symbols`` is the set of names that *exist* in the codebase.  A
    patch that references a name outside it is making an assumption about
    the existing system that nobody verified.  ``instruction_requirements``
    are the behaviours the instruction explicitly demanded; each carries
    the file that implements it, so the classifier can tell "the patch
    never touched the code for this requirement" from "the patch touched
    it and still failed".
    """

    #: The instruction text the patch was supposed to satisfy.
    instruction: str
    #: The behaviours the instruction explicitly required.
    instruction_requirements: Tuple[str, ...] = ()
    #: For each requirement, the file that implements it.
    requirement_files: Mapping[str, str] = field(default_factory=dict)
    #: What the patch did.
    changes: Tuple[PatchChange, ...] = ()
    #: The failing tests.
    failed_tests: Tuple[TestOutcome, ...] = ()
    #: Every test the caller ran (passed and failed) -- needed to see the
    #: symptom layer passing while a neighbouring layer fails.
    all_tests: Tuple[TestOutcome, ...] = ()
    #: Names that exist in the codebase, for the assumption check.
    repo_symbols: frozenset = frozenset()
    #: Names the patch refers to that are *not* in the codebase.
    unknown_references: Tuple[str, ...] = ()
    #: The layer the symptom was observed in, and the layer that owns the
    #: root cause (when the caller knows).  Both are file paths.
    symptom_layer: str = ""
    root_cause_layer: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.instruction, str):
            raise SweFailureModesError("instruction must be a string")
        if not isinstance(self.changes, tuple):
            object.__setattr__(self, "changes", tuple(self.changes))
        if not isinstance(self.failed_tests, tuple):
            object.__setattr__(self, "failed_tests", tuple(self.failed_tests))
        if not isinstance(self.all_tests, tuple):
            object.__setattr__(self, "all_tests", tuple(self.all_tests))
        if not isinstance(self.instruction_requirements, tuple):
            object.__setattr__(
                self, "instruction_requirements", tuple(self.instruction_requirements)
            )
        if not isinstance(self.unknown_references, tuple):
            object.__setattr__(self, "unknown_references", tuple(self.unknown_references))
        if not isinstance(self.repo_symbols, frozenset):
            object.__setattr__(self, "repo_symbols", frozenset(self.repo_symbols))
        if not isinstance(self.requirement_files, Mapping):
            raise SweFailureModesError("requirement_files must be a mapping")

    def changed_files(self) -> Tuple[str, ...]:
        """The files the patch touched."""
        return tuple(change.file for change in self.changes)

    def failing_tests(self) -> Tuple[TestOutcome, ...]:
        """The failed tests (from ``failed_tests`` if given, else from
        ``all_tests``)."""
        if self.failed_tests:
            return tuple(self.failed_tests)
        return tuple(t for t in self.all_tests if not t.passed)

    def passed_tests(self) -> Tuple[TestOutcome, ...]:
        """The tests that passed, from whichever field carries them."""
        if self.all_tests:
            return tuple(t for t in self.all_tests if t.passed)
        return tuple(t for t in self.failed_tests if t.passed)


# ---------------------------------------------------------------------------
# classification
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Evidence:
    """One piece of evidence backing a classification.

    The evidence names the thing (a test, a file, a symbol) *and* where it
    is (file, line), so a reader can go and look rather than trust the
    label.
    """

    kind: str
    detail: str
    file: str = ""
    line: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.kind, str) or not self.kind.strip():
            raise SweFailureModesError("evidence kind must be a non-empty string")
        if not isinstance(self.detail, str):
            raise SweFailureModesError("evidence detail must be a string")
        if not isinstance(self.line, int) or isinstance(self.line, bool):
            raise SweFailureModesError("evidence line must be an int")
        if self.line < 0:
            raise SweFailureModesError("evidence line must not be negative")

    def as_dict(self) -> Dict[str, object]:
        payload: Dict[str, object] = {"kind": self.kind, "detail": self.detail}
        if self.file:
            payload["file"] = self.file
        if self.line:
            payload["line"] = self.line
        return payload


@dataclass(frozen=True)
class Classification:
    """The verdict: a mode, the rule that fired, and the evidence.

    ``rule`` is never empty.  A classification with ``mode`` ``UNKNOWN``
    carries :data:`RULE_NONE` and says so in ``reason`` -- an explicit
    "this fit none of the four" rather than a forced bucket.
    """

    mode: FailureMode
    rule: str
    reason: str
    evidence: Tuple[Evidence, ...] = ()
    #: The failed tests the classification was reached from.
    failed_tests: Tuple[str, ...] = ()
    schema: str = SCHEMA_PIN

    def __post_init__(self) -> None:
        if not isinstance(self.mode, FailureMode):
            raise SweFailureModesError("mode must be a FailureMode")
        if not isinstance(self.rule, str) or not self.rule.strip():
            raise SweFailureModesError("rule must be a non-empty string")
        if not isinstance(self.reason, str):
            raise SweFailureModesError("reason must be a string")
        if not isinstance(self.evidence, tuple):
            object.__setattr__(self, "evidence", tuple(self.evidence))

    @property
    def is_unknown(self) -> bool:
        """True when the failure fit none of the four modes."""
        return self.mode is FailureMode.UNKNOWN

    def as_dict(self) -> Dict[str, object]:
        return {
            "mode": self.mode.value,
            "rule": self.rule,
            "reason": self.reason,
            "evidence": [e.as_dict() for e in self.evidence],
            "failed_tests": list(self.failed_tests),
            "schema": self.schema,
        }


# ---------------------------------------------------------------------------
# the rules
# ---------------------------------------------------------------------------
#
# The rules are checked in a fixed order and the first match wins.  The
# order matters, and it is deliberate:
#
#   1. WRONG_LAYER -- checked first.  A symptom-layer test that passes
#      while a neighbouring layer fails is the strongest signal there is
#      (the patch demonstrably did not fix the thing the caller asked
#      about), and it is invisible to the other three rules.
#   2. UNVERIFIED_ASSUMPTION -- a name the patch calls that does not
#      exist is a factual defect in the patch, whatever else is true.
#   3. REQUIREMENT_MISS -- a failing test maps onto a requirement the
#      instruction stated, and the patch never touched that code.
#   4. INTEGRATION_BREAK -- the failing test is elsewhere, and it was
#      green before the patch.
#
# The thresholds are pinned constants, not tunables: there is exactly one
# setting of each, and it is written down here.

#: A requirement is "met by the patch" when the patch touched a file the
#: requirement names.  File paths are compared by exact match.
REQUIREMENT_MATCH = "exact-file"

#: A failing test belongs to a file when the test's own file or its
#: target file matches the changed file.
TEST_MATCH = "file-or-target"

#: How many integration-break tests must be green-before-patch for the
#: rule to fire.  One is enough: one thing the patch broke is an
#: integration break.
MIN_BROKEN_BY_PATCH = 1


def _layer_of(test: TestOutcome) -> str:
    """The file layer a test exercises.

    ``target_file`` is the authoritative answer when the caller gave one;
    otherwise the test's own file is used.
    """
    return test.target_file or test.file


def _layer_matches(test: TestOutcome, layer: str) -> bool:
    """True when a test belongs to ``layer``.

    Two deterministic ways to say so:

    1. the test names the layer -- ``target_file`` (or the test's own
       file) equals it;
    2. the layer's file stem matches the test's stem, with the usual
       ``test_`` prefix stripped -- so ``store/store.py`` owns
       ``tests/test_store.py``.

    The stem rule is what lets a caller say "the symptom layer is
    ``ui/handler.py``" without also having to map every test file.
    """
    if not layer:
        return False
    if _layer_of(test) == layer:
        return True
    layer_stem = _file_stem(layer)
    if not layer_stem:
        return False
    for candidate in (test.target_file, test.file):
        if candidate and _file_stem(candidate) == layer_stem:
            return True
    name_stem = _file_stem(test.name)
    return bool(name_stem) and name_stem == layer_stem


def _file_stem(path: str) -> str:
    """The file's stem, with a leading ``test_`` removed."""
    base = path.rsplit("/", 1)[-1]
    if "." in base:
        base = base.rsplit(".", 1)[0]
    if base.startswith("test_"):
        base = base[len("test_"):]
    return base


def _requirement_files_for(record: FailureRecord, requirement: str) -> Tuple[str, ...]:
    """The files that implement ``requirement``, as the caller declared."""
    declared = record.requirement_files.get(requirement, "")
    if declared:
        return (declared,)
    return ()


def classify(record: FailureRecord) -> Classification:
    """Classify a failed patch into one of the four modes, or ``UNKNOWN``.

    The rules, in the order they are checked:

    ``symptom-only`` (``WRONG_LAYER``)
        The symptom layer's test passes and a neighbouring layer's test
        fails: the patch fixed the symptom, and the root cause is
        elsewhere.

    ``assumption-unverified`` (``UNVERIFIED_ASSUMPTION``)
        The patch refers to a name that does not exist in the codebase
        (either reported in ``unknown_references``, or a symbol the patch
        names that is absent from ``repo_symbols``).

    ``requirement-unmet`` (``REQUIREMENT_MISS``)
        A failing test maps onto a behaviour the instruction explicitly
        required, *and* the patch never touched the file implementing
        that behaviour.

    ``integration-off-target`` (``INTEGRATION_BREAK``)
        A failing test does not belong to any changed file, and it passed
        before the patch.

    ``no-rule-matched`` (``UNKNOWN``)
        Nothing above fired.  Reported explicitly, never forced into a
        bucket.
    """
    if not isinstance(record, FailureRecord):
        raise SweFailureModesError("classify requires a FailureRecord")

    failing = record.failing_tests()
    failed_names = tuple(t.name for t in failing)
    changed = record.changed_files()

    # -- 1. WRONG_LAYER ----------------------------------------------------
    wrong_layer = _classify_wrong_layer(record)
    if wrong_layer is not None:
        return wrong_layer

    # -- 2. UNVERIFIED_ASSUMPTION -----------------------------------------
    assumption = _classify_unverified_assumption(record)
    if assumption is not None:
        return assumption

    # -- 3. REQUIREMENT_MISS ------------------------------------------------
    requirement = _classify_requirement_miss(record)
    if requirement is not None:
        return requirement

    # -- 4. INTEGRATION_BREAK ----------------------------------------------
    integration = _classify_integration_break(record)
    if integration is not None:
        return integration

    # -- 5. UNKNOWN ---------------------------------------------------------
    return Classification(
        mode=FailureMode.UNKNOWN,
        rule=RULE_NONE,
        reason=(
            "no rule matched: the failure has no unmet requirement, no "
            "off-target breaking test, no unknown reference, and no "
            "symptom-only pattern"
        ),
        evidence=(),
        failed_tests=failed_names,
    )


# -- rule helpers ----------------------------------------------------------


def _classify_wrong_layer(record: FailureRecord) -> Optional[Classification]:
    """``symptom-only``: symptom layer green, neighbouring layer red.

    Fires when the record declares a symptom layer and a root-cause layer
    that differ, the symptom layer's test passes, and a test in the
    root-cause layer fails.
    """
    if not record.symptom_layer or not record.root_cause_layer:
        return None
    if record.symptom_layer == record.root_cause_layer:
        return None

    symptom_tests = [
        t for t in record.all_tests
        if _layer_matches(t, record.symptom_layer)
    ]
    root_tests = [
        t for t in record.all_tests
        if _layer_matches(t, record.root_cause_layer)
    ]
    symptom_green = [t for t in symptom_tests if t.passed]
    root_red = [t for t in root_tests if not t.passed]
    if not symptom_green or not root_red:
        return None

    evidence = [
        Evidence(
            kind="symptom-test-passed",
            detail=t.name,
            file=t.file or record.symptom_layer,
            line=t.line,
        )
        for t in symptom_green
    ]
    evidence.extend(
        Evidence(
            kind="root-cause-test-failed",
            detail=t.name,
            file=t.file or record.root_cause_layer,
            line=t.line,
        )
        for t in root_red
    )
    evidence.append(
        Evidence(
            kind="layer-split",
            detail=(
                f"symptom layer {record.symptom_layer!r} passes while root "
                f"cause layer {record.root_cause_layer!r} fails"
            ),
            file=record.root_cause_layer,
        )
    )
    return Classification(
        mode=FailureMode.WRONG_LAYER,
        rule=RULE_SYMPTOM_ONLY,
        reason=(
            f"symptom layer {record.symptom_layer!r} is green and the "
            f"neighbouring layer {record.root_cause_layer!r} is red: the "
            "patch fixed the symptom at the wrong layer"
        ),
        evidence=tuple(evidence),
        failed_tests=tuple(t.name for t in root_red),
    )


def _classify_unverified_assumption(
    record: FailureRecord,
) -> Optional[Classification]:
    """``assumption-unverified``: the patch calls a name that is not there.

    Two ways to know a name is absent: the caller reported it in
    ``unknown_references``, or the patch names a symbol that is not in
    ``repo_symbols``.  The second only fires when ``repo_symbols`` is a
    non-empty set -- an empty set means "the caller did not tell us", not
    "nothing exists".
    """
    references: List[Tuple[str, str]] = []
    seen = set()
    for name in record.unknown_references:
        if name and name not in seen:
            seen.add(name)
            references.append((name, "reported absent by the caller"))

    if record.repo_symbols:
        for change in record.changes:
            for symbol in change.touched_symbols():
                if symbol and symbol not in record.repo_symbols and symbol not in seen:
                    seen.add(symbol)
                    references.append(
                        (symbol, f"not defined in {change.file!r}")
                    )

    if not references:
        return None

    evidence = []
    for name, why in references:
        evidence.append(
            Evidence(
                kind="unknown-reference",
                detail=f"{name} -- {why}",
                file="",
                line=0,
            )
        )
    return Classification(
        mode=FailureMode.UNVERIFIED_ASSUMPTION,
        rule=RULE_ASSUMPTION_UNVERIFIED,
        reason=(
            "the patch refers to names the codebase does not define: "
            + ", ".join(name for name, _ in references)
        ),
        evidence=tuple(evidence),
        failed_tests=tuple(t.name for t in record.failing_tests()),
    )


def _classify_requirement_miss(
    record: FailureRecord,
) -> Optional[Classification]:
    """``requirement-unmet``: a demanded behaviour failed, untouched.

    Fires when a failing test names (or is declared for) a requirement the
    instruction stated, and the patch touched none of the files that
    implement that requirement.
    """
    if not record.instruction_requirements:
        return None

    changed = set(record.changed_files())
    matched: List[Tuple[str, TestOutcome, Tuple[str, ...]]] = []
    for requirement in record.instruction_requirements:
        impl_files = _requirement_files_for(record, requirement)
        if not impl_files:
            continue
        if changed.intersection(impl_files):
            # The patch touched the code for this requirement; a missing
            # requirement cannot be claimed on this evidence.
            continue
        for test in record.failing_tests():
            if _test_reflects_requirement(test, requirement, impl_files):
                matched.append((requirement, test, impl_files))
                break

    if not matched:
        return None

    evidence = []
    for requirement, test, impl_files in matched:
        evidence.append(
            Evidence(
                kind="requirement-not-implemented",
                detail=(
                    f"{requirement!r} was required by the instruction; the "
                    f"patch touched none of {', '.join(impl_files)}"
                ),
                file=impl_files[0],
                line=0,
            )
        )
        evidence.append(
            Evidence(
                kind="failing-test",
                detail=test.name,
                file=test.file,
                line=test.line,
            )
        )
    return Classification(
        mode=FailureMode.REQUIREMENT_MISS,
        rule=RULE_REQUIREMENT_UNMET,
        reason=(
            "the failing test covers behaviour the instruction explicitly "
            "required, and the patch never touched the code implementing it"
        ),
        evidence=tuple(evidence),
        failed_tests=tuple(t.name for _, t, _ in matched),
    )


def _test_reflects_requirement(
    test: TestOutcome, requirement: str, impl_files: Tuple[str, ...] = ()
) -> bool:
    """True when a failing test is about ``requirement``.

    Three deterministic ways a test can be about a requirement, in order:

    1. the requirement is named in the test name;
    2. the test exercises one of the files that implement the requirement
       (``target_file``);
    3. every content word of the requirement prefixes a word of the test
       name -- so "reject an expired token" is matched by
       "test_rejects_expired_token".
    """
    if requirement and requirement in test.name:
        return True
    if impl_files and _layer_of(test) in impl_files:
        return True
    return _requirement_name_matches(requirement, test.name)


#: Words too common to carry meaning when matching a requirement to a test.
_STOP_WORDS = frozenset({
    "a", "an", "and", "the", "to", "of", "in", "on", "for", "with", "is",
    "are", "be", "by", "as", "at", "it", "its", "that", "this", "must",
    "should", "shall", "when", "if", "not", "no",
})


def _requirement_name_matches(requirement: str, test_name: str) -> bool:
    """True when the requirement's content words all prefix test-name words.

    The match is one-directional on purpose: the requirement word may be
    shorter ("reject" vs "rejects"), because the requirement is prose
    and the test name is an identifier.
    """
    req_words = [
        w for w in _tokenize(requirement)
        if w not in _STOP_WORDS and len(w) >= 3
    ]
    if not req_words:
        return False
    test_words = _tokenize(test_name)
    for req_word in req_words:
        if not any(tw.startswith(req_word) for tw in test_words):
            return False
    return True


def _tokenize(text: str) -> Tuple[str, ...]:
    """Split text into lowercase word tokens."""
    tokens: List[str] = []
    current: List[str] = []
    for char in text:
        if char.isalnum():
            current.append(char.lower())
        elif current:
            tokens.append("".join(current))
            current = []
    if current:
        tokens.append("".join(current))
    return tuple(tokens)


def _classify_integration_break(
    record: FailureRecord,
) -> Optional[Classification]:
    """``integration-off-target``: the patch broke something elsewhere.

    Fires when a failing test belongs to none of the changed files *and*
    it passed before the patch.  Both halves are needed: "elsewhere"
    without "was green" is a pre-existing failure, not a break.
    """
    changed = record.changed_files()
    broken: List[Tuple[TestOutcome, str]] = []
    for test in record.failing_tests():
        if any(_layer_matches(test, f) for f in changed):
            continue
        if test.passed_before_patch is not True:
            continue
        broken.append((test, "in another file than the patch"))

    if len(broken) < MIN_BROKEN_BY_PATCH:
        return None

    evidence = []
    for test, why in broken:
        evidence.append(
            Evidence(
                kind="broken-by-patch",
                detail=f"{test.name} -- {why}",
                file=test.file,
                line=test.line,
            )
        )
    for changed_file in changed:
        evidence.append(
            Evidence(
                kind="patch-changed-file",
                detail=changed_file,
                file=changed_file,
                line=0,
            )
        )
    return Classification(
        mode=FailureMode.INTEGRATION_BREAK,
        rule=RULE_INTEGRATION_OFF_TARGET,
        reason=(
            f"{len(broken)} test(s) outside the changed files were green "
            "before the patch and are red after it"
        ),
        evidence=tuple(evidence),
        failed_tests=tuple(t.name for t, _ in broken),
    )


# ---------------------------------------------------------------------------
# routing
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CheckInput:
    """One input to a check: a named value the check reads."""

    name: str
    value: str
    #: What kind of thing this is (``requirement``, ``test``, ``file``,
    #: ``symbol``, ``layer``), so a reader can scan the list.
    kind: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name.strip():
            raise SweFailureModesError("check input name must be a non-empty string")
        if not isinstance(self.value, str):
            raise SweFailureModesError("check input value must be a string")

    def as_dict(self) -> Dict[str, object]:
        payload: Dict[str, object] = {"name": self.name, "value": self.value}
        if self.kind:
            payload["kind"] = self.kind
        return payload


@dataclass(frozen=True)
class CheckItem:
    """One check, in the fixed structure: name + inputs + criterion.

    Every check in every route has these three fields.  The criterion is
    a decision standard (what must hold for the check to pass), never a
    free-text instruction to a human.
    """

    #: The check's name -- stable across runs, so results can be compared.
    name: str
    #: The inputs the check reads.
    inputs: Tuple[CheckInput, ...] = ()
    #: The decision standard: what must be true for this check to pass.
    criterion: str = ""
    #: What kind of check this is (``diff-readback``, ``regression``,
    #: ``assumption-verification``, ``layer-crossing``).
    kind: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name.strip():
            raise SweFailureModesError("check name must be a non-empty string")
        if not isinstance(self.inputs, tuple):
            object.__setattr__(self, "inputs", tuple(self.inputs))
        if not isinstance(self.criterion, str) or not self.criterion.strip():
            raise SweFailureModesError("check criterion must be a non-empty string")

    def as_dict(self) -> Dict[str, object]:
        return {
            "name": self.name,
            "kind": self.kind,
            "inputs": [i.as_dict() for i in self.inputs],
            "criterion": self.criterion,
        }


@dataclass(frozen=True)
class CheckList:
    """The routed checks for one classification.

    ``route`` is the name of the check the failure is sent to; ``checks``
    holds the fixed-structure items.  The shape of a checklist is the same
    for every mode -- only its contents differ.
    """

    mode: FailureMode
    #: The single check this mode routes to.
    route: str
    checks: Tuple[CheckItem, ...] = ()
    schema: str = SCHEMA_PIN

    def __post_init__(self) -> None:
        if not isinstance(self.mode, FailureMode):
            raise SweFailureModesError("mode must be a FailureMode")
        if not isinstance(self.route, str) or not self.route.strip():
            raise SweFailureModesError("route must be a non-empty string")
        if not isinstance(self.checks, tuple):
            object.__setattr__(self, "checks", tuple(self.checks))

    def as_dict(self) -> Dict[str, object]:
        return {
            "mode": self.mode.value,
            "route": self.route,
            "checks": [c.as_dict() for c in self.checks],
            "schema": self.schema,
        }


#: The route each mode is sent to.  Pinned; one route per mode.
ROUTE_REQUIREMENT_READBACK = "instruction-diff-readback"
ROUTE_REGRESSION_SUITE = "regression-suite"
ROUTE_ASSUMPTION_VERIFICATION = "assumption-verification"
ROUTE_LAYER_CROSSING = "layer-crossing-check"


def route(
    classification: Classification,
    record: Optional[FailureRecord] = None,
) -> CheckList:
    """Route a classification to the check that can catch it.

    The routes, and what each one is for:

    ``REQUIREMENT_MISS`` -> ``instruction-diff-readback``
        Read the diff against the instruction, requirement by
        requirement: the checklist lists what the instruction demanded
        and what the patch covered, and the criterion is that every
        demanded behaviour appears in the patch.

    ``INTEGRATION_BREAK`` -> ``regression-suite``
        Run the regression / integration suite: the checklist lists the
        tests the patch broke and the files it changed, and the criterion
        is that the broken tests pass again with the patch reverted or
        fixed.

    ``UNVERIFIED_ASSUMPTION`` -> ``assumption-verification``
        Verify each assumption: the checklist lists every external name
        the patch refers to and whether it exists, and the criterion is
        that each name resolves to a definition in the codebase.

    ``WRONG_LAYER`` -> ``layer-crossing-check``
        Check across layers: the checklist lists the symptom layer and
        the root-cause layer, and the criterion is that the root-cause
        layer is repaired, not only the symptom layer.

    ``UNKNOWN`` -> ``unknown-triage``
        Nothing to route to; the checklist lists the classification's own
        evidence so a human can decide.  The module never invents a
        route for an unclassified failure.
    """
    if not isinstance(classification, Classification):
        raise SweFailureModesError("route requires a Classification")

    if classification.mode is FailureMode.REQUIREMENT_MISS:
        return _route_requirement_miss(classification, record)
    if classification.mode is FailureMode.INTEGRATION_BREAK:
        return _route_integration_break(classification, record)
    if classification.mode is FailureMode.UNVERIFIED_ASSUMPTION:
        return _route_unverified_assumption(classification, record)
    if classification.mode is FailureMode.WRONG_LAYER:
        return _route_wrong_layer(classification, record)
    return _route_unknown(classification)


def _route_requirement_miss(
    classification: Classification, record: Optional[FailureRecord]
) -> CheckList:
    requirements = list(record.instruction_requirements) if record else []
    if not requirements:
        requirements = [
            e.detail.split(" was required by the instruction")[0]
            for e in classification.evidence
            if e.kind == "requirement-not-implemented"
        ]
    changed = list(record.changed_files()) if record else []
    checks: List[CheckItem] = []
    for requirement in requirements:
        impl = record.requirement_files.get(requirement, "") if record else ""
        covered = bool(impl and impl in changed)
        inputs = (
            CheckInput(name="required-behaviour", value=requirement, kind="requirement"),
            CheckInput(
                name="implementation-file",
                value=impl or "(not declared)",
                kind="file",
            ),
            CheckInput(
                name="patch-coverage",
                value=("covered by patch" if covered else "NOT covered by patch"),
                kind="coverage",
            ),
            CheckInput(
                name="patch-changed-files",
                value=", ".join(changed) if changed else "(none)",
                kind="file",
            ),
        )
        checks.append(
            CheckItem(
                name="requirement-diff-readback",
                kind="diff-readback",
                inputs=inputs,
                criterion=(
                    "the patch implements the required behaviour "
                    f"{requirement!r}: its diff contains a change to "
                    f"{impl or 'the implementing file'} that produces the "
                    "required behaviour, and the behaviour's test passes"
                ),
            )
        )
    if not checks:
        checks.append(
            CheckItem(
                name="requirement-diff-readback",
                kind="diff-readback",
                inputs=(
                    CheckInput(
                        name="required-behaviour",
                        value="(none recorded)",
                        kind="requirement",
                    ),
                ),
                criterion=(
                    "every behaviour the instruction demanded appears in "
                    "the patch diff, and its test passes"
                ),
            )
        )
    return CheckList(
        mode=FailureMode.REQUIREMENT_MISS,
        route=ROUTE_REQUIREMENT_READBACK,
        checks=tuple(checks),
    )


def _route_integration_break(
    classification: Classification, record: Optional[FailureRecord]
) -> CheckList:
    broken = [
        t for t in (record.failing_tests() if record else ())
        if t.name in classification.failed_tests
    ]
    if not broken:
        broken = [
            TestOutcome(name=name, passed=False)
            for name in classification.failed_tests
        ]
    changed = list(record.changed_files()) if record else []
    checks: List[CheckItem] = []
    for test in broken:
        inputs = (
            CheckInput(name="broken-test", value=test.name, kind="test"),
            CheckInput(
                name="test-location",
                value=f"{test.file}:{test.line}" if test.file else test.name,
                kind="location",
            ),
            CheckInput(
                name="patch-changed-files",
                value=", ".join(changed) if changed else "(none)",
                kind="file",
            ),
        )
        checks.append(
            CheckItem(
                name="regression-suite",
                kind="regression",
                inputs=inputs,
                criterion=(
                    f"the regression/integration suite passes with the "
                    f"patch's changes to {', '.join(changed) if changed else 'the changed files'} "
                    f"corrected: {test.name} is green again, and no other "
                    "test outside the changed files regressed"
                ),
            )
        )
    if not checks:
        checks.append(
            CheckItem(
                name="regression-suite",
                kind="regression",
                inputs=(
                    CheckInput(
                        name="patch-changed-files",
                        value=", ".join(changed) if changed else "(none)",
                        kind="file",
                    ),
                ),
                criterion=(
                    "the regression/integration suite passes with the patch's "
                    "changes corrected, and no test outside the changed "
                    "files regressed"
                ),
            )
        )
    return CheckList(
        mode=FailureMode.INTEGRATION_BREAK,
        route=ROUTE_REGRESSION_SUITE,
        checks=tuple(checks),
    )


def _route_unverified_assumption(
    classification: Classification, record: Optional[FailureRecord]
) -> CheckList:
    names: List[Tuple[str, str]] = []
    if record:
        for name in record.unknown_references:
            names.append((name, "not defined in the codebase"))
        if record.repo_symbols:
            for change in record.changes:
                for symbol in change.touched_symbols():
                    if symbol not in record.repo_symbols:
                        names.append((symbol, f"not defined in {change.file}"))
    if not names:
        for evidence in classification.evidence:
            if evidence.kind == "unknown-reference":
                detail = evidence.detail
                name = detail.split(" -- ")[0]
                why = detail.split(" -- ", 1)[1] if " -- " in detail else "absent"
                names.append((name, why))
    checks: List[CheckItem] = []
    for name, why in names:
        inputs = (
            CheckInput(name="referenced-name", value=name, kind="symbol"),
            CheckInput(name="existence-evidence", value=why, kind="evidence"),
        )
        checks.append(
            CheckItem(
                name="assumption-verification",
                kind="assumption-verification",
                inputs=inputs,
                criterion=(
                    f"{name!r} resolves to a definition in the codebase, and "
                    "the patch's use of it matches that definition's "
                    "signature and semantics"
                ),
            )
        )
    if not checks:
        checks.append(
            CheckItem(
                name="assumption-verification",
                kind="assumption-verification",
                inputs=(
                    CheckInput(
                        name="referenced-name", value="(none recorded)", kind="symbol"
                    ),
                ),
                criterion=(
                    "every name the patch refers to resolves to a definition "
                    "in the codebase, and the patch's use of it matches that "
                    "definition"
                ),
            )
        )
    return CheckList(
        mode=FailureMode.UNVERIFIED_ASSUMPTION,
        route=ROUTE_ASSUMPTION_VERIFICATION,
        checks=tuple(checks),
    )


def _route_wrong_layer(
    classification: Classification, record: Optional[FailureRecord]
) -> CheckList:
    symptom = record.symptom_layer if record else ""
    root = record.root_cause_layer if record else ""
    if not symptom or not root:
        for evidence in classification.evidence:
            if evidence.kind == "layer-split" and "--" in evidence.detail:
                symptom = evidence.file
                root = evidence.detail.split("root cause layer ")[-1].split(" ")[0]
                root = root.strip("'\"")
    checks = (
        CheckItem(
            name="layer-crossing-check",
            kind="layer-crossing",
            inputs=(
                CheckInput(name="symptom-layer", value=symptom or "(unknown)", kind="layer"),
                CheckInput(name="root-cause-layer", value=root or "(unknown)", kind="layer"),
                CheckInput(
                    name="symptom-test-status",
                    value="passing (the symptom was suppressed)",
                    kind="status",
                ),
                CheckInput(
                    name="root-cause-test-status",
                    value="failing (the cause is still live)",
                    kind="status",
                ),
            ),
            criterion=(
                f"the root-cause layer {root or '(unknown)'} is repaired -- "
                "its failing test passes -- rather than only the symptom "
                f"layer {symptom or '(unknown)'}; the symptom layer's test "
                "stays green"
            ),
        ),
    )
    return CheckList(
        mode=FailureMode.WRONG_LAYER,
        route=ROUTE_LAYER_CROSSING,
        checks=checks,
    )


def _route_unknown(classification: Classification) -> CheckList:
    checks = (
        CheckItem(
            name="unknown-triage",
            kind="triage",
            inputs=(
                CheckInput(
                    name="failed-tests",
                    value=", ".join(classification.failed_tests) or "(none)",
                    kind="test",
                ),
                CheckInput(
                    name="classification-evidence",
                    value=(
                        "; ".join(e.detail for e in classification.evidence)
                        or "(no evidence recorded)"
                    ),
                    kind="evidence",
                ),
            ),
            criterion=(
                "the failure is triaged to one of the four modes (or stays "
                "UNKNOWN by decision) with the evidence that supports the "
                "choice recorded"
            ),
        ),
    )
    return CheckList(
        mode=FailureMode.UNKNOWN,
        route="unknown-triage",
        checks=checks,
    )


# ---------------------------------------------------------------------------
# cost accounting (Northstar extension)
# ---------------------------------------------------------------------------
#
# The source's cost shape: Fable 5.1 at 38.8% resolution costs $6.96 per
# rollout and "~$17.94" per resolved task -- "its true cost per completed
# fix (~$17.94) runs more than double its per-attempt price".  A failed
# attempt is not a delivery, so the module books cost per *verified
# delivery*: total cost divided by the number of verified deliveries.
#
# The module does no pricing and no estimation.  The caller supplies the
# costs and the counts; the module does arithmetic and nothing else.

#: The modes cost is apportioned across, in the pinned order.
COST_MODES: Tuple[FailureMode, ...] = CLASSIFIABLE_MODES + (FailureMode.UNKNOWN,)


@dataclass(frozen=True)
class DeliveryCost:
    """Cost booked per verified delivery.

    ``cost_per_delivery`` is ``total_cost / verified_deliveries``.  When
    there are no verified deliveries the value is ``None`` -- "no
    evidence", not "free".
    """

    total_cost: float
    verified_deliveries: int
    #: Total runs (rollouts) the cost was spent on.  Reported for
    #: comparison; it is never the divisor.
    total_runs: int = 0
    #: Cost per run, as reported by the caller.
    cost_per_run: Optional[float] = None
    schema: str = SCHEMA_PIN

    def __post_init__(self) -> None:
        if not isinstance(self.total_cost, (int, float)) or isinstance(
            self.total_cost, bool
        ):
            raise SweFailureModesError("total_cost must be a number")
        if not isinstance(self.verified_deliveries, int) or isinstance(
            self.verified_deliveries, bool
        ):
            raise SweFailureModesError("verified_deliveries must be an int")
        if self.verified_deliveries < 0:
            raise SweFailureModesError("verified_deliveries must not be negative")
        if not isinstance(self.total_runs, int) or isinstance(self.total_runs, bool):
            raise SweFailureModesError("total_runs must be an int")
        if self.total_runs < 0:
            raise SweFailureModesError("total_runs must not be negative")

    @property
    def cost_per_delivery(self) -> Optional[float]:
        """Total cost divided by verified deliveries (``None`` if none)."""
        if self.verified_deliveries <= 0:
            return None
        return self.total_cost / self.verified_deliveries

    def as_dict(self) -> Dict[str, object]:
        return {
            "total_cost": self.total_cost,
            "verified_deliveries": self.verified_deliveries,
            "total_runs": self.total_runs,
            "cost_per_delivery": self.cost_per_delivery,
            "cost_per_run": self.cost_per_run,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class ModeCost:
    """What one failure mode cost, and how many deliveries it produced."""

    mode: FailureMode
    #: Total cost attributed to this mode.
    cost: float
    #: Verified deliveries produced by this mode.
    resolved: int
    #: Runs spent on this mode.
    runs: int = 0
    #: Cost per verified delivery for this mode.
    cost_per_delivery: Optional[float] = None

    def __post_init__(self) -> None:
        if not isinstance(self.mode, FailureMode):
            raise SweFailureModesError("mode must be a FailureMode")
        if not isinstance(self.cost, (int, float)) or isinstance(self.cost, bool):
            raise SweFailureModesError("cost must be a number")
        if not isinstance(self.resolved, int) or isinstance(self.resolved, bool):
            raise SweFailureModesError("resolved must be an int")
        if self.resolved < 0:
            raise SweFailureModesError("resolved must not be negative")

    def as_dict(self) -> Dict[str, object]:
        return {
            "mode": self.mode.value,
            "cost": self.cost,
            "resolved": self.resolved,
            "runs": self.runs,
            "cost_per_delivery": self.cost_per_delivery,
        }


@dataclass(frozen=True)
class CostReport:
    """The whole cost picture: per delivery, and per failure mode."""

    delivery: DeliveryCost
    by_mode: Tuple[ModeCost, ...] = ()
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, object]:
        return {
            "delivery": self.delivery.as_dict(),
            "by_mode": [m.as_dict() for m in self.by_mode],
            "schema": self.schema,
        }


def cost_per_delivery(
    total_cost: float,
    verified_deliveries: int,
    *,
    total_runs: int = 0,
    cost_per_run: Optional[float] = None,
) -> DeliveryCost:
    """Book cost per verified delivery -- not per run.

    ``total_cost`` is what the caller spent; ``verified_deliveries`` is
    how many deliveries were actually verified.  The divisor is the
    verified deliveries, because a failed attempt delivers nothing.  This
    is the source's cost shape applied to a single slice's ledger.

    The function does no pricing: every number in the result comes from
    the caller.
    """
    return DeliveryCost(
        total_cost=total_cost,
        verified_deliveries=verified_deliveries,
        total_runs=total_runs,
        cost_per_run=cost_per_run,
    )


def apportion_cost_by_mode(
    mode_costs: Mapping[FailureMode, float],
    mode_resolved: Mapping[FailureMode, int],
    *,
    mode_runs: Optional[Mapping[FailureMode, int]] = None,
) -> Tuple[ModeCost, ...]:
    """Apportion cost across failure modes.

    Every mode in the pinned :data:`COST_MODES` order appears in the
    result, so two reports can be compared line by line.  A mode the
    caller did not mention appears with zero cost and zero resolutions --
    it is not dropped, because "this mode never fired" is information.
    """
    runs_map = mode_runs or {}
    result: List[ModeCost] = []
    for mode in COST_MODES:
        cost = float(mode_costs.get(mode, 0.0))
        resolved = int(mode_resolved.get(mode, 0))
        runs = int(runs_map.get(mode, 0))
        per_delivery = (cost / resolved) if resolved > 0 else None
        result.append(
            ModeCost(
                mode=mode,
                cost=cost,
                resolved=resolved,
                runs=runs,
                cost_per_delivery=per_delivery,
            )
        )
    return tuple(result)


def cost_report(
    total_cost: float,
    verified_deliveries: int,
    mode_costs: Mapping[FailureMode, float],
    mode_resolved: Mapping[FailureMode, int],
    *,
    total_runs: int = 0,
    cost_per_run: Optional[float] = None,
    mode_runs: Optional[Mapping[FailureMode, int]] = None,
) -> CostReport:
    """The full cost picture in one object."""
    return CostReport(
        delivery=cost_per_delivery(
            total_cost,
            verified_deliveries,
            total_runs=total_runs,
            cost_per_run=cost_per_run,
        ),
        by_mode=apportion_cost_by_mode(
            mode_costs, mode_resolved, mode_runs=mode_runs
        ),
    )


def main() -> None:
    """Self-check: classify one record of each mode and print the routes."""
    records = {
        FailureMode.REQUIREMENT_MISS: FailureRecord(
            instruction="The API must reject an expired token.",
            instruction_requirements=("reject an expired token",),
            requirement_files={"reject an expired token": "api/auth.py"},
            changes=(PatchChange(file="api/other.py", symbols=("other_fn",)),),
            failed_tests=(TestOutcome(name="test_rejects_expired_token",
                                      passed=False, file="tests/test_auth.py",
                                      line=42),),
        ),
        FailureMode.INTEGRATION_BREAK: FailureRecord(
            instruction="Make the parser stricter.",
            changes=(PatchChange(file="parser/core.py"),),
            failed_tests=(TestOutcome(name="test_legacy_format", passed=False,
                                      file="tests/test_legacy.py", line=10,
                                      passed_before_patch=True),),
        ),
        FailureMode.UNVERIFIED_ASSUMPTION: FailureRecord(
            instruction="Fix the retry.",
            changes=(PatchChange(file="net/retry.py", symbols=("retry_with_backoff",)),),
            repo_symbols=frozenset({"retry_once"}),
            failed_tests=(TestOutcome(name="test_retry", passed=False),),
        ),
        FailureMode.WRONG_LAYER: FailureRecord(
            instruction="Fix the crash.",
            changes=(PatchChange(file="ui/handler.py"),),
            all_tests=(
                TestOutcome(name="test_handler", passed=True, file="tests/test_handler.py"),
                TestOutcome(name="test_store", passed=False, file="tests/test_store.py"),
            ),
            symptom_layer="ui/handler.py",
            root_cause_layer="store/store.py",
        ),
    }
    for mode, record in records.items():
        result = classify(record)
        checklist = route(result, record)
        print(f"{mode.value}: classified as {result.mode.value} "
              f"(rule {result.rule}); route {checklist.route}")
    unknown = classify(FailureRecord(instruction="Do something."))
    print(f"unknown: classified as {unknown.mode.value} (rule {unknown.rule})")


if __name__ == "__main__":  # pragma: no cover
    main()
