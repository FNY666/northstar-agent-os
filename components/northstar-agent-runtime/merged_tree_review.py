"""Merged-tree review: find cross-slice conflicts in a merged tree.

The B173 batch landed 64 slices, each with its own module, its own test and
its own design doc.  Every slice was accepted against its own tree.  No
slice was ever accepted against the tree that carries all 64.  The gap
``b173-lessons.md`` records is:

    Merged-tree adversarial review: two slices each pass, merged they break
    (semantic conflict) is an acceptance blind spot.

This module is the **mechanically checkable half** of that review.  It
implements four rules over a tree of Python modules and Markdown design
docs:

Rule 1 -- dangling symbols
    A design doc says ``module.function``.  Does ``module`` still define
    ``function`` *now*?  Doc drift (slice A's doc names a symbol slice B
    later renamed) is invisible to slice B's own tests, because B only ever
    tested B.

Rule 2 -- same name, different meaning
    Two modules define a public function with the same name.  Same
    signature means "probably a duplicate implementation"; different
    signature means "probably two different things that happen to share a
    name" -- a caller that means one of them and writes the other gets a
    silent behaviour change instead of an error.

Rule 3 -- vocabulary overlap
    Inside a semantic group (budget / evidence / compaction / refusal),
    two modules may mint the same verdict word ("pass", "match", "mirror")
    for different things, or different words for the same thing.  The
    caller has to know which vocabulary to write.

Rule 4 -- record shapes
    Two modules in a group produce records that cannot be matched to each
    other -- one records ``transcript_hash``, the other does not have a
    field for it, so there is no join key.

**Read-only by construction.**  Every function here takes paths and returns
data.  Nothing in this module writes, deletes, or mutates a file, and
nothing imports the modules it inspects: parsing uses :mod:`ast` only,
because importing a runtime module has side effects and would be a
side-effecting read of the tree under review.

House style: frozen dataclasses, no wall clock, fail-closed validation,
stdlib only.
"""

from __future__ import annotations

import ast
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

__all__ = [
    "GROUP_MODULES",
    "DanglingReference",
    "ModuleFacts",
    "RecordShapeConflict",
    "SameNameGroup",
    "VocabularyOverlap",
    "analyze",
    "collect_module_facts",
    "find_same_name_symbols",
    "read_module_facts",
    "record_shape_conflicts",
    "scan_dangling_symbols",
    "vocabulary_overlap",
]


#: The four semantic-adjacency groups of the B173 batch.  These are the
#: groups where two slices can each pass their own acceptance and still
#: disagree once both are on the tree.
GROUP_MODULES: Mapping[str, Tuple[str, ...]] = {
    "budget": (
        "state_budget",
        "context_budget",
        "step_reliability_budget",
    ),
    "evidence": (
        "verifiability_tier",
        "scorer_disagreement",
        "evidence_independence",
    ),
    "compaction": (
        "event_condenser",
        "reversible_compaction",
        "scope_verbatim_compaction",
    ),
    "refusal": (
        "refusal_row",
        "scope_qualifier",
        "refusal_monitor",
        "refusal_hold",
    ),
}


#: Module-level constants whose name suggests they carry a verdict, an
#: outcome, a reason or a state.  Their string values form the "verdict
#: vocabulary" of a module.
_VERDICT_CONST_RE = re.compile(
    r"(VERDICT|OUTCOME|STATUS|STATE|REASON|DECISION|TIER|MODE|RESULT|"
    r"LEVEL|KIND|CATEGORY|CLASS|OUTCOME_KIND|ACTION)",
    re.IGNORECASE,
)

#: A code span in Markdown, single backticks, no newline inside.
_CODE_SPAN_RE = re.compile(r"`([^`\n]+)`")

#: A dotted python reference inside a code span: ``a.b`` or ``a.b.c``.
_DOTTED_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*(?:\.py)?)((?:\.[A-Za-z_][A-Za-z0-9_]*)+)")

#: An identifier-looking word.
_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

#: The verdict words these slices actually write into their records.  The
#: set is deliberately closed: a word outside it is not a verdict word in
#: this tree, so it cannot be a vocabulary overlap.
VERDICT_WORDS: frozenset = frozenset({
    "allow", "allowed", "approve", "approved",
    "block", "blocked", "clear", "contested",
    "denied", "deny", "expired", "fail", "failed",
    "fallback", "independent", "match", "mismatch", "mirror",
    "pass", "passed", "refuse", "refused", "rejected", "reject",
    "revoked", "skipped", "unknown", "undecidable",
})


def _base_name(node: ast.expr) -> str:
    """The last component of a base class expression (``a.b.C`` -> ``C``)."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


def _literal(node: ast.expr) -> Optional[str]:
    """The string value of a literal, or None.  Only constants, no eval."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _string_sequence(node: ast.expr) -> Tuple[str, ...]:
    """The string values of a literal tuple/list of strings, or of a
    single string constant."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return (node.value,)
    if not isinstance(node, (ast.Tuple, ast.List)):
        return ()
    out: List[str] = []
    for element in node.elts:
        value = _literal(element)
        if value is not None:
            out.append(value)
    return tuple(out)


def _class_fields(node: ast.ClassDef) -> Tuple[str, ...]:
    """The record fields of a class.

    Annotated class attributes are authoritative.  When a class has none,
    fall back to the keys of the dict literal returned by its ``as_dict``
    method -- many record types in this tree publish their shape that way
    instead of using ``dataclasses``.
    """
    fields: List[str] = []
    for statement in node.body:
        if isinstance(statement, ast.AnnAssign) and isinstance(statement.target, ast.Name):
            if statement.target.id not in fields:
                fields.append(statement.target.id)
    if fields:
        return tuple(fields)
    for statement in node.body:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)) and statement.name == "as_dict":
            for inner in ast.walk(statement):
                if isinstance(inner, ast.Return) and isinstance(inner.value, ast.Dict):
                    for key in inner.value.keys:
                        value = _literal(key) if key is not None else None
                        if value is not None and value not in fields:
                            fields.append(value)
    return tuple(fields)


def _class_members(node: ast.ClassDef) -> Tuple[str, ...]:
    """Every public member name of a class (methods and annotated fields)."""
    members: List[str] = []
    for statement in node.body:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if not statement.name.startswith("_"):
                members.append(statement.name)
        elif isinstance(statement, ast.AnnAssign) and isinstance(statement.target, ast.Name):
            if not statement.target.id.startswith("_"):
                members.append(statement.target.id)
    return tuple(members)


def _is_error_class(name: str, bases: Tuple[str, ...]) -> bool:
    """Is this class an error type?  Name-based or base-based."""
    if name.endswith(("Error", "Exception")):
        return True
    for base in bases:
        if base.endswith(("Error", "Exception")):
            return True
    return False


@dataclass(frozen=True)
class ModuleFacts:
    """Everything the four rules need to know about one module.

    Collected with :mod:`ast` only.  The module is never imported, so the
    facts describe the file on disk and not whatever that file does when it
    is loaded.
    """

    module: str
    path: str
    functions: Mapping[str, Tuple[str, ...]] = field(default_factory=dict)
    classes: Mapping[str, Tuple[str, ...]] = field(default_factory=dict)
    class_fields: Mapping[str, Tuple[str, ...]] = field(default_factory=dict)
    error_types: Tuple[str, ...] = ()
    verdict_vocabulary: Mapping[str, Tuple[str, ...]] = field(default_factory=dict)
    imports: Tuple[str, ...] = ()
    inline_verdicts: Tuple[str, ...] = ()

    def public_symbols(self) -> Tuple[str, ...]:
        """Every public top-level name this module defines."""
        return tuple(sorted(set(self.functions) | set(self.classes)))

    def has_symbol(self, name: str) -> bool:
        """Does this module define ``name`` at top level?"""
        return name in self.functions or name in self.classes

    def verdict_words(self) -> Tuple[str, ...]:
        """Every verdict-like word this module mints, across its vocabularies."""
        words: List[str] = []
        for values in self.verdict_vocabulary.values():
            for value in values:
                if value not in words:
                    words.append(value)
        for value in self.inline_verdicts:
            if value not in words:
                words.append(value)
        return tuple(words)


def _parse_module(path: Path) -> ast.Module:
    """Parse one python file.  A syntax error is a hard error: the review
    cannot judge a module it cannot read."""
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def read_module_facts(path: Path) -> ModuleFacts:
    """Collect the facts of one module file.  Read-only."""
    path = Path(path)
    tree = _parse_module(path)
    module = path.stem

    functions: Dict[str, Tuple[str, ...]] = {}
    classes: Dict[str, Tuple[str, ...]] = {}
    class_fields: Dict[str, Tuple[str, ...]] = {}
    error_types: List[str] = []
    vocabulary: Dict[str, Tuple[str, ...]] = {}
    imports: List[str] = []

    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if not node.name.startswith("_"):
                functions[node.name] = tuple(
                    argument.arg for argument in node.args.args
                ) + tuple(
                    argument.arg for argument in node.args.kwonlyargs
                )
        elif isinstance(node, ast.ClassDef):
            if not node.name.startswith("_"):
                bases = tuple(
                    base for base in (_base_name(base) for base in node.bases) if base
                )
                classes[node.name] = _class_members(node)
                class_fields[node.name] = _class_fields(node)
                if _is_error_class(node.name, bases):
                    error_types.append(node.name)
                # An Enum's members are a verdict vocabulary too: the
                # member *values* are the words callers write.
                for statement in node.body:
                    if not isinstance(statement, ast.Assign):
                        continue
                    for target in statement.targets:
                        if not isinstance(target, ast.Name):
                            continue
                        values = _string_sequence(statement.value)
                        if values:
                            vocabulary.setdefault(
                                f"{node.name}.{target.id}", values
                            )
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if not isinstance(target, ast.Name):
                    continue
                name = target.id
                if name.startswith("_"):
                    continue
                values = _string_sequence(node.value)
                if values and _VERDICT_CONST_RE.search(name):
                    vocabulary[name] = values
                elif len(values) == 1:
                    vocabulary.setdefault(name, values)
        elif isinstance(node, ast.AnnAssign):
            if isinstance(node.target, ast.Name) and not node.target.id.startswith("_"):
                if node.value is not None:
                    values = _string_sequence(node.value)
                    if values and _VERDICT_CONST_RE.search(node.target.id):
                        vocabulary[node.target.id] = values
                    elif len(values) == 1:
                        vocabulary.setdefault(node.target.id, values)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                imports.append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.append(node.module)

    inline: List[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            value = node.value.strip().lower()
            if value in VERDICT_WORDS and value not in inline:
                inline.append(value)

    return ModuleFacts(
        module=module,
        path=str(path),
        functions=functions,
        classes=classes,
        class_fields=class_fields,
        error_types=tuple(sorted(error_types)),
        verdict_vocabulary=vocabulary,
        imports=tuple(sorted(set(imports))),
        inline_verdicts=tuple(sorted(inline)),
    )


def collect_module_facts(module_paths: Iterable[Path]) -> Dict[str, ModuleFacts]:
    """Collect facts for many modules, keyed by module name."""
    facts: Dict[str, ModuleFacts] = {}
    for path in sorted(Path(p) for p in module_paths):
        facts[path.stem] = read_module_facts(path)
    return facts


# ---------------------------------------------------------------------------
# Rule 1 -- dangling cross-slice symbol references in the design docs
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DanglingReference:
    """A design doc names a module symbol that no longer exists."""

    doc: str
    line: int
    module: str
    symbol: str
    text: str
    reason: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "doc": self.doc,
            "line": self.line,
            "module": self.module,
            "symbol": self.symbol,
            "text": self.text,
            "reason": self.reason,
        }


def _iter_code_spans(text: str) -> Iterable[str]:
    """The contents of every single-backtick code span in a line."""
    for match in _CODE_SPAN_RE.finditer(text):
        yield match.group(1).strip()


def _candidate_references(span: str) -> List[Tuple[str, str]]:
    """Extract ``(module, symbol)`` pairs from one code span.

    Only spans that look like python dotted references qualify.  A
    ``.py`` suffix on the first component is dropped, so
    ``compaction.py`` and ``compaction`` name the same module.

    The split is module-first: the caller resolves the longest prefix of
    components that is a known module name.  ``a.b.c`` may be
    ``module=a.b`` symbol ``c``, or ``module=a`` symbol ``b.c`` -- which
    one it is depends on which module names exist, not on the text.
    """
    if "." not in span:
        return []
    if any(character.isspace() for character in span):
        return []
    if not re.match(r"^[A-Za-z_][A-Za-z0-9_.]*$", span):
        return []
    parts = span.split(".")
    if parts and parts[-1] == "py" and len(parts) > 1:
        parts = parts[:-1]
    if len(parts) < 2:
        return []
    references: List[Tuple[str, str]] = []
    # Longest module prefix first: ``pkg.mod.func`` -> module ``pkg.mod``.
    for split in range(len(parts) - 1, 0, -1):
        module = ".".join(parts[:split])
        symbol = ".".join(parts[split:])
        references.append((module, symbol))
    return references


def _symbol_resolves(module_facts: ModuleFacts, symbol_path: str) -> bool:
    """Does ``symbol_path`` resolve against ``module_facts``?

    ``symbol_path`` may be a dotted path: ``Class`` or
    ``Class.method``.  A method of a class counts as present when the
    class exists and the method is one of its public members.
    """
    parts = symbol_path.split(".")
    head = parts[0]
    if head not in module_facts.public_symbols():
        return False
    if len(parts) == 1:
        return True
    if head not in module_facts.classes:
        return False
    return all(part in module_facts.classes[head] for part in parts[1:])


def scan_dangling_symbols(
    doc_paths: Sequence[Path],
    facts: Mapping[str, ModuleFacts],
    known_modules: Optional[Sequence[str]] = None,
) -> List[DanglingReference]:
    """Rule 1: find design-doc references to module symbols that are gone.

    ``facts`` maps module name to its facts.  ``known_modules`` limits the
    scan to modules the review is about; a reference to a module outside
    that set (a stdlib name, a module that never existed) is not a
    dangling cross-slice reference and is ignored.

    Two kinds of dangling reference are reported:

    ``symbol-not-found``
        the module exists but the named symbol does not any more -- the
        doc drift case (slice B renamed or deleted the function slice A's
        doc names).
    ``module-not-found``
        the doc names a ``*.py`` file that is not in the tree -- the
        module itself went away.

    Read-only: the doc files are only read.
    """
    if known_modules is None:
        known = set(facts)
    else:
        known = set(known_modules)

    dangling: List[DanglingReference] = []
    for doc_path in sorted(Path(p) for p in doc_paths):
        doc = doc_path
        try:
            lines = doc.read_text(encoding="utf-8").splitlines()
        except OSError:
            continue
        for number, line in enumerate(lines, start=1):
            for span in _iter_code_spans(line):
                for module, symbol in _candidate_references(span):
                    if module in known:
                        if module in facts and _symbol_resolves(facts[module], symbol):
                            continue
                        dangling.append(
                            DanglingReference(
                                doc=str(doc),
                                line=number,
                                module=module,
                                symbol=symbol,
                                text=span,
                                reason="symbol-not-found",
                            )
                        )
                        break
    return dangling


def scan_missing_modules(
    doc_paths: Sequence[Path],
    known_modules: Sequence[str],
) -> List[DanglingReference]:
    """Rule 1b: design docs that name a ``*.py`` file the tree lacks.

    A doc that says ``alert_trigger_registry.py`` names a concrete file.
    If that file is not in the runtime, the doc points at a module that
    went away -- a weaker but unambiguous form of drift.
    """
    known = set(known_modules)
    missing: List[DanglingReference] = []
    for doc_path in sorted(Path(p) for p in doc_paths):
        doc = doc_path
        try:
            lines = doc.read_text(encoding="utf-8").splitlines()
        except OSError:
            continue
        for number, line in enumerate(lines, start=1):
            for span in _iter_code_spans(line):
                if not span.endswith(".py") or not re.match(r"^[A-Za-z_][A-Za-z0-9_]*\.py$", span):
                    continue
                module = span[:-3]
                if module in known:
                    continue
                missing.append(
                    DanglingReference(
                        doc=str(doc),
                        line=number,
                        module=module,
                        symbol="",
                        text=span,
                        reason="module-not-found",
                    )
                )
    return missing


# ---------------------------------------------------------------------------
# Rule 2 -- same public name in more than one module
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SameNameGroup:
    """A public name defined by more than one module."""

    name: str
    same_signature: bool
    signatures: Mapping[str, Tuple[str, ...]] = field(default_factory=dict)

    @property
    def modules(self) -> Tuple[str, ...]:
        return tuple(sorted(self.signatures))

    def as_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "kind": "same-signature" if self.same_signature else "different-signature",
            "signatures": {module: list(args) for module, args in sorted(self.signatures.items())},
        }


def find_same_name_symbols(
    facts: Mapping[str, ModuleFacts],
    only_functions: bool = True,
) -> List[SameNameGroup]:
    """Rule 2: public names defined in more than one module.

    A group whose members all share one signature is a probable duplicate
    implementation.  A group whose members differ in signature is the
    dangerous case: two different things that happen to share a name, so
    a caller that means one of them and reaches for the other gets a
    different behaviour rather than an error.

    Only functions are considered by default.  Class names are included
    when ``only_functions`` is false.
    """
    seen: Dict[str, Dict[str, Tuple[str, ...]]] = {}
    for module, module_facts in facts.items():
        symbols = module_facts.functions if only_functions else module_facts.public_symbols()
        for name in symbols:
            if name.startswith("_"):
                continue
            if only_functions:
                signature = module_facts.functions[name]
            else:
                signature = module_facts.functions.get(name, module_facts.classes.get(name, ()))
            seen.setdefault(name, {})[module] = signature

    groups: List[SameNameGroup] = []
    for name in sorted(seen):
        owners = seen[name]
        if len(owners) < 2:
            continue
        distinct = {signature for signature in owners.values()}
        groups.append(
            SameNameGroup(
                name=name,
                same_signature=len(distinct) == 1,
                signatures=dict(owners),
            )
        )
    return groups


# ---------------------------------------------------------------------------
# Rule 3 -- vocabulary overlap inside a semantic group
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class VocabularyOverlap:
    """A word two modules in the same group both mint.

    ``same_meaning`` is a judgement this tool cannot make: it reports the
    word, who mints it, and where each side mints it.  Whether the two
    sides mean the same thing is for the human reader.
    """

    group: str
    word: str
    holders: Mapping[str, Tuple[str, ...]] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "group": self.group,
            "word": self.word,
            "holders": {
                module: list(constants)
                for module, constants in sorted(self.holders.items())
            },
        }


def vocabulary_overlap(
    facts: Mapping[str, ModuleFacts],
    group_modules: Mapping[str, Sequence[str]] = GROUP_MODULES,
    extra_words: Optional[Mapping[str, Sequence[str]]] = None,
) -> List[VocabularyOverlap]:
    """Rule 3: verdict words shared by two modules of the same group.

    The words are the *values* of the module-level constants that look
    like verdicts, outcomes, reasons or states.  A word that two modules
    of the same group both mint is a vocabulary overlap: the caller has to
    know which vocabulary to write.

    ``extra_words`` adds words the AST scan cannot see -- for example
    the members of an ``Enum`` class, or a verdict set a module builds at
    runtime.  Keyed by module name.
    """
    overlaps: List[VocabularyOverlap] = []
    for group in sorted(group_modules):
        members = [
            module
            for module in group_modules[group]
            if module in facts
        ]
        holders: Dict[str, Dict[str, Tuple[str, ...]]] = {}
        for module in members:
            module_facts = facts[module]
            words: Dict[str, Tuple[str, ...]] = {}
            for constant, values in module_facts.verdict_vocabulary.items():
                words[constant] = tuple(values)
            if module_facts.inline_verdicts:
                words["<inline>"] = tuple(module_facts.inline_verdicts)
            if extra_words:
                for constant, values in extra_words.get(module, ()):  # type: ignore[union-attr]
                    words.setdefault(constant, tuple(values))
            for constant, values in words.items():
                for value in values:
                    holders.setdefault(value, {})[module] = (
                        holders.get(value, {}).get(module, ()) + (constant,)
                    )
        for word in sorted(holders):
            if len(holders[word]) < 2:
                continue
            overlaps.append(
                VocabularyOverlap(
                    group=group,
                    word=word,
                    holders={module: tuple(constants) for module, constants in holders[word].items()},
                )
            )
    return overlaps


# ---------------------------------------------------------------------------
# Rule 4 -- record shapes inside the compaction group
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RecordShapeConflict:
    """Two record types of the same group that cannot be joined.

    ``missing`` lists the fields of one record that the other has no
    counterpart for.  A record that has *no* counterpart field for the
    other's identity fields has no join key at all.
    """

    group: str
    left_module: str
    left_type: str
    right_module: str
    right_type: str
    missing: Tuple[str, ...] = ()
    right_missing: Tuple[str, ...] = ()
    shared: Tuple[str, ...] = ()

    def as_dict(self) -> Dict[str, Any]:
        return {
            "group": self.group,
            "left": f"{self.left_module}.{self.left_type}",
            "right": f"{self.right_module}.{self.right_type}",
            "shared": list(self.shared),
            "missing_on_right": list(self.missing),
            "missing_on_left": list(self.right_missing),
        }


def record_shape_conflicts(
    facts: Mapping[str, ModuleFacts],
    group_modules: Mapping[str, Sequence[str]] = GROUP_MODULES,
) -> List[RecordShapeConflict]:
    """Rule 4: compare the record shapes two modules of a group produce.

    A "record type" is a class whose name ends in ``Record``, ``Outcome``,
    ``Result``, ``Event``, ``Manifest``, ``Session``, ``Row`` or
    ``Entry`` -- the shapes these slices publish.  Two record types
    conflict when their field sets do not overlap enough to be joined:
    the fields of one that the other has no counterpart for are
    reported.
    """
    suffixes = (
        "Record", "Outcome", "Result", "Event", "Manifest",
        "Session", "Row", "Entry", "Report",
    )
    conflicts: List[RecordShapeConflict] = []
    for group in sorted(group_modules):
        members = [module for module in group_modules[group] if module in facts]
        records: List[Tuple[str, str, Tuple[str, ...]]] = []
        for module in members:
            for type_name, fields in sorted(facts[module].class_fields.items()):
                if not fields:
                    continue
                if not type_name.endswith(suffixes):
                    continue
                records.append((module, type_name, tuple(fields)))
        for index, (left_module, left_type, left_fields) in enumerate(records):
            for right_module, right_type, right_fields in records[index + 1:]:
                if left_module == right_module:
                    continue
                shared = tuple(
                    field for field in left_fields if field in right_fields
                )
                missing = tuple(
                    field for field in left_fields if field not in right_fields
                )
                right_missing = tuple(
                    field for field in right_fields if field not in left_fields
                )
                if not missing and not right_missing:
                    continue
                conflicts.append(
                    RecordShapeConflict(
                        group=group,
                        left_module=left_module,
                        left_type=left_type,
                        right_module=right_module,
                        right_type=right_type,
                        missing=missing,
                        right_missing=right_missing,
                        shared=shared,
                    )
                )
    return conflicts


# ---------------------------------------------------------------------------
# The whole review, in one call
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ReviewResult:
    """Everything the four rules found.  Pure data, no side effects."""

    modules: Tuple[str, ...] = ()
    docs: Tuple[str, ...] = ()
    dangling: Tuple[DanglingReference, ...] = ()
    same_name: Tuple[SameNameGroup, ...] = ()
    vocabulary: Tuple[VocabularyOverlap, ...] = ()
    record_shapes: Tuple[RecordShapeConflict, ...] = ()

    def as_dict(self) -> Dict[str, Any]:
        return {
            "modules": list(self.modules),
            "docs": list(self.docs),
            "dangling": [item.as_dict() for item in self.dangling],
            "same_name": [item.as_dict() for item in self.same_name],
            "vocabulary": [item.as_dict() for item in self.vocabulary],
            "record_shapes": [item.as_dict() for item in self.record_shapes],
        }

    def summary_lines(self) -> List[str]:
        """One line per rule, for a human reading the terminal."""
        return [
            "rule1 dangling symbols: %d" % len(self.dangling),
            "rule2 same-name symbols: %d (%d different-signature)"
            % (
                len(self.same_name),
                sum(1 for group in self.same_name if not group.same_signature),
            ),
            "rule3 vocabulary overlaps: %d" % len(self.vocabulary),
            "rule4 record shape conflicts: %d" % len(self.record_shapes),
        ]


def analyze(
    module_paths: Sequence[Path],
    doc_paths: Sequence[Path],
    group_modules: Mapping[str, Sequence[str]] = GROUP_MODULES,
) -> ReviewResult:
    """Run all four rules over a tree.  Read-only.

    ``module_paths`` are the python files to inspect, ``doc_paths`` the
    design docs to scan.  Nothing is written and nothing is imported.
    """
    facts = collect_module_facts(module_paths)
    known = sorted(facts)
    dangling = list(scan_dangling_symbols(doc_paths, facts, known_modules=known))
    dangling.extend(scan_missing_modules(doc_paths, known))
    return ReviewResult(
        modules=tuple(known),
        docs=tuple(sorted(str(path) for path in doc_paths)),
        dangling=tuple(dangling),
        same_name=tuple(find_same_name_symbols(facts)),
        vocabulary=tuple(vocabulary_overlap(facts, group_modules)),
        record_shapes=tuple(record_shape_conflicts(facts, group_modules)),
    )


def _default_paths(root: Path) -> Tuple[List[Path], List[Path]]:
    """The runtime modules and the design docs of a repository root."""
    runtime = root / "components" / "northstar-agent-runtime"
    modules = sorted(runtime.glob("*.py"))
    docs = sorted((root / "docs" / "design").glob("*.md"))
    return modules, docs


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Print the review over a repository root.  Read-only."""
    args = list(sys.argv[1:] if argv is None else argv)
    root = Path(args[0]) if args else Path.cwd()
    modules, docs = _default_paths(root)
    result = analyze(modules, docs)
    for line in result.summary_lines():
        print(line)
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI
    raise SystemExit(main())
