"""Prompt template lifecycle ledger (register / version / render / validate).

Research motivation: prompt engineering converged on versioned prompt
templates -- a named prompt text with declared ``{{variable}}``
placeholders, iterated over time, rendered with caller-supplied values,
and lint-checked before deployment. Getting the bookkeeping wrong
(silent variable renames, unversioned edits, renders with missing
values that silently interpolate empty strings) corrupts the audit
trail of *what prompt the agent actually saw*.

This module is the *lifecycle ledger* half of that shape, deliberately
distinct from the sibling ``template_engine.py`` (permissive Mustache:
sections, partials, HTML escaping, missing variables render as empty
string). This module is strict and audit-grade:

- ``PromptTemplate.template(template_id, text, seq)`` -- register a
  prompt template (version 1). Placeholder vocabulary is pinned to flat
  ``{{name}}`` (no sections, no partials, no logic -- prompts are
  flat). Returns a frozen ``TemplateRecord`` with a ``sha256:`` digest
  pin. Malformed text (unbalanced braces, bad variable names) is
  refused fail-closed; duplicate ids are refused; ids are never
  recycled.
- ``PromptTemplate.version(template_id, text, seq)`` -- book version
  N+1 of a template. Each version pins its ``prior_digest``, forming a
  tamper-evident chain. Returns a frozen ``VersionRecord``.
- ``PromptTemplate.render(template_id, variables, seq)`` -- book one
  render of the latest version. The variable set must *exactly* match
  the declared placeholders: missing variables raise
  ``MissingVariableError``, unknown variables raise
  ``UnknownVariableError`` (never silent empty strings). Returns a
  frozen ``RenderRecord`` carrying the rendered text; the audit row
  carries the digest pin only.
- ``PromptTemplate.validate(text, seq)`` -- lint-check a candidate
  prompt text *without* booking it as a template. The verdict is data
  (``valid`` bool plus a ``problems`` tuple over a pinned vocabulary),
  never raised. Returns a frozen ``ValidationReport``.
- ``prompt_template_audit_event(kind, ...)`` -- ``audit.ndjson/1``
  records (``template-registered`` / ``version-booked`` / ``rendered``
  / ``validated`` / ``rejected``); caller-supplied seqs only. Raw
  template text, rendered output, and variable values never cross the
  audit boundary -- audit rows carry ids, digests, and counts only.

Escape hatch: ``\\{{...}}`` renders its braces and inner text verbatim
(no placeholder parsing inside); ``\\}}`` renders a literal ``}}``;
``\\\\`` renders a literal backslash. Anything else with a stray brace
is malformed and refused fail-closed.

Fail-closed edges (fail loudly, never guess):

- ``template_id`` must be a non-empty str, <= 256 chars, no whitespace.
- ``text`` must be a non-empty str, <= 65536 chars.
- Placeholder names match ``[A-Za-z_][A-Za-z0-9_]{0,63}``; empty or
  malformed names, unclosed ``{{`` and stray braces raise
  ``BadTemplateError``.
- ``render`` on an unknown template raises ``UnknownTemplateError``.
- ``variables`` must be a dict of str -> str; values are substituted
  verbatim (no coercion -- a non-str value raises
  ``BadVariableError``).
- Seqs are ints (not bool), >= 0, strictly increasing per instance.
  Failed mutations consume their seq and book a ``rejected`` audit
  row; seq rewinds raise bare ``SeqOrderError`` without consuming.

Honest scope:

- This module books *declared* prompt text and *caller-supplied*
  variable values. A booked render is a ledger entry pinning the exact
  prompt text that was produced -- it is not proof the text was sent
  to any model, and the module cannot verify variable values are true.
- ``validate()`` lints *syntax* (braces, names, length). It does not
  judge prompt quality, safety, or injection risk -- a "valid" verdict
  means well-formed, nothing more.
- No persistence: the ledger is in-memory. Pair with the durable
  audit writer if template state must survive a restart.
"""

from __future__ import annotations

import hashlib
import re
import threading
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json, jcs_sha256_hex
except Exception:  # pragma: no cover - module must stay importable standalone
    import json as _json

    def jcs_canonical_json(obj):  # type: ignore[no-redef]
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("utf-8")

    def jcs_sha256_hex(obj) -> str:  # type: ignore[no-redef]
        return hashlib.sha256(jcs_canonical_json(obj)).hexdigest()


#: Version pin for this module's record shape.
PROMPT_TEMPLATE_VERSION = "prompt-template.v1"

#: Schema pin carried by records and audit events.
PROMPT_TEMPLATE_SCHEMA = "northstar.prompt-template.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Audit event kinds.
KIND_TEMPLATE_REGISTERED = "template-registered"
KIND_VERSION_BOOKED = "version-booked"
KIND_RENDERED = "rendered"
KIND_VALIDATED = "validated"
KIND_REJECTED = "rejected"
_KINDS = (KIND_TEMPLATE_REGISTERED, KIND_VERSION_BOOKED, KIND_RENDERED,
          KIND_VALIDATED, KIND_REJECTED)

#: Detail keys banned from the audit boundary (raw data never crosses it).
_BANNED_DETAIL_KEYS = frozenset(
    {"text", "rendered", "variables", "value", "payload", "raw"})

#: Max template-id length.
_MAX_TEMPLATE_ID_LEN = 256

#: Max template text length (chars).
_MAX_TEXT_LEN = 65536

#: Pinned placeholder-name vocabulary.
_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}\Z")

#: Pinned validation-problem vocabulary (validate() verdicts as data).
PROBLEM_UNBALANCED_BRACES = "unbalanced-braces"
PROBLEM_EMPTY_PLACEHOLDER = "empty-placeholder"
PROBLEM_BAD_VARIABLE_NAME = "bad-variable-name"
PROBLEM_TEXT_TOO_LONG = "text-too-long"
_PROBLEMS = (PROBLEM_UNBALANCED_BRACES, PROBLEM_EMPTY_PLACEHOLDER,
             PROBLEM_BAD_VARIABLE_NAME, PROBLEM_TEXT_TOO_LONG)


class PromptTemplateError(Exception):
    """Base error for the prompt template ledger (programming errors)."""


class BadTemplateError(PromptTemplateError):
    """Raised when template text is malformed."""


class DuplicateTemplateError(PromptTemplateError):
    """Raised when a template id is registered twice."""


class UnknownTemplateError(PromptTemplateError):
    """Raised when a template id names no registered template."""


class BadVariableError(PromptTemplateError):
    """Raised when a variable name or value is malformed."""


class MissingVariableError(PromptTemplateError):
    """Raised when render() is missing a declared variable."""


class UnknownVariableError(PromptTemplateError):
    """Raised when render() is given an undeclared variable."""


class SeqOrderError(PromptTemplateError):
    """Raised when a seq is malformed or not strictly increasing."""


class AuditKindError(PromptTemplateError):
    """Raised when an audit event kind is unknown or leaks banned keys."""


def _check_seq(value: object, name: str = "seq") -> int:
    """Validate a caller-supplied ordering seq: int, not bool, >= 0."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise SeqOrderError(f"{name} must be int, got {type(value).__name__}")
    if value < 0:
        raise SeqOrderError(f"{name} must be >= 0, got {value}")
    return value


def _check_template_id(template_id: object) -> str:
    """Validate a template id: non-empty str, no whitespace, <= 256 chars."""
    if isinstance(template_id, bool) or not isinstance(template_id, str):
        raise BadTemplateError(
            f"template_id must be str, got {type(template_id).__name__}")
    if not template_id:
        raise BadTemplateError("template_id must not be empty")
    if len(template_id) > _MAX_TEMPLATE_ID_LEN:
        raise BadTemplateError(
            f"template_id too long (>{_MAX_TEMPLATE_ID_LEN} chars)")
    if any(ch.isspace() for ch in template_id):
        raise BadTemplateError("template_id must not contain whitespace")
    return template_id


def _lint(text: object) -> Tuple[Tuple[str, ...], List[Tuple[str, str]]]:
    """Lint candidate template text.

    Returns ``(problems, tokens)`` where problems is a tuple over the
    pinned problem vocabulary and tokens is the parsed token list
    (only meaningful when problems is empty). Never raises for
    malformed text -- verdicts are data. Raises ``BadTemplateError``
    only when ``text`` is not a str.
    """
    if isinstance(text, bool) or not isinstance(text, str):
        raise BadTemplateError(
            f"text must be str, got {type(text).__name__}")
    problems: List[str] = []
    if not text:
        problems.append(PROBLEM_UNBALANCED_BRACES)
        return tuple(problems), []
    if len(text) > _MAX_TEXT_LEN:
        problems.append(PROBLEM_TEXT_TOO_LONG)
        return tuple(problems), []
    tokens: List[Tuple[str, str]] = []
    buf: List[str] = []
    i = 0
    n = len(text)

    def flush() -> None:
        if buf:
            tokens.append(("lit", "".join(buf)))
            del buf[:]

    broken = False
    while i < n and not broken:
        ch = text[i]
        if ch == "\\" and i + 1 < n and text[i + 1] in "{}\\":
            nxt = text[i + 1]
            if nxt == "{" and text.startswith("{{", i + 1):
                # Literal span: \{{ ... }} renders the braces and the
                # inner text verbatim (no placeholder parsing inside).
                j = text.find("}}", i + 3)
                if j == -1:
                    problems.append(PROBLEM_UNBALANCED_BRACES)
                    broken = True
                else:
                    buf.append(text[i + 1:j + 2])
                    i = j + 2
            elif nxt == "}" and text.startswith("}}", i + 1):
                buf.append("}}")
                i += 3
            else:
                buf.append(nxt)
                i += 2
        elif ch == "{":
            if text.startswith("{{", i):
                j = text.find("}}", i + 2)
                if j == -1:
                    problems.append(PROBLEM_UNBALANCED_BRACES)
                    broken = True
                else:
                    name = text[i + 2:j]
                    if not name:
                        problems.append(PROBLEM_EMPTY_PLACEHOLDER)
                        broken = True
                    elif not _NAME_RE.match(name):
                        problems.append(PROBLEM_BAD_VARIABLE_NAME)
                        broken = True
                    else:
                        flush()
                        tokens.append(("var", name))
                        i = j + 2
            else:
                problems.append(PROBLEM_UNBALANCED_BRACES)
                broken = True
        elif ch == "}":
            problems.append(PROBLEM_UNBALANCED_BRACES)
            broken = True
        else:
            buf.append(ch)
            i += 1
    if not broken:
        flush()
    return tuple(problems), tokens


def _analyze(text: object) -> Tuple[str, ...]:
    """Parse template text, returning declared variables in order.

    Fail-closed: the first lint problem raises ``BadTemplateError``.
    """
    problems, tokens = _lint(text)
    if problems:
        raise BadTemplateError(f"malformed template text: {problems[0]}")
    seen: List[str] = []
    for kind, value in tokens:
        if kind == "var" and value not in seen:
            seen.append(value)
    return tuple(seen)


def _pin(*parts: object) -> str:
    """Digest pin over a domain-separated canonical tuple."""
    return "sha256:" + jcs_sha256_hex({
        "domain": PROMPT_TEMPLATE_SCHEMA,
        "parts": list(parts),
    })


def prompt_template_audit_event(kind: str, detail: Dict[str, object],
                                seq: object) -> Dict[str, object]:
    """Build one ``audit.ndjson/1`` audit row for the template ledger."""
    if kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    banned = _BANNED_DETAIL_KEYS.intersection(detail.keys())
    if banned:
        raise AuditKindError(
            f"detail keys banned from audit boundary: {sorted(banned)}")
    return {
        "schema": AUDIT_SCHEMA,
        "module": PROMPT_TEMPLATE_VERSION,
        "kind": kind,
        "seq": seq,
        "detail": dict(detail),
    }


@dataclass(frozen=True)
class TemplateRecord:
    """Frozen record of a registered prompt template (version 1)."""
    template_id: str
    text: str
    # Declared placeholder names, first-appearance order, deduplicated.
    variables: Tuple[str, ...]
    seq: int
    digest: str

    def verify(self, text: str, seq: int) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin("template", self.template_id, text, seq)


@dataclass(frozen=True)
class VersionRecord:
    """Frozen record of one booked template version (N >= 2)."""
    template_id: str
    number: int
    text: str
    prior_digest: str
    variables: Tuple[str, ...]
    seq: int
    digest: str

    def verify(self, text: str, prior_digest: str, seq: int) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin("version", self.template_id, self.number,
                                   text, prior_digest, seq)


@dataclass(frozen=True)
class RenderRecord:
    """Frozen record of one booked render of the latest template version."""
    render_id: str
    template_id: str
    version: int
    # Sorted (name, value) pairs actually substituted.
    variables: Tuple[Tuple[str, str], ...]
    rendered: str
    seq: int
    digest: str

    def verify(self, template_id: str, version: int,
               variables: Tuple[Tuple[str, str], ...],
               rendered: str, seq: int) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin(
            "render", self.render_id, template_id, version,
            [[k, v] for k, v in variables], rendered, seq)


@dataclass(frozen=True)
class ValidationReport:
    """Frozen record of one lint-check decision (verdict as data)."""
    report_id: str
    text_digest: str
    valid: bool
    problems: Tuple[str, ...]
    seq: int
    digest: str

    def verify(self, text: str, seq: int) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin("validate", self.report_id,
                                   _pin("candidate-text", text),
                                   self.valid, list(self.problems), seq)


@dataclass(frozen=True)
class TemplateStats:
    """Ledger counts as data (pure read)."""
    templates: int
    versions: int
    renders: int
    validations: int


class PromptTemplate:
    """Deterministic prompt template lifecycle ledger.

    All mutations take caller-supplied strictly increasing int seqs,
    are RLock-guarded, and book frozen records with ``sha256:`` digest
    pins plus ``audit.ndjson/1`` rows. No wall-clock, no randomness.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        # template_id -> list of records; index 0 is TemplateRecord (v1),
        # the rest are VersionRecords (v2+).
        self._templates: Dict[str, list] = {}
        self._renders: Dict[str, RenderRecord] = {}
        self._reports: Dict[str, ValidationReport] = {}
        self._render_counter = 0
        self._report_counter = 0
        self._last_seq = 0
        self._audit: list = []

    # -- seq discipline ---------------------------------------------------

    def _claim(self, seq: object) -> int:
        """Validate seq; rewinds raise bare (no consumption)."""
        seq = _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq must be strictly increasing "
                f"(last={self._last_seq}, got={seq})")
        return seq

    def _burn(self, seq: int, error: Exception) -> None:
        """Consume the seq, book a rejected row, then raise."""
        self._last_seq = seq
        self._audit.append(prompt_template_audit_event(
            KIND_REJECTED, {"error": type(error).__name__}, seq))
        raise error

    def _emit(self, kind: str, detail: Dict[str, object], seq: int) -> None:
        self._audit.append(prompt_template_audit_event(kind, detail, seq))

    # -- mutations ---------------------------------------------------------

    def template(self, template_id: object, text: object,
                 seq: object) -> TemplateRecord:
        """Register a prompt template (version 1); malformed text refused."""
        with self._lock:
            seq = self._claim(seq)
            try:
                template_id = _check_template_id(template_id)
                if template_id in self._templates:
                    raise DuplicateTemplateError(
                        f"template already registered: {template_id!r}")
                variables = _analyze(text)
                text = str(text)
            except PromptTemplateError as e:
                self._burn(seq, e)
            rec = TemplateRecord(template_id=template_id, text=text,
                                 variables=variables, seq=seq,
                                 digest=_pin("template", template_id, text,
                                             seq))
            self._templates[template_id] = [rec]
            self._last_seq = seq
            self._emit(KIND_TEMPLATE_REGISTERED,
                       {"template_id": template_id,
                        "variable_count": len(variables),
                        "digest": rec.digest}, seq)
            return rec

    def version(self, template_id: object, text: object,
                seq: object) -> VersionRecord:
        """Book version N+1 of a template, chained to the prior digest."""
        with self._lock:
            seq = self._claim(seq)
            try:
                template_id = _check_template_id(template_id)
                if template_id not in self._templates:
                    raise UnknownTemplateError(
                        f"unknown template: {template_id!r}")
                variables = _analyze(text)
                text = str(text)
            except PromptTemplateError as e:
                self._burn(seq, e)
            chain = self._templates[template_id]
            number = len(chain) + 1
            prior_digest = chain[-1].digest
            rec = VersionRecord(template_id=template_id, number=number,
                                text=text, prior_digest=prior_digest,
                                variables=variables, seq=seq,
                                digest=_pin("version", template_id, number,
                                            text, prior_digest, seq))
            chain.append(rec)
            self._last_seq = seq
            self._emit(KIND_VERSION_BOOKED,
                       {"template_id": template_id, "number": number,
                        "variable_count": len(variables),
                        "digest": rec.digest}, seq)
            return rec

    def render(self, template_id: object, variables: object,
               seq: object) -> RenderRecord:
        """Book one render of the latest version; exact variable set required.

        The supplied mapping must cover *exactly* the declared
        placeholders: a missing variable raises ``MissingVariableError``,
        an undeclared one raises ``UnknownVariableError``. Values are
        substituted verbatim (str only, no coercion).
        """
        with self._lock:
            seq = self._claim(seq)
            try:
                template_id = _check_template_id(template_id)
                if template_id not in self._templates:
                    raise UnknownTemplateError(
                        f"unknown template: {template_id!r}")
                if isinstance(variables, bool) or not isinstance(variables,
                                                                 dict):
                    raise BadVariableError(
                        "variables must be a dict of str -> str, got "
                        f"{type(variables).__name__}")
                for key, value in variables.items():
                    if isinstance(key, bool) or not isinstance(key, str):
                        raise BadVariableError(
                            "variable names must be str, got "
                            f"{type(key).__name__}")
                    if isinstance(value, bool) or not isinstance(value, str):
                        raise BadVariableError(
                            f"variable {key!r} value must be str, got "
                            f"{type(value).__name__}")
                chain = self._templates[template_id]
                latest = chain[-1]
                declared = set(latest.variables)
                given = set(variables.keys())
                missing = sorted(declared - given)
                if missing:
                    raise MissingVariableError(
                        f"missing variables for {template_id!r}: {missing}")
                unknown = sorted(given - declared)
                if unknown:
                    raise UnknownVariableError(
                        f"unknown variables for {template_id!r}: {unknown}")
                problems, tokens = _lint(latest.text)
                assert not problems  # booked text was validated at book time
                parts: List[str] = []
                for kind, value in tokens:
                    parts.append(variables[value] if kind == "var" else value)
                rendered = "".join(parts)
            except PromptTemplateError as e:
                self._burn(seq, e)
            self._render_counter += 1
            render_id = f"render-{self._render_counter}"
            version = len(chain)
            var_items = tuple(sorted(variables.items()))
            rec = RenderRecord(render_id=render_id, template_id=template_id,
                               version=version, variables=var_items,
                               rendered=rendered, seq=seq,
                               digest=_pin("render", render_id, template_id,
                                           version,
                                           [[k, v] for k, v in var_items],
                                           rendered, seq))
            self._renders[render_id] = rec
            self._last_seq = seq
            # Rendered text banned from the audit boundary: digest pin only.
            self._emit(KIND_RENDERED,
                       {"render_id": render_id, "template_id": template_id,
                        "version": version, "digest": rec.digest}, seq)
            return rec

    def validate(self, text: object, seq: object) -> ValidationReport:
        """Lint-check candidate text without booking it; verdict as data."""
        with self._lock:
            seq = self._claim(seq)
            try:
                problems, _tokens = _lint(text)
                text = str(text)
            except PromptTemplateError as e:
                self._burn(seq, e)
            self._report_counter += 1
            report_id = f"report-{self._report_counter}"
            text_digest = _pin("candidate-text", text)
            valid = not problems
            rec = ValidationReport(report_id=report_id,
                                   text_digest=text_digest, valid=valid,
                                   problems=problems, seq=seq,
                                   digest=_pin("validate", report_id,
                                               text_digest, valid,
                                               list(problems), seq))
            self._reports[report_id] = rec
            self._last_seq = seq
            self._emit(KIND_VALIDATED,
                       {"report_id": report_id, "valid": valid,
                        "problem_count": len(problems),
                        "digest": rec.digest}, seq)
            return rec

    # -- views --------------------------------------------------------------

    def template_record(self, template_id: str) -> Optional[TemplateRecord]:
        """Return the version-1 record, or None when unknown (pure read)."""
        chain = self._templates.get(template_id)
        return chain[0] if chain else None

    def version_record(self, template_id: str,
                       number: int) -> Optional[object]:
        """Return one version record (v1 = TemplateRecord), or None."""
        chain = self._templates.get(template_id)
        if not chain or number < 1 or number > len(chain):
            return None
        return chain[number - 1]

    def template_ids(self) -> Tuple[str, ...]:
        """Sorted registered template ids (pure read)."""
        return tuple(sorted(self._templates))

    def version_count(self, template_id: str) -> int:
        """Booked version count for a template, 0 when unknown (pure read)."""
        chain = self._templates.get(template_id)
        return len(chain) if chain else 0

    def declared_variables(self, template_id: str) -> Optional[Tuple[str, ...]]:
        """Declared placeholder names of the latest version, or None."""
        chain = self._templates.get(template_id)
        return chain[-1].variables if chain else None

    def render_record(self, render_id: str) -> Optional[RenderRecord]:
        """Return a booked render record, or None when unknown (pure read)."""
        return self._renders.get(render_id)

    def validation_report(self, report_id: str) -> Optional[ValidationReport]:
        """Return a booked validation report, or None (pure read)."""
        return self._reports.get(report_id)

    def stats(self, seq: object) -> TemplateStats:
        """Ledger counts as data: seq validated, never consumed."""
        _check_seq(seq)
        versions = sum(len(chain) for chain in self._templates.values())
        return TemplateStats(templates=len(self._templates), versions=versions,
                             renders=len(self._renders),
                             validations=len(self._reports))

    def audit_log(self) -> Tuple[Dict[str, object], ...]:
        """Booked audit rows, oldest first (pure read)."""
        return tuple(self._audit)


def main() -> None:
    """Self-check: register, version, render, validate, pins, audit."""
    pt = PromptTemplate()
    rec = pt.template("greeting", "Hello, {{name}}! You are {{role}}.", 1)
    assert rec.verify("Hello, {{name}}! You are {{role}}.", 1)
    assert rec.variables == ("name", "role")
    assert pt.declared_variables("greeting") == ("name", "role")

    # Strict render: exact variable set required.
    r = pt.render("greeting", {"name": "Ada", "role": "operator"}, 2)
    assert r.rendered == "Hello, Ada! You are operator.", r.rendered
    assert r.version == 1
    assert r.verify("greeting", 1, (("name", "Ada"), ("role", "operator")),
                    r.rendered, 2)

    # Version chain: v2 links the prior digest.
    v2 = pt.version("greeting", "Hi {{name}} ({{role}}).", 3)
    assert v2.number == 2
    assert v2.prior_digest == rec.digest
    assert v2.verify("Hi {{name}} ({{role}}).", rec.digest, 3)
    assert pt.version_count("greeting") == 2
    r2 = pt.render("greeting", {"name": "Ada", "role": "operator"}, 4)
    assert r2.version == 2 and r2.rendered == "Hi Ada (operator)."

    # Validate: verdict as data, never raised for bad text.
    ok = pt.validate("Dear {{title}} {{last}},", 5)
    assert ok.valid and ok.problems == ()
    assert ok.verify("Dear {{title}} {{last}},", 5)
    bad = pt.validate("Hello {{name", 6)
    assert not bad.valid and bad.problems == ("unbalanced-braces",)

    # Escape hatch: literal braces survive rendering.
    pt.template("lit", "Use \\{{name}} for vars.", 7)
    rl = pt.render("lit", {}, 8)
    assert rl.rendered == "Use {{name}} for vars.", rl.rendered

    stats = pt.stats(8)
    assert (stats.templates, stats.versions, stats.renders,
            stats.validations) == (2, 3, 3, 2)
    assert len(pt.audit_log()) == 8
    print("prompt-template OK: register, version, render, validate, "
          "pins, audit")


if __name__ == "__main__":
    main()
