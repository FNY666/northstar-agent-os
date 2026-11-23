"""Changelog generator interface (conventional-commits shaped, simulated).

Research motivation: release notes should be derived from the commit
history, not hand-written after the fact. The Conventional Commits
specification is the reference: a commit's header carries a
``type`` (``feat``, ``fix``, ...), an optional ``scope``, an
optional ``!`` breaking marker, and a ``subject``; the body may
carry a ``BREAKING CHANGE:`` trailer. Given a ledger of parsed
commits, the module can render a markdown changelog grouped by
section (Features, Bug Fixes, ...) and propose the next semver
bump (breaking -> major, feat -> minor, else patch).

This module is the *bookkeeping* half of that shape -- the ledger
that holds parsed commit records, renders deterministic markdown,
and books the semver-bump decision. It cannot read a git history
(the host owns the repo); it books the parse / render / bump
decisions over host-reported commit text:

- ``ChangelogGenerator`` -- owns the commit ledger.
  ``parse(commit_text, seq, commit_id=None)`` parses one
  conventional-commit message into a frozen ``ParsedCommit``
  (type, scope, subject, body, breaking flag, digest pin).
  ``render(seq, version=None)`` renders the accumulated ledger
  into a frozen ``RenderedChangelog`` (markdown text + digest
  pin). ``bump(current_version, seq)`` books the semver decision
  from the ledger into a frozen ``VersionBump``.
- ``changelog_generator_audit_event(kind, ...)`` --
  ``audit.ndjson/1`` records (``parsed`` / ``rendered`` /
  ``bumped`` / ``rejected``); ids and digest pins only -- commit
  bodies never cross the audit boundary.

Fail-closed edges (fail loudly, never guess):

- ``parse()`` refuses non-conventional headers
  (``BadCommitError``): no ``type: subject`` colon shape, empty
  type, empty subject, unknown type, bad scope token.
- Only the pinned type vocabulary is accepted (``feat``,
  ``fix``, ``docs``, ``style``, ``refactor``, ``perf``,
  ``test``, ``build``, ``ci``, ``chore``, ``revert``).
  Anything else (e.g. ``wip``, ``update``) is refused -- a
  changelog derived from ad-hoc verbs is not trustworthy.
- Mutating calls consume strictly increasing caller-supplied int
  seqs (no wall-clock); rewinds raise ``SeqOrderError``. A failed
  mutation consumes its seq (fail-closed ledger position).
- ``bump()`` refuses malformed versions (``BadVersionError``);
  empty ledgers produce a ``patch`` bump with ``no-changes``
  reason (data, never an exception).

Honest scope:

- This module is simulated bookkeeping, not a VCS reader: it
  parses the commit text the *caller* supplies and pins it --
  a lying host gets a lying changelog (GIGO boundary).
- The semver decision is a policy over the parsed ledger
  (breaking present -> major; else any feat -> minor; else
  patch), never a judgment that the release *should* ship.
- In-memory only: pair with the durable audit writer if the
  changelog ledger must survive a restart. ``main()``
  self-checks the shape.
"""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

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
CHANGELOG_GENERATOR_VERSION = "changelog-generator.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.changelog-generator.v1"

#: Audit event schema pin.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Pinned conventional-commit type vocabulary.
TYPES: Tuple[str, ...] = (
    "feat", "fix", "docs", "style", "refactor", "perf",
    "test", "build", "ci", "chore", "revert",
)

#: Rendered section order: (type, section title).
SECTIONS: Tuple[Tuple[str, str], ...] = (
    ("feat", "Features"),
    ("fix", "Bug Fixes"),
    ("perf", "Performance Improvements"),
    ("revert", "Reverts"),
    ("docs", "Documentation"),
    ("style", "Styles"),
    ("refactor", "Code Refactoring"),
    ("test", "Tests"),
    ("build", "Build System"),
    ("ci", "Continuous Integration"),
    ("chore", "Chores"),
)

#: Header shape: ``type(scope)!: subject`` -- scope optional, ``!`` optional.
_HEADER_RE = re.compile(
    r"^(?P<type>[A-Za-z]+)"
    r"(?:\((?P<scope>[^)]*)\))?"
    r"(?P<bang>!)?"
    r":\s*(?P<subject>.*)$"
)

#: Scope token discipline: lowercase words, dashes, dots, underscores.
_SCOPE_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")

#: ``BREAKING CHANGE:`` trailer (case-sensitive, spec-exact).
_BREAKING_RE = re.compile(r"^BREAKING[ -]CHANGE:\s*(?P<note>.*)$")

#: Semver discipline: ``MAJOR.MINOR.PATCH`` with optional prerelease/build.
_SEMVER_RE = re.compile(
    r"^(?P<major>0|[1-9]\d*)\.(?P<minor>0|[1-9]\d*)\.(?P<patch>0|[1-9]\d*)"
    r"(?:-(?P<pre>[0-9A-Za-z.-]+))?(?:\+(?P<build>[0-9A-Za-z.-]+))?$"
)

#: Hard cap on a single commit message accepted by the ledger (guardrail).
MAX_COMMIT_BYTES = 64 * 1024

#: Hard cap on commits held in one ledger (guardrail).
MAX_COMMITS = 10_000


class ChangelogError(ValueError):
    """Base fail-closed changelog error."""


class BadCommitError(ChangelogError):
    """Commit text is not a conventional commit."""


class BadVersionError(ChangelogError):
    """Version text is not semver."""


class UnknownCommitError(ChangelogError):
    """No parsed commit under that id."""


class DuplicateCommitError(ChangelogError):
    """A commit id was registered twice."""


class SeqOrderError(ChangelogError):
    """Caller seq did not strictly increase."""


class LedgerFullError(ChangelogError):
    """The commit ledger hit MAX_COMMITS."""


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise SeqOrderError(f"seq must be a non-negative int, got {seq!r}")
    return seq


def _pin(obj: Any) -> str:
    return "sha256:" + jcs_sha256_hex(obj)


@dataclass(frozen=True)
class ParsedCommit:
    """One parsed conventional commit."""

    commit_id: str
    type: str
    scope: Optional[str]
    subject: str
    body: Tuple[str, ...]
    breaking: bool
    breaking_note: Optional[str]
    digest: str
    seq: int
    version: str = CHANGELOG_GENERATOR_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "commit_id": self.commit_id,
            "type": self.type,
            "scope": self.scope,
            "subject": self.subject,
            "body": list(self.body),
            "breaking": self.breaking,
            "breaking_note": self.breaking_note,
            "digest": self.digest,
            "seq": self.seq,
            "version": self.version,
            "schema": self.schema,
        }

    def verify(self) -> bool:
        """Re-derive the digest pin from the parsed fields."""
        body = {
            "commit_id": self.commit_id,
            "type": self.type,
            "scope": self.scope,
            "subject": self.subject,
            "body": list(self.body),
            "breaking": self.breaking,
            "breaking_note": self.breaking_note,
            "version": self.version,
        }
        return _pin(body) == self.digest


@dataclass(frozen=True)
class RenderedChangelog:
    """The markdown changelog rendered from the ledger."""

    version: str
    title: str
    text: str
    sections: Tuple[str, ...]
    commit_ids: Tuple[str, ...]
    digest: str
    seq: int
    module_version: str = CHANGELOG_GENERATOR_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "title": self.title,
            "text": self.text,
            "sections": list(self.sections),
            "commit_ids": list(self.commit_ids),
            "digest": self.digest,
            "seq": self.seq,
            "module_version": self.module_version,
            "schema": self.schema,
        }

    def verify(self, text: str) -> bool:
        """Re-derive the digest pin over (title, version, text)."""
        return _pin({
            "title": self.title,
            "version": self.version,
            "text": text,
        }) == self.digest


@dataclass(frozen=True)
class VersionBump:
    """The semver bump decision booked from the ledger."""

    current: str
    next: str
    level: str  # "major" | "minor" | "patch"
    reason: str  # "breaking-change" | "feature" | "no-breaking-or-feature" | "empty-ledger"
    commit_ids: Tuple[str, ...]
    digest: str
    seq: int
    version: str = CHANGELOG_GENERATOR_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "current": self.current,
            "next": self.next,
            "level": self.level,
            "reason": self.reason,
            "commit_ids": list(self.commit_ids),
            "digest": self.digest,
            "seq": self.seq,
            "version": self.version,
            "schema": self.schema,
        }


_AUDIT_KINDS: Tuple[str, ...] = ("parsed", "rendered", "bumped", "rejected")


def changelog_generator_audit_event(kind: str, seq: int, **detail: Any) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for changelog activity."""
    if kind not in _AUDIT_KINDS:
        raise ChangelogError(f"unknown audit kind {kind!r}")
    seq = _check_seq(seq)
    event: Dict[str, Any] = {
        "schema": AUDIT_SCHEMA,
        "event": kind,
        "audit_seq": seq,
        "module_version": CHANGELOG_GENERATOR_VERSION,
        "module_schema": SCHEMA_PIN,
    }
    for key in ("subject", "body", "message"):
        if key in detail:
            raise ChangelogError(f"audit boundary must not carry {key!r}")
    event.update(detail)
    return event


def _parse_header(line: str) -> Tuple[str, Optional[str], str, bool]:
    match = _HEADER_RE.match(line)
    if match is None:
        raise BadCommitError(f"header is not 'type[(scope)][!]: subject': {line!r}")
    ctype = match.group("type").lower()
    if ctype not in TYPES:
        raise BadCommitError(f"unknown commit type {match.group('type')!r}")
    scope = match.group("scope")
    if scope is not None:
        scope = scope.strip()
        if scope == "":
            raise BadCommitError("empty scope is not allowed; drop the parens")
        if not _SCOPE_RE.match(scope):
            raise BadCommitError(f"bad scope token {scope!r}")
    subject = match.group("subject").strip()
    if subject == "":
        raise BadCommitError("empty subject refused")
    breaking = match.group("bang") == "!"
    return ctype, scope, subject, breaking


def _parse_body(lines: List[str]) -> Tuple[Tuple[str, ...], Optional[str]]:
    body: List[str] = []
    note: Optional[str] = None
    for line in lines:
        bm = _BREAKING_RE.match(line)
        if bm is not None:
            text = bm.group("note").strip()
            note = text if text else None
        else:
            body.append(line)
    # Strip trailing blank lines for a stable digest.
    while body and body[-1].strip() == "":
        body.pop()
    return tuple(body), note


def _parse_semver(text: str) -> Tuple[int, int, int]:
    if not isinstance(text, str):
        raise BadVersionError(f"not semver: {text!r}")
    match = _SEMVER_RE.match(text)
    if match is None:
        raise BadVersionError(f"not semver: {text!r}")
    return int(match.group("major")), int(match.group("minor")), int(match.group("patch"))


class ChangelogGenerator:
    """Conventional-commit ledger: parse, render, bump."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq = -1
        self._counter = 0
        self._commits: Dict[str, ParsedCommit] = {}
        self._order: List[str] = []
        self._audit: List[Dict[str, Any]] = []

    def _monotonic(self, seq: int) -> int:
        seq = _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError(f"seq must strictly increase, got {seq}")
        self._last_seq = seq
        return seq

    def _emit(self, kind: str, seq: int, **detail: Any) -> None:
        self._audit.append(changelog_generator_audit_event(kind, seq, **detail))

    def parse(self, commit_text: str, seq: Any, commit_id: Optional[str] = None) -> ParsedCommit:
        """Parse one conventional-commit message into a frozen record."""
        with self._lock:
            seq = self._monotonic(seq)  # consumes seq even on refusal
            try:
                if not isinstance(commit_text, str) or commit_text == "":
                    raise BadCommitError("commit text must be a non-empty str")
                if len(commit_text.encode("utf-8")) > MAX_COMMIT_BYTES:
                    raise BadCommitError("commit text exceeds 64 KiB guardrail")
                if len(self._commits) >= MAX_COMMITS:
                    raise LedgerFullError("commit ledger is full")
                lines = commit_text.splitlines()
                ctype, scope, subject, bang = _parse_header(lines[0])
                body, note = _parse_body(lines[1:])
                breaking = bang or note is not None
                if commit_id is None:
                    self._counter += 1
                    commit_id = f"commit-{self._counter}"
                else:
                    if not isinstance(commit_id, str) or commit_id == "":
                        raise BadCommitError("commit_id must be a non-empty str")
                    if commit_id in self._commits:
                        raise DuplicateCommitError(f"commit id {commit_id!r} already parsed")
                digest_body = {
                    "commit_id": commit_id,
                    "type": ctype,
                    "scope": scope,
                    "subject": subject,
                    "body": list(body),
                    "breaking": breaking,
                    "breaking_note": note,
                    "version": CHANGELOG_GENERATOR_VERSION,
                }
                record = ParsedCommit(
                    commit_id=commit_id,
                    type=ctype,
                    scope=scope,
                    subject=subject,
                    body=body,
                    breaking=breaking,
                    breaking_note=note,
                    digest=_pin(digest_body),
                    seq=seq,
                )
            except ChangelogError as exc:
                self._emit("rejected", seq, error=str(exc))
                raise
            self._commits[commit_id] = record
            self._order.append(commit_id)
            self._emit("parsed", seq, commit_id=commit_id, commit_type=record.type,
                       commit_digest=record.digest)
            return record

    def commit(self, commit_id: str) -> ParsedCommit:
        """Read back one parsed commit by id."""
        with self._lock:
            try:
                return self._commits[commit_id]
            except KeyError:
                raise UnknownCommitError(f"unknown commit id {commit_id!r}")

    def commit_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(self._order)

    def commit_count(self) -> int:
        with self._lock:
            return len(self._order)

    def render(self, seq: Any, version: Optional[str] = None) -> RenderedChangelog:
        """Render the ledger into deterministic markdown."""
        with self._lock:
            seq = self._monotonic(seq)  # consumes seq even on refusal
            if version is not None and (not isinstance(version, str) or version == ""):
                raise BadVersionError("version label must be a non-empty str")
            label = version if version is not None else "Unreleased"
            title = f"## {label}"
            sections_used: List[str] = []
            lines: List[str] = [title, ""]
            for ctype, section in SECTIONS:
                entries = [self._commits[cid] for cid in self._order
                           if self._commits[cid].type == ctype]
                if not entries:
                    continue
                sections_used.append(section)
                lines.append(f"### {section}")
                lines.append("")
                for entry in entries:
                    scope = f"**{entry.scope}:** " if entry.scope else ""
                    lines.append(f"- {scope}{entry.subject}")
                lines.append("")
            breaking_notes = [e for e in (self._commits[c] for c in self._order)
                              if e.breaking and e.breaking_note]
            if breaking_notes:
                lines.append("### BREAKING CHANGES")
                lines.append("")
                for entry in breaking_notes:
                    scope = f"**{entry.scope}:** " if entry.scope else ""
                    lines.append(f"- {scope}{entry.breaking_note}")
                lines.append("")
                sections_used.append("BREAKING CHANGES")
            text = "\n".join(lines).rstrip("\n") + "\n"
            digest = _pin({"title": title, "version": label, "text": text})
            record = RenderedChangelog(
                version=label,
                title=title,
                text=text,
                sections=tuple(sections_used),
                commit_ids=tuple(self._order),
                digest=digest,
                seq=seq,
            )
            self._emit("rendered", seq, rendered_version=label,
                       section_count=len(sections_used),
                       rendered_digest=digest)
            return record

    def bump(self, current_version: str, seq: Any) -> VersionBump:
        """Book the semver bump decision from the ledger."""
        with self._lock:
            seq = self._monotonic(seq)  # consumes seq even on refusal
            major, minor, patch = _parse_semver(current_version)
            ids = tuple(self._order)
            if not ids:
                level, reason, nxt = "patch", "empty-ledger", f"{major}.{minor}.{patch + 1}"
            elif any(self._commits[c].breaking for c in ids):
                level, reason, nxt = "major", "breaking-change", f"{major + 1}.0.0"
            elif any(self._commits[c].type == "feat" for c in ids):
                level, reason, nxt = "minor", "feature", f"{major}.{minor + 1}.0"
            else:
                level, reason, nxt = "patch", "no-breaking-or-feature", f"{major}.{minor}.{patch + 1}"
            digest = _pin({
                "current": current_version,
                "next": nxt,
                "level": level,
                "reason": reason,
                "commit_ids": list(ids),
            })
            record = VersionBump(
                current=current_version,
                next=nxt,
                level=level,
                reason=reason,
                commit_ids=ids,
                digest=digest,
                seq=seq,
            )
            self._emit("bumped", seq, current=current_version, next_version=nxt,
                       level=level, reason=reason, bump_digest=digest)
            return record

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            return tuple(self._audit)


def main() -> None:
    """Self-check: parse, render, bump, refusals."""
    gen = ChangelogGenerator()
    r1 = gen.parse("feat(api): add pagination", 0)
    assert r1.type == "feat" and r1.scope == "api" and not r1.breaking
    assert r1.verify()
    r2 = gen.parse("fix: null pointer on empty cart\n\nCloses #42", 1)
    assert r2.type == "fix" and r2.body == ("", "Closes #42")
    r3 = gen.parse("refactor(db)!: drop legacy schema\n\nBREAKING CHANGE: v1 tables removed", 2)
    assert r3.breaking and r3.breaking_note == "v1 tables removed"
    changelog = gen.render(3, version="1.2.0")
    assert "### Features" in changelog.text and "### Bug Fixes" in changelog.text
    assert "### BREAKING CHANGES" in changelog.text
    assert changelog.verify(changelog.text)
    assert not changelog.verify(changelog.text + "tamper")
    bump = gen.bump("1.2.0", 4)
    assert bump.level == "major" and bump.next == "2.0.0" and bump.reason == "breaking-change"
    minor_gen = ChangelogGenerator()
    minor_gen.parse("feat: search", 0)
    b2 = minor_gen.bump("1.2.0", 1)
    assert b2.level == "minor" and b2.next == "1.3.0"
    patch_gen = ChangelogGenerator()
    patch_gen.parse("docs: typo", 0)
    b3 = patch_gen.bump("1.2.0", 1)
    assert b3.level == "patch" and b3.next == "1.2.1"
    empty_gen = ChangelogGenerator()
    b4 = empty_gen.bump("0.0.0", 0)
    assert b4.level == "patch" and b4.reason == "empty-ledger"
    for bad in ("no colon here", "WIP: done", "feat(): empty scope", "feat: ",
                "feat(BAD): uppercase scope"):
        try:
            ChangelogGenerator().parse(bad, 0)
        except BadCommitError:
            pass
        else:
            raise AssertionError(f"should have refused {bad!r}")
    try:
        ChangelogGenerator().bump("1.2", 0)
    except BadVersionError:
        pass
    else:
        raise AssertionError("should have refused non-semver")
    try:
        gen.parse("docs: seq rewind", 1)
    except SeqOrderError:
        pass
    else:
        raise AssertionError("should have refused seq rewind")
    print("changelog-generator OK: parse, render, bump, refusals, audit")


if __name__ == "__main__":
    main()
