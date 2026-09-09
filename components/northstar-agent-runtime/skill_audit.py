"""Skill supply-chain review: read-only, deterministic, and pinned by digest.

Why this exists
---------------
Agent Skills became an open standard fast, and the standard fixed the *format*
without fixing review. The public audits of third-party skill collections in 2026
found the same thing everywhere: almost no skill is signed, a large share carry
prompt-injection or instruction-override phrasing, and a host that reads
``SKILL.md`` into a system prompt has no way to notice that a reviewed file became a
different file. Nobody ships a checker, because a checker has opinions.

What this module refuses to be
------------------------------
It is **not** a classifier and not a model call: every rule is a pure function of the
bytes, so ``make test`` can prove it, an operator can read it, and it cannot be
prompted out of existence by the very file it is reviewing. It is **not** an allowlist
of trusted publishers either - that would require the online index this project
deliberately does not run.

What it does provide:

1. **Findings with a severity and a line number**, in three levels. ``error`` means
   "a skill that does this is an execution or escalation channel", ``warn`` means
   "a human should read this before trusting it", ``info`` is advice.
2. **One deliberate demotion.** A command inside a fenced code block is an example,
   not an instruction, so it is reported one level lower with a note. Invisible
   characters are invisible in code too, so that rule never demotes.
3. **A content digest per skill, and a lockfile of reviewed digests.** Drift is then
   a fact rather than a memory: ``skills check`` compares, ``run --require-skill-lock``
   refuses to start a run whose skills changed since review, and ``doctor`` warns.

The rules encode a position, so it can be argued with: a skill is instructions the
model reads. Anything that tells the reader to install software, talk to an
instance-metadata endpoint, read a credential file, or edit the agent's own policy is
not documentation of a workflow - it is the workflow becoming a supply chain.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Sequence

#: Bumped when a rule is added, removed, or changes meaning. A lockfile records the
#: rule version it was written under, so "no findings" from an older rule set is
#: reported as drift rather than trusted.
RULES_VERSION = "skills-rules/1"

#: Lockfile format id (the file is JSON so it diffs cleanly and needs no TOML writer).
LOCK_SCHEMA = "northstar-skills-lock/1"
LOCK_FILE_NAME = "skills.lock"

#: Trees scanned by ``--root`` when auditing a foreign checkout. The Agent Skills
#: standard fixes the file format but not the install path, so all three are read.
SKILL_TREE_GLOBS: tuple[str, ...] = (".northstar/skills", ".claude/skills", ".agents/skills")
SKILL_FILE_NAME = "SKILL.md"

SEVERITY_ORDER: dict[str, int] = {"info": 0, "warn": 1, "error": 2}

#: The open standard keeps frontmatter small; anything longer is a listing that will
#: be pasted into every session's context.
MAX_DESCRIPTION_CHARS = 1024
MAX_BODY_LINES = 500
MAX_BODY_CHARS = 20_000

# (rule id, severity, pattern, message). Patterns are matched case-insensitively on
# the *line*, which keeps the line number honest and the false positives cheap to
# explain: a rule that cannot name a line is not reviewable.
_TEXT_RULES: tuple[tuple[str, str, str, str], ...] = (
    (
        "injection.override",
        "error",
        r"\b(ignore|disregard|forget|discard)\b[^.\n]{0,40}\b(previous|prior|above|earlier|all)\b[^.\n]{0,25}\b(instructions?|rules?|prompts?|directives?)\b",
        "tells the reader to override instructions it was already given",
    ),
    (
        "injection.concealment",
        "error",
        r"\b(do not|don't|never|avoid) (tell|inform|mention|reveal|disclose|let)[^.\n]{0,30}\b(user|operator|reviewer)\b",
        "instructs the model to hide its own behaviour from the human in the loop",
    ),
    (
        "injection.role-hijack",
        "error",
        r"\b(you are now|act as if you have no|pretend (that )?you (have no|are not bound)|new system prompt|override the system prompt)\b",
        "attempts to restate the model's role or remove its constraints",
    ),
    (
        "policy.self-edit",
        "error",
        r"(edit|modify|change|rewrite|replace|append to|write to)[^.\n]{0,40}(\.northstar/config\.toml|\.claude/settings|settings\.json|permissions?\.toml|AGENTS\.md)",
        "instructs the agent to change its own policy or instructions (CBSE: config-before-self-escalation)",
    ),
    (
        "policy.self-edit",
        "error",
        r"(disable|turn off|remove)[^.\n]{0,30}(permission|sandbox|approval|gate|hook)s?\b",
        "instructs the agent to weaken the controls around it",
    ),
    (
        "execution.remote-script",
        "error",
        r"\b(curl|wget)\b[^|\n]*\|\s*(sudo\s+)?(ba|z|k|da)?sh\b",
        "pipes a remote script into a shell: the skill becomes an installer",
    ),
    (
        "execution.privilege",
        "error",
        r"\b(sudo|doas|rm -rf|chmod\s+\+x|mkfs|dd if=)\b",
        "asks for host-level or irreversible operations, which no instruction file needs",
    ),
    (
        "exfiltration.metadata-endpoint",
        "error",
        r"\b169\.254\.169\.254\b|\bmetadata\.(google\/internal|unicom)\b|/latest/meta-data",
        "reaches a cloud instance-metadata endpoint, the standard credential-theft hop",
    ),
    (
        "exfiltration.credentials",
        "error",
        r"(\.ssh/(id_[a-z0-9]+|config)|\.aws/credentials|\.netrc|\.git-credentials|\.npmrc|keychain|/etc/shadow)",
        "reads a credential store directly",
    ),
    (
        "exfiltration.environment",
        "warn",
        r"\b(printenv|env \|\s*grep|set \|\s*grep)\b"
        r"|\b(export|echo|print|cat|log|send|post|paste|dump)\b[^.\n]{0,25}\$?\{?[A-Z0-9_]*(API_KEY|AUTH_TOKEN|ACCESS_TOKEN|SECRET|PASSWORD|PASSWD|PRIVATE_KEY)\b"
        r"|\$\{?[A-Z0-9_]*(API_KEY|AUTH_TOKEN|ACCESS_TOKEN|SECRET|PASSWORD|PASSWD)\b[^.\n]{0,25}\b(echo|print|cat|curl|send|post|log)\b",
        "reads or forwards an environment value that routinely holds a credential",
    ),
    (
        "execution.installer",
        "warn",
        r"\b(pip|pip3|uv pip|poetry add|npm (install|i|add)|yarn add|pnpm add|gem install|cargo install|brew install|apt(-get)? install)\b",
        "installs packages: review the source and pin it, or run the install yourself",
    ),
    (
        "execution.evaluator",
        "warn",
        r"\b(eval|exec)\s+[\"'`$]|\bpython -c\b|\bnode -e\b|\bbash -c\b",
        "evaluates an inline payload, which no reproducible instruction needs",
    ),
    (
        "network.tunnelling",
        "warn",
        r"\b(ngrok|cloudflared|localhost\.run|serveo|transfer\.sh|webhook\.site)\b",
        "opens an outbound tunnel or throwaway endpoint: data leaves the workspace quietly",
    ),
    (
        "network.post",
        "warn",
        r"\b(curl|wget|http\.post|requests\.post|fetch)\b[^.\n]{0,60}\b(http://|https://)[^/\s\"']+",
        "sends data to a named host; confirm the destination is one you chose",
    ),
    (
        "prose.model-pressure",
        "info",
        r"\b(you must|you will|it is critical that|absolutely necessary|do not question)\b",
        "pressure phrasing; sometimes legitimate, sometimes an attempt to harden an instruction against review",
    ),
)

#: Characters a reviewer cannot see. Never demoted for being inside a code block.
_INVISIBLE = (
    ("zero-width character", re.compile("[\u200b\u200c\u200d\u2060\ufeff]")),
    ("bidi control character", re.compile("[\u202a-\u202e\u2066-\u2069]")),
    ("tag character", re.compile("[\ue000-\uf8ff]")),
)
_CODE_FENCE = re.compile(r"^\s*(```|~~~)")
_FRONTMATTER_DELIMITER = "---"


class SkillAuditError(ValueError):
    """Raised for an unusable audit target (unreadable file, bad lockfile)."""


@dataclass(frozen=True)
class Finding:
    """One rule hit at one line."""

    rule: str
    severity: str
    line: int
    detail: str
    excerpt: str = ""

    def as_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"rule": self.rule, "severity": self.severity, "line": self.line, "detail": self.detail}
        if self.excerpt:
            payload["excerpt"] = self.excerpt
        return payload


@dataclass(frozen=True)
class SkillAudit:
    """The review result for one skill file."""

    name: str
    relative_path: str
    digest: str
    size_bytes: int
    body_lines: int
    description_chars: int
    findings: tuple[Finding, ...] = ()
    parse_error: str = ""

    @property
    def worst(self) -> str:
        if not self.findings:
            return "clean"
        return max((finding.severity for finding in self.findings), key=lambda severity: SEVERITY_ORDER[severity])

    def highest_severity(self) -> int:
        return max((SEVERITY_ORDER[finding.severity] for finding in self.findings), default=-1)

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "path": self.relative_path,
            "digest": self.digest,
            "size_bytes": self.size_bytes,
            "body_lines": self.body_lines,
            "description_chars": self.description_chars,
            "worst": self.worst,
            "parse_error": self.parse_error,
            "findings": [finding.as_dict() for finding in self.findings],
        }


def digest_of(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _demote(severity: str) -> tuple[str, str]:
    """Inside a fenced block, a command is an example, not an instruction."""
    if severity == "error":
        return "warn", " (inside a fenced block: reported one level lower, as an example rather than an instruction)"
    if severity == "warn":
        return "info", " (inside a fenced block: reported as advice)"
    return severity, ""


def scan_text(text: str) -> tuple[Finding, ...]:
    """Apply the line rules to one skill file's text (frontmatter included)."""
    findings: list[Finding] = []
    compiled: list[tuple[str, str, re.Pattern[str], str]] = [
        (rule, severity, re.compile(pattern, re.IGNORECASE), message) for rule, severity, pattern, message in _TEXT_RULES
    ]
    in_fence = False
    for number, line in enumerate(text.splitlines(), start=1):
        if _CODE_FENCE.match(line):
            in_fence = not in_fence
            continue
        for label, pattern in _INVISIBLE:
            if pattern.search(line):
                findings.append(
                    Finding(
                        rule=f"unicode.{label.split(' ')[0]}",
                        severity="error",
                        line=number,
                        detail=f"{label} present: text a reviewer cannot see cannot be reviewed",
                    )
                )
        for rule, severity, pattern, message in compiled:
            if pattern.search(line):
                shown = line.strip()[:120]
                if in_fence:
                    severity, note = _demote(severity)
                    message = message + note
                findings.append(Finding(rule=rule, severity=severity, line=number, detail=message, excerpt=shown))
    # Two patterns of the same rule hitting one line is one finding; repeating it
    # makes a report look louder than the file is without adding information.
    merged: dict[tuple[str, int], Finding] = {}
    for finding in findings:
        key = (finding.rule, finding.line)
        previous = merged.get(key)
        if previous is None:
            merged[key] = finding
            continue
        if SEVERITY_ORDER[finding.severity] > SEVERITY_ORDER[previous.severity]:
            merged[key] = finding
    return tuple(merged.values())


def audit_text(name: str, text: str, *, relative_path: str = "", raw: bytes | None = None) -> SkillAudit:
    """Review one skill's text without touching the filesystem."""
    body = text
    description_chars = 0
    findings: list[Finding] = []
    lines = text.splitlines()
    if lines and lines[0].strip() == _FRONTMATTER_DELIMITER:
        for index in range(1, len(lines)):
            if lines[index].strip() == _FRONTMATTER_DELIMITER:
                frontmatter = "\n".join(lines[1:index])
                body = "\n".join(lines[index + 1 :])
                for field_line in frontmatter.splitlines():
                    if field_line.strip().lower().startswith("description:"):
                        description_chars = len(field_line.split(":", 1)[1].strip().strip("\"'"))
                break
        else:
            findings.append(Finding("frontmatter.unterminated", "error", 1, "frontmatter opens with --- but never closes"))
    digest = digest_of((raw if raw is not None else text.encode("utf-8")))
    body_lines = len(body.splitlines())
    if description_chars > MAX_DESCRIPTION_CHARS:
        findings.append(
            Finding(
                "spec.description-too-long",
                "warn",
                1,
                f"description is {description_chars} chars; the standard caps it at {MAX_DESCRIPTION_CHARS} and this text is injected into every session that loads the skill",
            )
        )
    if not description_chars:
        findings.append(
            Finding("spec.description-missing", "error", 1, "no description: the description is the trigger text, so the skill can never be selected safely")
        )
    if body_lines > MAX_BODY_LINES:
        findings.append(
            Finding(
                "spec.body-too-long-lines",
                "warn",
                1,
                f"body is {body_lines} lines (progressive disclosure expects < {MAX_BODY_LINES}); move detail into a linked file the model reads on demand",
            )
        )
    if len(body) > MAX_BODY_CHARS:
        findings.append(
            Finding(
                "spec.body-too-long-size",
                "warn",
                1,
                f"body is {len(body)} chars (> {MAX_BODY_CHARS}), so one skill can dominate the context window",
            )
        )
    findings.extend(scan_text(text))
    findings.sort(key=lambda finding: (-SEVERITY_ORDER[finding.severity], finding.line, finding.rule))
    return SkillAudit(
        name=name,
        relative_path=relative_path,
        digest=digest,
        size_bytes=len(raw if raw is not None else text.encode("utf-8")),
        body_lines=body_lines,
        description_chars=description_chars,
        findings=tuple(findings),
    )


def audit_file(path: Path | str, *, root: Path | str | None = None) -> SkillAudit:
    """Review one ``SKILL.md``. Unreadable files become a finding, not a crash."""
    path = Path(path)
    try:
        raw = path.read_bytes()
    except OSError as error:
        return SkillAudit(
            name=path.parent.name,
            relative_path=_relative(path, root),
            digest="",
            size_bytes=0,
            body_lines=0,
            description_chars=0,
            parse_error=f"cannot read: {error}",
            findings=(Finding("io.unreadable", "error", 0, f"cannot read the skill file: {error}"),),
        )
    text = raw.decode("utf-8", errors="replace")
    declared = _declared_name(text) or path.parent.name
    result = audit_text(declared, text, relative_path=_relative(path, root), raw=raw)
    if path.parent.name != declared:
        # Not fatal, but a skill whose folder and name disagree is how a review gets
        # pointed at the wrong file after a rename.
        drifted = Finding(
            "spec.name-mismatch",
            "warn",
            1,
            f"folder is {path.parent.name!r} but the frontmatter name is {declared!r}; the listing and the lockfile will not line up",
        )
        result = SkillAudit(
            name=result.name,
            relative_path=result.relative_path,
            digest=result.digest,
            size_bytes=result.size_bytes,
            body_lines=result.body_lines,
            description_chars=result.description_chars,
            findings=tuple(sorted(result.findings + (drifted,), key=lambda f: (-SEVERITY_ORDER[f.severity], f.line, f.rule))),
        )
    return result


def _declared_name(text: str) -> str:
    lines = text.splitlines()
    if not lines or lines[0].strip() != _FRONTMATTER_DELIMITER:
        return ""
    for index, line in enumerate(lines[1:], start=1):
        if line.strip() == _FRONTMATTER_DELIMITER:
            break
        if line.strip().lower().startswith("name:"):
            return line.split(":", 1)[1].strip().strip("\"'")
    return ""


def _relative(path: Path, root: Path | str | None) -> str:
    if root is None:
        return path.name
    try:
        return str(path.resolve().relative_to(Path(root).resolve()))
    except (OSError, ValueError):
        return path.name


def skill_files(root: Path | str, *, trees: Sequence[str] = SKILL_TREE_GLOBS) -> tuple[Path, ...]:
    """Every ``SKILL.md`` under the known skill install paths of one checkout."""
    base = Path(root)
    found: list[Path] = []
    for pattern in trees:
        directory = base / pattern
        if not directory.is_dir():
            continue
        for entry in sorted(directory.iterdir()):
            candidate = entry / SKILL_FILE_NAME
            if entry.is_dir() and candidate.is_file():
                found.append(candidate)
    return tuple(found)


def audit_tree(root: Path | str, *, trees: Sequence[str] = SKILL_TREE_GLOBS) -> tuple[SkillAudit, ...]:
    """Review a whole checkout, including foreign ``.claude`` / ``.agents`` trees."""
    base = Path(root)
    return tuple(audit_file(path, root=base) for path in skill_files(base, trees=trees))


def summarise(audits: Iterable[SkillAudit]) -> dict[str, Any]:
    """The aggregate a CLI or CI job reads."""
    audits = list(audits)
    counts = {"error": 0, "warn": 0, "info": 0}
    rules: dict[str, int] = {}
    for audit in audits:
        for finding in audit.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
            rules[finding.rule] = rules.get(finding.rule, 0) + 1
    return {
        "skills": len(audits),
        "clean": sum(1 for audit in audits if not audit.findings),
        "flagged": sum(1 for audit in audits if audit.findings),
        "unreadable": sum(1 for audit in audits if audit.parse_error),
        "findings": counts,
        "by_rule": dict(sorted(rules.items(), key=lambda item: (-item[1], item[0]))),
        "worst_skill": _worst_skill(audits),
    }


def _worst_skill(audits: Sequence[SkillAudit]) -> str:
    """The skill with the most severe finding, for one-line CI output."""
    ranked = [(audit.highest_severity(), index, audit.name) for index, audit in enumerate(audits)]
    if not ranked:
        return ""
    return max(ranked)[2]


def threshold_met(audits: Sequence[SkillAudit], fail_on: str) -> bool:
    """True when any finding is at or above ``fail_on`` (``never`` disables the gate)."""
    if fail_on == "never":
        return False
    bar = SEVERITY_ORDER.get(fail_on)
    if bar is None:
        raise SkillAuditError(f"unknown --fail-on {fail_on!r}; expected error, warn, info or never")
    return any(audit.highest_severity() >= bar for audit in audits)


# -- lockfile: what a reviewed skill set looks like on disk -------------------


def lock_payload(audits: Sequence[SkillAudit], *, source: str = "") -> dict[str, Any]:
    entries: dict[str, Any] = {}
    # Keyed by path, not by the frontmatter name: discovery reads the folder, so the
    # folder is the identity a pin has to bind. A rename or a name edit then shows up
    # as "added" plus "missing" rather than silently inheriting someone else's review.
    for audit in sorted(audits, key=lambda item: item.relative_path):
        entries[audit.relative_path] = {
            "name": audit.name,
            "digest": audit.digest,
            "size_bytes": audit.size_bytes,
            "findings": len(audit.findings),
            "worst": audit.worst,
        }
    payload: dict[str, Any] = {"schema": LOCK_SCHEMA, "rules": RULES_VERSION, "skills": entries}
    if source:
        payload["source"] = source
    return payload


def write_lock(path: Path | str, audits: Sequence[SkillAudit], *, source: str = "") -> dict[str, Any]:
    payload = lock_payload(audits, source=source)
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return payload


def load_lock(path: Path | str) -> dict[str, Any]:
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except OSError as error:
        raise SkillAuditError(f"cannot read {path}: {error}") from error
    except ValueError as error:
        raise SkillAuditError(f"{path}: not valid JSON: {error}") from error
    if not isinstance(payload, dict) or payload.get("schema") != LOCK_SCHEMA:
        raise SkillAuditError(f"{path}: expected a {LOCK_SCHEMA} lockfile")
    if not isinstance(payload.get("skills"), dict):
        raise SkillAuditError(f"{path}: 'skills' must be an object")
    return payload


@dataclass
class LockStatus:
    """Comparison of a reviewed set against a live one."""

    present: bool
    rules_match: bool
    stale: list[str] = field(default_factory=list)  # digest changed since review
    removed: list[str] = field(default_factory=list)  # pinned but no longer present
    added: list[str] = field(default_factory=list)  # present but never reviewed

    @property
    def clean(self) -> bool:
        return self.present and self.rules_match and not (self.stale or self.removed or self.added)

    def as_dict(self) -> dict[str, Any]:
        return {
            "present": self.present,
            "rules_match": self.rules_match,
            "rules_expected": RULES_VERSION,
            "stale": sorted(self.stale),
            "removed": sorted(self.removed),
            "added": sorted(self.added),
            "clean": self.clean,
        }

    def summary(self) -> str:
        if not self.present:
            return "no lockfile - this skill set was never reviewed"
        parts: list[str] = []
        if self.stale:
            parts.append(f"changed since review: {', '.join(sorted(self.stale))}")
        if self.added:
            parts.append(f"unreviewed: {', '.join(sorted(self.added))}")
        if self.removed:
            parts.append(f"pinned but missing: {', '.join(sorted(self.removed))}")
        if not self.rules_match:
            parts.append("reviewed under an older rule set")
        return "; ".join(parts) or "all pinned skills match their reviewed digest"


def check_lock(audits: Sequence[SkillAudit], payload: dict[str, Any]) -> LockStatus:
    status = LockStatus(present=True, rules_match=payload.get("rules") == RULES_VERSION)
    pinned: dict[str, Any] = dict(payload.get("skills") or {})
    live = {audit.relative_path: audit for audit in audits}
    for path, entry in pinned.items():
        expected = str(entry.get("digest", "")) if isinstance(entry, dict) else ""
        label = f"{path}" if isinstance(entry, dict) and not entry.get("name") else f"{entry.get('name')} ({path})"
        current = live.get(path)
        if current is None:
            status.removed.append(label)
        elif not expected or current.digest != expected:
            status.stale.append(label)
    for path, audit in live.items():
        if path not in pinned:
            status.added.append(f"{audit.name} ({path})")
    return status


def lock_path_for(workspace: str | Path) -> Path:
    return Path(workspace) / ".northstar" / LOCK_FILE_NAME


__all__ = [
    "Finding",
    "LOCK_FILE_NAME",
    "LOCK_SCHEMA",
    "LockStatus",
    "RULES_VERSION",
    "SEVERITY_ORDER",
    "SKILL_TREE_GLOBS",
    "SkillAudit",
    "SkillAuditError",
    "audit_file",
    "audit_text",
    "audit_tree",
    "check_lock",
    "digest_of",
    "load_lock",
    "lock_path_for",
    "lock_payload",
    "scan_text",
    "skill_files",
    "summarise",
    "threshold_met",
    "write_lock",
]
