"""Hardcoded credential detector for MCP configs and agent surfaces.

Research datum (Hush Security, 2026-10-05): ~1 in 8 MCP config credential
fields are hardcoded in public GitHub repos. A hardcoded credential in a
checked-in config is not a configuration — it is a leaked secret with a
file path.

This module scans text (config files, tool results, pastes) for known
credential shapes and reports them with masked values so the finding itself
is safe to log.

House style shared with ``compaction_masking.py``:
* patterns ordered most-specific-first; a span is claimed by the tightest
  pattern that matches it;
* every finding carries a line number (1-based), the credential type, and
  the value masked to first-2/last-2 characters — the raw secret never
  leaves this module in a finding;
* deterministic: no wall-clock, no network, no model calls; same input,
  same findings;
* fail-closed: non-str input raises ``TypeError`` rather than returning
  "no credentials".

Credential types:
* ``API_KEY``     — vendor API keys (sk-, AKIA, ghp_, xox, AIza, api_key=)
* ``PRIVATE_KEY`` — PEM-encoded private keys (BEGIN PRIVATE KEY / RSA
  PRIVATE KEY), whole block reported as one finding
* ``TOKEN``       — Bearer <redacted> / JWT-shaped / access-token assignments
* ``PASSWORD``    — password[:=] assignments

Honest scope: pattern-based detection is a backstop, not a guarantee. A
novel secret format, a credential split across lines, a credential stored
in a referenced env var (``${API_KEY}`` — correctly *not* flagged), or a
credential outside the covered shapes will pass through undetected. This
module proves *some* credentials are present; it cannot prove none are.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

#: Version of the detection rule set. Bump when patterns change so hosts can
#: pin or audit which rule set produced a scan report.
CREDENTIAL_DETECTOR_VERSION = "credential-detector.v1"


class CredentialType(str, Enum):
    """Fixed vocabulary of credential kinds this detector recognizes."""

    API_KEY = "api_key"
    PASSWORD = "password"
    TOKEN = "token"
    PRIVATE_KEY = "private_key"


@dataclass(frozen=True)
class CredentialFinding:
    """One detected hardcoded credential.

    ``masked_value`` shows the first two and last two characters with the
    middle replaced by ``*``; the raw secret is never retained in the
    finding.
    """

    credential_type: CredentialType
    masked_value: str
    line_number: int

    def __post_init__(self) -> None:
        if not isinstance(self.credential_type, CredentialType):
            raise TypeError("credential_type must be a CredentialType")
        if not isinstance(self.masked_value, str) or not self.masked_value:
            raise ValueError("masked_value must be a non-empty string")
        if (
            not isinstance(self.line_number, int)
            or isinstance(self.line_number, bool)
            or self.line_number < 1
        ):
            raise ValueError("line_number must be a positive integer")


def mask_value(raw: str) -> str:
    """Mask a secret to first-2 + asterisks + last-2.

    Values of length <= 4 keep only their length visible (``****``).
    """
    if not isinstance(raw, str):
        raise TypeError("raw must be a string")
    if len(raw) <= 4:
        return "*" * len(raw) if raw else ""
    return raw[:2] + "*" * (len(raw) - 4) + raw[-2:]


# ---------------------------------------------------------------------------
# Patterns — most-specific-first so the tightest pattern claims a span.
# ---------------------------------------------------------------------------

_PATTERNS: list[tuple[CredentialType, re.Pattern[str]]] = [
    # PEM private key block — multiline, one finding per block.
    (
        CredentialType.PRIVATE_KEY,
        re.compile(
            r"-----BEGIN (?:RSA )?PRIVATE KEY-----\s*"
            r"[A-Za-z0-9+/=\s]+?"
            r"-----END (?:RSA )?PRIVATE KEY-----"
        ),
    ),
    # Vendor API keys: Stripe/OpenAI style, AWS access keys, GitHub tokens,
    # Slack tokens, Google API keys, explicit api_key assignments.
    (
        CredentialType.API_KEY,
        re.compile(
            r"(?:"
            r"sk-[A-Za-z0-9\-_]{16,}"
            r"|AKIA[0-9A-Z]{16}"
            r"|gh[pousr]_[A-Za-z0-9]{20,}"
            r"|xox[bpras]-[A-Za-z0-9\-]{10,}"
            r"|AIza[0-9A-Za-z\-_]{35}"
            r"|(?i:api[_-]?key)\s*[:=]\s*[\"']?[A-Za-z0-9\-_.~+/=]{8,}[\"']?"
            r")"
        ),
    ),
    # Bearer <redacted> / JWT-shaped tokens / access-token assignments.
    (
        CredentialType.TOKEN,
        re.compile(
            r"(?:"
            r"[Bb]earer\s+[A-Za-z0-9\-_.~+/=]{10,}"
            r"|[A-Za-z0-9\-_]{20,}\.[A-Za-z0-9\-_]{20,}\.[A-Za-z0-9\-_]{10,}"
            r"|(?i:(?:access[_-]?)?token)\s*[:=]\s*[\"']?[A-Za-z0-9\-_.~+/=]{8,}[\"']?"
            r")"
        ),
    ),
    # Password assignments.
    (
        CredentialType.PASSWORD,
        re.compile(
            r"(?i)[\w-]*password\s*[:=]\s*[\"']?[^\s\"']{4,}[\"']?"
        ),
    ),
]


def scan_for_credentials(text: str) -> list[CredentialFinding]:
    """Scan text for hardcoded credentials.

    Returns one :class:`CredentialFinding` per match, in line order
    (then span order within a line). Matched spans are consumed by the
    first matching pattern in ``_PATTERNS`` order, so a span is never
    reported twice.

    ``${VAR}``-style env-var references are correctly *not* flagged —
    indirection is not hardcoding.
    """
    if not isinstance(text, str):
        raise TypeError("text must be a string")
    findings: list[CredentialFinding] = []
    # Multiline patterns (private keys) are searched on the whole text with
    # computed line numbers; single-line patterns run per line.
    lines = text.split("\n")
    claimed: set[tuple[int, int, int]] = set()  # (line_no, start, end)

    # 1. Multiline: private key blocks.
    priv_type, priv_re = _PATTERNS[0]
    for m in priv_re.finditer(text):
        line_no = text.count("\n", 0, m.start()) + 1
        masked = mask_value(re.sub(r"\s", "", m.group(0))[:64])
        findings.append(CredentialFinding(priv_type, masked, line_no))
        claimed.add((line_no, m.start(), m.end()))

    # 2. Single-line patterns.
    offset = 0
    for line_no, line in enumerate(lines, start=1):
        line_len = len(line)
        for cred_type, pattern in _PATTERNS[1:]:
            for m in pattern.finditer(line):
                abs_start, abs_end = offset + m.start(), offset + m.end()
                if any(
                    ln == line_no and not (abs_end <= cs or abs_start >= ce)
                    for ln, cs, ce in claimed
                ):
                    continue
                findings.append(
                    CredentialFinding(cred_type, mask_value(m.group(0)), line_no)
                )
                claimed.add((line_no, abs_start, abs_end))
        offset += line_len + 1  # +1 for the newline consumed by split

    findings.sort(key=lambda f: (f.line_number, f.masked_value))
    return findings


def main() -> None:
    sample = (
        "mcp_servers:\n"
        '  github: { token: "ghp_abcdefghij1234567890" }\n'
        '  openai: { api_key: "sk-abc123DEF456ghi789JKL" }\n'
        "db_password = hunter2\n"
        "auth = Bearer <redacted>\n"
        "safe_ref: ${API_KEY}\n"
    )
    findings = scan_for_credentials(sample)
    for f in findings:
        print(f"{f.line_number}: {f.credential_type.value} {f.masked_value}")
    print(f"scan OK: {len(findings)} finding(s)")


if __name__ == "__main__":
    main()
