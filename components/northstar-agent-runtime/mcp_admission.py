"""MCP server admission: scan what a config declares, then hold the line.

Two halves that belong together, absorbed from two independent projects that
converged on the same shape:

* The **scanner** reads an MCP config the way ``mcp_config`` reads it, but
  asks a different question: not "can we start this" but "should we trust
  this". The detection taxonomy comes from supply-chain-guard's
  ``mcp-scanner.ts`` (malicious server packages, C2 endpoints, secret
  forwarding, tool-description injection, unpinned ``npx -y``), reimplemented
  here as pure functions of the bytes - deterministic, offline, no model, no
  network - because a scanner that needs the network to decide is a scanner
  that fails open when the network is the attack.
* The **raise-only policy** is Doberman-Core's ``policy/drift.py`` discipline
  applied to admission: a policy may *tighten* freely (a scan finding can move
  a server from ``allow`` to ``auth`` to ``blocked`` on its own), but any
  *weakening* must be deliberate - classified, gated behind an explicit
  audited approval with a rendered before/after diff, and recorded in an
  append-only hash-chained ledger. Ambiguous or mixed changes classify as
  weaken (fail safe). The read side clamps: a hand-edit of the policy file
  that bypassed the gate is caught by replaying the ledger and clamped back
  to the stronger state (fail closed).

The admission levels, strongest first:

* ``blocked`` - the server is not admitted, period. Scanner-gated.
* ``auth`` - the server may be admitted, but every tool call needs approval.
* ``allow`` - the server is admitted; its tools follow the normal
  ``--allow-tool`` rules.
* *absent* - no admission decision recorded. The policy is an *opinion* layer:
  absence means "no opinion", and the classifier treats it with explicit
  rules rather than a rank - recording a restrictive opinion (``blocked`` /
  ``auth``) where none existed is a strengthening, recording ``allow`` is a
  permission grant that goes through the gate. "We never decided" is not a
  loophole in either direction.

What this module is not:

* It is not a threat-intel feed. The known-bad package list is a small
  curated sample (``KNOWN_BAD_PACKAGES``), versioned with the rules. A clean
  scan is "nothing on the list matched", never "this server is safe" - the
  report says so out loud.
* It is not the import gate. ``mcp_config`` decides what *can* start;
  admission decides what *may* be trusted. ``apply_admission_policy`` is the
  seam between them: feed it an ``McpImport`` and a policy and it splits
  admitted from refused, without changing what ``discover`` does on its own.
* The weakening gate is not multi-factor auth. Doberman-Core gates weakening
  behind a possession factor; this runtime has no auth infrastructure, so the
  gate here is *deliberateness*: a weakening requires an explicit approval
  record (who, why, the exact diff) written to the ledger. It can never be
  silent, never automatic, and every denial is ledgered too - the denials are
  the attack signal.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any, Mapping, Sequence

#: Bumped when a rule is added, removed, or changes meaning. A scan report
#: records the rule version it ran under, so "no findings" from an older rule
#: set is reported as drift rather than trusted (same habit as
#: ``skill_audit.RULES_VERSION``).
RULES_VERSION = "mcp-admission-rules/1"

#: Identity of admission decisions, reported in scan/policy dicts so a log line
#: can say which rules produced it.
ADMISSION_VERSION = "northstar.mcp-admission.v1"

#: Where the admission policy and its ledger live, next to the workspace policy
#: file. Both are JSON so they diff cleanly.
POLICY_DIRECTORY = ".northstar"
POLICY_FILE_NAME = "mcp-admission.json"
LEDGER_FILE_NAME = "mcp-admission-ledger.jsonl"
LEDGER_SCHEMA = "northstar-mcp-admission-ledger/1"


# ---------------------------------------------------------------------------
# Scanner: what the config declares
# ---------------------------------------------------------------------------

#: Severity ladder. ``ok`` means no finding at ``high`` or above.
SEVERITIES: tuple[str, ...] = ("critical", "high", "medium", "low")

#: Curated sample of known-hostile MCP server packages: name -> bad versions.
#: Sourced from supply-chain-guard's bundled threat intel (postmark-mcp was
#: the first documented hostile MCP server, Sep 2025; the @squawk/* entries
#: are Mini Shai-Hulud / TeamPCP hijacks, May 2026). This is a *sample*, not a
#: feed: absence from this list proves nothing, and the scan report says so.
#: Version-pinned on purpose: a name alone is not a verdict.
KNOWN_BAD_PACKAGES: dict[str, tuple[str, ...]] = {
    # postmark-mcp: developer-introduced hidden BCC of every outbound email
    # to an attacker-controlled address. 1.0.15 and earlier are clean.
    "postmark-mcp": ("1.0.16",),
    # @squawk/mcp, @squawk/weather, @squawk/flightplan: Mini Shai-Hulud /
    # TeamPCP npm hijacks carrying a worm payload.
    "@squawk/mcp": ("0.9.5",),
    "@squawk/weather": ("0.5.10",),
    "@squawk/flightplan": ("0.5.6",),
    # @vite-mcp/vite-type: ChainVeil RAT ("ViteVenom" campaign).
    "@vite-mcp/vite-type": ("1.0.0",),
    # @copilot-mcp/apex: AMOS stealer (Apex macOS infostealer campaign).
    "@copilot-mcp/apex": ("1.0.0",),
}

#: Env var names that look like forwarded credentials (same shape as
#: supply-chain-guard's CREDENTIAL_ENV_REGEX).
CREDENTIAL_ENV_REGEX = re.compile(r"TOKEN|SECRET|KEY|PASSWORD|CREDENTIAL", re.IGNORECASE)

#: Literal secret prefixes: a checked-in value starting with one of these is
#: a live credential in the file, worse than a ``${VAR}`` reference.
LITERAL_SECRET_PREFIXES: tuple[str, ...] = (
    "sk-",
    "sk-ant-",
    "ghp_",
    "gho_",
    "github_pat_",
    "xoxb-",
    "xoxp-",
    "AKIA",
    "AIza",
)

#: Hostnames that are local-only and safe to reach over plain http.
LOCALHOST_NAMES = frozenset({"localhost", "127.0.0.1", "::1", "[::1]", "0.0.0.0"})

#: Prompt-injection signals for tool description / instruction strings,
#: adapted from supply-chain-guard's PROMPT_INJECTION_PATTERNS. MCP
#: descriptions are fed verbatim to the model, so a description is an
#: instruction channel (tool poisoning). Patterns are conservative on
#: purpose: role-control tokens and imperative override prose, not vibes.
INJECTION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (rule, re.compile(pattern, re.IGNORECASE))
    for rule, pattern in (
        # Anthropic-style <system-reminder> / <system-prompt> tags.
        ("MCP_INJECTION_SYSTEM_TAG", r"<\s*/?\s*system[-_](?:reminder|prompt|message|instruction)\s*>"),
        # ChatML role boundaries: <|im_start|>system ... <|im_end|>.
        ("MCP_INJECTION_CHATML", r"<\|\s*im_(?:start|end|sep)\s*\|>"),
        # Mistral/Llama instruction tags: [INST] ... [/INST].
        ("MCP_INJECTION_INST_TAG", r"\[\s*/?\s*INST\s*\]"),
        # Generic role-control tokens: <|system|>, <|user|>, <|assistant|> ...
        ("MCP_INJECTION_ROLE_TOKEN", r"<\|\s*(?:system|user|assistant|developer|function|tool)\s*\|>"),
        # Natural-language override prose, imperative form only, so prose
        # *about* prompt injection does not match.
        (
            "MCP_INJECTION_OVERRIDE_PROSE",
            r"(?:^|[.!?\n]\s*)(?:please\s+)?(?:ignore|disregard|forget|override)\s+"
            r"(?:all\s+)?(?:previous|prior|above|earlier|the\s+system)\s+"
            r"(?:instructions?|prompts?|messages?|rules?|directives?|context)",
        ),
    )
)

#: Keys whose string values are instruction-shaped and therefore scanned for
#: injection. ``description`` is the MCP-native one; the rest are the shapes
#: hostile servers have used to smuggle instructions past config review.
INSTRUCTION_KEYS: tuple[str, ...] = ("description", "instructions", "systemPrompt", "prompt")


@dataclass(frozen=True)
class AdmissionFinding:
    """One scanner verdict about one server. Pure function of the config."""

    rule: str
    severity: str  # critical | high | medium | low
    server: str
    message: str
    recommendation: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "rule": self.rule,
            "severity": self.severity,
            "server": self.server,
            "message": self.message,
            "recommendation": self.recommendation,
        }


@dataclass(frozen=True)
class AdmissionScan:
    """What the scanner found across a workspace's MCP configs."""

    findings: tuple[AdmissionFinding, ...] = ()
    servers_scanned: int = 0
    files: tuple[str, ...] = ()
    version: str = ADMISSION_VERSION
    rules_version: str = RULES_VERSION

    @property
    def ok(self) -> bool:
        """No finding at high or above. Low/medium are advice, not a veto."""
        return not any(f.severity in ("critical", "high") for f in self.findings)

    def worst_for(self, server: str) -> str | None:
        """Worst severity recorded for a server, or None when clean."""
        order = {name: index for index, name in enumerate(SEVERITIES)}
        worst: str | None = None
        for finding in self.findings:
            if finding.server != server:
                continue
            if worst is None or order[finding.severity] < order[worst]:
                worst = finding.severity
        return worst

    def as_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "rules_version": self.rules_version,
            "files": list(self.files),
            "servers_scanned": self.servers_scanned,
            "ok": self.ok,
            "findings": [f.as_dict() for f in self.findings],
        }


@dataclass(frozen=True)
class _PackageSpec:
    ecosystem: str  # npm | pypi
    name: str
    version: str | None = None


def _first_positional(args: Sequence[str]) -> str | None:
    for arg in args:
        if arg and not arg.startswith("-"):
            return arg
    return None


def _split_spec(spec: str) -> tuple[str, str | None]:
    """Split "name@1.2.3" / "@scope/name@1.2.3" / "name==1.2.3" into name+version."""
    eq = spec.find("==")
    if eq > 0:
        return spec[:eq], spec[eq + 2 :]
    at = spec.rfind("@")
    if at > 0:  # a leading @ is an npm scope, not a version separator
        return spec[:at], spec[at + 1 :]
    return spec, None


def extract_package_spec(command: str, args: Sequence[str]) -> _PackageSpec | None:
    """Which package a server command launches, if it launches a package.

    npx/bunx -> npm, uvx/pipx -> pypi, ``python -m <mod>`` -> pypi (module
    name approximates the package), ``node .../node_modules/<pkg>/...`` ->
    npm. Anything else (a workspace script, a system binary) is not a
    registry package and returns None - the blocklist cannot judge it.
    """
    base = Path(command).name
    base = re.sub(r"\.(exe|cmd|bat)$", "", base, flags=re.IGNORECASE).lower()
    str_args = [str(a) for a in args]
    if base in ("npx", "bunx"):
        spec = _first_positional(str_args)
        if spec is None:
            return None
        name, version = _split_spec(spec)
        return _PackageSpec(ecosystem="npm", name=name, version=version)
    if base in ("uvx", "pipx"):
        spec = _first_positional(str_args)
        if spec is None:
            return None
        name, version = _split_spec(spec)
        return _PackageSpec(ecosystem="pypi", name=name, version=version)
    if base in ("python", "python3", "py"):
        try:
            module = str_args[str_args.index("-m") + 1]
        except (ValueError, IndexError):
            return None
        return _PackageSpec(ecosystem="pypi", name=module)
    if base == "node":
        for arg in str_args:
            norm = arg.replace("\\", "/")
            idx = norm.rfind("node_modules/")
            if idx == -1:
                continue
            parts = norm[idx + len("node_modules/") :].split("/")
            if parts[0].startswith("@") and len(parts) > 1:
                return _PackageSpec(ecosystem="npm", name=f"{parts[0]}/{parts[1]}")
            if parts[0]:
                return _PackageSpec(ecosystem="npm", name=parts[0])
        return None
    return None


def _is_localhost_url(url: str) -> bool:
    match = re.match(r"^https?://([^/:?#]+)", url, re.IGNORECASE)
    return bool(match and match.group(1).lower() in LOCALHOST_NAMES)


def _instruction_strings(settings: Mapping[str, Any]) -> list[tuple[str, str]]:
    """(key, value) pairs that are instruction-shaped. Nested one level deep:
    a hostile server hides its prompt in ``inputSchema.description`` as happily
    as in the top-level ``description``."""
    found: list[tuple[str, str]] = []
    for key in INSTRUCTION_KEYS:
        value = settings.get(key)
        if isinstance(value, str) and value.strip():
            found.append((key, value))
    for key, value in settings.items():
        if isinstance(value, Mapping):
            for inner_key in INSTRUCTION_KEYS:
                inner = value.get(inner_key)
                if isinstance(inner, str) and inner.strip():
                    found.append((f"{key}.{inner_key}", inner))
    return found


def scan_server(name: str, settings: Mapping[str, Any]) -> tuple[AdmissionFinding, ...]:
    """Scan one server entry. Pure function: no IO, no network, no model."""
    findings: list[AdmissionFinding] = []
    command = settings.get("command") if isinstance(settings.get("command"), str) else None
    raw_args = settings.get("args")
    args = [str(a) for a in raw_args] if isinstance(raw_args, list) else []
    url = settings.get("url") if isinstance(settings.get("url"), str) else None
    env = settings.get("env") if isinstance(settings.get("env"), Mapping) else {}

    # 1. Malicious server package: exact name@version match on the blocklist.
    if command:
        spec = extract_package_spec(command, args)
        if spec is not None:
            bad_versions = KNOWN_BAD_PACKAGES.get(spec.name)
            if bad_versions is not None and (spec.version is None or spec.version in bad_versions):
                pinned = f"@{spec.version}" if spec.version else " (unpinned: cannot prove a clean version)"
                findings.append(
                    AdmissionFinding(
                        rule="MCP_MALICIOUS_SERVER_PACKAGE",
                        severity="critical",
                        server=name,
                        message=(
                            f'server "{name}" launches known-hostile package {spec.name}{pinned}; '
                            "this package version carried a hostile payload"
                        ),
                        recommendation=(
                            f'Remove the "{name}" server entry. If the server is needed, pin a '
                            "release published before the compromise and verify its provenance "
                            "out of band. Rotate any credentials the server could have seen."
                        ),
                    )
                )
            elif bad_versions is not None:
                findings.append(
                    AdmissionFinding(
                        rule="MCP_SUSPICIOUS_SERVER_PACKAGE",
                        severity="high",
                        server=name,
                        message=(
                            f'server "{name}" launches {spec.name}@{spec.version}, a package family '
                            "with a known-hostile release; the pinned version is not on the "
                            "blocklist but the family is compromised"
                        ),
                        recommendation=(
                            f'Verify {spec.name}@{spec.version} out of band before admitting '
                            f'"{name}": check the registry advisory, the diff from the last '
                            "reviewed release, and the publisher identity."
                        ),
                    )
                )
            # 2. Unpinned npx/uvx -y: every start silently installs registry-latest,
            #    so a hijacked release becomes a rug-pull with no config change.
            if spec.version is None and any(a in ("-y", "--yes") for a in args):
                findings.append(
                    AdmissionFinding(
                        rule="MCP_UNPINNED_SERVER",
                        severity="low",
                        server=name,
                        message=(
                            f'server "{name}" runs "{Path(command).name} -y {spec.name}" without a '
                            "pinned version; every agent start installs whatever is latest"
                        ),
                        recommendation=(
                            f"Pin the server package ({spec.name}@x.y.z) to an audited release so "
                            "a hijacked publish cannot auto-install."
                        ),
                    )
                )

    # 3. Remote endpoints: plain http to a non-localhost host travels
    #    unencrypted; tool calls and any forwarded env travel with it.
    if url and re.match(r"^http://", url, re.IGNORECASE) and not _is_localhost_url(url):
        findings.append(
            AdmissionFinding(
                rule="MCP_HTTP_ENDPOINT",
                severity="medium",
                server=name,
                message=f'server "{name}" uses a plain-http remote endpoint ({url})',
                recommendation="Switch the endpoint to https, or bind the server to localhost if it is meant to run locally.",
            )
        )

    # 4. Secret forwarding: credential-looking env var names handed to the
    #    server process. A hostile server exfiltrates everything it receives.
    secret_vars = sorted(k for k in env if isinstance(k, str) and CREDENTIAL_ENV_REGEX.search(k))
    if secret_vars:
        remote = url is not None
        findings.append(
            AdmissionFinding(
                rule="MCP_ENV_SECRET_FORWARDING",
                severity="medium" if remote else "low",
                server=name,
                message=(
                    f'server "{name}" receives credential-looking env var(s) '
                    f"({', '.join(secret_vars)})"
                    + (f" and talks to a remote endpoint ({url})" if remote else " via its local command")
                ),
                recommendation=(
                    "Verify the endpoint is trusted before forwarding secrets; a hostile MCP "
                    "server can exfiltrate every env var it receives. Prefer per-run "
                    "explicit grants over checked-in forwarding."
                    if remote
                    else "Verify the launched server package is trusted and pinned; forwarded secrets are readable by the server process."
                ),
            )
        )
    # 4b. Literal secrets: a checked-in *value* that looks live is worse than
    #     a ${VAR} reference - the reference at least keeps the secret out of
    #     the repository.
    for key, value in sorted(env.items()):
        if not isinstance(value, str) or "${" in value:
            continue
        if value.startswith(LITERAL_SECRET_PREFIXES) or (len(value) >= 32 and len(set(value)) >= 20):
            findings.append(
                AdmissionFinding(
                    rule="MCP_ENV_LITERAL_SECRET",
                    severity="high",
                    server=name,
                    message=f'server "{name}" carries a literal secret-shaped value in env.{key} (checked into the config file)',
                    recommendation=(
                        f"Remove the literal value from env.{key}; reference it as "
                        "${" + key + "} instead and rotate the credential - it is now in the repository's history."
                    ),
                )
            )
            break  # one literal-secret finding per server is enough signal

    # 5. Tool-description injection: descriptions are fed verbatim to the
    #    model, so an instruction smuggled into one is tool poisoning.
    for key, value in _instruction_strings(settings):
        for rule, pattern in INJECTION_PATTERNS:
            if pattern.search(value):
                findings.append(
                    AdmissionFinding(
                        rule="MCP_DESCRIPTION_INJECTION",
                        severity="high",
                        server=name,
                        message=f'server "{name}" embeds a prompt-injection signal ({rule}) in its "{key}" string',
                        recommendation="Remove the injected instruction text. MCP descriptions reach the model verbatim and can hijack its behavior.",
                    )
                )
                break
        else:
            continue
        break  # one injection finding per server is enough signal

    return tuple(findings)


def scan_document(path: Path) -> tuple[AdmissionFinding, ...]:
    """Scan one config file's server entries. Malformed JSON scans as empty:
    ``mcp_config`` already refuses it loudly; the scanner does not double as a
    parser."""
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return ()
    if not isinstance(document, Mapping):
        return ()
    table = document.get("mcpServers", document.get("servers"))
    if not isinstance(table, Mapping):
        return ()
    findings: list[AdmissionFinding] = []
    for name, settings in sorted(table.items()):
        if isinstance(settings, Mapping):
            findings.extend(scan_server(str(name), settings))
    return tuple(findings)


def scan_workspace(
    workspace: str | Path,
    *,
    candidates: Sequence[str] | None = None,
) -> AdmissionScan:
    """Scan every MCP config file a workspace declares. Read-only."""
    from mcp_config import CONFIG_CANDIDATES  # local import: same component

    base = Path(workspace)
    files: list[str] = []
    findings: list[AdmissionFinding] = []
    servers = 0
    for relative in tuple(candidates) if candidates is not None else CONFIG_CANDIDATES:
        path = base / relative
        if not path.is_file():
            continue
        files.append(relative)
        file_findings = scan_document(path)
        findings.extend(file_findings)
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
            table = document.get("mcpServers", document.get("servers")) if isinstance(document, dict) else None
            if isinstance(table, dict):
                servers += len(table)
        except (OSError, ValueError):
            pass
    return AdmissionScan(
        findings=tuple(findings),
        servers_scanned=servers,
        files=tuple(files),
    )


# ---------------------------------------------------------------------------
# Raise-only admission policy
# ---------------------------------------------------------------------------


class AdmissionLevel(StrEnum):
    """Admission levels, strongest protection first."""

    blocked = "blocked"
    auth = "auth"
    allow = "allow"


class Classification(StrEnum):
    """How a proposed policy change affects protection."""

    strengthen = "strengthen"
    weaken = "weaken"
    neutral = "neutral"


#: Protection rank of a recorded admission level (higher = stronger
#: protection). Absence is *not* on this scale: it means "no admission opinion
#: recorded", and :func:`classify_change` handles it with explicit rules
#: instead of a rank, because absence plays two roles the scale cannot hold -
#: it is both "nothing recorded" and "nothing granted".
_RANK: dict[str, int] = {
    "blocked": 3,
    "auth": 2,
    "allow": 1,
}
#: An unrecognized token ranks mid - conservative, never "no protection".
_UNKNOWN_TOKEN_RANK = 2


def _rank(level: str) -> tuple[int, bool]:
    """(rank, known) for a recorded level. Unknown tokens fail safe."""
    rank = _RANK.get(level)
    if rank is None:
        return _UNKNOWN_TOKEN_RANK, False
    return rank, True


def _normalize(level: str | None) -> str | None:
    """The level name ``"absent"`` and None both mean "no recorded decision"."""
    if level is None or level == "absent":
        return None
    return level


def classify_change(before: str | None, after: str | None) -> Classification:
    """Label a proposed admission change. Ambiguous or mixed -> weaken.

    ``before``/``after`` are level names, ``"absent"``, or None for no
    recorded decision. The gate guards the direction toward *permission*:

    * recording a restrictive opinion (``blocked``/``auth``) where none
      existed is a strengthening - it can never grant;
    * recording ``allow`` where none existed is a weakening: an explicit
      trust grant goes through the gate;
    * removing a ``blocked`` decision is a weakening (an explicit refusal is
      lost); removing ``auth``/``allow`` changes nothing at the seam and is
      neutral;
    * between two recorded levels, the protection rank decides;
    * anything involving an unrecognized token is a weaken, because an
      unknown state is not a state the classifier may reason about.
    """
    before, after = _normalize(before), _normalize(after)
    if before == after:
        return Classification.neutral
    if before is None:
        if after in ("blocked", "auth"):
            return Classification.strengthen
        return Classification.weaken  # "allow" or an unknown token: fail safe
    if after is None:
        return Classification.weaken if before == "blocked" else Classification.neutral
    before_rank, before_known = _rank(before)
    after_rank, after_known = _rank(after)
    if not (before_known and after_known):
        return Classification.weaken
    if after_rank > before_rank:
        return Classification.strengthen
    if after_rank < before_rank:
        return Classification.weaken
    return Classification.neutral


@dataclass(frozen=True)
class LedgerEntry:
    """One row of the admission ledger. Append-only, hash-chained."""

    seq: int
    ts: str
    server: str
    before: str | None
    after: str | None
    classification: str
    reason: str
    decision: str  # applied | denied
    approver: str = ""
    prev_digest: str = ""
    digest: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": LEDGER_SCHEMA,
            "seq": self.seq,
            "ts": self.ts,
            "server": self.server,
            "before": self.before,
            "after": self.after,
            "classification": self.classification,
            "reason": self.reason,
            "decision": self.decision,
            "approver": self.approver,
            "prev_digest": self.prev_digest,
            "digest": self.digest,
        }


def _canonical(row: Mapping[str, Any]) -> str:
    return json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _digest_row_with_prev(row: Mapping[str, Any], prev_digest: str) -> str:
    body = dict(row)
    body.pop("digest", None)
    return hashlib.sha256((_canonical(body) + prev_digest).encode("utf-8")).hexdigest()


def _read_ledger(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        rows.append(json.loads(line))
    return rows


def verify_ledger(path: Path) -> tuple[bool, str]:
    """Check the ledger's hash chain. Returns (ok, reason)."""
    rows = _read_ledger(path)
    prev = ""
    for index, row in enumerate(rows):
        if row.get("schema") != LEDGER_SCHEMA:
            return False, f"row {index}: unknown schema {row.get('schema')!r}"
        if row.get("prev_digest") != prev:
            return False, f"row {index}: prev_digest mismatch (chain broken)"
        if row.get("digest") != _digest_row_with_prev(row, prev):
            return False, f"row {index}: digest mismatch (row tampered)"
        if row.get("seq") != index:
            return False, f"row {index}: seq out of order"
        prev = row["digest"]
    return True, f"{len(rows)} row(s), chain intact"


def _append_ledger(
    ledger_path: Path,
    *,
    server: str,
    before: str | None,
    after: str | None,
    classification: Classification,
    reason: str,
    decision: str,
    approver: str = "",
) -> LedgerEntry:
    rows = _read_ledger(ledger_path)
    prev = rows[-1]["digest"] if rows else ""
    entry = LedgerEntry(
        seq=len(rows),
        ts=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        server=server,
        before=before,
        after=after,
        classification=classification.value,
        reason=reason[:500],
        decision=decision,
        approver=approver,
        prev_digest=prev,
    )
    digest = _digest_row_with_prev(entry.as_dict(), prev)
    data = entry.as_dict()
    data.pop("schema", None)  # schema lives in the serialized row, not the dataclass
    data["digest"] = digest
    entry = LedgerEntry(**data)
    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    with ledger_path.open("a", encoding="utf-8") as handle:
        handle.write(_canonical(entry.as_dict()) + "\n")
    return entry


@dataclass
class AdmissionPolicy:
    """The admission policy: server name -> level, plus where it lives.

    ``levels`` holds only explicit decisions; absence is the deny-default.
    ``notes`` collects read-side clamp reports from :func:`effective_policy`.
    """

    levels: dict[str, str] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def level_for(self, server: str) -> str | None:
        return self.levels.get(server)

    def as_dict(self) -> dict[str, Any]:
        return {
            "version": ADMISSION_VERSION,
            "rules_version": RULES_VERSION,
            "levels": dict(sorted(self.levels.items())),
        }


def _policy_path(workspace: Path) -> Path:
    return workspace / POLICY_DIRECTORY / POLICY_FILE_NAME


def _ledger_path(workspace: Path) -> Path:
    return workspace / POLICY_DIRECTORY / LEDGER_FILE_NAME


def load_policy(workspace: str | Path) -> AdmissionPolicy:
    """Load the stored policy file. Unknown levels are kept verbatim so the
    classifier - not the loader - decides they are a weaken (fail safe)."""
    path = _policy_path(Path(workspace))
    if not path.is_file():
        return AdmissionPolicy()
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return AdmissionPolicy(notes=[f"{POLICY_FILE_NAME} unreadable; treating as empty (deny-default)"])
    levels = document.get("levels")
    if not isinstance(levels, Mapping):
        return AdmissionPolicy(notes=[f"{POLICY_FILE_NAME} has no levels object; treating as empty"])
    clean = {str(k): str(v) for k, v in levels.items() if isinstance(k, str) and isinstance(v, str)}
    return AdmissionPolicy(levels=clean)


def save_policy(workspace: str | Path, policy: AdmissionPolicy) -> None:
    path = _policy_path(Path(workspace))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(policy.as_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")


def effective_policy(workspace: str | Path) -> AdmissionPolicy:
    """The policy to act on: stored file clamped by the ledger (fail closed).

    Replays the ledger to find the last *applied* level per server. If the
    stored file disagrees - a hand-edit that bypassed the gate - the stronger
    of the two wins and the clamp is reported in ``notes``. A broken ledger
    chain fails closed to the stored file's stronger side: every stored level
    is kept, nothing is loosened on suspicion.
    """
    base = Path(workspace)
    policy = load_policy(base)
    ledger = _ledger_path(base)
    ok, reason = verify_ledger(ledger)
    if not ok:
        policy.notes.append(f"ledger verification failed ({reason}); no loosening applied on suspicion")
        return policy
    last_applied: dict[str, str | None] = {}
    for row in _read_ledger(ledger):
        if row.get("decision") == "applied":
            last_applied[str(row.get("server"))] = row.get("after")
    for server, ledger_level in sorted(last_applied.items()):
        stored_level = policy.levels.get(server)
        if _normalize(stored_level) == _normalize(ledger_level):
            continue
        # Classify the move FROM the ledger's last applied decision TO the
        # stored file: if that move is a weakening, the file bypassed the
        # gate - clamp back to the ledger state (fail closed).
        move = classify_change(ledger_level, stored_level)
        if move is Classification.weaken:
            if _normalize(ledger_level) is None:
                policy.levels.pop(server, None)
            else:
                policy.levels[server] = ledger_level  # type: ignore[assignment]
            policy.notes.append(
                f"{server}: stored {stored_level!r} weaker than ledger {ledger_level!r}; "
                "clamped to the stronger (hand-edit bypassed the gate)"
            )
        elif move is Classification.strengthen:
            policy.notes.append(
                f"{server}: stored {stored_level!r} stronger than ledger {ledger_level!r}; "
                "kept (tightening outside the gate is allowed)"
            )
        else:
            policy.notes.append(
                f"{server}: stored {stored_level!r} differs from ledger {ledger_level!r} "
                "without changing protection; ledger state kept"
            )
            if _normalize(ledger_level) is None:
                policy.levels.pop(server, None)
            else:
                policy.levels[server] = ledger_level  # type: ignore[assignment]
    return policy


@dataclass(frozen=True)
class PolicyChange:
    """A proposed admission change, classified, with its audit trail."""

    server: str
    before: str | None
    after: str
    classification: Classification
    reason: str
    decision: str  # applied | denied
    entry: LedgerEntry

    def as_dict(self) -> dict[str, Any]:
        return {
            "server": self.server,
            "before": self.before,
            "after": self.after,
            "classification": self.classification.value,
            "reason": self.reason,
            "decision": self.decision,
            "ledger_seq": self.entry.seq,
        }


def apply_change(
    policy: AdmissionPolicy,
    workspace: str | Path,
    *,
    server: str,
    new_level: str,
    reason: str,
    approver: str = "",
) -> PolicyChange:
    """The single chokepoint for admission changes (raise-only).

    Strengthening and neutral changes apply immediately and are ledgered.
    A weakening applies *only* with an explicit audited approval - ``approver``
    and ``reason`` both non-empty, naming a human who saw the before/after
    diff. Without it the change is denied, the policy is untouched, and the
    *denial* is ledgered: denials are the attack signal. There is no silent
    path and no automatic path for weakening, ever.
    """
    base = Path(workspace)
    before = policy.levels.get(server)
    classification = classify_change(before, new_level)
    reason = reason.strip()
    if classification is Classification.weaken and not (approver.strip() and reason):
        entry = _append_ledger(
            _ledger_path(base),
            server=server,
            before=before,
            after=new_level,
            classification=classification,
            reason=reason or "(no reason given)",
            decision="denied",
            approver=approver,
        )
        return PolicyChange(
            server=server, before=before, after=new_level,
            classification=classification, reason=reason, decision="denied", entry=entry,
        )
    if new_level == "absent":
        policy.levels.pop(server, None)
    else:
        policy.levels[server] = new_level
    save_policy(base, policy)
    entry = _append_ledger(
        _ledger_path(base),
        server=server,
        before=before,
        after=new_level,
        classification=classification,
        reason=reason,
        decision="applied",
        approver=approver,
    )
    return PolicyChange(
        server=server, before=before, after=new_level,
        classification=classification, reason=reason, decision="applied", entry=entry,
    )


@dataclass(frozen=True)
class TighteningProposal:
    """A tighten-only proposal derived from scan findings. Proposals never
    loosen: they are the raise-only learning half."""

    server: str
    before: str | None
    after: str
    why: str

    def as_dict(self) -> dict[str, Any]:
        return {"server": self.server, "before": self.before, "after": self.after, "why": self.why}


def propose_tightening(scan: AdmissionScan, policy: AdmissionPolicy) -> tuple[TighteningProposal, ...]:
    """Turn scan findings into tighten-only proposals.

    * critical finding -> ``blocked``
    * high finding -> ``auth`` (or ``blocked`` when already at ``auth``)
    * medium/low findings propose nothing: advice, not a veto.
    A proposal is emitted only when it strictly tightens the current level;
    servers already at or above the target are left alone.
    """
    proposals: list[TighteningProposal] = []
    for server in sorted({f.server for f in scan.findings}):
        worst = scan.worst_for(server)
        if worst == "critical":
            target = "blocked"
        elif worst == "high":
            target = "blocked" if policy.level_for(server) == "auth" else "auth"
        else:
            continue
        before = policy.level_for(server)
        if before is None:
            # No recorded decision: recording a restrictive level is always a
            # tightening of the recorded posture - it can never grant, because
            # the targets here are only ever "blocked" or "auth".
            if target not in ("blocked", "auth"):
                continue
        elif classify_change(before, target) is not Classification.strengthen:
            continue
        rules = sorted({f.rule for f in scan.findings if f.server == server})
        proposals.append(
            TighteningProposal(
                server=server,
                before=before,
                after=target,
                why=f"scan {scan.rules_version}: worst={worst} ({', '.join(rules)})",
            )
        )
    return tuple(proposals)


def auto_tighten(
    policy: AdmissionPolicy,
    workspace: str | Path,
    scan: AdmissionScan,
    *,
    reason_prefix: str = "auto-tighten",
) -> tuple[PolicyChange, ...]:
    """Apply every tightening proposal. Raise-only learning: policies
    auto-tighten on observed evidence, never silently loosen. Each applied
    change goes through :func:`apply_change`, so each is ledgered."""
    applied: list[PolicyChange] = []
    for proposal in propose_tightening(scan, policy):
        change = apply_change(
            policy,
            workspace,
            server=proposal.server,
            new_level=proposal.after,
            reason=f"{reason_prefix}: {proposal.why}",
        )
        applied.append(change)
    return tuple(applied)


def apply_admission_policy(
    servers: Sequence[tuple[str, Any]],
    policy: AdmissionPolicy,
) -> tuple[list[tuple[str, Any]], list[str]]:
    """Split ``(name, server)`` pairs into admitted and refused.

    The seam between ``mcp_config.discover`` and admission: ``blocked``
    servers are refused with a reason, ``auth`` servers are admitted with a
    note (their tools still need per-call approval), ``allow`` and undecided
    servers pass through unchanged - admission never *grants* what the
    import gate refused.
    """
    admitted: list[tuple[str, Any]] = []
    refused: list[str] = []
    for name, server in servers:
        level = policy.level_for(name)
        if level == "blocked":
            refused.append(f"{name}: refused by admission policy (blocked)")
        else:
            admitted.append((name, server))
    return admitted, refused


# ---------------------------------------------------------------------------
# CLI: `mcp scan`, `mcp admit`
# ---------------------------------------------------------------------------

def add_admission_arguments(actions: argparse._SubParsersAction) -> None:
    """Attach the admission actions to the ``mcp`` verb's subparsers.

    Takes the subparsers action returned by ``mcp_config.add_mcp_arguments`` -
    argparse allows only one subparsers group per parser, so the actions share it.
    """
    scan = actions.add_parser(
        "scan",
        help="scan MCP configs for hostile packages, secret forwarding, and description injection (read-only)",
    )
    scan.add_argument("--workspace", default=".", help="workspace to scan (default: current directory)")
    scan.add_argument("--config", default="", metavar="PATH", help="scan one file instead of searching")
    scan.add_argument("--json", action="store_true", help="print the scan report as JSON")
    scan.add_argument(
        "--apply-tightening",
        action="store_true",
        help="apply raise-only auto-tightening from the findings (tightenings only; never loosens)",
    )
    scan.set_defaults(handler=run_scan)

    admit = actions.add_parser(
        "admit",
        help="record an admission decision for one server through the raise-only gate",
    )
    admit.add_argument("--workspace", default=".", help="workspace whose policy to change (default: current directory)")
    admit.add_argument("--server", required=True, help="server name the decision is about")
    admit.add_argument(
        "--level",
        required=True,
        choices=("blocked", "auth", "allow", "absent"),
        help="admission level; 'absent' removes the recorded decision (deny-default)",
    )
    admit.add_argument("--reason", default="", help="why this change is made (required; recorded in the ledger)")
    admit.add_argument(
        "--approver",
        default="",
        help="who approves this change (required for weakenings; recorded in the ledger)",
    )
    admit.add_argument("--json", action="store_true", help="print the change record as JSON")
    admit.set_defaults(handler=run_admit)


def run_scan(args: argparse.Namespace) -> int:
    """Report admission findings; exit 1 when anything at high or above fired.

    The exit code is the point: CI can run ``mcp scan`` and fail when a
    dependency pulls in a hostile server package, forwards a secret, or
    smuggles an instruction into a tool description.
    """
    workspace = Path(str(getattr(args, "workspace", ".") or "."))
    config = str(getattr(args, "config", "") or "")
    if config:
        findings = scan_document(workspace / config)
        report = AdmissionScan(findings=findings, servers_scanned=0, files=(config,))
    else:
        report = scan_workspace(workspace)
    if getattr(args, "apply_tightening", False):
        policy = effective_policy(workspace)
        applied = auto_tighten(policy, workspace, report)
        if not getattr(args, "json", False):
            for change in applied:
                print(f"  ~ {change.server}: {change.before or 'absent'} -> {change.after} ({change.decision})")
    if getattr(args, "json", False):
        print(json.dumps(report.as_dict(), sort_keys=True))
        return 1 if not report.ok else 0
    print("== MCP admission scan ==")
    print(f"  workspace: {workspace.resolve()}")
    print(f"  rules: {report.rules_version}")
    for path in report.files:
        print(f"  file: {path}")
    if not report.findings:
        print("  no findings")
    for finding in report.findings:
        print(f"  [{finding.severity}] {finding.server}: {finding.message}")
        print(f"      -> {finding.recommendation}")
    if not report.ok:
        print("  (critical/high findings: admission refused until resolved)")
    else:
        print("  (no critical/high findings; medium/low are advice)")
    print("  (a clean scan is 'nothing on the list matched', never 'this server is safe')")
    return 1 if not report.ok else 0


def run_admit(args: argparse.Namespace) -> int:
    """Record one admission decision through the raise-only gate."""
    workspace = Path(str(getattr(args, "workspace", ".") or "."))
    server = str(args.server)
    level = str(args.level)
    reason = str(getattr(args, "reason", "") or "")
    approver = str(getattr(args, "approver", "") or "")
    if not reason.strip():
        print("! --reason is required: every admission change is ledgered with its reason", file=sys.stderr)
        return 2
    policy = effective_policy(workspace)
    for note in policy.notes:
        print(f"  ! policy note: {note}", file=sys.stderr)
    change = apply_change(policy, workspace, server=server, new_level=level, reason=reason, approver=approver)
    if getattr(args, "json", False):
        print(json.dumps(change.as_dict(), sort_keys=True))
    else:
        before = change.before if change.before is not None else "absent"
        print(f"  {change.server}: {before} -> {change.after} [{change.classification.value}] {change.decision}")
        if change.decision == "denied":
            print("  ! weakening denied: a weakening needs --approver naming who approved it (and --reason why)")
    return 0 if change.decision == "applied" else 1
