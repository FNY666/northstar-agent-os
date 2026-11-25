"""Dataflow sensitivity tracking with a deterministic TOML policy.

Mechanism absorbed — from real code, not from docs — from
``archestra-ai/openappa`` (MIT, Copyright 2026 Archestra Inc.):

* ``[policy] trust_chain``: an ordered rank list. "Content lowers the
  trajectory to the rank of its source; a sink needs at least its declared
  rank" (``examples/tests/three-trust-ranks/appa.toml``).
* ``delta = { trust = ..., audience = ... }`` on *source* tools and
  ``requires = { trust = ... }`` / ``requires = { audience = { contains =
  ["$to"] } }`` on *sink* tools
  (``examples/tests/secret-stays-inside/appa.toml``): reads attach labels
  to data; sinks refuse data whose labels they may not receive.
* The policy *dialect* is TOML compiled deterministically into the engine
  (``appa-policy/src/lib.rs``: "the configuration dialect (TOML) → the
  engine's RegistryConfig"; strict ``deny_unknown_fields`` parsing in
  ``appa-policy/src/raw.rs``).

Northstar's analogue is deliberately smaller and fully deterministic —
there is no LLM annotator in the loop. Sensitivity labels come from the
TOML policy's *source* rules (matched by tool name plus optional argument
globs); the permission gate *escalates* — it never silently downgrades —
when labelled data would flow to a sink that may not receive it.

Conservative modelling choices (documented, not hidden):

* Labels attach on the gate's *request* for an allowed call: the gate runs
  before execution, so it cannot know whether the call will succeed. A
  denied call attaches no label — a denied call produces no data.
* The audience check only constrains data with an audience label.
  Public (unlabelled) data may go anywhere; labelled data may only go to
  recipients named in its audience. A labelled trajectory escalates at any
  sink without an explicit audience contract, including an otherwise unknown
  sink. When labelled sources are combined,
  their allowed-recipient sets intersect. This mirrors OpenAPPA's
  "secret-stays-inside" without its symbolic audience-source machinery.
* A sink template (``$arg``) that names a missing argument fails closed:
  the expansion cannot be satisfied, so the call escalates.
* Escalation does not apply under ``bypassPermissions``: bypass means the
  host opted out of being asked, and escalation *is* asking the host.
"""

from __future__ import annotations

import fnmatch
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

POLICY_VERSION = 1

_DEFAULT_POLICY_PATH = Path(__file__).resolve().parent / "policy" / "dataflow.toml"

#: The canonical default policy, embedded so ``default()`` works even when
#: the component is installed without its data files. The shipped
#: ``policy/dataflow.toml`` MUST be byte-identical to this string — pinned
#: by ``test_default_policy_matches_shipped_toml``.
_DEFAULT_POLICY_TOML = """\
# Northstar default dataflow sensitivity policy.
#
# Deterministic: parsed by dataflow_policy.from_toml with a strict schema
# (unknown fields, unknown trust ranks, or a wrong version are refused and
# the gate fails closed). Versioned in git, so every policy change is
# auditable. Mechanism absorbed from archestra-ai/OpenAPPA (MIT):
# trust_chain + source `delta` + sink `requires`
# (examples/tests/three-trust-ranks/appa.toml,
#  examples/tests/secret-stays-inside/appa.toml).

[policy]
version = 1
trust_chain = ["public", "internal", "confidential", "restricted"]

# --- sources: reads attach a sensitivity label to the trajectory --------

[[policy.source]]
tool = "Read"
match_args = { path = "*.pem" }
delta = { trust = "restricted" }

[[policy.source]]
tool = "Read"
match_args = { path = "*credentials*" }
delta = { trust = "restricted" }

[[policy.source]]
tool = "Read"
match_args = { path = "/etc/*" }
delta = { trust = "confidential" }

[[policy.source]]
tool = "Read"
match_args = { path = "*.env" }
delta = { trust = "confidential" }

[[policy.source]]
tool = "mcp/files/read"
match_args = { path = "/hr/*" }
delta = { trust = "confidential", audience = ["hr@local"] }

[[policy.source]]
tool = "*secret*"
delta = { trust = "restricted" }

# --- sinks: destinations that may only receive data up to a level ------

[[policy.sink]]
tool = "send_mail"
requires = { trust = "internal" }

[[policy.sink]]
tool = "post_slack"
requires = { trust = "internal" }

[[policy.sink]]
tool = "http_post"
requires = { trust = "public" }

[[policy.sink]]
tool = "Fetch"
requires = { trust = "public" }

[[policy.sink]]
tool = "Task"
requires = { trust = "public" }

[[policy.sink]]
tool = "mcp/mail/send"
requires = { trust = "confidential", audience = { contains = ["$to"] } }
"""


class DataflowPolicyError(ValueError):
    """The TOML policy is malformed. Fail closed: the caller must not run
    with a policy it could not parse strictly."""


def _expect_mapping(value: Any, where: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise DataflowPolicyError(f"{where}: expected a TOML table, saw {type(value).__name__}")
    return value


def _expect_str_list(value: Any, where: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise DataflowPolicyError(f"{where}: expected a list of strings")
    return tuple(value)


def _check_no_unknown(mapping: Mapping[str, Any], allowed: frozenset[str], where: str) -> None:
    unknown = sorted(set(mapping) - allowed)
    if unknown:
        raise DataflowPolicyError(f"{where}: unknown field(s): {', '.join(unknown)}")


@dataclass(frozen=True)
class SourceRule:
    """A read whose results carry a sensitivity label into the trajectory.

    ``tool`` is a shell-style glob (``fnmatch``) over the tool name;
    ``match_args`` optionally pins argument values by glob (a missing
    argument never matches). The first matching rule in file order wins.
    """

    tool: str
    match_args: tuple[tuple[str, str], ...]
    delta_trust: int
    delta_audience: tuple[str, ...]

    def matches(self, tool_name: str, arguments: Mapping[str, Any]) -> bool:
        if not fnmatch.fnmatchcase(tool_name, self.tool):
            return False
        for name, pattern in self.match_args:
            value = arguments.get(name)
            if value is None or not fnmatch.fnmatchcase(str(value), pattern):
                return False
        return True


@dataclass(frozen=True)
class SinkRule:
    """A destination that may only receive data up to a sensitivity.

    ``requires_max_trust`` is the highest trust-chain index the sink may
    receive; a hotter trajectory escalates. ``requires_audience`` holds
    templates (``$arg`` expands from the call's arguments, bare words are
    literal); every expanded token must be in the trajectory's audience —
    but only when the trajectory actually carries an audience.
    """

    tool: str
    requires_max_trust: int
    requires_audience: tuple[str, ...]

    def matches(self, tool_name: str) -> bool:
        return fnmatch.fnmatchcase(tool_name, self.tool)

    def expand_audience(self, arguments: Mapping[str, Any]) -> tuple[str, ...]:
        expanded: list[str] = []
        for token in self.requires_audience:
            if token.startswith("$") and len(token) > 1 and " " not in token:
                expanded.append(str(arguments.get(token[1:], "")))
            else:
                expanded.append(token)
        return tuple(expanded)


@dataclass(frozen=True)
class SinkVerdict:
    escalate: bool
    reason: str


@dataclass(frozen=True)
class UntrustedSourceRule:
    """A tool or provenance trust level that introduces untrusted data (CaMeL).

    Once an allowed call matches an ``UntrustedSourceRule`` (either by tool/arg
    glob or by runtime ``ToolProvenance.trust``), the trajectory becomes
    integrity-tainted so downstream privileged sinks escalate to host approval
    (or deny fail-closed when no callback exists).
    """

    tool: str
    match_args: tuple[tuple[str, str], ...] = ()
    match_trust: tuple[str, ...] = ()
    label: str = "untrusted"

    def matches(
        self,
        tool_name: str,
        arguments: Mapping[str, Any] | None = None,
        *,
        trust: str = "",
    ) -> bool:
        if not fnmatch.fnmatchcase(tool_name, self.tool):
            return False
        if self.match_trust:
            if not trust or trust not in self.match_trust:
                return False
        args = arguments or {}
        for name, pattern in self.match_args:
            value = args.get(name)
            if value is None or not fnmatch.fnmatchcase(str(value), pattern):
                return False
        return True


@dataclass(frozen=True)
class PrivilegedSinkRule:
    """A privileged control-plane or exfiltration sink guarded against untrusted taint."""

    tool: str
    match_args: tuple[tuple[str, str], ...] = ()
    description: str = ""

    def matches(self, tool_name: str, arguments: Mapping[str, Any] | None = None) -> bool:
        if not fnmatch.fnmatchcase(tool_name, self.tool):
            return False
        args = arguments or {}
        for name, pattern in self.match_args:
            value = args.get(name)
            if value is None or not fnmatch.fnmatchcase(str(value), pattern):
                return False
        return True


_MAX_UNTRUSTED_ORIGINS = 64

_CAMEL_UNTRUSTED_SOURCES: tuple[UntrustedSourceRule, ...] = (
    UntrustedSourceRule(tool="Fetch", label="external_fetch"),
    UntrustedSourceRule(tool="mcp__*", label="external_mcp"),
    UntrustedSourceRule(tool="mcp/*", label="external_mcp"),
)

_CAMEL_STRICT_EXTRA_SOURCES: tuple[UntrustedSourceRule, ...] = (
    UntrustedSourceRule(tool="Read", label="untrusted_workspace_read"),
    UntrustedSourceRule(tool="Grep", label="untrusted_workspace_search"),
    UntrustedSourceRule(tool="SearchCode", label="untrusted_workspace_search"),
    UntrustedSourceRule(tool="GitInspect", label="untrusted_workspace_git"),
    UntrustedSourceRule(tool="RepoMap", label="untrusted_workspace_map"),
)

_CAMEL_PRIVILEGED_SINKS: tuple[PrivilegedSinkRule, ...] = (
    PrivilegedSinkRule(tool="Shell", description="host shell execution"),
    PrivilegedSinkRule(tool="RunCheck", description="host verification command"),
    PrivilegedSinkRule(tool="Edit", description="workspace file mutation"),
    PrivilegedSinkRule(tool="Write", description="workspace file creation/overwrite"),
    PrivilegedSinkRule(tool="ApplyPatch", description="workspace patch application"),
    PrivilegedSinkRule(tool="Fetch", description="external network egress"),
    PrivilegedSinkRule(tool="Task", description="subagent delegation"),
    PrivilegedSinkRule(tool="mcp__*", description="external MCP tool invocation"),
    PrivilegedSinkRule(tool="mcp/*", description="external MCP tool invocation"),
    PrivilegedSinkRule(tool="send_mail", description="outbound email"),
    PrivilegedSinkRule(tool="post_slack", description="outbound chat message"),
    PrivilegedSinkRule(tool="http_post", description="outbound HTTP POST"),
)


@dataclass(frozen=True)
class DataflowPolicy:
    """A compiled, deterministic dataflow policy."""

    version: int
    trust_chain: tuple[str, ...]
    sources: tuple[SourceRule, ...]
    sinks: tuple[SinkRule, ...]
    untrusted_sources: tuple[UntrustedSourceRule, ...] = ()
    privileged_sinks: tuple[PrivilegedSinkRule, ...] = ()

    @property
    def has_integrity_rules(self) -> bool:
        return bool(self.untrusted_sources and self.privileged_sinks)

    def rank_index(self, rank: str) -> int:
        return self.trust_chain.index(rank)

    def rank_name(self, index: int) -> str:
        return self.trust_chain[index]

    @classmethod
    def from_toml(cls, text: str, *, source: str = "<string>") -> DataflowPolicy:
        """Parse and strictly validate a TOML policy. Anything the schema
        does not understand is refused — fail closed, like OpenAPPA's
        ``deny_unknown_fields``."""
        try:
            raw = tomllib.loads(text)
        except tomllib.TOMLDecodeError as error:
            raise DataflowPolicyError(f"{source}: invalid TOML: {error}") from error
        _check_no_unknown(raw, frozenset({"policy"}), source)
        policy = _expect_mapping(raw.get("policy"), f"{source} [policy]")
        _check_no_unknown(
            policy,
            frozenset({"version", "trust_chain", "source", "sink", "untrusted_source", "privileged_sink"}),
            f"{source} [policy]",
        )

        version = policy.get("version")
        if version != POLICY_VERSION:
            raise DataflowPolicyError(
                f"{source} [policy]: version must be {POLICY_VERSION}, saw {version!r}"
            )
        chain = _expect_str_list(policy.get("trust_chain"), f"{source} [policy] trust_chain")
        if not chain:
            raise DataflowPolicyError(f"{source} [policy]: trust_chain must not be empty")
        if len(set(chain)) != len(chain):
            raise DataflowPolicyError(f"{source} [policy]: trust_chain ranks must be unique")
        if any(not rank for rank in chain):
            raise DataflowPolicyError(f"{source} [policy]: trust_chain ranks must be non-empty")

        def rank_of(name: Any, where: str) -> int:
            if not isinstance(name, str) or name not in chain:
                raise DataflowPolicyError(
                    f"{where}: unknown trust rank {name!r} (chain: {', '.join(chain)})"
                )
            return chain.index(name)

        sources: list[SourceRule] = []
        for i, entry in enumerate(policy.get("source", []) or []):
            where = f"{source} [[policy.source]] #{i}"
            entry = _expect_mapping(entry, where)
            _check_no_unknown(entry, frozenset({"tool", "match_args", "delta"}), where)
            tool = entry.get("tool")
            if not isinstance(tool, str) or not tool:
                raise DataflowPolicyError(f"{where}: tool must be a non-empty string")
            match_args = entry.get("match_args", {})
            match_args = _expect_mapping(match_args, f"{where} match_args")
            for name, pattern in match_args.items():
                if not isinstance(pattern, str):
                    raise DataflowPolicyError(f"{where} match_args.{name}: glob must be a string")
            delta = _expect_mapping(entry.get("delta", {}), f"{where} delta")
            _check_no_unknown(delta, frozenset({"trust", "audience"}), f"{where} delta")
            sources.append(
                SourceRule(
                    tool=tool,
                    match_args=tuple(sorted(match_args.items())),
                    delta_trust=rank_of(delta.get("trust", chain[0]), f"{where} delta"),
                    delta_audience=_expect_str_list(
                        delta.get("audience", []), f"{where} delta audience"
                    ),
                )
            )

        sinks: list[SinkRule] = []
        for i, entry in enumerate(policy.get("sink", []) or []):
            where = f"{source} [[policy.sink]] #{i}"
            entry = _expect_mapping(entry, where)
            _check_no_unknown(entry, frozenset({"tool", "requires"}), where)
            tool = entry.get("tool")
            if not isinstance(tool, str) or not tool:
                raise DataflowPolicyError(f"{where}: tool must be a non-empty string")
            requires = _expect_mapping(entry.get("requires", {}), f"{where} requires")
            _check_no_unknown(requires, frozenset({"trust", "audience"}), f"{where} requires")
            audience = requires.get("audience", {})
            audience = _expect_mapping(audience, f"{where} requires audience")
            _check_no_unknown(audience, frozenset({"contains"}), f"{where} requires audience")
            sinks.append(
                SinkRule(
                    tool=tool,
                    requires_max_trust=rank_of(requires.get("trust", chain[-1]), f"{where} requires"),
                    requires_audience=_expect_str_list(
                        audience.get("contains", []), f"{where} requires audience contains"
                    ),
                )
            )

        untrusted_sources: list[UntrustedSourceRule] = []
        for i, entry in enumerate(policy.get("untrusted_source", []) or []):
            where = f"{source} [[policy.untrusted_source]] #{i}"
            entry = _expect_mapping(entry, where)
            _check_no_unknown(entry, frozenset({"tool", "match_args", "match_trust", "label"}), where)
            tool = entry.get("tool")
            if not isinstance(tool, str) or not tool:
                raise DataflowPolicyError(f"{where}: tool must be a non-empty string")
            match_args = _expect_mapping(entry.get("match_args", {}), f"{where} match_args")
            for name, pattern in match_args.items():
                if not isinstance(pattern, str):
                    raise DataflowPolicyError(f"{where} match_args.{name}: glob must be a string")
            match_trust = _expect_str_list(entry.get("match_trust", []), f"{where} match_trust")
            label = entry.get("label", "untrusted")
            if not isinstance(label, str) or not label:
                raise DataflowPolicyError(f"{where}: label must be a non-empty string")
            untrusted_sources.append(
                UntrustedSourceRule(
                    tool=tool,
                    match_args=tuple(sorted(match_args.items())),
                    match_trust=match_trust,
                    label=label,
                )
            )

        privileged_sinks: list[PrivilegedSinkRule] = []
        for i, entry in enumerate(policy.get("privileged_sink", []) or []):
            where = f"{source} [[policy.privileged_sink]] #{i}"
            entry = _expect_mapping(entry, where)
            _check_no_unknown(entry, frozenset({"tool", "match_args", "description"}), where)
            tool = entry.get("tool")
            if not isinstance(tool, str) or not tool:
                raise DataflowPolicyError(f"{where}: tool must be a non-empty string")
            match_args = _expect_mapping(entry.get("match_args", {}), f"{where} match_args")
            for name, pattern in match_args.items():
                if not isinstance(pattern, str):
                    raise DataflowPolicyError(f"{where} match_args.{name}: glob must be a string")
            description = entry.get("description", "")
            if not isinstance(description, str):
                raise DataflowPolicyError(f"{where}: description must be a string")
            privileged_sinks.append(
                PrivilegedSinkRule(
                    tool=tool,
                    match_args=tuple(sorted(match_args.items())),
                    description=description,
                )
            )

        return cls(
            version=POLICY_VERSION,
            trust_chain=chain,
            sources=tuple(sources),
            sinks=tuple(sinks),
            untrusted_sources=tuple(untrusted_sources),
            privileged_sinks=tuple(privileged_sinks),
        )

    @classmethod
    def from_toml_file(cls, path: str | Path) -> DataflowPolicy:
        path = Path(path)
        return cls.from_toml(path.read_text(encoding="utf-8"), source=str(path))

    @classmethod
    def default(cls) -> DataflowPolicy:
        """The versioned, auditable policy shipped with the runtime.

        Reads ``policy/dataflow.toml`` next to this module when present;
        falls back to the embedded canonical text so an install without
        data files still gets exactly the same policy.
        """
        if _DEFAULT_POLICY_PATH.exists():
            return cls.from_toml_file(_DEFAULT_POLICY_PATH)
        return cls.from_toml(_DEFAULT_POLICY_TOML, source="<embedded default>")

    @classmethod
    def camel_default(cls) -> DataflowPolicy:
        """Default confidentiality policy plus CaMeL external-untrusted integrity taint.

        Any allowed ``Fetch`` / ``mcp__*`` / ``untrusted``-provenance result taints the
        session (and its parent/child subagents) so subsequent privileged sinks
        (``Shell``, ``Edit``, ``Write``, ``ApplyPatch``, ``Fetch``, ``Task``, ``mcp__*``)
        escalate to host approval (or deny fail-closed without a callback).
        """
        base = cls.default()
        return cls(
            version=base.version,
            trust_chain=base.trust_chain,
            sources=base.sources,
            sinks=base.sinks,
            untrusted_sources=_CAMEL_UNTRUSTED_SOURCES,
            privileged_sinks=_CAMEL_PRIVILEGED_SINKS,
        )

    @classmethod
    def camel_strict(cls) -> DataflowPolicy:
        """Strict CaMeL preset: treats workspace reads/searches as untrusted data too.

        Designed for untrusted repositories where reading files (``Read``/``Grep``/
        ``SearchCode``) may carry prompt-injection payloads; every subsequent
        privileged sink escalates to host approval or denies fail-closed.
        """
        base = cls.default()
        return cls(
            version=base.version,
            trust_chain=base.trust_chain,
            sources=base.sources,
            sinks=base.sinks,
            untrusted_sources=_CAMEL_UNTRUSTED_SOURCES + _CAMEL_STRICT_EXTRA_SOURCES,
            privileged_sinks=_CAMEL_PRIVILEGED_SINKS,
        )


@dataclass
class SessionDataflow:
    """Per-session trajectory: the sensitivity of data the agent has handled.

    ``trust_index`` only moves up (towards the hot end of the chain) —
    content raises the trajectory to the sensitivity of its most sensitive
    source, the dual of OpenAPPA's "content lowers the trajectory to the
    rank of its source" on an untrusted→internal chain.
    """

    policy: DataflowPolicy
    trust_index: int = 0
    audience: frozenset[str] = frozenset()
    audience_labeled: bool = False
    audience_unknown: bool = False
    untrusted_tainted: bool = False
    untrusted_sources: list[str] = field(default_factory=list)
    events: list[dict[str, Any]] = field(default_factory=list)

    @classmethod
    def from_memory_audience(
        cls, policy: DataflowPolicy, audience: tuple[str, ...] | list[str]
    ) -> "SessionDataflow":
        """Start a trajectory with the recipient boundary of injected memory.

        An empty audience means public/unlabelled memory. A non-empty operator
        grant stays labelled for the whole run and is intersected with later
        source labels like any other dataflow audience.
        """
        recipients = frozenset(audience)
        return cls(
            policy,
            audience=recipients,
            audience_labeled=bool(recipients),
            events=(
                [{
                    "tool": "workspace_memory",
                    "rule": "memory_audience_manifest",
                    "trust": policy.rank_name(0),
                    "audience": sorted(recipients),
                    "audience_labeled": True,
                }]
                if recipients else []
            ),
        )

    def _record_untrusted_origin(
        self,
        origin: str,
        *,
        tool_name: str,
        label: str,
        trust: str = "",
        agent: str = "main",
        depth: int = 0,
    ) -> None:
        self.untrusted_tainted = True
        scoped = f"subagent:{agent}->{origin}" if depth > 0 and not origin.startswith("subagent:") else origin
        if scoped not in self.untrusted_sources and len(self.untrusted_sources) < _MAX_UNTRUSTED_ORIGINS:
            self.untrusted_sources.append(scoped)
        self.events.append(
            {
                "kind": "integrity_taint",
                "tool": tool_name,
                "origin": scoped,
                "label": label,
                "trust": trust or "untrusted",
                "agent": agent,
                "depth": depth,
            }
        )

    def mark_resumed_untrusted(self) -> None:
        """Conservatively mark a resumed session as untrusted-tainted."""
        if not self.policy.has_integrity_rules:
            return
        self._record_untrusted_origin(
            "resumed_session",
            tool_name="session_resume",
            label="resumed_unproven_provenance",
            trust="untrusted",
        )

    def observe(self, tool_name: str, arguments: Mapping[str, Any]) -> SourceRule | None:
        """Attach the first matching source rule's label to the trajectory.
        Returns the confidentiality SourceRule applied, or None."""
        matched_source: SourceRule | None = None
        for rule in self.policy.sources:
            if rule.matches(tool_name, arguments):
                if rule.delta_trust > self.trust_index:
                    self.trust_index = rule.delta_trust
                if rule.delta_audience:
                    delta_audience = frozenset(rule.delta_audience)
                    if self.audience_labeled:
                        self.audience = self.audience & delta_audience
                    else:
                        self.audience = delta_audience
                        self.audience_labeled = True
                self.events.append(
                    {
                        "tool": tool_name,
                        "rule": rule.tool,
                        "trust": self.policy.rank_name(self.trust_index),
                        "audience": sorted(self.audience),
                        "audience_labeled": self.audience_labeled,
                    }
                )
                matched_source = rule
                break
        for u_rule in self.policy.untrusted_sources:
            if not u_rule.match_trust and u_rule.matches(tool_name, arguments):
                self._record_untrusted_origin(
                    f"tool:{tool_name}",
                    tool_name=tool_name,
                    label=u_rule.label,
                )
                break
        return matched_source

    def observe_provenance(
        self,
        tool_name: str,
        *,
        source: str = "",
        trust: str = "",
        agent: str = "main",
        depth: int = 0,
        arguments: Mapping[str, Any] | None = None,
    ) -> UntrustedSourceRule | None:
        """Observe a completed tool result's runtime provenance (CaMeL integrity)."""
        if not self.policy.has_integrity_rules:
            return None
        for rule in self.policy.untrusted_sources:
            if rule.matches(tool_name, arguments, trust=trust):
                origin = source or f"tool:{tool_name}"
                self._record_untrusted_origin(
                    origin,
                    tool_name=tool_name,
                    label=rule.label,
                    trust=trust,
                    agent=agent,
                    depth=depth,
                )
                return rule
        return None

    def integrity_summary(self) -> dict[str, Any]:
        """Content-free summary suitable for audit logs and ACP metadata."""
        return {
            "trust": self.policy.rank_name(self.trust_index),
            "audienceLabeled": self.audience_labeled,
            "audienceUnknown": self.audience_unknown,
            "untrustedTainted": self.untrusted_tainted,
            "untrustedSources": list(self.untrusted_sources[:16]),
        }

    def check_sink(self, tool_name: str, arguments: Mapping[str, Any]) -> SinkVerdict:
        """Decide whether this sink call must escalate given the trajectory.

        Checks both confidentiality (``trust_chain`` + ``audience``) and, when
        configured, CaMeL integrity taint (``untrusted_tainted`` against
        ``privileged_sinks``).
        """
        projected_trust = self.trust_index
        projected_audience = self.audience
        projected_audience_labeled = self.audience_labeled or bool(self.audience)
        matching_source = False
        for source in self.policy.sources:
            if source.matches(tool_name, arguments):
                matching_source = True
                projected_trust = max(projected_trust, source.delta_trust)
                if source.delta_audience:
                    delta_audience = frozenset(source.delta_audience)
                    if projected_audience_labeled:
                        projected_audience = projected_audience & delta_audience
                    else:
                        projected_audience = delta_audience
                        projected_audience_labeled = True
                break
        for rule in self.policy.sinks:
            if not rule.matches(tool_name):
                continue
            if self.audience_unknown:
                return SinkVerdict(
                    escalate=True,
                    reason=(
                        f"resumed trajectory audience is unknown for sink {tool_name!r}; "
                        "the original recipient boundary cannot be proven"
                    ),
                )
            if projected_trust > rule.requires_max_trust:
                return SinkVerdict(
                    escalate=True,
                    reason=(
                        f"trajectory carries {self.policy.rank_name(projected_trust)} data, "
                        f"but sink {tool_name!r} may receive at most "
                        f"{self.policy.rank_name(rule.requires_max_trust)}"
                    ),
                )
            if projected_audience_labeled and not rule.requires_audience:
                return SinkVerdict(
                    escalate=True,
                    reason=(
                        f"sink {tool_name!r} has no audience contract for a "
                        f"trajectory restricted to {sorted(projected_audience)}"
                    ),
                )
            if projected_audience_labeled and rule.requires_audience:
                expanded = rule.expand_audience(arguments)
                missing = [token for token in expanded if token not in projected_audience]
                if missing:
                    return SinkVerdict(
                        escalate=True,
                        reason=(
                            f"sink {tool_name!r} requires audience {sorted(expanded)}, "
                            f"trajectory audience is {sorted(projected_audience)}"
                        ),
                    )
            break
        else:
            if (projected_audience_labeled or self.audience_unknown) and not matching_source:
                return SinkVerdict(
                    escalate=True,
                    reason=(
                        (
                            f"no audience-aware sink rule matches {tool_name!r} for a "
                            "resumed trajectory whose audience is unknown"
                        )
                        if self.audience_unknown
                        else (
                            f"no audience-aware sink rule matches {tool_name!r} for a "
                            f"trajectory restricted to {sorted(projected_audience)}"
                        )
                    ),
                )

        if self.untrusted_tainted and self.policy.privileged_sinks:
            for sink_rule in self.policy.privileged_sinks:
                if sink_rule.matches(tool_name, arguments):
                    origins = ", ".join(self.untrusted_sources[:4]) or "untrusted source"
                    suffix = f" ({sink_rule.description})" if sink_rule.description else ""
                    return SinkVerdict(
                        escalate=True,
                        reason=(
                            f"CaMeL integrity taint: trajectory observed untrusted data from "
                            f"[{origins}]; privileged sink {tool_name!r}{suffix} requires host approval"
                        ),
                    )
        return SinkVerdict(escalate=False, reason="sink requirements satisfied")


__all__ = [
    "POLICY_VERSION",
    "DataflowPolicy",
    "DataflowPolicyError",
    "PrivilegedSinkRule",
    "SessionDataflow",
    "SinkRule",
    "SinkVerdict",
    "SourceRule",
    "UntrustedSourceRule",
]
