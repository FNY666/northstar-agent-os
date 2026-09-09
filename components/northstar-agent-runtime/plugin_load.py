"""Installing, pinning, loading and auditing plugin bundles in one workspace.

Where each piece of truth lives
-------------------------------
``.northstar/plugins/<name>/plugin.toml``  the bundle: what it *wants* to do.
``.northstar/plugins.lock``                the workspace's reviewed set: what it *may* do,
                                           pinned by content digest. A lockfile is the only
                                           honest place for "we looked at this and agreed",
                                           because a bundle cannot vouch for itself and a
                                           directory can be edited by anything with write
                                           access to it.

The loader is deliberately dumb: it reads installed bundles, checks them against the lock,
refuses anything that does not match, and hands the four contributions (skills, agents,
hooks, MCP servers) to the same seams a repository's own files use. No capability is added
by being inside a plugin: a plugin's ``[[hooks]]`` go through ``command_hooks.parse_hooks``,
its policy through the tighten-only check, its skills through ``skills.check`` rules, and its
MCP servers through the ordinary permission gate.

Install is a file copy, and uninstall is a directory removal. Both refuse to touch anything
outside ``.northstar/plugins/`` - the tool has no business deleting a workspace it was not
given, and "git revert" remains the way to undo a bundle you no longer want reviewed.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

import plugin_manifest as manifest_module
from plugin_manifest import (
    HOST_PROFILES,
    skill_candidates,
    LOCK_NAME,
    MANIFEST_NAME,
    PLUGINS_DIRECTORY,
    Bundle,
    PluginError,
    PluginManifest,
    check_host_compatibility,
    current_host_profile,
    load_bundle,
    parse_manifest,
    portability_report,
    verify_integrity,
)
from skill_audit import SEVERITY_ORDER, SkillAudit, audit_file
from skill_audit import summarise as summarise_audits
from skill_audit import threshold_met as skill_threshold_met

LOCK_SCHEMA_VERSION = "northstar.plugins-lock.v1"

#: The lockfile's whole shape. `schema_version` plus a map keyed by plugin name; entries
#: carry the digest and enough identity to answer "who shipped this, and which version did
#: we review" without re-reading the bundle (which is the untrusted artefact).
_LOCK_ENTRY_KEYS = frozenset({"version", "publisher", "content_digest", "source"})


#: The severities an operator may gate a bundle on, in the order `skills check` uses: a
#: finding counts when its severity is at or above the bar, so `never` is the only setting
#: that lets a flagged bundle land, and that is spelled out rather than implied.
FAIL_ON_CHOICES = ("error", "warn", "info", "never")


def review_bundle_skills(plugin: InstalledPlugin) -> tuple[SkillAudit, ...]:
    """Run the workspace's own skill-text rules over one bundle's skills.

    This is the half the blueprint's C5 ruling asked for: an install is a landing *plus* the
    review, and skill text is where that review has to look - the 2026 ecosystem audits that
    found instruction-override phrasing in most community ``SKILL.md`` files were about this
    content, not about a repository's own. A bundle is foreign, so it is held to the same
    deterministic rules; they are not a malware scanner, they name the shapes a human has to
    read.
    """
    if plugin.manifest is None or plugin.bundle is None:
        return ()
    return tuple(audit_file(path, root=plugin.bundle.root) for _name, path in skill_candidates(plugin.bundle, plugin.manifest))


def describe_findings(audits: Sequence[SkillAudit], *, at_or_above: str | None = None) -> tuple[str, ...]:
    """One line per finding, worst first, so a refusal says what to go and read.

    ``at_or_above`` narrows the list to the findings that actually tripped a bar: a refusal
    that counted the informational ones too would be a count nobody could reproduce from the
    flag they passed.
    """
    bar = None if at_or_above is None else SEVERITY_ORDER.get(at_or_above)
    lines: list[str] = []
    for audit in audits:
        for finding in sorted(audit.findings, key=lambda item: -SEVERITY_ORDER.get(item.severity, 0)):
            if bar is not None and SEVERITY_ORDER.get(finding.severity, 0) < bar:
                continue
            excerpt = f" ({finding.excerpt})" if finding.excerpt else ""
            lines.append(f"{audit.relative_path}:{finding.line} {finding.severity} {finding.rule} - {finding.detail}{excerpt}")
    return tuple(lines)


def skill_bar_met(audits: Sequence[SkillAudit], fail_on: str) -> bool:
    """True when any audited skill carries a finding at or above ``fail_on``."""
    return bool(audits) and skill_threshold_met(list(audits), fail_on)


class PluginInstallError(PluginError):
    """An install, uninstall or pinning step that cannot be completed safely.

    Refusals that belong to the bundle itself - a manifest that loosens a ceiling, a path
    that leaves the directory, a file over the size cap - keep raising the plain
    :class:`~plugin_manifest.PluginError` they were raised with, so a caller can tell "this
    bundle is malformed" from "this workspace will not accept it" if it cares.
    """


def plugins_directory(workspace: str | Path) -> Path:
    return Path(workspace) / PLUGINS_DIRECTORY


def lock_path(workspace: str | Path) -> Path:
    return Path(workspace) / ".northstar" / LOCK_NAME


# -- the lockfile -----------------------------------------------------------


def read_lock(workspace: str | Path) -> dict[str, dict[str, Any]]:
    """The reviewed set, as ``{name: entry}``. Missing file is "nothing reviewed yet"."""
    path = lock_path(workspace)
    if not path.is_file():
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise PluginInstallError(f"{path}: cannot read the plugin lockfile ({error})") from error
    if not isinstance(value, dict) or value.get("schema_version") != LOCK_SCHEMA_VERSION:
        raise PluginInstallError(
            f"{path}: expected a {LOCK_SCHEMA_VERSION} document; refusing to guess at another format's meaning"
        )
    plugins = value.get("plugins")
    if not isinstance(plugins, dict):
        raise PluginInstallError(f"{path}: 'plugins' must be a table keyed by plugin name")
    for name, entry in plugins.items():
        if not isinstance(entry, dict):
            raise PluginInstallError(f"{path}: {name}: entry must be a table")
        unknown = sorted(set(entry) - _LOCK_ENTRY_KEYS)
        if unknown:
            raise PluginInstallError(f"{path}: {name}: unknown key(s) {', '.join(unknown)}")
        digest = entry.get("content_digest")
        if not isinstance(digest, str) or not digest.startswith("sha256:"):
            raise PluginInstallError(f"{path}: {name}: content_digest must be sha256:<hex>")
    return {str(name): dict(entry) for name, entry in plugins.items()}


def write_lock(workspace: str | Path, entries: Mapping[str, Mapping[str, Any]]) -> Path:
    """Write the lockfile atomically, sorted, with a trailing newline: it is a review artefact."""
    path = lock_path(workspace)
    path.parent.mkdir(parents=True, exist_ok=True)
    document = {"schema_version": LOCK_SCHEMA_VERSION, "plugins": {name: dict(entries[name]) for name in sorted(entries)}}
    temporary = path.with_suffix(path.suffix + ".tmp")
    payload = json.dumps(document, indent=2, sort_keys=True) + "\n"
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except OSError as error:
        try:
            temporary.unlink()
        except OSError:
            pass
        raise PluginInstallError(f"{path}: cannot write the plugin lockfile ({error})") from error
    return path


# -- one installed bundle ---------------------------------------------------


@dataclass(frozen=True)
class InstalledPlugin:
    """A bundle on disk in a workspace, plus what the lock says about it."""

    name: str
    root: Path
    manifest: PluginManifest
    bundle: Bundle
    pinned_digest: str
    status: str  # "pinned" | "unpinned" | "drift" | "seal-invalid" | "seal-unchecked" | "host-mismatch" | "invalid"
    detail: str = ""
    #: Whether this bundle may contribute anything to a run. Decided by the loader, where
    #: the facts are - the loader is the only thing that knows whether a lock was required
    #: at all, and "unpinned is fine" is true in exactly one of those two configurations.
    loadable: bool = False

    @property
    def usable(self) -> bool:
        """``drift`` and ``unpinned`` are both refusals, and for the same reason: the content
        a reviewer agreed to is the unit of trust here, so anything else has to be
        re-reviewed, not run with a warning."""
        return self.loadable

    def as_dict(self) -> dict[str, Any]:
        if self.manifest is None:
            return {"name": self.name, "status": self.status, "detail": self.detail}
        return {
            "name": self.name,
            "version": self.manifest.version,
            "publisher": self.manifest.publisher,
            "status": self.status,
            "content_digest": self.manifest.content_digest,
            "pinned_digest": self.pinned_digest,
            "components": manifest_module.describe_components(self.manifest),
            "detail": self.detail,
        }


def load_installed(
    workspace: str | Path,
    *,
    require_lock: bool = True,
    workspace_policy: Mapping[str, Any] | None = None,
) -> tuple[list[InstalledPlugin], list[str]]:
    """Every installed bundle, verified, plus operator-facing problems found on the way.

    Problems are collected rather than raised so a report can show *all* of them: half the
    value of ``plugin verify`` is telling a reviewer that two plugins drifted, not just the
    first one the loop noticed. A host-incompatible bundle is reported here and refused at
    load time (:func:`load_contributions`), where refusing has consequences.
    """
    root = plugins_directory(workspace)
    entries = read_lock(workspace)
    problems: list[str] = []
    found: list[InstalledPlugin] = []
    if not root.is_dir():
        return found, problems
    for candidate in sorted(root.iterdir()):
        if not candidate.is_dir():
            continue  # a stray file in the plugins directory is not a plugin
        if not (candidate / MANIFEST_NAME).is_file():
            problems.append(f"{candidate.name}: no {MANIFEST_NAME}; an empty directory is not a plugin")
            continue
        try:
            bundle = load_bundle(candidate)
            # The same tighten-only check install runs, at load time too: a bundle that was
            # pinned before the workspace added a ceiling must not keep loading afterwards,
            # and "min-merge makes it harmless" is true of the numbers but not of the report
            # a reviewer reads.
            plugin = parse_manifest(bundle, workspace_policy=workspace_policy)
        except PluginError as error:
            # Recorded as an entry rather than skipped: a directory that fails to parse is
            # the most dangerous thing that can sit in a plugins directory, and a listing
            # that omits it would report "2 plugins, all fine".
            problems.append(f"{candidate.name}: {error}")
            found.append(
                InstalledPlugin(
                    name=candidate.name,
                    root=candidate,
                    manifest=None,  # type: ignore[arg-type] - the status says why there is none
                    bundle=None,  # type: ignore[arg-type]
                    pinned_digest=str((entries.get(candidate.name) or {}).get("content_digest") or ""),
                    status="invalid",
                    detail=str(error),
                    loadable=False,
                )
            )
            continue
        entry = entries.get(plugin.name)
        if entry and entry.get("content_digest") != bundle.content_digest:
            status, detail = "drift", (
                f"content changed since review: the lock pins {entry.get('content_digest')}, "
                f"this bundle hashes to {bundle.content_digest}"
            )
        elif entry:
            status, detail = "pinned", ""
        else:
            status, detail = "unpinned", (
                "not in plugins.lock: nobody has reviewed this bundle" if require_lock else ""
            )
        pinned = str(entry.get("content_digest") or "") if entry else ""
        integrity = verify_integrity(plugin, pinned_digest=pinned)
        if not integrity["ok"]:
            status, detail = ("seal-invalid" if integrity.get("seal") == "invalid" else "drift"), str(
                integrity.get("reason") or "integrity check failed"
            )
        elif plugin.seal and integrity.get("seal") == "unchecked":
            status, detail = "seal-unchecked", "a seal is declared but its key is unavailable"
        host_problem = check_host_compatibility(plugin)
        if host_problem:
            problems.append(f"{plugin.name}: will not load here - {host_problem}")
            status, detail = "host-mismatch", host_problem
        found.append(
            InstalledPlugin(
                name=plugin.name,
                root=candidate,
                manifest=plugin,
                bundle=bundle,
                pinned_digest=pinned,
                status=status,
                detail=detail,
                loadable=status == "pinned" or (status == "unpinned" and not require_lock),
            )
        )
    declared = {plugin.name for plugin in found}
    for name in sorted(set(entries) - declared):
        problems.append(f"{name}: pinned in plugins.lock but not installed (removed without updating the lock)")
    return found, problems


# -- what the workspace gets -------------------------------------------------


@dataclass
class PluginContributions:
    """Everything installed bundles add to a run, already gated.

    ``blocked`` is part of this object rather than a separate call so that a run cannot
    silently proceed on a partially-loaded plugin set: a bundle that drifted since review
    blocks the run, because "the skills loaded but not the hooks" is a state nobody
    reviewed and nobody can reason about.
    """

    skill_roots: list[tuple[str, Path]] = field(default_factory=list)
    agent_directories: list[tuple[str, Path]] = field(default_factory=list)
    hook_tables: list[tuple[str, dict[str, Any]]] = field(default_factory=list)
    mcp_servers: list[dict[str, Any]] = field(default_factory=list)
    context_blocks: list[tuple[str, str]] = field(default_factory=list)
    policy: dict[str, Any] = field(default_factory=dict)
    audit: list[dict[str, Any]] = field(default_factory=list)
    blocked: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def enabled(self) -> bool:
        return bool(self.audit)

    def merged_policy(self, workspace_policy: Mapping[str, Any] | None) -> dict[str, Any]:
        """Fold the plugins' ceilings into the workspace policy.

        The fold is min-merge on ceilings and union on denials, which is the only
        direction a plugin is allowed to move: the result is never wider than what the
        repository already agreed to, whatever the bundles asked for.
        """
        merged = dict(workspace_policy or {})
        if not self.policy:
            return merged
        for key in ("max_turns", "max_tool_calls"):
            if key in self.policy:
                want = int(self.policy[key])
                current = merged.get(key)
                merged[key] = want if current is None else min(int(current), want)
        if "max_budget_usd" in self.policy:
            want = float(self.policy["max_budget_usd"])
            current = merged.get("max_budget_usd")
            merged["max_budget_usd"] = want if current is None else min(float(current), want)
        denied = list(merged.get("deny_tools") or [])
        for name in self.policy.get("deny_tools") or ():
            if name not in denied:
                denied.append(name)
        if denied:
            merged["deny_tools"] = denied
        if self.policy.get("read_only"):
            merged["read_only"] = True
        if self.policy.get("halt_on_denial"):
            merged["halt_on_denial"] = True
        if self.policy.get("permission_mode") == "plan":
            merged["permission_mode"] = "plan"
        return merged

    def as_dict(self) -> dict[str, Any]:
        return {
            "plugins": self.audit,
            "blocked": list(self.blocked),
            "notes": list(self.notes),
            "skills": len(self.skill_roots),
            "agents": len(self.agent_directories),
            "hooks": len(self.hook_tables),
            "mcp_servers": [server["name"] for server in self.mcp_servers],
            "policy": dict(self.policy),
        }


def load_contributions(
    workspace: str | Path,
    *,
    require_lock: bool = True,
    known_tools: Iterable[str] = (),
    workspace_policy: Mapping[str, Any] | None = None,
) -> PluginContributions:
    """Load every usable installed bundle; block on anything that is not usable.

    ``known_tools`` is passed through to the hook validator, so a plugin that names a tool
    that does not exist is refused here rather than silently never firing - the silent
    version is the one that shows up in an audit as "the guard did nothing".
    """
    contributions = PluginContributions()
    if workspace_policy is None:
        workspace_policy = _workspace_policy_document(workspace)
    plugins, problems = load_installed(workspace, require_lock=require_lock, workspace_policy=workspace_policy)
    # A bundle that will not even parse is not "one plugin fewer": it is still sitting in
    # .northstar/plugins/, still named in the lock, and still part of what this workspace
    # looks like. Skipping it quietly is how a tampered bundle becomes a warning nobody
    # reads, so every problem here blocks the run - except for the ones already blocking it
    # as an invalid entry, which would otherwise be reported twice with different wording.
    invalid = {plugin.name for plugin in plugins if plugin.status == "invalid"}
    for problem in problems:
        contributions.notes.append(problem)
        if problem.split(":", 1)[0].strip() not in invalid:
            contributions.blocked.append(problem)
    tools = {str(name) for name in known_tools}
    for plugin in plugins:
        if not plugin.usable:
            contributions.blocked.append(f"{plugin.name}: {plugin.status} - {plugin.detail or 'refused'}")
            continue
        problems = _naming_problems(plugin, tools)
        contributions.blocked.extend(f"{plugin.name}: {problem}" for problem in problems)
        if problems:
            continue
        for declaration in plugin.manifest.skill_dirs:
            source = plugin.bundle.relative(declaration)
            if source.is_dir():
                contributions.skill_roots.append((plugin.name, source))
        for declaration in plugin.manifest.agent_dirs:
            source = plugin.bundle.relative(declaration)
            if source.is_dir() or source.is_file():
                contributions.agent_directories.append((plugin.name, source))
        for declaration in plugin.manifest.context_files:
            source = plugin.bundle.relative(declaration)
            if source.is_file():
                contributions.context_blocks.append((plugin.name, _read_capped(source)))
        for hook in plugin.manifest.hooks:
            installed = plugin.bundle.relative(hook.script)
            try:
                script = str(installed.resolve().relative_to(Path(workspace).resolve()))
            except (ValueError, OSError):
                # The bundle left the workspace between install and load (moved, or reached
                # by symlink). Refusing beats handing the validator a path it cannot confine.
                contributions.blocked.append(
                    f"{plugin.name}: hook script {hook.script} no longer resolves inside the workspace"
                )
                continue
            contributions.hook_tables.append((plugin.name, hook.as_hook_table(script_path=script)))
        for server in plugin.manifest.mcp_servers:
            if server.get("env"):
                # The manifest may *declare* env (other hosts carry it), but this runtime's
                # MCP loader takes a command line only, and inventing a side channel for a
                # plugin's secrets would be a new permission path. Refuse, and say where it
                # belongs instead.
                contributions.blocked.append(
                    f"{plugin.name}: MCP server {server.get('name')!r} declares env, which this runtime will not "
                    "start a server with; move that server into the workspace's own .mcp.json "
                    "(imported with --mcp-config) or the operator's own --mcp-server flag"
                )
                continue
            contributions.mcp_servers.append({**server, "plugin": plugin.name})
        for key, value in plugin.manifest.policy.items():
            if key in {"max_turns", "max_tool_calls"}:
                current = contributions.policy.get(key)
                contributions.policy[key] = int(value) if current is None else min(int(current), int(value))
            elif key == "max_budget_usd":
                current = contributions.policy.get(key)
                contributions.policy[key] = float(value) if current is None else min(float(current), float(value))
            elif key == "deny_tools":
                existing = list(contributions.policy.get("deny_tools") or [])
                contributions.policy["deny_tools"] = existing + [name for name in value if name not in existing]
            else:
                contributions.policy[key] = value
        contributions.audit.append(
            {
                "name": plugin.name,
                "version": plugin.manifest.version,
                "publisher": plugin.manifest.publisher,
                "content_digest": plugin.manifest.content_digest,
                "components": {
                    "skills": len(plugin.manifest.skill_dirs),
                    "agents": len(plugin.manifest.agent_dirs),
                    "hooks": len(plugin.manifest.hooks),
                    "mcp_servers": len(plugin.manifest.mcp_servers),
                    "policy": sorted(plugin.manifest.policy),
                },
            }
        )
    return contributions


MAX_CONTEXT_CHARS = 16_000


def _naming_problems(plugin: InstalledPlugin, tools: set[str]) -> list[str]:
    """Names a bundle uses that this runtime does not have - each one is a silent no-op.

    The rule is copied from the workspace's own policy file: the same known-tool set, the
    same ``mcp__`` exemption (a server that is not connected yet may still be the one that
    tool belongs to). A plugin held to a *looser* check than ``.northstar/config.toml``
    would become the seam everyone exploits, so it gets exactly the check the repository
    gets - a denial that matches nothing is not a denial, it is a false sense of one.
    """
    if not tools or plugin.manifest is None:
        return []
    from policy_file import ALWAYS_KNOWN_TOOLS

    recognised = tools | set(ALWAYS_KNOWN_TOOLS)
    problems: list[str] = []
    for name in plugin.manifest.policy.get("deny_tools") or ():
        if str(name) not in recognised and not str(name).startswith("mcp__"):
            problems.append(
                f"policy.deny_tools names {name!r}, which this runtime does not have (known tools: "
                f"{', '.join(sorted(recognised))})"
            )
    for hook in plugin.manifest.hooks:
        if hook.tool and hook.tool not in tools:
            problems.append(f"hook names tool {hook.tool!r}, which this runtime does not have")
    return problems
#: Where an installed bundle lives, relative to the workspace: the prefix every path a
#: plugin contributes (skill root, agent file, hook script) is measured from, and the
#: one thing a reader can grep for when they want to know how a file got here.
INSTALLED_PREFIX = PLUGINS_DIRECTORY


def _read_capped(path: Path) -> str:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as error:
        raise PluginInstallError(f"{path}: cannot read ({error})") from error
    if len(text) > MAX_CONTEXT_CHARS:
        return text[:MAX_CONTEXT_CHARS] + "\n[truncated]"
    return text


# -- install / uninstall ----------------------------------------------------


@dataclass(frozen=True)
class InstallResult:
    """What landed, and what the operator has to do next."""

    name: str
    version: str
    root: Path
    content_digest: str
    installed: bool
    replaced: bool
    note: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "path": str(self.root),
            "content_digest": self.content_digest,
            "installed": self.installed,
            "replaced": self.replaced,
            "note": self.note,
        }


def install(
    source: str | Path,
    workspace: str | Path,
    *,
    force: bool = False,
    pin: bool = True,
    require_seal: bool = False,
    fail_on: str = "error",
    environment: Mapping[str, str] | None = None,
) -> InstallResult:
    """Copy a bundle into the workspace and pin its digest.

    The refusal list is the point of the function: a bundle that does not run here, that
    tries to widen the workspace policy, or that carries a seal nobody can check, is
    *not installed* - it is not installed "with a warning". A plugin install is the moment
    with the most context available (the operator is standing there reading output), and
    every one of those checks costs nothing then and everything later.

    ``require_seal`` is what a CI job wants: refuse to land anything whose publisher the
    workspace cannot verify, instead of landing it and trusting the human to notice.
    """
    bundle = load_bundle(source)
    policy = _workspace_policy_document(workspace)
    plugin = parse_manifest(bundle, workspace_policy=policy)
    if plugin.name != Path(source).resolve().name:
        # The directory name is the lock key and the path a reader greps for; letting a
        # bundle call itself something else makes `.northstar/plugins/<x>` a lie.
        raise PluginInstallError(
            f"bundle directory is {Path(source).resolve().name!r} but the manifest names it {plugin.name!r}; "
            "rename one of them (the directory is where a reviewer looks)"
        )
    host_problem = check_host_compatibility(plugin)
    if host_problem:
        raise PluginInstallError(f"{plugin.name}: not installable on this host - {host_problem}")
    # The skill text is read before a single byte is copied. An install that lands a bundle
    # and then warns about its instructions is an install that trusts the reader to notice.
    audits = review_bundle_skills(InstalledPlugin(plugin.name, Path(source), plugin, bundle, "", "pinned"))
    if skill_bar_met(audits, fail_on):
        findings = describe_findings(audits, at_or_above=fail_on)
        raise PluginInstallError(
            f"{plugin.name}: {len(findings)} skill finding(s) at or above {fail_on!r} in the bundle's own "
            "SKILL.md files, so nothing was installed. Read them; --fail-on never is the only bar that lets a "
            "flagged bundle land, and choosing it is a decision, not a workaround: " + " | ".join(findings[:4])
        )
    if require_seal and not plugin.seal:
        raise PluginInstallError(
            f"{plugin.name}: declares no integrity.seal, and --require-seal says the workspace will only "
            "accept bundles whose publisher can be verified"
        )
    integrity = verify_integrity(plugin, pinned_digest="", environment=environment)
    if integrity.get("seal") not in {"valid", "none"}:
        raise PluginInstallError(
            f"{plugin.name}: seal is {integrity.get('seal')}; refusing to install something the seal check "
            "could not pass (an unverifiable seal is not an absent one)"
        )
    target = plugins_directory(workspace) / plugin.name
    if target.exists():
        existing, _problems = load_installed(workspace, require_lock=False)
        current = next((item for item in existing if item.name == plugin.name), None)
        if current and current.manifest.content_digest == bundle.content_digest and not force:
            return InstallResult(
                plugin.name, plugin.version, target, bundle.content_digest, False, False,
                "already installed and identical; nothing was written",
            )
        if not force:
            raise PluginInstallError(
                f"{plugin.name} is already installed at {target} and differs from this source; "
                "re-run with --force to replace it (the lock entry is updated only on success)"
            )
        _remove_tree(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(source, target, symlinks=False)
    if pin:
        entries = read_lock(workspace)
        entries[plugin.name] = {
            "version": plugin.version,
            "publisher": plugin.publisher,
            "content_digest": bundle.content_digest,
            "source": str(Path(source).resolve()),
        }
        write_lock(workspace, entries)
    note = (
        "installed but NOT pinned: `plugin verify --write-lock` is what makes this loadable"
        if not pin
        else "pinned in plugins.lock; review the diff before committing it"
    )
    return InstallResult(plugin.name, plugin.version, target, bundle.content_digest, True, force, note)


def uninstall(name: str, workspace: str | Path, *, keep_lock: bool = False) -> str:
    """Remove one installed bundle, and its lock entry unless ``keep_lock`` says otherwise."""
    target = plugins_directory(workspace) / name
    if not target.is_dir():
        raise PluginInstallError(f"{name}: no plugin installed at {target}")
    _remove_tree(target)
    removed = f"removed {target}"
    if not keep_lock:
        entries = read_lock(workspace)
        if name in entries:
            del entries[name]
            write_lock(workspace, entries)
            removed += f"; dropped {name} from {lock_path(workspace).name}"
        left = [path.name for path in plugins_directory(workspace).iterdir() if path.is_dir()] if plugins_directory(workspace).is_dir() else []
        if not left:
            try:
                plugins_directory(workspace).rmdir()
            except OSError:
                pass
    return removed


def _remove_tree(target: Path) -> None:
    for path in sorted(target.rglob("*"), reverse=True):
        if path.is_symlink():
            raise PluginInstallError(f"{path}: refusing to remove a symlink installed by a plugin")
    shutil.rmtree(target)


def _workspace_policy_document(workspace: str | Path) -> dict[str, Any] | None:
    """The workspace's ceilings, as a tighten-only comparison needs them.

    Read through :func:`policy_file.read_policy_document` rather than the validating loader,
    on purpose: comparing two numbers must not require the plugin loader to know the run's
    final tool and agent sets. Values of the wrong type are dropped instead of raising -
    such a file is refused by ``load_policy_file`` when the run starts, and a plugin report
    is not the place to invent a second, partial validator.
    """
    from policy_file import read_policy_document

    raw = read_policy_document(workspace)
    if raw is None:
        return None

    def positive_int(key: str) -> int | None:
        value = raw.get(key)
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            return None
        return int(value)

    document: dict[str, Any] = {}
    for key in ("max_turns", "max_tool_calls"):
        value = positive_int(key)
        if value is not None:
            document[key] = value
    budget = raw.get("max_budget_usd")
    if not isinstance(budget, bool) and isinstance(budget, (int, float)) and budget >= 0:
        document["max_budget_usd"] = float(budget)
    denied = raw.get("deny_tools")
    if isinstance(denied, list) and all(isinstance(item, str) and item for item in denied):
        document["deny_tools"] = list(denied)
    for key in ("read_only", "halt_on_denial"):
        if isinstance(raw.get(key), bool):
            document[key] = bool(raw[key])
    if raw.get("permission_mode") in {"default", "plan"}:
        document["permission_mode"] = str(raw["permission_mode"])
    return document


def verify_workspace(
    workspace: str | Path,
    *,
    require_lock: bool = True,
    pin: bool = False,
    environment: Mapping[str, str] | None = None,
    workspace_policy: Mapping[str, Any] | None = None,
    fail_on: str = "error",
) -> dict[str, Any]:
    """The report ``plugin verify`` prints, as data.

    With ``pin`` it records what it just read in the lockfile - which is how a reviewer
    says "I looked at this version", and why the digest is recomputed from disk rather than
    copied from the bundle: pinning a bundle's own claim would pin the thing under review.
    """
    if workspace_policy is None:
        workspace_policy = _workspace_policy_document(workspace)
    plugins, problems = load_installed(workspace, require_lock=require_lock, workspace_policy=workspace_policy)
    previous: dict[str, str] = {}
    if pin:
        entries = read_lock(workspace)
        previous = {name: str(entry.get("content_digest") or "") for name, entry in entries.items()}
        for plugin in plugins:
            entries[plugin.name] = {
                "version": plugin.manifest.version,
                "publisher": plugin.manifest.publisher,
                "content_digest": plugin.bundle.content_digest,
                "source": str(plugin.root),
            }
        for name in sorted(set(entries) - {plugin.name for plugin in plugins}):
            # Dropping stale entries here is safe and wanted: a lock that keeps a name with
            # no bundle behind it makes "pinned" mean something other than "installed and
            # reviewed", which is the one distinction the whole file exists to record.
            del entries[name]
        write_lock(workspace, entries)
        # Re-read, so the report describes the state the command *left* rather than the
        # state it found: a reviewer who just pinned a bundle should see "ok", and a report
        # that said "drift" after fixing the drift would be read as a broken tool.
        plugins, problems = load_installed(workspace, require_lock=require_lock, workspace_policy=workspace_policy)
    on_disk = {plugin.name: plugin.manifest.content_digest for plugin in plugins if plugin.manifest is not None}
    # Re-running the review belongs in verification, not in a courtesy: the rules change with
    # `skill_audit.RULES_VERSION`, so a bundle pinned in March can be clean-then-flagged in
    # September without its bytes moving. `run` deliberately does not consult this - a rule
    # bump must not turn every workspace's installed plugins into a configuration error by
    # itself; a human re-reviews, and `--write-lock` records that.
    reviews: dict[str, tuple[SkillAudit, ...]] = {}
    for plugin in plugins:
        audits = review_bundle_skills(plugin)
        reviews[plugin.name] = audits
        if skill_bar_met(audits, fail_on):
            findings = describe_findings(audits, at_or_above=fail_on)
            problems.append(
                f"{plugin.name}: its own SKILL.md files carry {len(findings)} finding(s) at or above "
                f"{fail_on!r} - " + "; ".join(finding.split(" - ", 1)[-1] for finding in findings[:3])
            )
    return {
        "ok": not problems and all(plugin.usable for plugin in plugins) and (not require_lock or all(plugin.pinned_digest for plugin in plugins)),
        # Which bundles' pins just moved. Pinning is the reviewer's act, so a tampered
        # bundle *can* be pinned - the point is that the report says it happened, instead of
        # letting "verify --pin" read as a green light.
        "repinned": sorted(
            name
            for name, digest in previous.items()
            if digest and on_disk.get(name, digest) != digest
        ),
        "host": current_host_profile()["name"],
        "lock": str(lock_path(workspace)),
        "plugins": [plugin.as_dict() for plugin in plugins],
        "problems": problems,
        # The review per bundle, findings and all: a CI job that runs `plugin verify` gets the
        # same detail a human sees on a terminal, and does not have to re-read the tree for it.
        "skill_review": {
            name: {
                "summary": summarise_audits(list(audits)),
                "findings": list(describe_findings(audits)),
                "fail_on": fail_on,
            }
            for name, audits in reviews.items()
        },
        "portability": {
            plugin.name: portability_report(plugin.manifest, plugin.bundle.files)
            for plugin in plugins
            if plugin.manifest is not None
        },
    }


#: Same meaning as everywhere else in this component (cli and skill_check define it too,
#: because importing `cli` from a module `cli` imports would be a cycle).
USAGE_ERROR = 64

__all__ = [
    "InstalledPlugin",
    "add_plugin_arguments",
    "run_plugin_command",
    "InstallResult",
    "LOCK_SCHEMA_VERSION",
    "PluginContributions",
    "PluginInstallError",
    "install",
    "load_contributions",
    "load_installed",
    "lock_path",
    "plugins_directory",
    "read_lock",
    "uninstall",
    "verify_workspace",
    "write_lock",
]


# -- command line -----------------------------------------------------------


def add_plugin_arguments(parser: argparse.ArgumentParser) -> None:
    """The ``plugin`` subcommands, built on one parser so `run` can share the flags."""
    sub = parser.add_subparsers(dest="plugin_command", metavar="ACTION")

    def workspace(flag: argparse.ArgumentParser) -> None:
        flag.add_argument("--workspace", default=".", help="project whose .northstar/plugins to act on")

    listing = sub.add_parser("list", help="installed bundles, their components and their lock status")
    workspace(listing)
    listing.add_argument("--json", action="store_true", help="emit one JSON object instead of the report")
    listing.set_defaults(handler=run_plugin_command)

    show = sub.add_parser("show", help="one bundle's declared components, ceilings and portability matrix")
    show.add_argument("name", help="plugin name, or its installed directory")
    workspace(show)
    show.add_argument("--json", action="store_true", help="emit one JSON object instead of the report")
    show.set_defaults(handler=run_plugin_command)

    verify = sub.add_parser("verify", help="re-hash every installed bundle and compare with plugins.lock")
    workspace(verify)
    verify.add_argument("--json", action="store_true", help="emit one JSON object instead of the report")
    verify.add_argument(
        "--write-lock",
        action="store_true",
        help="record what was just read as the reviewed set (the review, made durable)",
    )
    verify.add_argument(
        "--allow-unpinned",
        action="store_true",
        help="treat a bundle missing from plugins.lock as reviewable rather than refused",
    )
    verify.add_argument("--seal-key-env", default="", metavar="NAME", help="environment variable holding the seal key")
    verify.add_argument(
        "--fail-on",
        default="error",
        choices=FAIL_ON_CHOICES,
        help="also fail when a bundle's own skill text carries a finding at or above this severity",
    )
    verify.set_defaults(handler=run_plugin_command)

    install = sub.add_parser("install", help="copy a bundle into the workspace and pin its digest")
    install.add_argument("source", help="directory containing plugin.toml")
    workspace(install)
    install.add_argument("--force", action="store_true", help="replace an installed bundle that differs")
    install.add_argument("--no-pin", action="store_true", help="install without writing plugins.lock (it will not load)")
    install.add_argument("--require-seal", action="store_true", help="refuse a bundle with no verifiable publisher seal")
    install.add_argument(
        "--fail-on",
        default="error",
        choices=FAIL_ON_CHOICES,
        help=(
            "refuse a bundle whose own SKILL.md files carry a finding at or above this severity - the bar "
            "`skills check` uses (`never` is the only setting that lets a flagged bundle land)"
        ),
    )
    install.add_argument("--seal-key-env", default="", metavar="NAME", help="environment variable holding the seal key")
    install.set_defaults(handler=run_plugin_command)

    remove = sub.add_parser("uninstall", help="remove one installed bundle (and its lock entry)")
    remove.add_argument("name", help="plugin name")
    workspace(remove)
    remove.add_argument("--keep-lock", action="store_true", help="leave the reviewed entry in place (pinning is a review of its own)")
    remove.set_defaults(handler=run_plugin_command)

    compat = sub.add_parser("compat", help="portability of every installed bundle across host profiles")
    workspace(compat)
    compat.add_argument("--host", action="append", default=[], metavar="OS", help="limit to these hosts; repeatable")
    compat.add_argument("--json", action="store_true", help="emit one JSON object instead of the report")
    compat.set_defaults(handler=run_plugin_command)

    export = sub.add_parser("export", help="render a bundle into another agent host's files (with an explicit drop list)")
    export.add_argument("target", help=f"one of: {', '.join(manifest_module.EXPORT_TARGETS)}")
    export.add_argument("--only", default="", metavar="NAME", help="bundle to export (required when several are installed)")
    workspace(export)
    export.add_argument("--directory", default="", metavar="DIR", help="write the rendered files here instead of printing them")
    export.add_argument("--allow-drop", action="store_true", help="required when the target cannot carry something the bundle declares")
    export.add_argument("--json", action="store_true", help="emit one JSON object instead of the report")
    export.set_defaults(handler=run_plugin_command)


def run_plugin_command(args: argparse.Namespace) -> int:
    """The whole `plugin` verb: read, verify, install, remove, export."""
    workspace = Path(args.workspace or ".").resolve()
    action = getattr(args, "plugin_command", "") or ""
    try:
        if action == "list":
            return _plugin_list(args, workspace)
        if action == "show":
            return _plugin_show(args, workspace)
        if action == "verify":
            return _plugin_verify(args, workspace)
        if action == "install":
            return _plugin_install(args, workspace)
        if action == "uninstall":
            return _plugin_uninstall(args, workspace)
        if action == "compat":
            return _plugin_compat(args, workspace)
        if action == "export":
            return _plugin_export(args, workspace)
    except (PluginError, PluginInstallError) as error:
        print(f"configuration error: {error}", file=sys.stderr)
        return USAGE_ERROR
    print(f"unknown plugin action: {action}", file=sys.stderr)
    return USAGE_ERROR


def _plugin_list(args: argparse.Namespace, workspace: Path) -> int:
    # require_lock=False because `list` is a question about what is installed, not about
    # whether it may load - but the workspace policy still applies, so a bundle that would
    # loosen it is shown as broken here and refused by the run, identically.
    plugins, problems = load_installed(
        workspace, require_lock=False, workspace_policy=_workspace_policy_document(workspace)
    )
    if getattr(args, "json", False):
        print(json.dumps({"type": "plugin-list", "workspace": str(workspace), "lock": str(lock_path(workspace)), "plugins": [plugin.as_dict() for plugin in plugins], "problems": problems}, indent=2, sort_keys=True))
        return 0
    if not plugins:
        print("no plugins installed (.northstar/plugins/)")
        return 0
    entries = read_lock(workspace)
    print(f"{'PLUGIN':<20} {'VERSION':<10} {'STATUS':<14} SKILLS AGENTS HOOKS MCP  DIGEST")
    for plugin in plugins:
        declared = plugin.manifest
        if declared is None:
            counts = "   -   -   -   -"
        else:
            counts = "".join(
                f"{len(items):>4}"
                for items in (declared.skill_dirs, declared.agent_dirs, declared.hooks, declared.mcp_servers)
            )
        digest = (declared.content_digest if declared else "")[:15]
        pinned = "*" if plugin.name in entries else "-"
        print(f"{plugin.name:<20} {(plugin.manifest.version if plugin.manifest else '?'):<10} {pinned + ' ' + plugin.status:<14} {counts}  {digest}")
    for problem in problems:
        print(f"  ! {problem}")
    print("* = pinned in plugins.lock; a bundle without a pin will not load")
    return 0


def _plugin_show(args: argparse.Namespace, workspace: Path) -> int:
    plugins, _problems = load_installed(
        workspace, require_lock=False, workspace_policy=_workspace_policy_document(workspace)
    )
    wanted = str(args.name).strip()
    plugin = next((item for item in plugins if item.name == wanted or item.root.name == wanted), None)
    if plugin is None:
        print(f"{wanted}: no plugin installed under {plugins_directory(workspace)}", file=sys.stderr)
        return USAGE_ERROR
    if plugin.manifest is None:
        print(f"{plugin.name}: {plugin.detail}", file=sys.stderr)
        return 1
    manifest = plugin.manifest
    payload = {
        "type": "plugin-show",
        **manifest.as_dict(),
        "usable": plugin.usable,
        "status": plugin.status,
        "detail": plugin.detail,
        "portability": portability_report(manifest, plugin.bundle.files),
        "host_problem": check_host_compatibility(manifest) or "",
    }
    if getattr(args, "json", False):
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0
    print(f"{manifest.name} {manifest.version} - {manifest.publisher} ({manifest.license or 'no license declared'})")
    print(f"  {manifest.description}")
    if manifest.homepage:
        print(f"  homepage: {manifest.homepage}")
    print(f"  content digest: {manifest.content_digest}")
    files = plugin.bundle.files
    print(f"  files: {len(files)} ({sum(item.size for item in files)} bytes)")
    print("  components:")
    for line in manifest_module.component_lines(manifest):
        print(f"    {line}")
    if manifest.policy:
        print("  ceilings it asks for (tighten-only): " + ", ".join(f"{key}={value}" for key, value in sorted(manifest.policy.items())))
    else:
        print("  policy: none (the workspace's ceilings stand)")
    requirements = {
        "platforms": "/".join(manifest.platforms),
        "min_python": manifest.min_python,
        "requires_flock": manifest.requires_flock,
        "requires_network": manifest.requires_network,
    }
    print("  requires: " + ", ".join(f"{key}={value}" for key, value in requirements.items()))
    if payload["host_problem"]:
        print(f"  this host: refused - {payload['host_problem']}")
    report = payload["portability"]
    print(f"  portability: {'fits every host profile we know' if report['portable_everywhere'] else 'not portable'}")
    for row in report["hosts"]:
        print(f"    {row['host']:<8} {'ok' if row['fits'] else 'NO '}  " + "; ".join(row["reasons"]) + (" (this host)" if row["here"] else ""))
    for collision in report["case_collisions"]:
        print(f"    case collision: {collision}")
    if plugin.status != "pinned":
        print(f"  status: {plugin.status}" + (f" - {plugin.detail}" if plugin.detail else ""))
    return 0


def _plugin_verify(args: argparse.Namespace, workspace: Path) -> int:
    environment = {str(args.seal_key_env): os.environ.get(str(args.seal_key_env), "")} if getattr(args, "seal_key_env", "") else None
    report = verify_workspace(
        workspace,
        require_lock=not getattr(args, "allow_unpinned", False),
        pin=bool(getattr(args, "write_lock", False)),
        environment=environment,
        fail_on=str(getattr(args, "fail_on", "error")),
    )
    if getattr(args, "json", False):
        print(json.dumps({"type": "plugin-verify", **report}, indent=2, sort_keys=True))
    else:
        if not report["plugins"]:
            print("no plugins installed")
        for plugin in report["plugins"]:
            mark = "ok  " if plugin["status"] == "pinned" else "FAIL"
            print(f"  {mark} {plugin['name']} {plugin.get('version', '?')}: {plugin['status']}" + (f" - {plugin['detail']}" if plugin.get("detail") else ""))
        for problem in report["problems"]:
            print(f"  ! {problem}")
        for name in report.get("repinned", []):
            print(f"  ~ {name}: the pin moved (content changed since the last review); the new digest is recorded")
        for name, review in report["skill_review"].items():
            if not review["findings"]:
                continue
            counts = review["summary"]["findings"]
            print(
                f"  skill review: {name} - {counts['error']} error, {counts['warn']} warn, "
                f"{counts['info']} info (bar: {review['fail_on']})"
            )
            for line in review["findings"][:10]:
                print(f"    {line}")
            if len(review["findings"]) > 10:
                print(f"    … {len(review['findings']) - 10} more")
        if getattr(args, "write_lock", False):
            print(f"  reviewed set written to {report['lock']}")
        print(("plugins verified: all pinned bundles match the reviewed set" if report["ok"] else "plugins failed verification") + f" (host: {report['host']})")
    return 0 if report["ok"] else 1


def _plugin_install(args: argparse.Namespace, workspace: Path) -> int:
    environment = {str(args.seal_key_env): os.environ.get(str(args.seal_key_env), "")} if getattr(args, "seal_key_env", "") else None
    result = install(
        args.source,
        workspace,
        force=bool(args.force),
        pin=not bool(args.no_pin),
        require_seal=bool(args.require_seal),
        fail_on=str(getattr(args, "fail_on", "error")),
        environment=environment,
    )
    payload = result.as_dict()
    if getattr(args, "json", False):
        print(json.dumps({"type": "plugin-install", **payload}, indent=2, sort_keys=True))
        return 0
    if not payload["installed"]:
        print(f"{result.name} {result.version}: {result.note}")
        return 0
    print(f"installed {result.name} {result.version} at {result.root}")
    print(f"  content digest {result.content_digest}")
    print(f"  {result.note}")
    return 0


def _plugin_uninstall(args: argparse.Namespace, workspace: Path) -> int:
    print(uninstall(str(args.name).strip(), workspace, keep_lock=bool(args.keep_lock)))
    return 0


def _plugin_compat(args: argparse.Namespace, workspace: Path) -> int:
    plugins, problems = load_installed(
        workspace, require_lock=False, workspace_policy=_workspace_policy_document(workspace)
    )
    hosts = tuple(str(item) for item in (args.host or ()))
    payload = {
        "type": "plugin-compat",
        "host": current_host_profile()["name"],
        "hosts": {
            plugin.name: portability_report(plugin.manifest, plugin.bundle.files, only_hosts=hosts or None)
            for plugin in plugins
            if plugin.manifest is not None
        },
        "problems": problems,
    }
    if getattr(args, "json", False):
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0
    if not payload["hosts"]:
        print("no plugins installed")
        return 0
    names = hosts or [str(profile) for profile in HOST_PROFILES]
    print(f"{'PLUGIN':<20} " + " ".join(f"{name:<9}" for name in names) + "   portable")
    for name, report in payload["hosts"].items():
        by_host = {row["host"]: row for row in report["hosts"]}
        cells = []
        for host_name in names:
            row = by_host.get(host_name)
            cells.append("-" if row is None else ("ok" if row["fits"] else "NO"))
        print(f"{name:<20} " + " ".join(f"{cell:<9}" for cell in cells) + f"   {'yes' if report['portable_everywhere'] else 'no'}")
    print()
    for name, report in payload["hosts"].items():
        for row in report["hosts"]:
            if not row["fits"]:
                print(f"  {name} on {row['host']}: " + "; ".join(row["reasons"]))
        for collision in report["case_collisions"]:
            print(f"  {name}: case-insensitive collision: {collision}")
    print("  (a host profile is our description of the primitives this runtime uses there, not a conformance suite)")
    return 0


def _plugin_export(args: argparse.Namespace, workspace: Path) -> int:
    plugins, _problems = load_installed(
        workspace, require_lock=False, workspace_policy=_workspace_policy_document(workspace)
    )
    usable = [plugin for plugin in plugins if plugin.manifest is not None]
    if args.only:
        usable = [plugin for plugin in usable if plugin.name == str(args.only).strip()]
    if len(usable) != 1:
        print(
            f"{'no bundle to export' if not usable else 'name one bundle with --only (several are installed)'}",
            file=sys.stderr,
        )
        return USAGE_ERROR
    plugin = usable[0]
    target = str(args.target).strip()
    export = manifest_module.export_bundle(plugin.bundle, plugin.manifest, target=target)
    if export.dropped and not args.allow_drop:
        # Refusing to write is the point: the files a host would read are only half the
        # story, and nobody should discover the missing veto hooks by running without them.
        print(
            f"configuration error: {target} cannot carry {'; '.join(export.dropped)} from this bundle.\n"
            "  the export would be a downgrade, not a port. Re-run with --allow-drop to write it "
            "anyway (the drop list is printed either way), or keep those capabilities in Northstar.",
            file=sys.stderr,
        )
        return USAGE_ERROR
    payload = {"type": "plugin-export", **export.as_dict()}
    destination = Path(args.directory).resolve() if args.directory else None
    if destination is not None:
        for relative, text in sorted(export.files.items()):
            path = destination / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        payload["written_to"] = str(destination)
    if getattr(args, "json", False):
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0
    print(f"# {export.target} export of {plugin.name} {plugin.manifest.version}")
    for note in export.notes:
        print(f"# {note}")
    if export.dropped:
        print("# dropped (this target has no equivalent):")
        for item in export.dropped:
            print(f"#   - {item}")
    for relative, text in sorted(export.files.items()):
        print(f"\n# --- {relative} ---")
        print(text.rstrip())
    if destination is not None:
        print(f"\nwrote {len(export.files)} file(s) to {destination}")
    return 0
