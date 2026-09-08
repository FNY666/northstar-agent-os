"""The plugin bundle format: one directory of capability, five hosts that can read it.

What a plugin is here, and what it is not
-----------------------------------------
A plugin is **a directory with a manifest**, and everything in it is one of the four
extension seams this runtime already has: Agent Skills, agent definitions, lifecycle
command hooks, MCP servers, and a policy contribution that may only tighten. There is no
plugin code path in the loop: a plugin cannot register a tool, cannot widen permissions,
and cannot add a hook that bypasses `--enable-workspace-hooks`. "Plugin" is therefore not
a new authority - it is a *shippable, verifiable bundle of existing ones*, which is the
difference between an extension ecosystem and an unvetted second control plane.

Install is a file copy into ``.northstar/plugins/<name>/``, which is git-visible,
reviewable in a normal diff, and revertable by the normal means. There is no marketplace,
no resolver and no download: the blueprint's ruling (C5) is that a hosted index of
unsigned capability is the one thing this component must not become, because every
"install one thing to get ten" design moves the trust decision out of the repository and
into somebody else's uptime.

Two kinds of verification, and neither is theatre
-------------------------------------------------
* **Content digest** is computed over the manifest (minus its ``integrity`` table, which
  is a claim about the bundle and cannot include itself) plus every file, sorted by
  relative path, each length-prefixed. The *reviewed* value lives in the workspace's
  ``plugins.lock``, not in the bundle: a manifest that vouches for its own hash is a field
  an attacker simply does not update. ``plugin verify`` recomputes and compares, which is
  what catches the tamper-after-review case that ``skills.lock`` catches for skills.
* **Seal** (``integrity.seal``) is an HMAC-SHA256 over the *file digest only*, keyed from
  an environment variable the publisher and the installer both know. It is called a seal
  and not a signature deliberately: it proves "this bundle came from someone holding that
  key", nothing more, and the module says so in the report rather than letting a caller
  read it as publisher authentication. A present-but-unverifiable seal (no key, unknown
  algorithm) is a hard error; there is no code path where a seal fails and the plugin
  still loads.

Platform compatibility is a claim, checked per platform
-------------------------------------------------------
`compatibility.platforms` is the author's claim ("works on posix", "needs flock", "needs
python>=3.11"). `portability_report()` evaluates that claim against each *host* profile
this component knows about, so "does this work on all platforms?" is a question with a
printed answer on the machine you are asking from - and a `plugin install` on a host that
does not match is refused rather than half-applied. The honest limitation is in the
function's docstring: the profiles are ours, not a conformance suite.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from command_hooks import ALLOWED_INTERPRETERS, DEFAULT_TIMEOUT_MS, MAX_HOOKS, MAX_TIMEOUT_MS, MIN_TIMEOUT_MS
from hooks import VETO_EVENTS

try:  # same fallback chain as policy_file.py: 3.11+ has it in the standard library
    import tomllib as _toml
except ImportError:  # pragma: no cover - Python 3.10 fallback
    try:
        import tomli as _toml  # type: ignore[no-redef]
    except ImportError as error:  # pragma: no cover - depends on the host
        raise ImportError(
            "reading plugin.toml needs Python 3.11+ or the 'tomli' package (pip install tomli)"
        ) from error

PLUGIN_SCHEMA_VERSION = "northstar.plugin.v1"
MANIFEST_NAME = "plugin.toml"
PLUGINS_DIRECTORY = ".northstar/plugins"
LOCK_NAME = "plugins.lock"

#: A plugin name is a path segment and a lock key, so it gets the same rule the run
#: contract uses for ids, plus lowercase: mixed case in a directory name is how two
#: plugins end up in one folder on a case-insensitive filesystem.
NAME_PATTERN = r"^[a-z][a-z0-9_-]{0,63}$"
_NAME_RE = re.compile(NAME_PATTERN)
#: Semver-ish and nothing more: the runtime is not a package manager, and pretending to
#: resolve versions would be a promise this module cannot keep.
_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")
_SEAL_RE = re.compile(r"^[0-9a-f]{64}$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

MAX_DESCRIPTION_CHARS = 2_000
#: A bundle that needs more than this is a repository, not a plugin; the cap is also what
#: keeps `verify` bounded on a hostile directory.
MAX_FILES = 200
MAX_FILE_BYTES = 1 << 20  # 1 MiB per file
#: A plugin hook is not a new hook mechanism: it is a ``[[hooks]]`` table, validated by
#: :func:`command_hooks.parse_hooks` against the *same* bounds a repository's own hooks must
#: satisfy. So the event set and the limits are imported from where they are defined instead
#: of copied here - a copy is a second opinion about somebody else's guardrail, and the two
#: drift apart the first time one of them is tightened.
HOOK_EVENTS: tuple[str, ...] = tuple(VETO_EVENTS)

#: The whole manifest. An unknown key is an error, not a warning: a key the loader does
#: not read is a capability the author believes they granted.
ALLOWED_KEYS = frozenset(
    {
        "schema_version",
        "name",
        "version",
        "description",
        "publisher",
        "homepage",
        "license",
        "keywords",
        "components",
        "policy",
        "compatibility",
        "integrity",
    }
)
ALLOWED_COMPONENT_KEYS = frozenset({"skills", "agents", "hooks", "mcp_servers", "context"})
ALLOWED_POLICY_KEYS = frozenset(
    {
        "read_only",
        "deny_tools",
        "permission_mode",
        "max_turns",
        "max_tool_calls",
        "max_budget_usd",
        "halt_on_denial",
    }
)
ALLOWED_COMPATIBILITY_KEYS = frozenset({"platforms", "min_python", "requires_flock", "requires_network"})
#: A manifest may not carry the digest of itself - that is a self-reference, and the
#: usual way a "checksum" becomes a field an attacker simply does not update. The
#: workspace's ``plugins.lock`` records the reviewed digest instead (see
#: :func:`verify_integrity`), and ``verify`` compares the two.
ALLOWED_INTEGRITY_KEYS = frozenset({"seal", "seal_key_env"})

PLATFORMS = ("any", "posix", "linux", "darwin", "windows")

#: The host profiles `plugin compat` scores a bundle against. These are the platforms the
#: runtime itself claims, described by the primitives it actually uses: ``flock`` is the
#: session lease, ``execvp`` is the command-hook runner, ``os.replace`` is the atomic
#: writer. They are *our* profiles, not a conformance suite.
HOST_PROFILES: dict[str, dict[str, Any]] = {
    "linux": {"posix": True, "flock": True, "execvp": True, "case_sensitive": True, "python": (3, 11)},
    "darwin": {"posix": True, "flock": True, "execvp": True, "case_sensitive": True, "python": (3, 11)},
    "windows": {"posix": False, "flock": False, "execvp": True, "case_sensitive": False, "python": (3, 11)},
}


class PluginError(ValueError):
    """A plugin that cannot be trusted, loaded, or exported. Message is operator-facing."""


def _fail(message: str) -> "PluginError":
    return PluginError(message)


# -- the bundle on disk -----------------------------------------------------


@dataclass(frozen=True)
class BundleFile:
    """One file inside a bundle, with the digest the manifest's integrity claim covers."""

    relative_path: str
    size: int
    sha256: str

    def as_dict(self) -> dict[str, Any]:
        return {"path": self.relative_path, "bytes": self.size, "sha256": self.sha256}


@dataclass(frozen=True)
class Bundle:
    """A plugin directory as it exists on disk - which is not the same as what it claims."""

    root: Path
    manifest: dict[str, Any]
    files: tuple[BundleFile, ...]
    content_digest: str  # "sha256:<hex>" over the manifest + every file, canonical framing

    def relative(self, path: str) -> Path:
        """A declared path, resolved *inside* the bundle or refused."""
        candidate = (self.root / path).resolve(strict=False)
        if candidate != self.root and self.root not in candidate.parents:
            raise _fail(
                f"{path} resolves outside the plugin directory ({candidate}); a plugin may not "
                "reach into the workspace or the filesystem around it"
            )
        return candidate

    def component_paths(self, kind: str) -> tuple[str, ...]:
        components = self.manifest.get("components") or {}
        value = components.get(kind) or []
        return tuple(str(item) for item in value)

    def as_dict(self) -> dict[str, Any]:
        return {
            "root": str(self.root),
            "manifest": self.manifest,
            "files": [item.as_dict() for item in self.files],
            "content_digest": self.content_digest,
        }


def _digest_payload(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _canonical_bundle_digest(manifest: Mapping[str, Any], files: Sequence[BundleFile]) -> str:
    """Digest of the manifest (minus its ``integrity`` table) plus every file, length-prefixed.

    The framing is not cosmetic. A plain concatenation lets a bundle that is
    ``"ab"+"c"`` collide with one that is ``"a"+"bc"``, and a digest an attacker can
    collide is not an integrity check; lengths also stop a file boundary from being
    moved by adding a newline.
    """
    hasher = hashlib.sha256()
    # ``integrity`` is excluded: it is a claim *about* the bundle, and folding it in
    # produces a value nobody can compute before writing the file that contains it.
    payload = {key: value for key, value in manifest.items() if key != "integrity"}
    body = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    hasher.update(b"manifest")
    hasher.update(len(body).to_bytes(8, "big"))
    hasher.update(body)
    for item in files:
        hasher.update(b"file")
        name = item.relative_path.encode("utf-8")
        hasher.update(len(name).to_bytes(8, "big"))
        hasher.update(name)
        hasher.update(len(item.sha256).to_bytes(8, "big"))
        hasher.update(item.sha256.encode("ascii"))
    return "sha256:" + hasher.hexdigest()


def _collect_files(root: Path) -> tuple[BundleFile, ...]:
    found: list[BundleFile] = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise _fail(f"{path.relative_to(root)}: a plugin may not contain symlinks")
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        if relative == MANIFEST_NAME:
            continue  # the manifest is digested from its parsed content, not its bytes
        size = path.stat().st_size
        if size > MAX_FILE_BYTES:
            raise _fail(
                f"{relative}: {size} bytes exceeds the {MAX_FILE_BYTES}-byte per-file limit for plugins"
            )
        try:
            payload = path.read_bytes()
        except OSError as error:  # pragma: no cover - unreadable file on a live disk
            raise _fail(f"{relative}: cannot read ({error})") from error
        found.append(BundleFile(relative, size, _digest_payload(payload).removeprefix("sha256:")))
    if len(found) > MAX_FILES:
        raise _fail(f"{root.name}: {len(found)} files exceeds the {MAX_FILES}-file limit for plugins")
    return tuple(found)


def load_bundle(root: str | Path) -> Bundle:
    """Read a plugin directory: manifest parsed, files digested, nothing else executed."""
    directory = Path(root)
    if not directory.is_dir():
        raise _fail(f"{directory}: not a directory")
    manifest_path = directory / MANIFEST_NAME
    if not manifest_path.is_file():
        raise _fail(f"{manifest_path}: a plugin directory needs a {MANIFEST_NAME}")
    try:
        raw = manifest_path.read_bytes()
    except OSError as error:
        raise _fail(f"{manifest_path}: cannot read ({error})") from error
    try:
        manifest = _toml.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as error:
        raise _fail(f"{manifest_path}: {MANIFEST_NAME} is not valid TOML ({error})") from error
    if not isinstance(manifest, dict):
        raise _fail(f"{manifest_path}: top level must be a table")
    files = _collect_files(directory)
    return Bundle(
        root=directory,
        manifest=manifest,
        files=files,
        content_digest=_canonical_bundle_digest(manifest, files),
    )


# -- the manifest, as a closed schema --------------------------------------


@dataclass(frozen=True)
class HookClaim:
    """One declared lifecycle hook, in exactly the shape ``[[hooks]]`` uses.

    There is no ``command`` key and no ``argv`` here on purpose: a command hook in this
    runtime names a *script inside the bundle*, optionally an interpreter from a short
    allowlist, and is executed without a shell. A bundle that could write a shell line
    would be a bundle that can do anything the operator's own ``.northstar/config.toml``
    can do, with none of the review around it.
    """

    event: str
    script: str
    interpreter: str = ""
    timeout_ms: int = DEFAULT_TIMEOUT_MS
    tool: str = ""
    agent: str = ""
    description: str = ""

    def as_hook_table(self, *, script_path: str = "") -> dict[str, Any]:
        """The raw ``[[hooks]]`` entry, for :func:`command_hooks.parse_hooks` to police.

        ``script_path`` replaces the bundle-relative ``script`` when the caller hands the
        table to a validator whose root is the *workspace*: the loader passes the installed
        location, so the ordinary confinement check runs on the file that will actually be
        executed instead of on a path that only exists before installation.
        """
        table: dict[str, Any] = {"event": self.event, "script": script_path or self.script, "timeout_ms": self.timeout_ms}
        for key, value in (
            ("interpreter", self.interpreter),
            ("tool", self.tool),
            ("agent", self.agent),
            ("description", self.description),
        ):
            if value:
                table[key] = value
        return table


@dataclass(frozen=True)
class PluginManifest:
    """The parsed, validated claims of one bundle. Every field here was checked to load."""

    name: str
    version: str
    description: str
    publisher: str
    homepage: str
    license: str
    keywords: tuple[str, ...]
    skill_dirs: tuple[str, ...] = ()
    agent_dirs: tuple[str, ...] = ()
    context_files: tuple[str, ...] = ()
    hooks: tuple[HookClaim, ...] = ()
    mcp_servers: tuple[dict[str, Any], ...] = ()
    policy: Mapping[str, Any] = field(default_factory=dict)
    platforms: tuple[str, ...] = ("any",)
    min_python: str = "3.11"
    requires_flock: bool = False
    requires_network: bool = False
    content_digest: str = ""
    seal: str = ""
    seal_key_env: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": PLUGIN_SCHEMA_VERSION,
            "name": self.name,
            "version": self.version,
            "publisher": self.publisher,
            "description": self.description,
            "homepage": self.homepage,
            "license": self.license,
            "keywords": list(self.keywords),
            "components": {
                "skills": list(self.skill_dirs),
                "agents": list(self.agent_dirs),
                "context": list(self.context_files),
                "hooks": [
                    hook.as_hook_table()
                    for hook in self.hooks
                ],
                "mcp_servers": [dict(server) for server in self.mcp_servers],
            },
            "policy": dict(self.policy),
            "compatibility": {
                "platforms": list(self.platforms),
                "min_python": self.min_python,
                "requires_flock": self.requires_flock,
                "requires_network": self.requires_network,
            },
            "integrity": {
                # The digest a reviewer pins lives in plugins.lock, never in here.
                "seal": self.seal,
                "seal_key_env": self.seal_key_env,
                "content_digest": self.content_digest,
            },
            "content_digest": self.content_digest,
        }

    def summary_line(self) -> str:
        counts = (
            f"skills={len(self.skill_dirs)} agents={len(self.agent_dirs)} hooks={len(self.hooks)} "
            f"mcp={len(self.mcp_servers)} policy={'yes' if self.policy else 'no'}"
        )
        return f"{self.name}@{self.version} ({self.publisher}): {counts}; platforms={','.join(self.platforms)}"


def _require_exact_keys(value: Mapping[str, Any], allowed: frozenset[str], label: str) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise _fail(
            f"{label}: unknown key(s) {', '.join(unknown)}; allowed: {', '.join(sorted(allowed))}. "
            "A key nobody reads is a capability somebody meant."
        )


def _check_declared_paths(bundle: Bundle, manifest: Mapping[str, Any]) -> None:
    components = manifest.get("components") or {}
    for key in ("skills", "agents", "context", "hooks"):
        for item in components.get(key) or []:
            if isinstance(item, Mapping):
                script = str(item.get("script") or "")
                if not script:
                    raise _fail(f"components.{key}: a hook needs 'script' (a path inside the bundle)")
                target = bundle.relative(script)
                if not target.is_file():
                    raise _fail(f"components.{key}: {script} does not exist inside the bundle")
                continue
            target = bundle.relative(str(item))
            if not target.exists():
                raise _fail(f"components.{key}: {item} does not exist inside the bundle")


def parse_manifest(bundle: Bundle, *, workspace_policy: Mapping[str, Any] | None = None) -> PluginManifest:
    """Validate a bundle's manifest, resolve its claims, and *refuse* what cannot load.

    Every refusal here is fail-closed on purpose. A plugin that declares a Windows-only
    binary, a hook script that is not in the bundle, or a policy key the loader does not
    read must not be "loaded with a warning": in this runtime a warning is what a
    repository ships and nobody reads.
    """
    manifest = bundle.manifest
    _require_exact_keys(manifest, ALLOWED_KEYS, MANIFEST_NAME)
    version = manifest.get("schema_version")
    if version != PLUGIN_SCHEMA_VERSION:
        raise _fail(f"{MANIFEST_NAME}: schema_version must be {PLUGIN_SCHEMA_VERSION!r}, got {version!r}")

    name = manifest.get("name")
    if not isinstance(name, str) or not _NAME_RE.fullmatch(name):
        raise _fail(f"{MANIFEST_NAME}: name must match {NAME_PATTERN!r} (lowercase, no slashes or spaces)")
    raw_version = manifest.get("version")
    if not isinstance(raw_version, str) or not _VERSION_RE.fullmatch(raw_version):
        raise _fail(f"{MANIFEST_NAME}: version must be MAJOR.MINOR.PATCH (it is a label, not a range)")
    description = manifest.get("description")
    if not isinstance(description, str) or not description.strip():
        raise _fail(f"{MANIFEST_NAME}: description is required (it is what a reviewer reads first)")
    publisher = manifest.get("publisher")
    if not isinstance(publisher, str) or not publisher.strip():
        raise _fail(f"{MANIFEST_NAME}: publisher is required (an unattributed plugin has no one to ask)")

    for key in ("homepage", "license"):
        value = manifest.get(key, "")
        if value is not None and not isinstance(value, str):
            raise _fail(f"{MANIFEST_NAME}: {key} must be a string")

    keywords = manifest.get("keywords", [])
    if not isinstance(keywords, list) or any(not isinstance(item, str) or not item for item in keywords):
        raise _fail(f"{MANIFEST_NAME}: keywords must be a list of non-empty strings")

    components = manifest.get("components") or {}
    if not isinstance(components, Mapping):
        raise _fail(f"{MANIFEST_NAME}: components must be a table")
    _require_exact_keys(components, ALLOWED_COMPONENT_KEYS, f"{MANIFEST_NAME}: components")
    _check_declared_paths(bundle, manifest)

    def path_list(key: str) -> tuple[str, ...]:
        value = components.get(key) or []
        if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
            raise _fail(f"components.{key} must be a list of paths inside the bundle")
        return tuple(str(item) for item in value)

    hooks: list[HookClaim] = []
    declared_hooks = components.get("hooks") or []
    if not isinstance(declared_hooks, list):
        raise _fail("components.hooks must be a list of tables")
    if len(declared_hooks) > MAX_HOOKS:
        raise _fail(f"components.hooks: {len(declared_hooks)} hooks exceeds the per-workspace limit of {MAX_HOOKS}")
    for index, entry in enumerate(declared_hooks):
        if not isinstance(entry, Mapping):
            raise _fail(f"components.hooks[{index}] must be a table")
        _require_exact_keys(
            entry,
            frozenset({"event", "script", "interpreter", "tool", "agent", "timeout_ms", "description"}),
            f"components.hooks[{index}]",
        )
        event = entry.get("event")
        if event not in HOOK_EVENTS:
            raise _fail(
                f"components.hooks[{index}]: 'event' must be one of {', '.join(HOOK_EVENTS)} "
                "(only veto-capable events may come from a bundle - the same rule a repository's "
                "own [[hooks]] are held to)"
            )
        script = entry.get("script")
        if not isinstance(script, str) or not script.strip():
            raise _fail(f"components.hooks[{index}]: 'script' must be a non-empty path inside the bundle")
        if Path(script).is_absolute() or ".." in Path(script).parts:
            raise _fail(f"components.hooks[{index}]: 'script' must stay inside the bundle ({script!r})")
        if not bundle.relative(script.strip()).is_file():
            raise _fail(f"components.hooks[{index}]: {script} does not exist inside the bundle")
        interpreter = entry.get("interpreter")
        if interpreter is not None and (not isinstance(interpreter, str) or interpreter.strip() not in ALLOWED_INTERPRETERS):
            raise _fail(
                f"components.hooks[{index}]: 'interpreter' must be one of {', '.join(ALLOWED_INTERPRETERS)} "
                "(no paths, no absolute interpreters)"
            )
        timeout = entry.get("timeout_ms", DEFAULT_TIMEOUT_MS)
        if isinstance(timeout, bool) or not isinstance(timeout, int) or not MIN_TIMEOUT_MS <= timeout <= MAX_TIMEOUT_MS:
            raise _fail(f"components.hooks[{index}]: 'timeout_ms' must be between {MIN_TIMEOUT_MS} and {MAX_TIMEOUT_MS}")
        for key in ("tool", "agent", "description"):
            value = entry.get(key)
            if value is not None and not isinstance(value, str):
                raise _fail(f"components.hooks[{index}]: '{key}' must be a string")
        hooks.append(
            HookClaim(
                event=str(event),
                script=script.strip(),
                interpreter=str(interpreter or "").strip(),
                timeout_ms=int(timeout),
                tool=str(entry.get("tool") or "").strip(),
                agent=str(entry.get("agent") or "").strip(),
                description=str(entry.get("description") or "").strip(),
            )
        )

    servers = components.get("mcp_servers") or []
    if not isinstance(servers, list):
        raise _fail("components.mcp_servers must be a list of tables")
    mcp_servers: list[dict[str, Any]] = []
    for index, server in enumerate(servers):
        if not isinstance(server, Mapping):
            raise _fail(f"components.mcp_servers[{index}] must be a table")
        _require_exact_keys(server, frozenset({"name", "command", "args", "env"}), f"components.mcp_servers[{index}]")
        label = server.get("name")
        command = server.get("command")
        if not isinstance(label, str) or not _NAME_RE.fullmatch(label.replace("_", "-")):
            raise _fail(f"components.mcp_servers[{index}]: name must match {NAME_PATTERN!r}")
        if not isinstance(command, str) or not command:
            raise _fail(f"components.mcp_servers[{index}]: command must be a program name (no shell)")
        args = server.get("args") or []
        if not isinstance(args, list) or any(not isinstance(a, str) for a in args):
            raise _fail(f"components.mcp_servers[{index}]: args must be a list of strings")
        env = server.get("env") or {}
        if not isinstance(env, Mapping) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in env.items()):
            raise _fail(f"components.mcp_servers[{index}]: env must map strings to strings")
        mcp_servers.append({"name": label, "command": command, "args": list(args), "env": dict(env)})

    policy = manifest.get("policy") or {}
    if not isinstance(policy, Mapping):
        raise _fail(f"{MANIFEST_NAME}: policy must be a table")
    _require_exact_keys(policy, ALLOWED_POLICY_KEYS, f"{MANIFEST_NAME}: policy")
    deny_tools = policy.get("deny_tools") or []
    if not isinstance(deny_tools, list) or any(not isinstance(item, str) or not item for item in deny_tools):
        raise _fail("policy.deny_tools must be a list of tool names")
    for key in ("max_turns", "max_tool_calls"):
        if key in policy and (isinstance(policy[key], bool) or not isinstance(policy[key], int) or policy[key] < 1):
            raise _fail(f"policy.{key} must be a positive integer")
    if "max_budget_usd" in policy:
        budget = policy["max_budget_usd"]
        if isinstance(budget, bool) or not isinstance(budget, (int, float)) or budget < 0:
            raise _fail("policy.max_budget_usd must be a non-negative number")
    mode = policy.get("permission_mode")
    if mode is not None:
        # Two values are on the table for a bundle: 'plan' is a ceiling, and 'default' is
        # the no-op of asking for what the operator would have chosen anyway. 'acceptEdits'
        # and 'bypassPermissions' are *approvals* - auto-approving edits and skipping the
        # gate - so a bundle that could name them would grant itself what only a human at a
        # command line may grant. Same reasoning that keeps allow_tools out of a policy file.
        if mode not in {"default", "plan"}:
            raise _fail(
                f"policy.permission_mode {mode!r} is not something a bundle may ask for; the only ceiling here is "
                "'plan' ('default' asks for nothing) - approval stays an operator decision"
            )
    for key in ("read_only", "halt_on_denial"):
        if key in policy and not isinstance(policy[key], bool):
            raise _fail(f"policy.{key} must be a boolean")

    compatibility = manifest.get("compatibility") or {}
    if not isinstance(compatibility, Mapping):
        raise _fail(f"{MANIFEST_NAME}: compatibility must be a table")
    _require_exact_keys(compatibility, ALLOWED_COMPATIBILITY_KEYS, f"{MANIFEST_NAME}: compatibility")
    platforms = compatibility.get("platforms") or ["any"]
    if not isinstance(platforms, list) or not platforms or any(item not in PLATFORMS for item in platforms):
        raise _fail(f"compatibility.platforms must be a non-empty list of {', '.join(PLATFORMS)}")
    min_python = compatibility.get("min_python", "3.11")
    if not isinstance(min_python, str) or not re.fullmatch(r"\d+\.\d+", min_python):
        raise _fail("compatibility.min_python must look like '3.11'")
    for key in ("requires_flock", "requires_network"):
        if key in compatibility and not isinstance(compatibility[key], bool):
            raise _fail(f"compatibility.{key} must be a boolean")

    integrity = manifest.get("integrity") or {}
    if not isinstance(integrity, Mapping):
        raise _fail(f"{MANIFEST_NAME}: integrity must be a table")
    _require_exact_keys(integrity, ALLOWED_INTEGRITY_KEYS, f"{MANIFEST_NAME}: integrity")
    seal = str(integrity.get("seal") or "")
    if seal and not _SEAL_RE.fullmatch(seal):
        raise _fail("integrity.seal must be 64 lowercase hex characters (an HMAC-SHA256 digest)")
    key_env = str(integrity.get("seal_key_env") or ("NORTHSTAR_PLUGIN_KEY" if seal else ""))
    if seal and not key_env:
        raise _fail("integrity.seal needs integrity.seal_key_env naming where the key lives")

    resolved_policy = dict(policy)
    if workspace_policy is not None:
        _check_tighten_only(resolved_policy, workspace_policy)

    return PluginManifest(
        name=name,
        version=raw_version,
        description=description.strip()[:MAX_DESCRIPTION_CHARS],
        publisher=publisher.strip(),
        homepage=str(manifest.get("homepage") or ""),
        license=str(manifest.get("license") or ""),
        keywords=tuple(keywords),
        skill_dirs=path_list("skills"),
        agent_dirs=path_list("agents"),
        context_files=path_list("context"),
        hooks=tuple(hooks),
        mcp_servers=tuple(mcp_servers),
        policy=resolved_policy,
        platforms=tuple(str(item) for item in platforms),
        min_python=str(min_python),
        requires_flock=bool(compatibility.get("requires_flock", False)),
        requires_network=bool(compatibility.get("requires_network", False)),
        content_digest=bundle.content_digest,
        seal=seal,
        seal_key_env=key_env,
    )


def _check_tighten_only(claims: Mapping[str, Any], workspace: Mapping[str, Any]) -> None:
    """A plugin may narrow what a run may do, never widen it.

    The comparison is against the *loaded workspace policy*, because "tighten" is a
    relation and not a property: ``max_turns = 10`` tightens a workspace that allowed 25
    and loosens one that had already agreed on 5. ``deny_tools`` only ever grows, a mode
    may only become more restrictive, and a ceiling may only come down. There is no flag
    that lets a bundle through this: a plugin that needs a wider policy is a plugin that
    needs the repository owner to edit it themselves, in a diff.
    """
    for key in ("max_turns", "max_tool_calls"):
        if key in claims and key in workspace and int(claims[key]) > int(workspace[key]):
            raise _fail(
                f"policy.{key}={claims[key]} would widen the workspace's {workspace[key]}; "
                "a plugin may lower a ceiling, not raise one"
            )
    if "max_budget_usd" in claims and "max_budget_usd" in workspace:
        limit = workspace["max_budget_usd"]
        if limit is not None and float(claims["max_budget_usd"]) > float(limit):
            raise _fail("policy.max_budget_usd would widen the workspace budget ceiling")
    denied = workspace.get("deny_tools") or []
    if isinstance(denied, list) and "deny_tools" in claims:
        # A plugin may deny more tools; "un-denying" one the repository denied is exactly
        # the escalation this function exists to stop.
        removed = [name for name in denied if name not in set(claims["deny_tools"])]
        if removed:
            raise _fail(f"policy.deny_tools drops {', '.join(removed)}; a plugin may only add denials")
    if workspace.get("permission_mode") == "plan" and claims.get("permission_mode") not in (None, "plan"):
        # A workspace the owner pinned to plan stays in plan whatever a bundle prefers; the
        # only thing a bundle may do to a mode is make it stricter, and it already cannot.
        raise _fail("policy.permission_mode would widen a workspace pinned to plan; a plugin may only ask for plan")
    if workspace.get("read_only") and claims.get("read_only") is False:
        raise _fail("policy.read_only=False would widen a read-only workspace")


# -- integrity -------------------------------------------------------------


def verify_integrity(
    manifest: PluginManifest,
    *,
    pinned_digest: str = "",
    environment: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Recompute the bundle digest and compare it with what the workspace pinned.

    Returns a report rather than raising on *mismatch*, so a caller can print all of it;
    a missing key or an unusable seal still raises, because those are configurations where
    "verified" would be a lie. ``pinned_digest`` comes from ``plugins.lock`` - the point
    of the design is that the reviewed value lives with the reviewer, not in the bundle.
    """
    env = dict(os.environ if environment is None else environment)
    report: dict[str, Any] = {
        "pinned": pinned_digest or "(nothing pinned: run `plugin verify --write-lock`)",
        "actual": manifest.content_digest,
        "digest_ok": not pinned_digest or pinned_digest == manifest.content_digest,
        "seal": "none" if not manifest.seal else "unchecked",
    }
    if not report["digest_ok"]:
        report["ok"] = False
        report["reason"] = (
            f"content changed since review: the lock pins {pinned_digest}, the bundle hashes to "
            f"{manifest.content_digest}"
        )
        return report
    if manifest.seal:
        key = env.get(manifest.seal_key_env, "")
        if not key:
            raise _fail(
                f"{MANIFEST_NAME} declares an integrity.seal but {manifest.seal_key_env} is unset; "
                "refusing to treat an unverifiable seal as a passed check"
            )
        expected = hmac.new(
            key.encode("utf-8"),
            (f"northstar.plugin.v1\n{manifest.name}\n{manifest.version}\n{manifest.content_digest}").encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        # Constant-time, because the value is secret-keyed even though the payload is not:
        # a timing signal on a seal comparison is a free oracle for forging one.
        report["seal"] = "valid" if hmac.compare_digest(expected, manifest.seal) else "invalid"
        if report["seal"] != "valid":
            report["ok"] = False
            report["reason"] = "seal does not match: this bundle did not come from the key holder"
            return report
    report["ok"] = True
    return report


# -- platform compatibility -------------------------------------------------


def current_host_profile() -> dict[str, Any]:
    """The profile for the machine asking, from the same primitives the table describes."""
    name = {"linux": "linux", "darwin": "darwin", "win32": "windows", "cygwin": "windows"}.get(sys.platform, "posix-other")
    profile = {
        "name": name,
        "posix": os.name == "posix",
        "flock": False,
        "execvp": True,
        "case_sensitive": True,
        "python": (sys.version_info.major, sys.version_info.minor),
    }
    if profile["posix"]:
        try:
            import fcntl  # noqa: F401  - the probe is the import
        except ImportError:
            profile["flock"] = False
        else:
            profile["flock"] = True
    if name in HOST_PROFILES:
        profile["case_sensitive"] = HOST_PROFILES[name]["case_sensitive"]
        profile["execvp"] = HOST_PROFILES[name]["execvp"]
    return profile


def _claims_cover(claims: set[str], profile: Mapping[str, Any]) -> bool:
    """Whether a bundle's platform claim covers one host profile."""
    if "any" in claims:
        return True
    if profile["posix"]:
        return bool(claims & {"posix", str(profile.get("name") or "")})
    return "windows" in claims


def _case_collisions(files: Iterable[BundleFile]) -> tuple[str, ...]:
    """Paths that would collide on a case-insensitive filesystem.

    Worth checking rather than advising about: a bundle with ``Agents/Foo.md`` and
    ``agents/foo.md`` installs fine on Linux and silently overwrites one of them on
    Windows, which is exactly the class of "works on my machine" that a portability claim
    is supposed to prevent.
    """
    seen: dict[str, list[str]] = {}
    for item in files:
        seen.setdefault(item.relative_path.lower(), []).append(item.relative_path)
    return tuple(
        ", ".join(sorted(group)) + f" collide as {lower}"
        for lower, group in sorted(seen.items())
        if len(group) > 1
    )


def portability_report(
    manifest: PluginManifest,
    files: Sequence[BundleFile] = (),
    *,
    host: Mapping[str, Any] | None = None,
    only_hosts: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Score one bundle against every host profile this component knows about.

    This is the printed answer to "does this plugin work on all platforms?" - and the
    reason it is a *report* and not a boolean is that a bundle can be portable in the
    plain sense and still unusable in a specific one: a POSIX plugin is fine on Windows
    until it declares a shell hook, needs ``flock``, or ships two paths that differ only
    by case. Those are checked here, on the machine asking.

    Two limits, stated: :data:`HOST_PROFILES` are our own descriptions of the primitives
    the runtime uses, not a conformance suite; and a ``windows`` claim is *believed*, not
    tested - nothing in this repository runs on Windows.
    """
    claims = set(manifest.platforms)
    current = dict(host or current_host_profile())
    hosts = {name: dict(profile) for name, profile in HOST_PROFILES.items()}
    name = str(current.get("name") or "this-host")
    hosts.setdefault(name, {key: current.get(key) for key in HOST_PROFILES["linux"]})
    collisions = _case_collisions(files)
    rows: list[dict[str, Any]] = []
    for host_name, profile in sorted(hosts.items()):
        reasons: list[str] = []
        if not _claims_cover(claims, profile):
            reasons.append(f"claims {', '.join(sorted(claims))}, which does not cover this {profile['name'] if 'name' in profile else host_name} host")
        if manifest.requires_flock and not profile["flock"]:
            reasons.append("requires flock, which this platform does not provide (the session lease would be refused)")
        if manifest.hooks and not profile["execvp"]:
            reasons.append("declares command hooks, which need direct exec without a shell")
        if manifest.requires_network and host_name == name:
            reasons.append("needs network access; this runtime's offline guarantee does not extend to it")
        if tuple(int(part) for part in manifest.min_python.split(".")) > tuple(profile["python"]):
            reasons.append(f"needs python>={manifest.min_python}")
        if collisions and not profile["case_sensitive"]:
            reasons.append("file names collide case-insensitively: " + "; ".join(collisions))
        rows.append(
            {
                "host": host_name,
                "fits": not reasons,
                "reasons": reasons,
                "case_sensitive": profile["case_sensitive"],
                "flock": profile["flock"],
                "here": host_name == name,
            }
        )
    # `only_hosts` filters the *display*, never the verdict: a report that recomputed
    # "portable" over the two hosts somebody asked about would let a filtered view imply a
    # conclusion the full matrix contradicts. The host you are standing on is always kept.
    shown = rows
    if only_hosts is not None:
        wanted = {str(item) for item in only_hosts}
        unknown = sorted(wanted - set(HOST_PROFILES))
        if unknown:
            raise _fail(
                f"unknown host profile(s) {', '.join(unknown)}; known: {', '.join(sorted(HOST_PROFILES))}"
            )
        shown = [row for row in rows if row["host"] in wanted or row["here"]]
    here = next((row for row in rows if row["here"]), None)
    return {
        "plugin": f"{manifest.name}@{manifest.version}",
        "claims": sorted(claims),
        "hosts": shown,
        "portable_everywhere": all(row["fits"] for row in rows),
        "fits_here": bool(here["fits"]) if here else True,
        "here": name,
        "case_collisions": list(collisions),
    }


def check_host_compatibility(manifest: PluginManifest, *, host: Mapping[str, Any] | None = None) -> str:
    """Why this bundle cannot load here, or ``""`` when it can.

    The host check is what makes the manifest's claim load-bearing: an author writing
    ``platforms = ["windows"]`` gets refused on Linux instead of watching half the
    components load and the other half fail at turn three.
    """
    host = dict(host or current_host_profile())
    claims = set(manifest.platforms)
    posix = bool(host.get("posix"))
    name = str(host.get("name") or "")
    if "any" not in claims:
        if posix and not (claims & {"posix", "linux", "darwin"}):
            return f"claims {', '.join(sorted(claims))}; this host is posix ({name or 'unrecognised'})"
        if not posix and "windows" not in claims:
            return f"claims {', '.join(sorted(claims))}; this host is {name or 'non-posix'}, which that does not cover"
    if manifest.requires_flock and not host.get("flock"):
        return "requires flock for its session-lease claims, which this platform does not provide"
    try:
        needed = tuple(int(part) for part in manifest.min_python.split("."))
    except ValueError:  # pragma: no cover - rejected by parse_manifest
        return "compatibility.min_python is unreadable"
    if needed > tuple(host.get("python") or (3, 11)):
        return f"needs python>={manifest.min_python}, this interpreter is {'.'.join(str(p) for p in host.get('python') or (3, 11))}"
    return ""


# -- exports: the same bundle, in another host's shape ----------------------


@dataclass
class Export:  # not frozen: export_bundle appends the computed drop list after rendering
    """Rendered files plus what could not be rendered.

    ``dropped`` is the part that matters. A port that quietly omits the veto-capable
    hooks has not been exported, it has been downgraded, and the operator is entitled to
    the list before the files land.
    """

    target: str
    files: dict[str, str] = field(default_factory=dict)
    dropped: list[str] = field(default_factory=list)
    notes: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "files": sorted(self.files),
            "dropped": list(self.dropped),
            "notes": list(self.notes),
        }


def export_bundle(
    bundle: Bundle,
    manifest: PluginManifest,
    *,
    target: str,
) -> Export:
    """Render one bundle as another host's native files, and say what fell out.

    Format compatibility, not behaviour compatibility: the Agent Skills and agent-file
    formats are open and round-trip cleanly; veto-capable lifecycle hooks, tighten-only
    ceilings and the integrity story have no equivalent in the other hosts, so they land
    in :attr:`Export.dropped`. Export is an authoring aid for people shipping one source
    to several ecosystems - the runtime consumes only ``northstar.plugin.v1``, and nothing
    in a generated file is trusted by anything.
    """
    renderer = _EXPORT_RENDERERS.get(target)
    if renderer is None:
        raise _fail(f"unknown export target {target!r}; choose: {', '.join(sorted(_EXPORT_RENDERERS))}")
    export = renderer(bundle, manifest)
    carried = CARRIED_BY_TARGET.get(target, frozenset())
    # Computed, not hand-written per renderer: a target that gains the ability to carry
    # something gains the drop-list change in the same place, which is the only way to
    # keep the two from disagreeing about what "exported" means.
    export.dropped = sorted(declared_components(manifest) - carried)
    # One note, added here rather than written by each renderer: it is the limit of the whole
    # export feature, and a per-renderer string is one that can be forgotten.
    export.notes = tuple(list(export.notes) + [_EXPORT_LIMIT_NOTE.format(target=target)])
    return export


def _export_skills(bundle: Bundle, manifest: PluginManifest) -> Export:
    """The open Agent Skills layout: one directory per skill, ``SKILL.md`` inside."""
    files: dict[str, str] = {}
    notes: list[str] = []
    for declaration in manifest.skill_dirs:
        source = bundle.relative(declaration)
        if source.is_dir():
            for skill_file in sorted(source.glob("*/SKILL.md")):
                files[f"skills/{skill_file.parent.name}/SKILL.md"] = skill_file.read_text(encoding="utf-8", errors="replace")
        elif source.is_file():
            files[f"skills/{source.parent.name}/SKILL.md"] = source.read_text(encoding="utf-8", errors="replace")
        else:
            notes.append(f"skills: {declaration} is not a directory here")
    dropped = ("hooks", "policy", "mcp_servers") if (manifest.hooks or manifest.policy or manifest.mcp_servers) else ()
    return Export("skills", files, dropped, tuple(notes))


def _export_claude_code(bundle: Bundle, manifest: PluginManifest) -> Export:
    skills = _export_skills(bundle, manifest)
    files = dict(skills.files)
    notes: list[str] = list(skills.notes)
    plugin_json = {
        "name": manifest.name,
        "version": manifest.version,
        "description": manifest.description,
        "author": {"name": manifest.publisher},
        # The provenance we carry and a marketplace-format manifest does not: kept in an
        # explicitly namespaced key so a host that ignores it loses nothing.
        "x-northstar": {
            "schema_version": PLUGIN_SCHEMA_VERSION,
            "sha256": manifest.content_digest,
            "platforms": list(manifest.platforms),
        },
    }
    files[".claude-plugin/plugin.json"] = json.dumps(plugin_json, indent=2, sort_keys=True) + "\n"
    for declaration in manifest.agent_dirs:
        source = bundle.relative(declaration)
        targets = sorted(source.glob("*.md")) if source.is_dir() else ([source] if source.is_file() else [])
        for path in targets:
            files[f"agents/{path.name}"] = path.read_text(encoding="utf-8", errors="replace")
    hooks_document: dict[str, Any] = {}
    for hook in manifest.hooks:
        runner = f"{hook.interpreter} " if hook.interpreter else ""
        entry = {
            "type": "command",
            # Relative to the exported bundle root, because that is where the script lives
            # after export. This is a rendering, not a promise: no other host is exercised
            # here, and the note below says so instead of letting the file look authoritative.
            "command": f"{runner}{hook.script}",
            "timeout_ms": hook.timeout_ms,
        }
        hooks_document.setdefault(hook.event, []).append(entry)
    if hooks_document:
        files["hooks/hooks.json"] = json.dumps({"hooks": hooks_document}, indent=2, sort_keys=True) + "\n"
        notes.append(
            "hooks/hooks.json is our best rendering of a command-hook document; no Windows/macOS "
            "host was exercised here, so confirm the shape against that host's current docs before shipping"
        )
    if manifest.policy:
        # Named in the notes, not added to `dropped`: export_bundle computes the drop list
        # from one table, and a hand-written entry beside it would be a second, diverging
        # account of what did not travel.
        notes.append("policy ceilings stay behind: move them to the host's own managed settings")
    if manifest.mcp_servers:
        files[".mcp.json"] = json.dumps(
            {
                "mcpServers": {
                    server["name"]: {
                        "command": server["command"],
                        "args": server["args"],
                        "env": server["env"],
                    }
                    for server in manifest.mcp_servers
                }
            },
            indent=2,
            sort_keys=True,
        ) + "\n"
    if manifest.requires_flock:
        notes.append("this bundle needs flock; the exported form carries no such constraint")
    return Export("claude-code", files, [], tuple(notes))


def _export_agents_md(bundle: Bundle, manifest: PluginManifest) -> Export:
    """``AGENTS.md``, which several hosts read: guidance only, by construction."""
    lines = [f"# {manifest.name}", "", manifest.description, ""]
    lines += [f"Publisher: {manifest.publisher}  ·  Version: {manifest.version}", ""]
    for declaration in manifest.context_files:
        source = bundle.relative(declaration)
        if source.is_file():
            lines += ["", f"## {source.name}", "", source.read_text(encoding="utf-8", errors="replace").strip()]
    for declaration in manifest.skill_dirs:
        source = bundle.relative(declaration)
        if source.is_dir():
            for skill_file in sorted(source.glob("*/SKILL.md")):
                text = skill_file.read_text(encoding="utf-8", errors="replace")
                body = text.split("---", 2)[-1].strip() if text.startswith("---") else text.strip()
                lines += ["", f"## Skill: {skill_file.parent.name}", "", body]
    notes = [
        "AGENTS.md carries prose only: hooks, ceilings and MCP servers cannot travel here",
    ]
    return Export(
        "agents-md",
        {"AGENTS.md": "\n".join(lines).rstrip() + "\n"},
        ("hooks", "policy", "mcp_servers", "integrity"),
        tuple(notes),
    )


def _export_cursor(bundle: Bundle, manifest: PluginManifest) -> Export:
    rules = [
        "---",
        f'description: {json.dumps(manifest.description)}',
        "globs: []",
        "alwaysApply: true",
        "---",
        "",
        f"# {manifest.name}",
        "",
        manifest.description,
        "",
        "This rule set was exported from a Northstar plugin bundle. Lifecycle hooks, permission",
        "ceilings and MCP servers are enforced by the Northstar runtime and have no equivalent",
        "here; read the plugin's own SKILL.md files for the guidance that did travel.",
        "",
    ]
    files = {f".cursor/rules/{manifest.name}.mdc": "\n".join(rules)}
    files.update({f"skills/{key.split('/')[-2]}/SKILL.md": value for key, value in _export_skills(bundle, manifest).files.items()})
    return Export("cursor", files, ("hooks", "policy", "mcp_servers", "integrity"), ("rules are guidance; nothing here is enforced",))


def _export_mcp_config(bundle: Bundle, manifest: PluginManifest) -> Export:
    """Only the MCP servers, as a host would declare them. A plugin is not an MCP server."""
    if not manifest.mcp_servers:
        return Export("mcp", {}, ("mcp_servers",), ("this bundle declares no MCP servers",))
    payload = {
        "mcpServers": {
            server["name"]: {"command": server["command"], "args": server["args"], "env": server["env"]}
            for server in manifest.mcp_servers
        }
    }
    return Export(
        "mcp",
        {".mcp.json": json.dumps(payload, indent=2, sort_keys=True) + "\n"},
        ("skills", "agents", "hooks", "policy", "integrity"),
        ("a bundle does not become an MCP server by export; only its server declarations travel",),
    )


#: Which component kinds each target can actually express. A capability the target cannot
#: carry is reported in :attr:`Export.dropped`, and ``cli plugin export`` refuses to write
#: the downgrade unless ``--allow-drop`` says it is intended. ``policy`` and ``integrity``
#: are in no foreign target's set on purpose: no other ecosystem has Northstar's
#: tighten-only ceilings or its lockfile-pinned review, and an export that implied
#: otherwise would advertise enforcement that is not there.
_EXPORT_LIMIT_NOTE = (
    "rendered from this runtime's understanding of {target}'s file format: confirm it against that host's "
    "docs before relying on it - no other agent host is exercised by this repository"
)

CARRIED_BY_TARGET: dict[str, frozenset[str]] = {
    "claude-code": frozenset({"skills", "agents", "hooks", "mcp_servers", "context"}),
    "skills": frozenset({"skills"}),
    "agents-md": frozenset({"skills", "context"}),
    "codex": frozenset({"skills", "context"}),
    "openai-agents": frozenset({"skills", "context"}),
    "cursor": frozenset({"skills", "context"}),
    "mcp": frozenset({"mcp_servers"}),
}

#: Renderer per target. Two names map to ``AGENTS.md`` because several hosts read that
#: file; the drop list is what tells an operator which of the two they asked for.
_EXPORT_RENDERERS = {
    "claude-code": _export_claude_code,
    "codex": _export_agents_md,
    "openai-agents": _export_agents_md,
    "agents-md": _export_agents_md,
    "cursor": _export_cursor,
    "mcp": _export_mcp_config,
    "skills": _export_skills,
}

EXPORT_TARGETS: tuple[str, ...] = tuple(sorted(_EXPORT_RENDERERS))


def declared_components(manifest: PluginManifest) -> set[str]:
    """Which capabilities this bundle actually uses (not what it merely could)."""
    kinds = {
        "skills": bool(manifest.skill_dirs),
        "agents": bool(manifest.agent_dirs),
        "context": bool(manifest.context_files),
        "hooks": bool(manifest.hooks),
        "mcp_servers": bool(manifest.mcp_servers),
        "policy": bool(manifest.policy),
        "integrity": bool(manifest.seal),
    }
    return {kind for kind, present in kinds.items() if present}


def describe_components(manifest: PluginManifest) -> dict[str, Any]:
    """The capability surface, as data: what a reviewer is being asked to trust.

    Only what the manifest *declares* appears here. File counts and byte sizes belong to
    :class:`Bundle`, because that is the part read from disk rather than the part claimed -
    and a field that is a constant in the only place it can be computed is worse than no
    field at all, since it reads like a measurement.
    """
    return {
        "skills": list(manifest.skill_dirs),
        "agents": list(manifest.agent_dirs),
        "context": list(manifest.context_files),
        "hooks": [hook.as_hook_table() for hook in manifest.hooks],
        "mcp_servers": [server["name"] for server in manifest.mcp_servers],
        "policy": dict(manifest.policy),
    }


def component_lines(manifest: PluginManifest) -> tuple[str, ...]:
    """The declared components as one line each, for a human reading ``plugin show``."""
    described = describe_components(manifest)
    lines: list[str] = []
    for kind in ("skills", "agents", "context"):
        for value in described[kind]:
            lines.append(f"{kind}: {value}")
    for hook in described["hooks"]:
        lines.append(f"hook: {hook['event']} -> {hook['script']} ({hook['timeout_ms']} ms)")
    for name in described["mcp_servers"]:
        lines.append(f"mcp: {name}")
    if not lines:
        lines.append("(no files contributed: this bundle only asks for policy)")
    return tuple(lines)


def skill_candidates(bundle: Bundle, manifest: PluginManifest) -> Iterable[tuple[str, Path]]:
    """``(name, SKILL.md path)`` for every skill the bundle ships, resolved inside it."""
    for declaration in manifest.skill_dirs:
        directory = bundle.relative(declaration)
        if not directory.is_dir():
            continue
        for entry in sorted(directory.iterdir()):
            candidate = entry / "SKILL.md"
            if entry.is_dir() and candidate.is_file():
                yield entry.name, candidate


def agent_files(bundle: Bundle, manifest: PluginManifest) -> tuple[Path, ...]:
    found: list[Path] = []
    for declaration in manifest.agent_dirs:
        source = bundle.relative(declaration)
        if source.is_dir():
            found.extend(sorted(source.glob("*.md")))
        elif source.is_file():
            found.append(source)
    return tuple(found)


__all__ = [
    "ALLOWED_KEYS",
    "Bundle",
    "BundleFile",
    "EXPORT_TARGETS",
    "Export",
    "HOOK_EVENTS",
    "HOST_PROFILES",
    "LOCK_NAME",
    "MANIFEST_NAME",
    "PLUGINS_DIRECTORY",
    "PLUGIN_SCHEMA_VERSION",
    "PluginError",
    "PluginManifest",
    "agent_files",
    "check_host_compatibility",
    "component_lines",
    "current_host_profile",
    "describe_components",
    "export_bundle",
    "load_bundle",
    "parse_manifest",
    "portability_report",
    "skill_candidates",
    "verify_integrity",
]
