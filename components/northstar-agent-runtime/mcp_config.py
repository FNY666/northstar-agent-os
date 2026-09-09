"""Import the MCP config files other hosts already use, and say what was not carried.

Every agent host in 2026 reads a file like ``.mcp.json`` to declare its Model Context
Protocol servers - Claude Code, Cursor and VS Code all ship a dialect of it, Gemini uses
``.gemini/settings.json``. This runtime only ever accepted ``--mcp-server NAME=COMMAND``
typed by an operator, which meant an adopting repository had to duplicate its server list
in two places and keep them in sync by hand. That is the same problem the plugin bundle
solved in the other direction, and it gets the same answer: **read their format, keep our
gates.**

So this module is a reader, not a registrar. It produces the ``(name, argv)`` pairs the
flag path already feeds :mod:`mcp_client`, and it reports everything it refused to produce.
The refusals are the point:

* **a server we cannot run here is refused, not half-imported.** HTTP and SSE servers
  (``url``, ``type: "http" | "sse"``, their ``headers``) need a transport this component
  does not implement; importing them and failing at connect time would look like our bug.
  A refusal stops that one server and says so on stderr; it does not stop the run, because a
  repository with one remote server should still get the stdio ones next to it.
* **an approval grant in a repository file is refused outright.** ``autoApprove``/``alwaysAllow``
  exists so a host can stop asking; a file cannot buy back a permission the operator withheld,
  because approvals here are a human at a command line. An empty list is a no-op and gets a note.
* **secrets are expanded or the import fails.** ``${VAR}`` and ``${VAR:-fallback}`` are the
  conventions these files use; an unresolved ``${VAR}`` becomes an empty API key in a child
  process, which is a silent failure with a security shape, so a missing variable is an error.
* **a server directory outside the workspace is refused**, same rule as a bundle's files.
* **names are not rewritten.** ``"GitHub"`` is refused with instructions, because a tool name
  that a user did not write is a tool name nobody reviewed.

Nothing in this module starts a process, reads the network, or writes a file: discovery is
side-effect free, which is what lets ``mcp list`` be a CI check.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

#: The identity of this reader's decisions, reported in ``as_dict`` so a log line can say
#: which rules produced it (the same habit as ``skill_audit.RULES_VERSION``).
#: v2 is a launch-policy change, not a format change: a file may no longer name a shell or an
#: inline interpreter script, and it may read only the parent variables the operator released
#: with ``--mcp-env``. A log line that says v1 was written under the old, wider rules.
MCP_IMPORT_VERSION = "northstar.mcp-import.v2"

#: Where a workspace may declare its servers, in the order they are read. A name declared
#: twice across files is refused rather than last-one-wins: two sources for one server is
#: how a review of one file stops meaning anything.
CONFIG_CANDIDATES: tuple[str, ...] = (
    ".mcp.json",  # Claude Code, and the shape Cursor/VS Code accept too
    ".cursor/mcp.json",
    ".vscode/mcp.json",
    ".gemini/settings.json",
)
#: Keys a config document may carry a server map under. VS Code's ``servers`` and the
#: ``mcpServers`` everyone else converged on.
SERVER_TABLE_KEYS: tuple[str, ...] = ("mcpServers", "servers")

#: Per-server keys understood by the importer. Anything else is refused, so a key whose
#: meaning we have not read cannot quietly change what we launch.
ALLOWED_SERVER_KEYS: frozenset[str] = frozenset(
    {"type", "command", "args", "env", "cwd", "disabled", "autoApprove", "alwaysAllow", "url", "headers", "description"}
)
#: Keys that mean "a transport we do not have". Their presence is a refusal, not a drop.
UNSUPPORTED_TRANSPORT_KEYS: tuple[str, ...] = ("url", "headers")
UNSUPPORTED_TRANSPORT_TYPES: frozenset[str] = frozenset({"http", "sse", "streamable-http", "streamable_http"})
#: The approval-shaped keys, refused when non-empty.
APPROVAL_KEYS: tuple[str, ...] = ("autoApprove", "alwaysAllow")

NAME_PATTERN = re.compile(r"^[a-z][a-z0-9_-]*$")  # same rule as --mcp-server, on purpose
MAX_SERVERS = 16
MAX_ARGS = 32
MAX_ENV_VARS = 32
MAX_VALUE_CHARS = 4096

_VARIABLE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")

#: Programs that mean "execute the text that follows". A repository file may name a *program*
#: for us to start; it may not name a language we then feed a script, because the script is the
#: part nobody reviewed. This is the rule ``hooks.py`` has enforced for command hooks since the
#: first day, applied to the one remaining place a repository could still ask for a shell.
SHELL_PROGRAMS: frozenset[str] = frozenset(
    {"sh", "bash", "dash", "ksh", "zsh", "csh", "tcsh", "fish", "cmd", "command.com", "powershell", "pwsh"}
)
#: Programs that take a script on the command line as one of their first arguments.
INTERPRETERS: frozenset[str] = frozenset(
    {
        "python",
        "python2",
        "python3",
        "pypy",
        "pypy3",
        "node",
        "nodejs",
        "deno",
        "bun",
        "ruby",
        "perl",
        "php",
        "lua",
        "tclsh",
    }
)
#: The flags (and subcommands) that mean "the next token is source code".
INLINE_EVAL_FLAGS: frozenset[str] = frozenset(
    {"-c", "--command", "-e", "-E", "--eval", "-exec", "--exec", "/c", "/k", "/command", "eval"}
)
#: Tokens that only wrap another program. Without unwrapping them, ``env python3 -c ...``
#: would sail past a check that looks at argv[0] alone.
LAUNCH_WRAPPERS: frozenset[str] = frozenset({"env", "nohup", "nice", "stdbuf", "time", "timeout"})


def _program_name(token: str) -> str:
    """Basename of an argv token, Windows separators included, without its extension."""
    name = re.split(r"[/\\]", token.strip())[-1].lower()
    return name[:-4] if name.endswith(".exe") else name


def _launch_shape_for(name: str, argv: Sequence[str], *, source: str) -> str:
    """Return a refusal for a launch command whose payload cannot be reviewed, else "".

    Checked after ``${VAR}`` expansion on purpose: a declaration that resolves to ``sh`` is a
    declaration of ``sh``, whatever the file spelled.
    """
    argv = [str(item) for item in argv]
    if not argv:
        return ""
    index = 0
    while index < len(argv) and _program_name(argv[index]) in LAUNCH_WRAPPERS:
        index += 1
        while index < len(argv) and (argv[index].startswith("-") or "=" in argv[index]):
            index += 1  # env -i / KEY=VALUE pairs do not change which program runs
    if index >= len(argv):
        return ""
    program = _program_name(argv[index])
    where = f"{source}: {name}"
    if program in SHELL_PROGRAMS:
        return (
            f"{where}: command {argv[index]!r} is a shell, and the text after it would run with none of the limits "
            "this importer puts on a declaration. Name the program you mean and put its script in a file "
            "(an operator's own --mcp-server is not restricted this way)"
        )
    if program in INTERPRETERS and index + 1 < len(argv) and argv[index + 1] in INLINE_EVAL_FLAGS:
        return (
            f"{where}: {argv[index]!r} {argv[index + 1]!r} runs an inline script, which is the one part of this "
            "declaration no reviewer ever saw. Ship the script as a file and name it in args"
        )
    return ""


def check_launch_shape(name: str, argv: Sequence[str], *, source: str) -> None:
    """The rule above, for declarations assembled somewhere other than a config file.

    A plugin bundle's ``mcp_servers`` arrives as a list of strings, not as JSON, so it never
    passes through :func:`_argv_for` - and a bundle is repository content like ``.mcp.json`` is.
    """
    message = _launch_shape_for(name, argv, source=source)
    if message:
        raise McpConfigError(message)


class McpConfigError(ValueError):
    """A config file cannot be imported. Message is operator-facing, names the file."""


@dataclass(frozen=True)
class ImportedServer:
    """One server declaration, reduced to what this runtime can launch."""

    name: str
    argv: tuple[str, ...]
    env: tuple[tuple[str, str], ...] = ()
    cwd: str = ""
    source: str = ""

    @property
    def env_mapping(self) -> dict[str, str]:
        return dict(self.env)

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "argv": list(self.argv),
            "env": sorted(key for key, _value in self.env),  # keys only: values are the secrets
            "cwd": self.cwd,
            "source": self.source,
            # Said out loud because the absence of a note here is otherwise easy to misread as
            # "the sandbox will contain it": a launched MCP server is a child of the CLI, not a
            # child of the run's mount namespace.
            "sandboxed": False,
        }


@dataclass(frozen=True)
class McpImport:
    """What discovery found, what it refused, and what it ignored out loud."""

    servers: tuple[ImportedServer, ...] = ()
    refused: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()
    files: tuple[str, ...] = ()
    version: str = MCP_IMPORT_VERSION

    @property
    def ok(self) -> bool:
        return not self.refused

    def summary(self) -> str:
        if not self.files:
            return "none (no .mcp.json in the workspace)"
        if not self.servers and not self.refused:
            return f"none started ({', '.join(self.files)} declared nothing usable)"
        text = f"{len(self.servers)} server(s) from {', '.join(self.files)}: " + ", ".join(server.name for server in self.servers)
        if self.refused:
            text += f"; {len(self.refused)} refused"
        return text

    def as_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "files": list(self.files),
            "servers": [server.as_dict() for server in self.servers],
            "refused": list(self.refused),
            "notes": list(self.notes),
            "ok": self.ok,
        }


# --------------------------------------------------------------- `mcp list` --

def add_mcp_arguments(verb: argparse.ArgumentParser) -> None:
    """Attach the `mcp` verb's actions to the CLI parser.

    One action, and it is read-only on purpose. Whether a declaration should *run* is the
    operator's decision, taken with ``--mcp-config`` on a ``run`` command; the listing exists
    so that decision can be made from what the repository actually says, and so CI can check
    the same thing without a model, a provider key, or a workspace write.
    """
    actions = verb.add_subparsers(dest="mcp_action")
    listing = actions.add_parser("list", help="show what --mcp-config would start, and what it refuses")
    listing.add_argument("--workspace", default=".", help="workspace to read config files from (default: current directory)")
    listing.add_argument("--config", default="", metavar="PATH", help="read one file instead of searching")
    listing.add_argument("--json", action="store_true", help="print the parsed report as JSON")
    listing.set_defaults(handler=run_list)


def run_list(args: argparse.Namespace) -> int:
    """Report what the workspace declares, and exit 1 if any of it had to be refused.

    The exit code is the point of the verb: a CI job can run it and fail when a dependency
    pulls in a server nobody approved, or one that asks for approval on the model's behalf.
    """
    workspace = Path(str(getattr(args, "workspace", ".") or "."))
    config = str(getattr(args, "config", "") or "")
    try:
        if config:
            found, refused, notes = read_document(workspace / config, workspace=workspace, resolve=False)
            report = McpImport(servers=found, refused=refused, notes=notes, files=(config,))
        else:
            report = discover(workspace, resolve=False)
    except (McpConfigError, OSError, ValueError) as error:
        print(f"! {error}", file=sys.stderr)
        return 1
    if getattr(args, "json", False):
        print(json.dumps(report.as_dict(), sort_keys=True))
        return 1 if report.refused else 0
    print("== MCP declarations ==")
    print(f"  workspace: {workspace.resolve()}")
    for path in report.files:
        print(f"  file: {path}")
    for server in report.servers:
        argv = " ".join(server.argv)
        env = ", ".join(sorted(key for key, _value in server.env)) or "none"
        print(f"  {server.name}: {argv}")
        print(f"      env={env} cwd={server.cwd or '.'} sandboxed=false ({server.source})")
    if any("${" in item for server in report.servers for item in server.argv):
        print(
            "  - ${VAR} references are printed as declared: this verb never resolves them, so a "
            "secret stays out of the terminal and the CI log"
        )
    for why in report.refused:
        print(f"  ! {why}")
    for note in report.notes:
        print(f"  - {note}")
    if not report.files:
        print("  none (no " + ", ".join(CONFIG_CANDIDATES) + " found)")
    print(
        "  (declarations are inert until a run passes both --mcp-config and --mcp-allow-exec; "
        "approval lists are never honoured)"
    )
    return 1 if report.refused else 0


def _load_json(path: Path) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as error:
        raise McpConfigError(f"{path}: cannot read: {error}") from error
    if path.suffix == ".jsonc" or text.lstrip().startswith("//"):
        raise McpConfigError(f"{path}: JSON-with-comments is not accepted here; keep the file plain JSON")
    try:
        document = json.loads(text)
    except ValueError as error:
        raise McpConfigError(f"{path}: invalid JSON: {error}") from error
    if not isinstance(document, dict):
        raise McpConfigError(f"{path}: the document must be a JSON object")
    return document


def _tables(document: Mapping[str, Any], path: Path) -> dict[str, Any]:
    """The server map, from whichever key this dialect uses - never both at once."""
    present = [key for key in SERVER_TABLE_KEYS if key in document]
    if not present:
        return {}
    if len(present) > 1:
        raise McpConfigError(f"{path}: {', '.join(present)} both present; declare servers under one key")
    table = document[present[0]]
    if not isinstance(table, dict):
        raise McpConfigError(f"{path}: {present[0]} must be an object of server names to settings")
    return table


def _expand(value: str, *, environment: Mapping[str, str], where: str, resolve: bool = True) -> str:
    """Substitute ``${VAR}`` / ``${VAR:-default}``, refusing anything unresolved.

    Two things are refused here, in different directions. The first is the reason this function
    is not ``os.path.expandvars``: an empty ``API_KEY`` launches a server that fails with an
    authentication error three layers away from the typo that caused it. The second is that a
    workspace file may not *read* the operator's environment at all: ``environment`` is the view
    the operator released with ``--mcp-env``, so a name outside it is unreadable even when the
    process running us has it. ``os.environ`` is consulted below only to tell those two cases
    apart in the message - a value is never taken from it here.

    ``resolve=False`` is the review path (``mcp list``): references stay exactly as declared,
    which is what lets a reviewer print a file without printing a secret into a CI log.
    """

    def replace(match: re.Match[str]) -> str:
        name, fallback = match.group(1), match.group(2)
        if not resolve:
            return match.group(0)
        if name in environment:
            return environment[name]
        if fallback is not None:
            return fallback
        if name in os.environ:
            raise McpConfigError(
                f"{where}: ${{{name}}} is set in this environment, but a workspace file may not read it; "
                f"pass --mcp-env {name} on the command line if this run should give it to the server"
            )
        raise McpConfigError(f"{where}: ${{{name}}} is not set in this environment (give it a ${{{name}:-default}} fallback or export it)")

    return _VARIABLE.sub(replace, value)


def _released_variables(names: Sequence[str]) -> dict[str, str]:
    """The only parent variables a config file may read: the ones named, one at a time."""
    return {str(key): os.environ[str(key)] for key in names if str(key) in os.environ}


def _check_size(value: str, where: str) -> str:
    if len(value) > MAX_VALUE_CHARS:
        raise McpConfigError(f"{where}: {len(value)} characters exceeds the {MAX_VALUE_CHARS}-character limit for imported values")
    return value


def _environment_for(
    name: str,
    raw: Any,
    *,
    workspace: Path,
    source: str,
    allowed_variables: Sequence[str] = (),
    resolve: bool = True,
) -> tuple[tuple[str, str], ...]:
    if raw is None:
        return ()
    if not isinstance(raw, dict):
        raise McpConfigError(f"{source}: {name}: env must be an object of NAME to value")
    if len(raw) > MAX_ENV_VARS:
        raise McpConfigError(f"{source}: {name}: {len(raw)} env values exceeds the {MAX_ENV_VARS} limit")
    environment = _released_variables(allowed_variables)
    pairs: list[tuple[str, str]] = []
    for key, value in sorted(raw.items()):
        where = f"{source}: {name}: env.{key}"
        if not isinstance(key, str) or not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", key):
            raise McpConfigError(f"{source}: {name}: env key {key!r} is not a variable name")
        if not isinstance(value, str):
            raise McpConfigError(f"{where} must be a string, not {type(value).__name__}")
        pairs.append((key, _check_size(_expand(value, environment=environment, where=where, resolve=resolve), where)))
    return tuple(pairs)


def _cwd_for(name: str, raw: Any, *, workspace: Path, source: str) -> str:
    if raw in (None, ""):
        return ""
    if not isinstance(raw, str):
        raise McpConfigError(f"{source}: {name}: cwd must be a path string")
    base = Path(workspace)
    candidate = (base / raw).resolve() if not Path(raw).is_absolute() else Path(raw).resolve()
    try:
        candidate.relative_to(base.resolve())
    except ValueError:
        raise McpConfigError(
            f"{source}: {name}: cwd {raw!r} resolves outside the workspace; the server would start with a view of files this run does not own"
        ) from None
    if not candidate.is_dir():
        raise McpConfigError(f"{source}: {name}: cwd {raw!r} is not a directory in this workspace")
    return str(candidate)


def _argv_for(
    name: str,
    settings: Mapping[str, Any],
    *,
    workspace: Path,
    source: str,
    allowed_variables: Sequence[str] = (),
    resolve: bool = True,
) -> tuple[str, ...]:
    command = settings.get("command")
    if not isinstance(command, str) or not command.strip():
        raise McpConfigError(f"{source}: {name}: command is required and must be a non-empty string")
    if any(char in command for char in "\n\r") or re.search(r"\s", command.strip()):
        # A whole command line in `command` is how a declaration smuggles arguments past the
        # `args` list this importer sizes, counts and shape-checks. Splitting it would also put
        # `-c` and a script where the rules below expect to find a program name.
        raise McpConfigError(
            f"{source}: {name}: command must be a program name or path, not a command line; "
            f"put the arguments in args instead of writing {command.strip()!r}"
        )
    raw_args = settings.get("args") or []
    if not isinstance(raw_args, list) or not all(isinstance(item, str) for item in raw_args):
        raise McpConfigError(f"{source}: {name}: args must be an array of strings")
    if len(raw_args) > MAX_ARGS:
        raise McpConfigError(f"{source}: {name}: {len(raw_args)} args exceeds the {MAX_ARGS} limit")
    environment = _released_variables(allowed_variables)
    argv = [command.strip()]
    for index, item in enumerate(raw_args):
        where = f"{source}: {name}: args[{index}]"
        argv.append(_check_size(_expand(str(item), environment=environment, where=where, resolve=resolve), where))
    refused = _launch_shape_for(name, argv, source=source)
    if refused:
        raise McpConfigError(refused)
    return tuple(argv)


def read_document(
    path: Path,
    *,
    workspace: Path,
    allowed_variables: Sequence[str] = (),
    resolve: bool = True,
) -> tuple[tuple[ImportedServer, ...], tuple[str, ...]]:
    """One file, as servers, refusals and notes.

    Three severities, because the file can be wrong in three different ways:

    * raising :class:`McpConfigError` means *this file cannot be imported at all* - it is
      malformed, or it asks for something whose meaning we would have to guess.
    * a **refusal** means *this one server is not started and you will hear why*: an HTTP
      transport we do not speak is the common case, and a run should still get the stdio
      servers next to it.
    * a **note** is a decision the file already made deliberately, recorded so that a dry run
      and a log line can be read later.
    """
    document = _load_json(path)
    table = _tables(document, path)
    source = path.name if not str(path).startswith(str(workspace)) else str(path.relative_to(workspace))
    servers: list[ImportedServer] = []
    refusals: list[str] = []
    notes: list[str] = []
    if len(table) > MAX_SERVERS:
        raise McpConfigError(f"{source}: {len(table)} servers exceeds the {MAX_SERVERS}-server import limit")
    for name, settings in sorted(table.items()):
        where = f"{source}: {name}"
        if not isinstance(settings, dict):
            raise McpConfigError(f"{where}: each server must be an object of settings")
        unknown = sorted(set(settings) - set(ALLOWED_SERVER_KEYS))
        if unknown:
            raise McpConfigError(
                f"{where}: key(s) {', '.join(unknown)} are not read by this importer; a key nobody reads is a capability somebody meant"
            )
        if settings.get("disabled") is True:
            # The author switched it off; that is the file working as intended, so it gets a
            # note rather than an alarm - but not silence, because "disabled" in a file two
            # dependencies merged is exactly the kind of change a review should see.
            notes.append(f"{where}: not started (disabled = true)")
            continue
        approvals = settings.get("autoApprove") or settings.get("alwaysAllow") or []
        if approvals:
            raise McpConfigError(
                f"{where}: autoApprove/alwaysAllow is refused here - a repository file cannot buy back an approval the "
                "operator withheld; pass --allow-tool (or run in a mode that grants the tool) if that is really intended"
            )
        transport = str(settings.get("type") or "stdio").lower()
        if transport in UNSUPPORTED_TRANSPORT_TYPES or any(key in settings for key in UNSUPPORTED_TRANSPORT_KEYS):
            refusals.append(
                f"{where}: refused ({'url/headers' if any(key in settings for key in UNSUPPORTED_TRANSPORT_KEYS) else f'type = {transport}'}); "
                "this runtime speaks MCP over stdio only - there is no HTTP/SSE transport, and no client-side auth for it either"
            )
            continue
        if not NAME_PATTERN.match(name):
            refusals.append(f"{where}: refused (a server name must match {NAME_PATTERN.pattern}); rename it in the file rather than letting us rewrite it")
            continue
        argv = _argv_for(
            name, settings, workspace=workspace, source=source, allowed_variables=allowed_variables, resolve=resolve
        )
        env = _environment_for(
            name,
            settings.get("env"),
            workspace=workspace,
            source=source,
            allowed_variables=allowed_variables,
            resolve=resolve,
        )
        cwd = _cwd_for(name, settings.get("cwd"), workspace=workspace, source=source)
        servers.append(ImportedServer(name=name, argv=argv, env=env, cwd=cwd, source=source))
    return tuple(servers), tuple(refusals), tuple(notes)


def discover(
    workspace: str | Path,
    *,
    candidates: Sequence[str] | None = None,
    allowed_variables: Sequence[str] = (),
    resolve: bool = True,
) -> McpImport:
    """Read every config file this workspace declares, merged with no silent overrides."""
    base = Path(workspace)
    files: list[Path] = []
    refusals: list[str] = []
    for relative in tuple(candidates) if candidates is not None else CONFIG_CANDIDATES:
        path = base / relative
        if not path.is_file():
            continue
        files.append(path)
    servers: list[ImportedServer] = []
    notes: list[str] = []
    seen: dict[str, str] = {}
    for path in files:
        found, refused, per_file = read_document(
            path, workspace=base, allowed_variables=allowed_variables, resolve=resolve
        )
        servers.extend(found)
        refusals.extend(refused)
        notes.extend(per_file)
    for server in list(servers):
        previous = seen.get(server.name)
        if previous is not None:
            # Two files claiming one server: refuse both, because "which one wins" is a
            # question a reviewer should never have to answer about a process launcher.
            refusals.append(f"{server.name}: declared by both {previous} and {server.source}; the later file does not win")
            servers = [item for item in servers if item.name != server.name]
            continue
        seen[server.name] = server.source
    if not files:
        return McpImport(notes=("no MCP config file in this workspace",))
    notes.insert(0, f"read {len(files)} file(s): {', '.join(str(path.relative_to(base)) for path in files)}")
    notes.append("imported servers join the run's MCP list, which means mutating-by-default: denied until --allow-tool names one")
    if resolve:
        notes.append(
            "imported servers are started only by a run that also passes --mcp-allow-exec, "
            "and they run outside the OS sandbox"
        )
    return McpImport(
        servers=tuple(servers),
        refused=tuple(sorted(set(refusals))),
        notes=tuple(notes),
        files=tuple(str(path.relative_to(base)) for path in files),
    )
