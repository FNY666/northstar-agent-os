"""The TypeScript face must keep saying what the runtime means.

``components/northstar-agent-runtime/sdk-ts`` re-declares, in TypeScript, contracts that Python
owns: the exit-code table, the event vocabulary, the closed option sets, the flags a run accepts,
and the key set of a ``result`` payload. A mirror is only trustworthy while something checks it,
and that something cannot be the node suite alone - a build image with no node in it would go green
while the mirror rotted.

So this test runs everywhere the repository's tests run, uses no node, and reads the *runtime's*
own definitions (imported modules and the live ``argparse`` tree, not ``--help`` text) against the
TypeScript sources. Where node is present, ``node --test`` additionally exercises behaviour; what
is pinned here is shape, which is what drifts.
"""
import argparse
import ast
import json
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / "components" / "northstar-agent-runtime"
SDK_TS = RUNTIME / "sdk-ts"
sys.path.insert(0, str(RUNTIME))


def _source(name: str) -> str:
    return (SDK_TS / "src" / name).read_text(encoding="utf-8")


def _ts_const_array(source: str, name: str) -> list[str]:
    """The string members of ``export const NAME = [...] as const;``."""
    match = re.search(rf"export const {name} = \[(.*?)\] as const;", source, re.S)
    if not match:
        raise AssertionError(f"sdk-ts does not declare `export const {name} = [...] as const;`")
    return re.findall(r'"([^"]+)"', match.group(1))


def _ts_const_ints(source: str, name: str) -> dict[str, int]:
    match = re.search(rf"export const {name} = \{{(.*?)\}} as const;", source, re.S)
    if not match:
        raise AssertionError(f"sdk-ts does not declare `export const {name} = {{...}} as const;`")
    return {key: int(value) for key, value in re.findall(r"(\w+):\s*(-?\d+)", match.group(1))}


def _ts_const_number(source: str, name: str) -> int:
    match = re.search(rf"export const {name} = (-?\d+);", source)
    if not match:
        raise AssertionError(f"sdk-ts does not declare `export const {name} = <number>;`")
    return int(match.group(1))


def _ts_flag_map(source: str, name: str) -> dict[str, str]:
    """``const NAME: Record<...> = { key: "--flag", ... };`` as a dict (empty values kept)."""
    match = re.search(rf"const {name}: Record<[^=]*=\s*\{{(.*?)\n\}};", source, re.S)
    if not match:
        raise AssertionError(f"sdk-ts does not declare `const {name}` as a flag map")
    return dict(re.findall(r'(\w+):\s*"([^"]*)"', match.group(1)))


def _ts_type_fields(source: str, name: str) -> list[str]:
    """Field names of ``export type NAME = { ... };`` (index signatures ignored)."""
    match = re.search(rf"export type {name} = \{{(.*?)\n\}};", source, re.S)
    if not match:
        raise AssertionError(f"sdk-ts does not declare `export type {name}`")
    return re.findall(r"^\s{2}(\w+)\??:", match.group(1), re.M)


def _run_parser() -> argparse.ArgumentParser:
    import cli

    top = cli.build_parser()
    for action in top._actions:
        if isinstance(action, argparse._SubParsersAction) and "run" in action.choices:
            return action.choices["run"]
    raise AssertionError("`cli run` has no subparser to compare against")


def _parser_flags(parser: argparse.ArgumentParser) -> dict[str, argparse.Action]:
    flags: dict[str, argparse.Action] = {}
    for action in parser._actions:
        for option in action.option_strings:
            flags[option] = action
    return flags


class TypeScriptEventMirrorTest(unittest.TestCase):
    """`sdk-ts/src/events.ts` against the modules that define the vocabulary."""

    def test_exit_codes_match_the_runtime_table(self) -> None:
        import events

        self.assertEqual(_ts_const_ints(_source("events.ts"), "EXIT_CODES"), dict(events.EXIT_CODES))

    def test_usage_error_is_the_number_nothing_ran(self) -> None:
        import cli

        self.assertEqual(_ts_const_number(_source("events.ts"), "USAGE_ERROR"), cli.USAGE_ERROR)

    def test_unknown_subtypes_fall_back_the_way_the_cli_does(self) -> None:
        import events

        source = _source("events.ts")
        self.assertIn("return code === undefined ? 1 : code;", source)
        # The fallback is `1` at both call sites in Python; if either changes, the mirror is wrong.
        for module in ("cli.py", "sdk.py"):
            text = (RUNTIME / module).read_text(encoding="utf-8")
            self.assertIn("EXIT_CODES.get(", text, f"{module} no longer looks up EXIT_CODES")
        self.assertEqual(events.EXIT_CODES.get("error_not_a_real_subtype", 1), 1)

    def test_result_subtypes_are_the_exit_code_keys(self) -> None:
        """The subtypes a run may end with, and the table of codes, must be the same eight."""
        from providers.base import RESULT_SUBTYPES

        self.assertEqual(
            sorted(RESULT_SUBTYPES),
            sorted(_ts_const_ints(_source("events.ts"), "EXIT_CODES")),
            "a new subtype needs an exit code in events.py and a key in sdk-ts/src/events.ts",
        )

    def test_event_vocabulary_is_exactly_the_documented_five(self) -> None:
        self.assertEqual(
            _ts_const_array(_source("events.ts"), "KNOWN_EVENT_TYPES"),
            ["result", "system", "assistant", "user", "stream_delta"],
        )

    def test_result_payload_keys_are_the_keys_event_to_dict_writes(self) -> None:
        """The TS `ResultEvent` type and `events.event_to_dict` must agree field for field."""
        from providers.base import ResultMessage, Usage

        import events

        # `is_error` is derived on the Python side and carried on the wire; both are true, and the
        # TS type reads it from the payload, which is what a caller of `--json` actually sees.
        payload = events.event_to_dict(
            ResultMessage(
                subtype="success",
                num_turns=1,
                duration_ms=0,
                total_cost_usd=0.0,
                total_usage=Usage(),
                session_id="s",
                pricing_estimated=False,
            )
        )
        self.assertEqual(
            set(_ts_type_fields(_source("events.ts"), "ResultEvent")) - {"type"},
            set(payload) - {"type"},
            "the result event gained or lost a field: mirror it in sdk-ts/src/events.ts first",
        )

    def test_denial_fields_are_loop_denial_as_dict(self) -> None:
        from loop import Denial

        self.assertEqual(
            sorted(_ts_type_fields(_source("events.ts"), "Denial")),
            sorted(Denial().as_dict()),
        )

    def test_usage_fields_are_usage_as_dict(self) -> None:
        from providers.base import Usage

        self.assertEqual(
            sorted(_ts_type_fields(_source("events.ts"), "Usage")),
            sorted(Usage().as_dict()),
        )

    def test_the_fallback_for_an_unrenderable_event_is_type_and_repr(self) -> None:
        """`parseEventLine` passes unknown shapes straight through; check the shape it passes."""
        from loop import ToolCallReport

        import events

        payload = events.event_to_dict(ToolCallReport())
        self.assertEqual(sorted(payload), ["repr", "type"])
        source = _source("events.ts")
        # The TS side must not invent fields for that case, and must not drop it on the floor.
        self.assertIn("return payload as UnknownEvent;", source)


class TypeScriptOptionMirrorTest(unittest.TestCase):
    """`sdk-ts/src/options.ts` against `cli run`'s own parser and the closed sets."""

    def test_every_emitted_flag_exists_on_run(self) -> None:
        flags = _parser_flags(_run_parser())
        source = _source("options.ts")
        emitted: set[str] = set()
        for name in ("OPTION_FLAGS", "RETRY_FLAGS", "MCP_FLAGS", "SIDECAR_FLAGS"):
            emitted |= {value for value in _ts_flag_map(source, name).values() if value}
        emitted |= {"--json", "--no-retry"}
        unknown = sorted(flag for flag in emitted if flag not in flags)
        self.assertEqual(unknown, [], f"sdk-ts emits flags `run` does not have: {unknown}")

    def test_the_inventory_function_covers_the_maps_and_excludes_json(self) -> None:
        source = _source("options.ts")
        body = source[source.index("export function supportedFlags") : source.index("function fail(")]
        for name in ("OPTION_FLAGS", "RETRY_FLAGS", "MCP_FLAGS", "SIDECAR_FLAGS"):
            self.assertIn(f"Object.values({name})", body)
        self.assertIn('names.add("--no-retry")', body)
        self.assertNotIn('names.add("--json")', body, "--json is not caller-settable, so it is not offered")

    def test_the_run_options_type_has_no_private_flag_orphan(self) -> None:
        """Every scalar option maps to a flag; the three grouped namespaces are listed as such."""
        source = _source("options.ts")
        mapped = set(_ts_flag_map(source, "OPTION_FLAGS"))
        declared = set(_ts_type_fields(source, "RunOptions"))
        groups = set(_ts_const_array(source, "GROUP_OPTION_KEYS"))
        self.assertEqual(groups, {"retry", "mcp", "sidecar"})
        self.assertEqual(declared - mapped, groups, "an option is declared but compiles to no flag")

    def test_permission_modes_are_the_gate(self) -> None:
        from permissions import PERMISSION_MODES

        self.assertEqual(_ts_const_array(_source("options.ts"), "PERMISSION_MODES"), list(PERMISSION_MODES))

    def test_providers_and_mcp_protocols_are_the_parser_choices(self) -> None:
        flags = _parser_flags(_run_parser())
        for name, flag in (("PROVIDERS", "--provider"), ("MCP_PROTOCOLS", "--mcp-protocol")):
            declared = _ts_const_array(_source("options.ts"), name)
            self.assertEqual(
                declared,
                list(flags[flag].choices),
                f"`run {flag}` and sdk-ts disagree about the accepted values",
            )

    def test_verify_kinds_are_the_postconditions_kinds(self) -> None:
        from postconditions import KINDS

        self.assertEqual(_ts_const_array(_source("options.ts"), "VERIFY_KINDS"), list(KINDS))

    def test_retryable_classes_are_the_retry_policies(self) -> None:
        from provider_retry import NEVER_RETRYABLE_CLASSES, RETRYABLE_CLASSES

        source = _source("options.ts")
        self.assertEqual(_ts_const_array(source, "RETRYABLE_FAULTS"), list(RETRYABLE_CLASSES))
        policy_only = _ts_const_array(source, "POLICY_ONLY_RETRY_KEYS")
        # A class the policy owns may not be reachable from a run, and the never-retryable ones
        # must not appear in the retryable list: `--retry-on` refuses them and so must the SDK.
        self.assertIn("onContextOverflow", policy_only)
        for never in NEVER_RETRYABLE_CLASSES:
            self.assertNotIn(never, _ts_const_array(source, "RETRYABLE_FAULTS"))


class TypeScriptPackageShapeTest(unittest.TestCase):
    """The shipping decisions are part of the contract: unpinned deps, no build step, unpublished."""

    def setUp(self) -> None:
        self.manifest = json.loads((SDK_TS / "package.json").read_text(encoding="utf-8"))

    def test_the_package_is_not_publishable_from_here(self) -> None:
        """Publishing is the line the repository has not crossed; the TS face ships as source."""
        self.assertIs(self.manifest.get("private"), True)

    def test_there_is_nothing_to_install(self) -> None:
        self.assertEqual(self.manifest.get("dependencies"), {})
        self.assertEqual(self.manifest.get("devDependencies"), {})
        self.assertNotIn("build", self.manifest.get("scripts", {}), "a build step would need a registry")

    def test_the_engine_floor_is_the_type_stripping_floor(self) -> None:
        self.assertEqual(self.manifest["engines"]["node"], ">=22.6.0")
        self.assertEqual(self.manifest["type"], "module")
        self.assertIn("--test", self.manifest["scripts"]["test"])

    def test_the_package_entry_points_are_the_sources_themselves(self) -> None:
        exports = self.manifest["exports"]
        for name, target in exports.items():
            self.assertTrue((SDK_TS / target.lstrip("./")).exists(), f"{name} points at a missing {target}")

    def test_the_readme_records_the_traps_the_types_cannot(self) -> None:
        readme = (SDK_TS / "README.md").read_text(encoding="utf-8")
        for phrase in ("no tool call allowed", "unlimited", "22.6", "private"):
            self.assertIn(phrase, readme, f"sdk-ts/README.md must explain {phrase!r}")
        self.assertIn("python3 -m cli", readme, "the README must say what a run actually is")


if __name__ == "__main__":
    unittest.main()
