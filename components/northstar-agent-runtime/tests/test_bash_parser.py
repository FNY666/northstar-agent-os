"""Bash AST parser: fail-closed verdicts for every dangerous node class.

Covers (segment 6):
- benign commands pass (simple, pipeline, quoted args, env assignment,
  redirection inside the workspace)
- all 15 dangerous node classes denied, plus dangerous builtins
- bypass forms denied (unicode whitespace, array-subscript arithmetic RCE,
  zsh ~[name] / =cmd, quoted brace expansion, nested $() in backticks,
  substitution hidden in double quotes, eval via variable indirection)
- malformed input is TooComplex and never raises
- budget enforcement (very large input is rejected quickly)
- determinism (same input twice = same verdict)

The execution-gate test lives in test_governed_action_runner.py (segment 5)
and is deliberately not duplicated here.
"""

import importlib.util
import sys
import time
from pathlib import Path

import pytest

RUNTIME = Path(__file__).resolve().parent.parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


bp = _load("bash_parser")

ALLOW = bp.VerdictKind.ALLOW
DENY = bp.VerdictKind.DENY
TOO_COMPLEX = bp.VerdictKind.TOO_COMPLEX


# ---------------------------------------------------------------------------
# Benign commands
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "command",
    [
        "ls",
        "ls -la",
        "git status --short",
        "cat README.md",
        "echo hello",
    ],
)
def test_simple_command_allowed(command):
    verdict = bp.check_command(command)
    assert verdict.kind is ALLOW
    assert verdict.node == "list"


@pytest.mark.parametrize(
    "command",
    [
        "ls -la | grep foo",
        "cat file.txt | sort | uniq -c",
        "printf '%s\\n' a b | head -n 2",
    ],
)
def test_pipeline_of_safe_commands_allowed(command):
    verdict = bp.check_command(command)
    assert verdict.kind is ALLOW
    assert verdict.node == "pipeline"


@pytest.mark.parametrize(
    "command",
    [
        'echo "hello world"',
        "echo 'single quoted arg'",
        'grep "a b" file.txt',
        "echo \"escaped \\\" quote\"",
    ],
)
def test_quoted_args_allowed(command):
    assert bp.check_command(command).kind is ALLOW


@pytest.mark.parametrize(
    "command",
    [
        "FOO=bar ./run.sh",
        "PATH=/tmp/bin:$PATH ls",
        "A=1 B=2 env",
    ],
)
def test_env_assignment_allowed(command):
    assert bp.check_command(command).kind is ALLOW


@pytest.mark.parametrize(
    "command",
    [
        "echo hi > out.txt",
        "echo hi >> log.txt",
        "cat < in.txt",
        "echo hi 2> err.txt",
        "cat in.txt > out.txt",
    ],
)
def test_redirection_allowed(command):
    assert bp.check_command(command).kind is ALLOW


@pytest.mark.parametrize("command", ["", "   ", "\t", "\n"])
def test_empty_command_allowed(command):
    assert bp.check_command(command).kind is ALLOW


def test_plain_variable_expansion_allowed():
    assert bp.check_command("echo $HOME").kind is ALLOW
    assert bp.check_command("echo ${HOME}").kind is ALLOW


# ---------------------------------------------------------------------------
# The 15 dangerous node classes
# ---------------------------------------------------------------------------

DANGEROUS_NODE_CASES = [
    # 1. command substitution
    ("echo $(id)", "command_substitution"),
    ("echo `id`", "command_substitution"),
    ("x=$(cat /etc/passwd)", "command_substitution"),
    # 2. process substitution
    ("cat <(id)", "process_substitution"),
    ("diff <(ls a) <(ls b)", "process_substitution"),
    ("tee >(cat)", "process_substitution"),
    # 3. subshell
    ("(cd /tmp && ls)", "subshell"),
    ("(echo hi)", "subshell"),
    # 4. loops
    ("for i in 1 2; do echo $i; done", "loop"),
    ("while true; do echo x; done", "loop"),
    ("until false; do echo x; done", "loop"),
    # 5. conditionals
    ("if true; then echo x; fi", "conditional"),
    ("case $x in a) echo a;; esac", "conditional"),
    ("[[ -f x ]]", "conditional"),
    # 6. function definitions
    ("foo() { echo hi; }", "function_definition"),
    ("function foo { echo hi; }", "function_definition"),
    # 7. arithmetic expansion
    ("echo $((1+2))", "arithmetic_expansion"),
    ("echo $(( $(id) ))", "arithmetic_expansion"),
    # 8. array-subscript arithmetic
    ("echo ${a[$(id)]}", "array_subscript_arithmetic"),
    ("arr[$(id)]=1", "command_substitution"),
    # 9. brace expansion
    ("echo {a,b,c}", "brace_expansion"),
    ("echo {1..5}", "brace_expansion"),
    # 10. zsh dynamic tilde expansion
    ("echo ~[foo]", "zsh_tilde_expansion"),
    ("echo ~root/x", "zsh_tilde_expansion"),
    # 11. zsh equals expansion
    ("echo =curl", "zsh_equals_expansion"),
    ("=ls", "zsh_equals_expansion"),
    # 12. variable indirection
    ("echo ${!x}", "variable_indirection"),
    ("$cmd args", "variable_indirection"),
    # 13. control characters
    ("echo hi\x00", "control_character"),
    ("echo hi\x1b[31m", "control_character"),
    ("echo hi\x7f", "control_character"),
    # 14. unicode whitespace smuggling
    ("echo hi ; id", "unicode_whitespace"),
    ("echo hi ; id", "unicode_whitespace"),
    ("echo hi​; id", "unicode_whitespace"),
    ("echo hi ; id", "unicode_whitespace"),
    # 15. dangerous builtins (as their own node)
    ("eval echo hi", "eval"),
    ("source script.sh", "source"),
    ("exec ls", "exec"),
    ("trap 'id' EXIT", "trap"),
]


@pytest.mark.parametrize("command,node", DANGEROUS_NODE_CASES)
def test_dangerous_node_denied(command, node):
    verdict = bp.check_command(command)
    assert verdict.kind is DENY, (command, verdict)
    assert verdict.node == node, (command, verdict)
    assert verdict.reason


def test_all_fifteen_node_classes_are_exercised():
    """The parametrized set must cover all 15 dangerous node classes.

    Fourteen classes have a dedicated node name; the fifteenth is "dangerous
    builtin", whose node name is the builtin itself, so it is asserted by
    checking that a builtin node appears in the set.
    """
    nodes = {node for _, node in DANGEROUS_NODE_CASES}
    fourteen = {
        "command_substitution",
        "process_substitution",
        "subshell",
        "loop",
        "conditional",
        "function_definition",
        "arithmetic_expansion",
        "array_subscript_arithmetic",
        "brace_expansion",
        "zsh_tilde_expansion",
        "zsh_equals_expansion",
        "variable_indirection",
        "control_character",
        "unicode_whitespace",
    }
    assert len(fourteen) == 14
    assert fourteen <= nodes, sorted(fourteen - nodes)
    assert nodes & bp.DANGEROUS_BUILTINS, "no dangerous-builtin node covered"
    assert len(nodes) == 18  # 14 classes + 4 distinct builtin names here


# ---------------------------------------------------------------------------
# Dangerous builtins
# ---------------------------------------------------------------------------

STANDARD_DANGEROUS = ["eval", "source", ".", "exec", "trap"]

ZSH_DANGEROUS = [
    "zmodload", "ztcp", "zpty", "zsocket", "zprof", "zcompile",
    "zregexparse", "zparseopts", "zstyle", "zformat", "zle",
    "zsystem", "ztie", "zstat", "zselect", "zftp", "zkbd", "zcalc",
]

EXTRA_DANGEROUS = [
    "alias", "unalias", "builtin", "command", "enable", "typeset",
    "declare", "unset", "let", "read", "mapfile", "readarray",
]


@pytest.mark.parametrize(
    "builtin", STANDARD_DANGEROUS + ZSH_DANGEROUS + EXTRA_DANGEROUS
)
def test_dangerous_builtin_denied(builtin):
    verdict = bp.check_command(f"{builtin} somearg")
    assert verdict.kind is DENY, (builtin, verdict)
    assert verdict.node == builtin


@pytest.mark.parametrize("builtin", ["zmodload", "ztcp", "eval", "source", "exec", "trap"])
def test_dangerous_builtin_denied_without_args(builtin):
    verdict = bp.check_command(builtin)
    assert verdict.kind is DENY
    assert verdict.node == builtin


@pytest.mark.parametrize("builtin", ["eval", "source", "exec", "zmodload"])
def test_dangerous_builtin_denied_in_pipeline(builtin):
    verdict = bp.check_command(f"ls | {builtin} x")
    assert verdict.kind is DENY
    assert verdict.node == builtin


def test_builtin_set_is_declared_and_large():
    # 5 standard + 18 zsh + 12 additional = 35, the report's "35+" floor.
    assert len(bp.DANGEROUS_BUILTINS) >= 35
    assert set(STANDARD_DANGEROUS) <= bp.DANGEROUS_BUILTINS
    assert set(ZSH_DANGEROUS) <= bp.DANGEROUS_BUILTINS


# ---------------------------------------------------------------------------
# Pipelines / lists containing a dangerous element
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "command,node",
    [
        ("ls && echo $(id)", "command_substitution"),
        ("ls; cat <(id)", "process_substitution"),
        ("ls | grep x | eval", "eval"),
        ("true || (echo hi)", "subshell"),
        ("echo a; for i in 1; do echo $i; done", "loop"),
    ],
)
def test_dangerous_element_denies_whole_list(command, node):
    verdict = bp.check_command(command)
    assert verdict.kind is DENY, (command, verdict)
    assert verdict.node == node


def test_safe_list_allowed():
    verdict = bp.check_command("echo a && echo b; echo c")
    assert verdict.kind is ALLOW


# ---------------------------------------------------------------------------
# Bypass forms
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "command,node",
    [
        # Unicode whitespace smuggling
        ("echo hi && id", "unicode_whitespace"),
        ("ls ; id", "unicode_whitespace"),
        # array-subscript arithmetic RCE
        ("test -v 'a[$(id)]'", "array_subscript_arithmetic"),
        # same RCE hidden in double quotes is caught earlier as substitution
        ('test -v "a[$(id)]"', "command_substitution"),
        ("echo ${arr[$(id)]}", "array_subscript_arithmetic"),
        # zsh expansions
        ("echo ~[name]", "zsh_tilde_expansion"),
        ("echo =curl", "zsh_equals_expansion"),
        # quoted brace expansion
        ("echo '{a,b}'", "brace_expansion"),
        ('echo "{1..9}"', "brace_expansion"),
        # nested $() inside backticks
        ("echo `echo $(id)`", "command_substitution"),
        # command substitution hidden in double quotes
        ('echo "$(id)"', "command_substitution"),
        ('echo "prefix `id` suffix"', "command_substitution"),
        # eval reached via variable indirection
        ("cmd=eval; $cmd id", "variable_indirection"),
        ("${!ref}", "variable_indirection"),
    ],
)
def test_bypass_form_denied(command, node):
    verdict = bp.check_command(command)
    assert verdict.kind is DENY, (command, verdict)
    assert verdict.node == node


@pytest.mark.parametrize(
    "command",
    [
        "echo $(id",
        "echo `id",
        "cat <(id",
        "echo ${unbalanced",
        "echo $((1+2",
    ],
)
def test_unbalanced_bypass_forms_are_too_complex(command):
    verdict = bp.check_command(command)
    assert verdict.kind is TOO_COMPLEX, (command, verdict)


# ---------------------------------------------------------------------------
# Malformed input: TooComplex, never an exception
# ---------------------------------------------------------------------------

MALFORMED_INPUTS = [
    "echo 'unbalanced",
    'echo "unbalanced',
    "echo $(id",
    "echo `id",
    "(echo",
    "echo )",
    "(",
    ")",
    "echo ${unbalanced",
    "echo $((1+2",
    "echo a; ; ls",
    "echo hi &",
    "echo $",
    "echo \\",
    'echo "trailing \\',
    "| ls",
    "ls |",
    ";;",
]
# NOTE: "echo {a,b" is intentionally NOT listed: an unclosed brace is a literal
# word in POSIX shells, so the parser allows it rather than rejecting it.


@pytest.mark.parametrize("command", MALFORMED_INPUTS)
def test_malformed_input_is_too_complex_not_exception(command):
    verdict = bp.check_command(command)
    assert verdict.kind is TOO_COMPLEX, (command, verdict)
    assert verdict.node
    assert verdict.reason


@pytest.mark.parametrize("value", [None, 42, b"ls", [], object()])
def test_non_string_input_is_too_complex(value):
    verdict = bp.check_command(value)
    assert verdict.kind is TOO_COMPLEX


def test_never_raises_on_adversarial_input():
    samples = MALFORMED_INPUTS + [
        "$(" * 100,
        "`" * 100,
        "{" * 1000,
        "(" * 500 + ")" * 500,
        "\x00" * 100,
        "​" * 100,
        "echo " + "$" * 1000,
        "echo " + "'" * 999,
    ]
    for sample in samples:
        verdict = bp.check_command(sample)  # must not raise
        assert verdict.kind in (ALLOW, DENY, TOO_COMPLEX)


# ---------------------------------------------------------------------------
# Budget enforcement
# ---------------------------------------------------------------------------


def test_budget_constants():
    assert bp.MAX_PARSE_TIME_S <= 0.050
    assert bp.MAX_AST_NODES == 50000


@pytest.mark.parametrize("words", [100_000, 500_000, 1_000_000])
def test_very_large_input_is_too_complex_quickly(words):
    command = "echo " + "a " * words
    started = time.monotonic()
    verdict = bp.check_command(command)
    elapsed = time.monotonic() - started
    assert verdict.kind is TOO_COMPLEX
    assert verdict.node == "budget"
    assert elapsed < 1.0, f"budget rejection took {elapsed:.3f}s"


def test_large_quoted_input_is_too_complex_quickly():
    command = 'echo "' + "a" * 2_000_000 + '"'
    started = time.monotonic()
    verdict = bp.check_command(command)
    elapsed = time.monotonic() - started
    assert verdict.kind is TOO_COMPLEX
    assert elapsed < 1.0, f"budget rejection took {elapsed:.3f}s"


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------

DETERMINISM_SAMPLES = [
    "ls -la",
    "echo $(id)",
    "for i in 1; do echo $i; done",
    "echo 'unbalanced",
    "echo {a,b}",
    "echo hi ; id",
    "eval x",
    "ls | grep foo",
]


@pytest.mark.parametrize("command", DETERMINISM_SAMPLES)
def test_same_input_same_verdict(command):
    first = bp.check_command(command)
    for _ in range(4):
        again = bp.check_command(command)
        assert again == first


def test_determinism_across_fresh_instances():
    # Compare verdict fields: each _load() creates a distinct class object, so
    # dataclass equality between instances from different modules is False.
    results = []
    for _ in range(3):
        module = _load("bash_parser")
        verdict = module.check_command("echo $(id)")
        results.append((verdict.kind.value, verdict.node, verdict.reason))
    assert all(result == results[0] for result in results)


# ---------------------------------------------------------------------------
# Module hygiene
# ---------------------------------------------------------------------------


def test_parser_module_self_check():
    assert bp.stdlib_only() is True
    assert bp.BASH_PARSER_VERSION == "bash-parser.v1"
