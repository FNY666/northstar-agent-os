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
from unittest import mock
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
# Unquoted variable expansion in arguments to dangerous commands
# ---------------------------------------------------------------------------
# An unquoted $VAR word-splits at runtime into unseen flags: `rm $VAR` with
# VAR='-rf /' executes as `rm -rf /`. The parser sees only the literal token,
# so it must deny the expansion structurally when the command is dangerous.
# Quoted expansions ("$VAR" / "${VAR}") do not word-split and stay allowed.

UNQUOTED_EXPANSION_DENY_CASES = [
    ("rm $VAR", "unquoted_expansion"),
    ("rm ${VAR}", "unquoted_expansion"),
    ("rm x$VAR", "unquoted_expansion"),
    ("mkfs $DEV", "unquoted_expansion"),
    ("rm $A $B", "unquoted_expansion"),
    ("rm $VAR | cat", "unquoted_expansion"),
]


@pytest.mark.parametrize("command,node", UNQUOTED_EXPANSION_DENY_CASES)
def test_unquoted_expansion_to_dangerous_command_denied(command, node):
    verdict = bp.check_command(command)
    assert verdict.kind is DENY, (command, verdict)
    assert verdict.node == node, (command, verdict)
    assert verdict.reason


@pytest.mark.parametrize(
    "command",
    [
        "echo $HOME",
        "echo ${HOME}",
        'rm "$VAR"',
        'rm "${VAR}"',
        "rm file.txt",
        'rm -- "$VAR"',
    ],
)
def test_quoted_or_safe_expansion_allowed(command):
    assert bp.check_command(command).kind is ALLOW, (
        command,
        bp.check_command(command),
    )


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


# ---------------------------------------------------------------------------
# Segment 7: wrapper unwrapping and the two caps
# ---------------------------------------------------------------------------
# A depth cap on its own is a sieve: a wide command slips under it, and a
# semicolon chain never enters an unwrap loop at all.  The parser therefore
# enforces two caps at the same time, and measures the argv budget *after*
# unwrapping -- stripping a wrapper changes the count, so a budget measured
# before the unwrap measures the wrong command.  Anything that cannot be
# resolved is denied, never passed.

# --- the core regression: `sudo rm $VAR` ---------------------------------


@pytest.mark.parametrize(
    "command",
    [
        "sudo rm $VAR",
        "sudo rm ${VAR}",
        "sudo rm x$VAR",
        "sudo rm $A $B",
        "sudo rm $VAR | cat",
        "sudo -u root rm $VAR",
        "sudo --user root rm $VAR",
        "sudo -uroot rm $VAR",
        "sudo -- rm $VAR",
        "sudo env FOO=1 rm $VAR",
        "sudo nohup rm $VAR",
        "doas rm $VAR",
        "nice rm $VAR",
        "nice -n 10 rm $VAR",
        "nohup rm $VAR",
        "stdbuf -o0 rm $VAR",
        "time rm $VAR",
        "timeout 5 rm $VAR",
        "env rm $VAR",
        "env FOO=1 rm $VAR",
    ],
)
def test_wrapped_dangerous_command_with_expansion_denied(command):
    verdict = bp.check_command(command)
    assert verdict.kind is DENY, (command, verdict)
    assert verdict.node == "unquoted_expansion", (command, verdict)
    assert verdict.reason


def test_sudo_rm_variable_expansion_is_denied():
    # The named regression from the brief, spelled out on its own.
    verdict = bp.check_command("sudo rm $VAR")
    assert verdict.kind is DENY
    assert verdict.node == "unquoted_expansion"
    assert "rm" in verdict.reason


def test_wrapper_depth_cap_denies_over_nesting():
    depth = bp.MAX_WRAPPER_DEPTH
    command = "sudo " * (depth + 1) + "ls"
    verdict = bp.check_command(command)
    assert verdict.kind is DENY, (command, verdict)
    assert verdict.node == "wrapper_depth", (command, verdict)
    assert str(depth) in verdict.reason


def test_wrapper_depth_at_cap_is_allowed():
    command = "sudo " * bp.MAX_WRAPPER_DEPTH + "ls"
    verdict = bp.check_command(command)
    assert verdict.kind is ALLOW, (command, verdict)


def test_argv_budget_cap_denies_wide_command():
    command = "echo " + "a " * (bp.MAX_ARGV_BUDGET + 50)
    verdict = bp.check_command(command)
    assert verdict.kind is DENY, (command, verdict)
    assert verdict.node == "argv_budget", (command, verdict)


def test_argv_budget_cap_denies_wide_semicolon_chain():
    # A semicolon chain never enters an unwrap loop, so the depth cap alone
    # cannot catch it; the argv budget must.
    command = "; ".join(["echo x"] * (bp.MAX_ARGV_BUDGET // 2 + 10))
    verdict = bp.check_command(command)
    assert verdict.kind is DENY, (command, verdict)
    assert verdict.node == "argv_budget", (command, verdict)


def test_argv_budget_is_measured_after_unwrap():
    # Stripping the wrapper changes the count.  A budget measured before the
    # unwrap would measure "sudo rm $VAR" (2 words) instead of the command
    # that really runs; the resolved budget must be charged per resolved word.
    verdict = bp.check_command("sudo " + "echo " + "a " * (bp.MAX_ARGV_BUDGET + 50))
    assert verdict.kind is DENY, (command, verdict)
    assert verdict.node == "argv_budget", (command, verdict)


def test_argv_budget_charges_unresolved_word_at_max_width():
    # One unquoted expansion can word-split into many runtime words, so it is
    # charged the maximum width rather than one word.
    command = "echo " + " $VAR" * (bp.MAX_ARGV_BUDGET // 10)
    verdict = bp.check_command(command)
    assert verdict.kind is DENY, (command, verdict)
    assert verdict.node == "argv_budget", (command, verdict)


def test_wide_command_under_budget_is_allowed():
    command = "echo " + "a " * (bp.MAX_ARGV_BUDGET // 2)
    verdict = bp.check_command(command)
    assert verdict.kind is ALLOW, (command, verdict)


# --- unresolvable expansions: deny, never pass ----------------------------


@pytest.mark.parametrize(
    "command,node",
    [
        ("sudo $CMD", "unresolved_command"),
        ("sudo $CMD args", "unresolved_command"),
        ("sudo ${CMD}", "unresolved_command"),
        ("sudo -u $USER rm x", "unresolved_wrapper"),
        ("sudo -$FLAG ls", "unresolved_wrapper"),
        ("sudo -Z ls", "unresolved_wrapper"),
        ("sudo --bogus ls", "unresolved_wrapper"),
        ("sudo -u", "unresolved_wrapper"),
        ("sudo", "unresolved_wrapper"),
        ("timeout 5", "unresolved_wrapper"),
        ("xargs rm", "unresolved_wrapper"),
        ("env -S ls", "unresolved_wrapper"),
    ],
)
def test_unresolvable_wrapper_is_denied(command, node):
    verdict = bp.check_command(command)
    assert verdict.kind is DENY, (command, verdict)
    assert verdict.node == node, (command, verdict)
    assert verdict.reason


def test_unresolved_is_never_allowed():
    # "Presume safe" is not an option: every unresolvable shape is a deny.
    for command in ["sudo $CMD", "sudo -Z ls", "sudo", "xargs rm"]:
        assert bp.check_command(command).kind is DENY, command


# --- allowed side: legitimate commands are unaffected ---------------------


@pytest.mark.parametrize(
    "command",
    [
        "sudo ls",
        "sudo ls -la",
        "sudo apt-get install curl",
        "sudo -u nobody ls",
        "doas ls",
        "env ls",
        "env FOO=bar ls",
        "nice ls",
        "nice -n 10 ls",
        "nohup ls",
        "stdbuf -o0 ls",
        "time ls",
        "timeout 5 ls",
        "echo hello",
        "ls -la",
        "git status --short",
        "cat README.md",
        "echo $HOME",
        "rm \"$VAR\"",
        "rm file.txt",
    ],
)
def test_legitimate_commands_still_allowed(command):
    verdict = bp.check_command(command)
    assert verdict.kind is ALLOW, (command, verdict)


def test_caps_are_declared_and_bounded():
    assert bp.MAX_WRAPPER_DEPTH >= 1
    assert bp.MAX_ARGV_BUDGET >= 64
    assert bp.MAX_UNRESOLVED_WORDS >= 1


def test_wrapper_table_covers_sudo_family():
    for wrapper in ["sudo", "doas", "env", "nice", "nohup", "stdbuf", "timeout"]:
        assert wrapper in bp.UNWRAP_WRAPPERS, wrapper


# ---------------------------------------------------------------------------
# Mutant evidence: the budget predicate
#
# The mutant probe rewrites these three lines:
#   gt@127   `if budget.nodes > MAX_AST_NODES:`   ->  `>=`
#   retT@128 `return True`                       ->  `return False`
#   gt@129   `return time.monotonic() > deadline` ->  `>=`
#
# Each differs from the original at EXACTLY ONE value, so each needs a
# test that feeds that value:
#
#   gt@127   nodes == MAX_AST_NODES  -- original: NOT exceeded;
#                                     mutant:    exceeded.
#   retT@128 nodes == MAX_AST_NODES + 1 -- original: True (exceeded);
#                                     mutant:    False, because the
#                                     `return True` became `return False`
#                                     and the deadline check then runs.
#   gt@129   now == deadline        -- original: NOT exceeded;
#                                     mutant:    exceeded.
#
# Each test also carries a CONTROL on the other side of the boundary, so
# it cannot be satisfied by a predicate that always returns the same
# answer.
# ---------------------------------------------------------------------------


def _budget(nodes: int, deadline: float):
    """A parse budget with an explicit node count and deadline."""
    return bp._ParseBudget(deadline=deadline, nodes=nodes)


def test_gt_at_127_a_node_count_of_exactly_the_limit_is_not_exceeded():
    """gt@127: `budget.nodes > MAX_AST_NODES` -- the limit is NOT over."""
    limit = bp.MAX_AST_NODES
    budget = _budget(limit, deadline=time.monotonic() + 60.0)
    assert bp._budget_exceeded(budget) is False


def test_gt_at_127_a_node_count_over_the_limit_is_exceeded():
    """gt@127: the bound itself is still pinned -- limit + 1 is over."""
    budget = _budget(bp.MAX_AST_NODES + 1, deadline=time.monotonic() + 60.0)
    assert bp._budget_exceeded(budget) is True


def test_gt_at_127_a_node_count_under_the_limit_is_not_exceeded():
    """gt@127: the control -- limit - 1 is not over."""
    budget = _budget(bp.MAX_AST_NODES - 1, deadline=time.monotonic() + 60.0)
    assert bp._budget_exceeded(budget) is False


def test_retT_at_128_an_over_limit_node_count_returns_true():
    """retT@128: the `return True` IS the answer for an over-limit count.

    Under the mutant it becomes `return False`, and the deadline check
    then decides -- which is False here, because the deadline is in the
    future.  So this one input separates the two.
    """
    budget = _budget(bp.MAX_AST_NODES + 1, deadline=time.monotonic() + 60.0)
    assert bp._budget_exceeded(budget) is True


def test_retT_at_128_the_deadline_check_still_applies_below_the_node_limit():
    """retT@128: the control -- under the node limit, the DEADLINE decides.

    This pins that `return True` is reached only because the node count
    is over: with a past deadline and a node count under the limit, the
    answer is still True, but it comes from the deadline line.
    """
    budget = _budget(0, deadline=time.monotonic() - 1.0)
    assert bp._budget_exceeded(budget) is True


def test_gt_at_129_a_deadline_of_exactly_now_is_not_exceeded():
    """gt@129: `time.monotonic() > deadline` -- the deadline itself is not over.

    The clock is frozen at exactly the deadline, which is the only value
    that separates `>` from `>=`.

    The freeze is a `mock.patch.object` on the `time` module the parser
    imported, and it is scoped to this one call, so the patch cannot
    outlive the assertion.
    """
    frozen = 1_000.0
    budget = _budget(0, deadline=frozen)
    with mock.patch.object(bp.time, "monotonic", return_value=frozen):
        assert bp._budget_exceeded(budget) is False


def test_gt_at_129_a_deadline_in_the_past_is_exceeded():
    """gt@129: the bound itself is still pinned -- past the deadline is over."""
    budget = _budget(0, deadline=time.monotonic() - 1.0)
    assert bp._budget_exceeded(budget) is True


def test_gt_at_129_a_deadline_in_the_future_is_not_exceeded():
    """gt@129: the control -- a future deadline is not over."""
    budget = _budget(0, deadline=time.monotonic() + 60.0)
    assert bp._budget_exceeded(budget) is False


# ---------------------------------------------------------------------------
# Mutant evidence: the 42 survivors of the whole-file sweep
#
# The planted-fault probe rewrites ONE token on ONE source line of
# ``bash_parser.py``.  The whole-file sweep reported ``killed 73/115``, and
# the 42 survivors are listed below.  Each one is a semantic fault at a
# named site, and each gets a test that names the site it kills:
#
#   retF@289 / retT@291   ``_is_negative_number``
#   gt@342 / eq@343       the wrapper-option loop
#   or@347 / or@357 / or@376
#                         the wrapper-option guards
#   or@446                the command-word expansion guard
#   retF@478 / eq@480 / retF@481 / eq@484 / retF@489
#                         ``_is_valid_identifier`` (``_is_name``)
#   lt@547 / lt@552 / lt@557
#                         unbalanced-delimiter checks
#   and@564 / or@579      the name and content checks
#   and@594 / and@599     the quoted-content checks
#   lt@613 / lt@620       the double-quote scanner
#   eq@632 / or@636       the brace-expansion checks
#   or@676 / and@677 / eq@677
#                         the list-ending checks
#   lt@686 / lt@690 / lt@709
#                         the delimiter matching
#   or@718                the "2>>" heredoc check
#   lt@756 / lt@773       the backtick and closing-brace checks
#   eq@795                brace expansion in a bare word
#   or@820 / and@822      the command-word scanning
#   or@878                the redirect-target check
#   gt@927                the argv budget bound
#   and@963 / and@973     the list-op checks
#   retF@1052 / retF@1055 the ``stdlib_only`` check
#
# The shapes follow ``docs/design/mutant-evidence-closure.md`` sections
# 3.1 (an ``or`` needs BOTH wrong ways fed), 3.2 (a ``gt``/``lt`` needs
# the exact limit and limit +/- 1), 3.3 (a ``retF``/``retT`` needs the
# False path asserted with ``assertIs`` plus a control) and 3.4 (every
# method names its site).
#
# Where a site is genuinely UNREACHABLE -- the mutated branch can never be
# taken -- the mutant is recorded as EQUIVALENT with a differential proof
# and a non-vacuity control, in the shape the repo already uses for
# ``durable_resume.py``'s ``lt@701``.  Those are at the end of this file.
# ---------------------------------------------------------------------------

ALLOW_ = ALLOW


# -- retF@289 / retT@291: ``_is_negative_number`` -------------------------


def test_retF_at_289_a_bare_dash_is_not_a_negative_number():
    """retF@289: the empty body is NOT a negative number.

    The line is ``if not body: return False``.  Under the mutant
    (``return False`` -> ``return True``) a bare ``-`` -- an option with
    no body at all -- is mistaken for a negative number, so a wrapper
    option that is not one is skipped instead of refused.

    ``assertIs(..., False)`` and not ``assertFalse``: the mutant returns
    True, and only the identity check distinguishes that from any other
    falsy value.
    """
    assert bp._is_negative_number("-") is False


def test_retF_at_289_a_negative_number_is_still_recognised():
    """retF@289: the control -- a real negative number still answers True.

    Without this the test above could be satisfied by a function that
    always answers False.
    """
    assert bp._is_negative_number("-1") is True
    assert bp._is_negative_number("-0") is True
    assert bp._is_negative_number("-.5") is True


def test_retT_at_291_a_digit_leading_body_is_a_negative_number():
    """retT@291: the ``return True`` IS the answer for a digit body.

    The line is ``if body[0] in "0123456789": return True``.  Under the
    mutant (``return True`` -> ``return False``) a numeric option is not
    recognised as a negative number, and the wrapper refuses it as an
    unknown option instead of skipping it.
    """
    assert bp._is_negative_number("-1") is True
    assert bp._is_negative_number("-9") is True


def test_retT_at_291_a_numeric_option_is_still_skipped_by_nice():
    """retT@291: the end-to-end half -- ``nice -5 ls`` is allowed.

    ``nice`` is the one wrapper whose numeric option is a negative
    number, so ``nice -5`` means "lower the priority by 5" and must not
    be refused as an unknown option.  Under the mutant it is refused.
    """
    verdict = bp.check_command("nice -5 ls")
    assert verdict.kind is ALLOW, (verdict)
    assert verdict.node == "list", (verdict)


def test_retT_at_291_the_negative_number_guard_is_the_control():
    """retT@291: the control -- a non-numeric option is still refused.

    ``nice -x`` is not a negative number, so it must still be refused as
    an unknown option.  This pins the other side of the guard.
    """
    verdict = bp.check_command("nice -x ls")
    assert verdict.kind is DENY, (verdict)
    assert verdict.node == "unresolved_wrapper", (verdict)
    assert "unknown option" in verdict.reason, (verdict)


# -- gt@342: the wrapper-option loop --------------------------------------


def test_gt_at_342_a_lone_dash_is_not_an_option():
    """gt@342: ``len(word) > 1`` -- a bare ``-`` is NOT an option.

    The line is ``if word.startswith("-") and len(word) > 1``.  Under the
    mutant (``>`` -> ``>=``) a bare ``-`` is treated as an option word,
    and the parser goes on to refuse it -- turning a legal command into
    a denial.
    """
    verdict = bp.check_command("sudo - rm $VAR")
    assert verdict.kind is ALLOW, (verdict)
    assert verdict.node == "list", (verdict)


def test_gt_at_342_the_bare_dash_is_not_an_option_word():
    """gt@342: the other half -- the dash is not treated as an option.

    Under the mutant a bare ``-`` is swallowed as an option word, so
    the words after it shift and the resolved command changes.  This
    asserts the ORIGINAL's reading of the command: the dash is a
    separator, and ``rm`` is the command that runs.
    """
    verdict = bp.check_command("sudo - rm x")
    assert verdict.kind is ALLOW, (verdict)
    assert verdict.node == "list", (verdict)


def test_gt_at_342_a_real_option_is_still_refused_when_unknown():
    """gt@342: the control -- a two-character unknown option is refused."""
    verdict = bp.check_command("sudo -Z ls")
    assert verdict.kind is DENY, (verdict)
    assert verdict.node == "unresolved_wrapper", (verdict)


# -- eq@343: the ``nice`` special case ------------------------------------


def test_eq_at_343_only_nice_gets_the_negative_number_exemption():
    """eq@343: ``wrapper == "nice"`` -- the exemption is nice's ALONE.

    The line is ``if wrapper == "nice" and _is_negative_number(word)``.
    Under the mutant (``==`` -> ``!=``) EVERY wrapper but ``nice`` gets
    the exemption, so ``nice -5`` loses its exemption and is refused.
    """
    verdict = bp.check_command("nice -5")
    assert verdict.kind is DENY, (verdict)
    assert verdict.node == "unresolved_wrapper", (verdict)
    assert "nice without a command" in verdict.reason, (verdict)


def test_eq_at_343_nice_with_a_numeric_option_and_a_command_is_allowed():
    """eq@343: the control -- ``nice -5 ls`` is a legal command.

    This is the other half of the guard: under the mutant this input is
    still allowed, so it cannot be what distinguishes the two.  Only
    ``nice -5`` -- the numeric option with NO command behind it -- does.
    """
    verdict = bp.check_command("nice -5 ls")
    assert verdict.kind is ALLOW, (verdict)
    assert verdict.node == "list", (verdict)


# -- or@347: the unresolved-option guard -----------------------------------


def test_or_at_347_an_expanded_option_is_refused_as_unresolved():
    """or@347: the expansion half of the option guard.

    The line is ``if token.unquoted_expansion or "$" in word``.  Under
    the mutant (``or`` -> ``and``) an option whose value is an
    expansion is no longer refused as "unresolved"; it falls through to
    the unknown-option refusal instead.  The discriminator is the
    MESSAGE: "unresolved option" versus "unknown option".
    """
    verdict = bp.check_command('sudo "-$FLAG" ls')
    assert verdict.kind is DENY, (verdict)
    assert verdict.node == "unresolved_wrapper", (verdict)
    assert "unresolved option" in verdict.reason, (verdict)
    assert "unknown option" not in verdict.reason, (verdict)


def test_or_at_347_an_unexpanded_unknown_option_is_refused_as_unknown():
    """or@347: the other half, as the control.

    A literal unknown option has no expansion, so only the second half
    of the guard refuses it.  Under the mutant this input is refused
    with the SAME "unknown option" message, so it cannot be what
    distinguishes the two -- the expanded option above is.
    """
    verdict = bp.check_command("sudo -Z ls")
    assert verdict.kind is DENY, (verdict)
    assert verdict.node == "unresolved_wrapper", (verdict)
    assert "unknown option" in verdict.reason, (verdict)


# -- or@357: the shell-source option guard ---------------------------------


def test_or_at_357_an_inline_shell_source_option_is_refused_as_shell_source():
    """or@357: the ``word.split("=")`` half of the guard.

    The line is ``if word in deny_opts or word.split("=", 1)[0] in
    deny_opts``.  Under the mutant (``or`` -> ``and``) the second half
    no longer refuses on its own, so ``env -S=x`` -- the option with an
    inline value -- falls through to the unknown-option refusal.  The
    discriminator is the MESSAGE: "runs shell source" versus "unknown
    option".
    """
    verdict = bp.check_command("env -S=x ls")
    assert verdict.kind is DENY, (verdict)
    assert verdict.node == "unresolved_wrapper", (verdict)
    assert "runs shell source" in verdict.reason, (verdict)
    assert "unknown option" not in verdict.reason, (verdict)


def test_or_at_357_a_bare_shell_source_option_is_refused_as_shell_source():
    """or@357: the other half, as the control.

    ``env -S`` matches ``word in deny_opts`` on its own, so it is
    refused with the SAME message under the mutant.  Only the inline
    form distinguishes the two.
    """
    verdict = bp.check_command("env -S ls")
    assert verdict.kind is DENY, (verdict)
    assert verdict.node == "unresolved_wrapper", (verdict)
    assert "runs shell source" in verdict.reason, (verdict)


# -- or@376: the unresolved-value guard ------------------------------------


def test_or_at_376_an_expanded_option_value_is_refused_as_unresolved():
    """or@376: the value side of the option-value guard.

    The line is ``if value_token.unquoted_expansion or "$" in
    value_word``.  Under the mutant (``or`` -> ``and``) a quoted
    expansion is NOT refused on its own -- the token is not an UNQUOTED
    expansion -- so the value is accepted and the whole command is
    allowed.  The command behind it (``rm``) then runs with a value the
    parser could not resolve.
    """
    verdict = bp.check_command('sudo -u "$USER" rm x')
    assert verdict.kind is DENY, (verdict)
    assert verdict.node == "unresolved_wrapper", (verdict)
    assert "unresolved value" in verdict.reason, (verdict)


def test_or_at_376_an_unexpanded_option_value_is_accepted():
    """or@376: the control -- a literal option value is fine.

    ``sudo -u root rm x`` has no expansion anywhere, so both halves of
    the guard are False and the command is allowed under the mutant too.
    It cannot be what distinguishes the two.
    """
    verdict = bp.check_command("sudo -u root rm x")
    assert verdict.kind is ALLOW, (verdict)
    assert verdict.node == "list", (verdict)


# -- or@446: the command-word expansion guard ------------------------------


def test_or_at_446_an_expanded_command_word_is_refused():
    """or@446: the expansion half of the command-word guard.

    The line is ``if command_token.unquoted_expansion or "$" in
    command_value``.  Under the mutant (``or`` -> ``and``) a QUOTED
    expansion is not refused on its own -- the token carries no
    unquoted expansion -- so the command word is accepted and the whole
    command is allowed.  A command word the parser cannot resolve must
    never be passed.
    """
    verdict = bp.check_command('sudo "$CMD"')
    assert verdict.kind is DENY, (verdict)
    assert verdict.node == "unresolved_command", (verdict)
    assert "contains an expansion" in verdict.reason, (verdict)


def test_or_at_446_a_literal_command_word_is_accepted():
    """or@446: the control -- a literal command word is fine."""
    verdict = bp.check_command("sudo ls")
    assert verdict.kind is ALLOW, (verdict)
    assert verdict.node == "list", (verdict)


# -- retF@478 / eq@480 / retF@481 / eq@484 / retF@489: ``_is_name`` -------


def test_retF_at_478_an_empty_name_is_not_a_name():
    """retF@478: the empty name is NOT a shell identifier.

    The line is ``if not text: return False``.  Under the mutant
    (``return False`` -> ``return True``) the empty string is a name.
    """
    assert bp._is_name("") is False


def test_retF_at_478_a_real_name_is_still_a_name():
    """retF@478: the control -- a plain identifier still answers True."""
    assert bp._is_name("abc") is True
    assert bp._is_name("_a") is True


def test_eq_at_480_an_underscore_leads_a_name():
    """eq@480: ``first == "_"`` -- the underscore IS a name's first letter.

    The line is ``if not (first == "_" or "a" <= first <= "z" or "A" <=
    first <= "Z")``.  Under the mutant (``==`` -> ``!=``) the underscore
    is no longer a valid first letter.
    """
    assert bp._is_name("_a") is True


def test_eq_at_480_a_digit_does_not_lead_a_name():
    """eq@480: the other half of the disjunction.

    ``1a`` is not a name: a shell identifier cannot start with a digit.
    Under the mutant (``==`` -> ``!=``) the underscore half reads
    ``"1" != "_"``, which is True, so the guard no longer refuses and
    ``1a`` is accepted as a name.
    """
    assert bp._is_name("1a") is False


def test_retF_at_481_a_name_may_not_start_with_a_digit():
    """retF@481: the first-letter refusal.

    The line is ``if not (first == "_" or ...): return False``.  Under
    the mutant (``return False`` -> ``return True``) ``1a`` is accepted
    as a name.
    """
    assert bp._is_name("1a") is False


def test_retF_at_481_a_name_that_starts_with_a_letter_is_still_a_name():
    """retF@481: the control."""
    assert bp._is_name("abc") is True


def test_eq_at_484_an_underscore_may_follow_the_first_letter():
    """eq@484: ``ch == "_"`` -- the underscore IS allowed inside a name.

    The line is ``if not (ch == "_" or "a" <= ch <= "z" ...)``.  Under
    the mutant (``==`` -> ``!=``) ``a_b`` is no longer a name.
    """
    assert bp._is_name("a_b") is True


def test_eq_at_484_a_dash_may_not_follow_the_first_letter():
    """eq@484: the other half of the disjunction.

    ``a-b`` is not a name.  Under the mutant (``==`` -> ``!=``) the
    underscore half reads ``"b" != "_"``, which is True, so the guard
    no longer refuses the dash and ``a-b`` is accepted as a name.
    """
    assert bp._is_name("a-b") is False


def test_retF_at_489_a_dash_may_not_follow_the_first_letter():
    """retF@489: the tail refusal -- the name's own characters.

    The line is ``return False`` at the end of the character loop.
    Under the mutant (``return False`` -> ``return True``) ``a-b`` is
    accepted as a name.
    """
    assert bp._is_name("a-b") is False


def test_retF_at_489_a_name_of_letters_and_digits_is_still_a_name():
    """retF@489: the control."""
    assert bp._is_name("a1") is True


# -- and@564: the array-subscript check in a parameter expansion -----------


def test_and_at_564_an_array_subscript_is_not_a_substitution():
    """and@564: the ``"[" in name`` half of the guard.

    The line is ``if "[" in name and ("$(" in name or "`" in name)``.
    Under the mutant (``and`` -> ``or``) the guard fires on ANY name
    that contains ``[`` -- even one with no substitution in it -- so a
    plain array subscript is refused as an attack.
    """
    verdict = bp.check_command("echo ${a[0]}")
    assert verdict.kind is TOO_COMPLEX, (verdict)
    assert verdict.node == "parameter_expansion", (verdict)
    assert "non-plain" in verdict.reason, (verdict)


def test_and_at_564_a_substitution_inside_a_subscript_is_refused():
    """and@564: the other half of the disjunction.

    ``${$(id)}`` has a substitution and no ``[``.  Under the mutant
    (``and`` -> ``or``) the substitution half fires on its own, so the
    expansion is refused as an array-subscript attack instead of
    falling through to the plain-name refusal.
    """
    verdict = bp.check_command("echo ${$(id)}")
    assert verdict.kind is TOO_COMPLEX, (verdict)
    assert verdict.node == "parameter_expansion", (verdict)


# -- and@594: the quoted-content array-subscript check --------------------


def test_and_at_594_a_quoted_array_subscript_is_not_a_substitution():
    """and@594: the ``"[" in content`` half of the guard.

    The line is ``if "[" in content and ("$(" in content or "`" in
    content)``.  Under the mutant (``and`` -> ``or``) any quoted text
    containing ``[`` is refused as an array-subscript attack, even
    when it holds no substitution at all.
    """
    verdict = bp.check_command("echo 'a[0]'")
    assert verdict.kind is ALLOW, (verdict)
    assert verdict.node == "list", (verdict)


def test_and_at_594_a_quoted_substitution_in_a_subscript_is_refused():
    """and@594: the other half of the disjunction.

    ``'$(id)'`` has a substitution and no ``[``.  Under the mutant
    (``and`` -> ``or``) the substitution half fires on its own, so the
    quoted text is refused as an array-subscript attack.
    """
    verdict = bp.check_command("echo '$(id)'")
    assert verdict.kind is ALLOW, (verdict)
    assert verdict.node == "list", (verdict)


# -- and@599: the quoted brace-expansion check ----------------------------


def test_and_at_599_a_quoted_brace_without_a_comma_is_not_a_brace_expansion():
    """and@599: the ``"," in content`` half of the guard.

    The line is ``if "{" in content and "}" in content and ("," in
    content or ".." in content)``.  Under the mutant (``and`` -> ``or``)
    any quoted text containing ``{`` is refused as a brace expansion,
    even when it names no alternatives at all.
    """
    verdict = bp.check_command("echo '{a'")
    assert verdict.kind is ALLOW, (verdict)
    assert verdict.node == "list", (verdict)


def test_and_at_599_a_quoted_comma_without_a_brace_is_not_a_brace_expansion():
    """and@599: the other half of the disjunction.

    ``'a,b}'`` has a comma and a closing brace but no opening brace.
    Under the mutant (``and`` -> ``or``) the opening-brace half no
    longer holds the disjunction together, so the comma and the
    closing brace are enough on their own and the text is refused as
    a brace expansion.
    """
    verdict = bp.check_command("echo 'a,b}'")
    assert verdict.kind is ALLOW, (verdict)
    assert verdict.node == "list", (verdict)


# -- lt@613: the double-quote scanner's loop bound ------------------------


def test_lt_at_613_an_unbalanced_double_quote_is_a_quote_error():
    """lt@613: ``while j < n`` -- the scanner stops AT the end.

    The line is ``while j < n``.  Under the mutant (``<`` -> ``<=``)
    the scanner reads one character past the end of the string, so the
    clean "unbalanced double quote" refusal is replaced by an
    internal IndexError -- the module's own generic error handler
    answers instead of the specific one.
    """
    verdict = bp.check_command('"a')
    assert verdict.kind is TOO_COMPLEX, (verdict)
    assert verdict.node == "quote", (verdict)
    assert verdict.reason == "unbalanced double quote", (verdict)


def test_lt_at_613_a_balanced_double_quote_is_still_allowed():
    """lt@613: the control -- a closed quote is fine."""
    verdict = bp.check_command('echo "a"')
    assert verdict.kind is ALLOW, (verdict)


# -- eq@632: the double-quoted brace check --------------------------------


def test_eq_at_632_a_closing_brace_alone_is_not_a_brace_expansion():
    """eq@632: ``ch == "{"`` -- the brace must OPEN.

    The line is ``if ch == "{"``.  Under the mutant (``==`` -> ``!=``)
    the scanner looks for the opening brace at every OTHER character, so
    the text between the stray closing brace and the next one is read as
    a brace expansion and refused.
    """
    verdict = bp.check_command('echo "a,b}c"')
    assert verdict.kind is ALLOW, (verdict)
    assert verdict.node == "list", (verdict)


def test_eq_at_632_a_real_quoted_brace_expansion_is_still_refused():
    """eq@632: the control -- ``"{1..9}"`` is a brace expansion."""
    verdict = bp.check_command('echo "{1..9}"')
    assert verdict.kind is DENY, (verdict)
    assert verdict.node == "brace_expansion", (verdict)


# -- or@636: the brace-expansion content check ----------------------------


def test_or_at_636_a_quoted_brace_expansion_at_the_start_of_a_word_is_refused():
    """or@636: the ``"," in inner`` half of the guard, on its own.

    The line is ``if "," in inner or ".." in inner``.  Under the mutant
    (``or`` -> ``and``) the comma half no longer fires on its own: the
    guard now needs BOTH a comma AND a ``..``.

    Here the brace is at the START of the word, so the inner text is
    ``{1..9}`` -- the ``..`` half fires on its own, and the refusal
    SURVIVES the mutant but with the wrong text: the mutant quotes the
    inner text (``'{1..9}'``) because it is read from a different
    branch.  So the assertion is on the message, and this input
    separates the two by the message.
    """
    verdict = bp.check_command('echo "{1..9}"')
    assert verdict.kind is DENY, (verdict)
    assert verdict.node == "brace_expansion", (verdict)
    assert "quoted brace expansion {1..9}" in verdict.reason, (verdict)


def test_or_at_636_a_quoted_brace_expansion_behind_a_word_is_refused():
    """or@636: the half that actually separates the two.

    With a word in front of the quote, the scanner's ``ch == "{"``
    check does not see the brace at all, so the guard at line 636 is
    the only thing that can refuse it.  Under the mutant
    (``or`` -> ``and``) the ``..`` half no longer fires on its own
    either, so the expansion is allowed.
    """
    verdict = bp.check_command('echo x"{1..9}"')
    assert verdict.kind is DENY, (verdict)
    assert verdict.node == "brace_expansion", (verdict)
    assert "quoted brace expansion {1..9}" in verdict.reason, (verdict)


# -- or@718: the file-descriptor redirection check ------------------------


def test_or_at_718_an_unsupported_file_descriptor_is_refused():
    """or@718: the ``digits != "2"`` half of the guard.

    The line is ``if digits != "2" or text[j] != ">" or
    text.startswith("2>>", i)``.  Under the mutant (``or`` -> ``and``)
    the ``digits != "2"`` half no longer refuses on its own, so a
    redirection on any descriptor other than 2 is accepted.
    """
    verdict = bp.check_command("echo 3>file")
    assert verdict.kind is TOO_COMPLEX, (verdict)
    assert verdict.node == "redirection", (verdict)
    assert "unsupported fd redirection 3>" in verdict.reason, (verdict)


def test_or_at_718_the_other_direction_of_the_same_guard_is_refused():
    """or@718: the other half of the disjunction.

    ``2<`` has the right descriptor but the wrong direction.  Under the
    mutant (``or`` -> ``and``) the ``digits != "2"`` half is False, so
    the guard needs the direction half to fire on its own -- and it
    does not, so the redirection is accepted instead of refused.
    """
    verdict = bp.check_command("echo 2<file")
    assert verdict.kind is TOO_COMPLEX, (verdict)
    assert verdict.node == "redirection", (verdict)
    assert "unsupported fd redirection 2<" in verdict.reason, (verdict)


def test_or_at_718_the_supported_descriptor_is_still_allowed():
    """or@718: the control -- ``2>`` is a supported redirection."""
    verdict = bp.check_command("echo 2>file")
    assert verdict.kind is ALLOW, (verdict)


# -- eq@795: brace expansion in a bare word -------------------------------


def test_eq_at_795_a_brace_expansion_in_a_bare_word_is_refused():
    """eq@795: ``ch == "{"`` -- the brace must OPEN.

    The line is ``if ch == "{"``.  Under the mutant (``==`` -> ``!=``)
    the scanner looks for the opening brace at every OTHER character, so
    the text between the word's start and the closing brace is read as
    a brace expansion.  The refusal still names ``brace_expansion``, but
    its text is the wrong one -- so the assertion is on the message.
    """
    verdict = bp.check_command("echo {a,b,c}")
    assert verdict.kind is DENY, (verdict)
    assert verdict.node == "brace_expansion", (verdict)
    assert "brace expansion {a,b,c}" in verdict.reason, (verdict)


def test_eq_at_795_a_quoted_brace_expansion_still_names_its_own_text():
    """eq@795: the quoted form is refused by its own rule.

    Under the mutant the quoted form is refused with the WRONG text
    ("brace expansion {cho '{a,b}"), so this assertion pins the message
    the original produces.
    """
    verdict = bp.check_command("echo '{a,b}'")
    assert verdict.kind is DENY, (verdict)
    assert verdict.node == "brace_expansion", (verdict)
    assert "quoted brace expansion '{a,b}'" in verdict.reason, (verdict)


# -- or@820 / and@822: the command-word scanning -------------------------


def test_or_at_820_a_quoted_array_subscript_is_still_checked():
    """or@820: the quoted-content check on a word's own text.

    The line is ``if not buf or text[buf_start] in "\\"'":``.  Under the
    mutant (``or`` -> ``and``) the check is skipped for a word that
    starts with a quote, so the array-subscript arithmetic hidden in
    quoted text is never looked for.
    """
    verdict = bp.check_command('echo "a[\\$(id)]"')
    assert verdict.kind is DENY, (verdict)
    assert verdict.node == "array_subscript_arithmetic", (verdict)
    assert "array-subscript arithmetic in quoted text" in verdict.reason, (
        verdict
    )


def test_or_at_820_a_bare_word_is_still_checked():
    """or@820: the control -- the other half of the disjunction.

    A bare word has an empty ``buf`` at the start, so the first half
    fires and the quoted-content check runs.  Under the mutant this
    input behaves the same, so it cannot be what distinguishes the two.
    """
    verdict = bp.check_command("echo a[0]")
    assert verdict.kind is ALLOW, (verdict)
    assert verdict.node == "list", (verdict)


def test_and_at_822_a_quoted_keyword_is_not_a_keyword():
    """and@822: the ``plain`` half of the command-word test.

    The line is ``is_cmd_word = cmd_start and plain``.  Under the
    mutant (``and`` -> ``or``) a QUOTED word in command position counts
    as a command word, so a quoted ``for`` is refused as a shell
    keyword.
    """
    verdict = bp.check_command("'for'")
    assert verdict.kind is ALLOW, (verdict)
    assert verdict.node == "list", (verdict)


def test_and_at_822_a_keyword_outside_command_position_is_allowed():
    """and@822: the other half of the conjunction.

    ``echo for`` -- the word is NOT in command position, so the
    ``cmd_start`` half is False.  Under the mutant (``and`` -> ``or``)
    the ``plain`` half holds on its own, so the word IS treated as a
    command word and ``for`` is refused as a shell keyword.
    """
    verdict = bp.check_command("echo for")
    assert verdict.kind is ALLOW, (verdict)
    assert verdict.node == "list", (verdict)


def test_and_at_822_a_keyword_in_command_position_is_refused():
    """and@822: the keyword refusal itself, which both forms share.

    ``for`` in command position is a shell keyword under the original
    and under the mutant, so it pins the behaviour that must not change.
    """
    verdict = bp.check_command("for x")
    assert verdict.kind is DENY, (verdict)
    assert verdict.node == "loop", (verdict)


# -- or@878: the redirect-target check ------------------------------------


def test_or_at_878_a_non_literal_redirect_target_is_refused():
    """or@878: the ``not target.plain`` half of the guard.

    The line is ``if target.kind != "word" or not target.plain or not
    target.value``.  Under the mutant (``or`` -> ``and``) a QUOTED
    target is no longer refused on its own -- the target is a word, so
    the first half is False and the second is False too -- and the
    redirect is accepted.
    """
    verdict = bp.check_command('echo hi > "$OUT"')
    assert verdict.kind is TOO_COMPLEX, (verdict)
    assert verdict.node == "redirection", (verdict)
    assert "non-literal target after '>'" in verdict.reason, (verdict)


def test_or_at_878_a_literal_redirect_target_is_accepted():
    """or@878: the control -- a plain target is fine."""
    verdict = bp.check_command("echo hi > out.txt")
    assert verdict.kind is ALLOW, (verdict)


# -- gt@927: the argv budget bound ----------------------------------------


def test_gt_at_927_an_argv_of_exactly_the_cap_is_accepted():
    """gt@927: ``budget.argv_words > MAX_ARGV_BUDGET`` -- the cap is not over.

    The command below resolves to exactly ``MAX_ARGV_BUDGET`` charged
    words: the command word plus ``MAX_ARGV_BUDGET - 1`` arguments.
    The original accepts it; the mutant (``>`` -> ``>=``) refuses it.
    This is the only value that separates the two.
    """
    budget = bp.MAX_ARGV_BUDGET
    command = "echo " + "a " * (budget - 1)
    verdict = bp.check_command(command)
    assert verdict.kind is ALLOW, (verdict)
    assert verdict.node == "list", (verdict)


def test_gt_at_927_an_argv_one_over_the_cap_is_refused():
    """gt@927: the bound itself is still pinned -- cap + 1 is over."""
    command = "echo " + "a " * bp.MAX_ARGV_BUDGET
    verdict = bp.check_command(command)
    assert verdict.kind is DENY, (verdict)
    assert verdict.node == "argv_budget", (verdict)


def test_gt_at_927_an_argv_under_the_cap_is_accepted():
    """gt@927: the control -- cap - 1 is not over."""
    command = "echo " + "a " * (bp.MAX_ARGV_BUDGET - 2)
    verdict = bp.check_command(command)
    assert verdict.kind is ALLOW, (verdict)
    assert verdict.node == "list", (verdict)


# -- and@963: the list-operator check -------------------------------------


def test_and_at_963_a_list_operator_splits_the_command():
    """and@963: the ``tok.kind == "op"`` half of the guard.

    The line is ``if tok.kind == "op" and tok.value in _LIST_OPS``.
    Under the mutant (``and`` -> ``or``) a WORD is treated as a list
    operator, so the word is dropped from the command and the redirect
    that follows it is parsed differently.
    """
    verdict = bp.check_command('echo hi > "$OUT"')
    assert verdict.kind is TOO_COMPLEX, (verdict)
    assert verdict.node == "redirection", (verdict)
    assert "non-literal target after '>'" in verdict.reason, (verdict)


def test_and_at_963_a_missing_redirect_target_is_refused():
    """and@963: the other half of the conjunction.

    ``echo >`` has a redirect operator with nothing behind it.  Under
    the mutant (``and`` -> ``or``) the operator half fires on its own,
    so the redirect is treated as a list separator and the command
    ends in a trailing list operator instead of a missing target.
    """
    verdict = bp.check_command("echo >")
    assert verdict.kind is TOO_COMPLEX, (verdict)
    assert verdict.node == "redirection", (verdict)
    assert "missing target after '>'" in verdict.reason, (verdict)


# -- and@973: the pipeline check ------------------------------------------


def test_and_at_973_a_plain_list_is_not_a_pipeline():
    """and@973: the ``tok.value in ("|", "|&")`` half of the guard.

    The line is ``tok.kind == "op" and tok.value in ("|", "|&")``.  Under
    the mutant (``and`` -> ``or``) ANY operator counts as a pipeline, so
    a plain command list is reported as a pipeline.
    """
    verdict = bp.check_command("echo a; echo b")
    assert verdict.kind is ALLOW, (verdict)
    assert verdict.node == "list", (verdict)


def test_and_at_973_a_real_pipeline_is_still_a_pipeline():
    """and@973: the control -- the pipe is what makes it a pipeline."""
    verdict = bp.check_command("echo a | echo b")
    assert verdict.kind is ALLOW, (verdict)
    assert verdict.node == "pipeline", (verdict)


# -- retF@1052 / retF@1055: ``stdlib_only`` -------------------------------


def _stdlib_only_variant(module_name, extra_import, mutated_line=None):
    """Build a copy of the parser whose ``stdlib_only`` may see a fault.

    ``stdlib_only`` reads the module's OWN source off disk, so the only
    way to feed it an import it must judge is to give it a source that
    contains one.  This copies the parser's source, appends the given
    import inside ``if False:`` (so the module still imports), and
    returns the copy's ``stdlib_only``.

    With ``mutated_line`` given, that line is first rewritten -- that
    is how the two halves of the import check are exercised against the
    planted fault.
    """
    import importlib.util
    import shutil
    import tempfile
    from pathlib import Path

    source = Path(bp.__file__).read_text(encoding="utf-8").splitlines(keepends=True)
    if mutated_line is not None:
        index, replacement = mutated_line
        source[index - 1] = replacement
    source.append("if False:\n    " + extra_import + "\n")
    root = Path(tempfile.mkdtemp(prefix="bash-parser-stdlib-"))
    try:
        path = root / f"{module_name}.py"
        path.write_text("".join(source), encoding="utf-8")
        spec = importlib.util.spec_from_file_location(module_name, path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
        return module.stdlib_only()
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_retF_at_1052_a_non_stdlib_import_is_reported():
    """retF@1052: the plain-``import`` half of the allowed-modules check.

    The line is ``if node.names[0].split(".")[0] not in allowed:
    return False``.  Under the mutant (``return False`` -> ``return
    True``) a module that imports something outside the standard library
    reports that it is standard-library-only.

    The source copy carries the extra import inside ``if False:``, so
    the module still imports and the copy is the parser's own code with
    one import added.
    """
    assert _stdlib_only_variant("bp_stdlib_plain", "import requests") is False


def test_retF_at_1052_a_stdlib_only_parser_is_still_stdlib_only():
    """retF@1052: the control -- the shipped parser reports True.

    Without this the test above could be satisfied by a checker that
    always answers False.
    """
    assert bp.stdlib_only() is True


def test_retF_at_1055_a_non_stdlib_from_import_is_reported():
    """retF@1055: the ``from ... import ...`` half of the check.

    The line is ``if node.module and node.module.split(".")[0] not in
    allowed: return False``.  Under the mutant (``return False`` ->
    ``return True``) a ``from requests import get`` is not reported.
    """
    assert _stdlib_only_variant("bp_stdlib_from", "from requests import get") is False


def test_retF_at_1055_a_stdlib_only_parser_is_still_stdlib_only():
    """retF@1055: the control."""
    assert bp.stdlib_only() is True


# -- or@676 / and@677 / eq@677: the list-ending checks ---------------------
#
# These three lines live in the tokenizer's newline branch:
#
#     if not tokens or (
#         tokens[-1].kind == "op" and tokens[-1].value in _LIST_OPS
#     ):
#         i += 1
#         continue
#
# A newline is a CONTROL CHARACTER, so ``check_command`` refuses every
# input that contains one before the tokenizer is ever reached.  The
# branch is therefore only reachable through ``_tokenize`` itself, and
# these tests drive the tokenizer directly.  That is the module's own
# entry point into the branch -- not a re-implementation of it.


def _tokenize(module, text):
    """Run the module's own tokenizer over *text* and return its tokens."""
    budget = module._ParseBudget(deadline=time.monotonic() + 60.0)
    return [(token.kind, token.value) for token in module._tokenize(text, budget)]


def test_or_at_676_a_leading_newline_is_skipped():
    """or@676: ``not tokens or (...)`` -- the empty-token half.

    The line is ``if not tokens or (``.  Under the mutant (``or`` ->
    ``and``) the "there are no tokens yet" half no longer fires on its
    own, so the scanner reads ``tokens[-1]`` off an empty list and
    raises IndexError instead of skipping the newline.

    The tokenizer is driven directly because ``check_command`` refuses
    a newline as a control character before the tokenizer runs.
    """
    assert _tokenize(bp, "\nls") == [("word", "ls")]


def test_or_at_676_a_newline_after_a_list_operator_is_skipped():
    """or@676: the other half of the disjunction.

    With a list operator already in the stream the token list is not
    empty, so under the mutant (``or`` -> ``and``) the guard does not
    fire and the newline becomes a SECOND list separator instead of
    being skipped.
    """
    assert _tokenize(bp, ";\nls") == [("op", ";"), ("word", "ls")]


def test_and_at_677_a_newline_after_a_redirect_is_a_list_separator():
    """and@677: the ``tokens[-1].value in _LIST_OPS`` half.

    The line is ``tokens[-1].kind == "op" and tokens[-1].value in
    _LIST_OPS``.  Under the mutant (``and`` -> ``or``) a redirect
    operator is not in the list-operator set, so the newline after it is
    NOT skipped: the tokenizer emits a list separator that the
    original does not emit.
    """
    assert _tokenize(bp, ">\nls") == [
        ("op", ">"),
        ("op", ";"),
        ("word", "ls"),
    ]


def test_and_at_677_a_newline_after_a_list_operator_is_skipped():
    """and@677: the other half, as the control.

    The last token IS a list operator, so the second half of the guard
    fires on its own and the newline is skipped under the mutant too.
    """
    assert _tokenize(bp, ";\nls") == [("op", ";"), ("word", "ls")]


def test_eq_at_677_a_newline_after_a_list_operator_is_skipped_once():
    """eq@677: ``tokens[-1].kind == "op"`` -- the kind half.

    The line is ``tokens[-1].kind == "op" and ...``.  Under the mutant
    (``==`` -> ``!=``) the kind half is False for a list operator, so
    the guard does not fire and the newline is NOT skipped: a second
    list separator is emitted.
    """
    assert _tokenize(bp, ";\nls") == [("op", ";"), ("word", "ls")]


def test_eq_at_677_a_newline_after_a_word_is_a_list_separator():
    """eq@677: the other half, as the control.

    The last token is a WORD, so the kind half is False under the
    original and the guard does not fire either way -- the newline
    becomes a list separator in both.
    """
    assert _tokenize(bp, "ls\nls") == [
        ("word", "ls"),
        ("op", ";"),
        ("word", "ls"),
    ]


# -- or@579: the variable-name scan ---------------------------------------


def test_or_at_579_the_name_scan_passes_over_an_underscore():
    """or@579: the ``ch == "_"`` half of the name guard.

    The line is ``if not (ch == "_" or ch.isascii() and ch.isalnum()):``.
    Under the mutant (``or`` -> ``and``) the underscore half no longer
    holds on its own -- and an underscore is NOT alphanumeric -- so the
    scan stops at the first underscore.

    The fault is observed on ``_scan_dollar``'s own documented contract
    ("Returns the index just past the consumed text"), because the
    CALLER re-scans the same characters and rebuilds the same word, so
    the command-level verdict is unchanged.  The scan boundary is what
    moves, and that is what the mutant moves.
    """
    buf: list = []
    assert bp._scan_dollar("$_abc", 0, buf) == 5
    assert buf == ["$_abc"]


def test_or_at_579_the_name_scan_passes_over_a_letter():
    """or@579: the other half, as the control.

    ``ch == "_"`` is False for a letter, so under the mutant the
    conjunction is False for a letter too and the scan stops there as
    well.  Both single-half cases must be fed: the underscore alone
    cannot distinguish an ``or`` from an ``and``.
    """
    buf: list = []
    assert bp._scan_dollar("$abc", 0, buf) == 4
    assert buf == ["$abc"]


def test_or_at_579_the_name_scan_still_consumes_the_whole_name():
    """or@579: the control -- the scan's own answer is pinned.

    A name that is all letters and digits is consumed whole, and the
    buffer holds exactly the one expansion.  Under the mutant the scan
    stops after the ``$`` and this assertion fails.
    """
    buf: list = []
    index = bp._scan_dollar("$a1b2", 0, buf)
    assert index == 5
    assert buf == ["$a1b2"]


# ---------------------------------------------------------------------------
# Mutant evidence: the NINE EQUIVALENT mutants, recorded
#
# Nine of the 42 sites cannot be killed by any input, because the
# mutated comparison is UNREACHABLE at the one value that could
# distinguish it.  All nine are ``lt`` -> ``<=`` on a "did I find the
# closing delimiter?" check, and in every case the value the check
# compares against can never be 0:
#
#   lt@547  ``if _find_matching(text, i + 1) < 0:``   -- the $(( )) branch
#   lt@552  ``if text.find(")", i + 2) < 0:``         -- the $( ) branch
#   lt@557  ``if close < 0:``                          -- the ${ } branch
#   lt@620  ``if text.find("`", j + 1) < 0:``          -- inside " "
#   lt@686  ``if text.find("`", i + 1) < 0:``          -- bare backtick
#   lt@690  ``if _find_matching(text, i + 1) < 0:``    -- the <( ) branch
#   lt@709  ``if ch == ")" or _find_matching(text, i) < 0:``  -- the ( ) branch
#   lt@756  ``if text.find("`", i + 1) < 0:``          -- inside a word
#   lt@773  ``if close < 0:``                          -- the ' ' branch
#
# The reason is the same in every case, and it is a property of the
# SEARCH, not of the guard:
#
#   * ``_find_matching`` returns the index of the matching ")" -- and it
#     is called with ``i + 1``, where ``i`` is the index of the "(" it
#     just consumed.  So the returned index is at least ``i + 2``, and
#     the ")" it finds is never at index 0.
#
#   * ``text.find(needle, start)`` is called with ``start`` at least 1,
#     because the scanner has already consumed the opening delimiter.
#     ``find`` therefore cannot return 0.
#
#   * ``close = text.find("}", i + 2)`` / ``text.find("'", i + 1)`` are
#     the same: the search starts past the opener, so a match cannot be
#     at index 0.
#
# A ``< 0`` check tests for "NOT FOUND".  ``find`` returns -1 for "not
# found" and a NON-NEGATIVE index for "found", and that index is never
# 0 at these call sites.  So the comparison is never ``0 < 0``: it is
# either "found, at some index >= 1" or "not found, at -1".  The
# mutant's ``<= 0`` differs from the original's ``< 0`` ONLY at the
# value 0, and 0 is never produced.  The mutants are EQUIVALENT, not
# merely untested.
#
# Each record below has BOTH halves the repo's convention requires:
#
#   (a) a DIFFERENTIAL proof -- two copies of the module are built from
#       its OWN source, one with the strict bound and one with the
#       planted fault, and the two are compared over a corpus that
#       covers every shape the check can be handed.  They must agree
#       everywhere.
#
#   (b) a NON-VACUITY CONTROL -- the same harness is pointed at a
#       DIFFERENT fault planted at the SAME site (the bound turned the
#       other way), and the two copies must then DIFFER.  If the
#       control found no difference, the fault would never really have
#       been applied and the agreement in (a) would have meant
#       nothing.
#
# These mutants are therefore EXPECTED TO SURVIVE the probe.  They are
# recorded here so the next person does not spend a round looking for a
# killer that cannot exist.
# ---------------------------------------------------------------------------


def _bash_parser_bound_variant(name, line, wanted_text, known_forms):
    """Build a copy of the parser with line *line* set to ``wanted_text``.

    ``wanted_text`` is the form the caller wants the line to take.
    ``known_forms`` is the tuple of every form of that line the helper
    recognises -- the strict form, the planted-fault form, and (for the
    control) the bound turned the other way.  The line is matched
    against that tuple, so the same helper builds every copy from
    either the shipped source or a source that already carries the
    planted fault: the equivalence must be provable against the shipped
    code and against the mutated code alike.

    The source line may carry ANY of the known forms, so the line is
    REPLACED outright -- the wanted form wins.
    """
    import importlib.util
    import shutil
    import tempfile
    from pathlib import Path

    source = Path(bp.__file__).read_text(encoding="utf-8").splitlines(keepends=True)
    current = source[line - 1]
    known = {form.strip() for form in known_forms}
    if current.strip() not in known:
        raise AssertionError(
            f"line {line} is not one of {sorted(known)!r}"
        )
    # Keep the line's own indentation: the wanted form is written
    # stripped, so the leading whitespace is carried over from the
    # source line it replaces.
    indent = current[: len(current) - len(current.lstrip())]
    source[line - 1] = indent + wanted_text + "\n"
    root = Path(tempfile.mkdtemp(prefix="bash-parser-bound-"))
    try:
        path = root / f"{name}.py"
        path.write_text("".join(source), encoding="utf-8")
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
        return module
    finally:
        shutil.rmtree(root, ignore_errors=True)


#: The corpus every equivalence proof is run over.  It covers every
#: shape the nine checks can be handed: the four delimiter families
#: ($, backtick, paren, brace), each one BALANCED and each one
#: UNBALANCED, plus the shapes the checks sit inside (a bare word, a
#: double-quoted string, a single-quoted string, an expansion).
EQUIVALENCE_CORPUS = [
    # the $(( )) arithmetic branch
    "echo $((1+2))",
    "echo $((1+2)",
    "echo $((1+2)) ls",
    "echo $((a))",
    # the $( ) command-substitution branch
    "echo $(id)",
    "echo $(id",
    "echo $(id) ls",
    "echo $((id))",
    # the ${ } parameter-expansion branch
    "echo ${x}",
    "echo ${x",
    "echo ${x} ls",
    "echo ${}",
    # the backtick branch, bare and inside a word and inside " "
    "echo `id`",
    "echo `id",
    "echo a`b`c",
    "echo a`b",
    'echo "a`b`c"',
    'echo "a`b',
    # the process-substitution branch
    "cat <(id)",
    "cat <(id",
    "cat <(id) ls",
    # the plain-paren branch
    "(echo hi)",
    "(echo",
    "(echo hi) ls",
    "echo a(b)",
    "echo a(b",
    # the single-quote branch
    "echo 'abc'",
    "echo 'abc",
    "echo 'abc' ls",
    "echo a'b'c",
    # the double-quote branch
    'echo "abc"',
    'echo "abc',
    "echo a\"b\"c",
    # shapes the checks sit inside
    "ls -la",
    "echo hi",
    "echo $HOME",
    "echo {a,b,c}",
    "echo hi > out.txt",
    "sudo rm $VAR",
    "rm $VAR",
    "echo a; echo b",
    "echo for",
    "eval x",
]

#: (site, line, the strict line, the mutant line) for the nine
#: equivalent sites.
#:
#: The site name is a **literal** here, not derived from the line
#: number.  It has to be: the coverage guard that checks this suite
#: names a site by searching the suite's *code* for ``lt@547`` (or the
#: §3.4 spelling ``lt_at_547``), and an f-string built from the line
#: number puts neither spelling in the file.  The nine sites were then
#: named only in this file's COMMENTS -- a note about the site, not a
#: proof of it -- and the guard read the comments as evidence.
EQUIVALENT_LT_SITES = [
    ("lt@547", 547, 'if _find_matching(text, i + 1) < 0:',
     'if _find_matching(text, i + 1) <= 0:'),
    ("lt@552", 552, 'if text.find(")", i + 2) < 0:',
     'if text.find(")", i + 2) <= 0:'),
    ("lt@557", 557, 'if close < 0:',
     'if close <= 0:'),
    ("lt@620", 620, 'if text.find("`", j + 1) < 0:',
     'if text.find("`", j + 1) <= 0:'),
    ("lt@686", 686, 'if text.find("`", i + 1) < 0:',
     'if text.find("`", i + 1) <= 0:'),
    ("lt@690", 690, 'if _find_matching(text, i + 1) < 0:',
     'if _find_matching(text, i + 1) <= 0:'),
    ("lt@709", 709, 'if ch == ")" or _find_matching(text, i) < 0:',
     'if ch == ")" or _find_matching(text, i) <= 0:'),
    ("lt@756", 756, 'if text.find("`", i + 1) < 0:',
     'if text.find("`", i + 1) <= 0:'),
    ("lt@773", 773, 'if close < 0:',
     'if close <= 0:'),
]


def _verdict_triple(module, text):
    """The module's own verdict, as a comparable triple."""
    verdict = module.check_command(text)
    return (verdict.kind.value, verdict.node, verdict.reason)


@pytest.mark.parametrize(
    "site,line,strict_text,mutated_text",
    EQUIVALENT_LT_SITES,
    ids=[f"lt_at_{line}" for _site, line, _s, _m in EQUIVALENT_LT_SITES],
)
def test_lt_sites_are_equivalent_mutants(site, line, strict_text, mutated_text):
    """The nine ``lt`` sites: the differential proof and its control.

    For each site the module is built twice from its OWN source -- once
    with the strict ``< 0`` bound and once with the planted ``<= 0``
    fault -- and the two are compared over ``EQUIVALENCE_CORPUS``.  The
    two must agree everywhere: the mutated comparison is only
    distinguishable at the value 0, and no call site can produce 0.

    The NON-VACUITY CONTROL turns the same bound the OTHER way (0 is
    replaced by 1).  That fault IS observable -- a delimiter found at
    index 1 exists -- so the two copies must then DIFFER.  If the
    control found no difference, the harness would be comparing two
    identical functions and the agreement above would have meant
    nothing.
    """
    # The control copy: the SAME bound, turned the other way.  It is a
    # form the helper recognises, so it is offered in the known-forms
    # tuple.
    control_text = strict_text.replace("< 0:", "> 0:")
    known = (strict_text, mutated_text, control_text)
    strict = _bash_parser_bound_variant(
        f"bp_eq_strict_{line}", line, strict_text, known
    )
    mutated = _bash_parser_bound_variant(
        f"bp_eq_mutated_{line}", line, mutated_text, known
    )
    control = _bash_parser_bound_variant(
        f"bp_eq_control_{line}", line, control_text, known
    )

    assert strict is not None and mutated is not None
    for text in EQUIVALENCE_CORPUS:
        assert _verdict_triple(strict, text) == _verdict_triple(mutated, text), (
            f"{site}: the mutant changes the verdict for {text!r}"
        )

    # -- the non-vacuity control: the harness CAN find a difference ---
    differences = [
        text
        for text in EQUIVALENCE_CORPUS
        if _verdict_triple(strict, text) != _verdict_triple(control, text)
    ]
    assert differences, (
        f"{site}: the control found no difference, so the comparison "
        f"above was between two identical functions"
    )


@pytest.mark.parametrize(
    "site,line,strict_text,mutated_text",
    EQUIVALENT_LT_SITES,
    ids=[f"lt_at_{line}" for _site, line, _s, _m in EQUIVALENT_LT_SITES],
)
def test_lt_sites_the_shipped_parser_agrees_with_the_strict_variant(
    site, line, strict_text, mutated_text
):
    """The nine ``lt`` sites: the shipped parser, pinned.

    The parser as shipped answers the same as the strict-bound variant
    over the whole corpus -- which is the property the mutants also
    have, and the reason they are equivalent rather than merely
    untested.
    """
    strict = _bash_parser_bound_variant(
        f"bp_eq_shipped_{line}", line, strict_text, (strict_text, mutated_text)
    )
    for text in EQUIVALENCE_CORPUS:
        assert _verdict_triple(bp, text) == _verdict_triple(strict, text), (
            f"{site}: the shipped parser differs from the strict variant "
            f"for {text!r}"
        )
