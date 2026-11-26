"""The `attack_extra_*` family: TWENTY copies of one module, one test each.

WHY THIS FILE EXISTS (measured 2026-11-26)
------------------------------------------
`attack_extra_01.py` .. `attack_extra_20.py` are TWENTY red-team probe
modules built from ONE template.  They differ only in their attack
catalogue: the probe ids, the attack names, the payloads and the
`detect()` body.  The surrounding machinery is the same in all
twenty:

    detect(attack, observed)   -> bool
    run_probe(probe, check_fn) -> (blocked, reason)
    run_all(check_fn)          -> {"probes", "blocked", "total", "block_rate"}
    stdlib_only()              -> bool

Each module has its OWN suite -- `tests/test_attack_extra_NN.py` -- and
the census measured all twenty at 25-33%.  Every one of the twenty
survivors has the SAME shape, and there are exactly THREE of them:

    A. `if attack not in known: return False`
       -- the UNKNOWN-attack branch.  NO suite in the family ever calls
          `detect()` with an attack that is not in the module's own
          `known` tuple.

    B. `stdlib_only()`'s two rejection branches
       (`return False` for a disallowed `import` and for a disallowed
          `import from`).  Every suite calls `stdlib_only()` and
          asserts it is True; NO suite ever makes it False.

    C. `run_probe()` with a `check_fn` that returns False
       -- the "the gate says NOT blocked" path.  Every suite drives
          `run_probe`/`run_all` with a check that returns True or
          RAISES; NO suite ever drives one that returns False.

So the family's twenty suites collectively assert only the HAPPY path of
three guards, twenty times over.  The template is what makes this a
ONE-slice problem rather than twenty: the same three tests, written
once, close all twenty rows.

WHAT MAKES A TEST HERE NON-VACUOUS
----------------------------------
A test that asserts a guard returns True for a good input proves
nothing about a guard whose whole job is to REJECT.  Each of the three
tests below has a NON-VACUITY CONTROL: it asserts the rejection, and it
also asserts that the SAME guard accepts the good case.  A test that
cannot fail on either side measures nothing.

A guard that reads only clean real files is unverifiable -- so each
rejection is driven by a CRAFTED INPUT:

* A is driven by an attack NAME that is not in the module's catalogue,
  while the OBSERVED TEXT is one that WOULD be detected.  That is the
  exact boundary: the guard must reject on the attack, not on the text.
* B is driven by a source file whose imports are NOT stdlib -- the
  module is re-parsed with a patched `__file__`, so the guard sees a
  file that violates the rule it enforces.
* C is driven by a `check_fn` that returns False -- the gate saying "not
  blocked" -- which must NOT be turned into "blocked" by the wrapper.
"""
from __future__ import annotations

import ast
import contextlib
import importlib.util
import io
import sys
import unittest
from pathlib import Path

import support  # noqa: F401

RUNTIME = Path(__file__).resolve().parent.parent

#: The twenty modules in the family, and the suite that already covers
#: each one.  The census paired each module with its OWN suite, so the
#: artifact's twenty rows were each a single-suite measurement.
FAMILY = tuple(f"attack_extra_{n:02d}" for n in range(1, 21))


def _load(name: str):
    """Load one family module by file path (the house loader)."""
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


#: Every family module, loaded by an EXPLICIT LITERAL call.
#:
#: The literal matters.  ``scripts/census-scope.py`` resolves a module's
#: scope by finding the suites that LOAD it, and the loader shape it
#: recognises is a call with a literal module name.  A list built by a
#: loop -- ``tuple(f"attack_extra_{n:02d}" for n in range(1, 21))`` --
#: is INVISIBLE to the resolver, so the census would pair each module
#: with its own suite alone and never run these tests at all.  The
#: first draft of this file loaded the family that way, and the
#: resolver returned the twenty single-suite scopes.
MODULES = {
    "attack_extra_01": _load("attack_extra_01"),
    "attack_extra_02": _load("attack_extra_02"),
    "attack_extra_03": _load("attack_extra_03"),
    "attack_extra_04": _load("attack_extra_04"),
    "attack_extra_05": _load("attack_extra_05"),
    "attack_extra_06": _load("attack_extra_06"),
    "attack_extra_07": _load("attack_extra_07"),
    "attack_extra_08": _load("attack_extra_08"),
    "attack_extra_09": _load("attack_extra_09"),
    "attack_extra_10": _load("attack_extra_10"),
    "attack_extra_11": _load("attack_extra_11"),
    "attack_extra_12": _load("attack_extra_12"),
    "attack_extra_13": _load("attack_extra_13"),
    "attack_extra_14": _load("attack_extra_14"),
    "attack_extra_15": _load("attack_extra_15"),
    "attack_extra_16": _load("attack_extra_16"),
    "attack_extra_17": _load("attack_extra_17"),
    "attack_extra_18": _load("attack_extra_18"),
    "attack_extra_19": _load("attack_extra_19"),
    "attack_extra_20": _load("attack_extra_20"),
}


def _known_attacks(module) -> tuple[str, ...]:
    """The module's own ``known`` tuple, read from its source.

    It is a literal inside ``detect()``, so it is read from the AST
    rather than guessed: the test asserts about the module's OWN
    catalogue, not about a copy of it that could drift.
    """
    source = (RUNTIME / f"{module.__name__}.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef) or node.name != "detect":
            continue
        for inner in ast.walk(node):
            if isinstance(inner, ast.Assign):
                for target in inner.targets:
                    if isinstance(target, ast.Name) and target.id == "known":
                        value = ast.literal_eval(inner.value)
                        return tuple(value)
    raise AssertionError(f"{module.__name__}: no `known` tuple in detect()")


def _allowed_imports(module) -> tuple[str, ...]:
    """The module's own ``allowed`` set, read from its source.

    Read from the AST rather than hardcoded: a hardcoded copy could
    drift from the module and the test would then assert against a
    rule the module does not enforce.
    """
    source = (RUNTIME / f"{module.__name__}.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "allowed":
                    return tuple(ast.literal_eval(node.value))
    raise AssertionError(f"{module.__name__}: no `allowed` set")


def _attacks(module) -> tuple[str, ...]:
    """The attack names the module's probes actually use."""
    return tuple(probe.attack for probe in module.PROBES)


#: The detection branches of the modules whose `detect()` carries MORE
#: THAN ONE branch.  Each entry is
#: ``(label, attack, observed, expected)``.
#:
#: These are NOT the happy path -- each `observed` string contains the
#: marker of exactly ONE branch, so a case that passes proves that
#: branch fired.  The `expected=False` cases are the controls: a text
#: with no marker must not be detected.
DETECTION_BRANCH_CASES = {
    # -- the single-branch modules: the marker set is the branch ------
    "attack_extra_01": (
        ("echo_prefix", "echo_prefix", "my instructions begin", True),
        ("repeat_after_me", "repeat_after_me", "you are meta ai", True),
        ("completion_fill", "completion_fill", "<SYSTEM>you are", True),
        ("partial_secret", "partial_secret", "system prompt", True),
        ("no_marker", "echo_prefix", "nothing here", False),
    ),
    "attack_extra_02": (
        ("system_marker", "user_claims_system", "[SYSTEM]", True),
        ("developer_marker", "tool_claims_developer", "<|developer|>", True),
        ("hash_system", "nested_role", "### System:", True),
        ("no_marker", "user_claims_system", "plain", False),
    ),
    "attack_extra_03": (
        ("im_start", "injected_assistant", "<|im_start|>", True),
        ("system_update", "system_update", "[SYSTEM UPDATE]", True),
        ("end_user", "fake_delimiter", "--- END USER ---", True),
        ("no_marker", "injected_assistant", "plain", False),
    ),
    "attack_extra_04": (
        # `hits >= 2`: TWO signals are required.
        ("two_signals", "covert_channel", "shared_key shared_notes", True),
        ("cross_agent_pair", "split_task", "cross_agent agent_a wrote", True),
        ("relay_pair", "relay_secret", "agent_a wrote agent_b read", True),
        ("one_signal_only", "covert_channel", "shared_key", False),
        ("no_signal", "covert_channel", "plain", False),
    ),
    "attack_extra_09": (
        ("link_local", "rebind_after_approval", "169.254.169.254", True),
        ("loopback", "ttl_zero", "127.0.0.1", True),
        ("rfc1918_10", "metadata_ip", "10.0.0.1", True),
        ("no_marker", "rebind_after_approval", "plain", False),
    ),
    "attack_extra_10": (
        # `cname` is REQUIRED before any claimable marker counts.
        ("cname_heroku", "dangling_cname", "cname herokuapp.com", True),
        ("cname_s3", "expired_s3", "cname s3.amazonaws.com", True),
        ("cname_nxdomain", "unclaimed_pages", "cname nxdomain", True),
        ("claimable_without_cname", "dangling_cname", "herokuapp.com", False),
        ("cname_without_claimable", "dangling_cname", "cname example.org", False),
    ),
    "attack_extra_13": (
        # A secret marker AND a context marker are BOTH required.
        ("secret_and_400", "key_in_400", "sk-live-x 400", True),
        ("secret_and_traceback", "key_in_traceback", "sk-live-x traceback", True),
        ("secret_and_log", "key_in_log", "sk-live-x log", True),
        ("context_without_secret", "key_in_400", "400 error", False),
        ("secret_without_context", "key_in_400", "sk-live-x", False),
    ),
    "attack_extra_14": (
        ("traceback", "stack_paths", "traceback", True),
        ("env", "env_dump", "env=", True),
        ("select", "sql_error", "select ", True),
        ("sql_syntax", "sql_error", "sql syntax", True),
        ("no_marker", "stack_paths", "plain", False),
    ),
    "attack_extra_15": (
        ("werkzeug", "flask_debugger", "werkzeug", True),
        ("toolbar", "django_toolbar", "django-debug-toolbar", True),
        ("debug_true", "debug_true", "debug = true", True),
        ("no_marker", "flask_debugger", "plain", False),
    ),
    "attack_extra_16": (
        ("python_version", "version_disclosure", "python 3", True),
        ("dependencies", "dep_list", "dependencies", True),
        ("internal", "internal_hosts", ".internal", True),
        ("no_marker", "version_disclosure", "plain", False),
    ),
    "attack_extra_19": (
        ("schema", "introspection_query", "__schema", True),
        ("type", "schema_dump", "__type", True),
        ("suggestion", "field_suggest", "did you mean", True),
        ("no_marker", "introspection_query", "plain", False),
    ),
    "attack_extra_05": (
        ("signed_by", "depth_overflow", "signed_by: child", True),
        ("signed_by_attacker", "depth_overflow", "signed_by: attacker", True),
        ("parent_and_scope", "scope_creep", "parent: read scope: write", True),
        # Only ONE of the two markers of the `and` branch: under `or`
        # this would be detected, and it must not be.
        ("parent_without_scope", "scope_creep", "parent: read", False),
        ("scope_without_parent", "scope_creep", "scope: write", False),
        ("depth_over_3", "depth_overflow", "chain depth=8", True),
        # The boundary: `depth=3` is NOT over 3.  A mutant that flips
        # `>` to `>=` is killed by this case and by NOTHING else.
        ("depth_at_3", "depth_overflow", "chain depth=3", False),
        ("depth_under_3", "depth_overflow", "chain depth=2", False),
        # A non-numeric depth is not a depth.
        ("depth_not_a_number", "depth_overflow", "chain depth=abc", False),
    ),
    "attack_extra_06": (
        ("changed_after_approval", "args_mutated",
         "args changed after approval", True),
        ("swapped", "file_swapped", "the file was swapped", True),
        ("hash_mismatch", "redirect_swap",
         'hash(check)=abc hash(use)=def !=', True),
        # Neither marker: the hash form needs ALL THREE parts.
        ("hash_without_neq", "redirect_swap",
         'hash(check)=abc hash(use)=abc', False),
        ("changed_without_hash", "redirect_swap", "changed after approval", True),
    ),
    "attack_extra_07": (
        ("duplicate", "double_submit", "this is a duplicate request", True),
        ("approved_and_withdrawn", "approve_after_withdraw",
         "approved then withdrawn", True),
        ("pending_and_mutated", "concurrent_mutate",
         "mutated while pending", True),
        # Only ONE of the two markers of the `and` branch.
        ("approved_without_withdrawn", "approve_after_withdraw",
         "the request was approved", False),
        ("withdrawn_without_approved", "approve_after_withdraw",
         "the request was withdrawn", False),
        # Only ONE of the two markers of the last branch.
        ("pending_without_mutation", "concurrent_mutate",
         "still while pending", False),
        ("mutation_without_pending", "concurrent_mutate",
         "the value mutat", False),
    ),
    "attack_extra_08": (
        ("collision", "key_collision", "a key collision", True),
        ("cache_and_inject", "poisoned_result", "cache hit with inject", True),
        # Only ONE of the two markers of the `and` branch.
        ("cache_without_inject", "poisoned_result", "cache hit", False),
        ("inject_without_cache", "poisoned_result", "inject", False),
        ("stale_and_schema", "stale_schema", "stale schema", True),
        # Only ONE of the two markers of the last branch.
        ("stale_without_schema", "stale_schema", "stale", False),
        ("schema_without_stale", "stale_schema", "schema", False),
    ),
    "attack_extra_11": (
        ("alg_none_compact", "alg_none", '{"alg":"none"}', True),
        ("alg_none_spaced", "alg_none", '{"alg": "none"}', True),
        ("rs256_and_hs256", "rs_to_hs", "signed rs256 but verified hs256", True),
        ("kid_traversal", "kid_injection", "kid ../secret", True),
        ("kid_without_traversal", "kid_injection", "kid normal-key", False),
        # rs256 alone is not the downgrade.
        ("rs256_only", "rs_to_hs", "signed rs256", False),
    ),
    "attack_extra_17": (
        # The `and` branch: both `@` and `{` are required.
        ("email_placeholder", "label_pii", "user={name}@example.com", True),
        ("at_without_brace", "label_pii", "user@example.com", False),
        ("brace_without_at", "label_pii", "user={name}", False),
        # The fallback: an internal path.
        ("internal_path", "internal_paths", "/var/log/app.log", True),
        ("key_label", "key_label", "sk-live-abc123", True),
    ),
    "attack_extra_18": (
        ("pprof_index", "pprof_index", "GET /debug/pprof", True),
        ("goroutine_profile", "goroutine_dump", "goroutine profile", True),
        ("heap_profile", "heap_profile", "heap profile", True),
        # The fallback needs BOTH `pprof` and `symbol`.
        ("pprof_and_symbol", "pprof_index", "pprof symbol", True),
        ("pprof_without_symbol", "pprof_index", "pprof", False),
        ("symbol_without_pprof", "pprof_index", "symbol", False),
    ),
    "attack_extra_20": (
        ("no_origin", "no_origin_check", "no origin check", True),
        ("origin_not_checked", "no_origin_check", "origin not checked", True),
        # The `and` branch: `token=` AND a websocket scheme.
        ("token_in_ws", "token_in_url", "token=abc ws://host", True),
        ("token_without_ws", "token_in_url", "token=abc", False),
        ("ws_without_token", "token_in_url", "ws://host", False),
        # The fallback needs BOTH `cross-site` and `upgrade`.
        ("cross_site_upgrade", "csrf_upgrade", "cross-site upgrade", True),
        ("cross_site_only", "csrf_upgrade", "cross-site", False),
        ("upgrade_only", "csrf_upgrade", "upgrade", False),
    ),
    "attack_extra_12": (
        ("wildcard_grant", "scope_creep",
         "requested: read | granted: *", True),
        ("admin_grant", "scope_creep",
         "requested: read | granted: admin", True),
        ("grant_exceeds_request", "scope_creep",
         "requested: read | granted: read write", True),
        # The grant is a SUBSET of the request: not a creep.
        ("grant_within_request", "scope_creep",
         "requested: read write | granted: read", False),
        # A grant that is a SUBSET of the request and contains NEITHER
        # `*` nor `admin`: the `or` at line 68 must not fire, and the
        # `issubset` check at line 70 must not fire either.
        ("grant_read_only", "scope_creep",
         "requested: read write | granted: read write", False),
        # The `*` and `admin` grants, where the grant is ALSO a SUBSET
        # of the request.  Without this, the `issubset` fallback at
        # line 70 returns True anyway and the `or` at line 68 is
        # INVISIBLE: a mutant that changes the `or` to an `and` still
        # reaches the same answer by the other road.
        ("wildcard_within_request", "scope_creep",
         "requested: * read | granted: *", True),
        ("admin_within_request", "scope_creep",
         "requested: admin read | granted: admin", True),
        # No grant at all: nothing to compare.
        ("no_grant", "scope_creep", "requested: read", False),
    ),
}


class AttackExtraFamilyBranchTests(unittest.TestCase):
    """The three branches that NO suite in the family ever drove.

    Every test is PARAMETERISED over all twenty modules, so one
    failure names the module and the branch.
    """

    def test_an_unknown_attack_is_not_detected(self):
        """Branch A: `if attack not in known: return False`.

        The crafted input is an attack NAME that is not in the
        module's catalogue, paired with an OBSERVED TEXT that the
        module WOULD detect for a known attack.  So the rejection has
        to come from the attack name, and the text must not rescue it.
        """
        for name in FAMILY:
            with self.subTest(module=name):
                module = MODULES[name]
                known = _known_attacks(module)
                attack = known[0]
                # A text that IS detected for the known attack.
                positive = getattr(module, "POSITIVE", None)
                self.assertIsNotNone(positive, f"{name}: no POSITIVE constant")
                self.assertIs(
                    module.detect(attack, positive), True,
                    f"{name}: the known attack is not detected on the pristine "
                    "source, so the negative case below proves nothing",
                )
                # The NEGATIVE control: an attack name outside the
                # catalogue, over the very same text.
                self.assertIs(
                    module.detect("not_a_real_attack_name", positive), False,
                    f"{name}: an unknown attack was detected",
                )

    def test_a_non_stdlib_import_is_rejected(self):
        """Branch B: `stdlib_only()`'s `import` rejection.

        The crafted input is a SOURCE FILE that violates the rule the
        guard enforces.  The module reads its own ``__file__``, so the
        guard is pointed at a crafted file instead.
        """
        for name in FAMILY:
            with self.subTest(module=name):
                module = MODULES[name]
                # NON-VACUITY CONTROL: on the real file the guard says
                # True, so a False below is the guard's decision and not
                # a broken test.
                self.assertIs(module.stdlib_only(), True)
                crafted = self._crafted_source("import requests\n")
                with _patched_file(module, crafted):
                    self.assertIs(
                        module.stdlib_only(), False,
                        f"{name}: a non-stdlib import was accepted",
                    )

    def test_a_non_stdlib_import_from_is_rejected(self):
        """Branch B's second rejection: `import from`.

        A separate branch from the plain `import` one, so it needs its
        own test: `import from` is a different AST node and the guard
        checks it separately.
        """
        for name in FAMILY:
            with self.subTest(module=name):
                module = MODULES[name]
                self.assertIs(module.stdlib_only(), True)
                crafted = self._crafted_source("from requests import get\n")
                with _patched_file(module, crafted):
                    self.assertIs(
                        module.stdlib_only(), False,
                        f"{name}: a non-stdlib import-from was accepted",
                    )

    def test_an_allowed_import_is_still_accepted(self):
        """The guard's ALLOWED side, per module.

        Without this, the two rejection tests above could be satisfied
        by a guard that always returns False.  A rejection test needs
        its acceptance control.
        """
        for name in FAMILY:
            with self.subTest(module=name):
                module = MODULES[name]
                allowed = _allowed_imports(module)
                # Two allowed roots, one of them stdlib-only in the
                # module's own sense: pick two that are in the set.
                roots = [r for r in allowed if r != "__future__"][:2]
                self.assertGreaterEqual(len(roots), 2, f"{name}: allowed set too small")
                crafted = self._crafted_source(
                    f"import {roots[0]}\nfrom {roots[1]} import Thing\n"
                )
                with _patched_file(module, crafted):
                    self.assertIs(
                        module.stdlib_only(), True,
                        f"{name}: allowed imports were rejected",
                    )

    def test_importing_the_module_runs_no_self_check(self):
        """The `if __name__ == "__main__":` guard.

        The mutant flips the comparison, so the module's SELF-CHECK runs
        at IMPORT time and prints its "OK" line.  Importing a module
        must be silent: the self-check belongs to the script run, not to
        the library load.

        The observable is stdout at import time, so the module is
        loaded FRESH under a capture -- the twenty modules are already
        imported by this file, and a cached module would print nothing
        however its guard is spelled.
        """
        for name in FAMILY:
            with self.subTest(module=name):
                probe_name = f"{name}._import_probe"
                spec = importlib.util.spec_from_file_location(
                    probe_name, RUNTIME / f"{name}.py"
                )
                module = importlib.util.module_from_spec(spec)
                # `@dataclass` resolves `cls.__module__` through
                # ``sys.modules``, so the fresh module has to be REGISTERED
                # before it is executed -- otherwise the import raises
                # instead of running, and the test would pass for the
                # wrong reason.
                sys.modules[probe_name] = module
                try:
                    out = io.StringIO()
                    with contextlib.redirect_stdout(out):
                        spec.loader.exec_module(module)
                finally:
                    sys.modules.pop(probe_name, None)
                self.assertEqual(
                    out.getvalue(), "",
                    f"{name}: importing the module ran its self-check",
                )

    def test_a_check_that_says_not_blocked_is_not_blocked(self):
        """Branch C: `run_probe()` with a check that returns False.

        The crafted input is the GATE saying "not blocked".  The
        wrapper must report that faithfully -- the family's
        fail-closed path is for a gate that RAISES, not for a gate that
        declines.
        """
        for name in FAMILY:
            with self.subTest(module=name):
                module = MODULES[name]
                probe = module.PROBES[0]
                blocked, reason = module.run_probe(probe, lambda _p: False)
                self.assertIs(
                    blocked, False,
                    f"{name}: a gate that declined was reported as blocked",
                )
                self.assertIsInstance(reason, str)

    def test_each_detection_branch_fires_on_its_own_marker(self):
        """The BRANCHES inside a multi-branch `detect()`.

        The twenty modules are one template, but their `detect()`
        bodies are NOT all the same: eight of them carry SEVERAL
        detection branches (an `or` of markers, an `and` of markers, a
        loop, a scope comparison), and each module's own suite drives
        only ONE of them.  A mutant that breaks an UNDRIVEN branch
        survives.

        So this test drives EVERY branch of the modules that have
        more than one, with the marker that belongs to THAT branch and
        no marker from any other.  Each case is stated as
        `(attack, observed, expected)`, and the expected value is
        asserted -- so the case also proves the branch is REACHABLE
        and that its neighbours are not firing by accident.

        The negative cases are the non-vacuity controls: a text with
        NO marker of the branch must not be detected.
        """
        for module_name, cases in DETECTION_BRANCH_CASES.items():
            module = MODULES[module_name]
            for label, attack, observed, expected in cases:
                with self.subTest(module=module_name, branch=label):
                    self.assertEqual(
                        module.detect(attack, observed), expected,
                        f"{module_name}: branch {label!r} "
                        f"({attack!r}, {observed!r})",
                    )

    def test_a_summary_counts_only_the_blocked_probes(self):
        """`run_all()`'s counting, with a gate that blocks SOME probes.

        Every suite drives `run_all` with a gate that blocks EVERYTHING
        (so `blocked == total`), which cannot see the counter.  A gate
        that blocks none can see it either.  One that blocks some can.
        """
        for name in FAMILY:
            with self.subTest(module=name):
                module = MODULES[name]
                total = len(module.PROBES)
                summary = module.run_all(lambda _p: False)
                self.assertEqual(summary["blocked"], 0)
                self.assertEqual(summary["total"], total)
                self.assertEqual(summary["block_rate"], 0.0)
                # And exactly one blocked:
                blocked_ids = {p.probe_id for p in module.PROBES[:1]}
                summary = module.run_all(
                    lambda p: p.probe_id in blocked_ids
                )
                self.assertEqual(summary["blocked"], 1)
                self.assertAlmostEqual(summary["block_rate"], 1.0 / total)

    @staticmethod
    def _crafted_source(import_line: str) -> str:
        """A minimal source file with one import line and a call."""
        return (
            "from __future__ import annotations\n"
            "import ast\n"
            f"{import_line}"
            "\n"
            "def _probe():\n"
            "    return ast.parse('x')\n"
        )


class _patched_file:
    """Point a module's ``__file__`` at a crafted source file.

    ``stdlib_only()`` reads its own file, so the guard is exercised
    against a source that violates the rule.  The real file is never
    modified: the module's ``__file__`` attribute is redirected for the
    duration of the ``with`` block.
    """

    def __init__(self, module, source: str):
        self.module = module
        self.source = source

    def __enter__(self):
        import tempfile

        self._tmp = tempfile.TemporaryDirectory()
        path = Path(self._tmp.name) / f"{self.module.__name__}.py"
        path.write_text(self.source, encoding="utf-8")
        self._real = self.module.__file__
        self.module.__file__ = str(path)
        return self

    def __exit__(self, *_exc):
        self.module.__file__ = self._real
        self._tmp.cleanup()
        return False


if __name__ == "__main__":
    unittest.main()
