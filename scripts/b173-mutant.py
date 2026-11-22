#!/usr/bin/env python3
"""b173-mutant.py -- planted-fault probe: does the slice's test suite notice
a small semantic fault in the new module?
Usage: b173-mutant.py --file <abs path to module in worktree>
         --test-module <unittest module(s), e.g. test_retry_config,test_x>
         --workdir <abs path to component dir in worktree> [--tries N=3]
Method (from the mutation-testing literature: coverage is execution proof,
mutation score is verification proof; mutmut is not installed here, so this
is a 3-mutant probe, not a full mutation run):
  - Parse the module AST and collect mutable constructs in source order:
    ==, >, <, return True/False, and/or.
  - Try up to --tries of them. For each: replace the operator on that exact
    source line (AST guarantees the construct is real code, not a string or
    comment), verify the file still parses, write it, run the slice's new
    tests, record KILLED (tests failed) or SURVIVED (tests passed), restore.
  - Exit 0 if >=1 mutant killed (tests verify behavior).
  - Exit 1 if >=1 mutant applied and all survived (tests do not verify).
  - Exit 2 if no mutation could be applied or the test run could not execute.
"""
import argparse, ast, os, re, subprocess, sys

def collect_candidates(src):
    tree = ast.parse(src)
    cands = []  # (kind, lineno) in source order
    seen = set()
    def add(kind, lineno):
        key = (kind, lineno)
        if key not in seen:
            seen.add(key); cands.append(key)
    for node in ast.walk(tree):
        if isinstance(node, ast.Compare):
            for op in node.ops:
                if isinstance(op, ast.Eq): add("eq", node.lineno)
                elif isinstance(op, ast.Gt): add("gt", node.lineno)
                elif isinstance(op, ast.Lt): add("lt", node.lineno)
        elif isinstance(node, ast.Return) and isinstance(node.value, ast.Constant):
            if node.value.value is True: add("retT", node.lineno)
            elif node.value.value is False: add("retF", node.lineno)
        elif isinstance(node, ast.BoolOp):
            if isinstance(node.op, ast.And): add("and", node.lineno)
            elif isinstance(node.op, ast.Or): add("or", node.lineno)
    # ast.walk is breadth-first, not source order; sort by line, stable by kind order
    order = {"eq":0, "gt":1, "lt":2, "retT":3, "retF":4, "and":5, "or":6}
    cands.sort(key=lambda kc: (kc[1], order[kc[0]]))
    return cands

def mutate_line(line, kind):
    if kind == "eq":
        return line.replace("==", "!=", 1), "== -> !="
    if kind == "gt":
        return re.sub(r"(?<![->])>(?![=>])", ">=", line, count=1), "> -> >="
    if kind == "lt":
        return re.sub(r"(?<![-<])<(?![=<])", "<=", line, count=1), "< -> <="
    if kind == "retT":
        return line.replace("True", "False", 1), "return True -> return False"
    if kind == "retF":
        return line.replace("False", "True", 1), "return False -> return True"
    if kind == "and":
        return line.replace(" and ", " or ", 1), "and -> or"
    if kind == "or":
        return line.replace(" or ", " and ", 1), "or -> and"
    return line, "?"

def drop_cached_bytecode(path):
    """Remove the cached .pyc of ``path`` (if any).

    Python validates a .pyc against (source mtime in whole seconds, source
    byte size). A mutation probe rewrites the source with EQUAL-LENGTH
    replacements (e.g. " or " -> " and ") within the SAME second, so both
    halves of the key are unchanged and Python would REUSE the previous
    mutant's bytecode -- the probe would then report a KILLED that never
    happened. Removing the cache forces a fresh compile of the mutated
    source.
    """
    cache = os.path.join(os.path.dirname(os.path.abspath(path)), "__pycache__")
    stem = os.path.basename(path)
    if stem.endswith(".py"):
        stem = stem[:-3]
    if not os.path.isdir(cache):
        return
    for name in os.listdir(cache):
        if name.startswith(stem + ".") and name.endswith(".pyc"):
            try:
                os.unlink(os.path.join(cache, name))
            except OSError:
                pass

def run_tests(workdir, test_modules, timeout=180):
    """Run the given test modules as ONE suite.

    ``test_modules`` may be a single name or a list.  Several modules can
    be given because a module's real coverage is the UNION of the suites
    that reference it: ``agents.py`` is exercised by ``test_agents.py``
    (its own suite, 773 lines) AND by ``test_agent_handoff.py`` (601
    lines), and the second catches faults the first does not.

    THE RUNNER MATTERS, AND IT WAS WRONG
    ------------------------------------
    This used to run ``python -m unittest <module>``.  unittest's
    discovery collects only test METHODS inside TestCase classes.  The
    component's suite is mostly the other shape -- standalone module-level
    ``test_*`` FUNCTIONS:

        1,545 test files
          812 have ONLY standalone functions  (unittest sees 0 of them)
          730 have only TestCase classes
          815 files where unittest collects ZERO tests, holding 9,815
          test functions in total

    So for 815 of the suites the runner exited **5** ("NO TESTS RAN") and
    the probe read any non-zero exit as "the mutant was KILLED": every
    mutant in the module was reported killed by a suite that ran nothing.

    Measured 2026-11-22 on ``agents.py``, paired with
    ``test_agent_handoff.py``: ``killed 31/31``.  With the suite that
    unittest can actually see, ``test_agents.py``: ``killed 14/31``.

    pytest collects both shapes, and it is the runner CI uses, so the
    probe now runs pytest.

    "NO TESTS RAN" is ALSO not a kill, even under pytest: a collection
    error must not be reported as a caught mutant.  The probe therefore
    checks the output for a collected-test count and treats "collected
    nothing" as a SKIP.
    """
    env = dict(os.environ)
    env["PYTHONPATH"] = ".:tests"
    # Round 5: never write new .pyc files during a probe. This alone is NOT
    # enough -- it stops writing but not reading an existing stale one --
    # so drop_cached_bytecode() is called before every rewrite as well.
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    # The suite lives in ``tests/`` in the component, but a probe workdir
    # may hold it at the root.  Resolve whichever exists.
    paths = []
    for m in test_modules:
        candidate = os.path.join("tests", f"{m}.py")
        if not os.path.exists(os.path.join(workdir, candidate)):
            candidate = f"{m}.py"
        paths.append(candidate)
    try:
        r = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider",
             *paths],
            cwd=workdir, env=env, timeout=timeout,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        return r.returncode, r.stdout
    except subprocess.TimeoutExpired:
        return None, "TIMEOUT"


def collected_nothing(output):
    """True when the runner collected NO tests.

    A mutant cannot be caught by a suite that ran no tests, so this must
    never be reported as a kill.  pytest's own exit code for "no tests
    collected" is 5, the same code unittest uses, so the exit code alone
    does not distinguish "collection error" from "tests failed" -- the
    output does.

    The signals checked here, in the order pytest emits them:

      * "no tests ran"            -- pytest's wording
      * "error during collection" -- a suite that could not be imported
      * "collected 0 items"       -- an empty selection
    """
    lowered = output.lower()
    if "no tests ran" in lowered:
        return True
    if "error during collection" in lowered:
        return True
    if "collected 0 items" in lowered:
        return True
    return False

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", required=True)
    ap.add_argument(
        "--test-module", required=True,
        help="unittest module(s) to run; comma-separated for several. "
             "A module's real coverage is the UNION of the suites "
             "that reference it, so several may be given.",
    )
    ap.add_argument("--workdir", required=True)
    ap.add_argument("--tries", type=int, default=3)
    ap.add_argument("--no-early-stop", action="store_true",
                    help="try every candidate instead of stopping at the "
                         "first kill.  The judge-hygiene probe-behaviour "
                         "tests need to observe a KILLED and a SURVIVED "
                         "verdict to prove each round measures that round's "
                         "code, so they use this.")
    a = ap.parse_args()
    with open(a.file, encoding="utf-8") as f:
        orig = f.read()
    lines = orig.splitlines(keepends=True)
    cands = collect_candidates(orig)
    if not cands:
        print("MUTANT SKIP: no mutable construct found in module")
        return 2
    killed = 0; applied = 0; results = []
    # Crash-safe restore.  The probe writes a mutant into the file under
    # test, runs the suite, then restores the original.  If the process is
    # KILLED between the write and the restore -- a wall-clock timeout, a
    # SIGTERM from a batch runner, an OOM -- the file is left MUTATED.
    #
    # Measured 2026-11-22: a census run killed mid-flight left two
    # mutations behind in merged_tree_review.py
    # (`len(holders[word]) <= 2` and `left_module != right_module`).  The
    # next run then reported "killed 37/37" -- the two leftover mutants
    # broke four UNRELATED tests, so the suite failed for reasons that had
    # nothing to do with the mutant being measured.  A census that reads
    # "no survivors" off a contaminated tree is a FALSE KILL, the mirror
    # image of the stale-bytecode false kill.
    #
    # The restore is therefore registered three ways: as an atexit hook
    # (normal exit and unhandled exception), and as a SIGTERM/SIGINT
    # handler (a signal raises SystemExit, which atexit then sees).  The
    # handler re-raises with the default disposition so the process still
    # dies the way it was asked to.
    def restore_original():
        """Put the original source back, if the file is still mutated."""
        try:
            with open(a.file, encoding="utf-8") as f:
                current = f.read()
        except OSError:
            return
        if current == orig:
            return
        try:
            with open(a.file, "w", encoding="utf-8") as f:
                f.write(orig)
            drop_cached_bytecode(a.file)
        except OSError:
            pass

    import atexit
    import signal
    atexit.register(restore_original)

    def _on_signal(signum, _frame):
        restore_original()
        # Re-raise with the default disposition so the process dies the way
        # the signal asked it to, rather than exiting 0.
        signal.signal(signum, signal.SIG_DFL)
        os.kill(os.getpid(), signum)

    for _sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        try:
            signal.signal(_sig, _on_signal)
        except (ValueError, OSError, AttributeError):
            pass

    # Pre-flight: the file under test must be the one we read as the
    # original.  Re-reading it and comparing guards against the case where
    # another process rewrote it between our read and the first mutation.
    try:
        with open(a.file, encoding="utf-8") as f:
            if f.read() != orig:
                print("MUTANT SKIP: file under test changed since it was read")
                return 2
    except OSError:
        print("MUTANT SKIP: file under test could not be re-read")
        return 2
    for kind, lineno in cands[: a.tries]:
        idx = lineno - 1
        if idx < 0 or idx >= len(lines):
            continue
        new_line, desc = mutate_line(lines[idx], kind)
        if new_line == lines[idx]:
            continue
        trial = lines[:]; trial[idx] = new_line
        trial_src = "".join(trial)
        try:
            ast.parse(trial_src)
        except SyntaxError:
            results.append(f"MUTANT {kind}@{lineno} SKIP (parse fail after: {desc})")
            continue
        with open(a.file, "w", encoding="utf-8") as f:
            f.write(trial_src)
        # Round 5: drop the cached bytecode of the module under mutation so
        # the freshly written source is actually compiled and executed.
        drop_cached_bytecode(a.file)
        test_modules = [m.strip() for m in a.test_module.split(",")
                         if m.strip()]
        if not test_modules:
            print("MUTANT SKIP: no test module given")
            return 2
        rc, out = run_tests(a.workdir, test_modules)
        applied += 1
        if rc is None:
            results.append(f"MUTANT {kind}@{lineno} SKIP (test timeout: {desc})")
        elif collected_nothing(out):
            # A suite that collected NO tests cannot have caught anything.
            # Reporting this as KILLED is a false kill: it looks like
            # evidence where there is none.
            results.append(
                f"MUTANT {kind}@{lineno} SKIP (no tests collected: {desc})")
        elif rc != 0:
            killed += 1
            results.append(f"MUTANT {kind}@{lineno} KILLED ({desc})")
        else:
            results.append(f"MUTANT {kind}@{lineno} SURVIVED ({desc})")
        restore_original()
        # Print each verdict AS IT IS MEASURED. The old code collected the
        # results and printed them all at the end, so a run that hit the
        # wall clock produced NO output at all -- and "no output" and
        # "no mutants survived" look the same to whatever reads the file.
        print(results[-1], flush=True)
        # r7: the check's contract is ">=1 of up to N mutants killed".  Once
        # one is killed the verdict is settled, so stop here rather than
        # burning the rest of the budget on mutants nobody will look at.
        # (The old code always ran all --tries mutations, so raising --tries
        # from 3 to 12 would have made every probe 4x slower for nothing.)
        if killed >= 1 and not a.no_early_stop:
            # No extra output line: every line the probe prints is part of
            # the output contract that b173-accept.sh and the
            # judge-hygiene probe-format test depend on ("MUTANT <kind>@<n>
            # <VERDICT> (<desc>)" and "MUTANT RESULT: killed k/n").
            break
    if applied == 0:
        print("MUTANT SKIP: no mutation could be applied")
        return 2
    print(f"MUTANT RESULT: killed {killed}/{applied}")
    return 0 if killed >= 1 else 1

if __name__ == "__main__":
    sys.exit(main())
