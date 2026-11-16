"""RED test: the `capability-ceiling-probe` slice's promise, checked.

THE GAP (measured 2026-11-16)
-----------------------------
    $ bash b173-accept.sh capability-ceiling-probe
    FAIL COMMIT none
      commit: 9ea57f23b90ee6be410476b5db08b436f0a61bdb \
              B173 scorer-disagreement: disagreement detector over multi-scorer verdicts
    ACCEPT: FAIL (11/12, 0 skipped) capability-ceiling-probe

The slice's deliverable is in the branch -- a 695-line module, a 458-line
test file with 59 methods, and an 8.6 KB design doc -- but it was
committed under the subject

    B173 scorer-disagreement: disagreement detector over multi-scorer verdicts

so the referee, which attributes a slice by subject prefix, cannot see it.

The correctly-subjected twin still exists in the reflog:

    f85282fb  B173 capability-ceiling-probe: fail-first admission + ...
    9ea57f23  B173 scorer-disagreement: disagreement detector over ...

Both have the same parent (`0a2f3f42`) and the same author date.  The
reflog records `commit` -> `commit (amend)`: the commit was amended in
place and its subject was overwritten, so the slice lost its own name.

That is one fault.  Reading the slice's own deliverable turned up two
more, both of them the slice's own business:

    `runtime_registration.py:538` names **scorer-disagreement** as the
    slice that introduced `capability_ceiling_probe`.  The `slice_slug`
    field is documented as "the slice that introduced the module", and
    that is this slice.  The same mis-attribution as the commit subject,
    in the runtime registry itself.

    `UnknownProbeError` is declared at line 107 and **never raised**.
    A declared-and-never-raised refusal is a promise the module does not
    keep.

And one the slice's own taskbook flagged, which its rule-coverage
verifier was commissioned to check and which no commit fixed:

    "every new public function has a test naming it"

Measured, the slice's test file names **none** of these six public names:

    submit  CalibrationBucket  RoutingVerdict  Submission
    CapabilityCeilingProbeError  UnknownProbeError

WHAT THIS TEST PINS
--------------------
1. The registry names the slice that introduced the module.
2. Every public class, method and function is named by a test.
3. Every declared refusal is either raised, or documented as reserved.
4. The public surface has not shrunk unnoticed.
"""
from __future__ import annotations

import ast
import re
import unittest
from pathlib import Path

COMPONENT = Path(__file__).resolve().parents[1]
MODULE = COMPONENT / "capability_ceiling_probe.py"
TEST_FILE = COMPONENT / "tests" / "test_capability_ceiling_probe.py"
REGISTRY = COMPONENT / "runtime_registration.py"


def _public_surface(path: Path) -> list:
    """Every public class, method and function the module exposes."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    out = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if not node.name.startswith("_"):
                out.append(("function", node.name, node.lineno))
        elif isinstance(node, ast.ClassDef):
            out.append(("class", node.name, node.lineno))
            for member in node.body:
                if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if not member.name.startswith("_"):
                        out.append(
                            (
                                "method",
                                "%s.%s" % (node.name, member.name),
                                member.lineno,
                            )
                        )
    return out


def _declared_exceptions(src: str) -> list:
    """The exception classes the module declares.

    A class is an exception class when one of its bases is a name that
    ends in ``Error`` or ``Exception`` -- which covers both the module's
    own base class and the standard-library base.
    """
    tree = ast.parse(src)
    declared = []
    for node in tree.body:
        if not isinstance(node, ast.ClassDef):
            continue
        for base in node.bases:
            if isinstance(base, ast.Name) and base.id.endswith(("Error", "Exception")):
                declared.append(node.name)
                break
    return declared


class RegistryAttributionTests(unittest.TestCase):
    """The registry must name the slice that introduced the module."""

    def test_the_registry_names_this_slice(self):
        registry = REGISTRY.read_text(encoding="utf-8")
        m = re.search(
            r'_registration\(\s*"capability_ceiling_probe"\s*,\s*"([^"]+)"', registry
        )
        self.assertIsNotNone(
            m, "capability_ceiling_probe is not in the runtime registry"
        )
        self.assertEqual(
            "capability-ceiling-probe",
            m.group(1),
            "the registry names %r as the slice that introduced "
            "capability_ceiling_probe; it is the capability-ceiling-probe "
            "slice" % m.group(1),
        )


class PublicSurfaceCoverageTests(unittest.TestCase):
    """Every public name must be named by a test."""

    def test_every_public_name_is_named_by_a_test(self):
        """Every public class, method and function must be named.

        "Named by a test" means the name appears in the test file -- as
        the thing under test, as a type asserted on, or as a string the
        test checks for.  A public name that no test even mentions is a
        name the slice never exercised.
        """
        tests = TEST_FILE.read_text(encoding="utf-8")
        missing = []
        for kind, name, lineno in _public_surface(MODULE):
            if name == "main":
                # the module's own self-check; it is invoked by a test
                if "capability_ceiling_probe.main()" in tests:
                    continue
            base = name.split(".")[-1]
            if name in tests or base in tests:
                continue
            missing.append("%s %s (line %d)" % (kind, name, lineno))
        self.assertEqual(
            [],
            missing,
            "public surface with no test naming it:\n  " + "\n  ".join(missing),
        )

    def test_the_test_file_covers_the_whole_public_surface(self):
        """The count of public names must not shrink unnoticed."""
        surface = _public_surface(MODULE)
        self.assertGreaterEqual(
            len(surface),
            28,
            "the module's public surface shrank to %d names; the slice's "
            "test file was written against %d" % (len(surface), 28),
        )


class UnreachableErrorTests(unittest.TestCase):
    """A declared error that is never raised is a promise the module does
    not keep.  The test says so."""

    def test_every_declared_refusal_is_either_raised_or_documented(self):
        src = MODULE.read_text(encoding="utf-8")
        never_raised = []
        for name in _declared_exceptions(src):
            if ("raise %s" % name) not in src:
                never_raised.append(name)
        if not never_raised:
            return
        # A declared-but-unraised refusal must be documented as such.
        for name in never_raised:
            with self.subTest(error=name):
                self.assertRegex(
                    src,
                    r"(?s)%s.{0,400}?(?:never raised|not raised|reserved|"
                    r"unused|no path)" % re.escape(name),
                    "%s is declared but never raised, and the module does not "
                    "document it as reserved" % name,
                )


if __name__ == "__main__":
    unittest.main()
