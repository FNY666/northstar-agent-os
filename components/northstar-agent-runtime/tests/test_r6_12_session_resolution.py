"""r6-12 session-resolution conformance: the referee must read the RIGHT session.

This is a READ-ONLY test. It writes nothing into the repository, changes no
outside file, and re-takes no baseline.

Why it exists
--------------
``b173-accept.sh`` used to resolve a slice's session JSONL with::

    JSONL=$(grep -rl "$CANARY" <project dir>/*.jsonl 2>/dev/null | head -n1)

``grep -rl`` returns files in *directory read order*, not in any stable key,
and every session that READS a taskbook carries every canary in its
transcript. One such "poison" session dominated the lookup, so the
``REPORT_NUMBERS`` check was cross-checked against the wrong session for
most of the batch.

The fix replaces the lookup with a call to ``b173-resolve-session.py``, whose
rule is: a session belongs to slice S iff

  (1) its FIRST user message **declares** S's canary (the literal
      ``CANARY: <token>``), not merely mentions it, AND
  (2) its first record timestamp is at/after the slice's LAST watch start,
      minus a 5 second tolerance.

These tests assert the resolver's *behaviour* (never the text of its
source), plus two guards that keep the fix applied and keep the referee's
verdict semantics intact.

Outside-repo dependencies (the coordinator's artefacts). When they are absent
-- a clean clone -- the affected methods ``skipTest`` instead of failing:

    /home/muse-newapi/b173-resolve-session.py
    /home/muse-newapi/b173-accept.sh
    /home/muse-newapi/b173-watch.sh
    /home/muse-newapi/.claude/projects/-home-muse-newapi-northstar-agent-os/

Everything that needs only in-repo facts (the design doc) always runs.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

COMPONENT = Path(__file__).resolve().parents[1]
REPO_ROOT = COMPONENT.parents[1]
DESIGN_DOC = REPO_ROOT / "docs" / "design" / "r6-12-session-resolution.md"

HOME = Path("/home/muse-newapi")
RESOLVER = HOME / "b173-resolve-session.py"
ACCEPT = HOME / "b173-accept.sh"
WATCH = HOME / "b173-watch.sh"
PROJECT = HOME / ".claude" / "projects" / "-home-muse-newapi-northstar-agent-os"

CANARY_RE = re.compile(r"CANARY:\s*([A-Za-z0-9]{20})")


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def _write_session(path: Path, first_user_text: str, ts: str,
                   body_texts=()) -> None:
    """Write a minimal session JSONL.

    The first record is a ``user`` record whose content carries
    ``first_user_text``; later records are assistant records that carry
    ``body_texts`` (used to put canaries into a session's *body*).
    """
    lines = []
    lines.append(json.dumps({
        "type": "user",
        "timestamp": ts,
        "message": {"role": "user",
                    "content": [{"type": "text", "text": first_user_text}]},
    }))
    for i, body in enumerate(body_texts):
        lines.append(json.dumps({
            "type": "assistant",
            "timestamp": ts,
            "message": {"role": "assistant",
                        "content": [{"type": "text", "text": body}],
                        "model": "claude-fable-5-2",
                        "usage": {"input_tokens": 1000 + i,
                                  "output_tokens": 10}},
        }))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _write_watch_log(slug: str, ts: str) -> None:
    (HOME / ("b173-%s-watch.log" % slug)).write_text(
        "%s [%s] watch started (report_timeout=20m commit_timeout=360m "
        "canary=X)\n" % (ts, slug), encoding="utf-8")


def _run_resolver(args, resolver: Path = None):
    """Run the resolver. ``--slug`` is always given; the caller adds the rest."""
    cmd = [sys.executable, str(resolver or RESOLVER)] + list(args)
    proc = subprocess.run(cmd, capture_output=True, text=True)
    return proc.returncode, proc.stdout.strip()


def _resolver_available() -> bool:
    return RESOLVER.is_file()


def _make_taskbook(tmp: Path, slug: str, canary: str) -> Path:
    """Write a taskbook the resolver will read for its canary.

    The resolver derives its HOME from its OWN location, so the synthetic
    fixtures are laid out next to a COPY of the resolver inside the temp
    dir. That keeps the test hermetic: it never writes to the coordinator's
    home directory and leaves no residue anywhere.
    """
    tb = tmp / ("b173-%s-cc-prompt-rerun.md" % slug)
    tb.write_text("CANARY: %s\n" % canary, encoding="utf-8")
    return tb


class _SyntheticResolverCase(unittest.TestCase):
    """Base: a private copy of the resolver with private fixtures."""

    def setUp(self):
        if not _resolver_available():
            self.skipTest("b173-resolve-session.py not present: %s" % RESOLVER)
        self.tmp = Path(tempfile.mkdtemp(prefix="b173-r612-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.resolver = self.tmp / "b173-resolve-session.py"
        shutil.copy2(RESOLVER, self.resolver)
        self.project = self.tmp / "project"
        self.project.mkdir()
        self.canary = "AbCdEfGhIjKlMnOpQrSt"

    def _taskbook(self, slug: str, canary: str = None) -> Path:
        return _make_taskbook(self.tmp, slug, canary or self.canary)

    def _watch_log(self, slug: str, ts: str) -> None:
        (self.tmp / ("b173-%s-watch.log" % slug)).write_text(
            "%s [%s] watch started (report_timeout=20m commit_timeout=360m "
            "canary=X)\n" % (ts, slug), encoding="utf-8")

    def _run(self, args):
        return _run_resolver(args, self.resolver)


class R612ResolverBehaviour(_SyntheticResolverCase):
    """(a)-(d): the resolver's selection rule, on synthetic sessions."""

    def test_a_mention_is_not_a_declaration(self):
        """(a) a session that MENTIONS the canary is not selected.

        The poison session reads the taskbooks, so its body carries every
        canary -- but its first user message declares only its own.
        """
        slug = "mentiononly"
        self._taskbook(slug)
        self._watch_log(slug, "2026-11-13T10:00:00Z")
        # declares a DIFFERENT canary, mentions ours in the body
        _write_session(self.project / "aaa-mention.jsonl",
                       "CANARY: ZzYyXxWwVvUuTtSsRrQq", "2026-11-13T10:00:01Z",
                       body_texts=["taskbook says CANARY: " + self.canary])
        # the real one
        _write_session(self.project / "bbb-declare.jsonl",
                       "CANARY: " + self.canary, "2026-11-13T10:00:02Z")
        rc, out = self._run(["--slug", slug, "--project", str(self.project)])
        self.assertEqual(rc, 0, out)
        self.assertTrue(out.endswith("bbb-declare.jsonl"), out)
        self.assertNotIn("aaa-mention.jsonl", out)

    def test_b_session_predating_the_watch_start_is_excluded(self):
        """(b) a session that predates the last watch start is excluded."""
        slug = "toosoon"
        self._taskbook(slug)
        self._watch_log(slug, "2026-11-13T12:00:00Z")
        _write_session(self.project / "old.jsonl",
                       "CANARY: " + self.canary, "2026-11-13T09:00:00Z")
        _write_session(self.project / "new.jsonl",
                       "CANARY: " + self.canary, "2026-11-13T12:00:01Z")
        rc, out = self._run(["--slug", slug, "--project", str(self.project)])
        self.assertEqual(rc, 0, out)
        self.assertTrue(out.endswith("new.jsonl"), out)

    def test_c_ambiguity_is_reported_not_guessed(self):
        """(c) two candidates -> AMBIGUOUS by default, --latest takes the later."""
        slug = "twosessions"
        self._taskbook(slug)
        self._watch_log(slug, "2026-11-13T10:00:00Z")
        _write_session(self.project / "early.jsonl",
                       "CANARY: " + self.canary, "2026-11-13T10:00:01Z")
        _write_session(self.project / "late.jsonl",
                       "CANARY: " + self.canary, "2026-11-13T11:00:00Z")
        rc, out = self._run(["--slug", slug, "--project", str(self.project)])
        self.assertEqual(rc, 1, out)
        self.assertTrue(out.startswith("AMBIGUOUS"), out)
        self.assertIn("early.jsonl", out)
        self.assertIn("late.jsonl", out)
        rc, out = self._run(["--slug", slug, "--project", str(self.project),
                              "--latest"])
        self.assertEqual(rc, 0, out)
        self.assertTrue(out.endswith("late.jsonl"), out)

    def test_d_no_candidate_prints_none_and_exits_nonzero(self):
        """(d) no candidate -> NONE, non-zero exit."""
        slug = "nosession"
        self._taskbook(slug)
        self._watch_log(slug, "2026-11-13T10:00:00Z")
        _write_session(self.project / "other.jsonl",
                       "CANARY: SomethingElseEntirely1", "2026-11-13T10:00:01Z")
        rc, out = self._run(["--slug", slug, "--project", str(self.project)])
        self.assertEqual(rc, 1, out)
        self.assertEqual(out, "NONE", out)


class R612PoisonRegression(_SyntheticResolverCase):
    """(e)-(f): the poison session must not win."""

    def test_f_poison_session_is_not_selected_for_other_canaries(self):
        """(f) THE poison regression: many canaries in the body, one declared."""
        slug = "poisonregression"
        other = "ZyXwVuTsRqPoNmLkJiHg"
        self._taskbook(slug, other)
        self._watch_log(slug, "2026-11-13T10:00:00Z")
        # the poison: declares one canary, carries MANY in its body
        _write_session(self.project / "poison.jsonl",
                       "CANARY: " + self.canary, "2026-11-13T10:00:01Z",
                       body_texts=["saw CANARY: " + other,
                                   "saw CANARY: " + other,
                                   "saw CANARY: " + other])
        # the honest session for `slug`
        _write_session(self.project / "honest.jsonl",
                       "CANARY: " + other, "2026-11-13T10:00:02Z")
        rc, out = self._run(["--slug", slug, "--project", str(self.project)])
        self.assertEqual(rc, 0, out)
        self.assertTrue(out.endswith("honest.jsonl"), out)
        self.assertNotIn("poison.jsonl", out)

    def test_e_resolver_picks_the_session_the_report_names(self):
        """(e) for refusal-row and judge-hygiene the resolver picks the file
        the slice's own report names."""
        if not _resolver_available():
            self.skipTest("b173-resolve-session.py not present: %s" % RESOLVER)
        if not PROJECT.is_dir():
            self.skipTest("session project dir absent: %s" % PROJECT)
        for slug in ("refusal-row", "judge-hygiene"):
            with self.subTest(slug=slug):
                tb = HOME / ("b173-%s-cc-prompt-rerun.md" % slug)
                report = HOME / ("b173-%s-cc-final.txt" % slug)
                if not tb.is_file() or not report.is_file():
                    self.skipTest("taskbook/report absent for %s" % slug)
                text = report.read_text(encoding="utf-8", errors="replace")
                found = re.findall(
                    r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-"
                    r"[0-9a-f]{12})", text)
                self.assertTrue(found, "no session uuid named in %s" % report)
                rc, out = _run_resolver(["--slug", slug])
                self.assertEqual(rc, 0, out)
                picked = os.path.basename(out)
                if picked.endswith(".jsonl"):
                    picked = picked[:-len(".jsonl")]
                self.assertIn(picked, found,
                              "resolver picked %s, report names %s"
                              % (picked, found))


class R612RefereeGuard(unittest.TestCase):
    """(g)-(h): the fix stays applied and the verdict semantics are intact."""

    def test_g_no_arbitrary_recursive_grep_session_lookup_remains(self):
        """(g) b173-accept.sh no longer resolves the session by a recursive
        grep over the project directory piped into head.

        Until the coordinator applies the patch this is still open, so the
        test reports the state instead of failing outright -- but it never
        lets a RECURSION over the whole project directory back in.
        """
        if not ACCEPT.is_file():
            self.skipTest("b173-accept.sh not present: %s" % ACCEPT)
        text = ACCEPT.read_text(encoding="utf-8", errors="replace")
        m = re.search(r"# --- REPORT_NUMBERS.*?\nfi\n", text, re.DOTALL)
        self.assertIsNotNone(m, "REPORT_NUMBERS block not found")
        block = m.group(0)
        if "b173-resolve-session.py" not in block:
            self.skipTest(
                "the coordinator has not applied the r6-12 patch to "
                "b173-accept.sh yet: the block still uses the old lookup")
        self.assertNotRegex(
            block,
            r"grep\s+-r[^\n]*\.jsonl",
            "REPORT_NUMBERS still resolves the session by a recursive grep "
            "over the project directory")

    def test_h_check_helper_and_exit_semantics_unchanged(self):
        """(h) check() still emits PASS/FAIL/SKIP + name + detail, and the
        script still ends with ACCEPT: PASS / ACCEPT: FAIL and the same exit
        code semantics."""
        if not ACCEPT.is_file():
            self.skipTest("b173-accept.sh not present: %s" % ACCEPT)
        text = ACCEPT.read_text(encoding="utf-8", errors="replace")
        for pat in (r"PASS\) PASS=\$\(\(PASS\+1\)\); echo \"PASS \$name \$detail\"",
                    r"FAIL\) FAIL=\$\(\(FAIL\+1\)\); echo \"FAIL \$name \$detail\"",
                    r"\*\)\s+SKIP=\$\(\(SKIP\+1\)\); echo \"SKIP \$name \$detail\""):
            self.assertRegex(text, pat)
        self.assertRegex(text, r"TOTAL=\$\(\(PASS\+FAIL\)\)")
        self.assertRegex(text, r"echo \"ACCEPT: PASS \(\$PASS/\$TOTAL")
        self.assertRegex(text, r"echo \"ACCEPT: FAIL \(\$PASS/\$TOTAL")
        self.assertRegex(text, r"exit 0;")
        self.assertRegex(text, r"exit 1;")

    def test_watch_script_also_lost_the_arbitrary_lookup(self):
        """the watch script's stub builder must use the resolver too."""
        if not WATCH.is_file():
            self.skipTest("b173-watch.sh not present: %s" % WATCH)
        text = WATCH.read_text(encoding="utf-8", errors="replace")
        if "b173-resolve-session.py" not in text:
            self.skipTest(
                "the coordinator has not applied the r6-12 watch patch yet")
        self.assertNotRegex(
            text,
            r"grep\s+-r[^\n]*\.jsonl",
            "b173-watch.sh still resolves the session by a recursive grep "
            "over the project directory")

    def test_g2_a_patched_copy_of_the_referee_keeps_its_verdict_semantics(self):
        """(g2) the PATCH, applied to a copy, must not move any check other
        than REPORT_NUMBERS, and must keep the output format and the exit
        codes. This is checked on a COPY; the live referee is untouched."""
        patch = HOME / "b173-r6-12-session-resolution-fix.patch"
        if not patch.is_file():
            self.skipTest("patch not present: %s" % patch)
        if not ACCEPT.is_file():
            self.skipTest("b173-accept.sh not present: %s" % ACCEPT)
        live = ACCEPT.read_text(encoding="utf-8", errors="replace")
        if "b173-resolve-session.py" in live:
            self.skipTest("the coordinator has already applied the r6-12 "
                          "patch to b173-accept.sh")
        tmp = Path(tempfile.mkdtemp(prefix="b173-r612-patch-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        target = tmp / "b173-accept.sh"
        shutil.copy2(ACCEPT, target)
        with patch.open("rb") as fh:
            proc = subprocess.run(["patch", "-p1", "-d", str(tmp)],
                                  stdin=fh, capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0,
                         "patch does not apply: %s%s"
                         % (proc.stdout, proc.stderr))
        text = target.read_text(encoding="utf-8", errors="replace")
        self.assertNotRegex(text, r"grep\s+-r[^\n]*\.jsonl")
        self.assertIn("b173-resolve-session.py", text)
        # verdict semantics unchanged
        for pat in (r"PASS\) PASS=\$\(\(PASS\+1\)\); echo \"PASS \$name \$detail\"",
                    r"FAIL\) FAIL=\$\(\(FAIL\+1\)\); echo \"FAIL \$name \$detail\"",
                    r"\*\)\s+SKIP=\$\(\(SKIP\+1\)\); echo \"SKIP \$name \$detail\"",
                    r"TOTAL=\$\(\(PASS\+FAIL\)\)",
                    r"echo \"ACCEPT: PASS \(\$PASS/\$TOTAL",
                    r"echo \"ACCEPT: FAIL \(\$PASS/\$TOTAL"):
            self.assertRegex(text, pat)
        # the number of checks did not change: every check NAME is still there.
        # (The patch splits one SKIP branch of REPORT_NUMBERS into two
        # mutually exclusive branches -- same check name, same verdict set.)
        before = ACCEPT.read_text(encoding="utf-8", errors="replace")
        pat = re.compile(r"check ([A-Z_]+) (?:PASS|FAIL|SKIP)")
        pairs_before = sorted(set(pat.findall(before)))
        pairs_after = sorted(set(pat.findall(text)))
        self.assertEqual(pairs_before, pairs_after,
                         "the patch changed the set of check/verdict pairs")
        self.assertEqual(sorted(set(pairs_before)),
                         sorted(["COMMIT", "REPORT", "CANARY", "FABLE_VERIF",
                                 "FULL_SUITE", "BENCH", "NEW_TESTS",
                                 "WORKTREE_CLEAN", "TESTS_RAN", "BENCH_DIFF",
                                 "REPORT_NUMBERS", "MUTANT"]),
                         "the referee no longer runs the expected 12 checks")


class R612InRepoFacts(unittest.TestCase):
    """(i): facts that need nothing outside the repository."""

    def test_i_design_doc_exists_and_carries_the_before_after_table(self):
        self.assertTrue(DESIGN_DOC.is_file(),
                        "missing %s" % DESIGN_DOC)
        text = DESIGN_DOC.read_text(encoding="utf-8", errors="replace")
        self.assertIn("r6-12-session-resolution", text)
        self.assertRegex(text, r"(?i)before")
        self.assertRegex(text, r"(?i)after")
        self.assertIn("REPORT_NUMBERS", text)
        # the doc must name the resolver the fix calls
        self.assertIn("b173-resolve-session.py", text)

    def test_i2_design_doc_records_the_poison_session(self):
        self.assertTrue(DESIGN_DOC.is_file(), "missing %s" % DESIGN_DOC)
        text = DESIGN_DOC.read_text(encoding="utf-8", errors="replace")
        self.assertIn("3c2b6040-5c84-43e8-8bcf-4dea627d7135", text,
                      "the doc must name the poison session file")
        self.assertIn("259886", text,
                      "the doc must record the poison session's true peak")


if __name__ == "__main__":
    unittest.main()
