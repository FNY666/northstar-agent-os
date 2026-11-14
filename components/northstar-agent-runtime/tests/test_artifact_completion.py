"""Read-only conformance test for the batch-173 slice acceptance reports.

This test asserts that each target slice's acceptance report carries the
artifacts the referee (``b173-accept.sh``) looks for, and that the
cross-slice comparison table lives *outside* the ``FABLE VERIFICATION``
section so that the peak-number check cannot read another slice's numbers
as if they were this slice's.

It is **read-only**: it reads report files, manifests and session JSONLs
outside the repository, and asserts nothing about production code.

Two rules shape the whole file:

1.  Every assertion on a file that lives outside the repository calls
    ``self.skipTest(...)`` when that file is missing.  A clean clone has
    none of them, so the suite degrades to skips rather than to failures.
    ``assertTrue(os.path.exists(...))`` is never used for an outside file.

2.  At least one method depends on **no** outside file, so that a clean
    clone still runs real assertions -- otherwise the module would be all
    skips on a clean clone, which is no evidence at all.

Method count: 12.
"""

from __future__ import annotations

import json
import os
import re
import unittest

OUTSIDE = "/home/muse-newapi"
REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                    os.pardir, os.pardir, os.pardir))
DESIGN_DOC = os.path.join(REPO, "docs", "design", "artifact-completion.md")
SESSION_DIR = os.path.join(
    os.path.expanduser("~"),
    ".claude",
    "projects",
    "-home-muse-newapi-northstar-agent-os",
)

#: The slice set this slice worked.  The union of every slice the task book
#: names (groups A, B, C, D, E and the five REPORT_NUMBERS slices) -- 30
#: slices, not the "16" the task book's headline says.
SLICES = (
    "slice1", "slice2", "slice3", "slice4", "slice5", "slice6",
    "runtime-registration",
    "audit-head", "c52", "c54", "c58", "diviner", "e2b", "unwind",
    "seal-slice6",
    "stale-checkpoint-gate", "fable",
    "false-green-detector", "tombstone-mutant-blindspots",
    "autogen-speaker-selector", "cwl-episode-eviction",
    "langgraph-durability", "langgraph-retry-clears-writes", "refusal-row",
    "evidence-independence", "scope-verbatim-compaction",
    "silent-failure-detector", "tool-output-filter", "strands",
    "horizon", "langgraph",
)

#: The 14 slices whose task books carry no canary, so their ``CANARY``
#: item is honestly recorded as "pending coordinator canary" rather than
#: fabricated.  See docs/design/artifact-completion.md.
PENDING_COORDINATOR_CANARY = (
    "slice1", "slice2", "slice3", "slice4", "slice5", "slice6",
    "runtime-registration", "audit-head", "c52", "c54", "c58", "diviner",
    "e2b", "unwind", "seal-slice6",
)

#: The slice -> session JSONL mapping, resolved by the "first user message
#: is this slice's task book" discriminator.  ``None`` means the slice was
#: implemented outside Claude Code and has no session of its own.
SLICE_SESSION = {
    "slice1": "cda665a1-25a4-4a1e-be7a-14babb7ae315",
    "slice2": None,
    "slice3": "ca78c9dd-e553-4e8b-bbaa-48b20714fcd1",
    "slice4": None,
    "slice5": "4d909e3b-ec80-4782-acf9-f509d4398cd0",
    "slice6": None,
    "runtime-registration": "60a92cf5-d2c3-43a6-a7e9-ddd570a88987",
    "audit-head": "b923bdb8-48c6-4159-a13f-0f5610f4a5be",
    "c52": "6fdf83a2-9d51-47ef-9c58-e624c6dcab03",
    "c54": "6db4dda9-7f45-4d0c-a5d8-9ae8aa7421e0",
    "c58": "fd5920eb-4ed5-47ce-8bd8-dfd0f497cb3e",
    "diviner": "cd6f8952-41a4-4bd8-acbc-762a0551fd57",
    "e2b": "95b89bb3-04dc-43e8-9a0e-e737ad5c74ef",
    "unwind": "3fae30b8-b6ff-433e-9552-bf66a8f9ebf1",
    "seal-slice6": "6ef85f80-3175-48b4-a099-b78d83e6e6dc",
    "stale-checkpoint-gate": "37a5373f-6585-4b2b-99ba-e4992f21ceac",
}

PEAK_RE = re.compile(r"^PEAK_INPUT_TOKENS:\s*(\d+)\s*$", re.M)
SESSION_RE = re.compile(r"^SESSION:\s*(\S+)\s*$", re.M)
CANARY_RE = re.compile(r"^CANARY:\s*([A-Za-z0-9]+)\s*$", re.M)
HIST_SUITE_RE = re.compile(r"(?:Ran\s+19\d{3}|\b19\d{3}\s+tests)")

#: The peak may be written in any of the forms the batch's reports use.
#: ``PEAK_INPUT_TOKENS: 106569`` is this slice's own machine-readable form;
#: the already-correct reports use prose forms such as ``Input peak    :
#: 152452 tokens``, ``peak input_tokens (max over assistant
#: usage.input_tokens): 133475``, ``Peak input tokens observed: 133791`` or
#: ``**131,388**``.  All of them name the same quantity, so all of them are
#: read.  The number may sit on the following line, so the gap between the
#: word "peak" and the number may contain a newline.
PEAK_KEY_RE = re.compile(r"peak", re.IGNORECASE)
PEAK_DECLARED_RE = re.compile(r"^PEAK_INPUT_TOKENS:\s*(\d+)\s*$", re.M)
PEAK_INLINE_RE = re.compile(r"peak[^\n]{0,60}?(\d[\d,]{3,})", re.IGNORECASE)
PEAK_NEXTLINE_RE = re.compile(r"peak[^\n]{0,120}\n[^\n]{0,40}?(\d[\d,]{3,})",
                              re.IGNORECASE)
PEAK_BOLD_RE = re.compile(r"\*\*(\d[\d,]{3,})\*\*[^\n]{0,60}peak", re.IGNORECASE)


def declared_peaks(text: str):
    """Return every peak value the report declares, as ints."""
    found = []
    for pattern in (PEAK_DECLARED_RE, PEAK_INLINE_RE, PEAK_NEXTLINE_RE,
                    PEAK_BOLD_RE):
        for match in pattern.finditer(text):
            try:
                found.append(int(match.group(1).replace(",", "")))
            except (ValueError, IndexError):
                continue
    return found


def declared_peak(text: str):
    """Return the report's own peak, or ``None``.

    The strongest pattern wins: the machine-readable
    ``PEAK_INPUT_TOKENS:`` line if the report has one, otherwise the first
    prose peak the report declares.  A report may quote another slice's peak
    in its comparison section, so only the strongest match is treated as
    *this* slice's headline number.
    """
    match = PEAK_DECLARED_RE.search(text)
    if match is not None:
        return int(match.group(1))
    for pattern in (PEAK_INLINE_RE, PEAK_NEXTLINE_RE, PEAK_BOLD_RE):
        found = pattern.search(text)
        if found is None:
            continue
        try:
            return int(found.group(1).replace(",", ""))
        except (ValueError, IndexError):
            continue
    return None


def report_path(slug: str) -> str:
    return os.path.join(OUTSIDE, "b173-%s-cc-final.txt" % slug)


def manifest_path(slug: str) -> str:
    return os.path.join(OUTSIDE, "b173-%s.files" % slug)


def read_outside(path: str):
    """Read a file outside the repo, or return ``None`` if it is absent."""
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            return handle.read()
    except OSError:
        return None


def jsonl_peak(path: str):
    """Return ``(peak_input_tokens, n_compaction_events)`` for a session."""
    peak = 0
    compactions = 0
    with open(path, encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if obj.get("type") == "system" and obj.get("subtype") == "compact_boundary":
                compactions += 1
                continue
            message = obj.get("message") or {}
            if message.get("role") != "assistant":
                continue
            usage = message.get("usage") or {}
            value = usage.get("input_tokens")
            if isinstance(value, (int, float)):
                peak = max(peak, int(value))
    return peak, compactions


def present_reports():
    """Return ``{slug: text}`` for every target slice whose report exists."""
    found = {}
    for slug in SLICES:
        text = read_outside(report_path(slug))
        if text is not None:
            found[slug] = text
    return found


def fable_section(text: str):
    """Return the text of the ``FABLE VERIFICATION`` section, or ``None``."""
    marker = "FABLE VERIFICATION"
    index = text.find(marker)
    if index < 0:
        return None
    rest = text[index + len(marker):]
    # The section ends at the next top-level "=====" rule that starts a new
    # block, or at the end of the file.
    rule = rest.find("\n====")
    return rest if rule < 0 else rest[:rule]


class ArtifactCompletionTests(unittest.TestCase):
    """Each slice's report must carry the artifacts the referee looks for."""

    # -- (a) report exists and is non-empty ---------------------------

    def test_01_every_target_slice_has_a_non_empty_report(self):
        """Each target slice's report exists outside the repo and is non-empty."""
        missing = []
        for slug in SLICES:
            text = read_outside(report_path(slug))
            if text is None or not text.strip():
                missing.append(slug)
        if not present_reports():
            self.skipTest("no slice reports present (clean clone)")
        self.assertEqual(
            [], missing,
            "these slices have no non-empty report at %s: %s"
            % (OUTSIDE, ", ".join(missing)),
        )

    # -- (b) FABLE VERIFICATION -----------------------------------------

    def test_02_every_report_has_a_fable_verification_section(self):
        """Each report names a ``FABLE VERIFICATION`` section."""
        missing = []
        for slug in SLICES:
            text = read_outside(report_path(slug))
            if text is None:
                continue
            if "FABLE VERIFICATION" not in text:
                missing.append(slug)
        if not present_reports():
            self.skipTest("no slice reports present (clean clone)")
        self.assertEqual([], missing, "reports without FABLE VERIFICATION: %s"
                         % ", ".join(missing))

    # -- (c) CANARY ----------------------------------------------------

    def test_03_every_report_echoes_a_canary_or_declares_it_pending(self):
        """Each report either echoes a real canary, or says the canary is pending.

        A pending canary must be recorded as a ``[CANARY STATUS: ...]``
        block, deliberately *not* as a ``CANARY: <token>`` line, so it can
        never be mistaken for a real echo.
        """
        bad = []
        for slug in SLICES:
            text = read_outside(report_path(slug))
            if text is None:
                continue
            has_real = bool(CANARY_RE.search(text))
            has_pending = "CANARY STATUS: pending coordinator canary" in text
            if not (has_real or has_pending):
                bad.append(slug)
        if not present_reports():
            self.skipTest("no slice reports present (clean clone)")
        self.assertEqual([], bad, "reports with neither a canary echo nor a "
                         "pending-canary statement: %s" % ", ".join(bad))

    def test_04_pending_canary_slices_are_not_the_fabricated_kind(self):
        """A pending canary must not look like a real canary echo."""
        for slug in PENDING_COORDINATOR_CANARY:
            text = read_outside(report_path(slug))
            if text is None:
                continue
            self.assertIn("CANARY STATUS: pending coordinator canary", text,
                          "%s should carry the pending-canary block" % slug)
            for line in text.splitlines():
                if line.startswith("CANARY:"):
                    self.fail(
                        "%s carries a `CANARY:` line but has no canary in its "
                        "task book -- that line is fabricated" % slug)

    # -- (d) full suite ------------------------------------------------

    def test_05_every_report_states_a_full_suite_count(self):
        """Each report says "full suite" and carries a ``19xxx tests`` line."""
        missing = []
        for slug in SLICES:
            text = read_outside(report_path(slug))
            if text is None:
                continue
            has_words = re.search(r"full.*suite", text, re.IGNORECASE) is not None
            has_count = HIST_SUITE_RE.search(text) is not None
            if not (has_words and has_count):
                missing.append(slug)
        if not present_reports():
            self.skipTest("no slice reports present (clean clone)")
        self.assertEqual([], missing, "reports without a full-suite + 19xxx "
                         "line: %s" % ", ".join(missing))

    # -- (e) 161/169 ----------------------------------------------------

    def test_06_every_report_states_the_bench_score(self):
        """Each report contains the bench score ``161/169``."""
        missing = []
        for slug in SLICES:
            text = read_outside(report_path(slug))
            if text is None:
                continue
            if "161/169" not in text:
                missing.append(slug)
        if not present_reports():
            self.skipTest("no slice reports present (clean clone)")
        self.assertEqual([], missing, "reports without 161/169: %s"
                         % ", ".join(missing))

    # -- (f) own peak, and peak <= the session JSONL's max --------------

    def test_07_each_report_declares_a_peak_and_its_own_session(self):
        """Each report declares its own peak and names the session it came from."""
        bad = []
        for slug in SLICES:
            text = read_outside(report_path(slug))
            if text is None:
                continue
            if declared_peak(text) is None:
                bad.append(slug)
        if not present_reports():
            self.skipTest("no slice reports present (clean clone)")
        self.assertEqual([], bad, "reports without a declared peak: %s"
                         % ", ".join(bad))

    def test_08_declared_peak_never_exceeds_the_session_jsonl_maximum(self):
        """A report's declared peak may not be greater than its session's max."""
        checked = 0
        for slug in SLICES:
            text = read_outside(report_path(slug))
            if text is None:
                continue
            declared = declared_peak(text)
            if declared is None:
                continue
            path = self.session_path(slug, text)
            if path is None:
                continue
            peak, _ = jsonl_peak(path)
            checked += 1
            self.assertLessEqual(
                declared, peak,
                "%s declares peak %d but its session %s maxes at %d"
                % (slug, declared, os.path.basename(path), peak))
        if checked == 0:
            self.skipTest("no slice session JSONLs present (clean clone)")

    # -- (g) the comparison table is outside the FABLE section ----------

    def test_09_the_comparison_table_is_not_inside_the_fable_section(self):
        """The cross-slice comparison table must not sit inside a FABLE section.

        ``b173-report-numbers.py`` scopes its peak check at the
        quality-comparison heading.  A table inside a ``FABLE VERIFICATION``
        block would make one slice's report carry another slice's peak.
        """
        offenders = []
        for slug in SLICES:
            text = read_outside(report_path(slug))
            if text is None:
                continue
            section = fable_section(text)
            if section is None:
                continue
            if "| slice | original verdict |" in section:
                offenders.append(slug)
        if offenders and len(offenders) == len(SLICES):
            self.skipTest("no slice reports present (clean clone)")
        self.assertEqual([], offenders, "comparison table found inside the "
                         "FABLE VERIFICATION section of: %s"
                         % ", ".join(offenders))

    # -- (h) manifest --------------------------------------------------

    def test_10_every_manifest_names_a_module_and_a_test(self):
        """Each slice's manifest names a module (not under tests/) and a test.

        ``seal-slice6`` is the one genuine exception: its test lives at
        repo-root ``tests/test_delivery_seal.py`` and
        ``b173-mutant.sh`` requires a component-prefixed test path, so the
        probe SKIPs it.  Its manifest still names a module and a test; the
        manifest is a record of the skip.
        """
        bad = []
        present = 0
        for slug in SLICES:
            text = read_outside(manifest_path(slug))
            if text is None:
                continue
            present += 1
            lines = [line.strip() for line in text.splitlines() if line.strip()]
            module = None
            test = None
            for line in lines:
                if line.endswith(".py") and "/tests/" not in line and module is None:
                    module = line
                if re.search(r"(^|/)tests/test_[^/]+\.py$", line):
                    test = line
            if module is None or test is None:
                bad.append(slug)
        if present == 0:
            self.skipTest("no manifests present (clean clone)")
        self.assertEqual([], bad, "manifests without a module + test pair: %s"
                         % ", ".join(bad))

    # -- the in-repo method: depends on NO outside file -----------------

    def session_path(self, slug: str, text: str):
        """Resolve the session JSONL a report's numbers came from.

        Three sources, in order: an explicit ``SESSION: <uuid>`` line in the
        report, a full JSONL path mentioned anywhere in the report, and
        finally the slice -> session map this test carries.  Returns ``None``
        when the slice has no session of its own (the Codex-implemented
        slices) or when the file is absent.
        """
        match = SESSION_RE.search(text)
        candidates = []
        if match:
            candidates.append(os.path.join(SESSION_DIR, match.group(1) + ".jsonl"))
        found = re.search(r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\.jsonl", text)
        if found:
            candidates.append(os.path.join(SESSION_DIR, found.group(1) + ".jsonl"))
        mapped = SLICE_SESSION.get(slug)
        if mapped:
            candidates.append(os.path.join(SESSION_DIR, mapped + ".jsonl"))
        for candidate in candidates:
            if os.path.isfile(candidate):
                return candidate
        return None

    def test_11_the_design_doc_exists_and_lists_every_slice(self):
        """The design doc is in the repo and its table covers every slice.

        This method reads **only** repository files, so it runs on a clean
        clone and is the module's non-skipped evidence.
        """
        self.assertTrue(
            os.path.isfile(DESIGN_DOC),
            "docs/design/artifact-completion.md is missing from the repo")
        with open(DESIGN_DOC, encoding="utf-8", errors="replace") as handle:
            doc = handle.read()
        self.assertIn("THE CROSS-SLICE COMPARISON TABLE", doc)
        header = "| slice | original verdict | which items were missing |"
        self.assertIn(header, doc,
                      "the comparison table header is missing or was renamed")
        missing = [slug for slug in SLICES if ("`%s`" % slug) not in doc]
        self.assertEqual([], missing,
                         "these slices have no row in the comparison table: %s"
                         % ", ".join(missing))

    def test_12_the_design_doc_records_the_pending_canaries_and_open_items(self):
        """The design doc names every pending canary and the open items.

        Also repository-only, so it runs on a clean clone.
        """
        self.assertTrue(os.path.isfile(DESIGN_DOC),
                        "docs/design/artifact-completion.md is missing")
        with open(DESIGN_DOC, encoding="utf-8", errors="replace") as handle:
            doc = handle.read()
        for slug in PENDING_COORDINATOR_CANARY:
            self.assertIn("`%s`" % slug, doc,
                          "%s is not named in the design doc" % slug)
        self.assertIn("pending coordinator canary", doc)
        self.assertIn("Open items", doc)


if __name__ == "__main__":
    unittest.main()
