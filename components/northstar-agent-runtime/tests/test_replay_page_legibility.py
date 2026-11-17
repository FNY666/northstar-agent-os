"""The offline replay page must say what a cancellation revoked.

Slice 15 (`cancellation-visibility`) gave the runtime ONE rendering of a
cancellation -- `cancellation_view.describe_cancellation` -- and wired it
into the three read paths that live in Python: the audit feed, the replay
frames, and `sessions show`.

It did not reach `session_ui.py`, the runtime's own generated offline HTML
replay page.  That page has its OWN JavaScript renderer, `recordText`, and
it was left showing the chain hashes:

    northstar-audit-chain/2 92535ec4fa5e... sha256:1dd87cca... ... permission ...

Measured against a record the runtime itself wrote, that line contained
none of `publish`, `the release`, `user` or `stop, do not publish`, and
none of `STANDING` or `LIFTED`.

THE RULE THIS SLICE PINS:

> **On the offline replay page, a cancellation appears as what was
> revoked, on what, by whom -- never as a wall of hashes.**

> **The timeline line for a cancellation says whether the stop is STILL
> STANDING or has been LIFTED** -- whatever the grant id's length.  A
> reader who sees only the timeline must be able to answer "may I do it?".

> **The page does not grow a second rendering.**  The readable sentence is
> `cancellation_view.describe_cancellation`'s output, verbatim.

These tests measure the PAGE: the HTML the runtime generates, and --
where node is available -- the page's own JavaScript running against a
stubbed DOM.  A test that only reads the generated HTML would pass while
the page's script still rendered hashes, so the JavaScript is executed
for real.

The records are the ones the RUNTIME wrote (`SessionStore.record_cancellation`
/ `record_cancellation_lift`), not hand-written samples: a shape guess
cannot make a guard pass while proving nothing.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cancellation_tombstone import PERMISSION, Lift, Tombstone  # noqa: E402
from sessions import SessionStore  # noqa: E402


def a_tombstone(*, grant_id: str = "grant-1", action: str = "publish",
                subject: str = "the release", reason: str = "stop, do not publish") -> Tombstone:
    """A permission tombstone -- a stop that never expires."""
    return Tombstone(
        grant_id=grant_id,
        action=action,
        subject=subject,
        declarer="user",
        declarer_channel="chat",
        declared_at=1760000000.0,
        kind=PERMISSION,
        reason=reason,
    )


def a_lift(tombstone: Tombstone) -> Lift:
    """A named lift of ``tombstone`` -- the instruction that undoes it."""
    return Lift(
        declarer="user",
        declarer_channel="chat",
        grant_id=tombstone.grant_id,
        action=tombstone.action,
        subject=tombstone.subject,
        text="publish the release, the stop on it is lifted",
        lifted_at=1760000100.0,
    )


def a_standing_record(directory: str, session_id: str, **kwargs) -> dict:
    """A cancellation the runtime wrote, standing (not lifted)."""
    store = SessionStore(directory=directory, session_id=session_id)
    record = store.record_cancellation(a_tombstone(**kwargs))
    assert record is not None
    return record


def a_lifted_record(directory: str, session_id: str, **kwargs) -> dict:
    """A cancellation the runtime wrote, and then lifted."""
    store = SessionStore(directory=directory, session_id=session_id)
    tombstone = a_tombstone(**kwargs)
    record = store.record_cancellation_lift(tombstone, a_lift(tombstone))
    assert record is not None
    return record


def page_for(records: list[dict], session_id: str = "page-1") -> str:
    """The HTML the runtime generates for these records."""
    from session_ui import render_replay_page

    return render_replay_page(session_id, records)


def page_data(page: str) -> dict:
    """The JSON the page carries in its inert data element."""
    marker = '<script id="session-data" type="application/json">'
    assert marker in page, "the page carries no session-data element"
    encoded = page.split(marker, 1)[1].split("</script>", 1)[0]
    return json.loads(encoded)


class GeneratedPageTests(unittest.TestCase):
    """R1/R5: the page carries the SHARED description of a cancellation.

    The page must not grow a second renderer: the sentence it shows is
    `cancellation_view.describe_cancellation`'s output, verbatim.
    """

    def test_the_page_carries_the_shared_description_of_the_cancellation(self):
        from cancellation_view import describe_cancellation

        with tempfile.TemporaryDirectory() as directory:
            record = a_standing_record(directory, "page-standing")
            page = page_for([record])
        description = describe_cancellation(record)
        self.assertIn(description, page, "the shared description is not on the page")

    def test_the_description_the_page_shows_is_the_shared_rendering(self):
        """R5: verbatim, not a page-local paraphrase."""
        from cancellation_view import describe_cancellation

        with tempfile.TemporaryDirectory() as directory:
            record = a_standing_record(directory, "page-verbatim")
            shown = page_data(page_for([record]))["records"][0].get("description")
        self.assertEqual(shown, describe_cancellation(record))

    def test_the_description_names_what_was_revoked_and_by_whom(self):
        with tempfile.TemporaryDirectory() as directory:
            record = a_standing_record(directory, "page-names")
            shown = page_data(page_for([record]))["records"][0].get("description")
        self.assertIsInstance(shown, str)
        for needle in ("publish", "the release", "user", "stop, do not publish"):
            self.assertIn(needle, shown, "the description is missing %r" % needle)

    def test_the_description_carries_no_hashes(self):
        """The readable sentence is about the revocation, not the envelope."""
        with tempfile.TemporaryDirectory() as directory:
            record = a_standing_record(directory, "page-no-hashes")
            shown = page_data(page_for([record]))["records"][0].get("description")
        self.assertIsInstance(shown, str, "the page carries no description")
        for needle in ("chain_hash", "sha256:", "prev_hash", "genesis"):
            self.assertNotIn(needle, shown)

    def test_a_cancellation_gets_a_colour_of_its_own(self):
        """A revocation is a withheld authorization, not an ordinary line."""
        with tempfile.TemporaryDirectory() as directory:
            record = a_standing_record(directory, "page-colour")
            page = page_for([record])
        self.assertRegex(page, r"\.kind\.cancellation\b")

    def test_a_malformed_cancellation_does_not_break_the_page(self):
        """R8: the page must survive a record whose shape it did not expect."""
        page = page_for([{"index": 0, "type": "cancellation", "ts": "2026-09-09T00:00:00.000Z"}])
        self.assertIn("cancellation", page)
        data = page_data(page)
        self.assertEqual(len(data["records"]), 1)

    def test_an_ordinary_record_is_still_rendered_the_ordinary_way(self):
        """R7: this slice must not change how anything else renders."""
        page = page_for([{
            "index": 0, "type": "user_prompt", "ts": "2026-09-09T00:00:00.000Z",
            "role": "user", "content": [{"type": "text", "text": "do the thing"}],
        }])
        data = page_data(page)
        self.assertNotIn("description", data["records"][0])
        self.assertIn("do the thing", json.dumps(data))

    def test_the_page_still_normalises_non_finite_numbers(self):
        """The page copies a record to describe it; the copy must not
        smuggle a NaN into the payload.

        ``render_replay_page`` normalises non-finite floats to ``null``
        before the JSON is encoded, because a browser's parser rejects
        them.  This slice copies every record (to attach a description),
        so the copy has to stay inside that normalisation.
        """
        page = page_for([{
            "index": 0, "type": "user_prompt", "ts": "2026-09-09T00:00:00.000Z",
            "content": [{"type": "text", "text": "inspect"}],
            "metrics": {"score": float("nan"), "limit": float("inf")},
        }])
        self.assertEqual(page_data(page)["records"][0]["metrics"], {"score": None, "limit": None})
        self.assertNotIn(":NaN", page)

    def test_the_caller_s_records_are_not_mutated(self):
        """A record the runtime wrote is an audit boundary.

        The page describes a copy; the caller's record must come back
        exactly as it went in.
        """
        with tempfile.TemporaryDirectory() as directory:
            record = a_standing_record(directory, "page-no-mutation")
        before = json.dumps(record, sort_keys=True)
        page_for([record])
        self.assertEqual(json.dumps(record, sort_keys=True), before)
        self.assertNotIn("description", record)


#: A node harness that loads the GENERATED page, stubs the DOM, and reports
#: what the page's own JavaScript renders for each record.
#:
#: The generated page has TWO script elements: the first is the inert JSON
#: data island, the second is the real script, and that script lives inside
#: an IIFE -- so `recordText` and `preview` are NOT on the VM context.  They
#: are extracted by name from the source and re-run against a context that
#: carries the page's own payload.
#:
#: The DOM stub needs `append` (not only `appendChild`), because the page's
#: `addStat` uses `box.append(name, val)`.
_PAGE_HARNESS = r"""
const fs = require('fs'), vm = require('vm');
const page = fs.readFileSync(process.argv[2], 'utf8');
const blocks = [...page.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/g)];
const dataBlock = blocks[0][1];
const script = blocks[1][1];
const payload = JSON.parse(dataBlock);

function stubElement() {
  const e = {
    textContent: '', value: '', innerHTML: '', dataset: {}, children: [],
    style: {}, className: '',
    classList: { add(){}, remove(){}, toggle(){ return false; }, contains(){ return false; } },
    addEventListener(){}, removeEventListener(){}, appendChild(c){ e.children.push(c); },
    append(...cs){ for (const c of cs) e.children.push(c); }, removeChild(){},
    replaceChildren(){ e.children = []; }, click(){}, focus(){},
    querySelectorAll(){ return []; }, querySelector(){ return null; },
    setAttribute(){}, getAttribute(){ return null; }, scrollIntoView(){},
  };
  return e;
}

const elements = {};
const ctx = {
  console,
  document: {
    getElementById(id) {
      if (!elements[id]) {
        const e = stubElement();
        if (id === 'session-data') e.textContent = dataBlock;
        elements[id] = e;
      }
      return elements[id];
    },
    createElement(){ return stubElement(); },
    querySelectorAll(){ return []; },
    addEventListener(){}, activeElement: null,
  },
  setTimeout, clearTimeout, setInterval, clearInterval,
};
ctx.window = ctx; ctx.globalThis = ctx;

const out = { failure: null, previews: [], recordTexts: [] };
try {
  vm.createContext(ctx);
  vm.runInContext(script, ctx);
} catch (err) {
  out.failure = 'load: ' + err.message;
}

// The page's own functions are inside an IIFE, so they are extracted from
// the source and re-run with the page's payload in scope.
if (!out.failure) {
  const names = ['text', 'toolResultText', 'recordText', 'preview'];
  const extracted = [];
  for (const name of names) {
    const start = script.indexOf('function ' + name + '(');
    if (start === -1) { out.failure = 'no ' + name + ' in the page script'; break; }
    let depth = 0, i = script.indexOf('{', start), end = i;
    for (; end < script.length; end++) {
      if (script[end] === '{') depth++;
      else if (script[end] === '}') { depth--; if (depth === 0) { end++; break; } }
    }
    extracted.push(script.slice(start, end));
  }
  if (!out.failure) {
    const ctx2 = { console, JSON, String, Object, Array, Math, Number, Boolean };
    ctx2.window = ctx2; ctx2.globalThis = ctx2;
    try {
      vm.createContext(ctx2);
      vm.runInContext(
        'const payload = ' + JSON.stringify(payload) + ';\n'
        + 'const records = payload.records;\n'
        + extracted.join('\n'), ctx2);
      for (const rec of payload.records) {
        out.recordTexts.push(ctx2.recordText(rec));
        out.previews.push(ctx2.preview(rec));
      }
    } catch (err) {
      out.failure = 'extract: ' + err.message;
    }
  }
}
process.stdout.write(JSON.stringify(out) + '\n');
"""


def run_page_script(page: str) -> dict:
    """Run the generated page's own JavaScript and report what it renders.

    Returns the harness's output: ``previews`` is the text the TIMELINE
    shows for each record, ``recordTexts`` the full rendered text.
    """
    node = shutil.which("node")
    if node is None:
        raise unittest.SkipTest("node is not installed on this host")
    with tempfile.TemporaryDirectory() as directory:
        page_path = Path(directory) / "page.html"
        page_path.write_text(page, encoding="utf-8")
        harness_path = Path(directory) / "harness.js"
        harness_path.write_text(_PAGE_HARNESS, encoding="utf-8")
        completed = subprocess.run(
            [node, str(harness_path), str(page_path)],
            capture_output=True, text=True, timeout=120,
        )
    if completed.returncode != 0:
        raise AssertionError("the page's JavaScript did not run under node: %s"
                             % completed.stderr.strip()[:2000])
    lines = completed.stdout.strip().splitlines()
    if not lines:
        raise AssertionError("the page probe produced no output")
    result = json.loads(lines[-1])
    if result.get("failure"):
        raise AssertionError("the page probe failed: %s" % result["failure"])
    return result


class PageScriptTests(unittest.TestCase):
    """R2/R3/R4: the page's OWN JavaScript must render it legibly.

    Reading the generated HTML is not enough: the page's script is what
    the reader actually sees.  These tests run it under node against a
    stubbed DOM and assert on the strings it produces.
    """

    def test_the_timeline_line_names_what_was_revoked_and_by_whom(self):
        with tempfile.TemporaryDirectory() as directory:
            record = a_standing_record(directory, "js-names")
            result = run_page_script(page_for([record]))
        line = result["previews"][0]
        for needle in ("publish", "the release", "user"):
            self.assertIn(needle, line, "the timeline line is missing %r: %r" % (needle, line))

    def test_the_timeline_line_shows_no_hashes(self):
        with tempfile.TemporaryDirectory() as directory:
            record = a_standing_record(directory, "js-no-hashes")
            result = run_page_script(page_for([record]))
        line = result["previews"][0]
        for needle in ("chain_hash", "sha256:", record["chain_hash"]):
            self.assertNotIn(needle, line)

    def test_the_timeline_line_says_the_stop_is_standing(self):
        with tempfile.TemporaryDirectory() as directory:
            record = a_standing_record(directory, "js-standing")
            result = run_page_script(page_for([record]))
        self.assertIn("STANDING", result["previews"][0])

    def test_the_timeline_line_says_the_stop_was_lifted(self):
        with tempfile.TemporaryDirectory() as directory:
            record = a_lifted_record(directory, "js-lifted")
            result = run_page_script(page_for([record]))
        self.assertIn("LIFTED", result["previews"][0])

    def test_a_long_grant_id_does_not_push_the_verdict_out_of_the_line(self):
        """R4: the verdict must survive a realistic grant id.

        A real grant id is a uuid (36 characters).  With it, the shared
        description runs past the page's 150-character preview budget, so
        a naive truncation drops "STANDING"/"LIFTED" -- the one word a
        reader must not miss.
        """
        grant_id = str(uuid.uuid4())
        with tempfile.TemporaryDirectory() as directory:
            record = a_standing_record(directory, "js-long-grant", grant_id=grant_id)
            result = run_page_script(page_for([record]))
        line = result["previews"][0]
        self.assertIn("STANDING", line, "a long grant id pushed the verdict out: %r" % line)
        self.assertIn("publish", line)

    def test_a_long_grant_id_does_not_push_the_lift_out_of_the_line(self):
        grant_id = str(uuid.uuid4())
        with tempfile.TemporaryDirectory() as directory:
            record = a_lifted_record(directory, "js-long-lift", grant_id=grant_id)
            result = run_page_script(page_for([record]))
        self.assertIn("LIFTED", result["previews"][0])

    def test_the_two_states_are_distinguishable_on_the_page(self):
        with tempfile.TemporaryDirectory() as directory:
            standing = run_page_script(page_for([a_standing_record(directory, "js-a")]))
            lifted = run_page_script(page_for([a_lifted_record(directory, "js-b")]))
        self.assertNotEqual(standing["previews"][0], lifted["previews"][0])

    def test_an_ordinary_record_still_renders_on_the_page(self):
        """R7 in the browser: this slice must not change other records.

        The expectation is the BASELINE's rendering, measured by running
        the page's script at the pre-slice commit -- not a hand-written
        guess.  An ordinary record has no description, so it takes the
        page's own path, which this slice does not touch.
        """
        page = page_for([{
            "index": 0, "type": "user_prompt", "ts": "2026-09-09T00:00:00.000Z",
            "role": "user", "content": [{"type": "text", "text": "do the thing"}],
        }])
        result = run_page_script(page)
        line = result["previews"][0]
        self.assertIn("do the thing", line)
        self.assertNotIn("description", page_data(page)["records"][0])
        self.assertNotIn("STANDING", line)

    def test_the_page_shows_a_malformed_cancellation_without_throwing(self):
        """R8 in the browser: the script must survive a bad record."""
        page = page_for([{"index": 0, "type": "cancellation", "ts": "2026-09-09T00:00:00.000Z"}])
        result = run_page_script(page)
        self.assertTrue(result["previews"][0].strip())


class SharedRenderingTests(unittest.TestCase):
    """The shared rendering the page relies on, measured at the boundary.

    These are the properties the page's line depends on.  They live here
    because the page is where the truncation budget bites.
    """

    def test_the_verdict_comes_first_in_the_rendering(self):
        """The verdict must not be the thing a truncation drops.

        The page's timeline line is 150 characters.  A real grant id is 36
        characters of it.  If the verdict is last, it is the part that
        falls off the end, and a reader cannot tell a standing stop from
        a lifted one.
        """
        from cancellation_view import describe_cancellation

        with tempfile.TemporaryDirectory() as directory:
            record = a_standing_record(directory, "shared-order", grant_id=str(uuid.uuid4()))
            description = describe_cancellation(record)
        self.assertLess(
            description.index("STANDING"), description.index("publish"),
            "the verdict must come before the details it qualifies",
        )

    def test_a_blank_subject_is_dropped_rather_than_shown_as_a_gap(self):
        """A missing subject must not leave a dangling " on ".

        The rendering keeps the scope readable: with no subject there is
        nothing to say "on", so the scope is the action alone.
        """
        from cancellation_view import describe_cancellation

        with tempfile.TemporaryDirectory() as directory:
            record = a_standing_record(directory, "shared-blank", subject="")
            description = describe_cancellation(record)
        self.assertNotIn(" on ", description)
        self.assertIn("publish", description)

    def test_a_record_with_no_reason_says_so_rather_than_inventing_one(self):
        from cancellation_view import describe_cancellation

        with tempfile.TemporaryDirectory() as directory:
            record = a_standing_record(directory, "shared-no-reason", reason="")
            description = describe_cancellation(record)
        self.assertIn("(none given)", description)

    def test_the_rendering_survives_a_record_with_no_tombstone(self):
        from cancellation_view import describe_cancellation

        description = describe_cancellation({"type": "cancellation", "index": 3})
        self.assertIsInstance(description, str)
        self.assertTrue(description.strip())


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
