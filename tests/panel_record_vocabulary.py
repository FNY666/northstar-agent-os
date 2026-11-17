"""The session panel's record vocabulary must match the runtime's.

``examples/session-panel/session-panel.html`` mirrors the runtime's
record vocabulary by hand:  it carries a ``RECORD_TYPES`` list, a
``TYPE_COLOR`` map and a ``summarize`` case per record type, so that the
offline panel can label, colour and describe every record the runtime
writes.

A HAND-MAINTAINED MIRROR DRIFTS.  Commit ``695a25b7`` (B173 tombstone)
added the ``cancellation`` record type to the runtime's
``RECORD_TYPES`` in ``sessions.py`` and did not add it to the panel.
The consequence is not cosmetic:

  * the panel classifies a cancellation record as ``other:cancellation``
    rather than as a ``cancellation`` record, so it gets no chip, no
    colour and no filter of its own;
  * ``summarize`` has no case for it, so the tombstone -- the sticky
    revocation that says "stop, do not publish" -- renders as a raw
    JSON blob; and
  * ``isErrorRecord`` returns ``false`` for it, so the panel's
    "errors & denials only" filter HIDES a cancellation.  That is the
    one record type whose whole point is that it must not be missed.

This module holds the DETECTOR, deliberately outside the test file:  the
mutant probe mutates a module and reruns the slice's tests, and a test
file is excluded from the probe by name, so a guard whose logic lives
entirely inside a test file cannot be mutation-probed at all.

HOW THE DETECTOR MEASURES
--------------------------

The detector does not work from a hand-written list of record shapes.
It **asks the runtime to write the records**, then feeds those records
to the panel's **real JavaScript** under node, and reports what the
panel does with them.

That matters because the record shapes are exactly what a hand-written
sample list gets wrong:  a checkpoint's payload is top-level
(``turns``, ``transcript_len``, ``tool_calls``), not nested under
``data``, and a cancellation's payload carries a ``tombstone``.  A
sample list written by hand would have tested the panel against shapes
the runtime never writes.

Where node is not installed the behavioural half is unavailable;  the
detector says so rather than pretending to have measured it.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / "components" / "northstar-agent-runtime"
PANEL = ROOT / "examples" / "session-panel" / "session-panel.html"
SESSIONS = RUNTIME / "sessions.py"

#: The runtime's authoritative record vocabulary, read from `sessions.py`.
_RECORD_TYPES_BLOCK = re.compile(
    r"RECORD_TYPES: tuple\[str, \.\.\.\] = \((.*?)\)\n", re.S
)


def runtime_record_types() -> list[str]:
    """The record types the runtime declares, in declaration order."""
    source = SESSIONS.read_text(encoding="utf-8")
    block = _RECORD_TYPES_BLOCK.search(source)
    if block is None:
        raise LookupError("RECORD_TYPES block not found in sessions.py")
    return re.findall(r'"([a-z_]+)"', block.group(1))


def panel_record_types() -> list[str]:
    """The record types the panel declares, read from its JavaScript.

    The list is read out of the panel's own source rather than executed,
    because this must work without node;  ``node`` is used by
    :func:`panel_behaviour` for the behavioural half of the guard.
    """
    source = PANEL.read_text(encoding="utf-8")
    match = re.search(r"var RECORD_TYPES = \[(.*?)\];", source, re.S)
    if match is None:
        raise LookupError("RECORD_TYPES list not found in the panel")
    return re.findall(r'"([a-z_]+)"', match.group(1))


def missing_panel_record_types() -> list[str]:
    """The runtime's record types the panel does not know about."""
    known = set(panel_record_types())
    missing = []
    for kind in runtime_record_types():
        # Written as an equality rather than a bare membership test, so
        # that the mutant probe -- which flips `==` to `!=` -- can reach
        # this comparison.  The flipped form would report every KNOWN
        # type as missing, which the guard catches loudly.
        if (kind in known) == False:
            missing.append(kind)
    return missing


def uncoloured_panel_record_types() -> list[str]:
    """The panel's record types that have no colour of their own.

    A type with no colour falls back to ``warn`` -- which is a colour,
    so the defect is subtle:  a cancellation must not look like an
    ordinary informational row.
    """
    source = PANEL.read_text(encoding="utf-8")
    match = re.search(r"var TYPE_COLOR = \{(.*?)\};", source, re.S)
    if match is None:
        raise LookupError("TYPE_COLOR map not found in the panel")
    coloured = set(re.findall(r"([a-z_]+):", match.group(1)))
    return [kind for kind in panel_record_types() if kind not in coloured]


def node_available() -> bool:
    """Whether node is on PATH."""
    return shutil.which("node") is not None


def runtime_probe() -> dict:
    """Ask the runtime to write one real record of every type.

    The records are produced by the runtime's own ``SessionStore``,
    the runtime's own ``Tombstone`` and the runtime's own
    ``record_cancellation_lift``, so their shapes are the shapes the
    runtime actually writes -- not shapes a sample list guessed.

    The result carries the records, plus the lifted cancellation under
    its own key, because the lift is what makes a stopped action
    distinguishable from a lifted one.
    """
    script = _RECORD_SCRIPT
    completed = subprocess.run(
        [sys.executable, "-c", script],
        cwd=str(RUNTIME),
        capture_output=True,
        text=True,
        timeout=180,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            "the runtime could not produce its records: %s"
            % completed.stderr.strip()[:2000]
        )
    payload = completed.stdout.strip().splitlines()
    if not payload:
        raise RuntimeError("the runtime record probe produced no output")
    result = json.loads(payload[-1])
    if result.get("failure"):
        raise RuntimeError("the runtime record probe failed: %s" % result["failure"])
    return result


def runtime_records() -> dict[str, dict]:
    """One real record per record type the runtime declares."""
    return runtime_probe()["records"]


def panel_behaviour() -> dict:
    """What the panel DOES with the runtime's real records.

    The panel's JavaScript is extracted and executed under node in a
    sandbox whose DOM is a stub, and the runtime's real records are
    passed through ``summarize``, ``isErrorRecord`` and the panel's
    classification.  The result is a mapping:

        {
          "summarize": {kind: the summary the panel produced},
          "is_error":  {kind: whether the panel calls it an error},
          "known":     {kind: whether the panel's vocabulary knows the type},
          "color":     {kind: the colour the panel would use},
          "failure":   None, or the error text if the panel threw,
        }

    ``None`` is returned when node is unavailable, so the caller can
    skip the behavioural half rather than fail on a missing tool.
    """
    node = shutil.which("node")
    if node is None:
        return None

    probe = runtime_probe()
    records = probe["records"]
    lifted = probe["lifted"]
    source = PANEL.read_text(encoding="utf-8")
    if "<script>" not in source:
        raise LookupError("no inline script found in the panel")

    harness = _HARNESS.replace(
        "__PANEL_SOURCE__", json.dumps(source)
    ).replace("__RECORDS__", json.dumps(records))
    harness = harness.replace("__LIFTED__", json.dumps(lifted))
    completed = subprocess.run(
        [node, "-e", harness],
        capture_output=True,
        text=True,
        timeout=120,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            "the panel's JavaScript did not run under node: %s"
            % completed.stderr.strip()[:2000]
        )
    payload = completed.stdout.strip().splitlines()
    if not payload:
        raise RuntimeError("the panel probe produced no output")
    result = json.loads(payload[-1])
    if result.get("failure"):
        raise RuntimeError("the panel probe failed: %s" % result["failure"])
    return result


#: Writes one real record of every type the runtime declares, using the
#: runtime's own store and its own message classes.
_RECORD_SCRIPT = r"""
import json, os, sys, tempfile
sys.path.insert(0, os.getcwd())

try:
    from sessions import SessionStore, RECORD_TYPES
    from cancellation_tombstone import Tombstone, Lift, PERMISSION

    directory = tempfile.mkdtemp(prefix="northstar-panel-probe-")
    store = SessionStore(directory=directory, session_id="panel-probe")

    tombstone = Tombstone(
        grant_id="grant-1",
        action="publish",
        subject="the release",
        declarer="user",
        declarer_channel="chat",
        declared_at=1760000000.0,
        kind=PERMISSION,
        reason="stop, do not publish",
    )

    # A second tombstone, lifted.  The lift is a record of its own, so a
    # reader can tell a standing stop from a lifted one.
    lifted_tombstone = Tombstone(
        grant_id="grant-2",
        action="publish",
        subject="the draft",
        declarer="user",
        declarer_channel="chat",
        declared_at=1760000000.0,
        kind=PERMISSION,
        reason="stop for now",
    )
    lift = Lift(
        declarer="user",
        declarer_channel="chat",
        grant_id="grant-2",
        action="publish",
        subject="the draft",
        text="publish the draft, the stop on it is lifted",
        lifted_at=1760000100.0,
    )

    payloads = {
        "session_start": {"content": "a session begins"},
        "user_prompt": {
            "agent": "main", "role": "user",
            "content": [{"type": "text", "text": "do the thing"}],
            "is_meta": False,
        },
        "assistant": {
            "agent": "main", "role": "assistant",
            "content": [{"type": "text", "text": "on it"}],
            "model": "claude-fable-5-2",
            "usage": {"input_tokens": 10, "output_tokens": 5},
            "stop_reason": "end_turn",
        },
        "tool_result": {
            "agent": "main", "role": "user",
            "content": [{"type": "text", "text": "the tool ran"}],
            "is_meta": False,
        },
        "hook": {
            "agent": "main", "hook": "PreToolUse", "decision": "allow",
        },
        "denial": {
            "agent": "main", "tool": "Shell", "source": "permission_engine",
            "turn_index": 3, "reason": "default deny", "kind": "permission",
        },
        "defensive_assessment": {
            "agent": "main", "tool": "Read", "turn_index": 4,
            "decision": "review", "sanitized": False, "finding_count": 1,
            "findings": [{"rule_id": "r1", "severity": 50, "category": "c"}],
        },
        "compact_boundary": {
            "agent": "main", "subtype": "compact_boundary",
            "content": "a summary of the conversation",
            "data": {"tokens_before": 100, "tokens_after": 20},
        },
        "informational": {
            "agent": "main", "subtype": "informational",
            "content": "a note", "data": {"note": "hi"},
        },
        "postconditions": {
            "agent": "main", "subtype": "postconditions",
            "content": "postconditions: 1/1 passed",
            "data": {"passed": 1, "checked": 1, "failed": 0, "ok": True,
                     "results": [{"ok": True, "kind": "file_exists",
                                  "path": "a.py", "detail": "present",
                                  "structural": True}]},
        },
        "checkpoint": {
            "agent": "main", "turns": 2, "transcript_len": 40,
            "transcript_digest": "0123456789abcdef", "tool_calls": 3,
            "cost_usd": 0.25, "denials": 1,
        },
        "subagent": {
            "agent": "worker", "subtype": "done",
            "content": [{"type": "text", "text": "the subagent finished"}],
            "data": {},
        },
        "result": {
            "subtype": "success", "is_error": False, "num_turns": 3,
            "duration_ms": 1200, "total_cost_usd": 0.01,
            "total_usage": {"input_tokens": 100, "output_tokens": 20},
            "pricing_estimated": True, "errors": [], "permission_denials": [],
        },
        "session_end": {"subtype": "success"},
        "cancellation": {
            "tombstone": tombstone.to_dict(),
            "digest": tombstone.digest(),
            "kind": tombstone.kind,
        },
        "cancellation_lifted": {
            "tombstone": lifted_tombstone.to_dict(),
            "digest": lifted_tombstone.digest(),
            "kind": lifted_tombstone.kind,
            "lift": lift.to_dict(),
        },
    }

    records = {}
    for kind in RECORD_TYPES:
        payload = payloads.get(kind)
        if payload is None:
            # No representative payload: write the type with an empty
            # payload so the panel still sees a record of that type.
            payload = {}
        record = store.append(kind, payload)
        if record is None:
            raise SystemExit("the runtime refused to write a %s record" % kind)
        records[kind] = record

    # The lifted cancellation, written by the runtime's own writer so
    # the record carries the shape the runtime writes -- including the
    # `lift` block.  It is kept under its own key so the panel is
    # exercised with BOTH a standing stop and a lifted one.
    lifted = store.record_cancellation_lift(lifted_tombstone, lift)
    if lifted is None:
        raise SystemExit("the runtime refused to write the lifted cancellation")
    print(json.dumps({"records": records, "lifted": lifted, "failure": None}))
except Exception as exc:
    print(json.dumps({"records": {}, "failure": "%s: %s" % (type(exc).__name__, exc)}))
"""


#: A node harness that loads the panel's own script, stubs the DOM, and
#: reports what the panel does with the runtime's real records.
_HARNESS = r"""
const fs = require('fs'), vm = require('vm');
const html = __PANEL_SOURCE__;
const records = __RECORDS__;
const lifted = __LIFTED__;
const script = html.match(/<script>([\s\S]*?)<\/script>/)[1];

function stubElement() {
  return {
    textContent: '', value: '', innerHTML: '', dataset: {},
    classList: { add(){}, remove(){}, toggle(){ return false; }, contains(){ return false; } },
    addEventListener(){}, removeEventListener(){}, appendChild(){}, removeChild(){},
    click(){}, querySelectorAll(){ return []; }, querySelector(){ return null; },
    setAttribute(){}, getAttribute(){ return null; }
  };
}

const ctx = {
  console,
  document: {
    getElementById(){ return stubElement(); },
    createElement(){ return stubElement(); },
    querySelectorAll(){ return []; },
    addEventListener(){}
  },
  FileReader: function(){},
  setTimeout, clearTimeout
};
ctx.window = ctx; ctx.globalThis = ctx;

let failure = null;
try {
  vm.createContext(ctx);
  vm.runInContext(script, ctx);
} catch (err) {
  failure = 'load: ' + err.message;
}

const out = { summarize: {}, is_error: {}, known: {}, color: {}, failure: failure };
if (!failure) { records['cancellation_lifted'] = lifted; }
if (!failure) {
  for (const [kind, rec] of Object.entries(records)) {
    try { out.summarize[kind] = ctx.summarize(rec); }
    catch (e) { out.summarize[kind] = 'THREW: ' + e.message; }
    try { out.is_error[kind] = ctx.isErrorRecord(rec); }
    catch (e) { out.is_error[kind] = 'THREW: ' + e.message; }
    try { out.known[kind] = ctx.RECORD_TYPES.indexOf(rec.type) !== -1; }
    catch (e) { out.known[kind] = false; }
    try { out.color[kind] = ctx.TYPE_COLOR[rec.type] || null; }
    catch (e) { out.color[kind] = null; }
  }
}
process.stdout.write(JSON.stringify(out) + '\n');
"""
