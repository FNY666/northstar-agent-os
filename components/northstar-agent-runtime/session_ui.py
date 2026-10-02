"""Build a self-contained, offline interactive replay page for one transcript.

The generated HTML includes the transcript data and has no external assets or
network requests. It is written as a new owner-readable file (mode 0600) so
private tool output is not accidentally published by a permissive umask.
"""
from __future__ import annotations

import json
import math
import os
import webbrowser
from pathlib import Path
from typing import Any, Iterable

from sessions import (
    SESSION_FILE_SUFFIX,
    load_jsonl,
    summarise,
    validate_session_id,
)

__all__ = ("render_replay_page", "write_replay_page", "open_replay_page")

def _json_safe(value: Any) -> Any:
    """Normalize values accepted by Python's permissive JSON parser for browsers."""
    if isinstance(value, float) and not math.isfinite(value):
        return None
    if isinstance(value, dict):
        return {key: _json_safe(child) for key, child in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(child) for child in value]
    return value


_PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:; font-src data:; connect-src 'none'; base-uri 'none'; form-action 'none'">
<title>Northstar session replay</title>
<style>
:root{color-scheme:dark;--bg:#0b1020;--panel:#121a2d;--panel2:#172238;--line:#27344d;--text:#edf3ff;--muted:#9eabc2;--blue:#7dd3fc;--green:#86efac;--amber:#fbbf24;--red:#fda4af;--violet:#c4b5fd;--shadow:0 18px 60px #0005;font:15px/1.5 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(900px 420px at 10% -10%,#183151 0,transparent 70%),var(--bg);color:var(--text)}button,input,select{font:inherit}button,select,input[type=search]{color:var(--text);background:#0f1728;border:1px solid var(--line);border-radius:10px}button{cursor:pointer;padding:8px 12px}button:hover,select:hover{border-color:#6482aa}button:focus-visible,input:focus-visible,select:focus-visible{outline:2px solid var(--blue);outline-offset:2px}.shell{max-width:1500px;margin:auto;padding:24px clamp(14px,3vw,42px) 34px}.top{display:flex;justify-content:space-between;align-items:flex-start;gap:24px;margin-bottom:20px}.eyebrow{color:var(--blue);font-size:12px;text-transform:uppercase;letter-spacing:.16em;font-weight:750;margin:0 0 6px}.top h1{font-size:clamp(22px,3vw,34px);letter-spacing:-.035em;margin:0;overflow-wrap:anywhere}.subline{color:var(--muted);font-size:13px;margin:7px 0 0}.local-badge{white-space:nowrap;border:1px solid #23634a;color:var(--green);background:#10251e;border-radius:999px;padding:7px 11px;font-size:12px;font-weight:700}.stats{display:grid;grid-template-columns:repeat(5,minmax(110px,1fr));gap:10px;margin:18px 0}.stat{background:linear-gradient(140deg,#17243a,#111a2c);border:1px solid var(--line);border-radius:14px;padding:13px 15px;min-width:0}.stat-label{display:block;color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.08em}.stat-value{display:block;font-size:19px;font-weight:750;margin-top:3px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.controls{display:grid;grid-template-columns:minmax(190px,1.5fr) minmax(130px,.7fr) auto auto auto minmax(120px,1fr) auto;align-items:center;gap:9px;background:#111a2c;border:1px solid var(--line);border-radius:16px;padding:12px;margin-bottom:14px;box-shadow:var(--shadow)}input[type=search],select{padding:9px 11px;min-width:0}input[type=range]{width:100%;accent-color:var(--blue)}.play{background:#164160;border-color:#2476a0;font-weight:750}.position{color:var(--muted);font-variant-numeric:tabular-nums;white-space:nowrap;font-size:13px}.layout{display:grid;grid-template-columns:minmax(280px,390px) minmax(0,1fr);gap:14px;align-items:start}.timeline,.record{background:linear-gradient(155deg,#131d31,#101827);border:1px solid var(--line);border-radius:16px;box-shadow:var(--shadow);overflow:hidden}.timeline-head,.record-head{padding:15px 17px;border-bottom:1px solid var(--line);display:flex;justify-content:space-between;align-items:center;gap:12px}.timeline-head h2,.record-head h2{font-size:14px;margin:0}.timeline-head span,.record-head span{font-size:12px;color:var(--muted)}.events{max-height:calc(100vh - 330px);min-height:300px;overflow:auto;padding:9px}.event{display:grid;grid-template-columns:42px 1fr;gap:10px;width:100%;text-align:left;background:transparent;border:1px solid transparent;padding:10px;border-radius:12px;margin:2px 0}.event:hover{background:#19263d}.event[aria-current=true]{background:#18314a;border-color:#32638a}.event-index{color:#8191ad;font:12px/1.5 ui-monospace,monospace;padding-top:2px}.event-body{min-width:0}.event-top{display:flex;align-items:center;justify-content:space-between;gap:8px}.kind{font-size:11px;letter-spacing:.02em;font-weight:800;color:var(--blue)}.kind.user_prompt{color:var(--green)}.kind.tool_result{color:var(--amber)}.kind.denial{color:var(--red)}.kind.checkpoint{color:var(--violet)}.clock{font-size:10px;color:#8191ad;white-space:nowrap;font-variant-numeric:tabular-nums}.preview{display:block;color:#c4cede;font-size:12px;margin-top:5px;overflow:hidden;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow-wrap:anywhere}.record-body{padding:17px;min-height:360px}.record-meta{display:flex;align-items:center;flex-wrap:wrap;gap:8px;margin-bottom:16px}.pill{border:1px solid var(--line);border-radius:999px;padding:4px 9px;color:var(--muted);font-size:11px}.block{border:1px solid var(--line);background:#0e1626;border-radius:13px;padding:13px 14px;margin:10px 0}.block-title{display:flex;justify-content:space-between;align-items:center;gap:10px;color:var(--blue);font-size:12px;font-weight:800;margin-bottom:8px}.block-title .error{color:var(--red)}pre{white-space:pre-wrap;overflow-wrap:anywhere;margin:0;color:#dce6f6;font:13px/1.6 ui-monospace,SFMono-Regular,Consolas,monospace;max-height:480px;overflow:auto}.empty{padding:28px 18px;text-align:center;color:var(--muted)}.footer{color:#7f8ba1;font-size:12px;padding:12px 4px}.kbd{border:1px solid #394762;border-radius:5px;padding:1px 5px;color:#c7d4e8;font:11px ui-monospace,monospace}.notice{border-left:3px solid var(--amber);padding:9px 12px;background:#2a2415;color:#f3d99b;border-radius:7px;margin:12px 0;font-size:12px}.timeline:focus-within,.record:focus-within{border-color:#395878}
@media(max-width:1000px){.controls{grid-template-columns:1fr 1fr auto auto auto}.controls .search{grid-column:span 2}.controls .scrubber{grid-column:span 3}.layout{grid-template-columns:300px minmax(0,1fr)}}
@media(max-width:720px){.shell{padding:15px 12px 24px}.top{align-items:flex-start}.local-badge{font-size:10px}.stats{grid-template-columns:repeat(2,minmax(0,1fr))}.stat:last-child{grid-column:span 2}.controls{grid-template-columns:repeat(4,minmax(0,1fr));gap:7px}.controls .search{grid-column:span 4}.controls select{grid-column:span 2}.controls .scrubber{grid-column:span 3}.position{grid-column:span 1;text-align:right}.layout{grid-template-columns:1fr}.events{max-height:38vh;min-height:180px}.record-body{min-height:250px}}
.controls{grid-template-columns:minmax(190px,1.5fr) minmax(130px,.7fr) auto auto auto auto minmax(120px,1fr) auto}
@media(max-width:1000px){.controls{grid-template-columns:1fr 1fr auto auto auto auto}.controls .search{grid-column:span 2}.controls .scrubber{grid-column:span 3}}
@media(max-width:720px){.controls{grid-template-columns:repeat(4,minmax(0,1fr))}.controls .search{grid-column:span 4}.controls select{grid-column:span 2}.controls .scrubber{grid-column:span 3}}
@media(prefers-reduced-motion:no-preference){button,.stat{transition:background .15s ease,border-color .15s ease,transform .15s ease}.event:hover{transform:translateX(2px)}}
</style>
</head>
<body>
<div class="shell">
<header class="top">
  <div><p class="eyebrow">Northstar AgentOS / session replay</p><h1 id="session-title">Session replay</h1><p class="subline" id="session-subtitle">Offline transcript viewer</p></div>
  <div class="local-badge" title="This page has no external requests">LOCAL · READ ONLY</div>
</header>
<section class="stats" id="stats" aria-label="Session summary"></section>
<section class="controls" aria-label="Replay controls">
  <input class="search" id="search" type="search" placeholder="Filter transcript text…" aria-label="Filter transcript text">
  <select id="type-filter" aria-label="Filter by record type"><option value="">All event types</option></select>
  <button id="previous" type="button" title="Previous event (←)" aria-label="Previous event">← Prev</button>
  <button class="play" id="play" type="button" aria-pressed="false" aria-label="Play replay">▶ Play</button>
  <button id="next" type="button" title="Next event (→)" aria-label="Next event">Next →</button>
  <select id="speed" aria-label="Playback speed"><option value="0.5">0.5×</option><option value="1" selected>1×</option><option value="2">2×</option><option value="4">4×</option></select>
  <input class="scrubber" id="scrubber" type="range" min="0" max="0" value="0" aria-label="Replay position">
  <span class="position" id="position" aria-live="polite">0 / 0</span>
</section>
<div class="layout">
  <aside class="timeline" aria-label="Transcript timeline">
    <div class="timeline-head"><h2>Event timeline</h2><span id="event-count">0 records</span></div>
    <div class="events" id="events" role="listbox" aria-label="Transcript events"></div>
  </aside>
  <section class="record" aria-label="Selected transcript record" aria-live="polite">
    <div class="record-head"><h2 id="record-title">Select an event</h2><span id="record-clock"></span></div>
    <div class="record-body" id="record-body"><div class="empty">Choose an event from the timeline to inspect its payload.</div></div>
  </section>
</div>
<p class="footer">Keyboard: <span class="kbd">←</span> <span class="kbd">→</span> step · <span class="kbd">Space</span> play/pause. Playback follows the visible, filtered event list.</p>
</div>
<script id="session-data" type="application/json">__SESSION_DATA__</script>
<script>
(() => {
  "use strict";
  const payload = JSON.parse(document.getElementById("session-data").textContent);
  const records = Array.isArray(payload.records) ? payload.records : [];
  const byId = (id) => document.getElementById(id);
  const timeline = byId("events");
  const typeFilter = byId("type-filter");
  const searchInput = byId("search");
  const scrubber = byId("scrubber");
  const playButton = byId("play");
  let visible = [];
  let cursor = 0;
  let timer = null;

  function text(value) {
    if (typeof value === "string") return value;
    if (value === null || value === undefined) return "";
    try { return JSON.stringify(value, null, 2); } catch (_) { return String(value); }
  }
  function recordText(record) {
    const pieces = [];
    const content = record && record.content;
    if (Array.isArray(content)) {
      for (const block of content) {
        if (!block || typeof block !== "object") { pieces.push(String(block)); continue; }
        if (block.type === "text") pieces.push(block.text || "");
        else if (block.type === "tool_use") pieces.push("→ " + (block.name || "tool") + " " + text(block.input || {}));
        else if (block.type === "tool_result") pieces.push("← " + text(block.content || ""));
        else pieces.push(text(block));
      }
    }
    for (const [key, value] of Object.entries(record || {})) {
      if (["index", "ts", "session_id", "type", "content"].includes(key)) continue;
      if (typeof value === "string") pieces.push(value);
    }
    return pieces.join(" ").replace(/\s+/g, " ").trim();
  }
  function preview(record) {
    const value = recordText(record);
    return value.length > 150 ? value.slice(0, 147) + "…" : (value || "(no text payload)");
  }
  function clock(value) {
    if (!value) return "";
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleTimeString([], {hour12:false});
  }
  function addStat(label, value) {
    const box = document.createElement("div"); box.className = "stat";
    const name = document.createElement("span"); name.className = "stat-label"; name.textContent = label;
    const val = document.createElement("span"); val.className = "stat-value"; val.textContent = String(value);
    box.append(name, val); byId("stats").append(box);
  }
  function setPlaying(on) {
    on = Boolean(on && visible.length > 1);
    if (timer) { clearInterval(timer); timer = null; }
    playButton.setAttribute("aria-pressed", String(on));
    playButton.textContent = on ? "Ⅱ Pause" : "▶ Play";
    playButton.setAttribute("aria-label", on ? "Pause replay" : "Play replay");
    if (on && visible.length > 1) {
      const speed = Number(byId("speed")?.value || 1);
      timer = setInterval(() => {
        if (cursor >= visible.length - 1) setPlaying(false);
        else move(cursor + 1);
      }, 900 / speed);
    }
  }
  function addDetailBlock(title, value, error = false) {
    const block = document.createElement("article"); block.className = "block";
    const head = document.createElement("div"); head.className = "block-title";
    const label = document.createElement("span"); label.textContent = title;
    if (error) label.className = "error";
    head.append(label);
    const body = document.createElement("pre"); body.textContent = text(value);
    block.append(head, body); byId("record-body").append(block);
  }
  function renderRecord(record) {
    byId("record-title").textContent = (record.type || "record") + " · #" + (record.index ?? "?");
    byId("record-clock").textContent = record.ts || "";
    const body = byId("record-body"); body.replaceChildren();
    const meta = document.createElement("div"); meta.className = "record-meta";
    const type = document.createElement("span"); type.className = "pill"; type.textContent = record.type || "unknown";
    const index = document.createElement("span"); index.className = "pill"; index.textContent = "record " + (record.index ?? "?");
    meta.append(type, index); body.append(meta);
    if (Array.isArray(record.content) && record.content.some((v) => v && typeof v === "object")) {
      for (const block of record.content) {
        const kind = block && block.type ? block.type : "content";
        let title = kind;
        let value = block;
        let isError = false;
        if (kind === "text") { title = "Text"; value = block.text || ""; }
        else if (kind === "tool_use") { title = "Tool call · " + (block.name || "tool"); value = block.input || {}; }
        else if (kind === "tool_result") { title = block.is_error ? "Tool result · error" : "Tool result · success"; value = block.content ?? block; isError = Boolean(block.is_error); }
        addDetailBlock(title, value, isError);
      }
    }
    for (const [key, value] of Object.entries(record)) {
      if (["index", "ts", "session_id", "type", "content"].includes(key)) continue;
      addDetailBlock(key, value);
    }
    if (body.children.length === 1) addDetailBlock("Record payload", record);
  }
  function render() {
    const needle = searchInput.value.trim().toLocaleLowerCase();
    const kind = typeFilter.value;
    visible = records.map((record, original) => ({record, original})).filter(({record}) => {
      if (kind && record.type !== kind) return false;
      return !needle || JSON.stringify(record).toLocaleLowerCase().includes(needle);
    });
    if (cursor >= visible.length) cursor = Math.max(0, visible.length - 1);
    timeline.replaceChildren();
    byId("event-count").textContent = visible.length + " / " + records.length + " records";
    scrubber.max = String(Math.max(0, visible.length - 1));
    scrubber.value = String(cursor);
    scrubber.disabled = visible.length < 2;
    playButton.disabled = visible.length < 2;
    byId("previous").disabled = visible.length < 2 || cursor === 0;
    byId("next").disabled = visible.length < 2 || cursor >= visible.length - 1;
    if (!visible.length) {
      timeline.innerHTML = "";
      const empty = document.createElement("div"); empty.className = "empty"; empty.textContent = "No events match these filters."; timeline.append(empty);
      byId("position").textContent = "0 / 0";
      byId("record-title").textContent = "No matching event";
      byId("record-clock").textContent = "";
      byId("record-body").replaceChildren();
      setPlaying(false);
      return;
    }
    visible.forEach(({record}, index) => {
      const button = document.createElement("button"); button.type = "button"; button.className = "event"; button.setAttribute("role", "option");
      button.setAttribute("aria-selected", String(index === cursor)); button.setAttribute("aria-current", String(index === cursor));
      const number = document.createElement("span"); number.className = "event-index"; number.textContent = "#" + (record.index ?? "?");
      const content = document.createElement("span"); content.className = "event-body";
      const top = document.createElement("span"); top.className = "event-top";
      const kindLabel = document.createElement("span"); kindLabel.className = "kind " + (record.type || ""); kindLabel.textContent = record.type || "unknown";
      const time = document.createElement("span"); time.className = "clock"; time.textContent = clock(record.ts);
      top.append(kindLabel, time);
      const blurb = document.createElement("span"); blurb.className = "preview"; blurb.textContent = preview(record);
      content.append(top, blurb); button.append(number, content);
      button.addEventListener("click", () => move(index)); timeline.append(button);
    });
    byId("position").textContent = (cursor + 1) + " / " + visible.length;
    scrubber.value = String(cursor);
    renderRecord(visible[cursor].record);
    const current = timeline.querySelector('[aria-current="true"]'); if (current) current.scrollIntoView({block:"nearest"});
  }
  function move(next) { cursor = Math.max(0, Math.min(next, visible.length - 1)); render(); }

  document.title = "Replay · " + payload.session_id + " · Northstar";
  byId("session-title").textContent = payload.session_id;
  const start = records.find((record) => record.type === "session_start");
  const startData = start && start.data ? start.data : {};
  byId("session-subtitle").textContent = [startData.provider, startData.model, payload.dropped_trailing_lines ? (payload.dropped_trailing_lines + " torn trailing line(s) skipped") : "offline transcript"].filter(Boolean).join(" · ");
  const summary = payload.summary || {};
  addStat("Run status", summary.subtype || "in progress");
  addStat("Assistant turns", summary.assistant_turns || 0);
  addStat("Records", summary.records || records.length);
  addStat("Tool results", summary.by_type?.tool_result || 0);
  addStat("Cost", "$" + Number(summary.total_cost_usd || 0).toFixed(6));
  const selectOption = document.createElement("option"); selectOption.value = ""; selectOption.textContent = "All event types"; typeFilter.replaceChildren(selectOption);
  [...new Set(records.map((record) => record.type || "unknown"))].sort().forEach((value) => {
    const option = document.createElement("option"); option.value = value; option.textContent = value; typeFilter.append(option);
  });
  searchInput.addEventListener("input", () => { cursor = 0; setPlaying(false); render(); });
  typeFilter.addEventListener("change", () => { cursor = 0; setPlaying(false); render(); });
  byId("previous").addEventListener("click", () => move(cursor - 1));
  byId("next").addEventListener("click", () => move(cursor + 1));
  scrubber.addEventListener("input", () => move(Number(scrubber.value)));
  playButton.addEventListener("click", () => setPlaying(!timer));
  byId("speed").addEventListener("change", () => { if (timer) setPlaying(true); });
  document.addEventListener("keydown", (event) => {
    if (["INPUT", "SELECT", "TEXTAREA"].includes(document.activeElement?.tagName)) return;
    if (event.key === "ArrowLeft") { event.preventDefault(); move(cursor - 1); }
    else if (event.key === "ArrowRight") { event.preventDefault(); move(cursor + 1); }
    else if (event.code === "Space") { event.preventDefault(); setPlaying(!timer); }
  });
  render();
})();
</script>
</body>
</html>
"""


def render_replay_page(
    session_id: str,
    records: Iterable[dict[str, Any]],
    summary: dict[str, Any] | None = None,
    *,
    dropped_trailing_lines: int = 0,
) -> str:
    """Render the session's events and summary as self-contained interactive HTML."""
    safe_id = validate_session_id(session_id)
    materialized = list(records)
    payload = {
        "session_id": safe_id,
        "records": materialized,
        "summary": summary if summary is not None else summarise(materialized),
        "dropped_trailing_lines": int(dropped_trailing_lines),
    }
    encoded = json.dumps(
        _json_safe(payload),
        ensure_ascii=False,
        separators=(",", ":"),
        default=str,
        allow_nan=False,
    )
    # JSON lives in an inert script element; escaping '<' prevents transcript text
    # such as '</script><script>…' from terminating that data element.
    encoded = (
        encoded.replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )
    return _PAGE.replace("__SESSION_DATA__", encoded)


def write_replay_page(
    session_dir: str | Path,
    session_id: str,
    output: str | Path | None = None,
) -> Path:
    """Create a mode-0600 HTML replay file without following or overwriting a path."""
    safe_id = validate_session_id(session_id)
    transcript_path = Path(session_dir) / f"{safe_id}{SESSION_FILE_SUFFIX}"
    if not transcript_path.is_file():
        raise FileNotFoundError(f"no transcript for session {safe_id!r} in {session_dir}")
    records, dropped = load_jsonl(transcript_path)
    html = render_replay_page(
        safe_id,
        records,
        summarise(records),
        dropped_trailing_lines=dropped,
    )
    destination = Path(output).expanduser() if output is not None else Path.cwd() / f"session-{safe_id}-replay.html"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(destination, flags, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(html)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        try:
            destination.unlink()
        except OSError:
            pass
        raise
    return destination


def open_replay_page(path: str | Path) -> bool:
    """Ask the host's registered browser to open a generated local file URL."""
    return bool(webbrowser.open(Path(path).resolve().as_uri()))
