# Context-engineering thresholds: offload before summarize

Status: **FINAL** (B173 fable, 2026-11-13).
Implemented on `batch-173-moltbook-absorb`.

## 1. The gap

The frontier report this slice absorbs argues one thing loudly: *a
context-engineering system is a set of numbers, and the numbers belong in
one place.* Concretely, four claims:

* **Offload before summarize.** A tool result over ~20,000 tokens should
  go to disk and leave a pointer *before* anyone tries to summarize it.
  Summarizing is lossy; offloading is not. The summary is the fallback,
  not the first move.
* **85% window truncation.** At 85% of the context window, the old
  write/edit calls stop being useful and become pointers.
* **Post-compaction re-read is a budget, not a flood.** After a
  compaction the harness puts the workspace back into the context: a
  file over ~5,000 tokens comes back as a *path*, and at most five files
  are re-read.
* **The memory tax must be measured.** ETH Zurich's reported +20%/+23%
  is a *comparison*, not Northstar's number. Northstar has to book its
  own persistent-context cost and report the share.

### What the code actually had (read, not assumed)

* `compaction.py` — safe-boundary compaction (`is_safe_cut`,
  `latest_safe_cut`) plus an extractive summary. Correct, and it has no
  budget at all: it cuts when asked, and the caller decides when.
* `sessions.py` — a durable record of everything, with `RECORD_TYPES`
  covering compaction boundaries (`compact_boundary`) but nothing about
  *context cost*.
* `memory.py` — `discover_memory` returns workspace memory with a
  32KB / 12,000-char managed limit and an audience gate. The limit
  bounds the *file*; it says nothing about what a run pays to carry it.
* `skills.py` — `discover_skills` finds skill packages by digest. No
  token budget on a skill body.
* `loop.py` — `_generate` builds the provider payload with
  `transcript_to_api` and screens it. Nothing between those two steps
  reduces the payload.
* `agents.py` — `AgentDefinition.tags` distinguishes agent kinds;
  nothing bounds what a subagent hands back to its parent.

So: no offload, no window-pressure truncation, no re-read budget, no
skill cap, no subagent return budget, and no measurement of any of it.
Every number in the source report had to be built, and — more
importantly — had to be built so that it can be *checked*.

## 2. The design

### 2.1 One place for the numbers

`components/northstar-agent-runtime/context_budget.py` holds a single
frozen record, `ContextThresholds`, and every rule as a pure function
over it. No rule hard-codes a number of its own; the module's
`DEFAULT_*` constants are the record's defaults.

| Threshold | Default | Source |
| --- | --- | --- |
| `tool_result_offload_tokens` | 20,000 | source report; the point where a result stops being readable in-context |
| `offload_preview_lines` | 10 | source report |
| `offload_preview_max_bytes` | 4,000 | Northstar: the preview must not be able to reintroduce a huge result |
| `window_pressure_fraction` | 0.85 | source report (85% of window) |
| `summary_trigger_fraction` | 0.85 | source report; configurable down to 10–20% for eval |
| `reread_path_only_tokens` | 5,000 | source report (post-compaction re-read) |
| `reread_max_files` | 5 | source report |
| `skill_body_max_tokens` | 5,000 | source report |
| `skill_body_total_max_tokens` | 25,000 | source report |
| `auto_memory_max_lines` | 200 | source report |
| `auto_memory_max_bytes` | 25KB | source report |
| `subagent_read_budget_tokens` | 6,100 | source report (research read budget) |
| `subagent_result_budget_tokens` | 420 | source report (research return) |
| `subagent_summary_min_tokens` | 1,000 | source report (general return) |
| `subagent_summary_max_tokens` | 2,000 | source report (general return) |
| `context_window_tokens` | 200,000 | the default window the fractions are taken of |
| `todo_state_enabled` | `False` | Deep Agents v0.7 opt-in lesson |

The host sets these once, in `RuntimeConfig.context_thresholds`. When it
is `None` — the default — **every rule is off** and the runtime behaves
exactly as before. Northstar does not change observable behaviour
without a host asking for it; the switch is the contract.

### 2.2 Offload before summarize: the ordering is the rule

The order is not an implementation detail, it is the claim:

1. **Offload.** A tool result over `tool_result_offload_tokens` is
   written to `<workspace>/.northstar/offload/` and the provider payload
   gets a pointer: the path, the original size, a digest, and a short
   preview (first 10 lines, at most 4,000 bytes).
2. **Then, only if a cut is still needed**, the compaction summarizes
   what remains.

Why offload first: a summary is a lossy rewrite, and the lossy rewrite
is the thing the diviner slice showed to be dangerous (a dropped
qualifier becomes an apparent entitlement). An offload is not lossy —
the bytes are on disk, verbatim, and the pointer says where they are.
So the rule spends the *cheap, recoverable* option before the
*expensive, lossy* one.

The preview is bounded by bytes as well as lines. That is not in the
source report; it is Northstar's own fix for a real failure found while
wiring this up. `credential_detector.scan_for_credentials` is
**quadratic on long unbroken lines** (measured: 8,000 chars → 0.585 s,
16,000 chars → 2.335 s). A 30,000-token result is a single 120,000-char
line, and the 10-line preview put the whole thing back into the context
— a 20-second hang per request. Capping the preview at 4,000 bytes
brings it back to 0.09 s.

### 2.3 The offload is also screened

The offload moves bytes *out of the model's context*, not out of the
process's rules. So the bytes are passed through
`defensive_agent.sanitize_for_model` **before** they are written, and
the provider screening step is reordered to run *after* the context
rules. Otherwise the defensive scan would still pay the full quadratic
cost on the original text, which is exactly what the offload exists to
avoid.

### 2.4 Pointer recoverability

The word that matters for an agent that runs long is **recoverable**.
Every removal Northstar makes leaves a pointer that can be resolved
back to the exact bytes:

* an **offload** leaves a file on disk with a SHA-256 digest, the
  original token count, and the byte count. `OffloadPointer.render()`
  is what the model sees; the file is what the model (or a human, or
  the audit trail) can go back to.
* an **85% truncation** of a write/edit call leaves a `TruncatedCall`
  record with the path, the original argument size, and the argument
  keys. The *full* arguments stay in the durable transcript — the
  truncation is applied to the provider payload only. So the pointer
  resolves against the session record.
* a **post-compaction re-read** over `reread_path_only_tokens` leaves a
  path reference; the file itself is untouched on disk.
* a **subagent return** over budget is truncated *and marked* with a
  visible marker naming the subagent return budget. It is never
  silently dropped: a parent that cannot tell a short answer from a cut
  answer will act on a partial picture, and the run's own evidence
  would say the subagent "found nothing" when the finding was there and
  the budget ate it.

The invariant behind all four: **the durable record keeps the full
bytes; only the provider payload is reduced.** Northstar's transcript
is the archive; the request is the working set.

### 2.5 The relationship to the diviner's scope-qualifier check

The diviner slice (see `docs/design/scope-qualifier-check.md`) built a
check that re-derives a grant's scope from its *source line* at
dispatch time, because a qualifier dropped under compaction becomes an
apparent entitlement.

The obvious objection to this slice is that it makes that dropping more
likely: it removes bytes from the context on purpose. The two slices
answer to each other:

* The diviner's check reads the qualifier **from the grant's source
  line**, not from the compacted prose. So a compacted context cannot
  widen a scope even if the qualifier is gone from the context.
* The needle test (`tests/test_context_budget_needle.py`) proves this
  on the real path: a 30,000-token tool result whose *first line* is
  `scope-qualifier: folder X only` gets offloaded; the qualifier is
  still in the preview; a matching grant still runs; a grant with no
  fence is still refused; a *widened* fence is still refused; and the
  offloaded bytes on disk still carry the qualifier, so the check can
  resolve against the source.

So the two slices compose rather than conflict: this slice reduces the
context, and the diviner's check means a reduced context cannot lose a
fence. The check is what makes the removal safe; the removal is what
makes the check affordable.

### 2.6 The memory tax, measured

"Memory tax" is the share of a run's input that was *persistent
context* (re-read files, skill bodies, auto-memory) rather than *work*
(tool calls, tool results, model turns).

The methodology is deliberately simple and deliberately measured:

* `MemoryTaxLedger.record(source=, tokens=, kind=)` books every injected
  block, with its kind (`reread`, `skill`, `memory`, `skill_dropped`).
* The **denominator** is `state.total_input_tokens` — the sum of every
  provider input the run sent — not the peak. The peak alone is the
  wrong denominator: the rules exist to keep the *peak* down, so using
  the peak as the denominator would flatter the tax share. The peak is
  reported separately (`state.input_tokens`) because it is the number
  that decides whether a request fits.
* `tax_ratio = injected_tokens / total_input_tokens`.

The ETH Zurich study the frontier report cites (+20% / +23%) is a
**comparison, not Northstar's number**. Northstar's own share is
whatever the ledger says, and it is reported per run in
`report.context["memory_tax"]`. Nothing in this slice asserts a
percentage.

### 2.7 Todo-state recitation

Off by default, behind `ContextThresholds.todo_state_enabled`. Deep
Agents v0.7 (2026-07) made `TodoListMiddleware` opt-in after three task
categories showed slightly better reward and lower cost with it
disabled. Northstar has no todo recitation today; the switch exists so
that the first one is opt-in rather than inherited.

### 2.8 The summary trigger is separate from the offload

`summary_trigger_fraction` (default 0.85) decides when a summary is
produced. `window_pressure_fraction` (default 0.85) decides when old
write/edit calls become pointers. They are separate fields because the
LangChain evaluation practice is to drive the trigger *down* to 10–20%
to compare prompt variants, and doing that must not disable the offload
rules. Lowering the trigger to 0.15 makes compaction happen sooner and
more often; it does not change what a 30,000-token result costs.

## 3. Where the rules are wired

The rules are not a library with a docstring. Each one is on a real path.

| Rule | Seam | File |
| --- | --- | --- |
| tool-result offload | `AgentRuntime._generate` → `ContextController.apply_provider_rules` | `loop.py`, `context_controller.py` |
| 85% window truncation | same | `loop.py`, `context_controller.py` |
| offload before summarize | `AgentRuntime._compact` — the transcript is offloaded *before* `compact()` runs, and the compaction row records `tokens_before_offload` / `tokens_after_offload` / `offload_tokens_saved` | `loop.py` |
| post-compaction re-read | `AgentRuntime._reinject_context` → `ContextController.reinject_after_compaction` | `loop.py`, `context_controller.py` |
| skill-body cap | `_skill_bodies()` → `cap_skills` | `loop.py`, `context_budget.py` |
| auto-memory cap | `_auto_memory_text()` → `cap_memory` | `loop.py`, `context_budget.py` |
| subagent return budget | `AgentRuntime._subagent_result` | `loop.py` |
| memory tax | `ContextController.memory_tax`, reported in `report.context` | `context_controller.py` |

The **re-injection budget is a run budget, not a per-compaction one.** A
run that compacts twice must not pay for the same file twice: a file
already re-read in this run has not changed and the model already holds
the pointer. The same holds for the skill total budget — the budget is
on the skill context *in one request*, and a compaction drops the
previous injection, so the two injections are never live at the same
time.

## 4. Two real bugs this slice found and fixed

These were not test artifacts; they were live defects that the new path
exposed.

1. **The subagent truncation marker undid the truncation.**
   `_subagent_result` appended the "truncated" marker to
   `body_parts` and then rebuilt `body` from `body_parts` — restoring
   the uncapped text and discarding the very cap that had just been
   applied. The marker now goes onto the *capped* body.

2. **The credential detector is quadratic on long unbroken lines.**
   `scan_for_credentials` backtracks catastrophically on a long
   password/token pattern (measured: 8,000 chars → 0.585 s, 16,000
   chars → 2.335 s). A single-line 30,000-token tool result made the
   screening step take 20 seconds per request. The offload's
   byte-bounded preview and the reordered screening removed the
   exposure. The detector itself is unchanged — the defect remains in
   `credential_detector.py` and is worth a separate fix.

## 5. Open items

* The `credential_detector` quadratic is mitigated, not fixed.
* The subagent *read* budget (`subagent_read_budget_tokens`, 6,100) is
  recorded on the agent definition but is not yet enforced on the
  child's own tool reads; only the return budget is enforced.
* The window-pressure fraction is taken of a fixed
  `context_window_tokens` (200,000) rather than of the provider's real
  window, because Northstar does not yet read that from the provider.
* `summary_trigger_fraction` is configurable but is not yet wired to
  the runtime's own compaction trigger; the runtime still uses
  `RuntimeConfig.compaction_threshold_tokens`.
* The memory-tax ledger books *injected* context. It does not yet book
  the cost of the transcript's own growth (a run that never compacts
  has persistent context too).
* The tax ratio **under-counts** a block that persists across requests.
  The ledger books each injected block once, at the moment it is
  injected, but a block injected before request 5 is still carried by
  requests 6, 7 and 8. So `injected_tokens` is a *lower bound* on the
  persistent-context share of the input, and the ratio is a lower bound
  too. Booking per request instead would need the injection to be
  re-charged on every payload it survives into, which is a bigger change
  to the accounting than this slice should make.
