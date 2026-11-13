# tool-output-filter — filter tool outputs in code before they enter a context

**Module:** `components/northstar-agent-runtime/tool_output_filter.py`
**Tests:** `components/northstar-agent-runtime/tests/test_tool_output_filter.py`
**Slice:** `B173 tool-output-filter`

## The gap

A tool output reaches a model's context the way it came off the tool. Today
Northstar has three detectors — `credential_detector.py` (credential shapes),
`injection_detector.py` (instruction forgeries), `context_budget.py` (size
budgets) — and one place where tool results are reduced before a provider
payload is built, `context_controller.py`. None of them is a gate that runs
*on the way in*.

What exists today, read from the code:

| concern | today |
| --- | --- |
| oversized tool result | `context_controller._offload_tool_results` offloads it to `OffloadStore` and replaces it with a pointer, but only when `should_offload_tool_result` says so — a **token** estimate (`context_budget.estimate_text_tokens`, 4 bytes/token), and only when the controller is wired in with a store |
| credentials | `credential_detector.scan_for_credentials` **detects and masks** them; the mask is first-2/last-2 characters, and the detector is read-only — nothing replaces the value in a body that is about to be read |
| injection | `injection_detector.scan_injection` finds forgeries; `context_controller._screen` calls `defensive_agent.sanitize_for_model`, which **rewrites matched spans in place** so the result "looks clean" |

The three exist, but not as one ordered gate with one receipt per layer, and
the sensitive-content path does not remove the value.

## What this slice adds

`tool_output_filter.py` is a gate. One body goes in; one `FilteredOutput`
comes out; the `output` field is the only thing a caller may put into a
context; the three `receipts` are the audit trail.

```
ToolOutputFilter(FilterConfig(...)).filter(body, name="tool-x")
    -> FilteredOutput(output, receipts, full_output_path,
                      truncated, redacted, redaction_count,
                      quarantined, injection_rules)
```

## The three layers, in the fixed order

### 1. Size cap — `size_cap`

* **Unit:** UTF-8 **bytes**. Not tokens. A token estimate is not reproducible
  across tokenizers; a byte count is.
* **Default cap:** `DEFAULT_MAX_BYTES = 80_000` bytes.
* **Preview:** the first `DEFAULT_PREVIEW_LINES = 10` lines, additionally
  bounded at `DEFAULT_PREVIEW_MAX_BYTES = 4_000` bytes, applied at *line*
  granularity.
* **Explicit:** the preview is preceded by a notice naming the total byte
  count and the path. A tail is never dropped silently.
* **Recoverable:** the full body is written verbatim to disk; the receipt
  carries the path and the SHA-256 of the body.

The preview is a **verbatim prefix** of the original: the lines are taken
whole, in order, and nothing is added to them. The byte bound is applied at
line granularity so that the preview is always "the original's first N
lines", character for character — a bound that cut a line in half would
break that promise.

### 2. Redaction — `redaction`

* **Patterns:** the shapes `credential_detector` already knows, reused rather
  than reinvented — same order (most specific first), same claiming rule
  (a span is claimed by the tightest pattern that matches it).
* **What is replaced:** only the **value**. The label of an assignment
  survives (`api_key: "[[REDACTED:api_key]]"`), and so does its closing
  quote. A multi-line match (a PEM block) is replaced by the placeholder plus
  the newlines it spanned, so the line numbering of everything after it is
  unchanged.
* **Placeholder:** `[[REDACTED:<credential type>]]` — fixed format, fixed
  vocabulary, greppable.
* **The receipt** records how many replacements and of which types. It does
  **not** record the value, not even masked: a receipt that leaks the first
  and last two characters of a secret is a partial disclosure.

The one pattern not reused verbatim is the JWT-shaped branch of the token
pattern: a JWT is `header.payload.signature`, and redacting only the
`Bearer` prefix would leave the secret in the body.

### 3. Injection scan — `injection_scan`

* **Patterns:** `injection_detector`'s vocabulary, narrowed by
  `INJECTION_RULE_ALLOWLIST`.
* **On a hit:** the body is **quarantined**. It is not passed, and it is not
  quietly rewritten to look clean. The context gets an explicit refusal
  naming the rule that fired and the path where the body is kept.

The allowlist is narrower than the detector's full vocabulary on purpose:

* `code-fence` and `bare-markdown-header` are excluded — almost any tool
  output containing a fenced block or a markdown heading would otherwise be
  quarantined, and a quarantine that fires on ordinary output is a
  quarantine people learn to switch off.
* `base64-blob` is excluded — machine output carries base64 payloads
  (certificates, images, attachments) and flagging them proves nothing.

What remains is forgery: instructions aimed at the model, and markers that
impersonate a role a tool has no right to claim.

## Why this order

1. **Size cap first** — redacting a megabyte nobody will read is wasted work.
2. **Redaction before injection scan** — the scanner must never read a
   secret. A scanner that sees a secret is a scanner that can report one.

The receipts prove the order: the injection layer's `input_bytes` is the
redaction layer's `output_bytes`, and the redaction layer's `input_bytes` is
the size layer's `output_bytes`.

## Configuration and honest degradation

Every layer has a switch (`enable_size_cap`, `enable_redaction`,
`enable_injection_scan`). All three are **on by default**. A layer that is
switched off still produces a receipt, and that receipt says:

```json
{"layer": "redaction", "enabled": false, "action": "skipped",
 "reason": "disabled_by_configuration", ...}
```

There is no silent degradation. A filter that silently stops filtering is
worse than no filter at all.

## Scope and honest limits

* This module governs **what enters a model's context**. It does not claim
  at-rest hygiene: the file it writes for an oversized body holds the body
  **as produced**, so a host that needs secrets redacted on disk must apply
  `redact_credentials()` to the stored copy itself.
* A clean scan is evidence of "no known pattern matched", never proof of
  "no injection".
* The module is a library, not a wiring change. `context_controller.py` is
  **not** modified by this slice; a host adopts the gate by calling
  `ToolOutputFilter.filter()` on the body before it enters a context.
* **The module is not declared in `pyproject.toml`.** The runtime
  component's `test_module_layout.test_every_module_is_installed` asserts
  that every module on disk appears in `[tool.setuptools] py-modules`. That
  test already fails at this slice's parent commit — with
  `annotation_pin`, `artifact_authority`, `cancellation_tombstone`,
  `coverage_manifest`, `endpoint_identity`, `evidence_independence`,
  `key_custody`, `ledger_concurrency`, `retry_config`, `state_budget` and
  `strands_checkpoint` undeclared — and `tool_output_filter` joins the same
  list, so **no new test failure appears**. The declaration is still owed;
  this slice's writable-file set covers only the module, its tests and this
  design doc, so it is left to the slice that owns the packaging metadata.

## Mapping to the source

Verbatim from the source (see below) — these are the source's numbers and
claims, quoted as they stand:

* "Letting Opus 4.6 filter its own tool outputs in code (rather than
  streaming raw results through context) raised BrowseComp 45.3% → 61.6%."
  — Harness debt (AI Heroes, frontier #15, rank 1), quoting Anthropic's
  Opus 4.6 system card. **Second-hand reference**: the blog is commentary,
  not the primary measurement.
* "Opus 4.6 equipped with an experimental scaffold achieved over twice the
  performance of our standard scaffold" — same source, same second-hand
  status.
* The consequence boundaries the source keeps: "confirmation gates,
  staleness checks, structured logging, permission boundaries".
* Deep Agents writes a tool response above **20,000 tokens** to disk and
  keeps a path plus the **first 10 lines** — the context-engineering review
  (frontier #4) reporting the Deep Agents rule.

Northstar extensions (ours, not the source's):

* The unit is **bytes**, not tokens, and the default cap is
  `20_000 tokens × 4 bytes/token = 80_000 bytes`, using this repository's
  own `context_budget.BYTES_PER_TOKEN`. The source's rule is a *token*
  rule; we keep the rule and change the unit to something reproducible.
* `preview_max_bytes = 4_000` — our own bound, mirroring the reasoning in
  `context_budget.DEFAULT_OFFLOAD_PREVIEW_MAX_BYTES`: a line count is not a
  bound on one enormous line.
* `INJECTION_RULE_ALLOWLIST` — our narrowing of the detector's vocabulary.
* The receipt shape, the placeholder format `[[REDACTED:<type>]]`, and the
  quarantine-not-rewrite decision are Northstar's.

## Source

* Harness debt (AI Heroes, frontier #15, rank 1):
  https://www.ai-heroes.co/en-us/blog/ai-agent-harness-debt-2026
* The 20,000-token / 10-line numbers are the Deep Agents rule as reported in
  the context-engineering review (frontier #4), and are already encoded in
  `context_budget.py` — this slice reuses that rule, in bytes.
