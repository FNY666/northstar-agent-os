# Concurrent ledger append, check-then-append, and the Infra flag

Status: **DRAFT** (B173 ageofagents slice, 2026-11-13).
Implemented on `batch-173-moltbook-absorb`.

New module: `components/northstar-agent-runtime/ledger_concurrency.py`
New tests: `components/northstar-agent-runtime/tests/test_ledger_concurrency.py`

## 1. What Northstar has today (read from the code, not assumed)

**`forward_seal_ledger.py` — the sealed decision ledger.** Its own
docstring says it plainly: *"a single-writer, in-memory, forward-secure
append-only log"*. The sequence number is assigned at
`forward_seal_ledger.py:355`:

```python
with self._lock:
    seq = len(self._records) + 1
```

`self._lock` is an in-process `threading.RLock`. So:

* **Sequence allocation is in-memory.** Two *processes* writing the same
  ledger would each derive `len(records) + 1` from their own copy and
  race. There is no cross-process sequence discipline anywhere in the
  module — the module has no file, no lock file, and no persistence at
  all. Its honest scope says so: *"State is in-memory; persistence, WORM
  archiving, and external anchoring are the host's job."*
* **There is no rule about concurrent writers.** Nothing in the module
  says what two writers must do. The tombstone registry consultation
  (`forward_seal_ledger.py:488-511`) is a check-and-consume that is
  atomic *within one process*, because it happens under the same
  `RLock` that serializes the chain.
* **Check-then-append is transactional only in-process.** The
  tombstone check and the seal land under one `RLock`, so within one
  process no writer can slip between the check and the write. Across
  processes, nothing prevents it.
* **There is no Infra concept.** `forward_seal_ledger.py` records an
  `outcome` string supplied by the caller and does not classify it; a
  search of the runtime component finds no `infra` verdict state and no
  three-state verification result. The receipts are two-state
  pass/fail: a check that never ran is recorded the same way as a check
  that ran and failed.

**`checkpoint_store.py`** — writes are atomic per path (temp file plus
rename) and serialized by a per-path `_WriteQueue`, but that queue is an
in-process `threading.Lock` map, so it does not span processes either.

**`approval_rules.py`** — `ToolApprovalState` is plain data: a list of
rules, a list of queued approval requests, a list of collected
responses. There is no transaction around "is this ticket still awaiting
approval?" — the state is a snapshot the host reads and mutates.

**`ledger.py`** — the double-entry bookkeeping ledger. It is explicitly
caller-sequenced: `DuplicateSeqError` is raised when the caller's seq is
not strictly increasing, and the docstring says *"caller-supplied int
seqs (strictly increasing per ledger)"*. The sequencing authority is the
caller, not the ledger.

So the gap this slice closes is narrow and real: **the sealed ledger
has no concurrent-writer discipline at all**, and the receipt world has
no Infra state.

## 2. The source

**ageOfAgents** — https://github.com/bharadwaj6/ageOfAgents (clone HEAD
`7f575ca`, 2026-10-09). A Go multi-agent orchestrator that drives real
coding agents (Claude Code / Codex / Grok) to green and merges the
changes, with gates and a SWE-bench evaluation adapter. It is the
closest structural match the sweep found to Northstar's shape.

Three passages are absorbed. Each is quoted **verbatim** from the source;
the Northstar reshaping is marked separately in every section.

### 2.1 Sidecar lock, gapless sequence, torn-tail repair

`Ledger.Append()` — `internal/ledger/ledger.go:100`.

> "Windows locks are mandatory — locking the log would make lock-free
> readers fail"

> "every Append, Update and Open holds an exclusive lock… so sequence
> numbers stay gapless."

> "a writer's half-written line is never mistaken for a crash"

### 2.2 The check-then-append transaction

`Ledger.Update()` — `internal/ledger/ledger.go:135`.

> "No other writer, in this process or another, can append between the
> read and the write, so a check made in decide ('is this key already on
> the log?', 'is this ticket still awaiting approval?') still holds when
> its events land. That is what makes a check-then-append idempotent
> under concurrent callers."

### 2.3 The Infra flag

`Verifier.Run()` — `internal/verify/verify.go:58`, and
`isDockerInfraFailure()` — `internal/verify/verify.go:98`.

> "An Infra failure says nothing about the proposal, so counting it as a
> rejection misattributes a broken environment to the agent's work."

> "Exit codes alone cannot tell a stopped daemon from a failing test:
> docker 29 exits 1 for both."

The source's classifier is Docker-specific: exit codes **125 / 126 /
127** (daemon / image / invocation failure) are infra, every other status
belongs to the tested command. It probes `docker version` *before* the
gate, so a stopped daemon is not misread as a failing test.

## 3. The design

### 3.1 The sidecar lock

`SidecarLock` takes the exclusive lock on **`<log path>.lock`**, never on
the log. The suffix `.lock` is the source's rule, kept as
`SOURCE_LOCK_SUFFIX = ".lock"`.

The consequence is the point: a reader may read the log while a writer
holds the lock, because the reader never touches the lock file. That is
the source's stated reason for the sidecar (the Windows mandatory-lock
rule), and it is the right rule on POSIX too — a lock on the log itself
would make readers block behind writers.

The lock is **advisory and cooperative**: it serializes writers that go
through this class. A writer that ignores the lock file is not stopped.
This is stated in the module docstring rather than glossed.

Implementation notes:

* `fcntl.flock(LOCK_EX | LOCK_NB)` on the sidecar file, retried until a
  deadline (`lock_timeout`, default 30 s) — so a stuck writer fails
  loudly instead of hanging forever.
* An in-process `threading.Lock` per sidecar path, acquired with a
  deadline, so two *threads* on one path are serialized even where
  `fcntl` is unavailable.
* The lock is **not reentrant**. `SidecarLock.hold()` is the `with` form;
  `acquire()` acquires exactly once. (An early draft used
  `with lock.acquire():`, which re-acquires through `__enter__` and
  deadlocks on a non-reentrant lock. That is why `hold()` exists.)

### 3.2 Gapless sequence

`_append_locked` runs entirely inside the sidecar lock:

1. repair a torn tail (§3.3),
2. re-read the log **inside** the lock,
3. `seq = last.seq + 1`, or `1` when the log is empty,
4. write the line, `flush`, `fsync`.

Because the sequence is derived from the file's state *at the moment of
the write*, and the write is inside the lock, two concurrent writers
cannot derive the same number and cannot leave a gap between them. The
sequence is 1-based, monotonic, and gapless.

The record carries its own digest: `record_hash` is
`sha256:` over the canonical `{seq, payload, idempotency_key}`. The
digest is a tamper pin, not a seal — sealing is
`forward_seal_ledger.py`'s job, and this module does not claim it.

### 3.3 Torn-tail repair

`_repair_tail_locked` is the source's `sync()` re-read, as a Northstar
method:

* The trailing line with no terminating newline is examined.
* If it parses as a whole event, the missing newline is written (the
  event was complete; only its terminator was lost).
* If it does not parse, it is a **torn tail** — a writer that died
  mid-write. The fragment is truncated away and the file is closed
  cleanly.
* A fragment that does not parse in the **middle** of the file is
  corruption, not a tail: `LogCorruptError` is raised (fail-closed).

Two guarantees the tests pin:

* a torn tail is **never counted as an event** — it takes no sequence
  number;
* a torn tail is **never reported as a crash** — the reader skips it and
  the next append continues the sequence cleanly.

### 3.4 The check-then-append transaction

`ConcurrentLedger.update(key=..., check=..., decide=..., payload_of=...)`
runs the read, the decision and the append inside **one** sidecar-lock
critical section:

* `check(events)` answers the question the decision depends on — the
  Northstar-shaped questions being *"is this key already on the log?"*
  and *"is this ticket still awaiting approval?"*. It sees the events as
  they are inside the lock.
* `decide(events)` computes the decision from the same snapshot.
* `payload_of(decision)` renders it into the event body.
* `key` is the **idempotency key**. If an event already exists under
  that key, `update` returns it and appends **nothing**.

So the check still holds when the event lands (no writer can interpose),
and two concurrent callers racing one decision land exactly **one**
event: the second caller sees the existing decision and returns it
with `landed=False`.

If `check` returns false, `LedgerConcurrencyError` is raised and **no
event is written** — a refused decision must not leave a hole in the
chain, the same rule `forward_seal_ledger.append_grant` follows when it
refuses a seal.

### 3.5 The Infra flag

Three states, not two:

| outcome | meaning |
| --- | --- |
| `passed` | the gate ran and passed |
| `failed` | the gate ran and the thing under test failed |
| `infra` | the gate **never ran** — the environment failed |

`VerificationResult` carries `outcome`, `detail` and `signal`, plus
`passed` / `failed` / `infra` properties. `tally(results)` counts the
three states in three separate buckets, so an infra result can never
raise the executor's failure count. That is the misattribution the
source warns about, made mechanical.

**Source (verbatim, Docker-specific):** `SOURCE_DOCKER_INFRA_EXIT_CODES
= (125, 126, 127)`. These are the source's own codes, kept in the module
so the mapping back to the source stays checkable. They are **not** used
by Northstar's classifier.

**Northstar extension (NOT from the source):** Docker's exit codes do
not transfer. Northstar's own infra signals are:

* `NORTHSTAR_INFRA_SIGNALS` — `relay_unavailable`,
  `relay_forbidden`, `relay_rate_limited`, `relay_bad_gateway`,
  `sandbox_unreachable`, `sandbox_start_failed`, `sidecar_down`,
  `timeout_environment`, `resource_exhausted_environment`.
* `NORTHSTAR_INFRA_HTTP_STATUS` — `403, 429, 502, 503, 504`. A relay
  that answers one of those never ran the gate, so the outcome is not
  the executor's failure.
* `NORTHSTAR_AGENT_FAILURE_SIGNALS` — `test_failed`, `assertion_failed`,
  `command_failed`, `lint_failed`, `build_failed`. These are the thing
  under test failing.

The signal lists are **explicit and closed**, and the two lists are
disjoint (asserted by a test). An unknown signal is *not* silently
treated as infra: it falls through to the executor's own failure. This
is the source's lesson applied: *"Exit codes alone cannot tell a stopped
daemon from a failing test"* — so Northstar does not classify from an
exit code alone either. A non-zero exit with no infra signal is the
executor's own failure.

## 4. Honest scope

* This module does **not** seal events. Sealing is
  `forward_seal_ledger.py`'s job; this module carries an opaque payload.
* It does **not** decide what to check. The caller supplies the check
  and the decision as callables.
* It does **not** detect forks. Two hosts showing different chains to
  two verifiers still look fine to each — the same gap
  `forward_seal_ledger.py` documents.
* The sidecar lock is advisory and cooperative.
* The idempotency key is per-log: two different keys never collapse into
  one event, and one key never yields two events.
* The log is JSON Lines; a corrupt middle line is fail-closed.

## 5. Open items

* **`pyproject.toml` declaration.** The runtime component's packaging
  test (`tests/test_module_layout.py::test_every_module_is_installed`)
  asserts every top-level module is listed in
  `[tool.setuptools] py-modules`. `ledger_concurrency` is not declared,
  because `pyproject.toml` is outside this slice's writable-file set.
  The test **already fails at the slice's parent commit** on the same
  list (`artifact_authority`, `cancellation_tombstone`,
  `ledger_concurrency`, `retry_config`, `strands_checkpoint`), so this
  slice adds no new failure — but the declaration is owed. Same open item
  as the `vina` slice (commit `831b0312`).
* **No cross-process test in this slice.** The gapless-sequence and
  idempotency guarantees are exercised with concurrent *threads* in one
  process. The sidecar lock is an `fcntl` lock, so the cross-process
  path exists, but a multi-process test (spawning interpreters) is left
  open: it needs a separate worktree-level harness and would slow the
  suite.
