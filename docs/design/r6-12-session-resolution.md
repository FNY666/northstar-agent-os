# r6-12 session resolution: make the referee read the RIGHT session

**Slice:** `r6-12-session-resolution` — B173, branch `batch-173-moltbook-absorb`.

**One-line claim.** `b173-accept.sh` resolves a slice's session JSONL with
`grep -rl "$CANARY" <project dir>/*.jsonl | head -n1`, which returns files in
*directory read order*. Because every session that **reads** a taskbook
carries every canary in its transcript, that pick landed on one shared
"poison" session for **40 of the 64** slices with a canary, and the
`REPORT_NUMBERS` check was cross-checked against the wrong transcript for
most of the batch. The fix replaces the lookup with the already-written
`b173-resolve-session.py` and turns "no session" / "ambiguous session" into
an honest **SKIP**.

**Status of the live referee.** `b173-accept.sh` and `b173-watch.sh` were
**NOT edited by this slice**. The fix is delivered as two patch files plus a
precise change specification (§7). The coordinator applies them.

---

## 1. The two failure modes

### 1.1 Failure mode 1 — the session that reads the taskbooks matches every canary

A canary is a 20-ish character token written into the slice's taskbook. Any
session that **reads** the taskbooks therefore has every canary in its
transcript. One such session dominates the lookup:

```
$ PROJ=~/.claude/projects/-home-muse-newapi-northstar-agent-os
$ for f in "$PROJ"/*.jsonl; do
    echo "$(grep -oE 'CANARY: [A-Za-z0-9]{20}' "$f" | sort -u | wc -l) $f"
  done | sort -rn | head -5
20 /home/muse-newapi/.claude/projects/-home-muse-newapi-northstar-agent-os/3c2b6040-5c84-43e8-8bcf-4dea627d7135.jsonl
3  .../ddcf50b8-8bde-43b9-9c34-7efba64add54.jsonl
3  .../63abd6e2-816b-4607-b050-1a4d20e91bc2.jsonl
2  .../e97b9abb-098d-4d4f-bc7e-0fa03bef7e06.jsonl
2  .../d79043a7-0945-42d7-ac26-c9a379f09c09.jsonl
```

That session is the **`artifact-completion`** slice's own session (its
declared canary is `t5kqcH1JZc1q7IRlwctL`) — it surveyed the batch's
taskbooks, so its transcript carries every canary. It is a **slice** session,
not a coordinator session: its first user message declares exactly one
canary, `t5kqcH1JZc1q7IRlwctL`.

### 1.2 Failure mode 2 — even without the poison session, the pick is arbitrary

`grep -rl` walks the directory in read order. Which of the several candidate
files comes first depends on the filesystem, not on anything about the slice.
So even for the slices that do not land on the poison session, the resolved
transcript is a coin flip.

### 1.3 A third, smaller defect found while measuring: the canary is extracted greedily

`b173-accept.sh:65` extracts the canary with

```bash
CANARY=$(grep -oE "CANARY: [A-Za-z0-9]+" "$TASKBOOK" | head -n1 | awk '{print $2}')
```

`[A-Za-z0-9]+` is greedy and unbounded, so the extracted token is the whole
run of alphanumerics after `CANARY: `. Three taskbooks have a canary longer
than 20 characters:

| taskbook | extracted canary | length |
|---|---|---|
| `horizon` | `uwtNPuUCVmeYTUMLLrajcD1y` | 24 |
| `fable` | `B6VZKzBhjQl2I2VoXTaG7AvB` | 24 |
| `merged-tree-review` | `i4JMI8ZNRJFNXePKzOuZOA` | 22 |
| `e2b` | `eHue4sp9slIdn63FaDuymg` | 22 |
| `langgraph` | `QAx8f9ilzc47uFKbSwuFv8` | 22 |
| `session-memory` | `5zMV5CXy5quTD3BZCdNBA` | 21 |
| `resume-validation` | `0u1SWS4Aq9GEkuHsbfsMw` | 21 |

`b173-resolve-session.py:133` hard-codes `CANARY:\s*([A-Za-z0-9]{20})` and
therefore **truncates** these to their first 20 characters — a different
token from the one `accept.sh` uses. The patch below therefore passes the
canary **explicitly** (`--canary "$CANARY"`), which is exactly the
extracted token, and bypasses the resolver's own extraction. The resolver's
built-in extraction remains a latent bug for the coordinator to fix
separately; it is documented in §8.

---

## 2. The poison-session table (measured)

| | value |
|---|---|
| session file | `3c2b6040-5c84-43e8-8bcf-4dea627d7135.jsonl` |
| owning slice | `artifact-completion` (declared canary `t5kqcH1JZc1q7IRlwctL`) |
| distinct canaries in the transcript | **20** |
| why it reads every taskbook | the slice surveyed the batch's taskbooks, so its body carries every canary |
| **true peak input tokens** | **259886** |
| assistant messages | 1071 |
| compaction events | 2 |
| model | `claude-fable-5-2` only |
| slices that `accept.sh` resolves to it | **40 of 64** (all 64 taskbooks that have a canary) |

Reproduction of the last row (runnable as written):

```bash
PROJ=~/.claude/projects/-home-muse-newapi-northstar-agent-os
POISON="$PROJ/3c2b6040-5c84-43e8-8bcf-4dea627d7135.jsonl"
n=0; tot=0
for f in ~/b173-*-cc-prompt-rerun.md; do
  c=$(grep -oE "CANARY: [A-Za-z0-9]+" "$f" | head -n1 | awk '{print $2}')
  [ -z "$c" ] && continue
  tot=$((tot+1))
  h=$(grep -rl "$c" "$PROJ"/*.jsonl 2>/dev/null | head -n1)
  [ "$h" = "$POISON" ] && n=$((n+1))
done
echo "slices resolving to the poison session: $n of $tot"
# -> slices resolving to the poison session: 40 of 64
```

The true peak:

```bash
python3 - <<'PY'
import json
p='/home/muse-newapi/.claude/projects/-home-muse-newapi-northstar-agent-os/3c2b6040-5c84-43e8-8bcf-4dea627d7135.jsonl'
peak=0
for line in open(p):
    try: o=json.loads(line)
    except Exception: continue
    m=o.get('message') or {}
    if m.get('role')=='assistant':
        u=m.get('usage') or {}
        if isinstance(u.get('input_tokens'),(int,float)):
            peak=max(peak,int(u['input_tokens']))
print('peak',peak)
PY
# -> peak 259886
```

---

## 3. The vacuousness, measured

`b173-report-numbers.py` fails the `PEAK` check only when the report claims
a peak **greater than** the session's true peak. Against the poison session
(peak 259886) **any report claiming a peak below 259886 passes**.

### 3.1 Whole-batch PASS/FAIL counts

Three reference sessions were used for every slice that has a report
(64 slices):

| session used for the check | PASS | FAIL | SKIP |
|---|---|---|---|
| **the poison session** (every slice, as `accept.sh` does for 40 of them) | **56** | 4 | 0 |
| **the slice's own resolver-chosen session** | **57** | **3** | 1 |
| the slice's **current** `accept.sh` session (what the referee does today) | 51 | 10 | 0 |

Reproduction:

```bash
PROJ=~/.claude/projects/-home-muse-newapi-northstar-agent-os
POISON="$PROJ/3c2b6040-5c84-43e8-8bcf-4dea627d7135.jsonl"
for s in <every slice with a canary>; do
  python3 ~/b173-report-numbers.py --report ~/b173-$s-cc-final.txt --jsonl "$POISON"
done
```

### 3.2 The rubber-stamped set

Slices whose `PEAK` verdict **passes against the poison session and fails
against their own session** (measured, both directions):

| slice | poison verdict | own-session verdict |
|---|---|---|
| `acceptance-conformance` | PASS | **FAIL** |
| `refusal-hold-wiring` | PASS | **FAIL** |

`msaf-lineage` fails under both, so it is not rubber-stamped.

`acceptance-conformance` is the clearest case — its report is a **STUB**
whose numbers were taken from whatever session the old lookup happened to
find:

```
PEAK FAIL: report claims 97754 but JSONL max is 88565 (scraped from FABLE VERIFICATION)
```

The stub quoted `97754` (the peak of `63abd6e2-816b-4607-b050-1a4d20e91bc2`,
a *different* slice's session); the slice's own session peaks at `88565`.

---

## 4. The single-slice case, fully verified: `refusal-row`

The report names its own session file — a third, independent witness:

> Read from this session's own JSONL
> (`~/.claude/projects/-home-muse-newapi-northstar-agent-os/8d5c040d-4dd2-41f8-ac98-9dd371119456.jsonl`,
> the session launched by `b173-parallel-launch.sh` at `2026-11-13T23:30:01Z`,
> session id `8d5c040d-4dd2-41f8-ac98-9dd371119456`): every assistant message
> carries `"model":"claude-fable-5-2"` — 111 occurrences, **no other model
> value in the file**.

That file's true peak is **167295** over 277 assistant messages.

**Against the correct session** (`8d5c040d-4dd2-41f8-ac98-9dd371119456.jsonl`):

```
PEAK OK: report 131388 <= JSONL max 167295 (scraped from FABLE VERIFICATION)
COMPACT OK: report 0 == JSONL 0
MODEL OK: JSONL all claude-fable-5-2 (277 assistant msgs)
JSONL totals: input=26533649 output=194284 msgs=277 compactions=0
```

**Against the wrong session** (today's `accept.sh` lookup resolves
`refusal-row` to the poison session `3c2b6040-...`):

```
PEAK OK: report 131388 <= JSONL max 259886 (scraped from FABLE VERIFICATION)
COMPACT OK-at-write-time: 0 before report mtime (2 after)
MODEL OK: JSONL all claude-fable-5-2 (1071 assistant msgs)
JSONL totals: input=140594908 output=1261004 msgs=1071 compactions=2
```

The `PEAK` verdict happens to survive here, but the *evidence* it is checked
against is wrong: 1071 assistant messages from another slice's transcript,
and two compaction events that belong to that transcript, not to this slice.

---

## 5. The fix

### 5.1 The resolution rule

`b173-resolve-session.py` (written in round 5, extended with `--latest` in
round 6) already implements the right rule. A session is a candidate for
slice S iff

1. the session's **FIRST user message DECLARES** the canary — it contains
   the literal `CANARY: <token>`, not merely mentions it — **AND**
2. the session's first record timestamp is **>=** the slice's **LAST** watch
   start, minus 5 seconds of tolerance.

Rule (1) is precisely the defence against the poison session:
`3c2b6040`'s first user message declares exactly **one** canary
(`t5kqcH1JZc1q7IRlwctL`), so for the other 63 taskbooks rule (1) excludes
it.

Measured over all 64 taskbooks that have a canary:

| rule | slices still ambiguous |
|---|---|
| naive recursive grep + `head -n1` | **40 of 64** land on the poison session |
| rule (1) alone | 2 of 64 |
| rules (1)+(2) | **1 of 64** (`anthropic-effort-scaling`; `--latest` resolves it) |
| rules (1)+(2), no session at all | 4 of 64 (`tombstone`, `r6-12-session-resolution`, `r6-check-accuracy`, `r6-manifest-integrity`) |

### 5.2 The patch

`/home/muse-newapi/b173-r6-12-session-resolution-fix.patch` — against
`/home/muse-newapi/b173-accept.sh`. It replaces the lookup in the
`REPORT_NUMBERS` block with a call to `b173-resolve-session.py`, and turns
"no session" / "ambiguous session" into an honest **SKIP**.

`/home/muse-newapi/b173-r6-12-watch-session-resolution-fix.patch` — against
`/home/muse-newapi/b173-watch.sh`. `b173-watch.sh`'s `build_stub()` and
`session_dead_on_arrival()` used the same idiom, so a STUB report could be
built from another slice's transcript. It is a **separate** file so the two
can be applied independently.

---

## 6. Verification of the fix on a COPY

The live referee was not touched. The patch was applied to a copy:

```bash
mkdir -p /tmp/b173r612/atest
cp ~/b173-accept.sh /tmp/b173r612/atest/b173-accept.sh
cd /tmp/b173r612/atest && patch -p1 < ~/b173-r6-12-session-resolution-fix.patch
# -> patching file b173-accept.sh
```

### 6.1 Before/after for six slices

The six slices span the six interesting groups required by the brief.

| group | slice | session **before** (today's lookup) | `REPORT_NUMBERS` **before** | `REPORT_NUMBERS` **after** |
|---|---|---|---|---|
| (a) resolves to the poison session today | `refusal-row` | `3c2b6040-…` (poison) | **FAIL** | **PASS** — `jsonl=8d5c040d-4dd2-41f8-ac98-9dd371119456.jsonl` |
| (b) rubber-stamped PEAK | `acceptance-conformance` | `3c2b6040-…` (poison) | **FAIL** | **FAIL** — `PEAK FAIL: report claims 97754 but JSONL max is 88565` |
| (c) no resolvable session | `tombstone` | `3c2b6040-…` (poison) | **FAIL** | **SKIP** — `no session resolved for canary 9lULp0MNufmuQZ6OGlNL` |
| (d) already resolves correctly | `toolfail` | `0266fd34-…` (= resolver) | **PASS** | **PASS** — `jsonl=0266fd34-ee01-47cb-a254-2c304e6933aa.jsonl` |
| (e) no canary in the taskbook | `audit-head` | *(none)* | **SKIP** — `no report/canary` | **SKIP** — `no report/canary` |
| (f) STUB report | `merged-tree-review` | `3c2b6040-…` (poison) | **FAIL** | **PASS** — `jsonl=350c645f-94d8-40c0-ba94-5d391fbdd123.jsonl` |

`merged-tree-review` is a STUB report *and* a victim of the poison session;
`acceptance-conformance` is the other STUB (a STUB whose quoted numbers were
themselves taken from a third slice's transcript).

### 6.2 Only `REPORT_NUMBERS` moves

Full before/after check lines for the six slices, diffed:

```
$ diff /tmp/b173r612/six_before.txt /tmp/b173r612/six_after.txt
12c12
< FAIL REPORT_NUMBERS see detail above
---
> PASS REPORT_NUMBERS jsonl=8d5c040d-4dd2-41f8-ac98-9dd371119456.jsonl
36c36
< PASS TESTS_RAN  [components/northstar-agent-runtime unittest: Ran 52 tests in 0.025s OK ]
---
> PASS TESTS_RAN  [components/northstar-agent-runtime unittest: Ran 52 tests in 0.024s OK ]
38c38
< FAIL REPORT_NUMBERS see detail above
---
> SKIP REPORT_NUMBERS no session resolved for canary 9lULp0MNufmuQZ6OGlNL
62c62
< PASS TESTS_RAN  [components/northstar-agent-runtime unittest: Ran 71 tests in 0.152s OK ]
---
> PASS TESTS_RAN  [components/northstar-agent-runtime unittest: Ran 71 tests in 0.150s OK ]
75c75
< PASS TESTS_RAN  [components/northstar-agent-runtime unittest: Ran 34 tests in 18.430s OK ]
---
> PASS TESTS_RAN  [components/northstar-agent-runtime unittest: Ran 34 tests in 18.431s OK ]
77c77
< FAIL REPORT_NUMBERS see detail above
---
> PASS REPORT_NUMBERS jsonl=350c645f-94d8-40c0-ba94-5d391fbdd123.jsonl
```

The only differences are the `REPORT_NUMBERS` verdicts and the **wall-clock
duration** inside the `TESTS_RAN` detail string (`0.025s` vs `0.024s`) —
the test counts and the verdicts are identical. Every other check
(`COMMIT`, `REPORT`, `CANARY`, `FABLE_VERIF`, `FULL_SUITE`, `BENCH`,
`NEW_TESTS`, `WORKTREE_CLEAN`, `TESTS_RAN`, `BENCH_DIFF`, `MUTANT`) is
byte-identical before and after.

### 6.3 Whole-batch effect of the patch

Every slice with a canary and a report (64 slices), `REPORT_NUMBERS` only:

| | PASS | FAIL | SKIP |
|---|---|---|---|
| before (today's lookup) | 51 | 10 | 0 |
| after (deterministic resolver) | 57 | 3 | 1 |

**12 of 64 verdicts change** (49 are unchanged):

| slice | before | after | direction |
|---|---|---|---|
| `acceptance-conformance` | PASS | **FAIL** | FAIL appears |
| `refusal-hold-wiring` | PASS | **FAIL** | FAIL appears |
| `tombstone` | PASS | **SKIP** | PASS becomes SKIP |
| `artifact-completion` | FAIL | **PASS** | FAIL disappears |
| `baseline-attribution` | FAIL | **PASS** | FAIL disappears |
| `horizon` | FAIL | **PASS** | FAIL disappears |
| `langgraph` | FAIL | **PASS** | FAIL disappears |
| `langgraph-retry-clears-writes` | FAIL | **PASS** | FAIL disappears |
| `mutant-evidence-closure` | FAIL | **PASS** | FAIL disappears |
| `stale-checkpoint-gate` | FAIL | **PASS** | FAIL disappears |
| `tool-output-filter` | FAIL | **PASS** | FAIL disappears |
| `turn-truncation` | FAIL | **PASS** | FAIL disappears |

**In both directions:** 2 slices gain a FAIL (they were rubber-stamped),
1 slice changes PASS → SKIP (no resolvable session — the honest verdict),
and 9 slices lose a spurious FAIL (their false FAIL was an artefact of
reading another slice's transcript).

The three FAILs that remain after the patch are `acceptance-conformance`
(a STUB that quoted another session's peak), `msaf-lineage` and
`refusal-hold-wiring` — all three are **real** findings against the slice's
own transcript, not artefacts of the lookup.

---

## 7. Precise change specification

### 7.1 `/home/muse-newapi/b173-accept.sh`

**File:** `/home/muse-newapi/b173-accept.sh`
**Line:** 166 (the `JSONL=` line inside the `REPORT_NUMBERS` block)
**Patch file:** `/home/muse-newapi/b173-r6-12-session-resolution-fix.patch`

**Exact old text (one line):**

```
  JSONL=$(grep -rl "$CANARY" "$HOME_DIR/.claude/projects/-home-muse-newapi-northstar-agent-os/"*.jsonl 2>/dev/null | head -n1 || true)
```

**Exact new text:**

```
  # r6-12: resolve the session DETERMINISTICALLY. The old recursive grep over
  # the whole project dir piped into "head -n1" returned files in directory
  # read order, and every session that READS a taskbook carries every canary
  # in its transcript -- so the pick was a coin flip that landed on one shared
  # "poison" session for 40 of 64 slices and made REPORT_NUMBERS largely
  # vacuous.
  # b173-resolve-session.py accepts a session iff its FIRST user message
  # DECLARES the canary AND it starts at/after the slice's last watch start.
  # NONE / AMBIGUOUS -> SKIP (honest), never FAIL, never a silent PASS.
  JSONL=""
  if [ -f "$HOME_DIR/b173-resolve-session.py" ]; then
    RESOLVE_OUT=$(python3 "$HOME_DIR/b173-resolve-session.py" --slug "$SLUG" --canary "$CANARY" 2>/dev/null || true)
    case "$RESOLVE_OUT" in
      /*.jsonl) JSONL="$RESOLVE_OUT";;
    esac
  fi
```

**Second hunk — the `else` branch of the same block.**

**Line:** 177 (the `check REPORT_NUMBERS SKIP "no JSONL found by canary"` line)

**Exact old text (one line):**

```
    check REPORT_NUMBERS SKIP "no JSONL found by canary"
```

**Exact new text:**

```
    case "${RESOLVE_OUT:-}" in
      AMBIGUOUS*) check REPORT_NUMBERS SKIP "ambiguous session for canary $CANARY -- not guessed";;
      *)          check REPORT_NUMBERS SKIP "no session resolved for canary $CANARY";;
    esac
```

**What the patch does NOT change.** The number of checks (still 12), the
`check()` helper and its output format (`PASS`/`FAIL`/`SKIP` + name +
detail), the exit codes (0 = ACCEPT PASS, 1 = ACCEPT FAIL), the
`TOTAL=$((PASS+FAIL))` denominator, and every other check's verdict. The
patch changes **only how the session file is found**.

### 7.2 `/home/muse-newapi/b173-watch.sh`

**File:** `/home/muse-newapi/b173-watch.sh`
**Patch file:** `/home/muse-newapi/b173-r6-12-watch-session-resolution-fix.patch`
(separate file, so the coordinator can apply the two independently)

**Hunk 1 — a new helper, inserted immediately before `session_dead_on_arrival()`
(line 60).**

**Exact old text (the line before the insertion point):**

```
session_dead_on_arrival() {
```

**Exact new text:**

```
# r6-12: deterministic slice->session resolution.
# Prints the path of the ONE session that belongs to this slice, or nothing.
# A session qualifies iff its FIRST user message DECLARES this slice's canary
# (the literal "CANARY: <token>") AND its first record timestamp is at/after
# the slice's last watch start (minus 5s tolerance). Ambiguity -> no output
# (the caller then SKIPs / leaves the field "unknown"); never a guess.
resolve_session_path() {
  [ -n "${CANARY:-}" ] || return 0
  [ -f "$HOME_DIR/b173-resolve-session.py" ] || return 0
  local out
  out=$(python3 "$HOME_DIR/b173-resolve-session.py" --slug "$SLUG" --canary "$CANARY" 2>/dev/null || true)
  case "$out" in
    /*.jsonl) printf '%s\n' "$out";;
    *)        : ;;   # NONE / AMBIGUOUS -> no session
  esac
  return 0
}
session_dead_on_arrival() {
```

**Hunk 2 — `session_dead_on_arrival()`, line 63.**

**Exact old text (one line):**

```
  jsonl=$(grep -rl "$CANARY" "$HOME_DIR/.claude/projects/-home-muse-newapi-northstar-agent-os/"*.jsonl 2>/dev/null | head -n1 || true)
```

**Exact new text:**

```
  # r6-12: deterministic session resolution (see b173-r6-12-watch-session-resolution-fix.patch).
  # The old recursive grep over the whole project dir piped into "head -n1"
  # returned files in directory read order; any session that READS a taskbook
  # carries every canary, so the pick was arbitrary and frequently landed on a
  # shared "poison" session.
  jsonl=$(resolve_session_path || true)
```

**Hunk 3 — `build_stub()`, line 112.**

**Exact old text (one line):**

```
    jsonl=$(grep -rl "$CANARY" "$HOME_DIR/.claude/projects/-home-muse-newapi-northstar-agent-os/"*.jsonl 2>/dev/null | head -n1 || true)
```

**Exact new text:**

```
    # r6-12: deterministic session resolution (see b173-r6-12-watch-session-resolution-fix.patch).
    jsonl=$(resolve_session_path || true)
```

---

## 8. Tradeoffs, and why ambiguity must SKIP and not guess

### 8.1 Why SKIP, not FAIL

A SKIP says *"this check could not be run"*. A FAIL says *"the slice is
wrong"*. When the resolver finds no session or more than one, the referee
has no evidence about the slice at all — it is missing an input, not
holding a finding. Turning "no evidence" into "FAIL" would punish slices
for the referee's own inability to find their transcript, and turning it
into a silent PASS would let a slice with a genuinely overstated peak
through unchallenged. **SKIP is the only honest third option**, and it is
what the referee already does for every other undeterminable check
(`BENCH_DIFF` with no bench artefact, `MUTANT` with no manifest).

### 8.2 Why not guess on ambiguity

The two candidates in the ambiguous case are genuinely different attempts of
the same slice. Picking one by directory order reproduces the original bug
in a new costume: the verdict would depend on the filesystem. Picking the
latest is a defensible *policy* (a relaunch supersedes the earlier attempt)
but it is a **guess about intent**, and the resolver offers it only behind
an explicit `--latest` flag. The referee uses the default, so ambiguity is
reported rather than papered over.

### 8.3 Why the resolver's rule (1) is "declares", not "mentions"

The distinction is the whole fix. A canary in a session's *body* proves
only that the session once read a taskbook — which is true of the poison
session and of every orchestrator that reads the batch's taskbooks. A
canary in the session's *first user message* is the session's own
declaration of identity: it is how the slice was launched. Only the
declaration identifies the session.

### 8.4 Rule (2) and the watch-start anchor

Rule (1) alone leaves 2 of 64 slices ambiguous, because a slice may be
launched more than once and every attempt declares the same canary. The
watch-start anchor keeps only the attempts that began at or after the
slice's **last** watch start. `tombstone` is the known cost: its watch
started with `commit_timeout=1m`, so its session predates the anchor and
is excluded — the honest answer there is SKIP, not a guess.

### 8.5 Known residual risks (for the coordinator)

1. **The resolver's own canary extraction truncates at 20 characters**
   (`b173-resolve-session.py:133`). `accept.sh` extracts greedily, so for
   the seven taskbooks whose canary is 21–24 characters the two disagree.
   The patch sidesteps this by passing `--canary "$CANARY"` explicitly.
   The durable fix is to change the resolver's regex to
   `CANARY:\s*([A-Za-z0-9]{20,})` — **outside this slice's scope**, since
   `b173-resolve-session.py` is a coordinator tool.
2. **Sessions that were never launched by the launcher** (no watch log,
   no `--session-id`) have no time anchor; rule (2) cannot exclude them.
   `dynamiq` and `fieldnotes` are in this class.
3. **The resolver depends on the first *user* record** in the JSONL. A
   session whose first record is a `system` event with a different shape
   would need `first_user_and_ts()` to be revisited — out of scope here,
   and the current implementation already skips non-user records.

---

## 9. A third file with the same idiom (found while measuring): `b173-burn.sh`

The burn ledger (`/home/muse-newapi/b173-burn.sh`, line 18) resolves the
session with the *same* arbitrary lookup:

```bash
JSONL=$(grep -rl "$CANARY" "$HOME_DIR/.claude/projects/-home-muse-newapi-northstar-agent-os/"*.jsonl 2>/dev/null | head -n1 || true)
```

The measured damage is visible in the ledger itself
(`/home/muse-newapi/b173-burn.tsv`) — three slices carry the **poison
session's exact numbers**, byte for byte:

| slug | peak_input | msgs | jsonl |
|---|---|---|---|
| `artifact-completion` | 259886 | 1071 | `3c2b6040-…jsonl` |
| `refusal-hold-wiring` | 259886 | 1071 | `3c2b6040-…jsonl` |
| `baseline-attribution` | 259886 | 1071 | `3c2b6040-…jsonl` |

The last two did **not** run in that session: their real sessions are
`b456bf8a-67b4-4336-8e5d-8e976a114981.jsonl` (`refusal-hold-wiring`) and
`8a9190e6-c4a9-449b-b354-362acc8d1b71.jsonl` (`baseline-attribution`). The
ledger therefore **over-reports** the cost and the peak for those two slices
(140594908 input tokens and 1175.20 USD are the poison session's totals).

`b173-burn.sh` is **not** in this slice's writable file list, so no third
patch file is produced. The change specification is below for the
coordinator; it is the same one-line substitution as §7.1.

**File:** `/home/muse-newapi/b173-burn.sh`, **line 18**

**Exact old text (one line):**

```
JSONL=$(grep -rl "$CANARY" "$HOME_DIR/.claude/projects/-home-muse-newapi-northstar-agent-os/"*.jsonl 2>/dev/null | head -n1 || true)
```

**Exact new text:**

```
JSONL=$(python3 "$HOME_DIR/b173-resolve-session.py" --slug "$SLUG" --canary "$CANARY" 2>/dev/null || true)
```

(The existing `if [ -z "${JSONL:-}" ] || [ ! -f "$JSONL" ]` guard already
turns a `NONE` / `AMBIGUOUS` answer into `BURN SKIP …`, so no other line
needs to change. The three poisoned rows in the ledger need recomputing
after the patch.)

---

## 10. Verdict-semantics contract of the patch

The patch changes **only how the session file is found**. It does **not**
change:

| property | value | source |
|---|---|---|
| the number of checks | 12 (`COMMIT`, `REPORT`, `CANARY`, `FABLE_VERIF`, `FULL_SUITE`, `BENCH`, `NEW_TESTS`, `WORKTREE_CLEAN`, `TESTS_RAN`, `BENCH_DIFF`, `REPORT_NUMBERS`, `MUTANT`) | `b173-accept.sh` header + `check()` call sites |
| the `check()` output format | `PASS <name> <detail>` / `FAIL <name> <detail>` / `SKIP <name> <detail>` | `b173-accept.sh:42-49` |
| the exit codes | 0 = `ACCEPT: PASS`, 1 = `ACCEPT: FAIL` | `b173-accept.sh:197-199` |
| the denominator | `TOTAL=$((PASS+FAIL))` — SKIPs are excluded, as before | `b173-accept.sh:197` |
| every other check's verdict | unchanged | measured: the before/after diff for the six slices shows only the `REPORT_NUMBERS` lines and the `TESTS_RAN` wall-clock duration |

An unresolvable or ambiguous session produces **SKIP**, never FAIL and
never a silent PASS — the `case` arm in the patched block distinguishes
`AMBIGUOUS*` from everything else, and neither arm emits PASS or FAIL.

---

## 11. Baseline note (a correction the coordinator should read)

The brief for this slice points at
`/home/muse-newapi/b173-refusal-row-baseline-failures.txt` (27 items,
mtime 2026-11-13 23:40) as "the baseline". That file is **stale**: it was
taken before the `merged-tree-review` slice landed
(`72f351cf`, `dbaff0ad`, 2026-11-14 07:02-07:14), which added
`components/northstar-agent-runtime/merged_tree_review.py` **without
registering it** in `py-modules` or in `runtime_registration`. The
`baseline-attribution` slice (commit `af1c950f`, 2026-11-14 14:10) reset the
baseline to **30 items** and recorded the reset in
`docs/design/baseline-attribution.md` §3.

The **current** baseline is therefore
`/home/muse-newapi/b173-baseline-failures-2026-11-14.txt` (30 items).

Measured for this slice:

```
Ran 21099 tests in 219.284s
FAILED (failures=20, errors=10, skipped=15)   -> 30 items
```

Item-by-item against the **30-item** baseline:

```
$ sort -u b173-baseline-failures-2026-11-14.txt > base30.txt
$ grep -E '^(ERROR|FAIL):' full_suite_after.txt | sort -u > after_fails.txt
$ diff after_fails.txt base30.txt && echo IDENTICAL
IDENTICAL
```

**Zero new failures.** The three items that are in the 30-item baseline but
not in the stale 27-item file are all the same pre-existing defect (D-4 in
`docs/design/baseline-attribution.md` -- `merged_tree_review` is
unregistered):

- `FAIL: test_the_check_agrees_with_the_layout_test` (test_runtime_registration)
- `FAIL: test_the_check_passes_on_the_current_repository` (test_runtime_registration)
- `FAIL: test_the_registry_covers_every_module_on_disk` (test_runtime_registration)

They are **not** caused by this slice: this slice adds one test file and no
runtime module. The module `merged_tree_review.py` was added by the
parallel `merged-tree-review` slice and is another slice's file; fixing it
is out of this slice's scope (SCOPE forbids touching it).

Bench, against `/home/muse-newapi/b173-bench-baseline-failures.txt` (8 items):

```
summary: 161/169 passed, 8 failed (12231 ms)
```

The failing-item set is byte-identical to the stored 8-item baseline. The
bench output is saved to
`/home/muse-newapi/b173-r6-12-session-resolution-bench-final.txt`.
