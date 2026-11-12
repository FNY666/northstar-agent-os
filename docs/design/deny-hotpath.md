# Deny lookup on the hot path (conclusion 54)

**Source:** Moltbook post `eb164059`, comment `30be6cc9` (spiritofthefleet).
**Decision:** the deny lookup must be a single indexed read, and that fact
belongs in the acceptance tests. Refusal rows are written first; dispatch
fails closed on them. *(Coordinator decision — not to be re-litigated.)*

## The problem

Dispatch has to consult the sealed deny *before* a fresh start. That puts
the deny lookup on the hot path of every dispatch. A precondition that
makes every request pay a price is a precondition somebody will eventually
cache — and a cached deny is a diary entry: it keeps saying "denied" long
after the reason for the denial has gone.

## The shape of the answer

The decision state lives in a **counter**, not in a log:

| table | job | read on the hot path? |
|---|---|---|
| `revocation_counter` | the decision state, one row per scope, keyed by scope | **yes** — one indexed `SELECT` |
| `deny_log` | the record: one refusal row per decision attempt | no — written to, read back for archaeology |

The lookup is a seek on the scope primary key. The deny log is never
scanned to decide anything, so the cost of a dispatch does not grow with
the number of past denials. That property is *measured*, not asserted:
`measure_p99()` produces the distribution, and the acceptance tests grow
the deny log by thousands of rows and re-measure.

## Fail-closed

A counter that cannot be read is a **denial**, not an allow. "I could not
check" is never "allowed". The same holds one step earlier: if the refusal
row itself cannot be written, the dispatch denies — the one case where
"I could not record it" forces "no".

Fail-closed has a sharp edge worth naming: a store that cannot answer
*honestly* must not be the thing that decides. The parallel dispatch path
runs the lookup in worker threads, and `sqlite3` binds a connection to its
creating thread. An unguarded connection raised `ProgrammingError` there,
the lookup failed closed, and the result was that **every parallel
dispatch was denied** — the safety property held, but for the wrong reason,
and an unrevoked scope was refused. The store therefore opens its
connection with `check_same_thread=False` under a lock. The regression
tests in `ThreadSafetyTests` pin this: they fail against the unguarded
connection and pass against the guarded one.

## Refusal row first

The dispatch order is:

1. **write the refusal row** — outcome `unknown`, decision not yet made;
2. **the single indexed lookup** of the revocation counter;
3. **finalize the refusal row** with the decision.

Step 1 happens even when the answer will be "allowed": the row is the
record that a check happened at all. If the process dies between step 1
and step 3, the row says `unknown`, which is the truth. What must never
happen is *no row at all* — "no row" would read as "nothing was ever
denied".

## Not cacheable

`DENY_CACHE_TTL_MS` is zero, and every lookup result says so
(`cacheable` is always `False`). The reason the lookup need not be cached
is that it is cheap enough — which is a claim the p99 measurement has to
support, not a claim the code gets to make on its own.

## What this does not prove

This module books what the dispatcher decided. It cannot prove that a
denial was *correct* — only that a decision was reached, was recorded, and
was based on a counter read that can be re-checked. The same honest gap
every ledger in this repo carries.

## Wiring

`GovernedActionRunner` takes an optional `deny_dispatcher`. When wired,
every dispatch consults the deny *before* the gate decides, so a revoked
scope never reaches the gate at all. The scope is `<subject>/<tool>`: a
revocation is issued against the pair, not against every action the
process ever takes.

```python
store = DenyStore("/var/lib/northstar/deny.sqlite3")
store.revoke("svc/Write", reason="operator revoked")
runner = GovernedActionRunner(safr=..., gate=..., observer=..., ledger=...,
                              deny_dispatcher=DenyDispatcher(store))
```

## Acceptance coverage

| requirement | test |
|---|---|
| single indexed read, not a scan | `test_lookup_executes_exactly_one_statement`, `test_lookup_query_plan_is_a_seek_not_a_scan`, `test_lookup_does_not_touch_the_deny_log`, `test_the_lookup_stays_a_single_indexed_read_on_the_dispatch_path` |
| p99 measurement exists and passes | `test_measure_p99_returns_a_distribution`, `test_measure_p99_is_repeatable`, `test_measure_p99_is_bounded_by_an_absolute_ceiling`, `test_lookup_cost_does_not_grow_with_the_deny_log` |
| refusal row before the decision | `test_refusal_row_is_written_before_the_lookup`, `test_a_crash_between_row_and_decision_leaves_unknown_not_a_hole`, `test_every_decision_attempt_leaves_a_row` |
| counter read failure denies | `test_unreadable_counter_denies_instead_of_allowing`, `test_a_failed_counter_read_blocks_the_dispatch`, `test_a_broken_store_denies_rather_than_raising` |
| the store answers honestly off-thread | `test_a_lookup_from_another_thread_reads_the_counter`, `test_a_refusal_row_written_off_thread_lands`, `test_concurrent_lookups_all_see_the_same_counter` |
| the wiring is real, not isolated | `test_a_revoked_scope_blocks_the_tool_call`, `test_the_parallel_dispatch_path_also_refuses_a_revoked_scope`, `test_the_dispatch_path_leaves_a_refusal_row` |
