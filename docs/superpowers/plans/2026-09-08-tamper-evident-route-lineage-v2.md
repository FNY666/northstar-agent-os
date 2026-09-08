# Tamper-evident Route Lineage v2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `test-driven-development` task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Build a local-only, versioned Route Lineage store that cryptographically links existing `RouteEvent` v1 records, recovers verified history after restart, and migrates v1 JSONL into a separate v2 target without altering the source.

**Architecture:** Keep the existing `route_ledger.py` v1 record/replay contract backward-compatible. Create an independent `route_lineage.py`: a v2 envelope stores one validated v1 `RouteEvent`, its contiguous sequence, prior digest, and canonical event digest. A caller-held `LineageCursor` is required to detect suffix rollback/deletion; no hash chain can detect a deleted final record without a previously pinned head. Migration parses source bytes read-only, writes a fully verified temporary target, and atomically publishes only to a distinct, absent target path.

**Tech Stack:** Python 3.12 stdlib (`dataclasses`, `hashlib`, `json`, `os`, `tempfile`, `pathlib`, `unittest`); no network, dependency, external process, or remote environment.

## Global Constraints

- Scope is only `/var/minis/workspace/northstar-agent-os-local-only`.
- Do not modify the public checkout, research worktree, Git remotes, or 103/104/宿舍 systems.
- Do not copy or cherry-pick research-line source; user-provided capability summaries are only an acceptance checklist.
- Existing v1 `RouteLedger` APIs and persisted v1 JSONL remain compatible.
- Store only typed `RouteEvent` data already bounded by v1; do not introduce prompts, credentials, raw backend output, error text, or tokens.
- All malformed, reordered, modified, gapped, cross-run, conflicting, or invalid histories fail closed with `ValueError`.
- Source and target migration paths must resolve to distinct files; a migration must never truncate, rename, replace, lock, or otherwise write the source JSONL.
- A v2 migration target must be new. Existing targets are rejected rather than overwritten.

---

## File Structure

- Create: `components/northstar-agent-interop/route_lineage.py` — v2 envelope, cursor/recovery verdict, append/read verification, strict v1 parsing, and atomic migration.
- Create: `components/northstar-agent-interop/tests/test_route_lineage.py` — real filesystem TDD coverage for hash-chain integrity, recovery cursor, migration immutability, and post-migration append.
- Modify: `components/northstar-agent-interop/README.md` — local-only boundary and the external-head limitation.
- Modify: `docs/superpowers/plans/2026-09-08-tamper-evident-route-lineage-v2.md` — check off verified implementation tasks.

## Public Interfaces

```python
@dataclass(frozen=True)
class LineageCursor:
    sequence: int
    event_digest: str

@dataclass(frozen=True)
class LineageEvent:
    schema_version: str  # exactly "northstar.route-lineage.v2"
    sequence: int
    prev_event_digest: str | None
    event_digest: str
    route_event: RouteEvent

@dataclass(frozen=True)
class LineageRecovery:
    verdict: str  # exactly "verified"
    events: tuple[LineageEvent, ...]
    cursor: LineageCursor | None

class RouteLineage:
    def __init__(self, path: str | Path): ...
    def append(self, route_event: RouteEvent) -> LineageEvent: ...
    def recover(self, *, expected_cursor: LineageCursor | None = None) -> LineageRecovery: ...

def migrate_v1_to_v2(source_path: str | Path, target_path: str | Path) -> LineageRecovery: ...
```

`event_digest` is `sha256(canonical_json({"schema_version", "sequence", "prev_event_digest", "route_event"}))`. It never includes its own digest. The first event has `sequence=1` and `prev_event_digest=None`; every subsequent event must have the immediately preceding digest.

### Task 1: Add strict v2 envelope and verified recovery

**Files:**
- Create: `components/northstar-agent-interop/route_lineage.py`
- Test: `components/northstar-agent-interop/tests/test_route_lineage.py`

**Consumes:** `route_ledger.RouteEvent` and its existing strict v1 schema/parser.

**Produces:** `LineageEvent`, `LineageCursor`, `LineageRecovery`, `RouteLineage.recover()`.

- [x] **Step 1: Replace the module-existence RED test with concrete envelope/recovery tests.**

```python
def test_append_and_recover_yield_a_verified_v2_digest_chain(self):
    lineage = RouteLineage(self.path)
    first = lineage.append(self.decision_event())
    second = lineage.append(self.started_event(sequence=2))
    recovery = RouteLineage(self.path).recover()
    self.assertEqual(recovery.verdict, "verified")
    self.assertEqual([item.sequence for item in recovery.events], [1, 2])
    self.assertIsNone(first.prev_event_digest)
    self.assertEqual(second.prev_event_digest, first.event_digest)
    self.assertEqual(recovery.cursor, LineageCursor(2, second.event_digest))
```

- [x] **Step 2: Run the exact test to verify RED.**

```sh
PYTHONPATH=components/northstar-agent-interop:components/northstar-host:components/northstar-run-contract \
python3 -m unittest components.northstar-agent-interop.tests.test_route_lineage.RouteLineageTests.test_append_and_recover_yield_a_verified_v2_digest_chain -v
```

Expected: import failure because `route_lineage` does not exist.

- [x] **Step 3: Implement only the interfaces needed for this test.**

`RouteLineage.append()` loads/validates existing v2 envelopes, requires `route_event.sequence == next v1 event sequence` only within its v1 object, constructs the next lineage sequence/digest, then writes canonical JSON plus newline with `flush()` and `os.fsync()`. `recover()` loads all envelopes, validates v2 field sets/digests/links and returns `LineageRecovery("verified", ...)`.

- [x] **Step 4: Run the exact test to verify GREEN.**

Run the Step 2 command. Expected: `OK`.

### Task 2: Prove tampering and rollback fail closed

**Files:**
- Modify: `components/northstar-agent-interop/tests/test_route_lineage.py`
- Modify: `components/northstar-agent-interop/route_lineage.py`

**Consumes:** `RouteLineage.recover(expected_cursor=...)` and valid v2 JSONL from Task 1.

**Produces:** strict cursor verification that detects rollback/suffix deletion when the caller pins the prior head.

- [x] **Step 1: Add focused RED tests for modification, reordering/middle deletion, and suffix rollback.**

```python
def test_recovery_rejects_mutated_middle_envelope(self):
    cursor = self.append_three_events()
    rows = [json.loads(line) for line in self.path.read_text().splitlines()]
    rows[1]["route_event"]["recorded_at"] += 1
    self.path.write_text("\n".join(json.dumps(row) for row in rows) + "\n")
    with self.assertRaises(ValueError):
        RouteLineage(self.path).recover(expected_cursor=cursor)

def test_recovery_rejects_reordered_or_middle_deleted_envelope(self):
    cursor = self.append_three_events()
    rows = self.path.read_text().splitlines()
    self.path.write_text("\n".join((rows[0], rows[2])) + "\n")
    with self.assertRaises(ValueError):
        RouteLineage(self.path).recover(expected_cursor=cursor)

def test_recovery_rejects_suffix_rollback_when_caller_pins_cursor(self):
    cursor = self.append_three_events()
    rows = self.path.read_text().splitlines()
    self.path.write_text("\n".join(rows[:-1]) + "\n")
    with self.assertRaises(ValueError):
        RouteLineage(self.path).recover(expected_cursor=cursor)
```

- [x] **Step 2: Run these three tests to verify RED.**

```sh
PYTHONPATH=components/northstar-agent-interop:components/northstar-host:components/northstar-run-contract \
python3 -m unittest \
components.northstar-agent-interop.tests.test_route_lineage.RouteLineageTests.test_recovery_rejects_mutated_middle_envelope \
components.northstar-agent-interop.tests.test_route_lineage.RouteLineageTests.test_recovery_rejects_reordered_or_middle_deleted_envelope \
components.northstar-agent-interop.tests.test_route_lineage.RouteLineageTests.test_recovery_rejects_suffix_rollback_when_caller_pins_cursor -v
```

Expected: at least one assertion fails because cursor validation is absent.

- [x] **Step 3: Implement cursor equality checks after chain verification.**

A provided cursor must exactly equal the verified current `(last sequence, last event_digest)`. Empty history with an expected cursor fails. The API must not report “verified” when the cursor differs.

- [x] **Step 4: Run the three tests to verify GREEN.**

Run the Step 2 command. Expected: `OK`.

### Task 3: Migrate v1 history immutably and continue appending v2

**Files:**
- Modify: `components/northstar-agent-interop/route_lineage.py`
- Modify: `components/northstar-agent-interop/tests/test_route_lineage.py`

**Consumes:** a strict v1 JSONL source containing `RouteEvent.to_dict()` rows.

**Produces:** `migrate_v1_to_v2(source_path, target_path)` and appendability of the target lineage.

- [x] **Step 1: Add RED tests for immutable migration, invalid-source failure, and post-migration append.**

```python
def test_migration_preserves_source_creates_distinct_verified_target_and_allows_append(self):
    source = self.make_v1_history()
    source_bytes = source.read_bytes()
    target = self.root / "v2-lineage.jsonl"
    result = migrate_v1_to_v2(source, target)
    self.assertEqual(source.read_bytes(), source_bytes)
    self.assertEqual(result.verdict, "verified")
    lineage = RouteLineage(target)
    appended = lineage.append(self.succeeded_event(sequence=3))
    self.assertEqual(lineage.recover().cursor, LineageCursor(3, appended.event_digest))

def test_migration_rejects_invalid_source_without_creating_or_overwriting_target(self):
    source = self.root / "v1-invalid.jsonl"
    source.write_text('{"not":"route event"}\n')
    target = self.root / "target.jsonl"
    with self.assertRaises(ValueError):
        migrate_v1_to_v2(source, target)
    self.assertFalse(target.exists())

def test_migration_rejects_same_or_preexisting_target(self):
    source = self.make_v1_history()
    with self.assertRaises(ValueError):
        migrate_v1_to_v2(source, source)
    target = self.root / "existing.jsonl"
    target.write_text("do-not-overwrite\n")
    with self.assertRaises(ValueError):
        migrate_v1_to_v2(source, target)
    self.assertEqual(target.read_text(), "do-not-overwrite\n")
```

- [x] **Step 2: Run migration tests to verify RED.**

```sh
PYTHONPATH=components/northstar-agent-interop:components/northstar-host:components/northstar-run-contract \
python3 -m unittest components.northstar-agent-interop.tests.test_route_lineage.RouteLineageMigrationTests -v
```

Expected: import or attribute failures because migration is not implemented.

- [x] **Step 3: Implement pure source parsing and atomic target publication.**

Parse every nonblank source line with `RouteEvent.from_dict`; require consecutive v1 sequence values and reject any malformed/incomplete tail. Create a same-directory temporary v2 file at `0600`, fsync every canonical v2 row, verify it with `RouteLineage(temp).recover()`, then publish it only with a no-replace operation (`os.link(temp, target)` followed by `unlink(temp)`). If any step fails, remove the temporary file and leave source/target untouched.

- [x] **Step 4: Run migration tests to verify GREEN.**

Run the Step 2 command. Expected: `OK`.

### Task 4: Document boundary and run full local verification

**Files:**
- Modify: `components/northstar-agent-interop/README.md`
- Modify: `docs/superpowers/plans/2026-09-08-tamper-evident-route-lineage-v2.md`

- [x] **Step 1: Add a concise local-only Route Lineage section.**

Document that v2 envelopes are tamper-evident, not an authorization mechanism; caller-pinned cursors are required to detect a deleted suffix; migration does not change source v1 JSONL; no real backend, network, server, credentials, or public release is involved.

- [x] **Step 2: Check every completed checkbox and rerun focused/full tests.**

```sh
python3 -m py_compile components/northstar-agent-interop/*.py components/northstar-agent-interop/tests/*.py
PYTHONPATH=components/northstar-agent-interop:components/northstar-host:components/northstar-run-contract \
python3 -m unittest discover -s components/northstar-agent-interop/tests -p 'test_*.py' -v
git diff --check
```

- [x] **Step 3: Run sensitive-data scan and explicitly verify public checkout unchanged.**

```sh
grep -RInE '(BEGIN [A-Z ]*PRIVATE KEY|api[_-]?key[[:space:]]*=[[:space:]]*[^$]|authorization:[[:space:]]*bearer)' components/northstar-agent-interop || true
git -C /var/minis/workspace/northstar-agent-os status --short
```

- [x] **Step 4: Create one local-only commit only after fresh verification.**

```sh
git add components/northstar-agent-interop/route_lineage.py \
  components/northstar-agent-interop/tests/test_route_lineage.py \
  components/northstar-agent-interop/README.md \
  docs/superpowers/plans/2026-09-08-tamper-evident-route-lineage-v2.md
git commit -m "feat: add tamper-evident route lineage v2"
```

## Execution notes

- Task 1 had a verified RED caused by missing `route_lineage`, then a focused 3/3 GREEN.
- Task 2 tests were added after Task 1 had already included cursor validation; they passed immediately and therefore serve as regression coverage, **not** an independent RED→GREEN proof.
- Task 3 had a verified RED caused by missing `migrate_v1_to_v2`, then a focused migration GREEN. A later valid RED showed that structurally valid but state-illegal v1 input was accepted; migration now reuses the v1 replay state-machine validator.
- Two further valid RED tests found consistency gaps in direct v2 append and recovery. Both now reuse the same v1 history validation and were followed by focused GREEN runs.
- Final fresh verification: `py_compile` passed; Interop discovery ran **96/96 PASS**; `git diff --check` and sensitive scan passed; public checkout status/HEAD was observed but not modified.

## Self-review

- **Coverage:** envelope schema/digest/link (Task 1); middle tamper/reorder/deletion plus externally pinned suffix rollback (Task 2); distinct immutable migration, target non-overwrite, migration failure cleanup and post-migration append (Task 3); docs and complete verification (Task 4).
- **Known limit, explicit:** a hash chain alone cannot detect deletion of its final event. The plan requires a caller-held `LineageCursor` as external evidence; the API fails closed on cursor mismatch rather than claiming full deletion detection.
- **No placeholders:** checked for TBD/TODO/“appropriate handling”/“similar to”; all task interfaces and commands are explicit.
