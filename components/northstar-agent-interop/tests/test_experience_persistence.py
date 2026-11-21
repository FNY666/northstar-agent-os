"""Persistence behaviour of the Experience layers (R26c).

These pin what happens when the files on disk are not perfect, which is the one
situation the old loaders handled by silently losing history:

* a damaged line must never hide the good lines around it;
* damage must be counted and visible, not swallowed;
* rewriting a file must never destroy lines that could not be loaded;
* a crash while rewriting must leave the old file or the new one, never a mix.

A fault that is not content damage (the path cannot be read at all) is an
environment problem and is still raised.
"""
import hashlib
import json
import os
import sys
import tempfile
import unittest
import warnings
from pathlib import Path
from unittest import mock

COMPONENT_ROOT = Path(__file__).resolve().parents[1]
HOST_ROOT = COMPONENT_ROOT.parent / "northstar-host"
sys.path.insert(0, str(COMPONENT_ROOT))
sys.path.insert(0, str(HOST_ROOT))
sys.path.insert(0, str(COMPONENT_ROOT.parent))

import experience_layering as el  # noqa: E402
from experience_middleware import ExperienceMiddleware  # noqa: E402
from experience_layering import (  # noqa: E402
    ArchiveBatch,
    ExperienceLayering,
    ExperienceRecord,
    LostEvent,
    LostEventStream,
    RecallLayer,
    WorkingLayer,
)


def record(i: int, fingerprint: str = "actor:step") -> ExperienceRecord:
    return ExperienceRecord(
        fingerprint=fingerprint, outcome="success", timestamp=1_700_000_000 + i
    )


def lost(i: int) -> LostEvent:
    return LostEvent(
        goal_fingerprint="actor:step",
        run_id=f"run-{i}",
        reason="timeout",
        timestamp=1_700_000_000 + i,
        fencing_token=str(i),
    )


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def good_lines(path: Path) -> int:
    count = 0
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        try:
            json.loads(line)
        except ValueError:
            continue
        count += 1
    return count


class Base(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = Path(self._tmp.name)

    def working_file(self, lines, tail=""):
        path = self.dir / "working.jsonl"
        text = "".join(json.dumps(r.to_dict()) + "\n" for r in lines)
        path.write_text(text + tail)
        return path

    def lost_file(self, events, tail=""):
        path = self.dir / "lost-events.jsonl"
        text = "".join(json.dumps(e.to_dict()) + "\n" for e in events)
        path.write_text(text + tail)
        return path


class SingleDefinitionTests(unittest.TestCase):
    def test_components_hold_exactly_one_experience_layering(self):
        components = COMPONENT_ROOT.parent
        # Build artifacts are copies of the source, not second definitions:
        # `pip install .` leaves setuptools copies under build/lib, and a
        # later test run must not read those as a second implementation.
        generated = {"__pycache__", "build", "dist"}
        found = sorted(
            p.relative_to(components).as_posix()
            for p in components.rglob("experience_layering.py")
            if not generated.intersection(p.parts)
        )
        self.assertEqual(
            found,
            ["northstar-agent-interop/experience_layering.py"],
            "a second copy would shadow this one on sys.path and let edits here go untested",
        )


class CleanFileTests(Base):
    def test_a_healthy_file_loads_exactly_as_before(self):
        path = self.working_file([record(i) for i in range(10)])
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            layer = WorkingLayer(path, capacity=100)
        self.assertEqual(len(layer.records), 10)
        self.assertEqual(layer.corrupt_lines, 0)
        self.assertEqual(layer.load_errors, ())
        self.assertIsNone(layer.quarantined_to)
        self.assertEqual([w for w in caught if issubclass(w.category, RuntimeWarning)], [])

    def test_a_file_in_the_shape_the_monitor_wrote_still_loads(self):
        # Four records, one fingerprint, as written by monitor.py on 2026-09-18.
        path = self.dir / "working.jsonl"
        rows = [
            {
                "fingerprint": "server-health-check",
                "outcome": "success",
                "reason": None,
                "timestamp": 1_789_745_566 + 200 * i,
                "metadata": {},
            }
            for i in range(4)
        ]
        path.write_text("".join(json.dumps(r) + "\n" for r in rows))
        layer = WorkingLayer(path, capacity=100)
        self.assertEqual(len(layer.records), 4)
        self.assertEqual(layer.corrupt_lines, 0)


class DamagedLoadTests(Base):
    def test_torn_tail_keeps_every_complete_record_and_says_so(self):
        path = self.working_file([record(i) for i in range(50)], tail='{"fingerprint": "actor:step", "outc')
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            layer = WorkingLayer(path, capacity=100)
        self.assertEqual(len(layer.records), 50)
        self.assertEqual(layer.corrupt_lines, 1)
        self.assertEqual(layer.load_errors[0][0], 51)
        self.assertTrue(
            [w for w in caught if issubclass(w.category, RuntimeWarning)],
            "damage must be visible, not only countable",
        )

    def test_a_corrupt_middle_line_does_not_hide_the_records_after_it(self):
        rows = [json.dumps(record(i).to_dict()) for i in range(3)]
        rows.insert(1, "{not json")
        path = self.dir / "working.jsonl"
        path.write_text("\n".join(rows) + "\n")
        layer = WorkingLayer(path, capacity=100)
        self.assertEqual(len(layer.records), 3)
        self.assertEqual(layer.corrupt_lines, 1)

        events = [json.dumps(lost(i).to_dict()) for i in range(3)]
        events.insert(1, "{not json")
        lpath = self.dir / "lost-events.jsonl"
        lpath.write_text("\n".join(events) + "\n")
        stream = LostEventStream(lpath)
        self.assertEqual(len(stream.events), 3, "the old loader stopped at the first bad line")
        self.assertEqual(stream.corrupt_lines, 1)

    def test_a_line_that_is_valid_json_but_the_wrong_shape_is_counted_not_raised(self):
        rows = [json.dumps(record(0).to_dict()), json.dumps({"unrelated": 1}), "[1, 2, 3]", "5"]
        path = self.dir / "working.jsonl"
        path.write_text("\n".join(rows) + "\n")
        layer = WorkingLayer(path, capacity=100)
        self.assertEqual(len(layer.records), 1)
        self.assertEqual(layer.corrupt_lines, 3)

        lpath = self.dir / "lost-events.jsonl"
        lpath.write_text("\n".join([json.dumps({"unrelated": 1}), json.dumps(lost(1).to_dict())]) + "\n")
        stream = LostEventStream(lpath)
        self.assertEqual(len(stream.events), 1)
        self.assertEqual(stream.corrupt_lines, 1)

    def test_a_path_that_cannot_be_read_is_an_environment_fault_and_is_raised(self):
        unreadable = self.dir / "working.jsonl"
        unreadable.mkdir()  # opening a directory as a file fails with an OSError
        with self.assertRaises(OSError):
            WorkingLayer(unreadable, capacity=100)
        unreadable_lost = self.dir / "lost-events.jsonl"
        unreadable_lost.mkdir()
        with self.assertRaises(OSError):
            LostEventStream(unreadable_lost)


class RewriteSafetyTests(Base):
    def test_rewrite_after_a_damaged_load_keeps_the_original_bytes(self):
        path = self.working_file([record(i) for i in range(6)], tail='{"fingerprint": "actor:step", "outc')
        before = path.read_bytes()
        layer = WorkingLayer(path, capacity=3)
        for i in range(6, 10):
            layer.add(record(i))
        layer.evict(count=2)  # rewrites the file from memory

        self.assertIsNotNone(layer.quarantined_to)
        kept = Path(layer.quarantined_to)
        self.assertTrue(kept.name.startswith("working.jsonl.corrupt-"))
        self.assertTrue(
            kept.read_bytes().startswith(before),
            "the damaged original must survive byte for byte, not be overwritten",
        )
        self.assertEqual(good_lines(path), len(layer.records), "the live file now holds exactly the loaded records")
        self.assertEqual(len(layer.records), 8)

    def test_a_second_rewrite_does_not_pile_up_quarantine_copies(self):
        path = self.working_file([record(i) for i in range(4)], tail="{broken")
        layer = WorkingLayer(path, capacity=3)
        layer.add(record(10))
        layer.evict(count=1)
        layer.add(record(11))
        layer.evict(count=1)
        copies = sorted(p.name for p in self.dir.glob("working.jsonl.corrupt-*"))
        self.assertEqual(len(copies), 1, copies)

    def test_a_clean_file_is_rewritten_without_any_quarantine(self):
        path = self.working_file([record(i) for i in range(6)])
        layer = WorkingLayer(path, capacity=3)
        layer.evict(count=2)
        self.assertEqual(list(self.dir.glob("working.jsonl.corrupt-*")), [])
        self.assertEqual(good_lines(path), 4)

    def test_rewrite_is_atomic_when_the_replace_step_fails(self):
        path = self.working_file([record(i) for i in range(6)])
        layer = WorkingLayer(path, capacity=3)
        before = sha(path)
        with mock.patch.object(el.os, "replace", side_effect=OSError("disk gone")):
            with self.assertRaises(OSError):
                layer.evict(count=2)
        self.assertEqual(sha(path), before, "a failed rewrite must leave the old file untouched")
        self.assertEqual(
            [p.name for p in self.dir.iterdir() if p.name.endswith(".tmp")],
            [],
            "the temporary file must be cleaned up",
        )

    def test_rewrite_preserves_the_file_permissions(self):
        path = self.working_file([record(i) for i in range(6)])
        os.chmod(path, 0o644)
        WorkingLayer(path, capacity=3).evict(count=2)
        self.assertEqual(path.stat().st_mode & 0o777, 0o644)

    def test_quarantine_failure_means_no_rewrite(self):
        path = self.working_file([record(i) for i in range(4)], tail="{broken")
        layer = WorkingLayer(path, capacity=3)
        before = sha(path)
        with mock.patch.object(WorkingLayer, "_quarantine", side_effect=OSError("no space")):
            with self.assertRaises(OSError):
                layer.evict(count=1)
        self.assertEqual(sha(path), before, "never destroy before the evidence is safe")


class AppendTests(Base):
    def test_append_after_an_unterminated_line_starts_a_new_line(self):
        path = self.working_file([record(0)], tail='{"fingerprint": "actor:st')
        layer = WorkingLayer(path, capacity=100)
        layer.add(record(1))
        self.assertEqual(good_lines(path), 2, "the new record must not be glued onto the fragment")
        reloaded = WorkingLayer(path, capacity=100)
        self.assertEqual(len(reloaded.records), 2)

        lpath = self.lost_file([lost(0)], tail='{"goal_fingerprint": "ac')
        stream = LostEventStream(lpath)
        stream.add(lost(1))
        self.assertEqual(len(LostEventStream(lpath).events), 2)

    def test_append_creates_a_missing_file_and_directory(self):
        path = self.dir / "nested" / "working.jsonl"
        layer = WorkingLayer(path, capacity=100)
        layer.add(record(0))
        self.assertEqual(good_lines(path), 1)


class RecallTests(Base):
    def _recall(self):
        return RecallLayer(self.dir / "recall")

    def test_a_corrupt_line_does_not_stop_a_query(self):
        recall = self._recall()
        recall.add_batch([record(i) for i in range(5)])
        shard = sorted((self.dir / "recall").glob("recall-*.jsonl"))[0]
        lines = shard.read_text().splitlines()
        lines.insert(2, "{not json")
        shard.write_text("\n".join(lines) + "\n")
        results = recall.query("actor:step")
        self.assertEqual(len(results), 5, "the old query raised on the first bad line")
        self.assertEqual(recall.corrupt_lines, 1)
        recall.query("actor:step")
        self.assertEqual(recall.corrupt_lines, 1, "the same damaged line must not be counted twice")

    def test_the_index_is_written_atomically(self):
        recall = self._recall()
        recall.add_batch([record(0)])
        index = self.dir / "recall" / "recall-index.json"
        before = sha(index)
        real_replace = el.os.replace

        def fail_only_index_replace(source, target):
            if Path(target).name == "recall-index.json":
                raise OSError("disk gone")
            return real_replace(source, target)

        with mock.patch.object(el.os, "replace", side_effect=fail_only_index_replace):
            with self.assertRaises(OSError):
                recall.add_batch([record(1, fingerprint="other:step")])
        self.assertEqual(sha(index), before)
        self.assertEqual(json.loads(index.read_text()).keys(), {"actor:step"})

    def test_retrying_the_same_batch_after_index_failure_does_not_duplicate_rows(self):
        recall = self._recall()
        batch = [record(0), record(1)]
        original_save = recall._save_index
        calls = {"count": 0}

        def fail_once():
            calls["count"] += 1
            if calls["count"] == 1:
                raise OSError("index save failed")
            return original_save()

        with mock.patch.object(recall, "_save_index", side_effect=fail_once):
            with self.assertRaises(OSError):
                recall.add_batch(batch)
        recall.add_batch(batch)
        self.assertEqual(len(recall.query("actor:step")), 2)
        self.assertEqual(recall.structure_problems()["recall_index_content_mismatches"], [])

    def test_retrying_the_same_batch_after_index_failure_survives_restart(self):
        recall = self._recall()
        batch = [record(0), record(1)]
        with mock.patch.object(recall, "_save_index", side_effect=OSError("index save failed")):
            with self.assertRaises(OSError):
                recall.add_batch(batch)
        restarted = RecallLayer(self.dir / "recall")
        restarted.add_batch(batch)
        self.assertEqual(len(restarted.query("actor:step")), 2)

    def test_lost_record_identity_keeps_distinct_run_ids_with_same_timestamp(self):
        first = ExperienceRecord(
            fingerprint="actor:step", outcome="lost", timestamp=1_700_000_000,
            run_id="run-A", data_quality="complete", source="reaper-fenced",
        )
        second = ExperienceRecord(
            fingerprint="actor:step", outcome="lost", timestamp=1_700_000_000,
            run_id="run-B", data_quality="complete", source="reaper-fenced",
        )
        recall = self._recall()
        recall.add_batch([first, second])
        restarted = RecallLayer(self.dir / "recall")
        rows = restarted.query("actor:step")
        self.assertEqual(len(rows), 2)
        self.assertEqual({row.run_id for row in rows}, {"run-A", "run-B"})
        self.assertEqual({row.source for row in rows}, {"reaper-fenced"})
        self.assertEqual({row.data_quality for row in rows}, {"complete"})
        quality_variant = ExperienceRecord(
            fingerprint="actor:step", outcome="lost", timestamp=1_700_000_000,
            run_id="run-A", data_quality="degraded", source="reaper-fenced",
        )
        source_variant = ExperienceRecord(
            fingerprint="actor:step", outcome="lost", timestamp=1_700_000_000,
            run_id="run-A", data_quality="complete", source="manual-no-token",
        )
        self.assertNotEqual(el._record_identity(first), el._record_identity(quality_variant))
        self.assertNotEqual(el._record_identity(first), el._record_identity(source_variant))


class HealthTests(Base):
    def test_health_is_all_zero_on_a_healthy_store(self):
        layering = ExperienceLayering(base_dir=self.dir / "exp")
        health = layering.health()
        self.assertEqual(health["working_corrupt_lines"], 0)
        self.assertEqual(health["lost_stream_corrupt_lines"], 0)
        self.assertEqual(health["recall_corrupt_lines"], 0)
        self.assertEqual(health["quarantine_files"], [])

    def test_health_reports_damage_found_at_load(self):
        base = self.dir / "exp"
        base.mkdir()
        (base / "working.jsonl").write_text(json.dumps(record(0).to_dict()) + "\n{torn")
        (base / "lost-events.jsonl").write_text("{torn\n" + json.dumps(lost(1).to_dict()) + "\n")
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            layering = ExperienceLayering(base_dir=base)
        health = layering.health()
        self.assertEqual(health["working_corrupt_lines"], 1)
        self.assertEqual(health["lost_stream_corrupt_lines"], 1)



class QuarantineTests(Base):
    def test_the_quarantined_copy_is_private(self):
        path = self.working_file([record(i) for i in range(4)], tail="{broken")
        layer = WorkingLayer(path, capacity=3)
        layer.add(record(9))
        layer.evict(count=1)
        self.assertIsNotNone(layer.quarantined_to, "a damaged original must be preserved before the rewrite")
        mode = Path(layer.quarantined_to).stat().st_mode & 0o777
        self.assertEqual(mode, 0o600, "the copy may hold anything the layer ever recorded")

    def test_an_incomplete_quarantine_copy_is_removed_not_left_as_evidence(self):
        path = self.working_file([record(i) for i in range(4)], tail="{broken")
        layer = WorkingLayer(path, capacity=3)
        before = sha(path)
        with mock.patch.object(el.os, "fsync", side_effect=OSError("no space")):
            with self.assertRaises(OSError):
                layer.evict(count=1)
        self.assertEqual(list(self.dir.glob("working.jsonl.corrupt-*")), [])
        self.assertEqual(sha(path), before)


class HistoryStatusTests(Base):
    def _store(self, torn: bool):
        base = self.dir / "exp"
        base.mkdir()
        rows = "".join(json.dumps(record(i).to_dict()) + "\n" for i in range(12))
        (base / "working.jsonl").write_text(rows + ("{torn" if torn else ""))
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            return ExperienceLayering(base_dir=base), base

    def test_a_clean_store_reports_complete(self):
        layering, _ = self._store(torn=False)
        status = layering.history_status()
        self.assertTrue(status["complete"])
        self.assertEqual(status["skipped_lines"], 0)
        self.assertEqual(status["quarantine_files"], [])

    def test_a_damaged_store_reports_incomplete(self):
        layering, _ = self._store(torn=True)
        status = layering.history_status()
        self.assertFalse(status["complete"])
        self.assertEqual(status["skipped_lines"], 1)

    def test_incomplete_survives_a_rewrite_and_a_restart(self):
        layering, base = self._store(torn=True)
        for i in range(100, 120):
            layering.working.add(record(i))
        layering.working.evict(count=5)  # first rewrite: quarantines the damaged original
        self.assertEqual(len(layering.history_status()["quarantine_files"]), 1)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            restarted = ExperienceLayering(base_dir=base)
        self.assertEqual(restarted.working.corrupt_lines, 0, "the live file is clean again")
        self.assertFalse(
            restarted.history_status()["complete"],
            "but the lines it lost are only in the quarantine copy, so history is still incomplete",
        )

    def test_damage_in_an_unread_recall_shard_is_only_known_after_it_is_read(self):
        layering, base = self._store(torn=False)
        layering.recall.add_batch([record(i) for i in range(5)])
        shard = sorted((base / "recall").glob("recall-*.jsonl"))[0]
        shard.write_text(shard.read_text() + "{torn")
        self.assertTrue(layering.history_status()["complete"], "nobody has read the shard yet")
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            layering.recall.query("actor:step")
        self.assertFalse(layering.history_status()["complete"])


class AdmissionAnnotationTests(Base):
    CONTEXT = {"actor_id": "actor", "step_id": "step"}

    def _middleware(self, torn: bool):
        base = self.dir / ("torn" if torn else "clean")
        base.mkdir()
        rows = "".join(json.dumps(record(i).to_dict()) + "\n" for i in range(12))
        (base / "working.jsonl").write_text(rows + ("{torn" if torn else ""))
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            return ExperienceMiddleware(ExperienceLayering(base_dir=base))

    def test_the_decision_names_the_completeness_of_its_history(self):
        clean = self._middleware(torn=False).check_admission("actor:step", self.CONTEXT)
        torn = self._middleware(torn=True).check_admission("actor:step", self.CONTEXT)
        self.assertEqual(clean.metadata.get("history_complete"), True)
        self.assertEqual(clean.metadata.get("skipped_lines"), 0)
        self.assertEqual(torn.metadata.get("history_complete"), False)
        self.assertEqual(torn.metadata.get("skipped_lines"), 1)

    def test_reporting_damage_does_not_change_the_decision(self):
        clean = self._middleware(torn=False).check_admission("actor:step", self.CONTEXT)
        torn = self._middleware(torn=True).check_admission("actor:step", self.CONTEXT)
        self.assertEqual(
            (torn.decision, torn.execution_authorized, torn.reason),
            (clean.decision, clean.execution_authorized, clean.reason),
            "visibility only: this change must not move what is authorized",
        )

    def test_an_experience_object_without_history_status_is_still_served(self):
        class Plain:
            def query_statistics(self, fingerprint):
                return {"total_runs": 0}

        result = ExperienceMiddleware(Plain()).check_admission("actor:step", self.CONTEXT)
        self.assertNotIn("history_complete", result.metadata)

    def test_a_failing_history_status_is_counted_and_does_not_break_admission(self):
        class Broken:
            def query_statistics(self, fingerprint):
                return {"total_runs": 0}

            def history_status(self):
                raise RuntimeError("boom")

        middleware = ExperienceMiddleware(Broken(), error_sink=lambda where, error: None)
        result = middleware.check_admission("actor:step", self.CONTEXT)
        self.assertTrue(result.execution_authorized)
        self.assertEqual(middleware.error_counts.get("history_status"), 1)


class IndexAndArchiveTests(Base):
    def test_a_corrupt_recall_index_still_fails_loudly_at_start_up(self):
        recall_dir = self.dir / "recall"
        recall_dir.mkdir()
        (recall_dir / "recall-index.json").write_text('{"actor:step": ["2023-11')
        with self.assertRaises(ValueError):
            RecallLayer(recall_dir)

    def test_archive_still_refuses_to_delete_a_shard_it_could_not_read_fully(self):
        recall = RecallLayer(self.dir / "recall")
        recall.add_batch([record(i) for i in range(3)])
        shard = sorted((self.dir / "recall").glob("recall-*.jsonl"))[0]
        shard.write_text(shard.read_text() + "{torn\n")
        with self.assertRaises(ValueError):
            recall.archive_old_data(__import__("datetime").datetime(2099, 1, 1), archive=lambda records: True)
        self.assertTrue(shard.exists(), "a strict read protects the shard: do not make this read lenient")




class MemoryFollowsDiskTests(Base):
    """A failed write must leave memory equal to disk, and say so (C: eviction / add rollback)."""

    def test_a_failed_eviction_rewrite_keeps_memory_equal_to_disk(self):
        layering = ExperienceLayering(base_dir=self.dir / "exp", working_capacity=3)
        for i in range(6):
            layering.working.add(record(i))
        path = self.dir / "exp" / "working.jsonl"
        before = sha(path)
        with mock.patch.object(el.os, "replace", side_effect=OSError("disk gone")):
            with self.assertRaises(OSError):
                layering.working.evict(count=2)
        self.assertEqual(sha(path), before)
        self.assertEqual(len(layering.working.records), 6, "memory must not run ahead of the file")
        self.assertEqual(good_lines(path), len(layering.working.records))
        self.assertTrue(layering.history_status()["complete"], "nothing was lost: no false alarm either")

    def test_a_failed_eviction_does_not_hand_records_to_recall(self):
        layering = ExperienceLayering(base_dir=self.dir / "exp", working_capacity=3)
        for i in range(4):
            layering.working.records.append(record(i))
        with mock.patch.object(el.os, "replace", side_effect=OSError("disk gone")):
            with self.assertRaises(OSError):
                layering._check_and_evict()
        self.assertEqual(list((self.dir / "exp" / "recall").glob("recall-*.jsonl")), [])

    def test_a_recall_failure_does_not_lose_records_removed_from_working(self):
        layering = ExperienceLayering(base_dir=self.dir / "exp", working_capacity=3)
        for i in range(4):
            layering.working.add(record(i))
        before = [r.to_dict() for r in layering.working.records]
        with mock.patch.object(layering.recall, "add_batch", side_effect=OSError("recall unavailable")):
            with self.assertRaises(OSError):
                layering._check_and_evict()
        self.assertEqual([r.to_dict() for r in layering.working.records], before)
        self.assertEqual(good_lines(self.dir / "exp" / "working.jsonl"), len(before))
        self.assertTrue(layering.history_status()["working_recall_transfer_pending"])
        self.assertFalse(layering.history_status()["complete"])

    def test_settle_recall_failure_preserves_the_working_batch(self):
        layering = ExperienceLayering(base_dir=self.dir / "exp", working_capacity=2)
        layering.settle(record(0))
        layering.settle(record(1))
        with mock.patch.object(layering.recall, "add_batch", side_effect=OSError("recall unavailable")):
            with self.assertRaises(OSError):
                layering.settle(record(2))
        self.assertEqual(len(layering.working.records), 3)
        self.assertEqual(good_lines(self.dir / "exp" / "working.jsonl"), 3)
        self.assertFalse(list((self.dir / "exp" / "recall").glob("recall-*.jsonl")))

    def test_same_fingerprint_date_rows_survive_transfer_failure_and_restart(self):
        layering = ExperienceLayering(base_dir=self.dir / "exp", working_capacity=1)
        layering.recall.add_batch([record(99, fingerprint="actor:step")])
        layering.working.add(record(0, fingerprint="actor:step"))
        layering.working.add(record(1, fingerprint="actor:step"))
        with mock.patch.object(layering.recall, "add_batch", side_effect=OSError("recall unavailable")):
            with self.assertRaises(OSError):
                layering._check_and_evict()
        restarted = ExperienceLayering(base_dir=self.dir / "exp", working_capacity=2)
        self.assertEqual(len(restarted.recall.query("actor:step")), 3)
        self.assertTrue(restarted.history_status()["complete"])

    def test_a_pending_transfer_is_recovered_after_restart(self):
        layering = ExperienceLayering(base_dir=self.dir / "exp", working_capacity=3)
        for i in range(4):
            layering.working.add(record(i))
        with mock.patch.object(layering.recall, "add_batch", side_effect=OSError("recall unavailable")):
            with self.assertRaises(OSError):
                layering._check_and_evict()
        restarted = ExperienceLayering(base_dir=self.dir / "exp", working_capacity=3)
        self.assertFalse(restarted.history_status()["working_recall_transfer_pending"])
        self.assertEqual(len(restarted.recall.query("actor:step")), 4)
        self.assertEqual(len(restarted.working.records), 0)
        self.assertTrue(restarted.history_status()["complete"])

    def test_a_failed_working_delete_keeps_outbox_for_retry(self):
        layering = ExperienceLayering(base_dir=self.dir / "exp", working_capacity=3)
        for i in range(4):
            layering.working.add(record(i))
        with mock.patch.object(layering.working, "evict_records", side_effect=OSError("working unavailable")):
            with self.assertRaises(OSError):
                layering._check_and_evict()
        self.assertTrue((self.dir / "exp" / "working-recall.pending.json").exists())
        self.assertEqual(len(layering.recall.query("actor:step")), 4)

    def test_a_failed_append_is_not_remembered_in_memory(self):
        layer = WorkingLayer(self.dir / "working.jsonl", capacity=10)
        with mock.patch.object(el, "_append_lines", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                layer.add(record(0))
        self.assertEqual(layer.records, [])

        stream = LostEventStream(self.dir / "lost-events.jsonl")
        with mock.patch.object(el, "_append_lines", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                stream.add(lost(0))
        self.assertEqual(stream.events, [])

    def test_a_retry_after_a_failed_append_is_not_mistaken_for_a_duplicate(self):
        stream = LostEventStream(self.dir / "lost-events.jsonl")
        with mock.patch.object(el, "_append_lines", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                stream.add(lost(0))
        stream.add(lost(0))  # the same event, now that the disk works
        self.assertEqual(len(LostEventStream(self.dir / "lost-events.jsonl").events), 1)


class StrictUtf8Tests(Base):
    def test_invalid_utf8_is_damage_not_a_repaired_record(self):
        good = json.dumps(record(0).to_dict()).replace("success", "suc@@cess").encode().replace(b"@@", b"\xff")
        path = self.dir / "working.jsonl"
        path.write_bytes(good + b"\n" + json.dumps(record(1).to_dict()).encode() + b"\n")
        layer = WorkingLayer(path, capacity=10)
        self.assertEqual(len(layer.records), 1)
        self.assertEqual(layer.records[0].outcome, "success")
        self.assertEqual(layer.corrupt_lines, 1, "the altered record must be counted, not accepted")
        self.assertEqual(layer.load_errors[0][1], "UnicodeDecodeError")

    def test_a_multibyte_character_that_is_valid_still_loads(self):
        row = record(0).to_dict()
        row["reason"] = "超时"
        path = self.dir / "working.jsonl"
        path.write_bytes((json.dumps(row, ensure_ascii=False) + "\n").encode("utf-8"))
        layer = WorkingLayer(path, capacity=10)
        self.assertEqual(layer.corrupt_lines, 0)
        self.assertEqual(layer.records[0].reason, "超时")


class RecallStructureTests(Base):
    def _layering(self):
        return ExperienceLayering(base_dir=self.dir / "exp")

    def test_an_indexed_shard_that_is_gone_makes_history_incomplete(self):
        layering = self._layering()
        layering.recall.add_batch([record(i) for i in range(4)])
        next((self.dir / "exp" / "recall").glob("recall-*.jsonl")).unlink()
        self.assertEqual(layering.recall.query("actor:step"), [])
        status = layering.history_status()
        self.assertFalse(status["complete"])
        self.assertTrue(status["recall_index_missing_shards"])
        self.assertIn("recall_index_missing_shards", status["issues"])

    def test_a_shard_the_index_never_learned_about_makes_history_incomplete_after_restart(self):
        layering = self._layering()
        with mock.patch.object(layering.recall, "_save_index", side_effect=OSError("index write failed")):
            with self.assertRaises(OSError):
                layering.recall.add_batch([record(i) for i in range(4)])
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            restarted = ExperienceLayering(base_dir=self.dir / "exp")
        self.assertEqual(restarted.recall.query("actor:step"), [], "the records exist but no query reaches them")
        status = restarted.history_status()
        self.assertFalse(status["complete"])
        self.assertTrue(status["recall_unindexed_shards"])

    def test_rebuilding_the_index_makes_the_orphan_reachable_and_history_complete(self):
        layering = self._layering()
        with mock.patch.object(layering.recall, "_save_index", side_effect=OSError("index write failed")):
            with self.assertRaises(OSError):
                layering.recall.add_batch([record(i) for i in range(4)])
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            restarted = ExperienceLayering(base_dir=self.dir / "exp")
        self.assertEqual(restarted.recall.rebuild_index(), 1)
        self.assertEqual(len(restarted.recall.query("actor:step")), 4)
        self.assertTrue(restarted.history_status()["complete"])

    def test_a_rebuilt_index_survives_a_restart(self):
        layering = self._layering()
        with mock.patch.object(layering.recall, "_save_index", side_effect=OSError("index write failed")):
            with self.assertRaises(OSError):
                layering.recall.add_batch([record(i) for i in range(4)])
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            first = ExperienceLayering(base_dir=self.dir / "exp")
            first.recall.rebuild_index()
            second = ExperienceLayering(base_dir=self.dir / "exp")  # a fresh process reads the index from disk
        self.assertEqual(len(second.recall.query("actor:step")), 4, "a rebuild that is not saved is lost at restart")
        self.assertTrue(second.history_status()["complete"])

    def test_same_date_new_fingerprint_is_reported_after_index_failure_and_restart(self):
        layering = self._layering()
        layering.recall.add_batch([record(0, fingerprint="old:step")])
        with mock.patch.object(layering.recall, "_save_index", side_effect=OSError("index write failed")):
            with self.assertRaises(OSError):
                layering.recall.add_batch([record(1, fingerprint="new:step")])

        restarted = ExperienceLayering(base_dir=self.dir / "exp")
        self.assertEqual(restarted.recall.query("new:step"), [])
        status = restarted.history_status()
        self.assertFalse(status["complete"], "same-date content drift must not look complete")
        self.assertTrue(status["recall_index_content_mismatches"])
        self.assertIn("recall_index_content_mismatches", status["issues"])
        self.assertTrue(restarted.health()["recall_index_content_mismatches"])

    def test_rebuilding_index_repairs_same_date_fingerprint_drift(self):
        layering = self._layering()
        layering.recall.add_batch([record(0, fingerprint="old:step")])
        with mock.patch.object(layering.recall, "_save_index", side_effect=OSError("index write failed")):
            with self.assertRaises(OSError):
                layering.recall.add_batch([record(1, fingerprint="new:step")])

        restarted = ExperienceLayering(base_dir=self.dir / "exp")
        self.assertEqual(restarted.recall.rebuild_index(), 1)
        self.assertEqual(len(restarted.recall.query("new:step")), 1)
        self.assertTrue(restarted.history_status()["complete"])

    def test_a_healthy_recall_store_reports_no_structure_problems(self):
        layering = self._layering()
        layering.recall.add_batch([record(i) for i in range(4)])
        status = layering.history_status()
        self.assertEqual(status["recall_index_missing_shards"], [])
        self.assertEqual(status["recall_unindexed_shards"], [])
        self.assertEqual(status["recall_index_content_mismatches"], [])
        self.assertTrue(status["complete"])

    def test_health_says_when_the_index_may_lag_behind_the_shards(self):
        layering = self._layering()
        with mock.patch.object(layering.recall, "_save_index", side_effect=OSError("index write failed")):
            with self.assertRaises(OSError):
                layering.recall.add_batch([record(0)])
        self.assertTrue(layering.health()["recall_index_dirty"])
        self.assertTrue(layering.health()["recall_index_pending"])
        self.assertFalse(layering.history_status()["complete"])
        self.assertIn("recall_index_pending", layering.history_status()["issues"])
        self.assertTrue((self.dir / "exp" / "recall" / "recall-index.pending").exists())

    def test_a_successful_index_commit_removes_the_pending_marker(self):
        layering = self._layering()
        layering.recall.add_batch([record(0)])
        self.assertFalse((self.dir / "exp" / "recall" / "recall-index.pending").exists())

    def test_a_pending_marker_without_a_shard_append_is_still_incomplete(self):
        layering = self._layering()
        with mock.patch.object(el, "_append_lines", side_effect=OSError("shard write failed")):
            with self.assertRaises(OSError):
                layering.recall.add_batch([record(0)])
        status = layering.history_status()
        self.assertTrue(status["recall_index_pending"])
        self.assertFalse(status["complete"])
        self.assertIn("recall_index_pending", status["issues"])

    def test_restart_clears_a_pending_marker_when_disk_state_is_exactly_indexed(self):
        layering = self._layering()
        with mock.patch.object(el, "_append_lines", side_effect=OSError("shard write failed")):
            with self.assertRaises(OSError):
                layering.recall.add_batch([record(0)])
        restarted = ExperienceLayering(base_dir=self.dir / "exp")
        status = restarted.history_status()
        self.assertTrue(status["complete"], "a marker left after no durable append is stale")
        self.assertFalse(status["recall_index_pending"])
        self.assertFalse((self.dir / "exp" / "recall" / "recall-index.pending").exists())


class DurabilityTests(Base):
    def test_the_process_umask_is_never_touched(self):
        calls = []
        with mock.patch.object(el.os, "umask", side_effect=lambda mask: calls.append(mask) or 0o22):
            el._atomic_write_text(self.dir / "fresh.txt", "x")
        self.assertEqual(calls, [], "a process-wide umask change races with every other thread")

    def test_a_new_file_gets_the_permissions_a_plain_open_would_give(self):
        old = os.umask(0o027)
        try:
            el._atomic_write_text(self.dir / "fresh.txt", "x")
            plain = self.dir / "plain.txt"
            plain.write_text("x")
        finally:
            os.umask(old)
        self.assertEqual((self.dir / "fresh.txt").stat().st_mode & 0o777, plain.stat().st_mode & 0o777)

    def test_a_real_directory_sync_failure_is_reported(self):
        with mock.patch.object(el.os, "fsync", side_effect=OSError(5, "I/O error")):
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                synced = el._fsync_directory(self.dir)
        self.assertFalse(synced)
        self.assertTrue(
            [w for w in caught if issubclass(w.category, RuntimeWarning)],
            "a swallowed I/O error makes 'atomic' sound more durable than it is",
        )

    def test_a_filesystem_that_cannot_sync_a_directory_is_quiet(self):
        import errno
        with mock.patch.object(el.os, "fsync", side_effect=OSError(errno.EINVAL, "not supported")):
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                synced = el._fsync_directory(self.dir)
        self.assertFalse(synced)
        self.assertEqual([w for w in caught if issubclass(w.category, RuntimeWarning)], [])


class ArchiveOnlyAfterStoredTests(Base):
    CUTOFF = __import__("datetime").datetime(2099, 1, 1)

    def _recall(self):
        recall = RecallLayer(self.dir / "recall")
        recall.add_batch([record(i) for i in range(3)])
        return recall

    def test_without_an_archiver_nothing_is_deleted(self):
        recall = self._recall()
        shards = sorted((self.dir / "recall").glob("recall-*.jsonl"))
        before = [sha(p) for p in shards]
        self.assertEqual(recall.archive_old_data(self.CUTOFF), [])
        self.assertEqual([sha(p) for p in sorted((self.dir / "recall").glob("recall-*.jsonl"))], before)
        self.assertEqual(len(recall.query("actor:step")), 3, "the index must still point at the kept shard")

    def test_an_archiver_that_declines_leaves_shard_and_index_alone(self):
        recall = self._recall()
        self.assertEqual(recall.archive_old_data(self.CUTOFF, archive=lambda records: False), [])
        self.assertEqual(len(recall.query("actor:step")), 3)

    def test_a_truthy_non_bool_archive_result_does_not_delete(self):
        recall = self._recall()
        self.assertEqual(recall.archive_old_data(self.CUTOFF, archive=lambda records: 1), [])
        self.assertEqual(len(recall.query("actor:step")), 3)

    def test_an_archiver_that_confirms_lets_the_shard_go_after_it_has_the_records(self):
        recall = self._recall()
        taken = []

        def archive(records):
            taken.extend(records)
            shards_while_archiving = list((self.dir / "recall").glob("recall-*.jsonl"))
            self.assertTrue(shards_while_archiving, "the shard must still exist while the archiver runs")
            return True

        archived = recall.archive_old_data(self.CUTOFF, archive=archive)
        self.assertEqual(len(archived), 3)
        self.assertEqual(len(taken), 3)
        self.assertEqual(list((self.dir / "recall").glob("recall-*.jsonl")), [])
        self.assertEqual(recall.query("actor:step"), [])

    def test_an_archiver_that_raises_keeps_the_shard(self):
        recall = self._recall()

        def archive(records):
            raise OSError("archive store unavailable")

        with self.assertRaises(OSError):
            recall.archive_old_data(self.CUTOFF, archive=archive)
        self.assertEqual(len(recall.query("actor:step")), 3)

    def test_the_archive_check_through_the_coordinator_no_longer_deletes_anything(self):
        layering = ExperienceLayering(base_dir=self.dir / "exp", recall_window_days=0)
        layering.recall.add_batch([record(i) for i in range(3)])
        layering._check_and_archive()
        self.assertEqual(len(layering.recall.query("actor:step")), 3)
        self.assertFalse(layering.archival.archive([record(0)]), "the stub must say it stored nothing")

    def test_a_retry_after_unlink_failure_reuses_archive_identity_and_deduplicates(self):
        recall = self._recall()
        shard = sorted((self.dir / "recall").glob("recall-*.jsonl"))[0]
        calls = []
        stored = {}

        def archive(batch):
            self.assertIsInstance(batch, el.ArchiveBatch)
            calls.append((batch.shard_id, batch.digest))
            stored.setdefault(batch.shard_id, tuple(batch.records))
            return True

        real_unlink = Path.unlink
        failed = {"once": True}

        def unlink_once(path, *args, **kwargs):
            if path == shard and failed["once"]:
                failed["once"] = False
                raise OSError("crash after archive commit")
            return real_unlink(path, *args, **kwargs)

        with mock.patch.object(Path, "unlink", autospec=True, side_effect=unlink_once):
            with self.assertRaises(OSError):
                recall.archive_old_data(self.CUTOFF, archive=archive)

        self.assertEqual(len(calls), 1, "the first attempt must reach the archive callback")
        archived = recall.archive_old_data(self.CUTOFF, archive=archive)
        self.assertEqual(len(calls), 2, "retry must be explicit and observable")
        self.assertEqual(calls[0], calls[1], "retry must identify the same stable shard batch")
        self.assertEqual(len(stored), 1, "an idempotent archiver stores a committed batch once")
        self.assertEqual(len(archived), 3)
        self.assertEqual(list((self.dir / "recall").glob("recall-*.jsonl")), [])


if __name__ == "__main__":
    unittest.main()
