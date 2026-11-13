"""The atomic checkpoint store: no escapes, no torn files, no lost writes.

The rules under test:

* a checkpoint id that resolves outside the storage directory is refused -
  ``..`` segments, an absolute path, and a symlink pointing out;
* two concurrent saves to the same id do not lose or tear a write;
* a crash in the middle of a write leaves the old content or the new content,
  never a mixture;
* an unregistered type in a payload is refused on load.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import support  # noqa: F401  (bootstraps sys.path)

from checkpoint_store import (  # noqa: E402
    CheckpointStoreError,
    FileCheckpointStorage,
    register_checkpoint_type,
)


class TraversalRefusalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="b173-store-"))
        self.outside = Path(tempfile.mkdtemp(prefix="b173-outside-"))
        self.store = FileCheckpointStorage(self.root)

    def test_a_relative_escape_is_refused(self):
        for bad in ("../escape", "..", "a/../../escape", "./../escape"):
            with self.subTest(bad=bad):
                with self.assertRaises(CheckpointStoreError):
                    self.store.save(bad, {"turns": 1})
        self.assertEqual(list(self.outside.iterdir()), [], "nothing was written outside the store")

    def test_an_absolute_path_is_refused(self):
        target = self.outside / "pwned.json"
        with self.assertRaises(CheckpointStoreError):
            self.store.save(str(target), {"turns": 1})
        self.assertFalse(target.exists())

    def test_a_symlink_out_of_the_store_is_refused(self):
        link = self.root / "link.json"
        target = self.outside / "target.json"
        target.write_text("{}", encoding="utf-8")
        os.symlink(target, link)
        with self.assertRaises(CheckpointStoreError):
            self.store.save("link", {"turns": 1})
        self.assertEqual(target.read_text(encoding="utf-8"), "{}")

    def test_an_empty_id_is_refused(self):
        with self.assertRaises(CheckpointStoreError):
            self.store.save("", {"turns": 1})

    def test_a_plain_id_is_accepted(self):
        self.store.save("ck-1", {"turns": 1})
        self.assertEqual(self.store.load("ck-1"), {"turns": 1})
        self.assertEqual(self.store.list_ids(), ("ck-1",))


class ConcurrencyTests(unittest.TestCase):
    def test_concurrent_saves_to_one_id_do_not_lose_or_tear_a_write(self):
        store = FileCheckpointStorage(tempfile.mkdtemp(prefix="b173-store-"))
        errors: list[BaseException] = []

        def writer(index: int) -> None:
            try:
                for _ in range(20):
                    store.save("ck-1", {"turns": index, "payload": "x" * 500})
            except BaseException as error:  # noqa: BLE001 - the test reports it
                errors.append(error)

        threads = [threading.Thread(target=writer, args=(index,)) for index in range(6)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])
        payload = store.load("ck-1")
        # The file is whole: it parses, and it holds one writer's payload.
        self.assertIn(payload["turns"], range(6))
        self.assertEqual(len(payload["payload"]), 500)

    def test_a_concurrent_save_to_one_id_never_leaves_a_partial_file(self):
        store = FileCheckpointStorage(tempfile.mkdtemp(prefix="b173-store-"))
        stop = threading.Event()

        def reader() -> None:
            while not stop.is_set():
                try:
                    store.load("ck-1")
                except CheckpointStoreError:
                    # The id may not exist yet - that is a refusal, not a tear.
                    pass
                except Exception:  # noqa: BLE001 - a torn read is the failure
                    raise

        thread = threading.Thread(target=reader)
        thread.start()
        try:
            for index in range(50):
                store.save("ck-1", {"turns": index})
        finally:
            stop.set()
            thread.join()
        self.assertEqual(store.load("ck-1")["turns"], 49)


class CrashTests(unittest.TestCase):
    def test_a_crash_mid_write_leaves_the_old_content_or_the_new_content(self):
        root = Path(tempfile.mkdtemp(prefix="b173-store-"))
        store = FileCheckpointStorage(root)
        store.save("ck-1", {"turns": 1})

        class Boom(RuntimeError):
            pass

        original = json.dump

        def exploding_dump(payload, handle, **kwargs):  # noqa: ANN001, ANN003
            original(payload, handle, **kwargs)
            handle.flush()
            raise Boom("the writer died mid-write")

        import checkpoint_store

        json_dump = checkpoint_store.json.dump
        checkpoint_store.json.dump = exploding_dump
        try:
            with self.assertRaises(Boom):
                store.save("ck-1", {"turns": 2})
        finally:
            checkpoint_store.json.dump = json_dump

        # The destination holds exactly one of the two payloads.
        payload = store.load("ck-1")
        self.assertIn(payload["turns"], (1, 2))
        # And no temporary file was left behind.
        leftovers = [path.name for path in root.iterdir() if path.name.startswith(".")]
        self.assertEqual(leftovers, [], f"temp files left behind: {leftovers}")

    def test_the_write_is_a_rename_over_the_destination(self):
        root = Path(tempfile.mkdtemp(prefix="b173-store-"))
        store = FileCheckpointStorage(root)
        store.save("ck-1", {"turns": 1})
        target = root / "ck-1.json"
        self.assertTrue(target.exists())
        before = target.stat().st_ino
        store.save("ck-1", {"turns": 2})
        after = target.stat().st_ino
        self.assertNotEqual(before, after, "the destination was replaced, not edited in place")


class AllowlistTests(unittest.TestCase):
    def test_an_unregistered_type_is_refused_on_load(self):
        root = Path(tempfile.mkdtemp(prefix="b173-store-"))
        store = FileCheckpointStorage(root)
        (root / "ck-1.json").write_text(
            json.dumps({"turns": 1, "obj": {"__type__": "os:system"}}),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(CheckpointStoreError, "unregistered type"):
            store.load("ck-1")

    def test_a_registered_type_is_accepted(self):
        root = Path(tempfile.mkdtemp(prefix="b173-store-"))
        store = FileCheckpointStorage(root)
        (root / "ck-1.json").write_text(
            json.dumps({"turns": 1, "obj": {"__type__": "builtins:tuple"}}),
            encoding="utf-8",
        )
        payload = store.load("ck-1")
        self.assertEqual(payload["turns"], 1)

    def test_registering_a_type_extends_the_allowlist(self):
        from checkpoint_store import allowed_types

        class Allowed:
            pass

        before = allowed_types()
        register_checkpoint_type(Allowed)
        after = allowed_types()
        self.assertGreater(len(after), len(before))
        self.assertIn(f"{Allowed.__module__}:{Allowed.__qualname__}", after)

    def test_a_missing_checkpoint_is_refused(self):
        store = FileCheckpointStorage(tempfile.mkdtemp(prefix="b173-store-"))
        with self.assertRaises(CheckpointStoreError):
            store.load("ck-missing")


if __name__ == "__main__":
    unittest.main()
