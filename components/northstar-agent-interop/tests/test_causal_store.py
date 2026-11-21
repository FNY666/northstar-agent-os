import json
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

COMPONENT_ROOT = Path(__file__).resolve().parents[1]
HOST_ROOT = COMPONENT_ROOT.parent / "northstar-host"
CONTRACT_ROOT = COMPONENT_ROOT.parent / "northstar-run-contract"
sys.path.insert(0, str(COMPONENT_ROOT))
sys.path.insert(0, str(HOST_ROOT))
sys.path.insert(0, str(CONTRACT_ROOT))

from route_causality import CausalEdge  # noqa: E402
from causal_store import CausalEvidenceRecord, CausalEvidenceStore, EvidenceCursor  # noqa: E402


class CausalEvidenceStoreTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.path = Path(self.tempdir.name) / "causal-evidence.jsonl"
        self.edge = CausalEdge.create(
            "receipt",
            "sha256:" + "1" * 64,
            "sha256:" + "2" * 64,
        )
        self.edge2 = CausalEdge.create(
            "retry",
            "sha256:" + "2" * 64,
            "sha256:" + "3" * 64,
        )

    def tearDown(self):
        self.tempdir.cleanup()

    def test_append_and_restart_recovery_verify_record_chain(self):
        store = CausalEvidenceStore(self.path)
        first = store.append(self.edge)
        second = store.append(self.edge2)
        recovery = CausalEvidenceStore(self.path).recover()
        self.assertIsInstance(first, CausalEvidenceRecord)
        self.assertIsNone(first.prev_record_digest)
        self.assertEqual(second.prev_record_digest, first.record_digest)
        self.assertEqual(recovery.verdict, "verified")
        self.assertEqual(tuple(record.edge for record in recovery.records), (self.edge, self.edge2))
        self.assertEqual(recovery.cursor, EvidenceCursor(2, second.record_digest))

    def test_same_edge_append_is_idempotent(self):
        store = CausalEvidenceStore(self.path)
        first = store.append(self.edge)
        self.assertEqual(store.append(self.edge), first)
        self.assertEqual(len(store.recover().records), 1)

    def test_recovery_rejects_tampered_record_and_cursor_rollback(self):
        store = CausalEvidenceStore(self.path)
        store.append(self.edge)
        store.append(self.edge2)
        cursor = store.recover().cursor
        rows = self.path.read_text(encoding="utf-8").splitlines()
        rows[0] = rows[0].replace("receipt", "retry")
        self.path.write_text("\n".join(rows) + "\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            CausalEvidenceStore(self.path).recover(expected_cursor=cursor)

    def test_recovery_rejects_suffix_rollback_against_pinned_cursor(self):
        store = CausalEvidenceStore(self.path)
        store.append(self.edge)
        store.append(self.edge2)
        cursor = store.recover().cursor
        rows = self.path.read_text(encoding="utf-8").splitlines()
        self.path.write_text(rows[0] + "\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            CausalEvidenceStore(self.path).recover(expected_cursor=cursor)

    def test_external_lock_blocks_append_until_released(self):
        import fcntl
        import os
        import select
        import signal
        import time

        read_fd, write_fd = os.pipe()
        lock_path = self.path.with_name(self.path.name + ".lock")
        parent_lock = lock_path.open("a+b")
        child_pid = None
        try:
            fcntl.flock(parent_lock.fileno(), fcntl.LOCK_EX)
            child_pid = os.fork()
            if child_pid == 0:
                try:
                    parent_lock.close()
                    os.close(read_fd)
                    os.write(write_fd, b"S")
                    CausalEvidenceStore(self.path).append(self.edge)
                    os.write(write_fd, b"D")
                    os._exit(0)
                except BaseException:
                    try:
                        os.write(write_fd, b"E")
                    except OSError:
                        pass
                    os._exit(1)

            os.close(write_fd)
            write_fd = -1
            ready, _, _ = select.select([read_fd], [], [], 10)
            self.assertTrue(ready)
            self.assertEqual(os.read(read_fd, 1), b"S")
            time.sleep(0.2)
            self.assertFalse(self.path.exists())
            fcntl.flock(parent_lock.fileno(), fcntl.LOCK_UN)
            parent_lock.close()
            parent_lock = None

            done, _, _ = select.select([read_fd], [], [], 20)
            self.assertTrue(done)
            self.assertEqual(os.read(read_fd, 1), b"D")
            _, status = os.waitpid(child_pid, 0)
            self.assertEqual(os.waitstatus_to_exitcode(status), 0)
            child_pid = None
        finally:
            if parent_lock is not None:
                try:
                    fcntl.flock(parent_lock.fileno(), fcntl.LOCK_UN)
                finally:
                    parent_lock.close()
            if child_pid is not None:
                try:
                    os.kill(child_pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    os.waitpid(child_pid, 0)
                except ChildProcessError:
                    pass
            for fd in (read_fd, write_fd):
                if fd >= 0:
                    try:
                        os.close(fd)
                    except OSError:
                        pass
        self.assertEqual(len(CausalEvidenceStore(self.path).recover().records), 1)

    def test_recovery_rejects_sequence_gap(self):
        store = CausalEvidenceStore(self.path)
        first = store.append(self.edge)
        second = store.append(self.edge2)
        row = json.loads(self.path.read_text(encoding="utf-8").splitlines()[1])
        row["sequence"] = 3
        self.path.write_text(
            self.path.read_text(encoding="utf-8").splitlines()[0] + "\n" + json.dumps(row) + "\n",
            encoding="utf-8",
        )
        with self.assertRaises(ValueError):
            store.recover()

    def test_append_rejects_forged_edge_digest(self):
        store = CausalEvidenceStore(self.path)
        forged = replace(self.edge, edge_digest="sha256:" + "f" * 64)
        with self.assertRaises(ValueError):
            store.append(forged)
        self.assertEqual(store.recover().records, ())

    def test_recovery_rejects_duplicate_edge_in_distinct_records(self):
        store = CausalEvidenceStore(self.path)
        first = store.append(self.edge)
        duplicate = CausalEvidenceRecord.create(
            self.edge,
            sequence=2,
            prev_record_digest=first.record_digest,
        )
        with self.path.open("ab") as stream:
            stream.write(json.dumps(duplicate.to_dict(), sort_keys=True, separators=(",", ":")).encode() + b"\n")
        with self.assertRaises(ValueError):
            store.recover()

    def test_recovery_rejects_unknown_fields_and_incomplete_tail(self):
        store = CausalEvidenceStore(self.path)
        record = store.append(self.edge)
        value = record.to_dict()
        value["unknown"] = "reject"
        self.path.write_text(json.dumps(value) + "\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            store.recover()
        self.path.write_bytes(json.dumps(record.to_dict()).encode() + b"\n{" )
        with self.assertRaises(ValueError):
            store.recover()

    def test_concurrent_same_edge_append_is_written_once(self):
        import subprocess

        result_dir = Path(self.tempdir.name) / "results"
        result_dir.mkdir(mode=0o700)
        script = Path(self.tempdir.name) / "append-child.py"
        script.write_text(
            "import sys\n"
            "from pathlib import Path\n"
            "sys.path.insert(0, sys.argv[2])\n"
            "from causal_store import CausalEvidenceStore\n"
            "from route_causality import CausalEdge\n"
            "edge = CausalEdge.create('receipt', 'sha256:' + '1' * 64, 'sha256:' + '2' * 64)\n"
            "CausalEvidenceStore(sys.argv[1]).append(edge)\n"
            "Path(sys.argv[3]).write_text('ok')\n",
            encoding="utf-8",
        )
        processes = []
        streams = []
        for index in range(4):
            result_path = result_dir / f"child-{index}"
            error_path = result_dir / f"child-{index}.err"
            error_stream = error_path.open("w")
            streams.append(error_stream)
            process = subprocess.Popen(
                [sys.executable, str(script), str(self.path), str(COMPONENT_ROOT), str(result_path)],
                stdout=subprocess.DEVNULL,
                stderr=error_stream,
            )
            processes.append((process, result_path, error_path))
        try:
            for process, result_path, error_path in processes:
                process.wait(timeout=20)
                self.assertEqual(process.returncode, 0, error_path.read_text(encoding="utf-8"))
                self.assertEqual(result_path.read_text(encoding="utf-8"), "ok")
        finally:
            for stream in streams:
                stream.close()
            for process, _result_path, _error_path in processes:
                if process.poll() is None:
                    process.kill()
                    process.wait()
        self.assertEqual(len(CausalEvidenceStore(self.path).recover().records), 1)


if __name__ == "__main__":
    unittest.main()
