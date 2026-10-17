import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("prepare_native_tools", ROOT / "prepare-native-tools.py")
tools = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = tools
SPEC.loader.exec_module(tools)


class FakeResponse:
    def __init__(self, payload, headers=None):
        self.payload = payload
        self.headers = headers or {"Content-Length": str(len(payload))}
        self.offset = 0

    def read(self, amount):
        chunk = self.payload[self.offset:self.offset + amount]
        self.offset += len(chunk)
        return chunk

    def __enter__(self):
        return self

    def __exit__(self, *unused):
        return False


class DownloadTests(unittest.TestCase):
    def test_stream_download_records_header_hash_and_budgets(self):
        payload = b"database-data"
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "all.zip"
            response = FakeResponse(payload, {"Content-Length": str(len(payload)), "Last-Modified": "Tue, 01 Jan 2030 00:00:00 GMT"})
            with patch.object(tools, "urlopen", return_value=response) as request:
                record = tools.download_to_file(
                    tools.OSV_PYPI_ALL_URL, target, expected_sha256=None,
                    maximum_bytes=32, timeout_seconds=7, require_last_modified=True,
                )
            self.assertEqual(target.read_bytes(), payload)
            self.assertEqual(record["last_modified"], "Tue, 01 Jan 2030 00:00:00 GMT")
            self.assertEqual(record["bytes"], len(payload))
            self.assertEqual(record["byte_budget"], 32)
            self.assertEqual(request.call_args.kwargs["timeout"], 7)

    def test_bad_pinned_download_never_publishes_artifact(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "osv-scanner"
            with patch.object(tools, "urlopen", return_value=FakeResponse(b"not-the-pin")):
                with self.assertRaises(tools.ProvisionError):
                    tools.download_to_file(
                        tools.OSV_LINUX_AMD64_URL, target,
                        expected_sha256=tools.OSV_LINUX_AMD64_SHA256,
                        maximum_bytes=64, timeout_seconds=5,
                    )
            self.assertFalse(os.path.lexists(target))
            self.assertEqual(list(Path(temp).iterdir()), [])

    def test_database_without_last_modified_is_not_published(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "all.zip"
            with patch.object(tools, "urlopen", return_value=FakeResponse(b"db", {"Content-Length": "2"})):
                with self.assertRaises(tools.ProvisionError):
                    tools.download_to_file(
                        tools.OSV_PYPI_ALL_URL, target, expected_sha256=None,
                        maximum_bytes=8, timeout_seconds=5, require_last_modified=True,
                    )
            self.assertFalse(os.path.lexists(target))


class SemgrepIsolationTests(unittest.TestCase):
    def test_pip_is_offline_binary_only_and_version_uses_entry_point(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            wheelhouse = root / "wheelhouse"
            stage = root / "stage"
            wheelhouse.mkdir()
            stage.mkdir()
            completed = [
                subprocess.CompletedProcess([], 0),
                subprocess.CompletedProcess([], 0),
                subprocess.CompletedProcess([], 0, stdout=b"semgrep 1.181.0\n"),
            ]
            inherited = dict(os.environ)
            inherited["SEMGREP_APP_TOKEN"] = "must-not-pass"
            inherited["PIP_INDEX_URL"] = "https://attacker.invalid/simple"
            with patch.dict(os.environ, inherited, clear=True), patch.object(
                tools.subprocess, "run", side_effect=completed
            ) as run:
                result = tools.install_semgrep(stage, wheelhouse, "/approved/python", 9)
        self.assertEqual(result["version"], "1.181.0")
        self.assertEqual(run.call_count, 3)
        venv_command = run.call_args_list[0].args[0]
        pip_command = run.call_args_list[1].args[0]
        version_command = run.call_args_list[2].args[0]
        self.assertEqual(venv_command, ["/approved/python", "-m", "venv", str(stage / "semgrep")])
        self.assertIn("--no-index", pip_command)
        self.assertIn("--only-binary=:all:", pip_command)
        self.assertIn("semgrep==1.181.0", pip_command)
        self.assertNotIn(".", pip_command)
        self.assertEqual(version_command, [
            str(stage / "semgrep" / "bin" / "python"),
            str(stage / "semgrep" / "bin" / "semgrep"),
            "--version",
        ])
        self.assertNotIn("-m", version_command)
        for call in run.call_args_list:
            environment = call.kwargs["env"]
            self.assertEqual(environment["SEMGREP_SEND_METRICS"], "off")
            self.assertEqual(environment["SEMGREP_ENABLE_VERSION_CHECK"], "0")
            self.assertEqual(environment["PIP_CONFIG_FILE"], os.devnull)
            self.assertNotIn("SEMGREP_APP_TOKEN", environment)
            self.assertNotIn("PIP_INDEX_URL", environment)


class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.wheelhouse = self.root / "wheelhouse"
        self.wheelhouse.mkdir()
        self.bwrap = self.root / "trusted-bwrap"
        self.bwrap.write_bytes(b"trusted bwrap")
        self.bwrap.chmod(0o755)
        self.semgrep_record = {
            "version": "1.181.0",
            "path": "semgrep",
            "version_command": ["semgrep/bin/python", "semgrep/bin/semgrep", "--version"],
            "version_output": "semgrep 1.181.0",
            "install": {"network": "disabled", "only_binary": ":all:"},
        }

    def tearDown(self):
        self.temp.cleanup()

    def test_publish_is_atomic_and_manifest_records_unsigned_database(self):
        output = self.root / "native-tools"
        osv = b"pinned-osv"
        database = b"offline-pypi-db"
        with patch.object(tools, "OSV_LINUX_AMD64_SHA256", tools.hashlib.sha256(osv).hexdigest()), patch.object(
            tools, "urlopen", side_effect=[
                FakeResponse(osv),
                FakeResponse(database, {"Content-Length": str(len(database)), "Last-Modified": "Wed, 02 Jan 2030 00:00:00 GMT"}),
            ]
        ) as network, patch.object(tools, "install_semgrep", return_value=self.semgrep_record):
            result = tools.prepare(
                output, bwrap_source=self.bwrap, semgrep_wheelhouse=self.wheelhouse,
                python_executable="/approved/python", timeout_seconds=5,
            )
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(network.call_count, 2)
        manifest = json.loads((output / "tool-provisioning.json").read_text())
        self.assertEqual(manifest["tools"]["osv-scanner"]["binary"]["sha256"], tools.hashlib.sha256(osv).hexdigest())
        self.assertEqual(manifest["database"]["last_modified"], "Wed, 02 Jan 2030 00:00:00 GMT")
        self.assertFalse(manifest["database"]["signature_verified"])
        self.assertFalse(manifest["database"]["download_during_scan"])
        self.assertEqual((output / "bwrap" / "bwrap").read_bytes(), b"trusted bwrap")
        self.assertEqual(list(self.root.glob(".native-tools.tmp-*")), [])

    def test_existing_output_fails_before_network_and_is_unchanged(self):
        output = self.root / "native-tools"
        output.mkdir()
        (output / "keep").write_text("valid existing directory")
        with patch.object(tools, "urlopen") as network:
            with self.assertRaises(tools.ProvisionError):
                tools.prepare(
                    output, bwrap_source=self.bwrap, semgrep_wheelhouse=self.wheelhouse,
                    python_executable="/approved/python", timeout_seconds=5,
                )
        network.assert_not_called()
        self.assertEqual((output / "keep").read_text(), "valid existing directory")

    def test_failure_cleans_staging_and_never_creates_output(self):
        output = self.root / "native-tools"
        with patch.object(tools, "urlopen", return_value=FakeResponse(b"wrong")):
            with self.assertRaises(tools.ProvisionError):
                tools.prepare(
                    output, bwrap_source=self.bwrap, semgrep_wheelhouse=self.wheelhouse,
                    python_executable="/approved/python", timeout_seconds=5,
                )
        self.assertFalse(os.path.lexists(output))
        self.assertEqual(list(self.root.glob(".native-tools.tmp-*")), [])


if __name__ == "__main__":
    unittest.main()
