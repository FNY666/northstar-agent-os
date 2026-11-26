"""Tests for the SWE-bench batch runner, focused on resuming."""
import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "run_swe_bench_batch.py"


def _module():
    spec = importlib.util.spec_from_file_location("swe_batch", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules["swe_batch"] = module
    spec.loader.exec_module(module)
    return module


class _FakeProcess:
    def __init__(self, returncode=0):
        self.returncode = returncode


class BatchResumeTests(unittest.TestCase):
    def setUp(self):
        self.module = _module()
        self.sample = {"tasks": [{"instance_id": "a__x-1"}, {"instance_id": "b__y-2"}]}

    def _batch(self, out, **kwargs):
        params = dict(
            sample=self.sample, out=Path(out), provider="openai", model="m",
            base_url="", temperature=None, timeout=1, python=sys.executable,
            eval_python=sys.executable, log=lambda *a: None,
        )
        params.update(kwargs)
        return self.module.run_batch(**params)

    def test_an_instance_with_an_evaluation_receipt_is_not_solved_again(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            (out / "eval-a__x-1.json").write_text(json.dumps({"tasks": []}), encoding="utf-8")
            calls = []

            def fake_run(command, log):
                calls.append(command)
                return 0

            self.module._run = fake_run
            result = self._batch(out)
            self.assertIn("a__x-1", result["skipped"])
            # the solver never ran for the instance that already has a receipt
            self.assertFalse(any("a__x-1" in " ".join(c) for c in calls))

    def test_the_patch_file_is_never_truncated(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            patch_file = out / "patches.json"
            patch_file.write_text(json.dumps({"old__one-1": "diff --git a b\n"}), encoding="utf-8")
            (out / "solve-a__x-1-patches.json").write_text(
                json.dumps({"a__x-1": "diff --git a c\n"}), encoding="utf-8"
            )

            def fake_run(command, log):
                Path(log).parent.mkdir(parents=True, exist_ok=True)
                Path(log).write_text("{}", encoding="utf-8")
                return 0

            self.module._run = fake_run
            self._batch(out)
            merged = json.loads(patch_file.read_text(encoding="utf-8"))
            self.assertIn("old__one-1", merged)
            self.assertIn("a__x-1", merged)

    def test_a_second_run_skips_what_the_first_run_finished(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)

            def fake_run(command, log):
                Path(log).parent.mkdir(parents=True, exist_ok=True)
                if "run_swe_bench_eval.py" in " ".join(command):
                    name = command[command.index("--output") + 1]
                    Path(name).write_text(
                        json.dumps({"tasks": [{"instance_id": "x", "outcome": "RESOLVED_FULL"}]}),
                        encoding="utf-8",
                    )
                Path(log).write_text("{}", encoding="utf-8")
                return 0

            self.module._run = fake_run
            first = self._batch(out)
            self.assertEqual(len(first["solved"]), 2)
            second = self._batch(out)
            self.assertEqual(len(second["skipped"]), 2)
            self.assertEqual(len(second["solved"]), 0)


class BatchImageTests(unittest.TestCase):
    """The solver exports the repository out of the image, so it must exist."""

    def setUp(self):
        self.module = _module()

    def test_a_missing_image_is_pulled_for_its_own_platform(self):
        import tempfile
        calls = []

        class _Result:
            returncode = 1

        def fake_run(command, **kwargs):
            calls.append(command)
            if "inspect" in command[1]:
                return _Result()
            return _Result()

        self.module.subprocess = type("S", (), {"run": staticmethod(fake_run)})
        with tempfile.TemporaryDirectory() as tmp:
            ok = self.module._ensure_image("some/image:tag", Path(tmp) / "pull.log")
        self.assertFalse(ok)
        pulled = [c for c in calls if "pull" in c]
        self.assertTrue(pulled)
        self.assertIn("--platform", pulled[0])
        self.assertIn("linux/amd64", pulled[0])

    def test_an_image_that_is_already_present_is_not_pulled(self):
        import tempfile
        calls = []

        class _Result:
            returncode = 0

        def fake_run(command, **kwargs):
            calls.append(command)
            return _Result()

        self.module.subprocess = type("S", (), {"run": staticmethod(fake_run)})
        with tempfile.TemporaryDirectory() as tmp:
            ok = self.module._ensure_image("some/image:tag", Path(tmp) / "pull.log")
        self.assertTrue(ok)
        self.assertFalse([c for c in calls if "pull" in c])


def _fake_subprocess(run):
    """A stand-in for the subprocess module that keeps everything but run."""
    import subprocess as real

    class _Fake:
        DEVNULL = real.DEVNULL
        PIPE = real.PIPE
        STDOUT = real.STDOUT

        @staticmethod
        def run(command, **kwargs):
            return run(command, **kwargs)

    return _Fake


class BatchImageTests(unittest.TestCase):
    """The solver exports the repository out of the image, so it must exist."""

    def setUp(self):
        self.module = _module()

    def test_a_missing_image_is_pulled_for_its_own_platform(self):
        import tempfile
        calls = []

        class _Result:
            returncode = 1

        def fake_run(command, **kwargs):
            calls.append(command)
            if "inspect" in command[1]:
                return _Result()
            return _Result()

        self.module.subprocess = _fake_subprocess(fake_run)
        with tempfile.TemporaryDirectory() as tmp:
            ok = self.module._ensure_image("some/image:tag", Path(tmp) / "pull.log")
        self.assertFalse(ok)
        pulled = [c for c in calls if "pull" in c]
        self.assertTrue(pulled)
        self.assertIn("--platform", pulled[0])
        self.assertIn("linux/amd64", pulled[0])

    def test_an_image_that_is_already_present_is_not_pulled(self):
        import tempfile
        calls = []

        class _Result:
            returncode = 0

        def fake_run(command, **kwargs):
            calls.append(command)
            return _Result()

        self.module.subprocess = _fake_subprocess(fake_run)
        with tempfile.TemporaryDirectory() as tmp:
            ok = self.module._ensure_image("some/image:tag", Path(tmp) / "pull.log")
        self.assertTrue(ok)
        self.assertFalse([c for c in calls if "pull" in c])


class BatchCredentialTests(unittest.TestCase):
    """A batch without credentials must not look like a model that failed."""

    def setUp(self):
        self.module = _module()

    def test_a_missing_credential_variable_stops_the_batch(self):
        import os
        import tempfile
        os.environ.pop("NS_BATCH_TEST_KEY", None)
        with tempfile.TemporaryDirectory() as tmp:
            code = self.module.main([
                "--output", tmp,
                "--api-key-env", "NS_BATCH_TEST_KEY",
            ])
        self.assertEqual(code, 2)

    def test_an_instance_without_credentials_is_never_evaluated(self):
        import json
        import tempfile
        out = Path(tempfile.mkdtemp())
        instance = "acme__acme-1"
        (out / f"solve-{instance}.json").write_text(
            json.dumps({"tasks": [], "real_model_evaluated": False}),
            encoding="utf-8",
        )
        sample = {"tasks": [{"instance_id": instance}]}

        commands = []
        self.module._run = lambda command, log: commands.append(command) or 0
        self.module._ensure_image = lambda *a, **k: True
        self.module._image_for = lambda *a: ""
        self.module._docker_rmi = lambda *a: None

        result = self.module.run_batch(
            sample=sample,
            out=out,
            provider="openai",
            model="m",
            base_url="",
            temperature=None,
            timeout=1,
            python="python",
            eval_python="python",
            log=lambda *a: None,
        )
        self.assertFalse(commands, "no program should run for an instance with no credentials")
        self.assertFalse((out / f"eval-{instance}.json").exists())
        self.assertEqual(
            [f["code"] for f in result["failed"]],
            ["no_credentials"],
        )

    def test_an_instance_with_a_patch_is_evaluated(self):
        import json
        import tempfile
        out = Path(tempfile.mkdtemp())
        instance = "acme__acme-2"
        (out / f"solve-{instance}.json").write_text(
            json.dumps({"tasks": [], "real_model_evaluated": True}),
            encoding="utf-8",
        )
        (out / f"solve-{instance}-patches.json").write_text(
            json.dumps({instance: "diff --git a/x b/x\n"}),
            encoding="utf-8",
        )
        sample = {"tasks": [{"instance_id": instance}]}

        commands = []
        self.module._run = lambda command, log: commands.append(command) or 0
        self.module._ensure_image = lambda *a, **k: True
        self.module._image_for = lambda *a: ""
        self.module._docker_rmi = lambda *a: None

        self.module.run_batch(
            sample=sample,
            out=out,
            provider="openai",
            model="m",
            base_url="",
            temperature=None,
            timeout=1,
            python="python",
            eval_python="python",
            log=lambda *a: None,
        )
        self.assertTrue(any("run_swe_bench_eval.py" in " ".join(c) for c in commands))


if __name__ == "__main__":
    unittest.main()
