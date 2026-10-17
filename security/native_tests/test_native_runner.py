import io
import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import native_runner as runner


class NativeRunnerUnitTests(unittest.TestCase):
    def test_only_two_tools_no_arbitrary_command_interface(self):
        with self.assertRaises(runner.NativeRunnerError):
            runner.run_native('arbitrary-command',tool_root=Path('/missing'),input_dir=Path('/missing'),policy_dir=Path('/missing'),bwrap_path=Path('/missing'))

    def test_boolean_or_unbounded_time_and_capture_limits_rejected(self):
        for args in ({'timeout_seconds':True},{'timeout_seconds':0},{'max_stdout_bytes':2097153},{'max_stderr_bytes':1048577}):
            with self.subTest(args=args),self.assertRaises(runner.NativeRunnerError):
                runner.run_native('semgrep',tool_root=Path('/missing'),input_dir=Path('/missing'),policy_dir=Path('/missing'),bwrap_path=Path('/missing'),**args)

    def test_environment_has_no_host_token_proxy_or_pythonpath(self):
        with patch.dict(os.environ,{'OPENAI_API_KEY':'fixture-not-real','HTTPS_PROXY':'fixture-only','PYTHONPATH':'/candidate'},clear=False):
            environment=runner._safe_environment('semgrep',database_mounted=False)
        for name in ('OPENAI_API_KEY','HTTPS_PROXY','PYTHONPATH','LD_LIBRARY_PATH'):
            self.assertNotIn(name,environment)
        self.assertEqual(environment['SEMGREP_SEND_METRICS'],'off')

    def test_osv_environment_requires_prepared_database(self):
        with self.assertRaises(runner.NativeRunnerError):runner._safe_environment('osv-scanner',database_mounted=False)
        environment=runner._safe_environment('osv-scanner',database_mounted=True)
        self.assertEqual(environment['OSV_SCALIBR_LOCAL_DB_CACHE_DIRECTORY'],'/database')

    def test_semgrep_fixed_flags_prevent_fake_zero_and_suppression(self):
        with patch.object(runner,'_tool_file'),patch.object(runner,'_tool_directory'),patch.object(runner,'_existing_file'):
            command=runner._fixed_tool_command('semgrep',Path('/tool'),['src/app.py'])
        for flag in ('--error','--jobs=1','--disable-nosem','--no-rewrite-rule-ids','--metrics=off','--disable-version-check'):
            self.assertIn(flag,command)
        self.assertNotIn('python',command)
        self.assertIn('--library-path',command)
        self.assertEqual(command[-1],'/input/src/app.py')

    def test_osv_fixed_flags_disable_resolution_builds_and_network(self):
        with patch.object(runner,'_tool_file'):
            command=runner._fixed_tool_command('osv-scanner',Path('/tool'),['requirements.txt'])
        for flag in ('--offline','--no-resolve','--no-call-analysis=all','--all-packages','--no-ignore','--lockfile=/input/requirements.txt'):
            self.assertIn(flag,command)
        self.assertNotIn('--download-offline-databases',command)

    def test_input_tree_rejects_links_and_special_files(self):
        with tempfile.TemporaryDirectory() as temp:
            directory=Path(temp)
            (directory/'app.py').write_bytes(b'pass\n')
            self.assertEqual(runner._safe_tree_files(directory),['app.py'])
            (directory/'alias.py').symlink_to('app.py')
            with self.assertRaises(runner.NativeRunnerError):runner._safe_tree_files(directory)
            (directory/'alias.py').unlink()
            os.link(directory/'app.py',directory/'hard.py')
            with self.assertRaises(runner.NativeRunnerError):runner._safe_tree_files(directory)
            (directory/'hard.py').unlink()
            os.mkfifo(directory/'pipe')
            with self.assertRaises(runner.NativeRunnerError):runner._safe_tree_files(directory)

    def test_projection_cannot_accept_escape(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(runner.NativeRunnerError):runner._input_projection_arguments(Path(temp),['../escape'])

    def test_bounded_capture_does_not_keep_excess_bytes(self):
        data=bytearray()
        event=threading.Event()
        truncation={'stdout':False}
        runner._bounded_pipe_reader(io.BufferedReader(io.BytesIO(b'0123456789')),data,4,event,truncation,'stdout')
        self.assertEqual(data,b'0123')
        self.assertTrue(truncation['stdout'])
        self.assertTrue(event.is_set())

    def test_isolation_status_is_not_inferred_from_normal_stdout(self):
        self.assertEqual(runner._parse_status(b'garbage\n',False),(False,False,0))
        self.assertEqual(runner._parse_status(b'{"child-pid":2}\n{"exit-code":0}\n',False),(True,True,2))
        self.assertEqual(runner._parse_status(b'{"child-pid":2}\n',True),(False,False,0))

    def test_missing_backend_never_launches_process_fallback(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            for name in ('input','policy','tools'):(root/name).mkdir()
            (root/'input/app.py').write_text('pass\n')
            with patch.object(runner.subprocess,'Popen') as spawn:
                with self.assertRaises(runner.NativeRunnerError):
                    runner.run_native('semgrep',tool_root=root/'tools',input_dir=root/'input',policy_dir=root/'policy',bwrap_path=root/'missing-bwrap')
                spawn.assert_not_called()


if __name__=='__main__':unittest.main()
