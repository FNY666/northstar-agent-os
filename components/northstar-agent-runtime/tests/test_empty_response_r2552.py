"""Empty model response protocol tests (R2552 v2 criterion).

Criterion under test (loop.py _finish_without_tools):
  subtype = error_during_execution  iff  the whole run made NO tool call
                                         AND the final assistant text is empty/whitespace.
  otherwise                         success (postconditions unchanged).

Result groups (each is a real sdk.run over ScriptedProvider):
  G1 streamed non-empty text, no tools          -> success      (real ScriptedTurn.streamed)
  G2 tool call then silent (empty) finish       -> success
  G3 no tools, empty text                       -> error_during_execution
  G4 no tools, whitespace-only text             -> error_during_execution
  G5 streamed all-empty text, no tools          -> error_during_execution
  NC ordinary text, no tools (non-stream)       -> success
"""
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

sys.path.insert(0, '.')

import sdk
from hooks import HookResult
from postconditions import PostCondition
from providers.scripted import ScriptedProvider, ScriptedTurn
from support import HookRegistry, RuntimeTestCase


def _run(turns, *, stream=False):
    with TemporaryDirectory() as tmp:
        ws = Path(tmp)
        (ws / 'dummy.txt').write_text('content\n')
        provider = ScriptedProvider(turns=turns)
        return sdk.run(sdk.RunOptions(
            prompt='Test prompt',
            workspace=str(ws),
            provider=provider,
            max_turns=5,
            stream=stream,
        ))


def test_g1_streamed_nonempty_no_tools_is_success():
    report = _run(
        [ScriptedTurn.streamed('Here is my response.', ['', 'Here is my response.'])],
        stream=True,
    )
    assert report.subtype == 'success', f'G1 must be success, got {report.subtype}'
    assert report.tool_calls == 0


def test_g2_tool_then_silent_finish_is_success():
    report = _run([
        ScriptedTurn.tool('Read', {'path': 'dummy.txt'}),
        ScriptedTurn.text(''),
    ])
    assert report.subtype == 'success', f'G2 must be success, got {report.subtype}'
    assert report.tool_calls == 1, f'G2 tool_calls must be 1, got {report.tool_calls}'


def test_g3_no_tools_empty_text_is_error():
    report = _run([ScriptedTurn.text('')])
    assert report.subtype == 'error_during_execution', f'G3 must be error, got {report.subtype}'
    assert report.is_error


def test_g4_no_tools_whitespace_is_error():
    report = _run([ScriptedTurn.text('   \n')])
    assert report.subtype == 'error_during_execution', f'G4 must be error, got {report.subtype}'
    assert report.is_error


def test_g5_streamed_all_empty_no_tools_is_error():
    report = _run(
        [ScriptedTurn.streamed('', [''])],
        stream=True,
    )
    assert report.subtype == 'error_during_execution', f'G5 must be error, got {report.subtype}'
    assert report.is_error


def test_nc_ordinary_text_no_tools_is_success():
    report = _run([ScriptedTurn.text('Task completed')])
    assert report.subtype == 'success', f'NC must be success, got {report.subtype}'
    assert not report.is_error


class R2567BoundaryTests(RuntimeTestCase):
    def test_postconditions_run_after_success_but_not_empty_error_boundary(self):
        root = self.workspace({"task.txt": "before"})
        runtime = self.runtime(
            [ScriptedTurn.tool("Edit", {"path": "task.txt", "old_string": "before", "new_string": "after"}),
             ScriptedTurn.text("")],
            workspace=root,
            postconditions=[PostCondition(kind="exists", path="task.txt")],
        )
        report = self.drive(runtime)
        self.assertEqual(report.subtype, "success")
        records = [e for e in report.events if getattr(e, "subtype", "") == "postconditions"]
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].data["passed"], 1)

        empty = self.drive(self.runtime(
            [ScriptedTurn.text("")],
            postconditions=[PostCondition(kind="exists", path="never-created.txt")],
        ))
        self.assertEqual(empty.subtype, "error_during_execution")
        self.assertFalse([e for e in empty.events if getattr(e, "subtype", "") == "postconditions"])

    def test_stop_hook_and_max_turns_boundaries_remain_active(self):
        calls = []
        hooks = HookRegistry()
        hooks.register("Stop", lambda payload: calls.append(payload.turn_index) or
                       (HookResult.block("continue") if len(calls) == 1 else HookResult.allow()),
                       name="r2567-stop")
        report = self.drive(self.runtime(
            [ScriptedTurn.text("first"), ScriptedTurn.text("done")], hooks=hooks
        ))
        self.assertEqual(report.subtype, "success")
        self.assertEqual(len(calls), 2)

        limited = self.drive(self.runtime(
            provider=self.provider([ScriptedTurn.tool("LS", {"path": "."})], on_exhausted="repeat_last"),
            max_turns=1,
        ))
        self.assertEqual(limited.subtype, "error_max_turns")
