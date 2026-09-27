"""Red test: _connect_mcp_clients should pass args.workspace as workspace_root, not cwd."""
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

# Append parent to import cli
sys.path.insert(0, str(Path(__file__).parent.parent))
from cli import _connect_mcp_clients


def test_connect_mcp_clients_passes_workspace_root_from_args_not_cwd():
    """When allow_roots=True, workspace_root must be args.workspace absolute path, not cwd."""
    # Setup: cwd != workspace
    fake_workspace = Path("/fake/workspace").resolve()
    fake_cwd = Path("/fake/cwd").resolve()
    assert fake_workspace != fake_cwd, "Test precondition: workspace and cwd must differ"

    # Mock args with workspace != cwd (full attributes to avoid getattr on MagicMock)
    args = MagicMock()
    args.workspace = str(fake_workspace)
    args.mcp_protocol = "auto"
    args.mcp_allow_sensitive_input = False
    args.mcp_allow_roots = True
    args.mcp_max_rounds = 3
    args.mcp_elicit = False  # disable elicitor to avoid _mcp_elicitor call

    captured_options = {}

    # Mock McpStdioClient to capture workspace_root
    with patch("mcp_client.McpStdioClient") as MockClient, \
         patch("mcp_client.mcp_tool_specs", return_value=[]), \
         patch.object(Path, "cwd", return_value=fake_cwd):
        
        def capture_init(name, command, **kwargs):
            captured_options.update(kwargs)
            mock_instance = MagicMock()
            mock_instance.negotiation = None
            mock_instance.connect = MagicMock()
            mock_instance.close = MagicMock()
            return mock_instance
        
        MockClient.side_effect = capture_init
        
        registry = MagicMock()
        servers = [("test-server", ["echo", "test"])]
        
        _connect_mcp_clients(servers, timeout_ms=5000, registry=registry, args=args)
    
    # Red test assertion: should fail with current buggy code (Path.cwd())
    # but pass after fix (args.workspace absolute)
    assert "workspace_root" in captured_options, "workspace_root should be passed to McpStdioClient"
    actual = captured_options["workspace_root"]
    expected = fake_workspace
    
    if actual != expected:
        print(f"ASSERTION FAILED (expected - proves bug exists):")
        print(f"  Expected workspace_root: {expected}")
        print(f"  Actual workspace_root:   {actual}")
        print(f"  Bug confirmed: cli.py line 984 passes Path.cwd() instead of args.workspace")
        raise AssertionError(f"Expected workspace_root={expected}, got {actual}")
    else:
        print(f"ASSERTION PASSED (bug is fixed):")
        print(f"  workspace_root correctly set to: {actual}")


if __name__ == "__main__":
    try:
        test_connect_mcp_clients_passes_workspace_root_from_args_not_cwd()
        print("\n✓ TEST PASSED")
        sys.exit(0)
    except AssertionError as e:
        print(f"\n✗ TEST FAILED: {e}")
        sys.exit(1)

