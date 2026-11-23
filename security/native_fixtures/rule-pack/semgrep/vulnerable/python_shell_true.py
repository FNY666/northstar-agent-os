"""Static toy fixture only; this function is intentionally never invoked."""

import subprocess


def run_fixture_command(command: str):
    return subprocess.run(command, shell=True, check=False)
