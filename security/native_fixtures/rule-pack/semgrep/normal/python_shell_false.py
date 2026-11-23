"""Static toy fixture only; this function is intentionally never invoked."""

import subprocess


def run_fixed_fixture_command():
    return subprocess.run(["fixture-command"], shell=False, check=False)
