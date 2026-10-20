"""Run the expansion assertions against the pinned rollback target, never enforcement code."""
import subprocess
import sys


def test_pinned_expansion_runtime_contracts():
    result = subprocess.run([sys.executable, "-I", "tests/support/expand_snapshot_driver.py"],
                            capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stdout + result.stderr
