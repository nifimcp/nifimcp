"""The unmodified public predecessor utilities still pass their own tests (regression inputs)."""
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2] / "third_party"


@pytest.mark.parametrize("folder,args,count", [
    ("flow-doctor", ["-m", "unittest", "-v"], 7),
    ("checkride", ["-m", "unittest", "discover", "-s", "tests", "-v"], 11),
    ("flowcheck", ["-m", "unittest", "-v"], 16),
])
def test_unmodified_utilities_pass(folder, args, count):
    proc = subprocess.run([sys.executable, *args], cwd=ROOT / folder, capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stderr[-2000:]
    assert f"Ran {count} tests" in proc.stderr
