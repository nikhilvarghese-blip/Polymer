from __future__ import annotations

import subprocess
from pathlib import Path


def run_command(argv: list[str], timeout: int = 1800, cwd: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        argv,
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
        shell=False,
    )
