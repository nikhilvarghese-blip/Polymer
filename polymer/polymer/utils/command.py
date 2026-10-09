from __future__ import annotations

import subprocess
from pathlib import Path


class CommandExecutionError(RuntimeError):
    """Raised when a scanner process cannot be started or exceeds its deadline."""


def run_command(argv: list[str], timeout: float = 1800, cwd: Path | None = None) -> subprocess.CompletedProcess:
    if not argv or not argv[0]:
        raise CommandExecutionError("scanner command is empty")
    if timeout <= 0:
        raise CommandExecutionError(f"scanner timeout must be positive, got {timeout}")
    try:
        return subprocess.run(
            argv,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            shell=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise CommandExecutionError(
            f"command {argv[0]!r} timed out after {timeout}s"
        ) from exc
    except OSError as exc:
        raise CommandExecutionError(
            f"could not execute {argv[0]!r}: {exc}"
        ) from exc
