import sys

import pytest

from polymer.utils.command import CommandExecutionError, run_command


def test_command_timeout_has_actionable_message():
    with pytest.raises(CommandExecutionError, match="timed out"):
        run_command(
            [sys.executable, "-c", "import time; time.sleep(1)"],
            timeout=0.01,
        )
