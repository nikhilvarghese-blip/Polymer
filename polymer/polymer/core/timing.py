from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
import re
import subprocess


_END_TIME_PATTERN = re.compile(r"^(?P<hour>[01]\d|2[0-3]):(?P<minute>[0-5]\d)$")


def server_now() -> datetime:
    """Return the server wall clock, including its configured timezone."""

    return datetime.now().astimezone()


def resolve_end_time(value: str, started_at: datetime) -> datetime:
    """Resolve HH:MM to the next occurrence on the server clock."""

    match = _END_TIME_PATTERN.fullmatch(value.strip())
    if match is None:
        raise ValueError("end time must use 24-hour HH:MM format (for example, 18:30)")
    if started_at.tzinfo is None:
        raise ValueError("scan start time must include a timezone")

    end_at = started_at.replace(
        hour=int(match.group("hour")),
        minute=int(match.group("minute")),
        second=0,
        microsecond=0,
    )
    if end_at <= started_at:
        end_at += timedelta(days=1)
    return end_at


def ntp_sync_status() -> bool | None:
    """Best-effort status of the NTP-backed server system clock.

    Systems without systemd/timedatectl still have a usable OS clock, so an
    unknown result is recorded rather than preventing scans.
    """

    try:
        result = subprocess.run(
            ["timedatectl", "show", "--property=NTPSynchronized", "--value"],
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    value = result.stdout.strip().lower()
    if value == "yes":
        return True
    if value == "no":
        return False
    return None


@dataclass(frozen=True)
class ScanWindow:
    """A scan window based on the server's NTP-managed wall clock."""

    started_at: datetime
    end_at: datetime | None

    def remaining_seconds(self, now: datetime | None = None) -> float | None:
        if self.end_at is None:
            return None
        current = now or server_now()
        return max(0.0, (self.end_at - current).total_seconds())

    def expired(self, now: datetime | None = None) -> bool:
        remaining = self.remaining_seconds(now)
        return remaining is not None and remaining <= 0

    def timeout(self, configured_seconds: float) -> float:
        """Cap a scanner timeout to the time remaining in the window."""

        if configured_seconds <= 0:
            raise ValueError("scanner timeout must be positive")
        remaining = self.remaining_seconds()
        if remaining is None:
            return configured_seconds
        if remaining <= 0:
            raise ScanDeadlineReached("scan end time has been reached")
        return min(configured_seconds, remaining)


class ScanDeadlineReached(RuntimeError):
    """Raised when scanner work cannot continue inside the scan window."""
