"""Daily scan schedule: the instant from which a periodic scan counts as "done for today".

The fleet producer (auditors.gitlab_integration.enqueue_fleet_scan) runs every 10 minutes. With a daily time configured, a project is
due when its last finished job is older than the most recent occurrence of that time, so the whole fleet is queued right after it
(03:00 by default) instead of drifting through the day 24 h after each previous scan. A project the server could not reach at 03:00
(host down, instance unreachable) is queued on the next pass after that, so a missed night is caught up rather than skipped.

Configuration (env):
  GITLAB_SCAN_DAILY_AT  "HH:MM" local time of the daily run (default "03:00"); empty -> the older rolling GITLAB_RESCAN_HOURS interval.
  SCAN_TIMEZONE         IANA zone of that time (default "America/Mexico_City"; the containers themselves run in UTC).
"""
import os
import re
from datetime import datetime, timedelta, timezone
from typing import Optional
from zoneinfo import ZoneInfo

DEFAULT_DAILY_AT = "03:00"
DEFAULT_TIMEZONE = "America/Mexico_City"
_HHMM = re.compile(r"^([01]?\d|2[0-3]):([0-5]\d)$")


def parse_daily_at(value: str) -> tuple:
    """(hour, minute) from "HH:MM". Raises ValueError on anything else, so a typo in the configuration is reported, not ignored."""
    m = _HHMM.match((value or "").strip())
    if not m:
        raise ValueError(f"invalid daily scan time {value!r}: expected HH:MM (00:00-23:59)")
    return int(m.group(1)), int(m.group(2))


def daily_cutoff(now: Optional[datetime] = None, daily_at: str = DEFAULT_DAILY_AT, tz: str = DEFAULT_TIMEZONE) -> datetime:
    """Most recent occurrence of `daily_at` in zone `tz` at or before `now`, as an aware UTC datetime.

    Example (tz America/Mexico_City, UTC-6): at 08:00 local the cutoff is 03:00 today; at 02:00 local it is 03:00 yesterday."""
    zone = ZoneInfo(tz)
    now = (now or datetime.now(timezone.utc)).astimezone(zone)
    hour, minute = parse_daily_at(daily_at)
    cutoff = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if cutoff > now:
        cutoff -= timedelta(days=1)
    return cutoff.astimezone(timezone.utc)


def configured_fleet_cutoff(now: Optional[datetime] = None) -> Optional[datetime]:
    """Cutoff for the GitLab fleet scan from the environment, or None when GITLAB_SCAN_DAILY_AT is set to empty (rolling interval)."""
    daily_at = os.getenv("GITLAB_SCAN_DAILY_AT", DEFAULT_DAILY_AT).strip()
    if not daily_at:
        return None
    return daily_cutoff(now, daily_at, os.getenv("SCAN_TIMEZONE", DEFAULT_TIMEZONE).strip() or DEFAULT_TIMEZONE)
