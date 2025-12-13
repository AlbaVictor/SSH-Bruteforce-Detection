#!/usr/bin/env python3
# =============================================================
# Script: group_failed_logins.py
# Purpose:
#   Parse Linux SSH auth logs (e.g., /var/log/auth.log) and produce
#   simple SOC-style summaries of failed SSH logins:
#     1) Top source IPs
#     2) Top usernames targeted
#     3) Top (src_ip, username) pairs
# =============================================================

"""
group_failed_logins.py

Typical usage:
  python3 python/group_failed_logins.py --log data/auth.log

Output:
  - Top source IPs by failures
  - Top usernames targeted
  - Top (src_ip, user) pairs
"""

# -----------------------------
# Imports
# -----------------------------
from __future__ import annotations

import argparse
import re
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable

# -----------------------------
# Regex pattern (log parser)
# What this does:
#   Extracts month/day/time, host, username, source IP, and source port
#   from OpenSSH "Failed password" log lines.
#
# Matches examples like:
#   Dec 12 14:03:04 ubuntu sshd[4121]: Failed password for invalid user admin from 203.0.113.91 port 42201 ssh2
#   Dec 12 14:03:04 ubuntu sshd[4121]: Failed password for victor from 203.0.113.91 port 42201 ssh2
# -----------------------------
FAILED_RE = re.compile(
    r"^(?P<mon>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd\[\d+\]:\s+Failed password for\s+"
    r"(?:(?:invalid user)\s+)?(?P<user>\S+)\s+from\s+"
    r"(?P<src_ip>\d{1,3}(?:\.\d{1,3}){3})\s+port\s+(?P<src_port>\d+)\s+ssh2"
)

# -----------------------------
# Month mapping
# Why this exists:
#   Syslog-style timestamps in auth.log usually omit the year,
#   so we reconstruct a datetime using a user-supplied year.
# -----------------------------
MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

# -----------------------------
# Data structure for one parsed failed attempt
# -----------------------------
@dataclass(frozen=True)
class FailedAttempt:
    ts: datetime
    host: str
    user: str
    src_ip: str
    src_port: int

# -----------------------------
# Timestamp helper
# What this does:
#   Convert "Dec 12 14:03:04" + year into a real datetime object.
# -----------------------------
def parse_ts(mon: str, day: str, time_str: str, year: int) -> datetime:
    month = MONTHS.get(mon)
    if month is None:
        raise ValueError(f"Unknown month token: {mon}")

    return datetime(
        year, month, int(day),
        int(time_str[0:2]), int(time_str[3:5]), int(time_str[6:8])
    )

# -----------------------------
# Core parser
# What this does:
#   Reads each line, applies FAILED_RE, and yields FailedAttempt objects.
# -----------------------------
def iter_failed_attempts(lines: Iterable[str], year: int) -> Iterable[FailedAttempt]:
    for line in lines:
        m = FAILED_RE.search(line)
        if not m:
            continue

        yield FailedAttempt(
            ts=parse_ts(m.group("mon"), m.group("day"), m.group("time"), year),
            host=m.group("host"),
            user=m.group("user"),
            src_ip=m.group("src_ip"),
            src_port=int(m.group("src_port")),
        )

# -----------------------------
# Main function (CLI + reporting)
# What this does:
#   - Parse CLI args
#   - Read/parse the log file
#   - Count failures by IP/user/pair
#   - Print top-N summaries
# -----------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description="Summarize failed SSH logins from Linux auth logs.")
    ap.add_argument("--log", default="data/auth.log", help="Path to auth.log (default: data/auth.log)")
    ap.add_argument("--year", type=int, default=2025, help="Year to assume for timestamps (default: 2025)")
    ap.add_argument("--top", type=int, default=10, help="How many rows to show (default: 10)")
    args = ap.parse_args()

    # Read file + parse events
    try:
        with open(args.log, "r", encoding="utf-8", errors="replace") as f:
            attempts = list(iter_failed_attempts(f, year=args.year))
    except FileNotFoundError:
        print(f"[ERROR] File not found: {args.log}")
        return 2

    # If nothing matched our parser, end gracefully
    if not attempts:
        print("No failed SSH attempts found (no matching 'Failed password' lines).")
        return 0

    # Aggregations (simple SOC-style stats)
    by_ip = Counter(a.src_ip for a in attempts)
    by_user = Counter(a.user for a in attempts)
    by_pair = Counter((a.src_ip, a.user) for a in attempts)

    # Time range
    first_ts = min(a.ts for a in attempts)
    last_ts = max(a.ts for a in attempts)

    # Output
    print(f"Parsed {len(attempts)} failed attempts from: {args.log}")
    print(f"Time range: {first_ts}  →  {last_ts}\n")

    print(f"Top {args.top} source IPs by failures")
    for ip, c in by_ip.most_common(args.top):
        print(f"  {ip:15}  {c}")
    print()

    print(f"Top {args.top} usernames targeted")
    for user, c in by_user.most_common(args.top):
        print(f"  {user:15}  {c}")
    print()

    print(f"Top {args.top} (src_ip, user) pairs")
    for (ip, user), c in by_pair.most_common(args.top):
        print(f"  {ip:15}  {user:15}  {c}")

    return 0

# -----------------------------
# Entry point
# -----------------------------
if __name__ == "__main__":
    raise SystemExit(main())
