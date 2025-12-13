#!/usr/bin/env python3
# =============================================================
# Script: detect_bruteforce.py
# Purpose:
#   Detect SSH brute-force patterns from Linux auth logs by:
#     1) Parsing "Failed password" events
#     2) Grouping events by source IP
#     3) Alerting when failures >= threshold within a time window
# =============================================================

"""
detect_bruteforce.py

Typical usage:
  python3 python/detect_bruteforce.py --log data/auth.log --threshold 20 --window-min 10

Output:
  Prints one alert per offending IP with:
    - count of failures
    - time window start/end
    - usernames targeted
"""

# -----------------------------
# Imports
# -----------------------------
from __future__ import annotations

import argparse
import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Iterable, List

# -----------------------------
# Regex pattern (same idea as the summarizer)
# What this does:
#   Extract minimal fields we need for detection:
#     - timestamp (month/day/time)
#     - username
#     - source IP
# -----------------------------
FAILED_RE = re.compile(
    r"^(?P<mon>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd\[\d+\]:\s+Failed password for\s+"
    r"(?:(?:invalid user)\s+)?(?P<user>\S+)\s+from\s+"
    r"(?P<src_ip>\d{1,3}(?:\.\d{1,3}){3})\s+port\s+(?P<src_port>\d+)\s+ssh2"
)

# -----------------------------
# Month mapping (auth.log usually has no year)
# -----------------------------
MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

# -----------------------------
# Minimal event model for detection
# -----------------------------
@dataclass(frozen=True)
class Event:
    ts: datetime
    src_ip: str
    user: str

# -----------------------------
# Timestamp helper
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
# Load + sort events
# Why sorting matters:
#   The sliding-window logic assumes events are in chronological order.
# -----------------------------
def load_events(lines: Iterable[str], year: int) -> List[Event]:
    events: List[Event] = []

    for line in lines:
        m = FAILED_RE.search(line)
        if not m:
            continue

        events.append(Event(
            ts=parse_ts(m.group("mon"), m.group("day"), m.group("time"), year),
            src_ip=m.group("src_ip"),
            user=m.group("user"),
        ))

    events.sort(key=lambda e: e.ts)
    return events

# -----------------------------
# Detection logic (sliding window)
# What this does:
#   For each IP, keep a moving window [i..j] such that:
#     evs[j].ts - evs[i].ts <= window
#   If the number of events in that window >= threshold => alert.
# -----------------------------
def detect_bruteforce(events: List[Event], window: timedelta, threshold: int):
    # 1) Group events by IP
    per_ip: defaultdict[str, List[Event]] = defaultdict(list)
    for e in events:
        per_ip[e.src_ip].append(e)

    alerts = []

    # 2) Run sliding-window per IP
    for ip, evs in per_ip.items():
        i = 0
        for j in range(len(evs)):
            # Shrink window from the left until it fits
            while evs[j].ts - evs[i].ts > window:
                i += 1

            count = j - i + 1

            # Trigger alert once threshold is met
            if count >= threshold:
                window_events = evs[i:j + 1]
                alerts.append({
                    "src_ip": ip,
                    "count": count,
                    "start": window_events[0].ts,
                    "end": window_events[-1].ts,
                    "users": sorted({x.user for x in window_events}),
                })
                break  # Keep output simple: one alert per IP

    # Sort by highest count first
    alerts.sort(key=lambda a: a["count"], reverse=True)
    return alerts

# -----------------------------
# Main function (CLI + output)
# -----------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description="Detect SSH brute force patterns from auth.log")
    ap.add_argument("--log", default="data/auth.log", help="Path to auth.log (default: data/auth.log)")
    ap.add_argument("--year", type=int, default=2025, help="Year to assume for timestamps (default: 2025)")
    ap.add_argument("--threshold", type=int, default=20, help="Failures required to alert (default: 20)")
    ap.add_argument("--window-min", type=int, default=10, help="Time window in minutes (default: 10)")
    args = ap.parse_args()

    # Read + parse
    try:
        with open(args.log, "r", encoding="utf-8", errors="replace") as f:
            events = load_events(f, year=args.year)
    except FileNotFoundError:
        print(f"[ERROR] File not found: {args.log}")
        return 2

    if not events:
        print("No failed SSH attempts found (no matching 'Failed password' lines).")
        return 0

    # Detect
    window = timedelta(minutes=args.window_min)
    alerts = detect_bruteforce(events, window=window, threshold=args.threshold)

    if not alerts:
        print("No brute-force pattern detected with the current threshold/window.")
        return 0

    # Report
    print(f"Potential SSH brute force detected (threshold={args.threshold}, window={args.window_min}m)\n")
    for a in alerts:
        users = ", ".join(a["users"]) if a["users"] else "(none)"
        print(f"[ALERT] src_ip={a['src_ip']}  failures={a['count']}  window={a['start']} → {a['end']}")
        print(f"        usernames targeted: {users}\n")

    return 0

# -----------------------------
# Entry point
# -----------------------------
if __name__ == "__main__":
    raise SystemExit(main())

