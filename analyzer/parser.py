"""Parse Linux auth.log lines into structured events.

A typical sshd line looks like this:

    Nov 18 03:14:07 web01 sshd[2211]: Failed password for root from 203.0.113.45 port 52344 ssh2

Each line gets matched against a small set of regular expressions. Lines that
don't match any pattern are skipped, since auth.log has a lot of noise
(cron sessions, PAM messages, and so on) that isn't useful here.
"""

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, Iterator, Optional

# The front part every syslog line shares: "Nov 18 03:14:07 web01 sshd[2211]: "
LINE_PREFIX = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<process>[\w\-/]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.*)$"
)

# Message patterns, checked in order. The first one that matches wins.
PATTERNS = [
    (
        "failed_password",
        re.compile(
            r"^Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+) port (?P<port>\d+)"
        ),
    ),
    (
        "accepted_login",
        re.compile(
            r"^Accepted (?P<method>password|publickey) for (?P<user>\S+) from (?P<ip>[\d.]+) port (?P<port>\d+)"
        ),
    ),
    (
        "invalid_user",
        re.compile(r"^Invalid user (?P<user>\S+) from (?P<ip>[\d.]+)(?: port (?P<port>\d+))?"),
    ),
    (
        "sudo_command",
        re.compile(
            r"^(?P<user>\S+) : TTY=\S+ ; PWD=\S+ ; USER=(?P<target_user>\S+) ; COMMAND=(?P<command>.+)$"
        ),
    ),
]


@dataclass
class AuthEvent:
    timestamp: datetime
    host: str
    process: str
    event_type: str
    user: Optional[str] = None
    ip: Optional[str] = None
    port: Optional[int] = None
    method: Optional[str] = None
    target_user: Optional[str] = None
    command: Optional[str] = None
    raw: str = ""


def parse_line(line: str, year: int) -> Optional[AuthEvent]:
    """Turn one log line into an AuthEvent, or return None if it isn't one we track."""
    prefix = LINE_PREFIX.match(line.strip())
    if not prefix:
        return None

    # syslog leaves the year off, so it gets passed in.
    stamp = f"{year} {prefix['month']} {prefix['day']} {prefix['time']}"
    try:
        timestamp = datetime.strptime(stamp, "%Y %b %d %H:%M:%S")
    except ValueError:
        return None

    message = prefix["message"]
    for event_type, pattern in PATTERNS:
        found = pattern.match(message)
        if not found:
            continue
        fields = found.groupdict()
        port = fields.get("port")
        return AuthEvent(
            timestamp=timestamp,
            host=prefix["host"],
            process=prefix["process"],
            event_type=event_type,
            user=fields.get("user"),
            ip=fields.get("ip"),
            port=int(port) if port else None,
            method=fields.get("method"),
            target_user=fields.get("target_user"),
            command=fields.get("command"),
            raw=line.rstrip("\n"),
        )
    return None


def parse_lines(lines: Iterable[str], year: int) -> Iterator[AuthEvent]:
    for line in lines:
        event = parse_line(line, year)
        if event is not None:
            yield event


def parse_file(path: str, year: int) -> list:
    with open(path, encoding="utf-8", errors="replace") as handle:
        return list(parse_lines(handle, year))
