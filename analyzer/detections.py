"""Detection rules that run over parsed auth events.

Each rule looks for one pattern and returns a list of Finding objects.
The thresholds are defaults, not hard truths. A busy server might need a
higher brute force threshold than a home lab box.
"""

import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import timedelta
from typing import List

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}

# Commands that are worth a second look when someone runs them with sudo.
# \b is a word boundary, so "nc" matches the netcat command but not "rsync".
SENSITIVE_SUDO = {
    "reads password hashes": re.compile(r"/etc/shadow\b"),
    "edits accounts": re.compile(r"\b(useradd|usermod|userdel|passwd|visudo)\b"),
    "opens permissions": re.compile(r"\bchmod\s+(-R\s+)?777\b"),
    "downloads a file": re.compile(r"\b(wget|curl)\b"),
    "netcat": re.compile(r"(^|/)(nc|ncat|netcat)\b"),
    "flushes firewall": re.compile(r"\biptables\s+-F\b"),
    "stops a service": re.compile(r"\bsystemctl\s+(stop|disable)\b"),
}


@dataclass
class Finding:
    rule: str
    severity: str
    mitre: str
    ip: str = ""
    users: List[str] = field(default_factory=list)
    count: int = 0
    first_seen: str = ""
    last_seen: str = ""
    detail: str = ""


def _fmt(ts):
    return ts.strftime("%Y-%m-%d %H:%M:%S")


def _failures_by_ip(events):
    grouped = defaultdict(list)
    for e in events:
        if e.event_type == "failed_password" and e.ip:
            grouped[e.ip].append(e)
    for ip in grouped:
        grouped[ip].sort(key=lambda e: e.timestamp)
    return grouped


def _busiest_window(attempts, window):
    """Slide a time window over sorted attempts and return the busiest stretch.

    Uses two pointers: 'start' moves forward whenever the window gets wider
    than allowed, so each attempt is looked at a fixed number of times.
    """
    best = (0, 0, 0)  # (count, start index, end index)
    start = 0
    for end in range(len(attempts)):
        while attempts[end].timestamp - attempts[start].timestamp > window:
            start += 1
        size = end - start + 1
        if size > best[0]:
            best = (size, start, end)
    return best


def detect_brute_force(events, threshold=5, window_minutes=10):
    """One IP failing to log in many times in a short window (ATT&CK T1110.001)."""
    window = timedelta(minutes=window_minutes)
    findings = []
    for ip, attempts in _failures_by_ip(events).items():
        count, i, j = _busiest_window(attempts, window)
        if count < threshold:
            continue
        burst = attempts[i : j + 1]
        users = sorted({a.user for a in burst})
        findings.append(
            Finding(
                rule="Brute force",
                severity="high" if count >= threshold * 4 else "medium",
                mitre="T1110.001 Password Guessing",
                ip=ip,
                users=users,
                count=count,
                first_seen=_fmt(burst[0].timestamp),
                last_seen=_fmt(burst[-1].timestamp),
                detail=f"{count} failed logins within {window_minutes} minutes",
            )
        )
    return findings


def detect_password_spray(events, min_users=5, window_minutes=30):
    """One IP trying many different usernames, usually with a few common passwords (T1110.003)."""
    window = timedelta(minutes=window_minutes)
    findings = []
    for ip, attempts in _failures_by_ip(events).items():
        start = 0
        best_users = set()
        best_span = (None, None)
        for end in range(len(attempts)):
            while attempts[end].timestamp - attempts[start].timestamp > window:
                start += 1
            users = {a.user for a in attempts[start : end + 1]}
            if len(users) > len(best_users):
                best_users = users
                best_span = (attempts[start].timestamp, attempts[end].timestamp)
        if len(best_users) >= min_users:
            findings.append(
                Finding(
                    rule="Password spray",
                    severity="medium",
                    mitre="T1110.003 Password Spraying",
                    ip=ip,
                    users=sorted(best_users),
                    count=len(best_users),
                    first_seen=_fmt(best_span[0]),
                    last_seen=_fmt(best_span[1]),
                    detail=f"{len(best_users)} different usernames tried within {window_minutes} minutes",
                )
            )
    return findings


def detect_success_after_failures(events, min_failures=3):
    """A successful login from an IP that already failed several times.

    This is the most important rule. It can mean the attacker finally guessed
    the password (T1078 Valid Accounts).
    """
    findings = []
    failures_so_far = defaultdict(int)
    for e in sorted(events, key=lambda e: e.timestamp):
        if not e.ip:
            continue
        if e.event_type == "failed_password":
            failures_so_far[e.ip] += 1
        elif e.event_type == "accepted_login" and failures_so_far[e.ip] >= min_failures:
            findings.append(
                Finding(
                    rule="Login success after failures",
                    severity="high",
                    mitre="T1078 Valid Accounts",
                    ip=e.ip,
                    users=[e.user],
                    count=failures_so_far[e.ip],
                    first_seen=_fmt(e.timestamp),
                    last_seen=_fmt(e.timestamp),
                    detail=f"{e.method} login for '{e.user}' after {failures_so_far[e.ip]} failed attempts",
                )
            )
    return findings


def detect_root_attempts(events):
    """Any remote attempt to log in directly as root. Most hardened servers block this."""
    by_ip = defaultdict(list)
    for e in events:
        if e.user == "root" and e.event_type in ("failed_password", "accepted_login") and e.ip:
            by_ip[e.ip].append(e)
    findings = []
    for ip, hits in by_ip.items():
        hits.sort(key=lambda e: e.timestamp)
        succeeded = any(h.event_type == "accepted_login" for h in hits)
        findings.append(
            Finding(
                rule="Direct root login",
                severity="high" if succeeded else "low",
                mitre="T1078.003 Local Accounts",
                ip=ip,
                users=["root"],
                count=len(hits),
                first_seen=_fmt(hits[0].timestamp),
                last_seen=_fmt(hits[-1].timestamp),
                detail="root login SUCCEEDED" if succeeded else f"{len(hits)} root login attempts",
            )
        )
    return findings


def detect_sensitive_sudo(events):
    """sudo commands that touch accounts, credentials, firewall rules, or download files."""
    findings = []
    for e in events:
        if e.event_type != "sudo_command" or not e.command:
            continue
        hits = [label for label, pattern in SENSITIVE_SUDO.items() if pattern.search(e.command)]
        if hits:
            findings.append(
                Finding(
                    rule="Sensitive sudo command",
                    severity="medium",
                    mitre="T1548.003 Sudo and Sudo Caching",
                    users=[e.user],
                    count=1,
                    first_seen=_fmt(e.timestamp),
                    last_seen=_fmt(e.timestamp),
                    detail=f"{e.user} ran as {e.target_user}: {e.command.strip()} ({', '.join(hits)})",
                )
            )
    return findings


def run_all(events, threshold=5, window_minutes=10):
    findings = []
    findings += detect_brute_force(events, threshold, window_minutes)
    findings += detect_password_spray(events)
    findings += detect_success_after_failures(events)
    findings += detect_root_attempts(events)
    findings += detect_sensitive_sudo(events)
    findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.first_seen))
    return findings
