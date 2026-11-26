# Auth Log Analyzer

![tests](https://github.com/clint-caccia/auth-log-analyzer/actions/workflows/tests.yml/badge.svg)

A Python command line tool that reads a Linux `auth.log` and flags login activity a security analyst would want to look at: brute force attempts, password spraying, a successful login right after a string of failures, direct root logins, and risky `sudo` commands. Each finding is mapped to a MITRE ATT&CK technique.

I built this while studying for the CompTIA Security+ to get hands-on with the kind of log review a SOC analyst does every day. It uses only the Python standard library.

## What it detects

| Rule | What it looks for | ATT&CK |
|---|---|---|
| Brute force | One IP failing to log in 5+ times within 10 minutes (both adjustable) | T1110.001 |
| Password spray | One IP trying 5+ different usernames within 30 minutes | T1110.003 |
| Login success after failures | A successful login from an IP that already failed 3+ times | T1078 |
| Direct root login | Any remote attempt to log in as `root`, high severity if it worked | T1078.003 |
| Sensitive sudo command | `sudo` used to read `/etc/shadow`, add users, download files, flush the firewall, and similar | T1548.003 |

## Quick start

```bash
git clone https://github.com/clint-caccia/auth-log-analyzer.git
cd auth-log-analyzer

# make a fake log with four attack scenarios mixed into normal activity
python sample_logs/generate_sample.py

# analyze it
python analyze.py sample_logs/auth.log --year 2026

# save findings for a spreadsheet or another tool
python analyze.py sample_logs/auth.log --year 2026 --csv findings.csv --json findings.json
```

On a real Linux box you can point it at `/var/log/auth.log` (Ubuntu/Debian) or `/var/log/secure` (RHEL/CentOS). Reading those usually needs `sudo`.

### Options

| Flag | Default | Meaning |
|---|---|---|
| `--threshold` | 5 | failed logins from one IP that count as brute force |
| `--window` | 10 | brute force time window in minutes |
| `--year` | current year | syslog lines don't include a year, so this fills it in |
| `--csv` / `--json` | off | also write findings to a file |

The script exits with code `2` when it finds anything high severity, so it can be dropped into a cron job or a script that sends an alert.

## Sample output

From the included sample log ([full output](docs/sample_output.txt)):

```
Findings: 9 (high 2, medium 6, low 1)
------------------------------------------------------------
[HIGH  ] Brute force | 203.0.113.45
         60 failed logins within 10 minutes
         2026-11-18 03:12:00 -> 2026-11-18 03:20:35 | ATT&CK T1110.001 Password Guessing
[HIGH  ] Login success after failures | 198.51.100.88
         password login for 'deploy' after 6 failed attempts
         2026-11-18 21:07:20 -> 2026-11-18 21:07:20 | ATT&CK T1078 Valid Accounts
[MEDIUM] Password spray | 198.51.100.23
         10 different usernames tried within 30 minutes
[MEDIUM] Sensitive sudo command | deploy
         deploy ran as root: /usr/bin/cat /etc/shadow (reads password hashes)
```

The second finding is the one that matters most. Someone guessed the `deploy` account's password, and the sudo findings right after show them reading password hashes, creating a new account, and downloading a script.

## How it works

1. **Parse** (`analyzer/parser.py`). Each line is matched against a few regular expressions. The first one pulls out the timestamp, host and process, and the rest identify the event type (failed password, accepted login, invalid user, sudo command) and grab the username, IP and port. Lines that don't match, like cron sessions, get skipped.
2. **Detect** (`analyzer/detections.py`). Each rule is its own function. The brute force rule groups failures by IP, sorts them by time, and slides a 10 minute window across them with two pointers to find the busiest stretch. The success after failures rule walks through events in time order, keeps a running count of failures per IP, and flags any successful login from an IP that's already over the limit.
3. **Report** (`analyzer/report.py`). Prints a summary with top attacking IPs and targeted usernames, then the findings sorted by severity. Optionally writes CSV or JSON.

## Project layout

```
auth-log-analyzer/
├── analyze.py              # command line entry point
├── analyzer/
│   ├── parser.py           # log line -> AuthEvent
│   ├── detections.py       # detection rules -> Finding
│   └── report.py           # summary, CSV, JSON
├── sample_logs/
│   ├── generate_sample.py  # builds a fake auth.log
│   └── auth.log
├── tests/                  # pytest unit tests
└── docs/                   # sample output
```

## Tests

```bash
pip install -r requirements-dev.txt
python -m pytest -v
```

The tests cover each parser pattern, each detection rule, and the cases that should *not* trigger, like slow attempts spread over hours, failures split across different IPs, and routine sudo commands like `apt update` or `rsync`. GitHub Actions runs them on every push.

## Limitations and next steps

- A patient attacker who stays under the threshold (the `192.0.2.77` scenario in the sample) won't trip the brute force rule. A longer lookback window or a per-day count would help.
- It reads one file at a time and doesn't follow rotated logs (`auth.log.1`, `.gz`).
- It only knows OpenSSH and sudo message formats.
- Ideas: GeoIP lookup for attacker IPs, a live `--follow` mode like `tail -f`, and exporting to a SIEM format.

## Related projects

- [phishing-email-analyzer](https://github.com/clint-caccia/phishing-email-analyzer): catches the phishing emails that steal the passwords this tool would see being used.
- [nist-csf-risk-assessment](https://github.com/clint-caccia/nist-csf-risk-assessment): a CSF 2.0 assessment where this kind of log review covers the Detect function (DE.CM and DE.AE).

## About the sample data

All of the sample log data is fake. Attacker IPs come from the ranges reserved for documentation (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), so they don't belong to anyone.

## Author

**Clint Caccia**, Computer Information Systems, James Madison University
[LinkedIn](https://www.linkedin.com/in/clint-caccia-b70428354) · [GitHub](https://github.com/clint-caccia)
