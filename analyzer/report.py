"""Turn findings into a terminal summary, a CSV, or a JSON file."""

import csv
import json
from collections import Counter
from dataclasses import asdict


def summary_text(events, findings, top_n=5):
    lines = []
    failed = [e for e in events if e.event_type == "failed_password"]
    accepted = [e for e in events if e.event_type == "accepted_login"]
    invalid = [e for e in events if e.event_type == "invalid_user"]

    lines.append("=" * 60)
    lines.append("AUTH LOG SUMMARY")
    lines.append("=" * 60)
    if events:
        start = min(e.timestamp for e in events)
        end = max(e.timestamp for e in events)
        lines.append(f"Time range:        {start} to {end}")
    lines.append(f"Events parsed:     {len(events)}")
    lines.append(f"Failed logins:     {len(failed)}")
    lines.append(f"Successful logins: {len(accepted)}")
    lines.append(f"Invalid usernames: {len(invalid)}")
    lines.append("")

    if failed:
        lines.append(f"Top {top_n} source IPs by failed logins:")
        for ip, n in Counter(e.ip for e in failed).most_common(top_n):
            lines.append(f"  {ip:<18} {n}")
        lines.append("")
        lines.append(f"Top {top_n} usernames targeted:")
        for user, n in Counter(e.user for e in failed).most_common(top_n):
            lines.append(f"  {user:<18} {n}")
        lines.append("")

    by_sev = Counter(f.severity for f in findings)
    lines.append(
        f"Findings: {len(findings)} "
        f"(high {by_sev.get('high', 0)}, medium {by_sev.get('medium', 0)}, low {by_sev.get('low', 0)})"
    )
    lines.append("-" * 60)
    for f in findings:
        who = f.ip or ", ".join(f.users)
        lines.append(f"[{f.severity.upper():<6}] {f.rule} | {who}")
        lines.append(f"         {f.detail}")
        lines.append(f"         {f.first_seen} -> {f.last_seen} | ATT&CK {f.mitre}")
    if not findings:
        lines.append("No findings.")
    return "\n".join(lines)


def write_csv(findings, path):
    columns = ["severity", "rule", "ip", "users", "count", "first_seen", "last_seen", "mitre", "detail"]
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        for f in findings:
            row = asdict(f)
            row["users"] = ";".join(row["users"])
            writer.writerow({c: row[c] for c in columns})


def write_json(findings, path):
    with open(path, "w", encoding="utf-8") as handle:
        json.dump([asdict(f) for f in findings], handle, indent=2)
