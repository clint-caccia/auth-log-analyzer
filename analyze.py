#!/usr/bin/env python3
"""Command line entry point.

Examples:
    python analyze.py sample_logs/auth.log
    python analyze.py /var/log/auth.log --threshold 10 --window 5 --csv findings.csv
"""

import argparse
import sys
from datetime import datetime

from analyzer.detections import run_all
from analyzer.parser import parse_file
from analyzer.report import summary_text, write_csv, write_json


def main(argv=None):
    parser = argparse.ArgumentParser(description="Analyze a Linux auth.log for suspicious login activity.")
    parser.add_argument("logfile", help="path to an auth.log or secure file")
    parser.add_argument("--year", type=int, default=datetime.now().year,
                        help="year the log is from, since syslog leaves it out (default: this year)")
    parser.add_argument("--threshold", type=int, default=5,
                        help="failed logins from one IP that count as brute force (default: 5)")
    parser.add_argument("--window", type=int, default=10,
                        help="brute force time window in minutes (default: 10)")
    parser.add_argument("--csv", help="also write findings to this CSV file")
    parser.add_argument("--json", help="also write findings to this JSON file")
    args = parser.parse_args(argv)

    try:
        events = parse_file(args.logfile, args.year)
    except FileNotFoundError:
        print(f"Could not find {args.logfile}", file=sys.stderr)
        return 1

    findings = run_all(events, threshold=args.threshold, window_minutes=args.window)
    print(summary_text(events, findings))

    if args.csv:
        write_csv(findings, args.csv)
        print(f"\nWrote {len(findings)} findings to {args.csv}")
    if args.json:
        write_json(findings, args.json)
        print(f"Wrote {len(findings)} findings to {args.json}")

    # Exit code 2 when something high severity shows up, so this can be used in scripts.
    return 2 if any(f.severity == "high" for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
