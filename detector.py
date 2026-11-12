#!/usr/bin/env python3
"""
SSH Failed Login Detector and Auto-Blocker
------------------------------------------
Reads the Linux log file (auth.log), counts failed SSH logins per IP address,
and blocks the IPs that fail too many times using iptables.

By default it runs in DRY-RUN mode (it only prints what it WOULD block).
Use --block to really block (needs sudo).
"""

import argparse                      # to read command-line options
import json                          # to save the report file
import re                            # regex to find IP addresses in log lines
import subprocess                    # to run the iptables command
from collections import Counter      # to count attempts easily
from datetime import datetime        # to put the time in the report

# A failed SSH login line in auth.log looks like this:
# Failed password for invalid user admin from 203.0.113.45 port 5555 ssh2
# This pattern picks out the username and the IP address from such a line.
PATTERN = re.compile(
    r"Failed password for (?:invalid user )?(\S+) from (\d{1,3}(?:\.\d{1,3}){3})"
)


def read_failed_logins(log_path):
    """Read the log file and count failed attempts per IP and per username."""
    ip_counts = Counter()
    user_counts = Counter()
    try:
        with open(log_path, "r", errors="ignore") as log_file:
            for line in log_file:                 # read the file line by line
                match = PATTERN.search(line)      # look for a failed login
                if match:
                    username, ip = match.group(1), match.group(2)
                    ip_counts[ip] += 1            # +1 for this IP
                    user_counts[username] += 1    # +1 for this username
    except FileNotFoundError:
        print(f"[ERROR] Log file not found: {log_path}")
        raise SystemExit(1)
    except PermissionError:
        print("[ERROR] Permission denied. Run the script with sudo.")
        raise SystemExit(1)
    return ip_counts, user_counts


def is_already_blocked(ip):
    """Check if an iptables DROP rule already exists for this IP."""
    result = subprocess.run(
        ["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
        capture_output=True,
    )
    return result.returncode == 0                 # 0 means the rule exists


def block_ip(ip, really_block):
    """Block an IP with iptables. In dry-run mode, only print the command."""
    command = ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
    if not really_block:
        print("   [DRY-RUN] Would run:", " ".join(command))
        return "would block"
    if is_already_blocked(ip):
        print(f"   [SKIP] {ip} is already blocked")
        return "already blocked"
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode == 0:
        print(f"   [BLOCKED] {ip}")
        return "blocked"
    print(f"   [ERROR] Could not block {ip}: {result.stderr.strip()}")
    return "failed"


def main():
    # ---- 1. Command-line options ----
    parser = argparse.ArgumentParser(description="SSH failed login detector")
    parser.add_argument("--log", default="/var/log/auth.log",
                        help="log file to read (default: /var/log/auth.log)")
    parser.add_argument("--threshold", type=int, default=5,
                        help="block an IP after this many failures (default: 5)")
    parser.add_argument("--whitelist", nargs="*", default=["127.0.0.1"],
                        help="IPs that must never be blocked")
    parser.add_argument("--block", action="store_true",
                        help="really block IPs (default is dry-run)")
    parser.add_argument("--report", default="report.json",
                        help="file to save the report (default: report.json)")
    args = parser.parse_args()

    mode = "REAL BLOCKING" if args.block else "DRY-RUN"
    print(f"\n=== SSH Failed Login Detector ({mode}) ===")
    print(f"Log file : {args.log}")
    print(f"Threshold: {args.threshold} failed attempts\n")

    # ---- 2. Read the log and count ----
    ip_counts, user_counts = read_failed_logins(args.log)
    total = sum(ip_counts.values())
    print(f"Total failed attempts found: {total}")
    print(f"Different IP addresses     : {len(ip_counts)}\n")

    # ---- 3. Show the most targeted usernames ----
    print("Top usernames tried by attackers:")
    for username, count in user_counts.most_common(5):
        print(f"   {username:<15} {count} times")

    # ---- 4. Check each IP and decide ----
    print("\nAttempts per IP address:")
    results = []
    for ip, count in ip_counts.most_common():     # biggest number first
        status = "ok"
        if ip in args.whitelist:
            status = "whitelisted"
            print(f"   {ip:<16} {count:>4} attempts -> whitelisted (never blocked)")
        elif count >= args.threshold:
            print(f"   {ip:<16} {count:>4} attempts -> OFFENDER")
            status = block_ip(ip, args.block)
        else:
            print(f"   {ip:<16} {count:>4} attempts -> ok")
        results.append({"ip": ip, "failed_attempts": count, "status": status})

    # ---- 5. Save the report ----
    report = {
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "log_file": args.log,
        "threshold": args.threshold,
        "mode": mode,
        "total_failed_attempts": total,
        "results": results,
    }
    with open(args.report, "w") as report_file:
        json.dump(report, report_file, indent=2)
    print(f"\nReport saved to {args.report}\n")


if __name__ == "__main__":
    main()
