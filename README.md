# SSH Brute-Force Detector and Auto-Blocker

A small Python tool for Linux that reads the SSH authentication log, finds failed login attempts, counts them per IP address, and blocks the IPs that fail too many times using `iptables`.

It is a simple version of professional tools such as Fail2ban, built as a mini project to learn Linux logs, Python and basic server security.

## Why this project?

Any server on the internet is attacked by people who try to guess SSH passwords. Every wrong attempt is saved in `/var/log/auth.log`. Reading that file by hand is slow, so this tool does it automatically.

## How it works

```
auth.log -> find "Failed password" lines -> extract IP and username
         -> count attempts per IP -> 5 or more? -> block with iptables
         -> save report.json
```

1. Reads the log file line by line.
2. Uses a regular expression to find failed SSH logins.
3. Counts the failed attempts for each IP address.
4. Marks an IP as an offender if it reaches the threshold (default: 5).
5. Blocks the offender with `iptables` (or only prints the command in dry-run mode).
6. Saves a report in `report.json`.

## Features

- Dry-run mode by default (nothing is blocked unless you use `--block`)
- Configurable threshold
- Whitelist, so you never block your own IP (default: `127.0.0.1`)
- Skips IPs that are already blocked
- Shows the most tried usernames
- Saves a JSON report
- Clear error messages for a missing file or missing permission

## Requirements

- Linux (tested on Kali Linux in VirtualBox)
- Python 3
- `iptables` (needed only for real blocking)
- Root access (`sudo`) for real blocking and for reading `/var/log/auth.log`

## Usage

Dry-run on the sample log (safe, blocks nothing):

```bash
python3 detector.py --log sample_auth.log
```

Real blocking (needs sudo):

```bash
sudo python3 detector.py --log sample_auth.log --block
sudo iptables -L -n
```

Run on the real system log:

```bash
sudo python3 detector.py
```

Options:

| Option | Meaning | Default |
|---|---|---|
| `--log` | Log file to read | `/var/log/auth.log` |
| `--threshold` | Failed attempts before blocking | `5` |
| `--whitelist` | IPs that must never be blocked | `127.0.0.1` |
| `--block` | Really block IPs (otherwise dry-run) | off |
| `--report` | Report file name | `report.json` |

To remove the test rule afterwards:

```bash
sudo iptables -D INPUT -s 203.0.113.45 -j DROP
```

## Sample output

```
=== SSH Failed Login Detector (DRY-RUN) ===
Total failed attempts found: 8
Different IP addresses     : 2

Top usernames tried by attackers:
   admin           6 times
   root            2 times

Attempts per IP address:
   203.0.113.45      6 attempts -> OFFENDER
   [DRY-RUN] Would run: iptables -A INPUT -s 203.0.113.45 -j DROP
   198.51.100.7      2 attempts -> ok

Report saved to report.json
```

The IP addresses above are fake test addresses.

## Files

| File | Purpose |
|---|---|
| `detector.py` | The main tool |
| `sample_auth.log` | Sample log with fake failed logins for safe testing |
| `report.json` | Example report created by the tool |

## Safety notes

- Always test in dry-run mode first.
- Keep your own IP in the whitelist so you cannot lock yourself out.
- Rules added with `iptables` are lost after a reboot unless you save them.

## Future improvements

- Time windows (for example, 5 failures in 10 minutes) and automatic unblock
- Run automatically with `cron` or a `systemd` timer
- Email or Telegram alerts
- GeoIP lookup of attacker countries
- Upload reports to AWS S3 and deploy on an EC2 server

## Tech stack

Python, Linux, iptables, regex, Kali Linux, VirtualBox
