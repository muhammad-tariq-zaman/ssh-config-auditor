"""Audit an ssh_config file for risky settings.

Usage: python3 main.py ssh_config
Checks, per Host block (and global settings): PasswordAuthentication yes,
PubkeyAuthentication no, StrictHostKeyChecking no, ForwardAgent yes.
"""
import argparse
import sys


def parse_ssh_config(text):
    """Return {host_pattern: {key: value}}; global settings under '*'."""
    blocks = {"*": {}}
    current = "*"
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.lower().startswith("host "):
            current = line.split(None, 1)[1].strip()
            blocks.setdefault(current, {})
            continue
        parts = line.split(None, 1)
        if len(parts) == 2:
            blocks[current][parts[0].lower()] = parts[1].strip().lower()
    return blocks


def audit(blocks):
    """Return a list of (host, setting, message) findings."""
    findings = []
    for host, settings in blocks.items():
        if settings.get("passwordauthentication") == "yes":
            findings.append((host, "PasswordAuthentication",
                             "password authentication enabled"))
        if settings.get("pubkeyauthentication") == "no":
            findings.append((host, "PubkeyAuthentication",
                             "public-key authentication disabled"))
        if settings.get("stricthostkeychecking") == "no":
            findings.append((host, "StrictHostKeyChecking",
                             "host-key checking disabled"))
        if settings.get("forwardagent") == "yes":
            findings.append((host, "ForwardAgent",
                             "agent forwarding enabled"))
    return findings


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", help="Path to an ssh_config file")
    args = parser.parse_args(argv)
    with open(args.path, encoding="utf-8") as f:
        findings = audit(parse_ssh_config(f.read()))
    print(f"{len(findings)} finding(s).")
    for host, setting, message in findings:
        print(f"- [{host}] {setting}: {message}")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
