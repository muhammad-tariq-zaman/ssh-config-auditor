# ssh-config-auditor

Audit an `ssh_config` file, globally and per `Host` block, for risky
settings: password authentication on, public-key authentication off,
host-key checking off, and agent forwarding on.

## How to run

```bash
python3 main.py ssh_config
```

## Example output

```text
2 finding(s).
- [*] PasswordAuthentication: password authentication enabled
- [*] StrictHostKeyChecking: host-key checking disabled
```

Standard library only. No network access. It reads a file you supply;
it never touches your live SSH configuration.
