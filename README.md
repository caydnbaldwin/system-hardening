# system-hardening
Dynamic Linux hardening script for Debian- and RHEL-based systems. It runs recon, computes allowlists for users/services/ports/groups, and enforces changes only when `--apply` is set.

## How it works
- Recon: gather OS, services, users, SSH, and firewall context.
- Allowlist: build required users/services/ports/groups from inputs + discovery.
- Enforce: lock/disable by default; destructive actions are opt-in.

## Inputs
- Flags: supply `--services` (required) and optional `--users`, `--groups`, `--ports`.
- Prompts: if any input is missing, the script will prompt interactively.
- `--non-interactive`: fail fast if required inputs are missing.

## Config file
- `config.txt` must live at repo root and be invoked as: `./harden.sh config.txt`.
- The config file overrides all CLI flags and prompts.
- Use `key=value` lines (see [config.txt](config.txt)).

## Flags
- `--services` Required services (comma-separated).
- `--users` Required users (comma-separated).
- `--groups` Required groups (comma-separated).
- `--ports` Allowed inbound ports (comma-separated, optionally `port/proto`).
- `--apply` Apply changes (default is report-only).
- `--ssh-password-only` Disable SSH key auth; require passwords (competition mode).
- `--non-interactive` Fail if required inputs are missing.
- `--lock-users` Lock non-required users (default).
- `--delete-users` Delete non-required users (dangerous).
- `--rotate-passwords` Rotate passwords for eligible users (opt-in).
- `--purge` Uninstall known unsafe packages (opt-in).
- `--min-uid` Override minimum UID threshold (default from `/etc/login.defs`).
- `--firewall-rollback` Roll back nftables/iptables after N seconds (opt-in).

## Safety notes
- Apply mode requires root (`sudo`).
- Destructive actions (`--delete-users`, `--rotate-passwords`, `--purge`) are opt-in.
- Firewall enforcement prefers active `ufw` or `firewalld`, then falls back to `nftables` or `iptables`.
- Firewall rollback applies to `nftables` and `iptables` only and requires interactive confirmation.

## Usage
Example commands:
./harden.sh --services "ssh,http" --users "root,devteam" --ports "22,80,443" --apply
./harden.sh config.txt
