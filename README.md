# ISCSICSI

> Command-line iSCSI toolkit — detect, explore and retrieve files from your own iSCSI targets, read-only.

```
 ___ ____   ____ ____ ___ ____ ____ ___
|_ _/ ___| / ___/ ___|_ _/ ___/ ___|_ _|
 | |\___ \| |   \___ \| | |   \___ \| |
 | | ___) | |___ ___) | | |___ ___) | |
|___|____/ \____|____/___\____|____/___|
```

## ⚠️ Warning

**Only use these tools on hosts you own or are explicitly authorized to test.** Connecting to an iSCSI target belonging to a third party without authorization is illegal in most jurisdictions. The authors are not responsible for unauthorized use.

## Tools

### `iscsicsiscan.py` — detection only

Checks whether a host **actually** exposes an iSCSI service, not just an open port. Attempts a real iSCSI discovery (SendTargets) and distinguishes:
- a real iSCSI service that responds (and lists its targets), from
- an open TCP port with nothing valid behind it (firewall, honeypot, misconfigured service).

Does not connect to any target, mount anything, or read any file.

```bash
sudo python3 iscsicsiscan.py <target_ip> [port=3260]
```

### `iscsicsi.py` — full exploration and retrieval

Discovery → connection to a target → mounting the disk **read-only** → interactive file browsing → copying the chosen files to `~/iscsi-loot/<target>/`. Cleans up the session at the end (umount + logout), even on error.

```bash
sudo python3 iscsicsi.py <target_ip> [port=3260]
```

Navigation: a numbered menu lets you enter a folder, select/deselect files, or whole folders with `c<N>` (e.g. `c3`; marked with `*`), `s` to confirm and copy, `0` to go up, `q` to cancel). Copies keep the folder layout under `~/iscsi-loot/<target>/`; symlinks inside copied folders are skipped. Each folder shows its total size (measured with a short time limit, shown as `>X` if cut off).

**Useful automatic behaviors:**
- **Real portal detection**: after discovery, the tool re-reads the `iscsiadm` database to find the portal actually registered, in case the server advertises an address different from the one used for discovery (NAT, multi-homed interface, IPv6…).
- **CHAP authentication**: if login fails, the tool offers to enter a CHAP username/password (masked input, never displayed on screen) and retries the connection — see "Known limitations" for how the password reaches `iscsiadm`.
- **Robust device wait**: after a successful login, it waits up to 15 seconds (with `udevadm settle`) for a disk to appear, instead of a fixed delay that is too short for a remote server with higher latency.
- **Session diagnostics**: if no disk appears despite a successful login, it prints the full session detail (`iscsiadm -m session -P 3`) before disconnecting, to distinguish a simple delay from a target with no LUN mapped on the server side.

## Installation

```bash
git clone https://forgejo.london.li/<your-account>/iscsicsi.git
cd iscsicsi
chmod +x iscsicsi.py iscsicsiscan.py
```

No external Python dependency (standard library only, Python 3.10+).

### System requirements

- `open-iscsi` (provides `iscsiadm`)
- `mount` / `umount` / `lsblk` (already present on any standard Linux distribution)

```bash
sudo apt install open-iscsi   # Debian/Ubuntu
```

## Why `sudo`?

`iscsiadm` and `mount` require root privileges to manage the iSCSI session database and mount block devices. Both tools check for this at startup and refuse to continue without it.

## Security and best practices

- Mounting is always **read-only** (`-o ro`) — no write is ever possible on the tested target.
- The target's filesystem is untrusted content: a symlink on it that resolves outside the mountpoint is detected and refused, both when entering it as a folder and when selecting it as a file — so a malicious target can't use one to make the tool read or copy files from your own machine instead of the target's.
- The iSCSI session is systematically closed (`--logout`) at the end, including on error or interruption (`Ctrl+C`).
- Terminal colors are automatically disabled if the output isn't a terminal, or if the `NO_COLOR` environment variable is set.
- Always test `iscsicsiscan.py` before `iscsicsi.py` to confirm a real iSCSI service responds, before attempting a full connection.

## Known limitations

- Simple numbered-menu file selector (no `fzf`/fuzzy search).
- Only one LUN/partition explored at a time per run.
- If the target restricts access by a list of allowed IQNs (ACL), neither CHAP nor the tool can bypass that — the client machine's IQN must be added on the server side.
- If the portal advertised by the server is a private/local (LAN) address while you're testing from outside, the connection can never succeed: this isn't a limitation of the tool but a lack of an actual network route, to be fixed on the server side (public portal or access from the same network).
- The entered CHAP credentials are then stored in plaintext by `iscsiadm` itself in `/etc/iscsi/nodes/<iqn>/<portal>/default` (root-only read) — normal open-iscsi behavior, not specific to this tool.
- The CHAP password is masked as you type it, but is briefly passed to `iscsiadm` as a command-line argument (its own `--op=update` has no other way to set a value) — visible to another local account running `ps` for that one call. Only relevant on a shared multi-user machine.

## License

All rights reserved. No license is granted to use, copy, modify, or
distribute this software.
