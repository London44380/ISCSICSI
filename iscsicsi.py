#!/usr/bin/env python3
"""ISCSICSI - discovers and retrieves files from an iSCSI target.

Testing tool for your own infrastructure: discovers the iSCSI targets
exposed by a host (port 3260 by default), lets you pick a target, mounts
it READ-ONLY, lets you browse its files with an interactive selector,
and copies whatever you pick to a local folder ("loot").
The session is cleaned up at the end (umount + logout), even on error.

Dependencies: none (Python 3.8+, standard library only); requires the
open-iscsi system tools (iscsiadm), mount, umount, lsblk.

Only use this on hosts you own or are explicitly authorized to test.
"""
import getpass
import glob
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

VERSION = "1.0.0"

# ------------------------------------------------------------------ banner
BANNER = r"""
 ___ ____   ____ ____ ___ ____ ____ ___
|_ _/ ___| / ___/ ___|_ _/ ___/ ___|_ _|
 | |\___ \| |   \___ \| | |   \___ \| |
 | | ___) | |___ ___) | | |___ ___) | |
|___|____/ \____|____/___\____|____/___|
"""
GREENS = [22, 28, 34, 40, 70]  # military green gradient (256-color palette)


def use_color(stream):
    return stream.isatty() and "NO_COLOR" not in os.environ


def paint(text, code, stream=sys.stdout):
    return f"\033[38;5;{code}m{text}\033[0m" if use_color(stream) else text


def print_banner(stream=sys.stderr):
    lines = BANNER.strip("\n").split("\n")
    for i, line in enumerate(lines):
        print(paint(line, GREENS[i % len(GREENS)], stream), file=stream)
    print(paint(f"  iSCSI target explorer - v{VERSION}\n", 70, stream), file=stream)


def ok(msg: str) -> None:
    print(paint(f"[+] {msg}", 34))


def warn(msg: str) -> None:
    print(paint(f"[!] {msg}", 142))  # olive-yellow


def err(msg: str) -> None:
    print(paint(f"[x] {msg}", 160))  # red


# ------------------------------------------------------------------ helpers
def run(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, check=check)


def require_root() -> None:
    if os.geteuid() != 0:
        err("This script must be run with sudo (iscsiadm and mount need it).")
        sys.exit(1)


def require_tools() -> None:
    for tool in ("iscsiadm", "mount", "umount", "lsblk"):
        if shutil.which(tool) is None:
            err(f"Missing tool: {tool}. Install open-iscsi.")
            sys.exit(1)


def discover(ip: str, port: str) -> list[str]:
    ok(f"Discovering targets on {ip}:{port} ...")
    proc = run(
        ["iscsiadm", "-m", "discovery", "-t", "sendtargets", "-p", f"{ip}:{port}"],
        check=False,
    )
    if proc.returncode != 0:
        err("Discovery failed. Is the iSCSI port actually open and reachable?")
        print(proc.stderr.strip())
        sys.exit(1)

    iqns = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) >= 2:
            iqns.append(parts[1])
    if not iqns:
        warn("No target found.")
        sys.exit(0)
    return sorted(set(iqns))


def choose(items: list[str], label: str) -> str:
    if len(items) == 1:
        ok(f"Found a single {label}: {items[0]}")
        return items[0]
    print(paint(f"Choose a {label}:", 40))
    for i, item in enumerate(items, 1):
        print(f"  {i}. {item}")
    while True:
        choice = input(paint("> ", 34)).strip()
        if choice.isdigit() and 1 <= int(choice) <= len(items):
            return items[int(choice) - 1]
        print("Invalid entry.")


def node_portals(iqn: str) -> list[str]:
    """Portals (ip:port) actually registered by the discovery for this
    target. May differ from the IP used for discovery: a NAS/server
    behind NAT often advertises its LAN IP in the SendTargets response,
    not the external IP it was reached through."""
    # List ALL nodes and filter ourselves: `-m node -T <iqn>` without
    # `-p` doesn't filter reliably depending on the iscsiadm version.
    proc = run(["iscsiadm", "-m", "node"], check=False)
    portals = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) >= 2 and parts[1] == iqn:
            portal = parts[0].split(",")[0]  # "ip:port,tpgt" -> "ip:port"
            portals.append(portal)
    return sorted(set(portals))


def login(iqn: str, portal: str) -> bool:
    ok(f"Logging in to target {iqn} via {portal} ...")
    proc = run(
        ["iscsiadm", "-m", "node", "-T", iqn, "-p", portal, "--login"],
        check=False,
    )
    if proc.returncode != 0:
        err("Login failed.")
        print(proc.stderr.strip())
        return False
    return True


def configure_chap(iqn: str, portal: str) -> None:
    """Configures CHAP authentication for this node before retrying the
    login. The password is entered with masked input, never typed in
    the clear or logged by this script - but iscsiadm's own --op=update
    has no other way to set a value than as a -v argument, so it is
    briefly visible on this process's command line (e.g. to another
    local account running `ps`) for the duration of this one call. This
    is a limitation of iscsiadm's own interface, not something this
    script can avoid. iscsiadm then stores it itself in plaintext in
    /etc/iscsi/nodes/<iqn>/<portal>/default (root only), as with any
    normal open-iscsi CHAP setup."""
    username = input(paint("CHAP username: ", 34)).strip()
    password = getpass.getpass(paint("CHAP password (masked input): ", 34))
    run(
        [
            "iscsiadm", "-m", "node", "-T", iqn, "-p", portal, "--op=update",
            "-n", "node.session.auth.authmethod", "-v", "CHAP",
            "-n", "node.session.auth.username", "-v", username,
            "-n", "node.session.auth.password", "-v", password,
        ],
        check=False,
    )
    del password


def logout(iqn: str, portal: str) -> None:
    ok("Logging out of the iSCSI session ...")
    run(["iscsiadm", "-m", "node", "-T", iqn, "-p", portal, "--logout"], check=False)


SCSI_TYPES = {
    0: "disk", 1: "tape", 3: "processor", 4: "WORM", 5: "CD/DVD",
    7: "optical", 8: "medium changer", 12: "storage controller (RAID/array)",
    13: "enclosure",
}


def describe_scsi_luns(session_output: str) -> list[str]:
    """Describes each LUN of the session (type/vendor/model) by reading sysfs,
    to tell a real disk from a controller LUN (e.g. IET exposing only a
    'Controller' with no volume mapped)."""
    out = []
    for host in sorted(set(re.findall(r"Host Number:\s*(\d+)", session_output))):
        for dev in sorted(glob.glob(f"/sys/bus/scsi/devices/{host}:*:*:*")):
            def rd(name: str) -> str:
                try:
                    with open(os.path.join(dev, name)) as f:
                        return f.read().strip()
                except OSError:
                    return "?"
            raw = rd("type")
            label = SCSI_TYPES.get(int(raw), f"type {raw}") if raw.isdigit() else raw
            out.append(f"{os.path.basename(dev)}: {label} - {rd('vendor')} {rd('model')}")
    return out


def dump_session_detail() -> None:
    """Prints the detail of the active session (number of LUNs seen, etc.)
    before logging out, to diagnose a target without a device without
    having to chase the automatic logout."""
    proc = run(["iscsiadm", "-m", "session", "-P", "3"], check=False)
    if proc.returncode != 0:
        warn("Could not read session detail.")
        return
    print(paint("--- Session detail (iscsiadm -m session -P 3) ---", 40))
    print(proc.stdout.strip())
    print(paint("--- end of detail ---", 40))
    if "Attached scsi disk" in proc.stdout:
        ok("At least one disk is attached according to iscsiadm (Attached scsi disk) "
           "— the device should exist. Check 'lsblk' manually if needed.")
    elif re.search(r"scsi\d+ Channel", proc.stdout):
        for line in describe_scsi_luns(proc.stdout):
            warn(f"LUN seen by the kernel -> {line}")
        warn("The target exposes a SCSI LUN but no DISK is attached (probably a "
             "controller/enclosure LUN 0, or the disk LUN is not mapped to this "
             "initiator). Map a disk LUN to this IQN on the server side.")
    else:
        warn("No LUN/disk listed in the session: the target is probably exposing "
             "nothing to this initiator (ACL by IQN restricting visible LUNs, or "
             "target created with no LUN attached on the server side).")


def list_block_devices() -> set[str]:
    proc = run(["lsblk", "-ndo", "NAME"], check=False)
    return set(proc.stdout.split())


def wait_for_new_block_devices(before: set[str], timeout: float = 15.0) -> list[str]:
    """Waits for a new block device to appear after login, instead of a
    fixed delay: a remote server with higher latency (vs a LAN test) may
    take longer to surface the LUN. Also triggers `udevadm settle` to let
    the kernel/udev finish creating the node before checking again."""
    deadline = time.monotonic() + timeout
    while True:
        run(["udevadm", "settle", "--timeout=2"], check=False)
        after = list_block_devices()
        new = sorted(after - before)
        if new or time.monotonic() >= deadline:
            return [f"/dev/{name}" for name in new]
        time.sleep(1)


def list_partitions(device: str) -> list[str]:
    """Lists the partitions of `device`. Partition nodes can show up a moment
    after the disk itself, so ask the kernel to re-read the table and let
    udev settle first; otherwise we could wrongly fall back to the whole
    disk and fail to mount it."""
    run(["partprobe", device], check=False)
    run(["udevadm", "settle", "--timeout=5"], check=False)
    for attempt in range(3):
        proc = run(["lsblk", "-nlo", "NAME,TYPE", device], check=False)
        parts = []
        for line in proc.stdout.splitlines():
            fields = line.split()
            if len(fields) == 2 and fields[1] == "part":
                parts.append(f"/dev/{fields[0]}")
        if parts:
            return parts
        time.sleep(1)
    return [device]


def explain_mount_failure(device: str) -> None:
    """Gives a hint about WHY the mount failed (no filesystem, LUKS, LVM,
    BitLocker...) instead of only the raw mount error."""
    proc = run(["blkid", "-p", "-o", "export", device], check=False)
    info = dict(line.split("=", 1) for line in proc.stdout.splitlines() if "=" in line)
    fstype = info.get("TYPE") or info.get("PTTYPE")
    hints = {
        "crypto_LUKS": "LUKS-encrypted volume: unlock it with cryptsetup first.",
        "LVM2_member": "LVM physical volume: activate it (vgchange -ay) and mount the logical volume.",
        "BitLocker": "BitLocker-encrypted volume: use dislocker.",
        "ntfs": "NTFS volume: may be dirty/hibernated, or ntfs-3g is missing.",
        "xfs": "XFS volume: the xfs kernel module may be missing, or the log needs replay.",
        "zfs_member": "ZFS member: import the pool instead of mounting.",
        "linux_raid_member": "RAID member: assemble the array (mdadm) first.",
    }
    if not fstype:
        warn(f"No filesystem or partition table detected on {device}: the LUN is "
             "probably blank or uses a raw/unknown format.")
    else:
        warn(f"{device}: detected type '{fstype}'. " + hints.get(
            fstype, "The kernel could not mount it; check the matching module/tool."))
    if fstype == "LVM2_member":
        # Read-only lookup of the VG name; nothing is activated here.
        vg = run(["pvs", "--noheadings", "-o", "vg_name", device],
                 check=False).stdout.strip() or "<vg>"
        warn("To access it manually (read-only):\n"
             f"    sudo vgchange -ay {vg}\n"
             f"    sudo lvs {vg}\n"
             f"    sudo mount -o ro /dev/{vg}/<lv> /mnt/test\n"
             "    (if the LV is LUKS-encrypted: cryptsetup open first)")
    # Keep only kernel lines about this disk/storage; drop unrelated noise
    # (firewall blocks, network chatter...) that happens to be most recent.
    name = Path(device).name
    base = name.rstrip("0123456789") if not name.startswith(("nvme", "mmcblk")) else name
    relevant = re.compile(
        rf"\b({re.escape(name)}|{re.escape(base)})\b|iscsi|scsi|lvm|device-mapper|"
        r"ext[234]|xfs|btrfs|ntfs|fat|squashfs|I/O error|crypt", re.I)
    lines = run(["dmesg"], check=False).stdout.strip().splitlines()
    tail = [l for l in lines if relevant.search(l) and "UFW" not in l][-5:]
    if tail:
        warn("Last kernel messages:\n    " + "\n    ".join(tail))


def mount_readonly(device: str) -> Path | None:
    mountpoint = Path(f"/mnt/iscsicsi-{int(time.time())}")
    mountpoint.mkdir(parents=True, exist_ok=True)
    ok(f"Mounting {device} read-only on {mountpoint} ...")
    proc = run(["mount", "-o", "ro", device, str(mountpoint)], check=False)
    if proc.returncode != 0:
        err(f"Mount failed: {proc.stderr.strip()}")
        explain_mount_failure(device)
        mountpoint.rmdir()
        return None
    return mountpoint


def escapes_mount(entry: Path, root: Path) -> bool:
    """True if entry (possibly a symlink) resolves outside the read-only
    mount. The remote target is untrusted content: a symlink planted on
    its filesystem could otherwise point anywhere on the local machine
    (e.g. /etc, /home), and following it would silently read/copy local
    files instead of the remote target's actual content."""
    try:
        entry.resolve().relative_to(root.resolve())
        return False
    except ValueError:
        return True


def browse_and_select(root: Path) -> list[Path]:
    """Numbered-menu navigation. Returns the chosen files."""
    selected: list[Path] = []
    current = root
    while True:
        try:
            entries = sorted(current.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower()))
        except PermissionError:
            warn(f"Access denied: {current}")
            current = current.parent if current != root else root
            continue

        print(paint(f"\nCurrent folder: {current}", 40))
        print(f"  (selected so far: {len(selected)})")
        for i, entry in enumerate(entries, 1):
            if escapes_mount(entry, root):
                tag = "blocked symlink"
            else:
                tag = "DIR" if entry.is_dir() else "file"
            print(f"  {i}. [{tag}] {entry.name}")
        print("  0. .. (go up)")
        print("  s. Finish selection and copy")
        print("  q. Quit without copying")

        choice = input(paint("> ", 34)).strip().lower()
        if choice == "q":
            return []
        if choice == "s":
            return selected
        if choice == "0":
            current = current.parent if current != root else root
            continue
        if choice.isdigit() and 1 <= int(choice) <= len(entries):
            entry = entries[int(choice) - 1]
            if escapes_mount(entry, root):
                warn(f"'{entry.name}' is a symlink pointing outside the mounted "
                     "filesystem - refusing to follow it (would read local files, "
                     "not the remote target's).")
            elif entry.is_dir():
                current = entry
            elif entry in selected:
                selected.remove(entry)
                ok(f"Deselected: {entry.name}")
            else:
                selected.append(entry)
                ok(f"Selected: {entry.name}")
        else:
            print("Invalid entry.")


def copy_selected(files: list[Path], loot_dir: Path) -> None:
    loot_dir.mkdir(parents=True, exist_ok=True)
    for f in files:
        dest = loot_dir / f.name
        try:
            shutil.copy2(f, dest)
            ok(f"Copied: {f} -> {dest}")
        except Exception as e:
            err(f"Failed to copy {f}: {e}")


def main() -> None:
    print_banner()
    if len(sys.argv) < 2:
        print("Usage: sudo python3 iscsicsi.py <target_ip> [port=3260]")
        sys.exit(1)

    ip = sys.argv[1]
    port = sys.argv[2] if len(sys.argv) > 2 else "3260"

    require_root()
    require_tools()

    before_devices = list_block_devices()

    iqns = discover(ip, port)
    iqn = choose(iqns, "target")

    portals = node_portals(iqn)
    if not portals:
        err("No portal registered for this target after discovery.")
        sys.exit(1)
    portal = choose(portals, "portal")
    if portal != f"{ip}:{port}":
        warn(f"The NAS/server advertises a portal different from the one used for "
             f"discovery ({ip}:{port}): probably NAT. Using {portal}.")

    if not login(iqn, portal):
        warn("If the target requires authentication, it's probably CHAP.")
        retry = input(paint("Enter CHAP credentials and retry? (y/n) ", 142)).strip().lower()
        if retry != "y":
            sys.exit(1)
        configure_chap(iqn, portal)
        if not login(iqn, portal):
            err("Login still refused with CHAP. Check the credentials or the server's ACL.")
            sys.exit(1)

    ok("Connected. Waiting for a block device (up to 15s) ...")
    new_devices = wait_for_new_block_devices(before_devices)
    if not new_devices:
        err("No new block device detected after 15s of connection.")
        warn("The iSCSI session is indeed established (login succeeded), so this isn't "
             "a network/auth problem.")
        dump_session_detail()
        logout(iqn, portal)
        sys.exit(1)

    device = choose(new_devices, "disk")
    partitions = list_partitions(device)
    partition = choose(partitions, "partition")

    mountpoint = mount_readonly(partition)
    if mountpoint is None:
        logout(iqn, portal)
        sys.exit(1)

    try:
        selected = browse_and_select(mountpoint)
        if selected:
            loot_dir = Path.home() / "iscsi-loot" / re.sub(r"[^A-Za-z0-9._-]", "_", iqn)
            copy_selected(selected, loot_dir)
            ok(f"Done. Files in: {loot_dir}")
        else:
            warn("No file copied.")
    finally:
        ok("Cleaning up ...")
        run(["umount", str(mountpoint)], check=False)
        try:
            mountpoint.rmdir()
        except OSError:
            pass
        logout(iqn, portal)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        warn("Interrupted by user.")
        sys.exit(1)
