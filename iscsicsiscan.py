#!/usr/bin/env python3
"""ISCSISCAN - detects whether a host genuinely exposes an iSCSI service.

Unlike a simple port scan, this tool attempts a real iSCSI discovery
(SendTargets) against the target host: it doesn't just check that TCP
port 3260 is open, it verifies that an iSCSI service actually responds
to the protocol behind it.

No connection to any target, no mount, no file read: this tool ONLY
detects / lists the advertised targets. To go further (connection,
read-only mount, file retrieval), use iscsicsi.py.

Dependencies: none (Python 3.8+, standard library); requires the
open-iscsi system tools (iscsiadm).

Only use this on hosts you own or are explicitly authorized to test.
"""
import os
import shutil
import socket
import subprocess
import sys

VERSION = "1.0.0"

# ------------------------------------------------------------------ banner
BANNER = r"""
 ___ ____   ____ ____ ___ ____   ____    _    _   _
|_ _/ ___| / ___/ ___|_ _/ ___| / ___|  / \  | \ | |
 | |\___ \| |   \___ \| |\___ \| |     / _ \ |  \| |
 | | ___) | |___ ___) | | ___) | |___ / ___ \| |\  |
|___|____/ \____|____/___|____/ \____/_/   \_\_| \_|
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
    print(paint(f"  iSCSI detection - v{VERSION}\n", 70, stream), file=stream)


def ok(msg: str) -> None:
    print(paint(f"[+] {msg}", 34))


def warn(msg: str) -> None:
    print(paint(f"[!] {msg}", 142))  # olive-yellow


def err(msg: str) -> None:
    print(paint(f"[x] {msg}", 160))  # red


def run(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, check=check)


def require_root() -> None:
    if os.geteuid() != 0:
        err("This script must be run with sudo (iscsiadm needs it).")
        sys.exit(1)


def require_tools() -> None:
    if shutil.which("iscsiadm") is None:
        err("Missing tool: iscsiadm. Install open-iscsi.")
        sys.exit(1)


def tcp_check(ip: str, port: int, timeout: float = 5.0) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def iscsi_discover(ip: str, port: str) -> list[str]:
    """Attempts a real iSCSI discovery (SendTargets). Returns the IQNs found,
    an empty list if the port responds over TCP but not iSCSI, raises
    SystemExit if the command cannot run at all."""
    proc = run(
        ["iscsiadm", "-m", "discovery", "-t", "sendtargets", "-p", f"{ip}:{port}"],
        check=False,
    )
    if proc.returncode != 0:
        return []

    iqns = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) >= 2:
            iqns.append(parts[1])
    return sorted(set(iqns))


def main() -> None:
    print_banner()
    if len(sys.argv) < 2:
        print("Usage: sudo python3 iscsiscan.py <target_ip> [port=3260]")
        sys.exit(1)

    ip = sys.argv[1]
    port = sys.argv[2] if len(sys.argv) > 2 else "3260"

    require_root()
    require_tools()

    ok(f"TCP test on {ip}:{port} ...")
    port_open = tcp_check(ip, int(port))
    if not port_open:
        err(f"Port {port} closed or unreachable on {ip}. No iSCSI here.")
        sys.exit(1)
    ok(f"Port {port} open.")

    ok("Attempting a real iSCSI discovery (SendTargets) ...")
    iqns = iscsi_discover(ip, port)

    print()
    if iqns:
        ok(f"iSCSI CONFIRMED on {ip}:{port} — {len(iqns)} target(s) advertised:")
        for iqn in iqns:
            print(f"    - {iqn}")
        print()
        warn("To explore/retrieve files: iscsicsi.py")
        sys.exit(0)
    else:
        warn(f"Port {port} open but NO valid iSCSI response received.")
        warn("The port is probably open with no real iSCSI service behind it"
             " (or an ACL/firewall silently blocks discovery).")
        sys.exit(2)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        warn("Interrupted by user.")
        sys.exit(1)
