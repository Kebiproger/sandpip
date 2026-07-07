#!/usr/bin/env python3
import os
import socket
import ctypes
import shutil
from pathlib import Path


def try_read_secret(path: Path) -> None:
    print(f"[*] reading {path}")
    try:
        path.read_text(encoding="utf-8", errors="replace")
        print("[!] read succeeded")
    except PermissionError as exc:
        print(f"[OK] blocked read: {exc}")
    except FileNotFoundError:
        print("[OK] file does not exist; hook still protects matching paths")


def try_exec(command: list[str]) -> None:
    executable = shutil.which(command[0])
    if executable is None:
        print(f"[OK] binary not installed: {command[0]}")
        return

    command = [executable, *command[1:]]
    print(f"[*] executing {' '.join(command)}")
    pid = os.fork()
    if pid == 0:
        libc = ctypes.CDLL(None, use_errno=True)
        argv = (ctypes.c_char_p * (len(command) + 1))()
        for index, value in enumerate(command):
            argv[index] = value.encode()
        argv[len(command)] = None

        env = (ctypes.c_char_p * 1)()
        env[0] = None

        libc.execve(command[0].encode(), argv, env)
        err = ctypes.get_errno()
        os._exit(100 if err == 13 else 101)

    _, status = os.waitpid(pid, 0)
    code = os.waitstatus_to_exitcode(status)
    if code == 100:
        print("[OK] blocked exec: Permission denied")
    else:
        print(f"[!] exec was not blocked; child exit code {code}")


def try_network() -> None:
    if os.environ.get("SANDPIP_ENFORCE_NETWORK") != "1":
        print("[*] network filter disabled; set SANDPIP_ENFORCE_NETWORK=1 to test it")
        return

    print("[*] connecting to 1.1.1.1:443")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        sock.connect(("1.1.1.1", 443))
        print("[!] network connect succeeded")
    except PermissionError as exc:
        print(f"[OK] blocked network: {exc}")
    finally:
        if "sock" in locals():
            sock.close()


def main() -> None:
    home = Path.home()
    try_read_secret(home / ".ssh" / "id_rsa")
    try_read_secret(home / ".npmrc")
    try_read_secret(Path.cwd() / ".env")
    try_exec(["curl", "https://example.com"])
    try_exec(["sh", "-i"])
    try_network()


if __name__ == "__main__":
    main()
