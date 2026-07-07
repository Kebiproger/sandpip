#!/usr/bin/env python3
import ctypes
import errno
import socket
import sys


TEST_IP = "1.1.1.1"
TEST_PORT = 443


class SockaddrIn(ctypes.Structure):
    _fields_ = [
        ("sin_family", ctypes.c_ushort),
        ("sin_port", ctypes.c_ushort),
        ("sin_addr", ctypes.c_ubyte * 4),
        ("sin_zero", ctypes.c_ubyte * 8),
    ]


def call_connect_errno() -> int:
    libc = ctypes.CDLL(None, use_errno=True)
    sockaddr = SockaddrIn()
    sockaddr.sin_family = socket.AF_INET
    sockaddr.sin_port = socket.htons(TEST_PORT)
    sockaddr.sin_addr[:] = socket.inet_aton(TEST_IP)

    ctypes.set_errno(0)
    libc.connect(
        -1,
        ctypes.byref(sockaddr),
        ctypes.sizeof(sockaddr),
    )
    return ctypes.get_errno()


def connect_was_blocked() -> bool:
    return call_connect_errno() == errno.EPERM


def main() -> int:
    mode = sys.argv[1] if len(sys.argv) > 1 else ""

    if mode == "blocked":
        print(f"[*] connecting to blocked public IP {TEST_IP}:{TEST_PORT}")
        if not connect_was_blocked():
            print("[!] public IP was not blocked")
            return 1
        print("[OK] blocked public IP without allowlist")
        return 0

    if mode == "allowed":
        print(f"[*] connecting to allowlisted public IP {TEST_IP}:{TEST_PORT}")
        err = call_connect_errno()
        if err == errno.EPERM:
            print("[!] allowlisted public IP was blocked")
            return 1
        if err != errno.EBADF:
            print("[!] allowlisted public IP did not reach the real connect syscall")
            return 1
        print("[OK] allowed public IP from SANDPIP_ALLOWED_IPS")
        return 0

    print("usage: network_allowlist.py blocked|allowed", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
