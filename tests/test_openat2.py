#!/usr/bin/env python3
import ctypes
import os
import sys

class OpenHow(ctypes.Structure):
    _fields_ = [
        ("flags", ctypes.c_uint64),
        ("mode", ctypes.c_uint64),
        ("resolve", ctypes.c_uint64),
    ]

def call_openat2(dirfd: int, path: str, flags: int, mode: int) -> int:
    libc = ctypes.CDLL(None, use_errno=True)
    SYS_openat2 = 437
    how = OpenHow()
    how.flags = flags
    how.mode = mode
    how.resolve = 0
    
    if hasattr(libc, "openat2"):
        res = libc.openat2(dirfd, path.encode(), ctypes.byref(how), ctypes.sizeof(how))
        if res < 0:
            return -ctypes.get_errno()
        return res
    else:
        res = libc.syscall(SYS_openat2, dirfd, path.encode(), ctypes.byref(how), ctypes.sizeof(how))
        if res < 0:
            return -ctypes.get_errno()
        return res

def call_syscall_open(path: str) -> int:
    libc = ctypes.CDLL(None, use_errno=True)
    SYS_open = 2
    res = libc.syscall(SYS_open, path.encode(), 0)
    if res < 0:
        return -ctypes.get_errno()
    return res

def main():
    blocked_path = os.path.expanduser("~/.ssh/id_rsa")
    print(f"[*] Testing openat2 on blocked path {blocked_path}")
    res = call_openat2(-100, blocked_path, 0, 0)
    if res == -13:
        print("[OK] openat2 blocked access as expected (EACCES)")
    else:
        print(f"[ERROR] openat2 did not block access: {res}")
        sys.exit(1)
        
    print(f"[*] Testing syscall(SYS_open) on blocked path {blocked_path}")
    res = call_syscall_open(blocked_path)
    if res == -13:
        print("[OK] syscall(SYS_open) blocked access as expected (EACCES)")
    else:
        print(f"[ERROR] syscall(SYS_open) did not block access: {res}")
        sys.exit(1)
        
    allowed_path = "/dev/null"
    print(f"[*] Testing openat2 on allowed path {allowed_path}")
    res = call_openat2(-100, allowed_path, 0, 0)
    if res >= 0:
        print("[OK] openat2 allowed access to /dev/null")
        os.close(res)
    else:
        print(f"[ERROR] openat2 blocked allowed path: {res}")
        sys.exit(1)

if __name__ == "__main__":
    main()
