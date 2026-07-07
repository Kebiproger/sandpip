#!/usr/bin/env python3
import ctypes
import os
import sys
from pathlib import Path

def test_seccomp_ptrace():
    print("[*] Testing Seccomp: calling ptrace(PTRACE_TRACEME)...")
    libc = ctypes.CDLL(None, use_errno=True)
    res = libc.ptrace(0, 0, 0, 0)
    err = ctypes.get_errno()
    if res == -1 and err == 1:  # EPERM = 1
        print("[OK] ptrace was blocked by Seccomp (EPERM)")
    else:
        print(f"[ERROR] ptrace was not blocked correctly. Result: {res}, Errno: {err}")
        sys.exit(1)

def test_mount_namespace_ssh():
    ssh_dir = Path.home() / ".ssh"
    print(f"[*] Testing Mount Namespace: checking {ssh_dir}")
    key_path = ssh_dir / "id_rsa"
    if not key_path.exists():
        print("[OK] ~/.ssh/id_rsa is not visible (tmpfs is active)")
    else:
        print("[ERROR] ~/.ssh/id_rsa is still visible inside namespace!")
        sys.exit(1)

def test_bind_mount_env():
    env_file = Path.cwd() / ".env"
    print(f"[*] Testing Bind Mount: checking {env_file}")
    try:
        content = env_file.read_text()
        if content == "":
            print("[OK] .env file reads as empty (bind mounted to /dev/null)")
        else:
            print(f"[ERROR] .env file still contains data: {repr(content)}")
            sys.exit(1)
    except FileNotFoundError:
        print("[OK] .env file does not exist, safe")

def test_blocked_binaries():
    print("[*] Testing blocked binaries (curl)...")
    try:
        pid = os.fork()
        if pid == 0:
            try:
                os.execve("/usr/bin/curl", ["curl"], {})
                os._exit(0)
            except PermissionError:
                os._exit(100)
            except FileNotFoundError:
                os._exit(101)
            except Exception:
                os._exit(102)
        
        _, status = os.waitpid(pid, 0)
        code = os.waitstatus_to_exitcode(status)
        if code == 100:
            print("[OK] curl execution blocked at filesystem level (Permission denied)")
        elif code == 101:
            print("[OK] curl is not installed in the system, safe")
        else:
            print(f"[ERROR] curl execution returned unexpected exit code: {code}")
            sys.exit(1)
    except Exception as exc:
        print(f"[ERROR] failed to test curl: {exc}")
        sys.exit(1)

def main():
    test_seccomp_ptrace()
    test_mount_namespace_ssh()
    test_bind_mount_env()
    test_blocked_binaries()
    print("[ALL OK] SandPip v2.0 Namespace & Seccomp protection works perfectly!")

if __name__ == "__main__":
    main()
