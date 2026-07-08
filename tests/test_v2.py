#!/usr/bin/env python3
import ctypes
import os
import sys
import shutil
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
    print("[*] Testing blocked binaries...")
    target_bin = None
    for path in ["/usr/bin/curl", "/bin/curl", "/usr/bin/wget", "/bin/wget", "/usr/bin/nc", "/bin/nc"]:
        if os.path.exists(path):
            target_bin = path
            break
            
    if not target_bin:
        print("[OK] No blacklisted binaries (curl/wget/nc) found in the system, safe")
        return

    print(f"[*] Testing blocked binary: {target_bin}")
    try:
        pid = os.fork()
        if pid == 0:
            try:
                os.execve(target_bin, [target_bin], {})
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
            print(f"[OK] {target_bin} execution blocked at filesystem level (Permission denied)")
        elif code == 101:
            print(f"[OK] {target_bin} is not found inside namespace, safe")
        else:
            print(f"[ERROR] {target_bin} execution returned unexpected exit code: {code}")
            sys.exit(1)
    except Exception as exc:
        print(f"[ERROR] failed to test binary blocking: {exc}")
        sys.exit(1)

def test_pid_namespace():
    print("[*] Testing PID Namespace: checking /proc visibility")
    try:
        pids = [d for d in os.listdir('/proc') if d.isdigit()]
        print(f"[*] Visible PIDs in /proc: {len(pids)}")
        if len(pids) <= 5: # PID 1, 2, and a few others are normal
            print("[OK] PID isolation is active (very few processes visible)")
        else:
            print(f"[ERROR] Too many processes visible in /proc: {len(pids)}")
            sys.exit(1)
    except Exception as exc:
        print(f"[ERROR] failed to check PID namespace: {exc}")
        sys.exit(1)

def main():
    test_seccomp_ptrace()
    test_mount_namespace_ssh()
    test_bind_mount_env()
    test_blocked_binaries()
    test_pid_namespace()
    print("[ALL OK] SandPip v2.0 Namespace & Seccomp protection works perfectly!")

if __name__ == "__main__":
    main()
