#!/usr/bin/env python3
import os
import socket
import subprocess
import tempfile
from pathlib import Path
import re
import sys

def test_logging():
    # Create a temporary log file
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        log_path = tmp.name

    os.environ["SANDPIP_LOG_FILE"] = log_path
    
    print(f"[*] Testing logging to {log_path}")

    # 1. Trigger file access block
    home = Path.home()
    secret_path = home / ".ssh" / "id_rsa"
    print(f"[*] Triggering file access block: {secret_path}")
    try:
        secret_path.read_text()
    except Exception:
        pass

    # 2. Trigger exec block
    print("[*] Triggering exec block: /usr/bin/curl")
    try:
        subprocess.run(["/usr/bin/curl", "https://example.com"], capture_output=True)
    except Exception:
        pass

    # 3. Trigger network block
    os.environ["SANDPIP_ENFORCE_NETWORK"] = "1"
    print("[*] Triggering network block: 1.1.1.1")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        sock.connect(("1.1.1.1", 443))
    except Exception:
        pass
    finally:
        if 'sock' in locals():
            sock.close()

    # Verify logs
    with open(log_path, "r") as f:
        logs = f.read()

    print("[*] Log content:")
    print(logs)

    # Regex to match: [timestamp] [BLOCK] [library] kind denied: target
    # Example: [2026-07-08 13:43:06] [BLOCK] [/usr/lib/libpython3.14.so.1.0] file access denied: /home/kebi/.ssh/id_rsa
    pattern = r"\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\] \[BLOCK\] \[([^\]]+)\] (.+?) denied: (.+)"
    
    matches = re.findall(pattern, logs)
    
    if not matches:
        print("[ERROR] No log entries found matching the expected format!")
        sys.exit(1)

    print(f"[OK] Found {len(matches)} log entries.")
    
    # Check if libraries are identified (not 'unknown')
    for lib, kind, target in matches:
        if lib == "unknown":
            print(f"[WARNING] Library not identified for {kind} on {target}")
        else:
            print(f"[OK] Identified library {lib} for {kind}")

    # Check for specific blocks
    found_file = any("file access" in m[1] for m in matches)
    found_exec = any("exec" in m[1] for m in matches)
    found_net = any("network connect" in m[1] for m in matches)

    if not (found_file and found_exec and found_net):
        print(f"[ERROR] Missing some block logs. File: {found_file}, Exec: {found_exec}, Net: {found_net}")
        sys.exit(1)

    print("[ALL OK] Logging functionality works perfectly!")
    os.unlink(log_path)

if __name__ == "__main__":
    test_logging()
