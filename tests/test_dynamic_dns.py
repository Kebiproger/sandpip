#!/usr/bin/env python3
import socket
import sys

def main():
    # 1. Проверяем блокировку DNS для неразрешенного домена
    print("[*] Resolving non-allowed domain (example.com)...")
    try:
        socket.getaddrinfo("example.com", 80)
        print("[ERROR] Resolving non-allowed domain succeeded, but should have been blocked!")
        sys.exit(1)
    except socket.gaierror as exc:
        print(f"[OK] Blocked non-allowed domain resolution: {exc}")

    # 2. Проверяем успешный резолв разрешенного домена (pypi.org)
    print("[*] Resolving allowed domain (pypi.org)...")
    try:
        ips = socket.getaddrinfo("pypi.org", 443)
        print(f"[OK] Resolved pypi.org to: {[ip[4][0] for ip in ips]}")
    except socket.gaierror as exc:
        print(f"[ERROR] Failed to resolve pypi.org: {exc}")
        sys.exit(1)

    # 3. Пробуем подключиться к одному из разрешенных IP
    allowed_ip = ips[0][4][0]
    print(f"[*] Connecting to resolved allowed IP {allowed_ip}...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((allowed_ip, 443))
        print("[OK] Connected to pypi.org")
    except PermissionError as exc:
        print(f"[ERROR] pypi.org IP was blocked by network filter: {exc}")
        sys.exit(1)
    except Exception as exc:
        # Ожидаемая ошибка сети (Timeout/ConnectionRefused) — главное, что не EPERM (PermissionError)
        print(f"[OK] Reached real network (failed with: {exc})")
    finally:
        s.close()

    # 4. Проверяем, что неразрешенный IP блокируется напрямую
    blocked_ip = "8.8.8.8"
    print(f"[*] Connecting to blocked IP {blocked_ip}...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((blocked_ip, 443))
        print("[ERROR] Connection to blocked IP succeeded!")
        sys.exit(1)
    except PermissionError as exc:
        print(f"[OK] Connection to blocked IP successfully prevented: {exc}")
    finally:
        s.close()

if __name__ == "__main__":
    main()
