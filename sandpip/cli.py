import os
import socket
import subprocess
import sys
from pathlib import Path
from typing import Optional

DEFAULT_ALLOWED_DOMAINS = (
    "pypi.org",
    "files.pythonhosted.org",
    "github.com",
)


def split_env_list(value: Optional[str]) -> list[str]:
    if not value:
        return []

    items: list[str] = []
    for chunk in value.replace(",", " ").split():
        item = chunk.strip()
        if item:
            items.append(item)
    return items


def resolve_allowed_ips(domains: list[str]) -> list[str]:
    ips: set[str] = set()

    for domain in domains:
        try:
            results = socket.getaddrinfo(domain, None, proto=socket.IPPROTO_TCP)
        except socket.gaierror as exc:
            print(f"sandpip: warning: could not resolve {domain}: {exc}", file=sys.stderr)
            continue

        for family, _, _, _, sockaddr in results:
            if family in (socket.AF_INET, socket.AF_INET6):
                ips.add(sockaddr[0])

    return sorted(ips)


def check_v2_available(launcher_path: Path) -> bool:
    try:
        res = subprocess.run(
            [str(launcher_path), "true"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=1
        )
        return res.returncode == 0
    except Exception:
        return False


def main() -> int:
    # 1. Сначала проверяем доступность v3 (eBPF) - пока False
    v3_available = False

    # 2. Проверяем доступность v2 (Namespaces + Seccomp)
    launcher_v2 = Path(__file__).resolve().parent / "sandpip_v2_launcher"
    if not launcher_v2.exists():
        launcher_v2 = Path(__file__).resolve().parents[1] / "build" / "sandpip_v2_launcher"

    v2_available = launcher_v2.exists() and check_v2_available(launcher_v2)

    # 3. Ищем C-библиотеку v1 (LD_PRELOAD)
    library_v1 = Path(__file__).resolve().parent / "sandpip.so"
    if not library_v1.exists():
        library_v1 = Path(__file__).resolve().parents[1] / "build" / "sandpip.so"

    command = ["pip", *sys.argv[1:]]
    env = os.environ.copy()

    allowed_domains = [
        *DEFAULT_ALLOWED_DOMAINS,
        *split_env_list(env.get("SANDPIP_ALLOWED_DOMAINS")),
    ]
    allowed_ips = [
        *split_env_list(env.get("SANDPIP_ALLOWED_IPS")),
        *resolve_allowed_ips(allowed_domains),
    ]
    env.setdefault("SANDPIP_ENFORCE_NETWORK", "1")
    env["SANDPIP_ALLOWED_IPS"] = ",".join(sorted(set(allowed_ips)))
    env["SANDPIP_ALLOWED_DOMAINS"] = ",".join(allowed_domains)

    if v3_available:
        print("sandpip: using v3 eBPF isolation engine", file=sys.stderr)
        return 1
    elif v2_available:
        print("sandpip: using v2 kernel isolation engine (Namespaces & Seccomp)", file=sys.stderr)
        if library_v1.exists():
            existing_preload = env.get("LD_PRELOAD")
            env["LD_PRELOAD"] = (
                f"{library_v1} {existing_preload}" if existing_preload else str(library_v1)
            )
        v2_command = [str(launcher_v2), "pip", *sys.argv[1:]]
        return subprocess.call(v2_command, env=env)
    elif library_v1.exists():
        print("sandpip: using v1 user-space isolation engine (LD_PRELOAD)", file=sys.stderr)
        existing_preload = env.get("LD_PRELOAD")
        env["LD_PRELOAD"] = (
            f"{library_v1} {existing_preload}" if existing_preload else str(library_v1)
        )
        return subprocess.call(command, env=env)
    else:
        print(
            "sandpip: WARNING: no sandbox engine is available! Running in raw audit/warn mode.",
            file=sys.stderr,
        )
        return subprocess.call(command, env=env)


if __name__ == "__main__":
    raise SystemExit(main())
