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
            print(f"sandpip_v2: warning: could not resolve {domain}: {exc}", file=sys.stderr)
            continue

        for family, _, _, _, sockaddr in results:
            if family in (socket.AF_INET, socket.AF_INET6):
                ips.add(sockaddr[0])

    return sorted(ips)


def main() -> int:
    # Ищем библиотеку LD_PRELOAD (сохраняем ее для сетевой изоляции)
    library = Path(__file__).resolve().parent / "sandpip.so"
    if not library.exists():
        library = Path(__file__).resolve().parents[1] / "build" / "sandpip.so"

    # Ищем бинарный C-лаунчер v2
    launcher = Path(__file__).resolve().parent / "sandpip_v2_launcher"
    if not launcher.exists():
        launcher = Path(__file__).resolve().parents[1] / "build" / "sandpip_v2_launcher"

    if not launcher.exists():
        print(
            f"sandpip_v2: missing launcher {launcher}; run `make` first",
            file=sys.stderr,
        )
        return 2

    env = os.environ.copy()
    existing_preload = env.get("LD_PRELOAD")
    env["LD_PRELOAD"] = (
        f"{library} {existing_preload}" if existing_preload else str(library)
    )

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

    print("sandpip: forcing v2 kernel isolation engine (Namespaces & Seccomp)", file=sys.stderr)
    # Запускаем C-лаунчер, который применит Namespaces/Seccomp, а затем вызовет pip
    command = [str(launcher), "pip", *sys.argv[1:]]
    return subprocess.call(command, env=env)


if __name__ == "__main__":
    raise SystemExit(main())
