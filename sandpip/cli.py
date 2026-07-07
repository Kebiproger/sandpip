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


def main() -> int:
    library = Path(__file__).resolve().parent / "sandpip.so"

    if not library.exists():
        library = Path(__file__).resolve().parents[1] / "build" / "sandpip.so"

    if not library.exists():
        print(
            f"sandpip: missing {library}; please reinstall or rebuild the package",
            file=sys.stderr,
        )
        return 2

    command = ["pip", *sys.argv[1:]]
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

    return subprocess.call(command, env=env)


if __name__ == "__main__":
    raise SystemExit(main())
