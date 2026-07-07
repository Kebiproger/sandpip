# SandPip

SandPip is a lightweight, secure sandbox for risky package-manager install scripts (such as `setup.py` in pip or `postinstall` in npm). 

It prevents malicious scripts from stealing credentials, spawning reverse shells, or making unauthorized network requests during package installation.

---

## Architecture & Versions

SandPip supports two levels of sandboxing depending on your security needs:

| Command | Version | Isolation Technology | Targets Blocked | Strengths |
| :--- | :--- | :--- | :--- | :--- |
| `sandpip` (or `spip`) | **v1.0** | `LD_PRELOAD` Hooking | Files, sockets, execs | Lightweight, runs in user-space, dynamic DNS registry allowlist. |
| `sandpip_v2` (or `spip2`) | **v2.0** | **Namespaces + Seccomp** | SSH/Cloud folders, ptrace, curl/wget execution | **Kernel-level protection**. Prevents escapes via static binaries or direct assembler syscalls. |

---

## Installation

Install SandPip directly from GitHub using `pip`:

```bash
pip install git+https://github.com/YOUR_GITHUB_USERNAME/sandpip.git
```

This compiles the C components automatically and registers four global commands: `sandpip`, `sandpip_v2`, `spip`, and `spip2`.

> [!NOTE]
> Compilation requires a C compiler (such as `gcc`) installed on your Linux system.

---

## Usage

### Version 1.0 (LD_PRELOAD Sandbox)
Best for general lightweight use. Intercepts glibc dynamic calls to monitor files and DNS resolution.

```bash
spip install some-package
```

### Version 2.0 (Kernel Isolation Sandbox)
Best for strict security. Isolates the process in a new Linux namespace, hiding sensitive directories at the filesystem level and blocking kernel operations via Seccomp.

```bash
spip2 install some-package
```

### Advanced Options

* **Allow a custom registry domain**:
  ```bash
  SANDPIP_ALLOWED_DOMAINS="packages.example.com" spip2 install some-package
  ```
* **Allow a raw IP address**:
  ```bash
  SANDPIP_ALLOWED_IPS="1.2.3.4" spip2 install some-package
  ```

---

## Security Features in Detail

### 1. File Access Protection
* **v1.0**: Hooks `open`, `openat`, `openat2` and blocks access to sensitive paths (like `~/.ssh/`, `~/.aws/`, `.env` files).
* **v2.0**: Uses **Mount Namespaces** to mount a clean `tmpfs` over sensitive directories (`~/.ssh`, `~/.aws`, `~/.gcp`, `~/.kube`) and bind mounts `/dev/null` over `.env` files. Inside the sandbox, these files physically do not exist.

### 2. Process Execution Protection
* **v1.0**: Hooks `execve` to block shell utilities (`curl`, `wget`, `netcat`, interactive `bash`/`sh`).
* **v2.0**: Bind mounts `/dev/null` over system binaries (`/usr/bin/curl`, `/usr/bin/wget`, `/usr/bin/nc`, etc.). Even static binaries cannot spawn these utilities.

### 3. Kernel hardening (v2.0)
* Applies a **Seccomp-BPF** filter that blocks `ptrace` (preventing process memory injection), `reboot`, `syslog`, and `kexec_load` at the kernel level with `EPERM`.

---

## Local Development & Testing

Use the provided `Makefile` to compile or run test suites locally.

### Compile
```bash
make
```

### Run Tests
```bash
make test        # Runs v1.0 file/process validation tests
make test-network # Runs v1.0 dynamic DNS registry allowlist tests
make test-v2     # Runs v2.0 kernel namespaces and seccomp validation tests
```

### Clean
```bash
make clean
```
