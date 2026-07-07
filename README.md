# SandPip

SandPip is a lightweight, secure `LD_PRELOAD` sandbox for risky package-manager install scripts (such as `setup.py` in pip or `postinstall` in npm). 

It intercepts file accesses, process executions, and network connections to protect your sensitive credentials and files from malicious code during package installation.

## Features

- **File Access Prevention**: Intercepts `open`, `open64`, `openat`, `openat64`, `openat2`, `fopen`, `fopen64` (including low-level calls via `syscall()`).
- **Dynamic DNS Allowlisting**: Intercepts DNS resolution (`getaddrinfo`, `gethostbyname`, `gethostbyname2`) to restrict network connections strictly to approved package registries (like `pypi.org`, `files.pythonhosted.org`, and `github.com`).
- **Process Blocking**: Intercepts `execve`, `execveat`, `fexecve`, `posix_spawn`, and `posix_spawnp` to block unauthorized utility executions (like `curl`, `wget`, `netcat`, and interactive shells).

### Intercepted & Blocked Targets

* **Files & Configs**:
  - `~/.ssh/`
  - `~/.aws/`
  - `~/.config/gcloud/`
  - `~/.gcp/`
  - `~/.kube/`
  - `~/.npmrc`
  - `~/.pypirc`
  - Any `.env` file or path segment
* **Network & Connects**:
  - Automatically blocks all connections to public IPs except those resolved from allowed domains.
  - By default, local (`127.0.0.1`, `localhost`) and private subnet IP addresses are allowed.
* **Process Executions**:
  - `curl`
  - `wget`
  - `nc`, `ncat`, `netcat`
  - Interactive shells (`bash -i`, `sh -i`)

---

## Installation

You can install SandPip directly from GitHub using `pip`:

```bash
pip install git+https://github.com/YOUR_GITHUB_USERNAME/sandpip.git
```

> [!NOTE]
> Since SandPip includes a C sandbox library, a C compiler (like `gcc`) must be installed on your Linux system.

---

## Usage

Once installed, the `sandpip` command becomes available globally. It acts as a wrapper around `pip`.

### Basic Usage

Simply prefix your standard `pip install` commands with `sandpip`:

```bash
sandpip install some-risky-package
```

This runs `pip` under the `LD_PRELOAD` sandbox, intercepting any filesystem, process, or network requests initiated by the package's install script.

### Custom Registry Configuration

To allow custom package registries or domains, use the `SANDPIP_ALLOWED_DOMAINS` environment variable:

```bash
SANDPIP_ALLOWED_DOMAINS="packages.example.com" sandpip install some-package
```

To allow specific raw IP addresses:

```bash
SANDPIP_ALLOWED_IPS="1.2.3.4" sandpip install some-package
```

---

## Local Development & Compilation

For local hacking or testing, you can use the provided `Makefile`.

### Compile

```bash
make
```

This creates the sandbox library in `build/sandpip.so`.

### Run Tests

To run the security tests (which verify file, execution, and network blocks):

```bash
make test          # Tests file & process execution blocking
make test-network  # Tests static and dynamic network allowlisting
```

### Clean Build

```bash
make clean
```

---

## Limitations

`LD_PRELOAD` relies on dynamic linking and protects processes that call standard glibc symbols. 
* It **cannot** intercept static binaries, processes executing direct assembler syscalls (e.g., Go binaries), or programs that explicitly clear their environment variables.
* SandPip is optimized for standard Python runtimes and interpreters.
* Works only on Linux systems.

For enterprise-grade sandboxing, namespaces, seccomp-bpf, or containerized execution (Docker) should be used instead.
