#define _GNU_SOURCE

#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <spawn.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <linux/openat2.h>
#include <sys/syscall.h>
#include <netdb.h>
#include <pthread.h>
#include <time.h>
#include <execinfo.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

static __thread int sandpip_internal_call = 0;

static int (*real_open_fn)(const char *pathname, int flags, ...) = NULL;
static int (*real_open64_fn)(const char *pathname, int flags, ...) = NULL;
static int (*real_openat_fn)(int dirfd, const char *pathname, int flags, ...) = NULL;
static int (*real_openat64_fn)(int dirfd, const char *pathname, int flags, ...) = NULL;
static int (*real_openat2_fn)(int dirfd, const char *pathname, const struct open_how *how, size_t size) = NULL;
static FILE *(*real_fopen_fn)(const char *pathname, const char *mode) = NULL;
static FILE *(*real_fopen64_fn)(const char *pathname, const char *mode) = NULL;
static int (*real_execve_fn)(const char *pathname, char *const argv[], char *const envp[]) = NULL;
static int (*real_execveat_fn)(int dirfd, const char *pathname, char *const argv[], char *const envp[], int flags) = NULL;
static int (*real_fexecve_fn)(int fd, char *const argv[], char *const envp[]) = NULL;
static int (*real_connect_fn)(int sockfd, const struct sockaddr *addr, socklen_t addrlen) = NULL;
static int (*real_posix_spawn_fn)(pid_t *pid, const char *path,
                                  const posix_spawn_file_actions_t *file_actions,
                                  const posix_spawnattr_t *attrp,
                                  char *const argv[], char *const envp[]) = NULL;
static int (*real_posix_spawnp_fn)(pid_t *pid, const char *file,
                                   const posix_spawn_file_actions_t *file_actions,
                                   const posix_spawnattr_t *attrp,
                                   char *const argv[], char *const envp[]) = NULL;
static long (*real_syscall_fn)(long number, ...) = NULL;
static int (*real_getaddrinfo_fn)(const char *node, const char *service,
                                  const struct addrinfo *hints,
                                  struct addrinfo **res) = NULL;
static struct hostent *(*real_gethostbyname_fn)(const char *name) = NULL;
static struct hostent *(*real_gethostbyname2_fn)(const char *name, int af) = NULL;

#define MAX_DYNAMIC_IPS 1024

typedef struct {
    int family; // AF_INET or AF_INET6
    union {
        struct in_addr v4;
        struct in6_addr v6;
    } addr;
} allowed_ip_t;

static allowed_ip_t dynamic_allowed_ips[MAX_DYNAMIC_IPS];
static int dynamic_allowed_ips_count = 0;
static pthread_mutex_t dynamic_ips_mutex = PTHREAD_MUTEX_INITIALIZER;

static void init_real_functions(void)
{
    if (real_open_fn != NULL) {
        return;
    }

    sandpip_internal_call++;
    real_open_fn = dlsym(RTLD_NEXT, "open");
    real_open64_fn = dlsym(RTLD_NEXT, "open64");
    real_openat_fn = dlsym(RTLD_NEXT, "openat");
    real_openat64_fn = dlsym(RTLD_NEXT, "openat64");
    real_openat2_fn = dlsym(RTLD_NEXT, "openat2");
    real_fopen_fn = dlsym(RTLD_NEXT, "fopen");
    real_fopen64_fn = dlsym(RTLD_NEXT, "fopen64");
    real_execve_fn = dlsym(RTLD_NEXT, "execve");
    real_execveat_fn = dlsym(RTLD_NEXT, "execveat");
    real_fexecve_fn = dlsym(RTLD_NEXT, "fexecve");
    real_connect_fn = dlsym(RTLD_NEXT, "connect");
    real_posix_spawn_fn = dlsym(RTLD_NEXT, "posix_spawn");
    real_posix_spawnp_fn = dlsym(RTLD_NEXT, "posix_spawnp");
    real_syscall_fn = dlsym(RTLD_NEXT, "syscall");
    real_getaddrinfo_fn = dlsym(RTLD_NEXT, "getaddrinfo");
    real_gethostbyname_fn = dlsym(RTLD_NEXT, "gethostbyname");
    real_gethostbyname2_fn = dlsym(RTLD_NEXT, "gethostbyname2");
    sandpip_internal_call--;
}

static void sandpip_log(const char *kind, const char *target)
{
    if (target == NULL) {
        target = "(null)";
    }

    const char *log_path = getenv("SANDPIP_LOG_FILE");
    if (log_path == NULL) {
        log_path = "/tmp/sandpip.log";
    }

    // Try to find the calling library
    char library_name[PATH_MAX] = "unknown";
    void *buffer[10];
    int size = backtrace(buffer, 10);
    if (size > 0) {
        // Skip the first frame (sandpip_log) and second frame (the hook)
        for (int i = 2; i < size; i++) {
            Dl_info info;
            if (dladdr(buffer[i], &info) && info.dli_fname) {
                strncpy(library_name, info.dli_fname, sizeof(library_name) - 1);
                break;
            }
        }
    }

    sandpip_internal_call++;
    FILE *f = fopen(log_path, "a");
    if (f) {
        time_t now = time(NULL);
        char timestamp[20];
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));
        fprintf(f, "[%s] [BLOCK] [%s] %s denied: %s\n", timestamp, library_name, kind, target);
        fclose(f);
    }
    sandpip_internal_call--;
}

static bool starts_with(const char *value, const char *prefix)
{
    return value != NULL && prefix != NULL && strncmp(value, prefix, strlen(prefix)) == 0;
}

static bool path_has_segment(const char *path, const char *segment)
{
    const size_t segment_len = strlen(segment);
    const char *cursor = path;

    while (cursor != NULL && *cursor != '\0') {
        const char *found = strstr(cursor, segment);
        if (found == NULL) {
            return false;
        }

        const bool left_ok = found == path || found[-1] == '/';
        const char right = found[segment_len];
        const bool right_ok = right == '\0' || right == '/';
        if (left_ok && right_ok) {
            return true;
        }

        cursor = found + 1;
    }

    return false;
}

static bool same_path_or_child(const char *path, const char *parent)
{
    const size_t parent_len = strlen(parent);
    return strcmp(path, parent) == 0 ||
           (starts_with(path, parent) && path[parent_len] == '/');
}

static void join_path(char *out, size_t out_size, const char *base, const char *leaf)
{
    if (out_size == 0) {
        return;
    }

    if (base == NULL || *base == '\0') {
        snprintf(out, out_size, "%s", leaf != NULL ? leaf : "");
        return;
    }

    if (leaf == NULL || *leaf == '\0') {
        snprintf(out, out_size, "%s", base);
        return;
    }

    if (base[strlen(base) - 1] == '/') {
        snprintf(out, out_size, "%s%s", base, leaf);
    } else {
        snprintf(out, out_size, "%s/%s", base, leaf);
    }
}

static void expand_user_path(char *out, size_t out_size, const char *path)
{
    const char *home = getenv("HOME");

    if (path == NULL) {
        out[0] = '\0';
        return;
    }

    if (strcmp(path, "~") == 0 && home != NULL) {
        snprintf(out, out_size, "%s", home);
        return;
    }

    if (starts_with(path, "~/") && home != NULL) {
        join_path(out, out_size, home, path + 2);
        return;
    }

    snprintf(out, out_size, "%s", path);
}

static bool normalize_path(char *out, size_t out_size, const char *path)
{
    char expanded[PATH_MAX];

    if (path == NULL || out == NULL || out_size == 0) {
        return false;
    }

    expand_user_path(expanded, sizeof(expanded), path);

    if (expanded[0] == '/') {
        snprintf(out, out_size, "%s", expanded);
        return true;
    }

    char cwd[PATH_MAX];
    if (getcwd(cwd, sizeof(cwd)) == NULL) {
        snprintf(out, out_size, "%s", expanded);
        return true;
    }

    join_path(out, out_size, cwd, expanded);
    return true;
}

static bool is_blocked_path(const char *pathname)
{
    char normalized[PATH_MAX];
    const char *home = getenv("HOME");

    if (!normalize_path(normalized, sizeof(normalized), pathname)) {
        return false;
    }

    if (home != NULL && *home != '\0') {
        char blocked[PATH_MAX];

        join_path(blocked, sizeof(blocked), home, ".ssh");
        if (same_path_or_child(normalized, blocked)) {
            return true;
        }

        join_path(blocked, sizeof(blocked), home, ".aws");
        if (same_path_or_child(normalized, blocked)) {
            return true;
        }

        join_path(blocked, sizeof(blocked), home, ".config/gcloud");
        if (same_path_or_child(normalized, blocked)) {
            return true;
        }

        join_path(blocked, sizeof(blocked), home, ".gcp");
        if (same_path_or_child(normalized, blocked)) {
            return true;
        }

        join_path(blocked, sizeof(blocked), home, ".kube");
        if (same_path_or_child(normalized, blocked)) {
            return true;
        }

        join_path(blocked, sizeof(blocked), home, ".npmrc");
        if (strcmp(normalized, blocked) == 0) {
            return true;
        }

        join_path(blocked, sizeof(blocked), home, ".pypirc");
        if (strcmp(normalized, blocked) == 0) {
            return true;
        }
    }

    return path_has_segment(normalized, ".env");
}

static bool fd_to_path(int dirfd, char *out, size_t out_size)
{
    char proc_path[64];
    ssize_t len;

    if (dirfd == AT_FDCWD) {
        return getcwd(out, out_size) != NULL;
    }

    snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", dirfd);
    len = readlink(proc_path, out, out_size - 1);
    if (len < 0) {
        return false;
    }

    out[len] = '\0';
    return true;
}

static bool is_blocked_openat_path(int dirfd, const char *pathname)
{
    char base[PATH_MAX];
    char combined[PATH_MAX];

    if (pathname == NULL || pathname[0] == '/' || starts_with(pathname, "~/") || strcmp(pathname, "~") == 0) {
        return is_blocked_path(pathname);
    }

    if (!fd_to_path(dirfd, base, sizeof(base))) {
        return is_blocked_path(pathname);
    }

    join_path(combined, sizeof(combined), base, pathname);
    return is_blocked_path(combined);
}

static const char *basename_const(const char *path)
{
    const char *slash;

    if (path == NULL) {
        return "";
    }

    slash = strrchr(path, '/');
    return slash == NULL ? path : slash + 1;
}

static bool argv_contains_interactive_shell(char *const argv[])
{
    if (argv == NULL || argv[0] == NULL || argv[1] == NULL) {
        return false;
    }

    const char *cmd = basename_const(argv[0]);
    if (strcmp(cmd, "bash") != 0 && strcmp(cmd, "sh") != 0) {
        return false;
    }

    for (int i = 1; argv[i] != NULL && i < 16; i++) {
        if (strcmp(argv[i], "-i") == 0) {
            return true;
        }
    }

    return false;
}

static bool is_blocked_exec(const char *pathname, char *const argv[])
{
    const char *cmd = basename_const(pathname);

    if (cmd[0] == '\0' && argv != NULL && argv[0] != NULL) {
        cmd = basename_const(argv[0]);
    }

    if (strcmp(cmd, "curl") == 0 ||
        strcmp(cmd, "wget") == 0 ||
        strcmp(cmd, "nc") == 0 ||
        strcmp(cmd, "ncat") == 0 ||
        strcmp(cmd, "netcat") == 0) {
        return true;
    }

    return argv_contains_interactive_shell(argv);
}

static bool is_loopback_v4(uint32_t addr_be)
{
    const uint32_t addr = ntohl(addr_be);
    return (addr >> 24) == 127 || addr == 0;
}

static bool is_private_v4(uint32_t addr_be)
{
    const uint32_t addr = ntohl(addr_be);
    return (addr >> 24) == 10 ||
           (addr >> 20) == 0xAC1 ||
           (addr >> 16) == 0xC0A8 ||
           (addr >> 16) == 0xA9FE;
}

static bool env_has_token(const char *expected)
{
    const char *allowlist = getenv("SANDPIP_ALLOWED_IPS");
    char token[INET6_ADDRSTRLEN];
    size_t token_len = 0;

    if (allowlist == NULL || expected == NULL) {
        return false;
    }

    for (const char *cursor = allowlist;; cursor++) {
        const char ch = *cursor;
        const bool delimiter = ch == '\0' || ch == ',' || ch == ' ' || ch == '\t' || ch == '\n';

        if (delimiter) {
            if (token_len > 0) {
                token[token_len] = '\0';
                if (strcmp(token, expected) == 0) {
                    return true;
                }
                token_len = 0;
            }

            if (ch == '\0') {
                break;
            }
            continue;
        }

        if (token_len < sizeof(token) - 1) {
            token[token_len++] = ch;
        } else {
            token_len = 0;
            while (cursor[1] != '\0' && cursor[1] != ',' && cursor[1] != ' ' &&
                   cursor[1] != '\t' && cursor[1] != '\n') {
                cursor++;
            }
        }
    }

    return false;
}

static bool env_allows_ipv4(const struct in_addr *addr)
{
    char target[INET_ADDRSTRLEN];

    if (addr == NULL || inet_ntop(AF_INET, addr, target, sizeof(target)) == NULL) {
        return false;
    }

    return env_has_token(target);
}

static bool env_allows_ipv6(const struct in6_addr *addr)
{
    char target[INET6_ADDRSTRLEN];

    if (addr == NULL || inet_ntop(AF_INET6, addr, target, sizeof(target)) == NULL) {
        return false;
    }

    return env_has_token(target);
}

static void add_dynamic_allowed_ip(const struct sockaddr *sa)
{
    if (sa == NULL) {
        return;
    }

    pthread_mutex_lock(&dynamic_ips_mutex);

    if (sa->sa_family == AF_INET) {
        const struct sockaddr_in *sin = (const struct sockaddr_in *)sa;
        for (int i = 0; i < dynamic_allowed_ips_count; i++) {
            if (dynamic_allowed_ips[i].family == AF_INET &&
                dynamic_allowed_ips[i].addr.v4.s_addr == sin->sin_addr.s_addr) {
                pthread_mutex_unlock(&dynamic_ips_mutex);
                return;
            }
        }
        if (dynamic_allowed_ips_count < MAX_DYNAMIC_IPS) {
            dynamic_allowed_ips[dynamic_allowed_ips_count].family = AF_INET;
            dynamic_allowed_ips[dynamic_allowed_ips_count].addr.v4 = sin->sin_addr;
            dynamic_allowed_ips_count++;
        }
    } else if (sa->sa_family == AF_INET6) {
        const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)sa;
        for (int i = 0; i < dynamic_allowed_ips_count; i++) {
            if (dynamic_allowed_ips[i].family == AF_INET6 &&
                memcmp(&dynamic_allowed_ips[i].addr.v6, &sin6->sin6_addr, sizeof(struct in6_addr)) == 0) {
                pthread_mutex_unlock(&dynamic_ips_mutex);
                return;
            }
        }
        if (dynamic_allowed_ips_count < MAX_DYNAMIC_IPS) {
            dynamic_allowed_ips[dynamic_allowed_ips_count].family = AF_INET6;
            dynamic_allowed_ips[dynamic_allowed_ips_count].addr.v6 = sin6->sin6_addr;
            dynamic_allowed_ips_count++;
        }
    }

    pthread_mutex_unlock(&dynamic_ips_mutex);
}

static bool is_dynamic_allowed_ip(const struct sockaddr *sa)
{
    if (sa == NULL) {
        return false;
    }

    bool allowed = false;
    pthread_mutex_lock(&dynamic_ips_mutex);

    if (sa->sa_family == AF_INET) {
        const struct sockaddr_in *sin = (const struct sockaddr_in *)sa;
        for (int i = 0; i < dynamic_allowed_ips_count; i++) {
            if (dynamic_allowed_ips[i].family == AF_INET &&
                dynamic_allowed_ips[i].addr.v4.s_addr == sin->sin_addr.s_addr) {
                allowed = true;
                break;
            }
        }
    } else if (sa->sa_family == AF_INET6) {
        const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)sa;
        for (int i = 0; i < dynamic_allowed_ips_count; i++) {
            if (dynamic_allowed_ips[i].family == AF_INET6 &&
                memcmp(&dynamic_allowed_ips[i].addr.v6, &sin6->sin6_addr, sizeof(struct in6_addr)) == 0) {
                allowed = true;
                break;
            }
        }
    }

    pthread_mutex_unlock(&dynamic_ips_mutex);
    return allowed;
}

static bool is_allowed_ip(const struct sockaddr *addr)
{
    if (addr == NULL) {
        return true;
    }

    if (addr->sa_family == AF_UNIX) {
        return true;
    }

    if (addr->sa_family == AF_INET) {
        const struct sockaddr_in *in = (const struct sockaddr_in *)addr;
        return is_loopback_v4(in->sin_addr.s_addr) ||
               is_private_v4(in->sin_addr.s_addr) ||
               env_allows_ipv4(&in->sin_addr) ||
               is_dynamic_allowed_ip(addr);
    }

    if (addr->sa_family == AF_INET6) {
        const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)addr;
        return IN6_IS_ADDR_LOOPBACK(&in6->sin6_addr) ||
               IN6_IS_ADDR_LINKLOCAL(&in6->sin6_addr) ||
               IN6_IS_ADDR_UNSPECIFIED(&in6->sin6_addr) ||
               env_allows_ipv6(&in6->sin6_addr) ||
               is_dynamic_allowed_ip(addr);
    }

    return true;
}

static bool network_filter_enabled(void)
{
    const char *value = getenv("SANDPIP_ENFORCE_NETWORK");
    return value != NULL && strcmp(value, "1") == 0;
}

static const char *network_target(const struct sockaddr *addr, char *out, size_t out_size)
{
    if (out_size == 0) {
        return "non-allowlisted address";
    }

    if (addr == NULL) {
        snprintf(out, out_size, "unknown address");
        return out;
    }

    if (addr->sa_family == AF_INET) {
        const struct sockaddr_in *in = (const struct sockaddr_in *)addr;
        if (inet_ntop(AF_INET, &in->sin_addr, out, out_size) != NULL) {
            return out;
        }
    }

    if (addr->sa_family == AF_INET6) {
        const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)addr;
        if (inet_ntop(AF_INET6, &in6->sin6_addr, out, out_size) != NULL) {
            return out;
        }
    }

    snprintf(out, out_size, "non-allowlisted address");
    return out;
}

static int deny_with_errno(const char *kind, const char *target, int err)
{
    sandpip_log(kind, target);
    errno = err;
    return -1;
}

static bool is_allowed_domain(const char *node)
{
    if (node == NULL) {
        return true;
    }

    struct in_addr ipv4;
    struct in6_addr ipv6;
    if (inet_pton(AF_INET, node, &ipv4) == 1 || inet_pton(AF_INET6, node, &ipv6) == 1) {
        return true;
    }

    const char *env_domains = getenv("SANDPIP_ALLOWED_DOMAINS");
    char domains_buf[1024];
    if (env_domains != NULL) {
        strncpy(domains_buf, env_domains, sizeof(domains_buf) - 1);
        domains_buf[sizeof(domains_buf) - 1] = '\0';
    } else {
        strcpy(domains_buf, "pypi.org,files.pythonhosted.org,github.com");
    }

    char *saveptr = NULL;
    char *token = strtok_r(domains_buf, ", \t\n", &saveptr);
    while (token != NULL) {
        size_t node_len = strlen(node);
        size_t token_len = strlen(token);

        if (strcasecmp(node, token) == 0) {
            return true;
        }

        if (node_len > token_len && node[node_len - token_len - 1] == '.') {
            if (strcasecmp(node + (node_len - token_len), token) == 0) {
                return true;
            }
        }

        token = strtok_r(NULL, ", \t\n", &saveptr);
    }

    return false;
}

int open(const char *pathname, int flags, ...)
{
    mode_t mode = 0;

    init_real_functions();

    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = (mode_t)va_arg(args, int);
        va_end(args);
    }

    if (!sandpip_internal_call && is_blocked_path(pathname)) {
        return deny_with_errno("file access", pathname, EACCES);
    }

    return (flags & O_CREAT) ? real_open_fn(pathname, flags, mode) : real_open_fn(pathname, flags);
}

int open64(const char *pathname, int flags, ...)
{
    mode_t mode = 0;

    init_real_functions();

    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = (mode_t)va_arg(args, int);
        va_end(args);
    }

    if (!sandpip_internal_call && is_blocked_path(pathname)) {
        return deny_with_errno("file access", pathname, EACCES);
    }

    return (flags & O_CREAT) ? real_open64_fn(pathname, flags, mode) : real_open64_fn(pathname, flags);
}

int openat(int dirfd, const char *pathname, int flags, ...)
{
    mode_t mode = 0;

    init_real_functions();

    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = (mode_t)va_arg(args, int);
        va_end(args);
    }

    if (!sandpip_internal_call && is_blocked_openat_path(dirfd, pathname)) {
        return deny_with_errno("file access", pathname, EACCES);
    }

    return (flags & O_CREAT) ? real_openat_fn(dirfd, pathname, flags, mode) : real_openat_fn(dirfd, pathname, flags);
}

int openat64(int dirfd, const char *pathname, int flags, ...)
{
    mode_t mode = 0;

    init_real_functions();

    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = (mode_t)va_arg(args, int);
        va_end(args);
    }

    if (!sandpip_internal_call && is_blocked_openat_path(dirfd, pathname)) {
        return deny_with_errno("file access", pathname, EACCES);
    }

    return (flags & O_CREAT) ? real_openat64_fn(dirfd, pathname, flags, mode) : real_openat64_fn(dirfd, pathname, flags);
}

int openat2(int dirfd, const char *pathname, const struct open_how *how, size_t size)
{
    init_real_functions();

    if (!sandpip_internal_call && is_blocked_openat_path(dirfd, pathname)) {
        return deny_with_errno("file access", pathname, EACCES);
    }

    if (real_openat2_fn) {
        return real_openat2_fn(dirfd, pathname, how, size);
    } else {
        return syscall(SYS_openat2, dirfd, pathname, how, size);
    }
}

FILE *fopen(const char *pathname, const char *mode)
{
    init_real_functions();

    if (!sandpip_internal_call && is_blocked_path(pathname)) {
        sandpip_log("file access", pathname);
        errno = EACCES;
        return NULL;
    }

    return real_fopen_fn(pathname, mode);
}

FILE *fopen64(const char *pathname, const char *mode)
{
    init_real_functions();

    if (!sandpip_internal_call && is_blocked_path(pathname)) {
        sandpip_log("file access", pathname);
        errno = EACCES;
        return NULL;
    }

    return real_fopen64_fn(pathname, mode);
}

int execve(const char *pathname, char *const argv[], char *const envp[])
{
    init_real_functions();

    if (!sandpip_internal_call && is_blocked_exec(pathname, argv)) {
        return deny_with_errno("exec", pathname, EACCES);
    }

    return real_execve_fn(pathname, argv, envp);
}

int execveat(int dirfd, const char *pathname, char *const argv[], char *const envp[], int flags)
{
    init_real_functions();

    if (!sandpip_internal_call && is_blocked_exec(pathname, argv)) {
        return deny_with_errno("exec", pathname, EACCES);
    }

    return real_execveat_fn(dirfd, pathname, argv, envp, flags);
}

int fexecve(int fd, char *const argv[], char *const envp[])
{
    char proc_path[64];
    char target[PATH_MAX];
    const char *display = "fd";

    init_real_functions();

    snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", fd);
    ssize_t len = readlink(proc_path, target, sizeof(target) - 1);
    if (len >= 0) {
        target[len] = '\0';
        display = target;
    }

    if (!sandpip_internal_call && is_blocked_exec(display, argv)) {
        return deny_with_errno("exec", display, EACCES);
    }

    return real_fexecve_fn(fd, argv, envp);
}

int posix_spawn(pid_t *pid, const char *path,
                const posix_spawn_file_actions_t *file_actions,
                const posix_spawnattr_t *attrp,
                char *const argv[], char *const envp[])
{
    init_real_functions();

    if (!sandpip_internal_call && is_blocked_exec(path, argv)) {
        sandpip_log("exec", path);
        return EACCES;
    }

    return real_posix_spawn_fn(pid, path, file_actions, attrp, argv, envp);
}

int posix_spawnp(pid_t *pid, const char *file,
                 const posix_spawn_file_actions_t *file_actions,
                 const posix_spawnattr_t *attrp,
                 char *const argv[], char *const envp[])
{
    init_real_functions();

    if (!sandpip_internal_call && is_blocked_exec(file, argv)) {
        sandpip_log("exec", file);
        return EACCES;
    }

    return real_posix_spawnp_fn(pid, file, file_actions, attrp, argv, envp);
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    init_real_functions();

    if (!sandpip_internal_call && network_filter_enabled() && !is_allowed_ip(addr)) {
        char target[INET6_ADDRSTRLEN];
        return deny_with_errno("network connect", network_target(addr, target, sizeof(target)), EPERM);
    }

    return real_connect_fn(sockfd, addr, addrlen);
}

int getaddrinfo(const char *node, const char *service,
                const struct addrinfo *hints,
                struct addrinfo **res)
{
    init_real_functions();

    if (!sandpip_internal_call && network_filter_enabled()) {
        if (node != NULL && !is_allowed_domain(node)) {
            sandpip_log("DNS resolution", node);
            return EAI_NONAME;
        }
    }

    int ret = real_getaddrinfo_fn(node, service, hints, res);

    if (ret == 0 && res != NULL && !sandpip_internal_call && network_filter_enabled()) {
        struct addrinfo *curr = *res;
        while (curr != NULL) {
            add_dynamic_allowed_ip(curr->ai_addr);
            curr = curr->ai_next;
        }
    }

    return ret;
}

struct hostent *gethostbyname(const char *name)
{
    init_real_functions();

    if (!sandpip_internal_call && network_filter_enabled()) {
        if (name != NULL && !is_allowed_domain(name)) {
            sandpip_log("DNS resolution (gethostbyname)", name);
            h_errno = HOST_NOT_FOUND;
            return NULL;
        }
    }

    struct hostent *ret = real_gethostbyname_fn(name);

    if (ret != NULL && !sandpip_internal_call && network_filter_enabled()) {
        if (ret->h_addrtype == AF_INET) {
            for (int i = 0; ret->h_addr_list[i] != NULL; i++) {
                struct sockaddr_in sin;
                memset(&sin, 0, sizeof(sin));
                sin.sin_family = AF_INET;
                memcpy(&sin.sin_addr, ret->h_addr_list[i], sizeof(struct in_addr));
                add_dynamic_allowed_ip((struct sockaddr *)&sin);
            }
        } else if (ret->h_addrtype == AF_INET6) {
            for (int i = 0; ret->h_addr_list[i] != NULL; i++) {
                struct sockaddr_in6 sin6;
                memset(&sin6, 0, sizeof(sin6));
                sin6.sin6_family = AF_INET6;
                memcpy(&sin6.sin6_addr, ret->h_addr_list[i], sizeof(struct in6_addr));
                add_dynamic_allowed_ip((struct sockaddr *)&sin6);
            }
        }
    }

    return ret;
}

struct hostent *gethostbyname2(const char *name, int af)
{
    init_real_functions();

    if (!sandpip_internal_call && network_filter_enabled()) {
        if (name != NULL && !is_allowed_domain(name)) {
            sandpip_log("DNS resolution (gethostbyname2)", name);
            h_errno = HOST_NOT_FOUND;
            return NULL;
        }
    }

    struct hostent *ret = real_gethostbyname2_fn(name, af);

    if (ret != NULL && !sandpip_internal_call && network_filter_enabled()) {
        if (ret->h_addrtype == AF_INET) {
            for (int i = 0; ret->h_addr_list[i] != NULL; i++) {
                struct sockaddr_in sin;
                memset(&sin, 0, sizeof(sin));
                sin.sin_family = AF_INET;
                memcpy(&sin.sin_addr, ret->h_addr_list[i], sizeof(struct in_addr));
                add_dynamic_allowed_ip((struct sockaddr *)&sin);
            }
        } else if (ret->h_addrtype == AF_INET6) {
            for (int i = 0; ret->h_addr_list[i] != NULL; i++) {
                struct sockaddr_in6 sin6;
                memset(&sin6, 0, sizeof(sin6));
                sin6.sin6_family = AF_INET6;
                memcpy(&sin6.sin6_addr, ret->h_addr_list[i], sizeof(struct in6_addr));
                add_dynamic_allowed_ip((struct sockaddr *)&sin6);
            }
        }
    }

    return ret;
}

long syscall(long number, ...)
{
    init_real_functions();

    va_list args;
    va_start(args, number);
    long arg1 = va_arg(args, long);
    long arg2 = va_arg(args, long);
    long arg3 = va_arg(args, long);
    long arg4 = va_arg(args, long);
    long arg5 = va_arg(args, long);
    long arg6 = va_arg(args, long);
    va_end(args);

    if (!sandpip_internal_call) {
        if (number == SYS_openat2) {
            int dirfd = (int)arg1;
            const char *pathname = (const char *)arg2;
            if (is_blocked_openat_path(dirfd, pathname)) {
                sandpip_log("file access via syscall(openat2)", pathname);
                errno = EACCES;
                return -1;
            }
        }
        else if (number == SYS_openat) {
            int dirfd = (int)arg1;
            const char *pathname = (const char *)arg2;
            if (is_blocked_openat_path(dirfd, pathname)) {
                sandpip_log("file access via syscall(openat)", pathname);
                errno = EACCES;
                return -1;
            }
        }
        else if (number == SYS_open) {
            const char *pathname = (const char *)arg1;
            if (is_blocked_path(pathname)) {
                sandpip_log("file access via syscall(open)", pathname);
                errno = EACCES;
                return -1;
            }
        }
        else if (number == SYS_connect) {
            const struct sockaddr *addr = (const struct sockaddr *)arg2;
            if (network_filter_enabled() && !is_allowed_ip(addr)) {
                char target[INET6_ADDRSTRLEN];
                sandpip_log("network connect via syscall(connect)", network_target(addr, target, sizeof(target)));
                errno = EPERM;
                return -1;
            }
        }
        else if (number == SYS_execve) {
            const char *pathname = (const char *)arg1;
            char *const *argv = (char *const *)arg2;
            if (is_blocked_exec(pathname, argv)) {
                sandpip_log("exec via syscall(execve)", pathname);
                errno = EACCES;
                return -1;
            }
        }
        else if (number == SYS_execveat) {
            const char *pathname = (const char *)arg2;
            char *const *argv = (char *const *)arg3;
            if (is_blocked_exec(pathname, argv)) {
                sandpip_log("exec via syscall(execveat)", pathname);
                errno = EACCES;
                return -1;
            }
        }
    }

    return real_syscall_fn(number, arg1, arg2, arg3, arg4, arg5, arg6);
}
