#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <time.h>
#include <sys/wait.h>
#include <dlfcn.h>
#include <execinfo.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

static void sandpip_log(const char *kind, const char *target)
{
    if (target == NULL) {
        target = "(null)";
    }

    const char *log_path = getenv("SANDPIP_LOG_FILE");
    if (log_path == NULL) {
        log_path = "/tmp/sandpip.log";
    }

    char library_name[PATH_MAX] = "unknown";
    void *buffer[10];
    int size = backtrace(buffer, 10);
    if (size > 0) {
        for (int i = 2; i < size; i++) {
            Dl_info info;
            if (dladdr(buffer[i], &info) && info.dli_fname) {
                strncpy(library_name, info.dli_fname, sizeof(library_name) - 1);
                break;
            }
        }
    }

    FILE *f = fopen(log_path, "a");
    if (f) {
        time_t now = time(NULL);
        char timestamp[20];
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));
        fprintf(f, "[%s] [BLOCK] [%s] %s denied: %s\n", timestamp, library_name, kind, target);
        fclose(f);
    }
}

static void write_file(const char *path, const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    FILE *f = fopen(path, "w");
    if (f) {
        vfprintf(f, fmt, args);
        fclose(f);
    } else {
        fprintf(stderr, "sandpip_v2: failed to write to %s: %s\n", path, strerror(errno));
    }
    va_end(args);
}

static void setup_user_mappings(uid_t original_uid, gid_t original_gid)
{
    write_file("/proc/self/setgroups", "deny");
    write_file("/proc/self/uid_map", "0 %d 1\n", original_uid);
    write_file("/proc/self/gid_map", "0 %d 1\n", original_gid);
}

static void mount_tmpfs_over_dir(const char *path)
{
    struct stat st;
    if (stat(path, &st) == 0 && S_ISDIR(st.st_mode)) {
        if (mount("tmpfs", path, "tmpfs", 0, NULL) != 0) {
            sandpip_log("mount failure", path);
        }
    }
}

static void bind_mount_null_over_file(const char *path)
{
    struct stat st;
    if (stat(path, &st) == 0 && S_ISREG(st.st_mode)) {
        if (mount("/dev/null", path, NULL, MS_BIND, NULL) != 0) {
            sandpip_log("bind mount failure", path);
        }
    }
}

static int setup_seccomp(void)
{
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, nr))),
        
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_ptrace, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),

        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_reboot, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),

        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_syslog, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),

#ifdef SYS_kexec_load
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_kexec_load, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),
#endif

        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
    };

    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        perror("sandpip_v2: prctl(PR_SET_NO_NEW_PRIVS) failed");
        return -1;
    }

    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) != 0) {
        perror("sandpip_v2: prctl(PR_SET_SECCOMP) failed");
        return -1;
    }

    return 0;
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <command> [args...]\n", argv[0]);
        return 1;
    }

    uid_t original_uid = getuid();
    gid_t original_gid = getgid();

    if (unshare(CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID) != 0) {
        perror("sandpip_v2: unshare(CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID) failed");
        fprintf(stderr, "Please verify that user namespaces are enabled in your kernel (sysctl kernel.unprivileged_userns_clone=1)\n");
        return 1;
    }

    setup_user_mappings(original_uid, original_gid);

    const char *home = getenv("HOME");
    if (home != NULL && *home != '\0') {
        char path[PATH_MAX];

        snprintf(path, sizeof(path), "%s/.ssh", home);
        mount_tmpfs_over_dir(path);

        snprintf(path, sizeof(path), "%s/.aws", home);
        mount_tmpfs_over_dir(path);

        snprintf(path, sizeof(path), "%s/.config/gcloud", home);
        mount_tmpfs_over_dir(path);

        snprintf(path, sizeof(path), "%s/.gcp", home);
        mount_tmpfs_over_dir(path);

        snprintf(path, sizeof(path), "%s/.kube", home);
        mount_tmpfs_over_dir(path);

        snprintf(path, sizeof(path), "%s/.npmrc", home);
        bind_mount_null_over_file(path);

        snprintf(path, sizeof(path), "%s/.pypirc", home);
        bind_mount_null_over_file(path);
    }

    bind_mount_null_over_file(".env");

    bind_mount_null_over_file("/usr/bin/curl");
    bind_mount_null_over_file("/bin/curl");
    bind_mount_null_over_file("/usr/bin/wget");
    bind_mount_null_over_file("/bin/wget");
    bind_mount_null_over_file("/usr/bin/nc");
    bind_mount_null_over_file("/bin/nc");
    bind_mount_null_over_file("/usr/bin/netcat");
    bind_mount_null_over_file("/bin/netcat");
    bind_mount_null_over_file("/usr/bin/ncat");
    bind_mount_null_over_file("/bin/ncat");

    if (setup_seccomp() != 0) {
        fprintf(stderr, "sandpip_v2: failed to apply seccomp filter\n");
        return 1;
    }

    pid_t pid = fork();
    if (pid == 0) {
        // Child process
        if (mount("proc", "/proc", "proc", 0, NULL) != 0) {
            // We can't easily log this to sandpip_log because it's a system error
            // but we can ignore it or use perror
        }
        execvp(argv[1], &argv[1]);
        perror("sandpip_v2: execvp failed");
        exit(1);
    } else if (pid > 0) {
        // Parent process
        int status;
        if (waitpid(pid, &status, 0) == -1) {
            perror("sandpip_v2: waitpid failed");
            return 1;
        }
        if (WIFEXITED(status)) {
            return WEXITSTATUS(status);
        }
        return 1;
    } else {
        perror("sandpip_v2: fork failed");
        return 1;
    }
}
