#include "../../include/ushield_uapi.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#define LOG_PREFIX "[µShield] "

__attribute__((format(printf, 1, 2))) static inline void LOG_INFO(const char *fmt, ...) {
    fputs(LOG_PREFIX, stdout);
    va_list args;
    va_start(args, fmt);
    vfprintf(stdout, fmt, args);
    va_end(args);
}

__attribute__((format(printf, 1, 2))) static inline void LOG_ERR(const char *fmt, ...) {
    fputs(LOG_PREFIX, stderr);
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
}

static inline void LOG_PERROR(const char *msg) {
    fprintf(stderr, LOG_PREFIX "%s: %s\n", msg, strerror(errno));
}

/*
 * Unprivileged HTTP Worker Process (ushieldd-http)
 */
static void run_http_worker(int ipc_fd) {
    LOG_INFO("[ushieldd-http] Worker started (PID %d)\n", getpid());

    // Worker self-seals
    int dev_fd = open("/dev/ushield", O_RDWR);
    if (dev_fd >= 0) {
        uint32_t worker_perms = USHIELD_PERM_READ | USHIELD_PERM_WRITE | USHIELD_PERM_NET;
        if (ioctl(dev_fd, USHIELD_IOC_SEAL_SELF, &worker_perms) == 0) {
            LOG_INFO("[ushieldd-http] Worker successfully SELF-SEALED in Ring 0\n");
        }
        close(dev_fd);
    }

    // Send RPC message over socketpair
    const char *msg = "REQ_REGISTER_TARGET";
    LOG_INFO("[ushieldd-http] Sending Target Execution Request to Master Supervisor...\n");
    if (write(ipc_fd, msg, strlen(msg)) < 0) {
        LOG_PERROR("[ushieldd-http] IPC write failed");
    }

    char reply[64] = {0};
    ssize_t bytes = read(ipc_fd, reply, sizeof(reply) - 1);
    if (bytes > 0) {
        LOG_INFO("[ushieldd-http] Received IPC reply from Master: '%s'\n", reply);
    }

    close(ipc_fd);
    LOG_INFO("[ushieldd-http] Worker exiting cleanly.\n");
    exit(EXIT_SUCCESS);
}

/*
 * Helper to register target execution rule in Ring 0
 */
static int register_target_binary(int dev_fd, const char *abs_path, uint32_t perms) {
    struct ushield_target_config cfg = {0};
    snprintf(cfg.binary_path, sizeof(cfg.binary_path), "%s", abs_path);
    cfg.default_perm_mask = perms;

    LOG_INFO("[ushieldd-core] Registering target rule for '%s' (Perms: 0x%08X)...\n", abs_path,
             perms);

    if (ioctl(dev_fd, USHIELD_IOC_REGISTER_TARGET, &cfg) < 0) {
        LOG_PERROR("[ushieldd-core] Target registration failed");
        return -1;
    }
    return 0;
}

/*
 * Helper to unregister target execution rule in Ring 0
 */
static int unregister_target_binary(int dev_fd, const char *abs_path) {
    struct ushield_target_config cfg = {0};
    snprintf(cfg.binary_path, sizeof(cfg.binary_path), "%s", abs_path);

    LOG_INFO("[ushieldd-core] Unregistered target rule for '%s'...\n", abs_path);

    if (ioctl(dev_fd, USHIELD_IOC_UNREGISTER_TARGET, &cfg) < 0) {
        LOG_PERROR("[ushieldd-core] Target unregistration failed");
        return -1;
    }

    return 0;
}

/* Helper to push an edit delta layer to a target bianry */
static int push_delta_layer(int dev_fd, struct ushield_delta_layer *layer) {
    LOG_INFO("[ushieldd-core] Pushing Edit Delta Layer (Mounts: %u, Envs: %u)...\n",
             layer->mount_count, layer->env_count);

    if (ioctl(dev_fd, USHIELD_IOC_PUSH_DELTA, layer) < 0) {
        LOG_PERROR("[ushieldd-core] Failed to push delta layer");
        return -1;
    }

    return 0;
}

/* Helper to hot-patch a specific resource in real time */
static int patch_resource_rule(int dev_fd, const char *abs_binary_path, ushield_resource_t res_type,
                               uint64_t res_id, const char *res_name, uint32_t action_flags,
                               int32_t override_errno, uint64_t custom_ret) {
    struct ushield_resource_patch patch = {0};
    snprintf(patch.binary_path, sizeof(patch.binary_path), "%s", abs_binary_path);
    patch.resource_type = res_type;
    patch.resource_id = res_id;
    if (res_name) {
        snprintf(patch.resource_name, sizeof(patch.resource_name), "%s", res_name);
    }
    patch.action_flags = action_flags;
    patch.override_errno = override_errno;
    patch.custom_ret = custom_ret;

    LOG_INFO("[ushieldd-core] Hot-patching Resource (Type: %u, ID: %lu, Action: 0x%08X)...\n",
             res_type, res_id, action_flags);

    if (ioctl(dev_fd, USHIELD_IOC_PATCH_RESOURCE, &patch) < 0) {
        LOG_PERROR("[ushieldd-core] Failed to patch resource rule");
        return -1;
    }

    return 0;
}

int main(void) {
    LOG_INFO("Initializing µShield Control Daemon Engine (PID %d)...\n", getpid());

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
        LOG_PERROR("Failed to create PrivSep socketpair");
        return EXIT_FAILURE;
    }

    pid_t child_pid = fork();
    if (child_pid < 0) {
        LOG_PERROR("Fork failed");
        return EXIT_FAILURE;
    }

    if (child_pid == 0) {
        close(sv[0]);
        run_http_worker(sv[1]);
    }

    close(sv[1]);
    int master_ipc = sv[0];

    LOG_INFO("[ushieldd-core] Master Supervirsor initializing (PID %d)...\n", getpid());

    int dev_fd = open("/dev/ushield", O_RDWR);
    if (dev_fd < 0) {
        LOG_PERROR("[ushieldd-core] Failed to open /dev/ushield");
        goto ffailure;
    }

    // 1. Register Supervisor in Ring 0
    if (ioctl(dev_fd, USHIELD_IOC_REGISTER_SUPERVISOR) < 0) {
        LOG_PERROR("[ushieldd-core] Supervisor registration failed");
        goto failure;
    }

    // 2. Map Telemetry Ring Buffer
    size_t ring_size = sizeof(struct ushield_ring_buffer);
    struct ushield_ring_buffer *ring =
        mmap(NULL, ring_size, PROT_READ | PROT_WRITE, MAP_SHARED, dev_fd, 0);
    if (ring == MAP_FAILED) {
        LOG_PERROR("[ushieldd-core] Failed to mmap ring buffer");
        goto failure;
    }

    // 3. Resolve absolute path of test target binary
    char abs_target_path[USHIELD_PATH_MAX];
    if (realpath("dist/test_target", abs_target_path) == NULL) {
        LOG_PERROR("[ushieldd-core] Could not resolve dist/test_target path");
        goto failure;
    }

    // 4. Handle Worker IPC Request
    char buf[64] = {0};
    ssize_t bytes = read(master_ipc, buf, sizeof(buf) - 1);
    if (bytes > 0) {
        LOG_INFO("[ushieldd-core] Master received IPC request: '%s'\n", buf);

        // 1. Register execution rule for test target
        register_target_binary(dev_fd, abs_target_path, USHIELD_PERM_READ | USHIELD_PERM_EXEC);

        // 2. Delta Layer Push
        struct ushield_delta_layer layer = {0};
        layer.mount_count = 1;
        layer.mounts[0].op = USHIELD_MOUNT_BIND_RO;
        snprintf(layer.mounts[0].source_path, sizeof(layer.mounts[0].source_path), "/etc");
        snprintf(layer.mounts[0].target_path, sizeof(layer.mounts[0].target_path), "/etc");

        layer.env_count = 1;
        layer.envs[0].op = USHIELD_ENV_SET;
        snprintf(layer.envs[0].key, sizeof(layer.envs[0].key), "USH_ENV");
        snprintf(layer.envs[0].value, sizeof(layer.envs[0].value), "DEV");

        push_delta_layer(dev_fd, &layer);

        // 3. Real-Time Resource Hot-patching
        patch_resource_rule(dev_fd, abs_target_path, USHIELD_RES_SYSCALL, 257 /* SYS_openat */,
                            "/etc/passwd", USHIELD_PERM_READ, -EPERM, 0);

        const char *ack = "ACK_TARGET_REGISTERED";
        if (write(master_ipc, ack, strlen(ack)) < 0) {
            LOG_PERROR("[ushieldd-core] IPC ack write failed");
        }
    }

    int status;
    waitpid(child_pid, &status, 0);

    // 5. Unregister rule to verify dynamic cleanup in Ring 0
    unregister_target_binary(dev_fd, abs_target_path);

    // 6. Drain Telemetry Events
    LOG_INFO("[ushieldd-core] Draining telemetry events...\n");
    while (ring->tail < ring->head) {
        uint32_t idx = ring->tail & (USHIELD_RING_CAPACITY - 1);
        struct ushield_event *ev = &ring->events[idx];

        LOG_INFO("[EVENT] TS: %lu ns | PID: %u | Type: %u | Syscall: %u | Action: %u\n",
                 (unsigned long)ev->timestamp_ns, ev->pid, ev->event_type, ev->syscall_nr,
                 ev->action_taken);

        ring->tail++;
    }

    munmap(ring, ring_size);
    close(dev_fd);
    close(master_ipc);
    LOG_INFO("[ushieldd-core] Target registration engine test completed cleanly.\n");
    return EXIT_SUCCESS;

failure:
    close(dev_fd);
ffailure:
    close(master_ipc);
    return EXIT_FAILURE;
}
