#ifndef USHIELD_UAPI_H
#define USHIELD_UAPI_H

#ifdef __KERNEL__
#include <linux/ioctl.h>
#include <linux/types.h>
#else
#include <stdint.h>
#include <sys/ioctl.h>
#endif

#define USHIELD_IOC_MAGIC 's'
#define USHIELD_PATH_MAX 256
#define USHIELD_MAX_SYSCALL_RULES 128
#define USHIELD_MAX_DELTA_LAYERS 8
#define USHIELD_MAX_RESOURCE_PATCHES 32
#define USHIELD_VERSION 0x00010000

/* Permission Bitmask Categories */
#define USHIELD_PERM_NONE 0x00000000U
#define USHIELD_PERM_READ (1U << 0)
#define USHIELD_PERM_WRITE (1U << 1)
#define USHIELD_PERM_EXEC (1U << 2)
#define USHIELD_PERM_NET (1U << 3)
#define USHIELD_PERM_PROCESS (1U << 4)
#define USHIELD_PERM_ALL 0xFFFFFFFFU

/* Universal Resource Type Classification */
typedef enum ushield_resource_type {
    USHIELD_RES_SYSCALL = 1, /* System calls (__NR_*) */
    USHIELD_RES_FILE = 2,    /* Filesystem paths (/etc/passwd, /dev/...) */
    USHIELD_RES_FD = 3,      /* File descriptors (stdin, stdout, socket FDs) */
    USHIELD_RES_NET = 4,     /* Network sockets (AF_INET, ports, IPs) */
    USHIELD_RES_ENV = 5,     /* Environment variables (PATH, LD_PRELOAD) */
    USHIELD_RES_MOUNT = 6,   /* Mount points & VFS mounts */
    USHIELD_RES_REGISTER = 7 /* CPU registers (RIP, RAX, RDI, etc.) */
} ushield_resource_t;

/* Base Environment Templates */
typedef enum ushield_base_type {
    USHIELD_BASE_BARE = 0,        /* Bare environment: isolated proc/dev stubs */
    USHIELD_BASE_MINIMAL = 1,     /* Minimal environment: glibc + basic dev */
    USHIELD_BASE_HOST_REFLECT = 2 /* Full host system reflection (Read-Only COW) */
} ushield_base_type_t;

/* Mount Delta Operations */
typedef enum ushield_mount_op {
    USHIELD_MOUNT_BIND_RO = 1, /* Read-only bind mount */
    USHIELD_MOUNT_BIND_RW = 2, /* Read-write bind mount */
    USHIELD_MOUNT_MASK = 3,    /* Hide path completely (empty tmpfs overlay) */
    USHIELD_MOUNT_TMPFS = 4    /* Create isolated tmpfs */
} ushield_mount_op_t;

struct ushield_mount_delta {
    uint32_t op;                        /* ushield_mount_op_t */
    char source_path[USHIELD_PATH_MAX]; /* Host path */
    char target_path[USHIELD_PATH_MAX]; /* Sandbox target path */
};

/* Environment Variable Delta Operations */
typedef enum ushield_env_op {
    USHIELD_ENV_SET = 1,   /* Set/override variable */
    USHIELD_ENV_UNSET = 2, /* Strip variable */
    USHIELD_ENV_PASS = 3   /* Whitelist host variable */
} ushield_env_op_t;

struct ushield_env_delta {
    uint32_t op;     /* ushield_env_op_t */
    char key[128];   /* e.g., "LD_PRELOAD", "PATH" */
    char value[256]; /* Injected value */
};

/* Stackable Edit Delta Layer Header */
#define USHIELD_MAX_DELTAS_PER_LAYER 16

struct ushield_delta_layer {
    uint32_t layer_id; /* Incremental layer index (0 = Base Delta) */
    uint32_t ns_flags; /* CLONE_NEWPID | CLONE_NEWNET | CLONE_NEWNS */

    uint32_t mount_count;
    struct ushield_mount_delta mounts[USHIELD_MAX_DELTAS_PER_LAYER];

    uint32_t env_count;
    struct ushield_env_delta envs[USHIELD_MAX_DELTAS_PER_LAYER];
};

/* Real-Time Patch Payload for Dynamic Hot-Patching */
struct ushield_resource_patch {
    char binary_path[USHIELD_PATH_MAX];   /* Target binary rule to modify */
    uint32_t resource_type;               /* ushield_resource_t */
    uint64_t resource_id;                 /* Syscall NR, FD num, or String hash */
    char resource_name[USHIELD_PATH_MAX]; /* Path or variable name */
    uint32_t action_flags;                /* (ALLOW | DENY | HOOK) | LOG */
    int32_t override_errno;               /* Error code for DENY mode */
    uint64_t custom_ret;                  /* Return value for EMULATE/HOOK mode */
};

/* Syscall Enforcement & Fault Injection Actions */
typedef enum ushield_action {
    USHIELD_ACT_ALLOW_LOG = 0,  /* Allow syscall + log event */
    USHIELD_ACT_DENY_KILL = 1,  /* Block syscall + SIGKILL target */
    USHIELD_ACT_DENY_ERRNO = 2, /* Block syscall + return override_errno */
    USHIELD_ACT_EMULATE = 3     /* Bypass syscall + return custom_ret */
} ushield_action_t;

/* Granular Syscall Rule Specification */
struct ushield_syscall_rule {
    uint32_t syscall_nr;    /* Syscall ID (__NR_*) */
    uint8_t action;         /* ushield_action_t */
    int32_t override_errno; /* e.g., -EPERM, -ENOENT, -EACCES */
    uint64_t custom_ret;    /* Value returned to target during EMULATE mode */
};

/* Target Configuration Payload */
struct ushield_target_config {
    char binary_path[USHIELD_PATH_MAX];
    uint32_t base_template;     /* ushield_base_type_t */
    uint32_t default_perm_mask; /* Default USHIELD_PERM_* mask */
    uint32_t rule_count;
    struct ushield_syscall_rule rules[USHIELD_MAX_SYSCALL_RULES];
};

/* IOCTL Command Definitions */
#define USHIELD_IOC_PING _IO(USHIELD_IOC_MAGIC, 1)
#define USHIELD_IOC_GET_VERSION _IOR(USHIELD_IOC_MAGIC, 2, uint32_t)
#define USHIELD_IOC_REGISTER_SUPERVISOR _IO(USHIELD_IOC_MAGIC, 3)
#define USHIELD_IOC_SEAL_SELF _IOW(USHIELD_IOC_MAGIC, 4, uint32_t)
#define USHIELD_IOC_REGISTER_TARGET _IOW(USHIELD_IOC_MAGIC, 5, struct ushield_target_config)
#define USHIELD_IOC_UNREGISTER_TARGET _IOW(USHIELD_IOC_MAGIC, 6, struct ushield_target_config)
#define USHIELD_IOC_GET_POLICY _IOWR(USHIELD_IOC_MAGIC, 7, struct ushield_target_config)
#define USHIELD_IOC_PAUSE_TARGET _IOW(USHIELD_IOC_MAGIC, 8, uint32_t)
#define USHIELD_IOC_RESUME_TARGET _IOW(USHIELD_IOC_MAGIC, 9, uint32_t)
#define USHIELD_IOC_PUSH_DELTA _IOW(USHIELD_IOC_MAGIC, 10, struct ushield_delta_layer)
#define USHIELD_IOC_CLEAR_DELTAS _IOW(USHIELD_IOC_MAGIC, 11, char[USHIELD_PATH_MAX])
#define USHIELD_IOC_PATCH_RESOURCE _IOWR(USHIELD_IOC_MAGIC, 12, struct ushield_resource_patch)

/* Telemetry Ring Buffer Definitions */
#define USHIELD_RING_CAPACITY 1024

typedef enum ushield_event_type {
    USHIELD_EVENT_SYSCALL_EXEC = 1,
    USHIELD_EVENT_SYSCALL_DENY = 2,
    USHIELD_EVENT_PROCESS_SEAL = 3,
    USHIELD_EVENT_FAULT_INJECT = 4
} ushield_event_type_t;

struct ushield_event {
    uint64_t timestamp_ns;
    uint32_t pid;
    uint32_t uid;
    uint32_t event_type;
    uint32_t syscall_nr;
    uint64_t args[3];
    uint8_t action_taken;
    int32_t returned_errno;
    uint8_t reserved[3];
};

struct ushield_ring_buffer {
    uint32_t head;
    uint32_t tail;
    uint32_t capacity;
    uint32_t flags;
    struct ushield_event events[USHIELD_RING_CAPACITY];
};

#endif // USHIELD_UAPI_H
