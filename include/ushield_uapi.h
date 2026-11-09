#ifndef USHIELD_UAPI_H
#define USHIELD_UAPI_H

#ifdef __KERNEL__
#include <linux/ioctl.h>
#include <linux/types.h>
#else
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#endif

#define USHIELD_IOC_MAGIC 's'
#define USHIELD_MAX_PATH 256
#define USHIELD_MAX_RULES 4096
#define USHIELD_MAX_DELTA_LAYERS 8
#define USHIELD_MAX_RESOURCE_PATCHES 32
#define USHIELD_VERSION 0x00010000
#define USHIELD_MAX_CHILDREN 4096
#define USHIELD_MAX_CONTAINERS 4096

/* Permission Bitmask Categories */
#define USHIELD_PERM_NONE ((uint8_t)0x00U)
#define USHIELD_PERM_RO ((uint8_t)(1U << 0))   /* Read-Only. 0x01 */
#define USHIELD_PERM_WO ((uint8_t)(1U << 1))   /* Write-Only. 0x02 */
#define USHIELD_PERM_XO ((uint8_t)(1U << 2))   /* Execute-Only. 0x04 */
#define USHIELD_PERM_FS ((uint8_t)(1U << 3))   /* Filesystem. 0x08 */
#define USHIELD_PERM_NET ((uint8_t)(1U << 4))  /* Network. 0x10 */
#define USHIELD_PERM_ENV ((uint8_t)(1U << 5))  /* Environment. 0x20 */
#define USHIELD_PERM_PROC ((uint8_t)(1U << 6)) /* Processes. 0x40 */
#define USHIELD_PERM_MGMT ((uint8_t)(1U << 7)) /* Management. 0x80 */

#define USHIELD_PERM_RW ((uint8_t)(USHIELD_PERM_RO | USHIELD_PERM_WO))
#define USHIELD_PERM_RX ((uint8_t)(USHIELD_PERM_RO | USHIELD_PERM_XO))
#define USHIELD_PERM_WX ((uint8_t)(USHIELD_PERM_WO | USHIELD_PERM_XO))
#define USHIELD_PERM_RWX ((uint8_t)(USHIELD_PERM_RO | USHIELD_PERM_WO | USHIELD_PERM_XO))
#define USHIELD_PERM_ALL ((uint8_t)0xFFU)

/* Universal Resource Type Classification */
typedef enum ushield_resource_type {
    USHIELD_RES_FS = USHIELD_PERM_FS,
    USHIELD_RES_NET = USHIELD_PERM_NET,
    USHIELD_RES_ENV = USHIELD_PERM_ENV,
    USHIELD_RES_PROC = USHIELD_PERM_PROC,
    USHIELD_RES_MGMT = USHIELD_PERM_MGMT
} ushield_resource_t;

/* Base Environment Templates */
typedef enum ushield_base_type {
    USHIELD_BASE_BARE = 0,        /* Bare environment: isolated proc/dev stubs */
    USHIELD_BASE_MINIMAL = 1,     /* Minimal environment: glibc + basic dev */
    USHIELD_BASE_HOST_REFLECT = 2 /* Full host system reflection (Read-Only COW) */
} ushield_base_type_t;

/* Delta Operations */
typedef enum ushield_file_op {
    USHIELD_FILE_CREATE = 1,      // Create new file
    USHIELD_FILE_DELETE = 2,      // Delete file
    USHIELD_FILE_PERMISSIONS = 3, // Change file permissions
    USHIELD_FILE_MOUNT = 4,       // Mount file
    USHIELD_FILE_MASK = 5         // Mask file (hide from container / process)
} ushield_file_op_t;

typedef enum ushield_net_op {
    USHIELD_NET_CREATE = 1, // Create new net
    USHIELD_NET_DELETE = 2, // Delete net
    USHIELD_NET_BRIDGE = 3, // Bridge net to host
} ushield_net_op_t;

typedef enum ushield_env_op {
    USHIELD_ENV_SET = 1,      // Set variable
    USHIELD_ENV_UNSET = 2,    // Strip variable
    USHIELD_ENV_MIRROR = 3,   // Mirror variable from host (stays updated)
    USHIELD_ENV_UNMIRROR = 4, // Un-mirror variable from host
} ushield_env_op_t;

/* Generic Stackable Edit Delta Layer Header */
typedef struct ushield_delta_layer {
    /* Resource + Operation */
    ushield_resource_t resource;
    uint8_t op;

    /* Data */
    uint8_t data[USHIELD_MAX_PATH];
} ushield_delta_layer_t;

/* Ushield Execution */
typedef struct ushield_cpu_regs {
#if defined(__x86_64__)
    uint64_t rax, rbx, rcx, rdx;
    uint64_t rsi, rdi, rbp, rsp;
    uint64_t r8, r9, r10, r11;
    uint64_t r12, r13, r14, r15;
    uint64_t rip, rflags;
#elif defined(__aarch64__)
    uint64_t x[31];
    uint64_t sp, pc, pstate;
// TODO: for later: different architectures?
#endif
} ushield_cpu_regs_t;

typedef int ushield_rule_handler_ret;
typedef struct ushield_rule_ctx {
    ushield_resource_t resource;  // Requested Resource Type
    ushield_cpu_regs_t registers; // Complete CPU Register Snapshot

    uint32_t cid; // Container ID / Index
    uint32_t pid; // Process ID in Container / Index
} ushield_rule_ctx_t;
typedef ushield_rule_handler_ret (*ushield_rule_handler_fn)(const ushield_rule_ctx_t *ctx);

typedef struct ushield_rule {
    ushield_resource_t resource;
    ushield_rule_handler_fn handler_fn;
} ushield_rule_t;

typedef struct ushield_exec_info {
    _Bool active;      /* Currently running? */
    uint64_t start_ns; /* Timestamp of registration */
    uint64_t stop_ns;  /* Timestamp of latest stop */
    uint64_t end_ns;   /* Timestamp of unregistration */
} ushield_exec_info_t;

// TODO: these structs are bloated. Optimize later.
typedef struct ushield_process {
    uint8_t permissions;                       // Permissions. Check out USHIELD_PERM_*.
    uint32_t id;                               // ID inside Container / Index - not PID!
    pid_t pid;                                 // PID.
    pid_t owner;                               // Owner's PID (whoever started this).
    ushield_exec_info_t info;                  // Activity.
    uint32_t rules_count;                      // Currently active.
    char binary_path[USHIELD_MAX_PATH];        // Path to binary on host (at the moment of spawn).
    pid_t children_pids[USHIELD_MAX_CHILDREN]; // PIDs of all children / forks.
    ushield_rule_t *rules[USHIELD_MAX_RULES];  // Rules.
} ushield_process_t;

typedef struct ushield_container {
    uint8_t permissions;      // Permissions. Check out USHIELD_PERM_*.
    uint32_t id;              // Container ID / Index.
    uint32_t base;            // Base Container.
    ushield_exec_info_t info; // Activity.
    uint32_t processes_count; // Currently registered processes.
    uint32_t rules_count;     // Currently active / applied rules.
    pid_t owner;              // Owner's PID (whoever created this).
    ushield_delta_layer_t delta_layers[USHIELD_MAX_DELTA_LAYERS]; // Delta layers.
    ushield_process_t *processes[USHIELD_MAX_CHILDREN];           // All current processes sealed.
    ushield_rule_t *rules[USHIELD_MAX_RULES];                     // Rules.
} ushield_container_t;

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
#define USHIELD_IOC_CLEAR_DELTAS _IOW(USHIELD_IOC_MAGIC, 11, char[USHIELD_MAX_PATH])
#define USHIELD_IOC_PATCH_RESOURCE _IOWR(USHIELD_IOC_MAGIC, 12, struct ushield_resource_patch)

/* Telemetry Ring Buffer Definitions */
#define USHIELD_RING_CAPACITY 1024
#define USHIELD_EVENT_MESSAGE_SIZE 256

typedef enum ushield_event_type {
    USHIELD_EVENT_CONTAINER_CREATE = 0,
    USHIELD_EVENT_CONTAINER_START = 1,
    USHIELD_EVENT_CONTAINER_PAUSE = 2,
    USHIELD_EVENT_CONTAINER_STOP = 3,
    USHIELD_EVENT_CONTAINER_DELETE = 4,
    USHIELD_EVENT_CONTAINER_DUMP = 5,
    USHIELD_EVENT_CONTAINER_CONFIGURE = 6,
    USHIELD_EVENT_CONTAINER_READ = 7,
    USHIELD_EVENT_CONTAINER_WRITE = 8,
    USHIELD_EVENT_CONTAINER_EXECUTE = 9,

    USHIELD_EVENT_PROCESS_CREATE = 10,
    USHIELD_EVENT_PROCESS_START = 11,
    USHIELD_EVENT_PROCESS_PAUSE = 12,
    USHIELD_EVENT_PROCESS_STOP = 13,
    USHIELD_EVENT_PROCESS_DUMP = 14,
    USHIELD_EVENT_PROCESS_CONFIGURE = 15,

    USHIELD_EVENT_MASTER_REGISTER = 21,
    USHIELD_EVENT_MASTER_UNREGISTER = 22,

    USHIELD_EVENT_REQ_PING = 31,
    USHIELD_EVENT_REQ_VERSION = 32,
    USHIELD_EVENT_REQ_POLICY = 33,
    USHIELD_EVENT_REQ_OPEN_FD = 34,
    USHIELD_EVENT_REQ_CLOSE_FD = 35,
    USHIELD_EVENT_REQ_INITIALIZE = 36,
    USHIELD_EVENT_REQ_UNINITIALIZE = 37,

    USHIELD_EVENT_ATTENTION = 99, // Illegal action!
} ushield_event_type_t;

#define USEC_(name) USHIELD_EVENT_CONTAINER_##name
#define USEP_(name) USHIELD_EVENT_PROCESS_##name
#define USEM_(name) USHIELD_EVENT_MASTER_##name
#define USER_(name) USHIELD_EVENT_REQ_##name

struct ushield_event {
    uint64_t timestamp_ns;
    ushield_event_type_t event_type;

    uint32_t cid; // Container ID (ushield_container.id). Only set if container-related event.
    uint32_t pid; // Process-Container ID (ushield_process.id). Only set if process-related event.
    pid_t actor_pid; // Process (on host) who interacted. Only set if config-related event.
    uid_t actor_uid; // Process (on host) privileges. Only set if config-related event.

    char message[USHIELD_EVENT_MESSAGE_SIZE];
};

struct ushield_ring_buffer {
    uint32_t head;
    uint32_t tail;
    uint32_t capacity;
    uint32_t flags;
    struct ushield_event events[USHIELD_RING_CAPACITY];
};

struct ushield_target {
    uint32_t cid;
    uint32_t pid;
};

#endif // USHIELD_UAPI_H
