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
#define USIM USHIELD_IO_MAGIC
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
typedef enum ushield_op_file {
    USHIELD_FILE_CREATE = 1,      // Create new file
    USHIELD_FILE_DELETE = 2,      // Delete file
    USHIELD_FILE_PERMISSIONS = 3, // Change file permissions
    USHIELD_FILE_MOUNT = 4,       // Mount file
    USHIELD_FILE_MASK = 5         // Mask file (hide from container / process)
} ushield_op_file_t;

typedef enum ushield_op_net {
    USHIELD_NET_CREATE = 1, // Create new net
    USHIELD_NET_DELETE = 2, // Delete net
    USHIELD_NET_BRIDGE = 3, // Bridge net to host
} ushield_op_net_t;

typedef enum ushield_op_env {
    USHIELD_ENV_SET = 1,      // Set variable
    USHIELD_ENV_UNSET = 2,    // Strip variable
    USHIELD_ENV_MIRROR = 3,   // Mirror variable from host (stays updated)
    USHIELD_ENV_UNMIRROR = 4, // Un-mirror variable from host
} ushield_op_env_t;

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

#define ushield_buffer char[USHIELD_MAX_PATH] // Just a buffer.

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
    USHIELD_EVENT_CONTAINER_CONFIGURE = 6,   // Set *all* rules to provided ushield_rule_t[]
    USHIELD_EVENT_CONTAINER_RULE_ADD = 7,    // Add *one* rule at index *i*
    USHIELD_EVENT_CONTAINER_RULE_DELETE = 8, // Delete *one* rule at index *i*
    USHIELD_EVENT_CONTAINER_RULE_SET = 9,    // Set *one* rule at index *i* to new ushield_rule_t
    USHIELD_EVENT_CONTAINER_READ = 10,
    USHIELD_EVENT_CONTAINER_WRITE = 11,
    USHIELD_EVENT_CONTAINER_EXECUTE = 12,

    USHIELD_EVENT_PROCESS_CREATE = 20,
    USHIELD_EVENT_PROCESS_START = 21,
    USHIELD_EVENT_PROCESS_PAUSE = 22,
    USHIELD_EVENT_PROCESS_STOP = 23,
    USHIELD_EVENT_PROCESS_DUMP = 24,
    USHIELD_EVENT_PROCESS_CONFIGURE = 25,

    USHIELD_EVENT_MASTER_REGISTER = 31,
    USHIELD_EVENT_MASTER_UNREGISTER = 32,

    USHIELD_EVENT_REQ_PING = 51,
    USHIELD_EVENT_REQ_VERSION = 52,
    USHIELD_EVENT_REQ_OPEN_DEVICE = 53,  // For logging: opened device
    USHIELD_EVENT_REQ_CLOSE_DEVICE = 54, // For logging: closed device
    USHIELD_EVENT_REQ_INITIALIZE = 55,   // For logging: module initialized
    USHIELD_EVENT_REQ_UNINITIALIZE = 56, // For logging: module uninitialized

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

/* IOCTL Command Definitions */
#define USHIELD_IOC_CONTAINER_CREATE = _IOW(USIM, USEC_(CREATE), ushield_container_t)
#define USHIELD_IOC_CONTAINER_START = _IOW(USIM, USEC_(START), uint32_t)
#define USHIELD_IOC_CONTAINER_PAUSE = _IOW(USIM, USEC_(PAUSE), uint32_t)
#define USHIELD_IOC_CONTAINER_STOP = _IOW(USIM, USEC_(STOP), uint32_t)
#define USHIELD_IOC_CONTAINER_DELETE = _IOW(USIM, USEC_(DELETE), uint32_t)
#define USHIELD_IOC_CONTAINER_DUMP = _IOW(USIM, USEC_(DUMP), uint32_t)
#define USHIELD_IOC_CONTAINER_CONFIGURE = _IOW(USIM, USEC_(CONFIGURE), ushield_rule_t[])
#define USHIELD_IOC_CONTAINER_RULE_ADD                                                             \
    = _IOW(USIM, USEC_(RULE_ADD),                                                                  \
           ushield_buffer) // Required: container id (uint32_t) then ushield_rule_t
#define USHIELD_IOC_CONTAINER_RULE_DELETE = _IOW(USIM, USEC_(RULE_DELETE), uint32_t)
#define USHIELD_IOC_CONTAINER_RULE_SET                                                             \
    = _IOW(USIM, USEC_(RULE_SET),                                                                  \
           ushield_buffer) // Required: container id (uint32_t) then ushield_rule_t
#define USHIELD_IOC_CONTAINER_READ                                                                 \
    = _IOW(USIM, USEC_(READ), ushield_buffer) // Required: containre id (uint32_t) then
                                              // ushield_resource_t then ushield_op_* (uint8_t)
#define USHIELD_IOC_CONTAINER_WRITE                                                                \
    = _IOW(USIM, USEC_(WRITE), ushield_buffer) // Requires: container id (uint32_t) then
                                               // ushield_resource_t then ushield_op_* (uint8_t)
                                               // then rest to write
#define USHIELD_IOC_CONTAINER_EXECUTE                                                              \
    = _IOW(USIM, USEC_(EXECUTE),                                                                   \
           ushield_buffer) // Required: container id (uint32_t) then ushield_resource_t then
                           // ushield_op_* (uint8_t) then rest to execute

#define USHIELD_IOC_PROCESS_CREATE                                                                 \
    = _IOW(USIM, USEP_(CREATE),                                                                    \
           ushield_buffer) // Requires ushield_target then ushield_process_creation_t
#define USHIELD_IOC_PROCESS_START = _IOW(USIM, USEP_(START), ushield_target)
#define USHIELD_IOC_PROCESS_PAUSE = _IOW(USIM, USEP_(PAUSE), ushield_target)
#define USHIELD_IOC_PROCESS_STOP = _IOW(USIM, USEP_(STOP), ushield_target)
#define USHIELD_IOC_PROCESS_DUMP = _IOW(USIM, USEP_(DUMP), ushield_target)
#define USHIELD_IOC_PROCESS_CONFIGURE                                                              \
    = _IOW(USIM, USEP_(CONFIGURE), ushield_buffer) // Requires ushield_target then ushield_rule_t[]

#define USHIELD_IOC_MASTER_REGISTER = _IO(USIM, USEM_(REGISTER))
#define USHIELD_IOC_MASTER_UNREGISTER = _IO(USIM, USEM_(UNREGISTER))

#define USHIELD_IOC_REQ_PING = _IO(USIM, USER_(PING))
#define USHIELD_IOC_REQ_VERSION = _IOW(USIM, USER_(VERSION), uint32_t)

#endif // USHIELD_UAPI_H
