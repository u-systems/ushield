#ifndef USHIELD_INTERNALS_H
#define USHIELD_INTERNALS_H

#include "../../include/ushield_uapi.h"
#include "asm/current.h"
#include "linux/spinlock_types.h"

struct ushield_registry {
    pid_t master_daemon_pid;
    spinlock_t lock;
    uint32_t containers_count;
    ushield_container_t *containers[USHIELD_MAX_CONTAINERS];
};

extern struct ushield_ring_buffer *ring_buf;
extern struct ushield_registry registry;

#define cp current->pid
#define master registry.master_daemon_pid

inline const char *__event_to_string(ushield_event_type_t event);
inline const char *__resource_to_string(ushield_resource_t resource);
inline int __configure_rule_add(uint32_t rule_id, uint32_t *rules_count, ushield_rule_t *rules[],
                                ushield_rule_t *rule);
inline int __configure_rule_del(uint32_t rule_id, uint32_t *rules_count, ushield_rule_t *rules[]);

#endif // USHIELD_INTERNALS_H
