#ifndef USHIELD_INTERNALS_H
#define USHIELD_INTERNALS_H

#include "../../include/ushield_uapi.h"
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/types.h>

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

static inline const char *__event_to_string(ushield_event_type_t event) {
    const char *action = "???";
    switch (event) {
    case USEC_(CREATE):
    case USEP_(CREATE):
        action = "create";
        break;

    case USEC_(START):
    case USEP_(START):
        action = "start";
        break;

    case USEC_(PAUSE):
    case USEP_(PAUSE):
        action = "pause";
        break;

    case USEC_(STOP):
    case USEP_(STOP):
        action = "stop";
        break;

    case USEC_(DELETE):
        action = "delete";
        break;

    case USEC_(DUMP):
    case USEP_(DUMP):
        action = "dump";
        break;

    case USEC_(CONFIGURE):
    case USEP_(CONFIGURE):
        action = "configure";
        break;

    case USEC_(READ):
        action = "read";
        break;

    case USEC_(WRITE):
        action = "write";
        break;

    case USEC_(EXECUTE):
        action = "execute";
        break;

    default:
        break;
    }
    return action;
}

static inline const char *__resource_to_string(ushield_resource_t resource) {
    const char *rsrc = "???";
    switch (resource) {
    case USHIELD_RES_FS:
        rsrc = "filesystem";
        break;
    case USHIELD_RES_NET:
        rsrc = "network";
        break;
    case USHIELD_RES_ENV:
        rsrc = "environment";
        break;
    case USHIELD_RES_PROC:
        rsrc = "process";
        break;
    case USHIELD_RES_MGMT:
        rsrc = "management";
        break;
    }
    return rsrc;
}

/* Adds new rule by inserting rule into array (moves all elements at index to +1). For performance:
 * if the target rule is already set to 0, we just overwrite it. __configure_rule_del
 * sets elements to 0 instead of actually removing them for performance. So if you delete a rule,
 * make sure to add at the same index if possible! */
static inline int __configure_rule_add(uint32_t rule_id, uint32_t *rules_count,
                                       ushield_rule_t *rules[], ushield_rule_t *rule) {
    unsigned long flags;
    int status = 0;
    spin_lock_irqsave(&registry.lock, flags);

    if (rule_id > *rules_count) {
        status = -ESRCH;
        goto end;
    }

    if (*rules_count >= USHIELD_MAX_RULES) {
        status = -ENOMEM;
        goto end;
    }

    // Fast path - for whatever reason rule is empty
    if (rules[rule_id]) {
        // TODO: maybe we should validate the rule first; this is user input!
        rules[rule_id] = rule;
        goto end;
    }

    // Make space for rule and insert!
    for (size_t i = *rules_count; i > rule_id; i--) {
        rules[i] = rules[i - 1];
    }

    rules[rule_id] = rule;
    (*rules_count)++;

end:
    spin_unlock_irqrestore(&registry.lock, flags);
    return status;
}

/* For performance: it does NOT delete the object and move all elements back by one. It just sets it
 * to 0. */
static inline int __configure_rule_del(uint32_t rule_id, uint32_t *rules_count,
                                       ushield_rule_t *rules[]) {
    int status = 0;
    unsigned long flags;
    spin_lock_irqsave(&registry.lock, flags);

    if (!rules_count || !*rules_count || rule_id > *rules_count) {
        status = -ESRCH;
        goto end;
    }

    // For performance: just set to 0. Can be overwritten later.
    rules[rule_id] = 0;

end:
    spin_unlock_irqrestore(&registry.lock, flags);
    return status;
}

#endif // USHIELD_INTERNALS_H
