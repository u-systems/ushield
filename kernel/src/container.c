#include "../include/internals.h"

#include "../include/event.h"
#include "../include/process.h"
#include <linux/spinlock.h>

//////////////////////////////////////////
/// Container management
//////////////////////////////////////////
/*
 * Checks if cid even in bounds, if its pointer is real and the permissions.
 * Logs failed attempts.
 * Return Value: <0 on check fail, 0 on check success, 1 on invalid args.
 */
static int ushield_container_security_check(uint32_t cid, ushield_event_type_t event,
                                            ushield_resource_t resource) {
    // TODO: for now, we'll just lock the entire function for security purposes.

    const char *action = __event_to_string(event);
    const char *rsrc = __resource_to_string(resource);

    unsigned long flags;
    int status = 0;
    spin_lock_irqsave(&registry.lock, flags);

    if (registry.containers_count >= USHIELD_MAX_CONTAINERS) {
        ushield_produce_event_alarm(cid, 0,
                                    "PID %d requested action (%s) to resource (%s) of container "
                                    "%d, but reached USHIELD_MAX_CONTAINERS.\n",
                                    cp, action, rsrc, cid);
        status = -ENOMEM;
        goto end;
    }

    if (cid >= registry.containers_count || !registry.containers[cid]) {
        ushield_produce_event_alarm(
            cid, 0, "PID %d requested action (%s) to resource (%s) of non-existing container %d.\n",
            cp, action, rsrc, cid);
        status = -ESRCH;
        goto end;
    }

    ushield_container_t *container = registry.containers[cid];

    // Master / Owner => Safe
    if (cp == master || cp == container->owner)
        goto end;

    uint8_t p = resource;

    switch (event) {
    case USEC_(DELETE):
    case USEC_(START):
    case USEC_(STOP):
    case USEC_(CREATE): // CREATE doesn't even make sense here. NVM.
        if (resource != USHIELD_RES_MGMT) {
            status = 1;
            goto end; // Prevents wrong arguments turning into false alarms!
        }

        p |= USHIELD_PERM_XO;
        break;
    case USEC_(READ):
    case USEC_(DUMP):
        p |= USHIELD_PERM_RO;
        break;
    case USEC_(WRITE):
        p |= USHIELD_PERM_WO;
        break;
    case USEC_(EXECUTE):
        p |= USHIELD_PERM_XO;
        break;
    default:
        // TODO: dangerous. Requires skill.
        unreachable();
    }

    if (container->permissions & p)
        goto end;

    ushield_produce_event_alarm(cid, 0,
                                "PID %d tried to perform action (%s) on resource (%s) on container "
                                "%d without permission.\n",
                                current->pid, action, rsrc, cid);
    status = -EPERM;

end:
    spin_unlock_irqrestore(&registry.lock, flags);
    return status;
}
#define ushield_container_security_check(cid, event_name, resource)                                \
    ushield_container_security_check(cid, USHIELD_EVENT_CONTAINER_##event_name,                    \
                                     USHIELD_RES_##resource)

static int ushield_container_apply_rules(uint32_t cid) {
    // TODO: impl.
    return 0;
}

static int ushield_container_configure_rule_add(uint32_t cid, uint32_t rule_id,
                                                ushield_rule_t *rule) {
    if (ushield_container_security_check(cid, CONFIGURE, MGMT) < 0)
        return -EPERM;

    ushield_container_t *container = registry.containers[cid];

    int status = __configure_rule_add(rule_id, &container->rules_count, container->rules, rule);

    ushield_container_apply_rules(cid);
    return status;
}

static int ushield_container_configure_rule_del(uint32_t cid, uint32_t rule_id,
                                                ushield_rule_t *rule) {
    if (ushield_container_security_check(cid, CONFIGURE, MGMT) < 0)
        return -EPERM;

    ushield_container_t *container = registry.containers[cid];

    int status = __configure_rule_del(rule_id, &container->rules_count, container->rules);

    ushield_container_apply_rules(cid);
    return status;
}

static int ushield_container_create(ushield_container_t *container) {
    // Fast path: id already exists? => nothing to do.
    if (container->id < registry.containers_count && registry.containers[container->id])
        return 0;

    if (ushield_container_security_check(container->id, CREATE, MGMT) < 0)
        return -EPERM;

    ushield_container_t *ptr = kmemdup(container, sizeof(*container), GFP_KERNEL);
    if (!ptr)
        return -ENOMEM;

    unsigned long flags;
    spin_lock_irqsave(&registry.lock, flags);
    ptr->id = registry.containers_count;
    registry.containers[registry.containers_count] = ptr;
    registry.containers_count++;
    spin_unlock_irqrestore(&registry.lock, flags);

    // TODO: implement initialization of namespace, etc.
    return 0;
}

/*
 * Requires fully initialized container for unregistered containers,
 * for already registered containers only ushield_container_t->id must be set.
 */
static int ushield_container_start(ushield_container_t *container) {
    if (ushield_container_security_check(container->id, START, MGMT) < 0) {
        return -EPERM;
    }

    // Register if unregistered.
    // TODO: remove? Same for unregister > stop. Keep or remove?
    ushield_container_create(container);

    // TODO: implement container start / resume mechanism.
    return 0;
}

static int ushield_container_pause(uint32_t cid) {
    // TODO: impl.
    return 0;
}

static int ushield_container_stop(uint32_t cid) {
    if (ushield_container_security_check(cid, STOP, MGMT) < 0) {
        return -EPERM;
    }

    ushield_container_t *container = registry.containers[cid];
    for (size_t i = 0; i < container->processes_count; i++)
        ushield_process_stop(container->id, i);
    return 0;
}

static int ushield_container_delete(uint32_t cid) {
    if (ushield_container_security_check(cid, DELETE, MGMT) < 0) {
        return -EPERM;
    }

    ushield_container_stop(cid);

    // TODO: implement uninitialization of namespace/etc.

    unsigned long flags;
    spin_lock_irqsave(&registry.lock, flags);
    kfree(registry.containers[cid]);
    size_t last = registry.containers_count - 1;
    registry.containers[cid] = registry.containers[last];
    registry.containers[cid]->id = cid;
    registry.containers[last] = 0;
    registry.containers_count--;
    spin_unlock_irqrestore(&registry.lock, flags);
    return 0;
}

static int ushield_container_dump(uint32_t cid) {
    // TODO: impl.
    return 0;
}
static int ushield_container_self_seal(uint32_t cid) {
    // TODO: impl.
    return 0;
}
static int ushield_container_read(uint32_t cid) {
    // TODO: impl.
    return 0;
}
static int ushield_container_write(uint32_t cid) {
    // TODO: impl.
    return 0;
}
static int ushield_container_execute(uint32_t cid) {
    // TODO: impl.
    return 0;
}
