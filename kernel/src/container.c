#include "../include/internals.h"

#include "../include/container.h"
#include "../include/event.h"
#include "../include/process.h"
#include <linux/spinlock.h>

int ushield_container_configure_rule_add(uint32_t cid, uint32_t rule_id, ushield_rule_t *rule) {
    if (ushield_container_security_check(cid, CONFIGURE, MGMT) < 0)
        return -EPERM;

    ushield_container_t *container = registry.containers[cid];

    int status = __configure_rule_add(rule_id, &container->rules_count, container->rules, rule);

    ushield_container_apply_rules(cid);
    return status;
}

int ushield_container_configure_rule_del(uint32_t cid, uint32_t rule_id, ushield_rule_t *rule) {
    if (ushield_container_security_check(cid, CONFIGURE, MGMT) < 0)
        return -EPERM;

    ushield_container_t *container = registry.containers[cid];

    int status = __configure_rule_del(rule_id, &container->rules_count, container->rules);

    ushield_container_apply_rules(cid);
    return status;
}

int ushield_container_create(ushield_container_t *container) {
    // Fast path: id already exists? => nothing to do.
    if (container->id < registry.containers_count && registry.containers[container->id])
        return 0;

    if (registry.containers_count >= USHIELD_MAX_CONTAINERS)
        return -ENOMEM;

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
int ushield_container_start(ushield_container_t *container) {
    if (ushield_container_security_check(container->id, START, MGMT) < 0)
        return -EPERM;

    // Register if unregistered.
    // TODO: remove? Same for unregister > stop. Keep or remove?
    ushield_container_create(container);

    // TODO: implement container start / resume mechanism.
    return 0;
}

int ushield_container_pause(uint32_t cid) {
    // TODO: impl.
    return 0;
}

int ushield_container_stop(uint32_t cid) {
    if (ushield_container_security_check(cid, STOP, MGMT) < 0) {
        return -EPERM;
    }

    ushield_container_t *container = registry.containers[cid];
    for (size_t i = 0; i < container->processes_count; i++)
        ushield_process_stop(container->id, i);
    return 0;
}

int ushield_container_delete(uint32_t cid) {
    if (ushield_container_security_check(cid, DELETE, MGMT) < 0) {
        return -EPERM;
    }

    ushield_container_stop(cid);

    // TODO: implement uninitialization of namespace/etc.

    unsigned long flags;
    spin_lock_irqsave(&registry.lock, flags);
    kfree(registry.containers[cid]);
    size_t last = registry.containers_count - 1;
    if (cid == last) // last container was freed? No need to swap anything!
        goto end;

    registry.containers[cid] = registry.containers[last];
    registry.containers[cid]->id = cid;

end:
    registry.containers[last] = 0;
    registry.containers_count--;
    spin_unlock_irqrestore(&registry.lock, flags);
    return 0;
}

int ushield_container_dump(uint32_t cid) {
    // TODO: impl.
    return 0;
}
int ushield_container_self_seal(uint32_t cid) {
    // TODO: impl.
    return 0;
}
int ushield_container_read(uint32_t cid) {
    // TODO: impl.
    return 0;
}
int ushield_container_write(uint32_t cid) {
    // TODO: impl.
    return 0;
}
int ushield_container_execute(uint32_t cid) {
    // TODO: impl.
    return 0;
}
