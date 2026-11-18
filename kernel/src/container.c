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
    if (!container)
        return -EINVAL;

    // Fast path: id already exists? => nothing to do.
    if (container->id < registry.containers_count && registry.containers[container->id])
        return 0;

    if (registry.containers_count >= USHIELD_MAX_CONTAINERS)
        return -ENOMEM;

    ushield_container_t *ptr = kmemdup(container, sizeof(*container), GFP_KERNEL);
    if (!ptr)
        return -ENOMEM;

    memset(ptr->processes, 0, sizeof(ptr->processes));
    ptr->processes_count = 0;
    ptr->owner = cp;
    ptr->info.active = false;
    ptr->info.start_ns = 0; // TODO: add .created_ns ?
    ptr->permissions = container->permissions;
    memcpy(ptr->delta_layers, container->delta_layers, sizeof(ptr->delta_layers));
    memcpy(ptr->rules, container->rules, sizeof(ptr->rules));
    ptr->rules_count =
        container->rules_count; // WARN: Implicitly trust; but we'll stop on the first NULL anyways

    unsigned long flags;
    spin_lock_irqsave(&registry.lock, flags);
    ptr->id = registry.containers_count;
    registry.containers[registry.containers_count] = ptr;
    registry.containers_count++;
    spin_unlock_irqrestore(&registry.lock, flags);

    ushield_produce_event_container(USEC_(CREATE), ptr->id,
                                    "Container %u created by PID %d (perms 0x%02X)\n", ptr->id, cp,
                                    ptr->permissions);

    return 0;
}

/*
 * Requires fully initialized container for unregistered containers,
 * for already registered containers only ushield_container_t->id must be set.
 */
int ushield_container_start(uint32_t cid) {
    if (ushield_container_security_check(cid, START, MGMT) < 0)
        return -EPERM;

    unsigned long flags;
    bool is_cold_start = false;
    uint32_t proc_count = 0;

    spin_lock_irqsave(&registry.lock, flags);

    if (cid >= registry.containers_count || !registry.containers[cid]) {
        spin_unlock_irqrestore(&registry.lock, flags);
        return -ESRCH;
    }

    ushield_container_t *container = registry.containers[cid];
    ushield_exec_info_t *info = &container->info;

    /* Fast path: container is already running */
    if (info->active) {
        spin_unlock_irqrestore(&registry.lock, flags);
        return 0;
    }

    is_cold_start = (info->start_ns == 0);
    proc_count = container->processes_count;

    spin_unlock_irqrestore(&registry.lock, flags);

    /* Cold start: materialize namespaces & delta layers before anything executes */
    if (is_cold_start) {
        int err = ushield_ns_init_container(cid);
        if (err < 0) {
            ushield_produce_event_alarm(
                cid, 0, "Failed to initialize environment for container %u (err: %d)\n", cid, err);
            return err;
        }
    }

    /* Arm container-wide syscall/memory rules before releasing processes */
    int rule_err = ushield_container_apply_rules(cid);
    if (rule_err < 0)
        return rule_err;

    /* Commit active state & timestamps */
    spin_lock_irqsave(&registry.lock, flags);
    if (cid >= registry.containers_count || !registry.containers[cid]) {
        spin_unlock_irqrestore(&registry.lock, flags);
        return -ESRCH;
    }

    container = registry.containers[cid];
    info = &container->info;
    if (is_cold_start)
        info->start_ + ns = ktime_get_ns();

    info->stop_ns = 0;
    info->active = true;
    proc_count = container->processes_count;
    spin_unlock_irqrestore(&registry.lock, flags);

    /* Start or resume all registered processes in the container */
    uint32_t not_started = 0;
    for (uint32_t i = 0; i < proc_count; i++) {
        int proc_err = ushield_process_start(cid, i);
        if (proc_err < 0) {
            ushield_produce_event_process(
                USEP_(START), "Process %u on Container %u: failed to start process (err: %d)\n", i,
                cid, proc_err);
            not_started++;
            continue;
        }

        ushield_produce_event_process(USEP_(START),
                                      "Process %u on Container %u: started successfully.", i, cid);
    }

    ushield_produce_event_container(USEC_(START), cid, "Container %u %s by PID %d (%u processes)\n",
                                    cid, is_cold_start ? "started" : "resumed", cp,
                                    proc_count - not_started);

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
