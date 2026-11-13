#include "internals.h"

#include "event.h"

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
int ushield_container_configure_rule_add(uint32_t cid, uint32_t rule_id, ushield_rule_t *rule);
int ushield_container_configure_rule_del(uint32_t cid, uint32_t rule_id, ushield_rule_t *rule);
int ushield_container_create(ushield_container_t *container);

/*
 * Requires fully initialized container for unregistered containers,
 * for already registered containers only ushield_container_t->id must be set.
 */
int ushield_container_start(ushield_container_t *container);
int ushield_container_pause(uint32_t cid);
int ushield_container_stop(uint32_t cid);
int ushield_container_delete(uint32_t cid);
int ushield_container_dump(uint32_t cid);
int ushield_container_self_seal(uint32_t cid);
int ushield_container_read(uint32_t cid);
int ushield_container_write(uint32_t cid);
int ushield_container_execute(uint32_t cid);
