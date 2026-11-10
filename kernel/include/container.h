#include "../include/internals.h"

/*
 * Checks if cid even in bounds, if its pointer is real and the permissions.
 * Logs failed attempts.
 * Return Value: <0 on check fail, 0 on check success, 1 on invalid args.
 */
int ushield_container_security_check(uint32_t cid, ushield_event_type_t event,
                                     ushield_resource_t resource);
#define ushield_container_security_check(cid, event_name, resource)                                \
    ushield_container_security_check(cid, USHIELD_EVENT_CONTAINER_##event_name,                    \
                                     USHIELD_RES_##resource)

int ushield_container_apply_rules(uint32_t cid);
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
