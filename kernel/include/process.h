#include "../include/internals.h"

#include "../include/event.h"

/* Process alive? IN and OUTSIDE the container (pid) */
static bool ushield_process_is_alive(pid_t pid);

/* Searches for Process' index (pid) by vpid in Containers! Returns 0 if found and sets cid and pid
 * to valid numbers; returns -ESRCH if nothing found and doesn't update cid and pid. */
static int ushield_process_find_idx(pid_t vpid, uint32_t *cid, uint32_t *pid);

/*
 * IMPORTANT: pid IS NOT pid_t but the INDEX of process in Container!
 * Checks if pid even in bounds, if its pointer is real and the permissions.
 * Logs failed attempts.
 * Return Value: <0 on check fail, 0 on check success, 1 on invalid args.
 */
static int ushield_process_security_check(uint32_t cid, uint32_t pid,
                                          ushield_event_type_t event_type);
#define ushield_process_security_check(cid, pid, event_type)                                       \
    ushield_process_security_check(cid, pid, USHIELD_EVENT_PROCESS_##event_type)

static int ushield_process_apply_rules(uint32_t cid, uint32_t pid);

/* Adds new rule by inserting rule into array (moves all elements at index to +1). For performance:
 * if the target rule is already set to 0, we just overwrite it. ushield_process_configure_rule_del
 * sets elements to 0 instead of actually removing them for performance. So if you delete a rule,
 * make sure to add at the same index if possible! */
static int ushield_process_configure_rule_add(uint32_t cid, uint32_t pid, uint32_t rule_id,
                                              ushield_rule_t *rule);
/* For performance: it does NOT delete the object and move all elements back by one. It just sets it
 * to 0. */
static int ushield_process_configure_rule_del(uint32_t cid, uint32_t pid, uint32_t rule_id);
static int ushield_process_create(uint32_t cid, uint32_t pid);
static int ushield_process_start(uint32_t cid, uint32_t pid);
static int ushield_process_pause(uint32_t cid, uint32_t pid);
static int ushield_process_stop(uint32_t cid, uint32_t pid);
static int ushield_process_dump(uint32_t cid, uint32_t pid);
