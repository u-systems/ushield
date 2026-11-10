#include "../include/event.h"

bool ushield_process_is_alive(pid_t pid);
int ushield_process_find_idx(pid_t vpid, uint32_t *cid, uint32_t *pid);
int ushield_process_security_check(uint32_t cid, uint32_t pid, ushield_event_type_t event_type);
#define ushield_process_security_check(cid, pid, event_type)                                       \
    ushield_process_security_check(cid, pid, USHIELD_EVENT_PROCESS_##event_type)
int ushield_process_apply_rules(uint32_t cid, uint32_t pid);
int ushield_process_configure_rule_add(uint32_t cid, uint32_t pid, uint32_t rule_id,
                                       ushield_rule_t *rule);
int ushield_process_configure_rule_del(uint32_t cid, uint32_t pid, uint32_t rule_id);
int ushield_process_create(uint32_t cid, uint32_t pid);
int ushield_process_start(uint32_t cid, uint32_t pid);
int ushield_process_pause(uint32_t cid, uint32_t pid);
int ushield_process_stop(uint32_t cid, uint32_t pid);
int ushield_process_dump(uint32_t cid, uint32_t pid);
