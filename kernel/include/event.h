#include "internals.h"

//////////////////////////////////////////
/// Event management
//////////////////////////////////////////
static void ushield_produce_event(ushield_event_type_t event_type, uint32_t cid, uint32_t pid,
                                  pid_t actor_pid, uid_t actor_uid,
                                  char message[USHIELD_EVENT_MESSAGE_SIZE]);

__attribute__((format(printf, 6, 7))) static inline void
ushield_produce_event_fmt(ushield_event_type_t event_type, uint32_t cid, uint32_t pid,
                          pid_t actor_pid, uid_t actor_uid, const char *fmt, ...);

#define ushield_produce_event_container(event_type, cid, fmt, ...)                                 \
    ushield_produce_event_fmt((event_type), (cid), 0, current->pid, current_cred()->uid.val,       \
                              (fmt), ##__VA_ARGS__)

#define ushield_produce_event_process(event_type, cid, pid, fmt, ...)                              \
    ushield_produce_event_fmt((event_type), (cid), (pid), 0, 0, (fmt), ##__VA_ARGS__)

#define ushield_produce_event_master(event_type, fmt, ...)                                         \
    ushield_produce_event_fmt((event_type), 0, 0, 0, 0, (fmt), ##__VA_ARGS__)

#define ushield_produce_event_req(event_type, fmt, ...)                                            \
    ushield_produce_event_fmt((event_type), 0, 0, current->pid, current_cred()->uid.val,           \
                              (fmt), ##__VA_ARGS__)

#define ushield_produce_event_alarm(cid, cpid, fmt, ...)                                           \
    ushield_produce_event_fmt(USHIELD_EVENT_ATTENTION, (cid), (cpid), current->pid,                \
                              current_cred()->uid.val, (fmt), ##__VA_ARGS__)

#define ushield_produce_event_alarm_permd(cid, cpid, fmt, ...)                                     \
    ushield_produce_event_alarm(cid, cpid, "PERMISSION DENIED: " fmt, ##__VA_ARGS__)
