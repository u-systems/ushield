#include "../include/event.h"
#include "linux/timekeeping.h"

static void ushield_produce_event(ushield_event_type_t event_type, uint32_t cid, uint32_t pid,
                                  pid_t actor_pid, uid_t actor_uid,
                                  char message[USHIELD_EVENT_MESSAGE_SIZE]) {
    if (!ring_buf)
        return;

    uint32_t idx = ring_buf->head & (USHIELD_RING_CAPACITY - 1);
    struct ushield_event *ev = &ring_buf->events[idx];

    ev->timestamp_ns = ktime_get_ns();
    ev->event_type = event_type;
    ev->cid = cid;
    ev->pid = pid;
    ev->actor_pid = actor_pid;
    ev->actor_uid = actor_uid;
    strscpy(ev->message, message, USHIELD_EVENT_MESSAGE_SIZE);

    smp_wmb();
    ring_buf->head++;
}

__attribute__((format(printf, 6, 7))) static inline void
ushield_produce_event_fmt(ushield_event_type_t event_type, uint32_t cid, uint32_t pid,
                          pid_t actor_pid, uid_t actor_uid, const char *fmt, ...) {
    char msg[USHIELD_EVENT_MESSAGE_SIZE];
    va_list args;
    va_start(args, fmt);
    vsnprintf(msg, sizeof(msg), fmt, args);
    va_end(args);

    ushield_produce_event(event_type, cid, pid, actor_pid, actor_uid, msg);
}
