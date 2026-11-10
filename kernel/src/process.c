#include "../include/internals.h"

#include "../include/event.h"
#include "../include/process.h"
#include "linux/pid.h"
#include "linux/rcupdate.h"
#include "linux/sched/signal.h"
#include "linux/timekeeping.h"

/* Process alive? IN and OUTSIDE the container (pid) */
static bool ushield_process_is_alive(pid_t pid) {
    bool alive = false;
    if (pid <= 0)
        return false;

    rcu_read_lock();
    if (pid_task(find_vpid(pid), PIDTYPE_PID) != NULL) {
        alive = true;
    }
    rcu_read_unlock();

    return alive;
}

/* Searches for Process' index (pid) by vpid in Containers! Returns 0 if found and sets cid and pid
 * to valid numbers; returns -ESRCH if nothing found and doesn't update cid and pid. */
static int ushield_process_find_idx(pid_t vpid, uint32_t *cid, uint32_t *pid) {
    int status = -ESRCH;

    unsigned long flags;
    spin_lock_irqsave(&registry.lock, flags);

    for (size_t c = 0; c < registry.containers_count; c++) {
        ushield_container_t *container = registry.containers[c];
        if (!container)
            continue;

        for (size_t p = 0; p < container->processes_count; p++) {
            ushield_process_t *process = container->processes[p];
            if (!process)
                continue;

            if (process->pid == vpid) {
                status = 0;
                *cid = c;
                *pid = p;
                goto end;
            }
        }
    }

end:
    spin_unlock_irqrestore(&registry.lock, flags);
    return status;
}

/*
 * IMPORTANT: pid IS NOT pid_t but the INDEX of process in Container!
 * Checks if pid even in bounds, if its pointer is real and the permissions.
 * Logs failed attempts.
 * Return Value: <0 on check fail, 0 on check success, 1 on invalid args.
 */
static int ushield_process_security_check(uint32_t cid, uint32_t pid,
                                          ushield_event_type_t event_type) {
    // TODO: for now, the entire function will be locked for security reasons.
    // TODO: Also for later: make sure to separate locks.
    // All functionality (container, processes, and more) have the same lock!

    const char *action = __event_to_string(event_type);

    unsigned long flags;
    int status = 0;
    spin_lock_irqsave(&registry.lock, flags);

    if (cid > registry.containers_count || !registry.containers[cid] ||
        pid > registry.containers[cid]->processes_count ||
        !registry.containers[cid]->processes[pid]) {
        ushield_produce_event_alarm(cid, pid,
                                    "PID %d requested action (%s) to non-existing "
                                    "container/process %d/%d.\n",
                                    current->pid, action, cid, pid);

        status = -ESRCH;
        goto end;
    }

    const ushield_container_t *container = registry.containers[cid];
    const ushield_process_t *process = container->processes[pid];
    if (cp == master || cp == container->owner || cp == process->owner)
        goto end;

    uint8_t p = USHIELD_RES_MGMT;

    switch (event_type) {
    case USEP_(START):
    case USEP_(STOP):
        p |= USHIELD_PERM_XO;
        break;

    case USEP_(CONFIGURE):
        p |= USHIELD_PERM_WO;
        break;

    default:
        // TODO: dangerous. Requires skill.
        unreachable();
    }

    if (container->permissions & p || process->permissions & p)
        goto end;

    ushield_produce_event_alarm(cid, 0,
                                "PID %d tried to perform action (%s) to process "
                                "%d on container %d without permission.\n",
                                current->pid, action, pid, cid);
    status = -EPERM;

end:
    spin_unlock_irqrestore(&registry.lock, flags);
    return status;
}

#define ushield_process_security_check(cid, pid, event_type)                                       \
    ushield_process_security_check(cid, pid, USHIELD_EVENT_PROCESS_##event_type)

static int ushield_process_apply_rules(uint32_t cid, uint32_t pid) {
    // TODO: impl.
    return 0;
}

/* Adds new rule by inserting rule into array (moves all elements at index to +1). For performance:
 * if the target rule is already set to 0, we just overwrite it. ushield_process_configure_rule_del
 * sets elements to 0 instead of actually removing them for performance. So if you delete a rule,
 * make sure to add at the same index if possible! */
static int ushield_process_configure_rule_add(uint32_t cid, uint32_t pid, uint32_t rule_id,
                                              ushield_rule_t *rule) {
    // TODO: add rule != 0 check? I mean if it is 0, then nothing will break.
    // TODO: - can even be used to pre-allocate a rule. Maybe keep it as it is.
    if (ushield_process_security_check(cid, pid, CONFIGURE) < 0)
        return -EPERM;

    ushield_process_t *process = registry.containers[cid]->processes[pid];
    int status = __configure_rule_add(rule_id, &process->rules_count, process->rules, rule);

    ushield_process_apply_rules(cid, pid);
    return status;
}

/* For performance: it does NOT delete the object and move all elements back by one. It just sets it
 * to 0. */
static int ushield_process_configure_rule_del(uint32_t cid, uint32_t pid, uint32_t rule_id) {
    if (ushield_process_security_check(cid, pid, CONFIGURE) < 0)
        return -EPERM;

    ushield_process_t *process = registry.containers[cid]->processes[pid];

    int status = __configure_rule_del(rule_id, &process->rules_count, process->rules);

    ushield_process_apply_rules(cid, pid);
    return status;
}

static int ushield_process_create(uint32_t cid, uint32_t pid) {
    // TODO: impl.
    return 0;
}

static int ushield_process_start(uint32_t cid, uint32_t pid) {
    if (ushield_process_security_check(cid, pid, START) < 0)
        return -EPERM;

    int status = 0;
    unsigned long flags;
    spin_lock_irqsave(&registry.lock, flags);

    ushield_process_t *process = registry.containers[cid]->processes[pid];
    ushield_exec_info_t *info = &process->info;

    // Fast path - if started no need to start.
    // WARN: assumes only we control the real status of the target.
    // If this assumption is not true, the user will never be able to start the target!
    if (info->active)
        goto end;

    if (!info->start_ns) {
        // TODO: implement real start.
        info->start_ns = ktime_get_ns();
        info->active = true;
        goto end;
    }

    // We could check if info->stop_ns is set for robustness,
    // but we'll ignore it for performance.
    // TODO: implement real resume.
    info->active = true;

end:
    spin_unlock_irqrestore(&registry.lock, flags);
    return status;
}

static int ushield_process_pause(uint32_t cid, uint32_t pid) {
    if (ushield_process_security_check(cid, pid, PAUSE) < 0)
        return -EPERM;

    // TODO: due to small race window here,
    // the entire function will be locked for security purposes. FOR NOW.

    unsigned long flags;
    spin_lock_irqsave(&registry.lock, flags);

    ushield_process_t *process = registry.containers[cid]->processes[pid];
    struct task_struct *task;
    int status = -ESRCH;

    rcu_read_lock();
    task = pid_task(find_vpid(process->pid), PIDTYPE_PID);
    if (task) {
        get_task_struct(task);
        rcu_read_unlock();

        status = send_sig(SIGSTOP, task, 0);
        put_task_struct(task);
        ushield_produce_event_process(USHIELD_EVENT_PROCESS_STOP, cid, pid,
                                      "Target process PID %d PAUSED (SIGSTOP sent)\n",
                                      process->pid);

        ushield_exec_info_t *info = &process->info;
        info->active = false;
        info->stop_ns = ktime_get_ns();

        goto end;
    }
    rcu_read_unlock();

end:
    spin_unlock_irqrestore(&registry.lock, flags);
    return status;
}

static int ushield_process_stop(uint32_t cid, uint32_t pid) {
    // TODO: impl.
    return 0;
}

static int ushield_process_dump(uint32_t cid, uint32_t pid) {
    // TODO: impl.
    return 0;
}
