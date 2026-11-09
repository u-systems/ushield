#define pr_fmt(fmt) "[µShield] " fmt

#include <asm-generic/errno-base.h>
#include <linux/cdev.h>
#include <linux/compiler.h>
#include <linux/cred.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/gfp_types.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/ktime.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/pid.h>
#include <linux/rcupdate.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/timekeeping.h>
#include <linux/types.h>
#include <linux/uaccess.h>

#include "../../include/ushield_uapi.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("tralsesec");
MODULE_DESCRIPTION("µShield Ring 0 Sandbox & Telemetry Module");
MODULE_VERSION("0.1");

#define DEVICE_NAME "ushield"
#define CLASS_NAME "ushield_class"

struct ushield_registry {
    pid_t master_daemon_pid;
    spinlock_t lock;
    uint32_t containers_count;
    ushield_container_t *containers[USHIELD_MAX_CONTAINERS];
};

static dev_t dev_num;
static struct cdev ushield_cdev;
static struct class *ushield_class;
static struct device *ushield_device;
static struct ushield_ring_buffer *ring_buf = NULL;
static struct ushield_registry registry;

#define cp current->pid
#define master registry.master_daemon_pid

//////////////////////////////////////////
/// Event management
//////////////////////////////////////////
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

//////////////////////////////////////////
/// General Helpers
//////////////////////////////////////////
static inline const char *__event_to_string(ushield_event_type_t event) {
    const char *action = "???";
    switch (event) {
    case USEC_(CREATE):
    case USEP_(CREATE):
        action = "create";
        break;

    case USEC_(START):
    case USEP_(START):
        action = "start";
        break;

    case USEC_(PAUSE):
    case USEP_(PAUSE):
        action = "pause";
        break;

    case USEC_(STOP):
    case USEP_(STOP):
        action = "stop";
        break;

    case USEC_(DELETE):
        action = "delete";
        break;

    case USEC_(DUMP):
    case USEP_(DUMP):
        action = "dump";
        break;

    case USEC_(CONFIGURE):
    case USEP_(CONFIGURE):
        action = "configure";
        break;

    case USEC_(READ):
        action = "read";
        break;

    case USEC_(WRITE):
        action = "write";
        break;

    case USEC_(EXECUTE):
        action = "execute";
        break;

    default:
        break;
    }
    return action;
}

static inline const char *__resource_to_string(ushield_resource_t resource) {
    const char *rsrc = "???";
    switch (resource) {
    case USHIELD_RES_FS:
        rsrc = "filesystem";
        break;
    case USHIELD_RES_NET:
        rsrc = "network";
        break;
    case USHIELD_RES_ENV:
        rsrc = "environment";
        break;
    case USHIELD_RES_PROC:
        rsrc = "process";
        break;
    case USHIELD_RES_MGMT:
        rsrc = "management";
        break;
    }
    return rsrc;
}

/* Adds new rule by inserting rule into array (moves all elements at index to +1). For performance:
 * if the target rule is already set to 0, we just overwrite it. __configure_rule_del
 * sets elements to 0 instead of actually removing them for performance. So if you delete a rule,
 * make sure to add at the same index if possible! */
static inline int __configure_rule_add(uint32_t rule_id, uint32_t *rules_count,
                                       ushield_rule_t *rules[], ushield_rule_t *rule) {
    unsigned long flags;
    int status = 0;
    spin_lock_irqsave(&registry.lock, flags);

    if (rule_id > *rules_count) {
        status = -ESRCH;
        goto end;
    }

    if (*rules_count >= USHIELD_MAX_RULES) {
        status = -ENOMEM;
        goto end;
    }

    // Fast path - for whatever reason rule is empty
    if (rules[rule_id]) {
        // TODO: maybe we should validate the rule first; this is user input!
        rules[rule_id] = rule;
        goto end;
    }

    // Make space for rule and insert!
    for (size_t i = *rules_count; i >= rule_id; i--) {
        rules[i + 1] = rules[i];
    }

    rules[rule_id] = rule;
    (*rules_count)++;

end:
    spin_unlock_irqrestore(&registry.lock, flags);
    return status;
}

/* For performance: it does NOT delete the object and move all elements back by one. It just sets it
 * to 0. */
static inline int __configure_rule_del(uint32_t rule_id, uint32_t *rules_count,
                                       ushield_rule_t *rules[]) {
    int status = 0;
    unsigned long flags;
    spin_lock_irqsave(&registry.lock, flags);

    if (!rules_count || !*rules_count || rule_id > *rules_count) {
        status = -ESRCH;
        goto end;
    }

    // For performance: just set to 0. Can be overwritten later.
    rules[rule_id] = 0;

end:
    spin_unlock_irqrestore(&registry.lock, flags);
    return status;
}

//////////////////////////////////////////
/// Process management
//////////////////////////////////////////
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

    if (cid > registry.containers_count || !registry.containers[cid]) {
        ushield_produce_event_alarm(
            cid, 0, "PID %d requested action (%s) to resource (%s) of non-existing container %d.\n",
            current->pid, action, rsrc, cid);
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

    if (registry.containers_count >= USHIELD_MAX_CONTAINERS)
        return -ENOMEM;

    size_t size = sizeof(ushield_container_t);
    ushield_container_t *ptr = kmalloc(size, GFP_KERNEL);
    if (!ptr) {
        return -ENOMEM;
    }
    memcpy(ptr, container, size);

    unsigned long flags;
    spin_lock_irqsave(&registry.lock, flags);
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
        ushield_process_stop(container->id, container->processes[i]->pid);
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

//////////////////////////////////////////
/// Device management
//////////////////////////////////////////
static int ushield_open(struct inode *inode, struct file *file) {
    const struct cred *cred = current_cred();
    ushield_produce_event_req(USHIELD_EVENT_REQ_OPEN_FD,
                              "/dev/ushield opened by PID %d (UID: %d, EUID: %d)\n", current->pid,
                              cred->uid.val, cred->euid.val);
    return 0;
}

static int ushield_release(struct inode *inode, struct file *file) {
    unsigned long flags;
    spin_lock_irqsave(&registry.lock, flags);

    for (size_t i = 0; i < registry.containers_count; i++)
        ushield_container_stop(i);

    spin_unlock_irqrestore(&registry.lock, flags);

    ushield_produce_event_req(USHIELD_EVENT_REQ_CLOSE_FD, "/dev/ushield closed by PID %d\n",
                              current->pid);
    return 0;
}

static long ushield_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    switch (cmd) {
    case USHIELD_IOC_PING:
        ushield_produce_event_req(USHIELD_EVENT_REQ_PING, "ioctl PING received from PID %d\n",
                                  current->pid);
        return 0;

    case USHIELD_IOC_GET_VERSION: {
        uint32_t ver = USHIELD_VERSION;
        if (copy_to_user((uint32_t __user *)arg, &ver, sizeof(ver))) {
            return -EFAULT;
        }
        ushield_produce_event_req(USHIELD_EVENT_REQ_VERSION, "ioctl GET_VERSION called by PID %d\n",
                                  current->pid);
        return 0;
    }

    case USHIELD_IOC_REGISTER_SUPERVISOR: {
        pid_t pid = current->pid;
        _Bool active = ushield_process_is_alive(master);

        if (current_cred()->uid.val != 0) {
            ushield_produce_event_alarm_permd(0, 0, "PID %d tried to register as supervisor\n",
                                              pid);
            return -EPERM;
        }

        unsigned long flags;
        spin_lock_irqsave(&registry.lock, flags);

        if (active && master != pid) {
            ushield_produce_event_alarm_permd(
                0, 0,
                "PID %d (uid=0) tried to register as supervisor while supervisor PID %d is "
                "still alive and unregistered\n",
                pid, master);
            spin_unlock_irqrestore(&registry.lock, flags);
            return -EBUSY;
        }

        registry.master_daemon_pid = pid;
        spin_unlock_irqrestore(&registry.lock, flags);

        if (!active && master)
            ushield_produce_event_master(USHIELD_EVENT_MASTER_REGISTER,
                                         "PID %d replaced Stale Master Supervisor %d\n", pid,
                                         master);
        else
            ushield_produce_event_master(USHIELD_EVENT_MASTER_REGISTER,
                                         "PID %d took the lead and is Master Supervisor now\n",
                                         pid);
        return 0;
    }

    case USHIELD_IOC_SEAL_SELF: {
        uint32_t cid;
        if (copy_from_user(&cid, (uint32_t __user *)arg, sizeof(cid)))
            return -EFAULT;

        if (ushield_container_security_check(cid, EXECUTE, PROC) < 0)
            return -EPERM;

        if (registry.containers[cid]->processes_count >= USHIELD_MAX_CHILDREN)
            return -ENOMEM;

        return ushield_container_self_seal(cid);
    }

    case USHIELD_IOC_REGISTER_TARGET: {
        struct ushield_target_config *config = kmalloc(sizeof(*config), GFP_KERNEL);
        if (!config)
            return -ENOMEM;

        if (copy_from_user(config, (struct ushield_target_config __user *)arg, sizeof(*config))) {
            kfree(config);
            return -EFAULT;
        }

        config->binary_path[USHIELD_PATH_MAX - 1] = '\0';

        unsigned long flags;
        int status = 0;

        spin_lock_irqsave(&registry.lock, flags);

        if (current->pid != registry.master_daemon_pid) {
            spin_unlock_irqrestore(&registry.lock, flags);
            pr_warn("PID %d denied registering target rule (Not Master Supervisor)\n",
                    current->pid);
            kfree(config);
            return -EPERM;
        }

        bool exists = false;
        for (size_t i = 0; i < registry.rule_count; i++) {
            if (registry.target_rules[i].active &&
                strncmp(registry.target_rules[i].binary_path, config->binary_path,
                        USHIELD_PATH_MAX) == 0) {
                registry.target_rules[i].default_permissions = config->default_perm_mask;
                registry.target_rules[i].base_template = config->base_template;
                exists = true;
                pr_info("Updated target execution rule for binary '%s' (Perms: 0x%08X)\n",
                        config->binary_path, config->default_perm_mask);
                break;
            }
        }

        if (!exists) {
            if (registry.rule_count < MAX_TARGET_RULES) {
                struct ushield_target_rule *rule = &registry.target_rules[registry.rule_count];
                memset(rule, 0, sizeof(*rule));

                strscpy(rule->binary_path, config->binary_path, sizeof(rule->binary_path));
                rule->base_template = config->base_template;
                rule->default_permissions = config->default_perm_mask;
                rule->creator_pid = current->pid;
                rule->active = true;
                registry.rule_count++;

                pr_info("Registered target execution rule for binary '%s' (Perms: 0x%08X)\n",
                        config->binary_path, config->default_perm_mask);
            } else {
                status = -ENOMEM;
            }
        }

        spin_unlock_irqrestore(&registry.lock, flags);
        kfree(config);

        if (status == 0) {
            ushield_produce_event(USHIELD_EVENT_PROCESS_SEAL, 0, 0);
        }

        return status;
    }

    case USHIELD_IOC_UNREGISTER_TARGET: {
        struct ushield_target_config *config = kmalloc(sizeof(*config), GFP_KERNEL);
        if (!config)
            return -ENOMEM;

        if (copy_from_user(config, (struct ushield_target_config __user *)arg, sizeof(*config))) {
            kfree(config);
            return -EFAULT;
        }

        config->binary_path[USHIELD_PATH_MAX - 1] = '\0';

        unsigned long flags;
        bool found = false;

        spin_lock_irqsave(&registry.lock, flags);

        if (current->pid != registry.master_daemon_pid) {
            spin_unlock_irqrestore(&registry.lock, flags);
            kfree(config);
            return -EPERM;
        }

        for (size_t i = 0; i < registry.rule_count; i++) {
            if (registry.target_rules[i].active &&
                strncmp(registry.target_rules[i].binary_path, config->binary_path,
                        USHIELD_PATH_MAX) == 0) {
                registry.target_rules[i] = registry.target_rules[registry.rule_count - 1];
                memset(&registry.target_rules[registry.rule_count - 1], 0,
                       sizeof(struct ushield_target_rule));
                registry.rule_count--;
                found = true;
                pr_info("Unregistered target execution rule for binary '%s'\n",
                        config->binary_path);
                break;
            }
        }

        spin_unlock_irqrestore(&registry.lock, flags);
        kfree(config);

        return found ? 0 : -ENOENT;
    }

    case USHIELD_IOC_PAUSE_TARGET: {
        uint32_t target_pid = 0;
        if (copy_from_user(&target_pid, (uint32_t __user *)arg, sizeof(target_pid))) {
            return -EFAULT;
        }

        if (current->pid != registry.master_daemon_pid) {
            return -EPERM;
        }

        return ushield_pause_process((pid_t)target_pid);
    }

    case USHIELD_IOC_RESUME_TARGET: {
        uint32_t target_pid = 0;
        if (copy_from_user(&target_pid, (uint32_t __user *)arg, sizeof(target_pid))) {
            return -EFAULT;
        }

        if (current->pid != registry.master_daemon_pid) {
            return -EPERM;
        }

        return ushield_resume_process((pid_t)target_pid);
    }

    case USHIELD_IOC_PUSH_DELTA: {
        struct ushield_delta_layer *layer = kmalloc(sizeof(*layer), GFP_KERNEL);
        if (!layer)
            return -ENOMEM;

        if (copy_from_user(layer, (struct ushield_delta_layer __user *)arg, sizeof(*layer))) {
            kfree(layer);
            return -EFAULT;
        }

        unsigned long flags;
        int status = -ENOENT;

        spin_lock_irqsave(&registry.lock, flags);

        if (current->pid != registry.master_daemon_pid) {
            spin_unlock_irqrestore(&registry.lock, flags);
            kfree(layer);
            return -EPERM;
        }

        for (size_t i = 0; i < registry.rule_count; i++) {
            if (registry.target_rules[i].active) {
                if (registry.target_rules[i].layer_count < USHIELD_MAX_DELTA_LAYERS) {
                    size_t idx = registry.target_rules[i].layer_count;
                    registry.target_rules[i].layers[idx] = *layer;
                    registry.target_rules[i].layers[idx].layer_id = (uint32_t)idx;
                    registry.target_rules[i].layer_count++;

                    pr_info(
                        "Pushed Edit Delta Layer %zu to target binary '%s' (%u mounts, %u envs)\n",
                        idx, registry.target_rules[i].binary_path, layer->mount_count,
                        layer->env_count);
                    status = 0;
                } else {
                    status = -ENOMEM;
                }
                break;
            }
        }

        spin_unlock_irqrestore(&registry.lock, flags);
        kfree(layer);
        return status;
    }

    case USHIELD_IOC_PATCH_RESOURCE: {
        struct ushield_resource_patch *patch = kmalloc(sizeof(*patch), GFP_KERNEL);
        if (!patch)
            return -ENOMEM;

        if (copy_from_user(patch, (struct ushield_resource_patch __user *)arg, sizeof(*patch))) {
            kfree(patch);
            return -EFAULT;
        }

        patch->binary_path[USHIELD_PATH_MAX - 1] = '\0';
        patch->resource_name[USHIELD_PATH_MAX - 1] = '\0';

        unsigned long flags;
        int status = -ENOENT;

        spin_lock_irqsave(&registry.lock, flags);

        if (current->pid != registry.master_daemon_pid) {
            spin_unlock_irqrestore(&registry.lock, flags);
            kfree(patch);
            return -EPERM;
        }

        for (size_t i = 0; i < registry.rule_count; i++) {
            if (registry.target_rules[i].active &&
                strncmp(registry.target_rules[i].binary_path, patch->binary_path,
                        USHIELD_PATH_MAX) == 0) {

                bool updated = false;
                for (size_t j = 0; j < registry.target_rules[i].patch_count; j++) {
                    if (registry.target_rules[i].patches[j].resource_type == patch->resource_type &&
                        registry.target_rules[i].patches[j].resource_id == patch->resource_id) {
                        registry.target_rules[i].patches[j] = *patch;
                        updated = true;
                        pr_info(
                            "Hot-patched existing Resource Rule (Type: %u, ID: %llu) for '%s'\n",
                            patch->resource_type, (unsigned long long)patch->resource_id,
                            patch->binary_path);
                        break;
                    }
                }

                if (!updated) {
                    if (registry.target_rules[i].patch_count < USHIELD_MAX_RESOURCE_PATCHES) {
                        size_t p_idx = registry.target_rules[i].patch_count;
                        registry.target_rules[i].patches[p_idx] = *patch;
                        registry.target_rules[i].patch_count++;
                        pr_info(
                            "Added new Hot-Patched Resource Rule (Type: %u, ID: %llu) for '%s'\n",
                            patch->resource_type, (unsigned long long)patch->resource_id,
                            patch->binary_path);
                        status = 0;
                    } else {
                        status = -ENOMEM;
                    }
                } else {
                    status = 0;
                }
                break;
            }
        }

        spin_unlock_irqrestore(&registry.lock, flags);
        kfree(patch);
        return status;
    }

    default:
        pr_warn("Unknown ioctl command 0x%x from PID %d\n", cmd, current->pid);
        return -ENOTTY;
    }
}

static int ushield_mmap(struct file *file, struct vm_area_struct *vma) {
    unsigned long size = vma->vm_end - vma->vm_start;
    unsigned long expected_size = PAGE_ALIGN(sizeof(struct ushield_ring_buffer));

    if (size > expected_size) {
        pr_err("mmap size request (%lu bytes) exceeds allocated ring buffer (%lu bytes)\n", size,
               expected_size);
        return -EINVAL;
    }

    unsigned long pfn = virt_to_phys((void *)ring_buf) >> PAGE_SHIFT;

    if (remap_pfn_range(vma, vma->vm_start, pfn, size, vma->vm_page_prot)) {
        pr_err("remap_pfn_range failed!\n");
        return -EAGAIN;
    }

    pr_info("mmap successfully mapped %lu bytes to PID %d\n", size, current->pid);
    return 0;
}

static struct file_operations fops = {
    .owner = THIS_MODULE,
    .open = ushield_open,
    .release = ushield_release,
    .unlocked_ioctl = ushield_ioctl,
    .mmap = ushield_mmap,
};

static char *ushield_devnode(const struct device *dev, umode_t *mode) {
    if (mode) {
        *mode = 0666;
    }
    return NULL;
}

static int __init ushield_init(void) {
    int ret;

    pr_info("Initializing Ring 0 driver...\n");

    ring_buf = kmalloc(sizeof(struct ushield_ring_buffer), GFP_KERNEL);
    if (!ring_buf) {
        pr_err("Failed to allocate ring buffer memory\n");
        return -ENOMEM;
    }
    memset(ring_buf, 0, sizeof(struct ushield_ring_buffer));

    spin_lock_init(&registry.lock);
    registry.count = 0;
    registry.rule_count = 0;
    registry.master_daemon_pid = 0;
    ring_buf->capacity = USHIELD_RING_CAPACITY;

    ret = alloc_chrdev_region(&dev_num, 0, 1, DEVICE_NAME);
    if (ret < 0) {
        pr_err("Failed to allocate major/minor region (err: %d)\n", ret);
        goto fail_free_ring;
    }

    cdev_init(&ushield_cdev, &fops);
    ushield_cdev.owner = THIS_MODULE;

    ret = cdev_add(&ushield_cdev, dev_num, 1);
    if (ret < 0) {
        pr_err("Failed to add cdev (err: %d)\n", ret);
        goto fail_unregister;
    }

    ushield_class = class_create(CLASS_NAME);
    if (IS_ERR(ushield_class)) {
        ret = PTR_ERR(ushield_class);
        pr_err("Failed to create class (err: %d)\n", ret);
        goto fail_cdev;
    }

    ushield_class->devnode = ushield_devnode;

    ushield_device = device_create(ushield_class, NULL, dev_num, NULL, DEVICE_NAME);
    if (IS_ERR(ushield_device)) {
        ret = PTR_ERR(ushield_device);
        pr_err("Failed to create device (err: %d)\n", ret);
        goto fail_class;
    }

    pr_info("Driver registered at /dev/%s (Major: %d, Minor: %d)\n", DEVICE_NAME, MAJOR(dev_num),
            MINOR(dev_num));

    return 0;

fail_class:
    class_destroy(ushield_class);
fail_cdev:
    cdev_del(&ushield_cdev);
fail_unregister:
    unregister_chrdev_region(dev_num, 1);
fail_free_ring:
    kfree(ring_buf);
    return ret;
}

static void __exit ushield_exit(void) {
    device_destroy(ushield_class, dev_num);
    class_destroy(ushield_class);
    cdev_del(&ushield_cdev);
    unregister_chrdev_region(dev_num, 1);

    if (ring_buf) {
        kfree(ring_buf);
    }

    pr_info("Driver unloaded cleanly from Ring 0\n");
}

module_init(ushield_init);
module_exit(ushield_exit);
