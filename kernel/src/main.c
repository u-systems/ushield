#define pr_fmt(fmt) "[µShield] " fmt

#include <linux/cdev.h>
#include <linux/cred.h>
#include <linux/device.h>
#include <linux/fs.h>
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
#include <linux/types.h>
#include <linux/uaccess.h>

#include "../../include/ushield_uapi.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("tralsesec");
MODULE_DESCRIPTION("µShield Ring 0 Sandbox & Telemetry Module");
MODULE_VERSION("0.1");

#define DEVICE_NAME "ushield"
#define CLASS_NAME "ushield_class"
#define MAX_SEALED_PROCESSES 256
#define MAX_TARGET_RULES 64

struct ushield_policy {
    pid_t pid;
    pid_t creator_pid;
    uint32_t permissions;
    bool active;
};

struct ushield_target_rule {
    char binary_path[USHIELD_PATH_MAX];
    uint32_t base_template;
    uint32_t default_permissions;

    /* Edit Delta Stack */
    struct ushield_delta_layer layers[USHIELD_MAX_DELTA_LAYERS];
    size_t layer_count;

    /* Hot-Patched Resource Rules */
    struct ushield_resource_patch patches[USHIELD_MAX_RESOURCE_PATCHES];
    size_t patch_count;

    pid_t creator_pid;
    bool active;
};

struct ushield_registry {
    struct ushield_policy policies[MAX_SEALED_PROCESSES];
    struct ushield_target_rule target_rules[MAX_TARGET_RULES];
    size_t count;
    size_t rule_count;
    pid_t master_daemon_pid;
    spinlock_t lock;
};

static dev_t dev_num;
static struct cdev ushield_cdev;
static struct class *ushield_class;
static struct device *ushield_device;
static struct ushield_ring_buffer *ring_buf = NULL;
static struct ushield_registry registry;

static void ushield_produce_event(uint32_t type, uint32_t syscall_nr, uint8_t action) {
    if (!ring_buf)
        return;

    uint32_t idx = ring_buf->head & (USHIELD_RING_CAPACITY - 1);
    struct ushield_event *ev = &ring_buf->events[idx];

    ev->timestamp_ns = ktime_get_ns();
    ev->pid = current->pid;
    ev->uid = current_cred()->uid.val;
    ev->event_type = type;
    ev->syscall_nr = syscall_nr;
    ev->action_taken = action;

    smp_wmb();
    ring_buf->head++;
}

static bool is_pid_alive(pid_t pid) {
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

static int ushield_pause_process(pid_t target_pid) {
    struct task_struct *task;
    int ret = -ESRCH;

    rcu_read_lock();
    task = pid_task(find_vpid(target_pid), PIDTYPE_PID);
    if (task) {
        get_task_struct(task);
        rcu_read_unlock();

        ret = send_sig(SIGSTOP, task, 0);
        put_task_struct(task);
        pr_info("Target process PID %d PAUSED (SIGSTOP sent)\n", target_pid);
        return ret;
    }
    rcu_read_unlock();
    return ret;
}

static int ushield_resume_process(pid_t target_pid) {
    struct task_struct *task;
    int ret = -ESRCH;

    rcu_read_lock();
    task = pid_task(find_vpid(target_pid), PIDTYPE_PID);
    if (task) {
        get_task_struct(task);
        rcu_read_unlock();

        ret = send_sig(SIGCONT, task, 0);
        put_task_struct(task);
        pr_info("Target process PID %d RESUMED (SIGCONT sent)\n", target_pid);
        return ret;
    }
    rcu_read_unlock();
    return ret;
}

static int ushield_open(struct inode *inode, struct file *file) {
    const struct cred *cred = current_cred();
    pr_info("/dev/ushield opened by PID %d (UID: %d, EUID: %d)\n", current->pid, cred->uid.val,
            cred->euid.val);

    ushield_produce_event(USHIELD_EVENT_SYSCALL_EXEC, 2 /* __NR_open */, 0 /* ALLOW */);
    return 0;
}

static int ushield_release(struct inode *inode, struct file *file) {
    unsigned long flags;
    spin_lock_irqsave(&registry.lock, flags);

    if (registry.master_daemon_pid == current->pid) {
        registry.master_daemon_pid = 0;
        pr_info("Master Supervisor PID %d unregistered on close\n", current->pid);
    }

    size_t i = 0;
    while (i < registry.count) {
        if (registry.policies[i].creator_pid == current->pid) {
            pr_info("Cleaning up sealed policy %zu for exited creator PID %d\n", i, current->pid);
            registry.policies[i] = registry.policies[registry.count - 1];
            registry.count--;
        } else {
            i++;
        }
    }

    spin_unlock_irqrestore(&registry.lock, flags);

    pr_info("/dev/ushield closed by PID %d\n", current->pid);
    return 0;
}

static long ushield_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    switch (cmd) {
    case USHIELD_IOC_PING:
        pr_info("ioctl PING received from PID %d!\n", current->pid);
        return 0;

    case USHIELD_IOC_GET_VERSION: {
        uint32_t ver = USHIELD_VERSION;
        if (copy_to_user((uint32_t __user *)arg, &ver, sizeof(ver))) {
            return -EFAULT;
        }
        pr_info("ioctl GET_VERSION called by PID %d\n", current->pid);
        return 0;
    }

    case USHIELD_IOC_REGISTER_SUPERVISOR: {
        pid_t pid = current->pid;

        if (current_cred()->uid.val != 0) {
            pr_warn("PID %d failed supervisor registration (Requires UID 0)\n", pid);
            return -EPERM;
        }

        unsigned long flags;
        spin_lock_irqsave(&registry.lock, flags);

        if (registry.master_daemon_pid) {
            bool active = is_pid_alive(registry.master_daemon_pid);
            if (active && registry.master_daemon_pid != pid) {
                pr_warn("Supervisor registration denied for PID %d: Master Supervisor already "
                        "active (PID %d)\n",
                        pid, registry.master_daemon_pid);
                spin_unlock_irqrestore(&registry.lock, flags);
                return -EBUSY;
            }

            if (!active) {
                pr_info("Stale Master Supervisor detected (Dead PID %d). Replacing with PID %d\n",
                        registry.master_daemon_pid, pid);
            }
        }

        registry.master_daemon_pid = pid;
        spin_unlock_irqrestore(&registry.lock, flags);

        pr_info("Master Supervisor successfully registered (PID %d)\n", pid);
        return 0;
    }

    case USHIELD_IOC_SEAL_SELF: {
        uint32_t perms = 0;
        if (copy_from_user(&perms, (uint32_t __user *)arg, sizeof(perms))) {
            return -EFAULT;
        }

        unsigned long flags;
        int status = 0;

        spin_lock_irqsave(&registry.lock, flags);
        if (registry.count < MAX_SEALED_PROCESSES) {
            registry.policies[registry.count].pid = current->pid;
            registry.policies[registry.count].creator_pid = current->pid;
            registry.policies[registry.count].permissions = perms;
            registry.policies[registry.count].active = true;
            registry.count++;
            pr_info("Process PID %d SELF-SEALED (Perms: 0x%08X)\n", current->pid, perms);
        } else {
            status = -ENOMEM;
        }
        spin_unlock_irqrestore(&registry.lock, flags);

        if (status == 0) {
            ushield_produce_event(USHIELD_EVENT_PROCESS_SEAL, 0, 0);
        }
        return status;
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

    spin_lock_init(&registry.lock);
    registry.count = 0;
    registry.rule_count = 0;
    registry.master_daemon_pid = 0;

    ring_buf = kmalloc(sizeof(struct ushield_ring_buffer), GFP_KERNEL);
    if (!ring_buf) {
        pr_err("Failed to allocate ring buffer memory\n");
        return -ENOMEM;
    }
    memset(ring_buf, 0, sizeof(struct ushield_ring_buffer));
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
