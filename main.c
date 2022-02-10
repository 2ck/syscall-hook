#include <linux/module.h>
/* #include <linux/kernel.h> */
#include <linux/kprobes.h>
#include <linux/printk.h>

#include "syms.h"

/* bit 16 (for the CR0 register) */
#define WP_MASK 0x10000

MODULE_LICENSE("GPL");


static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name"
};

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);

unsigned long* sys_call_table;

/* extern int import_iovec(int type, const struct iovec *uvec, unsigned int nr_segs, unsigned int fast_segs, struct iovec **iovp, struct iov_iter *i); */
mm_access_t mm_access_sym;
zap_page_range_t zap_page_range_sym;
soft_offline_page_t soft_offline_page_sym;
find_vma_prev_t find_vma_prev_sym;
pidfd_get_task_t pidfd_get_task_sym;
iovec_from_user_t iovec_from_user_sym;

typedef asmlinkage ssize_t (*orig_process_madvise_t)(
    int pidfd, const struct iovec __user *vec, size_t vlen,
    int behavior, unsigned int flags);
orig_process_madvise_t orig_process_madvise;


/*
 * From kernel 5.0 onwards, the write protect bit of
 * cr0 cannot be changed using the normal write_cr0 function.
 * This custom function uses asm to directly access the register.
 * The "memory" clobber prevents reordering of the asm statement.
 */
static inline void custom_write_cr0(unsigned long val)
{
    asm volatile("mov %0,%%cr0": "+r" (val) : : "memory");
}

void write_protect_wrapper(void (*wrapped_worker)(void))
{
    unsigned long cr0;

    /* disable write protection */
    cr0 = read_cr0();
    custom_write_cr0(cr0 & ~WP_MASK);

    /* execute callback */
    wrapped_worker();

    /* re-enable write protection */
    custom_write_cr0(cr0);
}

void create_hook(void)
{
    orig_process_madvise = (orig_process_madvise_t) sys_call_table[__NR_process_madvise];
    sys_call_table[__NR_process_madvise] = (unsigned long) hooked_process_madvise;
}

void remove_hook(void)
{
    sys_call_table[__NR_process_madvise] = (unsigned long) orig_process_madvise;
}

int init_module(void)
{
    kallsyms_lookup_name_t kallsyms_lookup_name;

    pr_info("syscall-hook: module loaded");

    /*
     * From kernel 5.7.0 onwards, kallsyms_lookup_name
     * is no longer exported by default. This workaround
     * uses kprobes to find the address of the function.
    */
    register_kprobe(&kp);
    kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
    unregister_kprobe(&kp);

    sys_call_table = (unsigned long*) kallsyms_lookup_name("sys_call_table");
    if (!sys_call_table) {
        pr_err("syscall-hook: cannot find the sys_call_table address");
        return -1;
    } else {
        pr_info("syscall-hook: found sys_call_table at 0x%lx", (unsigned long) sys_call_table);
    }

    /* lookup required symbols/functions */
    mm_access_sym = (void*)kallsyms_lookup_name("mm_access");
    if (!mm_access_sym)
        return -1;
    zap_page_range_sym = (void*)kallsyms_lookup_name("zap_page_range");
    if (!zap_page_range_sym)
        return -1;
    soft_offline_page_sym = (void*)kallsyms_lookup_name("soft_offline_page");
    if (!soft_offline_page_sym)
        return -1;
    find_vma_prev_sym = (void*)kallsyms_lookup_name("find_vma_prev");
    if (!find_vma_prev_sym)
        return -1;
    pidfd_get_task_sym = (void*)kallsyms_lookup_name("pidfd_get_task");
    if (!pidfd_get_task_sym)
        return -1;
    iovec_from_user_sym = (void*)kallsyms_lookup_name("iovec_from_user");
    if (!iovec_from_user_sym)
        return -1;

    /* hook and replace the syscall */
    write_protect_wrapper(&create_hook);

    return 0;
}

void cleanup_module(void)
{
    /* restore the original syscall */
    write_protect_wrapper(&remove_hook);

    pr_info("syscall-hook: module unloaded");
}
