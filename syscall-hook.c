#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>

#ifdef pr_fmt
#undef pr_fmt
#endif
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

/* bit 16 (for the CR0 register) */
#define WP_MASK 0x10000

MODULE_LICENSE("GPL");


static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name"
};

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);

unsigned long* sys_call_table;

typedef asmlinkage long (*orig_read_t)(unsigned int fd, char *buf, size_t count);
orig_read_t orig_read;

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

asmlinkage long hooked_read(unsigned int fd, char *buf, size_t count)
{
    long ret = orig_read(fd, buf, count);
    pr_info("sys_read called\n");
    return ret;
}

void create_hook(void)
{
    orig_read = (orig_read_t) sys_call_table[__NR_read];
    sys_call_table[__NR_read] = (unsigned long) hooked_read;
}

void remove_hook(void)
{
    sys_call_table[__NR_read] = (unsigned long) orig_read;
}


int init_module(void)
{
    kallsyms_lookup_name_t kallsyms_lookup_name;

    pr_info("module loaded\n");

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
        pr_debug("cannot find the sys_call_table address\n");
        return -1;
    } else {
        pr_info("found sys_call_table at %lx\n", (unsigned long) sys_call_table);
    }

    /* hook and replace the syscall */
    write_protect_wrapper(&create_hook);

    return 0;
}

void cleanup_module(void)
{
    /* restore the original syscall */
    write_protect_wrapper(&remove_hook);

    pr_info("module unloaded\n");
}
