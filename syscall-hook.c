#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>

#ifdef pr_fmt
#undef pr_fmt
#endif
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

MODULE_LICENSE("GPL");


static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name"
};

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);

unsigned long sys_call_table;


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

    sys_call_table = kallsyms_lookup_name("sys_call_table");
    if (!sys_call_table) {
        pr_debug("cannot find the sys_call_table address\n");
        return -1;
    } else {
        pr_info("found sys_call_table at %lx\n", sys_call_table);
    }
    return 0;
}

void cleanup_module(void)
{
    pr_info("module unloaded\n");
}
