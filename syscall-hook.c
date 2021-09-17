#include <linux/module.h>
#include <linux/kernel.h>

#ifdef pr_fmt
#undef pr_fmt
#endif
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

MODULE_LICENSE("GPL");


int init_module(void) {
    pr_info("module loaded\n");
    return 0;
}

void cleanup_module(void) {
    pr_info("module unloaded\n");
}
