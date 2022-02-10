#pragma once

/* #include <linux/module.h> */
/* #include <linux/kernel.h> */
#include <linux/ptrace.h>
#include <linux/mman.h>
/* #include <uapi/asm-generic/mman-common.h> */
/* #include <uapi/linux/uio.h> */
/* #include <linux/uio.h> */
#include <linux/blkdev.h>

/* ================================ START needed symbols/functions ================================ */
extern void mmput(struct mm_struct *mm);
extern void kfree(const void *x);
extern ssize_t import_iovec(int type, const struct iovec *uvec, unsigned int nr_segs, unsigned int fast_segs, struct iovec **iovp, struct iov_iter *i);

typedef struct mm_struct *(*mm_access_t)(struct task_struct *task, unsigned int mode);
extern mm_access_t mm_access_sym;

typedef void (*zap_page_range_t)(struct vm_area_struct *vma, unsigned long start, unsigned long size);
extern zap_page_range_t zap_page_range_sym;

typedef int (*soft_offline_page_t)(unsigned long pfn, int flags);
extern soft_offline_page_t soft_offline_page_sym;

typedef struct vm_area_struct * (*find_vma_prev_t)(struct mm_struct * mm, unsigned long addr, struct vm_area_struct **pprev);
extern find_vma_prev_t find_vma_prev_sym;

typedef struct task_struct *(*pidfd_get_task_t)(int pidfd, unsigned int *flags);
extern pidfd_get_task_t pidfd_get_task_sym;

typedef struct iovec *(*iovec_from_user_t)(const struct iovec __user *uvec,
        unsigned long nr_segs, unsigned long fast_segs,
        struct iovec *fast_iov, bool compat);
extern iovec_from_user_t iovec_from_user_sym;

static inline bool can_madv_lru_vma(struct vm_area_struct *vma)
{
    return !(vma->vm_flags & (VM_LOCKED|VM_HUGETLB|VM_PFNMAP));
}

/* ================================ END needed symbols/functions ================================ */

asmlinkage ssize_t hooked_process_madvise(int pidfd, const struct iovec __user *vec, size_t vlen,
                                          int behavior, unsigned int flags);
