#pragma once

#include <linux/ptrace.h>
#include <linux/mman.h>
#include <linux/blkdev.h>
#include <linux/mmu_notifier.h>



#define MMU_GATHER_BUNDLE   8
struct mmu_gather_batch {
    struct mmu_gather_batch     *next;
    unsigned int        nr;
    unsigned int        max;
    struct page         *pages[0];
};

struct mmu_gather {
    struct mm_struct    *mm;

#ifdef CONFIG_MMU_GATHER_TABLE_FREE
    struct mmu_table_batch  *batch;
#endif

    unsigned long       start;
    unsigned long       end;
    /*
     * we are in the middle of an operation to clear
     * a full mm and can make some optimizations
     */
    unsigned int        fullmm : 1;

    /*
     * we have performed an operation which
     * requires a complete flush of the tlb
     */
    unsigned int        need_flush_all : 1;

    /*
     * we have removed page directories
     */
    unsigned int        freed_tables : 1;

    /*
     * at which levels have we cleared entries?
     */
    unsigned int        cleared_ptes : 1;
    unsigned int        cleared_pmds : 1;
    unsigned int        cleared_puds : 1;
    unsigned int        cleared_p4ds : 1;

    /*
     * tracks VM_EXEC | VM_HUGETLB in tlb_start_vma
     */
    unsigned int        vma_exec : 1;
    unsigned int        vma_huge : 1;

    unsigned int        batch_count;

#ifndef CONFIG_MMU_GATHER_NO_GATHER
    struct mmu_gather_batch *active;
    struct mmu_gather_batch     local;
    struct page         *__pages[MMU_GATHER_BUNDLE];

#ifdef CONFIG_MMU_GATHER_PAGE_SIZE
    unsigned int page_size;
#endif
#endif
};


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

typedef void (*lru_add_drain_t)(void);
extern lru_add_drain_t lru_add_drain_sym;

typedef void (*tlb_finish_mmu_t)(struct mmu_gather *tlb);
extern tlb_finish_mmu_t tlb_finish_mmu_sym;

typedef int (*__mmu_notifier_invalidate_range_start_t)(struct mmu_notifier_range *range);
extern __mmu_notifier_invalidate_range_start_t __mmu_notifier_invalidate_range_start_sym;

typedef void (*__mmu_notifier_invalidate_range_end_t)(struct mmu_notifier_range *range, bool only_end);
extern __mmu_notifier_invalidate_range_end_t __mmu_notifier_invalidate_range_end_sym;

typedef void (*tlb_gather_mmu_t)(struct mmu_gather *tlb, struct mm_struct *mm);
extern tlb_gather_mmu_t tlb_gather_mmu_sym;

typedef void (*unmap_single_vma_t)(struct mmu_gather *tlb, struct vm_area_struct *vma, unsigned long start_addr, unsigned long end_addr, struct zap_details *details);
extern unmap_single_vma_t unmap_single_vma_sym;

static inline bool can_madv_lru_vma(struct vm_area_struct *vma)
{
    return !(vma->vm_flags & (VM_LOCKED|VM_HUGETLB|VM_PFNMAP));
}

/* ================================ END needed symbols/functions ================================ */

asmlinkage ssize_t hooked_process_madvise(struct pt_regs *regs);
