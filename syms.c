#include "syms.h"

/* ================================ START unmodified functions from madvise.c ================================ */

static bool
madvise_behavior_valid(int behavior)
{
	switch (behavior) {
	case MADV_DOFORK:
	case MADV_DONTFORK:
	case MADV_NORMAL:
	case MADV_SEQUENTIAL:
	case MADV_RANDOM:
	case MADV_REMOVE:
	case MADV_WILLNEED:
	case MADV_DONTNEED:
	case MADV_FREE:
	case MADV_COLD:
	case MADV_PAGEOUT:
	case MADV_POPULATE_READ:
	case MADV_POPULATE_WRITE:
#ifdef CONFIG_KSM
	case MADV_MERGEABLE:
	case MADV_UNMERGEABLE:
#endif
#ifdef CONFIG_TRANSPARENT_HUGEPAGE
	case MADV_HUGEPAGE:
	case MADV_NOHUGEPAGE:
#endif
	case MADV_DONTDUMP:
	case MADV_DODUMP:
	case MADV_WIPEONFORK:
	case MADV_KEEPONFORK:
#ifdef CONFIG_MEMORY_FAILURE
	case MADV_SOFT_OFFLINE:
	case MADV_HWPOISON:
#endif
		return true;

	default:
		return false;
	}
}

static int madvise_inject_error(int behavior,
		unsigned long start, unsigned long end)
{
	unsigned long size;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;


	for (; start < end; start += size) {
		unsigned long pfn;
		struct page *page;
		int ret;

		ret = get_user_pages_fast(start, 1, 0, &page);
		if (ret != 1)
			return ret;
		pfn = page_to_pfn(page);

		/*
		 * When soft offlining hugepages, after migrating the page
		 * we dissolve it, therefore in the second loop "page" will
		 * no longer be a compound page.
		 */
		size = page_size(compound_head(page));

		if (behavior == MADV_SOFT_OFFLINE) {
			pr_info("Soft offlining pfn %#lx at process virtual address %#lx\n",
				 pfn, start);
			ret = soft_offline_page_sym(pfn, MF_COUNT_INCREASED);
		} else {
			pr_info("Injecting memory failure for pfn %#lx at process virtual address %#lx\n",
				 pfn, start);
			ret = memory_failure(pfn, MF_COUNT_INCREASED);
		}

		if (ret)
			return ret;
	}

	return 0;
}

static int madvise_need_mmap_write(int behavior)
{
	switch (behavior) {
	case MADV_REMOVE:
	case MADV_WILLNEED:
	case MADV_DONTNEED:
	case MADV_COLD:
	case MADV_PAGEOUT:
	case MADV_FREE:
	case MADV_POPULATE_READ:
	case MADV_POPULATE_WRITE:
		return 0;
	default:
		/* be safe, default to 1. list exceptions explicitly */
		return 1;
	}
}

static
int madvise_walk_vmas(struct mm_struct *mm, unsigned long start,
			  unsigned long end, unsigned long arg,
			  int (*visit)(struct vm_area_struct *vma,
				   struct vm_area_struct **prev, unsigned long start,
				   unsigned long end, unsigned long arg, struct mmu_gather *tlb),
			  struct mmu_gather *tlb)
{
	struct vm_area_struct *vma;
	struct vm_area_struct *prev;
	unsigned long tmp;
	int unmapped_error = 0;

	/*
	 * If the interval [start,end) covers some unmapped address
	 * ranges, just ignore them, but return -ENOMEM at the end.
	 * - different from the way of handling in mlock etc.
	 */
	vma = find_vma_prev_sym(mm, start, &prev);
	if (vma && start > vma->vm_start)
		prev = vma;

	for (;;) {
		int error;

		/* Still start < end. */
		if (!vma)
			return -ENOMEM;

		/* Here start < (end|vma->vm_end). */
		if (start < vma->vm_start) {
			unmapped_error = -ENOMEM;
			start = vma->vm_start;
			if (start >= end)
				break;
		}

		/* Here vma->vm_start <= start < (end|vma->vm_end) */
		tmp = vma->vm_end;
		if (end < tmp)
			tmp = end;

		/* Here vma->vm_start <= start < tmp <= (end|vma->vm_end). */
		error = visit(vma, &prev, start, tmp, arg, tlb);
		if (error)
			return error;
		start = tmp;
		if (prev && start < prev->vm_end)
			start = prev->vm_end;
		if (start >= end)
			break;
		if (prev)
			vma = prev->vm_next;
		else	/* madvise_remove dropped mmap_lock */
			vma = find_vma(mm, start);
	}

	return unmapped_error;
}


/* ================================ END unmodified functions from madvise.c ================================ */

static inline void
custom_mmu_notifier_invalidate_range_start(struct mmu_notifier_range *range)
{
	might_sleep();

	lock_map_acquire(&__mmu_notifier_invalidate_range_start_map);
	if (mm_has_notifiers(range->mm)) {
		range->flags |= MMU_NOTIFIER_RANGE_BLOCKABLE;
		__mmu_notifier_invalidate_range_start_sym(range);
	}
	lock_map_release(&__mmu_notifier_invalidate_range_start_map);
}

static inline void
custom_mmu_notifier_invalidate_range_end(struct mmu_notifier_range *range)
{
	if (mmu_notifier_range_blockable(range))
		might_sleep();

	if (mm_has_notifiers(range->mm))
		__mmu_notifier_invalidate_range_end_sym(range, false);
}

void zap_page_range_noflush(struct vm_area_struct *vma, unsigned long start,
		unsigned long size, struct mmu_gather* tlb)
{
	struct mmu_notifier_range range;

	if (!tlb)
		return;

	lru_add_drain_sym();
	mmu_notifier_range_init(&range, MMU_NOTIFY_CLEAR, 0, vma, vma->vm_mm,
				start, start + size);
	update_hiwater_rss(vma->vm_mm);
	custom_mmu_notifier_invalidate_range_start(&range);
	for ( ; vma && vma->vm_start < range.end; vma = vma->vm_next)
		unmap_single_vma_sym(tlb, vma, start, range.end, NULL);
	custom_mmu_notifier_invalidate_range_end(&range);
}

static long custom_madvise_dontneed_single_vma(struct vm_area_struct *vma,
					unsigned long start, unsigned long end, struct mmu_gather *tlb)
{
	if (tlb)
		zap_page_range_noflush(vma, start, end - start, tlb);
	else
		zap_page_range_sym(vma, start, end - start);
	return 0;
}

static long custom_madvise_dontneed_free(struct vm_area_struct *vma,
				  struct vm_area_struct **prev,
				  unsigned long start, unsigned long end,
				  int behavior, struct mmu_gather *tlb)
{
	/* struct mm_struct *mm = vma->vm_mm; */

	*prev = vma;
	if (!can_madv_lru_vma(vma))
		return -EINVAL;

	/* NOTE: hack */
	/* if (!userfaultfd_remove(vma, start, end)) { */
	/* 	*prev = NULL; /\* mmap_lock has been dropped, prev is stale *\/ */

	/* 	mmap_read_lock(mm); */
	/* 	vma = find_vma(mm, start); */
	/* 	if (!vma) */
	/* 		return -ENOMEM; */
	/* 	if (start < vma->vm_start) { */
	/* 		/\* */
	/* 		 * This "vma" under revalidation is the one */
	/* 		 * with the lowest vma->vm_start where start */
	/* 		 * is also < vma->vm_end. If start < */
	/* 		 * vma->vm_start it means an hole materialized */
	/* 		 * in the user address space within the */
	/* 		 * virtual range passed to MADV_DONTNEED */
	/* 		 * or MADV_FREE. */
	/* 		 *\/ */
	/* 		return -ENOMEM; */
	/* 	} */
	/* 	if (!can_madv_lru_vma(vma)) */
	/* 		return -EINVAL; */
	/* 	if (end > vma->vm_end) { */
	/* 		/\* */
	/* 		 * Don't fail if end > vma->vm_end. If the old */
	/* 		 * vma was split while the mmap_lock was */
	/* 		 * released the effect of the concurrent */
	/* 		 * operation may not cause madvise() to */
	/* 		 * have an undefined result. There may be an */
	/* 		 * adjacent next vma that we'll walk */
	/* 		 * next. userfaultfd_remove() will generate an */
	/* 		 * UFFD_EVENT_REMOVE repetition on the */
	/* 		 * end-vma->vm_end range, but the manager can */
	/* 		 * handle a repetition fine. */
	/* 		 *\/ */
	/* 		end = vma->vm_end; */
	/* 	} */
	/* 	VM_WARN_ON(start >= end); */
	/* } */

	if (behavior == MADV_DONTNEED)
		return custom_madvise_dontneed_single_vma(vma, start, end, tlb);
	/* else if (behavior == MADV_FREE) */
	/* 	return madvise_free_single_vma(vma, start, end); */
	else
		return -EINVAL;
}

/* NOTE hack, ignores every behavior except MADV_DONTNEED */
static int custom_madvise_vma_behavior(struct vm_area_struct *vma,
				struct vm_area_struct **prev,
				unsigned long start, unsigned long end,
				unsigned long behavior,
				struct mmu_gather *tlb)
{

	if (behavior == MADV_DONTNEED)
		return custom_madvise_dontneed_free(vma, prev, start, end, behavior, tlb);
	else
		return -EINVAL;
}


static bool
custom_process_madvise_behavior_valid(int behavior)
{
	switch (behavior) {
	case MADV_DONTNEED:
	case MADV_COLD:
	case MADV_PAGEOUT:
	case MADV_WILLNEED:
		return true;
	default:
		return false;
	}
}

int custom_do_madvise(struct mm_struct *mm, unsigned long start, size_t len_in, int behavior, struct mmu_gather *tlb)
{
	unsigned long end;
	int error;
	int write;
	size_t len;
	struct blk_plug plug;

	start = untagged_addr(start);

	if (!madvise_behavior_valid(behavior))
		return -EINVAL;

	if (!PAGE_ALIGNED(start))
		return -EINVAL;
	len = PAGE_ALIGN(len_in);

	/* Check to see whether len was rounded up from small -ve to zero */
	if (len_in && !len)
		return -EINVAL;

	end = start + len;
	if (end < start)
		return -EINVAL;

	if (end == start)
		return 0;

#ifdef CONFIG_MEMORY_FAILURE
	if (behavior == MADV_HWPOISON || behavior == MADV_SOFT_OFFLINE)
		return madvise_inject_error(behavior, start, start + len_in);
#endif

	write = madvise_need_mmap_write(behavior);
	if (write) {
		if (mmap_write_lock_killable(mm))
			return -EINTR;
	} else {
		mmap_read_lock(mm);
	}

	blk_start_plug(&plug);
	error = madvise_walk_vmas(mm, start, end, behavior,
			custom_madvise_vma_behavior, tlb);
	blk_finish_plug(&plug);
	if (write)
		mmap_write_unlock(mm);
	else
		mmap_read_unlock(mm);

	return error;
}


asmlinkage ssize_t hooked_process_madvise(struct pt_regs *regs)
{
	ssize_t ret;
	struct iovec iovstack[UIO_FASTIOV], iovec;
	struct iovec *iov = iovstack;
	struct iov_iter iter;
	struct task_struct *task;
	struct mm_struct *mm;
	size_t total_len;
	unsigned int f_flags;

	int pidfd = regs->di;
	const struct iovec __user *vec = (const struct iovec __user *)regs->si;
	size_t vlen = regs->dx;
	int behavior = regs->r10;
	unsigned int flags = regs->r8;

	struct mmu_gather tlb;

	if (flags != 0) {
		ret = -EINVAL;
		goto out;
	}

	ret = import_iovec(READ, vec, vlen, ARRAY_SIZE(iovstack), &iov, &iter);
	if (ret < 0)
		goto out;

	task = pidfd_get_task_sym(pidfd, &f_flags);
	if (IS_ERR(task)) {
		ret = PTR_ERR(task);
		goto free_iov;
	}

	if (!custom_process_madvise_behavior_valid(behavior)) {
		ret = -EINVAL;
		goto release_task;
	}

	/* Require PTRACE_MODE_READ to avoid leaking ASLR metadata. */
	mm = mm_access_sym(task, PTRACE_MODE_READ_FSCREDS);
	if (IS_ERR_OR_NULL(mm)) {
		ret = IS_ERR(mm) ? PTR_ERR(mm) : -ESRCH;
		goto release_task;
	}

	/*
	 * Require CAP_SYS_NICE for influencing process performance. Note that
	 * only non-destructive hints are currently supported.
	 */
	if (!capable(CAP_SYS_NICE)) {
		ret = -EPERM;
		goto release_mm;
	}

	total_len = iov_iter_count(&iter);

	if (behavior == MADV_DONTNEED)
		tlb_gather_mmu_sym(&tlb, mm);

	while (iov_iter_count(&iter)) {
		iovec = iov_iter_iovec(&iter);
		ret = custom_do_madvise(mm, (unsigned long)iovec.iov_base,
					iovec.iov_len, behavior, &tlb);
		if (ret < 0)
			break;
		iov_iter_advance(&iter, iovec.iov_len);
	}

	if (behavior == MADV_DONTNEED)
		tlb_finish_mmu_sym(&tlb);

	if (ret == 0)
		ret = total_len - iov_iter_count(&iter);

release_mm:
	mmput(mm);
release_task:
	put_task_struct(task);
free_iov:
	kfree(iov);
out:
	return ret;
}
