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
				   unsigned long end, unsigned long arg))
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
		error = visit(vma, &prev, start, tmp, arg);
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

static long custom_madvise_dontneed_single_vma(struct vm_area_struct *vma,
					unsigned long start, unsigned long end)
{
	zap_page_range_sym(vma, start, end - start);
	return 0;
}

static long custom_madvise_dontneed_free(struct vm_area_struct *vma,
				  struct vm_area_struct **prev,
				  unsigned long start, unsigned long end,
				  int behavior)
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
		return custom_madvise_dontneed_single_vma(vma, start, end);
	/* else if (behavior == MADV_FREE) */
	/* 	return madvise_free_single_vma(vma, start, end); */
	else
		return -EINVAL;
}

/* NOTE hack, ignores every behavior except MADV_DONTNEED */
static int custom_madvise_vma_behavior(struct vm_area_struct *vma,
				struct vm_area_struct **prev,
				unsigned long start, unsigned long end,
				unsigned long behavior)
{

	if (behavior == MADV_DONTNEED)
		return custom_madvise_dontneed_free(vma, prev, start, end, behavior);
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

int hooked_do_madvise(struct mm_struct *mm, unsigned long start, size_t len_in, int behavior)
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
			custom_madvise_vma_behavior);
	blk_finish_plug(&plug);
	if (write)
		mmap_write_unlock(mm);
	else
		mmap_read_unlock(mm);

	return error;
}


static int custom_copy_iovec_from_user(struct iovec *iov,
		const struct iovec __user *uvec, unsigned long nr_segs)
{
	unsigned long seg;

	pr_info("in copy_iovec");
	if (copy_from_user(iov, uvec, nr_segs * sizeof(*uvec)))
		return -EFAULT;
	for (seg = 0; seg < nr_segs; seg++) {
		if ((ssize_t)iov[seg].iov_len < 0)
			return -EINVAL;
	}

	return 0;
}
struct iovec *custom_iovec_from_user(const struct iovec __user *uvec,
		unsigned long nr_segs, unsigned long fast_segs,
		struct iovec *fast_iov, bool compat)
{
	struct iovec *iov = fast_iov;
	int ret;

	/*
	 * SuS says "The readv() function *may* fail if the iovcnt argument was
	 * less than or equal to 0, or greater than {IOV_MAX}.  Linux has
	 * traditionally returned zero for zero segments, so...
	 */
	pr_info("iovec_from_user: nr_segs = %lu", nr_segs);
	if (nr_segs == 0)
		return iov;
	if (nr_segs > UIO_MAXIOV)
		return ERR_PTR(-EINVAL);
	if (nr_segs > fast_segs) {
		iov = kmalloc_array(nr_segs, sizeof(struct iovec), GFP_KERNEL);
		if (!iov)
			return ERR_PTR(-ENOMEM);
	}

	/* if (compat) */
	/* 	ret = copy_compat_iovec_from_user(iov, uvec, nr_segs); */
	/* else */
	ret = custom_copy_iovec_from_user(iov, uvec, nr_segs);
	if (ret) {
		if (iov != fast_iov)
			kfree(iov);
		return ERR_PTR(ret);
	}

	return iov;
}

ssize_t custom_import_iovec(int type, const struct iovec __user *uvec,
		 unsigned nr_segs, unsigned fast_segs, struct iovec **iovp,
		 struct iov_iter *i, bool compat)
{
	ssize_t total_len = 0;
	unsigned long seg;
	struct iovec *iov;

	iov = custom_iovec_from_user(uvec, nr_segs, fast_segs, *iovp, compat);
	if (IS_ERR(iov)) {
		*iovp = NULL;
		return PTR_ERR(iov);
	}

	/*
	 * According to the Single Unix Specification we should return EINVAL if
	 * an element length is < 0 when cast to ssize_t or if the total length
	 * would overflow the ssize_t return value of the system call.
	 *
	 * Linux caps all read/write calls to MAX_RW_COUNT, and avoids the
	 * overflow case.
	 */
	for (seg = 0; seg < nr_segs; seg++) {
		ssize_t len = (ssize_t)iov[seg].iov_len;

		if (!access_ok(iov[seg].iov_base, len)) {
			if (iov != *iovp)
				kfree(iov);
			*iovp = NULL;
			return -EFAULT;
		}

		if (len > MAX_RW_COUNT - total_len) {
			len = MAX_RW_COUNT - total_len;
			iov[seg].iov_len = len;
		}
		total_len += len;
	}

	iov_iter_init(i, type, iov, nr_segs, total_len);
	if (iov == *iovp)
		*iovp = NULL;
	else
		*iovp = iov;
	return total_len;
}


asmlinkage ssize_t hooked_process_madvise(int pidfd, const struct iovec __user *vec, size_t vlen,
										  int behavior, unsigned int flags) {

	ssize_t ret;
	struct iovec iovstack[UIO_FASTIOV], iovec;
	struct iovec *iov = iovstack;
	struct iov_iter iter;
	struct task_struct *task;
	struct mm_struct *mm;
	size_t total_len;
	unsigned int f_flags;

	if (flags != 0) {
		ret = -EINVAL;
		goto out;
	}
	pr_info("process_madvise: pidfd = %d, vec = %p, vlen = %lu, behavior = %d, flags = %u", pidfd, vec, vlen, behavior, flags);

	ret = custom_import_iovec(READ, vec, vlen, ARRAY_SIZE(iovstack), &iov, &iter, 0);
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

	while (iov_iter_count(&iter)) {
		iovec = iov_iter_iovec(&iter);
		ret = hooked_do_madvise(mm, (unsigned long)iovec.iov_base,
					iovec.iov_len, behavior);
		if (ret < 0)
			break;
		iov_iter_advance(&iter, iovec.iov_len);
	}

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
