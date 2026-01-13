/* SPDX-License-Identifier: GPL-2.0 */
/*
 * KFENCE stub (disabled runtime)
 *
 * This file provides a minimal set of KFENCE symbols so the kernel can link
 * when the real KFENCE runtime sources (core.c/report.c) are removed from the
 * build. All functionality is disabled.
 */

#include <linux/atomic.h>
#include <linux/export.h>
#include <linux/kfence.h>
#include <linux/mm.h>
#include <linux/slab.h>

#include "kfence.h"

/*
 * The real runtime allocates and fills this pool. The stub keeps it NULL.
 * Exported for external test modules in the original implementation.
 */
char *__kfence_pool;
EXPORT_SYMBOL(__kfence_pool);

/* Provide the metadata array expected by other code paths. */
struct kfence_metadata kfence_metadata[CONFIG_KFENCE_NUM_OBJECTS];

/* Allocation gate used by slab hooks; keep it open but unused. */
atomic_t kfence_allocation_gate = ATOMIC_INIT(1);

#ifdef CONFIG_KFENCE_STATIC_KEYS
#include <linux/jump_label.h>
DEFINE_STATIC_KEY_FALSE(kfence_allocation_key);
#endif

void __init kfence_alloc_pool(void)
{
	/* KFENCE disabled: no pool. */
}

void __init kfence_init(void)
{
	/* KFENCE disabled. */
}

void kfence_shutdown_cache(struct kmem_cache *s)
{
	(void)s;
}

void *__kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags)
{
	(void)s;
	(void)size;
	(void)flags;
	/* Returning NULL makes callers fall back to the normal allocator. */
	return NULL;
}

size_t kfence_ksize(const void *addr)
{
	(void)addr;
	return 0;
}

void *kfence_object_start(const void *addr)
{
	(void)addr;
	return NULL;
}

void __kfence_free(void *addr)
{
	(void)addr;
}

bool kfence_handle_page_fault(unsigned long addr, bool is_write, struct pt_regs *regs)
{
	(void)addr;
	(void)is_write;
	(void)regs;
	/* Not handled by KFENCE when disabled. */
	return false;
}

void kfence_print_object(struct seq_file *seq, const struct kfence_metadata *meta)
{
	(void)seq;
	(void)meta;
}

void kfence_report_error(unsigned long address, bool is_write, struct pt_regs *regs,
			 const struct kfence_metadata *meta, enum kfence_error_type type)
{
	(void)address;
	(void)is_write;
	(void)regs;
	(void)meta;
	(void)type;
}
