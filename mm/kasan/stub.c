/* SPDX-License-Identifier: GPL-2.0 */
/*
 * KASAN runtime stub: disables KASAN/KHWASAN runtime while keeping required symbols.
 * Auto-generated patch: build only this file from this directory.
 */

#include <linux/types.h>
#include <linux/cache.h>
#include <linux/init.h>
#include <linux/stackdepot.h>
#include <linux/export.h>
#include <linux/jump_label.h>
#include <linux/string.h>
#include <linux/bug.h>

/* Forward declarations to avoid pulling heavy headers. */
struct page;
struct kmem_cache;
struct vm_struct;
struct task_struct;
struct mem_cgroup;
struct slab;
struct kasan_track;

/* Exported flags (used by some KASAN HW tags code paths). */
DEFINE_STATIC_KEY_FALSE(kasan_flag_enabled);
EXPORT_SYMBOL(kasan_flag_enabled);

bool kasan_flag_async __ro_after_init;
EXPORT_SYMBOL_GPL(kasan_flag_async);

/* Generic no-op helpers */
#define KASAN_STUB_BODY_VOID do { } while (0)


void __kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
			  slab_flags_t *flags)
{
	KASAN_STUB_BODY_VOID;
}


void __kasan_cache_create_kmalloc(struct kmem_cache *cache)
{
	KASAN_STUB_BODY_VOID;
}


bool __kasan_check_byte(const void *address, unsigned long ip)
{
	return false;
}



void * __must_check __kasan_init_slab_obj(struct kmem_cache *cache,
						const void *object)
{
	return NULL;
}


void __kasan_kfree_large(void *ptr, unsigned long ip)
{
	KASAN_STUB_BODY_VOID;
}


void * __must_check __kasan_kmalloc(struct kmem_cache *cache, const void *object,
					size_t size, gfp_t flags)
{
	return NULL;
}


void * __must_check __kasan_kmalloc_large(const void *ptr, size_t size,
						gfp_t flags)
{
	return NULL;
}


void * __must_check __kasan_krealloc(const void *object, size_t size, gfp_t flags)
{
	return NULL;
}


size_t __kasan_metadata_size(struct kmem_cache *cache)
{
	return 0;
}

slab_flags_t __kasan_never_merge(void)
{
	return 0;
}


void __kasan_poison_object_data(struct kmem_cache *cache, void *object)
{
	KASAN_STUB_BODY_VOID;
}


void __kasan_poison_pages(struct page *page, unsigned int order, bool init)
{
	KASAN_STUB_BODY_VOID;
}


void __kasan_poison_slab(struct page *page)
{
	KASAN_STUB_BODY_VOID;
}


void * __must_check __kasan_slab_alloc(struct kmem_cache *cache,
					void *object, gfp_t flags, bool init)
{
	return NULL;
}


bool __kasan_slab_free(struct kmem_cache *cache, void *object,
				unsigned long ip, bool init)
{
	return false;
}


void __kasan_slab_free_mempool(void *ptr, unsigned long ip)
{
	KASAN_STUB_BODY_VOID;
}


void __kasan_unpoison_object_data(struct kmem_cache *cache, void *object)
{
	KASAN_STUB_BODY_VOID;
}


void __kasan_unpoison_pages(struct page *page, unsigned int order, bool init)
{
	KASAN_STUB_BODY_VOID;
}


void __kasan_unpoison_range(const void *address, size_t size)
{
	KASAN_STUB_BODY_VOID;
}


int kasan_add_zero_shadow(void *start, unsigned long size)
{
	return 0;
}


void kasan_alloc_pages(struct page *page, unsigned int order, gfp_t flags)
{
	KASAN_STUB_BODY_VOID;
}


bool kasan_byte_accessible(const void *addr)
{
	return false;
}


void kasan_cache_shrink(struct kmem_cache *cache)
{
	KASAN_STUB_BODY_VOID;
}


void kasan_cache_shutdown(struct kmem_cache *cache)
{
	KASAN_STUB_BODY_VOID;
}


bool kasan_check_range(unsigned long addr, size_t size, bool write,
					unsigned long ret_ip)
{
	return false;
}


void kasan_disable_current(void)
{
	KASAN_STUB_BODY_VOID;
}

void kasan_enable_current(void)
{
	KASAN_STUB_BODY_VOID;
}


void kasan_free_pages(struct page *page, unsigned int order)
{
	KASAN_STUB_BODY_VOID;
}


void kasan_free_shadow(const struct vm_struct *vm)
{
	KASAN_STUB_BODY_VOID;
}

void __init kasan_init_hw_tags(void)
{
	KASAN_STUB_BODY_VOID;
}

void kasan_init_hw_tags_cpu(void)
{
	KASAN_STUB_BODY_VOID;
}


void __init kasan_init_sw_tags(void)
{
	KASAN_STUB_BODY_VOID;
}


void kasan_metadata_fetch_row(char *buffer, void *row)
{
	KASAN_STUB_BODY_VOID;
}


int kasan_module_alloc(void *addr, size_t size)
{
	return 0;
}

void kasan_non_canonical_hook(unsigned long addr)
{
	KASAN_STUB_BODY_VOID;
}


void kasan_poison(const void *addr, size_t size, u8 value, bool init)
{
	KASAN_STUB_BODY_VOID;
}

void kasan_poison_last_granule(const void *addr, size_t size)
{
	KASAN_STUB_BODY_VOID;
}

void kasan_poison_vmalloc(const void *start, unsigned long size)
{
	KASAN_STUB_BODY_VOID;
}

int __ref kasan_populate_early_shadow(const void *shadow_start,
					const void *shadow_end)
{
	return 0;
}


int kasan_populate_vmalloc(unsigned long addr, unsigned long size)
{
	return 0;
}


void kasan_print_address_stack_frame(const void *addr)
{
	KASAN_STUB_BODY_VOID;
}


void kasan_print_tags(u8 addr_tag, const void *addr)
{
	KASAN_STUB_BODY_VOID;
}


bool kasan_quarantine_put(struct kmem_cache *cache, void *object)
{
	return false;
}


void kasan_quarantine_reduce(void)
{
	KASAN_STUB_BODY_VOID;
}

void kasan_quarantine_remove_cache(struct kmem_cache *cache)
{
	KASAN_STUB_BODY_VOID;
}

u8 kasan_random_tag(void)
{
	return 0;
}


void kasan_record_aux_stack(void *addr)
{
	KASAN_STUB_BODY_VOID;
}

void kasan_release_vmalloc(unsigned long start, unsigned long end,
			   unsigned long free_region_start,
			   unsigned long free_region_end)
{
	KASAN_STUB_BODY_VOID;
}


void kasan_remove_zero_shadow(void *start, unsigned long size)
{
	KASAN_STUB_BODY_VOID;
}


bool kasan_report(unsigned long addr, size_t size, bool is_write,
			unsigned long ip)
{
	return false;
}

void kasan_report_async(void)
{
	KASAN_STUB_BODY_VOID;
}


void kasan_report_invalid_free(void *object, unsigned long ip)
{
	KASAN_STUB_BODY_VOID;
}


void kasan_restore_multi_shot(bool enabled)
{
	KASAN_STUB_BODY_VOID;
}


bool kasan_save_enable_multi_shot(void)
{
	return false;
}


depot_stack_handle_t kasan_save_stack(gfp_t flags)
{
	return 0;
}


void kasan_set_free_info(struct kmem_cache *cache,
				void *object, u8 tag)
{
	KASAN_STUB_BODY_VOID;
}


void kasan_set_track(struct kasan_track *track, gfp_t flags)
{
	KASAN_STUB_BODY_VOID;
}


void kasan_unpoison(const void *addr, size_t size, bool init)
{
	KASAN_STUB_BODY_VOID;
}

void kasan_unpoison_task_stack(struct task_struct *task)
{
	KASAN_STUB_BODY_VOID;
}

asmlinkage void kasan_unpoison_task_stack_below(const void *watermark)
{
	KASAN_STUB_BODY_VOID;
}


void kasan_unpoison_vmalloc(const void *start, unsigned long size)
{
	KASAN_STUB_BODY_VOID;
}

/* Optional exported helpers (present under some configs). */
void kasan_set_tagging_report_once(bool state) { (void)state; }
EXPORT_SYMBOL_GPL(kasan_set_tagging_report_once);
void kasan_enable_tagging_sync(void) { }
EXPORT_SYMBOL_GPL(kasan_enable_tagging_sync);
void kasan_force_async_fault(void) { }
EXPORT_SYMBOL_GPL(kasan_force_async_fault);

/*
 * Compiler-inserted ASan/HWASan entrypoints when KASAN is enabled.
 * In stub mode we don't check/report anything.
 */
void __asan_register_globals(void *globals, size_t size) { (void)globals; (void)size; }
EXPORT_SYMBOL(__asan_register_globals);
void __asan_unregister_globals(void *globals, size_t size) { (void)globals; (void)size; }
EXPORT_SYMBOL(__asan_unregister_globals);

void __asan_load1(unsigned long addr) { (void)addr; }
EXPORT_SYMBOL(__asan_load1);
void __asan_load1_noabort(unsigned long addr) { (void)addr; }
EXPORT_SYMBOL(__asan_load1_noabort);
void __asan_store1(unsigned long addr) { (void)addr; }
EXPORT_SYMBOL(__asan_store1);
void __asan_store1_noabort(unsigned long addr) { (void)addr; }
EXPORT_SYMBOL(__asan_store1_noabort);

void __asan_load2(unsigned long addr) { (void)addr; }
EXPORT_SYMBOL(__asan_load2);
void __asan_load2_noabort(unsigned long addr) { (void)addr; }
EXPORT_SYMBOL(__asan_load2_noabort);
void __asan_store2(unsigned long addr) { (void)addr; }
EXPORT_SYMBOL(__asan_store2);
void __asan_store2_noabort(unsigned long addr) { (void)addr; }
EXPORT_SYMBOL(__asan_store2_noabort);

void __asan_load4(unsigned long addr) { (void)addr; }
EXPORT_SYMBOL(__asan_load4);
void __asan_load4_noabort(unsigned long addr) { (void)addr; }
EXPORT_SYMBOL(__asan_load4_noabort);
void __asan_store4(unsigned long addr) { (void)addr; }
EXPORT_SYMBOL(__asan_store4);
void __asan_store4_noabort(unsigned long addr) { (void)addr; }
EXPORT_SYMBOL(__asan_store4_noabort);

void __asan_load8(unsigned long addr) { (void)addr; }
EXPORT_SYMBOL(__asan_load8);
void __asan_load8_noabort(unsigned long addr) { (void)addr; }
EXPORT_SYMBOL(__asan_load8_noabort);
void __asan_store8(unsigned long addr) { (void)addr; }
EXPORT_SYMBOL(__asan_store8);
void __asan_store8_noabort(unsigned long addr) { (void)addr; }
EXPORT_SYMBOL(__asan_store8_noabort);

void __asan_load16(unsigned long addr) { (void)addr; }
EXPORT_SYMBOL(__asan_load16);
void __asan_load16_noabort(unsigned long addr) { (void)addr; }
EXPORT_SYMBOL(__asan_load16_noabort);
void __asan_store16(unsigned long addr) { (void)addr; }
EXPORT_SYMBOL(__asan_store16);
void __asan_store16_noabort(unsigned long addr) { (void)addr; }
EXPORT_SYMBOL(__asan_store16_noabort);

void __asan_loadN(unsigned long addr, size_t size) { (void)addr; (void)size; }
EXPORT_SYMBOL(__asan_loadN);
void __asan_loadN_noabort(unsigned long addr, size_t size) { (void)addr; (void)size; }
EXPORT_SYMBOL(__asan_loadN_noabort);
void __asan_storeN(unsigned long addr, size_t size) { (void)addr; (void)size; }
EXPORT_SYMBOL(__asan_storeN);
void __asan_storeN_noabort(unsigned long addr, size_t size) { (void)addr; (void)size; }
EXPORT_SYMBOL(__asan_storeN_noabort);

void __asan_handle_no_return(void) { }
EXPORT_SYMBOL(__asan_handle_no_return);
void __asan_alloca_poison(const void *addr, size_t size) { (void)addr; (void)size; }
EXPORT_SYMBOL(__asan_alloca_poison);
void __asan_allocas_unpoison(const void *top, const void *bottom) { (void)top; (void)bottom; }
EXPORT_SYMBOL(__asan_allocas_unpoison);

void __asan_set_shadow_00(const void *addr, size_t size) { (void)addr; (void)size; }
EXPORT_SYMBOL(__asan_set_shadow_00);
void __asan_set_shadow_f1(const void *addr, size_t size) { (void)addr; (void)size; }
EXPORT_SYMBOL(__asan_set_shadow_f1);
void __asan_set_shadow_f2(const void *addr, size_t size) { (void)addr; (void)size; }
EXPORT_SYMBOL(__asan_set_shadow_f2);
void __asan_set_shadow_f3(const void *addr, size_t size) { (void)addr; (void)size; }
EXPORT_SYMBOL(__asan_set_shadow_f3);
void __asan_set_shadow_f5(const void *addr, size_t size) { (void)addr; (void)size; }
EXPORT_SYMBOL(__asan_set_shadow_f5);
void __asan_set_shadow_f8(const void *addr, size_t size) { (void)addr; (void)size; }
EXPORT_SYMBOL(__asan_set_shadow_f8);

void __asan_report_load1_noabort(unsigned long addr) { (void)addr; }
EXPORT_SYMBOL(__asan_report_load1_noabort);
void __asan_report_store1_noabort(unsigned long addr) { (void)addr; }
EXPORT_SYMBOL(__asan_report_store1_noabort);

void __asan_report_load2_noabort(unsigned long addr) { (void)addr; }
EXPORT_SYMBOL(__asan_report_load2_noabort);
void __asan_report_store2_noabort(unsigned long addr) { (void)addr; }
EXPORT_SYMBOL(__asan_report_store2_noabort);

void __asan_report_load4_noabort(unsigned long addr) { (void)addr; }
EXPORT_SYMBOL(__asan_report_load4_noabort);
void __asan_report_store4_noabort(unsigned long addr) { (void)addr; }
EXPORT_SYMBOL(__asan_report_store4_noabort);

void __asan_report_load8_noabort(unsigned long addr) { (void)addr; }
EXPORT_SYMBOL(__asan_report_load8_noabort);
void __asan_report_store8_noabort(unsigned long addr) { (void)addr; }
EXPORT_SYMBOL(__asan_report_store8_noabort);

void __asan_report_load16_noabort(unsigned long addr) { (void)addr; }
EXPORT_SYMBOL(__asan_report_load16_noabort);
void __asan_report_store16_noabort(unsigned long addr) { (void)addr; }
EXPORT_SYMBOL(__asan_report_store16_noabort);

void __asan_report_load_n_noabort(unsigned long addr, size_t size) { (void)addr; (void)size; }
EXPORT_SYMBOL(__asan_report_load_n_noabort);
void __asan_report_store_n_noabort(unsigned long addr, size_t size) { (void)addr; (void)size; }
EXPORT_SYMBOL(__asan_report_store_n_noabort);

void __hwasan_load1_noabort(unsigned long addr) { (void)addr; }
EXPORT_SYMBOL(__hwasan_load1_noabort);
void __hwasan_store1_noabort(unsigned long addr) { (void)addr; }
EXPORT_SYMBOL(__hwasan_store1_noabort);

void __hwasan_load2_noabort(unsigned long addr) { (void)addr; }
EXPORT_SYMBOL(__hwasan_load2_noabort);
void __hwasan_store2_noabort(unsigned long addr) { (void)addr; }
EXPORT_SYMBOL(__hwasan_store2_noabort);

void __hwasan_load4_noabort(unsigned long addr) { (void)addr; }
EXPORT_SYMBOL(__hwasan_load4_noabort);
void __hwasan_store4_noabort(unsigned long addr) { (void)addr; }
EXPORT_SYMBOL(__hwasan_store4_noabort);

void __hwasan_load8_noabort(unsigned long addr) { (void)addr; }
EXPORT_SYMBOL(__hwasan_load8_noabort);
void __hwasan_store8_noabort(unsigned long addr) { (void)addr; }
EXPORT_SYMBOL(__hwasan_store8_noabort);

void __hwasan_load16_noabort(unsigned long addr) { (void)addr; }
EXPORT_SYMBOL(__hwasan_load16_noabort);
void __hwasan_store16_noabort(unsigned long addr) { (void)addr; }
EXPORT_SYMBOL(__hwasan_store16_noabort);

void __hwasan_loadN_noabort(unsigned long addr, unsigned long size) { (void)addr; (void)size; }
EXPORT_SYMBOL(__hwasan_loadN_noabort);
void __hwasan_storeN_noabort(unsigned long addr, unsigned long size) { (void)addr; (void)size; }
EXPORT_SYMBOL(__hwasan_storeN_noabort);
void __hwasan_tag_memory(unsigned long addr, u8 tag, unsigned long size) { (void)addr; (void)tag; (void)size; }
EXPORT_SYMBOL(__hwasan_tag_memory);
