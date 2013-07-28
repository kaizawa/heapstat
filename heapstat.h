#ifndef _NHEAPSOLARIS_H
#define _NHEAPSOLARIS_H
void print_usage(char *);
size_t get_free_size ();
size_t get_lfree_size ();
size_t get_flist_free_size();
size_t get_small_free_size();
size_t get_bottom_size();
void find_heap();
offset_t get_diff_by_vaddr(uintptr_t);
offset_t get_diff_by_offset(offset_t);
offset_t get_core_offset_by_vaddr(uintptr_t);
offset_t get_core_offset_by_symname(char *);
uintptr_t get_core_mapaddr_by_symname(char *);
uintptr_t get_vaddr_by_core_offset(offset_t);
uintptr_t get_core_mapped_addr_by_vaddr(uintptr_t);
uintptr_t get_vaddr_by_symbol(char *);
int count_free(TREE *);
void report_heap_usage();
uintptr_t get_value_by_symbol(char *);
char *print_unit(size_t, char *);

#if defined(_LP64)
typedef Elf64_Ehdr Ehdr;
#else
typedef Elf32_Ehdr Ehdr;
#endif

#define	FREESIZE (1<<5) /* size for preserving free blocks until next malloc */
#define	FREEMASK FREESIZE-1
#define SIZE_STRING_LEN 100

#define MAX_PATH_LEN 256

#endif // _NHEAPSOLARIS_H
