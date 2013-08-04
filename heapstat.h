#ifndef _NHEAPSOLARIS_H
#define _NHEAPSOLARIS_H
void print_usage(char *);
void find_heap();
void report_heap_usage();
int count_free(TREE *);
size_t get_free_tree_size ();
size_t get_lfree_size ();
size_t get_flist_free_size();
size_t get_small_free_size();
size_t get_bottom_size();
uintptr_t get_vaddr_by_symbol(char *);
uintptr_t get_pointer_value_by_symbol(char *);

char *print_unit(size_t);

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
