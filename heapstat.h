#ifndef _NHEAPSOLARIS_H
#define _NHEAPSOLARIS_H
#include "Pcontrol.h"
void print_usage(char *);
void find_heap(struct ps_prochandle *);
void print_heap_usage(struct ps_prochandle *);
void print_process_info(struct ps_prochandle *);
int count_free(struct ps_prochandle *, TREE *);
size_t get_free_tree_size (struct ps_prochandle *);
size_t get_lfree_size (struct ps_prochandle *);
size_t get_flist_free_size(struct ps_prochandle *);
size_t get_small_free_size(struct ps_prochandle *);
size_t get_bottom_size(struct ps_prochandle *);
uintptr_t get_vaddr_by_symbol(struct ps_prochandle *, char *);
uintptr_t get_pointer_value_by_symbol(struct ps_prochandle *, char *);
struct ps_prochandle *get_prochandle(char *);

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
