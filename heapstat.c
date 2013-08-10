/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copright (c) 2013  Kazuyoshi Aizawa <admin2@whiteboard.ne.jp>
 * All rights reserved.
 */  

/*
 * heapstat
 * 
 * Solaris C heap free space analyzer for libc malloc.
 * 
 * Useful link: 
 *  Self-Adjusting Binary Search Trees (which is used by libc malloc)
 *  http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.95.1380&rep=rep1&type=pdf
 */
#include <fcntl.h>
#include <libgen.h>
#include <libproc.h>
#include <limits.h>
#include <stdio.h>
#include <strings.h>
#include <sys/mkdev.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <malloc.h>
#include <sys/mman.h>
#include <inttypes.h>
#include "mallint.h"
#include "Pcontrol.h"
#include "heapstat.h"

int debug = 0;
int verbose = 0;

map_info_t *heap_mptr; /* mapinfo for heap */
char size_strings[SIZE_STRING_LEN]; /* buffer for show size strings */
static int free_tree_nodes = 0;

int
main (int argc, char *argv[])
{
    int c;
    char *path;
    int interval = 0;    
    
    while ((c = getopt(argc, argv, "dv")) != EOF) {        
        switch (c) {
            case 'd':
                debug = 1;
            case 'v':
                verbose = 1;
                break;
            default:
                print_usage(argv[0]);                
        }
    }

    if ((argc - optind) < 1 || (argc - optind) > 2) {
        print_usage(argv[0]);
    }
    path = argv[optind++];
    
    if (1 == (argc - optind)) {
        interval = atoi(argv[optind++]);
        if (0 == interval) {
            print_usage(argv[0]);
        }
    }

    while(1) {
        struct ps_prochandle *pr;

        pr = get_prochandle(path);
        find_heap(pr);        
        if (verbose) {
            print_process_info(pr);
        }
        print_heap_usage(pr);        

        if (interval) {
            sleep(interval);
        } else {
            break;
        }
        Prelease(pr, PRELEASE_CLEAR);
    } 
    
    exit(0);
}

/*****************************************************************************
 * print_usage()
 *****************************************************************************/
void
print_usage(char *argv)
{
    fprintf(stderr,"Usage: %s [-v] { pid | core } [interval]\n", argv);
    fprintf(stderr,"       -v: verbose output\n");    
    exit(0);    
}

/*****************************************************************************
 * Get ps_prochandle for given core file or pid
 *****************************************************************************/
struct ps_prochandle *
get_prochandle(char *path)
{
    struct ps_prochandle *pr;
    int gcode;
    int prg_gflags = PGRAB_RDONLY;
        
    if ((pr = proc_arg_grab(path, PR_ARG_ANY,
                            prg_gflags, &gcode)) == NULL) {
        (void) fprintf(stderr, "%s: cannot examine core or process %s: \n",
                       path, Pgrab_error(gcode));
        exit(1);
    }
    return pr;
}
/*****************************************************************************
 * print_process_info
 *
 * Print process information
 *****************************************************************************/
void
print_process_info(struct ps_prochandle *pr)
{
    const pstatus_t *psp;
    psp = Pstatus(pr);
    
    printf("==============================\n");
    printf("General info\n");
    printf("==============================\n");
    printf("MINSIZE: %zu\n", MINSIZE);
    printf("WORDSIZE: %zu\n", WORDSIZE);
    printf("MINSIZE/WORDSIZE-1: %zu\n", MINSIZE/WORDSIZE-1);
    printf("CORESIZE: %d\n", CORESIZE);
    printf("NPS: %zu\n", WORDSIZE*8);        
    printf("\n");

    printf("==============================\n");
    printf("Process info\n");
    printf("==============================\n");
    printf("pid    : %d\n",psp->pr_pid);
    printf("brkbase: 0x%" PRIXPTR "\n",psp->pr_brkbase);
    printf("brksize: %zu bytes (0x%" PRIxPTR ")\n",
           psp->pr_brksize, psp->pr_brksize);
    printf("heap range: 0x%" PRIxPTR "-0x%" PRIxPTR "\n",
           psp->pr_brkbase, psp->pr_brkbase + psp->pr_brksize);
    printf("\n");                        
}

    
/*****************************************************************************
 * print_heap_usage
 *
 * Show report usage
 *****************************************************************************/
void
print_heap_usage(struct ps_prochandle *pr)
{
    const pstatus_t *psp;
    psp = Pstatus(pr);
    static unsigned long count = 0;

    size_t free_tree_size = get_free_tree_size(pr);
    size_t heap_size = psp->pr_brksize;
    size_t lfree_size = get_lfree_size(pr);
    size_t flist_free_size = get_flist_free_size(pr);
    size_t small_free_size = get_small_free_size(pr);
    size_t bottom_size = get_bottom_size(pr);
    size_t free_size = free_tree_size + flist_free_size + small_free_size + bottom_size;
    size_t used_size = heap_size - free_size;
    int free_rate = heap_size == 0 ? 0 : (int )((((float) free_size / (float) heap_size)) * 100);

    if (verbose) {
        printf("==============================\n");
        printf("Heap Usage\n");
        printf("==============================\n");
        printf("heap size       : %12zu (%s)\n", heap_size, print_unit(heap_size));
        printf("free tree size  : %12zu (%s)\n", free_tree_size, print_unit(free_tree_size));
        printf("next free size  : %12zu (%s)\n", flist_free_size, print_unit(flist_free_size));
        printf("    (last free) : %12zu (%s)\n", lfree_size, print_unit(lfree_size));    
        printf("small free size : %12zu (%s)\n", small_free_size, print_unit(small_free_size));
        printf("bottom size     : %12zu (%s)\n", bottom_size, print_unit(bottom_size));
        printf("\n");
        printf("used size       : %12zu (%s)\n", used_size, print_unit(used_size));
        printf("free size       : %12zu (%s)\n", used_size, print_unit(free_size));
        printf("free%%           :      %7d (%d %%)\n", free_rate, free_rate);
        printf("\n");
    } else {
        if(0 == count % 20) {
            printf("%12s %12s %12s %12s %12s %12s %7s\n", 
                   "free tree", "next free", "small free", "bottom size", "heap size",
                   "free size", "free%");
            printf("%12s %12s %12s %12s %12s %12s %7s\n",             
                   "size(kb)", "size(kb)", "size(kb)", "(kd)", "(kb)", "(kb)", "(%)");
        }
        printf("%12zu ", free_tree_size / 1024);
        printf("%12zu ", flist_free_size / 1024);
        printf("%12zu ", small_free_size / 1024);
        printf("%12zu ", bottom_size / 1024);
        printf("%12zu ", heap_size / 1024);        
        printf("%12zu ", free_size / 1024);
        printf("%7d ", free_rate);
        printf("\n");
    }
    count++;    
}

/*****************************************************************************
 * get_free_tree_size
 *
 * get free memory size under Root free tree
 *****************************************************************************/
size_t
get_free_tree_size (struct ps_prochandle *pr)
{
    size_t free_size = 0;
    uintptr_t root_addr = 0;    
    TREE tree; // Root address

    if (verbose) {
        printf("==============================\n");
        printf("free tree info\n");
        printf("==============================\n");
    }

    root_addr = get_pointer_value_by_symbol(pr, "Root");
    if (debug) {
        printf("get_free_tree_size: Root TREE address = 0x%" PRIxPTR "\n", root_addr);
    }

    if (root_addr) {
        if (pr->ops->p_pread(pr, &tree, sizeof(TREE), root_addr) < 0){
            printf("get_free_tree_size: cannot read Root tree\n");
            exit(1);
        }
        free_size = count_free(pr, &tree);
    }    

    if (verbose) {
        printf("free tree nodes: %12d\n", free_tree_nodes);
        printf("free tree size : %12zu\n", free_size);
        printf("\n");
    }
    
    return free_size;
}

/*****************************************************************************
 * count_free
 *
 * recursively count the size of left side of branch and right side of branch.
 * Then sum these branches total size and its own size.
 *
 *           o root
 *          /\
 *    Left o  o  Rigt
 *        /  / \
 *              o
 *
 * This function is thread unsafe. ...must be called exclusively.
 * otherwize free_tree_node would be corrupted.
 *****************************************************************************/
int
count_free(struct ps_prochandle *pr, TREE *tp)
{
    int free_size = SIZE(tp); /* First add its own size */
    free_tree_nodes++; // thread unsafe
    TREE tree;
    int nodenum = free_tree_nodes;

    if(verbose){
        printf("count_free: node#%d free_size = %d\n",
               nodenum, free_size);
    }    
    
    if(LEFT(tp)){
        uintptr_t left = (uintptr_t)LEFT(tp);        
        if (debug) {
            printf("count_free: node#%d LEFT = 0x%" PRIxPTR "\n",
                   nodenum, left);
        }        
        if (pr->ops->p_pread(pr, &tree, sizeof(TREE), left) < 0){
            printf("count_free: cannot read left tree\n");        
        }
        /* Add left side total Call recursively */
        free_size += count_free(pr, (TREE *)&tree);
    } else {
        if (debug) {
            printf("count_free: node#%d Left is null\n", nodenum);
        }        
    }
    
    if(RIGHT(tp)){
        uintptr_t right = (uintptr_t)RIGHT(tp);        
        if(debug) {
            printf("count_free: node#%d RIGHT = 0x%" PRIxPTR "\n",
                   nodenum, right);
        }        
        if (pr->ops->p_pread(pr, &tree, sizeof(TREE), right) < 0){
            printf("count_free: cannot read right tree\n");        
        }        
        /* Add right side total. Call recursively */        
        free_size += count_free(pr, (TREE *)&tree);
    } else {
        if (debug) {
            printf("count_free: node#%d Right is null\n", nodenum);
        }
    }
    
    return free_size;
}

/*****************************************************************************
 * find_heap
 *
 * find map_info of heap.
 * Print all map info, if verbose flag is set
 *****************************************************************************/
void
find_heap(struct ps_prochandle *pr)
{
    const pstatus_t *psp;
    map_info_t *mptr;
    unsigned int i;

    psp = Pstatus(pr);            

    if(verbose){
        printf("==============================\n");
        printf("All MAPs\n");
        printf("==============================\n");
        printf("map count: %zu\n", pr->map_count);
    }
    
    for (i = 0, mptr = pr->mappings; i < pr->map_count; i++, mptr++) {
        prmap_t *pmap;
        uintptr_t vaddr;
        size_t size;
        offset_t offset;

        pmap  = &mptr->map_pmap;
        vaddr = pmap->pr_vaddr;
        size  = pmap->pr_size;
        offset = mptr->map_offset;
        if(verbose){
            printf("vaddr=0x%" PRIxPTR ", file offset=0x%llx, size=%zu",
                   vaddr, offset, size);
        }
        if (pmap->pr_mflags & MA_ANON ) {
            if (vaddr + size > psp->pr_brkbase
                && vaddr < psp->pr_brkbase + psp->pr_brksize) {
                if(verbose) { printf ("[ heap ]"); }
                /* set to global variable */
                heap_mptr = mptr;
            } else {
                if(verbose) { printf ("[ anon ]");}
            }
        } else {
            if (pmap->pr_mapname) {
                if(verbose) {printf ("[ %s ]", basename(pmap->pr_mapname)); }
            }
        }
        if(verbose) { printf("\n"); }
    }
    if(verbose) { printf("\n"); }
}

/*****************************************************************************
 * get_lfree_size
 *
 * get last free size
 *****************************************************************************/
size_t
get_lfree_size (struct ps_prochandle *pr)
{
    size_t lfree_size = 0;    
    uintptr_t lfree_addr = 0;
    TREE tree;
    uintptr_t tree_addr;

    if(verbose){
        printf("==============================\n");
        printf("Lfree info\n");
        printf("block last time free'ed\n");
        printf("==============================\n");
    }

    lfree_addr = get_pointer_value_by_symbol(pr, "Lfree");
    if (debug) printf("get_lfree_size: Lfree = 0x%" PRIxPTR "\n", lfree_addr);

    if (lfree_addr) {
        tree_addr = (uintptr_t) BLOCK(lfree_addr);
        if (pr->ops->p_pread(pr, &tree, sizeof(TREE), tree_addr) < 0){
            printf("count_free: cannot read last free'ed tree\n");        
        }
        lfree_size =  SIZE(&tree);
        if(debug) printf("get_lfree_size: lfree_size = %zu\n", lfree_size);        
    }    

    if(verbose){
        printf("Lfree size: %zu\n", lfree_size);        
        printf("\n");
    }

    return lfree_size;    
}

/*****************************************************************************
 * get_flist_free_size
 *
 * get flist free size.
 *****************************************************************************/
size_t
get_flist_free_size(struct ps_prochandle *pr)
{
    size_t free_size = 0;
    uintptr_t freeidx = 0; /* index of free blocks in flist % FREESIZE */
    uintptr_t flist_addr = 0;
    uintptr_t *flist; /* list of blocks to be freed on next malloc */
    TREE tree;
    uintptr_t data_addr;
    uintptr_t tree_addr;
    size_t size;
    int i;    

    if(verbose){
        printf("==============================\n");
        printf("flist info\n");
        printf("to be freed on next malloc\n");
        printf("==============================\n");
    }
    flist = (void *) malloc(sizeof(uintptr_t) * FREESIZE);
    if (NULL == flist) {
        perror("malloc");
        exit(1);
    }
    
    freeidx = get_pointer_value_by_symbol(pr, "freeidx");
    flist_addr = get_vaddr_by_symbol(pr, "flist");

    if (0 == flist_addr) {
        /* we must be able to find address of flist */
        printf("get_flist_free_size: cannot find flist address\n");
        exit(1);     
    }
    
    if (pr->ops->p_pread(pr, flist, sizeof(uintptr_t) * FREESIZE,
                         flist_addr) < 0) {
        printf("get_flist_free_size: cannot read flist\n");
        exit(1);
    }    
    
    /*
     * From malloc.c
     * Last 2 bit of size field is used for special purpose.
     *	BIT0:	1 for busy (block is in use), 0 for free.
     *	BIT1:	if the block is busy, this bit is 1 if the
     *		preceding block in contiguous memory is free.
     *		Otherwise, it is always 0.
     */
    for (i = 0 ; i < FREESIZE ; i++ ) {
        data_addr = flist[i];
        if (0 == data_addr) {
            if(verbose)
                printf("flist[%02d](0x%" PRIxPTR "): empty\n", i, data_addr);
            continue;
        }
        tree_addr = (uintptr_t) BLOCK(data_addr);            
        if (pr->ops->p_pread(pr, &tree, sizeof(TREE), tree_addr) < 0){
            printf("get_flist_free_size: cannot tree data\n");
            exit(1);
        }
        size = SIZE(&tree);
        free_size += size;
        if (verbose) {
            printf("flist[%02d](0x%" PRIxPTR "): ISBIT(0)=%zu, ISBIT(1)=%zu, size=%zu \n",
                   i, data_addr, ISBIT0(size), ISBIT1(size), size);
        }
    }

    if(verbose){
        printf("FREESIZE       : %6d (# of slot)\n", FREESIZE);
        printf("freeidx        : %6zu \n", freeidx);
        printf("next free size : %6zu (%s)\n", free_size, print_unit(free_size));
        printf("\n");
    }
    free(flist);
    return free_size;    
}

/*****************************************************************************
 * get_small_free_size
 *
 * Report total size of unused list of node for small size.
 *
 * If requested, _smalloc() in malloc.c always allocates 128 nodes for each
 * List at a time regardless requested size. So the rest of nodes are reserved
 * for later use.
 *
 * MINSIZE: 80
 * WORDSIZE: 16 (in 64bit)
 * NPS = WORDSIZE * 8 = 148
 * List[MINSIZE/WORDSIZE-1] => List[4]
 *    Each list has (size + WORDSIZE) * NPS
 *
 * List[0] List of TREE for less than 16byte (# of node is 0-128)
 * List[1] List of TREE for less than 32byte (# of node is 0-128)
 * List[2] List of TREE for less than 48byte (# of node is 0-128)
 * List[3] List of TREE for less than 64byte (# of node is 0-128)
 * 
 *****************************************************************************/
size_t
get_small_free_size(struct ps_prochandle *pr)
{
    size_t free_size = 0;
    uintptr_t list_base_addr; // address of 'List' 
    size_t list_size = MINSIZE/WORDSIZE-1;
    unsigned int i;
    TREE tree;

    if(verbose){
        printf("==============================\n");
        printf("small list info\n");
        printf("free list for less than %zu bytes\n", MINSIZE);
        printf("==============================\n");
    }

    list_base_addr = get_vaddr_by_symbol(pr, "List");
    if (NULL == list_base_addr) {
            printf("get_small_free_size: cannot get List address\n");
            exit(1);
    }

    for (i = 0 ; i < list_size ; i ++) {
        size_t node_total = 0;
        size_t size = 0;
        int nodes = 0;
        uintptr_t tree_addr;
        uintptr_t list_addr;

        /* list_addr poins unused list of small node */
        list_addr = list_base_addr + sizeof(uintptr_t) * i;
        
        if (pr->ops->p_pread(pr, &tree_addr, sizeof(uintptr_t), list_addr) < 0) {
                printf("get_small_free_size: cannot get tree address\n");
                exit(1);
        }        
        
        if (verbose){
            printf("## list[%d] (0x%" PRIxPTR ") (for less than %zu bytes)\n", i, 
                   tree_addr, (i + 1) * WORDSIZE);
        }
        
        while (tree_addr) {
            if (pr->ops->p_pread(pr, &tree, sizeof(TREE), tree_addr) < 0) {
                printf("get_small_free_size: cannot read tree data\n");
                exit(1);
            }    
            size = SIZE(&tree);
            node_total += size;
            if (verbose){
                printf("list[%d]-node#%02d (0x%" PRIxPTR "): size=%zu\n", i, nodes,
                       tree_addr, size);
            }
            nodes++;            
            tree_addr = (uintptr_t) AFTER(&tree);
        }
        
        if (verbose) {
            printf("list[%d]: nodes=%d, total size=%zu (%s)\n", i, nodes,
                   node_total, print_unit(node_total));
            printf("\n");
        }        
        free_size += node_total;
    }
    if (verbose) {
        printf("small free size: %zu\n", free_size);
        printf("\n");
    }
    return free_size;
}

/*****************************************************************************
 * get_bottom_size
 *
 * get size of last free chunk 
 *****************************************************************************/
size_t
get_bottom_size(struct ps_prochandle *pr)
{
    size_t free_size = 0;
    uintptr_t bottom_addr;    
    TREE tree;

    if(verbose){
        printf("==============================\n");
        printf("bottom info\n");
        printf("last free chunk in this area\n");
        printf("==============================\n");
    }
    bottom_addr = get_pointer_value_by_symbol(pr, "Bottom");
    if(debug){
        printf("get_bottom_size: Bottom address = 0x%" PRIxPTR "\n", bottom_addr);
    }

    if (bottom_addr) {
        if (pr->ops->p_pread(pr, &tree, sizeof(TREE), bottom_addr) < 0){
            printf("get_free_size: cannot read Root tree\n");
            exit(1);
        }
        free_size = count_free(pr, &tree);
    }    

    if(verbose){
        printf("free size: %12zu\n", free_size);
        printf("\n");
    }
    return free_size;
}
    
char *
print_unit(size_t size)
{
    memset(size_strings, 0x0, SIZE_STRING_LEN);
    if(size > 1024 * 1024 * 1024)
        snprintf(size_strings, SIZE_STRING_LEN, "%.1f GB", ((float)size / (1024 * 1024 * 1024)));
    else if(size > 1024 * 1024)
        snprintf(size_strings, SIZE_STRING_LEN, "%.1f MB", ((float)size / (1024 * 1024)));
    else if(size > 1024)
        snprintf(size_strings, SIZE_STRING_LEN, "%.1f KB", ((float)size / 1024));
    else
        snprintf(size_strings, SIZE_STRING_LEN, "%zu B", size);
    return size_strings;
}

/*****************************************************************************
 * get_vaddr_by_symbol
 *
 * Get virtual address of symbol
 *****************************************************************************/
uintptr_t
get_vaddr_by_symbol(struct ps_prochandle *pr, char *symname)
{
    GElf_Sym sym;
    uintptr_t pointer;

    /*
     * NOTE: If I use PR_OBJ_EVERY, Lfree is resolved in libproc...
     * So I had to specify module name. 
     * if(Plookup_by_name(pr, PR_OBJ_EVERY, symname, &sym) < 0){
     */ 

    /* Get GElf_Sym from symbole name */    
    if(Plookup_by_name(pr, "libc.so.1", symname, &sym) < 0){        
        fprintf(stderr, "Cannot get map for symbol\n");
        exit(1);
    }
    pointer = sym.st_value;
    
    if (debug){
        printf("get_vaddr_by_symbol: Address of %s is 0x%" PRIxPTR "\n",
               symname, pointer);
    }
    return pointer;
}

/*****************************************************************************
 * get_pointer_value_by_symbol
 *
 * Get value of symbol as pointer
 *****************************************************************************/
uintptr_t
get_pointer_value_by_symbol(struct ps_prochandle *pr, char *symname)
{
    uintptr_t symaddr;
    uintptr_t pointer;
    int addr_size = Pstatus(pr)->pr_dmodel == PR_MODEL_LP64 ? 8 : 4;

    symaddr = get_vaddr_by_symbol(pr, symname);

    if (pr->ops->p_pread(pr, &pointer, addr_size, symaddr) < 0){
        printf("get_pointer_value_by_symbol: cannot read pointer value by %s\n",
               symname);
        exit(1);
    }
    return pointer;
}
