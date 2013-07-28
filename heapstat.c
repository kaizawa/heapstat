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
 *
 * Note: Terminorogy used in this source
 *  vaddr: virtual address of original process address space
 *  mapaddr: virtual address mmap'ed to core file.
 *  symname: symbol name where exist on original process image.
 *  offset: file offset of core file. 
 *          actuall mmapped addres would be mmap'ed addr + offset.
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
#include "mallint.h"
#include "Pcontrol.h"
#include "heapstat.h"

static	struct ps_prochandle *Pr;
int debug = 0;
int verbose = 0;

Ehdr *ehdr; /* ELF Header of core file */
map_info_t *heap_mptr; /* mapinfo for heap */
static TREE *List[MINSIZE/WORDSIZE-1]; /* lists of small blocks */
static int free_tree_nodes = 0;

int
main (int argc, char *argv[])
{
    int fd;
    int c;
    char *path;
    int gcode;
    int prg_gflags = PGRAB_RDONLY;
    const pstatus_t *Psp;
    struct stat st;
    int i;
    GElf_Sym sym;


    while ((c = getopt(argc, argv, "dvi:")) != EOF) {        
        switch (c) {
            case 'd':
                verbose = 1;
                debug = 1;
                break;
            case 'v':
                verbose = 1;
                break;
            default:
                break;
        }
    }

    if ((argc - optind) != 1) {
        print_usage(argv[0]);
    }
    path = argv[optind++];


    
    if ((fd = open(path, O_RDONLY, 0664))< 0) {
        perror("open fail");
        return (-1);
    }

    if (fstat(fd, &st) < 0) {
        perror("fstat error");
        return (-1);
    }

    /*
     * map core file to memory.
     */
    ehdr = (Ehdr *)mmap(0, st.st_size, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0);
    if( ehdr < 0) {
        perror("mmap error");
        return (-1);
    }
    
    if ((Pr = proc_arg_grab(path, PR_ARG_ANY,
                            prg_gflags, &gcode)) == NULL) {
        (void) fprintf(stderr, "%s: cannot examine %s: %s\n",
                       argv[0], path, Pgrab_error(gcode));
        exit(1);
    }

    if(verbose){
        char *p;
        p = (char *) ehdr;
        printf("==============================\n");
        printf("General info\n");
        printf("==============================\n");
        printf("mmap size: %lld\n",st.st_size);
        printf("MINSIZE: %d\n", MINSIZE);
        printf("WORDSIZE: %d\n", WORDSIZE);
        printf("MINSIZE/WORDSIZE-1: %d\n", MINSIZE/WORDSIZE-1);
        printf("CORESIZE: %d\n", CORESIZE);
        printf("\n");                
        printf("==============================\n");
        printf("ELF header\n");
        printf("==============================\n");            
        printf("ehdr: 0x%p\n", ehdr);  
        printf("e_type: %d\n", ehdr->e_type);
        printf("e_shentsize: %d\n", ehdr->e_shentsize);
        printf("e_shnum: %d\n", ehdr->e_shnum);
        printf("\n");        
        printf("==============================\n");
        printf("ELF header hex dump\n");
        printf("==============================\n");
        for ( i = 0 ; i < sizeof(Ehdr) ; i++ ){
            if ( i > 0 && i % 16  == 0)
                printf("\n");
            printf("0x%.2x ", p[i]);
        }
        printf("\n\n");
    }

    Psp = Pstatus(Pr);
    if(verbose) {
        printf("==============================\n");
        printf("Process info\n");
        printf("==============================\n");        
        printf("brkbase: 0x%lx\n",Psp->pr_brkbase);
        printf("brksize: %d bytes (0x%lx)\n",Psp->pr_brksize, Psp->pr_brksize);
        printf("heap range: 0x%p-0x%p\n",
           Psp->pr_brkbase, Psp->pr_brkbase + Psp->pr_brksize);
        printf("\n");                        
    }
    
    find_heap();

    report_heap_usage();

    /**
     * Get GElf_Sym from symbole name
    if(Plookup_by_name(Pr, PR_OBJ_EVERY, "Root", &sym) < 0){
       fprintf(stderr, "Cannot get map for simbol\n");
       exit(1);
    }
    */
}

/*****************************************************************************
 * print_usage()
 *****************************************************************************/
void
print_usage(char *argv)
{
    fprintf(stderr,"Usage: %s [-d|-v] core_file\n", argv);
    fprintf(stderr,"   -d   : debug output\n");
    fprintf(stderr,"   -v   : verbose output\n");    
    exit(0);    
}

/*****************************************************************************
 * get_core_offset_by_vaddr
 *
 * Get file offset from process vaddr
 *****************************************************************************/
offset_t
get_core_offset_by_vaddr(uintptr_t vaddr)
{
    offset_t diff = get_diff_by_vaddr(vaddr);
    offset_t offset = vaddr - diff;    
    if(debug){
        fprintf(stderr, "get_core_offset_by_vaddr: vaddr=0x%p, offset=%ld(0x%lx)\n",
                vaddr, offset, offset);
    }
    return offset;
}

/*****************************************************************************
 * get_core_mapaddr_by_vaddr
 *
 * Get mmap'ed address from process vaddr
 *****************************************************************************/
uintptr_t
get_core_mapaddr_by_vaddr(uintptr_t vaddr)
{
    if(debug) {
        printf("get_core_mapaddr_by_vaddr: vaddr=0x%p\n", vaddr);
    }
    uintptr_t mapaddr;
    offset_t offset = get_core_offset_by_vaddr(vaddr);
    char *p = (char *) ehdr + offset;
    if(debug){
        fprintf(stderr, "get_core_mapaddr_by_vaddr: ehdr=%p, vaddr=0x%p, mapaddr=%p\n",
                ehdr, vaddr, p);
    }
    return (uintptr_t)p;
}

/*****************************************************************************
 * get_vaddr_by_core_offset
 *
 * Get process vaddr from file offset
 *****************************************************************************/
uintptr_t
get_vaddr_by_core_offset(offset_t offset)
{
    offset_t diff = get_diff_by_vaddr(offset);
    uintptr_t vaddr = offset + diff;
    
    if(debug)
        printf("get_vaddr_by_core_offset: vaddr=0x%p, offset=%p\n", vaddr, offset);

    return vaddr;
}

/*****************************************************************************
 * get_core_mapaddr_by_symname
 *
 * Get core file mmaped address of symbol
 *****************************************************************************/
uintptr_t
get_core_mapaddr_by_symname(char *symname)
{
    offset_t offset;
    char *p;

    offset = get_core_offset_by_symname(symname);
    p  = (char *)ehdr + offset;

    if(debug)
        printf("get_core_mapaddr_by_symname: symname=\"%s\", ehdr=%p, mapaddr=%p\n",
               symname, ehdr, p);
    return (uintptr_t)p;
}

/*****************************************************************************
 * get_core_offset_by_symname
 *
 * Get core file offset of symbol within libc.so.1
 *****************************************************************************/
offset_t
get_core_offset_by_symname(char *symname)
{
    GElf_Sym sym;
    offset_t offset;

    /*
     * NOTE: If I use PR_OBJ_EVERY, Lfree is resolved in libproc...
     * So I had to specify module name. 
     * if(Plookup_by_name(Pr, PR_OBJ_EVERY, symname, &sym) < 0){
     */ 

    /* Get GElf_Sym from symbole name */    
    if(Plookup_by_name(Pr, "libc.so.1", symname, &sym) < 0){        
        fprintf(stderr, "Cannot get map for symbol\n");
        exit(1);
    }
    
    /*
     * Now we know process vaddr of the symbol
     * Convert it to core file file offset.
     */
    offset = get_core_offset_by_vaddr(sym.st_value);
    
    if(debug)
        printf("get_core_offset_by_symname: symname=\"%s\", vaddr=0x%p, offset=%lu(0x%lx)\n",
               symname, sym.st_value, offset, offset);
    return offset;
}

/*****************************************************************************
 * report_heap_usage
 *
 * Show report usage
 *****************************************************************************/
void
report_heap_usage()
{
    const pstatus_t *Psp;
    Psp = Pstatus(Pr);    
    size_t free_size = get_free_size();
//  size_t heap_size = heap_mptr->map_pmap.pr_size;    
    size_t heap_size = Psp->pr_brksize;
    size_t lfree_size = get_lfree_size();
    size_t flist_free_size = get_flist_free_size();
    size_t small_free_size = get_small_free_size();
    size_t bottom_size = get_bottom_size();
    size_t used_size = heap_size - free_size - lfree_size - flist_free_size - small_free_size - bottom_size;
    
    char size_strings[SIZE_STRING_LEN]; /* buffer for show size strings */

    printf("==============================\n");
    printf("Heap Usage\n");
    printf("==============================\n");
    printf("heap size       : %12d (%s)\n", heap_size, print_unit(heap_size, size_strings));
    printf("freed free size : %12d (%s)\n", free_size, print_unit(free_size, size_strings));
    printf("Last free size  : %12d (%s)\n", lfree_size, print_unit(lfree_size, size_strings));
    printf("free list size  : %12d (%s)\n", flist_free_size, print_unit(flist_free_size, size_strings));
    printf("small size      : %12d (%s)\n", small_free_size, print_unit(small_free_size, size_strings));
    printf("bottom size     : %12d (%s)\n", bottom_size, print_unit(bottom_size, size_strings));
    printf("\n");
    printf("used size       : %12d (%s)\n", used_size, print_unit(used_size, size_strings));

    printf("\n");
}

/*****************************************************************************
 * get_symbol_value
 *
 * Get value of symbol of original process.
 *****************************************************************************/
uintptr_t
get_symbol_value(char *symname)
{
    size_t free_size = 0;
    uintptr_t *sym = NULL;
    uintptr_t mapaddr;

    mapaddr = get_core_mapaddr_by_symname(symname);
    if(debug)    
        printf("get_symbol_value: symname=\"%s\" mapaddr=0x%p\n",
               symname, mapaddr);
    sym = (uintptr_t *) mapaddr;
    if(debug)
        printf("get_symbol_value: value of \"%s\"=0x%p\n",
               symname, *sym);

    if(sym == NULL){
        printf("get_symbol_value: can't get address of \"%s\"\n",
               symname);
        exit(1);
    }
    return *sym;
}

/*****************************************************************************
 * get_free_size
 *
 * get free memory size within heap area.
 *****************************************************************************/
size_t
get_free_size ()
{
    size_t free_size = 0;
    uintptr_t root_addr;    
    uintptr_t mapaddr;
    TREE *m_root; // Root address of mapped AS.

    if(verbose){
        printf("==============================\n");
        printf("free tree info\n");
        printf("==============================\n");
    }
        
    root_addr = get_symbol_value("Root");
    if(root_addr){
        m_root = (TREE *)get_core_mapaddr_by_vaddr(root_addr);
        free_size = count_free(m_root);
    } else {
        if(debug)
            printf("get_free_size: Root doesn't have value\n");
    }

    if(verbose){
        printf("free tree nodes: %12d\n", free_tree_nodes);
        printf("free       size: %12d\n", free_size);
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
count_free(TREE *tp)
{
    int free_size = SIZE(tp); /* First add its own size */
    free_tree_nodes++; // thread unsafe
    
    if(LEFT(tp)){

        if(debug)
            printf("count_free: Left exists\n");
        uintptr_t left = (uintptr_t)LEFT(tp);
        uintptr_t mapaddr = get_core_mapaddr_by_vaddr(left);
        if(debug)
            printf("count_free: LEFT(tp)=0x%p, mapaddr=0x%p\n",left, mapaddr);
        /* Add left side total Call recursively */
        free_size += count_free((TREE *)mapaddr);
    } else {
        if(debug)        
            printf("count_free: Left is null\n");
    }
    
    if(RIGHT(tp)){
        if(debug)        
            printf("count_free: Right exists\n");
        uintptr_t right = (uintptr_t)RIGHT(tp);        
        uintptr_t mapaddr = get_core_mapaddr_by_vaddr(right);
        if(debug)
            printf("count_free: LEFT(tp)=0x%p, mapaddr=0x%p\n", right, mapaddr);
        /* Add right side total. Call recursively */        
        free_size += count_free((TREE *)mapaddr);
    } else {
        if(debug)
            printf("count_free: Right is null\n");
    }
    if(debug)
        printf("get_free_size: free_size=%d", free_size);    
    return free_size;
}

/*****************************************************************************
 * get_diff_by_vaddr
 *
 * Calculate difference between process vaddr and core file offset of
 * heap area.
 *
 *****************************************************************************/
offset_t
get_diff_by_vaddr(uintptr_t vaddr)
{
    if(debug)
        printf("get_diff_by_vaddr: vaddr=0x%p\n", vaddr);    //here
    map_info_t *mptr;
    prmap_t *pmap;
    offset_t diff = 0;
    const pstatus_t *Psp;    
    int i;
        
    mptr = Pr->mappings;    
    pmap = &mptr->map_pmap;

    /*
     * Loop map list for a map which include this vaddr
     */
    for (i = 0, mptr = Pr->mappings; i < Pr->map_count; i++, mptr++) {
        prmap_t *pmap;
        uintptr_t pr_vaddr;
        size_t pr_size;
        offset_t map_offset = mptr->map_offset;

        Psp = Pstatus(Pr);        
        pmap  = &mptr->map_pmap;
        pr_vaddr = pmap->pr_vaddr;
        pr_size  = pmap->pr_size;

        if ( pr_vaddr <= vaddr && pr_vaddr + pr_size > vaddr){
            diff =pr_vaddr - map_offset;
            if(debug)
                printf("get_diff_by_vaddr: found map for vaddr(0x%p). diff=%u(0x%lx)\n",
                       vaddr, diff);
            return diff;                
        }
    }
    printf("get_diff_by_vaddr: Can't find map for vaddr=0x%p\n", vaddr);
    exit(1);
}

/*****************************************************************************
 * get_diff_by_offset
 *
 * Calculate difference between process vaddr and core file offset of
 * heap area.
 *
 *****************************************************************************/
offset_t
get_diff_by_offset(offset_t offset)
{
    map_info_t *mptr;
    prmap_t *pmap;
    offset_t diff = 0;
    const pstatus_t *Psp;    
    int i;
        
    mptr = Pr->mappings;    
    pmap = &mptr->map_pmap;

    /*
     * Check first map to see the differences 
     * bettween vaddr and file offset
     * This result would be used later calculation.
     */
    for (i = 0, mptr = Pr->mappings; i < Pr->map_count; i++, mptr++) {
        prmap_t *pmap;
        uintptr_t pr_vaddr;
        size_t pr_size;
        offset_t map_offset = mptr->map_offset;        

        Psp = Pstatus(Pr);        
        pmap  = &mptr->map_pmap;
        pr_vaddr = pmap->pr_vaddr;
        pr_size  = pmap->pr_size;

        if ( map_offset <= offset && map_offset + pr_size > offset){
            diff =pr_vaddr - map_offset;            
            if(debug){
                printf("get_diff_by_offset: offset=lu(0xlx), diff=%u(0x%lx)\n",
                       offset, offset, diff, diff);
            }
            break;
        }
    }
    return diff;    
}

/*****************************************************************************
 * find_heap
 *
 * find map_info of heap.
 * Print all map info, if verbose flag is set
 *****************************************************************************/
void
find_heap()
{
    const pstatus_t *Psp;
    map_info_t *mptr;
    int i;

    Psp = Pstatus(Pr);            

    if(verbose){
        printf("==============================\n");
        printf("All MAPs\n");
        printf("==============================\n");
    }
    
    for (i = 0, mptr = Pr->mappings; i < Pr->map_count; i++, mptr++) {
        prmap_t *pmap;
        uintptr_t vaddr;
        size_t size;
        offset_t offset;

        pmap  = &mptr->map_pmap;
        vaddr = pmap->pr_vaddr;
        size  = pmap->pr_size;
        offset = mptr->map_offset;
        if(verbose)
            printf("vaddr=0x%p, file offset=0x%p, size=%lu, diff=%0x%lx ",
                   vaddr, offset, size, get_diff_by_vaddr(vaddr));
        if(pmap->pr_mflags & MA_ANON ){
            if (vaddr + size > Psp->pr_brkbase && vaddr < Psp->pr_brkbase + Psp->pr_brksize){
                if(verbose)
                    printf ("[ heap ]");
                heap_mptr = mptr;
            }
            else
                if(verbose)
                    printf ("[ anon ]");                
        } else {
            if(pmap->pr_mapname)
                if(verbose)                
                    printf ("[ %s ]", basename(pmap->pr_mapname));
        }
        if(verbose)        
            printf("\n");        
    }
    if(verbose)    
        printf("\n");    
}

/*****************************************************************************
 * get_lfree_size
 *
 * get last free size
 *****************************************************************************/
size_t
get_lfree_size ()
{
    size_t lfree_size = 0;    
    uintptr_t lfree_addr;
    char *m_lfree; // Lfree address of mapped AS.
    TREE *sp;
    uintptr_t mapaddr;

    if(verbose){
        printf("==============================\n");
        printf("Lfree info\n");
        printf("block last time free'ed\n");
        printf("==============================\n");
    }    

    lfree_addr = get_symbol_value("Lfree");
//    m_lfree = (char *)get_core_mapaddr_by_symname("Lfree");

    if(lfree_addr){
//    if(m_lfree){
        m_lfree = (char *)get_core_mapaddr_by_vaddr(lfree_addr);
	sp = (TREE *)BLOCK(m_lfree);
        lfree_size =  SIZE(sp);
    } else {
        if(debug)
            printf("get_lfree_size: Lfree doesn't have value\n");
    }
    if(debug) printf("get_lfree_size: lfree_size=%d\n", lfree_size);

    if(verbose){
        printf("Lfree size: %d\n", lfree_size);        
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
get_flist_free_size()
{
    size_t free_size = 0;
    uintptr_t freeidx; /* index of free blocks in flist % FREESIZE */    
//    char **flist; /* list of blocks to be freed on next malloc */
    char **m_flist; /* list of blocks to be freed on next malloc */    
    char **flp;
    TREE *tp;
    int cnt = 0;
    size_t ts;
    uintptr_t flist_addr;
    char *data;
    char *m_data;
    int i;

    if(verbose){
        printf("==============================\n");
        printf("flist info\n");
        printf("to be freed on next malloc\n");
        printf("==============================\n");
    }
    
    freeidx = get_symbol_value("freeidx");
    m_flist = (char **) get_core_mapaddr_by_symname("flist");
    if(flist_addr){
        /*
         * From malloc.c
         * Last 2 bit of size field is used for special purpose.
         *	BIT0:	1 for busy (block is in use), 0 for free.
         *	BIT1:	if the block is busy, this bit is 1 if the
         *		preceding block in contiguous memory is free.
         *		Otherwise, it is always 0.
         */
        for (i = 0 ; i < FREESIZE ; i++ ) {
            data = m_flist[i];
            if(data == NULL){
                if(verbose)
                    printf("flist[%02d](0x%p): empty\n", i, data);
                continue;
            }
            m_data = (char *)get_core_mapaddr_by_vaddr((uintptr_t)data);
            tp = BLOCK(m_data);
            ts = SIZE(tp);
            free_size += ts;
            if(verbose){
                printf("flist[%02d](0x%p): ISBIT(0)=%d, ISBIT(1)=%d, size=%d \n",
                       i, data, ISBIT0(ts), ISBIT1(ts), ts);
            }
        }
    } else {
        if(debug)
            printf("get_flist_free_size: flist doesn't have value\n");
    }

    if(verbose){
        printf("FREESIZE : %6d (# of slot)\n", FREESIZE);
        printf("freeidx  : %6d \n", freeidx);
        printf("free size: %6d \n", free_size);
        printf("\n");
    }
    return free_size;    
}

/*****************************************************************************
 * get_small_free_size
 *
 * MINSIZE: 80
 * WORDSIZE: 16 (in 64bit)
 * NPS = WORDSIZE * 8 = 148
 * List[MINSIZE/WORDSIZE-1] => List[4]
 *    Each list has (size + WORDSIZE) * NPS
 * 
 *****************************************************************************/
size_t
get_small_free_size()
{
    size_t free_size = 0;
    size_t size;
    uintptr_t list_addr; // address of 'List' of original process
    TREE **m_list; /* list of small blocks */
    TREE *tp;
    TREE *m_tp;
    size_t list_size = MINSIZE/WORDSIZE-1;
    int i;

    if(verbose){
        printf("==============================\n");
        printf("small list info\n");
        printf("free list for less than %d bytes\n", MINSIZE);
        printf("==============================\n");
    }    

    m_list = (TREE **)get_core_mapaddr_by_symname("List");

    for (i = 0 ; i < list_size ; i ++){
        size_t node_total = 0;
        size_t size = 0;
        int nodes = 0;
        
        tp = m_list[i];

        if (verbose){
            printf("## list[%d] (for less than %d bytes)\n", i, (i + 1) * WORDSIZE, nodes, node_total);
        }
        
        while(tp){
            nodes++;            
            if(debug)
                printf("get_small_fee_size: tp=0x%p\n",m_tp);
            m_tp = (TREE *)get_core_mapaddr_by_vaddr((uintptr_t)tp);
            size = SIZE(m_tp);
            node_total += size;
            if (verbose){
                printf("list[%d]-node#%02d (0x%p): size=%d\n", i, nodes, tp, size);
            }
            tp = AFTER(m_tp);
        }
        if (verbose){
            printf("list[%d]: nodes=%d, total size=%d\n", i, nodes, node_total);
            printf("\n");
        }        
        free_size += node_total;
    }
    if (verbose){
        printf("small free size: %d\n", free_size);
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
get_bottom_size()
{
    size_t free_size = 0;
    uintptr_t bottom_addr;    
    uintptr_t mapaddr;
    TREE *m_bottom; // Root address of mapped AS.

    if(verbose){
        printf("==============================\n");
        printf("bottom info\n");
        printf("last free chunk in this area\n");
        printf("==============================\n");
    }    
    bottom_addr = get_symbol_value("Bottom");
    if(bottom_addr){
        m_bottom = (TREE *)get_core_mapaddr_by_vaddr(bottom_addr);
        free_size = count_free(m_bottom);
    } else {
        if(debug)
            printf("get_bottom_size: Root doesn't have value\n");
    }

    if(verbose){
        printf("free size: %12d\n", free_size);
        printf("\n");
    }
    return free_size;
}
/*
void
list_blocks()
{
*/  
    
char *
print_unit(size_t size, char *buffer)
{
    if(size > 1024 * 1024 * 1024)
        snprintf(buffer, SIZE_STRING_LEN, "%d GB", (size / (1024 * 1024 * 1024)));
    else if(size > 1024 * 1024)
        snprintf(buffer, SIZE_STRING_LEN, "%d MB", (size / (1024 * 1024)));
    else if(size > 1024)
        snprintf(buffer, SIZE_STRING_LEN, "%d KB", (size / 1024));
    else
        snprintf(buffer, SIZE_STRING_LEN, "%d B", size);
    return buffer;
}

        
