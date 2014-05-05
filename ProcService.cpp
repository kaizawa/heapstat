#include "ProcService.h"

ProcService::ProcService(char *path, bool verb, bool dbg) 
    :verbose(verb), debug(dbg)
{
    int gcode;
    int prg_gflags = PGRAB_RDONLY;

    pr = proc_arg_grab(path, PR_ARG_ANY, prg_gflags, &gcode);
    if (pr == NULL) {
        std::cerr << path <<  ": cannot examine core or process "
                  << Pgrab_error(gcode) << std::endl;
        // TODO: Should throw proper exception?
        throw;
    }
}

ProcService::~ProcService() {
    Prelease(pr, PRELEASE_CLEAR);
}

/*****************************************************************************
 * print_process_info
 *
 * Print process information
 *****************************************************************************/
void
ProcService::print_process_info()
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
    printf("brkbase: 0x%" PRIXPTR "\n",psp->pr_brkbase);
    printf("brksize: %zu bytes (0x%" PRIxPTR ")\n",
           psp->pr_brksize, psp->pr_brksize);
    printf("heap range: 0x%" PRIxPTR "-0x%" PRIxPTR "\n",
           psp->pr_brkbase, psp->pr_brkbase + psp->pr_brksize);
    printf("\n");                        
}

/*****************************************************************************
 * Get ps_prochandle for given core file or pid
 *****************************************************************************/
struct ps_prochandle *
ProcService::get_prochandle(const char *path)
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

int
ProcService::pread(void* buf_ptr, size_t buf_size, uintptr_t addr) const {
    return pr->ops->p_pread(pr, buf_ptr, buf_size, addr);
}

int
ProcService::plookup_by_name(const char *libname, const char *symname, GElf_Sym *sym) const {
    return Plookup_by_name(pr , libname, symname, sym);
}

const pstatus_t *
ProcService::pstatus() const 
{
    return Pstatus(pr);
}

map_info_t *
ProcService::getMappings() const {
    return pr->mappings;
}

size_t
ProcService::getMapCount() const {
    return pr->map_count;
}
