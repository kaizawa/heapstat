#pragma once

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
#include "MemorySpace.h"
#include "ProcService.h"
#include <iostream>
#include <sys/procfs.h>

class ProcService 
{
  public:
    ProcService(char *, bool verbose, bool debug);
    ~ProcService();
    void print_process_info();
    int pread(void *buf, size_t buf_size, uintptr_t addr) const;
    int plookup_by_name(const char *, const char *, GElf_Sym *) const;
    const pstatus_t *pstatus() const;
    map_info_t *getMappings() const;
    size_t getMapCount() const;
    
  private:

    struct ps_prochandle *pr;
    bool verbose;
    bool debug;
    struct ps_prochandle *get_prochandle(const char *path);
};
