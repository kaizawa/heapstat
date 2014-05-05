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

class MemorySpace
{
  public:
    MemorySpace() {};
    ~MemorySpace() {};
    void doPrint();
    virtual size_t get_free_size() const = 0;
};

    
    
