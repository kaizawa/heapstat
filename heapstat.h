#pragma once
#include "Pcontrol.h"
void print_usage(char *);

#if defined(_LP64)
typedef Elf64_Ehdr Ehdr;
#else
typedef Elf32_Ehdr Ehdr;
#endif

#define	FREESIZE (1<<5) /* size for preserving free blocks until next malloc */
#define	FREEMASK FREESIZE-1
#define SIZE_STRING_LEN 100

#define MAX_PATH_LEN 256

