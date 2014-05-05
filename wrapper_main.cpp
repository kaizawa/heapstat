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
 * This is wrapper command which invoke real heapstat[32|64]
 * command dependion on address size of target process or core.
 * 
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
#include <stdlib.h>
#include <iostream>
#include "mallint.h"
#include "Pcontrol.h"
#include "heapstat.h"
#include "MemorySpace.h"

char **get_argv(struct ps_prochandle *, int, char **);

int
main (int argc, char *argv[], char * envp[])
{
    int c;
    char *path;
    struct ps_prochandle *pr;
    int gcode;
    int prg_gflags = PGRAB_RDONLY;
    char **newargv;
    
    while ((c = getopt(argc, argv, "dv")) != EOF){
        switch (c) {
            case 'd':
            case 'v':
                break;
            default:
                print_usage(argv[0]);
        }
    }

    if ((argc - optind) < 1 || (argc - optind) > 2) {
        print_usage(argv[0]);
    }
    path = argv[optind++];
        
    if ((pr = proc_arg_grab(path, PR_ARG_ANY,
                            prg_gflags, &gcode)) == NULL) {
        (void) fprintf(stderr, "%s: cannot examine core or process %s: \n",
                       path, Pgrab_error(gcode));
        exit(1);
    }

    /* Create new argv for real heapstat command */
    newargv = get_argv(pr, argc, argv);
    execve(newargv[0], newargv, envp);
    exit(0);
}

char **
get_argv(struct ps_prochandle *pr, int argc, char **argv)
{
    char **newargv;
    char *cmdstr;    
    int i;
    int pathlen;

    newargv = (char **) malloc(sizeof(uintptr_t) * argc + 1);
    if (NULL == newargv) {
        perror("malloc");
        exit(1);
    }
    cmdstr = (char *) malloc(MAXPATHLEN);
    if (NULL == cmdstr) {
        perror("malloc");
        exit(1);
    }

    readlink("/proc/self/path/a.out", cmdstr, MAXPATHLEN);
    pathlen = strlen(cmdstr);

    if (pathlen + 3 > MAXPATHLEN)
    {
        printf("path length too long: %s\n", cmdstr);
        exit(0);
    }
    
    if (Pstatus(pr)->pr_dmodel == PR_MODEL_LP64) {
        strcpy(cmdstr + pathlen, "64");
    } else {
        strcpy(cmdstr + pathlen , "32");        
    }
    newargv[0] = cmdstr;

    for (i = 1 ; i < argc ; i++) {
        newargv[i] = argv[i];
    }
    newargv[argc] = NULL;

    return newargv;
}

void
print_usage(char *argv)
{
    std::cerr << "Usage: " << argv << " [-v] { pid | core } [interval]" << std::endl;
    std::cerr << "       -v: verbose output" << std::endl;
    exit(0);
}
