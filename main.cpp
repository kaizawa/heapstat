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
#include "MemorySpace.h"
#include "ProcService.h"
#include <iostream>
#include "HeapStat.h"

bool debug = false;
bool verbose = false;

int
main (int argc, char *argv[])
{
    int c;
    char *path;
    int interval = 0;    
    
    while ((c = getopt(argc, argv, "dv")) != EOF) {        
        switch (c) {
            case 'd':
                debug = true;
            case 'v':
                verbose = true;
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
    ProcService procService(path, debug, verbose);
    HeapStat heapStat(procService, debug, verbose);

    while (true) {
        if (verbose) {
            procService.print_process_info();
        }
        heapStat.print_heap_usage();        

        if (interval) {
            sleep(interval);
        } else {
            break;
        }
    }
    
    exit(0);
}

/*****************************************************************************
 * print_usage()
 *****************************************************************************/
void
print_usage(char *argv)
{
    std::cerr << "Usage: " << argv << " [-v] { pid | core } [interval]" << std::endl;
    std::cerr << "       -v: verbose output" << std::endl;
    exit(0);    
}
