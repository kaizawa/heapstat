#include "gtest/gtest.h"
#include <stdlib.h>
#include <stdio.h>
#include "HeapStat.h"
#include "ProcService.h"

TEST(BasicTest, SimpleTest) {

    int pid = fork();
    if (pid == 0)
    {
        char command[] = "leak";
        system(command);
        exit(0);
    }

    ProcService procService(path, debug, verbose);
    HeapStat heapStat(procService, debug, verbose);

    while (true) {
        if (verbose) {
            procService.print_process_info();
        }
        heapStat.print_heap_usage();        
    
    
    EXPECT_EQ(1, 1);
}
