#include "gtest/gtest.h"
#include <stdlib.h>
#include <stdio.h>
#include "HeapStat.h"
#include "ProcService.h"
#include <errno.h>
#include <strings.h>
#include <unistd.h>

#define BUFSIZE sizeof(long)*8+1

/**
 * @TODO
 * Following two test functions are almost same other
 * than option for leak32 program and expected result.
 * But because private member function of target class
 * (HeapStat::get_xxx) must be called from TEST(xxx,yyy)
 * function, I couldn't make code reusable.
 */ 

TEST(BasicTest, LargeAllocation)
{
    long long pid;
    char buf [BUFSIZE];
    char *strpid;
    const char *exeName = "leak32";
    const char *option = "-l";

    bzero(buf, BUFSIZE);

    pid = fork();
    if (pid == 0)
    {
        if (execl(exeName, exeName, option, NULL) < 0) {
            perror("execv");
            exit(1);
        }
        exit(0);
    }

    sleep(1);
    
    if ((strpid = lltostr(pid, buf)) == 0)
    {
        perror("lltostr");
    }
    
    ProcService procService(strpid, false, false);
    HeapStat heapStat(procService, false, false);

    const pstatus_t *psp;
    psp = procService.pstatus();

    size_t free_tree_size = heapStat.get_free_tree_size();
    size_t heap_size = psp->pr_brksize;
    size_t lfree_size = heapStat.get_lfree_size();
    size_t flist_free_size = heapStat.get_flist_free_size();
    size_t small_free_size = heapStat.get_small_free_size();
    size_t bottom_size = heapStat.get_bottom_size();
    size_t free_size = free_tree_size + flist_free_size + small_free_size + bottom_size;
    size_t used_size = heap_size - free_size;
    int free_rate = heap_size == 0 ? 0 : (int )((((float) free_size / (float) heap_size)) * 100);

    EXPECT_EQ(52412408, free_tree_size);
    EXPECT_EQ(52436992, heap_size);
    EXPECT_EQ(505, lfree_size);
    EXPECT_EQ(16162, flist_free_size);
    EXPECT_EQ(0, small_free_size);
    EXPECT_EQ(8176, bottom_size);
    EXPECT_EQ(52436746, free_size);
}

TEST(BasicTest, SmallAllocation)
{
    long long pid;
    char buf [BUFSIZE];
    char *strpid;
    const char *exeName = "leak32";
    const char *option = "-s";

    bzero(buf, BUFSIZE);

    pid = fork();
    if (pid == 0)
    {
        if (execl(exeName, exeName, option, NULL) < 0) {
            perror("execv");
            exit(1);
        }
        exit(0);
    }

    sleep(1);
    
    if ((strpid = lltostr(pid, buf)) == 0)
    {
        perror("lltostr");
    }
    
    ProcService procService(strpid, false, false);
    HeapStat heapStat(procService, false, false);

    const pstatus_t *psp;
    psp = procService.pstatus();

    size_t free_tree_size = heapStat.get_free_tree_size();
    size_t heap_size = psp->pr_brksize;
    size_t lfree_size = heapStat.get_lfree_size();
    size_t flist_free_size = heapStat.get_flist_free_size();
    size_t small_free_size = heapStat.get_small_free_size();
    size_t bottom_size = heapStat.get_bottom_size();
    size_t free_size = free_tree_size + flist_free_size + small_free_size + bottom_size;
    size_t used_size = heap_size - free_size;
    int free_rate = heap_size == 0 ? 0 : (int )((((float) free_size / (float) heap_size)) * 100);

    EXPECT_EQ(0, free_tree_size);    
    EXPECT_EQ(26427392, heap_size);
    EXPECT_EQ(9, lfree_size);
    EXPECT_EQ(288, flist_free_size);
    EXPECT_EQ(13106944, small_free_size);
    EXPECT_EQ(6576, bottom_size);
    EXPECT_EQ(13113808, free_size);
}

