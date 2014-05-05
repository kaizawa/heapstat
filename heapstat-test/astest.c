#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

#define MAX_FILE_PATH 256

/**
 * This is a test program to evaluate how
 * /proc/<PID>/as works.
 */
int
main(int argc, char *argv[])
{
    char *pid;
    char path_to_as[MAX_FILE_PATH];
    int fd;
    size_t offset;
    long buffer[1];
    off_t roff;
    size_t size;
    char *ehdr;
    
    if(argc < 3){
        printf("Usage: %s <PID> <offset>\n", argv[0]);
        exit(1);
    }

    pid = argv[1];
    offset = strtol(argv[2], NULL, 0);

    sprintf(path_to_as, "/proc/%s/as", pid);

    if((fd = open(path_to_as, O_CREAT | O_RDONLY)) < 0 ){
        perror("open");
        printf("cannot open %s\n", path_to_as);
        exit(1);
    }
    
    if ((roff = lseek( fd, offset, SEEK_SET )) < 0) {
        perror("lseek");
        exit(1);        
    }

    ehdr = (char *)mmap(0, 0x7fffffffL, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0);
    if( MAP_FAILED == ehdr) {
        perror("mmap error");
        return (-1);
    }
    
    size = read(fd, buffer, sizeof(long));

    printf("ofset: 0x%lx(%ld), roff: 0x%lx, size: %ld, data: %s\n",
           offset, offset, roff, size, (char *)buffer);
    exit(0);
}
