#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include "mallint.h"
#include "Pcontrol.h"

#define MAX_FILE_PATH 256

static	struct ps_prochandle *Pr;

/**
 * This is a test program to examine how libproc works.
 */
int
main(int argc, char *argv[])
{
    char *path;
    char path_to_as[MAX_FILE_PATH];
    int fd;
    size_t offset;
    long buffer[1];
    off_t roff;
    size_t size;
    int gcode;
    int prg_gflags = PGRAB_RDONLY;
    
    if(argc < 3){
        printf("Usage: %s [core|pid] offset\n", argv[0]);
        exit(1);
    }

    // Read data via ps_prochandle 
    path = argv[1];
    offset = strtol(argv[2], NULL, 0);

    if ((Pr = proc_arg_grab(path, PR_ARG_ANY,
                            prg_gflags, &gcode)) == NULL) {
        (void) fprintf(stderr, "%s: cannot examine %s: %s\n",
                       argv[0], path, Pgrab_error(gcode));
        exit(1);
    }

    size = Pr->ops->p_pread(Pr, buffer, sizeof(long), offset);
    printf("ofset: 0x%lx(%ld), size: %ld, data: %s\n",
           offset, offset, size, (char *)buffer);    

    // Read data via /proc/pid/as file 
    // open as file 
    sprintf(path_to_as, "/proc/%s/as", path);        
    if((fd = open(path_to_as, O_CREAT | O_RDONLY)) < 0 ){
        printf("%s is not valid core or pid \n", path_to_as);
        exit(1);
    }
    printf("%s is opened\n", path_to_as);        
    
    
    if ((roff = lseek( fd, offset, SEEK_SET )) < 0) {
        perror("lseek");
        exit(1);        
    }

    size = read(fd, buffer, sizeof(long));
    printf("ofset: 0x%lx(%ld), roff: 0x%lx, size: %ld, data: %s\n",
           offset, offset, roff, size, (char *)buffer);
    exit(0);
}
