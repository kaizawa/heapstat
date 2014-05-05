#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

#define LARGE_CHUNK_SIZE 499 
#define SMALL_CHUNK_SIZE 8 
#define LARGE_COUNT 102400
#define SMALL_COUNT 1638400

void run_once(long, long);
void run();

int
main(int argc, char *argv[])
{
    int interactive = 0;
    int large = 0;
    int small = 0;
    int c;
    
    while ((c = getopt(argc, argv, "isl")) != EOF) {        
        switch (c) {
            case 'i':
                interactive = 1;
                break;            
            case 's':
                small = 1;
                break;
            case 'l':
                large = 1;
                break;                
            default:
                break;
        }
    }
    
    if (interactive) {
        run();
    }
    else if (small)
    {
        run_once(SMALL_CHUNK_SIZE, SMALL_COUNT);
    }
    else if (large)
    {
        run_once(LARGE_CHUNK_SIZE, LARGE_COUNT);            
    }
    exit(0);
}

void
run ()
{
    int size = 0;
    int number = 0;
    int i;

    while(1){
        printf("Input size to be allocated and number(e.g. 1024 2): ");
        scanf("%d %d", &size, &number);

        char *list[number];

        for (i = 0 ; i < number ; i++) {
            list[i] = (char *)malloc(size);
            memset(list[i], 0xff, size);
        }
        
        printf("Enter to free: ");        
        getchar();
        getchar();        

        for (i = 0 ; i < number ;  i++) {
            free(list[i]);
        }
    }
}

void
run_once(long chunk_size, long count)
{
    char *list[count];    
    int i;
    
    for(i = 0 ; i < count ; i++){
        list[i] = (char *)malloc(chunk_size);        
    }
    //printf("Allocated %ld bytes.\n", chunk_size * count);

    for(i = 0 ; i < count ; i++){
        free(list[i]);
    }    
    getchar();
}

