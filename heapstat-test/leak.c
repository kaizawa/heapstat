#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

#define LARGE_CHUNK_SIZE 499 
#define SMALL_CHUNK_SIZE 29 
#define LARGE_COUNT 102400
#define SMALL_COUNT 1638400

void alloc(int);
void free_all();
void free_one(int);
void salloc(int);
void sfree_all();
void sfree_one(int);
void run_once();
void run();

char *slist[SMALL_COUNT];
char *list[LARGE_COUNT];


int interactive=0;

int
main(int argc, char *argv[])
{
    int c;
    while ((c = getopt(argc, argv, "i")) != EOF) {        
        switch (c) {
            case 'i':
                interactive = 1;
                break;
            default:
                break;
        }
    }

    if (interactive) {
        run();
    } else {
        run_once();
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

        char *ilist[number];

        for (i = 0 ; i < number ; i++) {
            ilist[i] = (char *)malloc(size);
            memset(ilist[i], 0xff, size);
        }
        
        printf("Enter to free: ");        
        getchar();
        getchar();        

        for (i = 0 ; i < number ;  i++) {
            free(ilist[i]);
        }
    }
}

void
run_once()
{
	int  i;

	for( i = 0 ; i < SMALL_COUNT ; i++){
		salloc(i);
	}
	printf("Allocate %d bytes of small chunk.\n", SMALL_CHUNK_SIZE * SMALL_COUNT);

	for( i = 0 ; i < LARGE_COUNT ; i++){
		alloc(i);
	}
	printf("Allocate %d bytes of large chunk.\n", LARGE_CHUNK_SIZE * LARGE_COUNT);
        
	free_all();
	sfree_all();

        printf("Enter to continue: ");
        getchar();

}

void
salloc(int i)
{
	slist[i] = (char *)malloc(SMALL_CHUNK_SIZE);
}

void
alloc(int i)
{
	list[i] = (char *)malloc(LARGE_CHUNK_SIZE);
}


void
free_one(int i)
{
	free(list[i]);
}

void
free_all()
{
	int i;
	for(i=0 ; i < LARGE_COUNT ; i++){
		free(list[i]);
	}
}

void
sfree_one(int i)
{
	printf("%p\n", slist[i]);
	free(slist[i]);
}

void
sfree_all()
{
	int i;
	for(i=0 ; i < SMALL_COUNT ; i++){
		free(slist[i]);
	}
}
