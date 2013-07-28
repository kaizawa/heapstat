#include <stdio.h>
#include <stdlib.h>

#define LARGE_CHUNK_SIZE 512 
#define SMALL_CHUNK_SIZE 32 
#define LARGE_COUNT 102400
#define SMALL_COUNT 1638400


void alloc(int);
void free_all();
void free_one(int);
void salloc(int);
void sfree_all();
void sfree_one(int);
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
    while(1){
        run();
    }
}

void
run()
{
	int  i;
	void *p;

        if(interactive){
            printf("Enter to allocate %d bytes of small chunk : ", SMALL_CHUNK_SIZE * SMALL_COUNT); 
            getchar();
        }
	for( i = 0 ; i < SMALL_COUNT ; i++){
		salloc(i);
	}
	printf("Allocate %d bytes of small chunk.\n", SMALL_CHUNK_SIZE * SMALL_COUNT);

        if(interactive){
            printf("Enter to allocate %d bytes of large chunk : ", LARGE_CHUNK_SIZE * LARGE_COUNT); 
            getchar();
        }
	for( i = 0 ; i < LARGE_COUNT ; i++){
		alloc(i);
	}
	printf("Allocate %d bytes of large chunk.\n", LARGE_CHUNK_SIZE * LARGE_COUNT);
        
        if(interactive){
            printf("Enter to free all memory: ");
            getchar();
        }        
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
