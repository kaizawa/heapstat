#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>

int
main()
{
    char *str;
    int len = 4;
    
    str = malloc(len + 1);

    bzero(str, len + 1);
    memset(str, 'a', 4);
    printf("%p\n", str);
    gets(str);
}

    
