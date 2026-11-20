/* Milestone 1 test: the smallest useful Windows console program. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
    printf("Hello from a Windows .exe running on Linux!\n");
    printf("argc=%d\n", argc);
    for (int i = 0; i < argc; i++)
        printf("argv[%d]=%s\n", i, argv[i]);

    char *buf = malloc(32);
    strcpy(buf, "heap works");
    printf("%s, %ld, %lld, 0x%x, %5.2f\n", buf, 42L, 1234567890123LL, 255u, 3.14159);
    free(buf);
    return 7;
}
