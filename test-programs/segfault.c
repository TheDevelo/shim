#define _GNU_SOURCE
#include <stdio.h>
#include <sys/mman.h>

int main() {
    void* page = mmap(NULL, 1, PROT_NONE, MAP_PRIVATE | MAP_ANON, -1, 0);
    printf("mmaped memory page: %p\n", page);
    getc(stdin);
    *((int*) page) = 1;
}
