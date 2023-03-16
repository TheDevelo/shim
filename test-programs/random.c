#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main() {
    int* heap_int = malloc(sizeof(int));
    int stack_int;
    printf("heap_int addr: %p, stack_int addr: %p\n", heap_int, &stack_int);

    // Initialize the randomizer
    srand(time(NULL));
    do {
        *heap_int = rand() % 10000; // 10000 so I don't have to type out long numbers :)
        stack_int = rand() % 10000;
        printf("heap_int: %d, stack_int: %d\n", *heap_int, stack_int);
    } while (getc(stdin) != EOF);

    free(heap_int);
}
