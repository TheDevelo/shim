#define _GNU_SOURCE
#include <stdio.h>

int main() {
    printf("Line Reader and Echo Program\n");
    char* line = NULL;
    size_t len = 0;
    while (1) {
        getline(&line, &len, stdin);
        printf("line: %sline_addr: 0x%p, len: %lu\n", line, line, len);
    }

    return 0;
}
