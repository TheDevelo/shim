#include <stdio.h>
#include <string.h>

int main() {
    char string_buf[4096];
    memset(string_buf, '\0', 4096);
    printf("4096 char string buffer at %p\n", string_buf);
    getc(stdin);
    printf("Value of string buffer: %s\n", string_buf);
}
