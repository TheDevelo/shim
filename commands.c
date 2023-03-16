#include <stdio.h>
#include <string.h>
#include "commands.h"

void help_cmd(char* input) {
    char sub_cmd[256];
    if (sscanf(input, "help %256s", sub_cmd) == 1) {
        if (strcmp(sub_cmd, "find") == 0) {
            printf("find - searches for memory that matches specified conditions\n");
            printf("format: find TYPE x where x CONDITION\n\n");

            printf("'find' searches through memory for regions that match the condition specified\n");
            printf("the memory searched is treated as if it was all of type TYPE\n");
            printf("the searches can then be further searched through using 'refine'\n\n");

            printf("TYPEs available:\n");
            printf("byte, short, int, long - signed integers corresponding to the architecture's C types\n");
            printf("ubyte, ushort, uint, ulong - unsigned integers corresponding to the architecture's C types\n");
            printf("float, double - floating point numbers corresponding to the architecture's C types\n"); 
            printf("ptr - pointer corresponding to the architecture's C type\n");
            printf("string - null-terminated string\n\n");

            printf("CONDITIONs available\n");
            printf(">, <, >=, <=, ==, != - comparisons corresponding to the equivalent C comparison operator\n");
            printf("    these comparison all take an additional value (e.g. '== VAL') to compare to\n");
            printf("    >, <, >=, <= are only available to numeric types (i.e. not 'string'), while ==, != are available to all types\n");
            printf("exists - all memory passes this condition (useful when further refining with 'refine')\n");
        }
        else if (strcmp(sub_cmd, "help") == 0) {
            printf("help - issues a help statement\n");
            printf("use 'help x' to find more about the command 'x'\n");
        }
        else if (strcmp(sub_cmd, "quit") == 0) {
            printf("quit - exits the program\n");
        }
        else {
            printf("invalid subcommand for help\n");
        }
    }
    else {
        printf("find - searches for memory that matches specified conditions\n");
        printf("help - issues a help statement - use 'help x' to find more about the command 'x'\n");
        printf("quit - exits the program\n");
    }
}
