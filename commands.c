#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include "commands.h"

#define READ_BUF_SIZE 4096 // Can't be bigger than one page (4096 bytes)

void find_cmd(char* input, pid_t child_pid) {
    int value;
    if (sscanf(input, "find %d", &value) != 1) {
        printf("invalid 'find' command\n");
        return;
    }

    // Open the child's memory and the memory maps
    char file_path[256];
    snprintf(file_path, 256, "/proc/%d/maps", child_pid);
    FILE* maps = fopen(file_path, "r");
    if (maps == NULL) {
        perror("failed to open the /proc/PID/maps file");
        return;
    }
    snprintf(file_path, 256, "/proc/%d/mem", child_pid);
    int memory_fd = open(file_path, O_RDWR);
    if (memory_fd == -1) {
        perror("failed to open the /proc/PID/mem file");
        return;
    }

    char* mmap_line = NULL;
    size_t mmap_len = 0;
    while (getline(&mmap_line, &mmap_len, maps) != -1) {
        // Parse the memory map line
        unsigned long start_addr;
        unsigned long end_addr;
        char perms[4];
        unsigned long offset;
        unsigned int major_id;
        unsigned int minor_id;
        unsigned int inode;
        char file_name[4096];
        file_name[0] = '\0'; // Set string to empty in case there is no file name in the mmap line

        int matched = sscanf(mmap_line, "%lx-%lx %4c %lx %u:%u %u %4096s", &start_addr, &end_addr, perms, &offset, &major_id, &minor_id, &inode, file_name);
        if (matched != 7 && matched != 8) {
            printf("malformed memory map file\n");
            return;
        }

        // Ignore [vvar], [vdso], [vsyscall] given they're kernel mechanisms for syscall acceleration (aka not what we want to search)
        // Anyways, can't even read from [vvar] or [vsyscall]
        if (strcmp(file_name, "[vsyscall]") == 0 || strcmp(file_name, "[vdso]") == 0 || strcmp(file_name, "[vvar]") == 0) {
            continue;
        }

        // Search the mapped memory page by page
        char page[READ_BUF_SIZE];
        if (lseek(memory_fd, start_addr, SEEK_SET) == -1) {
            perror("could not lseek() in the memory file");
            return;
        }
        for (unsigned long addr = start_addr; addr < end_addr; addr += READ_BUF_SIZE) {
            if (read(memory_fd, page, READ_BUF_SIZE) == -1) {
                perror("failed to read() from memory file");
                return;
            }
            for (unsigned long offset = 0; offset < READ_BUF_SIZE; offset += sizeof(int)) {
                int* mem_ptr = (int*) &page[offset];
                if (*mem_ptr == value) {
                    printf("found value at 0x%8lx\n", addr + offset);
                }
            }
        }
    }
}

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
