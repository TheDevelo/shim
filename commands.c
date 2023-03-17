#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include "commands.h"
#include "helpers.h"

struct scan_node* find_cmd(char* input, pid_t child_pid) {
    // Parse the find command
    char type_str[32];
    char cond_str[32];
    char extra_param_str[256];
    int matched = sscanf(input, "find %32s x where x %32s %256s", type_str, cond_str, extra_param_str);
    if (matched != 2 && matched != 3) {
        printf("invalid 'find' command\n");
        return NULL;
    }
    enum scan_type type = str_to_type(type_str);
    if (type == Tinvalid) {
        printf("invalid type specified\n");
        return NULL;
    }
    enum scan_cond cond = str_to_cond(cond_str);
    switch (cond) {
        // Disallow all temporal conditions (as this is the first scan)
        case Csame:
        case Cdiff:
        case Cabove:
        case Cbelow:
        case Cinvalid:
            printf("invalid condition specified\n");
            return NULL;
        default:
    }
    if (type == Tstring) {
        // Disallow all but Ceq for strings
        if (cond != Ceq) {
            printf("invalid condition specified - only valid condition for string in 'find' is ==\n");
            return NULL;
        }
        // Rescan input if string to force quotes and include whitespace in the following string
        matched = sscanf(input, "find string x where x %32s '%256[^'\n]'", cond_str, extra_param_str);
        matched += 1; // Adjust up by one since we didn't match the type in the retry
        if (matched != 3) {
            printf("invalid condition specified - wrap your string in single quotes\n");
            return NULL;
        }
    }
    union scan_value extra_param;
    if (cond == Cexists) {
        if (matched == 3) {
            printf("invalid condition specified - exists does not need an extra parameter\n");
            return NULL;
        }
    }
    else {
        if (matched == 2) {
            printf("invalid condition specified - %s requires an extra parameter\n", cond_str);
            return NULL;
        }
        extra_param = parse_value(extra_param_str, type);
    }

    // Open the child's memory and the memory maps
    char file_path[256];
    snprintf(file_path, 256, "/proc/%d/maps", child_pid);
    FILE* maps = fopen(file_path, "r");
    if (maps == NULL) {
        perror("failed to open the /proc/PID/maps file");
        return NULL;
    }
    snprintf(file_path, 256, "/proc/%d/mem", child_pid);
    int memory_fd = open(file_path, O_RDWR);
    if (memory_fd == -1) {
        perror("failed to open the /proc/PID/mem file");
        return NULL;
    }

    // Scan each memory mapped region and construct a list of values
    char* mmap_line = NULL;
    size_t mmap_len = 0;
    struct scan_node head = { .value.Tptr = NULL, .type = Tinvalid, .next = NULL };
    struct scan_node* cur_node = &head;
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

        matched = sscanf(mmap_line, "%lx-%lx %4c %lx %u:%u %u %4096s", &start_addr, &end_addr, perms, &offset, &major_id, &minor_id, &inode, file_name);
        if (matched != 7 && matched != 8) {
            printf("malformed memory map file\n");
            return NULL;
        }

        // Ignore [vvar], [vdso], [vsyscall] given they're kernel mechanisms for syscall acceleration (aka not what we want to search)
        // Anyways, can't even read from [vvar] or [vsyscall]
        if (strcmp(file_name, "[vsyscall]") == 0 || strcmp(file_name, "[vdso]") == 0 || strcmp(file_name, "[vvar]") == 0) {
            continue;
        }

        // Search the mapped memory page by page
        // To accomadate strings across page boundaries, we have a weird scanning scheme:
        // We read the next page into memory before scanning the current page, so that any overflows go onto the next page
        char page[2*READ_BUF_SIZE];
        if (lseek(memory_fd, start_addr, SEEK_SET) == -1) {
            perror("could not lseek() in the memory file");
            return NULL;
        }
        if (read(memory_fd, &page[READ_BUF_SIZE], READ_BUF_SIZE) == -1) {
            perror("failed to read() from memory file");
            return NULL;
        }

        for (unsigned long addr = start_addr; addr < end_addr; addr += READ_BUF_SIZE) {
            // Load our next page ahead
            memcpy(page, &page[READ_BUF_SIZE], READ_BUF_SIZE);
            if (addr + READ_BUF_SIZE < end_addr) {
                if (read(memory_fd, &page[READ_BUF_SIZE], READ_BUF_SIZE) == -1) {
                    perror("failed to read() from memory file");
                    return NULL;
                }
            }
            else {
                memset(&page[READ_BUF_SIZE], 0, READ_BUF_SIZE);
            }

            // Scan the previous page
            for (unsigned long offset = 0; offset < READ_BUF_SIZE; offset += type_step(type)) {
                void* mem_ptr = (void*) &page[offset];
                union scan_value mem_value = mem_to_value(mem_ptr, type);
                if (satisfies_condition(mem_value, type, cond, extra_param)) {
                    cur_node->next = malloc(sizeof(struct scan_node));
                    cur_node = cur_node->next;
                    cur_node->value = mem_value;
                    cur_node->type = type;
                    cur_node->next = NULL;
                    if (type == Tstring) {
                        size_t buf_len = strlen(extra_param.Tstring);
                        cur_node->value.Tstring = malloc(buf_len + 1);
                        strncpy(cur_node->value.Tstring, extra_param.Tstring, buf_len); // We can copy the param instead of memory since != and exists are disallowed
                    }

                    printf("found value at 0x%8lx\n", addr + offset);
                }
            }
        }
    }

    // Report to the user the result of the initial scan
    if (head.next == NULL) {
        printf("failed to find any memory values matching the condition! aborting scan\n");
    }
    else {
        unsigned long node_count = 0;
        struct scan_node* cur_node = head.next;
        while (cur_node != NULL) {
            node_count += 1;
            cur_node = cur_node->next;
        }
        printf("found %lu matching values (%lu pages)\n", node_count, node_count / 10);
    }
    printf("\n");

    return head.next;
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
            printf("due to memory limiations, 'exists' and '==' are not available to 'string' in 'find' (but are in 'refine')\n");
        }
        else if (strcmp(sub_cmd, "finish") == 0) {
            printf("finish - finishes the ongoing memory scan\n");
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
        printf("finish - finishes the ongoing memory scan\n");
        printf("help - issues a help statement - use 'help x' to find more about the command 'x'\n");
        printf("quit - exits the program\n");
    }
}
