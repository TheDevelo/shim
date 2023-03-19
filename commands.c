#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include "commands.h"
#include "helpers.h"

struct scan_node* find_cmd(char* input, struct scan_config config) {
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
        // Must actually specify some kind of string
        if (strlen(extra_param_str) == 0) {
            printf( "invalid condition specified - provide a non-empty string\n");
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
    snprintf(file_path, 256, "/proc/%d/maps", config.scan_pid);
    FILE* maps = fopen(file_path, "r");
    if (maps == NULL) {
        perror("failed to open the /proc/PID/maps file");
        return NULL;
    }
    snprintf(file_path, 256, "/proc/%d/mem", config.scan_pid);
    int memory_fd = open(file_path, O_RDWR);
    if (memory_fd == -1) {
        perror("failed to open the /proc/PID/mem file");
        fclose(maps);
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

        matched = sscanf(mmap_line, "%lx-%lx %4c %lx %x:%x %u %4096[^\n]", &start_addr, &end_addr, perms, &offset, &major_id, &minor_id, &inode, file_name);
        if (matched != 7 && matched != 8) {
            printf("malformed memory map file\n");
            fclose(maps);
            close(memory_fd);
            return NULL;
        }

        // Ignore [vvar], [vdso], [vsyscall] given they're kernel mechanisms for syscall acceleration (aka not what we want to search)
        // Anyways, can't even read from [vvar] or [vsyscall]
        if (strcmp(file_name, "[vsyscall]") == 0 || strcmp(file_name, "[vdso]") == 0 || strcmp(file_name, "[vvar]") == 0) {
            continue;
        }

        // Skip files if skip_files is enabled
        if (config.skip_files && inode != 0) {
            continue;
        }

        // Search the mapped memory page by page
        // To accomadate strings across page boundaries, we have a weird scanning scheme:
        // We read the next page into memory before scanning the current page, so that any overflows go onto the next page
        char page[2*READ_BUF_SIZE];
        if (lseek(memory_fd, start_addr, SEEK_SET) == -1) {
            perror("could not lseek() in the memory file");
            fclose(maps);
            close(memory_fd);
            return NULL;
        }
        if (read(memory_fd, &page[READ_BUF_SIZE], READ_BUF_SIZE) == -1) {
            perror("failed to read() from memory file");
            printf("skipping %lx-%lx (%s) due to read failure\n", start_addr, end_addr, file_name);
            continue;
        }

        for (unsigned long addr = start_addr; addr < end_addr; addr += READ_BUF_SIZE) {
            // Load our next page ahead
            memcpy(page, &page[READ_BUF_SIZE], READ_BUF_SIZE);
            if (addr + READ_BUF_SIZE < end_addr) {
                if (read(memory_fd, &page[READ_BUF_SIZE], READ_BUF_SIZE) == -1) {
                    perror("failed to read() from memory file");
                    printf("skipping %lx-%lx (%s) due to read failure\n", start_addr, end_addr, file_name);
                    break;
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
                    cur_node->addr = (void*) (addr + offset);
                    cur_node->next = NULL;
                    if (type == Tstring) {
                        size_t buf_len = strlen(extra_param.Tstring);
                        cur_node->value.Tstring = malloc(buf_len + 1);
                        strncpy(cur_node->value.Tstring, extra_param.Tstring, buf_len); // We can copy the param instead of memory since != and exists are disallowed
                    }
                }
            }
        }
    }
    fclose(maps);
    close(memory_fd);

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
        printf("found %lu matching values (%lu pages)\n", node_count, (node_count - 1) / 10 + 1);
    }
    printf("\n");

    return head.next;
}

struct scan_node* refine_cmd(char* input, struct scan_config config, struct scan_node* result_list) {
    // Parse the refine command
    char cond_str[32];
    char extra_param_str[256];
    int matched = sscanf(input, "refine x %32s %256s", cond_str, extra_param_str);
    if (matched != 1 && matched != 2) {
        printf("invalid 'refine' command\n");
        return result_list;
    }
    enum scan_cond cond = str_to_cond(cond_str);
    if (cond == Cinvalid) {
        printf("invalid condition specified\n");
        return result_list;
    }
    // Get type from top of result_list, since we have the same type for the whole list
    enum scan_type type = result_list->type;
    if (type == Tstring) {
        // Disallow numeric conditions for strings
        switch (cond) {
            case Cgreater:
            case Cless:
            case Cgeq:
            case Cleq:
            case Cabove:
            case Cbelow:
                printf("invalid condition specified - don't use numeric conditions for strings\n");
                return result_list;
            default:
        }
        // Rescan input if string to force quotes and include whitespace in the following string
        matched = sscanf(input, "refine x %32s '%256[^'\n]'", cond_str, extra_param_str);
        if (matched != 2) {
            printf("invalid condition specified - wrap your string in single quotes\n");
            return result_list;
        }
        // Must actually specify some kind of string
        if (strlen(extra_param_str) == 0) {
            printf("invalid condition specified - provide a non-empty string\n");
            return result_list;
        }
    }
    union scan_value extra_param;
    switch (cond) {
        case Cexists:
        case Csame:
        case Cdiff:
        case Cabove:
        case Cbelow:
            if (matched != 1) {
                printf("invalid condition specified - %s does not need an extra parameter\n", cond_str);
                return result_list;
            }
            break;
        case Ceq:
        case Cneq:
        case Cgreater:
        case Cless:
        case Cgeq:
        case Cleq:
        default:
            if (matched != 2) {
                printf("invalid condition specified - %s requires an extra parameter\n", cond_str);
                return result_list;
            }
            extra_param = parse_value(extra_param_str, type);
            break;
    }


    // Open the memory file for reading
    char file_path[256];
    snprintf(file_path, 256, "/proc/%d/mem", config.scan_pid);
    int memory_fd = open(file_path, O_RDWR);
    if (memory_fd == -1) {
        perror("failed to open the /proc/PID/mem file, aborting scan");
        return NULL;
    }

    // Scan on each entry in the result list
    struct scan_node head = { .value.Tptr = NULL, .type = Tinvalid, .addr = NULL, .next = result_list };
    struct scan_node* parent = &head;
    struct scan_node* cur = result_list;
    while (cur != NULL) {
        // Read the memory value at the specified address
        int read_size = type_step(type);
        if (type == Tstring) {
            read_size = strlen(cur->value.Tstring);
        }
        char read_buf[read_size + 1];
        read_buf[read_size] = '\0'; // Add null-terminator for strings
        if (lseek(memory_fd, (unsigned long) cur->addr, SEEK_SET) == -1) {
            perror("could not lseek() in the memory file, aborting scan");
            close(memory_fd);
            return NULL;
        }

        if (read(memory_fd, read_buf, read_size) == -1) {
            // Failed to read address from file, remove from the list
            printf("failed to read at 0x%p, removing\n", cur->addr);
            cur = free_node(cur);
            parent->next = cur;
            continue;
        }

        // Test value against condition
        union scan_value read_value = mem_to_value(&read_buf, type);
        union scan_value cond_param;
        switch (cond) {
            case Ceq:
            case Cneq:
            case Cgreater:
            case Cless:
            case Cgeq:
            case Cleq:
                cond_param = extra_param;
                break;
            case Csame:
            case Cdiff:
            case Cabove:
            case Cbelow:
                cond_param = cur->value;
                break;
            case Cexists:
            default:
        }
        if (satisfies_condition(read_value, type, cond, cond_param)) {
            // Update the node's value
            cur->value = read_value;
            parent = cur;
            cur = cur->next;
        }
        else {
            cur = free_node(cur);
            parent->next = cur;
        }
    }
    close(memory_fd);

    // Report to the user the result of the initial scan
    if (head.next == NULL) {
        printf("failed to find any memory values matching the condition! aborting scan\n");
    }
    else {
        unsigned long node_count = 0;
        cur = head.next;
        while (cur != NULL) {
            node_count += 1;
            cur = cur->next;
        }
        printf("found %lu matching values (%lu pages)\n", node_count, (node_count - 1) / 10 + 1);
    }
    printf("\n");

    return head.next;
}

void page_cmd(char* input, struct scan_config config, struct scan_node* result_list) {
    unsigned int page_num;
    if (sscanf(input, "page %u", &page_num) != 1) {
        printf("invalid 'page' command\n");
        return;
    }
    page_num -= 1; // Want to start the pages at page 1

    for (int i = 0; i < page_num * 10; i++) {
        result_list = result_list->next;
        if (result_list == NULL) {
            printf("invalid 'page' command - page does not exist\n");
            return;
        }
    }

    // Open the memory file for reading
    char file_path[256];
    snprintf(file_path, 256, "/proc/%d/mem", config.scan_pid);
    int memory_fd = open(file_path, O_RDWR);
    if (memory_fd == -1) {
        perror("failed to open the /proc/PID/mem file");
        return;
    }

    char scan_value_buf[256];
    char cur_value_buf[256];
    printf("entry number: address - value at scan - current value\n");
    for (int i = 1; i <= 10; i++) {
        // Read the memory value at the specified address
        int read_size = type_step(result_list->type);
        if (result_list->type == Tstring) {
            read_size = strlen(result_list->value.Tstring);
        }
        char read_buf[read_size + 1];
        read_buf[read_size] = '\0'; // Add null-terminator for strings
        if (lseek(memory_fd, (unsigned long) result_list->addr, SEEK_SET) == -1) {
            perror("could not lseek() in the memory file");
            close(memory_fd);
            return;
        }

        char* cur_value_str;
        if (read(memory_fd, read_buf, read_size) == -1) {
            cur_value_str = "INVALID";
        }
        else {
            // Convert read value into appropriate string
            union scan_value read_value = mem_to_value(&read_buf, result_list->type);
            cur_value_str = value_to_str(read_value, result_list->type, cur_value_buf, 256);
        }

        // Display the desired info
        printf("%d: %p - %s - %s\n", page_num * 10 + i, result_list->addr,
                value_to_str(result_list->value, result_list->type, scan_value_buf, 256),
                cur_value_str);

        result_list = result_list->next;
        if (result_list == NULL) {
            break;
        }
    }

    close(memory_fd);
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

            printf("CONDITIONs available:\n");
            printf(">, <, >=, <=, ==, != - comparisons corresponding to the equivalent C comparison operator\n");
            printf("    these comparison all take an additional value (e.g. '== VAL') to compare to\n");
            printf("    >, <, >=, <= are only available to numeric types (i.e. not 'string'), while ==, != are available to all types\n");
            printf("exists - all memory passes this condition (useful when further refining with 'refine')\n");
            printf("due to memory limiations, 'exists' and '!=' are not available to 'string' in 'find' (but are in 'refine')\n");
        }
        else if (strcmp(sub_cmd, "refine") == 0) {
            printf("refine - refines the memory scan to match new conditions\n");
            printf("format: refine x CONDITION\n\n");

            printf("'find' produces a list of memory addresses that satisfy some specified condition\n");
            printf("'refine' can then be used to further scan through ONLY the list of addresses produced by 'find'\n");
            printf("note that 'refine' uses the same type as was used with 'find'\n");
            printf("additionally, 'refine' applies the condition on the memory's current value, not the value at the time of 'find'\n\n");

            printf("CONDITIONs available:\n");
            printf("in addition to the conditions listed in 'find', these following temporal conditions have been added\n");
            printf("same, diff, above, below - comparisons corresponding to ==, !=, >, <\n");
            printf("    these comparisons compare the current value of memory to the value at the last use of 'find' or 'refine'\n");
            printf("    just as their non-temporal counterparts, above and below can not be used with 'string'\n");
            printf("in addition to the new conditions, exists and != can now be used with 'string' (unlike with 'find')\n");
        }
        else if (strcmp(sub_cmd, "page") == 0) {
            printf("page - displays the current results of the ongoing memory scan\n");
            printf("format: page X\n");
            printf("Displays the 10 memory values on page X for the scan results (ordered by address)\n");
        }
        else if (strcmp(sub_cmd, "finish") == 0) {
            printf("finish - finishes the ongoing memory scan\n");
        }
        else if (strcmp(sub_cmd, "config") == 0) {
            printf("config - sets configuration\n");
            printf("format: config PARAM VALUE\n\n");

            printf("Available configuration parameters (and value):\n");
            printf("pid PID: sets the PID to scan\n");
            printf("skip_files VAL: sets whether to scan mapped files (VAL is a uint following C's truth rules)\n");
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
        printf("refine - refines the memory scan to match new conditions\n");
        printf("page - displays the current results of the ongoing memory scan\n");
        printf("finish - finishes the ongoing memory scan\n");
        printf("config - sets configuration\n");
        printf("help - issues a help statement - use 'help x' to find more about the command 'x'\n");
        printf("quit - exits the program\n");
    }
}
