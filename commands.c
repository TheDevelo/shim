#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <syscall.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include "commands.h"
#include "helpers.h"

const char* TYPE_STR[Tinvalid + 1] = {
    [Tbyte] = "byte",
    [Tshort] = "short",
    [Tint] = "int",
    [Tlong] = "long",
    [Tubyte] = "ubyte",
    [Tushort] = "ushort",
    [Tuint] = "uint",
    [Tulong] = "ulong",
    [Tfloat] = "float",
    [Tdouble] = "double",
    [Tptr] = "ptr",
    [Tstring] = "string",
    [Tinvalid] = "invalid",
};

// Global vars for easy syscall scanning
static char* syscall_scan_cmd = "find ushort x where x == 1295"; // 1295 = 0x050f = syscall instruction in x86_64. Assume that we are running on x86_64 for simplicity
static struct scan_config syscall_scan_config = { .scan_pid = 0, .skip_files = 0, .debug = 0, .syscall_scan = 1, .in_core_only = 0 };

// Also coopted by monitor to find a syscall_addr
struct scan_list find_cmd(char* input, struct scan_config config) {
    struct scan_list result = { .head = NULL, .type = Tinvalid };

    // Parse the find command
    char type_str[32];
    char cond_str[32];
    char extra_param_str[256];
    int matched = sscanf(input, "find %32s x where x %32s %256s", type_str, cond_str, extra_param_str);
    if (matched != 2 && matched != 3) {
        printf("invalid 'find' command\n");
        return result;
    }
    enum scan_type type = str_to_type(type_str);
    if (type == Tinvalid) {
        printf("invalid type specified\n");
        return result;
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
            return result;
        default:
    }
    if (type == Tstring) {
        // Disallow all but Ceq for strings
        if (cond != Ceq) {
            printf("invalid condition specified - only valid condition for string in 'find' is ==\n");
            return result;
        }
        // Rescan input if string to force quotes and include whitespace in the following string
        matched = sscanf(input, "find string x where x %32s '%256[^'\n]'", cond_str, extra_param_str);
        matched += 1; // Adjust up by one since we didn't match the type in the retry
        if (matched != 3) {
            printf("invalid condition specified - wrap your string in single quotes\n");
            return result;
        }
        // Must actually specify some kind of string
        if (strlen(extra_param_str) == 0) {
            printf( "invalid condition specified - provide a non-empty string\n");
            return result;
        }
    }
    union scan_value extra_param;
    if (cond == Cexists) {
        if (matched == 3) {
            printf("invalid condition specified - exists does not need an extra parameter\n");
            return result;
        }
    }
    else {
        if (matched == 2) {
            printf("invalid condition specified - %s requires an extra parameter\n", cond_str);
            return result;
        }
        extra_param = parse_value(extra_param_str, type);
    }

    // Get syscall_addr if we are using ptrace for in_core_only.
    // We do this scan every time since the scan pid may change, thus changing where syscall_addr may lie
    unsigned long syscall_addr;
    if (config.in_core_only) {
        syscall_scan_config.scan_pid = config.scan_pid;
        void* syscall_addr_ptr = find_cmd(syscall_scan_cmd, syscall_scan_config).head;
        if (syscall_addr_ptr == NULL) {
            printf("failed to find a syscall instruction\n");
            return result;
        }
        syscall_addr = (unsigned long) syscall_addr_ptr;
    }

    // Open the child's memory and the memory maps
    char file_path[256];
    snprintf(file_path, 256, "/proc/%d/maps", config.scan_pid);
    FILE* maps = fopen(file_path, "r");
    if (maps == NULL) {
        perror("failed to open the /proc/PID/maps file");
        return result;
    }
    snprintf(file_path, 256, "/proc/%d/mem", config.scan_pid);
    int memory_fd = open(file_path, O_RDWR);
    if (memory_fd == -1) {
        perror("failed to open the /proc/PID/mem file");
        fclose(maps);
        return result;
    }

    // Scan each memory mapped region and construct a list of values
    char* mmap_line = NULL;
    size_t mmap_len = 0;
    struct scan_node head = { .value.Tptr = NULL, .next = NULL };
    struct scan_node* cur_node = &head;
    unsigned long node_count = 0;
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
            return result;
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

        // SKip non-executable sections if scanning for syscalls
        if (config.syscall_scan && perms[2] != 'x') {
            continue;
        }

        // Get which pages are in core using mincore
        // Don't use mincore on files since they will have data whether they've been paged or not
        unsigned long pages = (end_addr - start_addr) / 4096;
        char in_core[pages];
        if (config.in_core_only && inode == 0) {
            // Attach the ptrace instance and wait for execution to stop
            if (ptrace(PTRACE_ATTACH, config.scan_pid, NULL, NULL) == -1) {
                perror("failed to initiate ptrace()");
                fclose(maps);
                close(memory_fd);
                return result;
            }
            siginfo_t wait_info;
            waitid(P_PID, config.scan_pid, &wait_info, WSTOPPED);

            // Get the stack pointer to use as a short buffer for mincore
            // Tried using mmap to allocate new memory instead, but could not get the mmap call to go through
            struct user_regs_struct regs;
            ptrace(PTRACE_GETREGS, config.scan_pid, 0, &regs);
            unsigned long mincore_buffer = regs.rsp - pages;

            // Inject mincore to get which pages are in core
            unsigned long long syscall_retv;
            if (inject_syscall(&syscall_retv, config.scan_pid, syscall_addr, __NR_mincore, start_addr, end_addr - start_addr, mincore_buffer, 0, 0, 0) == -1) {
                printf("failed to inject mincore() syscall to find paged addresses\n");
                ptrace(PTRACE_DETACH, config.scan_pid, 0, 0);
                fclose(maps);
                close(memory_fd);
                return result;
            }

            // Read mincore buffer into our own buffer
            if (lseek(memory_fd, mincore_buffer, SEEK_SET) == -1) {
                perror("could not lseek() in the memory file");
                ptrace(PTRACE_DETACH, config.scan_pid, 0, 0);
                fclose(maps);
                close(memory_fd);
                return result;
            }
            int read_offset = 0;
            while (read_offset < pages) {
                int retv = read(memory_fd, &in_core[read_offset], pages - read_offset);
                if (retv == -1) {
                    perror("failed to read() from memory file");
                    ptrace(PTRACE_DETACH, config.scan_pid, 0, 0);
                    fclose(maps);
                    close(memory_fd);
                    return result;
                }
                read_offset += retv;
            }

            // Detach the ptrace instance
            ptrace(PTRACE_DETACH, config.scan_pid, 0, 0);
        }
        else {
            memset(in_core, 1, pages);
        }

        if (config.debug) {
            int n = 0;
            for (int i = 0; i < pages; i++) {
                if (in_core[i] == 1) {
                    n += 1;
                }
            }
            printf("%d of %lu in core for %lx-%lx (%s)\n", n, pages, start_addr, end_addr, file_name);
        }

        // Search the mapped memory page by page
        // To accomadate strings across page boundaries, we have a weird scanning scheme:
        // We read the next page into memory before scanning the current page, so that any overflows go onto the next page
        char page[2*READ_BUF_SIZE];
        if (lseek(memory_fd, start_addr, SEEK_SET) == -1) {
            perror("could not lseek() in the memory file");
            fclose(maps);
            close(memory_fd);
            return result;
        }
        if (read(memory_fd, &page[READ_BUF_SIZE], READ_BUF_SIZE) == -1) {
            perror("failed to read() from memory file");
            printf("skipping %lx-%lx (%s) due to read failure\n", start_addr, end_addr, file_name);
            continue;
        }

        for (unsigned long addr = start_addr; addr < end_addr; addr += READ_BUF_SIZE) {
            // Load our next page ahead
            memcpy(page, &page[READ_BUF_SIZE], READ_BUF_SIZE);
            unsigned long addr_page = (addr - start_addr) / 4096;
            if (addr + READ_BUF_SIZE < end_addr && in_core[addr_page + 1]) {
                if (read(memory_fd, &page[READ_BUF_SIZE], READ_BUF_SIZE) == -1) {
                    perror("failed to read() from memory file");
                    printf("skipping %lx-%lx (%s) due to read failure\n", start_addr, end_addr, file_name);
                    break;
                }
            }
            else {
                memset(&page[READ_BUF_SIZE], 0, READ_BUF_SIZE);
                // lseek as well since we may be skipping over a page if its not in core
                if (lseek(memory_fd, READ_BUF_SIZE, SEEK_CUR) == -1) {
                    perror("could not lseek() in the memory file");
                    fclose(maps);
                    close(memory_fd);
                    return result;
                }
            }

            // Skip page if not in core
            if (!in_core[addr_page]) {
                continue;
            }

            // Scan the previous page
            for (unsigned long offset = 0; offset < READ_BUF_SIZE; offset += type_step(type)) {
                void* mem_ptr = (void*) &page[offset];
                union scan_value mem_value = mem_to_value(mem_ptr, type);
                if (satisfies_condition(mem_value, type, cond, extra_param)) {
                    // Special return for syscall scans
                    if (config.syscall_scan) {
                        result.head = (void*) (addr + offset);
                        return result;
                    }

                    // Save the address to the scan list
                    cur_node->next = malloc(sizeof(struct scan_node));
                    cur_node = cur_node->next;
                    cur_node->value = mem_value;
                    cur_node->addr = (void*) (addr + offset);
                    cur_node->next = NULL;
                    if (type == Tstring) {
                        size_t buf_len = strlen(extra_param.Tstring);
                        cur_node->value.Tstring = malloc(buf_len + 1);
                        strncpy(cur_node->value.Tstring, extra_param.Tstring, buf_len); // We can copy the param instead of memory since != and exists are disallowed
                    }
                    node_count += 1;
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
        printf("found %lu matching values (%lu pages)\n", node_count, (node_count - 1) / 10 + 1);
    }
    printf("\n");

    result.head = head.next;
    result.type = type;
    return result;
}

struct scan_list refine_cmd(char* input, struct scan_config config, struct scan_list list) {
    // Parse the refine command
    char cond_str[32];
    char extra_param_str[256];
    int matched = sscanf(input, "refine x %32s %256s", cond_str, extra_param_str);
    if (matched != 1 && matched != 2) {
        printf("invalid 'refine' command\n");
        return list;
    }
    enum scan_cond cond = str_to_cond(cond_str);
    if (cond == Cinvalid) {
        printf("invalid condition specified\n");
        return list;
    }

    enum scan_type type = list.type;
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
                return list;
            default:
        }
        // Rescan input if string to force quotes and include whitespace in the following string
        matched = sscanf(input, "refine x %32s '%256[^'\n]'", cond_str, extra_param_str);
    }
    // Verify if an extra param is necesssary, and if so parse
    union scan_value extra_param;
    switch (cond) {
        case Cexists:
        case Csame:
        case Cdiff:
        case Cabove:
        case Cbelow:
            if (matched != 1) {
                printf("invalid condition specified - %s does not need an extra parameter\n", cond_str);
                return list;
            }
            break;
        case Ceq:
        case Cneq:
        case Cgreater:
        case Cless:
        case Cgeq:
        case Cleq:
        default:
            if (type == Tstring) {
                if (matched != 2) {
                    printf("invalid condition specified - wrap your string in single quotes\n");
                    return list;
                }
                // Must actually specify some kind of string
                if (strlen(extra_param_str) == 0) {
                    printf("invalid condition specified - provide a non-empty string\n");
                    return list;
                }
            }
            else {
                if (matched != 2) {
                    printf("invalid condition specified - %s requires an extra parameter\n", cond_str);
                    return list;
                }
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
        list.head = NULL;
        return list;
    }

    // Scan on each entry in the result list
    struct scan_node head = { .value.Tptr = NULL, .addr = NULL, .next = list.head };
    struct scan_node* parent = &head;
    struct scan_node* cur = list.head;
    unsigned long node_count = 0;
    char page_cache[READ_BUF_SIZE + 1];
    unsigned long cache_addr = 0;
    while (cur != NULL) {
        // Read the memory value at the specified address
        int read_size = 0;
        if (type == Tstring) {
            read_size = strlen(cur->value.Tstring);
            page_cache[read_size] = '\0'; // Add null-terminator
        }

        // Use a page cache for non-strings. Don't need to check if address is below cache since the list is ordered by address
        // For strings, variables are set up for a normal buffer read
        int cache_miss = 1;
        unsigned long read_addr = (unsigned long) cur->addr;
        char* mem_buf = page_cache;
        if (type != Tstring && read_addr >= cache_addr + READ_BUF_SIZE) {
            // Set read_addr to read the appropriate page in order to not possibly overflow into a non-readable page
            cache_miss = 1;
            mem_buf = &page_cache[read_addr & 0xfff]; // In case first miss is not the first address of page, need to move mem_buf into middle of cache
            read_addr &= ~0xfff;
            read_size = READ_BUF_SIZE;
            cache_addr = read_addr;
        }
        else if (type != Tstring) {
            // Update pointer to appropriate location in cache
            cache_miss = 0;
            mem_buf = &page_cache[read_addr - cache_addr];
        }

        if (cache_miss) {
            if (lseek(memory_fd, read_addr, SEEK_SET) == -1) {
                perror("could not lseek() in the memory file, aborting scan");
                close(memory_fd);
                list.head = NULL;
                return list;
            }

            if (read(memory_fd, page_cache, read_size) == -1) {
                // Failed to read address from file, remove from the list
                printf("failed to read at 0x%p, removing\n", cur->addr);
                cur = free_node(cur, type);
                parent->next = cur;
                continue;
            }
        }

        // Test value against condition
        union scan_value read_value = mem_to_value(mem_buf, type);
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
            if (type == Tstring) {
                free(cur->value.Tstring);
                cur->value.Tstring = malloc(read_size + 1);
                strncpy(cur->value.Tstring, read_value.Tstring, read_size);
            }
            else {
                cur->value = read_value;
            }
            parent = cur;
            cur = cur->next;
            node_count += 1;
        }
        else {
            // Remove the node from the scan list
            cur = free_node(cur, type);
            parent->next = cur;
        }
    }
    close(memory_fd);

    // Report to the user the result of the initial scan
    if (head.next == NULL) {
        printf("failed to find any memory values matching the condition! aborting scan\n");
    }
    else {
        printf("found %lu matching values (%lu pages)\n", node_count, (node_count - 1) / 10 + 1);
    }
    printf("\n");

    list.head = head.next;
    return list;
}

void page_cmd(char* input, struct scan_config config, struct scan_list list) {
    // Parse the page command
    unsigned int page_num;
    if (sscanf(input, "page %u", &page_num) != 1) {
        printf("invalid 'page' command\n");
        return;
    }
    if (page_num < 1) {
        printf("invalid 'page' command - page must be at least 1\n");
        return;
    }
    page_num -= 1; // Want to start the pages at page 1

    struct scan_node* cur_node = list.head;
    for (int i = 0; i < page_num * 10; i++) {
        cur_node = cur_node->next;
        if (cur_node == NULL) {
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
        int read_size = type_step(list.type);
        if (list.type == Tstring) {
            read_size = strlen(cur_node->value.Tstring);
        }
        char read_buf[read_size + 1];
        read_buf[read_size] = '\0'; // Add null-terminator for strings
        if (lseek(memory_fd, (unsigned long) cur_node->addr, SEEK_SET) == -1) {
            perror("could not lseek() in the memory file");
            close(memory_fd);
            return;
        }

        char* cur_value_str;
        if (read(memory_fd, read_buf, read_size) == -1) {
            // Failed to read, so specify to the user
            cur_value_str = "INVALID";
        }
        else {
            // Convert read value into appropriate string
            union scan_value read_value = mem_to_value(&read_buf, list.type);
            cur_value_str = value_to_str(read_value, list.type, cur_value_buf, 256);
        }

        // Display the desired info
        printf("%d: %p - %s - %s\n", page_num * 10 + i, cur_node->addr,
                value_to_str(cur_node->value, list.type, scan_value_buf, 256),
                cur_value_str);

        cur_node = cur_node->next;
        if (cur_node == NULL) {
            break;
        }
    }

    close(memory_fd);
}

struct save_node* save_cmd(char* input, struct scan_config config, struct scan_list list) {
    // Parse the save command
    unsigned int entry_num;
    if (sscanf(input, "save %u", &entry_num) != 1) {
        printf("invalid 'save' command\n");
        return NULL;
    }
    if (entry_num < 1) {
        printf("invalid 'save' command - entry must be at least 1\n");
        return NULL;
    }

    // Retrieve the specified entry
    struct scan_node* cur_node = list.head;
    for (int i = 1; i < entry_num; i++) {
        cur_node = cur_node->next;
        if (cur_node == NULL) {
            printf("invalid 'save' command - entry does not exist\n");
            return NULL;
        }
    }

    // Create and return the save node
    struct save_node* result = malloc(sizeof(struct save_node));
    result->type = list.type;
    result->addr = cur_node->addr;
    result->count = 1;
    result->next = NULL;
    if (list.type == Tstring) {
        result->count = strlen(cur_node->value.Tstring);
    }
    return result;
}

struct save_node* saveaddr_cmd(char* input) {
    // Parse the saveaddr command
    unsigned long address;
    unsigned int length = 1;
    char type_str[32];
    if (sscanf(input, "saveaddr 0x%lx as %32s", &address, type_str) != 2) {
        printf("invalid 'saveaddr' command\n");
        return NULL;
    }
    enum scan_type type = str_to_type(type_str);
    if (type == Tinvalid) {
        printf("invalid 'saveaddr' command - TYPE must be a valid type\n");
        return NULL;
    }
    else if (type == Tstring) {
        // Special handling for strings
        if (sscanf(input, "saveaddr 0x%lx as string of %u", &address, &length) != 2) {
            printf("invalid 'saveaddr' command - string length must also be specified\n");
            return NULL;
        }
    }

    // Create and return the save node
    struct save_node* result = malloc(sizeof(struct save_node));
    result->type = type;
    result->addr = (void*) address;
    result->count = length;
    result->next = NULL;
    return result;
}

void display_cmd(struct scan_config config, struct save_node* list) {
    // Open the memory file for reading
    char file_path[256];
    snprintf(file_path, 256, "/proc/%d/mem", config.scan_pid);
    int memory_fd = open(file_path, O_RDWR);
    if (memory_fd == -1) {
        perror("failed to open the /proc/PID/mem file");
        return;
    }

    // Print each element of the save list
    char cur_value_buf[256];
    int entry = 1;
    printf("entry number: address - type - current value\n");
    while (list != NULL) {
        // Read the memory value at the specified address
        int read_size = type_step(list->type) * list->count;
        char read_buf[read_size + 1];
        read_buf[read_size] = '\0'; // Add null-terminator for strings
        if (lseek(memory_fd, (unsigned long) list->addr, SEEK_SET) == -1) {
            perror("could not lseek() in the memory file");
            close(memory_fd);
            return;
        }

        char* cur_value_str;
        if (read(memory_fd, read_buf, read_size) == -1) {
            // Failed to read, so specify to the user
            cur_value_str = "INVALID";
        }
        else {
            // Convert read value into appropriate string
            union scan_value read_value = mem_to_value(&read_buf, list->type);
            cur_value_str = value_to_str(read_value, list->type, cur_value_buf, 256);
        }

        // Display the desired info
        printf("#%d: %p - %s - %s\n", entry, list->addr, TYPE_STR[list->type], cur_value_str);

        list = list->next;
        entry += 1;
    }

    close(memory_fd);
}

void modify_cmd(char* input, struct scan_config config, struct save_node* list) {
    // Parse the modify command
    unsigned int entry_num;
    char value_str[256];
    if (sscanf(input, "modify #%u %256s", &entry_num, value_str) != 2) {
        printf("invalid 'modify' command\n");
        return;
    }
    if (entry_num < 1) {
        printf("invalid 'modify' command - entry must be at least 1\n");
        return;
    }

    // Get the specified entry
    for (int i = 1; i < entry_num; i++) {
        list = list->next;
        if (list == NULL) {
            printf("invalid 'modify' command - specified entry does not exist\n");
            return;
        }
    }
    if (list == NULL) {
        printf("invalid 'modify' command - specified entry does not exist\n");
        return;
    }
    int value_count = list->count;

    // Special string handling
    if (list->type == Tstring) {
        if (sscanf(input, "modify #%u '%256[^'\n]'", &entry_num, value_str) != 2) {
            printf("invalid 'modify' command - wrap your string in single quotes\n");
            return;
        }
        int value_strlen = strlen(value_str);
        if (value_strlen < list->count) {
            printf("new string value is shorter than expected - writing fewer bytes\n");
            value_count = value_strlen;
        }
        else if (value_strlen > list->count) {
            printf("new string value is longer than expected - truncating string\n");
        }
    }
    union scan_value value = parse_value(value_str, list->type);

    // Open the memory file for writing
    char file_path[256];
    snprintf(file_path, 256, "/proc/%d/mem", config.scan_pid);
    int memory_fd = open(file_path, O_RDWR);
    if (memory_fd == -1) {
        perror("failed to open the /proc/PID/mem file");
        return;
    }

    // Write the memory value at the specified address
    int write_size = type_step(list->type) * value_count;
    if (lseek(memory_fd, (unsigned long) list->addr, SEEK_SET) == -1) {
        perror("could not lseek() in the memory file");
        close(memory_fd);
        return;
    }
    void* write_ptr = &value;
    if (list->type == Tstring) {
        write_ptr = value.Tstring;
    }
    if (write(memory_fd, write_ptr, write_size) != write_size) {
        perror("failed to write() at the memory address");
        close(memory_fd);
        return;
    }

    close(memory_fd);
}

void monitor_cmd(char* input, struct scan_config config, struct save_node* list) {
    // Parse the modify command
    unsigned int entry_num;
    if (sscanf(input, "monitor #%u", &entry_num) != 1) {
        printf("invalid 'monitor' command\n");
        return;
    }
    if (entry_num < 1) {
        printf("invalid 'monitor' command - entry must be at least 1\n");
        return;
    }

    // Get the specified entry
    for (int i = 1; i < entry_num; i++) {
        list = list->next;
        if (list == NULL) {
            printf("invalid 'monitor' command - specified entry does not exist\n");
            return;
        }
    }
    if (list == NULL) {
        printf("invalid 'monitor' command - specified entry does not exist\n");
        return;
    }

    // Get syscall_addr. We do this scan every time since the scan pid may change, thus changing where syscall_addr may lie
    syscall_scan_config.scan_pid = config.scan_pid;
    void* syscall_addr_ptr = find_cmd(syscall_scan_cmd, syscall_scan_config).head;
    if (syscall_addr_ptr == NULL) {
        printf("failed to find a syscall instruction\n");
        return;
    }
    unsigned long syscall_addr = (unsigned long) syscall_addr_ptr;

    // Open the memory map file
    char file_path[256];
    snprintf(file_path, 256, "/proc/%d/maps", config.scan_pid);
    FILE* maps = fopen(file_path, "r");
    if (maps == NULL) {
        perror("failed to open the /proc/PID/maps file");
        return;
    }

    // Get the permissions for the address we are looking for
    char* mmap_line = NULL;
    size_t mmap_len = 0;
    char perms[4];
    int found_perms = 0;
    while (getline(&mmap_line, &mmap_len, maps) != -1) {
        // Partially parse the memory map line
        unsigned long start_addr;
        unsigned long end_addr;

        int matched = sscanf(mmap_line, "%lx-%lx %4c", &start_addr, &end_addr, perms);
        if (matched != 3 && matched != 8) {
            printf("malformed memory map file\n");
            fclose(maps);
            return;
        }

        if ((unsigned long) list->addr >= start_addr && (unsigned long) list->addr < end_addr) {
            found_perms = 1;
            break;
        }
    }
    fclose(maps);
    if (!found_perms) {
        printf("failed to find the /proc/PID/maps line for the specified entry\n");
        return;
    }
    int orig_perms = 0;
    if (perms[0] == 'r') {
        orig_perms |= PROT_READ;
    }
    if (perms[1] == 'w') {
        orig_perms |= PROT_WRITE;
    }
    if (perms[2] == 'x') {
        orig_perms |= PROT_EXEC;
    }
    if (orig_perms == 0) {
        orig_perms = PROT_NONE;
    }

    // Attach the ptrace instance and wait for execution to stop
    if (ptrace(PTRACE_ATTACH, config.scan_pid, NULL, NULL) == -1) {
        perror("failed to initiate ptrace()");
        return;
    }
    siginfo_t wait_info;
    waitid(P_PID, config.scan_pid, &wait_info, WSTOPPED);

    // Inject mprotect to disable read & writes on the entry's address
    unsigned long long syscall_retv;
    unsigned long page_start = (unsigned long) list->addr & ~0xfff;
    unsigned long length = (unsigned long) list->addr - page_start + type_step(list->type) * list->count;
    unsigned long page_end = (page_start + length + 4095) & ~0xfff;
    if (inject_syscall(&syscall_retv, config.scan_pid, syscall_addr, __NR_mprotect, page_start, length, PROT_NONE, 0, 0, 0) == -1) {
        printf("failed to inject mprotect() syscall to remove permissions\n");
        ptrace(PTRACE_DETACH, config.scan_pid, 0, 0);
        return;
    }

    printf("Press enter to finish monitoring\n");
    // Spawn child that dies when stdin is readable (signals to monitoring thread to stop)
    pid_t pid = fork();
    if (pid == 0) {
        char* line = NULL;
        size_t len = 0;
        getline(&line, &len, stdin);
        if (line != NULL) {
            free(line);
        }
        exit(0);
    }

    // Monitor loop
    ptrace(PTRACE_CONT, config.scan_pid, NULL, NULL);
    while (1) {
        waitid(P_ALL, 0, &wait_info, WSTOPPED | WEXITED);
        if (wait_info.si_pid == pid) {
            // stdin child died, signals to stop monitoring
            break;
        }
        else if (wait_info.si_pid == config.scan_pid) {
            // Caught SEGFAULT, note info and retry instruction with correct permissions
            if (wait_info.si_code == CLD_TRAPPED && wait_info.si_status == SIGSEGV) {
                // Check if the faulting address is the one we are monitoring
                ptrace(PTRACE_GETSIGINFO, config.scan_pid, 0, &wait_info);
                if (wait_info.si_addr == list->addr) {
                    // Record the address that tripped the monitor
                    struct user_regs_struct saved_regs;
                    ptrace(PTRACE_GETREGS, config.scan_pid, 0, &saved_regs);

                    // Check if the tripping instruction is a read, write, or exec by restoring the
                    // permissions one by one until we successfully execute the desired instruction
                    int found_cause = 0;
                    if (orig_perms & PROT_READ) {
                        // Restore read permissions to page and re-execute
                        if (inject_syscall(&syscall_retv, config.scan_pid, syscall_addr, __NR_mprotect, page_start, length, PROT_READ, 0, 0, 0) == -1) {
                            printf("failed to inject mprotect() syscall to restore permissions\n");
                            ptrace(PTRACE_DETACH, config.scan_pid, 0, 0);
                            return;
                        }
                        ptrace(PTRACE_SINGLESTEP, config.scan_pid, NULL, NULL);
                        waitid(P_PID, config.scan_pid, &wait_info, WSTOPPED);

                        // Check if we successfully executed or SEGFAULTed again
                        if (wait_info.si_code == CLD_TRAPPED && wait_info.si_status != SIGSEGV) {
                            found_cause = 1;
                            printf("read intercepted at 0x%llx\n", saved_regs.rip);
                        }
                    }
                    if (!found_cause && orig_perms & PROT_WRITE) {
                        // Restore write permissions to page and re-execute
                        if (inject_syscall(&syscall_retv, config.scan_pid, syscall_addr, __NR_mprotect, page_start, length, PROT_WRITE, 0, 0, 0) == -1) {
                            printf("failed to inject mprotect() syscall to restore permissions\n");
                            ptrace(PTRACE_DETACH, config.scan_pid, 0, 0);
                            return;
                        }
                        ptrace(PTRACE_SINGLESTEP, config.scan_pid, NULL, NULL);
                        waitid(P_PID, config.scan_pid, &wait_info, WSTOPPED);

                        // Check if we successfully executed or SEGFAULTed again
                        if (wait_info.si_code == CLD_TRAPPED && wait_info.si_status != SIGSEGV) {
                            found_cause = 1;
                            printf("write intercepted at 0x%llx\n", saved_regs.rip);
                        }
                    }
                    if (!found_cause && orig_perms & PROT_EXEC) {
                        // Restore exec permissions to page and re-execute
                        // The executing instruction may also read or write, so just restore to original perms (already checked read and write)
                        if (inject_syscall(&syscall_retv, config.scan_pid, syscall_addr, __NR_mprotect, page_start, length, orig_perms, 0, 0, 0) == -1) {
                            printf("failed to inject mprotect() syscall to restore permissions\n");
                            ptrace(PTRACE_DETACH, config.scan_pid, 0, 0);
                            return;
                        }
                        ptrace(PTRACE_SINGLESTEP, config.scan_pid, NULL, NULL);
                        waitid(P_PID, config.scan_pid, &wait_info, WSTOPPED);

                        // Check if we successfully executed or SEGFAULTed again
                        if (wait_info.si_code == CLD_TRAPPED && wait_info.si_status != SIGSEGV) {
                            found_cause = 1;
                            printf("exec intercepted at 0x%llx\n", saved_regs.rip);
                        }
                    }

                    // Remove permissions for future monitoring events
                    if (inject_syscall(&syscall_retv, config.scan_pid, syscall_addr, __NR_mprotect, page_start, length, PROT_NONE, 0, 0, 0) == -1) {
                        printf("failed to inject mprotect() syscall to remove permissions\n");
                        ptrace(PTRACE_DETACH, config.scan_pid, 0, 0);
                        return;
                    }

                    // Resume execution
                    // If we can't find the cause, must be real SEGFAULT, so forward
                    if (!found_cause) {
                        printf("failed to find cause of SEGFAULT for monitored instruction\n");
                        ptrace(PTRACE_CONT, config.scan_pid, NULL, SIGSEGV);
                    }
                    else {
                        ptrace(PTRACE_CONT, config.scan_pid, NULL, NULL);
                    }
                }
                else if ((unsigned long) wait_info.si_addr >= page_start && (unsigned long) wait_info.si_addr < page_end) {
                    // Caught address is in affected page but is not monitored
                    // Restore permissions to the given page
                    if (inject_syscall(&syscall_retv, config.scan_pid, syscall_addr, __NR_mprotect, page_start, length, orig_perms, 0, 0, 0) == -1) {
                        printf("failed to inject mprotect() syscall to restore permissions\n");
                        ptrace(PTRACE_DETACH, config.scan_pid, 0, 0);
                        return;
                    }

                    // Re-execute the failed instruction
                    ptrace(PTRACE_SINGLESTEP, config.scan_pid, NULL, NULL);
                    waitid(P_PID, config.scan_pid, &wait_info, WSTOPPED);

                    // Remove permissions for future monitoring events
                    if (inject_syscall(&syscall_retv, config.scan_pid, syscall_addr, __NR_mprotect, page_start, length, PROT_NONE, 0, 0, 0) == -1) {
                        printf("failed to inject mprotect() syscall to remove permissions\n");
                        ptrace(PTRACE_DETACH, config.scan_pid, 0, 0);
                        return;
                    }

                    // Resume execution
                    // If we SEGFAULTed again, must be real SEGFAULT, so forward
                    if (wait_info.si_code == CLD_TRAPPED && wait_info.si_status == SIGSEGV) {
                        printf("natural SEGFAULT occurred, forwarding to the tracee\n");
                        ptrace(PTRACE_CONT, config.scan_pid, NULL, SIGSEGV);
                    }
                    else {
                        ptrace(PTRACE_CONT, config.scan_pid, NULL, NULL);
                    }
                }
                else {
                    // Lies outside the pages we are monitoring, so pass SEGFAULT back to process
                    printf("natural SEGFAULT occurred, forwarding to the tracee\n");
                    ptrace(PTRACE_CONT, config.scan_pid, NULL, SIGSEGV);
                }
            }
            // Caught anything other than SEGFAULT, forward to the program
            else if (wait_info.si_code == CLD_TRAPPED) {
                ptrace(PTRACE_CONT, config.scan_pid, NULL, wait_info.si_status);
            }
            else {
                // If the child stops from anything other than ptrace, stop monitoring.
                break;
            }
        }
    }
    kill(pid, SIGTERM); // Kill stdin reader in case the monitor loop exists unnaturally

    // Return if the program was killed/exited naturally, printing out an appropriate message
    if (wait_info.si_pid == config.scan_pid && wait_info.si_code == CLD_EXITED) {
        printf("tracee exited with a status of %d\n", wait_info.si_status);
        return;
    }
    else if (wait_info.si_pid == config.scan_pid && wait_info.si_code == CLD_KILLED) {
        printf("tracee killed by signal %s\n", strsignal(wait_info.si_status));
        return;
    }
    else if (wait_info.si_pid == config.scan_pid && wait_info.si_code == CLD_DUMPED) {
        printf("tracee killed and coredumped by signal %s\n", strsignal(wait_info.si_status));
        return;
    }

    // Setup tracee for syscall injection by interrupting using a signal
    // The signal doesn't actually get sent through to the tracee as we singlestep afterwards without forwarding
    kill(config.scan_pid, SIGTERM);
    ptrace(PTRACE_SINGLESTEP, config.scan_pid, NULL, NULL);
    waitid(P_PID, config.scan_pid, &wait_info, WSTOPPED | WEXITED);

    // Restore permissions to the given page
    if (inject_syscall(&syscall_retv, config.scan_pid, syscall_addr, __NR_mprotect, page_start, length, orig_perms, 0, 0, 0) == -1) {
        printf("failed to inject mprotect() syscall to restore permissions\n");
        ptrace(PTRACE_DETACH, config.scan_pid, 0, 0);
        return;
    }

    // Detach the process to end ptrace tracing
    ptrace(PTRACE_DETACH, config.scan_pid, NULL, NULL);
}

void lookup_cmd(char* input, struct scan_config config) {
    // Parse the lookup command
    unsigned long address;
    if (sscanf(input, "lookup 0x%lx", &address) != 1) {
        printf("invalid 'lookup' command\n");
        return;
    }

    // Open the memory map file
    char file_path[256];
    snprintf(file_path, 256, "/proc/%d/maps", config.scan_pid);
    FILE* maps = fopen(file_path, "r");
    if (maps == NULL) {
        perror("failed to open the /proc/PID/maps file");
        return;
    }

    // Get the permissions for the address we are looking for
    char* mmap_line = NULL;
    size_t mmap_len = 0;
    int matched = 0;
    int found_addr = 0;
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
            return;
        }

        if (address >= start_addr && address < end_addr) {
            printf("0x%lx located within %lx-%lx (%s)\n", address, start_addr, end_addr, file_name);
            if (inode != 0) {
                printf("corresponds to 0x%lx in file %s\n", address - start_addr + offset, file_name);
            }
            found_addr = 1;
            break;
        }
    }
    fclose(maps);

    if (!found_addr) {
        printf("failed to find address in /proc/PID/maps file\n");
    }
}

void help_cmd(char* input) {
    char sub_cmd[256];
    if (sscanf(input, "help %256s", sub_cmd) == 1) {
        // Subcommand specified, print appropriate message
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
        else if (strcmp(sub_cmd, "page") == 0) {
            printf("save - saves a memory address found\n");
            printf("format: save X\n");
            printf("saves entry X (numbered in 'page') from the scan results for later use with 'display' and 'modify'\n");
        }
        else if (strcmp(sub_cmd, "finish") == 0) {
            printf("finish - finishes the ongoing memory scan\n");
        }
        else if (strcmp(sub_cmd, "saveaddr") == 0) {
            printf("saveaddr - saves a given memory address\n");
            printf("format: saveaddr 0xADDR as TYPE\n");
            printf("saves the address at 0xADDR to the saved address list as TYPE\n");
            printf("if TYPE is string, then a length must be specified using a special format:\n");
            printf("saveaddr 0xADDR as string of LENGTH\n");
        }
        else if (strcmp(sub_cmd, "display") == 0) {
            printf("display - displays all saved memory addresses\n");
        }
        else if (strcmp(sub_cmd, "modify") == 0) {
            printf("modify - changes the value of a saved memory address\n");
            printf("format: modify #X VAL\n");
            printf("writes VAL to the memory address of entry #X (as listed in 'display')\n");
        }
        else if (strcmp(sub_cmd, "monitor") == 0) {
            printf("monitor - monitors a saved memory address for reads and writes\n");
            printf("format: monitor #X\n");
            printf("monitors the address of entry #X for reads and writes\n");
        }
        else if (strcmp(sub_cmd, "lookup") == 0) {
            printf("lookup - finds the memory region for a given address\n");
            printf("format: lookup 0xADDR\n");
            printf("also finds the location within the backing file if the region is file-backed\n");
        }
        else if (strcmp(sub_cmd, "config") == 0) {
            printf("config - sets configuration\n");
            printf("format: config PARAM VALUE\n\n");

            printf("Available configuration parameters (and value):\n");
            printf("pid PID: sets the PID to scan\n");
            printf("skip_files VAL: sets whether to scan mapped files (VAL is a uint following C's truth rules)\n");
            printf("debug VAL: sets whether to print debug info such as timestamps (VAL is a uint following C's truth rules)\n");
            printf("in_core_only VAL: sets whether to skip memory pages that have not been used (VAL is a uint following C's truth rules)\n");
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
        // No subcommand specified, print summary for each command
        printf("find - searches for memory that matches specified conditions\n");
        printf("refine - refines the memory scan to match new conditions\n");
        printf("page - displays the current results of the ongoing memory scan\n");
        printf("save - saves a memory address found\n");
        printf("finish - finishes the ongoing memory scan\n");
        printf("saveaddr - saves a given memory address\n");
        printf("display - displays all saved memory addresses\n");
        printf("modify - changes the value of a saved memory address\n");
        printf("monitor - monitors a saved memory address for reads and writes\n");
        printf("lookup - finds the memory region for a given address\n");
        printf("config - sets configuration\n");
        printf("help - issues a help statement - use 'help x' to find more about the command 'x'\n");
        printf("quit - exits the program\n");
    }
}
