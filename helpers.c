#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include "commands.h"
#include "helpers.h"

// Converts a string to its equivalent type enum value
enum scan_type str_to_type(char* type_str) {
    if (strcmp(type_str, "byte") == 0) {
        return Tbyte;
    }
    else if (strcmp(type_str, "short") == 0) {
        return Tshort;
    }
    else if (strcmp(type_str, "int") == 0) {
        return Tint;
    }
    else if (strcmp(type_str, "long") == 0) {
        return Tlong;
    }
    else if (strcmp(type_str, "ubyte") == 0) {
        return Tubyte;
    }
    else if (strcmp(type_str, "ushort") == 0) {
        return Tushort;
    }
    else if (strcmp(type_str, "uint") == 0) {
        return Tuint;
    }
    else if (strcmp(type_str, "ulong") == 0) {
        return Tulong;
    }
    else if (strcmp(type_str, "float") == 0) {
        return Tfloat;
    }
    else if (strcmp(type_str, "double") == 0) {
        return Tdouble;
    }
    else if (strcmp(type_str, "ptr") == 0) {
        return Tptr;
    }
    else if (strcmp(type_str, "string") == 0) {
        return Tstring;
    }
    else {
        return Tinvalid;
    }
}

// Converts a string to its equivalent condition enum value
enum scan_cond str_to_cond(char* cond_str) {
    if (strcmp(cond_str, "==") == 0) {
        return Ceq;
    }
    else if (strcmp(cond_str, "!=") == 0) {
        return Cneq;
    }
    else if (strcmp(cond_str, ">") == 0) {
        return Cgreater;
    }
    else if (strcmp(cond_str, "<") == 0) {
        return Cless;
    }
    else if (strcmp(cond_str, ">=") == 0) {
        return Cgeq;
    }
    else if (strcmp(cond_str, "<=") == 0) {
        return Cleq;
    }
    else if (strcmp(cond_str, "exists") == 0) {
        return Cexists;
    }
    else if (strcmp(cond_str, "same") == 0) {
        return Csame;
    }
    else if (strcmp(cond_str, "diff") == 0) {
        return Cdiff;
    }
    else if (strcmp(cond_str, "above") == 0) {
        return Cabove;
    }
    else if (strcmp(cond_str, "below") == 0) {
        return Cbelow;
    }
    else {
        return Cinvalid;
    }
}

// Gives size of a scan type, except for string (gives size of 1 character)
int type_step(enum scan_type type) {
    switch (type) {
        case Tbyte:
            return sizeof(signed char);
        case Tshort:
            return sizeof(signed short);
        case Tint:
            return sizeof(signed int);
        case Tlong:
            return sizeof(signed long);
        case Tubyte:
            return sizeof(unsigned char);
        case Tushort:
            return sizeof(unsigned short);
        case Tuint:
            return sizeof(unsigned int);
        case Tulong:
            return sizeof(unsigned long);
        case Tfloat:
            return sizeof(float);
        case Tdouble:
            return sizeof(double);
        case Tptr:
            return sizeof(void*);
        case Tstring:
            return sizeof(char);
        case Tinvalid:
        default:
            // This value doesn't really matter as we should NEVER have a case
            // where this function is called with Tinvalid, but keep it READ_BUF_SIZE
            // so that it skips over the full page as fast as possible in find.
            return READ_BUF_SIZE;
    }
}

// Parses a string to a scan_value union as the desired type
union scan_value parse_value(char* value_str, enum scan_type type) {
    union scan_value result;
    switch (type) {
        case Tbyte:
            sscanf(value_str, "%hhd", &result.Tbyte);
            break;
        case Tshort:
            sscanf(value_str, "%hd", &result.Tshort);
            break;
        case Tint:
            sscanf(value_str, "%d", &result.Tint);
            break;
        case Tlong:
            sscanf(value_str, "%ld", &result.Tlong);
            break;
        case Tubyte:
            sscanf(value_str, "%hhu", &result.Tubyte);
            break;
        case Tushort:
            sscanf(value_str, "%hu", &result.Tushort);
            break;
        case Tuint:
            sscanf(value_str, "%u", &result.Tuint);
            break;
        case Tulong:
            sscanf(value_str, "%lu", &result.Tulong);
            break;
        case Tfloat:
            sscanf(value_str, "%f", &result.Tfloat);
            break;
        case Tdouble:
            sscanf(value_str, "%lf", &result.Tdouble);
            break;
        case Tptr:
            sscanf(value_str, "%lx", &result.Tulong);
            result.Tptr = (void*) result.Tulong; // Probably does nothing as a union SHOULD just be the same for a pointer and unsigned long, but cast just to be sure
            break;
        case Tstring:
            result.Tstring = value_str;
            break;
        case Tinvalid:
            result.Tptr = NULL;
            break;
    }

    return result;
}

// Interprets the memory at mem as if it were the specified type, and then saves it to a scan_value union
union scan_value mem_to_value(void* mem, enum scan_type type) {
    union scan_value result;
    switch (type) {
        case Tbyte:
            result.Tbyte = *((signed char*) mem);
            break;
        case Tshort:
            result.Tshort = *((signed short*) mem);
            break;
        case Tint:
            result.Tint = *((signed int*) mem);
            break;
        case Tlong:
            result.Tlong = *((signed long*) mem);
            break;
        case Tubyte:
            result.Tubyte = *((unsigned char*) mem);
            break;
        case Tushort:
            result.Tushort = *((unsigned short*) mem);
            break;
        case Tuint:
            result.Tuint = *((unsigned int*) mem);
            break;
        case Tulong:
            result.Tulong = *((unsigned long*) mem);
            break;
        case Tfloat:
            result.Tfloat = *((float*) mem);
            break;
        case Tdouble:
            result.Tdouble = *((double*) mem);
            break;
        case Tptr:
            result.Tptr = *((void**) mem);
            break;
        case Tstring:
            result.Tstring = (char*) mem;
            break;
        case Tinvalid:
            result.Tptr = NULL;
            break;
    }

    return result;
}

// Converts a scan_value union to a string
// Return a char* since for Tstring we can just return the attached string buffer
// Avoids copying the string over to the output buffer
char* value_to_str(union scan_value value, enum scan_type type, char* output_buffer, size_t buf_len) {
    switch (type) {
        case Tbyte:
            snprintf(output_buffer, buf_len, "%hhd", value.Tbyte);
            return output_buffer;
        case Tshort:
            snprintf(output_buffer, buf_len, "%hd", value.Tshort);
            return output_buffer;
        case Tint:
            snprintf(output_buffer, buf_len, "%d", value.Tint);
            return output_buffer;
        case Tlong:
            snprintf(output_buffer, buf_len, "%ld", value.Tlong);
            return output_buffer;
        case Tubyte:
            snprintf(output_buffer, buf_len, "%hhu", value.Tubyte);
            return output_buffer;
        case Tushort:
            snprintf(output_buffer, buf_len, "%hu", value.Tushort);
            return output_buffer;
        case Tuint:
            snprintf(output_buffer, buf_len, "%u", value.Tuint);
            return output_buffer;
        case Tulong:
            snprintf(output_buffer, buf_len, "%lu", value.Tulong);
            return output_buffer;
        case Tfloat:
            snprintf(output_buffer, buf_len, "%f", value.Tfloat);
            return output_buffer;
        case Tdouble:
            snprintf(output_buffer, buf_len, "%lf", value.Tdouble);
            return output_buffer;
        case Tptr:
            snprintf(output_buffer, buf_len, "%p", value.Tptr);
            return output_buffer;
        case Tstring:
            return value.Tstring;
        case Tinvalid:
        default:
            return NULL;
    }
}

// Checks if a value satisfies a specified condition
// Oh boy do I love not having generics at times like these :)
// Would have been nice to implement this in Rust, but too late now.
int satisfies_condition(union scan_value value, enum scan_type type, enum scan_cond cond, union scan_value cond_value) {
    // Can simplify a bit going cond first since exists is always true, and the temporal conditions are the same as their non-temporal counterparts (only change is cond_value)
    // Could also use inversion to reduce 3 cases, but that leads to invalid results for invalid inputs (might have been worth it to ignore though)
    switch (cond) {
        case Ceq:
        case Csame:
            // == Case
            switch (type) {
                case Tbyte:
                    return value.Tbyte == cond_value.Tbyte;
                case Tshort:
                    return value.Tshort == cond_value.Tshort;
                case Tint:
                    return value.Tint == cond_value.Tint;
                case Tlong:
                    return value.Tlong == cond_value.Tlong;
                case Tubyte:
                    return value.Tubyte == cond_value.Tubyte;
                case Tushort:
                    return value.Tushort == cond_value.Tushort;
                case Tuint:
                    return value.Tuint == cond_value.Tuint;
                case Tulong:
                    return value.Tulong == cond_value.Tulong;
                case Tfloat:
                    return value.Tfloat == cond_value.Tfloat;
                case Tdouble:
                    return value.Tdouble == cond_value.Tdouble;
                case Tptr:
                    return value.Tptr == cond_value.Tptr;
                case Tstring:
                    // Compare character by character going by cond_value, so value doesn't have to be a valid string to work (instead of strcmp)
                    // Decided not to include the null-terminator to allow for substring search
                    // Could theoretically run into overflow issues, but should be fixed by the special reading case for strings
                    int end_offset = strlen(cond_value.Tstring);
                    for (int offset = 0; offset < end_offset; offset++) {
                        if (value.Tstring[offset] != cond_value.Tstring[offset]) {
                            return 0;
                        }
                    }
                    return 1;
                case Tinvalid:
                    return 0;
            }
        case Cneq:
        case Cdiff:
            // != case
            switch (type) {
                case Tbyte:
                    return value.Tbyte != cond_value.Tbyte;
                case Tshort:
                    return value.Tshort != cond_value.Tshort;
                case Tint:
                    return value.Tint != cond_value.Tint;
                case Tlong:
                    return value.Tlong != cond_value.Tlong;
                case Tubyte:
                    return value.Tubyte != cond_value.Tubyte;
                case Tushort:
                    return value.Tushort != cond_value.Tushort;
                case Tuint:
                    return value.Tuint != cond_value.Tuint;
                case Tulong:
                    return value.Tulong != cond_value.Tulong;
                case Tfloat:
                    return value.Tfloat != cond_value.Tfloat;
                case Tdouble:
                    return value.Tdouble != cond_value.Tdouble;
                case Tptr:
                    return value.Tptr != cond_value.Tptr;
                case Tstring:
                    // Same as for Ceq but negated
                    int end_offset = strlen(cond_value.Tstring);
                    for (int offset = 0; offset < end_offset; offset++) {
                        if (value.Tstring[offset] != cond_value.Tstring[offset]) {
                            return 1;
                        }
                    }
                    return 0;
                case Tinvalid:
                    return 0;
            }
        case Cgreater:
        case Cabove:
            // > case
            switch (type) {
                case Tbyte:
                    return value.Tbyte > cond_value.Tbyte;
                case Tshort:
                    return value.Tshort > cond_value.Tshort;
                case Tint:
                    return value.Tint > cond_value.Tint;
                case Tlong:
                    return value.Tlong > cond_value.Tlong;
                case Tubyte:
                    return value.Tubyte > cond_value.Tubyte;
                case Tushort:
                    return value.Tushort > cond_value.Tushort;
                case Tuint:
                    return value.Tuint > cond_value.Tuint;
                case Tulong:
                    return value.Tulong > cond_value.Tulong;
                case Tfloat:
                    return value.Tfloat > cond_value.Tfloat;
                case Tdouble:
                    return value.Tdouble > cond_value.Tdouble;
                case Tptr:
                    return value.Tptr > cond_value.Tptr;
                case Tstring:
                case Tinvalid:
                    return 0;
            }
        case Cless:
        case Cbelow:
            // < case
            switch (type) {
                case Tbyte:
                    return value.Tbyte < cond_value.Tbyte;
                case Tshort:
                    return value.Tshort < cond_value.Tshort;
                case Tint:
                    return value.Tint < cond_value.Tint;
                case Tlong:
                    return value.Tlong < cond_value.Tlong;
                case Tubyte:
                    return value.Tubyte < cond_value.Tubyte;
                case Tushort:
                    return value.Tushort < cond_value.Tushort;
                case Tuint:
                    return value.Tuint < cond_value.Tuint;
                case Tulong:
                    return value.Tulong < cond_value.Tulong;
                case Tfloat:
                    return value.Tfloat < cond_value.Tfloat;
                case Tdouble:
                    return value.Tdouble < cond_value.Tdouble;
                case Tptr:
                    return value.Tptr < cond_value.Tptr;
                case Tstring:
                case Tinvalid:
                    return 0;
            }
        case Cgeq:
            // >= case
            switch (type) {
                case Tbyte:
                    return value.Tbyte >= cond_value.Tbyte;
                case Tshort:
                    return value.Tshort >= cond_value.Tshort;
                case Tint:
                    return value.Tint >= cond_value.Tint;
                case Tlong:
                    return value.Tlong >= cond_value.Tlong;
                case Tubyte:
                    return value.Tubyte >= cond_value.Tubyte;
                case Tushort:
                    return value.Tushort >= cond_value.Tushort;
                case Tuint:
                    return value.Tuint >= cond_value.Tuint;
                case Tulong:
                    return value.Tulong >= cond_value.Tulong;
                case Tfloat:
                    return value.Tfloat >= cond_value.Tfloat;
                case Tdouble:
                    return value.Tdouble >= cond_value.Tdouble;
                case Tptr:
                    return value.Tptr >= cond_value.Tptr;
                case Tstring:
                case Tinvalid:
                    return 0;
            }
        case Cleq:
            // <= case
            switch (type) {
                case Tbyte:
                    return value.Tbyte <= cond_value.Tbyte;
                case Tshort:
                    return value.Tshort <= cond_value.Tshort;
                case Tint:
                    return value.Tint <= cond_value.Tint;
                case Tlong:
                    return value.Tlong <= cond_value.Tlong;
                case Tubyte:
                    return value.Tubyte <= cond_value.Tubyte;
                case Tushort:
                    return value.Tushort <= cond_value.Tushort;
                case Tuint:
                    return value.Tuint <= cond_value.Tuint;
                case Tulong:
                    return value.Tulong <= cond_value.Tulong;
                case Tfloat:
                    return value.Tfloat <= cond_value.Tfloat;
                case Tdouble:
                    return value.Tdouble <= cond_value.Tdouble;
                case Tptr:
                    return value.Tptr <= cond_value.Tptr;
                case Tstring:
                case Tinvalid:
                    return 0;
            }
        case Cexists:
            // exists case (always true)
            return 1;
        case Cinvalid:
        default:
            return 0;
    }
}

// Frees a node from the scan list
// Return the next node since we generally use this in context of manipulating the list
struct scan_node* free_node(struct scan_node* node, enum scan_type type) {
    struct scan_node* next = node->next;
    if (type == Tstring) {
        free(node->value.Tstring);
    }
    free(node);
    return next;
}

// Inject a syscall using ptrace
// Assume ptrace is already attached so that we can inject multiple calls in a row
// Also pass in syscall_addr instead of searching in inject_syscall to save on number of find commands issued
int inject_syscall(unsigned long long* syscall_retv, pid_t pid, unsigned long syscall_addr, unsigned long long syscall_no,
        unsigned long long arg1, unsigned long long arg2, unsigned long long arg3,
        unsigned long long arg4, unsigned long long arg5, unsigned long long arg6) {
    // Save registers for restoration later
    struct user_regs_struct saved_regs;
    if (ptrace(PTRACE_GETREGS, pid, 0, &saved_regs) == -1) {
        perror("failed to PTRACE_GETREGS");
        return -1;
    }

    // Set registers for syscall injection
    struct user_regs_struct inject_regs;
    memcpy(&inject_regs, &saved_regs, sizeof(struct user_regs_struct));
    inject_regs.rip = syscall_addr;
    inject_regs.rax = syscall_no;
    inject_regs.rdi = arg1;
    inject_regs.rsi = arg2;
    inject_regs.rdx = arg3;
    inject_regs.r10 = arg4;
    inject_regs.r9 = arg5;
    inject_regs.r8 = arg6;
    if (ptrace(PTRACE_SETREGS, pid, 0, &inject_regs) == -1) {
        perror("failed to PTRACE_SETREGS for injection");
        return -1;
    }

    // Inject (have to redo if stopped by a signal instead) and get return value
    siginfo_t wait_info;
    wait_info.si_code = CLD_CONTINUED;
    while (wait_info.si_code != CLD_TRAPPED) {
        if (ptrace(PTRACE_SINGLESTEP, pid, 0, 0) == -1) {
            perror("failed to PTRACE_SINGLESTEP through syscall");
            return -1;
        }
        waitid(P_PID, pid, &wait_info, WSTOPPED);
    }

    // Get return value from injected syscall
    if (ptrace(PTRACE_GETREGS, pid, 0, &inject_regs) == -1) {
        perror("failed to PTRACE_GETREGS after syscall");
        return -1;
    }
    *syscall_retv = inject_regs.rax;

    // Reset back to the initial registers
    if (ptrace(PTRACE_SETREGS, pid, 0, &saved_regs) == -1) {
        perror("failed to PTRACE_SETREGS for restoration");
        return -1;
    }
    return 0;
}

// Print a timestamp for a command's execution time
// From GNU documentation for subtracting timevals
void print_timestamp(char* command, struct timeval* start, struct timeval* end) {
    /* Perform the carry for the later subtraction by updating start. */
    if (end->tv_usec < start->tv_usec) {
        int nsec = (start->tv_usec - end->tv_usec) / 1000000 + 1;
        start->tv_usec -= 1000000 * nsec;
        start->tv_sec += nsec;
    }
    if (end->tv_usec - start->tv_usec > 1000000) {
        int nsec = (end->tv_usec - start->tv_usec) / 1000000;
        start->tv_usec += 1000000 * nsec;
        start->tv_sec -= nsec;
    }

    /* Compute the time remaining to wait. tv_usec is certainly positive. */
    long sec = end->tv_sec - start->tv_sec;
    long usec = end->tv_usec - start->tv_usec;

    // Print
    printf("Time to execute %s: %ld.%06lds\n", command, sec, usec);
}
