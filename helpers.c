#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "commands.h"
#include "helpers.h"

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
            return READ_BUF_SIZE;
    }
}

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
            snprintf(output_buffer, buf_len, "0x%p", value.Tptr);
            return output_buffer;
        case Tstring:
            return value.Tstring;
        case Tinvalid:
        default:
            return NULL;
    }
}

// Oh boy do I love not having generics at times like these :)
int satisfies_condition(union scan_value value, enum scan_type type, enum scan_cond cond, union scan_value cond_value) {
    // Can simplify a bit going cond first since exists is always true, and the temporal conditions are the same as their non-temporal counterparts
    // Could also use inversion to reduce 3 cases, but that leads to invalid results for invalid inputs (might have been worth it to ignore though)
    switch (cond) {
        case Ceq:
        case Csame:
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
                    // Compare character by character going by cond_value, so value doesn't have to be a valid string to work
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
            return 1;
        case Cinvalid:
        default:
            return 0;
    }
}

// Return the next node since we generally use this in context of manipulating the list
struct scan_node* free_node(struct scan_node* node) {
    struct scan_node* next = node->next;
    if (node->type == Tstring) {
        free(node->value.Tstring);
    }
    free(node);
    return next;
}
