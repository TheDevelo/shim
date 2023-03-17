#pragma once
#include <sys/types.h>

#define READ_BUF_SIZE 4096 // Can't be bigger than one page (4096 bytes)

enum scan_type {
    Tbyte,
    Tshort,
    Tint,
    Tlong,
    Tubyte,
    Tushort,
    Tuint,
    Tulong,
    Tfloat,
    Tdouble,
    Tptr,
    Tstring,
    Tinvalid
};

enum scan_cond {
    Ceq,
    Cneq,
    Cless,
    Cgreater,
    Cleq,
    Cgeq,
    Cexists,
    Csame,
    Cdiff,
    Cabove,
    Cbelow,
    Cinvalid
};

union scan_value {
    signed char Tbyte;
    signed short Tshort;
    signed int Tint;
    signed long Tlong;
    unsigned char Tubyte;
    unsigned short Tushort;
    unsigned int Tuint;
    unsigned long Tulong;
    float Tfloat;
    double Tdouble;
    void* Tptr;
    char* Tstring;
};

struct scan_node {
    union scan_value value;
    enum scan_type type;
    struct scan_node* next;
};

void help_cmd(char* input);
struct scan_node* find_cmd(char* input, pid_t child_pid);
