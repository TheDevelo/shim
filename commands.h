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

extern const char* TYPE_STR[Tinvalid + 1];

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
    void* addr; // Address in child's address space, not the parent's.
    struct scan_node* next;
};

struct scan_config {
    pid_t scan_pid;
    int skip_files;
    int timestamp;
    int syscall_scan; // Used only internally for syscall_addr scanning
};

struct scan_list {
    struct scan_node* head;
    enum scan_type type;
};

struct save_node {
    enum scan_type type;
    void* addr;
    unsigned long count; // For strings (and other array types)
    struct save_node* next;
};

struct scan_list find_cmd(char* input, struct scan_config config);
struct scan_list refine_cmd(char* input, struct scan_config config, struct scan_list list);
void page_cmd(char* input, struct scan_config config, struct scan_list list);
struct save_node* save_cmd(char* input, struct scan_config config, struct scan_list list);
struct save_node* saveaddr_cmd(char* input);
void display_cmd(struct scan_config config, struct save_node* list);
void modify_cmd(char* input, struct scan_config config, struct save_node* list);
void monitor_cmd(char* input, struct scan_config config, struct save_node* list);
void help_cmd(char* input);
