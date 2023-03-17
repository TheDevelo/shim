#pragma once
#include "commands.h"

enum scan_type str_to_type(char* type_str);
enum scan_cond str_to_cond(char* cond_str);
int type_step(enum scan_type type);
union scan_value parse_value(char* value_str, enum scan_type type);
union scan_value mem_to_value(void* mem_ptr, enum scan_type type);
int satisfies_condition(union scan_value value, enum scan_type type, enum scan_cond cond, union scan_value cond_value);