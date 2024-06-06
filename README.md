# shim
**shim** is a memory scanning tool for Linux. It is able to scan and monitor the memory of programs without pausing execution.
To run **shim**, launch the program you want to scan with
```bash
shim PROGRAM
```
This will launch an additional terminal that serves as the command interface for **shim**.

## Source Code
As documentation, below is a description of each file and functions within:

**main.c** - Entrypoint to shim, includes launch sequence that spawns new terminal and the tracee, setup for tracing, and the initial processing of user input. Commands are mainly delegated to **commands.c**
- **main()** - Entrypoint that setups shim and contains main execution loop
- **terminal_func()** - Child function that spawns the new terminal
- **dummy_func()** - Child function that writes to the FIFO, executed from the new terminal's dummy
- **child_func()** - Child function that executes the specified command, serves as the tracee

**commands.c** - Functions for each sufficiently complex command. One function per command.
- **find_cmd()** - find command, searches memory for addresses that pass a condition
- **refine_cmd()** - refine command, checks addresses in scan list for a second condition
- **page_cmd()** - page command, displays values in scan list
- **save_cmd()** - save command, copies an entry in scan list to save list
- **saveaddr_cmd()** - saveaddr command, saves a user-specified address to the save list
- **display_cmd()** - display command, displays values in save list
- **modify_cmd()** - modify command, modifies a value in save list
- **monitor_cmd()** - monitor command, monitors a value in save list for reads and writes
- **lookup_cmd()** - lookup command, searches for the memory region containing a specified address
- **help_cmd()** - help command, displays help information on commands

**commands.h** - Function signatures for **commands.c** AND custom datatypes used for the scan information (types, conditions, scan list nodes, save list nodes)

**helpers.c** - Miscellaneous helper functions, mainly dealing with functions that switch based on type or condition to clean up command processing code.
- **str_to_type()** - converts a string to the type enum
- **str_to_cond()** - converts a string to the condition enum
- **type_step()** - gets the size of a specified type in bytes (size of 1 character for a string)
- **parse_value()** - parses a string to a value as if it were the specified type
- **mem_to_value()** - creates a scan_value union from the memory pointed as if it were the specified type
- **value_to_str()** - converts a scan_value to a string using the specified type
- **satisfies_condition()** - checks if a value passes the specified condition
- **free_node()** - frees a scan list entry and returns the next entry in the list
- **inject_syscall()** - injects a system call (assumes that ptrace is already set up)
- **print_timestamp()** - prints a timestamp for a command's execution time

**helpers.h** - Function signatures for **helpers.c**

## Tests
Additional programs used for testing **shim** can be found in **test-programs/**. Below is a list of each program:
- **random.c** - Prints two random integers, one stored on the heap and one on the stack. Rerandomizes and reprints values on input from stdin.
- **line_reader.c** - Reads a string from stdin using getline() and prints back out to the terminal.
- **dense_mm.c** - Adapted from CSE 422S materials, multiplies two large matrices together, once for each input from stdin. Size is specified as a command line parameter. Prints timestamps for execution time. Allocates 4x the memory needed in order to demonstrate a usecase that does not page in all allocated memory.
- **string_write.c** - Prints address to a string buffer, waits for input, and then writes the contents of the string buffer.
- **rand_types.c** - Same as random.c but includes every type shim supports except for strings, and does not allocate on the heap.
- **segfault.c** - Allocates a region of memory with no permissions and intentionally accesses it. Used in order to verify that the monitor command properly forwards SEGFAULTS.
