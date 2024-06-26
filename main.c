#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include "commands.h"
#include "helpers.h"

// Use lxterminal --command= on Pi, gnome-terminal -- on laptop. Would be better to set using an environment variable.
char* term_format = "gnome-terminal -- /proc/%d/exe";
// char* term_format = "lxterminal --command=/proc/%d/exe";
char* fifo_location = "/tmp/shim-fifo";

int dummy_func();
int terminal_func();
int child_func(char** command);

int main(int argc, char** argv) {
    // If no args are provided, act as the dummy for the terminal connection
    if (argc == 1) {
        return dummy_func();
    }

    // Create a FIFO to talk to obtain the terminal dummy's PID
    if (mkfifo(fifo_location, S_IRWXU) == -1) {
        perror("failed to mkfifo() for dummy PID");
        return -2;
    }

    // Spawn the new terminal
    pid_t pid = fork();
    if (pid == -1) {
        perror("failed to call fork() for new terminal");
        return -1;
    }
    else if (pid == 0) {
        return terminal_func();
    }

    // Read the PID from the FIFO and clean up
    FILE* fifo = fopen(fifo_location, "r");
    if (fifo == NULL) {
        perror("failed to fopen() the FIFO");
        return -4;
    }
    pid_t dummy_pid;
    if (fscanf(fifo, "%d", &dummy_pid) != 1) {
        printf("failed to read dummy pid from FIFO\n");
        return -3;
    }
    fclose(fifo);
    if (unlink(fifo_location) == -1) {
        perror("failed to unlink() the FIFO");
        return -5;
    }

    // Spawn the child we want to monitor
    pid = fork();
    if (pid == -1) {
        perror("failed to call fork() for the program to monitor");
        return -1;
    }
    else if (pid == 0) {
        return child_func(&argv[1]);
    }

    // Overwrite the stdout, stdin, and stderr fds so that we write to the new terminal
    char fd_path[256];
    snprintf(fd_path, 256, "/proc/%d/fd/%d", dummy_pid, STDIN_FILENO);
    freopen(fd_path, "r", stdin);
    snprintf(fd_path, 256, "/proc/%d/fd/%d", dummy_pid, STDOUT_FILENO);
    freopen(fd_path, "w", stdout);
    snprintf(fd_path, 256, "/proc/%d/fd/%d", dummy_pid, STDERR_FILENO);
    freopen(fd_path, "w", stderr);

    // Main input loop
    char* input_line = NULL;
    size_t input_len = 0;
    struct scan_list scan_results = { .head = NULL, .type = Tinvalid };
    struct scan_config config = { .scan_pid = pid, .skip_files = 1, .debug = 0, .syscall_scan = 0, .in_core_only = 1 };
    struct save_node* save_head = NULL;
    struct save_node* save_tail = NULL;
    struct timeval start, end;
    while (1) {
        printf("> ");
        fflush(stdout);

        // Parse input command
        getline(&input_line, &input_len, stdin);
        char cmd_name[256];
        gettimeofday(&start, NULL);
        if (sscanf(input_line, "%256s", cmd_name) == 1) {
            if (strcmp(cmd_name, "find") == 0) {
                if (scan_results.head == NULL) {
                    scan_results = find_cmd(input_line, config);
                }
                else {
                    printf("a scan is already ongoing. please finish the current scan with 'finish' before starting a new one\n");
                }
            }
            else if (strcmp(cmd_name, "refine") == 0) {
                if  (scan_results.head != NULL) {
                    scan_results = refine_cmd(input_line, config, scan_results);
                }
                else {
                    printf("no scan is ongoing\n");
                }
            }
            else if (strcmp(cmd_name, "page") == 0) {
                if (scan_results.head != NULL) {
                    page_cmd(input_line, config, scan_results);
                }
                else {
                    printf("no scan is ongoing\n");
                }
            }
            else if (strcmp(cmd_name, "save") == 0) {
                if (scan_results.head != NULL) {
                    struct save_node* result = save_cmd(input_line, config, scan_results);
                    if (result != NULL) {
                        if (save_tail == NULL) {
                            save_head = result;
                            save_tail = result;
                        }
                        else {
                            save_tail->next = result;
                            save_tail = result;
                        }
                    }
                }
                else {
                    printf("no scan is ongoing\n");
                }
            }
            else if (strcmp(cmd_name, "saveaddr") == 0) {
                struct save_node* result = saveaddr_cmd(input_line);
                if (result != NULL) {
                    if (save_tail == NULL) {
                        save_head = result;
                        save_tail = result;
                    }
                    else {
                        save_tail->next = result;
                        save_tail = result;
                    }
                }
            }
            else if (strcmp(cmd_name, "display") == 0) {
                display_cmd(config, save_head);
            }
            else if (strcmp(cmd_name, "modify") == 0) {
                modify_cmd(input_line, config, save_head);
            }
            else if (strcmp(cmd_name, "monitor") == 0) {
                monitor_cmd(input_line, config, save_head);
            }
            else if (strcmp(cmd_name, "lookup") == 0) {
                lookup_cmd(input_line, config);
            }
            else if (strcmp(cmd_name, "finish") == 0) {
                // Clean up the scan nodes
                struct scan_node* cur_node = scan_results.head;
                while (cur_node != NULL) {
                    cur_node = free_node(cur_node, scan_results.type);
                }
                scan_results.head = NULL;
            }
            else if (strcmp(cmd_name, "config") == 0) {
                // Configuration options
                unsigned int value_uint;
                if (sscanf(input_line, "config pid %u", &value_uint) == 1) {
                    config.scan_pid = value_uint;
                    printf("now scanning pid %d\n", config.scan_pid);
                }
                else if (sscanf(input_line, "config skip_files %u", &value_uint) == 1) {
                    if (value_uint) {
                        config.skip_files = 1;
                        printf("skip files is now enabled\n");
                    }
                    else {
                        config.skip_files = 0;
                        printf("skip files is now disabled\n");
                    }
                }
                else if (sscanf(input_line, "config debug %u", &value_uint) == 1) {
                    if (value_uint) {
                        config.debug = 1;
                        printf("debug is now enabled\n");
                    }
                    else {
                        config.debug = 0;
                        printf("debug is now disabled\n");
                    }
                }
                else if (sscanf(input_line, "config in_core_only %u", &value_uint) == 1) {
                    if (value_uint) {
                        config.in_core_only = 1;
                        printf("in core only is now enabled\n");
                    }
                    else {
                        config.in_core_only = 0;
                        printf("in core only is now disabled\n");
                    }
                }
                else {
                    printf("invalid 'config' command\n");
                }
            }
            else if (strcmp(cmd_name, "quit") == 0) {
                break;
            }
            else if (strcmp(cmd_name, "help") == 0) {
                help_cmd(input_line);
            }
            else {
                printf("invalid command - use 'help' to view all available commands\n");
            }
        }
        gettimeofday(&end, NULL);

        if (config.debug) {
            print_timestamp(cmd_name, &start, &end);
        }
    }

    // Clean up the scan and save nodes
    struct save_node* cur_node_save = save_head;
    while (cur_node_save != NULL) {
        struct save_node* next = cur_node_save->next;
        free(cur_node_save);
        cur_node_save = next;
    }
    struct scan_node* cur_node_scan = scan_results.head;
    while (cur_node_scan != NULL) {
        cur_node_scan = free_node(cur_node_scan, scan_results.type);
    }

    // Kill all child processes
    // Send SIGTERM to allow themselves to kill themselves gracefully instead of SIGKILL
    // Unregister SIGTERM for self so that we can exit normally though
    signal(SIGTERM, SIG_IGN);
    kill(dummy_pid, SIGTERM);
    kill(0, SIGTERM);
    return 0;
}

int terminal_func() {
    // Use parent's pid (the initial shim process) since the child doesn't have /proc/PID/exe
    pid_t pid = getppid();
    char command[1024];
    snprintf(command, 1024, term_format, pid);
    return system(command);
}

int dummy_func() {
    printf("shim Command Terminal\n");

    // Write the dummy's PID to the FIFO
    if (access(fifo_location, W_OK) == -1) {
        perror("can't write to the FIFO");
        printf("Usage: shim COMMAND...\n");
        return -1;
    }
    FILE* fifo = fopen(fifo_location, "w");
    if (fifo == NULL) {
        perror("failed to fopen() the FIFO");
        return -2;
    }
    fprintf(fifo, "%d", getpid());
    fclose(fifo);

    return pause();
}

int child_func(char** command) {
    int ret = execvp(command[0], command);
    if (ret == -1) {
        perror("failed to execvp() the specified command");
    }
    return ret;
}
